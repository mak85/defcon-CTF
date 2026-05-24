#!/usr/bin/env python3
"""Solve branchless-compiler binary with angr.

The binary toggles rbp between two pages (realBase / fakeBase). To avoid
symbolic-memory blowup, force rbp to be concretized at every memory access.
"""
import sys
import os
import re
import subprocess
import time
import logging

import claripy
import angr
import angr.concretization_strategies as cs

logging.getLogger("angr").setLevel(logging.ERROR)
logging.getLogger("cle").setLevel(logging.ERROR)
logging.getLogger("pyvex").setLevel(logging.ERROR)

SECRET_LEN = 32
REAL_BASE = 0x0beef000
FAKE_BASE = 0x4beef000
SUCCESS_LABEL = 0x0f1a5000
FAILURE_LABEL = 0x0eadf1a5
TIMEOUT_SECONDS = int(os.environ.get("SOLVER_TIMEOUT", "900"))


def find_handlers(binary_path):
    out = subprocess.check_output(["objdump", "-d", binary_path], stderr=subprocess.DEVNULL).decode()
    s = f = None
    for line in out.split("\n"):
        m = re.match(r"^([0-9a-fA-F]+)\s+<(\w+)>:", line)
        if m:
            addr, name = int(m.group(1), 16), m.group(2)
            if name == "success_handler": s = addr
            elif name == "failure_handler": f = addr
    return s, f


def solve(binary_path):
    t0 = time.time()
    proj = angr.Project(binary_path, auto_load_libs=False)
    s, f = find_handlers(binary_path)
    print(f"[angr] success={hex(s)} failure={hex(f)}", file=sys.stderr)

    stdin_bytes = [claripy.BVS(f"b{i}", 8) for i in range(SECRET_LEN)]
    stdin_data = claripy.Concat(*stdin_bytes)

    state = proj.factory.entry_state(
        stdin=angr.SimFileStream(name="stdin", content=stdin_data, has_end=True),
    )
    state.options.add(angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY)
    state.options.add(angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS)
    state.options.add(angr.options.LAZY_SOLVES)
    # Concretize symbolic memory addresses to one of {realBase, fakeBase}
    state.memory.write_strategies.insert(0, cs.SimConcretizationStrategySolutions(2))
    state.memory.read_strategies.insert(0, cs.SimConcretizationStrategySolutions(2))

    for b in stdin_bytes:
        state.solver.add(b >= ord("a"))
        state.solver.add(b <= ord("z"))

    simgr = proj.factory.simgr(state)
    deadline = t0 + TIMEOUT_SECONDS

    last_report = t0
    while time.time() < deadline:
        simgr.explore(find=s, avoid=f, num_find=3, n=50)
        if simgr.found or not simgr.active:
            break
        if time.time() - last_report > 10:
            print(f"[angr] t={time.time()-t0:.0f}s active={len(simgr.active)} found={len(simgr.found)} avoid={len(simgr.avoid) if hasattr(simgr,'avoid') else 0}", file=sys.stderr)
            last_report = time.time()

    print(f"[angr] done t={time.time()-t0:.0f}s found={len(simgr.found)}", file=sys.stderr)
    for found in simgr.found:
        try:
            secret = bytes(found.solver.eval(b) for b in stdin_bytes).decode("ascii", errors="replace")
            print(f"[angr] candidate: {secret!r}", file=sys.stderr)
            r = subprocess.run([binary_path], input=secret.encode(), timeout=10, capture_output=True)
            print(f"[verify] exit={r.returncode}", file=sys.stderr)
            if r.returncode == 0:
                print(secret)
                return
        except Exception as e:
            print(f"[angr] eval err: {e}", file=sys.stderr)
    print("FAILED", file=sys.stderr)
    sys.exit(1)


def main():
    if len(sys.argv) != 2:
        print("usage: solve_binary.py <binary>", file=sys.stderr)
        sys.exit(2)
    binary = sys.argv[1]
    os.chmod(binary, 0o755)
    solve(binary)


if __name__ == "__main__":
    main()
