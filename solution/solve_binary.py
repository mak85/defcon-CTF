#!/usr/bin/env python3
"""Solve a single soaring-swifts compiled binary via angr symbolic execution.

Usage:
  solve_binary.py <binary_path>

Environment:
  SOLVER_TIMEOUT  Seconds to allow angr exploration before giving up (default 600).

Prints the recovered 32-char secret on stdout, or exits non-zero on failure.
"""
import sys
import os
import re
import subprocess
import time
import logging

import claripy
import angr

logging.getLogger("angr").setLevel(logging.ERROR)
logging.getLogger("cle").setLevel(logging.ERROR)
logging.getLogger("pyvex").setLevel(logging.ERROR)

SECRET_LEN = 32
TIMEOUT_SECONDS = int(os.environ.get("SOLVER_TIMEOUT", "600"))


def find_handlers(binary_path):
    """Find success/failure handler addresses via symbol table or exit-syscall scan."""
    success_addr, failure_addr = None, None
    try:
        disasm = subprocess.check_output(
            ["objdump", "-d", binary_path], stderr=subprocess.DEVNULL
        ).decode()
        for line in disasm.split("\n"):
            m = re.match(r"^([0-9a-fA-F]+)\s+<(\w+)>:", line)
            if m:
                addr = int(m.group(1), 16)
                name = m.group(2)
                if name == "success_handler":
                    success_addr = addr
                elif name == "failure_handler":
                    failure_addr = addr
    except Exception:
        pass

    if success_addr is None or failure_addr is None:
        # Fallback: scan binary for `mov edi,0; mov eax,60; syscall` (exit 0) and exit 1 patterns
        from elftools.elf.elffile import ELFFile

        with open(binary_path, "rb") as f:
            elf = ELFFile(f)
            for seg in elf.iter_segments():
                if seg["p_type"] == "PT_LOAD" and (seg["p_flags"] & 0x1):
                    vaddr = seg["p_vaddr"]
                    text = seg.data()
                    pat0 = b"\xbf\x00\x00\x00\x00\xb8\x3c\x00\x00\x00\x0f\x05"
                    pat1 = b"\xbf\x01\x00\x00\x00\xb8\x3c\x00\x00\x00\x0f\x05"
                    i0 = text.find(pat0)
                    i1 = text.find(pat1)
                    if i0 != -1 and success_addr is None:
                        success_addr = vaddr + i0
                    if i1 != -1 and failure_addr is None:
                        failure_addr = vaddr + i1
                    break
    return success_addr, failure_addr


def solve(binary_path):
    t0 = time.time()
    proj = angr.Project(binary_path, auto_load_libs=False)
    success_addr, failure_addr = find_handlers(binary_path)
    print(
        f"[solve] success={hex(success_addr) if success_addr else None} "
        f"failure={hex(failure_addr) if failure_addr else None}",
        file=sys.stderr,
    )
    if success_addr is None:
        raise RuntimeError("Cannot find success_handler address")

    stdin_bytes = [claripy.BVS(f"b{i}", 8) for i in range(SECRET_LEN)]
    stdin_data = claripy.Concat(*stdin_bytes)

    state = proj.factory.entry_state(
        stdin=angr.SimFileStream(name="stdin", content=stdin_data, has_end=True),
    )
    state.options.add(angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY)
    state.options.add(angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS)
    state.options.add(angr.options.LAZY_SOLVES)

    for b in stdin_bytes:
        state.solver.add(b >= ord("a"))
        state.solver.add(b <= ord("z"))

    simgr = proj.factory.simgr(state)
    print(f"[solve] starting exploration t={time.time()-t0:.1f}s", file=sys.stderr)
    deadline = t0 + TIMEOUT_SECONDS
    while time.time() < deadline:
        simgr.explore(find=success_addr, avoid=failure_addr, num_find=4, n=20)
        if simgr.found and len(simgr.found) >= 1 and not simgr.active:
            break
        if simgr.found and len(simgr.found) >= 4:
            break
        if not simgr.active:
            break
        elapsed = time.time() - t0
        print(
            f"[solve] t={elapsed:.1f}s active={len(simgr.active)} found={len(simgr.found)}",
            file=sys.stderr,
        )

    print(
        f"[solve] explore done t={time.time()-t0:.1f}s found={len(simgr.found)}",
        file=sys.stderr,
    )
    candidates = []
    for found in simgr.found:
        try:
            secret_bytes = [found.solver.eval(b) for b in stdin_bytes]
            candidates.append(bytes(secret_bytes).decode("ascii", errors="replace"))
        except Exception as e:
            print(f"[solve] eval error: {e}", file=sys.stderr)
    return candidates


def verify(binary_path, secret):
    try:
        r = subprocess.run(
            [binary_path], input=secret.encode(), timeout=10, capture_output=True
        )
        return r.returncode == 0
    except Exception as e:
        print(f"[verify] error: {e}", file=sys.stderr)
        return False


def main():
    if len(sys.argv) != 2:
        print("usage: solve_binary.py <binary>", file=sys.stderr)
        sys.exit(2)
    binary = sys.argv[1]
    os.chmod(binary, 0o755)
    candidates = solve(binary)
    if not candidates:
        print("FAILED: no candidates", file=sys.stderr)
        sys.exit(1)
    for c in candidates:
        ok = verify(binary, c)
        print(f"[verify] secret={c!r} ok={ok}", file=sys.stderr)
        if ok:
            print(c)
            return
    print("VERIFY FAILED for all candidates", file=sys.stderr)
    sys.exit(2)


if __name__ == "__main__":
    main()
