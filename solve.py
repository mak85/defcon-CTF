#!/usr/bin/env python3
"""
angr solver — attempt 6: pure DFS, no veritesting, expanded timeouts.

The validator has ~16 branches in 70K instructions; without veritesting
each step is a basic block (huge linear region). Try this for speed.
"""

import angr
import claripy
import logging
import sys
import time

logging.getLogger('angr').setLevel(logging.WARNING)
sys.setrecursionlimit(50000)

BINARY = './myfavoriteinstructions'
GHIDRA_BASE = 0x100000
OFF_VALIDATOR = 0x1011a0 - GHIDRA_BASE

ARRAY_LEN_U64 = 360
ARRAY_ADDR    = 0x60000000
STACK_BASE    = 0x70000000
STACK_TOP     = 0x70200000
FAKE_RET      = 0xdeadbeefcafef00d


def main():
    print(f'[+] Loading {BINARY}')
    proj = angr.Project(BINARY, auto_load_libs=False)
    base = proj.loader.main_object.mapped_base
    addr_validator = base + OFF_VALIDATOR

    sym = [claripy.BVS(f't{i}', 64) for i in range(ARRAY_LEN_U64)]

    state = proj.factory.blank_state(
        addr=addr_validator,
        add_options={
            angr.options.LAZY_SOLVES,
            angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY,
            angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS,
        },
        remove_options={
            angr.options.STRICT_PAGE_ACCESS,
        },
    )
    state.memory.map_region(STACK_BASE, STACK_TOP - STACK_BASE, 0b111)

    for i, s in enumerate(sym):
        state.memory.store(ARRAY_ADDR + i*8, s, endness='Iend_LE')
        state.solver.add(s >= 0)
        state.solver.add(s <= 2)
    state.regs.r12 = ARRAY_ADDR
    state.regs.rsp = STACK_TOP - 8
    state.memory.store(STACK_TOP - 8, claripy.BVV(FAKE_RET, 64), endness='Iend_LE')

    sm = proj.factory.simulation_manager(state, save_unsat=True)
    sm.use_technique(angr.exploration_techniques.DFS())

    print(f'[+] Starting DFS exploration...', flush=True)
    t0 = time.time()
    last_print = t0

    step_count = 0
    finished_states = []

    while sm.active and (time.time() - t0) < 1800:  # 30 min
        try:
            sm.step()
        except Exception as e:
            print(f'[!] step error: {e}', flush=True)
            break
        step_count += 1

        now = time.time()
        if now - last_print > 5:
            try:
                pcs = [hex(s.solver.eval(s.regs.rip)) for s in sm.active[:3]]
            except Exception:
                pcs = ['?']
            stashes_summary = {k: len(v) for k, v in sm.stashes.items() if v}
            print(f'    [{now-t0:.0f}s] step {step_count}: '
                  f'stashes={stashes_summary} pc={pcs}', flush=True)
            last_print = now

        still_active = []
        for s in sm.active:
            try:
                if s.solver.is_true(s.regs.rip == FAKE_RET):
                    finished_states.append(s)
                else:
                    still_active.append(s)
            except Exception:
                still_active.append(s)
        sm.stashes['active'] = still_active

    elapsed = time.time() - t0
    print(f'[+] Stopped after {elapsed:.0f}s, {step_count} steps', flush=True)
    print(f'    stashes: {dict((k, len(v)) for k, v in sm.stashes.items() if v)}')
    print(f'    finished={len(finished_states)}')
    if sm.errored:
        print(f'[!] errored states: {len(sm.errored)}')
        for e in sm.errored[:3]:
            print(f'    error: {e.error}')

    candidates = finished_states + sm.deadended
    for st in candidates:
        try:
            st.solver.add(st.regs.rax & 0xffffffff == 2)
            if st.satisfiable():
                vals = [st.solver.eval(s) for s in sym]
                print(f'[+] WIN!')
                print(vals)
                with open('ternary_digits.txt', 'w') as f:
                    f.write(','.join(map(str, vals)))
                return 0
        except Exception:
            pass

    print('[-] No winning state.')
    return 1


if __name__ == '__main__':
    sys.exit(main())
