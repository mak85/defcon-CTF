#!/usr/bin/env python3
"""
angr solver for myfavoriteinstructions

Strategy: symbolically execute main with a 68-char symbolic argv[1],
then find a state where execution reaches the CMP at 0x14dd40
with EAX == 2 (the win condition).
"""

import angr
import claripy
import logging
import sys
import time

logging.getLogger('angr').setLevel(logging.ERROR)

BINARY = './myfavoriteinstructions'
FLAG_LEN = 68

# Key addresses from Ghidra analysis (assuming non-PIE; otherwise add base)
ADDR_VALIDATOR_RET = 0x14dd40   # CMP EAX, 0x2 — return point of FUN_001011a0
ADDR_TOO_SHORT     = 0x14dd8f   # "Flag too short" branch — avoid
ADDR_USAGE_1       = 0x14dd6c   # usage branch — avoid
ADDR_USAGE_2       = 0x14dd6d   # usage branch — avoid


def main():
    print(f'[+] Loading {BINARY}')
    proj = angr.Project(BINARY, auto_load_libs=False)
    print(f'[+] Arch: {proj.arch}, entry: {hex(proj.entry)}, base: {hex(proj.loader.main_object.mapped_base)}')

    # Build 68-byte symbolic flag, restrict to printable ASCII
    flag_bytes = [claripy.BVS(f'f{i}', 8) for i in range(FLAG_LEN)]
    flag = claripy.Concat(*flag_bytes)

    # argv[1] needs to be null-terminated for strlen
    argv1 = claripy.Concat(flag, claripy.BVV(0, 8))

    state = proj.factory.full_init_state(
        args=[BINARY, argv1],
        add_options={
            angr.options.LAZY_SOLVES,
            angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS,
            angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY,
        },
    )

    # Printable ASCII constraint
    for b in flag_bytes:
        state.solver.add(b >= 0x20)
        state.solver.add(b <= 0x7e)

    sm = proj.factory.simulation_manager(state)

    print(f'[+] Exploring to {hex(ADDR_VALIDATOR_RET)} avoiding error branches...')
    t0 = time.time()
    sm.explore(
        find=ADDR_VALIDATOR_RET,
        avoid=[ADDR_TOO_SHORT, ADDR_USAGE_1, ADDR_USAGE_2],
    )
    print(f'[+] Exploration took {time.time()-t0:.1f}s')
    print(f'[+] found={len(sm.found)}, avoid={len(sm.avoid)}, active={len(sm.active)}')

    if not sm.found:
        print('[-] No path reached the validator return.')
        return 1

    found = sm.found[0]
    # Constrain EAX == 2 (the win condition)
    found.solver.add(found.regs.eax == 2)

    if not found.satisfiable():
        print('[-] Reached validator return but EAX==2 is unsatisfiable.')
        return 1

    flag_val = found.solver.eval(flag, cast_to=bytes)
    print(f'\n[+] FLAG: {flag_val.decode(errors="replace")}')
    print(f'[+] hex : {flag_val.hex()}')
    return 0


if __name__ == '__main__':
    sys.exit(main())
