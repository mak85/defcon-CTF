#!/usr/bin/env python3
"""
Trace which conditional branches are taken by the validator
with different inputs. This reveals where the decisions are.
"""
from unicorn import *
from unicorn.x86_const import *
import struct
import sys

sys.path.insert(0, '.')
from trace import load_text, hook_plt, CODE_BASE, ARRAY_ADDR, STACK_BASE, STACK_TOP, \
    FAKE_RET, OFF_VALIDATOR_START, OFF_VALIDATOR_RET, PLT_MEMSET, PLT_MEMCPY, PLT_MEMMOVE

# Branch instructions found earlier
BRANCH_OFFSETS = [
    0x102f6, 0x17c5c, 0x17cb0, 0x1b3c4,
    0x1c0a1, 0x1ce67, 0x248a5, 0x263df,
    0x263fb, 0x2db1f, 0x2decf, 0x2e22a,
    0x2e230, 0x38d60, 0x3ccd1, 0x48c8b,
]


def trace_branches(ternary_array):
    """Returns list of (branch_addr, taken) tuples."""
    mu = Uc(UC_ARCH_X86, UC_MODE_64)
    mu.mem_map(CODE_BASE, 0x100000)
    mu.mem_write(CODE_BASE, load_text()[:0x100000])
    mu.mem_map(ARRAY_ADDR, 0x10000)
    for i, v in enumerate(ternary_array):
        mu.mem_write(ARRAY_ADDR + i*8, struct.pack('<Q', v))
    mu.mem_map(STACK_BASE, STACK_TOP - STACK_BASE)
    mu.mem_write(STACK_TOP - 8, struct.pack('<Q', FAKE_RET))
    mu.reg_write(UC_X86_REG_RSP, STACK_TOP - 8)
    mu.reg_write(UC_X86_REG_R12, ARRAY_ADDR)

    for plt_addr in (PLT_MEMSET, PLT_MEMCPY, PLT_MEMMOVE):
        mu.hook_add(UC_HOOK_CODE, hook_plt,
                    begin=CODE_BASE + plt_addr,
                    end=CODE_BASE + plt_addr + 1)

    # Track branch outcomes by hooking the instruction AFTER each branch
    # If we land there, the branch was NOT taken (fell through)
    # We also note when we land at the branch target (taken)
    branches_taken = {}  # addr -> True/False
    branch_pcs = {CODE_BASE + b for b in BRANCH_OFFSETS}

    def code_hook(mu, addr, size, ud):
        if addr in branch_pcs:
            # Disassemble or check the branch direction
            # We'll record the PC when we hit a branch
            insn_bytes = mu.mem_read(addr, size)
            # We just record that the branch was reached
            branches_taken.setdefault(addr, []).append('reached')

    mu.hook_add(UC_HOOK_CODE, code_hook)

    try:
        start = CODE_BASE + OFF_VALIDATOR_START
        end = CODE_BASE + OFF_VALIDATOR_RET + 1
        mu.emu_start(start, end, timeout=10_000_000, count=0)
    except UcError:
        pass

    rax = mu.reg_read(UC_X86_REG_RAX) & 0xffffffff
    return rax, branches_taken


def trace_full_path(ternary_array, branch_set):
    """Records the order in which conditional branches are encountered."""
    mu = Uc(UC_ARCH_X86, UC_MODE_64)
    mu.mem_map(CODE_BASE, 0x100000)
    mu.mem_write(CODE_BASE, load_text()[:0x100000])
    mu.mem_map(ARRAY_ADDR, 0x10000)
    for i, v in enumerate(ternary_array):
        mu.mem_write(ARRAY_ADDR + i*8, struct.pack('<Q', v))
    mu.mem_map(STACK_BASE, STACK_TOP - STACK_BASE)
    mu.mem_write(STACK_TOP - 8, struct.pack('<Q', FAKE_RET))
    mu.reg_write(UC_X86_REG_RSP, STACK_TOP - 8)
    mu.reg_write(UC_X86_REG_R12, ARRAY_ADDR)

    for plt_addr in (PLT_MEMSET, PLT_MEMCPY, PLT_MEMMOVE):
        mu.hook_add(UC_HOOK_CODE, hook_plt,
                    begin=CODE_BASE + plt_addr,
                    end=CODE_BASE + plt_addr + 1)

    pcs = []
    def code_hook(mu, addr, size, ud):
        if addr in branch_set:
            pcs.append(addr - CODE_BASE)

    mu.hook_add(UC_HOOK_CODE, code_hook)
    try:
        mu.emu_start(CODE_BASE + OFF_VALIDATOR_START,
                     CODE_BASE + OFF_VALIDATOR_RET + 1,
                     timeout=10_000_000, count=0)
    except UcError:
        pass
    rax = mu.reg_read(UC_X86_REG_RAX) & 0xffffffff
    return rax, pcs


def main():
    import random
    random.seed(42)

    branch_set = {CODE_BASE + b for b in BRANCH_OFFSETS}

    # Try a few inputs
    inputs = [
        ('all zeros', [0]*200),
        ('all ones',  [1]*200),
        ('all twos',  [2]*200),
        ('random 1',  [random.randint(0,2) for _ in range(200)]),
        ('random 2',  [random.randint(0,2) for _ in range(200)]),
        ('aaaa..',    [2, 0, 1, 2, 0, 2, 0, 1, 2, 0, 2, 0, 1, 2, 0, 2, 0, 1, 2, 0, 2, 1, 1, 2, 0, 0, 2, 1, 1, 1, 1, 2, 0, 0, 0, 1, 0, 1, 0, 0, 2, 1, 0, 1, 0, 2, 1, 1, 1, 1, 0, 2, 2, 1, 0, 1, 2, 1, 0, 1, 0, 0, 2, 2, 2, 0, 0, 0, 0, 0, 2, 1, 2, 2, 1, 0, 2, 0, 0, 2, 2, 2, 1, 1, 2, 0, 1, 1, 0, 2, 1, 0, 1, 2, 1, 1, 2, 0, 2, 1, 0, 0, 2, 1, 1, 2, 0, 0, 2, 1, 1, 1, 1, 2, 0, 0, 0, 1, 0, 1, 0, 0, 2, 1, 0, 1, 0, 2, 1, 1, 1, 1, 0, 2, 2, 1, 0, 1, 2, 1, 0, 1, 0, 0, 2, 2, 2, 0, 0, 0, 0, 0, 2, 1, 2, 2, 1, 0, 2, 0, 0, 2, 2, 2, 1, 1, 2, 0, 1, 1, 0, 2, 1, 0, 1, 2, 1, 1, 2, 0, 2, 1, 0, 0, 1, 1, 1, 2, 2, 2, 0, 1, 0, 1, 2, 0, 2, 2, 2, 0]),
    ]

    for name, arr in inputs:
        rax, branches_hit = trace_full_path(arr, branch_set)
        print(f'  {name:12}: RAX={rax}, branches hit: {[hex(b) for b in branches_hit]}')


if __name__ == '__main__':
    main()
