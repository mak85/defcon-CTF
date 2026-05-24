#!/usr/bin/env python3
"""
Hybrid concolic emulator for FUN_001011a0.

We run unicorn concretely on the validator, then replay the executed
instructions as a Z3 formula. Since the branches in the validator are
all loop counters that don't depend on input, the executed trace for
any input is the same — we just need to symbolize one trace.
"""

import struct
import sys
import time
import json
from unicorn import *
from unicorn.x86_const import *
from capstone import *
import z3

BINARY = './myfavoriteinstructions'
GHIDRA_BASE = 0x100000
OFF_VAL_START = 0x1011a0 - GHIDRA_BASE
OFF_VAL_RET   = 0x14d985 - GHIDRA_BASE

CODE_BASE  = 0x400000
ARRAY_ADDR = 0x60000000
STACK_BASE = 0x70000000
STACK_TOP  = 0x70200000
FAKE_RET   = 0xdeadbeefcafef00d

PLT_MEMSET  = 0x1050
PLT_MEMCPY  = 0x1060
PLT_MEMMOVE = 0x1090

INPUT_SIZE = 200


# Step 1: Run unicorn concretely and record the trace of executed instruction
#         addresses in order. Also record concrete operand values for memory ops.
def hook_plt(mu, addr, size, ud):
    """Emulate memset/memcpy/memmove."""
    if addr == CODE_BASE + PLT_MEMSET:
        dest = mu.reg_read(UC_X86_REG_RDI)
        c    = mu.reg_read(UC_X86_REG_RSI) & 0xff
        n    = mu.reg_read(UC_X86_REG_RDX)
        try:
            mu.mem_write(dest, bytes([c]) * n)
        except UcError:
            pass
        ud['plt_calls'].append(('memset', dest, c, n))
    elif addr == CODE_BASE + PLT_MEMCPY or addr == CODE_BASE + PLT_MEMMOVE:
        dest = mu.reg_read(UC_X86_REG_RDI)
        src  = mu.reg_read(UC_X86_REG_RSI)
        n    = mu.reg_read(UC_X86_REG_RDX)
        try:
            data = mu.mem_read(src, n)
            mu.mem_write(dest, bytes(data))
        except UcError:
            pass
        ud['plt_calls'].append(('memcpy' if addr == CODE_BASE + PLT_MEMCPY else 'memmove',
                                dest, src, n))
    rsp = mu.reg_read(UC_X86_REG_RSP)
    ret_addr = struct.unpack('<Q', mu.mem_read(rsp, 8))[0]
    mu.reg_write(UC_X86_REG_RSP, rsp + 8)
    mu.reg_write(UC_X86_REG_RIP, ret_addr)


def trace_concrete(input_array):
    """Run validator with concrete input, recording executed PCs in order."""
    mu = Uc(UC_ARCH_X86, UC_MODE_64)
    mu.mem_map(CODE_BASE, 0x100000)
    with open(BINARY, 'rb') as f:
        mu.mem_write(CODE_BASE, f.read()[:0x100000])
    mu.mem_map(ARRAY_ADDR, 0x10000)
    for i, v in enumerate(input_array):
        mu.mem_write(ARRAY_ADDR + i*8, struct.pack('<Q', v))
    mu.mem_map(STACK_BASE, STACK_TOP - STACK_BASE)
    mu.mem_write(STACK_TOP - 8, struct.pack('<Q', FAKE_RET))
    mu.reg_write(UC_X86_REG_RSP, STACK_TOP - 8)
    mu.reg_write(UC_X86_REG_R12, ARRAY_ADDR)

    ud = {'pcs': [], 'plt_calls': []}

    def code_hook(mu, addr, size, ud_):
        # Only record PCs inside the validator
        if CODE_BASE + OFF_VAL_START <= addr <= CODE_BASE + OFF_VAL_RET:
            ud_['pcs'].append(addr - CODE_BASE)

    mu.hook_add(UC_HOOK_CODE, code_hook, user_data=ud)
    for plt_addr in (PLT_MEMSET, PLT_MEMCPY, PLT_MEMMOVE):
        mu.hook_add(UC_HOOK_CODE, hook_plt,
                    begin=CODE_BASE + plt_addr,
                    end=CODE_BASE + plt_addr + 1,
                    user_data=ud)

    try:
        mu.emu_start(CODE_BASE + OFF_VAL_START,
                     CODE_BASE + OFF_VAL_RET + 1,
                     timeout=30_000_000, count=0)
    except UcError as e:
        print(f'    [unicorn error: {e}]')

    rax = mu.reg_read(UC_X86_REG_RAX) & 0xffffffff
    return rax, ud


def main():
    print('[+] Tracing validator with concrete input (all zeros)...')
    t0 = time.time()
    rax, ud = trace_concrete([0] * INPUT_SIZE)
    print(f'    {time.time()-t0:.1f}s')
    print(f'    RAX={rax}')
    print(f'    instructions executed: {len(ud["pcs"])}')
    print(f'    PLT calls: {len(ud["plt_calls"])}')
    for c in ud['plt_calls'][:5]:
        print(f'      {c}')

    # Save the trace
    with open('trace.json', 'w') as f:
        json.dump({
            'pcs': ud['pcs'],
            'plt_calls': ud['plt_calls'],
            'rax': rax,
        }, f)
    print(f'[+] Trace saved to trace.json')

    # Test that another input takes the same path
    print('[+] Verifying path is input-independent with all-1s...')
    t0 = time.time()
    rax2, ud2 = trace_concrete([1] * INPUT_SIZE)
    print(f'    {time.time()-t0:.1f}s')
    print(f'    RAX={rax2}, same path? {ud["pcs"] == ud2["pcs"]}')


if __name__ == '__main__':
    main()
