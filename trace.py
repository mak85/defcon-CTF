#!/usr/bin/env python3
"""
Trace the validator function with concrete input using Unicorn.

We hook the PLT calls (memset/memcpy/memmove) to emulate them in Python
so we can run the full function.
"""

from unicorn import *
from unicorn.x86_const import *
import struct

BINARY = './myfavoriteinstructions'

GHIDRA_BASE = 0x100000
OFF_VALIDATOR_START = 0x1011a0 - GHIDRA_BASE
OFF_VALIDATOR_RET   = 0x14d985 - GHIDRA_BASE

CODE_BASE  = 0x400000
ARRAY_ADDR = 0x60000000
STACK_BASE = 0x70000000
STACK_TOP  = 0x70200000
FAKE_RET   = 0xdeadbeefcafef00d


# PLT addresses (file offsets, added to CODE_BASE at load):
PLT_MEMSET  = 0x1050
PLT_MEMCPY  = 0x1060
PLT_MEMMOVE = 0x1090


def hook_plt(mu, addr, size, user_data):
    """Hook the PLT calls to emulate memset/memcpy/memmove in Python."""
    if addr == CODE_BASE + PLT_MEMSET:
        # void* memset(void* s, int c, size_t n) — RDI, RSI, RDX
        dest = mu.reg_read(UC_X86_REG_RDI)
        c    = mu.reg_read(UC_X86_REG_RSI) & 0xff
        n    = mu.reg_read(UC_X86_REG_RDX)
        try:
            mu.mem_write(dest, bytes([c]) * n)
        except UcError as e:
            print(f'    memset({hex(dest)},{c},{n}) failed: {e}')
        # Fake return — pop ret addr and jump
        rsp = mu.reg_read(UC_X86_REG_RSP)
        ret_addr = struct.unpack('<Q', mu.mem_read(rsp, 8))[0]
        mu.reg_write(UC_X86_REG_RSP, rsp + 8)
        mu.reg_write(UC_X86_REG_RIP, ret_addr)
        mu.reg_write(UC_X86_REG_RAX, dest)
    elif addr == CODE_BASE + PLT_MEMCPY or addr == CODE_BASE + PLT_MEMMOVE:
        # memcpy/memmove(void* dest, const void* src, size_t n)
        dest = mu.reg_read(UC_X86_REG_RDI)
        src  = mu.reg_read(UC_X86_REG_RSI)
        n    = mu.reg_read(UC_X86_REG_RDX)
        try:
            data = mu.mem_read(src, n)
            mu.mem_write(dest, bytes(data))
        except UcError as e:
            print(f'    memcpy/memmove({hex(dest)},{hex(src)},{n}) failed: {e}')
        rsp = mu.reg_read(UC_X86_REG_RSP)
        ret_addr = struct.unpack('<Q', mu.mem_read(rsp, 8))[0]
        mu.reg_write(UC_X86_REG_RSP, rsp + 8)
        mu.reg_write(UC_X86_REG_RIP, ret_addr)
        mu.reg_write(UC_X86_REG_RAX, dest)


def load_text():
    with open(BINARY, 'rb') as f:
        return f.read()


def run_validator(ternary_array, verbose=False):
    mu = Uc(UC_ARCH_X86, UC_MODE_64)

    # Map a large region for binary
    mu.mem_map(CODE_BASE, 0x100000)
    data = load_text()
    mu.mem_write(CODE_BASE, data[:0x100000])

    # Map array region
    mu.mem_map(ARRAY_ADDR, 0x10000)
    for i, v in enumerate(ternary_array):
        mu.mem_write(ARRAY_ADDR + i*8, struct.pack('<Q', v))

    # Map stack
    mu.mem_map(STACK_BASE, STACK_TOP - STACK_BASE)
    mu.mem_write(STACK_TOP - 8, struct.pack('<Q', FAKE_RET))

    # Set registers
    mu.reg_write(UC_X86_REG_RSP, STACK_TOP - 8)
    mu.reg_write(UC_X86_REG_R12, ARRAY_ADDR)

    # Hook PLT calls
    for plt_addr in (PLT_MEMSET, PLT_MEMCPY, PLT_MEMMOVE):
        mu.hook_add(UC_HOOK_CODE, hook_plt,
                    begin=CODE_BASE + plt_addr,
                    end=CODE_BASE + plt_addr + 1)

    try:
        start = CODE_BASE + OFF_VALIDATOR_START
        end   = CODE_BASE + OFF_VALIDATOR_RET + 1
        mu.emu_start(start, end, timeout=10_000_000, count=0)  # 10s
    except UcError as e:
        if verbose:
            pc = mu.reg_read(UC_X86_REG_RIP)
            print(f'    [unicorn error at pc={hex(pc)}: {e}]')

    rax = mu.reg_read(UC_X86_REG_RAX) & 0xffffffff
    final_pc = mu.reg_read(UC_X86_REG_RIP)
    return rax, final_pc


def main():
    tests = [
        ('all zeros',           [0] * 200),
        ('all ones',            [1] * 200),
        ('all twos',            [2] * 200),
        ('alt 0/1',             [(i & 1) for i in range(200)]),
        ('alt 0/2',             [(2 if i & 1 else 0) for i in range(200)]),
        ('seq 0/1/2',           [(i % 3) for i in range(200)]),
        ('first=1, rest 0',     [1] + [0]*199),
        ('first=2, rest 0',     [2] + [0]*199),
        ('first 3 = 1',         [1,1,1] + [0]*197),
        ('first 5 = 1',         [1]*5 + [0]*195),
        ('first 10 = 1',        [1]*10 + [0]*190),
    ]
    for name, arr in tests:
        rax, pc = run_validator(arr)
        status = 'WIN' if rax == 2 else ''
        print(f'  {name:25}: RAX = {rax} (0x{rax:x}) pc=0x{pc:x} {status}')


if __name__ == '__main__':
    main()
