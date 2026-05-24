#!/usr/bin/env python3
"""Custom z3-based solver for branchless-compiler binaries.

Disassembles the main_loop body, then symbolically interprets it for N
iterations until [realBase] can be made equal to successLabel. Much faster
than angr for large binaries because it knows the runtime's structure
(rbp toggles between two fixed pages, all "fake" writes are no-ops we
can drop).

Usage: solve_z3.py <binary> [max_iters]
"""
import re
import subprocess
import sys
import os
import z3

REAL_BASE = 0x0beef000
FAKE_BASE = 0x4beef000
SUCCESS_LABEL = 0x0f1a5000
FAILURE_LABEL = 0x0eadf1a5

SECRET_LEN = 32


def disasm(binary_path):
    """Return list of (addr, mnemonic, operands_str) tuples."""
    out = subprocess.check_output(["objdump", "-d", "-M", "intel", "--no-show-raw-insn", binary_path]).decode()
    insns = []
    for line in out.split("\n"):
        m = re.match(r"\s*([0-9a-fA-F]+):\s+(\S+)\s*(.*)", line)
        if m:
            addr = int(m.group(1), 16)
            mnem = m.group(2).strip()
            ops = m.group(3).strip().split("#")[0].strip()
            insns.append((addr, mnem, ops))
    return insns


def find_section(insns, name):
    """Find address of label `name` and return slice of insns starting there."""
    out = subprocess.check_output(["objdump", "-t", "/tmp/dummy"], stderr=subprocess.DEVNULL)
    return None


def find_labels(binary_path):
    """Get addresses of main_loop, success_handler, failure_handler from symbol table."""
    out = subprocess.check_output(["objdump", "-d", binary_path]).decode()
    labels = {}
    for line in out.split("\n"):
        m = re.match(r"^([0-9a-fA-F]+)\s+<(\w+)>:", line)
        if m:
            labels[m.group(2)] = int(m.group(1), 16)
    return labels


def parse_operand(s):
    """Parse one operand. Returns ('reg', name) or ('mem', base, offset) or ('imm', value)."""
    s = s.strip()
    if "PTR" in s or "[" in s:
        # memory: QWORD PTR [reg + offset] or [reg - offset] or [reg]
        m = re.match(r"(?:QWORD\s+PTR\s+)?\[(\w+)(?:\s*([+-])\s*(0x[0-9a-fA-F]+|\d+))?\]", s)
        if not m:
            raise ValueError(f"bad mem operand: {s}")
        reg = m.group(1)
        if m.group(2):
            off = int(m.group(3), 0)
            if m.group(2) == "-":
                off = -off
        else:
            off = 0
        return ("mem", reg, off)
    if s.startswith("0x") or s.lstrip("-").isdigit():
        v = int(s, 0)
        # nasm/objdump signed display - normalize to 64-bit unsigned
        if v < 0:
            v = v & 0xFFFFFFFFFFFFFFFF
        return ("imm", v)
    return ("reg", s)


REG_ALIASES = {
    "eax": "rax", "ebx": "rbx", "ecx": "rcx", "edx": "rdx",
    "r8d": "r8", "r9d": "r9", "r10d": "r10", "r11d": "r11", "r12d": "r12",
    "r13d": "r13", "r14d": "r14",
    "ebp": "rbp",
    "esi": "rsi", "edi": "rdi",
}


def canon(reg):
    return REG_ALIASES.get(reg, reg)


def optimize_body(body):
    """Detect the eqCheck pattern and replace with `EQCHECK r12 r9` pseudo-op.

    The pattern (after Set R9 triv1; SetBitXor R9 triv2):
       bsr rcx, r9
       mov r11, r9
       shr r11, cl
       mov r9, r11
       mov r11, r9
       mov r14d, 0x1
       xor r11, r14
       mov r9, r11
       mov r11, r9
       mov ecx, 0x1e          ; (or movabs ecx, 30 etc.)
       shl r11, cl
       mov r9, r11
       mov r11, r9
       mov r12, r11

    Replace this 14-insn block with single ('EQCHECK_FROM_R9', r12).
    """
    out = []
    i = 0
    while i < len(body):
        # Look for "bsr rcx, r9" and check if next 13 instructions match
        a, m, o = body[i]
        if m == "bsr" and re.match(r"rcx\s*,\s*r9", o.strip()):
            # Check next 13 instructions
            expected = [
                ("mov", r"r11\s*,\s*r9"),
                ("mov", r"r11d?\s*,\s*0x1\b"),
                ("xor", r"r11\s*,\s*r14"),
                ("mov", r"r9\s*,\s*r11"),
                ("mov", r"r11\s*,\s*r9"),
                ("mov", r"e?cx\s*,\s*0x1e\b"),
                ("shl", r"r11\s*,\s*cl"),
                ("mov", r"r9\s*,\s*r11"),
                ("mov", r"r11\s*,\s*r9"),
                ("mov", r"r12\s*,\s*r11"),
            ]
            # Sequence in actual code: bsr; mov r11,r9; shr r11,cl; mov r9,r11; mov r11,r9; mov r14,1; xor r11,r14; mov r9,r11; mov r11,r9; mov rcx,30; shl r11,cl; mov r9,r11; mov r11,r9; mov r12,r11
            actual = [
                ("mov", r"r11\s*,\s*r9"),
                ("shr", r"r11\s*,\s*cl"),
                ("mov", r"r9\s*,\s*r11"),
                ("mov", r"r11\s*,\s*r9"),
                ("mov", r"r14d?\s*,\s*0x1\b"),
                ("xor", r"r11\s*,\s*r14"),
                ("mov", r"r9\s*,\s*r11"),
                ("mov", r"r11\s*,\s*r9"),
                ("mov", r"e?cx\s*,\s*0x1e\b"),
                ("shl", r"r11\s*,\s*cl"),
                ("mov", r"r9\s*,\s*r11"),
                ("mov", r"r11\s*,\s*r9"),
                ("mov", r"r12\s*,\s*r11"),
            ]
            ok = True
            if i + len(actual) >= len(body):
                ok = False
            else:
                for k, (em, eo) in enumerate(actual):
                    aa, am, ao = body[i + 1 + k]
                    if am != em or not re.match(eo, ao.strip()):
                        ok = False
                        break
            if ok:
                # Emit pseudo-op: EQCHECK_R9 -> r12 = (1<<30) if r9==0 else 0
                out.append((a, "_eqcheck_r9", ""))
                # Also need to fake the rcx/r11/r9 side effects (rcx becomes bsr position, r9 becomes 0 or 0, r11 likewise)
                i += 1 + len(actual)
                continue
        # Similar pattern for ltCheck would go here (skipping for now)
        out.append((a, m, o))
        i += 1
    return out


class Interp:
    def __init__(self, input_bytes):
        # Registers as 64-bit z3 bit vectors
        self.regs = {r: z3.BitVecVal(0, 64) for r in
                     ["rax", "rbx", "rcx", "rdx", "rsi", "rdi",
                      "rbp", "r8", "r9", "r10", "r11", "r12", "r13", "r14"]}
        # rbp starts at realBase after the prologue
        self.regs["rbp"] = z3.BitVecVal(REAL_BASE, 64)
        # r13 = input base (concrete fake address)
        self.regs["r13"] = z3.BitVecVal(0x10000, 64)
        # Memory: address -> z3 BitVec64
        self.mem = {}
        # Input bytes at offsets 0..31 from r13
        self.input_bytes = input_bytes
        for i, b in enumerate(input_bytes):
            self.mem[0x10000 + i] = b  # 1-byte; we'll pack when reading 8 bytes

    def read_input_word(self, off):
        """Read 8-byte word from input buffer at offset off."""
        # Little-endian pack of 8 bytes
        bs = [self.input_bytes[off + i] for i in range(8)]
        # b0 | (b1 << 8) | ... | (b7 << 56)
        return z3.Concat(*[b for b in reversed(bs)])

    def read_mem(self, base_reg, off):
        if base_reg == "r13":
            return self.read_input_word(off)
        if base_reg == "rbp":
            # rbp can only be REAL_BASE or FAKE_BASE. Read both and select.
            rbp_is_real = self.regs["rbp"] == z3.BitVecVal(REAL_BASE, 64)
            real_addr = REAL_BASE + off
            fake_addr = FAKE_BASE + off
            real_val = self.mem.setdefault(real_addr, z3.BitVecVal(0, 64))
            fake_val = self.mem.setdefault(fake_addr, z3.BitVecVal(0, 64))
            return z3.If(rbp_is_real, real_val, fake_val)
        try:
            base_val = z3.simplify(self.regs[base_reg]).as_long()
        except Exception:
            raise RuntimeError(f"Non-concrete base register {base_reg}")
        addr = base_val + off
        return self.mem.setdefault(addr, z3.BitVecVal(0, 64))

    def write_mem(self, base_reg, off, value):
        if base_reg == "rbp":
            rbp_is_real = self.regs["rbp"] == z3.BitVecVal(REAL_BASE, 64)
            real_addr = REAL_BASE + off
            fake_addr = FAKE_BASE + off
            cur_real = self.mem.setdefault(real_addr, z3.BitVecVal(0, 64))
            cur_fake = self.mem.setdefault(fake_addr, z3.BitVecVal(0, 64))
            self.mem[real_addr] = z3.If(rbp_is_real, value, cur_real)
            self.mem[fake_addr] = z3.If(rbp_is_real, cur_fake, value)
            return
        try:
            base_val = z3.simplify(self.regs[base_reg]).as_long()
        except Exception:
            raise RuntimeError(f"Non-concrete base register {base_reg}")
        self.mem[base_val + off] = value

    def get_val(self, op):
        if op[0] == "reg":
            r = canon(op[1])
            if r == "cl":
                return z3.Extract(7, 0, self.regs["rcx"])
            return self.regs[r]
        if op[0] == "imm":
            return z3.BitVecVal(op[1], 64)
        if op[0] == "mem":
            return self.read_mem(canon(op[1]), op[2])
        raise ValueError(op)

    def set_val(self, op, value):
        if op[0] == "reg":
            r = canon(op[1])
            if r == "cl":
                rcx = self.regs["rcx"]
                self.regs["rcx"] = z3.Concat(z3.Extract(63, 8, rcx), value if value.size() == 8 else z3.Extract(7, 0, value))
                return
            # If value is smaller than 64 bits, zero-extend
            if value.size() < 64:
                value = z3.ZeroExt(64 - value.size(), value)
            self.regs[r] = value
            return
        if op[0] == "mem":
            if value.size() != 64:
                value = z3.ZeroExt(64 - value.size(), value) if value.size() < 64 else z3.Extract(63, 0, value)
            self.write_mem(canon(op[1]), op[2], value)
            return
        raise ValueError(op)

    def execute(self, addr, mnem, ops):
        parts = [p.strip() for p in ops.split(",")] if ops else []
        opnds = [parse_operand(p) for p in parts]

        if mnem == "_eqcheck_r9":
            # r12 = (1 << 30) if r9 == 0 else 0
            r9 = self.regs["r9"]
            r12 = z3.If(r9 == z3.BitVecVal(0, 64),
                        z3.BitVecVal(1 << 30, 64),
                        z3.BitVecVal(0, 64))
            self.regs["r12"] = r12
            # r9 becomes 1 (or 0 in the equal case where bsr is undefined and shr gives 0, then xor with 1 = 1, then shl 30, then before mov r12 from r11... well it's been replaced)
            # We simulate the "final" register states roughly: r9 = (1<<30) if eq else 0 (same as r12), r11 same
            self.regs["r9"] = r12
            self.regs["r11"] = r12
            # rcx: position of highest bit if r9 was nonzero, unchanged if r9 was 0
            # We don't model this precisely; if downstream cares, that'd be a bug
            return
        if mnem in ("mov", "movabs"):
            dst, src = opnds
            v = self.get_val(src)
            self.set_val(dst, v)
        elif mnem == "add":
            dst, src = opnds
            v = self.get_val(dst) + self.get_val(src)
            self.set_val(dst, v)
        elif mnem == "sub":
            dst, src = opnds
            v = self.get_val(dst) - self.get_val(src)
            self.set_val(dst, v)
        elif mnem == "imul":
            dst, src = opnds
            v = self.get_val(dst) * self.get_val(src)
            self.set_val(dst, v)
        elif mnem == "and":
            dst, src = opnds
            v = self.get_val(dst) & self.get_val(src)
            self.set_val(dst, v)
        elif mnem in ("or",):
            dst, src = opnds
            v = self.get_val(dst) | self.get_val(src)
            self.set_val(dst, v)
        elif mnem == "xor":
            dst, src = opnds
            v = self.get_val(dst) ^ self.get_val(src)
            self.set_val(dst, v)
        elif mnem == "not":
            dst = opnds[0]
            v = ~self.get_val(dst)
            self.set_val(dst, v)
        elif mnem == "shl":
            dst, src = opnds
            sv = self.get_val(src)
            if sv.size() == 8:
                sv = z3.ZeroExt(56, sv)
            v = self.get_val(dst) << (sv & z3.BitVecVal(63, 64))
            self.set_val(dst, v)
        elif mnem == "shr":
            dst, src = opnds
            sv = self.get_val(src)
            if sv.size() == 8:
                sv = z3.ZeroExt(56, sv)
            v = z3.LShR(self.get_val(dst), sv & z3.BitVecVal(63, 64))
            self.set_val(dst, v)
        elif mnem == "bsr":
            dst, src = opnds
            sv = self.get_val(src)
            # bit-scan reverse: returns index of highest set bit. Undefined if 0.
            # Iterate low-to-high so later (higher) sets win.
            result = z3.BitVecVal(0, 64)
            for i in range(0, 64):
                bit = z3.Extract(i, i, sv)
                result = z3.If(bit == 1, z3.BitVecVal(i, 64), result)
            cur = self.get_val(dst)
            self.set_val(dst, z3.If(sv == 0, cur, result))
        elif mnem in ("popcnt", "tzcnt"):
            dst, src = opnds
            sv = self.get_val(src)
            if mnem == "popcnt":
                result = z3.BitVecVal(0, 64)
                for i in range(64):
                    bit = z3.Extract(i, i, sv)
                    result = result + z3.ZeroExt(63, bit)
            else:  # tzcnt
                result = z3.BitVecVal(64, 64)
                for i in range(63, -1, -1):
                    bit = z3.Extract(i, i, sv)
                    result = z3.If(bit == 1, z3.BitVecVal(i, 64), result)
            self.set_val(dst, result)
        elif mnem == "cmp":
            pass  # We handle this via the je/jne pattern below
        else:
            raise NotImplementedError(f"unhandled insn at {hex(addr)}: {mnem} {ops}")


def main():
    if len(sys.argv) < 2:
        print("usage: solve_z3.py <binary> [max_iters]", file=sys.stderr)
        sys.exit(2)
    binary = sys.argv[1]
    max_iters = int(sys.argv[2]) if len(sys.argv) > 2 else 200

    os.chmod(binary, 0o755)
    insns = disasm(binary)
    labels = find_labels(binary)
    print(f"[z3] labels: {labels}", file=sys.stderr)

    # The body runs from `main_loop:` until the cmp/je sequence at the end.
    # Find the main_loop start address and the cmp instruction that compares to successLabel
    ml_start = labels["main_loop"]
    # Find body end: the `mov rax, 0xbeef000; mov rax, [rax]; cmp rax, successLabel` sequence
    # Body addresses are [ml_start, body_end)
    addr_to_idx = {a: i for i, (a, _, _) in enumerate(insns)}
    body_start_idx = addr_to_idx[ml_start]
    # Walk forward looking for `mov rax, 0xbeef000` followed by `mov rax, QWORD [rax]` etc.
    body_end_idx = None
    for i in range(body_start_idx, len(insns)):
        a, m, o = insns[i]
        if m == "mov" and re.match(r"[er]ax\s*,\s*0xbeef000\b", o.strip()):
            body_end_idx = i
            break
    if body_end_idx is None:
        raise RuntimeError("Could not find main_loop end")
    body = insns[body_start_idx:body_end_idx]
    print(f"[z3] body has {len(body)} instructions", file=sys.stderr)

    # Create symbolic input bytes (8-bit each)
    input_bytes = [z3.BitVec(f"b{i}", 8) for i in range(SECRET_LEN)]
    interp = Interp(input_bytes)

    # Initialize [realBase] = 0 (mmap zero)
    interp.mem[REAL_BASE] = z3.BitVecVal(0, 64)
    interp.mem[FAKE_BASE] = z3.BitVecVal(0, 64)  # initial [realBase + 0] = 0

    import time
    solver = z3.Solver()
    solver.set("timeout", 60000)  # 60s per check
    for b in input_bytes:
        solver.add(b >= ord("a"), b <= ord("z"))

    # Build optimized body: detect the eqCheck pattern and replace with single op
    body = optimize_body(body)
    print(f"[z3] optimized body: {len(body)} insns", file=sys.stderr)

    for it in range(max_iters):
        t0 = time.time()
        for (a, m, o) in body:
            try:
                interp.execute(a, m, o)
            except NotImplementedError as e:
                print(f"[z3] {e}", file=sys.stderr)
                sys.exit(3)
        rb_val = interp.mem.get(REAL_BASE, z3.BitVecVal(0, 64))
        rb_val = z3.simplify(rb_val)
        # Also simplify rbp and memory entries to prevent expression blowup
        interp.regs["rbp"] = z3.simplify(interp.regs["rbp"])
        for k in list(interp.mem.keys()):
            interp.mem[k] = z3.simplify(interp.mem[k])
        t_exec = time.time() - t0
        t0 = time.time()
        solver.push()
        solver.add(rb_val == z3.BitVecVal(SUCCESS_LABEL, 64))
        chk = solver.check()
        t_check = time.time() - t0
        print(f"[z3] iter {it+1}: exec={t_exec:.1f}s check={t_check:.1f}s result={chk}", file=sys.stderr)
        if chk == z3.sat:
            model = solver.model()
            secret = bytes(model[b].as_long() for b in input_bytes).decode()
            print(f"[z3] solved at iter {it+1}: {secret!r}", file=sys.stderr)
            print(secret)
            return
        solver.pop()

    print("[z3] no solution within iteration limit", file=sys.stderr)
    sys.exit(1)


if __name__ == "__main__":
    main()
