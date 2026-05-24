# myfavoriteinstructions — Reverse Engineering Report

A reverse-engineering walkthrough of the `myfavoriteinstructions` challenge
from **DEF CON 34 CTF Quals (May 22–24, 2026)**, organized by the
Benevolent Bureau of Birds.

This report documents the approach, key technical findings, why standard
symbolic-execution tools fail against this binary, and what we learned —
even though the challenge was not solved within the available time.

---

## 1. Challenge Overview

| Property | Value |
|----------|-------|
| Binary | `myfavoriteinstructions` |
| Architecture | x86-64 |
| Format | ELF 64-bit LSB PIE, dynamically linked, stripped |
| Size | 436 056 bytes (~426 KB) |
| Theme | Bit-manipulation instructions (BMI2: `BSR`, `BZHI`) |
| Input | Single command-line argument, 68 ASCII characters minimum |
| Output | `Correct!` (win) or `Nope` (lose) |
| Win signal | Validator function `FUN_001011a0` must return `2` |

### Observable behavior

```
$ ./myfavoriteinstructions
Usage: ./myfavoriteinstructions <flag>

$ ./myfavoriteinstructions hello
Flag too short (got 5, need >= 68)

$ ./myfavoriteinstructions $(python3 -c "print('A'*68)")
Nope
```

---

## 2. Static Analysis (Ghidra)

### 2.1 Finding `main`

Standard ELF reverse-engineering workflow:

1. Locate the program entry point (`entry` at `0x001010b0` in Ghidra's
   default PIE base of `0x100000`).
2. Disassemble the entry function — it has the canonical
   `_start` prologue (`ENDBR64`, `XOR EBP,EBP`, `MOV R9,RDX`, `POP RSI`,
   `MOV RDX,RSP`, `AND RSP,-0x10`, …).
3. The address of `main` is loaded into `RDI` immediately before the
   call to `__libc_start_main`. In this binary that's
   `LEA RDI, [LAB_0014d990]`, so `main` lives at offset `0x14d990`.

### 2.2 The `main` function

`main(int argc, char **argv)` has a very clean shape:

```c
if (argc == 1)          goto usage1;
if (argc != 2)          goto usage2;
len = strlen(argv[1]);
if (len <= 67)          goto too_short;        // CMP EAX, 0x43; JLE …
//  ───────── input is converted to a ternary digit array ─────────
//  Loop body at 0x4dcb0 — 175 iterations, step rbx by 2 ─────────
//   • Treats argv[1] as a 128-bit number in (rdi:rsi).
//   • Each iteration computes "value mod 3" twice (using the magic
//     multiplier R14 = 0xAAAAAAAAAAAAAAAB for division-by-3),
//     storing two ternary digits at [rsp + rbx*8 - 8] and [rsp + rbx*8].
//   • Then calls __udivti3 to divide the 128-bit value by 9,
//     advancing to the next pair of digits.
//
//  Net effect: ~350 ternary digits laid out at [rsp + 0 ..]
//  R12 is then set to point at this array.
//  ──────────────────────────────────────────────────────────────
if (FUN_001011a0() == 2) puts("Correct!");
else                     puts("Nope");
```

### 2.3 The win path — CMOVZ idiom

The success/failure decision is **branchless**:

```asm
CALL   FUN_001011a0          ; validator
CMP    EAX, 0x2              ; win if EAX == 2
LEA    RAX, [s_Correct!]     ; preload "Correct!" pointer
LEA    param_1, [LAB_Nope]   ; preload "Nope" pointer
CMOVZ  param_1, RAX          ; if ZF=1 (EAX==2), param_1 = "Correct!"
CALL   puts                  ; print the chosen string
XOR    EAX, EAX
```

**Pattern to remember:** two `LEA`s followed by `CMOV<cond>` and `CALL`
is a classic compiler idiom for `puts(cond ? str_a : str_b);`. Spotting
it immediately tells you which value the validator must return.

---

## 3. The Validator — `FUN_001011a0`

This is where the challenge lives.

### 3.1 Scale

| Metric | Value |
|--------|-------|
| Function size (static) | 313 317 bytes (~306 KB) |
| Static instructions | 66 590 |
| Conditional branches | **16 total** |
| Loop-related branches | 16 (all are loop counters, not data-dependent) |
| Calls (all PLT) | 11 — to `memset`, `memcpy`, `memmove` only |
| Stack frame | `SUB RSP, 0x24c0` — 9 408 bytes |
| **Dynamic instructions per call** | **~39 000 000** |
| **PLT calls per execution** | **10 703** |

### 3.2 Instruction frequency

```
27 987   bsr        (Bit Scan Reverse — BMI1)
21 316   mov
16 208   bzhi       (Bit Zero High — BMI2)
   859   xor
    51   movaps
    38   lea
    29   movups
    16   add
    14   cmp
    11   imul
    11   call       (only memset/memcpy/memmove)
     8   nop
     8   jne
```

Over **44 000** BMI2/BMI1 instructions in one function. This is the
"my favorite instructions" joke in the binary name.

### 3.3 What it reads from the input

The validator reads **163 distinct u64 positions** from the R12 array,
at offsets `0x0` through `0x5b0`, skipping ~20 indices. Higher positions
of the array (beyond ~183) are never touched.

### 3.4 The return value computation

The function ends with:

```asm
4d967  BSR    RDI, R8
4d96b  MOV    EDX, 0x2
4d970  BSR    RDX, RCX
4d974  BSR    RAX, RDI
4d978  BZHI   RAX, RAX, RDX        ; RAX = bsr(bsr(R8)) & ((1 << bsr(RCX)) - 1)
4d97d  ADD    RSP, 0x24c0
4d984  POP    RBP
4d985  RET
```

Symbolically: `RAX = bzhi(bsr(bsr(R8_final)), bsr(RCX_final))`. We need
this to evaluate to **2**.

---

## 4. Concrete-Execution Tooling

Before attempting any solver, build a fast, reliable oracle that says
"yes / no" for any candidate input. We did this with **Unicorn**:

| Tool | Purpose |
|------|---------|
| `trace.py` | Unicorn-based emulator of `FUN_001011a0` with PLT hooks emulating `memset` / `memcpy` / `memmove` in Python. Returns `RAX` (the validator's verdict) in ~0.5 s. |
| `gdbscript.py` | Runs the real binary under GDB, breaks at the validator entry, dumps the R12 array (ground truth). Used to validate the Unicorn oracle. |
| `trace_branches.py` | Logs which of the 16 conditional branches fire (and how many times) for a given input. Confirmed that the control flow is **input-independent** — every test input takes the same code path. |

### Why this matters

A fast concrete oracle lets you:

* Verify your understanding of the function (does my model agree with reality?)
* Run differential / mutation tests (does flipping one input bit change the output?)
* Validate any putative solver result before posting it to the scoreboard.

---

## 5. Solver Attempts

### 5.1 angr (4 attempts)

**Attempt 1 — full program, symbolic argv[1]:**
- `auto_load_libs=False`, 68 printable-ASCII symbolic bytes, `find=`
  the post-validator CMP, `avoid=` the three error branches.
- Result: Z3 backend hit Python recursion-depth limit while abstracting
  the constraint AST. The encoding loop in `main` (175 iterations of
  128-bit multiply / `__udivti3`) creates an AST that grows
  multiplicatively per iteration.

**Attempt 2 — `call_state` directly into the validator:**
- Skip `main`'s encoding loop. Allocate a 200-entry symbolic ternary
  array at `0x60000000`, set `R12` to point there, constrain each entry
  to `{0,1,2}`.
- Result: returned immediately. Investigation showed `call_state`
  doesn't establish a working stack frame; the function didn't actually
  execute.

**Attempt 3 — `blank_state` with explicit stack mapping:**
- Map a real stack region at `0x70000000 – 0x70200000`, set RSP near
  the top, push a sentinel return address.
- Result: 1 errored state with `Ijk_SigSEGV` after 38 steps. The
  validator accesses its own stack frame (`mov rbp, [rsp+0x340]`) and
  angr's default page-access protection rejected it.

**Attempt 4 — same setup with `STRICT_PAGE_ACCESS` removed and
veritesting enabled:**
- Veritesting merges parallel paths to combat path explosion.
- Result: 3 steps in 12 seconds (PC `0x1649`, only ~1 KB into the
  function). Linear extrapolation: **~3 000 seconds (50 min) per call**.
- Each "step" added thousands of BMI2 ops to the symbolic AST, and the
  per-step time grew superlinearly as the AST got more complex.

### 5.2 Hand-rolled hybrid Z3 emulator

**Plan:** trace one concrete execution with Unicorn (recording every
PC), then replay the trace using Z3 BitVecs for the input array,
building a single symbolic formula for the entire function.

**Why this would have been better than angr:**
- Branches are input-independent → no path explosion.
- Only one path to symbolize → no branch fan-out.

**Why it still doesn't work:**
- A single concrete run executes **39 million** instructions.
- Each BMI2 op is a Z3 BitVec operation. Even after aggressive
  simplification, the resulting formula would have **hundreds of
  millions of nodes**.
- Z3 cannot solve formulas of that size in any reasonable time.
- Even *building* the formula in Python would take many hours per pass.

### 5.3 Single-position differential test

We tried 366 single-position flips (each of 183 input positions × values
{1, 2}) from an all-zeros baseline, looking for any change in `RAX`.
**None changed `RAX`.** There is no exploitable gradient — the
validator only flips its verdict when many positions are correct
simultaneously.

### 5.4 .rodata lookup tables

The `.rodata` section contains **14 016 sequential u64 values, all in
{0, 1, 2}** — a giant ternary table. The validator references 6 RIP-
relative offsets into this table during its inner loops
(e.g. `LEA RCX, [RIP+0x36388]` → `0x4e050`, then
`MOV R10, [RCX + RAX*8 - 0x298]`).

Feeding the first 200 entries of the table directly as input to the
validator returns `RAX=0`. The table is consumed by the validator's
internal computation; the expected ternary input is **not** stored
directly anywhere in the binary.

---

## 6. Why This Challenge Resists Standard Tools

| Resistance mechanism | Effect on solver |
|----------------------|------------------|
| ~70 K static instructions, ~39 M dynamic | Symbolic AST grows unbounded; Z3 cannot solve. |
| 16 branches, all loop counters | Eliminates the only "free win" symex offers (branch-by-branch path constraints). |
| Heavy BSR/BZHI chains | Each op compounds non-linearly; simplifiers struggle. |
| BSR-on-zero undefined-behavior reliance | Different emulators (angr, real CPU) may disagree on semantics. |
| Branchless `CMOVZ` win check | Can't simply patch a `JZ` to win — the "Correct!"/"Nope" strings are unconditionally prepared. |
| No "flag in binary" leak | The flag is the input; nothing else in the binary reveals it. |
| 6 different `.rodata` lookup tables | The expected input isn't stored anywhere — it's encoded in the relationship between tables. |

---

## 7. RE Lessons Learned

These transfer to any future RE challenge:

### 7.1 Workflow

1. **Strings first.** Two minutes with `Search → For Strings` would have
   told us "Flag too short (got %d, need >= 68)" — instant input-length
   information.
2. **Cross-references second.** Every interesting string has XREFs.
   Backtracking from "Correct!" landed us directly at the validator
   call site.
3. **Decompile what you can; read assembly where you must.** Ghidra's
   decompiler refused to lift this function, but the assembly remained
   readable — the prologue, the BMI2 patterns, and the final
   `BZHI/BSR/RET` were all decipherable by hand.

### 7.2 Compiler idioms

- **`LEA reg, [s_X] / LEA reg, [s_Y] / CMOV<cond> / CALL puts`** =
  `puts(cond ? "X" : "Y")`. The branchless form is the giveaway that
  the verdict is computed *before* the print.
- **`MUL rN / SHR rdx, k / LEA rax, [rdx + rdx*2] / SUB`** =
  multiply-by-magic division by a small constant followed by `mod`
  recovery. Here it was division-by-3 / `mod 3`.
- **`__udivti3`** in a loop = 128-bit unsigned division. Strongly
  implies multi-precision arithmetic / arbitrary-precision number work.
- **`f3 0f 1e fa`** = `ENDBR64`. Intel CET endbranch — appears at every
  function entry on modern compilers.

### 7.3 When to give up on symex

If you can answer "yes" to any of these, *don't waste time on
angr/KLEE/S2E*:

- The function executes more than ~100 K dynamic instructions per call.
- There are >20 chained BSR/BZHI/PEXT/PDEP ops on symbolic data.
- A simple concrete trace shows the same instruction count regardless
  of input (= author has unrolled the verification *intentionally* to
  defeat symex).

Pivot to **manual structure recognition** or **giving up on the
challenge** at that point — both are valid CTF strategies.

### 7.4 Tooling patterns

- **Always build a Unicorn-based concrete oracle for crackmes.** It
  takes 30 minutes and gives you ground truth for the rest of the
  session.
- **Hook the PLT** to emulate `memset` / `memcpy` / `memmove` cheaply
  in Python. The pattern in `trace.py` is reusable across binaries.
- **Use GDB scripting** (`gdb -x script.py`) to capture register / memory
  snapshots at specific breakpoints. Validates your offline analysis.

---

## 8. Repository Contents

All on branch `claude/stoic-bardeen-6Cw3l`:

| File | Purpose |
|------|---------|
| `myfavoriteinstructions` | The challenge binary |
| `trace.py` | Unicorn-based concrete validator oracle |
| `trace_branches.py` | Instruments which conditional branches fire |
| `gdbscript.py` | GDB script for ground-truth R12 capture |
| `symemu.py` | Concrete tracer; demonstrates the 39 M dynamic insn count |
| `solve.py` | Four iterations of angr attempts |
| `expected_array.json` | The 14 016 ternary lookup values from `.rodata` |
| `REPORT.md` | This document |

---

## 9. Outcome

The challenge was **not solved** within the working session. This is an
honest result: the validator's design (39 M instructions, BMI2-heavy,
no gradient, no flag leak in the binary) was specifically engineered to
defeat off-the-shelf reverse-engineering. The intended solution likely
requires either:

- A custom symbolic engine with specialized BMI2 semantic models, or
- Deep manual reverse-engineering by someone fluent in obfuscated
  multi-precision arithmetic, or
- 8–24+ hours of focused, expert effort.

When the BBB release the source after DEF CON 34 concludes, the
intended approach can be studied directly and added to this report.

---

## 10. Acknowledgements

Challenge by **Benevolent Bureau of Birds (BBB)** — DEF CON 34 CTF
Quals, May 22–24, 2026.
