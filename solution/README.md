# Soaring Swifts - End-to-End Solver

## How it works

The challenge generates a small x86-64 binary that uses a "branchless"
control-flow trick: two memory pages (`realBase=0xbeef000` and
`fakeBase=0x4beef000`, differing only in bit 30) are mmap'd, and every
write either lands in the active region or the inert one depending on
whether the comparison register holds `1 << 30`. Effectively, every basic
block runs every iteration of `main_loop`; only the values written to
`[realBase]` matter, and the main loop's epilogue exits with code 0 or 1
based on a sentinel value written there.

The trick means the produced binary is straight-line code per iteration -
no real branches, so `angr` can symbolically execute through it cleanly.
We:

1. Mark stdin as 32 symbolic bytes constrained to `[a-z]`.
2. Ask angr to find a path to `success_handler`, avoiding `failure_handler`.
3. Concretize and emit the secret.

## Files

- `solve_binary.py` - takes one path to a compiled binary, prints the
  recovered 32-char secret on stdout.
- `run.py` - end-to-end driver: connects to the CTF server, sends the
  token, solves the argon2id proof-of-work, downloads each of the 3
  challenge binaries, runs the solver, submits the answer, prints the
  flag.

## Running

On a machine with outbound TCP to the CTF server and to
`pow.ctfwithbirds.com` (a Kali container with the usual networking is
fine), in a virtualenv with `angr` installed:

```bash
# one-time setup
python3 -m venv venv
source venv/bin/activate
pip install angr

# run the full pipeline
python3 run.py
```

The driver streams the server's prompts to stderr so you can watch
progress, and prints just the flag on stdout when it finishes.

### Manual mode

If something goes wrong in the automation, you can drive the protocol by
hand:

```bash
# 1. Connect
ncat --ssl soaring-swifts.ctfwithbirds.com 1337

# 2. Paste the token at the "Team token:" prompt.
# 3. Run the PoW command the server prints, paste its output at "Solution?".
# 4. For each of the 3 challenges, copy the base64 between the ====== lines
#    into a file (e.g. chal.b64), then:
base64 -d chal.b64 > chal.bin && chmod +x chal.bin
python3 solve_binary.py chal.bin
# 5. Paste the printed secret back at "Enter your guess:".
```

## Performance

On the samples we tested (32-byte secret, hash + per-word checks, ~600
lines of generated asm) angr takes 1-3 minutes per binary. The
`SOLVER_TIMEOUT` env var (default 600s) caps how long it'll explore
before giving up.
