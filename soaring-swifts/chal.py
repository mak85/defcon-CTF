#!/usr/bin/env python3

import base64
import os
import random
import string
import subprocess
import sys
import tempfile

COMPILER_BINARY = "./compiler"
FLAG = os.environ.get("FLAG", "bbb{you_should_set_FLAG_env}")
SECRET_LENGTH = 32
MAX_RETRIES = 10
NUM_CHALLENGES = int(os.environ.get("NUM_CHALLENGES", "3"))

def generate_secret(length=SECRET_LENGTH):
    charset = string.ascii_lowercase
    return "".join(random.choice(charset) for _ in range(length))

def generate_seed():
    return random.randint(0, 2**31 - 1)

def run_haskell_compiler(secret, seed, work_dir):
    asm_path = os.path.join(work_dir, "checker.asm")

    try:
        proc = subprocess.run(
            [COMPILER_BINARY],
            input=f"{secret}\n{seed}\n",
            capture_output=True,
            text=True,
            timeout=30,
        )
    except (subprocess.TimeoutExpired, OSError):
        return None

    if proc.returncode != 0:
        return None

    with open(asm_path, "w") as f:
        f.write(proc.stdout)

    return asm_path

def assemble_and_link(asm_path, work_dir):
    obj_path = os.path.join(work_dir, "checker.o")
    bin_path = os.path.join(work_dir, "checker")

    try:
        proc = subprocess.run(
            ["nasm", "-f", "elf64", "-o", obj_path, asm_path],
            capture_output=True,
            text=True,
            timeout=30,
        )
        if proc.returncode != 0:
            return None

        proc = subprocess.run(
            ["ld", "-o", bin_path, obj_path],
            capture_output=True,
            text=True,
            timeout=30,
        )
        if proc.returncode != 0:
            return None
    except (subprocess.TimeoutExpired, OSError):
        return None

    os.chmod(bin_path, 0o755)
    return bin_path

def run_checker(bin_path, input_str):
    proc = subprocess.run(
        [bin_path],
        input=input_str.encode("ascii"),
        capture_output=True,
        timeout=10,
    )
    return proc.returncode

def binary_to_base64(bin_path):
    with open(bin_path, "rb") as f:
        return base64.b64encode(f.read()).decode("ascii")

def build_challenge(work_dir):
    for attempt in range(MAX_RETRIES):
        secret = generate_secret()
        seed = generate_seed()

        asm_path = run_haskell_compiler(secret, seed, work_dir)
        if asm_path is None:
            continue

        bin_path = assemble_and_link(asm_path, work_dir)
        if bin_path is None:
            continue

        if run_checker(bin_path, secret) != 0:
            continue

        wrong = "A" * SECRET_LENGTH
        if wrong == secret:
            wrong = "B" * SECRET_LENGTH
        if run_checker(bin_path, wrong) == 0:
            continue

        return secret, bin_path

    sys.exit(1)

def main():
    random.seed()

    with tempfile.TemporaryDirectory(prefix="chall_") as work_dir:
        for i in range(NUM_CHALLENGES):
            secret, bin_path = build_challenge(work_dir)

            b64 = binary_to_base64(bin_path)
            print(f"Challenge {i+1}/{NUM_CHALLENGES}")
            print("=" * 60)
            print(b64)
            print("=" * 60)

            try:
                guess = input("Enter your guess: ")
            except (EOFError, KeyboardInterrupt):
                print("\nBye!")
                sys.exit(0)

            exit_code = run_checker(bin_path, guess)
            if exit_code != 0:
                print("Wrong :(")
                sys.exit(1)

            print("Correct!")

        print(f"Here is your flag: {FLAG}")

if __name__ == "__main__":
    main()
