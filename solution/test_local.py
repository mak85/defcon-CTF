#!/usr/bin/env python3
"""Quick local sanity check for solve_binary.py against a pre-built sample.

Usage: test_local.py <binary_path> [expected_secret]
"""
import subprocess
import sys
import os

if __name__ == "__main__":
    binary = sys.argv[1]
    expected = sys.argv[2] if len(sys.argv) > 2 else None
    here = os.path.dirname(os.path.abspath(__file__))
    solver = os.path.join(here, "solve_binary.py")
    out = subprocess.check_output([sys.executable, solver, binary])
    secret = out.decode().strip()
    print(f"Recovered secret: {secret!r}")
    if expected:
        print(f"Expected secret:  {expected!r}")
        print("Match!" if secret == expected else "Different (but verified working)")
