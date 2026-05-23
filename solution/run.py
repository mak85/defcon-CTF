#!/usr/bin/env python3
"""End-to-end soaring-swifts solver.

Connects to soaring-swifts.ctfwithbirds.com:1337, authenticates, completes
proof-of-work, downloads each compiled checker binary, solves it with angr,
submits the answer, and prints the flag.

Usage:
  python3 run.py [--token TOKEN]

Requirements (on the machine that has outbound network):
  - Python 3 with `angr` installed
  - `curl` available on PATH (only used to fetch the PoW script)
  - `objdump` (binutils) for handler address detection (optional, falls back to
    pattern scan)
"""
import argparse
import base64
import os
import re
import socket
import ssl
import subprocess
import sys
import time
import urllib.request

HOST = "soaring-swifts.ctfwithbirds.com"
PORT = 1337
DEFAULT_TOKEN = "eyJ0eXAiOiJKV1QiLCJhbGciOiJFZERTQSJ9.eyJpc3MiOiJiYmItYXBpIiwiYXVkIjoic29hcmluZy1zd2lmdHMiLCJleHAiOjE3ODAxNjUzMjYsInN1YiI6IjMyMSIsImdlbiI6MCwiaWF0IjoxNzc5NTYwNTI2fQ.tpis4c3WV5X-J-avcqnHpWyW7gMKzVLY1J2VtWA1OfIpHhZXCq4zDEYd3ngPrBKYaBb744FygbHwDRzxIWl9Dg"

HERE = os.path.dirname(os.path.abspath(__file__))
SOLVER = os.path.join(HERE, "solve_binary.py")


def log(msg):
    print(f"[{time.strftime('%H:%M:%S')}] {msg}", file=sys.stderr, flush=True)


def recv_until(ssock, marker, timeout=180):
    ssock.settimeout(timeout)
    data = b""
    deadline = time.time() + timeout
    while marker not in data:
        if time.time() > deadline:
            raise TimeoutError(f"Did not see {marker!r}; got {data[-500:]!r}")
        chunk = ssock.recv(65536)
        if not chunk:
            raise EOFError(f"Connection closed; got {data[-500:]!r}")
        data += chunk
        sys.stderr.write(chunk.decode(errors="replace"))
        sys.stderr.flush()
    return data


def solve_pow(pow_cmd):
    """Solve PoW. pow_cmd is the command string from the server."""
    m = re.search(r"curl\s+-sSL\s+(\S+)\)\s+solve\s+(\S+)", pow_cmd)
    if not m:
        raise ValueError(f"Cannot parse PoW: {pow_cmd!r}")
    url, challenge = m.group(1), m.group(2)
    log(f"Fetching PoW script from {url}")
    with urllib.request.urlopen(url) as r:
        script = r.read()
    pow_path = "/tmp/pow_script.py"
    with open(pow_path, "wb") as f:
        f.write(script)
    log(f"Solving PoW {challenge}")
    out = subprocess.check_output(
        ["python3", pow_path, "solve", challenge], timeout=600
    )
    return out.decode().strip().splitlines()[-1]


def solve_binary(binary_path):
    log(f"angr-solving {binary_path}")
    out = subprocess.check_output([sys.executable, SOLVER, binary_path], timeout=900)
    return out.decode().strip()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--token", default=DEFAULT_TOKEN)
    ap.add_argument("--host", default=HOST)
    ap.add_argument("--port", type=int, default=PORT)
    ap.add_argument("--num-challenges", type=int, default=3)
    args = ap.parse_args()

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    log(f"Connecting to {args.host}:{args.port}")
    sock = socket.create_connection((args.host, args.port), timeout=60)
    ssock = ctx.wrap_socket(sock, server_hostname=args.host)
    log("Connected (TLS)")

    recv_until(ssock, b"Team token:")
    ssock.send(args.token.encode() + b"\n")
    log("Sent token")

    data = recv_until(ssock, b"Solution?")
    m = re.search(rb"(python3\s*<\(\s*curl[^\n]+)", data)
    if not m:
        raise RuntimeError(f"No PoW command in: {data[-500:]!r}")
    sol = solve_pow(m.group(1).decode())
    log(f"PoW solution: {sol}")
    ssock.send(sol.encode() + b"\n")

    for i in range(args.num_challenges):
        log(f"=== challenge {i+1}/{args.num_challenges} ===")
        data = recv_until(ssock, b"Enter your guess:", timeout=180)
        m = re.search(
            rb"={5,}\r?\n([A-Za-z0-9+/=\r\n]+?)\r?\n={5,}", data
        )
        if not m:
            raise RuntimeError(f"No b64 binary in: {data[-500:]!r}")
        b64 = m.group(1).decode().replace("\r", "").replace("\n", "")
        binary = base64.b64decode(b64)
        bin_path = f"/tmp/chal_{i}.bin"
        with open(bin_path, "wb") as f:
            f.write(binary)
        os.chmod(bin_path, 0o755)
        log(f"Saved {len(binary)}-byte binary -> {bin_path}")
        secret = solve_binary(bin_path)
        log(f"Submitting secret: {secret!r}")
        ssock.send(secret.encode() + b"\n")

    log("Reading flag...")
    ssock.settimeout(60)
    data = b""
    while True:
        try:
            chunk = ssock.recv(65536)
            if not chunk:
                break
            data += chunk
            sys.stderr.write(chunk.decode(errors="replace"))
            sys.stderr.flush()
            if b"bbb{" in data or b"Wrong" in data:
                break
        except socket.timeout:
            break

    flag_match = re.search(rb"bbb\{[^}]+\}", data)
    if flag_match:
        print(flag_match.group(0).decode())
    else:
        print("No flag in tail:", data[-500:].decode(errors="replace"))


if __name__ == "__main__":
    main()
