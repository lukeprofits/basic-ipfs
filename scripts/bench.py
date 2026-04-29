#!/usr/bin/env python3
"""
Micro-benchmark for basic_ipfs. Adds N small files and measures throughput.

Run:    python scripts/bench.py [--n 1000] [--size 10240]

Use the recorded number to spot regressions across releases.
"""

from __future__ import annotations

import argparse
import os
import time

import basic_ipfs


def main() -> int:
    p = argparse.ArgumentParser(description="basic_ipfs add() throughput benchmark")
    p.add_argument("--n", type=int, default=1000, help="number of files (default: 1000)")
    p.add_argument("--size", type=int, default=10240, help="bytes per file (default: 10240)")
    args = p.parse_args()

    print(f"Starting daemon (basic_ipfs {basic_ipfs.__version__})…")
    basic_ipfs.start()

    print(f"Adding {args.n} × {args.size}-byte payloads…")
    cids = []
    t0 = time.monotonic()
    for i in range(args.n):
        payload = os.urandom(args.size)
        cids.append(basic_ipfs.add(payload))
    elapsed_add = time.monotonic() - t0

    print(f"Reading them back…")
    t0 = time.monotonic()
    for cid in cids:
        basic_ipfs.get(cid)
    elapsed_get = time.monotonic() - t0

    print()
    print(f"add():  {args.n} ops in {elapsed_add:.2f}s  ({args.n / elapsed_add:.0f} ops/s, "
          f"{args.n * args.size / elapsed_add / 1024 / 1024:.1f} MB/s)")
    print(f"get():  {args.n} ops in {elapsed_get:.2f}s  ({args.n / elapsed_get:.0f} ops/s, "
          f"{args.n * args.size / elapsed_get / 1024 / 1024:.1f} MB/s)")

    print("Cleaning up pins…")
    basic_ipfs.unpin(cids)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
