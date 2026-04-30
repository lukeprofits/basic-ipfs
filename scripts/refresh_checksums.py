#!/usr/bin/env python3
"""
Refresh basic_ipfs/kubo_checksums.py for a Kubo version.

Fetches the .sha512 file for every supported platform from dist.ipfs.tech
and updates the table in kubo_checksums.py.

Usage:
    python scripts/refresh_checksums.py v0.41.0

Run this before bumping basic_ipfs.KUBO_VERSION. Verify the resulting diff
is what you expect, then commit.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

import requests

DIST = "https://dist.ipfs.tech/kubo"
GITHUB = "https://github.com/ipfs/kubo/releases/download"
PLATFORMS = [
    ("linux-amd64",   "tar.gz"),
    ("linux-arm64",   "tar.gz"),
    ("linux-riscv64", "tar.gz"),
    ("darwin-amd64",  "tar.gz"),
    ("darwin-arm64",  "tar.gz"),
    ("windows-amd64", "zip"),
]


def _fetch_sha(url: str) -> str:
    r = requests.get(url, timeout=30, allow_redirects=True)
    r.raise_for_status()
    sha = r.text.strip().split()[0].lower()
    if len(sha) != 128 or not all(c in "0123456789abcdef" for c in sha):
        raise SystemExit(f"unexpected SHA-512 from {url}: {r.text!r}")
    return sha


def fetch_sha(version: str, platform: str, ext: str) -> str:
    """Fetch the SHA-512 from both dist.ipfs.tech and github.com release
    assets, refusing to record it unless both sources agree.

    Two independent origins (Cloudflare-fronted dist + GitHub release CDN)
    means an attacker has to compromise both to get a malicious hash baked
    into the wheel. That's the trust gate this script controls — once a
    hash lands in kubo_checksums.py and is committed, runtime verification
    in basic_ipfs/__init__.py is fail-closed against any single origin
    being swapped.
    """
    archive = f"kubo_{version}_{platform}.{ext}"
    dist_sha = _fetch_sha(f"{DIST}/{version}/{archive}.sha512")
    gh_sha = _fetch_sha(f"{GITHUB}/{version}/{archive}.sha512")
    if dist_sha != gh_sha:
        raise SystemExit(
            f"SHA-512 disagreement for {archive}:\n"
            f"  dist.ipfs.tech: {dist_sha}\n"
            f"  github.com:     {gh_sha}\n"
            f"Refusing to record an ambiguous hash. Investigate before retrying."
        )
    return dist_sha


def update_table(version: str, shas: dict[str, str]) -> None:
    path = Path(__file__).resolve().parent.parent / "basic_ipfs" / "kubo_checksums.py"
    text = path.read_text()

    # Locate the CHECKSUMS dict and inject/replace the entry for `version`.
    new_block = f'    "{version}": {{\n'
    for plat, _ in PLATFORMS:
        new_block += f'        "{plat:<13}": "{shas[plat]}",\n'
    new_block += "    },"

    # Replace existing entry, or insert before the closing `}` of CHECKSUMS.
    pattern = re.compile(rf'    "{re.escape(version)}":\s*\{{[^}}]*\}},?', re.DOTALL)
    if pattern.search(text):
        text = pattern.sub(new_block.rstrip(","), text)
    else:
        text = re.sub(
            r"(CHECKSUMS:\s*dict\[str,\s*dict\[str,\s*str\]\]\s*=\s*\{)",
            r"\1\n" + new_block,
            text,
            count=1,
        )

    path.write_text(text)
    print(f"Updated {path} with {version}:")
    for plat in shas:
        print(f"  {plat:<13} {shas[plat][:16]}…")


def main() -> int:
    p = argparse.ArgumentParser(description="Refresh kubo_checksums.py for a Kubo version")
    p.add_argument("version", help="Kubo version, e.g. v0.41.0")
    args = p.parse_args()

    version = args.version
    if not version.startswith("v"):
        version = "v" + version

    shas: dict[str, str] = {}
    for plat, ext in PLATFORMS:
        print(f"Fetching {plat}…", end=" ", flush=True)
        try:
            shas[plat] = fetch_sha(version, plat, ext)
        except requests.HTTPError as e:
            print(f"FAILED ({e})")
            return 1
        print("ok")

    update_table(version, shas)
    print("\nDone. Review the diff, then bump KUBO_VERSION in basic_ipfs/__init__.py and commit.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
