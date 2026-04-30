"""
CLI smoke tests — exercise argparse plumbing on every platform.

These don't start the daemon. They only verify that the command-line
entry point exists, parses its subcommands, and surfaces --help / --version
without crashing. Catches things like a missing import or a typo'd
``set_defaults(func=...)`` before they hit a release.
"""

from __future__ import annotations

import subprocess
import sys


def _run(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "basic_ipfs.cli", *args],
        capture_output=True,
        text=True,
        timeout=30,
    )


def test_cli_version():
    result = _run("--version")
    assert result.returncode == 0
    assert "basic-ipfs" in result.stdout


def test_cli_help_lists_all_subcommands():
    result = _run("--help")
    assert result.returncode == 0
    out = result.stdout
    expected = [
        "status", "pins",
        "add", "announce", "add-folder", "compute-cid",
        "get", "pin", "unpin",
        "is-pinned", "exists", "gc",
        "peers", "connect", "connect-nodes", "my-addr",
        "create-private-network", "join-private-network", "network-key",
        "rotate-identity", "lockdown",
    ]
    for cmd in expected:
        assert cmd in out, f"{cmd!r} not advertised in --help output"


def test_cli_subcommand_help():
    """Every leaf subcommand should accept --help without error."""
    subcommands = [
        ("status",), ("pins",),
        ("add", "--help"), ("announce", "--help"), ("add-folder", "--help"),
        ("compute-cid", "--help"),
        ("get", "--help"), ("pin", "--help"), ("unpin", "--help"),
        ("is-pinned", "--help"), ("exists", "--help"), ("gc", "--help"),
        ("peers", "--help"), ("connect", "--help"), ("connect-nodes", "--help"),
        ("my-addr", "--help"),
        ("create-private-network", "--help"),
        ("join-private-network", "--help"),
        ("network-key", "--help"),
        ("rotate-identity", "--help"),
        ("lockdown", "--help"),
    ]
    for cmd in subcommands:
        if cmd[-1] != "--help":
            continue  # status/pins have no required args; skip — would start daemon
        result = _run(*cmd)
        assert result.returncode == 0, (
            f"basic-ipfs {' '.join(cmd)} exited {result.returncode}: "
            f"{result.stderr.strip()}"
        )


def test_cli_no_subcommand_errors():
    result = _run()
    # argparse exits 2 when a required subcommand is missing
    assert result.returncode == 2


def test_cli_unknown_subcommand_errors():
    result = _run("frobnicate")
    assert result.returncode == 2
    assert "frobnicate" in result.stderr or "invalid choice" in result.stderr.lower()
