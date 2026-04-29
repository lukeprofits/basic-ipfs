"""
Two-node integration test.

Spawns a SECOND basic_ipfs daemon in a subprocess with its own repo, has
node A add a CID, has node B fetch it over the local swarm.

Gated behind ``IPFS_E2E=1`` because it's slow and depends on local
peer discovery / mDNS quirks of the host.

Run with:  IPFS_E2E=1 .venv/bin/python -m pytest tests/test_two_node.py -v
"""

from __future__ import annotations

import os
import subprocess
import sys
import textwrap
import time

import pytest

import basic_ipfs

if not os.environ.get("IPFS_E2E"):
    pytest.skip("set IPFS_E2E=1 to run two-node integration tests", allow_module_level=True)


@pytest.fixture(scope="module", autouse=True)
def _node_a():
    basic_ipfs.start()
    yield


def _spawn_node_b(
    repo_path: str,
    api_port: int,
    gateway_port: int,
    swarm_port: int,
) -> subprocess.Popen:
    """Run a second basic_ipfs daemon inside a subprocess."""
    code = textwrap.dedent(f"""
        import sys, time, json
        import basic_ipfs
        basic_ipfs.REPO_PATH = {repo_path!r}
        basic_ipfs.API_PORT = {api_port}
        basic_ipfs.GATEWAY_PORT = {gateway_port}
        basic_ipfs.SWARM_ADDRESSES = [
            "/ip4/0.0.0.0/tcp/{swarm_port}",
            "/ip6/::/tcp/{swarm_port}",
        ]
        basic_ipfs.start()
        # Print readiness sentinel and our address for the parent to consume.
        ipv4, ipv6 = basic_ipfs.my_node_multiaddress()
        print("READY", json.dumps({{"ipv4": ipv4, "ipv6": ipv6}}), flush=True)
        # Stay alive — parent will signal completion by closing stdin.
        try:
            sys.stdin.read()
        finally:
            basic_ipfs.stop()
    """)
    return subprocess.Popen(
        [sys.executable, "-c", code],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )


def test_two_nodes_share_content(tmp_path):
    repo_b = tmp_path / "repo_b"
    api_port_b = basic_ipfs.API_PORT + 100  # avoid clash
    gateway_port_b = basic_ipfs.GATEWAY_PORT + 100
    swarm_port_b = 4101  # default 4001 + 100

    proc = _spawn_node_b(str(repo_b), api_port_b, gateway_port_b, swarm_port_b)
    try:
        # Wait for READY line (up to 90 s — first run downloads Kubo).
        deadline = time.monotonic() + 120
        ready_line = None
        while time.monotonic() < deadline:
            line = proc.stdout.readline()
            if not line:
                err = proc.stderr.read()
                pytest.fail(f"node B exited prematurely: {err[:1000]}")
            if line.startswith("READY"):
                ready_line = line
                break
        assert ready_line, "node B never reported READY"

        import json
        info = json.loads(ready_line.split(" ", 1)[1])
        # Connect A → B
        target = info["ipv4"] or info["ipv6"]
        assert target, "node B has no shareable multiaddr"
        basic_ipfs.connect_to_node(target)

        # A adds. Use bytes so the add is fast and the CID is deterministic.
        payload = os.urandom(4096) + b"-two-node-test"
        cid = basic_ipfs.add(payload)

        # Node B fetches via its own API. Use raw HTTP since we're outside
        # of node B's basic_ipfs instance.
        import requests
        api = f"http://127.0.0.1:{api_port_b}/api/v0"
        deadline = time.monotonic() + 60
        fetched: bytes = b""
        last_error = None
        while time.monotonic() < deadline:
            try:
                r = requests.post(f"{api}/cat", params={"arg": cid}, timeout=10)
                r.raise_for_status()
                fetched = r.content
                if fetched == payload:
                    break
            except requests.RequestException as e:
                last_error = e
            time.sleep(2)
        assert fetched == payload, f"B never received the content (last_error={last_error})"
    finally:
        try:
            proc.stdin.close()
            proc.wait(timeout=10)
        except (subprocess.TimeoutExpired, BrokenPipeError):
            proc.kill()
