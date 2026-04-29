"""
Concurrency smoke test: hammer the daemon from many threads at once.

Goal: catch deadlocks, dropped requests, and the pipe-fill bug specifically
(the daemon would hang forever when stderr was redirected to subprocess.PIPE
and never drained).
"""

from __future__ import annotations

import os
import socket
import threading
import time

import pytest

import basic_ipfs
from basic_ipfs import IPFSBinaryNotFound


def _has_internet() -> bool:
    try:
        socket.create_connection(("1.1.1.1", 53), timeout=3).close()
        return True
    except OSError:
        return False


@pytest.fixture(scope="module", autouse=True)
def _node():
    try:
        basic_ipfs.start()
    except IPFSBinaryNotFound:
        if not _has_internet():
            pytest.skip("Kubo binary missing and no internet to download it")
        raise
    yield
    # Don't stop — other test modules in the same session may still need it.


def test_many_threads_add_get_unpin():
    n_threads = 32
    iters_per_thread = 5
    errors: list[BaseException] = []
    cids: list[str] = []
    cids_lock = threading.Lock()

    def worker(idx: int):
        try:
            for i in range(iters_per_thread):
                payload = os.urandom(4096) + f"-thread-{idx}-iter-{i}".encode()
                cid = basic_ipfs.add(payload)
                with cids_lock:
                    cids.append(cid)
                got = basic_ipfs.get(cid)
                assert got == payload
        except BaseException as e:  # noqa: BLE001
            errors.append(e)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(n_threads)]
    t0 = time.monotonic()
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=120)
        assert not t.is_alive(), "thread hung — possible deadlock"
    elapsed = time.monotonic() - t0

    assert not errors, f"{len(errors)} workers raised: {errors[:3]}"
    assert len(cids) == n_threads * iters_per_thread

    # Cleanup pins from this run.
    basic_ipfs.unpin(list(set(cids)))
    print(f"\n  {n_threads * iters_per_thread} add+get round-trips in {elapsed:.1f}s")


def test_no_pipe_fill_deadlock():
    """
    The original bug: subprocess.PIPE on stderr never drained → daemon blocks.

    Verify the daemon is reachable after a sustained period of activity. If
    the pipe ever filled, the daemon would block on its next stderr write
    and the API would stop responding.
    """
    deadline = time.monotonic() + 10  # 10 s of churn
    count = 0
    while time.monotonic() < deadline:
        cid = basic_ipfs.add(f"pipe-test-{count}".encode())
        basic_ipfs.unpin(cid)
        count += 1
    # Final liveness check.
    s = basic_ipfs.status()
    assert s["peer_id"]
