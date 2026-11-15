"""Blocks one by one, pins of a block alone, and telling the DHT.

Checked without a daemon by capturing what each call sends to Kubo's RPC, and
-- with ``IPFS_E2E=1`` -- for real, against a daemon on this machine.

Run the real one with:  IPFS_E2E=1 python -m pytest tests/test_blocks.py -v
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import pytest

import basic_ipfs


class _Reply:
    def __init__(self, body: bytes = b"", key: str = "bafyblock") -> None:
        self.body, self.key = body, key

    def json(self) -> dict[str, str]:
        return {"Key": self.key}

    def iter_content(self, chunk_size: int) -> list[bytes]:
        return [self.body]

    def close(self) -> None:
        pass


def _capturing(m: basic_ipfs.IPFSManager, reply: _Reply) -> list[dict[str, Any]]:
    calls: list[dict[str, Any]] = []

    def post(endpoint: str, **kw: Any) -> _Reply:
        if "data" in kw and not isinstance(kw["data"], (bytes, type(None))):
            kw["body"] = b"".join(kw.pop("data"))
        calls.append({"endpoint": endpoint, **kw})
        return reply

    m._post = post  # type: ignore[method-assign,assignment]
    return calls


def test_a_block_is_put_as_it_is_and_got_back() -> None:
    m = basic_ipfs.IPFSManager()
    calls = _capturing(m, _Reply(b"node bytes"))
    assert m.block_put(b"node bytes") == "bafyblock"
    assert calls[0]["endpoint"] == "block/put"
    assert calls[0]["params"] == {"cid-codec": "dag-pb", "mhtype": "sha2-256"}
    assert b"node bytes" in calls[0]["body"]
    assert m.block_get("bafyblock") == b"node bytes"
    assert calls[1]["params"] == {"arg": "bafyblock"}
    m.block_get("bafyblock", local_only=True)
    assert calls[2]["params"]["offline"] == "true"


def test_a_block_over_the_limit_is_refused() -> None:
    m = basic_ipfs.IPFSManager()
    _capturing(m, _Reply(b"x" * 11))
    with pytest.raises(basic_ipfs.IPFSError):
        m.block_get("bafyblock", max_bytes=10)


def test_a_block_can_be_pinned_alone_and_unpinned_so() -> None:
    m = basic_ipfs.IPFSManager()
    calls = _capturing(m, _Reply())
    m.pin_add("bafyroot", recursive=False)
    m.pin_rm("bafyroot", recursive=False)
    m.pin_add("bafyroot")
    assert calls[0]["params"] == [("arg", "bafyroot"), ("recursive", "false")]
    assert calls[1]["params"] == [("arg", "bafyroot"), ("recursive", "false")]
    assert calls[2]["params"] == [("arg", "bafyroot"), ("recursive", "true")]


def test_providing_tells_the_dht_of_one_cid() -> None:
    m = basic_ipfs.IPFSManager()
    calls = _capturing(m, _Reply())
    m.provide("bafyroot")
    assert calls[0]["endpoint"] == "routing/provide"
    assert calls[0]["params"] == {"arg": "bafyroot"}


@pytest.mark.skipif(not os.environ.get("IPFS_E2E"), reason="set IPFS_E2E=1")
def test_blocks_for_real(tmp_path: Path) -> None:
    m = basic_ipfs.IPFSManager(
        port=5628, repo=tmp_path / "ipfs", gateway_port=8628, swarm_port=4628
    )
    try:
        m.start()
        raw = m.block_put(b"plain block", codec="raw")
        assert m.block_get(raw, local_only=True) == b"plain block"
        m.pin_add(raw, recursive=False)
        m.repo_gc()
        assert m.block_exists(raw)  # kept by its pin alone
        m.pin_rm(raw, recursive=False)
        m.repo_gc()
        assert not m.block_exists(raw)
        with pytest.raises(basic_ipfs.IPFSError):
            m.block_get(raw, local_only=True, timeout=5)
    finally:
        m.stop()
