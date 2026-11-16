"""What a node announces: a provide strategy, and MFS as the list of it.

Kubo's default announces every block added. `provide_strategy="mfs"` makes it
announce only what is in MFS, and `mfs_add` / `mfs_remove` put things there.
Run the real one with:  IPFS_E2E=1 python -m pytest tests/test_announcing.py -v
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path
from typing import Any

import pytest

import basic_ipfs


def test_the_strategy_is_set_only_when_asked_and_a_failure_is_an_error() -> None:
    seen: list[tuple[str, ...]] = []
    plain = basic_ipfs.IPFSManager()
    plain._run_cli = lambda *a, **k: seen.append(a)  # type: ignore[method-assign,assignment]
    plain._configure_provide_strategy()
    assert seen == []
    m = basic_ipfs.IPFSManager(provide_strategy="mfs")
    m._run_cli = lambda *a, **k: seen.append(a)  # type: ignore[method-assign,assignment]
    m._configure_provide_strategy()
    assert seen == [("config", "Provide.Strategy", "mfs")]

    def refuse(*a: Any, **k: Any) -> Any:
        raise subprocess.CalledProcessError(1, "ipfs", stderr="no")

    m._run_cli = refuse  # type: ignore[method-assign]
    with pytest.raises(basic_ipfs.IPFSError, match="announces"):
        m._configure_provide_strategy()


def test_mfs_add_and_remove_are_what_kubo_is_asked() -> None:
    m = basic_ipfs.IPFSManager()
    calls: list[tuple[str, Any]] = []
    m._post = lambda endpoint, **kw: calls.append((endpoint, kw["params"]))  # type: ignore[method-assign,assignment,func-returns-value]
    m.mfs_add("bafyx", "/shown/bafyx")
    m.mfs_remove("/shown/bafyx")
    assert calls == [
        ("files/mkdir", {"arg": "/shown", "parents": "true"}),
        ("files/cp", [("arg", "/ipfs/bafyx"), ("arg", "/shown/bafyx")]),
        ("files/rm", {"arg": "/shown/bafyx", "recursive": "true"}),
    ]


@pytest.mark.skipif(not os.environ.get("IPFS_E2E"), reason="set IPFS_E2E=1")
def test_only_what_is_in_mfs_is_scheduled_for_the_dht(tmp_path: Path) -> None:
    m = basic_ipfs.IPFSManager(
        port=5629,
        repo=tmp_path / "ipfs",
        gateway_port=8629,
        swarm_port=4629,
        provide_strategy="mfs",
    )

    try:
        m.start()
        assert m._run_cli("config", "Provide.Strategy").stdout.strip() == "mfs"
        hidden = m.add(os.urandom(3_000_000), provide=False)
        shown = m.add(os.urandom(3_000_000))
        m.mfs_add(shown, f"/shown/{shown}")
        m.mfs_add(shown, f"/shown/{shown}")  # twice is fine
        listed = m._post("files/ls", params={"arg": "/shown"}).json()
        assert [e["Name"] for e in listed["Entries"]] == [shown]
        assert hidden not in str(listed)
        m.mfs_remove(f"/shown/{shown}")
        m.mfs_remove(f"/shown/{shown}")  # gone already is fine
        assert not m._post("files/ls", params={"arg": "/shown"}).json().get("Entries")
    finally:
        m.stop()


class _Lines:
    """A streamed reply from Kubo: newline-delimited JSON."""

    def __init__(self, lines: list[bytes], fail_after: int | None = None) -> None:
        self.lines, self.fail_after, self.closed = lines, fail_after, False

    def iter_lines(self) -> Any:
        import requests

        for n, line in enumerate(self.lines):
            if self.fail_after is not None and n == self.fail_after:
                raise requests.ConnectionError("read timed out")
            yield line

    def close(self) -> None:
        self.closed = True


def _provider(*peers: str) -> bytes:
    import json

    return json.dumps(
        {"Type": 4, "Responses": [{"ID": p, "Addrs": []} for p in peers]}
    ).encode()


def test_who_has_reads_providers_alone_and_stops_at_the_limit() -> None:
    m = basic_ipfs.IPFSManager()
    asked: list[tuple[str, Any]] = []
    reply = _Lines(
        [
            b'{"Type": 0, "ID": "12D3query", "Responses": null}',  # a query step
            b"",
            b"not json",
            _provider("12D3a"),
            _provider("12D3a", "12D3b"),  # the same one again
            _provider("12D3c"),
            _provider("12D3d"),
        ]
    )

    def post(endpoint: str, **kw: Any) -> Any:
        asked.append((endpoint, kw["params"]))
        return reply

    m._post = post  # type: ignore[method-assign,assignment]
    assert m.who_has("bafyx", limit=3) == ["12D3a", "12D3b", "12D3c"]
    assert asked == [("routing/findprovs", {"arg": "bafyx", "num-providers": "3"})]
    assert reply.closed
    # a lookup cut short answers with what it had
    m._post = lambda endpoint, **kw: _Lines(  # type: ignore[method-assign,assignment]
        [_provider("12D3a"), _provider("12D3b")], fail_after=1
    )
    assert m.who_has("bafyx") == ["12D3a"]
