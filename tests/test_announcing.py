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
