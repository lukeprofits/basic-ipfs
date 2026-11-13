"""Topics: publish to a name, hear a name.

Checked without a daemon by capturing what each call sends to Kubo's RPC, and
-- with ``IPFS_E2E=1`` -- for real, between two daemons on this machine.

Run the real one with:  IPFS_E2E=1 python -m pytest tests/test_topics.py -v
"""

from __future__ import annotations

import os
import time
from pathlib import Path
from typing import Any

import pytest

import basic_ipfs


def test_a_topic_name_goes_to_kubo_as_multibase() -> None:
    assert basic_ipfs._topic_arg("ehe/offers/v1") == "uZWhlL29mZmVycy92MQ"
    assert basic_ipfs._from_multibase("uAQID") == b"\x01\x02\x03"
    for bad in ("", None, 5):
        with pytest.raises(basic_ipfs.IPFSError):
            basic_ipfs._topic_arg(bad)  # type: ignore[arg-type]
    for bad in ("AQID", "", 5):
        with pytest.raises(ValueError):
            basic_ipfs._from_multibase(bad)  # type: ignore[arg-type]


def test_publish_sends_the_bytes_to_the_topic() -> None:
    m = basic_ipfs.IPFSManager()
    calls: list[dict[str, Any]] = []
    m._post = lambda endpoint, **kw: calls.append({"endpoint": endpoint, **kw})  # type: ignore[method-assign,assignment,func-returns-value]
    m.topic_publish("weather", b"rain")
    assert calls[0]["endpoint"] == "pubsub/pub"
    assert calls[0]["params"] == {"arg": basic_ipfs._topic_arg("weather")}
    assert calls[0]["files"] == {"file": ("data", b"rain")}


def test_topics_off_is_said_plainly() -> None:
    m = basic_ipfs.IPFSManager()

    def refuse(endpoint: str, **kwargs: Any) -> Any:
        raise basic_ipfs.IPFSOperationError(
            "IPFS API error [500] pubsub/pub: experimental pubsub feature not "
            "enabled, run daemon with --enable-pubsub-experiment to use"
        )

    m._post = refuse  # type: ignore[method-assign]
    with pytest.raises(basic_ipfs.IPFSError, match="topics=True"):
        m.topic_publish("weather", b"rain")
    with pytest.raises(basic_ipfs.IPFSError, match="topics=True"):
        m.topic_listen("weather", lambda data, sender: None)


def test_topics_are_switched_on_only_when_asked() -> None:
    seen: list[tuple[str, ...]] = []
    plain = basic_ipfs.IPFSManager()
    plain._run_cli = lambda *args, **kw: seen.append(args)  # type: ignore[method-assign,assignment]
    plain._configure_topics()
    assert seen == []
    m = basic_ipfs.IPFSManager(topics=True)
    m._run_cli = lambda *args, **kw: seen.append(args)  # type: ignore[method-assign,assignment]
    m._configure_topics()
    assert seen == [("config", "--json", "Pubsub.Enabled", "true")]


def _until(condition: Any, seconds: float = 20.0) -> bool:
    deadline = time.time() + seconds
    while time.time() < deadline:
        if condition():
            return True
        time.sleep(0.05)
    return False


@pytest.mark.skipif(not os.environ.get("IPFS_E2E"), reason="set IPFS_E2E=1")
def test_what_one_node_publishes_another_hears(tmp_path: Path) -> None:
    a = basic_ipfs.IPFSManager(
        port=5625, repo=tmp_path / "a", gateway_port=8625, swarm_port=4625, topics=True
    )
    b = basic_ipfs.IPFSManager(
        port=5626, repo=tmp_path / "b", gateway_port=8626, swarm_port=4626, topics=True
    )
    try:
        a.start()
        b.start()
        b.swarm_connect(f"/ip4/127.0.0.1/tcp/4625/p2p/{a.peer_id()}")
        weather: list[tuple[bytes, str]] = []
        sport: list[tuple[bytes, str]] = []

        def fussy(data: bytes, sender: str) -> None:
            if data == b"bad":
                raise ValueError("no")
            weather.append((data, sender))

        stop = a.topic_listen("weather", fussy)
        a.topic_listen("sport", lambda data, sender: sport.append((data, sender)))
        # the two daemons need a moment to learn each other's topics
        payload = bytes(range(256)) * 8

        def heard() -> bool:
            b.topic_publish("weather", payload)
            return bool(weather)

        assert _until(heard)
        assert weather[0] == (payload, b.peer_id())
        # a callback that raises does not end the listening
        b.topic_publish("weather", b"bad")
        b.topic_publish("weather", b"good")
        assert _until(lambda: (b"good", b.peer_id()) in weather)
        assert sport == []
        stop()
        stop()  # twice is fine
        before = len(weather)
        b.topic_publish("weather", b"after stop")
        time.sleep(1.5)
        assert len(weather) == before
    finally:
        b.stop()
        a.stop()
