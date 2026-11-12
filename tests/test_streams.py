"""A manager with its own repo and ports, and peer-to-peer streams.

Checked without a daemon by capturing what each call sends to Kubo's RPC, and
-- with ``IPFS_E2E=1`` -- for real: two daemons on this machine, one program
talking to another through them.

Run the real one with:  IPFS_E2E=1 python -m pytest tests/test_streams.py -v
"""

from __future__ import annotations

import os
import socket
import threading
from pathlib import Path
from typing import Any

import pytest

import basic_ipfs


class _Resp:
    text = ""

    def json(self) -> dict[str, Any]:
        return {"ID": "12D3KooWExamplePeer"}


def _capture(manager: basic_ipfs.IPFSManager) -> list[dict[str, Any]]:
    calls: list[dict[str, Any]] = []

    def fake_post(endpoint: str, **kwargs: Any) -> _Resp:
        calls.append({"endpoint": endpoint, **kwargs})
        return _Resp()

    manager._post = fake_post  # type: ignore[method-assign]
    return calls


def test_listen_forward_and_close_send_what_kubo_expects() -> None:
    m = basic_ipfs.IPFSManager()
    calls = _capture(m)
    m.stream_listen("chat", 9001)
    m.stream_forward("chat", 9002, "12D3KooWPeer")
    m.stream_close("chat")
    m.stream_close()
    assert calls[0]["endpoint"] == "p2p/listen"
    assert calls[0]["params"] == [("arg", "/x/chat"), ("arg", "/ip4/127.0.0.1/tcp/9001")]
    assert calls[1]["endpoint"] == "p2p/forward"
    assert calls[1]["params"] == [
        ("arg", "/x/chat"),
        ("arg", "/ip4/127.0.0.1/tcp/9002"),
        ("arg", "/p2p/12D3KooWPeer"),
    ]
    assert calls[2]["params"] == [("protocol", "/x/chat")]
    assert calls[3]["params"] == [("all", "true")]


def test_peer_id_reads_the_daemons_identity() -> None:
    m = basic_ipfs.IPFSManager()
    _capture(m)
    assert m.peer_id() == "12D3KooWExamplePeer"


@pytest.mark.parametrize("name", ["", "has space", "a/b", "/x/chat", "semi;colon"])
def test_a_stream_name_is_a_plain_token(name: str) -> None:
    m = basic_ipfs.IPFSManager()
    calls = _capture(m)
    with pytest.raises(basic_ipfs.IPFSError):
        m.stream_listen(name, 9001)
    assert calls == []


@pytest.mark.parametrize("peer", ["", "/p2p/12D3KooWPeer", "a/b"])
def test_a_forward_names_a_bare_peer_id(peer: str) -> None:
    m = basic_ipfs.IPFSManager()
    calls = _capture(m)
    with pytest.raises(basic_ipfs.IPFSError):
        m.stream_forward("chat", 9002, peer)
    assert calls == []


def test_streams_off_is_said_plainly() -> None:
    m = basic_ipfs.IPFSManager()

    def refuse(endpoint: str, **kwargs: Any) -> _Resp:
        raise basic_ipfs.IPFSOperationError("libp2p stream mounting not enabled")

    m._post = refuse  # type: ignore[method-assign]
    with pytest.raises(basic_ipfs.IPFSError, match="streams=True"):
        m.stream_listen("chat", 9001)


def test_a_manager_may_have_its_own_repo_and_ports(tmp_path: Path) -> None:
    m = basic_ipfs.IPFSManager(
        port=5611, repo=tmp_path / "repo", gateway_port=8611, swarm_port=4611
    )
    assert m._repo_override == tmp_path / "repo"
    assert m._gateway_port == 8611
    assert m._port == 5611
    seen: list[tuple[str, ...]] = []
    m._run_cli = lambda *args, **kw: seen.append(args)  # type: ignore[method-assign,assignment]
    m._configure_swarm_addresses()
    m._configure_gateway_address()
    m._configure_streams()  # off by default: nothing is written
    assert seen[0][:2] == ("config", "Addresses.Swarm")
    assert "/ip4/0.0.0.0/tcp/4611" in seen[0][3]
    assert "/udp/4611/quic-v1" in seen[0][3]
    assert seen[1] == ("config", "Addresses.Gateway", "/ip4/127.0.0.1/tcp/8611")
    assert len(seen) == 2
    # and one left alone still follows the module's settings
    plain = basic_ipfs.IPFSManager()
    assert plain._repo_override is None
    assert plain._gateway_port == basic_ipfs.GATEWAY_PORT


def test_streams_are_switched_on_only_when_asked() -> None:
    m = basic_ipfs.IPFSManager(streams=True)
    seen: list[tuple[str, ...]] = []
    m._run_cli = lambda *args, **kw: seen.append(args)  # type: ignore[method-assign,assignment]
    m._configure_streams()
    assert seen == [("config", "--json", "Experimental.Libp2pStreamMounting", "true")]


@pytest.mark.skipif(not os.environ.get("IPFS_E2E"), reason="set IPFS_E2E=1")
def test_two_programs_talk_through_two_daemons(tmp_path: Path) -> None:
    a = basic_ipfs.IPFSManager(
        port=5621, repo=tmp_path / "a", gateway_port=8621, swarm_port=4621, streams=True
    )
    b = basic_ipfs.IPFSManager(
        port=5622, repo=tmp_path / "b", gateway_port=8622, swarm_port=4622, streams=True
    )
    try:
        a.start()
        b.start()
        assert a.peer_id() != b.peer_id()
        b.swarm_connect(f"/ip4/127.0.0.1/tcp/4621/p2p/{a.peer_id()}")

        server = socket.socket()
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(("127.0.0.1", 9621))
        server.listen()

        def echo() -> None:
            conn, _ = server.accept()
            conn.sendall(b"echo:" + conn.recv(100))
            conn.close()

        threading.Thread(target=echo, daemon=True).start()
        a.stream_listen("basic-ipfs-test", 9621)
        b.stream_forward("basic-ipfs-test", 9622, a.peer_id())
        with socket.create_connection(("127.0.0.1", 9622), timeout=30) as conn:
            conn.sendall(b"hello")
            assert conn.recv(100) == b"echo:hello"
        server.close()
        # and content added on one is fetched by the other
        cid = a.add(b"x" * 100_000, provide=False)
        assert b.cat(cid, timeout=30) == b"x" * 100_000
    finally:
        b.stop()
        a.stop()
