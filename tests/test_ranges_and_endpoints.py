"""Range reads, per-instance endpoints and explicit add() options.

These are what EHE asked for (REQUESTS-from-EHE.md). They are checked here
without a daemon, by capturing what each call sends to Kubo's RPC.
"""

from __future__ import annotations

from typing import Any

import pytest

import basic_ipfs


class _Resp:
    def __init__(self, body: bytes = b"", text: str = "") -> None:
        self._body = body
        self.text = text

    def iter_content(self, chunk_size: int = 65536):  # noqa: ARG002
        yield self._body

    def close(self) -> None:
        pass


def _capture(manager: basic_ipfs.IPFSManager, reply: _Resp) -> list[dict[str, Any]]:
    calls: list[dict[str, Any]] = []

    def fake_post(endpoint: str, **kwargs: Any) -> _Resp:
        calls.append({"endpoint": endpoint, **kwargs})
        return reply

    manager._post = fake_post  # type: ignore[method-assign]
    return calls


def test_cat_passes_offset_and_length() -> None:
    m = basic_ipfs.IPFSManager()
    calls = _capture(m, _Resp(b"x" * 4096))
    assert m.cat("bafy", offset=15969535, length=4096) == b"x" * 4096
    assert calls[0]["endpoint"] == "cat"
    assert calls[0]["params"] == {"arg": "bafy", "offset": 15969535, "length": 4096}


def test_cat_without_a_range_sends_only_the_cid() -> None:
    m = basic_ipfs.IPFSManager()
    calls = _capture(m, _Resp(b"abc"))
    m.cat("bafy")
    assert calls[0]["params"] == {"arg": "bafy"}


@pytest.mark.parametrize("bad", [-1, 1.5, True, "10"])
def test_cat_refuses_a_nonsense_range(bad: object) -> None:
    m = basic_ipfs.IPFSManager()
    _capture(m, _Resp())
    with pytest.raises(ValueError):
        m.cat("bafy", offset=bad)  # type: ignore[arg-type]


def test_module_get_forwards_the_range(monkeypatch: pytest.MonkeyPatch) -> None:
    m = basic_ipfs.IPFSManager()
    calls = _capture(m, _Resp(b"y"))
    monkeypatch.setattr(basic_ipfs, "_manager", m)
    basic_ipfs.get("bafy", offset=4096, length=1)
    assert calls[0]["params"] == {"arg": "bafy", "offset": 4096, "length": 1}


def test_add_states_chunker_cid_version_and_raw_leaves() -> None:
    m = basic_ipfs.IPFSManager()
    calls = _capture(m, _Resp(text='{"Hash": "bafyX"}'))
    cid = m.add(b"hello", chunker="size-1048576", cid_version=1, raw_leaves=True)
    assert cid == "bafyX"
    params = dict(calls[0]["params"])
    assert params["chunker"] == "size-1048576"
    assert params["cid-version"] == "1"
    assert params["raw-leaves"] == "true"


def test_add_defaults_are_unchanged() -> None:
    m = basic_ipfs.IPFSManager()
    calls = _capture(m, _Resp(text='{"Hash": "bafyY"}'))
    m.add(b"hello")
    params = dict(calls[0]["params"])
    assert params["cid-version"] == "1"
    assert "chunker" not in params and "raw-leaves" not in params


def test_add_refuses_an_unknown_cid_version() -> None:
    m = basic_ipfs.IPFSManager()
    _capture(m, _Resp(text='{"Hash": "x"}'))
    with pytest.raises(ValueError):
        m.add(b"hello", cid_version=2)


def test_an_instance_can_pin_its_own_endpoint(monkeypatch: pytest.MonkeyPatch) -> None:
    """Two managers, two daemons, no globals touched."""
    monkeypatch.setattr(basic_ipfs, "API_PORT", 5001)
    pinned = basic_ipfs.IPFSManager(host="127.0.0.1", port=5099)
    default = basic_ipfs.IPFSManager()
    assert pinned._api_url == "http://127.0.0.1:5099/api/v0"
    assert default._api_url == "http://127.0.0.1:5001/api/v0"
    monkeypatch.setattr(basic_ipfs, "API_PORT", 6001)
    assert pinned._port == 5099  # an instance's own port does not follow the global
    assert basic_ipfs.IPFSManager()._port == 6001  # the default still does


def test_is_daemon_up_answers_before_start_without_starting_anything() -> None:
    m = basic_ipfs.IPFSManager(host="127.0.0.1", port=1)  # nothing listens on port 1
    assert m.is_daemon_up() is False
    assert m._process is None
