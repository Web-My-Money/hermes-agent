"""WMM: a non-admin sender's approval card is delivered to the owner's chat.

Drives the real ``TurnRunner._approval_notify_sync`` with a fake button adapter
(same harness shape as test_exec_approval_timeout_notice.py).
"""

from __future__ import annotations

import asyncio
from types import SimpleNamespace
from typing import Any, List

import pytest

import tools.approval_principal as principal
from gateway.platforms.base import SendResult

SESSION = "agent:main:telegram:dm:555"
APPROVAL = {"command": "rm -rf /tmp/x", "description": "recursive delete", "pattern_key": "k"}
OWNER_CHAT = "8635020128"


class _ButtonAdapter:
    typed_command_prefix = "/"

    def __init__(self) -> None:
        self.cards: List[dict] = []
        self.sends: List[tuple] = []

    def pause_typing_for_chat(self, chat_id: str) -> None:
        return None

    async def send_exec_approval(self, **k: Any) -> SendResult:
        self.cards.append(k)
        return SendResult(success=True, message_id="card-1")

    async def send(self, chat_id: str, message: str, **k: Any) -> SendResult:
        self.sends.append((chat_id, message))
        return SendResult(success=True, message_id="m2")


def _runner(adapter):
    from gateway.run_turn_runner import TurnRunner

    runner = object.__new__(TurnRunner)
    runner._ctx = SimpleNamespace(
        _status_adapter=adapter, _status_chat_id="555", _status_thread_metadata={"thread_id": "t1"},
        session_key=SESSION, source=SimpleNamespace(chat_id="555", platform="telegram", session_key=SESSION),
    )

    class _Fut:
        def __init__(self, result): self._r = result
        def result(self, timeout=None): return self._r

    runner._schedule = lambda coro, _label: _Fut(asyncio.run(coro))
    runner._close_native_stream_boundary = lambda _why: None
    return runner


@pytest.fixture(autouse=True)
def _no_timeout_hook(monkeypatch):
    import gateway.run_turn_runner_approval_settle as settle
    monkeypatch.setattr(settle, "register_timeout_notice", lambda *a, **k: None)


def test_teammate_card_goes_to_owner(monkeypatch):
    monkeypatch.setattr(principal, "approver_chat_for_current_session", lambda: OWNER_CHAT)
    monkeypatch.setattr(principal, "requester_label", lambda: "Carolina (555)")
    adapter = _ButtonAdapter()
    _runner(adapter)._approval_notify_sync(dict(APPROVAL))

    assert len(adapter.cards) == 1
    card = adapter.cards[0]
    assert card["chat_id"] == OWNER_CHAT
    assert card["metadata"] is None  # the requester's thread metadata must not leak into the owner's DM
    assert card["allow_permanent"] is False
    assert "requested by Carolina (555)" in card["description"]
    assert adapter.sends and adapter.sends[0][0] == "555"
    assert "owner's approval" in adapter.sends[0][1]


def test_owner_card_unchanged(monkeypatch):
    monkeypatch.setattr(principal, "approver_chat_for_current_session", lambda: None)
    adapter = _ButtonAdapter()
    _runner(adapter)._approval_notify_sync(dict(APPROVAL))

    card = adapter.cards[0]
    assert card["chat_id"] == "555"
    assert card["metadata"] == {"thread_id": "t1"}
    assert card["description"] == "recursive delete"
    assert adapter.sends == []
