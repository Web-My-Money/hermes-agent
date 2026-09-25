"""WMM: owner/teammate approval split (tools/approval_principal.py).

The admin list is the slash-gating one (platforms.<p>.allow_admin_from). A non-admin
sender gets approvals.non_admin_mode and approvals.non_admin_deny; the owner keeps
approvals.mode; non-messaging sessions (CLI, cron) are never non-admin.
"""

import pytest

import tools.approval_principal as principal
from gateway.session_context import clear_session_vars, set_session_vars
from tools import approval as mod
from tools import approval_context

OWNER = "8635020128"
TEAMMATE = "555000111"


@pytest.fixture
def cfg(monkeypatch):
    state = {
        "approvals": {"mode": "off"},
        "platforms": {"telegram": {"allow_admin_from": [OWNER]}},
    }
    monkeypatch.setattr(approval_context, "_get_approval_config", lambda: state["approvals"])
    import hermes_cli.config as hc
    monkeypatch.setattr(hc, "load_config_readonly", lambda: state)
    for var in ("HERMES_YOLO_MODE", "HERMES_PLATFORM", "HERMES_SESSION_PLATFORM", "HERMES_SESSION_USER_ID"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setattr(mod, "_YOLO_MODE_FROZEN", False)
    return state


@pytest.fixture
def as_user():
    tokens = []

    def bind(user_id, chat_type="dm", platform="telegram", name="Someone"):
        tokens.append(set_session_vars(platform=platform, chat_id=user_id, chat_type=chat_type,
                                       user_id=user_id, user_name=name, session_key=f"s-{user_id}"))
    yield bind
    for t in reversed(tokens):
        clear_session_vars(t)


def test_inert_without_non_admin_mode(cfg, as_user):
    as_user(TEAMMATE)
    assert approval_context._get_approval_mode() == "off"


def test_teammate_escalated_owner_unchanged(cfg, as_user):
    cfg["approvals"]["non_admin_mode"] = "manual"
    as_user(TEAMMATE)
    assert principal.is_non_admin_session() is True
    assert approval_context._get_approval_mode() == "manual"


def test_owner_keeps_off(cfg, as_user):
    cfg["approvals"]["non_admin_mode"] = "manual"
    as_user(OWNER)
    assert principal.is_non_admin_session() is False
    assert approval_context._get_approval_mode() == "off"


def test_never_relaxes_a_stricter_base(cfg, as_user):
    cfg["approvals"].update(mode="manual", non_admin_mode="smart")
    as_user(TEAMMATE)
    assert approval_context._get_approval_mode() == "manual"


def test_no_admin_list_means_no_gating(cfg, as_user):
    cfg["approvals"]["non_admin_mode"] = "manual"
    cfg["platforms"]["telegram"] = {}
    as_user(TEAMMATE)
    assert approval_context._get_approval_mode() == "off"


def test_group_scope_uses_group_admin_list(cfg, as_user):
    cfg["approvals"]["non_admin_mode"] = "manual"
    cfg["platforms"]["telegram"]["group_allow_admin_from"] = [OWNER]
    as_user(OWNER, chat_type="group")
    assert approval_context._get_approval_mode() == "off"
    as_user(TEAMMATE, chat_type="group")
    assert approval_context._get_approval_mode() == "manual"


def test_extra_subdict_spelling(cfg, as_user):
    cfg["approvals"]["non_admin_mode"] = "manual"
    cfg["platforms"]["telegram"] = {"extra": {"allow_admin_from": [OWNER]}}
    as_user(TEAMMATE)
    assert approval_context._get_approval_mode() == "manual"


def test_cli_session_is_never_non_admin(cfg):
    cfg["approvals"]["non_admin_mode"] = "manual"
    assert principal.is_non_admin_session() is False
    assert approval_context._get_approval_mode() == "off"


def test_principal_error_fails_closed(cfg, as_user, monkeypatch):
    cfg["approvals"]["non_admin_mode"] = "manual"
    as_user(OWNER)
    monkeypatch.setattr(principal, "is_non_admin_session", lambda: (_ for _ in ()).throw(RuntimeError("boom")))
    assert approval_context._get_approval_mode() == "manual"


def test_non_admin_deny_blocks_teammate_only(cfg, as_user):
    cfg["approvals"]["non_admin_deny"] = ["*hermes pairing*"]
    as_user(TEAMMATE)
    assert mod._match_user_deny_rule("hermes pairing approve telegram ABCD2345") == "*hermes pairing*"
    blocked = mod.check_dangerous_command("hermes pairing approve telegram ABCD2345", "local")
    assert blocked["approved"] is False
    as_user(OWNER)
    assert mod._match_user_deny_rule("hermes pairing approve telegram ABCD2345") is None


def test_non_admin_deny_beats_mode_off(cfg, as_user):
    cfg["approvals"].update(mode="off", non_admin_deny=["*TELEGRAM_ALLOWED_USERS*"])
    as_user(TEAMMATE)
    assert mod.check_dangerous_command("export TELEGRAM_ALLOWED_USERS=1,2", "local")["approved"] is False


def test_approver_chat_only_for_teammates(cfg, as_user):
    cfg["approvals"]["non_admin_approver_chat"] = {"telegram": OWNER}
    as_user(TEAMMATE, name="Carolina")
    assert principal.approver_chat_for_current_session() == OWNER
    assert principal.requester_label() == f"Carolina ({TEAMMATE})"
    as_user(OWNER)
    assert principal.approver_chat_for_current_session() is None
