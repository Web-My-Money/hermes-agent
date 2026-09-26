"""WMM: per-principal approval policy for messaging gateways.

Upstream Hermes has ONE approval mode per profile. On a shared bot (one owner plus
paired teammates) that forces a choice between prompting the owner for everything
and letting every approved teammate run anything, including ``hermes pairing
approve`` for someone else. Slash commands already have an owner/teammate split
(``platforms.<p>.allow_admin_from`` / ``user_allowed_commands``, see
:mod:`gateway.slash_access`); this module reuses that same admin list for tool
approvals, so there is one definition of "who is the owner".

Config (all under ``approvals``; every key is optional and inert when unset):

``non_admin_mode``
    ``manual`` or ``smart``. For a messaging session whose sender is NOT an admin
    of that platform/scope, the effective approval mode is the stricter of this and
    ``approvals.mode``. Admins keep ``approvals.mode`` unchanged.
``non_admin_deny``
    fnmatch globs (same matching as ``approvals.deny``) that block unconditionally
    for non-admins only, e.g. ``"*hermes pairing*"``. Admins are not affected.
``non_admin_approver_chat``
    ``{platform: chat_id}``. When set, a non-admin's approval card is delivered to
    that chat (the owner's DM) instead of the teammate's own chat, so the owner — not
    the requester — decides. The requester gets a plain "waiting" notice.

Gating is only active when the platform has an admin list for the scope (the same
rule slash gating uses). CLI, cron, TUI and other non-messaging sessions are never
non-admin.
"""

from __future__ import annotations

import logging
from typing import Any, Optional

logger = logging.getLogger("tools.approval")

_STRICTNESS = {"off": 0, "smart": 1, "manual": 2}


def _approvals_cfg() -> dict:
    from tools.approval_context import _get_approval_config
    return _get_approval_config() or {}


def _platform_extra(platform: str) -> dict:
    """The platform's config block merged with its ``extra`` sub-dict (both spellings
    reach ``PlatformConfig.extra`` in the gateway loader)."""
    from hermes_cli.config import load_config_readonly
    block = ((load_config_readonly() or {}).get("platforms") or {}).get(platform) or {}
    if not isinstance(block, dict):
        return {}
    merged = {k: v for k, v in block.items() if k != "extra"}
    extra = block.get("extra")
    if isinstance(extra, dict):
        merged.update(extra)
    return merged


def _session(name: str) -> str:
    from gateway.session_context import get_session_env
    return str(get_session_env(name, "") or "").strip()


def current_principal() -> Optional[tuple[str, str, str]]:
    """``(platform, user_id, scope)`` for a human messaging session, else None."""
    try:
        from gateway.session_context import session_is_messaging_surface
        if not session_is_messaging_surface():
            return None
    except Exception:
        return None
    platform = _session("HERMES_SESSION_PLATFORM").lower()
    if not platform:
        return None
    chat_type = _session("HERMES_SESSION_CHAT_TYPE").lower()
    scope = "dm" if chat_type in {"dm", "direct", "private", ""} else "group"
    return platform, _session("HERMES_SESSION_USER_ID"), scope


def is_non_admin_session() -> bool:
    """True only when admin gating is configured for this platform/scope and the
    current sender is not on the admin list."""
    principal = current_principal()
    if principal is None:
        return False
    platform, user_id, scope = principal
    from gateway.slash_access import policy_from_extra
    policy = policy_from_extra(_platform_extra(platform), scope)
    return policy.enabled and not policy.is_admin(user_id)


def effective_mode(base_mode: str, approvals_cfg: Optional[dict] = None) -> str:
    """Escalate ``base_mode`` for a non-admin sender; unchanged for everyone else.

    Fails CLOSED: if ``non_admin_mode`` is configured and the principal check itself
    errors, the session is treated as non-admin rather than silently inheriting
    ``approvals.mode: off``."""
    try:
        cfg = approvals_cfg if approvals_cfg is not None else _approvals_cfg()
        wanted = str(cfg.get("non_admin_mode") or "").strip().lower()
    except Exception:
        return base_mode
    if wanted not in ("smart", "manual"):
        return base_mode
    try:
        non_admin = is_non_admin_session()
    except Exception as exc:
        logger.warning("approval principal check failed (%s) — treating the sender as non-admin", exc)
        non_admin = True
    if non_admin and _STRICTNESS.get(wanted, 0) > _STRICTNESS.get(base_mode, 2):
        return wanted
    return base_mode


def non_admin_deny_globs(approvals_cfg: Optional[dict] = None) -> list[str]:
    """Extra deny globs for a non-admin sender ([] for everyone else). Cheap when unset:
    the admin check only runs if rules are configured."""
    try:
        cfg = approvals_cfg if approvals_cfg is not None else _approvals_cfg()
        raw = cfg.get("non_admin_deny") or []
        globs = [p.strip() for p in raw if isinstance(p, str) and p.strip()]
        if not globs:
            return []
        return globs if is_non_admin_session() else []
    except Exception as exc:
        logger.warning("non_admin_deny check failed (%s) — applying the rules", exc)
        try:
            cfg = approvals_cfg if approvals_cfg is not None else _approvals_cfg()
            return [p.strip() for p in (cfg.get("non_admin_deny") or []) if isinstance(p, str) and p.strip()]
        except Exception:
            return []


def approver_chat_for_current_session() -> Optional[str]:
    """The owner's chat id to route this session's approval card to, or None to keep
    the upstream behaviour (card goes to the requester's own chat)."""
    try:
        principal = current_principal()
        if principal is None or not is_non_admin_session():
            return None
        routes: Any = _approvals_cfg().get("non_admin_approver_chat") or {}
        if not isinstance(routes, dict):
            return None
        chat = routes.get(principal[0])
        chat = str(chat).strip() if chat is not None else ""
        return chat or None
    except Exception as exc:
        logger.warning("approver routing check failed: %s", exc)
        return None


def requester_label() -> str:
    """``name (id)`` of the current sender, for the owner's approval card."""
    try:
        name, uid = _session("HERMES_SESSION_USER_NAME"), _session("HERMES_SESSION_USER_ID")
        return f"{name} ({uid})" if name and uid else (name or uid or "unknown user")
    except Exception:
        return "unknown user"
