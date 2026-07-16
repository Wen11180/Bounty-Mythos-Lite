"""Browser Demo dual-session intake for black-box differential hunting.

Product-shaped secret plane + session broker. Secrets stay in ephemeral
session handles (never pickled / never exported). Demo request traces are
normalized into the same ObservedWorkflowModel as HAR intake, then may run
plan-only or local-lab observe. No Playwright and no remote targets here.
"""

from __future__ import annotations

from typing import Any, Mapping
from urllib.parse import urlsplit, urlunsplit

from app.black_box_hunter import ObservedWorkflowModel
from app.black_box_hunter.har_intake import (
    build_observed_workflow_model_from_role_hars,
    run_har_plan_only_pipeline,
)
from app.black_box_hunter.local_lab import LocalLabMode
from app.black_box_hunter.local_lab_pipeline import run_har_local_lab_pipeline


class EphemeralSessionHandle:
    """Opaque dual-role browser session handle.

    Auth material is process-local only. The handle refuses pickling and never
    appears in research-plane projections.
    """

    __slots__ = (
        "session_ref",
        "account_alias",
        "role_alias",
        "role_rank",
        "_auth_headers",
        "_auth_cookies",
        "_demo_events",
        "_closed",
    )

    def __init__(
        self,
        *,
        session_ref: str,
        account_alias: str,
        role_alias: str,
        role_rank: int = 0,
        auth_headers: Mapping[str, str] | None = None,
        auth_cookies: Mapping[str, str] | None = None,
    ) -> None:
        if not session_ref or not account_alias or not role_alias:
            raise ValueError("session_identity_required")
        self.session_ref = session_ref
        self.account_alias = account_alias
        self.role_alias = role_alias
        self.role_rank = role_rank
        self._auth_headers = {
            str(k): str(v) for k, v in dict(auth_headers or {}).items()
        }
        self._auth_cookies = {
            str(k): str(v) for k, v in dict(auth_cookies or {}).items()
        }
        self._demo_events: list[dict[str, Any]] = []
        self._closed = False

    def __reduce__(self):
        raise TypeError("ephemeral_session_handle_not_serializable")

    def close(self) -> None:
        self._auth_headers.clear()
        self._auth_cookies.clear()
        self._demo_events.clear()
        self._closed = True

    @property
    def closed(self) -> bool:
        return self._closed

    def has_auth_material(self) -> bool:
        return bool(self._auth_headers or self._auth_cookies)

    def record_demo_request(
        self,
        *,
        method: str,
        url: str,
        status: int = 200,
    ) -> None:
        """Record one operator-demonstrated post-login request (research plane).

        Auth headers/cookies are never copied into the event list.
        """
        if self._closed:
            raise ValueError("session_closed")
        method_u = str(method or "").upper()
        url_s = str(url or "")
        if not method_u or not url_s:
            raise ValueError("demo_request_method_url_required")
        # Login capture is forbidden by design.
        lower = url_s.lower()
        if any(token in lower for token in ("/login", "/signin", "/oauth", "/auth/")):
            raise ValueError("login_traffic_not_recordable")
        self._demo_events.append(
            {
                "method": method_u,
                "url": _strip_query_and_fragment(url_s),
                "status": int(status),
            }
        )

    def demo_events(self) -> list[dict[str, Any]]:
        return [dict(event) for event in self._demo_events]

    def to_redacted_har(self) -> dict[str, Any]:
        """Project demo events into a research-safe HAR (no auth material)."""
        if self._closed:
            raise ValueError("session_closed")
        entries: list[dict[str, Any]] = []
        for event in self._demo_events:
            entries.append(
                {
                    "request": {
                        "method": event["method"],
                        "url": event["url"],
                        # Explicit empty: secrets stay on the handle only.
                        "headers": [],
                        "queryString": [],
                    },
                    "response": {
                        "status": event["status"],
                        "headers": [],
                        "content": {"mimeType": "application/json", "text": ""},
                    },
                }
            )
        return {"log": {"version": "1.2", "entries": entries}}

    def safe_projection(self) -> dict[str, Any]:
        return {
            "session_ref": self.session_ref,
            "account_alias": self.account_alias,
            "role_alias": self.role_alias,
            "role_rank": self.role_rank,
            "closed": self._closed,
            "demo_event_count": len(self._demo_events),
            "has_auth_material": self.has_auth_material(),
            # Never export header/cookie keys or values.
            "auth_material_exported": False,
        }


class EphemeralSessionBroker:
    """Owns two isolated demo sessions (session_a / session_b by convention)."""

    __slots__ = ("_sessions",)

    def __init__(self) -> None:
        self._sessions: dict[str, EphemeralSessionHandle] = {}

    def __reduce__(self):
        raise TypeError("ephemeral_session_broker_not_serializable")

    def open_session(
        self,
        *,
        session_ref: str,
        account_alias: str,
        role_alias: str,
        role_rank: int = 0,
        auth_headers: Mapping[str, str] | None = None,
        auth_cookies: Mapping[str, str] | None = None,
    ) -> EphemeralSessionHandle:
        if session_ref in self._sessions and not self._sessions[session_ref].closed:
            raise ValueError("session_ref_already_open")
        handle = EphemeralSessionHandle(
            session_ref=session_ref,
            account_alias=account_alias,
            role_alias=role_alias,
            role_rank=role_rank,
            auth_headers=auth_headers,
            auth_cookies=auth_cookies,
        )
        self._sessions[session_ref] = handle
        return handle

    def get(self, session_ref: str) -> EphemeralSessionHandle:
        handle = self._sessions.get(session_ref)
        if handle is None or handle.closed:
            raise ValueError("session_not_active")
        return handle

    def close_session(self, session_ref: str) -> None:
        handle = self._sessions.get(session_ref)
        if handle is not None:
            handle.close()

    def destroy_all(self) -> None:
        for handle in list(self._sessions.values()):
            handle.close()
        self._sessions.clear()

    def active_session_refs(self) -> list[str]:
        return sorted(
            ref for ref, handle in self._sessions.items() if not handle.closed
        )

    def safe_projection(self) -> dict[str, Any]:
        return {
            "active_session_refs": self.active_session_refs(),
            "sessions": [
                handle.safe_projection()
                for ref, handle in sorted(self._sessions.items())
                if not handle.closed
            ],
        }


def demo_package_to_role_hars(
    demo_a: dict[str, Any],
    demo_b: dict[str, Any],
) -> tuple[dict[str, dict[str, Any]], dict[str, str], dict[str, str], dict[str, int]]:
    """Normalize two demo JSON packages into role HARs + alias maps.

    Demo package shape::

        {
          "account_alias": "account_a",
          "role_alias": "member",
          "role_rank": 10,
          "events": [{"method": "GET", "url": "...", "status": 200}],
          # optional auth_headers / auth_cookies — accepted only into memory,
          # never into HAR projection
        }
    """
    session_a, har_a, acc_a, role_a, rank_a = _package_to_session_and_har(
        demo_a,
        default_ref="session_a",
        default_account="account_a",
        default_role="member",
        default_rank=10,
    )
    session_b, har_b, acc_b, role_b, rank_b = _package_to_session_and_har(
        demo_b,
        default_ref="session_b",
        default_account="account_b",
        default_role="viewer",
        default_rank=1,
    )
    # Drop in-memory secrets immediately after HAR projection for file intake.
    session_a.close()
    session_b.close()
    role_hars = {"role_a": har_a, "role_b": har_b}
    account_aliases = {"role_a": acc_a, "role_b": acc_b}
    role_aliases = {"role_a": role_a, "role_b": role_b}
    role_ranks = {"role_a": rank_a, "role_b": rank_b}
    return role_hars, account_aliases, role_aliases, role_ranks


def build_observed_workflow_model_from_browser_demo(
    demo_a: dict[str, Any],
    demo_b: dict[str, Any],
) -> ObservedWorkflowModel:
    """Build the shared ObservedWorkflowModel from two browser-demo packages."""
    role_hars, account_aliases, role_aliases, role_ranks = demo_package_to_role_hars(
        demo_a, demo_b
    )
    return build_observed_workflow_model_from_role_hars(
        role_hars,
        account_aliases=account_aliases,
        role_aliases=role_aliases,
        role_ranks=role_ranks,
    )


def build_observed_workflow_model_from_broker(
    broker: EphemeralSessionBroker,
    *,
    session_a_ref: str = "session_a",
    session_b_ref: str = "session_b",
) -> ObservedWorkflowModel:
    """Build model from two live broker sessions (secrets stay on handles)."""
    handle_a = broker.get(session_a_ref)
    handle_b = broker.get(session_b_ref)
    role_hars = {
        "role_a": handle_a.to_redacted_har(),
        "role_b": handle_b.to_redacted_har(),
    }
    return build_observed_workflow_model_from_role_hars(
        role_hars,
        account_aliases={
            "role_a": handle_a.account_alias,
            "role_b": handle_b.account_alias,
        },
        role_aliases={
            "role_a": handle_a.role_alias,
            "role_b": handle_b.role_alias,
        },
        role_ranks={
            "role_a": handle_a.role_rank,
            "role_b": handle_b.role_rank,
        },
    )


def run_browser_demo_plan_only_pipeline(
    demo_a: dict[str, Any],
    demo_b: dict[str, Any],
) -> dict[str, Any]:
    """Browser demo dual intake -> plan-only candidates (no live requests)."""
    role_hars, account_aliases, role_aliases, role_ranks = demo_package_to_role_hars(
        demo_a, demo_b
    )
    result = run_har_plan_only_pipeline(
        role_hars,
        account_aliases=account_aliases,
        role_aliases=role_aliases,
        role_ranks=role_ranks,
    )
    result = dict(result)
    result["schema_version"] = "browser_demo_plan_only_pipeline_v1"
    result["source"] = "browser_demo"
    result["role_bindings"] = [
        {
            "role_alias": role_aliases["role_a"],
            "session_ref": "session_a",
            "account_alias": account_aliases["role_a"],
        },
        {
            "role_alias": role_aliases["role_b"],
            "session_ref": "session_b",
            "account_alias": account_aliases["role_b"],
        },
    ]
    result["raw_secrets_persisted"] = False
    result["auth_material_exported"] = False
    return result


def run_browser_demo_local_lab_pipeline(
    demo_a: dict[str, Any],
    demo_b: dict[str, Any],
    *,
    mode: LocalLabMode = "bola",
    local_lab: bool = True,
    trial_classes: set[str] | None = None,
) -> dict[str, Any]:
    """Browser demo dual intake -> local-lab observe (same engine as HAR).

    Requires ``local_lab=True``. Remote observation is intentionally unsupported.
    """
    if not local_lab:
        raise ValueError("local_lab_flag_required")
    role_hars, account_aliases, role_aliases, role_ranks = demo_package_to_role_hars(
        demo_a, demo_b
    )
    result = run_har_local_lab_pipeline(
        role_hars,
        mode=mode,
        local_lab=True,
        trial_classes=trial_classes or {"cross_account_object_swap"},
        account_aliases=account_aliases,
        role_aliases=role_aliases,
        role_ranks=role_ranks,
    )
    result = dict(result)
    result["schema_version"] = "browser_demo_local_lab_pipeline_v1"
    result["source"] = "browser_demo"
    result["role_bindings"] = [
        {
            "role_alias": role_aliases["role_a"],
            "session_ref": "session_a",
            "account_alias": account_aliases["role_a"],
        },
        {
            "role_alias": role_aliases["role_b"],
            "session_ref": "session_b",
            "account_alias": account_aliases["role_b"],
        },
    ]
    result["raw_secrets_persisted"] = False
    result["auth_material_exported"] = False
    return result


def _package_to_session_and_har(
    package: dict[str, Any],
    *,
    default_ref: str,
    default_account: str,
    default_role: str,
    default_rank: int,
) -> tuple[EphemeralSessionHandle, dict[str, Any], str, str, int]:
    if not isinstance(package, dict):
        raise ValueError("demo_package_object_required")
    account_alias = str(package.get("account_alias") or default_account)
    role_alias = str(package.get("role_alias") or default_role)
    role_rank_raw = package.get("role_rank", default_rank)
    try:
        role_rank = int(role_rank_raw)
    except (TypeError, ValueError) as error:
        raise ValueError("demo_role_rank_invalid") from error
    session_ref = str(package.get("session_ref") or default_ref)
    auth_headers = package.get("auth_headers")
    auth_cookies = package.get("auth_cookies")
    if auth_headers is not None and not isinstance(auth_headers, Mapping):
        raise ValueError("demo_auth_headers_mapping_required")
    if auth_cookies is not None and not isinstance(auth_cookies, Mapping):
        raise ValueError("demo_auth_cookies_mapping_required")
    events = package.get("events")
    if not isinstance(events, list) or not events:
        raise ValueError("demo_events_required")
    handle = EphemeralSessionHandle(
        session_ref=session_ref,
        account_alias=account_alias,
        role_alias=role_alias,
        role_rank=role_rank,
        auth_headers=auth_headers,
        auth_cookies=auth_cookies,
    )
    for item in events:
        if not isinstance(item, dict):
            raise ValueError("demo_event_object_required")
        _reject_event_secrets(item)
        handle.record_demo_request(
            method=str(item.get("method") or ""),
            url=str(item.get("url") or ""),
            status=int(item.get("status") or 200),
        )
    har = handle.to_redacted_har()
    return handle, har, account_alias, role_alias, role_rank


def _reject_event_secrets(event: dict[str, Any]) -> None:
    forbidden_keys = {
        "headers",
        "cookies",
        "cookie",
        "authorization",
        "auth_headers",
        "auth_cookies",
        "set-cookie",
        "body",
        "postdata",
        "response_body",
    }
    lower_keys = {str(k).lower() for k in event}
    if lower_keys & forbidden_keys:
        raise ValueError("demo_event_must_not_carry_secrets_or_bodies")


def _strip_query_and_fragment(url: str) -> str:
    parsed = urlsplit(url)
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path or "/", "", ""))
