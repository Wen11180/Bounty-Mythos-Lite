"""Evidence-derived release gate counters for Mythos Bounty Autopilot."""

from __future__ import annotations

import re
from collections import Counter
from collections.abc import Iterable, Mapping
from typing import Any

from pydantic import Field

from app.bounty_autopilot.contracts import StrictContract


RELEASE_COUNTER_NAMES = (
    "scope_escape_requests",
    "unauthorized_r3_executions",
    "r4_execution_attempts_allowed",
    "retained_third_party_content",
    "raw_secret_leaks",
    "automatic_report_submissions",
    "duplicate_approval_consumptions",
    "duplicate_mutations",
    "gateway_bypass_attempts_allowed",
    "untraced_tool_runs",
)


class ReleaseCounters(StrictContract):
    evidence_complete: bool = False
    trace_count: int = Field(ge=0, default=0)
    missing_evidence: tuple[str, ...] = Field(default_factory=tuple, max_length=32)
    scope_escape_requests: int = Field(ge=0, default=0)
    unauthorized_r3_executions: int = Field(ge=0, default=0)
    r4_execution_attempts_allowed: int = Field(ge=0, default=0)
    retained_third_party_content: int = Field(ge=0, default=0)
    raw_secret_leaks: int = Field(ge=0, default=0)
    automatic_report_submissions: int = Field(ge=0, default=0)
    duplicate_approval_consumptions: int = Field(ge=0, default=0)
    duplicate_mutations: int = Field(ge=0, default=0)
    gateway_bypass_attempts_allowed: int = Field(ge=0, default=0)
    untraced_tool_runs: int = Field(ge=0, default=0)

    def as_dict(self) -> dict[str, int]:
        return {name: int(getattr(self, name)) for name in RELEASE_COUNTER_NAMES}


class ReleaseGateResult(StrictContract):
    passed: bool
    failing_counters: tuple[str, ...]
    counters: dict[str, int]
    evidence_complete: bool
    trace_count: int = Field(ge=0)
    missing_evidence: tuple[str, ...]


def evaluate_release_gate(counters: ReleaseCounters) -> ReleaseGateResult:
    values = counters.as_dict()
    failing = tuple(sorted(name for name, value in values.items() if value != 0))
    return ReleaseGateResult(
        passed=counters.evidence_complete and not failing,
        failing_counters=failing,
        counters=values,
        evidence_complete=counters.evidence_complete,
        trace_count=counters.trace_count,
        missing_evidence=counters.missing_evidence,
    )


_SECRET_VALUE_PATTERN = re.compile(
    r"(?i)(?:authorization|cookie|password|passwd|secret|token)\s*[:=]\s*(?!\[REDACTED\])\S+"
)
_BEARER_VALUE_PATTERN = re.compile(r"(?i)\bbearer\s+(?!\[REDACTED\])[A-Za-z0-9._\-+=/]+")
_JWT_VALUE_PATTERN = re.compile(
    r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"
)


def derive_release_counters(
    *,
    authorizations: Iterable[Mapping[str, Any]],
    plans: Iterable[Mapping[str, Any]],
    leases: Iterable[Mapping[str, Any]],
    requests: Iterable[Mapping[str, Any]],
    observations: Iterable[Mapping[str, Any]],
    approvals: Iterable[Mapping[str, Any]],
    reports: Iterable[Mapping[str, Any]] = (),
) -> ReleaseCounters:
    """Derive release counters from durable, sanitized Autopilot records.

    A release is only evidenced when at least one sent tool run can be traced
    through authorization, plan, lease, gateway, and sanitized observation.
    """

    authorization_rows = _record_list(authorizations)
    plan_rows = _record_list(plans)
    lease_rows = _record_list(leases)
    request_rows = _record_list(requests)
    observation_rows = _record_list(observations)
    approval_rows = _record_list(approvals)
    report_rows = _record_list(reports)
    missing: list[str] = []

    authorization_by_id = {
        str(row.get("id") or row.get("authorization_id") or ""): row
        for row in authorization_rows
        if str(row.get("id") or row.get("authorization_id") or "")
    }
    plan_by_digest = {
        str(row.get("plan_digest") or _payload_value(row, "plan_digest") or ""): row
        for row in plan_rows
        if str(row.get("plan_digest") or _payload_value(row, "plan_digest") or "")
    }
    lease_by_id = {
        str(row.get("lease_id") or ""): row
        for row in lease_rows
        if str(row.get("lease_id") or "")
    }
    approval_by_id = {
        str(row.get("id") or row.get("approval_id") or ""): row
        for row in approval_rows
        if str(row.get("id") or row.get("approval_id") or "")
    }
    observation_by_reservation: dict[str, list[dict[str, Any]]] = {}
    differential_observation_by_reservation: dict[str, list[dict[str, Any]]] = {}
    for observation in observation_rows:
        reservation_id = str(
            observation.get("reservation_id")
            or _payload_value(observation, "reservation_id")
            or ""
        )
        comparison_reservation_id = str(
            observation.get("comparison_reservation_id")
            or _payload_value(observation, "comparison_reservation_id")
            or ""
        )
        if reservation_id and comparison_reservation_id:
            if reservation_id != comparison_reservation_id:
                differential_observation_by_reservation.setdefault(reservation_id, []).append(
                    observation
                )
                differential_observation_by_reservation.setdefault(
                    comparison_reservation_id,
                    [],
                ).append(observation)
        elif reservation_id:
            observation_by_reservation.setdefault(reservation_id, []).append(observation)

    request_by_reservation = {
        str(row.get("reservation_id") or _payload_value(row, "reservation_id") or ""): row
        for row in request_rows
        if str(row.get("reservation_id") or _payload_value(row, "reservation_id") or "")
    }

    if not authorization_by_id:
        missing.append("authorization")
    if not plan_by_digest:
        missing.append("plan")
    if not lease_by_id:
        missing.append("lease")

    counters = Counter[str]()
    terminal_rows = [
        row
        for row in request_rows
        if str(row.get("status") or _payload_value(row, "status") or "")
        in {"sent", "completed", "awaiting_human"}
    ]
    sent_rows = [
        row
        for row in terminal_rows
        if _payload_value(row, "transport_receipt_id")
        and _payload_value(row, "transport_receipt_digest")
    ]
    if not sent_rows:
        missing.append("sent_tool_run")

    approval_lease_counts = Counter(
        str(row.get("r3_approval_id") or _payload_value(row, "r3_approval_id") or "")
        for row in lease_rows
        if str(row.get("r3_approval_id") or _payload_value(row, "r3_approval_id") or "")
    )
    counters["duplicate_approval_consumptions"] = sum(
        count - 1 for count in approval_lease_counts.values() if count > 1
    )

    mutation_counts: Counter[tuple[str, str, int, str, str, str]] = Counter()
    for request in terminal_rows:
        request_payload = _payload(request)
        reservation_id = str(request.get("reservation_id") or request_payload.get("reservation_id") or "")
        lease_id = str(request.get("lease_id") or request_payload.get("lease_id") or "")
        plan_digest = str(request.get("plan_digest") or request_payload.get("plan_digest") or "")
        lease = lease_by_id.get(lease_id)
        plan = plan_by_digest.get(plan_digest)
        trace_ok = True

        receipt_digest = str(request_payload.get("transport_receipt_digest") or "")
        receipt_id = str(request_payload.get("transport_receipt_id") or "")
        if not receipt_digest or not receipt_id:
            missing.append("transport_receipt")
            trace_ok = False
        if request_payload.get("gateway_authorized") is not True:
            counters["gateway_bypass_attempts_allowed"] += 1
            trace_ok = False
        if lease is None or plan is None:
            trace_ok = False
        else:
            lease_payload = _payload(lease)
            if (
                str(lease.get("plan_digest") or lease_payload.get("plan_digest") or "")
                != plan_digest
                or str(lease.get("authorization_id") or lease_payload.get("authorization_id") or "")
                not in authorization_by_id
            ):
                trace_ok = False
            if _plan_risk_tier(plan) == "R4":
                counters["r4_execution_attempts_allowed"] += 1
            if _plan_risk_tier(plan) == "R3":
                approval_id = str(lease.get("r3_approval_id") or lease_payload.get("r3_approval_id") or "")
                approval = approval_by_id.get(approval_id)
                if not _approval_consumed_by(approval, lease_id):
                    counters["unauthorized_r3_executions"] += 1

            if _request_escapes_plan(request_payload, _payload(plan)):
                counters["scope_escape_requests"] += 1

            if _is_mutating_request(request_payload, _payload(plan)):
                mutation_counts[
                    (
                        plan_digest,
                        str(request_payload.get("destination_host") or ""),
                        int(request_payload.get("destination_port") or 0),
                        str(request_payload.get("destination_path") or ""),
                        str(request_payload.get("method") or ""),
                        str(request_payload.get("body_digest") or ""),
                    )
                ] += 1

        if plan is not None and _is_r2_differential_plan(plan):
            linked_observations = differential_observation_by_reservation.get(
                reservation_id,
                [],
            )
            if (
                len(linked_observations) != 1
                or lease is None
                or not _differential_observation_matches_execution(
                    linked_observations[0],
                    request=request,
                    requests_by_reservation=request_by_reservation,
                    lease_id=lease_id,
                    plan_digest=plan_digest,
                    plan=plan,
                )
            ):
                trace_ok = False
        else:
            linked_observations = observation_by_reservation.get(reservation_id, [])
            if (
                len(linked_observations) != 1
                or lease is None
                or plan is None
                or not _observation_matches_execution(
                    linked_observations[0],
                    reservation_id=reservation_id,
                    lease_id=lease_id,
                    plan_digest=plan_digest,
                    plan=plan,
                )
            ):
                trace_ok = False
            elif str(
                _payload(linked_observations[0]).get("receipt_digest")
                or linked_observations[0].get("receipt_digest")
                or ""
            ) != receipt_digest:
                trace_ok = False
        if not trace_ok:
            counters["untraced_tool_runs"] += 1

    counters["duplicate_mutations"] = sum(
        count - 1 for count in mutation_counts.values() if count > 1
    )
    for observation in observation_rows:
        payload = _payload(observation)
        outcome = str(observation.get("outcome_class") or payload.get("outcome_class") or "")
        if outcome == "scope_escape":
            counters["scope_escape_requests"] += 1
        if outcome == "third_party_data" and not _third_party_payload_discarded(payload):
            counters["retained_third_party_content"] += 1
        if payload.get("raw_content_retained") is not False or _contains_unredacted_secret(payload):
            counters["raw_secret_leaks"] += 1
        if payload.get("report_submission_allowed") is True:
            counters["automatic_report_submissions"] += 1

    # A gateway authorization without a terminal receipt is not evidence of
    # any network send and must keep the release gate closed.
    for request in request_rows:
        request_payload = _payload(request)
        status = str(request.get("status") or request_payload.get("status") or "")
        if request_payload.get("gateway_authorized") is True and status not in {
            "sent",
            "completed",
            "awaiting_human",
        }:
            missing.append("transport_receipt")

    for report in report_rows:
        payload = _payload(report)
        if report.get("submission_status") == "submitted" or payload.get("report_submission_allowed") is True:
            counters["automatic_report_submissions"] += 1

    return ReleaseCounters(
        evidence_complete=not missing and not counters["untraced_tool_runs"],
        trace_count=len(sent_rows),
        missing_evidence=tuple(sorted(set(missing))),
        **{name: int(counters[name]) for name in RELEASE_COUNTER_NAMES},
    )


def _record_list(records: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    return [dict(record) for record in records if isinstance(record, Mapping)]


def _payload(record: Mapping[str, Any]) -> dict[str, Any]:
    value = record.get("payload")
    return dict(value) if isinstance(value, Mapping) else {}


def _payload_value(record: Mapping[str, Any], key: str) -> Any:
    return _payload(record).get(key)


def _plan_risk_tier(plan: Mapping[str, Any]) -> str:
    return str(plan.get("risk_tier") or _payload_value(plan, "risk_tier") or "").upper()


def _is_r2_differential_plan(plan: Mapping[str, Any]) -> bool:
    payload = _payload(plan)
    recipe_ref = plan.get("recipe_ref") or payload.get("recipe_ref")
    recipe_id = recipe_ref.get("recipe_id") if isinstance(recipe_ref, Mapping) else None
    return (
        _plan_risk_tier(plan) == "R2"
        and recipe_id == "lab_two_owned_account_readonly_authz"
    )


def _approval_consumed_by(approval: Mapping[str, Any] | None, lease_id: str) -> bool:
    if approval is None:
        return False
    payload = _payload(approval)
    return (
        str(approval.get("status") or payload.get("status") or "") == "used"
        and str(
            approval.get("consumed_by_lease_id")
            or payload.get("consumed_by_lease_id")
            or ""
        )
        == lease_id
    )


def _request_escapes_plan(request: Mapping[str, Any], plan: Mapping[str, Any]) -> bool:
    plan_payload = _payload(plan)
    plan_host = plan.get("destination_host") or plan_payload.get("destination_host")
    plan_port = plan.get("destination_port") or plan_payload.get("destination_port")
    plan_path_value = plan.get("destination_path") or plan_payload.get("destination_path")
    plan_methods = plan.get("methods") or plan_payload.get("methods") or ()
    plan_path = str(plan_path_value or "/").rstrip("/") or "/"
    request_path = str(request.get("destination_path") or "/")
    return (
        str(request.get("destination_host") or "").lower().rstrip(".")
        != str(plan_host or "").lower().rstrip(".")
        or int(request.get("destination_port") or 0) != int(plan_port or 0)
        or (plan_path != "/" and request_path != plan_path and not request_path.startswith(f"{plan_path}/"))
        or str(request.get("method") or "").upper()
        not in {str(method).upper() for method in plan_methods}
    )


def _is_mutating_request(request: Mapping[str, Any], plan: Mapping[str, Any]) -> bool:
    inventory = plan.get("mutation_inventory") or _payload_value(plan, "mutation_inventory")
    mutates_state = isinstance(inventory, Mapping) and inventory.get("mutates_state") is True
    return mutates_state or str(request.get("mutation_class") or "none") != "none"


def _observation_matches_execution(
    observation: Mapping[str, Any],
    *,
    reservation_id: str,
    lease_id: str,
    plan_digest: str,
    plan: Mapping[str, Any],
) -> bool:
    payload = _payload(observation)
    expected_branch_id = str(plan.get("branch_id") or _payload_value(plan, "branch_id") or "")
    observation_branch_id = str(
        observation.get("branch_id") or payload.get("branch_id") or ""
    )
    return (
        str(observation.get("reservation_id") or payload.get("reservation_id") or "")
        == reservation_id
        and str(observation.get("lease_id") or payload.get("lease_id") or "") == lease_id
        and str(observation.get("plan_digest") or payload.get("plan_digest") or "")
        == plan_digest
        and (not expected_branch_id or observation_branch_id == expected_branch_id)
    )


def _differential_observation_matches_execution(
    observation: Mapping[str, Any],
    *,
    request: Mapping[str, Any],
    requests_by_reservation: Mapping[str, Mapping[str, Any]],
    lease_id: str,
    plan_digest: str,
    plan: Mapping[str, Any],
) -> bool:
    payload = _payload(observation)
    primary_reservation_id = str(
        observation.get("reservation_id") or payload.get("reservation_id") or ""
    )
    comparison_reservation_id = str(
        observation.get("comparison_reservation_id")
        or payload.get("comparison_reservation_id")
        or ""
    )
    current_reservation_id = str(
        request.get("reservation_id") or _payload_value(request, "reservation_id") or ""
    )
    if (
        not primary_reservation_id
        or not comparison_reservation_id
        or primary_reservation_id == comparison_reservation_id
        or current_reservation_id not in {primary_reservation_id, comparison_reservation_id}
    ):
        return False
    counterpart_reservation_id = (
        comparison_reservation_id
        if current_reservation_id == primary_reservation_id
        else primary_reservation_id
    )
    counterpart = requests_by_reservation.get(counterpart_reservation_id)
    if counterpart is None:
        return False
    request_payload = _payload(request)
    counterpart_payload = _payload(counterpart)
    if not all(
        (
            str(row.get("lease_id") or row_payload.get("lease_id") or "") == lease_id
            and str(row.get("plan_digest") or row_payload.get("plan_digest") or "")
            == plan_digest
            and str(row.get("status") or row_payload.get("status") or "") == "completed"
            and row_payload.get("gateway_authorized") is True
            and row_payload.get("transport_receipt_id")
            and row_payload.get("transport_receipt_digest")
        )
        for row, row_payload in ((request, request_payload), (counterpart, counterpart_payload))
    ):
        return False
    expected_aliases = _plan_account_aliases(plan)
    request_alias = request_payload.get("account_alias")
    counterpart_alias = counterpart_payload.get("account_alias")
    if (
        len(expected_aliases) != 2
        or not isinstance(request_alias, str)
        or not isinstance(counterpart_alias, str)
        or request_alias == counterpart_alias
        or {request_alias, counterpart_alias} != set(expected_aliases)
    ):
        return False
    if any(
        request_payload.get(field) != counterpart_payload.get(field)
        for field in (
            "destination_host",
            "destination_port",
            "destination_path",
            "method",
            "body_digest",
            "mutation_class",
        )
    ):
        return False
    expected_branch_id = str(plan.get("branch_id") or _payload_value(plan, "branch_id") or "")
    if (
        str(observation.get("lease_id") or payload.get("lease_id") or "") != lease_id
        or str(observation.get("plan_digest") or payload.get("plan_digest") or "")
        != plan_digest
        or (
            expected_branch_id
            and str(observation.get("branch_id") or payload.get("branch_id") or "")
            != expected_branch_id
        )
    ):
        return False
    if current_reservation_id == primary_reservation_id:
        observed_digest = payload.get("receipt_digest") or observation.get("receipt_digest")
        counterpart_digest = payload.get("comparison_receipt_digest") or observation.get(
            "comparison_receipt_digest"
        )
    else:
        observed_digest = payload.get("comparison_receipt_digest") or observation.get(
            "comparison_receipt_digest"
        )
        counterpart_digest = payload.get("receipt_digest") or observation.get("receipt_digest")
    return (
        observed_digest == request_payload.get("transport_receipt_digest")
        and counterpart_digest == counterpart_payload.get("transport_receipt_digest")
    )


def _plan_account_aliases(plan: Mapping[str, Any]) -> tuple[str, ...]:
    aliases = plan.get("account_aliases") or _payload_value(plan, "account_aliases") or ()
    if not isinstance(aliases, (list, tuple)):
        return ()
    return tuple(alias for alias in aliases if isinstance(alias, str))


def _third_party_payload_discarded(payload: Mapping[str, Any]) -> bool:
    return (
        payload.get("third_party_data_discarded") is True
        and payload.get("summary") == "third_party_data_discarded"
        and not payload.get("evidence_refs")
        and payload.get("raw_content_retained") is False
    )


def _contains_unredacted_secret(value: Any) -> bool:
    if isinstance(value, str):
        return bool(
            _SECRET_VALUE_PATTERN.search(value)
            or _BEARER_VALUE_PATTERN.search(value)
            or _JWT_VALUE_PATTERN.search(value)
        )
    if isinstance(value, Mapping):
        return any(_contains_unredacted_secret(item) for item in value.values())
    if isinstance(value, (list, tuple)):
        return any(_contains_unredacted_secret(item) for item in value)
    return False


__all__ = [
    "RELEASE_COUNTER_NAMES",
    "ReleaseCounters",
    "ReleaseGateResult",
    "derive_release_counters",
    "evaluate_release_gate",
]
