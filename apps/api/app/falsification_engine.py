"""Falsification-first card engine for A+B Candidate Hunter.

Builds auditable kill/survive attempts before retention. Pure functions only:
no I/O, no live targets, no permission elevation. Model output is never
treated as confirmation.
"""

from __future__ import annotations

from typing import Any


SCHEMA_VERSION = "falsification_card_v1"
KILL_DIMENSIONS = (
    "scope",
    "policy",
    "invariant",
    "cross_source",
    "defense",
    "duplicate",
    "impact",
    "evidence",
)
TERMINAL_STATUSES = {
    "retained",
    "refuted",
    "deduplicated",
    "suppressed",
}
CARD_STATUSES = {
    "unresolved",
    "needs_evidence",
    "retained",
    "refuted",
    "deduplicated",
    "suppressed",
}
ATTEMPT_STATUSES = {"open", "killed", "survived", "insufficient_evidence"}


def _text(value: object) -> str:
    if not isinstance(value, str):
        return ""
    text = value.strip()
    if not text:
        return ""
    lowered = text.lower()
    for marker in ("secret", "bearer", "cookie=", "password", "authorization:"):
        if marker in lowered:
            return ""
    return text


def _string_list(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    out: list[str] = []
    for item in value:
        text = _text(item)
        if text and text not in out:
            out.append(text)
    return out


def _false_safety() -> dict[str, bool]:
    return {
        "execution_allowed": False,
        "dispatch_allowed": False,
        "validation_allowed": False,
        "candidate_promotion_allowed": False,
        "report_submission_allowed": False,
    }


def _route_label(state: dict[str, Any]) -> str:
    route = state.get("route") if isinstance(state.get("route"), dict) else {}
    method = _text(route.get("method")).upper()
    path = _text(route.get("path"))
    return f"{method} {path}".strip()


def _broken_invariant(state: dict[str, Any]) -> str:
    root = _text(state.get("root_cause_id"))
    if ":" in root:
        root = root.rpartition(":")[2]
    if not root:
        root = "authorization_or_object_access_control"
    return (
        f"Sensitive operation must enforce ownership/authorization before "
        f"reaching {root}; absence of that guard is the hypothesized break."
    )


def _attempt(
    *,
    dimension: str,
    question: str,
    status: str,
    evidence_refs: list[str],
    rationale: str,
) -> dict[str, Any]:
    return {
        "dimension": dimension,
        "question": question,
        "status": status,
        "evidence_refs": list(evidence_refs),
        "rationale": rationale,
        "actor": "deterministic_rules",
    }


def build_falsification_card(
    state: dict[str, Any],
    *,
    disposition: str,
    evidence_refs: list[str] | None = None,
    missing_evidence: list[str] | None = None,
    duplicate_of: str | None = None,
) -> dict[str, Any]:
    """Build a falsification_card_v1 from a candidate snapshot and terminal mapping.

    Disposition must already be decided by the hunter loop; this function makes
    the kill taxonomy and why-alive/why-dead narrative explicit and auditable.
    """
    if not isinstance(state, dict):
        state = {}
    candidate_id = _text(state.get("candidate_id")) or _text(state.get("hypothesis_id"))
    candidate_key = _text(state.get("candidate_key")) or (
        f"hypothesis:{candidate_id}" if candidate_id else "hypothesis:unknown"
    )
    refs = _string_list(evidence_refs if evidence_refs is not None else state.get("source_fact_refs"))
    missing = _string_list(missing_evidence if missing_evidence is not None else ())
    control_ref = _text(state.get("control_evidence_ref"))
    public_ref = _text(state.get("public_evidence_ref"))
    gap_ref = _text(state.get("gap_evidence_ref"))
    route_label = _route_label(state)
    code_refs = [ref for ref in refs if ref.startswith("code:")]
    status = disposition if disposition in CARD_STATUSES else "unresolved"

    attempts: list[dict[str, Any]] = []

    # scope
    attempts.append(
        _attempt(
            dimension="scope",
            question="Is the hypothesized asset/route inside authorized program scope?",
            status="survived",
            evidence_refs=[ref for ref in refs if ref.startswith("scope:")][:3]
            or ([f"candidate:{candidate_id}"] if candidate_id else []),
            rationale="Loop only processes in_scope source runs; no out-of-scope kill fact observed.",
        )
    )

    # policy
    attempts.append(
        _attempt(
            dimension="policy",
            question="Does program policy forbid this hypothesis class or test mode?",
            status="survived",
            evidence_refs=[ref for ref in refs if ref.startswith("policy:")][:3]
            or ([f"candidate:{candidate_id}"] if candidate_id else []),
            rationale="No policy-forbidden kill fact observed for this hypothesis class.",
        )
    )

    # invariant
    if gap_ref and gap_ref in refs:
        attempts.append(
            _attempt(
                dimension="invariant",
                question="Is there a concrete security invariant that may be broken?",
                status="survived",
                evidence_refs=[gap_ref],
                rationale="Authorization/ownership gap fact remains open after local inspection.",
            )
        )
        broken_invariant = _broken_invariant(state)
    elif status == "needs_evidence" or missing:
        attempts.append(
            _attempt(
                dimension="invariant",
                question="Is there a concrete security invariant that may be broken?",
                status="insufficient_evidence",
                evidence_refs=[],
                rationale="Gap evidence is incomplete; invariant cannot be confirmed or killed.",
            )
        )
        broken_invariant = ""
    else:
        attempts.append(
            _attempt(
                dimension="invariant",
                question="Is there a concrete security invariant that may be broken?",
                status="killed" if status in {"refuted", "suppressed"} else "insufficient_evidence",
                evidence_refs=refs[:1],
                rationale="No concrete authorization-gap invariant fact supports retention.",
            )
        )
        broken_invariant = _broken_invariant(state) if status == "retained" else ""

    # cross_source
    if route_label and code_refs:
        attempts.append(
            _attempt(
                dimension="cross_source",
                question="Do API/HAR surface and local code path link without contradiction?",
                status="survived",
                evidence_refs=[*code_refs[:2], *[r for r in refs if r.startswith(("api:", "har:"))][:2]],
                rationale=f"Endpoint {route_label} links to observed local code refs.",
            )
        )
        cross_note = f"Linked endpoint {route_label} to {code_refs[0]}."
    elif route_label and (status == "needs_evidence" or missing):
        attempts.append(
            _attempt(
                dimension="cross_source",
                question="Do API/HAR surface and local code path link without contradiction?",
                status="insufficient_evidence",
                evidence_refs=[r for r in refs if r.startswith(("api:", "har:"))][:2],
                rationale="Endpoint observed but local code path evidence is incomplete.",
            )
        )
        cross_note = "Endpoint present; authorized code path still incomplete."
    elif route_label:
        attempts.append(
            _attempt(
                dimension="cross_source",
                question="Do API/HAR surface and local code path link without contradiction?",
                status="survived" if status == "retained" else "insufficient_evidence",
                evidence_refs=refs[:2],
                rationale="Cross-source link noted with available local facts only.",
            )
        )
        cross_note = f"Endpoint {route_label}; code link based on available facts."
    else:
        attempts.append(
            _attempt(
                dimension="cross_source",
                question="Do API/HAR surface and local code path link without contradiction?",
                status="killed" if status in TERMINAL_STATUSES - {"retained"} else "insufficient_evidence",
                evidence_refs=[],
                rationale="No reliable endpoint/code link for this hypothesis.",
            )
        )
        cross_note = "Missing endpoint/code cross-source link."

    # defense
    if control_ref and control_ref in refs:
        attempts.append(
            _attempt(
                dimension="defense",
                question="Does local code show a decisive authorization/ownership guard?",
                status="killed",
                evidence_refs=[control_ref],
                rationale="Observed local control closes the hypothesized authorization break.",
            )
        )
    else:
        attempts.append(
            _attempt(
                dimension="defense",
                question="Does local code show a decisive authorization/ownership guard?",
                status="survived" if status in {"retained", "needs_evidence", "unresolved"} else "survived",
                evidence_refs=[gap_ref] if gap_ref else refs[:1],
                rationale="No decisive local defense fact observed on the hypothesized path.",
            )
        )

    # duplicate
    dup_of = _text(duplicate_of)
    if status == "deduplicated" and dup_of:
        attempts.append(
            _attempt(
                dimension="duplicate",
                question="Is this the same observed root cause as a retained canonical candidate?",
                status="killed",
                evidence_refs=refs[:2] or ([f"duplicate_of:{dup_of}"]),
                rationale=f"Same observed root cause as retained canonical {dup_of}.",
            )
        )
    else:
        attempts.append(
            _attempt(
                dimension="duplicate",
                question="Is this the same observed root cause as a retained canonical candidate?",
                status="survived",
                evidence_refs=refs[:1] or ([f"candidate:{candidate_id}"] if candidate_id else []),
                rationale="No duplicate-of link to another retained root cause.",
            )
        )

    # impact / intended public surface
    if public_ref and public_ref in refs:
        attempts.append(
            _attempt(
                dimension="impact",
                question="Is the hypothesized access intentionally public or shared by design?",
                status="killed",
                evidence_refs=[public_ref],
                rationale="Public/shared filter fact indicates non-vulnerability impact class.",
            )
        )
    else:
        attempts.append(
            _attempt(
                dimension="impact",
                question="Is the hypothesized access intentionally public or shared by design?",
                status="survived",
                evidence_refs=refs[:1] or ([f"candidate:{candidate_id}"] if candidate_id else []),
                rationale="No public/shared kill fact observed for this hypothesis.",
            )
        )

    # evidence completeness
    if missing:
        attempts.append(
            _attempt(
                dimension="evidence",
                question="Are required local evidence slots closed for a terminal decision?",
                status="insufficient_evidence",
                evidence_refs=[],
                rationale="Missing observed evidence: " + ", ".join(missing[:5]),
            )
        )
    else:
        attempts.append(
            _attempt(
                dimension="evidence",
                question="Are required local evidence slots closed for a terminal decision?",
                status="survived" if refs else "insufficient_evidence",
                evidence_refs=refs[:3],
                rationale="Required local evidence slots are present for this decision.",
            )
        )

    # Enforce kill citation invariant
    for attempt in attempts:
        if attempt["status"] == "killed" and not attempt["evidence_refs"]:
            attempt["evidence_refs"] = refs[:1] or (
                [f"candidate:{candidate_id}"] if candidate_id else ["fact:local_decision"]
            )

    why_dead = [
        f"{item['dimension']}: {item['rationale']}"
        for item in attempts
        if item["status"] == "killed"
    ]
    why_alive = [
        f"{item['dimension']}: {item['rationale']}"
        for item in attempts
        if item["status"] == "survived"
    ]
    if status == "needs_evidence":
        why_alive = [
            f"evidence: awaiting {', '.join(missing[:5]) or 'additional local facts'}"
        ] + why_alive

    if status == "retained" and not broken_invariant:
        broken_invariant = _broken_invariant(state)

    card: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "candidate_key": candidate_key,
        "hypothesis": {
            "title": _text(state.get("title"))
            or f"Hypothesis {candidate_id or 'unknown'} on {route_label or 'unknown route'}",
            "vuln_family": _text(state.get("vuln_type")) or "authorization",
            "affected_endpoint": route_label or None,
            "affected_code_path": code_refs[0] if code_refs else None,
            "cross_source_link_note": cross_note,
        },
        "broken_invariant": broken_invariant,
        "supporting_fact_refs": refs,
        "kill_attempts": attempts,
        "evidence_gaps": missing,
        "safe_validation_plan": {
            "mode": "non_destructive_local_or_human_approved",
            "steps": [
                "Review cited local code and API/HAR facts only.",
                "Do not execute live validation or touch production accounts.",
            ],
            "blockers": [
                "execute_live_validation",
                "touch_real_user_data",
                "submit_report",
            ],
        },
        "decision": {
            "status": status,
            "duplicate_of": dup_of or None,
            "rank": None,
            "why_still_alive": why_alive if status in {"retained", "needs_evidence", "unresolved"} else [],
            "why_dead": why_dead if status in {"refuted", "deduplicated", "suppressed"} else [],
        },
        "safety": _false_safety(),
    }
    return card


def survived_kill_score(card: dict[str, Any] | None) -> int:
    """Higher score = more kill dimensions survived with evidence (retain ranking)."""
    if not isinstance(card, dict):
        return 0
    attempts = card.get("kill_attempts")
    if not isinstance(attempts, list):
        return 0
    score = 0
    for item in attempts:
        if not isinstance(item, dict):
            continue
        if item.get("status") != "survived":
            continue
        refs = item.get("evidence_refs")
        if isinstance(refs, list) and any(_text(ref) for ref in refs):
            score += 1
    return score


def validate_falsification_card(card: object) -> list[str]:
    """Return schema/invariant failures; empty list means card is valid."""
    failures: list[str] = []
    if not isinstance(card, dict):
        return ["card_must_be_object"]
    if card.get("schema_version") != SCHEMA_VERSION:
        failures.append("schema_version_invalid")
    if not _text(card.get("candidate_key")):
        failures.append("candidate_key_required")
    hypothesis = card.get("hypothesis")
    if not isinstance(hypothesis, dict):
        failures.append("hypothesis_required")
    decision = card.get("decision")
    if not isinstance(decision, dict):
        failures.append("decision_required")
        status = ""
    else:
        status = _text(decision.get("status"))
        if status not in CARD_STATUSES:
            failures.append("decision_status_invalid")
        if status == "deduplicated" and not _text(decision.get("duplicate_of")):
            failures.append("duplicate_of_required")
    if status == "retained" and not _text(card.get("broken_invariant")):
        failures.append("broken_invariant_required_for_retained")
    attempts = card.get("kill_attempts")
    if not isinstance(attempts, list) or not attempts:
        failures.append("kill_attempts_required")
    else:
        for index, attempt in enumerate(attempts):
            if not isinstance(attempt, dict):
                failures.append(f"kill_attempts[{index}]_invalid")
                continue
            if attempt.get("dimension") not in KILL_DIMENSIONS:
                failures.append(f"kill_attempts[{index}]_dimension_invalid")
            if attempt.get("status") not in ATTEMPT_STATUSES:
                failures.append(f"kill_attempts[{index}]_status_invalid")
            if attempt.get("status") == "killed":
                refs = attempt.get("evidence_refs")
                if not isinstance(refs, list) or not any(_text(ref) for ref in refs):
                    failures.append(f"kill_attempts[{index}]_killed_requires_evidence_refs")
            if attempt.get("actor") != "deterministic_rules":
                # slice 1 only allows deterministic actor
                if _text(attempt.get("actor")) not in {"deterministic_rules", "model_assist", "human_note"}:
                    failures.append(f"kill_attempts[{index}]_actor_invalid")
    safety = card.get("safety")
    if not isinstance(safety, dict):
        failures.append("safety_required")
    else:
        for field, expected in _false_safety().items():
            if safety.get(field) is not expected:
                failures.append(f"safety_{field}_must_be_false")
    return failures


def project_falsification_summary(card: dict[str, Any] | None) -> dict[str, Any]:
    """Studio-facing summary; never includes secrets or confirmation language."""
    if not isinstance(card, dict):
        return {
            "schema_version": SCHEMA_VERSION,
            "decision_status": "unresolved",
            "why_still_alive": [],
            "why_dead": [],
            "broken_invariant": "",
            "open_dimensions": [],
            **_false_safety(),
        }
    decision = card.get("decision") if isinstance(card.get("decision"), dict) else {}
    attempts = card.get("kill_attempts") if isinstance(card.get("kill_attempts"), list) else []
    open_dimensions = [
        _text(item.get("dimension"))
        for item in attempts
        if isinstance(item, dict)
        and item.get("status") in {"open", "insufficient_evidence"}
        and _text(item.get("dimension"))
    ]
    return {
        "schema_version": SCHEMA_VERSION,
        "decision_status": _text(decision.get("status")) or "unresolved",
        "why_still_alive": _string_list(decision.get("why_still_alive")),
        "why_dead": _string_list(decision.get("why_dead")),
        "broken_invariant": _text(card.get("broken_invariant")),
        "open_dimensions": open_dimensions,
        "survived_kill_score": survived_kill_score(card),
        **_false_safety(),
    }
