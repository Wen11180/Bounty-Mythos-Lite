"""Unit tests for falsification_card_v1 engine invariants."""

from __future__ import annotations

import json

from app.falsification_engine import (
    KILL_DIMENSIONS,
    SCHEMA_VERSION,
    build_falsification_card,
    project_falsification_summary,
    survived_kill_score,
    validate_falsification_card,
)


def _base_state(**overrides) -> dict:
    state = {
        "candidate_id": "H-001",
        "candidate_key": "pipeline_run:run-001+hypothesis:H-001",
        "vuln_type": "authorization",
        "root_cause_id": "missing_object_ownership_check:read_record",
        "route": {"method": "GET", "path": "/records/{record_id}"},
        "source_fact_refs": [
            "scope:scope_context",
            "policy:policy_context",
            "code:code.py:read_record",
            "api:GET:/records/{record_id}",
            "har:har_context",
        ],
        "gap_evidence_ref": "code:code.py:read_record",
    }
    state.update(overrides)
    return state


def test_retained_card_validates_and_requires_broken_invariant():
    card = build_falsification_card(
        _base_state(),
        disposition="retained",
        evidence_refs=_base_state()["source_fact_refs"],
    )
    assert validate_falsification_card(card) == []
    assert card["schema_version"] == SCHEMA_VERSION
    assert card["broken_invariant"]
    assert card["decision"]["status"] == "retained"
    assert card["decision"]["why_still_alive"]
    assert not card["decision"]["why_dead"]
    assert {item["dimension"] for item in card["kill_attempts"]} == set(KILL_DIMENSIONS)
    assert survived_kill_score(card) >= 5
    assert all(flag is False for flag in card["safety"].values())
    summary = project_falsification_summary(card)
    assert summary["decision_status"] == "retained"
    assert summary["why_still_alive"]


def test_refuted_card_kills_require_evidence_and_why_dead():
    control = "api:GET:/records/{record_id}:security_required"
    state = _base_state(
        control_evidence_ref=control,
        source_fact_refs=_base_state()["source_fact_refs"] + [control],
    )
    card = build_falsification_card(
        state,
        disposition="refuted",
        evidence_refs=[control],
    )
    assert validate_falsification_card(card) == []
    assert card["decision"]["status"] == "refuted"
    assert card["decision"]["why_dead"]
    killed = [item for item in card["kill_attempts"] if item["status"] == "killed"]
    assert killed
    assert all(item["evidence_refs"] for item in killed)


def test_suppressed_public_and_deduplicated_duplicate_of():
    public = "api:GET:/records/{record_id}:public_access"
    suppress = build_falsification_card(
        _base_state(public_evidence_ref=public),
        disposition="suppressed",
        evidence_refs=[public],
    )
    assert validate_falsification_card(suppress) == []
    assert suppress["decision"]["why_dead"]

    dedupe = build_falsification_card(
        _base_state(),
        disposition="deduplicated",
        evidence_refs=["code:code.py:load_record"],
        duplicate_of="missing_object_ownership_check:read_record",
    )
    assert validate_falsification_card(dedupe) == []
    assert dedupe["decision"]["duplicate_of"] == (
        "missing_object_ownership_check:read_record"
    )


def test_public_filter_does_not_kill_non_authorization_candidate():
    public = "api:GET:/records/{record_id}:public_access"
    card = build_falsification_card(
        _base_state(
            vuln_type="ssrf",
            public_evidence_ref=public,
            source_fact_refs=_base_state()["source_fact_refs"] + [public],
        ),
        disposition="retained",
        evidence_refs=_base_state()["source_fact_refs"] + [public],
    )

    impact = next(
        attempt for attempt in card["kill_attempts"] if attempt["dimension"] == "impact"
    )
    assert impact["status"] == "survived"
    assert validate_falsification_card(card) == []


def test_needs_evidence_lists_gaps_and_is_non_terminal_shape():
    card = build_falsification_card(
        _base_state(gap_evidence_ref=""),
        disposition="needs_evidence",
        evidence_refs=["api:GET:/records/{record_id}"],
        missing_evidence=["artifact:code", "gap_provenance"],
    )
    assert validate_falsification_card(card) == []
    assert card["decision"]["status"] == "needs_evidence"
    assert "artifact:code" in card["evidence_gaps"]
    assert card["decision"]["why_still_alive"]


def test_validate_catches_retained_without_invariant_and_killed_without_refs():
    card = build_falsification_card(
        _base_state(),
        disposition="retained",
        evidence_refs=_base_state()["source_fact_refs"],
    )
    card["broken_invariant"] = ""
    assert "broken_invariant_required_for_retained" in validate_falsification_card(card)

    bad = build_falsification_card(
        _base_state(),
        disposition="refuted",
        evidence_refs=["api:GET:/records/{record_id}:security_required"],
    )
    for attempt in bad["kill_attempts"]:
        if attempt["status"] == "killed":
            attempt["evidence_refs"] = []
    failures = validate_falsification_card(bad)
    assert any("killed_requires_evidence_refs" in item for item in failures)


def test_redacts_secret_like_strings_from_text_fields():
    card = build_falsification_card(
        _base_state(
            title="leak Bearer SECRET cookie=x",
            source_fact_refs=["scope:scope_context", "code:code.py:read_record"],
            gap_evidence_ref="code:code.py:read_record",
        ),
        disposition="retained",
        evidence_refs=["scope:scope_context", "code:code.py:read_record"],
    )
    blob = json.dumps(card)
    assert "SECRET" not in blob
    assert "Bearer" not in blob
    assert "cookie=" not in blob.lower() or "cookie=" not in blob
