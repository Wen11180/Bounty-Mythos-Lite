from pathlib import Path

import json

from app.advisory_static_engines import (
    ENGINE_CODEQL,
    ENGINE_SEMGREP,
    build_advisory_signals_for_candidate,
    build_codeql_advisory_signal,
    build_semgrep_advisory_signal,
    load_advisory_findings,
    load_package_advisory_bundle,
)
from app.multi_engine_verifier import (
    VERDICT_FALSE_POSITIVE_LIKELY,
    VERDICT_LOCAL_STATIC_CONSISTENT,
    VERDICT_NEEDS_HUMAN_REVIEW,
    build_multi_engine_verdict,
    verdict_from_hunter_and_map,
)


def test_load_findings_list_and_sarif(tmp_path: Path):
    findings = load_advisory_findings(
        [
            {
                "rule_id": "python.lang.security.audit.ssrf",
                "message": "Possible SSRF",
                "path": "code.ts",
                "root_cause_id": "missing_ssrf_validation:deliver",
            }
        ]
    )
    assert len(findings) == 1
    sarif_path = tmp_path / "semgrep.sarif.json"
    sarif_path.write_text(
        (
            '{"runs":[{"results":[{"ruleId":"js/ssrf",'
            '"message":{"text":"SSRF risk"},'
            '"locations":[{"physicalLocation":{"artifactLocation":{"uri":"src/a.ts"}}}]}]}]}'
        ),
        encoding="utf-8",
    )
    loaded = load_advisory_findings(sarif_path)
    assert len(loaded) == 1
    assert loaded[0]["rule_id"] == "js/ssrf"


def test_semgrep_match_supports_candidate():
    signal = build_semgrep_advisory_signal(
        [
            {
                "rule_id": "python.ssrf",
                "message": "user controlled URL fetch",
                "path": "code.ts",
                "root_cause_id": "missing_ssrf_validation:deliver",
            }
        ],
        candidate={
            "candidate_id": "H-1",
            "root_cause_id": "missing_ssrf_validation:deliver",
            "affected_code_path": "code:code.ts:deliver",
        },
    )
    assert signal["engine"] == ENGINE_SEMGREP
    assert signal["supports_candidate"] is True
    assert signal["execution_allowed"] is False
    assert signal["confirmed_vulnerability"] is False
    assert any(ref.startswith("advisory:") for ref in signal["evidence_refs"])


def test_codeql_control_opposes():
    signal = build_codeql_advisory_signal(
        [
            {
                "rule_id": "js/ssrf-control",
                "message": "control-present allowlist",
                "path": "validate.ts",
                "polarity": "control",
                "tags": ["control"],
            }
        ],
        candidate={"candidate_id": "H-2", "root_cause_id": "missing_ssrf_validation:deliver"},
    )
    assert signal["engine"] == ENGINE_CODEQL
    assert signal["supports_candidate"] is False
    assert signal["report_submission_allowed"] is False


def test_empty_findings_pending_neutral():
    signal = build_semgrep_advisory_signal([], candidate={"candidate_id": "H-3"})
    assert signal["status"] == "pending"
    assert signal["supports_candidate"] is None


def test_advisory_wires_into_multi_engine_retain():
    signals = build_advisory_signals_for_candidate(
        candidate={
            "candidate_id": "H-10",
            "root_cause_id": "missing_ssrf_validation:deliver",
            "disposition": "retained",
        },
        semgrep_findings=[
            {
                "rule_id": "python.ssrf",
                "root_cause_id": "missing_ssrf_validation:deliver",
                "message": "ssrf",
            }
        ],
    )
    verdict = verdict_from_hunter_and_map(
        candidate={
            "candidate_id": "H-10",
            "root_cause_id": "missing_ssrf_validation:deliver",
            "disposition": "retained",
            "source_fact_refs": ["code:code.ts:deliver"],
        },
        gap_root_causes=["missing_ssrf_validation:deliver"],
        report_submission_blocked=True,
        semgrep_signal=signals[ENGINE_SEMGREP],
    )
    assert verdict.status == VERDICT_LOCAL_STATIC_CONSISTENT
    assert verdict.confirmed_vulnerability is False
    assert any(e.engine == ENGINE_SEMGREP for e in verdict.engines)


def test_advisory_conflict_needs_human_review():
    # hunter+map support, codeql opposes -> human review
    verdict = build_multi_engine_verdict(
        candidate={"candidate_id": "H-11", "root_cause_id": "missing_path_validation:serve"},
        hunter_signal={"status": "ready", "supports_candidate": True},
        codebase_map_signal={"status": "ready", "supports_candidate": True},
        report_bridge_signal={"status": "ready", "supports_candidate": True},
        codeql_signal={
            "status": "ready",
            "supports_candidate": False,
            "notes": ["control"],
        },
    )
    assert verdict.status == VERDICT_NEEDS_HUMAN_REVIEW
    assert verdict.execution_allowed is False


def test_all_oppose_false_positive_with_advisory():
    verdict = build_multi_engine_verdict(
        candidate={"candidate_id": "H-12"},
        hunter_signal={"status": "ready", "supports_candidate": False},
        codebase_map_signal={"status": "ready", "supports_candidate": False},
        semgrep_signal={"status": "ready", "supports_candidate": False},
    )
    assert verdict.status == VERDICT_FALSE_POSITIVE_LIKELY
    assert verdict.report_submission_allowed is False


def test_load_package_advisory_bundle_missing_is_absent(tmp_path: Path):
    bundle = load_package_advisory_bundle(tmp_path)
    assert bundle["present"] is False
    assert bundle["execution_allowed"] is False
    assert bundle["confirmed_vulnerability"] is False


def test_load_package_advisory_bundle_from_inputs(tmp_path: Path):
    adv = tmp_path / "inputs" / "advisory"
    adv.mkdir(parents=True)
    (adv / "semgrep.json").write_text(
        json.dumps(
            {
                "findings": [
                    {
                        "rule_id": "python.ssrf",
                        "message": "ssrf",
                        "root_cause_id": "missing_ssrf_validation:deliver",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    (adv / "token-secret.json").write_text("[]", encoding="utf-8")
    bundle = load_package_advisory_bundle(tmp_path)
    assert bundle["present"] is True
    assert len(bundle["semgrep_findings"]) == 1
    assert any("blocked_filename" in item for item in bundle["skipped"])
    assert bundle["report_submission_allowed"] is False


def test_bridge_uses_package_advisory_bundle():
    from app.intelligence_benchmark.candidate_report_bridge import (
        bridge_operator_trial_result,
        build_submission_blocked_report_bundle,
    )

    card = {
        "candidate_id": "H-ADV-1",
        "vuln_type": "ssrf",
        "root_cause_id": "missing_ssrf_validation:deliver_local_lab_webhook",
        "route": {"method": "POST", "path": "/local/lab/webhooks/deliver"},
        "affected_code_path": "code:code.ts:deliver_local_lab_webhook",
        "source_fact_refs": ["code:code.ts:deliver_local_lab_webhook"],
        "execution_allowed": False,
        "validation_allowed": False,
        "report_submission_allowed": False,
        "refutation_questions": ["Is SSRF validation present?"],
        "safe_validation_plan": ["Local review only."],
        "next_allowed_action": "Human review",
    }
    advisory = {
        "present": True,
        "sources": [{"path": "inputs/advisory/semgrep.json", "engine": ENGINE_SEMGREP, "finding_count": 1}],
        "semgrep_findings": [
            {
                "rule_id": "javascript.ssrf",
                "message": "fetch subscriberUrl",
                "root_cause_id": "missing_ssrf_validation:deliver_local_lab_webhook",
            }
        ],
        "codeql_findings": [],
    }
    bundle = build_submission_blocked_report_bundle(
        card,
        package_id="pkg",
        advisory_bundle=advisory,
    )
    assert bundle["multi_engine_verdict"]["advisory_attached"] is True
    engines = {e["engine"] for e in bundle["multi_engine_verdict"]["engines"]}
    assert ENGINE_SEMGREP in engines
    assert bundle["confirmed_vulnerability"] is False
    assert bundle["report_submission_allowed"] is False

    result = bridge_operator_trial_result(
        {
            "package_id": "pkg",
            "final_candidates": [card],
            "candidate_decisions": [
                {
                    "candidate_id": "H-ADV-1",
                    "disposition": "retained",
                    "root_cause_id": card["root_cause_id"],
                }
            ],
            "advisory_bundle": advisory,
        }
    )
    assert result["advisory_bundle_present"] is True
    assert result["multi_engine_verdicts"][0]["advisory_attached"] is True
    assert result["multi_engine_verdicts"][0]["confirmed_vulnerability"] is False
