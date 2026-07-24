from types import SimpleNamespace

from app.codebase_map import CodebaseFactCandidate
from app.candidate_hunter_loop import (
    advance_candidate_hunter_round,
    build_candidate_hunter_observations,
)
from app.cross_source_candidate_generator import (
    registered_local_advisory_artifact_ids,
    registered_local_advisory_fact_references,
    registered_local_dependency_advisory_facts,
)


SNAPSHOT_DIGEST = f"sha256:{'a' * 64}"
CAMPAIGN_ID = "campaign_local_analysis"


def _artifact(
    *,
    artifact_id: str = "artifact_static_advisory",
    rule_id: str = "mythos.local.ssrf-fetch",
    source_path: str = "routes.py",
    line: int = 7,
    snapshot_digest: str = SNAPSHOT_DIGEST,
    campaign_id: str = CAMPAIGN_ID,
):
    return SimpleNamespace(
        id=artifact_id,
        kind="static_advisory",
        source_type="registered_local_tool",
        ingestion_status="advisory_only",
        provenance={
            "campaign_id": campaign_id,
            "source_snapshot_digest": snapshot_digest,
            "tool_id": "semgrep_local",
            "raw_payload_processed": False,
        },
        derived_facts={
            "advisory_findings": [
                {
                    "rule_id": rule_id,
                    "path": source_path,
                    "line": line,
                    "message": "Bearer value must never enter the fact path",
                }
            ],
            "execution_allowed": False,
            "validation_allowed": False,
            "candidate_promotion_allowed": False,
            "report_submission_allowed": False,
        },
    )


def _dependency_artifact(
    *,
    artifact_id: str = "artifact_dependency_advisory",
    source_path: str = "routes.py",
    snapshot_digest: str = SNAPSHOT_DIGEST,
    campaign_id: str = CAMPAIGN_ID,
):
    return SimpleNamespace(
        id=artifact_id,
        kind="dependency_sbom_advisory",
        source_type="registered_local_tool",
        ingestion_status="advisory_only",
        provenance={
            "campaign_id": campaign_id,
            "source_snapshot_digest": snapshot_digest,
            "tool_id": "dependency_sbom_local",
            "raw_payload_processed": False,
        },
        derived_facts={
            "dependency_profile": {
                "network_access": False,
                "live_advisory_lookup": False,
                "execution_allowed": False,
                "validation_allowed": False,
                "candidate_promotion_allowed": False,
                "report_submission_allowed": False,
            },
            "dependency_advisories": [
                {
                    "package": "lodash",
                    "version": "4.17.20",
                    "ecosystem": "npm",
                    "advisory_id": "OFFLINE-LODASH-1",
                    "priority": "high",
                    "source_paths": [source_path],
                    "description": "must-not-enter-candidate-facts",
                }
            ],
            "execution_allowed": False,
            "validation_allowed": False,
            "candidate_promotion_allowed": False,
            "report_submission_allowed": False,
        },
    )


def _candidate():
    return {
        "hypothesis_id": "H-001",
        "vuln_type": "ssrf",
        "location": "POST /webhooks/test",
        "priority_score": 70,
        "source_facts": [
            {
                "artifact_kind": "code",
                "fact_type": "authorization_gap_candidate",
                "source_path": "routes.py",
                "symbol_name": "send_webhook",
                "root_cause": "missing_ssrf_validation",
            }
        ],
    }


def _candidate_for(*, vuln_type: str, root_cause: str):
    candidate = _candidate()
    candidate["vuln_type"] = vuln_type
    candidate["source_facts"][0]["root_cause"] = root_cause
    return candidate


def _candidate_sink_facts(*, sink_name: str = "fetch"):
    return [
        CodebaseFactCandidate(
            fact_type="route_handler",
            source_path="routes.py",
            symbol_name="send_webhook",
            route_method="POST",
            route_path="/webhooks/test",
            authz_hint=None,
            sensitivity_label="low",
            payload={"handler": "send_webhook", "line": 5},
        ),
        CodebaseFactCandidate(
            fact_type="sensitive_sink",
            source_path="routes.py",
            symbol_name=sink_name,
            route_method=None,
            route_path=None,
            authz_hint=None,
            sensitivity_label="low",
            payload={"handler": "send_webhook", "line": 7},
        ),
    ]


def test_snapshot_bound_registered_advisories_become_candidate_hunter_facts_only():
    facts = registered_local_advisory_fact_references(
        artifacts=[_artifact()],
        campaign_id=CAMPAIGN_ID,
        source_snapshot_digest=SNAPSHOT_DIGEST,
    )

    assert len(facts) == 1
    fact = facts[0]
    assert fact.fact_ref == (
        "static_advisory:artifact_static_advisory:7:mythos.local.ssrf-fetch"
    )
    assert fact.source_path == "routes.py"
    assert fact.symbol_name == "mythos.local.ssrf-fetch"
    assert "Bearer value" not in str(fact.model_dump(mode="json"))

    observations = build_candidate_hunter_observations(
        pipeline_run_id="run-static-advisory",
        candidates=[_candidate()],
        code_files=[],
        supplemental_code_facts=_candidate_sink_facts(),
        surface_facts=[],
        context_facts=[
            {"artifact_kind": "scope", "fact_type": "scope_context"},
            {"artifact_kind": "policy", "fact_type": "policy_context"},
        ],
        static_advisory_facts=[fact.model_dump(mode="json")],
    )

    state = observations["candidate_states"][0]
    assert fact.fact_ref in state["source_fact_refs"]
    assert "static_advisory" not in state["observed_artifact_kinds"]
    assert any(item["fact_ref"] == fact.fact_ref for item in observations["facts"])
    assert observations["candidate_promotion_allowed"] is False
    assert observations["report_submission_allowed"] is False


def test_registered_advisories_reject_wrong_campaign_or_snapshot():
    facts = registered_local_advisory_fact_references(
        artifacts=[
            _artifact(campaign_id="campaign_other"),
            _artifact(snapshot_digest=f"sha256:{'b' * 64}"),
        ],
        campaign_id=CAMPAIGN_ID,
        source_snapshot_digest=SNAPSHOT_DIGEST,
    )

    assert facts == []


def test_registered_dependency_advisory_is_snapshot_bound_and_path_matched_only():
    facts = registered_local_dependency_advisory_facts(
        artifacts=[_dependency_artifact()],
        campaign_id=CAMPAIGN_ID,
        source_snapshot_digest=SNAPSHOT_DIGEST,
    )

    assert len(facts) == 1
    fact = facts[0]
    assert fact["artifact_kind"] == "sbom"
    assert fact["fact_type"] == "dependency_signal"
    assert fact["source_path"] == "routes.py"
    assert fact["package_name"] == "lodash"
    assert fact["vulnerability_id"] == "OFFLINE-LODASH-1"
    assert "must-not-enter-candidate-facts" not in str(fact)

    observations = build_candidate_hunter_observations(
        pipeline_run_id="run-dependency-advisory",
        candidates=[_candidate()],
        code_files=[],
        supplemental_code_facts=_candidate_sink_facts(),
        dependency_advisory_facts=facts,
        surface_facts=[],
        context_facts=[
            {"artifact_kind": "scope", "fact_type": "scope_context"},
            {"artifact_kind": "policy", "fact_type": "policy_context"},
        ],
    )

    state = observations["candidate_states"][0]
    assert fact["fact_ref"] not in state["source_fact_refs"]
    assert "sbom" not in state["observed_artifact_kinds"]
    assert any(item["fact_ref"] == fact["fact_ref"] for item in observations["facts"])
    assert observations["candidate_promotion_allowed"] is False
    assert observations["report_submission_allowed"] is False


def test_registered_dependency_advisory_does_not_join_another_source_path():
    fact = registered_local_dependency_advisory_facts(
        artifacts=[_dependency_artifact(source_path="other.py")],
        campaign_id=CAMPAIGN_ID,
        source_snapshot_digest=SNAPSHOT_DIGEST,
    )[0]

    observations = build_candidate_hunter_observations(
        pipeline_run_id="run-dependency-advisory-unrelated",
        candidates=[_candidate()],
        code_files=[],
        supplemental_code_facts=_candidate_sink_facts(),
        dependency_advisory_facts=[fact],
        surface_facts=[],
        context_facts=[
            {"artifact_kind": "scope", "fact_type": "scope_context"},
            {"artifact_kind": "policy", "fact_type": "policy_context"},
        ],
    )

    assert fact["fact_ref"] not in observations["candidate_states"][0][
        "source_fact_refs"
    ]


def test_registered_dependency_advisory_rejects_any_permission_grant():
    artifact = _dependency_artifact()
    artifact.derived_facts["dependency_profile"]["validation_allowed"] = True

    assert registered_local_dependency_advisory_facts(
        artifacts=[artifact],
        campaign_id=CAMPAIGN_ID,
        source_snapshot_digest=SNAPSHOT_DIGEST,
    ) == []


def test_same_file_unrelated_static_advisory_does_not_join_candidate_evidence():
    fact = registered_local_advisory_fact_references(
        artifacts=[_artifact(rule_id="mythos.local.raw-sql")],
        campaign_id=CAMPAIGN_ID,
        source_snapshot_digest=SNAPSHOT_DIGEST,
    )[0]

    observations = build_candidate_hunter_observations(
        pipeline_run_id="run-static-advisory",
        candidates=[_candidate()],
        code_files=[],
        surface_facts=[],
        context_facts=[
            {"artifact_kind": "scope", "fact_type": "scope_context"},
            {"artifact_kind": "policy", "fact_type": "policy_context"},
        ],
        static_advisory_facts=[fact.model_dump(mode="json")],
    )

    assert fact.fact_ref not in observations["candidate_states"][0]["source_fact_refs"]
    assert any(item["fact_ref"] == fact.fact_ref for item in observations["facts"])


def test_same_family_static_advisory_in_another_handler_does_not_join_candidate_evidence():
    matching_fact, other_handler_fact = registered_local_advisory_fact_references(
        artifacts=[
            _artifact(
                artifact_id="artifact_static_advisory_matching",
                source_path="routes.ts",
                line=9,
            ),
            _artifact(
                artifact_id="artifact_static_advisory_other_handler",
                source_path="routes.ts",
                line=13,
            ),
        ],
        campaign_id=CAMPAIGN_ID,
        source_snapshot_digest=SNAPSHOT_DIGEST,
    )
    candidate = _candidate()
    candidate["location"] = "POST /webhooks/primary"
    candidate["source_facts"][0].update(
        {
            "source_path": "routes.ts",
            "symbol_name": "sendWebhook",
            "route_method": "POST",
            "route_path": "/webhooks/primary",
        }
    )

    observations = build_candidate_hunter_observations(
        pipeline_run_id="run-static-advisory",
        candidates=[candidate],
        code_files=[
            {
                "path": "routes.ts",
                "content": """import { Router } from \"express\";

const router = Router();

router.post(\"/webhooks/primary\", sendWebhook);
router.post(\"/webhooks/secondary\", sendOtherWebhook);

async function sendWebhook(req: Request, res: Response) {
  return fetch(req.body.primaryUrl);
}

async function sendOtherWebhook(req: Request, res: Response) {
  return fetch(req.body.secondaryUrl);
}
""",
            }
        ],
        surface_facts=[],
        context_facts=[
            {"artifact_kind": "scope", "fact_type": "scope_context"},
            {"artifact_kind": "policy", "fact_type": "policy_context"},
        ],
        static_advisory_facts=[
            matching_fact.model_dump(mode="json"),
            other_handler_fact.model_dump(mode="json"),
        ],
    )

    source_fact_refs = observations["candidate_states"][0]["source_fact_refs"]
    assert matching_fact.fact_ref in source_fact_refs
    assert other_handler_fact.fact_ref not in source_fact_refs


def test_compatible_static_advisory_families_join_candidate_evidence():
    cases = (
        ("mythos.local.ssrf-fetch", "ssrf", "missing_ssrf_validation", "fetch"),
        ("py/path-injection", "path_traversal", "missing_path_validation", "read_file"),
        ("mythos.local.raw-sql", "injection", "missing_injection_validation", "run_sql"),
        (
            "mythos.agent-tool-authorization",
            "agent_tool_authz_gap",
            "missing_agent_tool_authorization_check",
            "dispatch_agent_tool",
        ),
    )

    for index, (rule_id, vuln_type, root_cause, sink_name) in enumerate(cases, start=1):
        fact = registered_local_advisory_fact_references(
            artifacts=[
                _artifact(
                    artifact_id=f"artifact_static_advisory_{index}",
                    rule_id=rule_id,
                )
            ],
            campaign_id=CAMPAIGN_ID,
            source_snapshot_digest=SNAPSHOT_DIGEST,
        )[0]
        observations = build_candidate_hunter_observations(
            pipeline_run_id=f"run-static-advisory-{index}",
            candidates=[
                _candidate_for(vuln_type=vuln_type, root_cause=root_cause)
            ],
            code_files=[],
            supplemental_code_facts=_candidate_sink_facts(sink_name=sink_name),
            surface_facts=[],
            context_facts=[
                {"artifact_kind": "scope", "fact_type": "scope_context"},
                {"artifact_kind": "policy", "fact_type": "policy_context"},
            ],
            static_advisory_facts=[fact.model_dump(mode="json")],
        )

        assert fact.fact_ref in observations["candidate_states"][0]["source_fact_refs"]


def test_cwe_static_advisories_join_only_matching_candidate_families():
    cases = (
        ("semgrep.java.cwe-918", "ssrf", "missing_ssrf_validation", "fetch"),
        ("codeql/java/cwe-089", "injection", "missing_injection_validation", "run_sql"),
        ("audit:CWE_915", "mass_assignment", "missing_mass_assignment_guard", "update_user"),
        ("codeql/cwe-862", "authorization", "missing_object_ownership_check", "send_file"),
        (
            "scanner.cwe-362",
            "race_condition",
            "missing_transactional_state_guard",
            "consume_one_time_token",
        ),
    )

    for index, (rule_id, vuln_type, root_cause, sink_name) in enumerate(cases, start=1):
        fact = registered_local_advisory_fact_references(
            artifacts=[
                _artifact(
                    artifact_id=f"artifact_static_advisory_cwe_{index}",
                    rule_id=rule_id,
                )
            ],
            campaign_id=CAMPAIGN_ID,
            source_snapshot_digest=SNAPSHOT_DIGEST,
        )[0]
        observations = build_candidate_hunter_observations(
            pipeline_run_id=f"run-static-advisory-cwe-{index}",
            candidates=[
                _candidate_for(vuln_type=vuln_type, root_cause=root_cause)
            ],
            code_files=[],
            supplemental_code_facts=_candidate_sink_facts(sink_name=sink_name),
            surface_facts=[],
            context_facts=[
                {"artifact_kind": "scope", "fact_type": "scope_context"},
                {"artifact_kind": "policy", "fact_type": "policy_context"},
            ],
            static_advisory_facts=[fact.model_dump(mode="json")],
        )

        assert fact.fact_ref in observations["candidate_states"][0]["source_fact_refs"]
        assert observations["candidate_promotion_allowed"] is False
        assert observations["report_submission_allowed"] is False


def test_ambiguous_cwe_static_advisory_does_not_join_candidate_evidence():
    fact = registered_local_advisory_fact_references(
        artifacts=[_artifact(rule_id="scanner.cwe-918.cwe-89")],
        campaign_id=CAMPAIGN_ID,
        source_snapshot_digest=SNAPSHOT_DIGEST,
    )[0]
    observations = build_candidate_hunter_observations(
        pipeline_run_id="run-static-advisory-ambiguous-cwe",
        candidates=[_candidate()],
        code_files=[],
        supplemental_code_facts=_candidate_sink_facts(),
        surface_facts=[],
        context_facts=[
            {"artifact_kind": "scope", "fact_type": "scope_context"},
            {"artifact_kind": "policy", "fact_type": "policy_context"},
        ],
        static_advisory_facts=[fact.model_dump(mode="json")],
    )

    assert fact.fact_ref not in observations["candidate_states"][0]["source_fact_refs"]


def test_agent_tool_candidate_rejects_same_file_object_access_rule():
    fact = registered_local_advisory_fact_references(
        artifacts=[_artifact(rule_id="codeql/idor")],
        campaign_id=CAMPAIGN_ID,
        source_snapshot_digest=SNAPSHOT_DIGEST,
    )[0]

    observations = build_candidate_hunter_observations(
        pipeline_run_id="run-static-advisory",
        candidates=[
            _candidate_for(
                vuln_type="agent_tool_authz_gap",
                root_cause="missing_agent_tool_authorization_check",
            )
        ],
        code_files=[],
        surface_facts=[],
        context_facts=[
            {"artifact_kind": "scope", "fact_type": "scope_context"},
            {"artifact_kind": "policy", "fact_type": "policy_context"},
        ],
        static_advisory_facts=[fact.model_dump(mode="json")],
    )

    assert fact.fact_ref not in observations["candidate_states"][0]["source_fact_refs"]


def test_related_static_advisory_is_preserved_in_retained_candidate_projection():
    fact = registered_local_advisory_fact_references(
        artifacts=[_artifact()],
        campaign_id=CAMPAIGN_ID,
        source_snapshot_digest=SNAPSHOT_DIGEST,
    )[0]
    state = {
        "candidate_id": "H-001",
        "candidate_key": "run-static-advisory:H-001",
        "vuln_type": "ssrf",
        "root_cause_id": "missing_ssrf_validation:send_webhook",
        "route": {"method": "POST", "path": "/webhooks/test"},
        "source_fact_refs": [
            "scope:scope_context",
            "policy:policy_context",
            "code:routes.py:send_webhook",
            "api:POST:/webhooks/test",
            "har:har_context",
            fact.fact_ref,
        ],
        "observed_artifact_kinds": ["scope", "policy", "code", "api", "har"],
        "required_artifact_kinds": ["scope", "policy", "code", "api", "har"],
        "evidence_trace_status": "traceable",
        "priority_score": 70,
        "gap_evidence_ref": "code:routes.py:send_webhook",
    }

    result = advance_candidate_hunter_round(
        pipeline_run_id="run-static-advisory",
        round_number=1,
        candidate_states=[state],
        observations={
            "execution_allowed": False,
            "dispatch_allowed": False,
            "validation_allowed": False,
            "candidate_promotion_allowed": False,
            "report_submission_allowed": False,
            "raw_payload_processed": False,
        },
        prior_decisions=[],
    )

    retained = result["final_candidates"][0]
    assert fact.fact_ref in retained["source_fact_refs"]
    assert retained["validation_allowed"] is False
    assert retained["report_submission_allowed"] is False


def test_registered_advisories_can_be_frozen_to_task_bound_artifacts_only():
    bound = _artifact()
    later = _artifact(
        artifact_id="artifact_scanned_after_task_creation",
        rule_id="mythos.local.path-traversal",
    )

    artifact_ids = registered_local_advisory_artifact_ids(
        artifacts=[bound, later],
        campaign_id=CAMPAIGN_ID,
        source_snapshot_digest=SNAPSHOT_DIGEST,
    )
    facts = registered_local_advisory_fact_references(
        artifacts=[bound, later],
        campaign_id=CAMPAIGN_ID,
        source_snapshot_digest=SNAPSHOT_DIGEST,
        artifact_ids=[bound.id],
    )

    assert artifact_ids == sorted([bound.id, later.id])
    assert [fact.fact_ref for fact in facts] == [
        "static_advisory:artifact_static_advisory:7:mythos.local.ssrf-fetch"
    ]
