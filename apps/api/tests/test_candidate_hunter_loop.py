from __future__ import annotations

from copy import deepcopy
import json

import pytest
from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app.codebase_map import CodebaseFactCandidate, map_authorized_code_files
from app.candidate_hunter_loop import (
    SAFE_VALIDATION_STEP,
    _safe_prior_candidate_projection,
    _snapshot_candidate,
    advance_candidate_hunter_round,
    build_candidate_hunter_observations,
    load_candidate_hunter_projection,
    run_candidate_hunter_loop,
)
from app.db import Base
from app.db_models import CampaignTaskRecord, PipelineStageRecord
from app.repository import DatabaseRepository


REQUIRED_ARTIFACT_KINDS = ["scope", "policy", "code", "api", "har"]


def _repository() -> tuple[DatabaseRepository, Session]:
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    session = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)()
    return DatabaseRepository(session), session


def _pipeline_run(repository: DatabaseRepository, scope_status: str = "in_scope"):
    return repository.save_pipeline_run(
        asset="local.test",
        policy_text="Synthetic local policy.",
        scope_status=scope_status,
        hypothesis_count=1,
        blocked_count=0,
        report_title=None,
        payload={"hypotheses": []},
    )


def _safe_observations() -> dict:
    return {
        "execution_allowed": False,
        "dispatch_allowed": False,
        "validation_allowed": False,
        "candidate_promotion_allowed": False,
        "report_submission_allowed": False,
        "raw_payload_processed": False,
    }


def _complete_candidate_state(candidate_id: str = "H-001") -> dict:
    return {
        "candidate_id": candidate_id,
        "candidate_key": f"run-001:{candidate_id}",
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
        "observed_artifact_kinds": REQUIRED_ARTIFACT_KINDS,
        "required_artifact_kinds": REQUIRED_ARTIFACT_KINDS,
        "evidence_trace_status": "traceable",
        "priority_score": 80,
        "gap_evidence_ref": "code:code.py:read_record",
        "shared_root": "read_record",
        "shared_root_evidence_ref": "code:code.py:read_record",
    }


def _build_single_candidate_observations(
    code: str,
    *,
    access_mode: str | None = None,
    pipeline_run_id: str = "run-001",
    route_path: str = "/records/{record_id}",
    symbol_name: str = "read_record",
    source_path: str = "code.py",
    vuln_type: str = "authorization",
    root_cause: str = "missing_object_ownership_check",
) -> dict:
    route = route_path
    api_fact = {
        "fact_type": "api_surface",
        "artifact_kind": "api",
        "route_method": "GET",
        "route_path": route,
    }
    if access_mode is not None:
        api_fact["access_mode"] = access_mode
    return build_candidate_hunter_observations(
        pipeline_run_id=pipeline_run_id,
        candidates=[
            {
                "hypothesis_id": "H-001",
                "vuln_type": vuln_type,
                "location": f"GET {route}",
                "priority_score": 80,
                "source_facts": [
                    {
                        "fact_type": "authorization_gap_candidate",
                        "artifact_kind": "code",
                        "source_path": source_path,
                        "symbol_name": symbol_name,
                        "route_method": "GET",
                        "route_path": route,
                        "root_cause": root_cause,
                    }
                ],
            }
        ],
        code_files=[{"path": source_path, "content": code}],
        surface_facts=[
            api_fact,
            {"fact_type": "har_context", "artifact_kind": "har"},
        ],
        context_facts=[
            {"fact_type": "scope_context", "artifact_kind": "scope"},
            {"fact_type": "policy_context", "artifact_kind": "policy"},
        ],
    )


def test_observations_use_run_and_hypothesis_for_stable_candidate_identity():
    observations = build_candidate_hunter_observations(
        pipeline_run_id="run-001",
        candidates=[{"hypothesis_id": "H-001"}],
        code_files=[],
        surface_facts=[],
        context_facts=[],
    )

    assert len(observations["candidate_states"]) == 1
    assert observations["candidate_states"][0]["candidate_id"] == "H-001"
    assert observations["candidate_states"][0]["candidate_key"] == "run-001:H-001"


def test_observations_preserve_model_priority_for_advisory_tiebreak():
    observations = build_candidate_hunter_observations(
        pipeline_run_id="run-001",
        candidates=[{"hypothesis_id": "H-001", "model_priority_score": 100}],
        code_files=[],
        surface_facts=[],
        context_facts=[],
    )

    assert observations["candidate_states"][0]["model_priority_score"] == 100


def test_observations_preserve_sarif_route_support_without_making_it_required():
    route = "/records/{record_id}"
    observations = build_candidate_hunter_observations(
        pipeline_run_id="run-001",
        candidates=[
            {
                "hypothesis_id": "H-001",
                "vuln_type": "authorization",
                "location": f"GET {route}",
                "source_facts": [
                    {
                        "fact_type": "scope_context",
                        "artifact_kind": "scope",
                    },
                    {
                        "fact_type": "policy_context",
                        "artifact_kind": "policy",
                    },
                    {
                        "fact_type": "authorization_gap_candidate",
                        "artifact_kind": "code",
                        "source_path": "routes.py",
                        "symbol_name": "read_record",
                        "route_method": "GET",
                        "route_path": route,
                    },
                    {
                        "fact_type": "route_handler",
                        "artifact_kind": "api",
                        "route_method": "GET",
                        "route_path": route,
                    },
                    {
                        "fact_type": "route_handler",
                        "artifact_kind": "har",
                        "route_method": "GET",
                        "route_path": route,
                    },
                    {
                        "fact_type": "route_handler",
                        "artifact_kind": "sarif",
                        "route_method": "GET",
                        "route_path": route,
                    },
                ],
            }
        ],
        code_files=[],
        surface_facts=[],
        context_facts=[],
    )

    state = observations["candidate_states"][0]

    assert "sarif:GET:/records/{record_id}" in state["source_fact_refs"]
    assert state["required_artifact_kinds"] == REQUIRED_ARTIFACT_KINDS
    assert "sarif" not in state["observed_artifact_kinds"]


def test_observations_keep_sbom_support_out_of_candidate_evidence():
    route = "/records/{record_id}"
    observations = build_candidate_hunter_observations(
        pipeline_run_id="run-001",
        candidates=[
            {
                "hypothesis_id": "H-001",
                "vuln_type": "authorization",
                "location": f"GET {route}",
                "source_facts": [
                    {
                        "fact_type": "scope_context",
                        "artifact_kind": "scope",
                    },
                    {
                        "fact_type": "policy_context",
                        "artifact_kind": "policy",
                    },
                    {
                        "fact_type": "authorization_gap_candidate",
                        "artifact_kind": "code",
                        "source_path": "routes.py",
                        "symbol_name": "read_record",
                        "route_method": "GET",
                        "route_path": route,
                    },
                    {
                        "fact_type": "route_handler",
                        "artifact_kind": "api",
                        "route_method": "GET",
                        "route_path": route,
                    },
                    {
                        "fact_type": "route_handler",
                        "artifact_kind": "har",
                        "route_method": "GET",
                        "route_path": route,
                    },
                    {
                        "fact_ref": "sbom_artifact:dependency:" + "a" * 64,
                        "fact_type": "dependency_signal",
                        "artifact_kind": "sbom",
                        "source_path": "routes.py",
                        "symbol_name": "django",
                        "package_name": "django",
                        "package_version": "4.2.1",
                        "ecosystem": "pypi",
                        "vulnerability_id": "CVE-2099-0001",
                        "severity": "high",
                        "description": "sbom-body-marker",
                    },
                ],
            }
        ],
        code_files=[],
        surface_facts=[],
        context_facts=[],
    )

    state = observations["candidate_states"][0]

    assert "sbom_artifact:dependency:" + "a" * 64 not in state["source_fact_refs"]
    assert state["required_artifact_kinds"] == REQUIRED_ARTIFACT_KINDS
    assert "sbom" not in state["observed_artifact_kinds"]
    assert "sbom-body-marker" not in json.dumps(observations)


def test_complete_unguarded_sensitive_flow_is_retained():
    result = advance_candidate_hunter_round(
        pipeline_run_id="run-001",
        round_number=1,
        candidate_states=[_complete_candidate_state()],
        observations=_safe_observations(),
        prior_decisions=[],
    )

    assert result["candidate_decisions"][0]["disposition"] == "retained"
    assert result["candidate_decisions"][0]["evidence_refs"]
    assert result["final_candidates"][0]["candidate_id"] == "H-001"
    assert result["final_candidates"][0]["execution_allowed"] is False
    assert result["final_candidates"][0]["validation_allowed"] is False
    assert result["final_candidates"][0]["report_submission_allowed"] is False


def test_retained_projection_includes_research_card_fields():
    """L3 usability: retained cards expose refute Qs, code path, concrete plan."""
    state = _complete_candidate_state()
    state["refutation_questions"] = [
        "Does a local ownership check run before send_file?",
    ]
    result = advance_candidate_hunter_round(
        pipeline_run_id="run-001",
        round_number=1,
        candidate_states=[state],
        observations=_safe_observations(),
        prior_decisions=[],
    )

    retained = result["final_candidates"][0]
    assert retained["refutation_questions"] == [
        "Does a local ownership check run before send_file?",
    ]
    assert retained["affected_code_path"].startswith("code:")
    assert retained["affected_code_path"] in retained["source_fact_refs"]
    assert any(
        "Local review only" in item and "GET" in item
        for item in retained["safe_validation_plan"]
    )
    assert any(
        "Do not execute live validation" in item
        and "submit a report" in item
        for item in retained["safe_validation_plan"]
    )
    projection = result["candidate_decisions"][0]["candidate_projection"]
    assert projection["refutation_questions"] == retained["refutation_questions"]
    assert projection["affected_code_path"] == retained["affected_code_path"]


def test_complete_candidate_without_observed_code_ref_requests_code_evidence():
    state = _complete_candidate_state()
    state["source_fact_refs"] = [
        ref for ref in state["source_fact_refs"] if not ref.startswith("code:")
    ]
    state["gap_evidence_ref"] = "api:GET:/records/{record_id}"

    result = advance_candidate_hunter_round(
        pipeline_run_id="run-001",
        round_number=1,
        candidate_states=[state],
        observations=_safe_observations(),
        prior_decisions=[],
    )

    assert result["final_candidates"] == []
    assert result["candidate_decisions"] == []
    assert result["evidence_requests"][0]["missing_evidence"] == ["code_path"]
    assert result["evidence_requests"][0]["requested_artifact_kinds"] == ["code"]


def test_retained_projection_preserves_specific_research_metadata():
    state = _complete_candidate_state()
    state.update(
        {
            "broken_invariant": (
                "Outbound requests to user-controlled URLs must validate the target "
                "against private networks, metadata endpoints, and unsafe schemes."
            ),
            "validation_mode": "offline_ssrf_target_policy_review",
            "evidence_needed": ["local_egress_validation_trace"],
            "impact_rationale": (
                "Potential server-side outbound request risk if an untrusted target "
                "reaches the mapped egress sink."
            ),
            "impact_score": 80,
            "safe_validation_plan": [
                "Review the local URL parsing and egress policy call path.",
            ],
            "refutation_questions": [
                "Does a same-handler URL validation control run before the outbound sink?",
            ],
        }
    )

    result = advance_candidate_hunter_round(
        pipeline_run_id="run-001",
        round_number=1,
        candidate_states=[state],
        observations=_safe_observations(),
        prior_decisions=[],
    )

    retained = result["final_candidates"][0]
    assert retained["broken_invariant"] == state["broken_invariant"]
    assert retained["falsification_card"]["broken_invariant"] == state[
        "broken_invariant"
    ]
    assert retained["validation_mode"] == "offline_ssrf_target_policy_review"
    assert retained["evidence_needed"] == ["local_egress_validation_trace"]
    assert retained["impact_rationale"] == state["impact_rationale"]
    assert retained["impact_score"] == 80
    assert retained["safe_validation_plan"][0].startswith("Local review only")
    assert state["safe_validation_plan"][0] not in retained["safe_validation_plan"]
    assert "Do not execute live validation" in retained["safe_validation_plan"][-1]
    assert retained["refutation_questions"] == state["refutation_questions"]
    assert all(retained[field] is False for field in (
        "execution_allowed",
        "dispatch_allowed",
        "validation_allowed",
        "candidate_promotion_allowed",
        "report_submission_allowed",
    ))


def test_validation_plans_are_fixed_across_final_snapshot_and_recovery():
    state = _complete_candidate_state()
    unsafe_step = "Local POST to public endpoint with a synthetic payload."
    state["safe_validation_plan"] = [unsafe_step]

    result = advance_candidate_hunter_round(
        pipeline_run_id="run-001",
        round_number=1,
        candidate_states=[state],
        observations=_safe_observations(),
        prior_decisions=[],
    )

    final_candidate = result["final_candidates"][0]
    snapshot = _snapshot_candidate(state)
    recovered = _safe_prior_candidate_projection(
        {**final_candidate, "safe_validation_plan": [unsafe_step]},
        final_candidate["candidate_id"],
        final_candidate["root_cause_id"],
    )

    assert recovered is not None
    for projection in (final_candidate, snapshot, recovered):
        plan = projection["safe_validation_plan"]
        assert unsafe_step not in plan
        assert plan[0].startswith("Local review only")
        assert plan[-1] == SAFE_VALIDATION_STEP


def test_positive_observed_control_refutes_candidate():
    state = _complete_candidate_state()
    control_ref = "api:GET:/records/{record_id}:security_required"
    state["source_fact_refs"].append(control_ref)
    state["control_evidence_ref"] = control_ref

    result = advance_candidate_hunter_round(
        pipeline_run_id="run-001",
        round_number=1,
        candidate_states=[state],
        observations=_safe_observations(),
        prior_decisions=[],
    )

    decision = result["candidate_decisions"][0]
    assert decision["candidate_id"] == "H-001"
    assert decision["root_cause_id"] == "missing_object_ownership_check:read_record"
    assert decision["disposition"] == "refuted"
    assert decision["evidence_refs"] == [control_ref]
    assert decision["falsification_card"]["decision"]["status"] == "refuted"
    assert decision["falsification_card"]["decision"]["why_dead"]
    assert result["final_candidates"] == []


def test_explicit_public_evidence_suppresses_candidate():
    state = _complete_candidate_state()
    public_ref = "api:GET:/records/{record_id}:public_access"
    state["source_fact_refs"].append(public_ref)
    state["public_evidence_ref"] = public_ref

    result = advance_candidate_hunter_round(
        pipeline_run_id="run-001",
        round_number=1,
        candidate_states=[state],
        observations=_safe_observations(),
        prior_decisions=[],
    )

    decision = result["candidate_decisions"][0]
    assert decision["candidate_id"] == "H-001"
    assert decision["root_cause_id"] == "missing_object_ownership_check:read_record"
    assert decision["disposition"] == "suppressed"
    assert decision["evidence_refs"] == [public_ref]
    assert decision["falsification_card"]["decision"]["status"] == "suppressed"
    assert decision["falsification_card"]["decision"]["why_dead"]
    assert result["final_candidates"] == []


@pytest.mark.parametrize(
    "vuln_type",
    [
        "ssrf",
        "path_traversal",
        "mass_assignment",
        "command_injection",
        "unsafe_deserialization",
        "file_upload",
        "business_logic",
        "agent_tool_authz_gap",
    ],
)
def test_public_evidence_does_not_suppress_non_authorization_candidate(vuln_type):
    state = _complete_candidate_state()
    state["vuln_type"] = vuln_type
    state["root_cause_id"] = f"missing_{vuln_type}_validation:local_handler"
    public_ref = "api:GET:/records/{record_id}:public_access"
    state["source_fact_refs"].append(public_ref)
    state["public_evidence_ref"] = public_ref

    result = advance_candidate_hunter_round(
        pipeline_run_id="run-001",
        round_number=1,
        candidate_states=[state],
        observations=_safe_observations(),
        prior_decisions=[],
    )

    decision = result["candidate_decisions"][0]
    impact_attempt = next(
        attempt
        for attempt in decision["falsification_card"]["kill_attempts"]
        if attempt["dimension"] == "impact"
    )
    assert decision["disposition"] == "retained"
    assert impact_attempt["status"] == "survived"
    assert result["final_candidates"][0]["vuln_type"] == vuln_type


def test_candidates_sharing_observed_service_root_are_deduplicated():
    canonical = _complete_candidate_state("H-001")
    canonical["shared_root"] = "load_record"
    canonical["shared_root_evidence_ref"] = "code:code.py:load_record"
    canonical["source_fact_refs"].append("code:code.py:load_record")

    duplicate = _complete_candidate_state("H-002")
    duplicate["root_cause_id"] = (
        "missing_object_ownership_check:read_record_summary"
    )
    duplicate["route"] = {
        "method": "GET",
        "path": "/records/{record_id}/summary",
    }
    duplicate["priority_score"] = 70
    duplicate["shared_root"] = "load_record"
    duplicate["shared_root_evidence_ref"] = "code:code.py:load_record"
    duplicate["source_fact_refs"].append("code:code.py:load_record")

    result = advance_candidate_hunter_round(
        pipeline_run_id="run-001",
        round_number=1,
        candidate_states=[duplicate, canonical],
        observations=_safe_observations(),
        prior_decisions=[],
    )

    assert [item["candidate_id"] for item in result["final_candidates"]] == ["H-001"]
    decisions = {item["candidate_id"]: item for item in result["candidate_decisions"]}
    assert decisions["H-001"]["disposition"] == "retained"
    assert decisions["H-001"]["falsification_card"]["broken_invariant"]
    assert decisions["H-002"]["candidate_id"] == "H-002"
    assert decisions["H-002"]["root_cause_id"] == (
        "missing_object_ownership_check:read_record_summary"
    )
    assert decisions["H-002"]["disposition"] == "deduplicated"
    assert decisions["H-002"]["evidence_refs"] == ["code:code.py:load_record"]
    assert decisions["H-002"]["duplicate_of"] == (
        "missing_object_ownership_check:read_record"
    )
    assert decisions["H-002"]["falsification_card"]["decision"]["status"] == (
        "deduplicated"
    )
    assert decisions["H-002"]["falsification_card"]["decision"]["duplicate_of"] == (
        "missing_object_ownership_check:read_record"
    )


def test_direct_sinks_in_distinct_resource_families_are_not_deduplicated():
    observations = build_candidate_hunter_observations(
        pipeline_run_id="run-001",
        candidates=[
            {
                "hypothesis_id": "H-read",
                "vuln_type": "authorization",
                "location": "GET /records/{record_id}",
                "priority_score": 80,
            },
            {
                "hypothesis_id": "H-download",
                "vuln_type": "authorization",
                "location": "GET /exports/{export_id}",
                "priority_score": 70,
            },
        ],
        code_files=[
            {
                "path": "RecordsController.cs",
                "content": """
using Microsoft.AspNetCore.Mvc;

[Route("/records")]
public class RecordsController : ControllerBase {
  [HttpGet("{recordId}")]
  public IActionResult ReadRecord(string recordId) {
    return File(loadRecord(recordId).Path);
  }

  [HttpGet("/exports/{exportId}")]
  public IActionResult DownloadRecord(string exportId) {
    return File(loadRecord(exportId).Path);
  }
}
""",
            }
        ],
        surface_facts=[
            {
                "fact_type": "api_surface",
                "artifact_kind": "api",
                "route_method": "GET",
                "route_path": "/records/{record_id}",
            },
            {
                "fact_type": "api_surface",
                "artifact_kind": "api",
                "route_method": "GET",
                "route_path": "/exports/{export_id}",
            },
            {
                "fact_type": "har_surface",
                "artifact_kind": "har",
                "route_method": "GET",
                "route_path": "/records/123",
            },
            {
                "fact_type": "har_surface",
                "artifact_kind": "har",
                "route_method": "GET",
                "route_path": "/exports/123",
            },
        ],
        context_facts=[
            {"fact_type": "scope_context", "artifact_kind": "scope"},
            {"fact_type": "policy_context", "artifact_kind": "policy"},
        ],
    )

    assert {
        (state["shared_root"], state["shared_root_kind"])
        for state in observations["candidate_states"]
    } == {("File", "direct_sink")}
    result = advance_candidate_hunter_round(
        pipeline_run_id="run-001",
        round_number=1,
        candidate_states=observations["candidate_states"],
        observations=observations,
        prior_decisions=[],
    )

    assert {
        decision["candidate_id"]: decision["disposition"]
        for decision in result["candidate_decisions"]
    } == {"H-read": "retained", "H-download": "retained"}
    assert {candidate["candidate_id"] for candidate in result["final_candidates"]} == {
        "H-read",
        "H-download",
    }


def test_cross_controller_service_calls_share_sink_provenance_for_deduplication():
    observations = build_candidate_hunter_observations(
        pipeline_run_id="run-001",
        candidates=[
            {
                "hypothesis_id": "H-read",
                "vuln_type": "authorization",
                "location": "GET /records/{record_id}",
                "priority_score": 80,
            },
            {
                "hypothesis_id": "H-export",
                "vuln_type": "authorization",
                "location": "GET /exports/{export_id}",
                "priority_score": 70,
            },
        ],
        code_files=[
            {
                "path": "RecordsController.cs",
                "content": """
using Microsoft.AspNetCore.Mvc;

[Route("/records")]
public class RecordsController : ControllerBase {
  [HttpGet("{recordId}")]
  public IActionResult ReadRecord(string recordId) {
    return recordService.ExportRecord(recordId);
  }
}
""",
            },
            {
                "path": "ExportsController.cs",
                "content": """
using Microsoft.AspNetCore.Mvc;

[Route("/exports")]
public class ExportsController : ControllerBase {
  [HttpGet("{exportId}")]
  public IActionResult ExportRecordFile(string exportId) {
    return recordService.ExportRecord(exportId);
  }
}
""",
            },
            {
                "path": "RecordService.cs",
                "content": """
using Microsoft.AspNetCore.Mvc;

public class RecordService : ControllerBase {
  public IActionResult ExportRecord(string recordId) {
    return File(loadRecord(recordId).Path);
  }
}
""",
            },
        ],
        surface_facts=[
            {
                "fact_type": "api_surface",
                "artifact_kind": "api",
                "route_method": "GET",
                "route_path": "/records/{record_id}",
            },
            {
                "fact_type": "api_surface",
                "artifact_kind": "api",
                "route_method": "GET",
                "route_path": "/exports/{export_id}",
            },
            {
                "fact_type": "har_surface",
                "artifact_kind": "har",
                "route_method": "GET",
                "route_path": "/records/123",
            },
            {
                "fact_type": "har_surface",
                "artifact_kind": "har",
                "route_method": "GET",
                "route_path": "/exports/123",
            },
        ],
        context_facts=[
            {"fact_type": "scope_context", "artifact_kind": "scope"},
            {"fact_type": "policy_context", "artifact_kind": "policy"},
        ],
    )

    assert {
        (state["shared_root"], state["shared_root_evidence_ref"])
        for state in observations["candidate_states"]
    } == {("ExportRecord", "code:RecordService.cs:File")}
    assert {state["shared_root_kind"] for state in observations["candidate_states"]} == {
        "service"
    }
    assert all(
        "code:RecordService.cs:File" in state["source_fact_refs"]
        for state in observations["candidate_states"]
    )
    result = advance_candidate_hunter_round(
        pipeline_run_id="run-001",
        round_number=1,
        candidate_states=observations["candidate_states"],
        observations=observations,
        prior_decisions=[],
    )

    assert [candidate["candidate_id"] for candidate in result["final_candidates"]] == [
        "H-read"
    ]
    assert {
        decision["candidate_id"]: decision["disposition"]
        for decision in result["candidate_decisions"]
    } == {"H-read": "retained", "H-export": "deduplicated"}


def test_equal_priority_duplicates_use_model_priority_as_advisory_tiebreak():
    lower_model_priority = _complete_candidate_state("H-001")
    lower_model_priority["priority_score"] = 100
    lower_model_priority["model_priority_score"] = 80
    lower_model_priority["shared_root"] = "load_record"
    lower_model_priority["shared_root_evidence_ref"] = "code:code.py:load_record"
    lower_model_priority["source_fact_refs"].append("code:code.py:load_record")

    higher_model_priority = _complete_candidate_state("H-002")
    higher_model_priority["root_cause_id"] = (
        "missing_object_ownership_check:read_record_detail"
    )
    higher_model_priority["route"] = {
        "method": "GET",
        "path": "/records/{record_id}/detail",
    }
    higher_model_priority["priority_score"] = 100
    higher_model_priority["model_priority_score"] = 100
    higher_model_priority["shared_root"] = "load_record"
    higher_model_priority["shared_root_evidence_ref"] = "code:code.py:load_record"
    higher_model_priority["source_fact_refs"].append("code:code.py:load_record")

    result = advance_candidate_hunter_round(
        pipeline_run_id="run-001",
        round_number=1,
        candidate_states=[lower_model_priority, higher_model_priority],
        observations=_safe_observations(),
        prior_decisions=[],
    )

    assert [item["candidate_id"] for item in result["final_candidates"]] == ["H-002"]
    decisions = {item["candidate_id"]: item for item in result["candidate_decisions"]}
    assert decisions["H-001"]["disposition"] == "deduplicated"
    assert decisions["H-001"]["duplicate_of"] == higher_model_priority["root_cause_id"]


def test_same_service_name_in_different_sources_is_not_deduplicated():
    first = _complete_candidate_state("H-001")
    first["shared_root"] = "load_record"
    first["shared_root_evidence_ref"] = "code:first.py:load_record"
    first["source_fact_refs"].append("code:first.py:load_record")

    second = _complete_candidate_state("H-002")
    second["root_cause_id"] = "missing_object_ownership_check:second_handler"
    second["shared_root"] = "load_record"
    second["shared_root_evidence_ref"] = "code:second.py:load_record"
    second["source_fact_refs"].append("code:second.py:load_record")

    result = advance_candidate_hunter_round(
        pipeline_run_id="run-001",
        round_number=1,
        candidate_states=[first, second],
        observations=_safe_observations(),
        prior_decisions=[],
    )

    assert [
        decision["disposition"] for decision in result["candidate_decisions"]
    ] == ["retained", "retained"]


@pytest.mark.parametrize(
    ("mutation", "expected_gap"),
    [
        (lambda state: state.update(root_cause_id=""), "root_cause"),
        (lambda state: state.update(route={}), "route"),
        (lambda state: state.update(source_fact_refs=[]), "provenance"),
        (
            lambda state: state.update(
                observed_artifact_kinds=["scope", "policy", "code", "api"]
            ),
            "artifact:har",
        ),
    ],
)
def test_incomplete_candidate_requests_evidence_instead_of_terminal_decision(
    mutation,
    expected_gap: str,
):
    state = _complete_candidate_state()
    mutation(state)

    result = advance_candidate_hunter_round(
        pipeline_run_id="run-001",
        round_number=1,
        candidate_states=[state],
        observations=_safe_observations(),
        prior_decisions=[],
    )

    assert result["candidate_decisions"] == []
    assert result["final_candidates"] == []
    assert result["evidence_requests"][0]["candidate_id"] == "H-001"
    assert expected_gap in result["evidence_requests"][0]["missing_evidence"]


def test_evidence_request_names_refutation_questions_and_local_inspection_targets():
    state = _complete_candidate_state()
    state["observed_artifact_kinds"] = ["scope", "policy", "code", "api"]
    state["evidence_trace_status"] = "needs_evidence"
    state["refutation_questions"] = [
        "Does an observed ownership guard execute before the sensitive sink?"
    ]

    result = advance_candidate_hunter_round(
        pipeline_run_id="run-001",
        round_number=1,
        candidate_states=[state],
        observations=_safe_observations(),
        prior_decisions=[],
    )

    request = result["evidence_requests"][0]
    assert request["refutation_questions"] == state["refutation_questions"]
    assert request["requested_artifact_kinds"] == ["har"]
    assert request["inspection_targets"] == [
        {
            "artifact_kind": "har",
            "route": {"method": "GET", "path": "/records/{record_id}"},
        }
    ]
    assert request["decision_change_reason"] == (
        "A cited local control may refute or suppress the candidate; a complete "
        "unguarded trace may retain it for human review."
    )


@pytest.mark.parametrize(
    ("mutation", "expected_gap"),
    [
        (
            lambda state: state.update(candidate_key="another-run:H-001"),
            "stable_identity",
        ),
        (
            lambda state: state.update(gap_evidence_ref="code:code.py:not_observed"),
            "gap_provenance",
        ),
    ],
)
def test_candidate_identity_and_gap_reference_must_be_observed(
    mutation,
    expected_gap: str,
):
    state = _complete_candidate_state()
    mutation(state)

    result = advance_candidate_hunter_round(
        pipeline_run_id="run-001",
        round_number=1,
        candidate_states=[state],
        observations=_safe_observations(),
        prior_decisions=[],
    )

    assert result["candidate_decisions"] == []
    assert expected_gap in result["evidence_requests"][0]["missing_evidence"]


def test_final_ranking_is_deterministic_and_limited_to_five_candidates():
    states = []
    for candidate_id, priority in (
        ("H-007", 40),
        ("H-001", 80),
        ("H-006", 50),
        ("H-003", 90),
        ("H-005", 60),
        ("H-002", 90),
        ("H-004", 70),
    ):
        state = _complete_candidate_state(candidate_id)
        state["root_cause_id"] = f"missing_object_ownership_check:{candidate_id.lower()}"
        state["shared_root"] = candidate_id.lower()
        state["priority_score"] = priority
        states.append(state)

    result = advance_candidate_hunter_round(
        pipeline_run_id="run-001",
        round_number=1,
        candidate_states=states,
        observations=_safe_observations(),
        prior_decisions=[],
    )

    assert [item["candidate_id"] for item in result["final_candidates"]] == [
        "H-002",
        "H-003",
        "H-001",
        "H-004",
        "H-005",
    ]
    assert [item["rank"] for item in result["final_candidates"]] == [1, 2, 3, 4, 5]


@pytest.mark.parametrize(
    "field",
    [
        "execution_allowed",
        "dispatch_allowed",
        "validation_allowed",
        "candidate_promotion_allowed",
        "report_submission_allowed",
        "raw_payload_processed",
    ],
)
@pytest.mark.parametrize("unsafe_mode", ["true", "missing"])
def test_unsafe_or_missing_permission_flags_fail_closed(
    field: str,
    unsafe_mode: str,
):
    observations = _safe_observations()
    if unsafe_mode == "true":
        observations[field] = True
    else:
        observations.pop(field)

    result = advance_candidate_hunter_round(
        pipeline_run_id="run-001",
        round_number=1,
        candidate_states=[_complete_candidate_state()],
        observations=observations,
        prior_decisions=[],
    )

    assert result["safety_status"] == "blocked"
    assert result["candidate_decisions"] == []
    assert result["final_candidates"] == []
    assert result["execution_allowed"] is False
    assert result["dispatch_allowed"] is False
    assert result["validation_allowed"] is False
    assert result["candidate_promotion_allowed"] is False
    assert result["report_submission_allowed"] is False


def test_observation_projection_keeps_safe_facts_and_drops_raw_sensitive_text():
    route = "/records/{record_id}"
    observations = build_candidate_hunter_observations(
        pipeline_run_id="run-001",
        candidates=[
            {
                "hypothesis_id": "H-001",
                "vuln_type": "authorization",
                "location": f"GET {route}",
                "priority_score": 80,
                "review_note": "Authorization: Bearer synthetic-placeholder",
                "refutation_review": {
                    "questions": [
                        "Authorization: Bearer synthetic-placeholder",
                        "Does a local ownership guard execute before the sink?",
                    ]
                },
                "source_facts": [
                    {
                        "fact_type": "authorization_gap_candidate",
                        "artifact_kind": "code",
                        "source_path": "code.py",
                        "symbol_name": "read_record",
                        "route_method": "GET",
                        "route_path": route,
                        "root_cause": "missing_object_ownership_check",
                    }
                ],
            }
        ],
        code_files=[
            {
                "path": "code.py",
                "content": '''
from fastapi import APIRouter

router = APIRouter()

@router.get("/records/{record_id}")
def read_record(record_id: str):
    # Authorization: Bearer synthetic-placeholder; real user data
    return send_file(record_id)
''',
            }
        ],
        surface_facts=[
            {
                "fact_type": "api_surface",
                "artifact_kind": "api",
                "route_method": "GET",
                "route_path": route,
                "access_mode": "protected",
            },
            {"fact_type": "har_context", "artifact_kind": "har"},
        ],
        context_facts=[
            {"fact_type": "scope_context", "artifact_kind": "scope"},
            {"fact_type": "policy_context", "artifact_kind": "policy"},
        ],
    )

    state = observations["candidate_states"][0]
    assert state["route"] == {"method": "GET", "path": route}
    assert state["root_cause_id"] == (
        "missing_object_ownership_check:read_record"
    )
    assert f"api:GET:{route}:security_required" in state["source_fact_refs"]
    assert "control_evidence_ref" not in state
    assert state["observed_artifact_kinds"] == REQUIRED_ARTIFACT_KINDS
    assert state["evidence_trace_status"] == "traceable"
    assert state["gap_evidence_ref"] == "code:code.py:read_record"
    assert state["refutation_questions"] == [
        "Does a local ownership guard execute before the sink?"
    ]
    serialized = json.dumps(observations).lower()
    assert "synthetic-placeholder" not in serialized
    assert "bearer" not in serialized
    assert "real user data" not in serialized
    assert "return send_file" not in serialized


@pytest.mark.parametrize("access_mode", ["protected", "public"])
def test_openapi_access_mode_alone_is_not_terminal_evidence(access_mode: str):
    observations = _build_single_candidate_observations(
        '''
from fastapi import APIRouter

router = APIRouter()

@router.get("/records/{record_id}")
def read_record(record_id: str):
    return send_file(record_id)
''',
        access_mode=access_mode,
    )
    state = observations["candidate_states"][0]

    assert "control_evidence_ref" not in state
    assert "public_evidence_ref" not in state
    result = advance_candidate_hunter_round(
        pipeline_run_id="run-001",
        round_number=1,
        candidate_states=[state],
        observations=observations,
        prior_decisions=[],
    )
    assert result["candidate_decisions"][0]["disposition"] == "retained"


def test_observations_match_template_candidate_route_to_concrete_har_route():
    observations = build_candidate_hunter_observations(
        pipeline_run_id="run-001",
        candidates=[
            {
                "hypothesis_id": "H-001",
                "vuln_type": "authorization",
                "location": "GET /records/{record_id}",
                "source_facts": [
                    {
                        "fact_type": "authorization_gap_candidate",
                        "artifact_kind": "code",
                        "source_path": "code.py",
                        "symbol_name": "read_record",
                        "route_method": "GET",
                        "route_path": "/records/{record_id}",
                        "root_cause": "missing_object_ownership_check",
                    }
                ],
            }
        ],
        code_files=[
            {
                "path": "code.py",
                "content": "def read_record(record_id):\n    return send_file(record_id)\n",
            }
        ],
        surface_facts=[
            {
                "fact_type": "api_surface",
                "artifact_kind": "api",
                "route_method": "GET",
                "route_path": "/records/{record_id}",
            },
            {
                "fact_type": "har_surface",
                "artifact_kind": "har",
                "route_method": "GET",
                "route_path": "/records/123",
            },
        ],
        context_facts=[
            {"fact_type": "scope_context", "artifact_kind": "scope"},
            {"fact_type": "policy_context", "artifact_kind": "policy"},
        ],
    )

    state = observations["candidate_states"][0]
    assert state["observed_artifact_kinds"] == REQUIRED_ARTIFACT_KINDS
    assert "har:GET:/records/123" in state["source_fact_refs"]
    assert observations["initial_candidate_states"][0]["reanalysis_status"] == (
        "pending"
    )
    assert state["reanalysis_status"] == "completed"


def test_observations_link_csharp_controller_template_to_api_and_har_routes():
    observations = build_candidate_hunter_observations(
        pipeline_run_id="run-001",
        candidates=[
            {
                "hypothesis_id": "H-001",
                "vuln_type": "authorization",
                "location": "GET /api/v1/records/{record_id}",
                "priority_score": 80,
            }
        ],
        code_files=[
            {
                "path": "RecordsController.cs",
                "content": """
using Microsoft.AspNetCore.Mvc;

[Route("/api/v1/records")]
public class RecordsController : ControllerBase {
  [HttpGet("{recordId}")]
  public IActionResult ReadRecord(string recordId) {
    return File(loadRecord(recordId).Path);
  }
}
""",
            }
        ],
        surface_facts=[
            {
                "fact_type": "api_surface",
                "artifact_kind": "api",
                "route_method": "GET",
                "route_path": "/api/v1/records/{record_id}",
            },
            {
                "fact_type": "har_surface",
                "artifact_kind": "har",
                "route_method": "GET",
                "route_path": "/api/v1/records/123",
            },
        ],
        context_facts=[
            {"fact_type": "scope_context", "artifact_kind": "scope"},
            {"fact_type": "policy_context", "artifact_kind": "policy"},
        ],
    )

    state = observations["candidate_states"][0]
    csharp_route = next(
        fact
        for fact in observations["facts"]
        if fact["fact_type"] == "route_handler"
        and fact["source_path"] == "RecordsController.cs"
    )

    assert csharp_route["route"] == {
        "method": "GET",
        "path": "/api/v1/records/{recordId}",
    }
    assert state["root_cause_id"] == "missing_object_ownership_check:readrecord"
    assert state["gap_evidence_ref"] == "code:RecordsController.cs:ReadRecord"
    assert "api:GET:/api/v1/records/{record_id}" in state["source_fact_refs"]
    assert "har:GET:/api/v1/records/123" in state["source_fact_refs"]
    assert state["observed_artifact_kinds"] == REQUIRED_ARTIFACT_KINDS
    assert state["evidence_trace_status"] == "traceable"


def test_reachable_ownership_guard_is_decisive_refutation_evidence():
    observations = _build_single_candidate_observations(
        '''
from fastapi import APIRouter

router = APIRouter()

@router.get("/records/{record_id}")
def read_record(record_id: str, current_user):
    verify_record_access(record_id, current_user)
    return send_file(record_id)

def verify_record_access(record_id: str, current_user):
    record = load_record(record_id)
    if record.owner_id != current_user.id:
        raise PermissionError()
    return record
'''
    )
    state = observations["candidate_states"][0]

    assert state["control_evidence_ref"] == (
        "code:code.py:verify_record_access:ownership_guard"
    )
    result = advance_candidate_hunter_round(
        pipeline_run_id="run-001",
        round_number=1,
        candidate_states=[state],
        observations=observations,
        prior_decisions=[],
    )
    assert result["candidate_decisions"][0]["disposition"] == "refuted"


def test_unrelated_ownership_helper_does_not_refute_sensitive_sink():
    observations = _build_single_candidate_observations(
        '''
from fastapi import APIRouter

router = APIRouter()

@router.get("/records/{record_id}")
def read_record(record_id: str, profile_id: str, current_user):
    verify_profile_access(profile_id, current_user)
    record = load_record(record_id)
    return send_file(record.path)

def verify_profile_access(profile_id: str, current_user):
    profile = load_profile(profile_id)
    if profile.owner_id != current_user.id:
        raise PermissionError()
    return profile
'''
    )
    state = observations["candidate_states"][0]

    assert "control_evidence_ref" not in state
    result = advance_candidate_hunter_round(
        pipeline_run_id="run-001",
        round_number=1,
        candidate_states=[state],
        observations=observations,
        prior_decisions=[],
    )

    assert result["candidate_decisions"][0]["disposition"] == "retained"


@pytest.mark.parametrize(
    "source_order",
    [("foreign.py", "target.py"), ("target.py", "foreign.py")],
)
def test_ambiguous_route_bound_code_facts_do_not_attach_foreign_control(
    source_order,
):
    route = "/records/{record_id}"
    code_by_path = {
        "foreign.py": '''
from fastapi import APIRouter

router = APIRouter()

@router.get("/records/{record_id}")
def read_record(record_id: str, current_user):
    verify_record_access(record_id, current_user)
    return send_file(record_id)

def verify_record_access(record_id: str, current_user):
    record = load_record(record_id)
    if record.owner_id != current_user.id:
        raise PermissionError()
    return record
''',
        "target.py": '''
from fastapi import APIRouter

router = APIRouter()

@router.get("/records/{record_id}")
def read_record(record_id: str):
    return send_file(record_id)
''',
    }
    observations = build_candidate_hunter_observations(
        pipeline_run_id="run-001",
        candidates=[
            {
                "hypothesis_id": "H-001",
                "vuln_type": "authorization",
                "location": f"GET {route}",
                "priority_score": 80,
                "source_facts": [
                    {
                        "fact_type": "authorization_gap_candidate",
                        "artifact_kind": "code",
                        "source_path": source_path,
                        "symbol_name": "read_record",
                        "route_method": "GET",
                        "route_path": route,
                        "root_cause": "missing_object_ownership_check",
                    }
                    for source_path in source_order
                ],
            }
        ],
        code_files=[
            {"path": source_path, "content": code_by_path[source_path]}
            for source_path in source_order
        ],
        surface_facts=[
            {
                "fact_type": "api_surface",
                "artifact_kind": "api",
                "route_method": "GET",
                "route_path": route,
            },
            {"fact_type": "har_context", "artifact_kind": "har"},
        ],
        context_facts=[
            {"fact_type": "scope_context", "artifact_kind": "scope"},
            {"fact_type": "policy_context", "artifact_kind": "policy"},
        ],
    )
    state = observations["candidate_states"][0]

    assert "hypothesis_source_path" not in state
    assert "control_evidence_ref" not in state
    result = advance_candidate_hunter_round(
        pipeline_run_id="run-001",
        round_number=1,
        candidate_states=[state],
        observations=observations,
        prior_decisions=[],
    )

    assert result["candidate_decisions"][0]["disposition"] == "retained"


@pytest.mark.parametrize(
    "source_order",
    [("foreign.py", "target.py"), ("target.py", "foreign.py")],
)
def test_ambiguous_routeless_code_facts_do_not_attach_foreign_control(
    source_order,
):
    route = "/records/{record_id}"
    code_by_path = {
        "foreign.py": '''
from fastapi import APIRouter

router = APIRouter()

@router.get("/records/{record_id}")
def read_record(record_id: str, current_user):
    verify_record_access(record_id, current_user)
    return send_file(record_id)

def verify_record_access(record_id: str, current_user):
    record = load_record(record_id)
    if record.owner_id != current_user.id:
        raise PermissionError()
    return record
''',
        "target.py": '''
from fastapi import APIRouter

router = APIRouter()

@router.get("/records/{record_id}")
def read_record(record_id: str):
    return send_file(record_id)
''',
    }
    observations = build_candidate_hunter_observations(
        pipeline_run_id="run-001",
        candidates=[
            {
                "hypothesis_id": "H-001",
                "vuln_type": "authorization",
                "location": f"GET {route}",
                "priority_score": 80,
                "source_facts": [
                    {
                        "fact_type": "authorization_gap_candidate",
                        "artifact_kind": "code",
                        "source_path": source_path,
                        "symbol_name": "read_record",
                        "root_cause": "missing_object_ownership_check",
                    }
                    for source_path in source_order
                ],
            }
        ],
        code_files=[
            {"path": source_path, "content": code_by_path[source_path]}
            for source_path in source_order
        ],
        surface_facts=[
            {
                "fact_type": "api_surface",
                "artifact_kind": "api",
                "route_method": "GET",
                "route_path": route,
            },
            {"fact_type": "har_context", "artifact_kind": "har"},
        ],
        context_facts=[
            {"fact_type": "scope_context", "artifact_kind": "scope"},
            {"fact_type": "policy_context", "artifact_kind": "policy"},
        ],
    )
    state = observations["candidate_states"][0]

    assert "hypothesis_source_path" not in state
    assert "control_evidence_ref" not in state
    result = advance_candidate_hunter_round(
        pipeline_run_id="run-001",
        round_number=1,
        candidate_states=[state],
        observations=observations,
        prior_decisions=[],
    )

    assert result["candidate_decisions"][0]["disposition"] == "retained"


def test_depends_ownership_helper_must_match_sink_resource():
    observations = _build_single_candidate_observations(
        '''
from fastapi import APIRouter, Depends

router = APIRouter()

@router.get("/records/{record_id}")
def read_record(
    record_id: str,
    profile=Depends(verify_profile_access),
):
    return send_file(record_id)

def verify_profile_access(profile_id: str, current_user):
    profile = load_profile(profile_id)
    if profile.owner_id != current_user.id:
        raise PermissionError()
    return profile
'''
    )
    state = observations["candidate_states"][0]

    assert "control_evidence_ref" not in state
    result = advance_candidate_hunter_round(
        pipeline_run_id="run-001",
        round_number=1,
        candidate_states=[state],
        observations=observations,
        prior_decisions=[],
    )

    assert result["candidate_decisions"][0]["disposition"] == "retained"


@pytest.mark.parametrize("helper_name", ["get_owned", "verify_access"])
def test_generic_depends_helper_must_prove_sink_resource(helper_name):
    observations = _build_single_candidate_observations(
        f'''
from fastapi import APIRouter, Depends

router = APIRouter()

@router.get("/records/{{record_id}}")
def read_record(
    record_id: str,
    profile=Depends({helper_name}),
):
    return send_file(record_id)

def {helper_name}(profile_id: str, current_user):
    profile = load_profile(profile_id)
    if profile.owner_id != current_user.id:
        raise PermissionError()
    return profile
'''
    )
    state = observations["candidate_states"][0]

    assert "control_evidence_ref" not in state
    result = advance_candidate_hunter_round(
        pipeline_run_id="run-001",
        round_number=1,
        candidate_states=[state],
        observations=observations,
        prior_decisions=[],
    )

    assert result["candidate_decisions"][0]["disposition"] == "retained"


def test_depends_helper_name_must_agree_with_its_resource_parameter():
    observations = _build_single_candidate_observations(
        '''
from fastapi import APIRouter, Depends

router = APIRouter()

@router.get("/records/{record_id}")
def read_record(
    record_id: str,
    profile=Depends(get_owned_record),
):
    return send_file(record_id)

def get_owned_record(profile_id: str, current_user):
    profile = load_profile(profile_id)
    if profile.owner_id != current_user.id:
        raise PermissionError()
    return profile
'''
    )
    state = observations["candidate_states"][0]

    assert "control_evidence_ref" not in state
    result = advance_candidate_hunter_round(
        pipeline_run_id="run-001",
        round_number=1,
        candidate_states=[state],
        observations=observations,
        prior_decisions=[],
    )

    assert result["candidate_decisions"][0]["disposition"] == "retained"


def test_depends_helper_must_not_borrow_an_unchecked_resource_parameter():
    observations = _build_single_candidate_observations(
        '''
from fastapi import APIRouter, Depends

router = APIRouter()

@router.get("/records/{record_id}")
def read_record(
    record_id: str,
    profile=Depends(get_owned_record),
):
    return send_file(record_id)

def get_owned_record(record_id: str, profile_id: str, current_user):
    profile = load_profile(profile_id)
    if profile.owner_id != current_user.id:
        raise PermissionError()
    return profile
'''
    )
    state = observations["candidate_states"][0]

    assert "control_evidence_ref" not in state
    result = advance_candidate_hunter_round(
        pipeline_run_id="run-001",
        round_number=1,
        candidate_states=[state],
        observations=observations,
        prior_decisions=[],
    )

    assert result["candidate_decisions"][0]["disposition"] == "retained"


def test_resource_specific_ownership_decorator_must_match_sink_resource():
    observations = _build_single_candidate_observations(
        '''
from fastapi import APIRouter

router = APIRouter()

@router.get("/records/{record_id}")
@require_profile_ownership
def read_record(record_id: str):
    return send_file(record_id)
'''
    )
    state = observations["candidate_states"][0]

    assert "control_evidence_ref" not in state
    result = advance_candidate_hunter_round(
        pipeline_run_id="run-001",
        round_number=1,
        candidate_states=[state],
        observations=observations,
        prior_decisions=[],
    )

    assert result["candidate_decisions"][0]["disposition"] == "retained"


def test_generic_ownership_decorator_refutes_candidate():
    observations = _build_single_candidate_observations(
        '''
from fastapi import APIRouter

router = APIRouter()

@router.get("/records/{record_id}")
@require_ownership
def read_record(record_id: str):
    return send_file(record_id)
'''
    )
    state = observations["candidate_states"][0]

    assert state["control_evidence_ref"] == "code:code.py:read_record:ownership_guard"
    result = advance_candidate_hunter_round(
        pipeline_run_id="run-001",
        round_number=1,
        candidate_states=[state],
        observations=observations,
        prior_decisions=[],
    )

    assert result["candidate_decisions"][0]["disposition"] == "refuted"


def test_depends_ownership_helper_for_sink_resource_refutes_candidate():
    observations = _build_single_candidate_observations(
        '''
from fastapi import APIRouter, Depends

router = APIRouter()

@router.get("/records/{record_id}")
def read_record(
    record_id: str,
    record=Depends(get_owned_record),
):
    return send_file(record_id)

def get_owned_record(record_id: str, current_user):
    record = load_record(record_id)
    if record.owner_id != current_user.id:
        raise PermissionError()
    return record
'''
    )
    state = observations["candidate_states"][0]

    assert state["control_evidence_ref"] == (
        "code:code.py:get_owned_record:ownership_guard"
    )
    result = advance_candidate_hunter_round(
        pipeline_run_id="run-001",
        round_number=1,
        candidate_states=[state],
        observations=observations,
        prior_decisions=[],
    )

    assert result["candidate_decisions"][0]["disposition"] == "refuted"


def test_sink_after_alias_does_not_link_unrelated_ownership_helper():
    observations = _build_single_candidate_observations(
        '''
from fastapi import APIRouter

router = APIRouter()

@router.get("/records/{record_id}")
def read_record(record_id: str, profile_id: str, current_user):
    verify_profile_access(profile_id, current_user)
    record = load_record(record_id)
    response = send_file(record.path)
    profile_id = record_id
    return response

def verify_profile_access(profile_id: str, current_user):
    profile = load_profile(profile_id)
    if profile.owner_id != current_user.id:
        raise PermissionError()
    return profile
'''
    )
    state = observations["candidate_states"][0]

    assert "control_evidence_ref" not in state
    result = advance_candidate_hunter_round(
        pipeline_run_id="run-001",
        round_number=1,
        candidate_states=[state],
        observations=observations,
        prior_decisions=[],
    )

    assert result["candidate_decisions"][0]["disposition"] == "retained"


@pytest.mark.parametrize(
    ("source_path", "symbol_name", "code"),
    [
        (
            "views.py",
            "read_record",
            """
def read_record(request, record_id):
    record = Record.objects.get(pk=record_id)
    if record.owner_id != request.user.id:
        raise PermissionDenied()
    return send_file(record.path)
""",
        ),
        (
            "routes.py",
            "resolve_record",
            """
def resolve_record(root, info, record_id):
    record = load_record(record_id)
    if record.owner_id != info.context.user.id:
        raise PermissionError("forbidden")
    return send_file(record.path)
""",
        ),
    ],
)
def test_candidate_route_fallback_links_python_semantic_ownership_guard(
    source_path,
    symbol_name,
    code,
):
    observations = _build_single_candidate_observations(
        code,
        source_path=source_path,
        symbol_name=symbol_name,
    )
    state = observations["candidate_states"][0]

    assert state["control_evidence_ref"] == (
        f"code:{source_path}:{symbol_name}:ownership_guard"
    )
    result = advance_candidate_hunter_round(
        pipeline_run_id="run-001",
        round_number=1,
        candidate_states=[state],
        observations=observations,
        prior_decisions=[],
    )

    assert result["candidate_decisions"][0]["disposition"] == "refuted"


def test_go_nested_ownership_guard_is_decisive_refutation_evidence():
    observations = _build_single_candidate_observations(
        '''
package handlers

func mount(r Router) { r.GET("/records/{recordId}", readRecord) }

func readRecord() {
  record := loadRecord(recordId)
  loadRecordForUser(record, user)
  sendFile(record.Path)
}

func loadRecordForUser(record Record, user User) {
  validateAccess(record, user)
}

func validateAccess(record Record, user User) {
  if record.OwnerID != user.ID { return }
}
''',
        route_path="/records/{recordId}",
        symbol_name="readRecord",
        source_path="handlers.go",
    )
    state = observations["candidate_states"][0]

    assert state["control_evidence_ref"].startswith("code:handlers.go:")
    result = advance_candidate_hunter_round(
        pipeline_run_id="run-001",
        round_number=1,
        candidate_states=[state],
        observations=observations,
        prior_decisions=[],
    )

    assert result["candidate_decisions"][0]["disposition"] == "refuted"


def test_go_nested_ownership_guard_after_sink_is_not_decisive():
    observations = _build_single_candidate_observations(
        '''
package handlers

func mount(r Router) { r.GET("/records/{recordId}", readRecord) }

func readRecord() {
  record := loadRecord(recordId)
  loadRecordForUser(record, user)
}

func loadRecordForUser(record Record, user User) {
  sendFile(record.Path)
  validateAccess(record, user)
}

func validateAccess(record Record, user User) {
  if record.OwnerID != user.ID { return }
}
''',
        route_path="/records/{recordId}",
        symbol_name="readRecord",
        source_path="handlers.go",
    )
    state = observations["candidate_states"][0]

    assert "control_evidence_ref" not in state
    result = advance_candidate_hunter_round(
        pipeline_run_id="run-001",
        round_number=1,
        candidate_states=[state],
        observations=observations,
        prior_decisions=[],
    )

    assert result["candidate_decisions"][0]["disposition"] == "retained"


def test_ruby_nested_ownership_guard_is_decisive_refutation_evidence():
    observations = _build_single_candidate_observations(
        '''
get "/records/:record_id", to: "records#read_record"

def read_record
  record = load_record(params[:record_id])
  load_record_for_user(record, current_user)
  send_file record.path
end

def load_record_for_user(record, user)
  validate_access(record, user)
end

def validate_access(record, user)
  if record.owner_id != user.id
    deny
  end
end
''',
        source_path="records.rb",
    )
    state = observations["candidate_states"][0]

    assert state["control_evidence_ref"].startswith("code:records.rb:")
    result = advance_candidate_hunter_round(
        pipeline_run_id="run-001",
        round_number=1,
        candidate_states=[state],
        observations=observations,
        prior_decisions=[],
    )

    assert result["candidate_decisions"][0]["disposition"] == "refuted"


def test_ruby_nested_ownership_guard_after_sink_is_not_decisive():
    observations = _build_single_candidate_observations(
        '''
get "/records/:record_id", to: "records#read_record"

def read_record
  record = load_record(params[:record_id])
  load_record_for_user(record, current_user)
end

def load_record_for_user(record, user)
  send_file record.path
  validate_access(record, user)
end

def validate_access(record, user)
  if record.owner_id != user.id
    deny
  end
end
''',
        source_path="records.rb",
    )
    state = observations["candidate_states"][0]

    assert "control_evidence_ref" not in state
    result = advance_candidate_hunter_round(
        pipeline_run_id="run-001",
        round_number=1,
        candidate_states=[state],
        observations=observations,
        prior_decisions=[],
    )

    assert result["candidate_decisions"][0]["disposition"] == "retained"


def test_hypothesis_source_path_does_not_borrow_guard_from_same_named_file():
    route = "/records/{record_id}"
    observations = build_candidate_hunter_observations(
        pipeline_run_id="run-001",
        candidates=[
            {
                "hypothesis_id": "H-001",
                "vuln_type": "authorization",
                "location": f"GET {route}",
                "priority_score": 80,
                "source_facts": [
                    {
                        "fact_type": "authorization_gap_candidate",
                        "artifact_kind": "code",
                        "source_path": "api/routes.py",
                        "symbol_name": "read_record",
                        "route_method": "GET",
                        "route_path": route,
                        "root_cause": "missing_object_ownership_check",
                    }
                ],
            }
        ],
        code_files=[
            {
                "path": "admin/routes.py",
                "content": f'''
from fastapi import APIRouter

router = APIRouter()

@router.get("{route}")
def read_record(record_id: str, current_user):
    verify_record_access(record_id, current_user)
    return send_file(record_id)

def verify_record_access(record_id: str, current_user):
    record = load_record(record_id)
    if record.owner_id != current_user.id:
        raise PermissionError()
    return record
''',
            },
            {
                "path": "api/routes.py",
                "content": f'''
from fastapi import APIRouter

router = APIRouter()

@router.get("{route}")
def read_record(record_id: str):
    return send_file(record_id)
''',
            },
        ],
        surface_facts=[
            {
                "fact_type": "api_surface",
                "artifact_kind": "api",
                "route_method": "GET",
                "route_path": route,
            },
            {"fact_type": "har_context", "artifact_kind": "har"},
        ],
        context_facts=[
            {"fact_type": "scope_context", "artifact_kind": "scope"},
            {"fact_type": "policy_context", "artifact_kind": "policy"},
        ],
    )

    state = observations["candidate_states"][0]

    assert state["hypothesis_source_path"] == "api/routes.py"
    assert "control_evidence_ref" not in state
    result = advance_candidate_hunter_round(
        pipeline_run_id="run-001",
        round_number=1,
        candidate_states=[state],
        observations=observations,
        prior_decisions=[],
    )
    assert result["candidate_decisions"][0]["disposition"] == "retained"


def test_route_bound_code_fact_takes_precedence_over_routeless_fact():
    route = "/records/{record_id}"
    observations = build_candidate_hunter_observations(
        pipeline_run_id="run-001",
        candidates=[
            {
                "hypothesis_id": "H-001",
                "vuln_type": "authorization",
                "location": f"GET {route}",
                "priority_score": 80,
                "source_facts": [
                    {
                        "fact_type": "code_symbol",
                        "artifact_kind": "code",
                        "source_path": "foreign.py",
                        "symbol_name": "read_foreign",
                    },
                    {
                        "fact_type": "authorization_gap_candidate",
                        "artifact_kind": "code",
                        "source_path": "target.py",
                        "symbol_name": "read_record",
                        "route_method": "GET",
                        "route_path": route,
                        "root_cause": "missing_object_ownership_check",
                    },
                ],
            }
        ],
        code_files=[
            {
                "path": "foreign.py",
                "content": '''
def read_foreign(foreign_id: str, current_user):
    foreign = load_record(foreign_id)
    if foreign.owner_id != current_user.id:
        raise PermissionError()
    return send_file(foreign.path)
''',
            },
            {
                "path": "target.py",
                "content": f'''
from fastapi import APIRouter

router = APIRouter()

@router.get("{route}")
def read_record(record_id: str):
    return send_file(record_id)
''',
            },
        ],
        surface_facts=[
            {
                "fact_type": "api_surface",
                "artifact_kind": "api",
                "route_method": "GET",
                "route_path": route,
            },
            {"fact_type": "har_context", "artifact_kind": "har"},
        ],
        context_facts=[
            {"fact_type": "scope_context", "artifact_kind": "scope"},
            {"fact_type": "policy_context", "artifact_kind": "policy"},
        ],
    )
    state = observations["candidate_states"][0]

    assert state["hypothesis_source_path"] == "target.py"
    assert "control_evidence_ref" not in state
    result = advance_candidate_hunter_round(
        pipeline_run_id="run-001",
        round_number=1,
        candidate_states=[state],
        observations=observations,
        prior_decisions=[],
    )

    assert result["candidate_decisions"][0]["disposition"] == "retained"


def test_unique_cross_file_guard_remains_reachable_from_hypothesis_source_path():
    route = "/records/{record_id}"
    persisted_code_facts = [
        CodebaseFactCandidate(
            fact_type="route_handler",
            source_path="api/routes.py",
            symbol_name="read_record",
            route_method="GET",
            route_path=route,
            authz_hint=None,
            sensitivity_label="authorized_local_code",
            payload={"handler": "read_record", "line": 4},
        ),
        CodebaseFactCandidate(
            fact_type="service_call",
            source_path="api/routes.py",
            symbol_name="verify_record_access",
            route_method=None,
            route_path=None,
            authz_hint=None,
            sensitivity_label="authorized_local_code",
            payload={"caller": "read_record", "line": 5},
        ),
        CodebaseFactCandidate(
            fact_type="authz_check",
            source_path="services/access.py",
            symbol_name="verify_record_access",
            route_method=None,
            route_path=None,
            authz_hint="ownership_boundary_check",
            sensitivity_label="authorized_local_code",
            payload={"handler": "verify_record_access", "line": 8},
        ),
        CodebaseFactCandidate(
            fact_type="sensitive_sink",
            source_path="api/routes.py",
            symbol_name="send_file",
            route_method=None,
            route_path=None,
            authz_hint=None,
            sensitivity_label="authorized_local_code",
            payload={"handler": "read_record", "line": 12},
        ),
    ]
    observations = build_candidate_hunter_observations(
        pipeline_run_id="run-001",
        candidates=[
            {
                "hypothesis_id": "H-001",
                "vuln_type": "authorization",
                "location": f"GET {route}",
                "priority_score": 80,
                "source_facts": [
                    {
                        "fact_type": "authorization_gap_candidate",
                        "artifact_kind": "code",
                        "source_path": "api/routes.py",
                        "symbol_name": "read_record",
                        "route_method": "GET",
                        "route_path": route,
                        "root_cause": "missing_object_ownership_check",
                    },
                    {
                        "fact_type": "api_surface",
                        "artifact_kind": "api",
                        "route_method": "GET",
                        "route_path": route,
                    },
                    {"fact_type": "har_context", "artifact_kind": "har"},
                ],
            }
        ],
        code_files=[],
        supplemental_code_facts=persisted_code_facts,
        surface_facts=[],
        context_facts=[
            {"fact_type": "scope_context", "artifact_kind": "scope"},
            {"fact_type": "policy_context", "artifact_kind": "policy"},
        ],
    )

    state = observations["candidate_states"][0]
    result = advance_candidate_hunter_round(
        pipeline_run_id="run-001",
        round_number=1,
        candidate_states=[state],
        observations=observations,
        prior_decisions=[],
    )

    assert state["control_evidence_ref"] == (
        "code:services/access.py:verify_record_access"
    )
    assert result["candidate_decisions"][0]["disposition"] == "refuted"


def test_reachable_public_filter_is_positive_suppression_evidence():
    observations = _build_single_candidate_observations(
        '''
from fastapi import APIRouter

router = APIRouter()

@router.get("/records/{record_id}")
def read_record(record_id: str):
    record = load_published_record(record_id)
    return send_file(record.path)

def load_published_record(record_id: str):
    return record_store.get(record_id=record_id, visibility="public")
'''
    )
    state = observations["candidate_states"][0]

    assert state["public_evidence_ref"] == (
        "code:code.py:load_published_record:public_filter"
    )
    result = advance_candidate_hunter_round(
        pipeline_run_id="run-001",
        round_number=1,
        candidate_states=[state],
        observations=observations,
        prior_decisions=[],
    )
    assert result["candidate_decisions"][0]["disposition"] == "suppressed"


def test_reachable_public_filter_is_not_attached_to_non_authorization_candidate():
    observations = _build_single_candidate_observations(
        '''
from fastapi import APIRouter

router = APIRouter()

@router.get("/records/{record_id}")
def read_record(record_id: str):
    record = load_published_record(record_id)
    return send_file(record.path)

def load_published_record(record_id: str):
    return record_store.get(record_id=record_id, visibility="public")
''',
        vuln_type="ssrf",
        root_cause="missing_ssrf_validation",
    )

    assert "public_evidence_ref" not in observations["candidate_states"][0]


def test_mapper_sensitive_sink_drives_ownership_guard_detection():
    observations = _build_single_candidate_observations(
        '''
from fastapi import APIRouter

router = APIRouter()

@router.get("/records/{record_id}")
def read_record(record_id: str, current_user):
    verify_record_access(record_id, current_user)
    return execute_agent_tool(record_id)

def verify_record_access(record_id: str, current_user):
    record = load_record(record_id)
    if record.owner_id != current_user.id:
        raise PermissionError()
    return record
'''
    )
    state = observations["candidate_states"][0]

    assert state["control_evidence_ref"] == (
        "code:code.py:verify_record_access:ownership_guard"
    )
    result = advance_candidate_hunter_round(
        pipeline_run_id="run-001",
        round_number=1,
        candidate_states=[state],
        observations=observations,
        prior_decisions=[],
    )
    assert result["candidate_decisions"][0]["disposition"] == "refuted"


def test_mapper_sensitive_sink_drives_public_filter_detection():
    observations = _build_single_candidate_observations(
        '''
from fastapi import APIRouter

router = APIRouter()

@router.get("/records/{record_id}")
def read_record(record_id: str):
    record = load_published_record(record_id)
    return execute_agent_tool(record.path)

def load_published_record(record_id: str):
    return record_store.get(record_id=record_id, visibility="public")
'''
    )
    state = observations["candidate_states"][0]

    assert state["public_evidence_ref"] == (
        "code:code.py:load_published_record:public_filter"
    )
    result = advance_candidate_hunter_round(
        pipeline_run_id="run-001",
        round_number=1,
        candidate_states=[state],
        observations=observations,
        prior_decisions=[],
    )
    assert result["candidate_decisions"][0]["disposition"] == "suppressed"


def test_ownership_guard_after_sensitive_sink_is_not_decisive():
    observations = _build_single_candidate_observations(
        '''
from fastapi import APIRouter

router = APIRouter()

@router.get("/records/{record_id}")
def read_record(record_id: str, current_user):
    response = send_file(record_id)
    verify_record_access(record_id, current_user)
    return response

def verify_record_access(record_id: str, current_user):
    record = load_record(record_id)
    if record.owner_id != current_user.id:
        raise PermissionError()
    return record
'''
    )

    assert "control_evidence_ref" not in observations["candidate_states"][0]


def test_conditional_ownership_guard_does_not_dominate_sensitive_sink():
    observations = _build_single_candidate_observations(
        '''
from fastapi import APIRouter

router = APIRouter()

@router.get("/records/{record_id}")
def read_record(record_id: str, current_user, enforce: bool):
    if enforce:
        verify_record_access(record_id, current_user)
    return send_file(record_id)

def verify_record_access(record_id: str, current_user):
    record = load_record(record_id)
    if record.owner_id != current_user.id:
        raise AccessDenied()
    return record
'''
    )

    assert "control_evidence_ref" not in observations["candidate_states"][0]


def test_unrelated_public_query_does_not_suppress_sensitive_sink():
    observations = _build_single_candidate_observations(
        '''
from fastapi import APIRouter

router = APIRouter()

@router.get("/records/{record_id}")
def read_record(record_id: str):
    published = load_published_record(record_id)
    return send_file(record_id)

def load_published_record(record_id: str):
    return record_store.get(record_id=record_id, visibility="public")
'''
    )

    assert "public_evidence_ref" not in observations["candidate_states"][0]


def test_round_snapshot_digest_and_stop_candidate_are_deterministic():
    first = _complete_candidate_state("H-001")
    first["root_cause_id"] = "missing_object_ownership_check:h_001"
    first["shared_root"] = "h_001"
    second = _complete_candidate_state("H-002")
    second["root_cause_id"] = "missing_object_ownership_check:h_002"
    second["shared_root"] = "h_002"

    forward = advance_candidate_hunter_round(
        pipeline_run_id="run-001",
        round_number=1,
        candidate_states=[first, second],
        observations=_safe_observations(),
        prior_decisions=[],
    )
    reversed_result = advance_candidate_hunter_round(
        pipeline_run_id="run-001",
        round_number=1,
        candidate_states=[second, first],
        observations=_safe_observations(),
        prior_decisions=[],
    )
    empty = advance_candidate_hunter_round(
        pipeline_run_id="run-001",
        round_number=1,
        candidate_states=[],
        observations=_safe_observations(),
        prior_decisions=[],
    )

    assert [item["candidate_id"] for item in forward["snapshot_candidates"]] == [
        "H-001",
        "H-002",
    ]
    assert forward["state_digest"] == reversed_result["state_digest"]
    assert len(forward["state_digest"]) == 64
    assert forward["stop_candidate"] == "all_candidates_terminal"
    assert empty["stop_candidate"] == "no_candidates"


def test_later_round_preserves_prior_terminal_decisions_and_candidates():
    retained = _complete_candidate_state("H-001")
    retained["root_cause_id"] = "missing_object_ownership_check:first"
    retained["shared_root"] = "first"
    unresolved = _complete_candidate_state("H-002")
    unresolved["root_cause_id"] = "missing_object_ownership_check:second"
    unresolved["shared_root"] = "second"
    unresolved["observed_artifact_kinds"] = ["scope", "policy", "code", "api"]

    first_round = advance_candidate_hunter_round(
        pipeline_run_id="run-001",
        round_number=1,
        candidate_states=[retained, unresolved],
        observations=_safe_observations(),
        prior_decisions=[],
    )
    completed_second = deepcopy(unresolved)
    completed_second["observed_artifact_kinds"] = REQUIRED_ARTIFACT_KINDS
    second_round = advance_candidate_hunter_round(
        pipeline_run_id="run-001",
        round_number=2,
        candidate_states=[completed_second],
        observations=_safe_observations(),
        prior_decisions=first_round["candidate_decisions"],
    )

    assert {
        decision["candidate_id"]: decision["disposition"]
        for decision in second_round["candidate_decisions"]
    } == {"H-001": "retained", "H-002": "retained"}
    assert {
        candidate["candidate_id"] for candidate in second_round["final_candidates"]
    } == {"H-001", "H-002"}


def test_transition_never_echoes_secret_or_real_user_data_markers():
    state = _complete_candidate_state()
    state["source_fact_refs"].extend(
        [
            "Authorization: Bearer synthetic-placeholder",
            "code:real user data",
        ]
    )

    result = advance_candidate_hunter_round(
        pipeline_run_id="run-001",
        round_number=1,
        candidate_states=[state],
        observations=_safe_observations(),
        prior_decisions=[],
    )

    serialized = json.dumps(result).lower()
    assert "synthetic-placeholder" not in serialized
    assert "bearer" not in serialized
    assert "real user data" not in serialized


def test_observed_shared_service_flows_into_deduplication_decision():
    routes = ["/records/{record_id}", "/records/{record_id}/summary"]
    symbols = ["read_record", "read_record_summary"]
    candidates = [
        {
            "hypothesis_id": f"H-{index:03d}",
            "vuln_type": "authorization",
            "location": f"GET {route}",
            "priority_score": 90 - index,
            "source_facts": [
                {
                    "fact_type": "authorization_gap_candidate",
                    "artifact_kind": "code",
                    "source_path": "code.py",
                    "symbol_name": symbol,
                    "route_method": "GET",
                    "route_path": route,
                    "root_cause": "missing_object_ownership_check",
                }
            ],
        }
        for index, (route, symbol) in enumerate(zip(routes, symbols, strict=True), 1)
    ]
    observations = build_candidate_hunter_observations(
        pipeline_run_id="run-001",
        candidates=candidates,
        code_files=[
            {
                "path": "code.py",
                "content": '''
from fastapi import APIRouter

router = APIRouter()

@router.get("/records/{record_id}")
def read_record(record_id: str):
    return load_record(record_id)

@router.get("/records/{record_id}/summary")
def read_record_summary(record_id: str):
    return load_record(record_id)

def load_record(record_id: str):
    return send_file(record_id)
''',
            }
        ],
        surface_facts=[
            *(
                {
                    "fact_type": "api_surface",
                    "artifact_kind": "api",
                    "route_method": "GET",
                    "route_path": route,
                }
                for route in routes
            ),
            {"fact_type": "har_context", "artifact_kind": "har"},
        ],
        context_facts=[
            {"fact_type": "scope_context", "artifact_kind": "scope"},
            {"fact_type": "policy_context", "artifact_kind": "policy"},
        ],
    )

    assert {
        state["candidate_id"]: state["shared_root"]
        for state in observations["candidate_states"]
    } == {"H-001": "load_record", "H-002": "load_record"}
    result = advance_candidate_hunter_round(
        pipeline_run_id="run-001",
        round_number=1,
        candidate_states=observations["candidate_states"],
        observations=observations,
        prior_decisions=[],
    )
    decisions = {item["candidate_id"]: item for item in result["candidate_decisions"]}
    assert decisions["H-001"]["disposition"] == "retained"
    assert decisions["H-002"]["disposition"] == "deduplicated"
    assert decisions["H-002"]["duplicate_of"] == decisions["H-001"]["root_cause_id"]


@pytest.mark.parametrize("scope_status", [None, "out_of_scope", "ambiguous"])
def test_ineligible_run_creates_no_candidate_hunter_records(scope_status):
    repository, session = _repository()
    try:
        record = _pipeline_run(repository, scope_status) if scope_status else None

        result = run_candidate_hunter_loop(
            repository=repository,
            record=record,
            policy_text="Synthetic local policy.",
            candidates=[],
            observations={"candidate_states": [], **_safe_observations()},
        )

        assert result["status"] == "scope_not_in_scope"
        assert repository.list_campaigns() == []
        assert session.scalar(select(func.count()).select_from(CampaignTaskRecord)) == 0
        assert session.scalar(select(func.count()).select_from(PipelineStageRecord)) == 0
    finally:
        session.close()


def test_malformed_observations_fail_before_candidate_hunter_persistence():
    repository, session = _repository()
    try:
        record = _pipeline_run(repository)

        result = run_candidate_hunter_loop(
            repository=repository,
            record=record,
            policy_text="Synthetic local policy.",
            candidates=[],
            observations=None,
        )

        assert result["status"] == "blocked"
        assert result["stop_reason"] == "unsafe_observations"
        assert repository.list_campaigns() == []
        assert repository.list_pipeline_stages_for_run(record.id) == []
    finally:
        session.close()


def test_eligible_run_creates_one_read_only_campaign_and_loop_task():
    repository, session = _repository()
    try:
        record = _pipeline_run(repository)

        result = run_candidate_hunter_loop(
            repository=repository,
            record=record,
            policy_text="Synthetic local policy.",
            candidates=[],
            observations={"candidate_states": [], **_safe_observations()},
        )

        campaigns = repository.list_campaigns()
        assert len(campaigns) == 1
        campaign = campaigns[0]
        assert result["campaign_id"] == campaign.id
        assert campaign.autonomy_level == "level_0_read_only"
        assert campaign.scope_status == "in_scope"
        assert campaign.default_asset == "local.test"
        assert campaign.allowed_tools == ["static_analyzer", "api_artifact_mapper"]
        assert campaign.payload["pipeline_run_id"] == record.id
        assert all(
            campaign.payload[field] is False for field in _safe_observations()
        )

        budget = repository.get_campaign_budget(campaign.id)
        assert budget is not None
        assert budget.validation_budget == 0

        tasks = repository.list_campaign_tasks(campaign.id)
        assert len(tasks) == 1
        task = tasks[0]
        assert result["task_id"] == task.id
        assert task.task_type == "candidate_hunter_loop"
        assert task.input_refs == [f"pipeline_run:{record.id}"]
        assert all(task.payload[field] is False for field in _safe_observations())
    finally:
        session.close()


def test_ambiguous_existing_loop_ownership_fails_closed_without_third_owner():
    repository, session = _repository()
    try:
        record = _pipeline_run(repository)
        for index in range(2):
            campaign = repository.create_campaign(
                program_id=None,
                name=f"existing owner {index}",
                autonomy_level="level_0_read_only",
                scope_status="in_scope",
                policy_text="Synthetic local policy.",
                default_asset=record.asset,
                allowed_tools=["static_analyzer", "api_artifact_mapper"],
                created_by="test",
                payload={
                    "pipeline_run_id": record.id,
                    **_safe_observations(),
                },
            )
            repository.create_campaign_task(
                campaign_id=campaign.id,
                task_type="candidate_hunter_loop",
                agent_type="candidate_hunter",
                title="existing loop",
                input_refs=[f"pipeline_run:{record.id}"],
                payload=_safe_observations(),
            )

        result = run_candidate_hunter_loop(
            repository=repository,
            record=record,
            policy_text="Synthetic local policy.",
            candidates=[],
            observations={"candidate_states": [], **_safe_observations()},
        )

        assert result["status"] == "blocked"
        assert result["stop_reason"] == "ambiguous_loop_owner"
        assert len(repository.list_campaigns()) == 2
        assert repository.list_pipeline_stages_for_run(record.id) == []
    finally:
        session.close()


def test_loop_persists_one_complete_immutable_round_in_stage_order():
    repository, session = _repository()
    try:
        record = _pipeline_run(repository)
        state = _complete_candidate_state()
        state["candidate_key"] = f"{record.id}:H-001"
        result = run_candidate_hunter_loop(
            repository=repository,
            record=record,
            policy_text="Synthetic local policy.",
            candidates=[],
            observations={
                "candidate_states": [state],
                **_safe_observations(),
            },
        )

        stages = repository.list_pipeline_stages_for_run(record.id)
        assert [stage.stage_key for stage in stages] == [
            "candidate_hunter_snapshot",
            "candidate_hunter_evidence_request",
            "candidate_hunter_decision",
            "candidate_hunter_rerank",
        ]
        assert [stage.stage_order for stage in stages] == [1, 2, 3, 4]
        assert len({stage.payload["idempotency_key"] for stage in stages}) == 4
        for stage in stages:
            assert stage.status == "completed"
            assert stage.safety_gate_state == "safe"
            assert stage.payload["schema_version"] == "candidate_hunter_loop_v1"
            assert stage.payload["round"] == 1
            assert stage.payload["state_digest"] == result["state_digest"]
            assert all(
                stage.payload[field] is False for field in _safe_observations()
            )
        assert result["status"] == "completed"
        assert result["stop_reason"] == "all_candidates_terminal"
    finally:
        session.close()


def test_loop_replay_reuses_campaign_task_and_immutable_stages():
    repository, session = _repository()
    try:
        record = _pipeline_run(repository)
        state = _complete_candidate_state()
        state["candidate_key"] = f"{record.id}:H-001"
        kwargs = {
            "repository": repository,
            "record": record,
            "policy_text": "Synthetic local policy.",
            "candidates": [],
            "observations": {
                "candidate_states": [state],
                **_safe_observations(),
            },
        }

        first = run_candidate_hunter_loop(**kwargs)
        original_stages = repository.list_pipeline_stages_for_run(record.id)
        original_stage_ids = [stage.id for stage in original_stages]
        original_payloads = [deepcopy(stage.payload) for stage in original_stages]
        second = run_candidate_hunter_loop(**kwargs)

        campaigns = repository.list_campaigns()
        assert len(campaigns) == 1
        assert len(repository.list_campaign_tasks(campaigns[0].id)) == 1
        replayed_stages = repository.list_pipeline_stages_for_run(record.id)
        assert [stage.id for stage in replayed_stages] == original_stage_ids
        assert [stage.payload for stage in replayed_stages] == original_payloads
        assert second["campaign_id"] == first["campaign_id"]
        assert second["task_id"] == first["task_id"]
        assert second["stage_refs"] == first["stage_refs"]
    finally:
        session.close()


def test_loop_resume_appends_only_missing_stages_after_interruption(monkeypatch):
    repository, session = _repository()
    try:
        record = _pipeline_run(repository)
        state = _complete_candidate_state()
        state["candidate_key"] = f"{record.id}:H-001"
        kwargs = {
            "repository": repository,
            "record": record,
            "policy_text": "Synthetic local policy.",
            "candidates": [],
            "observations": {
                "candidate_states": [state],
                **_safe_observations(),
            },
        }
        original_save = repository.save_pipeline_stage
        call_count = 0

        def interrupting_save(**stage_kwargs):
            nonlocal call_count
            call_count += 1
            if call_count == 2:
                raise RuntimeError("simulated interruption")
            return original_save(**stage_kwargs)

        monkeypatch.setattr(repository, "save_pipeline_stage", interrupting_save)
        with pytest.raises(RuntimeError, match="simulated interruption"):
            run_candidate_hunter_loop(**kwargs)

        partial_stages = repository.list_pipeline_stages_for_run(record.id)
        assert [stage.stage_key for stage in partial_stages] == [
            "candidate_hunter_snapshot"
        ]
        original_snapshot_id = partial_stages[0].id

        monkeypatch.setattr(repository, "save_pipeline_stage", original_save)
        run_candidate_hunter_loop(**kwargs)

        resumed_stages = repository.list_pipeline_stages_for_run(record.id)
        assert [stage.stage_key for stage in resumed_stages] == [
            "candidate_hunter_snapshot",
            "candidate_hunter_evidence_request",
            "candidate_hunter_decision",
            "candidate_hunter_rerank",
        ]
        assert resumed_stages[0].id == original_snapshot_id
    finally:
        session.close()


def test_projection_loader_uses_latest_valid_rerank_and_rejects_unsafe_stage():
    repository, session = _repository()
    try:
        record = _pipeline_run(repository)
        state = _complete_candidate_state()
        state["candidate_key"] = f"{record.id}:H-001"
        run_candidate_hunter_loop(
            repository=repository,
            record=record,
            policy_text="Synthetic local policy.",
            candidates=[],
            observations={
                "candidate_states": [state],
                **_safe_observations(),
            },
        )

        projection = load_candidate_hunter_projection(
            repository=repository,
            pipeline_run_id=record.id,
        )

        assert projection["status"] == "ready"
        assert [item["candidate_id"] for item in projection["final_candidates"]] == [
            "H-001"
        ]
        assert projection["candidate_decisions"][0]["disposition"] == "retained"
        candidate = projection["final_candidates"][0]
        decision = projection["candidate_decisions"][0]
        for field in (
            "survived_kill_score",
            "evidence_completeness_score",
            "priority_score",
        ):
            assert candidate[field] == decision[field]
        assert candidate["priority_score"] == 80
        assert candidate["evidence_completeness_score"] == len(REQUIRED_ARTIFACT_KINDS)
        assert projection["audit"]["round_count"] == 1
        assert len(projection["audit"]["stage_refs"]) == 4

        rerank = repository.list_pipeline_stages_for_run(record.id)[-1]
        rerank.payload = {**rerank.payload, "execution_allowed": True}
        session.add(rerank)
        session.commit()

        blocked = load_candidate_hunter_projection(
            repository=repository,
            pipeline_run_id=record.id,
        )
        assert blocked["status"] == "invalid_stage_sequence"
        assert blocked["final_candidates"] == []
        assert blocked["candidate_decisions"] == []
    finally:
        session.close()


def test_projection_loader_rejects_cross_stage_decision_mismatch():
    repository, session = _repository()
    try:
        record = _pipeline_run(repository)
        state = _complete_candidate_state()
        state["candidate_key"] = f"{record.id}:H-001"
        run_candidate_hunter_loop(
            repository=repository,
            record=record,
            policy_text="Synthetic local policy.",
            candidates=[],
            observations={
                "candidate_states": [state],
                **_safe_observations(),
            },
        )
        rerank = repository.list_pipeline_stages_for_run(record.id)[-1]
        rerank.payload = {**rerank.payload, "candidate_decisions": []}
        session.add(rerank)
        session.commit()

        projection = load_candidate_hunter_projection(
            repository=repository,
            pipeline_run_id=record.id,
        )

        assert projection["status"] == "invalid_stage_sequence"
        assert projection["final_candidates"] == []
        assert projection["candidate_decisions"] == []
    finally:
        session.close()


@pytest.mark.parametrize("tamper", ["rank", "evidence", "code_path"])
def test_projection_loader_rejects_invalid_rerank_schema(tamper: str):
    repository, session = _repository()
    try:
        record = _pipeline_run(repository)
        state = _complete_candidate_state()
        state["candidate_key"] = f"{record.id}:H-001"
        run_candidate_hunter_loop(
            repository=repository,
            record=record,
            policy_text="Synthetic local policy.",
            candidates=[],
            observations={
                "candidate_states": [state],
                **_safe_observations(),
            },
        )
        stages = repository.list_pipeline_stages_for_run(record.id)
        decision_stage = stages[-2]
        rerank = stages[-1]
        if tamper == "rank":
            final_candidates = deepcopy(rerank.payload["final_candidates"])
            final_candidates[0]["rank"] = 2
            rerank.payload = {
                **rerank.payload,
                "final_candidates": final_candidates,
            }
            session.add(rerank)
        elif tamper == "code_path":
            final_candidates = deepcopy(rerank.payload["final_candidates"])
            final_candidates[0]["affected_code_path"] = "code:invented.py:read_record"
            rerank.payload = {
                **rerank.payload,
                "final_candidates": final_candidates,
            }
            session.add(rerank)
        else:
            decisions = deepcopy(rerank.payload["candidate_decisions"])
            decisions[0]["evidence_refs"] = []
            decision_stage.payload = {
                **decision_stage.payload,
                "candidate_decisions": decisions,
            }
            rerank.payload = {
                **rerank.payload,
                "candidate_decisions": decisions,
            }
            session.add_all([decision_stage, rerank])
        session.commit()

        projection = load_candidate_hunter_projection(
            repository=repository,
            pipeline_run_id=record.id,
        )

        assert projection["status"] == "invalid_stage_sequence"
        assert projection["final_candidates"] == []
    finally:
        session.close()


def test_changed_unresolved_state_appends_rounds_until_max_rounds_reached():
    repository, session = _repository()
    try:
        record = _pipeline_run(repository)
        state = _complete_candidate_state()
        state["candidate_key"] = f"{record.id}:H-001"

        def run_with_kinds(kinds: list[str]):
            round_state = deepcopy(state)
            round_state["observed_artifact_kinds"] = kinds
            return run_candidate_hunter_loop(
                repository=repository,
                record=record,
                policy_text="Synthetic local policy.",
                candidates=[],
                observations={
                    "candidate_states": [round_state],
                    **_safe_observations(),
                },
            )

        first = run_with_kinds(["scope", "policy"])
        second = run_with_kinds(["scope", "policy", "code"])
        third = run_with_kinds(["scope", "policy", "code", "api"])
        fourth = run_with_kinds(REQUIRED_ARTIFACT_KINDS)

        assert first["round_count"] == 1
        assert second["round_count"] == 2
        assert third["round_count"] == 3
        assert third["status"] == "needs_evidence"
        assert third["stop_reason"] == "max_rounds_reached"
        assert fourth["round_count"] == 3
        assert fourth["stop_reason"] == "max_rounds_reached"
        stages = repository.list_pipeline_stages_for_run(record.id)
        assert [stage.stage_order for stage in stages] == list(range(1, 13))
        assert [stage.payload["round"] for stage in stages] == [
            1,
            1,
            1,
            1,
            2,
            2,
            2,
            2,
            3,
            3,
            3,
            3,
        ]
    finally:
        session.close()


def test_persisted_second_round_closes_evidence_gap_without_losing_prior_candidate():
    repository, session = _repository()
    try:
        record = _pipeline_run(repository)
        retained = _complete_candidate_state("H-001")
        retained["candidate_key"] = f"{record.id}:H-001"
        retained["root_cause_id"] = "missing_object_ownership_check:first"
        retained["shared_root"] = "first"
        unresolved = _complete_candidate_state("H-002")
        unresolved["candidate_key"] = f"{record.id}:H-002"
        unresolved["root_cause_id"] = "missing_object_ownership_check:second"
        unresolved["shared_root"] = "second"
        unresolved["observed_artifact_kinds"] = ["scope", "policy", "code", "api"]

        first = run_candidate_hunter_loop(
            repository=repository,
            record=record,
            policy_text="Synthetic local policy.",
            candidates=[],
            observations={
                "candidate_states": [retained, unresolved],
                **_safe_observations(),
            },
        )
        completed_second = deepcopy(unresolved)
        completed_second["observed_artifact_kinds"] = REQUIRED_ARTIFACT_KINDS
        second = run_candidate_hunter_loop(
            repository=repository,
            record=record,
            policy_text="Synthetic local policy.",
            candidates=[],
            observations={
                "candidate_states": [completed_second],
                **_safe_observations(),
            },
        )

        assert first["status"] == "needs_evidence"
        assert second["status"] == "completed"
        assert second["round_count"] == 2
        assert {item["candidate_id"] for item in second["final_candidates"]} == {
            "H-001",
            "H-002",
        }
        projection = load_candidate_hunter_projection(
            repository=repository,
            pipeline_run_id=record.id,
        )
        assert projection["status"] == "ready"
        assert projection["audit"]["round_count"] == 2
    finally:
        session.close()


def test_single_run_reanalyzes_requested_local_evidence_in_a_second_round():
    repository, session = _repository()
    try:
        record = _pipeline_run(repository)
        observations = _build_single_candidate_observations(
            '''
from fastapi import APIRouter

router = APIRouter()

@router.get("/records/{record_id}")
def read_record(record_id: str, current_user):
    verify_record_access(record_id, current_user)
    return send_file(record_id)

def verify_record_access(record_id: str, current_user):
    record = load_record(record_id)
    if record.owner_id != current_user.id:
        raise PermissionError()
    return record
''',
            pipeline_run_id=record.id,
        )

        result = run_candidate_hunter_loop(
            repository=repository,
            record=record,
            policy_text="Synthetic local policy.",
            candidates=[],
            observations=observations,
        )

        assert result["status"] == "completed"
        assert result["stop_reason"] == "all_candidates_terminal"
        assert result["round_count"] == 2
        assert result["final_candidates"] == []
        assert result["candidate_decisions"][0]["disposition"] == "refuted"
        stages = repository.list_pipeline_stages_for_run(record.id)
        assert [stage.payload["round"] for stage in stages] == [
            1,
            1,
            1,
            1,
            2,
            2,
            2,
            2,
        ]
        assert stages[1].payload["evidence_requests"]
        assert stages[2].payload["candidate_decisions"] == []
        assert stages[6].payload["candidate_decisions"][0]["disposition"] == (
            "refuted"
        )

        replay = run_candidate_hunter_loop(
            repository=repository,
            record=record,
            policy_text="Synthetic local policy.",
            candidates=[],
            observations=observations,
        )
        assert replay["stage_refs"] == result["stage_refs"]
        assert len(repository.list_pipeline_stages_for_run(record.id)) == 8
    finally:
        session.close()


def test_persisted_java_ownership_guard_refutes_without_source_body():
    route = "/records/{recordId}"
    source_marker = "raw-java-source-must-not-reach-candidate-hunter"
    persisted_code_facts = [
        CodebaseFactCandidate(
            fact_type="route_handler",
            source_path="src/RecordsController.java",
            symbol_name="readRecord",
            route_method="GET",
            route_path=route,
            authz_hint=None,
            sensitivity_label="authorized_local_code",
            payload={
                "handler": "readRecord",
                "line": 4,
                "raw_source": source_marker,
            },
        ),
        CodebaseFactCandidate(
            fact_type="service_call",
            source_path="src/RecordsController.java",
            symbol_name="verifyRecordAccess",
            route_method=None,
            route_path=None,
            authz_hint=None,
            sensitivity_label="authorized_local_code",
            payload={"handler": "readRecord", "caller": "readRecord", "line": 5},
        ),
        CodebaseFactCandidate(
            fact_type="authz_check",
            source_path="src/RecordsController.java",
            symbol_name="verifyRecordAccess",
            route_method=None,
            route_path=None,
            authz_hint="ownership_boundary_check",
            sensitivity_label="authorized_local_code",
            payload={"handler": "verifyRecordAccess", "line": 8},
        ),
        CodebaseFactCandidate(
            fact_type="sensitive_sink",
            source_path="src/RecordsController.java",
            symbol_name="sendFile",
            route_method=None,
            route_path=None,
            authz_hint=None,
            sensitivity_label="authorized_local_code",
            payload={"handler": "readRecord", "line": 12},
        ),
    ]
    observations = build_candidate_hunter_observations(
        pipeline_run_id="run-001",
        candidates=[
            {
                "hypothesis_id": "H-java-001",
                "vuln_type": "authorization",
                "location": f"GET {route}",
                "priority_score": 80,
                "source_facts": [
                    {
                        "fact_type": "authorization_gap_candidate",
                        "artifact_kind": "code",
                        "source_path": "src/RecordsController.java",
                        "symbol_name": "readRecord",
                        "route_method": "GET",
                        "route_path": route,
                        "root_cause": "missing_object_ownership_check",
                    },
                    {
                        "fact_type": "api_surface",
                        "artifact_kind": "api",
                        "route_method": "GET",
                        "route_path": route,
                    },
                    {"fact_type": "har_context", "artifact_kind": "har"},
                ],
            }
        ],
        code_files=[],
        supplemental_code_facts=persisted_code_facts,
        surface_facts=[],
        context_facts=[
            {"fact_type": "scope_context", "artifact_kind": "scope"},
            {"fact_type": "policy_context", "artifact_kind": "policy"},
        ],
    )

    state = observations["candidate_states"][0]
    result = advance_candidate_hunter_round(
        pipeline_run_id="run-001",
        round_number=1,
        candidate_states=[state],
        observations=observations,
        prior_decisions=[],
    )

    assert state["control_evidence_ref"] == (
        "code:src/RecordsController.java:verifyRecordAccess"
    )
    assert result["candidate_decisions"][0]["disposition"] == "refuted"
    assert source_marker not in json.dumps(observations)


def test_typescript_express_one_hop_ownership_guard_refutes_candidate():
    route = "/records/:recordId"
    observations = build_candidate_hunter_observations(
        pipeline_run_id="run-001",
        candidates=[
            {
                "hypothesis_id": "H-001",
                "vuln_type": "authorization",
                "location": f"GET {route}",
                "priority_score": 80,
                "source_facts": [
                    {
                        "fact_type": "authorization_gap_candidate",
                        "artifact_kind": "code",
                        "source_path": "routes.ts",
                        "symbol_name": "readRecord",
                        "route_method": "GET",
                        "route_path": route,
                        "root_cause": "missing_object_ownership_check",
                    }
                ],
            }
        ],
        code_files=[
            {
                "path": "routes.ts",
                "content": '''
import { Router } from "express";

const router = Router();

router.get("/records/:recordId", readRecord);

async function readRecord(req: Request, res: Response) {
  await verifyRecordAccess(req.params.recordId, req.user);
  return sendFile(req.params.recordId);
}

async function verifyRecordAccess(recordId: string, user: User) {
  const record = await loadRecord(recordId);
  if (record.ownerId !== user.id) {
    return res.sendStatus(403);
  }
  return record;
}
''',
            }
        ],
        surface_facts=[
            {
                "fact_type": "api_surface",
                "artifact_kind": "api",
                "route_method": "GET",
                "route_path": route,
            },
            {"fact_type": "har_context", "artifact_kind": "har"},
        ],
        context_facts=[
            {"fact_type": "scope_context", "artifact_kind": "scope"},
            {"fact_type": "policy_context", "artifact_kind": "policy"},
        ],
    )

    state = observations["candidate_states"][0]
    result = advance_candidate_hunter_round(
        pipeline_run_id="run-001",
        round_number=1,
        candidate_states=[state],
        observations=observations,
        prior_decisions=[],
    )

    assert state["control_evidence_ref"].startswith("code:routes.ts:")
    assert result["candidate_decisions"][0]["disposition"] == "refuted"


def test_typescript_nestjs_class_guard_does_not_refute_an_adjacent_controller():
    route = "/public-records/:recordId"
    observations = build_candidate_hunter_observations(
        pipeline_run_id="run-001",
        candidates=[
            {
                "hypothesis_id": "H-001",
                "vuln_type": "authorization",
                "location": f"GET {route}",
                "priority_score": 80,
                "source_facts": [
                    {
                        "fact_type": "authorization_gap_candidate",
                        "artifact_kind": "code",
                        "source_path": "records.controller.ts",
                        "symbol_name": "readPublicRecord",
                        "route_method": "GET",
                        "route_path": route,
                        "root_cause": "missing_object_ownership_check",
                    }
                ],
            }
        ],
        code_files=[
            {
                "path": "records.controller.ts",
                "content": '''
import { Controller, Get, UseGuards } from "@nestjs/common";

@UseGuards(OwnerGuard)
@Controller("admin-records")
export class AdminRecordsController {
  @Get(":recordId")
  async readAdminRecord(recordId: string) {
    return sendFile(recordId);
  }
}

@Controller("public-records")
export class PublicRecordsController {
  @Get(":recordId")
  async readPublicRecord(recordId: string) {
    return sendFile(recordId);
  }
}
''',
            }
        ],
        surface_facts=[
            {
                "fact_type": "api_surface",
                "artifact_kind": "api",
                "route_method": "GET",
                "route_path": route,
            },
            {"fact_type": "har_context", "artifact_kind": "har"},
        ],
        context_facts=[
            {"fact_type": "scope_context", "artifact_kind": "scope"},
            {"fact_type": "policy_context", "artifact_kind": "policy"},
        ],
    )

    state = observations["candidate_states"][0]
    result = advance_candidate_hunter_round(
        pipeline_run_id="run-001",
        round_number=1,
        candidate_states=[state],
        observations=observations,
        prior_decisions=[],
    )

    assert "control_evidence_ref" not in state
    assert result["candidate_decisions"][0]["disposition"] == "retained"


def test_typescript_nestjs_injectable_ownership_guard_refutes_candidate():
    route = "/records/:recordId"
    observations = build_candidate_hunter_observations(
        pipeline_run_id="run-001",
        candidates=[
            {
                "hypothesis_id": "H-001",
                "vuln_type": "authorization",
                "location": f"GET {route}",
                "priority_score": 80,
                "source_facts": [
                    {
                        "fact_type": "authorization_gap_candidate",
                        "artifact_kind": "code",
                        "source_path": "records.controller.ts",
                        "symbol_name": "readRecord",
                        "route_method": "GET",
                        "route_path": route,
                        "root_cause": "missing_object_ownership_check",
                    }
                ],
            }
        ],
        code_files=[
            {
                "path": "records.controller.ts",
                "content": '''
import { Controller, Get } from "@nestjs/common";
import { RecordsService } from "./records.service";

@Controller("records")
export class RecordsController {
  constructor(private readonly recordsService: RecordsService) {}

  @Get(":recordId")
  async readRecord(recordId: string, user: User) {
    const record = await this.recordsService.getForUser(recordId, user);
    return sendFile(record.path);
  }
}
''',
            },
            {
                "path": "records.service.ts",
                "content": '''
import { Injectable } from "@nestjs/common";

@Injectable()
export class RecordsService {
  async getForUser(recordId: string, user: User) {
    const record = await loadRecord(recordId);
    if (record.ownerId !== user.id) {
      return deny();
    }
    return record;
  }
}
''',
            }
        ],
        surface_facts=[
            {
                "fact_type": "api_surface",
                "artifact_kind": "api",
                "route_method": "GET",
                "route_path": route,
            },
            {"fact_type": "har_context", "artifact_kind": "har"},
        ],
        context_facts=[
            {"fact_type": "scope_context", "artifact_kind": "scope"},
            {"fact_type": "policy_context", "artifact_kind": "policy"},
        ],
    )

    state = observations["candidate_states"][0]
    result = advance_candidate_hunter_round(
        pipeline_run_id="run-001",
        round_number=1,
        candidate_states=[state],
        observations=observations,
        prior_decisions=[],
    )

    assert state["control_evidence_ref"] == "code:records.service.ts:owner_id_filter"
    assert result["candidate_decisions"][0]["disposition"] == "refuted"


def test_typescript_nestjs_imported_service_does_not_link_same_named_service_from_another_module():
    route = "/records/:recordId"
    observations = build_candidate_hunter_observations(
        pipeline_run_id="run-001",
        candidates=[
            {
                "hypothesis_id": "H-001",
                "vuln_type": "authorization",
                "location": f"GET {route}",
                "priority_score": 80,
                "source_facts": [
                    {
                        "fact_type": "authorization_gap_candidate",
                        "artifact_kind": "code",
                        "source_path": "records.controller.ts",
                        "symbol_name": "readRecord",
                        "route_method": "GET",
                        "route_path": route,
                        "root_cause": "missing_object_ownership_check",
                    }
                ],
            }
        ],
        code_files=[
            {
                "path": "records.controller.ts",
                "content": '''
import { Controller, Get } from "@nestjs/common";
import { RecordsService } from "./audit/records.service";

@Controller("records")
export class RecordsController {
  constructor(private readonly recordsService: RecordsService) {}

  @Get(":recordId")
  async readRecord(recordId: string, user: User) {
    const record = await this.recordsService.getForUser(recordId, user);
    return sendFile(record.path);
  }
}
''',
            },
            {
                "path": "audit/records.service.ts",
                "content": '''
import { Injectable } from "@nestjs/common";

@Injectable()
export class RecordsService {
  async getForUser(recordId: string, user: User) {
    return recordId;
  }
}
''',
            },
            {
                "path": "records.service.ts",
                "content": '''
import { Injectable } from "@nestjs/common";

@Injectable()
export class RecordsService {
  async getForUser(recordId: string, user: User) {
    const record = await loadRecord(recordId);
    if (record.ownerId !== user.id) {
      return deny();
    }
    return record;
  }
}
''',
            },
        ],
        surface_facts=[
            {
                "fact_type": "api_surface",
                "artifact_kind": "api",
                "route_method": "GET",
                "route_path": route,
            },
            {"fact_type": "har_context", "artifact_kind": "har"},
        ],
        context_facts=[
            {"fact_type": "scope_context", "artifact_kind": "scope"},
            {"fact_type": "policy_context", "artifact_kind": "policy"},
        ],
    )

    state = observations["candidate_states"][0]
    result = advance_candidate_hunter_round(
        pipeline_run_id="run-001",
        round_number=1,
        candidate_states=[state],
        observations=observations,
        prior_decisions=[],
    )

    assert "control_evidence_ref" not in state
    assert result["candidate_decisions"][0]["disposition"] == "retained"


def test_typescript_nestjs_service_receiver_does_not_link_unrelated_service_method():
    route = "/records/:recordId"
    observations = build_candidate_hunter_observations(
        pipeline_run_id="run-001",
        candidates=[
            {
                "hypothesis_id": "H-001",
                "vuln_type": "authorization",
                "location": f"GET {route}",
                "priority_score": 80,
                "source_facts": [
                    {
                        "fact_type": "authorization_gap_candidate",
                        "artifact_kind": "code",
                        "source_path": "records.controller.ts",
                        "symbol_name": "readRecord",
                        "route_method": "GET",
                        "route_path": route,
                        "root_cause": "missing_object_ownership_check",
                    }
                ],
            }
        ],
        code_files=[
            {
                "path": "records.controller.ts",
                "content": '''
import { Controller, Get } from "@nestjs/common";

@Controller("records")
export class RecordsController {
  constructor(private readonly auditService: AuditService) {}

  @Get(":recordId")
  async readRecord(recordId: string, user: User) {
    const record = await this.auditService.getForUser(recordId, user);
    return sendFile(record.path);
  }
}
''',
            },
            {
                "path": "records.service.ts",
                "content": '''
import { Injectable } from "@nestjs/common";

@Injectable()
export class RecordsService {
  async getForUser(recordId: string, user: User) {
    const record = await loadRecord(recordId);
    if (record.ownerId !== user.id) {
      return deny();
    }
    return record;
  }
}
''',
            },
        ],
        surface_facts=[
            {
                "fact_type": "api_surface",
                "artifact_kind": "api",
                "route_method": "GET",
                "route_path": route,
            },
            {"fact_type": "har_context", "artifact_kind": "har"},
        ],
        context_facts=[
            {"fact_type": "scope_context", "artifact_kind": "scope"},
            {"fact_type": "policy_context", "artifact_kind": "policy"},
        ],
    )

    state = observations["candidate_states"][0]
    result = advance_candidate_hunter_round(
        pipeline_run_id="run-001",
        round_number=1,
        candidate_states=[state],
        observations=observations,
        prior_decisions=[],
    )

    assert "control_evidence_ref" not in state
    assert result["candidate_decisions"][0]["disposition"] == "retained"


def test_typescript_nestjs_same_file_service_methods_do_not_share_authz_facts():
    route = "/records/:recordId"
    observations = build_candidate_hunter_observations(
        pipeline_run_id="run-001",
        candidates=[
            {
                "hypothesis_id": "H-001",
                "vuln_type": "authorization",
                "location": f"GET {route}",
                "priority_score": 80,
                "source_facts": [
                    {
                        "fact_type": "authorization_gap_candidate",
                        "artifact_kind": "code",
                        "source_path": "records.ts",
                        "symbol_name": "readRecord",
                        "route_method": "GET",
                        "route_path": route,
                        "root_cause": "missing_object_ownership_check",
                    }
                ],
            }
        ],
        code_files=[
            {
                "path": "records.ts",
                "content": '''
import { Controller, Get, Injectable } from "@nestjs/common";

@Controller("records")
export class RecordsController {
  constructor(private readonly recordsService: RecordsService) {}

  @Get(":recordId")
  async readRecord(recordId: string, user: User) {
    const record = await this.recordsService.getForUser(recordId, user);
    return sendFile(record.path);
  }
}

@Injectable()
export class RecordsService {
  async getForUser(recordId: string, user: User) {
    return loadRecord(recordId);
  }
}

@Injectable()
export class AuditService {
  async getForUser(recordId: string, user: User) {
    const record = await loadRecord(recordId);
    if (record.ownerId !== user.id) {
      return deny();
    }
    return record;
  }
}
''',
            }
        ],
        surface_facts=[
            {
                "fact_type": "api_surface",
                "artifact_kind": "api",
                "route_method": "GET",
                "route_path": route,
            },
            {"fact_type": "har_context", "artifact_kind": "har"},
        ],
        context_facts=[
            {"fact_type": "scope_context", "artifact_kind": "scope"},
            {"fact_type": "policy_context", "artifact_kind": "policy"},
        ],
    )

    state = observations["candidate_states"][0]
    result = advance_candidate_hunter_round(
        pipeline_run_id="run-001",
        round_number=1,
        candidate_states=[state],
        observations=observations,
        prior_decisions=[],
    )

    assert "control_evidence_ref" not in state
    assert result["candidate_decisions"][0]["disposition"] == "retained"


def test_typescript_express_two_hop_verified_access_guard_refutes_candidate():
    route = "/records/:recordId"
    observations = build_candidate_hunter_observations(
        pipeline_run_id="run-001",
        candidates=[
            {
                "hypothesis_id": "H-001",
                "vuln_type": "authorization",
                "location": f"GET {route}",
                "priority_score": 80,
                "source_facts": [
                    {
                        "fact_type": "authorization_gap_candidate",
                        "artifact_kind": "code",
                        "source_path": "routes.ts",
                        "symbol_name": "readRecord",
                        "route_method": "GET",
                        "route_path": route,
                        "root_cause": "missing_object_ownership_check",
                    }
                ],
            }
        ],
        code_files=[
            {
                "path": "routes.ts",
                "content": '''
import { Router } from "express";

const router = Router();

router.get("/records/:recordId", readRecord);

async function readRecord(req: Request, res: Response) {
  const record = await verifyRecordAccess(req.params.recordId, req.user);
  return sendFile(record.id);
}

function isRecordOwner(record: Record, user: User): boolean {
  return record.ownerId === user.id;
}

async function verifyRecordAccess(recordId: string, user: User) {
  const record = await loadRecord(recordId);
  if (isRecordOwner(record, user)) {
    return record;
  }
  return deny();
}
''',
            }
        ],
        surface_facts=[
            {
                "fact_type": "api_surface",
                "artifact_kind": "api",
                "route_method": "GET",
                "route_path": route,
            },
            {"fact_type": "har_context", "artifact_kind": "har"},
        ],
        context_facts=[
            {"fact_type": "scope_context", "artifact_kind": "scope"},
            {"fact_type": "policy_context", "artifact_kind": "policy"},
        ],
    )

    state = observations["candidate_states"][0]
    result = advance_candidate_hunter_round(
        pipeline_run_id="run-001",
        round_number=1,
        candidate_states=[state],
        observations=observations,
        prior_decisions=[],
    )

    assert state["control_evidence_ref"] == "code:routes.ts:owner_id_filter"
    assert result["candidate_decisions"][0]["disposition"] == "refuted"


def test_typescript_two_hop_verified_access_after_sink_is_not_decisive():
    route = "/records/:recordId"
    observations = build_candidate_hunter_observations(
        pipeline_run_id="run-001",
        candidates=[
            {
                "hypothesis_id": "H-001",
                "vuln_type": "authorization",
                "location": f"GET {route}",
                "priority_score": 80,
                "source_facts": [
                    {
                        "fact_type": "authorization_gap_candidate",
                        "artifact_kind": "code",
                        "source_path": "routes.ts",
                        "symbol_name": "readRecord",
                        "route_method": "GET",
                        "route_path": route,
                        "root_cause": "missing_object_ownership_check",
                    }
                ],
            }
        ],
        code_files=[
            {
                "path": "routes.ts",
                "content": '''
import { Router } from "express";

const router = Router();

router.get("/records/:recordId", readRecord);

async function readRecord(req: Request, res: Response) {
  const response = sendFile(req.params.recordId);
  await verifyRecordAccess(req.params.recordId, req.user);
  return response;
}

function isRecordOwner(record: Record, user: User): boolean {
  return record.ownerId === user.id;
}

async function verifyRecordAccess(recordId: string, user: User) {
  const record = await loadRecord(recordId);
  if (isRecordOwner(record, user)) {
    return record;
  }
  return deny();
}
''',
            }
        ],
        surface_facts=[
            {
                "fact_type": "api_surface",
                "artifact_kind": "api",
                "route_method": "GET",
                "route_path": route,
            },
            {"fact_type": "har_context", "artifact_kind": "har"},
        ],
        context_facts=[
            {"fact_type": "scope_context", "artifact_kind": "scope"},
            {"fact_type": "policy_context", "artifact_kind": "policy"},
        ],
    )

    state = observations["candidate_states"][0]
    result = advance_candidate_hunter_round(
        pipeline_run_id="run-001",
        round_number=1,
        candidate_states=[state],
        observations=observations,
        prior_decisions=[],
    )

    assert "control_evidence_ref" not in state
    assert result["candidate_decisions"][0]["disposition"] == "retained"


def test_typescript_jwt_verification_control_refutes_jwt_candidate():
    route = "/reports/:reportId/export"
    observations = build_candidate_hunter_observations(
        pipeline_run_id="run-001",
        candidates=[
            {
                "hypothesis_id": "H-jwt-001",
                "vuln_type": "jwt_authentication_bypass",
                "location": f"GET {route}",
                "priority_score": 85,
                "source_facts": [
                    {
                        "fact_type": "authorization_gap_candidate",
                        "artifact_kind": "code",
                        "source_path": "routes.ts",
                        "symbol_name": "exportReport",
                        "route_method": "GET",
                        "route_path": route,
                        "root_cause": "missing_jwt_verification",
                    }
                ],
            }
        ],
        code_files=[
            {
                "path": "routes.ts",
                "content": '''
import { Router } from "express";
import jwt from "jsonwebtoken";

const router = Router();

router.get("/reports/:reportId/export", exportReport);

async function exportReport(req: Request, res: Response) {
  const claims = jwt.decode(req.headers.authorization || "");
  const verifiedClaims = jwt.verify(req.headers.authorization || "", verificationKey);
  return sendFile(verifiedClaims.path);
}
''',
            }
        ],
        surface_facts=[
            {
                "fact_type": "api_surface",
                "artifact_kind": "api",
                "route_method": "GET",
                "route_path": route,
            },
            {"fact_type": "har_context", "artifact_kind": "har"},
        ],
        context_facts=[
            {"fact_type": "scope_context", "artifact_kind": "scope"},
            {"fact_type": "policy_context", "artifact_kind": "policy"},
        ],
    )

    state = observations["candidate_states"][0]
    result = advance_candidate_hunter_round(
        pipeline_run_id="run-001",
        round_number=1,
        candidate_states=[state],
        observations=observations,
        prior_decisions=[],
    )

    assert state["control_evidence_ref"] == "code:routes.ts:verify"
    assert result["candidate_decisions"][0]["disposition"] == "refuted"


def test_typescript_jwt_verification_does_not_refute_unverified_claims_sink():
    observations = _build_single_candidate_observations(
        '''
import { Router } from "express";
import jwt from "jsonwebtoken";

const router = Router();

router.get("/reports/:reportId/export", exportReport);

async function exportReport(req: Request, res: Response) {
  const unsafeClaims = jwt.decode(req.headers.authorization || "");
  const verifiedClaims = jwt.verify(req.headers.authorization || "", verificationKey);
  return sendFile(unsafeClaims?.path);
}
''',
        route_path="/reports/:reportId/export",
        symbol_name="exportReport",
        source_path="routes.ts",
        vuln_type="jwt_authentication_bypass",
        root_cause="missing_jwt_verification",
    )

    state = observations["candidate_states"][0]
    result = advance_candidate_hunter_round(
        pipeline_run_id="run-001",
        round_number=1,
        candidate_states=[state],
        observations=observations,
        prior_decisions=[],
    )

    assert "control_evidence_ref" not in state
    assert result["candidate_decisions"][0]["disposition"] == "retained"


def test_typescript_jwt_verification_of_other_token_does_not_refute_jwt_candidate():
    route = "/reports/:reportId/export"
    observations = build_candidate_hunter_observations(
        pipeline_run_id="run-001",
        candidates=[
            {
                "hypothesis_id": "H-jwt-002",
                "vuln_type": "jwt_authentication_bypass",
                "location": f"GET {route}",
                "priority_score": 85,
                "source_facts": [
                    {
                        "fact_type": "authorization_gap_candidate",
                        "artifact_kind": "code",
                        "source_path": "routes.ts",
                        "symbol_name": "exportReport",
                        "route_method": "GET",
                        "route_path": route,
                        "root_cause": "missing_jwt_verification",
                    }
                ],
            }
        ],
        code_files=[
            {
                "path": "routes.ts",
                "content": '''
import { Router } from "express";
import jwt from "jsonwebtoken";

const router = Router();

router.get("/reports/:reportId/export", exportReport);

async function exportReport(req: Request, res: Response) {
  const claims = jwt.decode(req.headers.attackerToken || "");
  const verifiedClaims = jwt.verify(req.headers.serviceToken || "", verificationKey);
  return sendFile(claims?.path);
}
''',
            }
        ],
        surface_facts=[
            {
                "fact_type": "api_surface",
                "artifact_kind": "api",
                "route_method": "GET",
                "route_path": route,
            },
            {"fact_type": "har_context", "artifact_kind": "har"},
        ],
        context_facts=[
            {"fact_type": "scope_context", "artifact_kind": "scope"},
            {"fact_type": "policy_context", "artifact_kind": "policy"},
        ],
    )

    state = observations["candidate_states"][0]
    result = advance_candidate_hunter_round(
        pipeline_run_id="run-001",
        round_number=1,
        candidate_states=[state],
        observations=observations,
        prior_decisions=[],
    )

    assert "control_evidence_ref" not in state
    assert result["candidate_decisions"][0]["disposition"] == "retained"


def test_typescript_jwt_verification_does_not_refute_unresolved_token_decode():
    route = "/reports/:reportId/export"
    observations = build_candidate_hunter_observations(
        pipeline_run_id="run-001",
        candidates=[
            {
                "hypothesis_id": "H-jwt-003",
                "vuln_type": "jwt_authentication_bypass",
                "location": f"GET {route}",
                "priority_score": 85,
                "source_facts": [
                    {
                        "fact_type": "authorization_gap_candidate",
                        "artifact_kind": "code",
                        "source_path": "routes.ts",
                        "symbol_name": "exportReport",
                        "route_method": "GET",
                        "route_path": route,
                        "root_cause": "missing_jwt_verification",
                    }
                ],
            }
        ],
        code_files=[
            {
                "path": "routes.ts",
                "content": '''
import { Router } from "express";
import jwt from "jsonwebtoken";

const router = Router();

router.get("/reports/:reportId/export", exportReport);

async function exportReport(req: Request, res: Response) {
  const serviceClaims = jwt.decode(req.headers.authorization || "");
  const verifiedClaims = jwt.verify(req.headers.authorization || "", verificationKey);
  const attackerClaims = jwt.decode(req.headers.attackerToken || req.query.fallbackToken);
  return sendFile(attackerClaims?.path);
}
''',
            }
        ],
        surface_facts=[
            {
                "fact_type": "api_surface",
                "artifact_kind": "api",
                "route_method": "GET",
                "route_path": route,
            },
            {"fact_type": "har_context", "artifact_kind": "har"},
        ],
        context_facts=[
            {"fact_type": "scope_context", "artifact_kind": "scope"},
            {"fact_type": "policy_context", "artifact_kind": "policy"},
        ],
    )

    state = observations["candidate_states"][0]
    result = advance_candidate_hunter_round(
        pipeline_run_id="run-001",
        round_number=1,
        candidate_states=[state],
        observations=observations,
        prior_decisions=[],
    )

    assert "control_evidence_ref" not in state
    assert result["candidate_decisions"][0]["disposition"] == "retained"


def test_jwt_candidate_ignores_unrelated_ownership_control():
    observations = _build_single_candidate_observations(
        '''
from flask import Blueprint
import jwt

bp = Blueprint("reports", __name__)

@bp.get("/reports/<report_id>/export")
def export_report(report_id, token):
    verify_record_access(report_id, current_user)
    claims = jwt.decode(token, options={"verify_signature": False})
    return send_file(claims["path"])

def verify_record_access(record_id, user):
    record = load_record(record_id)
    if record.owner_id != user.id:
        return deny()
    return record
''',
        route_path="/reports/{report_id}/export",
        symbol_name="export_report",
        vuln_type="jwt_authentication_bypass",
        root_cause="missing_jwt_verification",
    )

    state = observations["candidate_states"][0]
    result = advance_candidate_hunter_round(
        pipeline_run_id="run-001",
        round_number=1,
        candidate_states=[state],
        observations=observations,
        prior_decisions=[],
    )

    assert "control_evidence_ref" not in state
    assert result["candidate_decisions"][0]["disposition"] == "retained"


def test_typescript_command_validation_control_refutes_command_execution_candidate():
    route = "/maintenance/run"
    observations = build_candidate_hunter_observations(
        pipeline_run_id="run-001",
        candidates=[
            {
                "hypothesis_id": "H-command-001",
                "vuln_type": "command_injection",
                "location": f"POST {route}",
                "priority_score": 80,
                "source_facts": [
                    {
                        "fact_type": "authorization_gap_candidate",
                        "artifact_kind": "code",
                        "source_path": "routes.ts",
                        "symbol_name": "runMaintenance",
                        "route_method": "POST",
                        "route_path": route,
                        "root_cause": "missing_command_injection_validation",
                    }
                ],
            }
        ],
        code_files=[
            {
                "path": "routes.ts",
                "content": '''
import { Router } from "express";

const router = Router();

router.post("/maintenance/run", runMaintenance);

async function runMaintenance(req: Request, res: Response) {
  const command = commandAllowlist(req.body.command);
  return exec(command);
}

function commandAllowlist(command: string) {
  return command;
}
''',
            }
        ],
        surface_facts=[
            {
                "fact_type": "api_surface",
                "artifact_kind": "api",
                "route_method": "POST",
                "route_path": route,
            },
            {"fact_type": "har_context", "artifact_kind": "har"},
        ],
        context_facts=[
            {"fact_type": "scope_context", "artifact_kind": "scope"},
            {"fact_type": "policy_context", "artifact_kind": "policy"},
        ],
    )

    state = observations["candidate_states"][0]
    result = advance_candidate_hunter_round(
        pipeline_run_id="run-001",
        round_number=1,
        candidate_states=[state],
        observations=observations,
        prior_decisions=[],
    )

    assert state["control_evidence_ref"] == "code:routes.ts:commandAllowlist"
    assert result["candidate_decisions"][0]["disposition"] == "refuted"


def test_typescript_command_validation_of_different_input_does_not_refute_candidate():
    observations = _build_single_candidate_observations(
        '''
import { Router } from "express";

const router = Router();

router.get("/maintenance/run", runMaintenance);

async function runMaintenance(req: Request, res: Response) {
  const safeCommand = req.query.safeCommand;
  const attackerCommand = req.query.command;
  validateCommand(safeCommand);
  return exec(attackerCommand);
}
''',
        route_path="/maintenance/run",
        symbol_name="runMaintenance",
        source_path="routes.ts",
        vuln_type="command_injection",
        root_cause="missing_command_injection_validation",
    )

    state = observations["candidate_states"][0]
    result = advance_candidate_hunter_round(
        pipeline_run_id="run-001",
        round_number=1,
        candidate_states=[state],
        observations=observations,
        prior_decisions=[],
    )

    assert "control_evidence_ref" not in state
    assert result["candidate_decisions"][0]["disposition"] == "retained"


def test_typescript_query_validation_of_different_input_does_not_refute_candidate():
    observations = _build_single_candidate_observations(
        '''
import { Router } from "express";

const router = Router();

router.get("/maintenance/run", runSearch);

async function runSearch(req: Request, res: Response) {
  const safeQuery = req.query.safeQuery;
  const attackerQuery = req.query.query;
  parameterize(safeQuery);
  return runSql(attackerQuery);
}
''',
        route_path="/maintenance/run",
        symbol_name="runSearch",
        source_path="routes.ts",
        vuln_type="injection",
        root_cause="missing_injection_validation",
    )

    state = observations["candidate_states"][0]
    result = advance_candidate_hunter_round(
        pipeline_run_id="run-001",
        round_number=1,
        candidate_states=[state],
        observations=observations,
        prior_decisions=[],
    )

    assert "control_evidence_ref" not in state
    assert result["candidate_decisions"][0]["disposition"] == "retained"


def test_typescript_query_validation_does_not_refute_command_execution_candidate():
    route = "/maintenance/run"
    observations = build_candidate_hunter_observations(
        pipeline_run_id="run-001",
        candidates=[
            {
                "hypothesis_id": "H-command-002",
                "vuln_type": "command_injection",
                "location": f"POST {route}",
                "priority_score": 80,
                "source_facts": [
                    {
                        "fact_type": "authorization_gap_candidate",
                        "artifact_kind": "code",
                        "source_path": "routes.ts",
                        "symbol_name": "runMaintenance",
                        "route_method": "POST",
                        "route_path": route,
                        "root_cause": "missing_command_injection_validation",
                    }
                ],
            }
        ],
        code_files=[
            {
                "path": "routes.ts",
                "content": '''
import { Router } from "express";

const router = Router();

router.post("/maintenance/run", runMaintenance);

async function runMaintenance(req: Request, res: Response) {
  const command = parameterize(req.body.command);
  return exec(command);
}
''',
            }
        ],
        surface_facts=[
            {
                "fact_type": "api_surface",
                "artifact_kind": "api",
                "route_method": "POST",
                "route_path": route,
            },
            {"fact_type": "har_context", "artifact_kind": "har"},
        ],
        context_facts=[
            {"fact_type": "scope_context", "artifact_kind": "scope"},
            {"fact_type": "policy_context", "artifact_kind": "policy"},
        ],
    )

    state = observations["candidate_states"][0]
    result = advance_candidate_hunter_round(
        pipeline_run_id="run-001",
        round_number=1,
        candidate_states=[state],
        observations=observations,
        prior_decisions=[],
    )

    assert "control_evidence_ref" not in state
    assert result["candidate_decisions"][0]["disposition"] == "retained"


def test_typescript_validation_after_service_sink_does_not_refute_ssrf_candidate():
    route = "/webhooks/test"
    observations = build_candidate_hunter_observations(
        pipeline_run_id="run-001",
        candidates=[
            {
                "hypothesis_id": "H-ssrf-after-sink-001",
                "vuln_type": "ssrf",
                "location": f"POST {route}",
                "priority_score": 80,
                "source_facts": [
                    {
                        "fact_type": "authorization_gap_candidate",
                        "artifact_kind": "code",
                        "source_path": "routes.ts",
                        "symbol_name": "testWebhook",
                        "route_method": "POST",
                        "route_path": route,
                        "root_cause": "missing_ssrf_validation",
                    }
                ],
            }
        ],
        code_files=[
            {
                "path": "routes.ts",
                "content": '''
import { Router } from "express";

const router = Router();

router.post("/webhooks/test", testWebhook);

async function testWebhook(req: Request, res: Response) {
  await fetchRemote(req.body.url);
  validateUrlForSSRF(req.body.url);
  return res.sendStatus(204);
}

async function fetchRemote(url: string) {
  return fetch(url);
}
''',
            }
        ],
        surface_facts=[
            {
                "fact_type": "api_surface",
                "artifact_kind": "api",
                "route_method": "POST",
                "route_path": route,
            },
            {"fact_type": "har_context", "artifact_kind": "har"},
        ],
        context_facts=[
            {"fact_type": "scope_context", "artifact_kind": "scope"},
            {"fact_type": "policy_context", "artifact_kind": "policy"},
        ],
    )

    state = observations["candidate_states"][0]
    result = advance_candidate_hunter_round(
        pipeline_run_id="run-001",
        round_number=1,
        candidate_states=[state],
        observations=observations,
        prior_decisions=[],
    )

    assert "control_evidence_ref" not in state
    assert result["candidate_decisions"][0]["disposition"] == "retained"


def test_typescript_validation_of_different_input_does_not_refute_ssrf_candidate():
    route = "/webhooks/test"
    observations = build_candidate_hunter_observations(
        pipeline_run_id="run-001",
        candidates=[
            {
                "hypothesis_id": "H-ssrf-different-input-001",
                "vuln_type": "ssrf",
                "location": f"POST {route}",
                "priority_score": 80,
                "source_facts": [
                    {
                        "fact_type": "authorization_gap_candidate",
                        "artifact_kind": "code",
                        "source_path": "routes.ts",
                        "symbol_name": "testWebhook",
                        "route_method": "POST",
                        "route_path": route,
                        "root_cause": "missing_ssrf_validation",
                    }
                ],
            }
        ],
        code_files=[
            {
                "path": "routes.ts",
                "content": '''
import { Router } from "express";

const router = Router();

router.post("/webhooks/test", testWebhook);

async function testWebhook(req: Request, res: Response) {
  const serviceTarget = req.body.serviceUrl;
  const attackerTarget = req.body.callbackUrl;
  validateUrlForSSRF(serviceTarget);
  await fetch(serviceTarget);
  return fetch(attackerTarget);
}
''',
            }
        ],
        surface_facts=[
            {
                "fact_type": "api_surface",
                "artifact_kind": "api",
                "route_method": "POST",
                "route_path": route,
            },
            {"fact_type": "har_context", "artifact_kind": "har"},
        ],
        context_facts=[
            {"fact_type": "scope_context", "artifact_kind": "scope"},
            {"fact_type": "policy_context", "artifact_kind": "policy"},
        ],
    )

    state = observations["candidate_states"][0]
    result = advance_candidate_hunter_round(
        pipeline_run_id="run-001",
        round_number=1,
        candidate_states=[state],
        observations=observations,
        prior_decisions=[],
    )

    assert "control_evidence_ref" not in state
    assert result["candidate_decisions"][0]["disposition"] == "retained"


def test_typescript_validation_does_not_cross_service_call_for_ssrf_candidate():
    route = "/webhooks/test"
    observations = build_candidate_hunter_observations(
        pipeline_run_id="run-001",
        candidates=[
            {
                "hypothesis_id": "H-ssrf-service-call-input-001",
                "vuln_type": "ssrf",
                "location": f"POST {route}",
                "priority_score": 80,
                "source_facts": [
                    {
                        "fact_type": "authorization_gap_candidate",
                        "artifact_kind": "code",
                        "source_path": "routes.ts",
                        "symbol_name": "testWebhook",
                        "route_method": "POST",
                        "route_path": route,
                        "root_cause": "missing_ssrf_validation",
                    }
                ],
            }
        ],
        code_files=[
            {
                "path": "routes.ts",
                "content": '''
import { Router } from "express";

const router = Router();

router.post("/webhooks/test", testWebhook);

async function testWebhook(req: Request, res: Response) {
  const url = req.body.serviceUrl;
  validateUrlForSSRF(url);
  return fetchRemote(req.body.callbackUrl);
}

async function fetchRemote(url: string) {
  return fetch(url);
}
''',
            }
        ],
        surface_facts=[
            {
                "fact_type": "api_surface",
                "artifact_kind": "api",
                "route_method": "POST",
                "route_path": route,
            },
            {"fact_type": "har_context", "artifact_kind": "har"},
        ],
        context_facts=[
            {"fact_type": "scope_context", "artifact_kind": "scope"},
            {"fact_type": "policy_context", "artifact_kind": "policy"},
        ],
    )

    state = observations["candidate_states"][0]
    result = advance_candidate_hunter_round(
        pipeline_run_id="run-001",
        round_number=1,
        candidate_states=[state],
        observations=observations,
        prior_decisions=[],
    )

    assert "control_evidence_ref" not in state
    assert result["candidate_decisions"][0]["disposition"] == "retained"


def test_typescript_reassigned_input_does_not_refute_ssrf_candidate():
    route = "/webhooks/test"
    observations = build_candidate_hunter_observations(
        pipeline_run_id="run-001",
        candidates=[
            {
                "hypothesis_id": "H-ssrf-reassigned-input-001",
                "vuln_type": "ssrf",
                "location": f"POST {route}",
                "priority_score": 80,
                "source_facts": [
                    {
                        "fact_type": "authorization_gap_candidate",
                        "artifact_kind": "code",
                        "source_path": "routes.ts",
                        "symbol_name": "testWebhook",
                        "route_method": "POST",
                        "route_path": route,
                        "root_cause": "missing_ssrf_validation",
                    }
                ],
            }
        ],
        code_files=[
            {
                "path": "routes.ts",
                "content": '''
import { Router } from "express";

const router = Router();

router.post("/webhooks/test", testWebhook);

async function testWebhook(req: Request, res: Response) {
  const target: { serviceUrl: string; callbackUrl: string } = req.body;
  validateUrlForSSRF(target.serviceUrl);
  target.serviceUrl = target.callbackUrl;
  return fetch(target.serviceUrl);
}
''',
            }
        ],
        surface_facts=[
            {
                "fact_type": "api_surface",
                "artifact_kind": "api",
                "route_method": "POST",
                "route_path": route,
            },
            {"fact_type": "har_context", "artifact_kind": "har"},
        ],
        context_facts=[
            {"fact_type": "scope_context", "artifact_kind": "scope"},
            {"fact_type": "policy_context", "artifact_kind": "policy"},
        ],
    )

    state = observations["candidate_states"][0]
    result = advance_candidate_hunter_round(
        pipeline_run_id="run-001",
        round_number=1,
        candidate_states=[state],
        observations=observations,
        prior_decisions=[],
    )

    assert "control_evidence_ref" not in state
    assert result["candidate_decisions"][0]["disposition"] == "retained"


def test_typescript_deserialization_validation_refutes_deserialization_candidate():
    route = "/imports/profile"
    observations = build_candidate_hunter_observations(
        pipeline_run_id="run-001",
        candidates=[
            {
                "hypothesis_id": "H-deserialization-001",
                "vuln_type": "unsafe_deserialization",
                "location": f"POST {route}",
                "priority_score": 80,
                "source_facts": [
                    {
                        "fact_type": "authorization_gap_candidate",
                        "artifact_kind": "code",
                        "source_path": "routes.ts",
                        "symbol_name": "importProfile",
                        "route_method": "POST",
                        "route_path": route,
                        "root_cause": "missing_unsafe_deserialization_guard",
                    }
                ],
            }
        ],
        code_files=[
            {
                "path": "routes.ts",
                "content": '''
import { Router } from "express";

const router = Router();

router.post("/imports/profile", importProfile);

async function importProfile(req: Request, res: Response) {
  const payload = validateSerializedPayload(req.body.payload);
  return unsafeDeserialize(payload);
}

function validateSerializedPayload(payload: string) {
  return payload;
}
''',
            }
        ],
        surface_facts=[
            {
                "fact_type": "api_surface",
                "artifact_kind": "api",
                "route_method": "POST",
                "route_path": route,
            },
            {"fact_type": "har_context", "artifact_kind": "har"},
        ],
        context_facts=[
            {"fact_type": "scope_context", "artifact_kind": "scope"},
            {"fact_type": "policy_context", "artifact_kind": "policy"},
        ],
    )

    state = observations["candidate_states"][0]
    result = advance_candidate_hunter_round(
        pipeline_run_id="run-001",
        round_number=1,
        candidate_states=[state],
        observations=observations,
        prior_decisions=[],
    )

    assert state["control_evidence_ref"] == "code:routes.ts:validateSerializedPayload"
    assert result["candidate_decisions"][0]["disposition"] == "refuted"


def test_typescript_upload_validation_refutes_file_upload_candidate():
    route = "/uploads"
    observations = build_candidate_hunter_observations(
        pipeline_run_id="run-001",
        candidates=[
            {
                "hypothesis_id": "H-upload-001",
                "vuln_type": "file_upload",
                "location": f"POST {route}",
                "priority_score": 80,
                "source_facts": [
                    {
                        "fact_type": "authorization_gap_candidate",
                        "artifact_kind": "code",
                        "source_path": "routes.ts",
                        "symbol_name": "uploadDocument",
                        "route_method": "POST",
                        "route_path": route,
                        "root_cause": "missing_file_upload_validation",
                    }
                ],
            }
        ],
        code_files=[
            {
                "path": "routes.ts",
                "content": '''
import { Router } from "express";

const router = Router();

router.post("/uploads", uploadDocument);

async function uploadDocument(req: Request, res: Response) {
  const upload = validateUpload(req.file);
  return storeUpload(upload);
}

function validateUpload(upload: unknown) {
  return upload;
}
''',
            }
        ],
        surface_facts=[
            {
                "fact_type": "api_surface",
                "artifact_kind": "api",
                "route_method": "POST",
                "route_path": route,
            },
            {"fact_type": "har_context", "artifact_kind": "har"},
        ],
        context_facts=[
            {"fact_type": "scope_context", "artifact_kind": "scope"},
            {"fact_type": "policy_context", "artifact_kind": "policy"},
        ],
    )

    state = observations["candidate_states"][0]
    result = advance_candidate_hunter_round(
        pipeline_run_id="run-001",
        round_number=1,
        candidate_states=[state],
        observations=observations,
        prior_decisions=[],
    )

    assert state["control_evidence_ref"] == "code:routes.ts:validateUpload"
    assert result["candidate_decisions"][0]["disposition"] == "refuted"


def test_typescript_server_amount_derivation_refutes_money_flow_candidate():
    route = "/payments/transfers"
    observations = build_candidate_hunter_observations(
        pipeline_run_id="run-001",
        candidates=[
            {
                "hypothesis_id": "H-money-flow-001",
                "vuln_type": "business_logic",
                "location": f"POST {route}",
                "priority_score": 85,
                "source_facts": [
                    {
                        "fact_type": "authorization_gap_candidate",
                        "artifact_kind": "code",
                        "source_path": "routes.ts",
                        "symbol_name": "createTransfer",
                        "route_method": "POST",
                        "route_path": route,
                        "root_cause": "missing_server_authoritative_amount_check",
                    }
                ],
            }
        ],
        code_files=[
            {
                "path": "routes.ts",
                "content": '''
import { Router } from "express";

const router = Router();

router.post("/payments/transfers", createTransfer);

async function createTransfer(req: Request, res: Response) {
  const serverAmount = deriveServerAmount(req.body.orderId);
  return transferFunds(req.body.recipientId, serverAmount);
}

function deriveServerAmount(orderId: string) {
  return 1;
}
''',
            }
        ],
        surface_facts=[
            {
                "fact_type": "api_surface",
                "artifact_kind": "api",
                "route_method": "POST",
                "route_path": route,
            },
            {"fact_type": "har_context", "artifact_kind": "har"},
        ],
        context_facts=[
            {"fact_type": "scope_context", "artifact_kind": "scope"},
            {"fact_type": "policy_context", "artifact_kind": "policy"},
        ],
    )

    state = observations["candidate_states"][0]
    result = advance_candidate_hunter_round(
        pipeline_run_id="run-001",
        round_number=1,
        candidate_states=[state],
        observations=observations,
        prior_decisions=[],
    )

    assert state["control_evidence_ref"] == "code:routes.ts:deriveServerAmount"
    assert result["candidate_decisions"][0]["disposition"] == "refuted"


def test_typescript_server_amount_derivation_after_sink_does_not_refute_money_flow_candidate():
    route = "/payments/transfers"
    observations = build_candidate_hunter_observations(
        pipeline_run_id="run-001",
        candidates=[
            {
                "hypothesis_id": "H-money-flow-after-sink-001",
                "vuln_type": "business_logic",
                "location": f"POST {route}",
                "priority_score": 85,
                "source_facts": [
                    {
                        "fact_type": "authorization_gap_candidate",
                        "artifact_kind": "code",
                        "source_path": "routes.ts",
                        "symbol_name": "createTransfer",
                        "route_method": "POST",
                        "route_path": route,
                        "root_cause": "missing_server_authoritative_amount_check",
                    }
                ],
            }
        ],
        code_files=[
            {
                "path": "routes.ts",
                "content": '''
import { Router } from "express";

const router = Router();

router.post("/payments/transfers", createTransfer);

async function createTransfer(req: Request, res: Response) {
  const result = transferFunds(req.body.recipientId, req.body.amount);
  deriveServerAmount(req.body.orderId);
  return result;
}

function deriveServerAmount(orderId: string) {
  return 1;
}
''',
            }
        ],
        surface_facts=[
            {
                "fact_type": "api_surface",
                "artifact_kind": "api",
                "route_method": "POST",
                "route_path": route,
            },
            {"fact_type": "har_context", "artifact_kind": "har"},
        ],
        context_facts=[
            {"fact_type": "scope_context", "artifact_kind": "scope"},
            {"fact_type": "policy_context", "artifact_kind": "policy"},
        ],
    )

    state = observations["candidate_states"][0]
    result = advance_candidate_hunter_round(
        pipeline_run_id="run-001",
        round_number=1,
        candidate_states=[state],
        observations=observations,
        prior_decisions=[],
    )

    assert "control_evidence_ref" not in state
    assert result["candidate_decisions"][0]["disposition"] == "retained"


def test_typescript_agent_tool_policy_refutes_agent_tool_candidate():
    route = "/agents/:agentId/tools/execute"
    observations = build_candidate_hunter_observations(
        pipeline_run_id="run-001",
        candidates=[
            {
                "hypothesis_id": "H-agent-tool-001",
                "vuln_type": "agent_tool_authz_gap",
                "location": f"POST {route}",
                "priority_score": 85,
                "source_facts": [
                    {
                        "fact_type": "authorization_gap_candidate",
                        "artifact_kind": "code",
                        "source_path": "routes.ts",
                        "symbol_name": "runAgentTool",
                        "route_method": "POST",
                        "route_path": route,
                        "root_cause": "missing_agent_tool_authorization_check",
                    }
                ],
            }
        ],
        code_files=[
            {
                "path": "routes.ts",
                "content": '''
import { Router } from "express";

const router = Router();

router.post("/agents/:agentId/tools/execute", runAgentTool);

async function runAgentTool(req: Request, res: Response) {
  assertToolAllowed(req.params.agentId, req.body.toolName);
  return executeAgentTool(req.params.agentId, req.body.toolName);
}

function assertToolAllowed(agentId: string, toolName: string) {
  return true;
}
''',
            }
        ],
        surface_facts=[
            {
                "fact_type": "api_surface",
                "artifact_kind": "api",
                "route_method": "POST",
                "route_path": route,
            },
            {"fact_type": "har_context", "artifact_kind": "har"},
        ],
        context_facts=[
            {"fact_type": "scope_context", "artifact_kind": "scope"},
            {"fact_type": "policy_context", "artifact_kind": "policy"},
        ],
    )

    state = observations["candidate_states"][0]
    result = advance_candidate_hunter_round(
        pipeline_run_id="run-001",
        round_number=1,
        candidate_states=[state],
        observations=observations,
        prior_decisions=[],
    )

    assert state["control_evidence_ref"] == "code:routes.ts:assertToolAllowed"
    assert result["candidate_decisions"][0]["disposition"] == "refuted"


def test_typescript_express_public_filter_suppresses_candidate():
    route = "/records/:recordId"
    observations = build_candidate_hunter_observations(
        pipeline_run_id="run-001",
        candidates=[
            {
                "hypothesis_id": "H-001",
                "vuln_type": "authorization",
                "location": f"GET {route}",
                "priority_score": 80,
                "source_facts": [
                    {
                        "fact_type": "authorization_gap_candidate",
                        "artifact_kind": "code",
                        "source_path": "routes.ts",
                        "symbol_name": "readRecord",
                        "route_method": "GET",
                        "route_path": route,
                        "root_cause": "missing_object_ownership_check",
                    }
                ],
            }
        ],
        code_files=[
            {
                "path": "routes.ts",
                "content": '''
import { Router } from "express";

const router = Router();

router.get("/records/:recordId", readRecord);

async function readRecord(req: Request, res: Response) {
  const record = await loadPublicRecord(req.params.recordId);
  return sendFile(record.path);
}

async function loadPublicRecord(recordId: string) {
  return recordStore.get(recordId, { visibility: "public" });
}
''',
            }
        ],
        surface_facts=[
            {
                "fact_type": "api_surface",
                "artifact_kind": "api",
                "route_method": "GET",
                "route_path": route,
            },
            {"fact_type": "har_context", "artifact_kind": "har"},
        ],
        context_facts=[
            {"fact_type": "scope_context", "artifact_kind": "scope"},
            {"fact_type": "policy_context", "artifact_kind": "policy"},
        ],
    )

    state = observations["candidate_states"][0]
    result = advance_candidate_hunter_round(
        pipeline_run_id="run-001",
        round_number=1,
        candidate_states=[state],
        observations=observations,
        prior_decisions=[],
    )

    assert state["public_evidence_ref"].startswith("code:routes.ts:")
    assert result["candidate_decisions"][0]["disposition"] == "suppressed"


@pytest.mark.parametrize(
    ("state_factory", "expected_status", "expected_stop"),
    [
        (lambda: None, "completed", "no_candidates"),
        (
            lambda: {
                **_complete_candidate_state(),
                "root_cause_id": "",
            },
            "needs_evidence",
            "no_state_change",
        ),
        (
            lambda: {
                **_complete_candidate_state(),
                "gap_evidence_ref": "",
            },
            "needs_evidence",
            "no_processable_candidates",
        ),
    ],
)
def test_loop_stop_reasons_map_to_task_summary_status(
    state_factory,
    expected_status: str,
    expected_stop: str,
):
    repository, session = _repository()
    try:
        record = _pipeline_run(repository)
        state = state_factory()
        states = []
        if state is not None:
            state["candidate_key"] = f"{record.id}:{state['candidate_id']}"
            states.append(state)

        result = run_candidate_hunter_loop(
            repository=repository,
            record=record,
            policy_text="Synthetic local policy.",
            candidates=[],
            observations={
                "candidate_states": states,
                **_safe_observations(),
            },
        )

        assert result["status"] == expected_status
        assert result["stop_reason"] == expected_stop
        campaign = repository.list_campaigns()[0]
        task = repository.list_campaign_tasks(campaign.id)[0]
        assert task.status == expected_status
    finally:
        session.close()


def test_incomplete_candidate_never_emits_retained_decision():
    state = _complete_candidate_state()
    state["source_fact_refs"] = []
    state["evidence_trace_status"] = "needs_evidence"

    result = advance_candidate_hunter_round(
        pipeline_run_id="run-001",
        round_number=1,
        candidate_states=[state],
        observations=_safe_observations(),
        prior_decisions=[],
    )

    assert result["final_candidates"] == []
    assert result["evidence_requests"]
    assert all(item.get("disposition") != "retained" for item in result["candidate_decisions"])


def test_python_deny_return_ownership_guard_refutes():
    observations = _build_single_candidate_observations(
        '''
from flask import Blueprint

bp = Blueprint("records", __name__)

@bp.get("/records/<record_id>")
def read_record(record_id):
    verify_record_access(record_id, current_user)
    return send_file(record_id)

def verify_record_access(record_id, user):
    record = load_record(record_id)
    if record.owner_id != user.id:
        return deny()
    return record
'''
    )
    state = observations["candidate_states"][0]
    assert state["control_evidence_ref"] == (
        "code:code.py:verify_record_access:ownership_guard"
    )
    result = advance_candidate_hunter_round(
        pipeline_run_id="run-001",
        round_number=1,
        candidate_states=[state],
        observations=observations,
        prior_decisions=[],
    )
    assert result["candidate_decisions"][0]["disposition"] == "refuted"


def test_python_tenant_boundary_guard_refutes():
    observations = _build_single_candidate_observations(
        '''
from flask import Blueprint

bp = Blueprint("docs", __name__)

@bp.get("/orgs/<org_id>/docs/<doc_id>")
def read_doc(org_id, doc_id):
    verify_tenant_doc(org_id, doc_id, current_user)
    return send_file(doc_id)

def verify_tenant_doc(org_id, doc_id, user):
    doc = load_doc(doc_id)
    if doc.tenant_id != user.tenant_id:
        return deny()
    return doc
''',
        route_path="/orgs/{org_id}/docs/{doc_id}",
        symbol_name="read_doc",
    )
    state = observations["candidate_states"][0]
    assert state["control_evidence_ref"] == (
        "code:code.py:verify_tenant_doc:ownership_guard"
    )
    result = advance_candidate_hunter_round(
        pipeline_run_id="run-001",
        round_number=1,
        candidate_states=[state],
        observations=observations,
        prior_decisions=[],
    )
    assert result["candidate_decisions"][0]["disposition"] == "refuted"


def test_python_inline_ownership_guard_refutes():
    observations = _build_single_candidate_observations(
        """
from flask import Blueprint

bp = Blueprint("records", __name__)

@bp.get("/records/<record_id>")
def read_record(record_id):
    record = load_record(record_id)
    if record.owner_id != current_user.id:
        raise PermissionError()
    return send_file(record_id)
"""
    )
    state = observations["candidate_states"][0]
    assert state["control_evidence_ref"] == (
        "code:code.py:read_record:ownership_guard"
    )
    result = advance_candidate_hunter_round(
        pipeline_run_id="run-001",
        round_number=1,
        candidate_states=[state],
        observations=observations,
        prior_decisions=[],
    )
    assert result["candidate_decisions"][0]["disposition"] == "refuted"


def test_graphql_resolver_candidate_refutes_context_ownership_control():
    source_path = "gql/records.py"
    content = """
import strawberry


@strawberry.type
class Query:
    @strawberry.field
    def record(self, info, record_id: str):
        record = load_record(record_id)
        if record.owner_id != info.context.user.id:
            raise PermissionError("forbidden")
        return send_file(record_id)
"""
    mapped = map_authorized_code_files(
        {"authorized_code_files": [{"path": source_path, "content": content}]}
    )
    assert not any(
        fact.fact_type == "authorization_gap_candidate" for fact in mapped.facts
    )
    observations = build_candidate_hunter_observations(
        pipeline_run_id="run-001",
        candidates=[
            {
                "hypothesis_id": "H-001",
                "vuln_type": "authorization",
                "location": "GraphQL query record",
                "priority_score": 80,
                "source_facts": [
                    {
                        "fact_type": "authorization_gap_candidate",
                        "artifact_kind": "code",
                        "source_path": source_path,
                        "symbol_name": "record",
                        "root_cause": "missing_object_ownership_check",
                    }
                ],
            }
        ],
        code_files=[{"path": source_path, "content": content}],
        surface_facts=[
            {"fact_type": "api_surface", "artifact_kind": "api"},
            {"fact_type": "har_context", "artifact_kind": "har"},
        ],
        context_facts=[
            {"fact_type": "scope_context", "artifact_kind": "scope"},
            {"fact_type": "policy_context", "artifact_kind": "policy"},
        ],
    )

    state = observations["candidate_states"][0]
    result = advance_candidate_hunter_round(
        pipeline_run_id="run-001",
        round_number=1,
        candidate_states=[state],
        observations=observations,
        prior_decisions=[],
    )

    assert any(fact.fact_type == "graphql_operation" for fact in mapped.facts)
    assert state["route"] == {}
    assert state["control_evidence_ref"] == "code:gql/records.py:record:ownership_guard"
    assert result["candidate_decisions"][0]["disposition"] == "refuted"
