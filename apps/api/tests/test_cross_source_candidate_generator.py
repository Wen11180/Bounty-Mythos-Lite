import asyncio
import inspect
import json

from app.cross_source_candidate_generator import (
    CandidateModelConfig,
    CandidateModelResult,
    RegistryCandidateReasoner,
    ReplayCandidateReasoner,
    build_fact_pack,
    candidate_hunter_inputs,
    generation_stage_payload,
    generate_cross_source_candidates,
)
from app.llm.base import LLMMode, LLMResponse, ProviderName


def _fact_pack():
    return build_fact_pack(
        pipeline_run_id="run-001",
        scope_status="in_scope",
        source_files=[
            {
                "path": "apps/api/routes/files.ts",
                "content": "const token = 'not included in the fact pack';",
            }
        ],
        facts=[
            {"fact_ref": "scope:scope_context", "fact_type": "scope_context", "artifact_kind": "scope"},
            {"fact_ref": "policy:policy_context", "fact_type": "policy_context", "artifact_kind": "policy"},
            {
                "fact_ref": "code:files.ts:exportFile:route_handler",
                "fact_type": "route_handler",
                "artifact_kind": "code",
                "source_path": "apps/api/routes/files.ts",
                "symbol_name": "exportFile",
                "route": {"method": "GET", "path": "/files/{file_id}/export"},
            },
            {
                "fact_ref": "code:files.ts:exportFile:authorization_gap_candidate",
                "fact_type": "authorization_gap_candidate",
                "artifact_kind": "code",
                "source_path": "apps/api/routes/files.ts",
                "symbol_name": "exportFile",
                "root_cause": "missing_object_ownership_check",
                "route": {"method": "GET", "path": "/files/{file_id}/export"},
            },
            {
                "fact_ref": "api:GET:/files/{file_id}/export",
                "fact_type": "api_surface",
                "artifact_kind": "api",
                "route": {"method": "GET", "path": "/files/{file_id}/export"},
                "authorization_header": "Bearer should-not-appear",
            },
            {
                "fact_ref": "har:GET:/files/123/export",
                "fact_type": "har_surface",
                "artifact_kind": "har",
                "route": {"method": "GET", "path": "/files/123/export"},
            },
        ],
        baseline_candidates=[
            {
                "hypothesis_id": "H-001",
                "vuln_type": "authorization",
                "location": "GET /files/{file_id}/export",
                "priority_score": 80,
                "source_fact_refs": [
                    "code:files.ts:exportFile:authorization_gap_candidate"
                ],
                "evidence_needed": ["review ownership checks"],
                "false_positive_checks": ["middleware may enforce authorization"],
                "root_cause": "missing_object_ownership_check",
            }
        ],
    )


def _model_config():
    return CandidateModelConfig(provider=ProviderName.OPENAI, model="test-model")


def _proposal(**overrides):
    proposal = {
        "vulnerability_family": "authorization",
        "affected_endpoint": {
            "method": "GET",
            "path": "/files/{file_id}/export",
        },
        "affected_code_path": {
            "source_path": "apps/api/routes/files.ts",
            "symbol_name": "exportFile",
        },
        "suspected_broken_invariant": "Object export must verify ownership before a sensitive sink.",
        "impact_rationale": "An unauthorized object export could expose another account's file.",
        "evidence_requirements": ["Review local ownership checks."],
        "refutation_questions": ["Does middleware enforce object ownership?"],
        "root_cause_summary": "missing_object_ownership_check",
        "risk_estimate": "high",
        "cited_fact_refs": [
            "code:files.ts:exportFile:authorization_gap_candidate",
            "api:GET:/files/{file_id}/export",
        ],
    }
    proposal.update(overrides)
    return proposal


def _response(*proposals):
    return {
        "schema_version": "cross_source_candidate_model_v1",
        "proposals": list(proposals),
    }


def test_fact_pack_excludes_raw_content_and_sensitive_fields():
    fact_pack = _fact_pack()
    serialized = str(fact_pack.model_dump(mode="json"))

    assert "not included in the fact pack" not in serialized
    assert "Bearer should-not-appear" not in serialized
    assert fact_pack.allowed_fact_refs
    assert fact_pack.execution_allowed is False
    assert fact_pack.validation_allowed is False
    assert fact_pack.report_submission_allowed is False


def test_fact_pack_prefers_observed_gap_when_code_fact_refs_collide():
    fact_pack = build_fact_pack(
        pipeline_run_id="run-colliding-code-ref",
        scope_status="in_scope",
        source_files=[{"path": "routes.ts", "content": "synthetic"}],
        facts=[
            {
                "fact_ref": "code:routes.ts:readRecord",
                "fact_type": "route_handler",
                "artifact_kind": "code",
                "source_path": "routes.ts",
                "symbol_name": "readRecord",
                "route_method": "GET",
                "route_path": "/records/:recordId",
            },
            {
                "fact_ref": "code:routes.ts:readRecord",
                "fact_type": "authorization_gap_candidate",
                "artifact_kind": "code",
                "source_path": "routes.ts",
                "symbol_name": "readRecord",
                "route_method": "GET",
                "route_path": "/records/:recordId",
                "root_cause": "missing_object_ownership_check",
            },
        ],
        baseline_candidates=[],
    )

    assert len(fact_pack.code_facts) == 1
    assert fact_pack.code_facts[0].fact_type == "authorization_gap_candidate"
    assert fact_pack.code_facts[0].root_cause == "missing_object_ownership_check"


def test_fact_pack_redacts_sensitive_baseline_text():
    fact_pack = build_fact_pack(
        pipeline_run_id="run-001",
        scope_status="in_scope",
        source_files=[],
        facts=[],
        baseline_candidates=[
            {
                "hypothesis_id": "H-secret",
                "vuln_type": "authorization",
                "root_cause": "Authorization: Bearer secret-value",
                "evidence_needed": ["Bearer secret-value"],
            }
        ],
    )

    serialized = str(fact_pack.model_dump(mode="json"))

    assert "secret-value" not in serialized


def test_valid_cross_source_model_proposal_is_accepted_with_stable_identity():
    fact_pack = _fact_pack()

    result = asyncio.run(
        generate_cross_source_candidates(
            fact_pack=fact_pack,
            baseline_candidates=[],
            model_config=_model_config(),
            reasoner=ReplayCandidateReasoner(_response(_proposal())),
        )
    )

    candidate = result.accepted_candidates[0]

    assert result.model_status == "completed"
    assert candidate["candidate_id"].startswith("model_")
    assert candidate["root_cause_id"] == "missing_object_ownership_check:export_file"
    assert candidate["evidence_trace_status"] == "traceable"
    assert set(candidate["source_fact_refs"]) == {
        "code:files.ts:exportFile:authorization_gap_candidate",
        "api:GET:/files/{file_id}/export",
    }
    assert candidate["execution_allowed"] is False
    assert candidate["validation_allowed"] is False
    assert candidate["report_submission_allowed"] is False


def test_unknown_fact_reference_is_rejected_without_dropping_baseline():
    fact_pack = _fact_pack()
    proposal = _proposal(cited_fact_refs=["code:unknown", "api:GET:/files/{file_id}/export"])

    result = asyncio.run(
        generate_cross_source_candidates(
            fact_pack=fact_pack,
            baseline_candidates=fact_pack.baseline_candidates,
            model_config=_model_config(),
            reasoner=ReplayCandidateReasoner(_response(proposal)),
        )
    )

    assert result.model_status == "completed"
    assert result.accepted_candidates == []
    assert result.rejection_reason_counts == {"invalid_fact_refs": 1}
    assert [candidate["candidate_id"] for candidate in result.working_candidates] == [
        "H-001"
    ]


def test_invalid_schema_is_visible_and_keeps_baseline_candidates():
    fact_pack = _fact_pack()
    proposal = _proposal(unexpected_permission=True)

    result = asyncio.run(
        generate_cross_source_candidates(
            fact_pack=fact_pack,
            baseline_candidates=fact_pack.baseline_candidates,
            model_config=_model_config(),
            reasoner=ReplayCandidateReasoner(_response(proposal)),
        )
    )

    assert result.model_status == "needs_model_review"
    assert result.model_failure_reason == "invalid_schema"
    assert [candidate["candidate_id"] for candidate in result.working_candidates] == [
        "H-001"
    ]


def test_model_timeout_is_visible_and_keeps_baseline_candidates():
    class TimeoutReasoner:
        async def generate(self, **_kwargs):
            return CandidateModelResult(status="timeout")

    fact_pack = _fact_pack()
    result = asyncio.run(
        generate_cross_source_candidates(
            fact_pack=fact_pack,
            baseline_candidates=fact_pack.baseline_candidates,
            model_config=_model_config(),
            reasoner=TimeoutReasoner(),
        )
    )

    assert result.model_status == "needs_model_review"
    assert result.model_failure_reason == "timeout"
    assert [candidate["candidate_id"] for candidate in result.working_candidates] == [
        "H-001"
    ]


def test_registry_reasoner_preserves_safe_provider_error_audit_metadata():
    class ErrorRegistry:
        async def generate(self, request):
            return LLMResponse(
                provider=request.provider,
                model=request.model,
                text="",
                mode=LLMMode.LIVE,
                prompt_hash="prompt-hash",
                latency_ms=37,
                error="provider unavailable",
            )

    result = asyncio.run(
        RegistryCandidateReasoner(ErrorRegistry()).generate(
            fact_pack=_fact_pack(),
            model_config=_model_config(),
            request_key="request-key",
        )
    )

    assert result.status == "provider_error"
    assert result.prompt_hash == "prompt-hash"
    assert result.latency_ms == 37


def test_registry_reasoner_preserves_success_latency_for_audit():
    class SuccessRegistry:
        async def generate(self, request):
            return LLMResponse(
                provider=request.provider,
                model=request.model,
                text=json.dumps(_response(_proposal())),
                mode=LLMMode.LIVE,
                prompt_hash="prompt-hash",
                latency_ms=41,
                error=None,
            )

    result = asyncio.run(
        RegistryCandidateReasoner(SuccessRegistry()).generate(
            fact_pack=_fact_pack(),
            model_config=_model_config(),
            request_key="request-key",
        )
    )

    assert result.status == "completed"
    assert result.latency_ms == 41


def test_generation_preserves_model_latency_for_audit():
    class ErrorReasoner:
        async def generate(self, **_kwargs):
            return CandidateModelResult(
                status="provider_error",
                prompt_hash="prompt-hash",
                latency_ms=37,
            )

    fact_pack = _fact_pack()
    result = asyncio.run(
        generate_cross_source_candidates(
            fact_pack=fact_pack,
            baseline_candidates=fact_pack.baseline_candidates,
            model_config=_model_config(),
            reasoner=ErrorReasoner(),
        )
    )

    assert result.model_status == "needs_model_review"
    assert result.model_failure_reason == "provider_error"
    assert result.model_latency_ms == 37


def test_model_candidate_merges_with_baseline_without_removing_evidence():
    fact_pack = _fact_pack()

    result = asyncio.run(
        generate_cross_source_candidates(
            fact_pack=fact_pack,
            baseline_candidates=fact_pack.baseline_candidates,
            model_config=_model_config(),
            reasoner=ReplayCandidateReasoner(_response(_proposal())),
        )
    )

    assert len(result.working_candidates) == 1
    candidate = result.working_candidates[0]
    assert candidate["candidate_id"] == "H-001"
    assert set(candidate["source_fact_refs"]) == {
        "code:files.ts:exportFile:authorization_gap_candidate",
        "api:GET:/files/{file_id}/export",
    }
    assert "review ownership checks" in candidate["evidence_requirements"]
    assert "Does middleware enforce object ownership?" in candidate[
        "refutation_questions"
    ]
    assert candidate["model_priority_score"] == 80
    hunter_inputs = candidate_hunter_inputs(
        candidates=result.working_candidates,
        fact_pack=fact_pack,
    )
    assert hunter_inputs[0]["model_priority_score"] == 80


def test_fact_bound_model_enriches_unique_placeholder_baseline_on_same_route():
    fact_pack = _fact_pack()
    placeholder_baseline = {
        "candidate_id": "H-placeholder",
        "vulnerability_family": "authorization",
        "route": {"method": "GET", "path": "/files/{file_id}/export"},
        "priority_score": 90,
        "root_cause_summary": "baseline_candidate",
        "source_fact_refs": [
            "scope:scope_context",
            "policy:policy_context",
            "api:GET:/files/{file_id}/export",
        ],
        "evidence_requirements": ["Review local ownership checks."],
        "refutation_questions": ["Could an upstream control enforce ownership?"],
    }

    result = asyncio.run(
        generate_cross_source_candidates(
            fact_pack=fact_pack,
            baseline_candidates=[placeholder_baseline],
            model_config=_model_config(),
            reasoner=ReplayCandidateReasoner(_response(_proposal())),
        )
    )

    assert len(result.accepted_candidates) == 1
    assert len(result.working_candidates) == 1
    candidate = result.working_candidates[0]
    assert candidate["candidate_id"] == "H-placeholder"
    assert candidate["origin"] == "baseline+model"
    assert candidate["root_cause_id"] == (
        "missing_object_ownership_check:export_file"
    )
    assert "code:files.ts:exportFile:authorization_gap_candidate" in candidate[
        "source_fact_refs"
    ]


def test_duplicate_model_proposals_merge_without_claiming_baseline_origin():
    fact_pack = _fact_pack()
    duplicate = _proposal(
        evidence_requirements=["Review service ownership checks."],
        refutation_questions=["Does the service reject cross-account access?"],
    )

    result = asyncio.run(
        generate_cross_source_candidates(
            fact_pack=fact_pack,
            baseline_candidates=[],
            model_config=_model_config(),
            reasoner=ReplayCandidateReasoner(_response(_proposal(), duplicate)),
        )
    )

    assert len(result.accepted_candidates) == 2
    assert len(result.working_candidates) == 1
    assert result.working_candidates[0]["origin"] == "model"


def test_sensitive_model_content_is_rejected_and_missing_link_stays_unresolved():
    fact_pack = _fact_pack()
    sensitive = _proposal(impact_rationale="Authorization: Bearer secret-value")
    unresolved = _proposal(
        affected_code_path=None,
        missing_link_reason="No local handler link is observed yet.",
        cited_fact_refs=["api:GET:/files/{file_id}/export"],
    )

    result = asyncio.run(
        generate_cross_source_candidates(
            fact_pack=fact_pack,
            baseline_candidates=[],
            model_config=_model_config(),
            reasoner=ReplayCandidateReasoner(_response(sensitive, unresolved)),
        )
    )

    assert result.rejection_reason_counts == {"sensitive_content": 1}
    assert len(result.accepted_candidates) == 1
    assert result.accepted_candidates[0]["evidence_trace_status"] == "needs_evidence"
    assert result.final_candidates == []


def test_candidate_hunter_inputs_keep_only_cited_normalized_facts():
    fact_pack = _fact_pack()
    result = asyncio.run(
        generate_cross_source_candidates(
            fact_pack=fact_pack,
            baseline_candidates=fact_pack.baseline_candidates,
            model_config=None,
            reasoner=None,
        )
    )

    inputs = candidate_hunter_inputs(
        candidates=result.working_candidates,
        fact_pack=fact_pack,
    )

    assert inputs[0]["hypothesis_id"] == "H-001"
    assert inputs[0]["location"] == "GET /files/{file_id}/export"
    assert inputs[0]["source_facts"] == [
        {
            "fact_ref": "code:files.ts:exportFile:authorization_gap_candidate",
            "fact_type": "authorization_gap_candidate",
            "artifact_kind": "code",
            "source_path": "apps/api/routes/files.ts",
            "symbol_name": "exportFile",
            "route_method": "GET",
            "route_path": "/files/{file_id}/export",
            "root_cause": "missing_object_ownership_check",
        }
    ]


def test_generation_stage_payload_is_redacted_and_idempotent():
    fact_pack = _fact_pack()
    result = asyncio.run(
        generate_cross_source_candidates(
            fact_pack=fact_pack,
            baseline_candidates=fact_pack.baseline_candidates,
            model_config=None,
            reasoner=None,
        )
    )

    payload = generation_stage_payload(fact_pack=fact_pack, result=result)

    assert payload["schema_version"] == "cross_source_candidate_generation_v1"
    assert payload["model_requested"] is False
    assert payload["model_status"] == "model_not_requested"
    assert "provider" not in payload
    assert "model" not in payload
    assert payload["baseline_count"] == 1
    assert payload["proposed_count"] == 0
    assert payload["accepted_count"] == 0
    assert payload["rejected_count"] == 0
    assert payload["working_candidate_count"] == 1
    assert payload["idempotency_key"]
    assert payload["execution_allowed"] is False
    assert payload["validation_allowed"] is False
    assert payload["report_submission_allowed"] is False
    assert "not included in the fact pack" not in str(payload)


def test_generation_stage_payload_records_requested_model_metadata():
    assert "model_config" in inspect.signature(generation_stage_payload).parameters

    fact_pack = _fact_pack()
    result = asyncio.run(
        generate_cross_source_candidates(
            fact_pack=fact_pack,
            baseline_candidates=[],
            model_config=_model_config(),
            reasoner=ReplayCandidateReasoner(_response(_proposal())),
        )
    )

    payload = generation_stage_payload(
        fact_pack=fact_pack,
        result=result,
        model_config=_model_config(),
    )

    assert payload["model_requested"] is True
    assert payload["provider"] == "openai"
    assert payload["model"] == "test-model"
    assert payload["model_status"] == "completed"
    assert payload["model_latency_ms"] is None
    assert payload["baseline_count"] == 0
    assert payload["proposed_count"] == 1
    assert payload["accepted_count"] == 1
    assert payload["rejected_count"] == 0
    assert payload["working_candidate_count"] == 1
