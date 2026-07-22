from hashlib import sha256

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from threading import Event, Thread

import pytest

import app.autonomous_research_runtime as autonomous_research_runtime
from app.db import Base
from app.repository import DatabaseRepository, seed_sample_data
from app.worker import tasks as worker_tasks
from app.config import get_settings
from app.worker.tasks import dispatch_agent_task, ping, run_agent_task


def build_repository():
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    session = sessionmaker(bind=engine)()
    seed_sample_data(session)
    return DatabaseRepository(session), session


def _persisted_codebase_fact_ref(
    facts,
    *,
    fact_type,
    source_path=None,
    route_path=None,
    symbol_name=None,
):
    matches = [
        fact
        for fact in facts
        if fact.fact_type == fact_type
        and (source_path is None or fact.source_path == source_path)
        and (route_path is None or fact.route_path == route_path)
        and (symbol_name is None or fact.symbol_name == symbol_name)
    ]
    assert len(matches) == 1
    return f"codebase_fact:{matches[0].id}"


def test_ping_task_returns_pong():
    assert ping.run() == "pong"


def test_candidate_fingerprint_ignores_persisted_fact_ids_but_keeps_stable_evidence():
    base_candidate = {
        "vuln_type": "authorization",
        "root_cause_id": "missing_object_ownership_check:export_file",
        "route": {"method": "GET", "path": "/files/{file_id}/export"},
        "affected_code_path": "code:apps/api/routes/files.py:export_file",
        "source_fact_refs": [
            "scope:scope_context",
            "policy:policy_context",
            "code:apps/api/routes/files.py:export_file",
            "api:GET:/files/{file_id}/export",
            "codebase_fact:codebase_fact_" + "a" * 32,
            "codebase_fact:codebase_fact_" + "b" * 32,
        ],
    }
    remapped_candidate = {
        **base_candidate,
        "source_fact_refs": [
            *base_candidate["source_fact_refs"][:4],
            "codebase_fact:codebase_fact_" + "c" * 32,
            "codebase_fact:codebase_fact_" + "d" * 32,
        ],
    }
    different_code_path = {
        **remapped_candidate,
        "affected_code_path": "code:apps/api/routes/admin.py:export_file",
        "source_fact_refs": [
            "scope:scope_context",
            "policy:policy_context",
            "code:apps/api/routes/admin.py:export_file",
            "api:GET:/files/{file_id}/export",
            "codebase_fact:codebase_fact_" + "e" * 32,
        ],
    }
    opaque_first = {
        **base_candidate,
        "source_fact_refs": ["codebase_fact:codebase_fact_" + "f" * 32],
    }
    opaque_second = {
        **base_candidate,
        "source_fact_refs": ["codebase_fact:codebase_fact_" + "0" * 32],
    }

    base_fingerprint = worker_tasks._candidate_fingerprint(base_candidate)
    remapped_fingerprint = worker_tasks._candidate_fingerprint(remapped_candidate)
    different_path_fingerprint = worker_tasks._candidate_fingerprint(different_code_path)
    opaque_first_fingerprint = worker_tasks._candidate_fingerprint(opaque_first)
    opaque_second_fingerprint = worker_tasks._candidate_fingerprint(opaque_second)

    assert base_fingerprint is not None
    assert base_fingerprint == remapped_fingerprint
    assert different_path_fingerprint != base_fingerprint
    assert opaque_first_fingerprint != opaque_second_fingerprint


def test_finding_dedup_ranking_uses_persisted_candidate_scores_with_legacy_fallback(
    monkeypatch,
):
    repository, session = build_repository()
    try:
        campaign = repository.create_campaign(
            program_id="program_example",
            name="Candidate ranking campaign",
            autonomy_level="level_0_read_only",
            scope_status="in_scope",
            policy_text="Authorized local review only.",
            default_asset="api.example.com",
            created_by="operator",
        )
        pipeline_run = repository.save_pipeline_run(
            asset=campaign.default_asset,
            policy_text="a" * 64,
            policy_text_is_hash=True,
            scope_status="in_scope",
            hypothesis_count=2,
            blocked_count=0,
            report_title=None,
            payload={"campaign_id": campaign.id},
        )
        task = repository.create_campaign_task(
            campaign_id=campaign.id,
            task_type="finding_dedup_and_rank",
            agent_type="triage_agent",
            title="Deduplicate and rank retained candidates",
            input_refs=[f"pipeline_run:{pipeline_run.id}"],
            payload={"pipeline_run_id": pipeline_run.id},
        )

        def candidate(candidate_id, *, include_scores):
            value = {
                "candidate_id": candidate_id,
                "vuln_type": "authorization",
                "root_cause_id": f"missing_object_ownership_check:{candidate_id}",
                "route": {"method": "GET", "path": f"/records/{candidate_id}"},
                "affected_code_path": f"code:routes.py:{candidate_id}",
                "source_fact_refs": [
                    "scope:scope_context",
                    "policy:policy_context",
                    f"code:routes.py:{candidate_id}",
                    f"api:GET:/records/{candidate_id}",
                    "har:har_context",
                ],
                "execution_allowed": False,
                "dispatch_allowed": False,
                "validation_allowed": False,
                "candidate_promotion_allowed": False,
                "report_submission_allowed": False,
            }
            if include_scores:
                value.update(
                    {
                        "survived_kill_score": 2,
                        "evidence_completeness_score": 5,
                        "priority_score": 20,
                    }
                )
            return value

        final_candidates = [
            candidate("A-low", include_scores=True),
            candidate("Z-high", include_scores=False),
        ]
        decisions = [
            {
                "candidate_id": "A-low",
                "root_cause_id": "missing_object_ownership_check:A-low",
                "disposition": "retained",
                "survived_kill_score": 2,
                "evidence_completeness_score": 5,
                "priority_score": 20,
            },
            {
                "candidate_id": "Z-high",
                "root_cause_id": "missing_object_ownership_check:Z-high",
                "disposition": "retained",
                "survived_kill_score": 8,
                "evidence_completeness_score": 5,
                "priority_score": 90,
            },
        ]
        monkeypatch.setattr(
            "app.candidate_hunter_loop.load_candidate_hunter_projection",
            lambda **_kwargs: {
                "status": "ready",
                "final_candidates": final_candidates,
                "candidate_decisions": decisions,
            },
        )

        result = worker_tasks._run_finding_dedup_and_rank_task(
            task=task,
            campaign=campaign,
            repository=repository,
        )

        assert result["status"] == "completed", result
        ranking_stage = next(
            stage
            for stage in repository.list_pipeline_stages_for_run(pipeline_run.id)
            if stage.stage_key == "autonomous_finding_dedup_and_rank"
        )
        assert [item["candidate_id"] for item in ranking_stage.payload["top_candidates"]] == [
            "Z-high",
            "A-low",
        ]
        assert [item["priority_score"] for item in ranking_stage.payload["top_candidates"]] == [
            90,
            20,
        ]
    finally:
        session.close()


def test_report_review_completes_without_handoff_when_no_candidates_remain(monkeypatch):
    repository, session = build_repository()
    try:
        source_snapshot_digest = "sha256:" + "a" * 64
        campaign = repository.create_campaign(
            program_id="program_example",
            name="No reportable candidate campaign",
            autonomy_level="level_0_read_only",
            scope_status="in_scope",
            policy_text="Authorized local review only.",
            default_asset="api.example.com",
            created_by="operator",
            payload={
                "scope_guard_rule": {
                    "asset": "api.example.com",
                    "scope_status": "in_scope",
                    "automation": "none",
                    "allowed_validation": [],
                    "forbidden": [],
                    "human_approval_required": True,
                },
                "source_snapshot_digest": source_snapshot_digest,
                "execution_allowed": False,
                "dispatch_allowed": False,
                "validation_allowed": False,
                "candidate_promotion_allowed": False,
                "report_submission_allowed": False,
                "raw_payload_processed": False,
            },
        )
        campaign = repository.update_campaign_status(campaign.id, "running")
        assert campaign is not None
        pipeline_run = repository.save_pipeline_run(
            program_id=campaign.program_id,
            asset=campaign.default_asset,
            policy_text="a" * 64,
            policy_text_is_hash=True,
            scope_status="in_scope",
            hypothesis_count=0,
            blocked_count=0,
            report_title=None,
            payload={"campaign_id": campaign.id},
        )
        ranking_stage = repository.save_pipeline_stage(
            pipeline_run_id=pipeline_run.id,
            campaign_id=campaign.id,
            task_id="ranking-task",
            stage_key="autonomous_finding_dedup_and_rank",
            stage_order=30,
            status="completed",
            input_refs=[f"pipeline_run:{pipeline_run.id}"],
            output_refs=[],
            safety_gate_state="safe",
            stop_reason=None,
            payload={
                "schema_version": "autonomous_finding_dedup_and_rank_v1",
                "pipeline_run_id": pipeline_run.id,
                "top_candidates": [],
                "excluded_candidate_ids": ["refuted-candidate"],
                "cross_run_duplicates": [],
                "submission_blocked": True,
                "raw_payload_processed": False,
                "execution_allowed": False,
                "dispatch_allowed": False,
                "validation_allowed": False,
                "candidate_promotion_allowed": False,
                "report_submission_allowed": False,
            },
        )
        task = repository.create_campaign_task(
            campaign_id=campaign.id,
            task_type="report_review",
            agent_type="report_agent",
            title="Build submission-blocked report review",
            input_refs=[f"pipeline_run:{pipeline_run.id}"],
            payload=autonomous_research_runtime._runtime_task_payload(
                campaign_id=campaign.id,
                task_type="report_review",
                source_snapshot_digest=source_snapshot_digest,
                pipeline_run_id=pipeline_run.id,
            ),
        )
        task = repository.claim_campaign_task_execution(task.id)
        assert task is not None
        monkeypatch.setattr(
            worker_tasks,
            "_runtime_candidate_hunter_projection_for_downstream",
            lambda **_kwargs: (None, None),
        )
        monkeypatch.setattr(
            "app.candidate_hunter_loop.load_candidate_hunter_projection",
            lambda **_kwargs: {
                "status": "ready",
                "final_candidates": [],
                "candidate_decisions": [
                    {
                        "candidate_id": "refuted-candidate",
                        "disposition": "refuted",
                    }
                ],
            },
        )

        result = worker_tasks._run_report_review_task(
            task=task,
            campaign=campaign,
            repository=repository,
        )

        persisted_campaign = repository.get_campaign(campaign.id)
        persisted_task = repository.session.get(type(task), task.id)
        report_stage = next(
            stage
            for stage in repository.list_pipeline_stages_for_run(pipeline_run.id)
            if stage.task_id == task.id
            and stage.stage_key == "autonomous_report_review"
        )
        runtime_stage = next(
            stage
            for stage in repository.list_campaign_pipeline_stages(campaign.id)
            if stage.task_id == task.id
            and stage.stage_key == "autonomous_research:report_review"
        )

        assert result["status"] == "completed"
        assert result["stop_reason"] == "no_reportable_candidates"
        assert persisted_campaign is not None
        assert persisted_campaign.status == "completed"
        selection = autonomous_research_runtime.select_autonomous_research_work(
            campaign=persisted_campaign,
            repository=repository,
        )
        assert selection["status"] == "blocked"
        assert selection["stop_reason"] == "campaign_completed"
        assert persisted_task is not None
        assert persisted_task.status == "completed"
        assert report_stage.safety_gate_state == "safe"
        assert report_stage.stop_reason == "no_reportable_candidates"
        assert report_stage.payload["report_drafts"] == []
        assert report_stage.payload["human_review_required"] is False
        assert runtime_stage.stop_reason == "no_reportable_candidates"
        assert not [
            item
            for item in repository.list_campaign_tasks(campaign.id)
            if item.task_type == "validation_handoff"
        ]
        assert ranking_stage.id in {
            stage.id
            for stage in repository.list_pipeline_stages_for_run(pipeline_run.id)
        }

        replay = worker_tasks._run_report_review_task(
            task=persisted_task,
            campaign=persisted_campaign,
            repository=repository,
        )

        assert replay["status"] == "completed"
        assert replay["stop_reason"] == "no_reportable_candidates"
        assert len(
            [
                stage
                for stage in repository.list_pipeline_stages_for_run(pipeline_run.id)
                if stage.task_id == task.id
                and stage.stage_key == "autonomous_report_review"
            ]
        ) == 1
        assert len(
            [
                stage
                for stage in repository.list_campaign_pipeline_stages(campaign.id)
                if stage.task_id == task.id
                and stage.stage_key == "autonomous_research:report_review"
            ]
        ) == 1
        assert len(
            [
                run
                for run in repository.list_campaign_agent_runs(campaign.id)
                if run.task_id == task.id
            ]
        ) == 1
    finally:
        session.close()


def test_report_review_creates_candidate_specific_validation_handoffs(monkeypatch):
    repository, session = build_repository()
    try:
        source_snapshot_digest = "sha256:" + "b" * 64
        safety = {
            "execution_allowed": False,
            "dispatch_allowed": False,
            "validation_allowed": False,
            "candidate_promotion_allowed": False,
            "report_submission_allowed": False,
        }
        campaign = repository.create_campaign(
            program_id="program_example",
            name="Candidate-specific validation handoffs",
            autonomy_level="level_0_read_only",
            scope_status="in_scope",
            policy_text="Authorized local review only.",
            default_asset="api.example.com",
            created_by="operator",
            payload={
                "scope_guard_rule": {
                    "asset": "api.example.com",
                    "scope_status": "in_scope",
                    "automation": "none",
                    "allowed_validation": [],
                    "forbidden": [],
                    "human_approval_required": True,
                },
                "source_snapshot_digest": source_snapshot_digest,
                "raw_payload_processed": False,
                **safety,
            },
        )
        campaign = repository.update_campaign_status(campaign.id, "running")
        assert campaign is not None
        pipeline_run = repository.save_pipeline_run(
            program_id=campaign.program_id,
            asset=campaign.default_asset,
            policy_text=campaign.policy_text_hash,
            policy_text_is_hash=True,
            scope_status="in_scope",
            hypothesis_count=2,
            blocked_count=0,
            report_title=None,
            payload={"campaign_id": campaign.id},
        )
        decisions = [
            {
                "candidate_id": "H-ssrf",
                "root_cause_id": "missing_ssrf_validation:fetch_remote",
                "disposition": "retained",
            },
            {
                "candidate_id": "H-upload",
                "root_cause_id": "missing_file_upload_validation:store_upload",
                "disposition": "retained",
            },
        ]
        decision_stage = repository.save_pipeline_stage(
            pipeline_run_id=pipeline_run.id,
            campaign_id=campaign.id,
            task_id="candidate-hunter-task",
            stage_key="candidate_hunter_decision",
            stage_order=20,
            status="completed",
            input_refs=[f"pipeline_run:{pipeline_run.id}"],
            output_refs=[],
            safety_gate_state="safe",
            stop_reason=None,
            payload={
                "state_digest": "candidate-state-digest",
                "candidate_decisions": decisions,
                "raw_payload_processed": False,
                **safety,
            },
        )
        ranking_stage = repository.save_pipeline_stage(
            pipeline_run_id=pipeline_run.id,
            campaign_id=campaign.id,
            task_id="ranking-task",
            stage_key="autonomous_finding_dedup_and_rank",
            stage_order=30,
            status="completed",
            input_refs=[f"pipeline_run:{pipeline_run.id}"],
            output_refs=[],
            safety_gate_state="safe",
            stop_reason=None,
            payload={
                "schema_version": "autonomous_finding_dedup_and_rank_v1",
                "pipeline_run_id": pipeline_run.id,
                "top_candidates": [
                    {"candidate_id": "H-ssrf", "rank": 1, **safety},
                    {"candidate_id": "H-upload", "rank": 2, **safety},
                ],
                "submission_blocked": True,
                "raw_payload_processed": False,
                **safety,
            },
        )
        task = repository.create_campaign_task(
            campaign_id=campaign.id,
            task_type="report_review",
            agent_type="report_agent",
            title="Build submission-blocked report review",
            input_refs=[f"pipeline_run:{pipeline_run.id}"],
            payload=autonomous_research_runtime._runtime_task_payload(
                campaign_id=campaign.id,
                task_type="report_review",
                source_snapshot_digest=source_snapshot_digest,
                pipeline_run_id=pipeline_run.id,
            ),
        )
        task = repository.claim_campaign_task_execution(task.id)
        assert task is not None
        monkeypatch.setattr(
            worker_tasks,
            "_runtime_candidate_hunter_projection_for_downstream",
            lambda **_kwargs: (None, None),
        )
        candidates = [
            {
                "candidate_id": "H-ssrf",
                "vuln_type": "ssrf",
                "root_cause_id": "missing_ssrf_validation:fetch_remote",
                "route": {"method": "POST", "path": "/fetch"},
                "affected_code_path": "code:routes.py:fetch_remote",
                "source_fact_refs": [
                    "scope:scope_context",
                    "policy:policy_context",
                    "code:routes.py:fetch_remote",
                    "api:POST:/fetch",
                    "har:har_context",
                ],
                "validation_mode": "offline_ssrf_target_policy_review",
                "evidence_needed": ["local_egress_validation_trace"],
                "safe_validation_plan": ["Review local egress policy."],
                **safety,
            },
            {
                "candidate_id": "H-upload",
                "vuln_type": "file_upload",
                "root_cause_id": "missing_file_upload_validation:store_upload",
                "route": {"method": "POST", "path": "/uploads"},
                "affected_code_path": "code:routes.py:store_upload",
                "source_fact_refs": [
                    "scope:scope_context",
                    "policy:policy_context",
                    "code:routes.py:store_upload",
                    "api:POST:/uploads",
                    "har:har_context",
                ],
                "validation_mode": "offline_file_upload_policy_review",
                "evidence_needed": ["local_upload_validation_trace"],
                "safe_validation_plan": ["Review local upload policy."],
                **safety,
            },
        ]
        monkeypatch.setattr(
            "app.candidate_hunter_loop.load_candidate_hunter_projection",
            lambda **_kwargs: {
                "status": "ready",
                "final_candidates": candidates,
                "candidate_decisions": decisions,
                "audit": {
                    "state_digest": "candidate-state-digest",
                    "stage_refs": [
                        {
                            "stage_key": "candidate_hunter_decision",
                            "round": 1,
                            "stage_id": decision_stage.id,
                        }
                    ],
                },
            },
        )
        monkeypatch.setattr(
            "app.intelligence_benchmark.candidate_report_bridge.build_submission_blocked_report_bundle",
            lambda candidate: {
                "candidate_id": candidate["candidate_id"],
                "vuln_type": candidate["vuln_type"],
                "root_cause_id": candidate["root_cause_id"],
                "route": (
                    f"{candidate['route']['method']} {candidate['route']['path']}"
                ),
                "affected_code_path": candidate["affected_code_path"],
                "source_fact_refs": candidate["source_fact_refs"],
                "status": "unverified_hypothesis",
                "submission_blocked": True,
                "human_review_required": True,
                "execution_allowed": False,
                "validation_allowed": False,
                "report_submission_allowed": False,
                "confirmed_vulnerability": False,
                "multi_engine_verdict": {
                    "candidate_id": candidate["candidate_id"],
                    "status": "local_static_consistent",
                    "execution_allowed": False,
                    "validation_allowed": False,
                    "report_submission_allowed": False,
                    "finding_promotion_allowed": False,
                    "confirmed_vulnerability": False,
                },
                "falsification_summary": {
                    "schema_version": "falsification_card_v1",
                    "decision_status": "retained",
                    "why_still_alive": [
                        "No decisive local defense fact refuted the candidate."
                    ],
                    "why_dead": [],
                    "broken_invariant": "Mapped security invariant remains unverified.",
                    "open_dimensions": [],
                    "survived_kill_score": 1,
                    "execution_allowed": False,
                    "dispatch_allowed": False,
                    "validation_allowed": False,
                    "candidate_promotion_allowed": False,
                    "report_submission_allowed": False,
                },
                "report_draft": {
                    "title": "Submission-blocked review",
                    "falsification_summary": {
                        "schema_version": "falsification_card_v1",
                        "decision_status": "retained",
                        "why_still_alive": [
                            "No decisive local defense fact refuted the candidate."
                        ],
                        "why_dead": [],
                        "broken_invariant": "Mapped security invariant remains unverified.",
                        "open_dimensions": [],
                        "survived_kill_score": 1,
                        "execution_allowed": False,
                        "dispatch_allowed": False,
                        "validation_allowed": False,
                        "candidate_promotion_allowed": False,
                        "report_submission_allowed": False,
                    },
                },
            },
        )

        original_claim = repository.claim_campaign_task
        failed_handoff_creation = False

        def interrupted_handoff_claim(**kwargs):
            nonlocal failed_handoff_creation
            payload = kwargs.get("payload")
            if (
                isinstance(payload, dict)
                and payload.get("candidate_id") == "H-upload"
                and not failed_handoff_creation
            ):
                failed_handoff_creation = True
                raise RuntimeError("simulated validation handoff interruption")
            return original_claim(**kwargs)

        monkeypatch.setattr(repository, "claim_campaign_task", interrupted_handoff_claim)
        with pytest.raises(RuntimeError, match="simulated validation handoff interruption"):
            worker_tasks._run_report_review_task(
                task=task,
                campaign=campaign,
                repository=repository,
            )
        monkeypatch.setattr(repository, "claim_campaign_task", original_claim)

        result = worker_tasks._run_report_review_task(
            task=task,
            campaign=campaign,
            repository=repository,
        )

        handoffs = sorted(
            (
                item
                for item in repository.list_campaign_tasks(campaign.id)
                if item.task_type == "validation_handoff"
            ),
            key=lambda item: item.payload["candidate_id"],
        )
        report_stage = next(
            stage
            for stage in repository.list_pipeline_stages_for_run(pipeline_run.id)
            if stage.stage_key == "autonomous_report_review"
        )

        assert result["status"] == "completed"
        assert len(handoffs) == 2
        assert [handoff.payload["candidate_ids"] for handoff in handoffs] == [
            ["H-ssrf"],
            ["H-upload"],
        ]
        assert [handoff.payload["candidate_validation_context"] for handoff in handoffs] == [
            {
                "candidate_id": "H-ssrf",
                "vuln_type": "ssrf",
                "suggested_validation_mode": "offline_ssrf_target_policy_review",
                "evidence_needed": ["local_egress_validation_trace"],
                "safe_validation_step_count": 1,
            },
            {
                "candidate_id": "H-upload",
                "vuln_type": "file_upload",
                "suggested_validation_mode": "offline_file_upload_policy_review",
                "evidence_needed": ["local_upload_validation_trace"],
                "safe_validation_step_count": 1,
            },
        ]
        assert all(handoff.status == "awaiting_approval" for handoff in handoffs)
        assert all(
            f"candidate:{handoff.payload['candidate_id']}" in handoff.input_refs
            for handoff in handoffs
        )
        assert {
            f"campaign_task:{handoff.id}" for handoff in handoffs
        }.issubset(report_stage.output_refs)
        assert repository.get_campaign(campaign.id).status == "awaiting_review"
        trusted_provenance = worker_tasks._trusted_report_stage_provenance(
            stage=report_stage,
            pipeline_run=pipeline_run,
            repository=repository,
        )
        assert trusted_provenance == report_stage.payload["report_provenance"]
        for draft, provenance in zip(
            report_stage.payload["report_drafts"], trusted_provenance, strict=True
        ):
            assert provenance["multi_engine_status"] == "local_static_consistent"
            assert provenance["multi_engine_verdict_digest"] == (
                worker_tasks._canonical_digest(draft["multi_engine_verdict"])
            )
            assert provenance["falsification_status"] == "retained"
            assert provenance["falsification_summary_digest"] == (
                worker_tasks._canonical_digest(draft["falsification_summary"])
            )

        first_draft = report_stage.payload["report_drafts"][0]
        assert not worker_tasks._runtime_report_multi_engine_verdict_is_valid(
            {
                **first_draft["multi_engine_verdict"],
                "status": "blocked",
            },
            candidate_id=first_draft["candidate_id"],
        )
        assert not worker_tasks._runtime_report_multi_engine_verdict_is_valid(
            {
                **first_draft["multi_engine_verdict"],
                "status": [],
            },
            candidate_id=first_draft["candidate_id"],
        )
        assert not worker_tasks._runtime_report_falsification_summary_is_valid(
            {
                **first_draft["falsification_summary"],
                "decision_status": "refuted",
            }
        )
        original_payload = report_stage.payload
        report_stage.payload = {
            **original_payload,
            "report_drafts": [
                {
                    **first_draft,
                    "falsification_summary": {
                        **first_draft["falsification_summary"],
                        "why_still_alive": ["tampered"],
                    },
                },
                *original_payload["report_drafts"][1:],
            ],
        }
        assert worker_tasks._trusted_report_stage_provenance(
            stage=report_stage,
            pipeline_run=pipeline_run,
            repository=repository,
        ) == []
        report_stage.payload = {
            **original_payload,
            "report_drafts": [
                {
                    **first_draft,
                    "report_draft": {
                        **first_draft["report_draft"],
                        "falsification_summary": {
                            **first_draft["falsification_summary"],
                            "why_still_alive": ["tampered"],
                        },
                    },
                },
                *original_payload["report_drafts"][1:],
            ],
        }
        assert worker_tasks._trusted_report_stage_provenance(
            stage=report_stage,
            pipeline_run=pipeline_run,
            repository=repository,
        ) == []
        report_stage.payload = {
            **original_payload,
            "report_drafts": [
                {
                    **first_draft,
                    "multi_engine_verdict": {
                        **first_draft["multi_engine_verdict"],
                        "next_allowed_action": "tampered",
                    },
                },
                *original_payload["report_drafts"][1:],
            ],
        }
        assert worker_tasks._trusted_report_stage_provenance(
            stage=report_stage,
            pipeline_run=pipeline_run,
            repository=repository,
        ) == []
    finally:
        session.close()


def test_report_review_recovery_blocks_legacy_multi_candidate_handoff():
    repository, session = build_repository()
    try:
        source_snapshot_digest = "sha256:" + "c" * 64
        campaign = repository.create_campaign(
            program_id="program_example",
            name="Legacy validation handoff recovery",
            autonomy_level="level_0_read_only",
            scope_status="in_scope",
            policy_text="Authorized local review only.",
            default_asset="api.example.com",
            created_by="operator",
        )
        campaign = repository.update_campaign_status(campaign.id, "running")
        assert campaign is not None
        pipeline_run = repository.save_pipeline_run(
            program_id=campaign.program_id,
            asset=campaign.default_asset,
            policy_text=campaign.policy_text_hash,
            policy_text_is_hash=True,
            scope_status="in_scope",
            hypothesis_count=2,
            blocked_count=0,
            report_title=None,
            payload={"campaign_id": campaign.id},
        )
        report_task = repository.create_campaign_task(
            campaign_id=campaign.id,
            task_type="report_review",
            agent_type="report_agent",
            title="Build submission-blocked report review",
            input_refs=[f"pipeline_run:{pipeline_run.id}"],
            payload=autonomous_research_runtime._runtime_task_payload(
                campaign_id=campaign.id,
                task_type="report_review",
                source_snapshot_digest=source_snapshot_digest,
                pipeline_run_id=pipeline_run.id,
            ),
        )
        legacy_handoff_id = "campaign_task_validation_handoff_" + sha256(
            f"{report_task.id}:{pipeline_run.id}:validation_handoff".encode("utf-8")
        ).hexdigest()
        legacy_handoff, created = repository.claim_campaign_task(
            task_id=legacy_handoff_id,
            campaign_id=campaign.id,
            task_type="validation_handoff",
            agent_type="human_review",
            title="Review submission-blocked validation handoff",
            input_refs=[
                f"pipeline_run:{pipeline_run.id}",
                f"campaign_task:{report_task.id}",
            ],
            payload={
                "schema_version": "autonomous_validation_handoff_v1",
                "pipeline_run_id": pipeline_run.id,
                "report_review_task_id": report_task.id,
                "source_snapshot_digest": source_snapshot_digest,
                "candidate_ids": ["H-ssrf", "H-upload"],
                "submission_blocked": True,
                "human_review_required": True,
                "approval_required": True,
                "allowed_to_execute": False,
                "execution_allowed": False,
                "dispatch_allowed": False,
                "validation_allowed": False,
                "candidate_promotion_allowed": False,
                "report_submission_allowed": False,
                "raw_payload_processed": False,
            },
        )
        assert created is True
        legacy_handoff = repository.update_campaign_task_status(
            legacy_handoff.id,
            "awaiting_approval",
        )
        assert legacy_handoff is not None

        result = worker_tasks._block_report_review_recovery(
            task=report_task,
            campaign=campaign,
            repository=repository,
        )

        persisted_handoff = next(
            item
            for item in repository.list_campaign_tasks(campaign.id)
            if item.id == legacy_handoff_id
        )
        persisted_report_task = next(
            item
            for item in repository.list_campaign_tasks(campaign.id)
            if item.id == report_task.id
        )

        assert result["status"] == "blocked"
        assert result["stop_reason"] == "report_review_recovery_integrity_invalid"
        assert persisted_handoff.status == "blocked"
        assert persisted_report_task.status == "blocked"
        assert [
            item
            for item in repository.list_campaign_tasks(campaign.id)
            if item.task_type == "validation_handoff" and item.status == "awaiting_approval"
        ] == []
    finally:
        session.close()


def test_autonomous_research_wakeup_task_uses_a_worker_session(monkeypatch):
    import app.autonomous_research_wakeup as autonomous_research_wakeup

    events = []
    repository_sentinel = object()

    class SessionContext:
        def __enter__(self):
            return object()

        def __exit__(self, *_args):
            return False

    def run_wakeup(*, repository, dispatcher):
        events.append((repository, dispatcher))
        return {"status": "completed"}

    monkeypatch.setattr(worker_tasks, "initialize_database", lambda: None)
    monkeypatch.setattr(
        worker_tasks,
        "get_session_factory",
        lambda: lambda: SessionContext(),
    )
    monkeypatch.setattr(
        worker_tasks,
        "DatabaseRepository",
        lambda _session: repository_sentinel,
    )
    monkeypatch.setattr(
        autonomous_research_wakeup,
        "run_autonomous_research_wakeup",
        run_wakeup,
    )

    result = worker_tasks.run_autonomous_research_wakeup_from_queue.run()

    assert result == {"status": "completed"}
    assert events == [(repository_sentinel, worker_tasks.dispatch_agent_task)]
    assert worker_tasks.celery_app.conf.beat_schedule[
        "autonomous-research-wakeup"
    ] == {"task": "autonomous_research.wakeup", "schedule": 60.0}


def test_background_autonomous_wakeup_handoff_is_single_flight(monkeypatch):
    started = Event()
    release = Event()

    def run_wakeup():
        started.set()
        assert release.wait(timeout=1)

    monkeypatch.setattr(
        worker_tasks,
        "_run_autonomous_research_wakeup_with_worker_session",
        run_wakeup,
    )

    assert worker_tasks.start_autonomous_research_wakeup_in_background() is True
    assert started.wait(timeout=1)
    first_thread = worker_tasks._autonomous_research_wakeup_thread
    assert first_thread is not None
    assert worker_tasks.start_autonomous_research_wakeup_in_background() is False

    release.set()
    first_thread.join(timeout=1)

    assert not first_thread.is_alive()
    assert worker_tasks._autonomous_research_wakeup_thread is None


def test_background_autonomous_wakeup_releases_its_slot_when_thread_start_fails(
    monkeypatch,
):
    class FailingThread:
        def __init__(self, **_kwargs):
            pass

        def start(self):
            raise RuntimeError("synthetic thread start failure")

    monkeypatch.setattr(worker_tasks, "Thread", FailingThread)

    with pytest.raises(RuntimeError, match="synthetic thread start failure"):
        worker_tasks.start_autonomous_research_wakeup_in_background()

    assert worker_tasks._autonomous_research_wakeup_thread is None


def test_dispatch_agent_task_enqueues_only_campaign_task_id(monkeypatch):
    calls: list[tuple[tuple, dict]] = []

    class FakeAsyncResult:
        id = "celery_task_1"

    def fake_delay(*args, **kwargs):
        calls.append((args, kwargs))
        return FakeAsyncResult()

    monkeypatch.setattr(worker_tasks.run_agent_task_from_queue, "delay", fake_delay)

    result = dispatch_agent_task(campaign_task_id="campaign_task_1")

    assert calls == [(("campaign_task_1",), {})]
    assert result == {
        "campaign_task_id": "campaign_task_1",
        "dispatch_mode": "celery",
        "celery_task_id": "celery_task_1",
    }


def test_dispatch_agent_task_can_run_inline_without_celery(monkeypatch):
    monkeypatch.setenv("WORKER_DISPATCH_MODE", "inline")
    get_settings.cache_clear()
    calls: list[str] = []

    def fake_run(campaign_task_id: str):
        calls.append(campaign_task_id)
        return {"status": "completed", "task_id": campaign_task_id}

    monkeypatch.setattr(worker_tasks.run_agent_task_from_queue, "run", fake_run)

    try:
        result = dispatch_agent_task(campaign_task_id="campaign_task_1")
    finally:
        get_settings.cache_clear()

    assert calls == ["campaign_task_1"]
    assert result == {
        "campaign_task_id": "campaign_task_1",
        "dispatch_mode": "inline",
        "result": {"status": "completed", "task_id": "campaign_task_1"},
    }


def test_run_agent_task_reloads_task_by_id_and_completes_safe_read_only_work():
    repository, session = build_repository()
    try:
        campaign = repository.create_campaign(
            program_id="program_example",
            name="Worker campaign",
            autonomy_level="level_0_read_only",
            scope_status="in_scope",
            policy_text="Testing allowed",
            default_asset="api.example.com",
            created_by="operator",
        )
        repository.update_campaign_status(campaign.id, "running")
        task = repository.create_campaign_task(
            campaign_id=campaign.id,
            task_type="attack_surface_mapping",
            agent_type="target_model_agent",
            title="Map surface",
            input_refs=["campaign:worker"],
            payload={"raw": "Authorization: Bearer secret-token"},
        )

        result = run_agent_task(task.id, repository=repository)

        assert result["status"] == "completed"
        assert result["task_id"] == task.id
        updated_task = repository.list_campaign_tasks(campaign.id)[0]
        agent_run = repository.list_campaign_agent_runs(campaign.id)[0]
        assert updated_task.status == "completed"
        assert updated_task.output_refs[0] == f"agent_run:{agent_run.id}"
        assert any(ref.startswith("codebase_map:") for ref in updated_task.output_refs)
        assert agent_run.status == "completed"
        assert agent_run.safety_gate_state == "allowed"
        assert agent_run.input_refs == [f"campaign_task:{task.id}"]
        assert "secret-token" not in str(updated_task.payload)
        assert "secret-token" not in str(agent_run.payload)
    finally:
        session.close()


def test_sarif_only_route_never_becomes_a_validation_target():
    repository, session = build_repository()
    try:
        campaign = repository.create_campaign(
            program_id="program_example",
            name="SARIF-only validation gate campaign",
            autonomy_level="level_0_read_only",
            scope_status="in_scope",
            policy_text="Testing allowed",
            default_asset="authorized/service",
            created_by="operator",
        )
        repository.update_campaign_status(campaign.id, "running")
        map_task = repository.create_campaign_task(
            campaign_id=campaign.id,
            task_type="attack_surface_mapping",
            agent_type="target_model_agent",
            title="Map SARIF advisory only",
            input_refs=[f"campaign:{campaign.id}"],
            payload={
                "authorized_advisory_artifacts": [
                    {
                        "kind": "sarif",
                        "source_name": "sarif/scanner.sarif",
                        "payload": {
                            "runs": [
                                {
                                    "results": [
                                        {
                                            "message": {
                                                "text": "GET /records/{record_id}"
                                            }
                                        }
                                    ]
                                }
                            ]
                        },
                    }
                ]
            },
        )
        report_task = repository.create_campaign_task(
            campaign_id=campaign.id,
            task_type="report_chain_review",
            agent_type="report_agent",
            title="Plan a human-gated validation review",
            input_refs=[f"campaign:{campaign.id}"],
            payload={},
        )

        assert run_agent_task(map_task.id, repository=repository)["status"] == "completed"
        assert run_agent_task(report_task.id, repository=repository)["status"] == "completed"

        validation_run = repository.list_campaign_validation_runs(campaign.id)[0]

        assert validation_run.target_ref == f"campaign:{campaign.id}"
        assert validation_run.allowed_to_execute is False
        assert validation_run.approval_required is True
        assert validation_run.payload.get("target_route") is None
    finally:
        session.close()


@pytest.mark.parametrize(
    ("task_type", "title", "failure_target"),
    (
        (
            "attack_surface_mapping",
            "Map authorized attack surface facts",
            "_map_authorized_attack_surface",
        ),
        (
            "hypothesis_generation",
            "Generate candidate hypotheses from safe facts",
            "_fallback_hypothesis_payload",
        ),
    ),
)
def test_runtime_worker_failure_is_audited_and_requires_explicit_retry(
    monkeypatch,
    task_type,
    title,
    failure_target,
):
    repository, session = build_repository()
    try:
        source_snapshot_digest = "sha256:" + "a" * 64
        campaign = repository.create_campaign(
            program_id=None,
            name="Runtime worker failure campaign",
            autonomy_level="level_0_read_only",
            scope_status="in_scope",
            policy_text="Testing allowed",
            default_asset="api.example.com",
            created_by="operator",
            payload={
                "scope_guard_rule": {
                    "asset": "api.example.com",
                    "scope_status": "in_scope",
                    "automation": "none",
                    "allowed_validation": [],
                    "forbidden": [],
                    "human_approval_required": True,
                },
                "source_snapshot_digest": source_snapshot_digest,
            },
        )
        campaign = repository.update_campaign_status(campaign.id, "running")
        assert campaign is not None
        observation_task = repository.create_campaign_task(
            campaign_id=campaign.id,
            task_type="campaign_observation",
            agent_type="orchestrator_agent",
            title="Observe authorized campaign state",
            input_refs=[f"campaign:{campaign.id}"],
            payload=autonomous_research_runtime._runtime_task_payload(
                campaign_id=campaign.id,
                task_type="campaign_observation",
                source_snapshot_digest=source_snapshot_digest,
            ),
        )
        assert (
            run_agent_task(observation_task.id, repository=repository)["status"]
            == "completed"
        )
        if task_type == "hypothesis_generation":
            mapping_task = repository.create_campaign_task(
                campaign_id=campaign.id,
                task_type="attack_surface_mapping",
                agent_type="target_model_agent",
                title="Map authorized attack surface facts",
                input_refs=[f"campaign:{campaign.id}"],
                payload=autonomous_research_runtime._runtime_task_payload(
                    campaign_id=campaign.id,
                    task_type="attack_surface_mapping",
                    source_snapshot_digest=source_snapshot_digest,
                ),
            )
            assert (
                run_agent_task(mapping_task.id, repository=repository)["status"]
                == "completed"
            )
            invariant_task = repository.create_campaign_task(
                campaign_id=campaign.id,
                task_type="security_invariant_generation",
                agent_type="invariant_agent",
                title="Derive security invariants from mapped facts",
                input_refs=[f"campaign:{campaign.id}"],
                payload=autonomous_research_runtime._runtime_task_payload(
                    campaign_id=campaign.id,
                    task_type="security_invariant_generation",
                    source_snapshot_digest=source_snapshot_digest,
                ),
            )
            invariant_ref = f"security_invariant_projection:{invariant_task.id}"
            invariant_task = repository.update_campaign_task_status(
                invariant_task.id,
                "completed",
                output_refs=[invariant_ref],
            )
            assert invariant_task is not None
            repository.save_pipeline_stage(
                pipeline_run_id=None,
                campaign_id=campaign.id,
                task_id=invariant_task.id,
                stage_key="autonomous_research:security_invariant_generation",
                stage_order=2,
                status="completed",
                input_refs=invariant_task.input_refs,
                output_refs=[invariant_ref],
                safety_gate_state="allowed",
                stop_reason=None,
                payload=autonomous_research_runtime._runtime_stage_payload(
                    campaign_id=campaign.id,
                    task_type="security_invariant_generation",
                    source_snapshot_digest=source_snapshot_digest,
                    outcome="completed",
                ),
            )
            repository.save_agent_run(
                campaign_id=campaign.id,
                task_id=invariant_task.id,
                agent_type="invariant_agent",
                status="completed",
                input_refs=[f"campaign_task:{invariant_task.id}"],
                output_refs=[invariant_ref],
                tool_calls=[],
                safety_gate_state="allowed",
                stop_reason=None,
                payload={
                    "artifact_kind": "security_invariant_projection",
                    "projection_schema": "security_invariant_projection_v1",
                    "source_snapshot_digest": source_snapshot_digest,
                    "invariants": [],
                    "raw_payload_processed": False,
                    "execution_allowed": False,
                    "validation_allowed": False,
                    "candidate_promotion_allowed": False,
                    "report_submission_allowed": False,
                },
            )
        task = repository.create_campaign_task(
            campaign_id=campaign.id,
            task_type=task_type,
            agent_type="target_model_agent",
            title=title,
            input_refs=[
                f"campaign:{campaign.id}",
                f"source_snapshot:{source_snapshot_digest}",
            ],
            payload=autonomous_research_runtime._runtime_task_payload(
                campaign_id=campaign.id,
                task_type=task_type,
                source_snapshot_digest=source_snapshot_digest,
            ),
        )
        dispatched_run = repository.save_agent_run(
            campaign_id=campaign.id,
            task_id=task.id,
            agent_type=task.agent_type,
            status="dispatched",
            input_refs=[f"campaign_task:{task.id}"],
            output_refs=[],
            tool_calls=[],
            safety_gate_state="allowed",
            stop_reason=None,
            payload=autonomous_research_runtime.build_autonomous_research_agent_payload(
                source_snapshot_digest=source_snapshot_digest,
            ),
        )
        task = repository.mark_campaign_task_dispatched(
            task.id,
            execution_claim_id=dispatched_run.id,
        )
        assert task is not None
        task_id = task.id

        def fail_analysis(*_args, **_kwargs):
            raise RuntimeError("synthetic worker failure")

        monkeypatch.setattr(
            worker_tasks,
            failure_target,
            fail_analysis,
        )
        result = run_agent_task(task_id, repository=repository)

        failed_task = next(
            task
            for task in repository.list_campaign_tasks(campaign.id)
            if task.id == task_id
        )
        agent_runs = repository.list_campaign_agent_runs(campaign.id)
        task_agent_runs = [run for run in agent_runs if run.task_id == task_id]
        failure_stages = [
            stage
            for stage in repository.list_campaign_pipeline_stages(campaign.id)
            if stage.task_id == task_id and stage.status == "failed"
        ]

        assert result["status"] == "failed"
        assert result["stop_reason"] == "worker_failed"
        assert failed_task.status == "failed"
        assert len(task_agent_runs) == 1
        assert task_agent_runs[0].status == "failed"
        assert task_agent_runs[0].safety_gate_state == "blocked"
        assert task_agent_runs[0].stop_reason == "worker_failed"
        assert task_agent_runs[0].payload == (
            autonomous_research_runtime.build_autonomous_research_agent_payload(
                source_snapshot_digest=source_snapshot_digest,
            )
        )
        assert len(failure_stages) == 1
        assert failure_stages[0].stage_key == f"autonomous_research:{task_type}"
        assert failure_stages[0].safety_gate_state == "blocked"
        assert failure_stages[0].stop_reason == "worker_failed"
        assert failure_stages[0].payload["execution_allowed"] is False
        assert failure_stages[0].payload["validation_allowed"] is False
        assert failure_stages[0].payload["report_submission_allowed"] is False
        assert "synthetic worker failure" not in str(
            [failed_task, *agent_runs, *failure_stages]
        )
        assert repository.get_campaign(campaign.id).status == "awaiting_review"

        retry_dispatches = []
        retry = autonomous_research_runtime.retry_autonomous_research_task(
            campaign.id,
            task_id,
            repository=repository,
            dispatcher=lambda *, campaign_task_id: retry_dispatches.append(campaign_task_id),
        )

        assert retry["status"] == "dispatched"
        assert retry["campaign_task_id"] == task_id
        assert retry_dispatches == [task_id]
        assert repository.get_campaign(campaign.id).status == "running"
    finally:
        session.close()


def test_security_invariant_projection_rejects_unbounded_statement_text():
    source_snapshot_digest = "sha256:" + "a" * 64
    invariant_ref = "security_invariant:" + "b" * 64
    route_fact_ref = "codebase_fact:route_fact_1"
    payload = {
        "artifact_kind": "security_invariant_projection",
        "projection_schema": "security_invariant_projection_v1",
        "source_snapshot_digest": source_snapshot_digest,
        "invariants": [
            {
                "invariant_ref": invariant_ref,
                "family": "object_authorization_boundary",
                "statement": (
                    "Object-scoped routes must enforce ownership or role checks "
                    "before mapped sensitive work."
                ),
                "status": "needs_evidence",
                "route_fact_ref": route_fact_ref,
                "source_fact_refs": [route_fact_ref],
            }
        ],
        "raw_payload_processed": False,
        "execution_allowed": False,
        "validation_allowed": False,
        "candidate_promotion_allowed": False,
        "report_submission_allowed": False,
    }

    assert worker_tasks._safe_security_invariant_projection(
        payload,
        source_snapshot_digest=source_snapshot_digest,
    ) == payload["invariants"]

    payload["invariants"][0]["statement"] = "unbounded model text"
    assert (
        worker_tasks._safe_security_invariant_projection(
            payload,
            source_snapshot_digest=source_snapshot_digest,
        )
        is None
    )


def test_run_agent_task_reconciles_existing_dispatched_agent_run():
    repository, session = build_repository()
    try:
        campaign = repository.create_campaign(
            program_id="program_example",
            name="Worker reconcile campaign",
            autonomy_level="level_0_read_only",
            scope_status="in_scope",
            policy_text="Testing allowed",
            default_asset="api.example.com",
            created_by="operator",
        )
        repository.update_campaign_status(campaign.id, "running")
        task = repository.create_campaign_task(
            campaign_id=campaign.id,
            task_type="hypothesis_generation",
            agent_type="hypothesis_agent",
            title="Generate candidates",
            input_refs=[f"campaign:{campaign.id}"],
            payload={"raw": "Authorization: Bearer secret-token"},
        )
        dispatched_run = repository.save_agent_run(
            campaign_id=campaign.id,
            task_id=task.id,
            agent_type=task.agent_type,
            status="dispatched",
            input_refs=[f"campaign_task:{task.id}"],
            output_refs=[],
            tool_calls=[],
            safety_gate_state="allowed",
            stop_reason=None,
            payload={"dispatch_contract": "id_only"},
        )

        result = run_agent_task(task.id, repository=repository)

        agent_runs = repository.list_campaign_agent_runs(campaign.id)
        updated_task = repository.list_campaign_tasks(campaign.id)[0]
        pipeline_runs = [
            run
            for run in repository.list_pipeline_runs()
            if run.program_id == campaign.program_id and run.asset == campaign.default_asset
        ]
        assert result["status"] == "completed"
        assert result["agent_run_id"] == dispatched_run.id
        assert len(agent_runs) == 1
        assert len(pipeline_runs) == 1
        assert pipeline_runs[0].payload["hypotheses"][0]["hypothesis_id"] == (
            "campaign_worker_hypothesis_1"
        )
        assert agent_runs[0].id == dispatched_run.id
        assert agent_runs[0].status == "completed"
        assert any(ref.startswith("pipeline_run:") for ref in agent_runs[0].output_refs)
        assert updated_task.output_refs[0] == f"agent_run:{dispatched_run.id}"
        assert any(ref.startswith("pipeline_run:") for ref in updated_task.output_refs)
        assert "secret-token" not in str(agent_runs[0].payload)
    finally:
        session.close()


def test_run_agent_task_claims_work_before_a_concurrent_delivery_materializes_it(
    tmp_path,
    monkeypatch,
):
    engine = create_engine(
        f"sqlite+pysqlite:///{(tmp_path / 'worker-claim.db').as_posix()}",
        connect_args={"check_same_thread": False},
    )
    Base.metadata.create_all(bind=engine)
    session_factory = sessionmaker(bind=engine)
    with session_factory() as setup_session:
        seed_sample_data(setup_session)
        setup_repository = DatabaseRepository(setup_session)
        campaign = setup_repository.create_campaign(
            program_id="program_example",
            name="Concurrent worker claim campaign",
            autonomy_level="level_0_read_only",
            scope_status="in_scope",
            policy_text="Testing allowed",
            default_asset="api.example.com",
            created_by="operator",
        )
        campaign = setup_repository.update_campaign_status(campaign.id, "running")
        assert campaign is not None
        task = setup_repository.create_campaign_task(
            campaign_id=campaign.id,
            task_type="campaign_observation",
            agent_type="orchestrator_agent",
            title="Observe authorized campaign state",
        )
        campaign_id = campaign.id
        task_id = task.id
        task_record_type = type(task)

    first_materialization_started = Event()
    release_first_materialization = Event()
    materialization_calls: list[str] = []

    def hold_first_materialization(*, task, **_kwargs):
        materialization_calls.append(task.id)
        if len(materialization_calls) == 1:
            first_materialization_started.set()
            assert release_first_materialization.wait(timeout=5)
        return [], {"artifact_kind": "task_completion_marker"}

    monkeypatch.setattr(
        worker_tasks,
        "_materialize_read_only_artifacts",
        hold_first_materialization,
    )
    first_result: dict = {}

    def run_first_delivery():
        with session_factory() as first_session:
            first_result.update(
                run_agent_task(
                    task_id,
                    repository=DatabaseRepository(first_session),
                )
            )

    first_delivery = Thread(target=run_first_delivery)
    first_delivery.start()
    assert first_materialization_started.wait(timeout=5)
    try:
        with session_factory() as duplicate_session:
            duplicate_result = run_agent_task(
                task_id,
                repository=DatabaseRepository(duplicate_session),
            )
    finally:
        release_first_materialization.set()
    first_delivery.join(timeout=5)

    with session_factory() as verification_session:
        verification_repository = DatabaseRepository(verification_session)
        persisted_task = verification_session.get(task_record_type, task_id)
        agent_runs = verification_repository.list_campaign_agent_runs(campaign_id)

    assert not first_delivery.is_alive()
    assert first_result["status"] == "completed"
    assert duplicate_result == {
        "status": "running",
        "task_id": task_id,
        "stop_reason": "task_already_running",
    }
    assert materialization_calls == [task_id]
    assert persisted_task is not None
    assert persisted_task.status == "completed"
    assert len(agent_runs) == 1


def test_run_agent_task_extracts_authorized_codebase_facts_without_secret_payloads():
    repository, session = build_repository()
    try:
        campaign = repository.create_campaign(
            program_id="program_example",
            name="Static code map campaign",
            autonomy_level="level_0_read_only",
            scope_status="in_scope",
            policy_text="Testing allowed",
            default_asset="authorized/service",
            created_by="operator",
        )
        repository.update_campaign_status(campaign.id, "running")
        task = repository.create_campaign_task(
            campaign_id=campaign.id,
            task_type="attack_surface_mapping",
            agent_type="target_model_agent",
            title="Map authorized local code",
            input_refs=[f"campaign:{campaign.id}"],
            payload={
                "authorized_code_files": [
                    {
                        "path": "apps/api/routes/files.py",
                        "content": """
from fastapi import APIRouter, Depends
from pydantic import BaseModel

router = APIRouter()

class FileExport(BaseModel):
    file_id: str
    owner_id: str

@router.get("/files/{file_id}/export")
def export_file(file_id: str, current_user = Depends(require_user)):
    authorize_owner_or_admin(current_user, file_id)
    return send_file(file_id)
""",
                    }
                ],
                "authorization": "Bearer secret-token",
            },
        )

        result = run_agent_task(task.id, repository=repository)

        assert result["status"] == "completed"
        maps = repository.list_campaign_codebase_maps(campaign.id)
        facts = repository.list_campaign_codebase_facts(campaign.id)
        scanner_runs = repository.list_campaign_scanner_runs(campaign.id)

        assert len(maps) == 1
        assert maps[0].repository == "authorized/service"
        assert maps[0].route_count == 1
        assert maps[0].handler_count == 1
        assert maps[0].model_count == 1
        assert maps[0].authz_check_count == 1
        assert maps[0].sensitive_sink_count == 1
        assert maps[0].payload == {
            "file_count": 1,
            "mapping_mode": "static_code_snippet_analysis",
            "raw_payload_processed": False,
        }

        facts_by_type = {fact.fact_type: fact for fact in facts}
        assert set(facts_by_type) == {
            "authz_check",
            "data_model",
            "route_handler",
            "sensitive_sink",
        }
        assert facts_by_type["route_handler"].source_path == "apps/api/routes/files.py"
        assert facts_by_type["route_handler"].symbol_name == "export_file"
        assert facts_by_type["route_handler"].route_method == "GET"
        assert facts_by_type["route_handler"].route_path == "/files/{file_id}/export"
        assert facts_by_type["authz_check"].authz_hint == "owner_or_admin_check"
        assert facts_by_type["sensitive_sink"].symbol_name == "send_file"
        assert facts_by_type["data_model"].symbol_name == "FileExport"

        assert len(scanner_runs) == 1
        assert scanner_runs[0].tool_name == "mythos_static_code_mapper"
        assert scanner_runs[0].candidate_count == 4
        assert "secret-token" not in str(maps + facts + scanner_runs)
        assert "Bearer" not in str(maps + facts + scanner_runs)
    finally:
        session.close()


def test_run_agent_task_persists_static_django_urlconf_attack_surface():
    repository, session = build_repository()
    try:
        campaign = repository.create_campaign(
            program_id="program_example",
            name="Django static code map campaign",
            autonomy_level="level_0_read_only",
            scope_status="in_scope",
            policy_text="Testing allowed",
            default_asset="authorized/service",
            created_by="operator",
        )
        repository.update_campaign_status(campaign.id, "running")
        task = repository.create_campaign_task(
            campaign_id=campaign.id,
            task_type="attack_surface_mapping",
            agent_type="target_model_agent",
            title="Map authorized Django local code",
            input_refs=[f"campaign:{campaign.id}"],
            payload={
                "authorized_code_files": [
                    {
                        "path": "project/settings.py",
                        "content": 'ROOT_URLCONF = "project.urls"',
                    },
                    {
                        "path": "project/urls.py",
                        "content": """
from django.urls import include, path

urlpatterns = []
urlpatterns += [
    path("v1/", include(("api.urls", "api"), namespace="api")),
]
""",
                    },
                    {
                        "path": "api/urls.py",
                        "content": """
from django.urls import path
from .views import export_file

urlpatterns = [
    path("exports/<uuid:file_id>/", export_file),
]
""",
                    },
                    {
                        "path": "api/views.py",
                        "content": """
def export_file(file_id: str):
    return send_file(file_id)
""",
                    },
                ]
            },
        )

        result = run_agent_task(task.id, repository=repository)

        assert result["status"] == "completed"
        maps = repository.list_campaign_codebase_maps(campaign.id)
        facts = repository.list_campaign_codebase_facts(campaign.id)
        route = next(
            fact
            for fact in facts
            if fact.fact_type == "route_handler"
            and fact.source_path == "api/views.py"
        )
        gap = next(
            fact
            for fact in facts
            if fact.fact_type == "authorization_gap_candidate"
            and fact.source_path == "api/views.py"
        )

        assert len(maps) == 1
        assert maps[0].route_count == 1
        assert (route.route_method, route.route_path) == (
            "ANY",
            "/v1/exports/<uuid:file_id>/",
        )
        assert route.symbol_name == "export_file"
        assert gap.route_path == "/v1/exports/<uuid:file_id>/"
        assert gap.payload["root_cause"] == "missing_object_ownership_check"
    finally:
        session.close()


def test_run_agent_task_materializes_safe_runtime_campaign_observation_projection(
    monkeypatch,
):
    repository, session = build_repository()
    try:
        source_snapshot_digest = "sha256:" + "b" * 64
        campaign = repository.create_campaign(
            program_id="program_example",
            name="Runtime observation campaign",
            autonomy_level="level_0_read_only",
            scope_status="in_scope",
            policy_text="Testing allowed",
            default_asset="authorized/service",
            created_by="operator",
            payload={
                "scope_guard_rule": {
                    "asset": "authorized/service",
                    "scope_status": "in_scope",
                    "automation": "none",
                    "allowed_validation": [],
                    "forbidden": [],
                    "human_approval_required": True,
                },
                "source_snapshot_digest": source_snapshot_digest,
                "execution_allowed": False,
                "dispatch_allowed": False,
                "validation_allowed": False,
                "candidate_promotion_allowed": False,
                "report_submission_allowed": False,
                "raw_payload_processed": False,
            },
        )
        repository.update_campaign_status(campaign.id, "running")
        task = repository.create_campaign_task(
            campaign_id=campaign.id,
            task_type="campaign_observation",
            agent_type="orchestrator_agent",
            title="Observe authorized campaign state",
            input_refs=[
                f"campaign:{campaign.id}",
                f"source_snapshot:{source_snapshot_digest}",
            ],
            payload=autonomous_research_runtime._runtime_task_payload(
                campaign_id=campaign.id,
                task_type="campaign_observation",
                source_snapshot_digest=source_snapshot_digest,
            ),
        )
        raw_marker = "runtime-observation-raw-token"
        monkeypatch.setattr(
            worker_tasks,
            "_runtime_workspace_inputs",
            lambda **_kwargs: (
                {
                    "source_manifest": [
                        {
                            "source_path": "routes/records.py",
                            "content_digest": "sha256:" + "c" * 64,
                        }
                    ],
                    "code_files": [
                        {
                            "path": "auth/routes.py",
                            "content": f'''
from fastapi import APIRouter

router = APIRouter()

@router.get("/records/{{record_id}}")
def read_record(record_id: str):
    return "{raw_marker}"
''',
                        }
                    ],
                    "api_artifacts": [
                        {
                            "kind": "openapi",
                            "payload": {"token": raw_marker},
                        },
                        {"kind": "har", "payload": {"cookie": raw_marker}},
                    ],
                    "advisory_artifacts": [
                        {"kind": "sarif", "payload": {"secret": raw_marker}}
                    ],
                },
                None,
            ),
        )

        result = run_agent_task(task.id, repository=repository)

        assert result["status"] == "completed"
        persisted_task = repository.session.get(type(task), task.id)
        agent_run = repository.list_campaign_agent_runs(campaign.id)[0]
        completed_stages = [
            stage
            for stage in repository.list_campaign_pipeline_stages(campaign.id)
            if stage.stage_key == "autonomous_research:campaign_observation"
            and stage.status == "completed"
        ]
        projection_ref = f"campaign_observation_projection:{task.id}"

        assert persisted_task is not None
        assert projection_ref in persisted_task.output_refs
        assert agent_run.output_refs == [projection_ref]
        assert len(completed_stages) == 1
        assert projection_ref in completed_stages[0].output_refs
        assert agent_run.payload["artifact_kind"] == "campaign_observation_projection"
        assert agent_run.payload["projection_schema"] == (
            "campaign_observation_projection_v1"
        )
        assert agent_run.payload["source_snapshot_digest"] == source_snapshot_digest
        assert agent_run.payload["workspace_loaded"] is True
        assert agent_run.payload["source_manifest_count"] == 1
        assert agent_run.payload["authorized_code_file_count"] == 1
        assert agent_run.payload["authorized_api_artifact_count"] == 2
        assert agent_run.payload["authorized_advisory_artifact_count"] == 1
        intake = agent_run.payload["target_intake"]
        assert intake["projection_schema"] == "runtime_target_intake_projection_v1"
        assert intake["languages"] == ["Python"]
        assert intake["frameworks"] == ["FastAPI"]
        assert intake["source_files_scanned"] == 1
        assert intake["entrypoint_count"] >= 1
        assert intake["auth_component_count"] == 1
        assert "entrypoints" not in intake
        assert "auth_components" not in intake
        assert "package_root" not in intake
        assert intake["execution_allowed"] is False
        assert intake["validation_allowed"] is False
        assert intake["report_submission_allowed"] is False
        assert agent_run.payload["execution_allowed"] is False
        assert agent_run.payload["dispatch_allowed"] is False
        assert agent_run.payload["validation_allowed"] is False
        assert agent_run.payload["candidate_promotion_allowed"] is False
        assert agent_run.payload["report_submission_allowed"] is False
        assert raw_marker not in str(agent_run.payload)
        assert raw_marker not in str(persisted_task.output_refs)
    finally:
        session.close()


def test_runtime_evidence_resume_attaches_candidate_hunter_projection(monkeypatch):
    repository, session = build_repository()
    try:
        source_snapshot_digest = "sha256:" + "d" * 64
        campaign = repository.create_campaign(
            program_id="program_example",
            name="Runtime evidence resume projection campaign",
            autonomy_level="level_0_read_only",
            scope_status="in_scope",
            policy_text="Authorized local review only.",
            default_asset="authorized/service",
            created_by="operator",
            payload={
                "scope_guard_rule": {
                    "asset": "authorized/service",
                    "scope_status": "in_scope",
                    "automation": "none",
                    "allowed_validation": [],
                    "forbidden": [],
                    "human_approval_required": True,
                },
                "source_snapshot_digest": source_snapshot_digest,
                "execution_allowed": False,
                "dispatch_allowed": False,
                "validation_allowed": False,
                "candidate_promotion_allowed": False,
                "report_submission_allowed": False,
                "raw_payload_processed": False,
            },
        )
        campaign = repository.update_campaign_status(campaign.id, "running")
        assert campaign is not None
        pipeline_run = repository.save_pipeline_run(
            program_id=campaign.program_id,
            asset=campaign.default_asset,
            policy_text=campaign.policy_text_hash,
            policy_text_is_hash=True,
            scope_status="in_scope",
            hypothesis_count=1,
            blocked_count=0,
            report_title=None,
            payload={"campaign_id": campaign.id},
        )
        owner_task = repository.create_campaign_task(
            campaign_id=campaign.id,
            task_type="candidate_refutation",
            agent_type="candidate_hunter_agent",
            title="Refute candidate hypotheses from persisted evidence",
            input_refs=[f"pipeline_run:{pipeline_run.id}"],
            payload=autonomous_research_runtime._runtime_task_payload(
                campaign_id=campaign.id,
                task_type="candidate_refutation",
                source_snapshot_digest=source_snapshot_digest,
                pipeline_run_id=pipeline_run.id,
            ),
        )
        owner_task = repository.update_campaign_task_status(
            owner_task.id,
            "completed",
            output_refs=[f"pipeline_run:{pipeline_run.id}"],
        )
        assert owner_task is not None
        owner_run = repository.save_agent_run(
            campaign_id=campaign.id,
            task_id=owner_task.id,
            agent_type=owner_task.agent_type,
            status="completed",
            input_refs=[f"campaign_task:{owner_task.id}"],
            output_refs=[f"pipeline_run:{pipeline_run.id}"],
            tool_calls=[],
            safety_gate_state="allowed",
            stop_reason=None,
            payload={"raw_payload_processed": False},
        )
        evidence_task = repository.create_campaign_task(
            campaign_id=campaign.id,
            task_type="candidate_hunter_evidence_inspection",
            agent_type="candidate_hunter_evidence_specialist",
            title="Inspect authorized local evidence",
            input_refs=[f"pipeline_run:{pipeline_run.id}"],
            payload={
                "owner_task_id": owner_task.id,
                "pipeline_run_id": pipeline_run.id,
            },
        )
        candidate_hunter_projection = {
            "projection_schema": "runtime_candidate_hunter_projection_v1",
            "pipeline_run_id": pipeline_run.id,
            "source_snapshot_digest": source_snapshot_digest,
            "candidate_hunter_task_id": owner_task.id,
            "candidate_hunter_state_digest": "e" * 64,
            "candidate_hunter_stage_refs": ["pipeline_stage:stage-1"],
            "final_candidate_count": 0,
            "final_candidates_digest": "f" * 64,
            "candidate_decision_count": 1,
            "candidate_decisions_digest": "a" * 64,
            "raw_payload_processed": False,
            "execution_allowed": False,
            "dispatch_allowed": False,
            "validation_allowed": False,
            "candidate_promotion_allowed": False,
            "report_submission_allowed": False,
        }
        monkeypatch.setattr(
            worker_tasks,
            "_load_runtime_candidate_hunter_output_projection",
            lambda **_kwargs: (candidate_hunter_projection, {}, None),
        )

        worker_tasks._record_runtime_evidence_resume(
            evidence_task=evidence_task,
            resumed={"status": "completed"},
            repository=repository,
        )

        persisted_owner = repository.session.get(type(owner_task), owner_task.id)
        persisted_run = repository.session.get(type(owner_run), owner_run.id)
        projection_ref = f"candidate_hunter_projection:{owner_task.id}"
        runtime_stages = [
            stage
            for stage in repository.list_campaign_pipeline_stages(campaign.id)
            if stage.task_id == owner_task.id
            and stage.stage_key == "autonomous_research:candidate_refutation"
            and stage.status == "completed"
        ]

        assert persisted_owner is not None
        assert projection_ref in persisted_owner.output_refs
        assert persisted_run is not None
        assert persisted_run.output_refs == [
            f"pipeline_run:{pipeline_run.id}",
            "pipeline_stage:stage-1",
            projection_ref,
        ]
        assert persisted_run.payload["candidate_hunter_projection"] == (
            candidate_hunter_projection
        )
        assert len(runtime_stages) == 1
        assert projection_ref in runtime_stages[0].output_refs
    finally:
        session.close()


def test_run_agent_task_maps_authorized_api_and_har_artifacts_into_route_facts():
    repository, session = build_repository()
    try:
        campaign = repository.create_campaign(
            program_id="program_example",
            name="API artifact map campaign",
            autonomy_level="level_0_read_only",
            scope_status="in_scope",
            policy_text="Testing allowed",
            default_asset="authorized/service",
            created_by="operator",
        )
        repository.update_campaign_status(campaign.id, "running")
        task = repository.create_campaign_task(
            campaign_id=campaign.id,
            task_type="attack_surface_mapping",
            agent_type="target_model_agent",
            title="Map authorized API and HAR",
            input_refs=[f"campaign:{campaign.id}"],
            payload={
                "authorized_api_artifacts": [
                    {
                        "kind": "openapi",
                        "source_name": "openapi.json",
                        "payload": {
                            "paths": {
                                "/files/{file_id}/export": {
                                    "parameters": [
                                        {
                                            "name": "file_id",
                                            "in": "path",
                                            "required": True,
                                        },
                                        {
                                            "name": "Authorization",
                                            "in": "header",
                                        },
                                    ],
                                    "get": {
                                        "operationId": "exportFile",
                                        "security": [{"bearerAuth": []}],
                                        "parameters": [
                                            {"name": "download", "in": "query"},
                                            {"name": "session_token", "in": "query"},
                                        ],
                                        "requestBody": {
                                            "content": {
                                                "application/json": {
                                                    "schema": {
                                                        "type": "object",
                                                        "properties": {
                                                            "format": {"type": "string"},
                                                            "password": {"type": "string"},
                                                        },
                                                    }
                                                }
                                            }
                                        },
                                    }
                                }
                            }
                        },
                    },
                    {
                        "kind": "har",
                        "source_name": "capture.har",
                        "payload": {
                            "log": {
                                "entries": [
                                    {
                                        "request": {
                                            "method": "GET",
                                            "url": "https://authorized.example/files/123/export?token=secret-token",
                                        }
                                    }
                                ]
                            }
                        },
                    },
                ],
                "authorization": "Bearer secret-token",
            },
        )

        result = run_agent_task(task.id, repository=repository)

        assert result["status"] == "completed"
        maps = repository.list_campaign_codebase_maps(campaign.id)
        facts = repository.list_campaign_codebase_facts(campaign.id)
        route_facts = [fact for fact in facts if fact.fact_type == "route_handler"]

        assert len(maps) == 1
        assert maps[0].route_count == 2
        assert maps[0].payload["mapping_mode"] == "authorized_attack_surface_analysis"
        assert maps[0].payload["api_artifact_route_count"] == 2
        assert {fact.source_path for fact in route_facts} == {
            "capture.har",
            "openapi.json",
        }
        assert {
            (fact.route_method, fact.route_path, fact.symbol_name)
            for fact in route_facts
        } == {
            ("GET", "/[REDACTED]", "har_get_[REDACTED]"),
            ("GET", "/files/{file_id}/export", "exportFile"),
        }
        assert all(
            fact.payload["mapping_mode"] == "authorized_api_artifact"
            for fact in route_facts
        )
        assert "secret-token" not in str(maps + facts)
        assert "Bearer" not in str(maps + facts)
    finally:
        session.close()


def test_run_agent_task_maps_sarif_as_advisory_route_evidence_without_raw_output():
    repository, session = build_repository()
    try:
        campaign = repository.create_campaign(
            program_id="program_example",
            name="SARIF advisory map campaign",
            autonomy_level="level_0_read_only",
            scope_status="in_scope",
            policy_text="Testing allowed",
            default_asset="authorized/service",
            created_by="operator",
        )
        repository.update_campaign_status(campaign.id, "running")
        raw_marker = "sarif-body-marker"
        map_task = repository.create_campaign_task(
            campaign_id=campaign.id,
            task_type="attack_surface_mapping",
            agent_type="target_model_agent",
            title="Map authorized SARIF route evidence",
            input_refs=[f"campaign:{campaign.id}"],
            payload={
                "authorized_code_files": [
                    {
                        "path": "apps/api/routes/files.py",
                        "content": '''
from fastapi import APIRouter

router = APIRouter()

@router.get("/files/{file_id}/export")
def export_file(file_id: str):
    return send_file(file_id)
''',
                    }
                ],
                "authorized_api_artifacts": [
                    {
                        "kind": "openapi",
                        "source_name": "openapi.json",
                        "payload": {
                            "paths": {
                                "/files/{file_id}/export": {
                                    "get": {"operationId": "exportFile"}
                                }
                            }
                        },
                    }
                ],
                "authorized_advisory_artifacts": [
                    {
                        "kind": "sarif",
                        "source_name": "sarif/scanner.sarif",
                        "payload": {
                            "runs": [
                                {
                                    "results": [
                                        {
                                            "ruleId": "local-route-review",
                                            "message": {
                                                "text": (
                                                    "GET /files/{file_id}/export "
                                                    + raw_marker
                                                )
                                            },
                                        }
                                    ]
                                }
                            ]
                        },
                    }
                ],
            },
        )
        hypothesis_task = repository.create_campaign_task(
            campaign_id=campaign.id,
            task_type="hypothesis_generation",
            agent_type="hypothesis_agent",
            title="Generate SARIF-supported hypotheses",
            input_refs=[f"campaign:{campaign.id}"],
            payload={},
        )

        assert run_agent_task(map_task.id, repository=repository)["status"] == "completed"
        assert run_agent_task(hypothesis_task.id, repository=repository)["status"] == "completed"

        facts = repository.list_campaign_codebase_facts(campaign.id)
        sarif_fact = next(
            fact
            for fact in facts
            if fact.fact_type == "route_handler"
            and fact.payload.get("artifact_kind") == "sarif"
        )
        pipeline_run = repository.list_pipeline_runs_for_program("program_example")[0]
        hypothesis = pipeline_run.payload["hypotheses"][0]

        assert sarif_fact.source_path == "sarif/scanner.sarif"
        assert sarif_fact.route_method == "GET"
        assert sarif_fact.route_path == "/files/{file_id}/export"
        assert sarif_fact.payload == {
            "artifact_kind": "sarif",
            "mapping_mode": "authorized_advisory_artifact",
            "advisory_only": True,
            "raw_payload_processed": False,
        }
        assert [
            fact["artifact_kind"]
            for fact in hypothesis["source_facts"]
            if fact["fact_type"] == "route_handler"
        ] == ["code", "api", "sarif"]
        assert "evidence_satisfied:independent_static_signal" in hypothesis[
            "hunter_assessment"
        ]["reasons"]
        assert pipeline_run.payload["hypothesis_assessments"][0]["validation_plan"][
            "human_approval_required"
        ] is True
        assert raw_marker not in str(
            [fact.payload for fact in facts] + [pipeline_run.payload]
        )
    finally:
        session.close()


@pytest.mark.parametrize(
    (
        "source_path",
        "source_code",
        "expected_vuln_type",
        "expected_validation_mode",
        "expected_evidence",
        "expected_invariant_family",
    ),
    (
        (
            "apps/api/routes/webhooks.ts",
            """
import { Router } from "express";

const router = Router();

router.post("/webhooks/deliver", deliver_webhook);

async function deliver_webhook(req: Request, res: Response) {
  return fetch(req.body.subscriberUrl);
}
""",
            "ssrf",
            "offline_ssrf_target_policy_review",
            "local_egress_validation_trace",
            "ssrf_egress_boundary",
        ),
        (
            "apps/api/routes/media.ts",
            """
import { Router } from "express";

const router = Router();

router.get("/media/:filepath", serve_media);

async function serve_media(req: Request, res: Response) {
  return get_blob(req.params.filepath);
}
""",
            "path_traversal",
            "offline_path_canonicalization_review",
            "local_path_validation_trace",
            "path_traversal_boundary",
        ),
        (
            "apps/api/routes/users.ts",
            """
import { Router } from "express";

const router = Router();

router.put("/users/:id", update_self_user);

async function update_self_user(req: Request, res: Response) {
  return update_user(req.params.id, req.body);
}
""",
            "mass_assignment",
            "offline_field_allowlist_review",
            "local_field_allowlist_trace",
            "mass_assignment_boundary",
        ),
        (
            "apps/api/routes/search.ts",
            """
import { Router } from "express";

const router = Router();

router.get("/campaigns/search", search_campaigns);

async function search_campaigns(req: Request, res: Response) {
  return run_sql(req.query.q);
}
""",
            "injection",
            "offline_query_parameterization_review",
            "local_query_parameterization_trace",
            "injection_query_boundary",
        ),
        (
            "apps/api/routes/maintenance.ts",
            """
import { Router } from "express";

const router = Router();

router.post("/maintenance/run", run_maintenance);

async function run_maintenance(req: Request, res: Response) {
  return exec(req.body.command);
}
""",
            "command_injection",
            "offline_command_execution_boundary_review",
            "local_command_validation_trace",
            "command_execution_boundary",
        ),
        (
            "apps/api/routes/imports.py",
            """
import pickle

from fastapi import APIRouter

router = APIRouter()

@router.post("/imports/profile")
def import_profile(serialized_payload: bytes):
    return pickle.loads(serialized_payload)
""",
            "unsafe_deserialization",
            "offline_deserialization_policy_review",
            "local_deserialization_trace",
            "unsafe_deserialization_boundary",
        ),
        (
            "apps/api/routes/yaml_imports.py",
            """
import yaml as config_yaml

from fastapi import APIRouter

router = APIRouter()

@router.post("/imports/yaml-profile")
def import_yaml_profile(serialized_payload: bytes):
    return config_yaml.load(serialized_payload)
""",
            "unsafe_deserialization",
            "offline_deserialization_policy_review",
            "local_deserialization_trace",
            "unsafe_deserialization_boundary",
        ),
        (
            "apps/api/routes/uploads.py",
            """
from fastapi import APIRouter, UploadFile

router = APIRouter()

@router.post("/uploads")
def upload_document(document: UploadFile):
    return save_upload(document)
""",
            "file_upload",
            "offline_file_upload_policy_review",
            "local_upload_validation_trace",
            "file_upload_boundary",
        ),
        (
            "apps/api/routes/payments.py",
            """
from fastapi import APIRouter

router = APIRouter()

@router.post("/payments/transfers")
def create_transfer(order_id: str, recipient_id: str, amount: int):
    return transfer_funds(recipient_id, amount)
""",
            "business_logic",
            "offline_server_amount_policy_review",
            "local_money_flow_trace",
            "server_authoritative_money_flow",
        ),
        (
            "apps/api/routes/redemptions.py",
            """
from fastapi import APIRouter

router = APIRouter()

@router.post("/redemptions/{token_id}")
def redeem_token(token_id: str):
    return consume_one_time_token(token_id)
""",
            "race_condition",
            "offline_transactional_state_review",
            "local_state_transition_trace",
            "state_transition_consistency",
        ),
        (
            "apps/api/routes/agents.py",
            """
from fastapi import APIRouter

router = APIRouter()

@router.post("/agents/{agent_id}/tools/execute")
def run_agent_tool(agent_id: str, tool_name: str):
    return execute_agent_tool(agent_id, tool_name)
""",
            "agent_tool_authz_gap",
            "offline_agent_tool_policy_review",
            "local_agent_tool_policy_trace",
            "agent_tool_authorization_boundary",
        ),
    ),
)
def test_run_agent_task_classifies_static_gap_families_without_live_validation(
    source_path,
    source_code,
    expected_vuln_type,
    expected_validation_mode,
    expected_evidence,
    expected_invariant_family,
):
    repository, session = build_repository()
    try:
        campaign = repository.create_campaign(
            program_id="program_example",
            name=f"{expected_vuln_type} static gap hypothesis campaign",
            autonomy_level="level_0_read_only",
            scope_status="in_scope",
            policy_text="Testing allowed",
            default_asset="authorized/service",
            created_by="operator",
        )
        repository.update_campaign_status(campaign.id, "running")
        map_task = repository.create_campaign_task(
            campaign_id=campaign.id,
            task_type="attack_surface_mapping",
            agent_type="target_model_agent",
            title="Map authorized local code",
            input_refs=[f"campaign:{campaign.id}"],
            payload={
                "authorized_code_files": [
                    {"path": source_path, "content": source_code}
                ],
            },
        )
        hypothesis_task = repository.create_campaign_task(
            campaign_id=campaign.id,
            task_type="hypothesis_generation",
            agent_type="hypothesis_agent",
            title="Generate code-backed hypotheses",
            input_refs=[f"campaign:{campaign.id}"],
            payload={},
        )

        assert run_agent_task(map_task.id, repository=repository)["status"] == "completed"
        facts = repository.list_campaign_codebase_facts(campaign.id)
        route = worker_tasks._worker_candidate_routes(facts)[0]
        static_gap = worker_tasks._related_fact(
            facts,
            route,
            "authorization_gap_candidate",
        )
        invariant = worker_tasks._build_security_invariant_projection(facts)[0]
        matching_hypothesis = worker_tasks._codebase_route_hypothesis(
            codebase_facts=facts,
            route=route,
            index=1,
            security_invariant=invariant,
        )["hypothesis"]
        mismatched_hypothesis = worker_tasks._codebase_route_hypothesis(
            codebase_facts=facts,
            route=route,
            index=1,
            security_invariant={
                **invariant,
                "family": "route_authorization_boundary",
                "statement": worker_tasks._SECURITY_INVARIANT_FAMILIES[
                    "route_authorization_boundary"
                ],
            },
        )["hypothesis"]

        assert static_gap is not None
        assert worker_tasks._worker_static_gap_profile(static_gap)[
            "security_invariant_family"
        ] == expected_invariant_family
        assert invariant["family"] == expected_invariant_family
        assert invariant["statement"] == worker_tasks._SECURITY_INVARIANT_FAMILIES[
            expected_invariant_family
        ]
        assert matching_hypothesis["security_invariant_ref"] == invariant["invariant_ref"]
        assert matching_hypothesis["security_invariant_status"] == "needs_refutation"
        assert (
            matching_hypothesis["broken_invariant"]
            == worker_tasks._SECURITY_INVARIANT_FAMILIES[expected_invariant_family]
        )
        assert "security_invariant_ref" not in mismatched_hypothesis
        assert "security_invariant_status" not in mismatched_hypothesis
        assert (
            run_agent_task(hypothesis_task.id, repository=repository)["status"]
            == "completed"
        )

        payload = repository.list_pipeline_runs_for_program("program_example")[0].payload
        hypothesis = payload["hypotheses"][0]
        assessment = payload["hypothesis_assessments"][0]

        assert hypothesis["vuln_type"] == expected_vuln_type
        assert hypothesis["validation_mode"] == expected_validation_mode
        assert expected_evidence in hypothesis["evidence_needed"]
        assert hypothesis["safe_validation_plan"] == assessment["validation_plan"]["steps"]
        assert hypothesis["refutation_questions"] == assessment["refutation"]["questions"]
        assert hypothesis["impact_rationale"] == assessment["exploit_chain"]["impact"]
        assert hypothesis["impact_score"] == assessment["hunter_assessment"]["impact_score"]
        assert assessment["validation_plan"]["methods"] == [
            "manual_review",
            expected_validation_mode,
        ]
        assert assessment["validation_plan"]["human_approval_required"] is True
        assert assessment["exploit_chain"]["safety_notes"] == [
            "non_executable_chain_summary",
            "no_payloads_or_requests",
            "human_review_required",
        ]
        assert "fetch(" not in str(payload)
        assert "run_sql(" not in str(payload)
        assert "exec(" not in str(payload)
        assert "pickle.loads(" not in str(payload)
        assert "save_upload(" not in str(payload)
        assert "transfer_funds(" not in str(payload)
        assert "consume_one_time_token(" not in str(payload)
        assert "execute_agent_tool(" not in str(payload)
    finally:
        session.close()


def test_run_agent_task_generates_hypothesis_from_codebase_facts():
    repository, session = build_repository()
    try:
        campaign = repository.create_campaign(
            program_id="program_example",
            name="Code fact hypothesis campaign",
            autonomy_level="level_0_read_only",
            scope_status="in_scope",
            policy_text="Testing allowed",
            default_asset="authorized/service",
            target_classes=["idor"],
            created_by="operator",
        )
        repository.update_campaign_status(campaign.id, "running")
        map_task = repository.create_campaign_task(
            campaign_id=campaign.id,
            task_type="attack_surface_mapping",
            agent_type="target_model_agent",
            title="Map authorized local code",
            input_refs=[f"campaign:{campaign.id}"],
            payload={
                "authorized_code_files": [
                    {
                        "path": "apps/api/routes/files.py",
                        "content": """
from fastapi import APIRouter

router = APIRouter()

@router.get("/files/{file_id}/export")
def export_file(file_id: str):
    authorize_owner_or_admin(file_id)
    return send_file(file_id)
""",
                    }
                ],
            },
        )
        hypothesis_task = repository.create_campaign_task(
            campaign_id=campaign.id,
            task_type="hypothesis_generation",
            agent_type="hypothesis_agent",
            title="Generate code-backed hypotheses",
            input_refs=[f"campaign:{campaign.id}"],
            payload={"authorization": "Bearer secret-token"},
        )

        map_result = run_agent_task(map_task.id, repository=repository)
        result = run_agent_task(hypothesis_task.id, repository=repository)

        pipeline_runs = [
            run
            for run in repository.list_pipeline_runs()
            if run.program_id == campaign.program_id and run.asset == campaign.default_asset
        ]
        assert map_result["status"] == "completed"
        assert result["status"] == "completed"
        assert len(pipeline_runs) == 1

        facts = repository.list_campaign_codebase_facts(campaign.id)
        route_fact_ref = _persisted_codebase_fact_ref(
            facts,
            fact_type="route_handler",
            source_path="apps/api/routes/files.py",
            route_path="/files/{file_id}/export",
        )
        authz_fact_ref = _persisted_codebase_fact_ref(
            facts,
            fact_type="authz_check",
            source_path="apps/api/routes/files.py",
            symbol_name="authorize_owner_or_admin",
        )
        sink_fact_ref = _persisted_codebase_fact_ref(
            facts,
            fact_type="sensitive_sink",
            source_path="apps/api/routes/files.py",
            symbol_name="send_file",
        )
        payload = pipeline_runs[0].payload
        hypothesis = payload["hypotheses"][0]
        assessment = payload["hypothesis_assessments"][0]

        assert pipeline_runs[0].hypothesis_count == 1
        assert hypothesis["hypothesis_id"] == "codebase_fact_hypothesis_1"
        assert hypothesis["hypothesis"] == (
            "Review GET /files/{file_id}/export for object authorization boundary drift."
        )
        assert hypothesis["source_facts"] == [
            {
                "fact_ref": route_fact_ref,
                "artifact_kind": "code",
                "fact_type": "route_handler",
                "route_method": "GET",
                "route_path": "/files/{file_id}/export",
                "source_path": "apps/api/routes/files.py",
                "symbol_name": "export_file",
            },
            {
                "fact_ref": authz_fact_ref,
                "artifact_kind": "code",
                "authz_hint": "owner_or_admin_check",
                "fact_type": "authz_check",
                "source_path": "apps/api/routes/files.py",
                "symbol_name": "authorize_owner_or_admin",
            },
            {
                "fact_ref": sink_fact_ref,
                "artifact_kind": "code",
                "fact_type": "sensitive_sink",
                "source_path": "apps/api/routes/files.py",
                "symbol_name": "send_file",
            },
        ]
        assert payload["target_model"] == {
            "objects": ["file"],
            "roles": ["user", "owner"],
            "sensitive_actions": ["GET /files/{file_id}/export"],
            "source_fact_refs": [
                route_fact_ref,
                authz_fact_ref,
                sink_fact_ref,
            ],
        }
        assert assessment["candidate_id"] == "codebase_fact_hypothesis_1"
        assert assessment["candidate_status"] == "needs_human_review"
        assert assessment["refutation"]["reasons"] == ["codebase_fact_candidate_not_validated"]
        assert assessment["exploit_chain"]["primitives"] == [
            "GET /files/{file_id}/export",
            "owner_or_admin_check",
            "send_file",
        ]
        assert assessment["validation_plan"]["human_approval_required"] is True
        assert "secret-token" not in str(payload)
        assert "Bearer" not in str(payload)
    finally:
        session.close()


def test_run_agent_task_preserves_same_route_code_paths_with_traceable_fact_refs():
    repository, session = build_repository()
    try:
        campaign = repository.create_campaign(
            program_id="program_example",
            name="Same route code path hypothesis campaign",
            autonomy_level="level_0_read_only",
            scope_status="in_scope",
            policy_text="Testing allowed",
            default_asset="authorized/service",
            target_classes=["idor"],
            created_by="operator",
        )
        repository.update_campaign_status(campaign.id, "running")
        map_task = repository.create_campaign_task(
            campaign_id=campaign.id,
            task_type="attack_surface_mapping",
            agent_type="target_model_agent",
            title="Map same-route authorized local code and artifacts",
            input_refs=[f"campaign:{campaign.id}"],
            payload={
                "authorized_code_files": [
                    {
                        "path": "apps/api/routes/export_primary.py",
                        "content": """
from fastapi import APIRouter

router = APIRouter()

@router.get("/files/{file_id}/export")
def export_file(file_id: str):
    authorize_owner_or_admin(file_id)
    return send_file(file_id)
""",
                    },
                    {
                        "path": "apps/api/routes/export_replica.py",
                        "content": """
from fastapi import APIRouter

router = APIRouter()

@router.get("/files/{file_id}/export")
def export_file(file_id: str):
    return send_file(file_id)
""",
                    },
                ],
                "authorized_api_artifacts": [
                    {
                        "kind": "openapi",
                        "source_name": "openapi.json",
                        "payload": {
                            "paths": {
                                "/files/{file_id}/export": {
                                    "get": {"operationId": "exportFile"}
                                }
                            }
                        },
                    },
                    {
                        "kind": "har",
                        "source_name": "traffic.har",
                        "payload": {
                            "log": {
                                "entries": [
                                    {
                                        "request": {
                                            "method": "GET",
                                            "url": (
                                                "https://authorized.example/"
                                                "files/123/export"
                                            ),
                                        }
                                    }
                                ]
                            }
                        },
                    },
                ],
            },
        )
        hypothesis_task = repository.create_campaign_task(
            campaign_id=campaign.id,
            task_type="hypothesis_generation",
            agent_type="hypothesis_agent",
            title="Generate same-route code-backed hypotheses",
            input_refs=[f"campaign:{campaign.id}"],
            payload={},
        )

        assert run_agent_task(map_task.id, repository=repository)["status"] == "completed"
        assert (
            run_agent_task(hypothesis_task.id, repository=repository)["status"]
            == "completed"
        )

        facts = repository.list_campaign_codebase_facts(campaign.id)
        code_route_facts = {
            fact.source_path: fact
            for fact in facts
            if fact.fact_type == "route_handler"
            and worker_tasks._route_artifact_kind(fact) == "code"
        }
        api_route_fact = next(
            fact
            for fact in facts
            if fact.fact_type == "route_handler"
            and worker_tasks._route_artifact_kind(fact) == "api"
        )
        har_route_fact = next(
            fact
            for fact in facts
            if fact.fact_type == "route_handler"
            and worker_tasks._route_artifact_kind(fact) == "har"
        )
        payload = repository.list_pipeline_runs_for_program("program_example")[0].payload

        assert set(code_route_facts) == {
            "apps/api/routes/export_primary.py",
            "apps/api/routes/export_replica.py",
        }
        assert payload["target_model"]["sensitive_actions"] == [
            "GET /files/{file_id}/export",
        ]
        assert len(payload["hypotheses"]) == 2
        assert len(payload["autonomous_hunt_queue"]) == 2
        assert all(
            item["status"] != "awaiting_deduplication_review"
            for item in payload["autonomous_hunt_queue"]
        )

        hypotheses_by_source_path = {}
        for hypothesis in payload["hypotheses"]:
            route_source_facts = [
                fact
                for fact in hypothesis["source_facts"]
                if fact["fact_type"] == "route_handler"
            ]
            code_source_facts = [
                fact
                for fact in route_source_facts
                if fact["artifact_kind"] == "code"
            ]
            assert len(code_source_facts) == 1
            code_source_fact = code_source_facts[0]
            source_path = code_source_fact["source_path"]
            hypotheses_by_source_path[source_path] = hypothesis
            assert code_source_fact["fact_ref"] == (
                f"codebase_fact:{code_route_facts[source_path].id}"
            )
            assert [
                (fact["artifact_kind"], fact["fact_ref"])
                for fact in route_source_facts
                if fact["artifact_kind"] != "code"
            ] == [
                ("api", f"codebase_fact:{api_route_fact.id}"),
                ("har", f"codebase_fact:{har_route_fact.id}"),
            ]

        assert set(hypotheses_by_source_path) == set(code_route_facts)
        assert "authz_check" in {
            fact["fact_type"]
            for fact in hypotheses_by_source_path[
                "apps/api/routes/export_primary.py"
            ]["source_facts"]
        }
        assert "authz_check" not in {
            fact["fact_type"]
            for fact in hypotheses_by_source_path[
                "apps/api/routes/export_replica.py"
            ]["source_facts"]
        }
    finally:
        session.close()


def test_run_agent_task_correlates_api_artifact_with_code_route_and_gates_api_only_candidate():
    repository, session = build_repository()
    try:
        campaign = repository.create_campaign(
            program_id="program_example",
            name="API plus code hypothesis campaign",
            autonomy_level="level_0_read_only",
            scope_status="in_scope",
            policy_text="Testing allowed",
            default_asset="authorized/service",
            target_classes=["idor"],
            created_by="operator",
        )
        repository.update_campaign_status(campaign.id, "running")
        map_task = repository.create_campaign_task(
            campaign_id=campaign.id,
            task_type="attack_surface_mapping",
            agent_type="target_model_agent",
            title="Map authorized code and API",
            input_refs=[f"campaign:{campaign.id}"],
            payload={
                "authorized_code_files": [
                    {
                        "path": "apps/api/routes/files.py",
                        "content": """
from fastapi import APIRouter

router = APIRouter()

@router.get("/files/{file_id}/export")
def export_file(file_id: str):
    return send_file(file_id)
""",
                    }
                ],
                "authorized_api_artifacts": [
                    {
                        "kind": "openapi",
                        "source_name": "openapi.json",
                        "payload": {
                            "paths": {
                                "/files/{file_id}/export": {
                                    "get": {"operationId": "exportFile"}
                                },
                                "/teams/{team_id}/invite": {
                                    "parameters": [
                                        {
                                            "name": "team_id",
                                            "in": "path",
                                            "required": True,
                                        }
                                    ],
                                    "post": {"operationId": "inviteTeamMember"}
                                },
                            }
                        },
                    }
                ],
            },
        )
        hypothesis_task = repository.create_campaign_task(
            campaign_id=campaign.id,
            task_type="hypothesis_generation",
            agent_type="hypothesis_agent",
            title="Generate correlated hypotheses",
            input_refs=[f"campaign:{campaign.id}"],
            payload={},
        )

        assert run_agent_task(map_task.id, repository=repository)["status"] == "completed"
        assert (
            run_agent_task(hypothesis_task.id, repository=repository)["status"]
            == "completed"
        )

        pipeline_run = repository.list_pipeline_runs_for_program("program_example")[0]
        payload = pipeline_run.payload

        assert pipeline_run.hypothesis_count == 2
        file_assessment = next(
            assessment
            for assessment in payload["hypothesis_assessments"]
            if assessment["hypothesis"]["hypothesis_id"] == "codebase_fact_hypothesis_1"
        )
        team_assessment = next(
            assessment
            for assessment in payload["hypothesis_assessments"]
            if assessment["hypothesis"]["hypothesis_id"] == "codebase_fact_hypothesis_2"
        )

        file_source_facts = file_assessment["hypothesis"]["source_facts"]
        assert [
            fact["artifact_kind"]
            for fact in file_source_facts
            if fact["fact_type"] == "route_handler"
        ] == ["code", "api"]
        assert "api_artifact_candidate" not in file_assessment["hunter_assessment"]["reasons"]

        assert team_assessment["hypothesis"]["source_facts"][0]["artifact_kind"] == "api"
        assert team_assessment["hypothesis"]["source_facts"][0]["api_shape"] == {
            "path_parameters": ["team_id"]
        }
        assert "api_artifact_candidate" in team_assessment["hunter_assessment"]["reasons"]
        assert "api_shape:object_identifier_present" in team_assessment[
            "hunter_assessment"
        ]["reasons"]
        assert "missing_evidence:declared_authentication_or_scope_model" in team_assessment[
            "hunter_assessment"
        ]["reasons"]
        assert "declared_authentication_or_scope_model" in team_assessment[
            "hypothesis"
        ]["evidence_needed"]
        assert (
            "Resolve the declared authentication or scope model before preparing validation evidence."
            in team_assessment["validation_plan"]["steps"]
        )
        team_queue_item = next(
            item
            for item in payload["autonomous_hunt_queue"]
            if item["candidate_id"] == team_assessment["candidate_id"]
        )
        assert team_queue_item["status"] == "awaiting_evidence_review"
        assert team_queue_item["next_action"] == "resolve_evidence_gaps"
        assert team_queue_item["required_evidence"] == [
            "local_code_or_har_correlation",
            "declared_authentication_or_scope_model",
        ]
        assert team_queue_item["quality_gate_reasons"] == ["required_evidence_missing"]
        assert team_queue_item["human_approval_required"] is True
        assert "secret-token" not in str(payload)
        assert "Bearer" not in str(payload)
    finally:
        session.close()


def test_run_agent_task_marks_api_har_route_correlation_as_satisfied_evidence():
    repository, session = build_repository()
    try:
        campaign = repository.create_campaign(
            program_id="program_example",
            name="API HAR correlated hypothesis campaign",
            autonomy_level="level_0_read_only",
            scope_status="in_scope",
            policy_text="Testing allowed",
            default_asset="authorized/service",
            target_classes=["idor"],
            created_by="operator",
        )
        repository.update_campaign_status(campaign.id, "running")
        map_task = repository.create_campaign_task(
            campaign_id=campaign.id,
            task_type="attack_surface_mapping",
            agent_type="target_model_agent",
            title="Map authorized API and HAR",
            input_refs=[f"campaign:{campaign.id}"],
            payload={
                "authorized_api_artifacts": [
                    {
                        "kind": "openapi",
                        "source_name": "openapi.json",
                        "payload": {
                            "paths": {
                                "/files/123/export": {
                                    "get": {"operationId": "exportFile"}
                                }
                            }
                        },
                    },
                    {
                        "kind": "har",
                        "source_name": "traffic.har",
                        "payload": {
                            "log": {
                                "entries": [
                                    {
                                        "request": {
                                            "method": "GET",
                                            "url": "https://authorized.example/files/123/export",
                                        }
                                    }
                                ]
                            }
                        },
                    },
                ],
            },
        )
        hypothesis_task = repository.create_campaign_task(
            campaign_id=campaign.id,
            task_type="hypothesis_generation",
            agent_type="hypothesis_agent",
            title="Generate correlated API HAR hypotheses",
            input_refs=[f"campaign:{campaign.id}"],
            payload={},
        )

        assert run_agent_task(map_task.id, repository=repository)["status"] == "completed"
        assert (
            run_agent_task(hypothesis_task.id, repository=repository)["status"]
            == "completed"
        )

        payload = repository.list_pipeline_runs()[0].payload
        assessment = payload["hypothesis_assessments"][0]
        hunter = assessment["hunter_assessment"]
        hunt_queue = payload["autonomous_hunt_queue"][0]

        assert [
            fact["artifact_kind"]
            for fact in assessment["hypothesis"]["source_facts"]
            if fact["fact_type"] == "route_handler"
        ] == ["api", "har"]
        assert "api_artifact_candidate" in hunter["reasons"]
        assert "evidence_satisfied:local_code_or_har_correlation" in hunter["reasons"]
        assert "evidence_satisfied:local_code_or_api_schema_correlation" in hunter[
            "reasons"
        ]
        assert "cross_artifact_route_correlation" in hunter["evidence_focus"]
        assert hunt_queue["status"] == "awaiting_human_approval"
        assert hunt_queue["next_action"] == "review_validation_plan"
        assert hunt_queue["satisfied_evidence"] == [
            "local_code_or_har_correlation",
            "local_code_or_api_schema_correlation",
        ]
        assert "required_evidence" not in hunt_queue
        assert "quality_gate_reasons" not in hunt_queue
        assert hunt_queue["human_approval_required"] is True
        assert hunt_queue["blocked_actions"] == [
            "execute_live_validation",
            "touch_real_user_data",
            "submit_report",
            "bypass_scope_guard",
        ]
        assert "Authorization" not in str(payload)
        assert "secret-token" not in str(payload)
    finally:
        session.close()


def test_run_agent_task_correlates_template_routes_with_concrete_har_path():
    repository, session = build_repository()
    try:
        campaign = repository.create_campaign(
            program_id="program_example",
            name="Template route correlation campaign",
            autonomy_level="level_0_read_only",
            scope_status="in_scope",
            policy_text="Testing allowed",
            default_asset="authorized/service",
            target_classes=["idor"],
            created_by="operator",
        )
        repository.update_campaign_status(campaign.id, "running")
        map_task = repository.create_campaign_task(
            campaign_id=campaign.id,
            task_type="attack_surface_mapping",
            agent_type="target_model_agent",
            title="Map template route with concrete traffic",
            input_refs=[f"campaign:{campaign.id}"],
            payload={
                "authorized_code_files": [
                    {
                        "path": "apps/api/routes/files.py",
                        "content": """
from fastapi import APIRouter

router = APIRouter()

@router.get("/files/{file_id}/export")
def export_file(file_id: str):
    return send_file(file_id)
""",
                    }
                ],
                "authorized_api_artifacts": [
                    {
                        "kind": "openapi",
                        "source_name": "openapi.json",
                        "payload": {
                            "paths": {
                                "/files/{file_id}/export": {
                                    "parameters": [
                                        {
                                            "name": "file_id",
                                            "in": "path",
                                            "required": True,
                                        },
                                        {
                                            "name": "Authorization",
                                            "in": "header",
                                        },
                                    ],
                                    "get": {
                                        "operationId": "exportFile",
                                        "security": [{"bearerAuth": []}],
                                        "parameters": [
                                            {"name": "download", "in": "query"},
                                            {"name": "session_token", "in": "query"},
                                        ],
                                        "requestBody": {
                                            "content": {
                                                "application/json": {
                                                    "schema": {
                                                        "type": "object",
                                                        "properties": {
                                                            "format": {"type": "string"},
                                                            "password": {"type": "string"},
                                                        },
                                                    }
                                                }
                                            }
                                        },
                                    }
                                }
                            }
                        },
                    },
                    {
                        "kind": "har",
                        "source_name": "traffic.har",
                        "payload": {
                            "log": {
                                "entries": [
                                    {
                                        "request": {
                                            "method": "GET",
                                            "url": "https://authorized.example/files/123/export",
                                            "headers": [
                                                {
                                                    "name": "Authorization",
                                                    "value": "Bearer secret-token",
                                                }
                                            ],
                                        }
                                    }
                                ]
                            }
                        },
                    },
                ],
            },
        )
        hypothesis_task = repository.create_campaign_task(
            campaign_id=campaign.id,
            task_type="hypothesis_generation",
            agent_type="hypothesis_agent",
            title="Generate template-correlated hypotheses",
            input_refs=[f"campaign:{campaign.id}"],
            payload={},
        )

        assert run_agent_task(map_task.id, repository=repository)["status"] == "completed"
        assert (
            run_agent_task(hypothesis_task.id, repository=repository)["status"]
            == "completed"
        )

        pipeline_run = repository.list_pipeline_runs_for_program("program_example")[0]
        payload = pipeline_run.payload

        assert pipeline_run.hypothesis_count == 1
        assessment = payload["hypothesis_assessments"][0]
        hunter = assessment["hunter_assessment"]
        hunt_queue = payload["autonomous_hunt_queue"][0]

        assert [
            fact["artifact_kind"]
            for fact in assessment["hypothesis"]["source_facts"]
            if fact["fact_type"] == "route_handler"
        ] == ["code", "api", "har"]
        api_fact = next(
            fact
            for fact in assessment["hypothesis"]["source_facts"]
            if fact["fact_type"] == "route_handler" and fact["artifact_kind"] == "api"
        )
        assert api_fact["api_shape"] == {
            "path_parameters": ["file_id"],
            "query_parameters": ["download"],
            "body_fields": ["format"],
            "request_body_present": True,
            "security_declared": True,
        }
        assert "codebase_route_candidate" in hunter["reasons"]
        assert "authorization_gap_candidate" in hunter["reasons"]
        assert "sensitive_sink_present" in hunter["reasons"]
        assert "evidence_satisfied:local_code_or_har_correlation" in hunter["reasons"]
        assert "evidence_satisfied:local_code_or_api_schema_correlation" in hunter[
            "reasons"
        ]
        assert "api_shape:object_identifier_present" in hunter["reasons"]
        assert "api_shape:request_body_present" in hunter["reasons"]
        assert "cross_artifact_route_correlation" in hunter["evidence_focus"]
        assert "api_object_identifier_shape" in hunter["evidence_focus"]
        assert "request_body_field_review" in hunter["evidence_focus"]
        assert "approved_test_object_id_matrix" in assessment["hypothesis"][
            "evidence_needed"
        ]
        assert "request_body_field_policy_review" in assessment["hypothesis"][
            "evidence_needed"
        ]
        assert "declared_authentication_or_scope_model" not in assessment[
            "hypothesis"
        ]["evidence_needed"]
        validation_steps = assessment["validation_plan"]["steps"]
        assert (
            "Map API object identifier fields to approved test objects before any two-account comparison."
            in validation_steps
        )
        assert (
            "Review request body field names locally; do not store raw body values or secrets."
            in validation_steps
        )
        assert (
            "Use only redacted HAR method and path evidence; ignore headers, cookies, and request values."
            in validation_steps
        )
        assert not any("raw body values" in step and "secret-token" in step for step in validation_steps)
        assert hunt_queue["status"] == "awaiting_evidence_review"
        assert hunt_queue["next_action"] == "resolve_evidence_gaps"
        assert hunt_queue["satisfied_evidence"] == [
            "local_code_or_har_correlation",
            "local_code_or_api_schema_correlation",
        ]
        assert hunt_queue["evidence_needed"] == assessment["hypothesis"][
            "evidence_needed"
        ]
        assert hunt_queue["safe_validation_plan"] == validation_steps
        assert hunt_queue["safe_validation_step_count"] == len(validation_steps)
        assert hunt_queue["validation_plan_status"] == "approval_required"
        assert hunt_queue["required_evidence"] == [
            "independent_refutation_or_static_rule"
        ]
        assert "local_code_or_har_correlation" not in hunt_queue["required_evidence"]
        assert "local_code_or_api_schema_correlation" not in hunt_queue[
            "required_evidence"
        ]
        assert hunt_queue["quality_gate_reasons"] == ["required_evidence_missing"]
        assert hunt_queue["human_approval_required"] is True
        assert hunt_queue["blocked_actions"] == [
            "execute_live_validation",
            "touch_real_user_data",
            "submit_report",
            "bypass_scope_guard",
        ]
        assert "Authorization" not in str(payload)
        assert "secret-token" not in str(payload)
        assert "session_token" not in str(payload)
        assert "password" not in str(payload)
        assert "execute_live_validation" in hunt_queue["blocked_actions"]
        assert "submit_report" in hunt_queue["blocked_actions"]
    finally:
        session.close()


def test_run_agent_task_generates_multiple_hypotheses_from_multiple_code_routes():
    repository, session = build_repository()
    try:
        campaign = repository.create_campaign(
            program_id="program_example",
            name="Multi route hypothesis campaign",
            autonomy_level="level_0_read_only",
            scope_status="in_scope",
            policy_text="Testing allowed",
            default_asset="authorized/service",
            target_classes=["idor"],
            created_by="operator",
        )
        repository.update_campaign_status(campaign.id, "running")
        map_task = repository.create_campaign_task(
            campaign_id=campaign.id,
            task_type="attack_surface_mapping",
            agent_type="target_model_agent",
            title="Map authorized local code",
            input_refs=[f"campaign:{campaign.id}"],
            payload={
                "authorized_code_files": [
                    {
                        "path": "apps/api/routes/files.py",
                        "content": """
from fastapi import APIRouter

router = APIRouter()

@router.get("/files/{file_id}/export")
def export_file(file_id: str):
    authorize_owner_or_admin(file_id)
    return send_file(file_id)

@router.post("/teams/{team_id}/invites")
def create_team_invite(team_id: str):
    require_role(team_id, "owner")
    return update_role(team_id)
""",
                    }
                ],
            },
        )
        hypothesis_task = repository.create_campaign_task(
            campaign_id=campaign.id,
            task_type="hypothesis_generation",
            agent_type="hypothesis_agent",
            title="Generate multi-route code-backed hypotheses",
            input_refs=[f"campaign:{campaign.id}"],
            payload={"authorization": "Bearer secret-token"},
        )

        run_agent_task(map_task.id, repository=repository)
        result = run_agent_task(hypothesis_task.id, repository=repository)

        pipeline_runs = [
            run
            for run in repository.list_pipeline_runs()
            if run.program_id == campaign.program_id and run.asset == campaign.default_asset
        ]
        assert result["status"] == "completed"
        assert len(pipeline_runs) == 1

        facts = repository.list_campaign_codebase_facts(campaign.id)
        file_route_fact_ref = _persisted_codebase_fact_ref(
            facts,
            fact_type="route_handler",
            source_path="apps/api/routes/files.py",
            route_path="/files/{file_id}/export",
        )
        file_authz_fact_ref = _persisted_codebase_fact_ref(
            facts,
            fact_type="authz_check",
            source_path="apps/api/routes/files.py",
            symbol_name="authorize_owner_or_admin",
        )
        file_sink_fact_ref = _persisted_codebase_fact_ref(
            facts,
            fact_type="sensitive_sink",
            source_path="apps/api/routes/files.py",
            symbol_name="send_file",
        )
        team_route_fact_ref = _persisted_codebase_fact_ref(
            facts,
            fact_type="route_handler",
            source_path="apps/api/routes/files.py",
            route_path="/teams/{team_id}/invites",
        )
        team_authz_fact_ref = _persisted_codebase_fact_ref(
            facts,
            fact_type="authz_check",
            source_path="apps/api/routes/files.py",
            symbol_name="require_role",
        )
        team_sink_fact_ref = _persisted_codebase_fact_ref(
            facts,
            fact_type="sensitive_sink",
            source_path="apps/api/routes/files.py",
            symbol_name="update_role",
        )
        payload = pipeline_runs[0].payload
        hypotheses = payload["hypotheses"]
        assessments = payload["hypothesis_assessments"]
        hunt_queue = payload["autonomous_hunt_queue"]

        assert pipeline_runs[0].hypothesis_count == 2
        assert [item["hypothesis"] for item in hypotheses] == [
            "Review GET /files/{file_id}/export for object authorization boundary drift.",
            "Review POST /teams/{team_id}/invites for object authorization boundary drift.",
        ]
        assert [item["candidate_id"] for item in assessments] == [
            "codebase_fact_hypothesis_1",
            "codebase_fact_hypothesis_2",
        ]
        assert [item["hypothesis_index"] for item in assessments] == [0, 1]
        assert payload["target_model"]["objects"] == ["file", "team"]
        assert payload["target_model"]["sensitive_actions"] == [
            "GET /files/{file_id}/export",
            "POST /teams/{team_id}/invites",
        ]
        assert payload["target_model"]["source_fact_refs"] == [
            file_route_fact_ref,
            file_authz_fact_ref,
            file_sink_fact_ref,
            team_route_fact_ref,
            team_authz_fact_ref,
            team_sink_fact_ref,
        ]
        assert assessments[0]["exploit_chain"]["primitives"] == [
            "GET /files/{file_id}/export",
            "owner_or_admin_check",
            "send_file",
        ]
        assert assessments[1]["exploit_chain"]["primitives"] == [
            "POST /teams/{team_id}/invites",
            "role_check",
            "update_role",
        ]
        assert all(item["validation_plan"]["human_approval_required"] is True for item in assessments)
        assert all(item["candidate_status"] == "needs_human_review" for item in assessments)
        file_hunter = assessments[0]["hunter_assessment"]
        role_hunter = assessments[1]["hunter_assessment"]
        assert file_hunter["playbook_id"] == "bola_idor"
        assert file_hunter["hunter_priority_score"] == 56
        assert "refutation_evidence:same_handler_object_authz" in file_hunter["reasons"]
        assert "missing_evidence:authz_bypass_or_misbind_trace" in file_hunter["reasons"]
        assert "same_handler_object_authz_trace" in file_hunter["evidence_focus"]
        assert "authz_bypass_or_misbind_trace" in file_hunter["evidence_focus"]
        assert role_hunter["playbook_id"] == "role_boundary"
        assert role_hunter["hunter_priority_score"] == 72
        assert "refutation_evidence:same_handler_object_authz" not in role_hunter["reasons"]
        assert hypotheses[0]["hunter_assessment"] == assessments[0]["hunter_assessment"]
        assert hypotheses[1]["hunter_assessment"] == assessments[1]["hunter_assessment"]
        assert hypotheses[0]["priority_score"] == assessments[0]["hunter_assessment"][
            "hunter_priority_score"
        ]
        assert hypotheses[1]["priority_score"] == assessments[1]["hunter_assessment"][
            "hunter_priority_score"
        ]
        assert [item["candidate_id"] for item in hunt_queue] == [
            "codebase_fact_hypothesis_2",
            "codebase_fact_hypothesis_1",
        ]
        assert [item["top_candidate_rank"] for item in hunt_queue] == [1, 2]
        assert hunt_queue[0]["evidence_trace_summary"]["trace_status"] == "traceable"
        assert hunt_queue[0]["report_readiness"]["status"] == "needs_safe_validation_plan"
        assert hunt_queue[0]["report_readiness"]["report_submission_allowed"] is False
        assert hunt_queue[1]["required_evidence"] == ["authz_bypass_or_misbind_trace"]
        assert hunt_queue[1]["report_readiness"]["status"] == "blocked_by_required_evidence"
        assert all(item["human_approval_required"] is True for item in hunt_queue)
        assert all("execute_live_validation" in item["blocked_actions"] for item in hunt_queue)
        assert "secret-token" not in str(payload)
        assert "Bearer" not in str(payload)
    finally:
        session.close()


def test_run_agent_task_applies_program_lessons_to_code_hunt_queue():
    repository, session = build_repository()
    try:
        campaign = repository.create_campaign(
            program_id="program_example",
            name="Lesson-aware code hunt campaign",
            autonomy_level="level_0_read_only",
            scope_status="in_scope",
            policy_text="Testing allowed",
            default_asset="authorized/service",
            target_classes=["idor"],
            created_by="operator",
        )
        repository.update_campaign_status(campaign.id, "running")
        for index in range(2):
            repository.save_learning_signal(
                program_id="program_example",
                playbook_id="bola_idor",
                outcome="accepted",
                surface_key="file_id:export",
                notes=f"Accepted safe fixture {index}; Authorization: Bearer secret-token",
                evidence_quality="strong",
            )
        map_task = repository.create_campaign_task(
            campaign_id=campaign.id,
            task_type="attack_surface_mapping",
            agent_type="target_model_agent",
            title="Map authorized local code",
            input_refs=[f"campaign:{campaign.id}"],
            payload={
                "authorized_code_files": [
                    {
                        "path": "apps/api/routes/files.py",
                        "content": """
from fastapi import APIRouter

router = APIRouter()

@router.get("/files/{file_id}/export")
def export_file(file_id: str):
    authorize_owner_or_admin(file_id)
    return send_file(file_id)

@router.post("/teams/{team_id}/invites")
def create_team_invite(team_id: str):
    require_role(team_id, "owner")
    return update_role(team_id)
""",
                    }
                ],
            },
        )
        hypothesis_task = repository.create_campaign_task(
            campaign_id=campaign.id,
            task_type="hypothesis_generation",
            agent_type="hypothesis_agent",
            title="Generate lesson-aware hypotheses",
            input_refs=[f"campaign:{campaign.id}"],
            payload={},
        )

        run_agent_task(map_task.id, repository=repository)
        run_agent_task(hypothesis_task.id, repository=repository)

        pipeline_run = repository.list_pipeline_runs()[0]
        payload = pipeline_run.payload
        assessments = payload["hypothesis_assessments"]
        file_assessment = assessments[0]["hunter_assessment"]
        role_assessment = assessments[1]["hunter_assessment"]

        assert file_assessment["playbook_id"] == "bola_idor"
        assert file_assessment["hunter_priority_score"] == 64
        assert "lesson:applied:boost" in file_assessment["reasons"]
        assert "lesson:boost:accepted_strong_evidence" in file_assessment["reasons"]
        assert "refutation_evidence:same_handler_object_authz" in file_assessment["reasons"]
        assert "advisory_memory_only" in file_assessment["safety_notes"]
        assert role_assessment["hunter_priority_score"] == 72
        assert payload["autonomous_hunt_queue"][0]["candidate_id"] == "codebase_fact_hypothesis_2"
        file_queue_item = next(
            item
            for item in payload["autonomous_hunt_queue"]
            if item["candidate_id"] == "codebase_fact_hypothesis_1"
        )
        assert file_queue_item["raw_priority_score"] == 64
        assert file_queue_item["priority_score"] == 39
        assert file_queue_item["status"] == "awaiting_evidence_review"
        assert file_queue_item["human_approval_required"] is True
        assert "secret-token" not in str(payload)
        assert "Bearer" not in str(payload)
    finally:
        session.close()


def test_run_agent_task_routes_evidence_needed_lessons_to_evidence_review_queue():
    repository, session = build_repository()
    try:
        campaign = repository.create_campaign(
            program_id="program_example",
            name="Evidence-needed lesson code hunt campaign",
            autonomy_level="level_0_read_only",
            scope_status="in_scope",
            policy_text="Testing allowed",
            default_asset="authorized/service",
            target_classes=["idor"],
            created_by="operator",
        )
        repository.update_campaign_status(campaign.id, "running")
        repository.save_learning_signal(
            program_id="program_example",
            playbook_id="bola_idor",
            outcome="informative",
            surface_key="file_id:export",
            notes="Candidate needed more evidence before ranking boost.",
            evidence_quality="weak",
            target_relationships=[
                "candidate:H-001",
                "evidence_ready:false",
                "trace_status:needs_evidence",
                "missing_evidence:independent_cross_check",
                "missing_required_artifact:policy",
                "learned_evidence:lesson_evidence_needed_missing_evidence_independent_cross_check",
            ],
        )
        map_task = repository.create_campaign_task(
            campaign_id=campaign.id,
            task_type="attack_surface_mapping",
            agent_type="target_model_agent",
            title="Map authorized local code",
            input_refs=[f"campaign:{campaign.id}"],
            payload={
                "authorized_code_files": [
                    {
                        "path": "apps/api/routes/files.py",
                        "content": """
from fastapi import APIRouter

router = APIRouter()

@router.get("/files/{file_id}/export")
def export_file(file_id: str):
    authorize_owner_or_admin(file_id)
    return send_file(file_id)
""",
                    }
                ],
            },
        )
        hypothesis_task = repository.create_campaign_task(
            campaign_id=campaign.id,
            task_type="hypothesis_generation",
            agent_type="hypothesis_agent",
            title="Generate evidence-aware hypotheses",
            input_refs=[f"campaign:{campaign.id}"],
            payload={},
        )

        run_agent_task(map_task.id, repository=repository)
        run_agent_task(hypothesis_task.id, repository=repository)

        payload = repository.list_pipeline_runs()[0].payload
        hunter = payload["hypothesis_assessments"][0]["hunter_assessment"]
        hunt_queue = payload["autonomous_hunt_queue"][0]

        assert "lesson:applied:evidence_needed" in hunter["reasons"]
        assert "lesson:evidence_needed:missing_evidence:independent_cross_check" in hunter[
            "reasons"
        ]
        assert hunt_queue["next_action"] == "resolve_evidence_gaps"
        assert hunt_queue["required_evidence"] == [
            "independent_refutation_or_static_rule",
            "policy",
            "authz_bypass_or_misbind_trace",
        ]
        assert hunt_queue["status"] == "awaiting_evidence_review"
        assert hunt_queue["human_approval_required"] is True
        assert hunt_queue["blocked_actions"] == [
            "execute_live_validation",
            "touch_real_user_data",
            "submit_report",
            "bypass_scope_guard",
        ]
        assert "secret-token" not in str(payload)
        assert "Bearer" not in str(payload)
    finally:
        session.close()


def test_worker_hunt_queue_demotes_duplicate_risk_before_ranking():
    queue = worker_tasks._worker_autonomous_hunt_queue(
        [
            {
                "candidate_id": "high_duplicate_risk",
                "hunter_assessment": {
                    "playbook_id": "bola_idor",
                    "hunter_priority_score": 95,
                    "duplicate_risk_score": 80,
                    "reasons": [
                        "codebase_route_candidate",
                        "lesson:applied:duplicate_watch",
                    ],
                },
            },
            {
                "candidate_id": "clean_code_backed_candidate",
                "hunter_assessment": {
                    "playbook_id": "role_boundary",
                    "hunter_priority_score": 72,
                    "duplicate_risk_score": 20,
                    "reasons": ["codebase_route_candidate"],
                },
            },
        ]
    )

    assert queue[0]["candidate_id"] == "clean_code_backed_candidate"
    duplicate_item = queue[1]
    assert duplicate_item["candidate_id"] == "high_duplicate_risk"
    assert duplicate_item["raw_priority_score"] == 95
    assert duplicate_item["priority_score"] < queue[0]["priority_score"]
    assert duplicate_item["status"] == "awaiting_deduplication_review"
    assert duplicate_item["next_action"] == "deduplicate_candidate"
    assert duplicate_item["required_evidence"] == [
        "prior_submission_search",
        "candidate_similarity_review",
    ]
    assert duplicate_item["quality_gate_reasons"] == ["duplicate_risk_high"]
    assert duplicate_item["human_approval_required"] is True
    assert duplicate_item["blocked_actions"] == [
        "execute_live_validation",
        "touch_real_user_data",
        "submit_report",
        "bypass_scope_guard",
    ]


def test_worker_hunt_queue_routes_direct_missing_evidence_reasons_to_review():
    queue = worker_tasks._worker_autonomous_hunt_queue(
        [
            {
                "candidate_id": "missing_independent_review",
                "hunter_assessment": {
                    "playbook_id": "bola_idor",
                    "hunter_priority_score": 88,
                    "duplicate_risk_score": 10,
                    "reasons": [
                        "codebase_route_candidate",
                        "missing_evidence:independent_cross_check",
                        "missing_required_artifact:policy",
                    ],
                },
                "hypothesis": {
                    "source_facts": [
                        {
                            "fact_ref": "codebase_fact:route_handler:/files/{file_id}/export",
                            "artifact_kind": "code",
                        }
                    ]
                },
            }
        ]
    )

    queue_item = queue[0]
    assert queue_item["status"] == "awaiting_evidence_review"
    assert queue_item["next_action"] == "resolve_evidence_gaps"
    assert queue_item["required_evidence"] == [
        "independent_refutation_or_static_rule",
        "policy",
    ]
    assert queue_item["raw_priority_score"] == 88
    assert queue_item["priority_score"] == 63
    assert queue_item["quality_gate_reasons"] == ["required_evidence_missing"]
    assert queue_item["human_approval_required"] is True


def test_worker_hunt_queue_accepts_cross_artifact_route_correlation_as_evidence():
    queue = worker_tasks._worker_autonomous_hunt_queue(
        [
            {
                "candidate_id": "api_har_correlated_candidate",
                "hunter_assessment": {
                    "playbook_id": "bola_idor",
                    "hunter_priority_score": 88,
                    "duplicate_risk_score": 10,
                    "reasons": [
                        "codebase_route_candidate",
                        "api_artifact_candidate",
                    ],
                },
                "hypothesis": {
                    "source_facts": [
                        {
                            "fact_ref": "api_artifact:route:GET:/files/{file_id}/export",
                            "artifact_kind": "api",
                            "fact_type": "route_handler",
                        },
                        {
                            "fact_ref": "har_artifact:route:GET:/files/{file_id}/export",
                            "artifact_kind": "har",
                            "fact_type": "route_handler",
                        },
                    ]
                },
            }
        ]
    )

    queue_item = queue[0]
    assert queue_item["status"] == "awaiting_human_approval"
    assert queue_item["next_action"] == "review_validation_plan"
    assert queue_item["priority_score"] == 88
    assert queue_item["satisfied_evidence"] == [
        "local_code_or_har_correlation",
        "local_code_or_api_schema_correlation",
    ]
    assert queue_item["evidence_trace_summary"] == {
        "trace_status": "traceable",
        "source_fact_count": 2,
        "traceable_source_fact_count": 2,
        "route_fact_count": 2,
        "artifact_kinds": ["api", "har"],
        "source_fact_types": ["route_handler"],
        "report_submission_allowed": False,
    }
    assert queue_item["report_readiness"] == {
        "status": "needs_safe_validation_plan",
        "submission_blocked": True,
        "report_submission_allowed": False,
        "required_evidence_count": 0,
        "safe_validation_step_count": 0,
        "trace_status": "traceable",
        "next_allowed_action": "Draft a non-destructive validation plan before report drafting.",
    }
    assert "required_evidence" not in queue_item
    assert "quality_gate_reasons" not in queue_item
    assert "raw_priority_score" not in queue_item
    assert queue_item["human_approval_required"] is True
    assert queue_item["blocked_actions"] == [
        "execute_live_validation",
        "touch_real_user_data",
        "submit_report",
        "bypass_scope_guard",
    ]


def test_worker_hunt_queue_returns_ranked_top_five_candidates_only():
    queue = worker_tasks._worker_autonomous_hunt_queue(
        [
            {
                "candidate_id": f"candidate_{score}",
                "hunter_assessment": {
                    "playbook_id": "bola_idor",
                    "hunter_priority_score": score,
                    "duplicate_risk_score": 10,
                    "reasons": ["codebase_route_candidate"],
                },
            }
            for score in [30, 90, 70, 95, 50, 85]
        ]
    )

    assert [item["candidate_id"] for item in queue] == [
        "candidate_95",
        "candidate_90",
        "candidate_85",
        "candidate_70",
        "candidate_50",
    ]
    assert [item["top_candidate_rank"] for item in queue] == [1, 2, 3, 4, 5]
    assert "candidate_30" not in [item["candidate_id"] for item in queue]
    assert all(item["human_approval_required"] is True for item in queue)
    assert all("submit_report" in item["blocked_actions"] for item in queue)


def test_worker_hunt_queue_demotes_same_route_duplicate_candidates():
    queue = worker_tasks._worker_autonomous_hunt_queue(
        [
            {
                "candidate_id": "same_route_lower",
                "hunter_assessment": {
                    "playbook_id": "bola_idor",
                    "hunter_priority_score": 78,
                    "duplicate_risk_score": 10,
                    "reasons": ["codebase_route_candidate"],
                },
                "hypothesis": {
                    "source_facts": [
                        {
                            "fact_ref": "api_artifact:route:GET:/files/{file_id}/export",
                            "artifact_kind": "api",
                            "fact_type": "route_handler",
                            "route_method": "GET",
                            "route_path": "/files/{file_id}/export",
                        }
                    ]
                },
            },
            {
                "candidate_id": "unique_route",
                "hunter_assessment": {
                    "playbook_id": "bola_idor",
                    "hunter_priority_score": 82,
                    "duplicate_risk_score": 10,
                    "reasons": ["codebase_route_candidate"],
                },
                "hypothesis": {
                    "source_facts": [
                        {
                            "fact_ref": "api_artifact:route:GET:/teams/{team_id}/members",
                            "artifact_kind": "api",
                            "fact_type": "route_handler",
                            "route_method": "GET",
                            "route_path": "/teams/{team_id}/members",
                        }
                    ]
                },
            },
            {
                "candidate_id": "same_route_best",
                "hunter_assessment": {
                    "playbook_id": "bola_idor",
                    "hunter_priority_score": 90,
                    "duplicate_risk_score": 10,
                    "reasons": ["codebase_route_candidate"],
                },
                "hypothesis": {
                    "source_facts": [
                        {
                            "fact_ref": "har_artifact:route:GET:/files/{file_id}/export",
                            "artifact_kind": "har",
                            "fact_type": "route_handler",
                            "route_method": "GET",
                            "route_path": "/files/{file_id}/export",
                        }
                    ]
                },
            },
        ]
    )

    assert [item["candidate_id"] for item in queue] == [
        "same_route_best",
        "unique_route",
        "same_route_lower",
    ]
    assert [item["top_candidate_rank"] for item in queue] == [1, 2, 3]
    lower_duplicate = queue[2]
    assert lower_duplicate["priority_score"] == 58
    assert lower_duplicate["raw_priority_score"] == 78
    assert lower_duplicate["status"] == "awaiting_deduplication_review"
    assert lower_duplicate["next_action"] == "deduplicate_candidate"
    assert lower_duplicate["required_evidence"] == [
        "prior_submission_search",
        "candidate_similarity_review",
    ]
    assert lower_duplicate["quality_gate_reasons"] == ["similar_candidate_shape"]
    assert all("_candidate_similarity_key" not in item for item in queue)
    assert all(item["human_approval_required"] is True for item in queue)


def test_worker_hunt_queue_evidence_trace_summary_filters_sensitive_labels():
    queue = worker_tasks._worker_autonomous_hunt_queue(
        [
            {
                "candidate_id": "sensitive_trace_labels",
                "hunter_assessment": {
                    "playbook_id": "bola_idor",
                    "hunter_priority_score": 72,
                    "duplicate_risk_score": 10,
                    "reasons": ["codebase_route_candidate"],
                },
                "hypothesis": {
                    "source_facts": [
                        {
                            "fact_ref": "codebase_fact:route_handler:/files/{file_id}/export",
                            "artifact_kind": "Authorization",
                            "fact_type": "session_token",
                        },
                        {
                            "fact_ref": "codebase_fact:route_handler:/teams/{team_id}/members",
                            "artifact_kind": "code",
                            "fact_type": "route_handler",
                        },
                    ]
                },
            }
        ]
    )

    summary = queue[0]["evidence_trace_summary"]
    assert summary == {
        "trace_status": "needs_evidence",
        "source_fact_count": 2,
        "traceable_source_fact_count": 1,
        "route_fact_count": 1,
        "artifact_kinds": ["code"],
        "source_fact_types": ["route_handler"],
        "report_submission_allowed": False,
    }
    assert "Authorization" not in str(summary)
    assert "session_token" not in str(summary)
    assert queue[0]["report_readiness"] == {
        "status": "blocked_by_evidence_trace",
        "submission_blocked": True,
        "report_submission_allowed": False,
        "required_evidence_count": 0,
        "safe_validation_step_count": 0,
        "trace_status": "needs_evidence",
        "next_allowed_action": "Confirm candidate source facts are traceable before report drafting.",
    }


def test_worker_hunt_queue_marks_traceable_planned_candidate_report_draft_ready():
    queue = worker_tasks._worker_autonomous_hunt_queue(
        [
            {
                "candidate_id": "report_ready_candidate",
                "hunter_assessment": {
                    "playbook_id": "bola_idor",
                    "hunter_priority_score": 88,
                    "duplicate_risk_score": 10,
                    "reasons": ["codebase_route_candidate"],
                },
                "hypothesis": {
                    "evidence_needed": ["approved_test_object_id_matrix"],
                    "source_facts": [
                        {
                            "fact_ref": "api_artifact:route:GET:/files/{file_id}/export",
                            "artifact_kind": "api",
                            "fact_type": "route_handler",
                        },
                        {
                            "fact_ref": "har_artifact:route:GET:/files/{file_id}/export",
                            "artifact_kind": "har",
                            "fact_type": "route_handler",
                        },
                    ],
                },
                "validation_plan": {
                    "status": "approval_required",
                    "steps": [
                        "Confirm scope and approved test accounts before validation.",
                        "Use only redacted HAR method and path evidence.",
                    ],
                },
            }
        ]
    )

    queue_item = queue[0]
    assert queue_item["report_readiness"] == {
        "status": "submission_blocked_draft_ready",
        "submission_blocked": True,
        "report_submission_allowed": False,
        "required_evidence_count": 0,
        "safe_validation_step_count": 2,
        "trace_status": "traceable",
        "next_allowed_action": "Prepare a submission-blocked draft for human redaction review.",
    }
    assert queue_item["safe_validation_step_count"] == 2
    assert queue_item["evidence_trace_summary"]["trace_status"] == "traceable"
    assert "required_evidence" not in queue_item


def test_worker_hunt_queue_deduplicates_template_and_concrete_route_shapes():
    queue = worker_tasks._worker_autonomous_hunt_queue(
        [
            {
                "candidate_id": "api_template_route",
                "hunter_assessment": {
                    "playbook_id": "bola_idor",
                    "hunter_priority_score": 88,
                    "duplicate_risk_score": 10,
                    "reasons": ["codebase_route_candidate"],
                },
                "hypothesis": {
                    "source_facts": [
                        {
                            "fact_ref": "api_artifact:route:GET:/files/{file_id}/export",
                            "artifact_kind": "api",
                            "fact_type": "route_handler",
                            "route_method": "GET",
                            "route_path": "/files/{file_id}/export",
                        }
                    ]
                },
            },
            {
                "candidate_id": "har_concrete_route",
                "hunter_assessment": {
                    "playbook_id": "bola_idor",
                    "hunter_priority_score": 84,
                    "duplicate_risk_score": 10,
                    "reasons": ["codebase_route_candidate"],
                },
                "hypothesis": {
                    "source_facts": [
                        {
                            "fact_ref": "har_artifact:route:GET:/files/123/export",
                            "artifact_kind": "har",
                            "fact_type": "route_handler",
                            "route_method": "GET",
                            "route_path": "/files/123/export",
                        }
                    ]
                },
            },
            {
                "candidate_id": "different_concrete_route",
                "hunter_assessment": {
                    "playbook_id": "bola_idor",
                    "hunter_priority_score": 80,
                    "duplicate_risk_score": 10,
                    "reasons": ["codebase_route_candidate"],
                },
                "hypothesis": {
                    "source_facts": [
                        {
                            "fact_ref": "har_artifact:route:GET:/teams/123/members",
                            "artifact_kind": "har",
                            "fact_type": "route_handler",
                            "route_method": "GET",
                            "route_path": "/teams/123/members",
                        }
                    ]
                },
            },
        ]
    )

    assert [item["candidate_id"] for item in queue] == [
        "api_template_route",
        "different_concrete_route",
        "har_concrete_route",
    ]
    concrete_duplicate = queue[2]
    assert concrete_duplicate["priority_score"] == 64
    assert concrete_duplicate["raw_priority_score"] == 84
    assert concrete_duplicate["status"] == "awaiting_deduplication_review"
    assert concrete_duplicate["required_evidence"] == [
        "prior_submission_search",
        "candidate_similarity_review",
    ]
    assert concrete_duplicate["quality_gate_reasons"] == ["similar_candidate_shape"]
    assert all("_candidate_similarity_key" not in item for item in queue)


def test_worker_hunt_queue_demotes_untraceable_candidate_before_ranking():
    queue = worker_tasks._worker_autonomous_hunt_queue(
        [
            {
                "candidate_id": "untraceable_high_score",
                "hunter_assessment": {
                    "playbook_id": "bola_idor",
                    "hunter_priority_score": 90,
                    "duplicate_risk_score": 10,
                    "reasons": ["codebase_route_candidate"],
                },
                "hypothesis": {"source_facts": []},
            },
            {
                "candidate_id": "traceable_lower_score",
                "hunter_assessment": {
                    "playbook_id": "role_boundary",
                    "hunter_priority_score": 70,
                    "duplicate_risk_score": 10,
                    "reasons": ["codebase_route_candidate"],
                },
                "hypothesis": {
                    "source_facts": [
                        {
                            "fact_ref": "codebase_fact:route_handler:/teams/{team_id}/invites",
                            "artifact_kind": "code",
                        }
                    ]
                },
            },
        ]
    )

    assert queue[0]["candidate_id"] == "traceable_lower_score"
    untraceable_item = queue[1]
    assert untraceable_item["candidate_id"] == "untraceable_high_score"
    assert untraceable_item["status"] == "awaiting_evidence_review"
    assert untraceable_item["next_action"] == "resolve_evidence_gaps"
    assert untraceable_item["required_evidence"] == ["traceable_source_fact"]
    assert untraceable_item["quality_gate_reasons"] == ["source_trace_missing"]
    assert untraceable_item["raw_priority_score"] == 90
    assert untraceable_item["priority_score"] < queue[0]["priority_score"]


def test_run_agent_task_does_not_borrow_hypothesis_facts_from_unrelated_files():
    repository, session = build_repository()
    try:
        campaign = repository.create_campaign(
            program_id="program_example",
            name="Code fact source scoping campaign",
            autonomy_level="level_0_read_only",
            scope_status="in_scope",
            policy_text="Testing allowed",
            default_asset="authorized/service",
            target_classes=["idor"],
            created_by="operator",
        )
        repository.update_campaign_status(campaign.id, "running")
        map_task = repository.create_campaign_task(
            campaign_id=campaign.id,
            task_type="attack_surface_mapping",
            agent_type="target_model_agent",
            title="Map authorized local code",
            input_refs=[f"campaign:{campaign.id}"],
            payload={
                "authorized_code_files": [
                    {
                        "path": "apps/api/routes/files.py",
                        "content": """
from fastapi import APIRouter

router = APIRouter()

@router.get("/files/{file_id}/export")
def export_file(file_id: str):
    return {"file_id": file_id}
""",
                    },
                    {
                        "path": "apps/api/routes/admin.py",
                        "content": """
def admin_archive(file_id: str):
    authorize_owner_or_admin(file_id)
    return send_file(file_id)
""",
                    },
                ],
            },
        )
        hypothesis_task = repository.create_campaign_task(
            campaign_id=campaign.id,
            task_type="hypothesis_generation",
            agent_type="hypothesis_agent",
            title="Generate code-backed hypotheses",
            input_refs=[f"campaign:{campaign.id}"],
            payload={},
        )

        map_result = run_agent_task(map_task.id, repository=repository)
        result = run_agent_task(hypothesis_task.id, repository=repository)

        pipeline_runs = [
            run
            for run in repository.list_pipeline_runs()
            if run.program_id == campaign.program_id and run.asset == campaign.default_asset
        ]
        payload = pipeline_runs[0].payload
        assessment = payload["hypothesis_assessments"][0]
        route_fact_ref = _persisted_codebase_fact_ref(
            repository.list_campaign_codebase_facts(campaign.id),
            fact_type="route_handler",
            source_path="apps/api/routes/files.py",
            route_path="/files/{file_id}/export",
        )

        assert map_result["status"] == "completed"
        assert result["status"] == "completed"
        assert payload["hypotheses"][0]["source_facts"] == [
            {
                "fact_ref": route_fact_ref,
                "artifact_kind": "code",
                "fact_type": "route_handler",
                "route_method": "GET",
                "route_path": "/files/{file_id}/export",
                "source_path": "apps/api/routes/files.py",
                "symbol_name": "export_file",
            }
        ]
        assert payload["target_model"]["source_fact_refs"] == [
            route_fact_ref
        ]
        assert assessment["exploit_chain"]["primitives"] == ["GET /files/{file_id}/export"]
    finally:
        session.close()


def test_run_agent_task_does_not_borrow_hypothesis_facts_from_unrelated_handlers():
    repository, session = build_repository()
    try:
        campaign = repository.create_campaign(
            program_id="program_example",
            name="Code fact handler scoping campaign",
            autonomy_level="level_0_read_only",
            scope_status="in_scope",
            policy_text="Testing allowed",
            default_asset="authorized/service",
            target_classes=["idor"],
            created_by="operator",
        )
        repository.update_campaign_status(campaign.id, "running")
        map_task = repository.create_campaign_task(
            campaign_id=campaign.id,
            task_type="attack_surface_mapping",
            agent_type="target_model_agent",
            title="Map authorized local code",
            input_refs=[f"campaign:{campaign.id}"],
            payload={
                "authorized_code_files": [
                    {
                        "path": "apps/api/routes/files.py",
                        "content": """
from fastapi import APIRouter

router = APIRouter()

@router.get("/files/{file_id}/export")
def export_file(file_id: str):
    return {"file_id": file_id}

def admin_archive(file_id: str):
    authorize_owner_or_admin(file_id)
    return send_file(file_id)
""",
                    }
                ],
            },
        )
        hypothesis_task = repository.create_campaign_task(
            campaign_id=campaign.id,
            task_type="hypothesis_generation",
            agent_type="hypothesis_agent",
            title="Generate handler-scoped hypotheses",
            input_refs=[f"campaign:{campaign.id}"],
            payload={},
        )

        map_result = run_agent_task(map_task.id, repository=repository)
        result = run_agent_task(hypothesis_task.id, repository=repository)

        pipeline_runs = [
            run
            for run in repository.list_pipeline_runs()
            if run.program_id == campaign.program_id and run.asset == campaign.default_asset
        ]
        payload = pipeline_runs[0].payload
        assessment = payload["hypothesis_assessments"][0]
        route_fact_ref = _persisted_codebase_fact_ref(
            repository.list_campaign_codebase_facts(campaign.id),
            fact_type="route_handler",
            source_path="apps/api/routes/files.py",
            route_path="/files/{file_id}/export",
        )

        assert map_result["status"] == "completed"
        assert result["status"] == "completed"
        assert payload["hypotheses"][0]["source_facts"] == [
            {
                "fact_ref": route_fact_ref,
                "artifact_kind": "code",
                "fact_type": "route_handler",
                "route_method": "GET",
                "route_path": "/files/{file_id}/export",
                "source_path": "apps/api/routes/files.py",
                "symbol_name": "export_file",
            }
        ]
        assert payload["target_model"]["source_fact_refs"] == [
            route_fact_ref
        ]
        assert assessment["exploit_chain"]["primitives"] == ["GET /files/{file_id}/export"]
    finally:
        session.close()


def test_run_agent_task_ignores_comment_and_string_calls_when_mapping_code_facts():
    repository, session = build_repository()
    try:
        campaign = repository.create_campaign(
            program_id="program_example",
            name="Code fact lexical scoping campaign",
            autonomy_level="level_0_read_only",
            scope_status="in_scope",
            policy_text="Testing allowed",
            default_asset="authorized/service",
            target_classes=["idor"],
            created_by="operator",
        )
        repository.update_campaign_status(campaign.id, "running")
        map_task = repository.create_campaign_task(
            campaign_id=campaign.id,
            task_type="attack_surface_mapping",
            agent_type="target_model_agent",
            title="Map authorized local code",
            input_refs=[f"campaign:{campaign.id}"],
            payload={
                "authorized_code_files": [
                    {
                        "path": "apps/api/routes/files.py",
                        "content": '''
from fastapi import APIRouter

router = APIRouter()

@router.get("/files/{file_id}/export")
def export_file(file_id: str):
    # authorize_owner_or_admin(file_id) is intentionally not active code
    note = "send_file(file_id) should not be mapped from documentation text"
    return {"file_id": file_id, "note": note}
''',
                    }
                ],
            },
        )
        hypothesis_task = repository.create_campaign_task(
            campaign_id=campaign.id,
            task_type="hypothesis_generation",
            agent_type="hypothesis_agent",
            title="Generate lexical code-backed hypotheses",
            input_refs=[f"campaign:{campaign.id}"],
            payload={},
        )

        map_result = run_agent_task(map_task.id, repository=repository)
        result = run_agent_task(hypothesis_task.id, repository=repository)

        facts = repository.list_campaign_codebase_facts(campaign.id)
        pipeline_runs = [
            run
            for run in repository.list_pipeline_runs()
            if run.program_id == campaign.program_id and run.asset == campaign.default_asset
        ]
        payload = pipeline_runs[0].payload
        assessment = payload["hypothesis_assessments"][0]

        assert map_result["status"] == "completed"
        assert result["status"] == "completed"
        assert {fact.fact_type for fact in facts} == {"route_handler"}
        route_fact_ref = _persisted_codebase_fact_ref(
            facts,
            fact_type="route_handler",
            source_path="apps/api/routes/files.py",
            route_path="/files/{file_id}/export",
        )
        assert payload["hypotheses"][0]["source_facts"] == [
            {
                "fact_ref": route_fact_ref,
                "artifact_kind": "code",
                "fact_type": "route_handler",
                "route_method": "GET",
                "route_path": "/files/{file_id}/export",
                "source_path": "apps/api/routes/files.py",
                "symbol_name": "export_file",
            }
        ]
        assert payload["target_model"]["source_fact_refs"] == [
            route_fact_ref
        ]
        assert assessment["exploit_chain"]["primitives"] == ["GET /files/{file_id}/export"]
    finally:
        session.close()


def test_run_agent_task_does_not_attach_module_level_calls_to_route_hypotheses():
    repository, session = build_repository()
    try:
        campaign = repository.create_campaign(
            program_id="program_example",
            name="Code fact module scope campaign",
            autonomy_level="level_0_read_only",
            scope_status="in_scope",
            policy_text="Testing allowed",
            default_asset="authorized/service",
            target_classes=["idor"],
            created_by="operator",
        )
        repository.update_campaign_status(campaign.id, "running")
        map_task = repository.create_campaign_task(
            campaign_id=campaign.id,
            task_type="attack_surface_mapping",
            agent_type="target_model_agent",
            title="Map authorized local code",
            input_refs=[f"campaign:{campaign.id}"],
            payload={
                "authorized_code_files": [
                    {
                        "path": "apps/api/routes/files.py",
                        "content": """
from fastapi import APIRouter

router = APIRouter()
authorize_owner_or_admin("startup-check")
send_file("startup-check")

@router.get("/files/{file_id}/export")
def export_file(file_id: str):
    return {"file_id": file_id}
""",
                    }
                ],
            },
        )
        hypothesis_task = repository.create_campaign_task(
            campaign_id=campaign.id,
            task_type="hypothesis_generation",
            agent_type="hypothesis_agent",
            title="Generate module-scope-safe hypotheses",
            input_refs=[f"campaign:{campaign.id}"],
            payload={},
        )

        map_result = run_agent_task(map_task.id, repository=repository)
        result = run_agent_task(hypothesis_task.id, repository=repository)

        pipeline_runs = [
            run
            for run in repository.list_pipeline_runs()
            if run.program_id == campaign.program_id and run.asset == campaign.default_asset
        ]
        payload = pipeline_runs[0].payload
        assessment = payload["hypothesis_assessments"][0]
        route_fact_ref = _persisted_codebase_fact_ref(
            repository.list_campaign_codebase_facts(campaign.id),
            fact_type="route_handler",
            source_path="apps/api/routes/files.py",
            route_path="/files/{file_id}/export",
        )

        assert map_result["status"] == "completed"
        assert result["status"] == "completed"
        assert payload["hypotheses"][0]["source_facts"] == [
            {
                "fact_ref": route_fact_ref,
                "artifact_kind": "code",
                "fact_type": "route_handler",
                "route_method": "GET",
                "route_path": "/files/{file_id}/export",
                "source_path": "apps/api/routes/files.py",
                "symbol_name": "export_file",
            }
        ]
        assert payload["target_model"]["source_fact_refs"] == [
            route_fact_ref
        ]
        assert assessment["exploit_chain"]["primitives"] == ["GET /files/{file_id}/export"]
    finally:
        session.close()


def test_run_agent_task_does_not_attach_post_handler_module_calls_to_route_hypotheses():
    repository, session = build_repository()
    try:
        campaign = repository.create_campaign(
            program_id="program_example",
            name="Code fact post handler module scope campaign",
            autonomy_level="level_0_read_only",
            scope_status="in_scope",
            policy_text="Testing allowed",
            default_asset="authorized/service",
            target_classes=["idor"],
            created_by="operator",
        )
        repository.update_campaign_status(campaign.id, "running")
        map_task = repository.create_campaign_task(
            campaign_id=campaign.id,
            task_type="attack_surface_mapping",
            agent_type="target_model_agent",
            title="Map authorized local code",
            input_refs=[f"campaign:{campaign.id}"],
            payload={
                "authorized_code_files": [
                    {
                        "path": "apps/api/routes/files.py",
                        "content": """
from fastapi import APIRouter

router = APIRouter()

@router.get("/files/{file_id}/export")
def export_file(file_id: str):
    return {"file_id": file_id}

authorize_owner_or_admin("startup-check")
send_file("startup-check")
""",
                    }
                ],
            },
        )
        hypothesis_task = repository.create_campaign_task(
            campaign_id=campaign.id,
            task_type="hypothesis_generation",
            agent_type="hypothesis_agent",
            title="Generate post-handler module-scope-safe hypotheses",
            input_refs=[f"campaign:{campaign.id}"],
            payload={},
        )

        map_result = run_agent_task(map_task.id, repository=repository)
        result = run_agent_task(hypothesis_task.id, repository=repository)

        pipeline_runs = [
            run
            for run in repository.list_pipeline_runs()
            if run.program_id == campaign.program_id and run.asset == campaign.default_asset
        ]
        payload = pipeline_runs[0].payload
        assessment = payload["hypothesis_assessments"][0]
        route_fact_ref = _persisted_codebase_fact_ref(
            repository.list_campaign_codebase_facts(campaign.id),
            fact_type="route_handler",
            source_path="apps/api/routes/files.py",
            route_path="/files/{file_id}/export",
        )

        assert map_result["status"] == "completed"
        assert result["status"] == "completed"
        assert payload["hypotheses"][0]["source_facts"] == [
            {
                "fact_ref": route_fact_ref,
                "artifact_kind": "code",
                "fact_type": "route_handler",
                "route_method": "GET",
                "route_path": "/files/{file_id}/export",
                "source_path": "apps/api/routes/files.py",
                "symbol_name": "export_file",
            }
        ]
        assert payload["target_model"]["source_fact_refs"] == [
            route_fact_ref
        ]
        assert assessment["exploit_chain"]["primitives"] == ["GET /files/{file_id}/export"]
    finally:
        session.close()


def test_run_agent_task_plans_validation_against_codebase_fact_target():
    repository, session = build_repository()
    try:
        campaign = repository.create_campaign(
            program_id="program_example",
            name="Code fact validation plan campaign",
            autonomy_level="level_0_read_only",
            scope_status="in_scope",
            policy_text="Testing allowed",
            default_asset="authorized/service",
            target_classes=["idor"],
            created_by="operator",
        )
        repository.update_campaign_status(campaign.id, "running")
        map_task = repository.create_campaign_task(
            campaign_id=campaign.id,
            task_type="attack_surface_mapping",
            agent_type="target_model_agent",
            title="Map authorized local code",
            input_refs=[f"campaign:{campaign.id}"],
            payload={
                "authorized_code_files": [
                    {
                        "path": "apps/api/routes/files.py",
                        "content": """
from fastapi import APIRouter

router = APIRouter()

@router.get("/files/{file_id}/export")
def export_file(file_id: str):
    authorize_owner_or_admin(file_id)
    return send_file(file_id)
""",
                    }
                ],
            },
        )
        report_task = repository.create_campaign_task(
            campaign_id=campaign.id,
            task_type="report_chain_review",
            agent_type="report_agent",
            title="Review code-backed validation gate",
            input_refs=[f"campaign:{campaign.id}"],
            payload={"cookie": "session=secret"},
        )

        map_result = run_agent_task(map_task.id, repository=repository)
        result = run_agent_task(report_task.id, repository=repository)

        validation_runs = repository.list_campaign_validation_runs(campaign.id)
        approvals = repository.list_campaign_approval_records(campaign.id)

        assert map_result["status"] == "completed"
        assert result["status"] == "completed"
        assert len(validation_runs) == 1
        assert len(approvals) == 1
        validation_run = validation_runs[0]
        approval = approvals[0]
        facts = repository.list_campaign_codebase_facts(campaign.id)
        route_fact_ref = _persisted_codebase_fact_ref(
            facts,
            fact_type="route_handler",
            source_path="apps/api/routes/files.py",
            route_path="/files/{file_id}/export",
        )
        authz_fact_ref = _persisted_codebase_fact_ref(
            facts,
            fact_type="authz_check",
            source_path="apps/api/routes/files.py",
            symbol_name="authorize_owner_or_admin",
        )
        sink_fact_ref = _persisted_codebase_fact_ref(
            facts,
            fact_type="sensitive_sink",
            source_path="apps/api/routes/files.py",
            symbol_name="send_file",
        )

        assert validation_run.target_ref == route_fact_ref
        assert validation_run.approval_required is True
        assert validation_run.allowed_to_execute is False
        assert validation_run.safety_gate_state == "awaiting_approval"
        assert validation_run.summary == (
            "Validation is planned for mapped code fact GET /files/{file_id}/export but blocked pending durable human approval."
        )
        assert validation_run.payload == {
            "approval_record_id": approval.id,
            "no_live_requests": True,
            "raw_payload_processed": False,
            "source_fact_refs": [
                route_fact_ref,
                authz_fact_ref,
                sink_fact_ref,
            ],
            "target_route": "GET /files/{file_id}/export",
        }
        assert approval.requested_action == "two_account_authorization_check"
        assert approval.asset == "authorized/service"
        assert approval.plan_digest == validation_run.plan_digest
        assert "session=secret" not in str(validation_runs + approvals)
    finally:
        session.close()


def test_run_agent_task_prioritizes_authorization_gap_candidate_without_execution():
    repository, session = build_repository()
    try:
        campaign = repository.create_campaign(
            program_id="program_example",
            name="Authorization gap hypothesis campaign",
            autonomy_level="level_0_read_only",
            scope_status="in_scope",
            policy_text="Testing allowed",
            default_asset="authorized/service",
            target_classes=["idor"],
            created_by="operator",
        )
        repository.update_campaign_status(campaign.id, "running")
        map_task = repository.create_campaign_task(
            campaign_id=campaign.id,
            task_type="attack_surface_mapping",
            agent_type="target_model_agent",
            title="Map authorized local code",
            input_refs=[f"campaign:{campaign.id}"],
            payload={
                "authorized_code_files": [
                    {
                        "path": "apps/api/routes/files.py",
                        "content": """
from fastapi import APIRouter

router = APIRouter()

@router.get("/files/{file_id}/export")
def export_file(file_id: str):
    return send_file(file_id)
""",
                    }
                ],
            },
        )
        hypothesis_task = repository.create_campaign_task(
            campaign_id=campaign.id,
            task_type="hypothesis_generation",
            agent_type="hypothesis_agent",
            title="Generate code-backed hypotheses",
            input_refs=[f"campaign:{campaign.id}"],
            payload={"authorization": "Bearer secret-token"},
        )

        map_result = run_agent_task(map_task.id, repository=repository)
        result = run_agent_task(hypothesis_task.id, repository=repository)

        facts = repository.list_campaign_codebase_facts(campaign.id)
        pipeline_runs = [
            run
            for run in repository.list_pipeline_runs()
            if run.program_id == campaign.program_id and run.asset == campaign.default_asset
        ]

        assert map_result["status"] == "completed"
        assert result["status"] == "completed"
        assert {fact.fact_type for fact in facts} == {
            "authorization_gap_candidate",
            "route_handler",
            "sensitive_sink",
        }
        assert len(pipeline_runs) == 1

        payload = pipeline_runs[0].payload
        assessment = payload["hypothesis_assessments"][0]
        hunt_queue = payload["autonomous_hunt_queue"][0]

        assert assessment["candidate_status"] == "needs_human_review"
        assert assessment["validation_plan"]["human_approval_required"] is True
        assert {
            fact["fact_type"] for fact in assessment["hypothesis"]["source_facts"]
        } == {
            "authorization_gap_candidate",
            "route_handler",
            "sensitive_sink",
        }
        persisted_gap = next(
            fact for fact in facts if fact.fact_type == "authorization_gap_candidate"
        )
        assert persisted_gap.payload["root_cause"] == "missing_object_ownership_check"
        assert persisted_gap.payload["security_invariant"] == (
            "Object-level actions must verify requester ownership or role before sensitive sinks run."
        )
        assert persisted_gap.payload["sink_symbols"] == ["send_file"]
        source_gap = next(
            fact
            for fact in assessment["hypothesis"]["source_facts"]
            if fact["fact_type"] == "authorization_gap_candidate"
        )
        assert source_gap["root_cause"] == "missing_object_ownership_check"
        assert source_gap["security_invariant"] == (
            "Object-level actions must verify requester ownership or role before sensitive sinks run."
        )
        assert source_gap["sink_symbols"] == ["send_file"]
        assert source_gap["sink_count"] == 1
        assert source_gap["review_state"] == "needs_human_review"
        assert source_gap["execution_allowed"] is False
        assert source_gap["validation_allowed"] is False
        assert source_gap["report_submission_allowed"] is False
        assert "missing_handler_authz_check" in assessment["exploit_chain"]["primitives"]
        assert hunt_queue["status"] == "awaiting_evidence_review"
        assert hunt_queue["next_action"] == "resolve_evidence_gaps"
        assert hunt_queue["required_evidence"] == ["independent_refutation_or_static_rule"]
        assert hunt_queue["quality_gate_reasons"] == ["required_evidence_missing"]
        assert hunt_queue["raw_priority_score"] > hunt_queue["priority_score"]
        assert hunt_queue["human_approval_required"] is True
        assert hunt_queue["blocked_actions"] == [
            "execute_live_validation",
            "touch_real_user_data",
            "submit_report",
            "bypass_scope_guard",
        ]
        assert "secret-token" not in str(facts + pipeline_runs)
        assert "Bearer" not in str(facts + pipeline_runs)
    finally:
        session.close()


def test_run_agent_task_boosts_authorization_gap_candidate_over_mapped_authz_route():
    repository, session = build_repository()
    try:
        campaign = repository.create_campaign(
            program_id="program_example",
            name="Authorization gap triage campaign",
            autonomy_level="level_0_read_only",
            scope_status="in_scope",
            policy_text="Testing allowed",
            default_asset="authorized/service",
            target_classes=["idor"],
            created_by="operator",
        )
        repository.update_campaign_status(campaign.id, "running")
        map_task = repository.create_campaign_task(
            campaign_id=campaign.id,
            task_type="attack_surface_mapping",
            agent_type="target_model_agent",
            title="Map authorized local code",
            input_refs=[f"campaign:{campaign.id}"],
            payload={
                "authorized_code_files": [
                    {
                        "path": "apps/api/routes/files.py",
                        "content": """
from fastapi import APIRouter

router = APIRouter()

@router.get("/files/{file_id}/export")
def export_file(file_id: str):
    return send_file(file_id)

@router.post("/teams/{team_id}/invites")
def create_team_invite(team_id: str):
    require_role(team_id, "owner")
    return update_role(team_id)
""",
                    }
                ],
                "authorization": "Bearer secret-token",
            },
        )
        hypothesis_task = repository.create_campaign_task(
            campaign_id=campaign.id,
            task_type="hypothesis_generation",
            agent_type="hypothesis_agent",
            title="Generate gap-aware hypotheses",
            input_refs=[f"campaign:{campaign.id}"],
            payload={},
        )

        run_agent_task(map_task.id, repository=repository)
        result = run_agent_task(hypothesis_task.id, repository=repository)

        pipeline_runs = [
            run
            for run in repository.list_pipeline_runs()
            if run.program_id == campaign.program_id and run.asset == campaign.default_asset
        ]
        assert result["status"] == "completed"
        assert len(pipeline_runs) == 1

        payload = pipeline_runs[0].payload
        assessments = payload["hypothesis_assessments"]
        file_assessment = assessments[0]
        role_assessment = assessments[1]
        file_hunter = file_assessment["hunter_assessment"]
        role_hunter = role_assessment["hunter_assessment"]

        assert "authorization_gap_candidate" in {
            fact["fact_type"] for fact in file_assessment["hypothesis"]["source_facts"]
        }
        assert "authorization_gap_candidate" not in {
            fact["fact_type"] for fact in role_assessment["hypothesis"]["source_facts"]
        }
        assert "authorization_gap_candidate" in file_hunter["reasons"]
        assert file_hunter["hunter_priority_score"] > role_hunter["hunter_priority_score"]
        file_queue_item = next(
            item
            for item in payload["autonomous_hunt_queue"]
            if item["candidate_id"] == file_assessment["candidate_id"]
        )
        assert payload["autonomous_hunt_queue"][0]["candidate_id"] == role_assessment["candidate_id"]
        assert file_queue_item["status"] == "awaiting_evidence_review"
        assert file_queue_item["next_action"] == "resolve_evidence_gaps"
        assert file_queue_item["required_evidence"] == [
            "independent_refutation_or_static_rule"
        ]
        assert file_queue_item["quality_gate_reasons"] == [
            "required_evidence_missing"
        ]
        assert file_queue_item["human_approval_required"] is True
        assert file_assessment["refutation"]["questions"][0] == (
            "Can same-handler authorization evidence refute the missing access-control check candidate?"
        )
        assert file_assessment["validation_plan"]["human_approval_required"] is True
        assert "secret-token" not in str(payload)
        assert "Bearer" not in str(payload)
    finally:
        session.close()


def test_run_agent_task_blocks_out_of_scope_campaign_without_processing_payload():
    repository, session = build_repository()
    try:
        campaign = repository.create_campaign(
            program_id="program_example",
            name="Blocked worker campaign",
            autonomy_level="level_0_read_only",
            scope_status="out_of_scope",
            policy_text="Testing not allowed",
            default_asset="api.example.com",
            created_by="operator",
        )
        repository.update_campaign_status(campaign.id, "running")
        task = repository.create_campaign_task(
            campaign_id=campaign.id,
            task_type="campaign_observation",
            agent_type="orchestrator_agent",
            title="Observe",
            payload={"cookie": "session=secret"},
        )

        result = run_agent_task(task.id, repository=repository)

        assert result["status"] == "blocked"
        assert result["stop_reason"] == "scope_not_in_scope"
        updated_task = repository.list_campaign_tasks(campaign.id)[0]
        agent_run = repository.list_campaign_agent_runs(campaign.id)[0]
        assert updated_task.status == "blocked"
        assert agent_run.status == "blocked"
        assert agent_run.safety_gate_state == "blocked"
        assert "session=secret" not in str(agent_run.payload)
    finally:
        session.close()


def test_run_agent_task_blocks_existing_dispatched_run_without_duplicate_record():
    repository, session = build_repository()
    try:
        campaign = repository.create_campaign(
            program_id="program_example",
            name="Blocked reconcile campaign",
            autonomy_level="level_0_read_only",
            scope_status="out_of_scope",
            policy_text="Testing not allowed",
            default_asset="api.example.com",
            created_by="operator",
        )
        repository.update_campaign_status(campaign.id, "running")
        task = repository.create_campaign_task(
            campaign_id=campaign.id,
            task_type="campaign_observation",
            agent_type="orchestrator_agent",
            title="Observe",
            payload={"cookie": "session=secret"},
        )
        dispatched_run = repository.save_agent_run(
            campaign_id=campaign.id,
            task_id=task.id,
            agent_type=task.agent_type,
            status="dispatched",
            input_refs=[f"campaign_task:{task.id}"],
            output_refs=[],
            tool_calls=[],
            safety_gate_state="allowed",
            stop_reason=None,
            payload={"dispatch_contract": "id_only"},
        )

        result = run_agent_task(task.id, repository=repository)

        agent_runs = repository.list_campaign_agent_runs(campaign.id)
        assert result["status"] == "blocked"
        assert result["agent_run_id"] == dispatched_run.id
        assert len(agent_runs) == 1
        assert agent_runs[0].status == "blocked"
        assert agent_runs[0].safety_gate_state == "blocked"
        assert agent_runs[0].stop_reason == "scope_not_in_scope"
        assert "session=secret" not in str(agent_runs[0].payload)
    finally:
        session.close()


def test_run_agent_task_blocks_paused_campaign_with_specific_stop_reason():
    repository, session = build_repository()
    try:
        campaign = repository.create_campaign(
            program_id="program_example",
            name="Paused worker campaign",
            autonomy_level="level_0_read_only",
            scope_status="in_scope",
            policy_text="Testing paused",
            default_asset="api.example.com",
            created_by="operator",
        )
        repository.update_campaign_status(campaign.id, "paused")
        task = repository.create_campaign_task(
            campaign_id=campaign.id,
            task_type="attack_surface_mapping",
            agent_type="target_model_agent",
            title="Map surface",
            payload={"cookie": "session=secret"},
        )

        result = run_agent_task(task.id, repository=repository)

        updated_task = repository.list_campaign_tasks(campaign.id)[0]
        agent_run = repository.list_campaign_agent_runs(campaign.id)[0]
        assert result["status"] == "blocked"
        assert result["stop_reason"] == "campaign_paused"
        assert updated_task.status == "blocked"
        assert agent_run.status == "blocked"
        assert agent_run.stop_reason == "campaign_paused"
        assert repository.list_campaign_codebase_maps(campaign.id) == []
        assert "session=secret" not in str(agent_run.payload)
    finally:
        session.close()


def test_run_agent_task_allows_read_only_work_when_validation_budget_is_zero():
    repository, session = build_repository()
    try:
        campaign = repository.create_campaign(
            program_id="program_example",
            name="Budget exhausted worker campaign",
            autonomy_level="level_0_read_only",
            scope_status="in_scope",
            policy_text="Testing budget",
            default_asset="api.example.com",
            created_by="operator",
        )
        repository.update_campaign_status(campaign.id, "running")
        repository.upsert_campaign_budget(
            campaign_id=campaign.id,
            time_budget_minutes=None,
            token_budget=None,
            tool_call_budget=None,
            validation_budget=0,
        )
        task = repository.create_campaign_task(
            campaign_id=campaign.id,
            task_type="attack_surface_mapping",
            agent_type="target_model_agent",
            title="Map surface",
            payload={"cookie": "session=secret"},
        )

        result = run_agent_task(task.id, repository=repository)

        updated_task = repository.list_campaign_tasks(campaign.id)[0]
        agent_run = repository.list_campaign_agent_runs(campaign.id)[0]
        assert result["status"] == "completed"
        assert result["stop_reason"] is None
        assert updated_task.status == "completed"
        assert agent_run.status == "completed"
        assert repository.list_campaign_codebase_maps(campaign.id)
        assert "session=secret" not in str(agent_run.payload)
    finally:
        session.close()


def test_run_agent_task_blocks_recorded_token_budget_without_materializing_artifacts():
    repository, session = build_repository()
    try:
        campaign = repository.create_campaign(
            program_id="program_example",
            name="Token exhausted worker campaign",
            autonomy_level="level_0_read_only",
            scope_status="in_scope",
            policy_text="Testing budget",
            default_asset="api.example.com",
            created_by="operator",
        )
        repository.update_campaign_status(campaign.id, "running")
        repository.upsert_campaign_budget(
            campaign_id=campaign.id,
            time_budget_minutes=None,
            token_budget=100,
            tool_call_budget=None,
            validation_budget=None,
        )
        repository.save_agent_run(
            campaign_id=campaign.id,
            task_id=None,
            agent_type="semantic_audit_agent",
            status="completed",
            safety_gate_state="allowed",
            stop_reason=None,
            payload={"token_usage": {"total_tokens": 100}},
        )
        task = repository.create_campaign_task(
            campaign_id=campaign.id,
            task_type="attack_surface_mapping",
            agent_type="target_model_agent",
            title="Map surface",
        )

        result = run_agent_task(task.id, repository=repository)

        assert result["status"] == "blocked"
        assert result["stop_reason"] == "budget_exhausted"
        assert repository.list_campaign_codebase_maps(campaign.id) == []
    finally:
        session.close()


def test_run_agent_task_blocks_consumed_tool_call_budget_without_materializing_artifacts():
    repository, session = build_repository()
    try:
        campaign = repository.create_campaign(
            program_id="program_example",
            name="Consumed tool budget worker campaign",
            autonomy_level="level_0_read_only",
            scope_status="in_scope",
            policy_text="Testing budget",
            default_asset="api.example.com",
            created_by="operator",
        )
        repository.update_campaign_status(campaign.id, "running")
        repository.upsert_campaign_budget(
            campaign_id=campaign.id,
            time_budget_minutes=None,
            token_budget=None,
            tool_call_budget=1,
            validation_budget=None,
        )
        first_task = repository.create_campaign_task(
            campaign_id=campaign.id,
            task_type="campaign_observation",
            agent_type="orchestrator_agent",
            title="Observe",
        )
        repository.save_agent_run(
            campaign_id=campaign.id,
            task_id=first_task.id,
            agent_type=first_task.agent_type,
            status="completed",
            input_refs=[f"campaign_task:{first_task.id}"],
            output_refs=[],
            tool_calls=[],
            safety_gate_state="allowed",
            stop_reason=None,
            payload={"raw_payload_processed": False},
        )
        second_task = repository.create_campaign_task(
            campaign_id=campaign.id,
            task_type="attack_surface_mapping",
            agent_type="target_model_agent",
            title="Map surface",
            payload={"cookie": "session=secret"},
        )

        result = run_agent_task(second_task.id, repository=repository)

        updated_tasks = repository.list_campaign_tasks(campaign.id)
        agent_runs = repository.list_campaign_agent_runs(campaign.id)
        blocked_run = next(run for run in agent_runs if run.task_id == second_task.id)
        assert result["status"] == "blocked"
        assert result["stop_reason"] == "budget_exhausted"
        assert len(agent_runs) == 2
        assert blocked_run.status == "blocked"
        assert blocked_run.safety_gate_state == "blocked"
        assert blocked_run.stop_reason == "budget_exhausted"
        assert next(task for task in updated_tasks if task.id == second_task.id).status == "blocked"
        assert repository.list_campaign_codebase_maps(campaign.id) == []
        assert "session=secret" not in str(blocked_run.payload)
    finally:
        session.close()


def test_run_agent_task_materializes_read_only_research_artifacts_by_task_type():
    repository, session = build_repository()
    try:
        campaign = repository.create_campaign(
            program_id="program_example",
            name="Artifact worker campaign",
            autonomy_level="level_0_read_only",
            scope_status="in_scope",
            policy_text="Testing allowed. Authorization: Bearer secret-token",
            default_asset="api.example.com",
            target_classes=["idor"],
            created_by="operator",
        )
        repository.update_campaign_status(campaign.id, "running")
        tasks = [
            repository.create_campaign_task(
                campaign_id=campaign.id,
                task_type="attack_surface_mapping",
                agent_type="target_model_agent",
                title="Map attack surface",
                payload={"raw": "Authorization: Bearer secret-token"},
            ),
            repository.create_campaign_task(
                campaign_id=campaign.id,
                task_type="hypothesis_generation",
                agent_type="hypothesis_agent",
                title="Generate hypotheses",
                payload={"cookie": "session=secret"},
            ),
            repository.create_campaign_task(
                campaign_id=campaign.id,
                task_type="report_chain_review",
                agent_type="report_agent",
                title="Review report chain",
                payload={"api_key": "secret-token"},
            ),
        ]

        results = [run_agent_task(task.id, repository=repository) for task in tasks]

        assert [result["status"] for result in results] == ["completed", "completed", "completed"]

        codebase_maps = repository.list_campaign_codebase_maps(campaign.id)
        codebase_facts = repository.list_campaign_codebase_facts(campaign.id)
        scanner_runs = repository.list_campaign_scanner_runs(campaign.id)
        pipeline_runs = [
            run
            for run in repository.list_pipeline_runs()
            if run.program_id == campaign.program_id and run.asset == campaign.default_asset
        ]
        validation_runs = repository.list_campaign_validation_runs(campaign.id)
        approvals = repository.list_campaign_approval_records(campaign.id)

        assert len(codebase_maps) == 1
        assert len(codebase_facts) == 1
        assert len(scanner_runs) == 1
        assert codebase_maps[0].safety_gate_state == "allowed"
        assert codebase_facts[0].authz_hint == "authorization_boundary_candidate"
        assert scanner_runs[0].tool_name == "mythos_static_mapper"

        assert len(pipeline_runs) == 1
        assert pipeline_runs[0].hypothesis_count == 1
        assert pipeline_runs[0].blocked_count == 1
        assert pipeline_runs[0].payload["campaign_id"] == campaign.id
        assert pipeline_runs[0].payload["source_task_id"] == tasks[1].id
        worker_assessment = pipeline_runs[0].payload["hypothesis_assessments"][0]
        assert worker_assessment["refutation"]["questions"]
        assert worker_assessment["exploit_chain"]["primitives"]
        assert worker_assessment["exploit_chain"]["preconditions"]
        assert worker_assessment["exploit_chain"]["safety_notes"] == [
            "non_executable_chain_summary",
            "no_payloads_or_requests",
            "human_review_required",
        ]
        linked_preview_stages = [
            stage
            for stage in repository.list_campaign_pipeline_stages(campaign.id)
            if stage.pipeline_run_id == pipeline_runs[0].id
        ]
        assert len(linked_preview_stages) == 1
        assert linked_preview_stages[0].stage_key == "campaign_report_preview"
        assert linked_preview_stages[0].status == "awaiting_review"
        assert linked_preview_stages[0].safety_gate_state == "awaiting_review"

        assert len(validation_runs) == 1
        assert validation_runs[0].approval_required is True
        assert validation_runs[0].allowed_to_execute is False
        assert validation_runs[0].status == "awaiting_approval"
        assert len(approvals) == 1
        assert approvals[0].status == "pending"

        output_refs = [
            ref
            for task in repository.list_campaign_tasks(campaign.id)
            for ref in task.output_refs
        ]
        assert any(ref.startswith("codebase_map:") for ref in output_refs)
        assert any(ref.startswith("pipeline_run:") for ref in output_refs)
        assert any(ref.startswith("validation_run:") for ref in output_refs)
        assert "secret-token" not in str(
            codebase_maps
            + codebase_facts
            + scanner_runs
            + pipeline_runs
            + validation_runs
            + approvals
        )
        assert "session=secret" not in str(
            codebase_maps
            + codebase_facts
            + scanner_runs
            + pipeline_runs
            + validation_runs
            + approvals
        )
    finally:
        session.close()
