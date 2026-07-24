from __future__ import annotations

from datetime import UTC, datetime, timedelta
from hashlib import sha256
import json

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

import app.autonomous_research_runtime as autonomous_research_runtime
import app.candidate_hunter_evidence as candidate_hunter_evidence
from app.candidate_hunter_evidence import (
    materialize_evidence_inspection_task,
    run_evidence_inspection_task,
)
from app.candidate_hunter_loop import (
    advance_candidate_hunter_round,
    build_candidate_hunter_observations,
    run_candidate_hunter_loop,
)
from app.db import Base
from app.db_models import AgentRunRecord
from app.repository import DatabaseRepository
from app.worker.tasks import run_agent_task


def _repository() -> tuple[DatabaseRepository, Session]:
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    session = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)()
    return DatabaseRepository(session), session


def _safe_payload() -> dict[str, bool]:
    return {
        "execution_allowed": False,
        "dispatch_allowed": False,
        "validation_allowed": False,
        "candidate_promotion_allowed": False,
        "report_submission_allowed": False,
        "raw_payload_processed": False,
    }


def test_evidence_collection_accepts_all_mapped_source_suffixes(tmp_path):
    source_names = [
        "routes.py",
        "routes.ts",
        "routes.tsx",
        "routes.mts",
        "routes.cts",
        "routes.java",
        "routes.go",
        "routes.rb",
        "routes.cs",
        "routes.php",
        "routes.kt",
        "routes.rs",
        "routes.scala",
    ]
    for source_name in source_names:
        (tmp_path / source_name).write_text("local source\n", encoding="utf-8")

    files = candidate_hunter_evidence._collect_authorized_evidence_files(tmp_path)

    assert [item["path"] for item in files] == sorted(source_names)


def _source_snapshot(
    code: str,
    *,
    extra_files: dict[str, str] | None = None,
) -> tuple[str, list[dict[str, str]]]:
    files = {"routes.py": code, **(extra_files or {})}
    manifest = [
        {
            "source_path": source_path,
            "content_digest": sha256(content.encode("utf-8")).hexdigest(),
        }
        for source_path, content in sorted(files.items())
    ]
    digest = sha256(
        json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    return digest, manifest


def test_materialize_evidence_task_reuses_one_task_for_one_request_stage():
    repository, session = _repository()
    try:
        pipeline_run = repository.save_pipeline_run(
            asset="C:/authorized/project",
            policy_text="Synthetic local policy.",
            scope_status="in_scope",
            hypothesis_count=1,
            blocked_count=0,
            report_title=None,
            payload={"hypotheses": []},
        )
        campaign = repository.create_campaign(
            program_id=None,
            name="Candidate Hunter",
            autonomy_level="level_0_read_only",
            scope_status="in_scope",
            policy_text="Synthetic local policy.",
            default_asset=pipeline_run.asset,
            allowed_tools=["candidate_hunter_local_evidence_inspector"],
            created_by="candidate_hunter_loop",
            payload={
                "pipeline_run_id": pipeline_run.id,
                "source_snapshot_digest": "a" * 64,
                **_safe_payload(),
            },
        )
        owner_task = repository.create_campaign_task(
            campaign_id=campaign.id,
            task_type="candidate_hunter_loop",
            agent_type="candidate_hunter",
            title="Candidate Hunter owner",
            input_refs=[f"pipeline_run:{pipeline_run.id}"],
            payload=_safe_payload(),
        )
        request_stage = repository.save_pipeline_stage(
            pipeline_run_id=pipeline_run.id,
            campaign_id=campaign.id,
            task_id=owner_task.id,
            stage_key="candidate_hunter_evidence_request",
            stage_order=2,
            status="completed",
            input_refs=[f"pipeline_run:{pipeline_run.id}"],
            output_refs=[],
            safety_gate_state="safe",
            stop_reason=None,
            payload={
                "schema_version": "candidate_hunter_loop_v1",
                "round": 1,
                "state_digest": "b" * 64,
                "idempotency_key": "c" * 64,
                "evidence_requests": [
                    {
                        "candidate_id": "H-001",
                        "candidate_key": f"{pipeline_run.id}:H-001",
                        "requested_artifact_kinds": ["code"],
                        "refutation_questions": [
                            "Does a local ownership guard run before the sink?"
                        ],
                        "inspection_targets": [
                            {
                                "artifact_kind": "code",
                                "route": {
                                    "method": "GET",
                                    "path": "/records/{record_id}",
                                },
                                "symbols": ["read_record"],
                            }
                        ],
                    }
                ],
                **_safe_payload(),
            },
        )

        first = materialize_evidence_inspection_task(
            repository=repository,
            pipeline_run=pipeline_run,
            campaign=campaign,
            owner_task=owner_task,
            evidence_request_stage=request_stage,
        )
        second = materialize_evidence_inspection_task(
            repository=repository,
            pipeline_run=pipeline_run,
            campaign=campaign,
            owner_task=owner_task,
            evidence_request_stage=request_stage,
        )

        assert first.id == second.id
        assert first.task_type == "candidate_hunter_evidence_inspection"
        assert first.agent_type == "candidate_hunter_evidence_specialist"
        assert first.status == "queued"
        assert first.input_refs == [
            f"pipeline_run:{pipeline_run.id}",
            f"pipeline_stage:{request_stage.id}",
        ]
        assert first.payload["state_digest"] == "b" * 64
        assert first.payload["candidate_ids"] == ["H-001"]
        assert all(first.payload[field] is False for field in _safe_payload())
        evidence_tasks = [
            task
            for task in repository.list_campaign_tasks(campaign.id)
            if task.task_type == "candidate_hunter_evidence_inspection"
        ]
        assert [task.id for task in evidence_tasks] == [first.id]
    finally:
        session.close()


def test_leased_evidence_result_clears_execution_claim():
    repository, session = _repository()
    try:
        pipeline_run = repository.save_pipeline_run(
            asset="C:/authorized/project",
            policy_text="Synthetic local policy.",
            scope_status="in_scope",
            hypothesis_count=1,
            blocked_count=0,
            report_title=None,
            payload={"hypotheses": []},
        )
        campaign = repository.create_campaign(
            program_id=None,
            name="Leased evidence completion",
            autonomy_level="level_0_read_only",
            scope_status="in_scope",
            policy_text="Synthetic local policy.",
            default_asset=pipeline_run.asset,
            created_by="candidate_hunter_loop",
            payload=_safe_payload(),
        )
        task = repository.create_campaign_task(
            campaign_id=campaign.id,
            task_type="candidate_hunter_evidence_inspection",
            agent_type="candidate_hunter_evidence_specialist",
            title="Inspect authorized local evidence",
            input_refs=[f"pipeline_run:{pipeline_run.id}"],
            payload={
                "schema_version": "candidate_hunter_evidence_task_v1",
                "execution_lease_required": True,
                "pipeline_run_id": pipeline_run.id,
                "evidence_request_stage_id": "pipeline_stage_evidence_request",
                "owner_task_id": "campaign_task_owner",
                "round": 1,
                "state_digest": "b" * 64,
                "source_snapshot_digest": "a" * 64,
                **_safe_payload(),
            },
        )
        claim_id = "agent_run_leased_evidence"
        dispatched = repository.mark_campaign_task_dispatched(
            task.id,
            execution_claim_id=claim_id,
            now=datetime.now(UTC),
        )
        assert dispatched is not None
        claimed = repository.claim_campaign_task_execution(task.id)
        assert claimed is not None
        agent_run = repository.session.get(AgentRunRecord, claim_id)
        assert agent_run is not None

        result_stage = candidate_hunter_evidence._commit_evidence_result(
            repository=repository,
            task=claimed,
            agent_run=agent_run,
            context={"pipeline_run": pipeline_run, "campaign": campaign},
            payload={
                "round": 1,
                "idempotency_key": "evidence-result-idempotency",
            },
        )
        persisted_task = repository.session.get(type(task), task.id)
        persisted_run = repository.session.get(type(agent_run), agent_run.id)

        assert result_stage is not None
        assert persisted_task is not None
        assert persisted_task.status == "completed"
        assert persisted_task.execution_claim_id is None
        assert persisted_task.execution_lease_expires_at is None
        assert persisted_run is not None
        assert persisted_run.status == "completed"
        assert persisted_run.output_refs == [f"pipeline_stage:{result_stage.id}"]
    finally:
        session.close()


def test_leased_evidence_recovers_an_existing_canonical_result_stage():
    repository, session = _repository()
    try:
        pipeline_run = repository.save_pipeline_run(
            asset="C:/authorized/project",
            policy_text="Synthetic local policy.",
            scope_status="in_scope",
            hypothesis_count=1,
            blocked_count=0,
            report_title=None,
            payload={"hypotheses": []},
        )
        campaign = repository.create_campaign(
            program_id=None,
            name="Leased evidence recovery",
            autonomy_level="level_0_read_only",
            scope_status="in_scope",
            policy_text="Synthetic local policy.",
            default_asset=pipeline_run.asset,
            created_by="candidate_hunter_loop",
            payload=_safe_payload(),
        )
        task = repository.create_campaign_task(
            campaign_id=campaign.id,
            task_type="candidate_hunter_evidence_inspection",
            agent_type="candidate_hunter_evidence_specialist",
            title="Recover authorized local evidence",
            input_refs=[f"pipeline_run:{pipeline_run.id}"],
            payload={
                "schema_version": "candidate_hunter_evidence_task_v1",
                "execution_lease_required": True,
                "pipeline_run_id": pipeline_run.id,
                "evidence_request_stage_id": "pipeline_stage_evidence_request",
                "owner_task_id": "campaign_task_owner",
                "round": 1,
                "state_digest": "b" * 64,
                "source_snapshot_digest": "a" * 64,
                **_safe_payload(),
            },
        )
        claim_id = "agent_run_recovered_evidence"
        assert (
            repository.mark_campaign_task_dispatched(
                task.id,
                execution_claim_id=claim_id,
                now=datetime.now(UTC),
            )
            is not None
        )
        claimed = repository.claim_campaign_task_execution(task.id)
        assert claimed is not None
        result_stage = repository.save_pipeline_stage(
            pipeline_run_id=pipeline_run.id,
            campaign_id=campaign.id,
            task_id=task.id,
            stage_key="candidate_hunter_evidence_result",
            stage_order=5,
            status="completed",
            input_refs=task.input_refs,
            output_refs=[],
            safety_gate_state="safe",
            stop_reason=None,
            payload={
                "schema_version": candidate_hunter_evidence.RESULT_SCHEMA_VERSION,
                "evidence_task_id": task.id,
                "evidence_request_stage_id": "pipeline_stage_evidence_request",
                "state_digest": "b" * 64,
                "source_snapshot_digest": "a" * 64,
                "complete": True,
                "new_facts": [],
                "candidate_state_updates": [],
                "idempotency_key": candidate_hunter_evidence._result_idempotency_key(
                    pipeline_run_id=pipeline_run.id,
                    task_id=task.id,
                    state_digest="b" * 64,
                    source_snapshot_digest="a" * 64,
                ),
                **_safe_payload(),
            },
        )

        recovered = run_evidence_inspection_task(repository=repository, task_id=task.id)
        persisted_task = repository.session.get(type(task), task.id)
        persisted_run = repository.session.get(AgentRunRecord, claim_id)

        assert recovered == {
            "status": "completed",
            "task_id": task.id,
            "result_stage_id": result_stage.id,
            "stop_reason": None,
        }
        assert persisted_task is not None
        assert persisted_task.status == "completed"
        assert persisted_task.execution_claim_id is None
        assert persisted_task.execution_lease_expires_at is None
        assert persisted_run is not None
        assert persisted_run.status == "completed"
        assert persisted_run.output_refs == [f"pipeline_stage:{result_stage.id}"]
    finally:
        session.close()


def test_evidence_inspection_persists_one_canonical_read_only_result(tmp_path):
    repository, session = _repository()
    try:
        code = '''
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
        (tmp_path / "routes.py").write_text(code, encoding="utf-8")
        java_code = "class Record { String id; }\n"
        (tmp_path / "Record.java").write_text(java_code, encoding="utf-8")
        source_snapshot_digest, source_manifest = _source_snapshot(
            code,
            extra_files={"Record.java": java_code},
        )
        pipeline_run = repository.save_pipeline_run(
            asset=str(tmp_path),
            policy_text="Synthetic local policy.",
            scope_status="in_scope",
            hypothesis_count=1,
            blocked_count=0,
            report_title=None,
            payload={"hypotheses": []},
        )
        campaign = repository.create_campaign(
            program_id=None,
            name="Candidate Hunter",
            autonomy_level="level_0_read_only",
            scope_status="in_scope",
            policy_text="Synthetic local policy.",
            default_asset=pipeline_run.asset,
            allowed_tools=["candidate_hunter_local_evidence_inspector"],
            created_by="candidate_hunter_loop",
            payload={
                "pipeline_run_id": pipeline_run.id,
                "source_snapshot_digest": source_snapshot_digest,
                "source_manifest": source_manifest,
                "inspector_tool_allowlist": [
                    "candidate_hunter_local_evidence_inspector"
                ],
                "saved_scope_guard": {
                    "scope_status": "in_scope",
                    "authorized_local_root": str(tmp_path),
                },
                **_safe_payload(),
            },
        )
        owner_task = repository.create_campaign_task(
            campaign_id=campaign.id,
            task_type="candidate_hunter_loop",
            agent_type="candidate_hunter",
            title="Candidate Hunter owner",
            input_refs=[f"pipeline_run:{pipeline_run.id}"],
            payload=_safe_payload(),
        )
        snapshot_state = {
            "candidate_id": "H-001",
            "candidate_key": f"{pipeline_run.id}:H-001",
            "vuln_type": "authorization",
            "root_cause_id": "missing_object_ownership_check:read_record",
            "route": {"method": "GET", "path": "/records/{record_id}"},
            "source_fact_refs": [
                "scope:scope_context",
                "policy:policy_context",
                "code:routes.py:read_record",
                "api:GET:/records/{record_id}",
                "har:har_context",
            ],
            "observed_artifact_kinds": ["scope", "policy", "code", "api", "har"],
            "required_artifact_kinds": ["scope", "policy", "code", "api", "har"],
            "evidence_trace_status": "needs_evidence",
            "priority_score": 80,
            "gap_evidence_ref": "code:routes.py:read_record",
            "shared_root": "read_record",
            "shared_root_evidence_ref": "code:routes.py:read_record",
            "reanalysis_status": "pending",
        }
        repository.save_pipeline_stage(
            pipeline_run_id=pipeline_run.id,
            campaign_id=campaign.id,
            task_id=owner_task.id,
            stage_key="candidate_hunter_snapshot",
            stage_order=1,
            status="completed",
            input_refs=[f"pipeline_run:{pipeline_run.id}"],
            output_refs=[],
            safety_gate_state="safe",
            stop_reason=None,
            payload={
                "schema_version": "candidate_hunter_loop_v1",
                "round": 1,
                "state_digest": "b" * 64,
                "idempotency_key": "snapshot" * 8,
                "snapshot_candidates": [snapshot_state],
                "prior_decisions": [],
                **_safe_payload(),
            },
        )
        request_stage = repository.save_pipeline_stage(
            pipeline_run_id=pipeline_run.id,
            campaign_id=campaign.id,
            task_id=owner_task.id,
            stage_key="candidate_hunter_evidence_request",
            stage_order=2,
            status="completed",
            input_refs=[f"pipeline_run:{pipeline_run.id}"],
            output_refs=[],
            safety_gate_state="safe",
            stop_reason=None,
            payload={
                "schema_version": "candidate_hunter_loop_v1",
                "round": 1,
                "state_digest": "b" * 64,
                "idempotency_key": "request" * 9 + "r",
                "evidence_requests": [
                    {
                        "candidate_id": "H-001",
                        "candidate_key": f"{pipeline_run.id}:H-001",
                        "requested_artifact_kinds": ["code"],
                        "refutation_questions": [
                            "Does a local ownership guard run before the sink?"
                        ],
                        "inspection_targets": [
                            {
                                "artifact_kind": "code",
                                "route": {
                                    "method": "GET",
                                    "path": "/records/{record_id}",
                                },
                                "symbols": ["read_record"],
                            }
                        ],
                    }
                ],
                **_safe_payload(),
            },
        )
        task = materialize_evidence_inspection_task(
            repository=repository,
            pipeline_run=pipeline_run,
            campaign=campaign,
            owner_task=owner_task,
            evidence_request_stage=request_stage,
        )

        first = run_evidence_inspection_task(repository=repository, task_id=task.id)
        second = run_evidence_inspection_task(repository=repository, task_id=task.id)

        assert first["status"] == "completed"
        assert second["result_stage_id"] == first["result_stage_id"]
        result_stages = [
            stage
            for stage in repository.list_pipeline_stages_for_run(pipeline_run.id)
            if stage.stage_key == "candidate_hunter_evidence_result"
        ]
        assert len(result_stages) == 1
        result_stage = result_stages[0]
        assert result_stage.status == "completed"
        assert result_stage.safety_gate_state == "safe"
        assert result_stage.payload["complete"] is True
        assert result_stage.payload["state_digest"] == "b" * 64
        assert result_stage.payload["source_snapshot_digest"] == source_snapshot_digest
        assert any(
            fact["fact_type"] == "ownership_guard"
            for fact in result_stage.payload["new_facts"]
        )
        assert result_stage.payload["candidate_state_updates"][0][
            "shared_root_kind"
        ] == ""
        assert "return send_file" not in json.dumps(result_stage.payload)
        assert repository.session.get(type(task), task.id).status == "completed"
        agent_runs = repository.list_campaign_agent_runs(campaign.id)
        assert len(agent_runs) == 1
        assert agent_runs[0].status == "completed"
    finally:
        session.close()


def test_failed_evidence_inspection_blocks_owner_once_instead_of_stranding_it(
    monkeypatch,
):
    repository, session = _repository()
    try:
        pipeline_run = repository.save_pipeline_run(
            asset="C:/authorized/project",
            policy_text="Synthetic local policy.",
            scope_status="in_scope",
            hypothesis_count=1,
            blocked_count=0,
            report_title=None,
            payload={"hypotheses": []},
        )
        campaign = repository.create_campaign(
            program_id=None,
            name="Fail-closed evidence inspection",
            autonomy_level="level_0_read_only",
            scope_status="in_scope",
            policy_text="Synthetic local policy.",
            default_asset=pipeline_run.asset,
            created_by="candidate_hunter_loop",
            payload=_safe_payload(),
        )
        owner_task = repository.create_campaign_task(
            campaign_id=campaign.id,
            task_type="candidate_refutation",
            agent_type="candidate_hunter",
            title="Candidate Hunter owner",
            input_refs=[f"pipeline_run:{pipeline_run.id}"],
            payload={
                "runtime_schema": "autonomous_research_v1",
                "source_snapshot_digest": "sha256:" + "a" * 64,
                "raw_payload_in_dispatch": False,
                **_safe_payload(),
            },
        )
        owner_task = repository.update_campaign_task_status(
            owner_task.id,
            "awaiting_evidence",
        )
        assert owner_task is not None
        evidence_task = repository.create_campaign_task(
            campaign_id=campaign.id,
            task_type="candidate_hunter_evidence_inspection",
            agent_type="candidate_hunter_evidence_specialist",
            title="Inspect authorized local evidence",
            input_refs=[f"pipeline_run:{pipeline_run.id}"],
            payload={
                "pipeline_run_id": pipeline_run.id,
                "evidence_request_stage_id": "pipeline_stage_request",
                "owner_task_id": owner_task.id,
                "round": 1,
                "state_digest": "b" * 64,
                **_safe_payload(),
            },
        )
        context = {"pipeline_run": pipeline_run, "campaign": campaign}
        monkeypatch.setattr(
            candidate_hunter_evidence,
            "_inspection_context",
            lambda _repository, _task: (context, None),
        )

        def fail_local_inspection(**_kwargs):
            raise OSError("synthetic local inspection failure")

        monkeypatch.setattr(
            candidate_hunter_evidence,
            "_build_evidence_result_payload",
            fail_local_inspection,
        )

        first = run_agent_task(evidence_task.id, repository=repository)
        second = run_agent_task(evidence_task.id, repository=repository)

        persisted_evidence = repository.session.get(type(evidence_task), evidence_task.id)
        persisted_owner = repository.session.get(type(owner_task), owner_task.id)
        attempts = [
            stage
            for stage in repository.list_pipeline_stages_for_run(pipeline_run.id)
            if stage.stage_key == "candidate_hunter_evidence_attempt"
        ]
        assert first["status"] == "blocked"
        assert first["stop_reason"] == "local_evidence_inspection_failed"
        assert second["status"] == "blocked"
        assert second["task_id"] == evidence_task.id
        assert persisted_evidence is not None
        assert persisted_evidence.status == "blocked"
        assert persisted_owner is not None
        assert persisted_owner.status == "blocked"
        assert f"campaign_task:{evidence_task.id}" in persisted_owner.output_refs
        assert len(attempts) == 1
        assert attempts[0].status == "failed"
        assert attempts[0].safety_gate_state == "blocked"
        assert repository.get_campaign(campaign.id).status == "blocked"
    finally:
        session.close()


def test_context_failure_blocks_evidence_and_owner_without_an_intermediate_commit_gap(
    monkeypatch,
):
    repository, session = _repository()
    try:
        pipeline_run = repository.save_pipeline_run(
            asset="C:/authorized/project",
            policy_text="Synthetic local policy.",
            scope_status="in_scope",
            hypothesis_count=1,
            blocked_count=0,
            report_title=None,
            payload={"hypotheses": []},
        )
        source_snapshot_digest = "a" * 64
        campaign = repository.create_campaign(
            program_id=None,
            name="Atomic evidence context failure",
            autonomy_level="level_0_read_only",
            scope_status="in_scope",
            policy_text="Synthetic local policy.",
            default_asset=pipeline_run.asset,
            created_by="candidate_hunter_loop",
            payload={
                "pipeline_run_id": pipeline_run.id,
                "source_snapshot_digest": source_snapshot_digest,
                **_safe_payload(),
            },
        )
        campaign = repository.update_campaign_status(campaign.id, "running")
        assert campaign is not None
        owner_task = repository.create_campaign_task(
            campaign_id=campaign.id,
            task_type="candidate_refutation",
            agent_type="candidate_hunter",
            title="Candidate Hunter owner",
            input_refs=[f"pipeline_run:{pipeline_run.id}"],
            payload={
                "runtime_schema": "autonomous_research_v1",
                "pipeline_run_id": pipeline_run.id,
                "source_snapshot_digest": "sha256:" + source_snapshot_digest,
                "raw_payload_in_dispatch": False,
                **_safe_payload(),
            },
        )
        owner_task = repository.update_campaign_task_status(
            owner_task.id,
            "awaiting_evidence",
        )
        assert owner_task is not None
        evidence_task = repository.create_campaign_task(
            campaign_id=campaign.id,
            task_type="candidate_hunter_evidence_inspection",
            agent_type="candidate_hunter_evidence_specialist",
            title="Inspect authorized local evidence",
            input_refs=[f"pipeline_run:{pipeline_run.id}"],
            payload={
                "schema_version": "candidate_hunter_evidence_task_v1",
                "execution_lease_required": True,
                "pipeline_run_id": pipeline_run.id,
                "evidence_request_stage_id": "pipeline_stage_request",
                "owner_task_id": owner_task.id,
                "round": 1,
                "state_digest": "b" * 64,
                "source_snapshot_digest": source_snapshot_digest,
                **_safe_payload(),
            },
        )
        monkeypatch.setattr(
            candidate_hunter_evidence,
            "_inspection_context",
            lambda _repository, _task: (None, "workspace_snapshot_changed"),
        )
        original_update = repository.update_campaign_task_status

        def fail_old_owner_only_update(task_id, status, *, output_refs=None):
            if task_id == owner_task.id and status == "blocked":
                raise RuntimeError("synthetic intermediate owner update failure")
            return original_update(task_id, status, output_refs=output_refs)

        monkeypatch.setattr(
            repository,
            "update_campaign_task_status",
            fail_old_owner_only_update,
        )

        result = run_agent_task(evidence_task.id, repository=repository)

        persisted_evidence = repository.session.get(type(evidence_task), evidence_task.id)
        persisted_owner = repository.session.get(type(owner_task), owner_task.id)
        assert result["status"] == "blocked"
        assert result["stop_reason"] == "workspace_snapshot_changed"
        assert persisted_evidence is not None
        assert persisted_evidence.status == "blocked"
        assert persisted_evidence.execution_claim_id is None
        assert persisted_evidence.execution_lease_expires_at is None
        assert persisted_owner is not None
        assert persisted_owner.status == "blocked"
        assert persisted_owner.payload["blocked_by_evidence_task_id"] == evidence_task.id
        assert persisted_owner.payload["blocked_stop_reason"] == "workspace_snapshot_changed"
    finally:
        session.close()


def test_worker_resumes_hunter_from_persisted_evidence_without_request_observations(
    tmp_path,
):
    repository, session = _repository()
    try:
        code = '''
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
        (tmp_path / "routes.py").write_text(code, encoding="utf-8")
        source_snapshot_digest, source_manifest = _source_snapshot(code)
        pipeline_run = repository.save_pipeline_run(
            asset=str(tmp_path),
            policy_text="Synthetic local policy.",
            scope_status="in_scope",
            hypothesis_count=1,
            blocked_count=0,
            report_title=None,
            payload={"hypotheses": []},
        )
        observations = build_candidate_hunter_observations(
            pipeline_run_id=pipeline_run.id,
            candidates=[
                {
                    "hypothesis_id": "H-001",
                    "vuln_type": "authorization",
                    "location": "GET /records/{record_id}",
                    "priority_score": 80,
                    "source_facts": [
                        {
                            "fact_type": "authorization_gap_candidate",
                            "artifact_kind": "code",
                            "source_path": "routes.py",
                            "symbol_name": "read_record",
                            "route_method": "GET",
                            "route_path": "/records/{record_id}",
                            "root_cause": "missing_object_ownership_check",
                        }
                    ],
                }
            ],
            code_files=[{"path": "routes.py", "content": code}],
            surface_facts=[
                {
                    "fact_type": "api_surface",
                    "artifact_kind": "api",
                    "route_method": "GET",
                    "route_path": "/records/{record_id}",
                },
                {"fact_type": "har_context", "artifact_kind": "har"},
            ],
            context_facts=[
                {"fact_type": "scope_context", "artifact_kind": "scope"},
                {"fact_type": "policy_context", "artifact_kind": "policy"},
            ],
        )

        first = run_candidate_hunter_loop(
            repository=repository,
            record=pipeline_run,
            policy_text="Synthetic local policy.",
            candidates=[],
            observations=observations,
            evidence_context={
                "source_snapshot_digest": source_snapshot_digest,
                "source_manifest": source_manifest,
                "saved_scope_guard": {
                    "scope_status": "in_scope",
                    "authorized_local_root": str(tmp_path),
                },
            },
        )

        assert first["status"] == "awaiting_evidence"
        campaign = repository.list_campaigns()[0]
        evidence_task = next(
            task
            for task in repository.list_campaign_tasks(campaign.id)
            if task.task_type == "candidate_hunter_evidence_inspection"
        )
        resumed = run_agent_task(evidence_task.id, repository=repository)

        assert resumed["status"] == "completed"
        assert resumed["round_count"] == 2
        assert resumed["final_candidates"] == []
        assert resumed["candidate_decisions"][0]["disposition"] == "refuted"
        loop_stages = [
            stage
            for stage in repository.list_pipeline_stages_for_run(pipeline_run.id)
            if stage.stage_key.startswith("candidate_hunter_")
            and stage.stage_key
            not in {
                "candidate_hunter_evidence_result",
                "candidate_hunter_evidence_attempt",
            }
        ]
        assert [stage.stage_key for stage in loop_stages] == [
            "candidate_hunter_snapshot",
            "candidate_hunter_evidence_request",
            "candidate_hunter_decision",
            "candidate_hunter_rerank",
            "candidate_hunter_snapshot",
            "candidate_hunter_evidence_request",
            "candidate_hunter_decision",
            "candidate_hunter_rerank",
        ]
    finally:
        session.close()


def test_evidence_recovery_preserves_direct_sink_kind_for_resource_scoped_deduplication():
    def snapshot(candidate_id: str, path: str, priority_score: int) -> dict[str, object]:
        return {
            "candidate_id": candidate_id,
            "candidate_key": f"run-001:{candidate_id}",
            "vuln_type": "authorization",
            "root_cause_id": "missing_object_ownership_check:download_record",
            "route": {"method": "GET", "path": path},
            "source_fact_refs": [
                "scope:scope_context",
                "policy:policy_context",
                "code:RecordsController.cs:File",
                f"api:GET:{path}",
                f"har:GET:{path}",
            ],
            "observed_artifact_kinds": ["scope", "policy", "code", "api", "har"],
            "required_artifact_kinds": ["scope", "policy", "code", "api", "har"],
            "evidence_trace_status": "traceable",
            "priority_score": priority_score,
            "gap_evidence_ref": "code:RecordsController.cs:File",
            "shared_root": "",
            "shared_root_evidence_ref": "",
            "shared_root_kind": "",
            "reanalysis_status": "pending",
        }

    def recovered(snapshot_state: dict[str, object]) -> dict[str, object]:
        observed = {
            **snapshot_state,
            "shared_root": "File",
            "shared_root_evidence_ref": "code:RecordsController.cs:File",
            "shared_root_kind": "direct_sink",
            "reanalysis_status": "completed",
        }
        update, _ = candidate_hunter_evidence._candidate_state_update(
            original=snapshot_state,
            observed=observed,
            facts_by_ref={},
            source_snapshot_digest="a" * 64,
            file_digests={},
        )
        merged = candidate_hunter_evidence._merge_result_state(
            snapshot=snapshot_state,
            update=update,
            new_fact_refs=set(),
        )

        assert update["shared_root_kind"] == "direct_sink"
        assert merged is not None
        return merged

    record = recovered(snapshot("H-record", "/records/{record_id}", 80))
    export = recovered(snapshot("H-export", "/exports/{export_id}", 70))
    legacy = snapshot("H-legacy", "/records/{record_id}/file", 60)
    legacy["shared_root"] = "File"
    legacy["shared_root_evidence_ref"] = "code:RecordsController.cs:File"
    legacy_recovered = recovered(legacy)
    assert legacy_recovered["shared_root_kind"] == "direct_sink"

    observed = {
        **legacy,
        "shared_root_kind": "direct_sink",
        "reanalysis_status": "completed",
    }
    valid_update, _ = candidate_hunter_evidence._candidate_state_update(
        original=legacy,
        observed=observed,
        facts_by_ref={},
        source_snapshot_digest="a" * 64,
        file_digests={},
    )
    invalid_snapshot = {**legacy, "shared_root_kind": 42}
    invalid_update = {**valid_update, "shared_root_kind": ["direct_sink"]}
    invalid_string_snapshot = {**legacy, "shared_root_kind": "secret"}
    invalid_string_update = {**valid_update, "shared_root_kind": "secret"}
    assert candidate_hunter_evidence._merge_result_state(
        snapshot=invalid_snapshot,
        update=valid_update,
        new_fact_refs=set(),
    ) is None
    assert candidate_hunter_evidence._merge_result_state(
        snapshot=legacy,
        update=invalid_update,
        new_fact_refs=set(),
    ) is None
    assert candidate_hunter_evidence._merge_result_state(
        snapshot=invalid_string_snapshot,
        update=valid_update,
        new_fact_refs=set(),
    ) is None
    assert candidate_hunter_evidence._merge_result_state(
        snapshot=legacy,
        update=invalid_string_update,
        new_fact_refs=set(),
    ) is None

    result = advance_candidate_hunter_round(
        pipeline_run_id="run-001",
        round_number=1,
        candidate_states=[record, export],
        observations={"candidate_states": [record, export], **_safe_payload()},
        prior_decisions=[],
    )

    assert {candidate["candidate_id"] for candidate in result["final_candidates"]} == {
        "H-record",
        "H-export",
    }
    assert {
        decision["candidate_id"]: decision["disposition"]
        for decision in result["candidate_decisions"]
    } == {"H-record": "retained", "H-export": "retained"}


@pytest.mark.parametrize("resume_path", ("worker", "scheduler"))
def test_runtime_evidence_dispatch_completes_and_resumes_owner(
    tmp_path,
    resume_path,
):
    repository, session = _repository()
    try:
        code = '''
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
        (tmp_path / "routes.py").write_text(code, encoding="utf-8")
        source_snapshot_digest, source_manifest = _source_snapshot(code)
        runtime_snapshot_digest = "sha256:" + source_snapshot_digest
        campaign = repository.create_campaign(
            program_id=None,
            name="Runtime evidence completion",
            autonomy_level="level_0_read_only",
            scope_status="in_scope",
            policy_text="Synthetic local policy.",
            default_asset=str(tmp_path),
            allowed_tools=["candidate_hunter_local_evidence_inspector"],
            created_by="candidate_hunter_loop",
            payload={
                "scope_guard_rule": {
                    "asset": str(tmp_path),
                    "scope_status": "in_scope",
                    "automation": "none",
                    "allowed_validation": [],
                    "forbidden": [],
                    "human_approval_required": True,
                },
                "source_snapshot_digest": runtime_snapshot_digest,
                "source_manifest": source_manifest,
                "saved_scope_guard": {
                    "scope_status": "in_scope",
                    "authorized_local_root": str(tmp_path),
                },
                "inspector_tool_allowlist": [
                    "candidate_hunter_local_evidence_inspector"
                ],
                **_safe_payload(),
            },
        )
        campaign = repository.update_campaign_status(campaign.id, "running")
        assert campaign is not None
        candidate = {
            "hypothesis_id": "H-001",
            "vuln_type": "authorization",
            "family": "authorization",
            "location": "GET /records/{record_id}",
            "priority_score": 80,
            "source_facts": [
                {
                    "fact_type": "authorization_gap_candidate",
                    "artifact_kind": "code",
                    "source_path": "routes.py",
                    "symbol_name": "read_record",
                    "route_method": "GET",
                    "route_path": "/records/{record_id}",
                    "root_cause": "missing_object_ownership_check",
                },
                {
                    "fact_type": "api_surface",
                    "artifact_kind": "api",
                    "route_method": "GET",
                    "route_path": "/records/{record_id}",
                },
                {"fact_type": "har_context", "artifact_kind": "har"},
            ],
        }
        pipeline_run = repository.save_pipeline_run(
            asset=str(tmp_path),
            policy_text="Synthetic local policy.",
            scope_status="in_scope",
            hypothesis_count=1,
            blocked_count=0,
            report_title=None,
            payload={"campaign_id": campaign.id, "hypotheses": [candidate]},
        )
        for task_type, agent_type, title in (
            (
                "campaign_observation",
                "orchestrator_agent",
                "Observe authorized campaign state",
            ),
            (
                "attack_surface_mapping",
                "surface_mapper_agent",
                "Map authorized attack surface",
            ),
        ):
            prerequisite_task = repository.create_campaign_task(
                campaign_id=campaign.id,
                task_type=task_type,
                agent_type=agent_type,
                title=title,
                input_refs=[f"pipeline_run:{pipeline_run.id}"],
                payload=autonomous_research_runtime._runtime_task_payload(
                    campaign_id=campaign.id,
                    task_type=task_type,
                    source_snapshot_digest=runtime_snapshot_digest,
                    pipeline_run_id=pipeline_run.id,
                ),
            )
            assert (
                run_agent_task(prerequisite_task.id, repository=repository)["status"]
                == "completed"
            )
        chain_task = repository.create_campaign_task(
            campaign_id=campaign.id,
            task_type="exploit_chain_reasoning",
            agent_type="exploit_chain_reasoning_agent",
            title="Build local exploit-chain projection",
            input_refs=[f"pipeline_run:{pipeline_run.id}"],
            payload=autonomous_research_runtime._runtime_task_payload(
                campaign_id=campaign.id,
                task_type="exploit_chain_reasoning",
                source_snapshot_digest=runtime_snapshot_digest,
                pipeline_run_id=pipeline_run.id,
            ),
        )

        chain_result = run_agent_task(chain_task.id, repository=repository)

        assert chain_result["status"] == "completed"
        variant_task = repository.create_campaign_task(
            campaign_id=campaign.id,
            task_type="variant_analysis",
            agent_type="variant_analysis_agent",
            title="Plan sibling-variant review from safe hypotheses",
            input_refs=[f"pipeline_run:{pipeline_run.id}"],
            payload=autonomous_research_runtime._runtime_task_payload(
                campaign_id=campaign.id,
                task_type="variant_analysis",
                source_snapshot_digest=runtime_snapshot_digest,
                pipeline_run_id=pipeline_run.id,
            ),
        )
        assert run_agent_task(variant_task.id, repository=repository)["status"] == "completed"
        deep_task = repository.create_campaign_task(
            campaign_id=campaign.id,
            task_type="deep_code_reasoning",
            agent_type="deep_code_reasoning_agent",
            title="Plan cross-file permission reasoning from safe hypotheses",
            input_refs=[f"pipeline_run:{pipeline_run.id}"],
            payload=autonomous_research_runtime._runtime_task_payload(
                campaign_id=campaign.id,
                task_type="deep_code_reasoning",
                source_snapshot_digest=runtime_snapshot_digest,
                pipeline_run_id=pipeline_run.id,
            ),
        )
        assert run_agent_task(deep_task.id, repository=repository)["status"] == "completed"
        owner_task = repository.create_campaign_task(
            campaign_id=campaign.id,
            task_type="candidate_refutation",
            agent_type="candidate_hunter_agent",
            title="Refute candidate with local evidence",
            input_refs=[f"pipeline_run:{pipeline_run.id}"],
            payload=autonomous_research_runtime._runtime_task_payload(
                campaign_id=campaign.id,
                task_type="candidate_refutation",
                source_snapshot_digest=runtime_snapshot_digest,
                pipeline_run_id=pipeline_run.id,
            ),
        )

        owner_result = run_agent_task(owner_task.id, repository=repository)
        persisted_owner = repository.session.get(type(owner_task), owner_task.id)
        evidence_task = next(
            task
            for task in repository.list_campaign_tasks(campaign.id)
            if task.task_type == "candidate_hunter_evidence_inspection"
        )

        assert owner_result["status"] == "awaiting_evidence"
        assert persisted_owner is not None
        assert persisted_owner.status == "awaiting_evidence"
        dispatched_task_ids: list[str] = []
        dispatched = autonomous_research_runtime._dispatch_queued_local_evidence_task_if_needed(
            campaign=campaign,
            repository=repository,
            dispatcher=lambda *, campaign_task_id: dispatched_task_ids.append(
                campaign_task_id
            ),
            now=datetime.now(UTC) + timedelta(minutes=2),
        )
        persisted_dispatched_evidence = repository.session.get(
            type(evidence_task), evidence_task.id
        )

        assert dispatched is not None
        assert dispatched["status"] == "dispatched"
        assert dispatched_task_ids == [evidence_task.id]
        assert persisted_dispatched_evidence is not None
        assert persisted_dispatched_evidence.execution_claim_id is not None
        evidence_claim_id = persisted_dispatched_evidence.execution_claim_id

        if resume_path == "worker":
            resumed = run_agent_task(evidence_task.id, repository=repository)
        else:
            claimed_evidence = repository.claim_campaign_task_execution(evidence_task.id)
            assert claimed_evidence is not None
            completed_evidence = run_evidence_inspection_task(
                repository=repository,
                task_id=evidence_task.id,
            )
            assert completed_evidence["status"] == "completed"
            resumed = autonomous_research_runtime._dispatch_queued_local_evidence_task_if_needed(
                campaign=campaign,
                repository=repository,
                dispatcher=lambda **_kwargs: None,
                now=datetime.now(UTC) + timedelta(minutes=4),
            )
        persisted_evidence = repository.session.get(type(evidence_task), evidence_task.id)
        persisted_owner = repository.session.get(type(owner_task), owner_task.id)
        evidence_run = repository.session.get(AgentRunRecord, evidence_claim_id)

        assert resumed is not None
        assert resumed["status"] == "completed"
        assert persisted_evidence is not None
        assert persisted_evidence.status == "completed"
        assert persisted_evidence.execution_claim_id is None
        assert persisted_evidence.execution_lease_expires_at is None
        assert evidence_run is not None
        assert evidence_run.status == "completed"
        assert persisted_owner is not None
        assert persisted_owner.status == "completed"
        assert any(
            ref == f"candidate_hunter_projection:{owner_task.id}"
            for ref in persisted_owner.output_refs
        )
    finally:
        session.close()


def test_resume_blocks_runtime_evidence_when_scope_guard_is_missing():
    repository, session = _repository()
    try:
        source_snapshot_digest = "sha256:" + "a" * 64
        campaign = repository.create_campaign(
            program_id=None,
            name="Resume scope guard campaign",
            autonomy_level="level_0_read_only",
            scope_status="in_scope",
            policy_text="Synthetic local policy.",
            default_asset="api.example.com",
            created_by="candidate_hunter_loop",
            payload={
                "source_snapshot_digest": source_snapshot_digest,
                **_safe_payload(),
            },
        )
        campaign = repository.update_campaign_status(campaign.id, "running")
        assert campaign is not None
        pipeline_run = repository.save_pipeline_run(
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
            title="Refute candidates",
            input_refs=[f"pipeline_run:{pipeline_run.id}"],
            payload={
                "runtime_schema": "autonomous_research_v1",
                "pipeline_run_id": pipeline_run.id,
                "source_snapshot_digest": source_snapshot_digest,
                "raw_payload_in_dispatch": False,
                **_safe_payload(),
            },
        )
        owner_task = repository.update_campaign_task_status(
            owner_task.id,
            "needs_evidence",
        )
        assert owner_task is not None
        evidence_task = repository.create_campaign_task(
            campaign_id=campaign.id,
            task_type="candidate_hunter_evidence_inspection",
            agent_type="candidate_hunter_evidence_specialist",
            title="Inspect authorized evidence",
            input_refs=[f"pipeline_run:{pipeline_run.id}"],
            payload={
                "schema_version": "candidate_hunter_evidence_task_v1",
                "pipeline_run_id": pipeline_run.id,
                "owner_task_id": owner_task.id,
                "source_snapshot_digest": source_snapshot_digest.removeprefix(
                    "sha256:"
                ),
                **_safe_payload(),
            },
        )

        result = candidate_hunter_evidence.resume_candidate_hunter_after_evidence(
            repository=repository,
            evidence_task_id=evidence_task.id,
        )

        persisted_owner = repository.session.get(type(owner_task), owner_task.id)
        assert result["status"] == "blocked"
        assert result["stop_reason"] == "scope_guard_rule_missing"
        assert result["pipeline_run_id"] == pipeline_run.id
        assert result["final_candidates"] == []
        assert all(result[field] is False for field in _safe_payload())
        assert persisted_owner is not None
        assert persisted_owner.status == "blocked"
        assert repository.list_pipeline_stages_for_run(pipeline_run.id) == []
    finally:
        session.close()
