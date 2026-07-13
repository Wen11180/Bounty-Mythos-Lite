from __future__ import annotations

from hashlib import sha256
import json

from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app.candidate_hunter_evidence import (
    materialize_evidence_inspection_task,
    run_evidence_inspection_task,
)
from app.candidate_hunter_loop import (
    build_candidate_hunter_observations,
    run_candidate_hunter_loop,
)
from app.db import Base
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
        assert "return send_file" not in json.dumps(result_stage.payload)
        assert repository.session.get(type(task), task.id).status == "completed"
        agent_runs = repository.list_campaign_agent_runs(campaign.id)
        assert len(agent_runs) == 1
        assert agent_runs[0].status == "completed"
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
