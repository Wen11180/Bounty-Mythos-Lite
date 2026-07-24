from datetime import UTC, datetime, timedelta
from hashlib import sha256
import json
import os
from threading import Barrier, Thread
from uuid import uuid4
import warnings

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.engine import make_url
from sqlalchemy.exc import SAWarning
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

import app.autonomous_research_wakeup as autonomous_research_wakeup
import app.autonomous_research_runtime as autonomous_research_runtime
import app.candidate_hunter_evidence as candidate_hunter_evidence
import app.repository as repository_module
import app.worker.tasks as worker_tasks
from app.config import get_settings
from app.db import Base
from app.repository import (
    AUTONOMOUS_RESEARCH_TASK_LEASE_SECONDS,
    DatabaseRepository,
    seed_sample_data,
)
from app.studio_workspace import (
    StudioArtifactImport,
    build_authorized_campaign_snapshot,
    create_workspace,
    import_workspace_artifact,
)
from app.worker.tasks import run_agent_task


SOURCE_SNAPSHOT_DIGEST = "sha256:" + "a" * 64


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


def create_running_campaign(repository, *, name):
    campaign = repository.create_campaign(
        program_id="program_example",
        name=name,
        autonomy_level="level_0_read_only",
        scope_status="in_scope",
        policy_text="Authorized local review only.",
        default_asset="local.example",
        created_by="operator",
    )
    campaign = repository.update_campaign_status(campaign.id, "running")
    assert campaign is not None
    return campaign


def runtime_campaign_payload():
    return {
        "scope_guard_rule": {
            "asset": "local.example",
            "scope_status": "in_scope",
            "automation": "none",
            "allowed_validation": [],
            "forbidden": [],
            "human_approval_required": True,
        },
        "source_snapshot_digest": SOURCE_SNAPSHOT_DIGEST,
        "execution_allowed": False,
        "dispatch_allowed": False,
        "validation_allowed": False,
        "candidate_promotion_allowed": False,
        "report_submission_allowed": False,
        "raw_payload_processed": False,
    }


def runtime_agent_run_payload():
    return {
        "runtime_schema": "autonomous_research_v1",
        "source_snapshot_digest": SOURCE_SNAPSHOT_DIGEST,
        "dispatch_contract": "id_only",
        "execution_allowed": False,
        "dispatch_allowed": False,
        "validation_allowed": False,
        "candidate_promotion_allowed": False,
        "report_submission_allowed": False,
        "raw_payload_processed": False,
        "raw_payload_in_dispatch": False,
    }


def create_runtime_running_campaign(repository, *, name):
    campaign = repository.create_campaign(
        program_id="program_example",
        name=name,
        autonomy_level="level_0_read_only",
        scope_status="in_scope",
        policy_text="Authorized local review only.",
        default_asset="local.example",
        created_by="operator",
        payload=runtime_campaign_payload(),
    )
    campaign = repository.update_campaign_status(campaign.id, "running")
    assert campaign is not None
    return campaign


def test_runtime_candidate_refutation_binds_registered_advisories_at_creation(
    monkeypatch,
):
    repository, session = build_repository()
    try:
        campaign = create_runtime_running_campaign(
            repository,
            name="Frozen advisory input campaign",
        )
        pipeline_run = repository.save_pipeline_run(
            program_id=campaign.program_id,
            asset=campaign.default_asset,
            policy_text=campaign.policy_text_hash,
            policy_text_is_hash=True,
            scope_status="in_scope",
            hypothesis_count=1,
            blocked_count=0,
            report_title=None,
            payload={"campaign_id": campaign.id, "hypotheses": []},
        )
        advisory = repository.save_artifact(
            program_id=campaign.program_id,
            asset=campaign.default_asset,
            kind="static_advisory",
            source_type="registered_local_tool",
            source_hash=f"sha256:{'d' * 64}",
            ingestion_status="advisory_only",
            provenance={
                "campaign_id": campaign.id,
                "source_snapshot_digest": SOURCE_SNAPSHOT_DIGEST,
                "tool_id": "semgrep_local",
                "raw_payload_processed": False,
            },
            payload_summary={"raw_payload_processed": False},
            derived_facts={
                "advisory_findings": [
                    {
                        "rule_id": "mythos.local.ssrf-fetch",
                        "path": "routes.py",
                        "line": 7,
                    }
                ],
                "execution_allowed": False,
                "validation_allowed": False,
                "candidate_promotion_allowed": False,
                "report_submission_allowed": False,
            },
        )
        captured: dict[str, object] = {}
        monkeypatch.setattr(
            autonomous_research_runtime,
            "_reconcile_missing_runtime_failure_stage",
            lambda **_kwargs: None,
        )
        monkeypatch.setattr(
            autonomous_research_runtime,
            "_recover_runtime_task_if_needed",
            lambda **_kwargs: None,
        )
        monkeypatch.setattr(
            autonomous_research_runtime,
            "_dispatch_queued_local_evidence_task_if_needed",
            lambda **_kwargs: None,
        )
        monkeypatch.setattr(
            autonomous_research_runtime,
            "select_autonomous_research_work",
            lambda **_kwargs: {
                "status": "ready",
                "task_type": "candidate_refutation",
                "agent_type": "candidate_hunter_agent",
                "title": "Refute candidate hypotheses from persisted evidence",
                "source_snapshot_digest": SOURCE_SNAPSHOT_DIGEST,
            },
        )
        monkeypatch.setattr(
            autonomous_research_runtime,
            "_pipeline_run_id_from_completed_runtime_stage",
            lambda **_kwargs: pipeline_run.id,
        )
        monkeypatch.setattr(
            autonomous_research_runtime,
            "_runtime_tick_stop_reason",
            lambda **_kwargs: None,
        )

        def capture_dispatch(**kwargs):
            captured["task"] = kwargs["task"]
            return {"status": "dispatched"}

        monkeypatch.setattr(
            autonomous_research_runtime,
            "_dispatch_runtime_task",
            capture_dispatch,
        )

        result = autonomous_research_runtime.tick_autonomous_research_campaign(
            campaign.id,
            repository=repository,
            dispatcher=lambda **_kwargs: None,
        )
        task = captured["task"]

        assert result == {"status": "dispatched"}
        assert task.input_refs == [
            f"campaign:{campaign.id}",
            f"source_snapshot:{SOURCE_SNAPSHOT_DIGEST}",
            f"pipeline_run:{pipeline_run.id}",
            f"artifact:{advisory.id}",
        ]
        assert task.payload["candidate_promotion_allowed"] is False
        assert task.payload["report_submission_allowed"] is False
    finally:
        session.close()


def test_runtime_hypothesis_generation_binds_learning_signals_at_creation(
    monkeypatch,
):
    repository, session = build_repository()
    try:
        campaign = create_runtime_running_campaign(
            repository,
            name="Frozen learning signal input campaign",
        )
        signal = repository.save_learning_signal(
            program_id=campaign.program_id,
            playbook_id="bola_idor",
            outcome="accepted",
            surface_key="record_id:export",
            notes="Operator-reviewed outcome.",
            evidence_quality="strong",
        )
        captured: dict[str, object] = {}
        monkeypatch.setattr(
            autonomous_research_runtime,
            "_reconcile_missing_runtime_failure_stage",
            lambda **_kwargs: None,
        )
        monkeypatch.setattr(
            autonomous_research_runtime,
            "_recover_runtime_task_if_needed",
            lambda **_kwargs: None,
        )
        monkeypatch.setattr(
            autonomous_research_runtime,
            "_dispatch_queued_local_evidence_task_if_needed",
            lambda **_kwargs: None,
        )
        monkeypatch.setattr(
            autonomous_research_runtime,
            "select_autonomous_research_work",
            lambda **_kwargs: {
                "status": "ready",
                "task_type": "hypothesis_generation",
                "agent_type": "hypothesis_agent",
                "title": "Generate candidate hypotheses from safe facts",
                "source_snapshot_digest": SOURCE_SNAPSHOT_DIGEST,
            },
        )
        monkeypatch.setattr(
            autonomous_research_runtime,
            "_runtime_tick_stop_reason",
            lambda **_kwargs: None,
        )

        def capture_dispatch(**kwargs):
            captured["task"] = kwargs["task"]
            return {"status": "dispatched"}

        monkeypatch.setattr(
            autonomous_research_runtime,
            "_dispatch_runtime_task",
            capture_dispatch,
        )

        result = autonomous_research_runtime.tick_autonomous_research_campaign(
            campaign.id,
            repository=repository,
            dispatcher=lambda **_kwargs: None,
        )
        task = captured["task"]

        assert result == {"status": "dispatched"}
        assert task.input_refs == [
            f"campaign:{campaign.id}",
            f"source_snapshot:{SOURCE_SNAPSHOT_DIGEST}",
            f"learning_signal:{signal.id}",
        ]
        assert task.payload["candidate_promotion_allowed"] is False
        assert task.payload["report_submission_allowed"] is False
    finally:
        session.close()


def test_runtime_finding_dedup_binds_historical_report_stages_at_creation(
    monkeypatch,
):
    repository, session = build_repository()
    try:
        campaign = create_runtime_running_campaign(
            repository,
            name="Frozen historical report input campaign",
        )
        pipeline_run = repository.save_pipeline_run(
            program_id=campaign.program_id,
            asset=campaign.default_asset,
            policy_text=campaign.policy_text_hash,
            policy_text_is_hash=True,
            scope_status="in_scope",
            hypothesis_count=1,
            blocked_count=0,
            report_title=None,
            payload={"campaign_id": campaign.id, "hypotheses": []},
        )
        captured: dict[str, object] = {}
        monkeypatch.setattr(
            autonomous_research_runtime,
            "_reconcile_missing_runtime_failure_stage",
            lambda **_kwargs: None,
        )
        monkeypatch.setattr(
            autonomous_research_runtime,
            "_recover_runtime_task_if_needed",
            lambda **_kwargs: None,
        )
        monkeypatch.setattr(
            autonomous_research_runtime,
            "_dispatch_queued_local_evidence_task_if_needed",
            lambda **_kwargs: None,
        )
        monkeypatch.setattr(
            autonomous_research_runtime,
            "select_autonomous_research_work",
            lambda **_kwargs: {
                "status": "ready",
                "task_type": "finding_dedup_and_rank",
                "agent_type": "triage_agent",
                "title": "Deduplicate and rank retained candidates",
                "source_snapshot_digest": SOURCE_SNAPSHOT_DIGEST,
            },
        )
        monkeypatch.setattr(
            autonomous_research_runtime,
            "_pipeline_run_id_from_completed_runtime_stage",
            lambda **_kwargs: pipeline_run.id,
        )
        monkeypatch.setattr(
            autonomous_research_runtime,
            "_runtime_tick_stop_reason",
            lambda **_kwargs: None,
        )
        monkeypatch.setattr(
            worker_tasks,
            "historical_report_stage_refs_for_dedup",
            lambda **_kwargs: ["historical_report_stage:pipeline_stage_prior"],
        )

        def capture_dispatch(**kwargs):
            captured["task"] = kwargs["task"]
            return {"status": "dispatched"}

        monkeypatch.setattr(
            autonomous_research_runtime,
            "_dispatch_runtime_task",
            capture_dispatch,
        )

        result = autonomous_research_runtime.tick_autonomous_research_campaign(
            campaign.id,
            repository=repository,
            dispatcher=lambda **_kwargs: None,
        )
        task = captured["task"]

        assert result == {"status": "dispatched"}
        assert task.input_refs == [
            f"campaign:{campaign.id}",
            f"source_snapshot:{SOURCE_SNAPSHOT_DIGEST}",
            f"pipeline_run:{pipeline_run.id}",
            "historical_report_stage:pipeline_stage_prior",
        ]
        assert task.payload["candidate_promotion_allowed"] is False
        assert task.payload["report_submission_allowed"] is False
    finally:
        session.close()


def create_dispatched_runtime_task(repository, *, campaign, now):
    task = repository.create_campaign_task(
        campaign_id=campaign.id,
        task_type="attack_surface_mapping",
        agent_type="target_model_agent",
        title="Map authorized attack surface facts",
        input_refs=[f"campaign:{campaign.id}"],
        payload=autonomous_research_runtime._runtime_task_payload(
            campaign_id=campaign.id,
            task_type="attack_surface_mapping",
            source_snapshot_digest=SOURCE_SNAPSHOT_DIGEST,
        ),
    )
    agent_run = repository.save_agent_run(
        campaign_id=campaign.id,
        task_id=task.id,
        agent_type=task.agent_type,
        status="dispatched",
        input_refs=[f"campaign_task:{task.id}"],
        output_refs=[],
        tool_calls=[],
        safety_gate_state="allowed",
        stop_reason=None,
        payload=runtime_agent_run_payload(),
    )
    task = repository.mark_campaign_task_dispatched(
        task.id,
        execution_claim_id=agent_run.id,
        now=now,
    )
    assert task is not None
    return task, agent_run


def test_runtime_evidence_dispatch_uses_a_lease_and_expires_without_redispatch():
    repository, session = build_repository()
    try:
        now = datetime(2026, 7, 19, tzinfo=UTC)
        campaign = create_runtime_running_campaign(
            repository,
            name="Leased local evidence campaign",
        )
        pipeline_run_id = "pipeline_run_evidence"
        owner_task = repository.create_campaign_task(
            campaign_id=campaign.id,
            task_type="candidate_refutation",
            agent_type="candidate_hunter_agent",
            title="Refute candidate with local evidence",
            input_refs=[f"campaign:{campaign.id}"],
            payload=autonomous_research_runtime._runtime_task_payload(
                campaign_id=campaign.id,
                task_type="candidate_refutation",
                source_snapshot_digest=SOURCE_SNAPSHOT_DIGEST,
                pipeline_run_id=pipeline_run_id,
            ),
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
            input_refs=[f"pipeline_run:{pipeline_run_id}"],
            payload={
                "schema_version": "candidate_hunter_evidence_task_v1",
                "execution_lease_required": True,
                "pipeline_run_id": pipeline_run_id,
                "evidence_request_stage_id": "pipeline_stage_evidence_request",
                "owner_task_id": owner_task.id,
                "round": 1,
                "state_digest": "b" * 64,
                "source_snapshot_digest": SOURCE_SNAPSHOT_DIGEST.removeprefix(
                    "sha256:"
                ),
                "execution_allowed": False,
                "dispatch_allowed": False,
                "validation_allowed": False,
                "candidate_promotion_allowed": False,
                "report_submission_allowed": False,
                "raw_payload_processed": False,
            },
        )
        dispatched_task_ids = []

        dispatched = autonomous_research_runtime._dispatch_queued_local_evidence_task_if_needed(
            campaign=campaign,
            repository=repository,
            dispatcher=lambda *, campaign_task_id: dispatched_task_ids.append(
                campaign_task_id
            ),
            now=now,
        )
        persisted_dispatched = repository.session.get(type(evidence_task), evidence_task.id)

        assert dispatched is not None
        assert dispatched["status"] == "dispatched"
        assert dispatched_task_ids == [evidence_task.id]
        assert persisted_dispatched is not None
        assert persisted_dispatched.execution_claim_id is not None
        assert persisted_dispatched.execution_lease_expires_at is not None

        expired = autonomous_research_runtime._dispatch_queued_local_evidence_task_if_needed(
            campaign=campaign,
            repository=repository,
            dispatcher=lambda *, campaign_task_id: dispatched_task_ids.append(
                campaign_task_id
            ),
            now=now + timedelta(seconds=AUTONOMOUS_RESEARCH_TASK_LEASE_SECONDS + 1),
        )
        persisted_evidence = repository.session.get(type(evidence_task), evidence_task.id)
        persisted_owner = repository.session.get(type(owner_task), owner_task.id)

        assert expired is not None
        assert expired["status"] == "blocked"
        assert expired["stop_reason"] == "execution_lease_expired"
        assert dispatched_task_ids == [evidence_task.id]
        assert persisted_evidence is not None
        assert persisted_evidence.status == "failed"
        assert persisted_evidence.execution_claim_id is None
        assert persisted_owner is not None
        assert persisted_owner.status == "blocked"
        assert repository.get_campaign(campaign.id).status == "blocked"
    finally:
        session.close()


def test_runtime_evidence_dispatch_does_not_block_owner_after_concurrent_claim():
    repository, session = build_repository()
    try:
        campaign = create_runtime_running_campaign(
            repository,
            name="Concurrent evidence dispatch campaign",
        )
        pipeline_run_id = "pipeline_run_concurrent_evidence"
        owner_task = repository.create_campaign_task(
            campaign_id=campaign.id,
            task_type="candidate_refutation",
            agent_type="candidate_hunter_agent",
            title="Refute candidate with local evidence",
            input_refs=[f"campaign:{campaign.id}"],
            payload=autonomous_research_runtime._runtime_task_payload(
                campaign_id=campaign.id,
                task_type="candidate_refutation",
                source_snapshot_digest=SOURCE_SNAPSHOT_DIGEST,
                pipeline_run_id=pipeline_run_id,
            ),
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
            input_refs=[f"pipeline_run:{pipeline_run_id}"],
            payload={
                "schema_version": "candidate_hunter_evidence_task_v1",
                "execution_lease_required": True,
                "pipeline_run_id": pipeline_run_id,
                "evidence_request_stage_id": "pipeline_stage_evidence_request",
                "owner_task_id": owner_task.id,
                "round": 1,
                "state_digest": "b" * 64,
                "source_snapshot_digest": SOURCE_SNAPSHOT_DIGEST.removeprefix(
                    "sha256:"
                ),
                "execution_allowed": False,
                "dispatch_allowed": False,
                "validation_allowed": False,
                "candidate_promotion_allowed": False,
                "report_submission_allowed": False,
                "raw_payload_processed": False,
            },
        )
        now = datetime(2026, 7, 19, tzinfo=UTC)

        def dispatcher(*, campaign_task_id):
            assert campaign_task_id == evidence_task.id
            assert (
                repository.claim_campaign_task_execution(campaign_task_id, now=now)
                is not None
            )
            raise RuntimeError("dispatcher acknowledgement lost after worker claim")

        result = autonomous_research_runtime._dispatch_queued_local_evidence_task_if_needed(
            campaign=campaign,
            repository=repository,
            dispatcher=dispatcher,
            now=now,
        )
        persisted_evidence = repository.session.get(type(evidence_task), evidence_task.id)
        persisted_owner = repository.session.get(type(owner_task), owner_task.id)

        assert result is not None
        assert result["status"] == "awaiting_evidence"
        assert result["stop_reason"] == "evidence_task_active"
        assert persisted_evidence is not None
        assert persisted_evidence.status == "running"
        assert persisted_evidence.execution_claim_id is not None
        assert persisted_owner is not None
        assert persisted_owner.status == "awaiting_evidence"
        assert repository.get_campaign(campaign.id).status == "running"
    finally:
        session.close()


def test_runtime_evidence_dispatches_the_next_round_after_completed_evidence():
    repository, session = build_repository()
    try:
        campaign = create_runtime_running_campaign(
            repository,
            name="Sequential evidence dispatch campaign",
        )
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
        pipeline_run_id = pipeline_run.id
        owner_task = repository.create_campaign_task(
            campaign_id=campaign.id,
            task_type="candidate_refutation",
            agent_type="candidate_hunter_agent",
            title="Refute candidate with local evidence",
            input_refs=[f"campaign:{campaign.id}"],
            payload=autonomous_research_runtime._runtime_task_payload(
                campaign_id=campaign.id,
                task_type="candidate_refutation",
                source_snapshot_digest=SOURCE_SNAPSHOT_DIGEST,
                pipeline_run_id=pipeline_run_id,
            ),
        )
        owner_task = repository.update_campaign_task_status(
            owner_task.id,
            "awaiting_evidence",
        )
        assert owner_task is not None

        def evidence_payload(round_number):
            return {
                "schema_version": "candidate_hunter_evidence_task_v1",
                "execution_lease_required": True,
                "pipeline_run_id": pipeline_run_id,
                "evidence_request_stage_id": (
                    f"pipeline_stage_evidence_request_{round_number}"
                ),
                "owner_task_id": owner_task.id,
                "round": round_number,
                "state_digest": f"{round_number:x}" * 64,
                "source_snapshot_digest": SOURCE_SNAPSHOT_DIGEST.removeprefix(
                    "sha256:"
                ),
                "execution_allowed": False,
                "dispatch_allowed": False,
                "validation_allowed": False,
                "candidate_promotion_allowed": False,
                "report_submission_allowed": False,
                "raw_payload_processed": False,
            }

        completed_evidence = repository.create_campaign_task(
            campaign_id=campaign.id,
            task_type="candidate_hunter_evidence_inspection",
            agent_type="candidate_hunter_evidence_specialist",
            title="Inspect first-round local evidence",
            input_refs=[f"pipeline_run:{pipeline_run_id}"],
            payload=evidence_payload(1),
        )
        completed_evidence = repository.update_campaign_task_status(
            completed_evidence.id,
            "completed",
        )
        repository.save_pipeline_stage(
            pipeline_run_id=pipeline_run.id,
            campaign_id=campaign.id,
            task_id=completed_evidence.id,
            stage_key="candidate_hunter_evidence_result",
            stage_order=5,
            status="completed",
            input_refs=completed_evidence.input_refs,
            output_refs=[],
            safety_gate_state="safe",
            stop_reason=None,
            payload={
                "schema_version": candidate_hunter_evidence.RESULT_SCHEMA_VERSION,
                "evidence_task_id": completed_evidence.id,
                "evidence_request_stage_id": "pipeline_stage_evidence_request_1",
                "state_digest": "1" * 64,
                "source_snapshot_digest": SOURCE_SNAPSHOT_DIGEST.removeprefix(
                    "sha256:"
                ),
                "complete": True,
                "new_facts": [],
                "candidate_state_updates": [],
                "idempotency_key": candidate_hunter_evidence._result_idempotency_key(
                    pipeline_run_id=pipeline_run.id,
                    task_id=completed_evidence.id,
                    state_digest="1" * 64,
                    source_snapshot_digest=SOURCE_SNAPSHOT_DIGEST.removeprefix(
                        "sha256:"
                    ),
                ),
                "execution_allowed": False,
                "dispatch_allowed": False,
                "validation_allowed": False,
                "candidate_promotion_allowed": False,
                "report_submission_allowed": False,
                "raw_payload_processed": False,
            },
        )
        next_evidence = repository.create_campaign_task(
            campaign_id=campaign.id,
            task_type="candidate_hunter_evidence_inspection",
            agent_type="candidate_hunter_evidence_specialist",
            title="Inspect second-round local evidence",
            input_refs=[f"pipeline_run:{pipeline_run_id}"],
            payload=evidence_payload(2),
        )
        dispatched_task_ids = []

        result = autonomous_research_runtime._dispatch_queued_local_evidence_task_if_needed(
            campaign=campaign,
            repository=repository,
            dispatcher=lambda *, campaign_task_id: dispatched_task_ids.append(
                campaign_task_id
            ),
            now=datetime(2026, 7, 19, tzinfo=UTC),
        )
        persisted_owner = repository.session.get(type(owner_task), owner_task.id)
        persisted_completed = repository.session.get(
            type(completed_evidence), completed_evidence.id
        )
        persisted_next = repository.session.get(type(next_evidence), next_evidence.id)

        assert result is not None
        assert result["status"] == "dispatched"
        assert result["campaign_task_id"] == next_evidence.id
        assert dispatched_task_ids == [next_evidence.id]
        assert persisted_owner is not None
        assert persisted_owner.status == "awaiting_evidence"
        assert persisted_completed is not None
        assert persisted_completed.status == "completed"
        assert persisted_next is not None
        assert persisted_next.status == "dispatched"
        assert persisted_next.execution_claim_id is not None
    finally:
        session.close()


def test_runtime_recovery_fails_expired_dispatched_task_and_requires_manual_retry():
    repository, session = build_repository()
    try:
        now = datetime(2026, 7, 19, tzinfo=UTC)
        campaign = create_runtime_running_campaign(
            repository,
            name="Expired runtime dispatch campaign",
        )
        task, agent_run = create_dispatched_runtime_task(
            repository,
            campaign=campaign,
            now=now,
        )
        expired_claim_id = task.execution_claim_id

        recovered = autonomous_research_runtime._recover_runtime_task_if_needed(
            campaign=campaign,
            repository=repository,
            dispatcher=lambda **_kwargs: None,
            now=now
            + timedelta(seconds=AUTONOMOUS_RESEARCH_TASK_LEASE_SECONDS + 1),
        )

        persisted_task = repository.session.get(type(task), task.id)
        persisted_run = repository.session.get(type(agent_run), agent_run.id)
        failure_stages = [
            stage
            for stage in repository.list_campaign_pipeline_stages(campaign.id)
            if stage.task_id == task.id and stage.status == "failed"
        ]

        assert recovered is not None
        assert recovered["status"] == "awaiting_review"
        assert recovered["stop_reason"] == "execution_lease_expired"
        assert persisted_task is not None
        assert persisted_task.status == "failed"
        assert persisted_task.execution_claim_id is None
        assert persisted_run is not None
        assert persisted_run.status == "failed"
        assert persisted_run.stop_reason == "execution_lease_expired"
        assert len(failure_stages) == 1
        assert failure_stages[0].stop_reason == "execution_lease_expired"
        assert repository.get_campaign(campaign.id).status == "awaiting_review"

        late_completion = repository.finish_campaign_task_execution(
            task_id=task.id,
            execution_claim_id=expired_claim_id,
            task_status="completed",
            task_output_refs=[f"agent_run:{agent_run.id}"],
            agent_status="completed",
            agent_output_refs=[],
            safety_gate_state="allowed",
            stop_reason=None,
            payload={"raw_payload_processed": False},
        )
        retry_dispatches = []
        retry = autonomous_research_runtime.retry_autonomous_research_task(
            campaign.id,
            task.id,
            repository=repository,
            dispatcher=lambda *, campaign_task_id: retry_dispatches.append(
                campaign_task_id
            ),
        )
        retried_task = repository.session.get(type(task), task.id)

        assert late_completion is None
        assert retry["status"] == "dispatched"
        assert retry_dispatches == [task.id]
        assert retried_task is not None
        assert retried_task.execution_claim_id not in {None, expired_claim_id}
    finally:
        session.close()


@pytest.mark.parametrize(
    ("stop_reason", "execution_status"),
    (
        ("execution_lease_expired", "expired"),
        ("dispatch_failed", "dispatched"),
        ("worker_failed", "running"),
    ),
)
def test_runtime_recovery_repairs_missing_failure_stage_before_manual_retry(
    stop_reason,
    execution_status,
):
    repository, session = build_repository()
    try:
        now = datetime(2026, 7, 19, tzinfo=UTC)
        campaign = create_runtime_running_campaign(
            repository,
            name=f"Missing failure stage {stop_reason} campaign",
        )
        task, agent_run = create_dispatched_runtime_task(
            repository,
            campaign=campaign,
            now=now,
        )
        recovery_now = now + timedelta(seconds=1)
        if execution_status == "expired":
            failed_task = repository.expire_campaign_task_execution(
                task.id,
                now=now
                + timedelta(seconds=AUTONOMOUS_RESEARCH_TASK_LEASE_SECONDS + 1),
            )
            recovery_now = now + timedelta(
                seconds=AUTONOMOUS_RESEARCH_TASK_LEASE_SECONDS + 2
            )
        else:
            if execution_status == "running":
                task = repository.claim_campaign_task_execution(
                    task.id,
                    now=now + timedelta(seconds=1),
                )
                assert task is not None
            failed_execution = repository.finish_campaign_task_execution(
                task_id=task.id,
                execution_claim_id=task.execution_claim_id,
                task_status="failed",
                task_output_refs=[f"agent_run:{agent_run.id}"],
                agent_status="failed",
                agent_output_refs=[],
                safety_gate_state="blocked",
                stop_reason=stop_reason,
                payload=runtime_agent_run_payload(),
                expected_execution_statuses={execution_status},
            )
            failed_task = failed_execution[0] if failed_execution is not None else None
        assert failed_task is not None
        assert not [
            stage
            for stage in repository.list_campaign_pipeline_stages(campaign.id)
            if stage.task_id == task.id and stage.status == "failed"
        ]

        recovered = autonomous_research_runtime.tick_autonomous_research_campaign(
            campaign.id,
            repository=repository,
            dispatcher=lambda **_kwargs: None,
            now=recovery_now,
        )
        failure_stages = [
            stage
            for stage in repository.list_campaign_pipeline_stages(campaign.id)
            if stage.task_id == task.id and stage.status == "failed"
        ]
        retry_dispatches = []
        retry = autonomous_research_runtime.retry_autonomous_research_task(
            campaign.id,
            task.id,
            repository=repository,
            dispatcher=lambda *, campaign_task_id: retry_dispatches.append(
                campaign_task_id
            ),
        )

        assert recovered["status"] == "awaiting_review"
        assert recovered["campaign_task_id"] == task.id
        assert recovered["stop_reason"] == stop_reason
        assert len(failure_stages) == 1
        assert failure_stages[0].stop_reason == stop_reason
        assert retry["status"] == "dispatched"
        assert retry_dispatches == [task.id]
    finally:
        session.close()


def test_runtime_failure_recovery_rejects_unsafe_agent_payload():
    repository, session = build_repository()
    try:
        now = datetime(2026, 7, 19, tzinfo=UTC)
        campaign = create_runtime_running_campaign(
            repository,
            name="Unsafe failure payload recovery campaign",
        )
        task, agent_run = create_dispatched_runtime_task(
            repository,
            campaign=campaign,
            now=now,
        )
        task = repository.claim_campaign_task_execution(
            task.id,
            now=now + timedelta(seconds=1),
        )
        assert task is not None
        unsafe_payload = runtime_agent_run_payload()
        unsafe_payload["execution_allowed"] = True
        failed_execution = repository.finish_campaign_task_execution(
            task_id=task.id,
            execution_claim_id=task.execution_claim_id,
            task_status="failed",
            task_output_refs=[f"agent_run:{agent_run.id}"],
            agent_status="failed",
            agent_output_refs=[],
            safety_gate_state="blocked",
            stop_reason="worker_failed",
            payload=unsafe_payload,
            expected_execution_statuses={"running"},
        )
        assert failed_execution is not None
        assert failed_execution[1].payload == unsafe_payload
        assert (
            autonomous_research_runtime._verified_runtime_failure_stop_reason(
                task=failed_execution[0],
                repository=repository,
            )
            is None
        )
        assert not autonomous_research_runtime._has_retryable_runtime_failure(
            task=failed_execution[0],
            repository=repository,
            source_snapshot_digest=SOURCE_SNAPSHOT_DIGEST,
        )
        assert (
            autonomous_research_runtime._reconcile_missing_runtime_failure_stage(
                campaign=campaign,
                repository=repository,
                task_id=task.id,
            )
            is None
        )
        dispatched_task_ids = []

        retry = autonomous_research_runtime.retry_autonomous_research_task(
            campaign.id,
            task.id,
            repository=repository,
            dispatcher=lambda *, campaign_task_id: dispatched_task_ids.append(
                campaign_task_id
            ),
        )
        failure_stages = [
            stage
            for stage in repository.list_campaign_pipeline_stages(campaign.id)
            if stage.task_id == task.id and stage.status == "failed"
        ]

        assert retry["status"] == "awaiting_review"
        assert retry["stop_reason"] == "human_review_required"
        assert dispatched_task_ids == []
        assert failure_stages == []
    finally:
        session.close()


def test_runtime_recovery_resumes_verified_queued_dispatch_after_claim_write_interruption():
    repository, session = build_repository()
    try:
        now = datetime(2026, 7, 19, tzinfo=UTC)
        campaign = create_runtime_running_campaign(
            repository,
            name="Queued dispatch claim interruption campaign",
        )
        task = repository.create_campaign_task(
            campaign_id=campaign.id,
            task_type="attack_surface_mapping",
            agent_type="target_model_agent",
            title="Map authorized attack surface facts",
            input_refs=[f"campaign:{campaign.id}"],
            payload=autonomous_research_runtime._runtime_task_payload(
                campaign_id=campaign.id,
                task_type="attack_surface_mapping",
                source_snapshot_digest=SOURCE_SNAPSHOT_DIGEST,
            ),
        )
        dispatched_task_ids = []
        original_mark_dispatched = repository.mark_campaign_task_dispatched

        def interrupt_before_claim(*_args, **_kwargs):
            raise RuntimeError("simulated interruption before execution claim")

        repository.mark_campaign_task_dispatched = interrupt_before_claim
        try:
            autonomous_research_runtime._dispatch_runtime_task(
                campaign=campaign,
                task=task,
                source_snapshot_digest=SOURCE_SNAPSHOT_DIGEST,
                repository=repository,
                dispatcher=lambda *, campaign_task_id: dispatched_task_ids.append(
                    campaign_task_id
                ),
                now=now,
            )
        except RuntimeError:
            pass
        finally:
            repository.mark_campaign_task_dispatched = original_mark_dispatched

        orphan_run = next(
            run
            for run in repository.list_campaign_agent_runs(campaign.id)
            if run.task_id == task.id
        )
        assert repository.session.get(type(task), task.id).status == "queued"
        assert dispatched_task_ids == []

        recovered = autonomous_research_runtime._recover_runtime_task_if_needed(
            campaign=campaign,
            repository=repository,
            dispatcher=lambda *, campaign_task_id: dispatched_task_ids.append(
                campaign_task_id
            ),
            now=now + timedelta(seconds=1),
        )
        persisted_task = repository.session.get(type(task), task.id)

        assert recovered is not None
        assert recovered["status"] == "dispatched"
        assert recovered["campaign_task_id"] == task.id
        assert recovered["stop_reason"] is None
        assert dispatched_task_ids == [task.id]
        assert persisted_task is not None
        assert persisted_task.status == "dispatched"
        assert persisted_task.execution_claim_id == orphan_run.id
        assert len(
            [
                run
                for run in repository.list_campaign_agent_runs(campaign.id)
                if run.task_id == task.id
            ]
        ) == 1
    finally:
        session.close()


def test_runtime_recovery_fails_unverified_queued_dispatch_for_review():
    repository, session = build_repository()
    try:
        campaign = create_runtime_running_campaign(
            repository,
            name="Unverified queued dispatch recovery campaign",
        )
        task = repository.create_campaign_task(
            campaign_id=campaign.id,
            task_type="attack_surface_mapping",
            agent_type="target_model_agent",
            title="Map authorized attack surface facts",
            input_refs=[f"campaign:{campaign.id}"],
            payload=autonomous_research_runtime._runtime_task_payload(
                campaign_id=campaign.id,
                task_type="attack_surface_mapping",
                source_snapshot_digest=SOURCE_SNAPSHOT_DIGEST,
            ),
        )
        orphan_run = repository.save_agent_run(
            campaign_id=campaign.id,
            task_id=task.id,
            agent_type=task.agent_type,
            status="dispatched",
            input_refs=[f"campaign_task:{task.id}"],
            output_refs=[],
            tool_calls=[],
            safety_gate_state="allowed",
            stop_reason=None,
            payload={"raw_payload_processed": False},
        )

        recovered = autonomous_research_runtime._recover_runtime_task_if_needed(
            campaign=campaign,
            repository=repository,
            dispatcher=lambda **_kwargs: None,
            now=datetime(2026, 7, 19, tzinfo=UTC),
        )
        persisted_task = repository.session.get(type(task), task.id)
        persisted_run = repository.session.get(type(orphan_run), orphan_run.id)

        assert recovered is not None
        assert recovered["status"] == "awaiting_review"
        assert recovered["campaign_task_id"] == task.id
        assert recovered["stop_reason"] == "recovery_dispatch_integrity_invalid"
        assert persisted_task is not None
        assert persisted_task.status == "failed"
        assert persisted_run is not None
        assert persisted_run.status == "failed"
        assert persisted_run.safety_gate_state == "blocked"
        assert persisted_run.stop_reason == "recovery_dispatch_integrity_invalid"
        assert repository.get_campaign(campaign.id).status == "awaiting_review"
    finally:
        session.close()


def test_runtime_recovery_fails_running_task_without_execution_lease_for_review():
    repository, session = build_repository()
    try:
        campaign = create_runtime_running_campaign(
            repository,
            name="Running task without execution lease recovery campaign",
        )
        task = repository.create_campaign_task(
            campaign_id=campaign.id,
            task_type="attack_surface_mapping",
            agent_type="target_model_agent",
            title="Map authorized attack surface facts",
            input_refs=[f"campaign:{campaign.id}"],
            payload=autonomous_research_runtime._runtime_task_payload(
                campaign_id=campaign.id,
                task_type="attack_surface_mapping",
                source_snapshot_digest=SOURCE_SNAPSHOT_DIGEST,
            ),
        )
        task = repository.update_campaign_task_status(task.id, "running")
        assert task is not None
        orphan_run = repository.save_agent_run(
            campaign_id=campaign.id,
            task_id=task.id,
            agent_type=task.agent_type,
            status="running",
            input_refs=[f"campaign_task:{task.id}"],
            output_refs=[],
            tool_calls=[],
            safety_gate_state="allowed",
            stop_reason=None,
            payload={"raw_payload_processed": False},
        )

        recovered = autonomous_research_runtime._recover_runtime_task_if_needed(
            campaign=campaign,
            repository=repository,
            dispatcher=lambda **_kwargs: None,
            now=datetime(2026, 7, 19, tzinfo=UTC),
        )
        persisted_task = repository.session.get(type(task), task.id)
        persisted_run = repository.session.get(type(orphan_run), orphan_run.id)

        assert recovered is not None
        assert recovered["status"] == "awaiting_review"
        assert recovered["campaign_task_id"] == task.id
        assert recovered["stop_reason"] == "recovery_dispatch_integrity_invalid"
        assert persisted_task is not None
        assert persisted_task.status == "failed"
        assert persisted_task.execution_claim_id is None
        assert persisted_task.execution_lease_expires_at is None
        assert persisted_run is not None
        assert persisted_run.status == "failed"
        assert persisted_run.safety_gate_state == "blocked"
        assert persisted_run.stop_reason == "recovery_dispatch_integrity_invalid"
        assert repository.get_campaign(campaign.id).status == "awaiting_review"
    finally:
        session.close()


def test_runtime_recovery_fails_dispatched_task_with_claim_but_without_lease():
    repository, session = build_repository()
    try:
        now = datetime(2026, 7, 19, tzinfo=UTC)
        campaign = create_runtime_running_campaign(
            repository,
            name="Dispatched task without execution lease recovery campaign",
        )
        task, agent_run = create_dispatched_runtime_task(
            repository,
            campaign=campaign,
            now=now,
        )
        task.execution_lease_expires_at = None
        session.add(task)
        session.commit()

        assert repository.claim_campaign_task_execution(
            task.id,
            now=now + timedelta(seconds=1),
        ) is None

        recovered = autonomous_research_runtime._recover_runtime_task_if_needed(
            campaign=campaign,
            repository=repository,
            dispatcher=lambda **_kwargs: None,
            now=now + timedelta(seconds=1),
        )
        persisted_task = repository.session.get(type(task), task.id)
        persisted_run = repository.session.get(type(agent_run), agent_run.id)

        assert recovered is not None
        assert recovered["status"] == "awaiting_review"
        assert recovered["campaign_task_id"] == task.id
        assert recovered["stop_reason"] == "recovery_dispatch_integrity_invalid"
        assert persisted_task is not None
        assert persisted_task.status == "failed"
        assert persisted_task.execution_claim_id is None
        assert persisted_task.execution_lease_expires_at is None
        assert persisted_run is not None
        assert persisted_run.status == "failed"
        assert persisted_run.safety_gate_state == "blocked"
        assert persisted_run.stop_reason == "recovery_dispatch_integrity_invalid"
        assert repository.get_campaign(campaign.id).status == "awaiting_review"
    finally:
        session.close()


def test_runtime_recovery_records_incomplete_execution_failure_after_restart():
    repository, session = build_repository()
    try:
        now = datetime(2026, 7, 19, tzinfo=UTC)
        campaign = create_runtime_running_campaign(
            repository,
            name="Incomplete execution failure audit recovery campaign",
        )
        task, _agent_run = create_dispatched_runtime_task(
            repository,
            campaign=campaign,
            now=now,
        )
        task.execution_lease_expires_at = None
        session.add(task)
        session.commit()
        failed_task = repository.fail_incomplete_campaign_task_execution(
            task.id,
            stop_reason="recovery_dispatch_integrity_invalid",
            now=now,
        )
        assert failed_task is not None
        assert failed_task.status == "failed"
        assert not [
            stage
            for stage in repository.list_campaign_pipeline_stages(campaign.id)
            if stage.task_id == task.id and stage.status == "failed"
        ]

        recovered = autonomous_research_runtime._recover_runtime_task_if_needed(
            campaign=campaign,
            repository=repository,
            dispatcher=lambda **_kwargs: None,
            now=now + timedelta(seconds=1),
        )
        failure_stages = [
            stage
            for stage in repository.list_campaign_pipeline_stages(campaign.id)
            if stage.task_id == task.id and stage.status == "failed"
        ]

        assert recovered is not None
        assert recovered["status"] == "awaiting_review"
        assert recovered["campaign_task_id"] == task.id
        assert recovered["stop_reason"] == "recovery_dispatch_integrity_invalid"
        assert len(failure_stages) == 1
        assert failure_stages[0].stop_reason == "recovery_dispatch_integrity_invalid"
        assert failure_stages[0].payload["outcome"] == (
            "failed:recovery_dispatch_integrity_invalid"
        )
        assert repository.get_campaign(campaign.id).status == "awaiting_review"

        manual_dispatches = []
        retry = autonomous_research_runtime.retry_autonomous_research_task(
            campaign.id,
            task.id,
            repository=repository,
            dispatcher=lambda *, campaign_task_id: manual_dispatches.append(
                campaign_task_id
            ),
        )

        assert retry["status"] == "dispatched"
        assert retry["campaign_task_id"] == task.id
        assert manual_dispatches == [task.id]
        assert repository.get_campaign(campaign.id).status == "running"
    finally:
        session.close()


def test_runtime_recovery_records_conflicting_failure_state_for_manual_retry():
    repository, session = build_repository()
    try:
        campaign = create_runtime_running_campaign(
            repository,
            name="Conflicting runtime failure recovery campaign",
        )
        task = repository.create_campaign_task(
            campaign_id=campaign.id,
            task_type="attack_surface_mapping",
            agent_type="target_model_agent",
            title="Map authorized attack surface facts",
            input_refs=[f"campaign:{campaign.id}"],
            payload=autonomous_research_runtime._runtime_task_payload(
                campaign_id=campaign.id,
                task_type="attack_surface_mapping",
                source_snapshot_digest=SOURCE_SNAPSHOT_DIGEST,
            ),
        )
        task = repository.update_campaign_task_status(task.id, "failed")
        assert task is not None
        for stop_reason in ("dispatch_failed", "worker_failed"):
            repository.save_agent_run(
                campaign_id=campaign.id,
                task_id=task.id,
                agent_type=task.agent_type,
                status="failed",
                input_refs=[f"campaign_task:{task.id}"],
                output_refs=[],
                tool_calls=[],
                safety_gate_state="blocked",
                stop_reason=stop_reason,
                payload=runtime_agent_run_payload(),
            )

        recovered = autonomous_research_runtime._recover_runtime_task_if_needed(
            campaign=campaign,
            repository=repository,
            dispatcher=lambda **_kwargs: None,
            now=datetime(2026, 7, 19, tzinfo=UTC),
        )

        assert recovered is not None
        assert recovered["status"] == "awaiting_review"
        assert recovered["campaign_task_id"] == task.id
        assert recovered["stop_reason"] == "recovery_dispatch_integrity_invalid"
        assert repository.get_campaign(campaign.id).status == "awaiting_review"
        failure_stages = [
            stage
            for stage in repository.list_campaign_pipeline_stages(campaign.id)
            if stage.task_id == task.id and stage.status == "failed"
        ]
        assert len(failure_stages) == 1
        assert failure_stages[0].stop_reason == "recovery_dispatch_integrity_invalid"

        manual_dispatches = []
        retry = autonomous_research_runtime.retry_autonomous_research_task(
            campaign.id,
            task.id,
            repository=repository,
            dispatcher=lambda *, campaign_task_id: manual_dispatches.append(
                campaign_task_id
            ),
        )

        assert retry["status"] == "dispatched"
        assert manual_dispatches == [task.id]
    finally:
        session.close()


def test_runtime_execution_lease_expires_at_the_shared_boundary():
    repository, session = build_repository()
    try:
        now = datetime(2026, 7, 19, tzinfo=UTC)
        campaign = create_runtime_running_campaign(
            repository,
            name="Execution lease boundary campaign",
        )
        dispatched, _dispatched_run = create_dispatched_runtime_task(
            repository,
            campaign=campaign,
            now=now,
        )
        dispatched_expiry = dispatched.execution_lease_expires_at
        assert dispatched_expiry is not None

        assert repository.claim_campaign_task_execution(
            dispatched.id,
            now=dispatched_expiry,
        ) is None
        assert repository.expire_campaign_task_execution(
            dispatched.id,
            now=dispatched_expiry,
        ) is not None

        renewable, _renewable_run = create_dispatched_runtime_task(
            repository,
            campaign=campaign,
            now=now,
        )
        claimed = repository.claim_campaign_task_execution(
            renewable.id,
            now=now + timedelta(seconds=1),
        )
        assert claimed is not None
        renewal_expiry = claimed.execution_lease_expires_at
        assert renewal_expiry is not None

        assert repository.renew_campaign_task_execution_lease(
            renewable.id,
            execution_claim_id=claimed.execution_claim_id,
            now=renewal_expiry,
        ) is None
        assert repository.expire_campaign_task_execution(
            renewable.id,
            now=renewal_expiry,
        ) is not None
    finally:
        session.close()


def test_recovered_orphan_dispatch_failure_fails_closed():
    repository, session = build_repository()
    try:
        now = datetime(2026, 7, 19, tzinfo=UTC)
        campaign = create_runtime_running_campaign(
            repository,
            name="Recovered orphan dispatch failure campaign",
        )
        task = repository.create_campaign_task(
            campaign_id=campaign.id,
            task_type="attack_surface_mapping",
            agent_type="target_model_agent",
            title="Map authorized attack surface facts",
            input_refs=[f"campaign:{campaign.id}"],
            payload=autonomous_research_runtime._runtime_task_payload(
                campaign_id=campaign.id,
                task_type="attack_surface_mapping",
                source_snapshot_digest=SOURCE_SNAPSHOT_DIGEST,
            ),
        )
        orphan_run = repository.save_agent_run(
            campaign_id=campaign.id,
            task_id=task.id,
            agent_type=task.agent_type,
            status="dispatched",
            input_refs=[f"campaign_task:{task.id}"],
            output_refs=[],
            tool_calls=[],
            safety_gate_state="allowed",
            stop_reason=None,
            payload={
                "runtime_schema": "autonomous_research_v1",
                "source_snapshot_digest": SOURCE_SNAPSHOT_DIGEST,
                "dispatch_contract": "id_only",
                "execution_allowed": False,
                "dispatch_allowed": False,
                "validation_allowed": False,
                "candidate_promotion_allowed": False,
                "report_submission_allowed": False,
                "raw_payload_processed": False,
                "raw_payload_in_dispatch": False,
            },
        )

        def failing_dispatcher(**_kwargs):
            raise RuntimeError("synthetic recovered dispatch failure")

        recovered = autonomous_research_runtime._claim_and_dispatch_runtime_task(
            campaign=campaign,
            task=task,
            source_snapshot_digest=SOURCE_SNAPSHOT_DIGEST,
            repository=repository,
            dispatcher=failing_dispatcher,
            agent_run=orphan_run,
            dispatch_attempt=1,
            now=now,
        )
        persisted_task = repository.session.get(type(task), task.id)
        persisted_run = repository.session.get(type(orphan_run), orphan_run.id)

        assert recovered["status"] == "blocked"
        assert recovered["campaign_task_id"] == task.id
        assert recovered["stop_reason"] == "dispatch_failed"
        assert persisted_task is not None
        assert persisted_task.status == "failed"
        assert persisted_run is not None
        assert persisted_run.status == "failed"
        assert persisted_run.safety_gate_state == "blocked"
        assert persisted_run.stop_reason == "dispatch_failed"
        assert repository.get_campaign(campaign.id).status == "awaiting_review"
    finally:
        session.close()


def test_expired_runtime_task_remains_manual_retry_only_across_multi_hour_ticks():
    repository, session = build_repository()
    try:
        now = datetime(2026, 7, 19, tzinfo=UTC)
        campaign = create_runtime_running_campaign(
            repository,
            name="Multi-hour manual retry recovery campaign",
        )
        task, _agent_run = create_dispatched_runtime_task(
            repository,
            campaign=campaign,
            now=now,
        )
        expired_at = now + timedelta(
            seconds=AUTONOMOUS_RESEARCH_TASK_LEASE_SECONDS + 1
        )
        automatic_dispatches = []

        expired = autonomous_research_runtime.tick_autonomous_research_campaign(
            campaign.id,
            repository=repository,
            dispatcher=lambda *, campaign_task_id: automatic_dispatches.append(
                campaign_task_id
            ),
            now=expired_at,
        )
        follow_up_ticks = [
            autonomous_research_runtime.tick_autonomous_research_campaign(
                campaign.id,
                repository=repository,
                dispatcher=lambda *, campaign_task_id: automatic_dispatches.append(
                    campaign_task_id
                ),
                now=expired_at + timedelta(hours=hour),
            )
            for hour in range(1, 49)
        ]
        persisted_task = repository.session.get(type(task), task.id)
        task_runs = [
            run
            for run in repository.list_campaign_agent_runs(campaign.id)
            if run.task_id == task.id
        ]
        failure_stages = [
            stage
            for stage in repository.list_campaign_pipeline_stages(campaign.id)
            if stage.task_id == task.id and stage.status == "failed"
        ]

        assert expired["status"] == "awaiting_review"
        assert expired["stop_reason"] == "execution_lease_expired"
        assert all(
            result["status"] == "awaiting_review"
            and result["stop_reason"] == "human_review_required"
            for result in follow_up_ticks
        )
        assert all(
            result[field] is False
            for result in [expired, *follow_up_ticks]
            for field in (
                "execution_allowed",
                "dispatch_allowed",
                "validation_allowed",
                "candidate_promotion_allowed",
                "report_submission_allowed",
            )
        )
        assert automatic_dispatches == []
        assert persisted_task is not None
        assert persisted_task.status == "failed"
        assert len(task_runs) == 1
        assert len(failure_stages) == 1
        assert repository.get_campaign(campaign.id).status == "awaiting_review"

        manual_dispatches = []
        retry = autonomous_research_runtime.retry_autonomous_research_task(
            campaign.id,
            task.id,
            repository=repository,
            dispatcher=lambda *, campaign_task_id: manual_dispatches.append(
                campaign_task_id
            ),
        )

        assert retry["status"] == "dispatched"
        assert retry["campaign_task_id"] == task.id
        assert manual_dispatches == [task.id]
        assert len(
            [
                run
                for run in repository.list_campaign_agent_runs(campaign.id)
                if run.task_id == task.id
            ]
        ) == 2
        retry_stages = [
            stage
            for stage in repository.list_campaign_pipeline_stages(campaign.id)
            if stage.task_id == task.id
            and stage.status == "dispatched"
            and stage.payload.get("outcome") == "retry_dispatched_2"
        ]
        assert len(retry_stages) == 1, [
            (stage.status, stage.payload.get("outcome"))
            for stage in repository.list_campaign_pipeline_stages(campaign.id)
            if stage.task_id == task.id
        ]
        assert all(
            retry_stages[0].payload[field] is False
            for field in (
                "execution_allowed",
                "dispatch_allowed",
                "validation_allowed",
                "candidate_promotion_allowed",
                "report_submission_allowed",
            )
        )
    finally:
        session.close()


def test_runtime_stage_outcome_is_bounded_for_audit_projection():
    safe = autonomous_research_runtime._runtime_stage_payload(
        campaign_id="campaign_example",
        task_type="attack_surface_mapping",
        source_snapshot_digest=SOURCE_SNAPSHOT_DIGEST,
        outcome="retry_dispatched_2",
    )
    invalid = autonomous_research_runtime._runtime_stage_payload(
        campaign_id="campaign_example",
        task_type="attack_surface_mapping",
        source_snapshot_digest=SOURCE_SNAPSHOT_DIGEST,
        outcome="token=should-not-persist",
    )

    assert safe["outcome"] == "retry_dispatched_2"
    assert invalid["outcome"] == "invalid_outcome"
    assert "should-not-persist" not in str(invalid)
    assert all(
        invalid[field] is False
        for field in (
            "execution_allowed",
            "dispatch_allowed",
            "validation_allowed",
            "candidate_promotion_allowed",
            "report_submission_allowed",
            "raw_payload_processed",
            "raw_payload_in_dispatch",
        )
    )


def test_runtime_failure_stage_replay_is_atomic_on_primary_key_conflict(monkeypatch):
    repository, session = build_repository()
    try:
        campaign = create_runtime_running_campaign(
            repository,
            name="Atomic runtime failure stage replay campaign",
        )
        task = repository.create_campaign_task(
            campaign_id=campaign.id,
            task_type="attack_surface_mapping",
            agent_type="target_model_agent",
            title="Map authorized attack surface facts",
            input_refs=[f"campaign:{campaign.id}"],
            payload=autonomous_research_runtime._runtime_task_payload(
                campaign_id=campaign.id,
                task_type="attack_surface_mapping",
                source_snapshot_digest=SOURCE_SNAPSHOT_DIGEST,
            ),
        )
        payload = autonomous_research_runtime._runtime_stage_payload(
            campaign_id=campaign.id,
            task_type=task.task_type,
            source_snapshot_digest=SOURCE_SNAPSHOT_DIGEST,
            outcome="failed:worker_failed",
        )
        stage_id = autonomous_research_runtime._runtime_failure_stage_id(
            task_id=task.id,
            source_snapshot_digest=SOURCE_SNAPSHOT_DIGEST,
            stop_reason="worker_failed",
        )
        save_kwargs = {
            "pipeline_run_id": None,
            "campaign_id": campaign.id,
            "task_id": task.id,
            "stage_id": stage_id,
            "stage_key": f"autonomous_research:{task.task_type}",
            "stage_order": 1,
            "status": "failed",
            "input_refs": task.input_refs,
            "output_refs": [],
            "safety_gate_state": "blocked",
            "stop_reason": "worker_failed",
            "payload": payload,
        }
        first = repository.save_pipeline_stage(**save_kwargs)
        monkeypatch.setattr(
            repository_module,
            "_existing_pipeline_stage_for_idempotency_key",
            lambda *_args, **_kwargs: None,
        )

        with warnings.catch_warnings():
            warnings.simplefilter("error", SAWarning)
            replay = repository.save_pipeline_stage(**save_kwargs)

        assert replay.id == stage_id
        assert [
            stage.id
            for stage in repository.list_campaign_pipeline_stages(campaign.id)
            if stage.id == stage_id
        ] == [stage_id]
        session.expunge(replay)
        original_get = session.get
        skip_initial_stage_lookup = True

        def get_after_concurrent_insert(entity, ident, *args, **kwargs):
            nonlocal skip_initial_stage_lookup
            if ident == stage_id and skip_initial_stage_lookup:
                skip_initial_stage_lookup = False
                return None
            return original_get(entity, ident, *args, **kwargs)

        monkeypatch.setattr(session, "get", get_after_concurrent_insert)
        with warnings.catch_warnings():
            warnings.simplefilter("error", SAWarning)
            recovered = repository.save_pipeline_stage(**save_kwargs)

        assert recovered.id == stage_id
        with warnings.catch_warnings():
            warnings.simplefilter("error", SAWarning)
            with pytest.raises(ValueError, match="pipeline_stage_id_conflict"):
                repository.save_pipeline_stage(
                    **{**save_kwargs, "stop_reason": "dispatch_failed"}
                )
    finally:
        session.close()


def test_runtime_retry_rejects_mismatched_failure_stage_idempotency_record():
    repository, session = build_repository()
    try:
        now = datetime(2026, 7, 19, tzinfo=UTC)
        campaign = create_runtime_running_campaign(
            repository,
            name="Mismatched runtime failure stage campaign",
        )
        task, agent_run = create_dispatched_runtime_task(
            repository,
            campaign=campaign,
            now=now,
        )
        task = repository.claim_campaign_task_execution(
            task.id,
            now=now + timedelta(seconds=1),
        )
        assert task is not None
        failed_execution = repository.finish_campaign_task_execution(
            task_id=task.id,
            execution_claim_id=task.execution_claim_id,
            task_status="failed",
            task_output_refs=[f"agent_run:{agent_run.id}"],
            agent_status="failed",
            agent_output_refs=[],
            safety_gate_state="blocked",
            stop_reason="worker_failed",
            payload=runtime_agent_run_payload(),
            expected_execution_statuses={"running"},
        )
        assert failed_execution is not None
        failed_task = failed_execution[0]
        repository.save_pipeline_stage(
            pipeline_run_id=None,
            campaign_id=campaign.id,
            task_id=failed_task.id,
            stage_id="pipeline_stage_mismatched_runtime_failure",
            stage_key=f"autonomous_research:{failed_task.task_type}",
            stage_order=1,
            status="failed",
            input_refs=failed_task.input_refs,
            output_refs=failed_task.output_refs,
            safety_gate_state="blocked",
            stop_reason="worker_failed",
            payload=autonomous_research_runtime._runtime_stage_payload(
                campaign_id=campaign.id,
                task_type=failed_task.task_type,
                source_snapshot_digest=SOURCE_SNAPSHOT_DIGEST,
                outcome="failed:worker_failed",
            ),
        )
        dispatched_task_ids = []

        retry = autonomous_research_runtime.retry_autonomous_research_task(
            campaign.id,
            failed_task.id,
            repository=repository,
            dispatcher=lambda *, campaign_task_id: dispatched_task_ids.append(
                campaign_task_id
            ),
        )

        assert retry["status"] == "awaiting_review"
        assert retry["stop_reason"] == "human_review_required"
        assert dispatched_task_ids == []
        assert repository.get_pipeline_stage(
            autonomous_research_runtime._runtime_failure_stage_id(
                task_id=failed_task.id,
                source_snapshot_digest=SOURCE_SNAPSHOT_DIGEST,
                stop_reason="worker_failed",
            )
        ) is None
    finally:
        session.close()


def test_runtime_retry_claim_prevents_duplicate_dispatch(monkeypatch):
    repository, session = build_repository()
    try:
        now = datetime(2026, 7, 19, tzinfo=UTC)
        campaign = create_runtime_running_campaign(
            repository,
            name="Atomic runtime retry claim campaign",
        )
        task, agent_run = create_dispatched_runtime_task(
            repository,
            campaign=campaign,
            now=now,
        )
        task = repository.claim_campaign_task_execution(
            task.id,
            now=now + timedelta(seconds=1),
        )
        assert task is not None
        failed_execution = repository.finish_campaign_task_execution(
            task_id=task.id,
            execution_claim_id=task.execution_claim_id,
            task_status="failed",
            task_output_refs=[f"agent_run:{agent_run.id}"],
            agent_status="failed",
            agent_output_refs=[],
            safety_gate_state="blocked",
            stop_reason="worker_failed",
            payload=runtime_agent_run_payload(),
            expected_execution_statuses={"running"},
        )
        assert failed_execution is not None
        failed_task = failed_execution[0]
        assert autonomous_research_runtime.record_autonomous_research_task_failure(
            task=failed_task,
            repository=repository,
            stop_reason="worker_failed",
        )

        original_claim = repository.claim_failed_campaign_task_retry
        interleaved_results = []
        dispatcher_calls = []

        def claim_with_interleaved_retry(campaign_task_id):
            claimed_task = original_claim(campaign_task_id)
            if claimed_task is not None and not interleaved_results:
                interleaved_results.append(
                    autonomous_research_runtime.retry_autonomous_research_task(
                        campaign.id,
                        failed_task.id,
                        repository=repository,
                        dispatcher=lambda *, campaign_task_id: dispatcher_calls.append(
                            campaign_task_id
                        ),
                    )
                )
            return claimed_task

        monkeypatch.setattr(
            repository,
            "claim_failed_campaign_task_retry",
            claim_with_interleaved_retry,
        )

        retry = autonomous_research_runtime.retry_autonomous_research_task(
            campaign.id,
            failed_task.id,
            repository=repository,
            dispatcher=lambda *, campaign_task_id: dispatcher_calls.append(
                campaign_task_id
            ),
        )
        active_runs = [
            run
            for run in repository.list_campaign_agent_runs(campaign.id)
            if run.task_id == failed_task.id
            and run.status in {"dispatched", "running", "awaiting_approval"}
        ]

        assert retry["status"] == "dispatched"
        assert interleaved_results == [
            {
                "status": "blocked",
                "campaign_task_id": failed_task.id,
                "stop_reason": "runtime_task_not_retryable",
                "source_snapshot_digest": SOURCE_SNAPSHOT_DIGEST,
                "execution_allowed": False,
                "dispatch_allowed": False,
                "validation_allowed": False,
                "candidate_promotion_allowed": False,
                "report_submission_allowed": False,
                "raw_payload_processed": False,
                "raw_payload_in_dispatch": False,
            }
        ]
        assert dispatcher_calls == [failed_task.id]
        assert len(active_runs) == 1
    finally:
        session.close()


def test_retry_claim_is_atomic_across_database_sessions(tmp_path):
    database_path = tmp_path / "autonomous-retry-claim.db"
    engine = create_engine(
        f"sqlite+pysqlite:///{database_path.as_posix()}",
        connect_args={"check_same_thread": False, "timeout": 10},
    )
    Base.metadata.create_all(bind=engine)
    Session = sessionmaker(bind=engine)
    setup_session = Session()
    try:
        setup_repository = DatabaseRepository(setup_session)
        campaign = setup_repository.create_campaign(
            program_id=None,
            name="Cross-session retry claim campaign",
            autonomy_level="level_0_read_only",
            scope_status="in_scope",
            policy_text="Authorized local review only.",
            default_asset="local.example",
            created_by="operator",
        )
        task = setup_repository.create_campaign_task(
            campaign_id=campaign.id,
            task_type="attack_surface_mapping",
            agent_type="target_model_agent",
            title="Map authorized attack surface facts",
        )
        task = setup_repository.update_campaign_task_status(task.id, "failed")
        assert task is not None
    finally:
        setup_session.close()

    barrier = Barrier(2)
    results = []
    errors = []

    def claim_retry():
        session = Session()
        try:
            repository = DatabaseRepository(session)
            barrier.wait(timeout=10)
            claimed_task = repository.claim_failed_campaign_task_retry(task.id)
            results.append(claimed_task.id if claimed_task is not None else None)
        except BaseException as exc:
            errors.append(exc)
        finally:
            session.close()

    threads = [Thread(target=claim_retry), Thread(target=claim_retry)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=10)

    verification_session = Session()
    try:
        persisted_task = verification_session.get(type(task), task.id)

        assert all(not thread.is_alive() for thread in threads)
        assert errors == []
        assert set(results) == {task.id, None}
        assert persisted_task is not None
        assert persisted_task.status == "queued"
        assert persisted_task.execution_claim_id is None
        assert persisted_task.execution_lease_expires_at is None
    finally:
        verification_session.close()
        engine.dispose()


def _local_postgresql_runtime_test_url():
    database_url = os.getenv("AUTONOMOUS_RESEARCH_POSTGRES_TEST_URL")
    if not database_url:
        return None
    try:
        url = make_url(database_url)
    except Exception:
        return None
    if (
        url.drivername != "postgresql+psycopg"
        or url.host not in {"127.0.0.1", "localhost"}
        or not isinstance(url.database, str)
        or not url.database.startswith("phase6_")
        or url.query
    ):
        return None
    return url


def test_local_postgresql_retry_claim_url_rejects_connection_overrides(monkeypatch):
    monkeypatch.setenv(
        "AUTONOMOUS_RESEARCH_POSTGRES_TEST_URL",
        "postgresql+psycopg://phase6:phase6@127.0.0.1:55432/"
        "phase6_retry_claim?host=remote.example",
    )

    assert _local_postgresql_runtime_test_url() is None


def test_retry_claim_is_atomic_on_local_postgresql():
    url = _local_postgresql_runtime_test_url()
    if url is None:
        pytest.skip("postgres_runtime_test_not_configured")

    engine = create_engine(url)
    schema_name = f"phase6_retry_{uuid4().hex}"
    scoped_engine = engine.execution_options(
        schema_translate_map={None: schema_name}
    )
    try:
        with engine.begin() as connection:
            connection.execute(text(f'CREATE SCHEMA "{schema_name}"'))
        Base.metadata.create_all(bind=scoped_engine)
        Session = sessionmaker(bind=scoped_engine)
        setup_session = Session()
        try:
            setup_repository = DatabaseRepository(setup_session)
            campaign = setup_repository.create_campaign(
                program_id=None,
                name="PostgreSQL retry claim campaign",
                autonomy_level="level_0_read_only",
                scope_status="in_scope",
                policy_text="Authorized local review only.",
                default_asset="local.example",
                created_by="operator",
            )
            task = setup_repository.create_campaign_task(
                campaign_id=campaign.id,
                task_type="attack_surface_mapping",
                agent_type="target_model_agent",
                title="Map authorized attack surface facts",
            )
            task = setup_repository.update_campaign_task_status(task.id, "failed")
            assert task is not None
        finally:
            setup_session.close()

        barrier = Barrier(2)
        results = []
        errors = []

        def claim_retry():
            session = Session()
            try:
                repository = DatabaseRepository(session)
                barrier.wait(timeout=10)
                claimed_task = repository.claim_failed_campaign_task_retry(task.id)
                results.append(claimed_task.id if claimed_task is not None else None)
            except BaseException as exc:
                errors.append(exc)
            finally:
                session.close()

        threads = [Thread(target=claim_retry), Thread(target=claim_retry)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=10)

        verification_session = Session()
        try:
            persisted_task = verification_session.get(type(task), task.id)

            assert all(not thread.is_alive() for thread in threads)
            assert errors == []
            assert set(results) == {task.id, None}
            assert persisted_task is not None
            assert persisted_task.status == "queued"
            assert persisted_task.execution_claim_id is None
            assert persisted_task.execution_lease_expires_at is None
        finally:
            verification_session.close()
    finally:
        with engine.begin() as connection:
            connection.execute(text(f'DROP SCHEMA IF EXISTS "{schema_name}" CASCADE'))
        engine.dispose()


def test_runtime_execution_heartbeat_renews_running_task_lease():
    repository, session = build_repository()
    try:
        now = datetime(2026, 7, 19, tzinfo=UTC)
        campaign = create_runtime_running_campaign(
            repository,
            name="Runtime execution heartbeat campaign",
        )
        task, _agent_run = create_dispatched_runtime_task(
            repository,
            campaign=campaign,
            now=now,
        )
        claimed_task = repository.claim_campaign_task_execution(
            task.id,
            now=now + timedelta(seconds=1),
        )
        assert claimed_task is not None
        original_expiry = claimed_task.execution_lease_expires_at
        assert original_expiry is not None

        renewed_task = repository.renew_campaign_task_execution_lease(
            task.id,
            execution_claim_id=claimed_task.execution_claim_id,
            now=original_expiry - timedelta(seconds=1),
        )
        expired_task = repository.expire_campaign_task_execution(
            task.id,
            now=original_expiry + timedelta(seconds=1),
        )
        persisted_task = repository.session.get(type(task), task.id)

        assert renewed_task is not None
        assert renewed_task.execution_lease_expires_at is not None
        assert renewed_task.execution_lease_expires_at > original_expiry
        assert expired_task is None
        assert persisted_task is not None
        assert persisted_task.status == "running"
    finally:
        session.close()


def test_report_terminal_completion_preserves_unrelated_pending_human_review():
    repository, session = build_repository()
    try:
        campaign = create_runtime_running_campaign(
            repository,
            name="Terminal report completion with pending human review",
        )
        report_task = repository.create_campaign_task(
            campaign_id=campaign.id,
            task_type="report_review",
            agent_type="report_agent",
            title="Build submission-blocked report review",
            input_refs=[f"campaign:{campaign.id}"],
            payload=autonomous_research_runtime._runtime_task_payload(
                campaign_id=campaign.id,
                task_type="report_review",
                source_snapshot_digest=SOURCE_SNAPSHOT_DIGEST,
            ),
        )
        handoff = repository.create_campaign_task(
            campaign_id=campaign.id,
            task_type="validation_handoff",
            agent_type="human_review",
            title="Review another validation handoff",
            input_refs=[f"campaign:{campaign.id}"],
            payload={"raw_payload_processed": False},
        )
        handoff = repository.update_campaign_task_status(
            handoff.id,
            "awaiting_approval",
        )
        assert handoff is not None

        autonomous_research_runtime.record_autonomous_research_task_completion(
            task=report_task,
            repository=repository,
            terminal_stop_reason="no_reportable_candidates",
            terminal_campaign_status="completed",
        )

        persisted_campaign = repository.get_campaign(campaign.id)
        runtime_stage = next(
            stage
            for stage in repository.list_campaign_pipeline_stages(campaign.id)
            if stage.task_id == report_task.id
            and stage.stage_key == "autonomous_research:report_review"
        )

        assert persisted_campaign is not None
        assert persisted_campaign.status == "awaiting_review"
        assert runtime_stage.stop_reason == "no_reportable_candidates"
        assert repository.session.get(type(handoff), handoff.id).status == "awaiting_approval"
    finally:
        session.close()


def test_runtime_recovers_partial_candidate_specific_report_handoff(monkeypatch):
    repository, session = build_repository()
    try:
        campaign = create_runtime_running_campaign(
            repository,
            name="Partial candidate-specific report recovery",
        )
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
        report_task = repository.create_campaign_task(
            campaign_id=campaign.id,
            task_type="report_review",
            agent_type="report_agent",
            title="Build submission-blocked report review",
            input_refs=[f"pipeline_run:{pipeline_run.id}"],
            payload=autonomous_research_runtime._runtime_task_payload(
                campaign_id=campaign.id,
                task_type="report_review",
                source_snapshot_digest=SOURCE_SNAPSHOT_DIGEST,
                pipeline_run_id=pipeline_run.id,
            ),
        )
        report_task = repository.update_campaign_task_status(report_task.id, "running")
        assert report_task is not None
        handoff = repository.create_campaign_task(
            campaign_id=campaign.id,
            task_type="validation_handoff",
            agent_type="human_review",
            title="Review submission-blocked validation handoff",
            input_refs=[
                f"pipeline_run:{pipeline_run.id}",
                f"campaign_task:{report_task.id}",
                "candidate:H-001",
            ],
            payload={
                "schema_version": "autonomous_validation_handoff_v1",
                "pipeline_run_id": pipeline_run.id,
                "report_review_task_id": report_task.id,
                "source_snapshot_digest": SOURCE_SNAPSHOT_DIGEST,
                "candidate_id": "H-001",
                "candidate_ids": ["H-001"],
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
        recovered_tasks = []

        def recover_report_review_task(*, task, campaign, repository):
            recovered_tasks.append((task.id, campaign.id))
            return {"status": "completed", "stop_reason": None}

        monkeypatch.setattr(
            worker_tasks,
            "recover_report_review_task",
            recover_report_review_task,
        )

        recovered = autonomous_research_runtime._recover_runtime_task_if_needed(
            campaign=campaign,
            repository=repository,
            dispatcher=lambda **_kwargs: None,
            now=datetime(2026, 7, 22, tzinfo=UTC),
        )

        assert recovered is not None
        assert recovered["status"] == "completed"
        assert recovered["campaign_task_id"] == report_task.id
        assert recovered_tasks == [(report_task.id, campaign.id)]
        assert repository.session.get(type(handoff), handoff.id).status == "queued"
    finally:
        session.close()


def test_runtime_recovery_fails_expired_running_task():
    repository, session = build_repository()
    try:
        now = datetime(2026, 7, 19, tzinfo=UTC)
        campaign = create_runtime_running_campaign(
            repository,
            name="Expired runtime worker campaign",
        )
        task, _agent_run = create_dispatched_runtime_task(
            repository,
            campaign=campaign,
            now=now,
        )
        claimed_task = repository.claim_campaign_task_execution(
            task.id,
            now=now + timedelta(seconds=1),
        )
        assert claimed_task is not None
        assert claimed_task.status == "running"

        recovered = autonomous_research_runtime._recover_runtime_task_if_needed(
            campaign=campaign,
            repository=repository,
            dispatcher=lambda **_kwargs: None,
            now=now
            + timedelta(seconds=AUTONOMOUS_RESEARCH_TASK_LEASE_SECONDS + 2),
        )
        persisted_task = repository.session.get(type(task), task.id)

        assert recovered is not None
        assert recovered["status"] == "awaiting_review"
        assert recovered["stop_reason"] == "execution_lease_expired"
        assert persisted_task is not None
        assert persisted_task.status == "failed"
        assert repository.get_campaign(campaign.id).status == "awaiting_review"
    finally:
        session.close()


def test_wakeup_stops_budget_and_scope_preflight_failures_from_repeating():
    repository, session = build_repository()
    try:
        budget_campaign = create_runtime_running_campaign(
            repository,
            name="Budget exhausted runtime campaign",
        )
        scope_campaign = create_running_campaign(
            repository,
            name="Missing scope guard runtime campaign",
        )
        repository.upsert_campaign_budget(
            campaign_id=budget_campaign.id,
            time_budget_minutes=0,
            token_budget=100,
            tool_call_budget=100,
            validation_budget=0,
        )
        dispatched_task_ids = []
        now = datetime(2026, 7, 19, tzinfo=UTC)

        first = autonomous_research_wakeup.run_autonomous_research_wakeup(
            repository=repository,
            dispatcher=lambda *, campaign_task_id: dispatched_task_ids.append(
                campaign_task_id
            ),
            now=now,
        )
        second = autonomous_research_wakeup.run_autonomous_research_wakeup(
            repository=repository,
            dispatcher=lambda *, campaign_task_id: dispatched_task_ids.append(
                campaign_task_id
            ),
            now=now + timedelta(minutes=1),
        )
        preflight_stages = [
            stage
            for campaign in (budget_campaign, scope_campaign)
            for stage in repository.list_campaign_pipeline_stages(campaign.id)
            if stage.stage_key == "autonomous_research_preflight"
        ]

        assert first["status"] == "completed"
        assert first["outcome_counts"] == {"blocked": 2}
        assert second["status"] == "completed"
        assert second["processed_count"] == 0
        assert dispatched_task_ids == []
        assert repository.get_campaign(budget_campaign.id).status == "paused"
        assert repository.get_campaign(scope_campaign.id).status == "blocked"
        assert len(preflight_stages) == 2
        assert {
            (stage.status, stage.stop_reason)
            for stage in preflight_stages
        } == {
            ("paused", "budget_exhausted"),
            ("blocked", "scope_guard_rule_missing"),
        }
        assert all(
            all(
                stage.payload[field] is False
                for field in (
                    "execution_allowed",
                    "dispatch_allowed",
                    "validation_allowed",
                    "candidate_promotion_allowed",
                    "report_submission_allowed",
                    "raw_payload_processed",
                    "raw_payload_in_dispatch",
                )
            )
            for stage in preflight_stages
        )
        assert "source_snapshot_digest" not in next(
            stage.payload
            for stage in preflight_stages
            if stage.stop_reason == "scope_guard_rule_missing"
        )
    finally:
        session.close()


def test_runtime_rejects_snapshot_change_without_a_reviewed_refresh_stage():
    repository, session = build_repository()
    try:
        campaign = create_runtime_running_campaign(
            repository,
            name="Unreviewed snapshot change campaign",
        )
        task = repository.create_campaign_task(
            campaign_id=campaign.id,
            task_type="campaign_observation",
            agent_type="orchestrator_agent",
            title="Observe authorized campaign state",
            payload=autonomous_research_runtime._runtime_task_payload(
                campaign_id=campaign.id,
                task_type="campaign_observation",
                source_snapshot_digest=SOURCE_SNAPSHOT_DIGEST,
            ),
        )
        task = repository.update_campaign_task_status(task.id, "completed")
        assert task is not None
        autonomous_research_runtime.record_autonomous_research_task_completion(
            task=task,
            repository=repository,
        )
        campaign = repository.get_campaign(campaign.id)
        assert campaign is not None
        campaign.payload = {
            **campaign.payload,
            "source_snapshot_digest": "sha256:" + "b" * 64,
        }
        session.add(campaign)
        session.commit()

        selection = autonomous_research_runtime.select_autonomous_research_work(
            campaign=repository.get_campaign(campaign.id),
            repository=repository,
        )

        assert selection["status"] == "blocked"
        assert selection["stop_reason"] == "source_snapshot_changed"
    finally:
        session.close()


@pytest.mark.parametrize(
    "task_status",
    ("queued", "failed"),
)
def test_runtime_rejects_completed_stage_without_a_matching_completed_task(
    task_status,
):
    repository, session = build_repository()
    try:
        campaign = create_runtime_running_campaign(
            repository,
            name="Unlinked completed stage campaign",
        )
        task = repository.create_campaign_task(
            campaign_id=campaign.id,
            task_type="campaign_observation",
            agent_type="orchestrator_agent",
            title="Observe authorized campaign state",
            input_refs=[
                f"campaign:{campaign.id}",
                f"source_snapshot:{SOURCE_SNAPSHOT_DIGEST}",
            ],
            payload=autonomous_research_runtime._runtime_task_payload(
                campaign_id=campaign.id,
                task_type="campaign_observation",
                source_snapshot_digest=SOURCE_SNAPSHOT_DIGEST,
            ),
        )
        task = repository.update_campaign_task_status(task.id, task_status)
        assert task is not None
        repository.save_pipeline_stage(
            pipeline_run_id=None,
            campaign_id=campaign.id,
            task_id=task.id,
            stage_key="autonomous_research:campaign_observation",
            stage_order=1,
            status="completed",
            input_refs=[
                f"campaign:{campaign.id}",
                f"source_snapshot:{SOURCE_SNAPSHOT_DIGEST}",
            ],
            output_refs=[],
            safety_gate_state="allowed",
            stop_reason=None,
            payload=autonomous_research_runtime._runtime_stage_payload(
                campaign_id=campaign.id,
                task_type="campaign_observation",
                source_snapshot_digest=SOURCE_SNAPSHOT_DIGEST,
                outcome="completed",
            ),
        )

        selection = autonomous_research_runtime.select_autonomous_research_work(
            campaign=campaign,
            repository=repository,
        )

        assert selection["status"] == "blocked"
        assert selection["stop_reason"] == "malformed_runtime_stage"
    finally:
        session.close()


def test_wakeup_paginates_running_campaigns_without_starving_later_ids(monkeypatch):
    repository, session = build_repository()
    try:
        for index in range(25):
            create_running_campaign(repository, name=f"Wakeup campaign {index}")
        first_page = repository.list_autonomous_wakeup_campaigns()
        first_page_ids = [item["id"] for item in first_page]
        second_page_ids = [
            item["id"]
            for item in repository.list_autonomous_wakeup_campaigns(
                after_id=first_page_ids[-1]
            )
        ]
        ticked_campaign_ids = []

        def tick(campaign_id, *, repository, dispatcher, now):
            ticked_campaign_ids.append(campaign_id)
            return {"status": "dispatched", "stop_reason": None}

        monkeypatch.setattr(
            autonomous_research_wakeup,
            "tick_autonomous_research_campaign",
            tick,
        )
        now = datetime(2026, 7, 19, tzinfo=UTC)

        first = autonomous_research_wakeup.run_autonomous_research_wakeup(
            repository=repository,
            dispatcher=lambda **_kwargs: None,
            now=now,
        )
        second = autonomous_research_wakeup.run_autonomous_research_wakeup(
            repository=repository,
            dispatcher=lambda **_kwargs: None,
            now=now + timedelta(minutes=1),
        )

        state = repository.get_autonomous_research_wakeup_state()
        assert first["status"] == "completed"
        assert first["processed_count"] == 20
        assert first["outcome_counts"] == {"dispatched": 20}
        assert second["status"] == "completed"
        assert second["processed_count"] == 5
        assert second["outcome_counts"] == {"dispatched": 5}
        assert ticked_campaign_ids == [*first_page_ids, *second_page_ids]
        assert state is not None
        assert state.after_campaign_id is None
        assert state.lease_token_digest is None
        assert state.execution_allowed is False
        assert state.validation_allowed is False
        assert state.report_submission_allowed is False
    finally:
        session.close()


def test_wakeup_renewal_extends_only_the_owned_lease():
    repository, session = build_repository()
    try:
        now = datetime(2026, 7, 19, tzinfo=UTC)
        owner_token = sha256(b"owner").hexdigest()
        claim = repository.claim_autonomous_research_wakeup(
            claim_token_digest=owner_token,
            now=now,
        )
        initial_state = repository.get_autonomous_research_wakeup_state()
        initial_expiry = (
            initial_state.lease_expires_at if initial_state is not None else None
        )

        renewed = repository.renew_autonomous_research_wakeup(
            claim_token_digest=owner_token,
            now=now + timedelta(seconds=1),
        )
        rejected = repository.renew_autonomous_research_wakeup(
            claim_token_digest=sha256(b"other").hexdigest(),
            now=now + timedelta(seconds=2),
        )
        renewed_state = repository.get_autonomous_research_wakeup_state()

        assert claim is not None
        assert initial_state is not None
        assert initial_expiry is not None
        assert renewed is True
        assert rejected is False
        assert renewed_state is not None
        assert renewed_state.lease_token_digest == owner_token
        assert renewed_state.lease_expires_at is not None
        assert renewed_state.lease_expires_at > initial_expiry
        assert renewed_state.execution_allowed is False
        assert renewed_state.validation_allowed is False
        assert renewed_state.report_submission_allowed is False
    finally:
        session.close()


def test_wakeup_stops_without_advancing_cursor_when_lease_renewal_fails(monkeypatch):
    repository, session = build_repository()
    try:
        for index in range(20):
            create_running_campaign(repository, name=f"Renewal campaign {index}")
        candidate_ids = [
            item["id"] for item in repository.list_autonomous_wakeup_campaigns()
        ]
        ticked_campaign_ids = []
        renewal_timestamps = []

        def tick(campaign_id, *, repository, dispatcher, now):
            ticked_campaign_ids.append(campaign_id)
            return {"status": "dispatched", "stop_reason": None}

        def renew(*, claim_token_digest, now):
            renewal_timestamps.append(now)
            return len(renewal_timestamps) == 1

        monkeypatch.setattr(
            autonomous_research_wakeup,
            "tick_autonomous_research_campaign",
            tick,
        )
        monkeypatch.setattr(
            repository,
            "renew_autonomous_research_wakeup",
            renew,
            raising=False,
        )
        now = datetime(2026, 7, 19, tzinfo=UTC)

        result = autonomous_research_wakeup.run_autonomous_research_wakeup(
            repository=repository,
            dispatcher=lambda **_kwargs: None,
            now=now,
        )

        state = repository.get_autonomous_research_wakeup_state()
        assert result["status"] == "lease_lost"
        assert result["stop_reason"] == "wakeup_lease_lost"
        assert result["processed_count"] == 1
        assert result["outcome_counts"] == {"dispatched": 1}
        assert ticked_campaign_ids == [candidate_ids[0]]
        assert renewal_timestamps == [now, now]
        assert state is not None
        assert state.after_campaign_id is None
    finally:
        session.close()


def test_wakeup_recovers_from_an_expired_lease_without_duplicate_parallel_work(monkeypatch):
    repository, session = build_repository()
    try:
        campaign = create_running_campaign(repository, name="Lease recovery campaign")
        now = datetime(2026, 7, 19, tzinfo=UTC)
        active_claim = repository.claim_autonomous_research_wakeup(
            claim_token_digest=sha256(b"active").hexdigest(),
            now=now,
        )
        assert active_claim is not None
        ticked_campaign_ids = []

        def tick(campaign_id, *, repository, dispatcher, now):
            ticked_campaign_ids.append(campaign_id)
            return {"status": "dispatched", "stop_reason": None}

        monkeypatch.setattr(
            autonomous_research_wakeup,
            "tick_autonomous_research_campaign",
            tick,
        )

        held = autonomous_research_wakeup.run_autonomous_research_wakeup(
            repository=repository,
            dispatcher=lambda **_kwargs: None,
            now=now + timedelta(seconds=1),
        )
        recovered = autonomous_research_wakeup.run_autonomous_research_wakeup(
            repository=repository,
            dispatcher=lambda **_kwargs: None,
            now=now
            + timedelta(
                seconds=autonomous_research_wakeup.WAKEUP_LEASE_SECONDS + 1
            ),
        )

        assert held["status"] == "lease_held"
        assert recovered["status"] == "completed"
        assert ticked_campaign_ids == [campaign.id]
    finally:
        session.close()


def test_wakeup_isolates_a_crashed_campaign_and_retries_it_after_the_page_cycle(monkeypatch):
    repository, session = build_repository()
    try:
        create_running_campaign(repository, name="Wakeup retry campaign A")
        create_running_campaign(repository, name="Wakeup retry campaign B")
        candidate_ids = [
            candidate["id"]
            for candidate in repository.list_autonomous_wakeup_campaigns()
        ]
        failed_campaign_id = candidate_ids[0]
        now = datetime(2026, 7, 19, tzinfo=UTC)
        ticked_campaign_ids = []

        def failing_tick(campaign_id, *, repository, dispatcher, now):
            ticked_campaign_ids.append(campaign_id)
            if campaign_id == failed_campaign_id:
                raise RuntimeError("synthetic wakeup crash")
            return {"status": "dispatched", "stop_reason": None}

        monkeypatch.setattr(
            autonomous_research_wakeup,
            "tick_autonomous_research_campaign",
            failing_tick,
        )
        first = autonomous_research_wakeup.run_autonomous_research_wakeup(
            repository=repository,
            dispatcher=lambda **_kwargs: None,
            now=now,
        )
        state_after_failure = repository.get_autonomous_research_wakeup_state()
        recovered_campaign_ids = []

        def recovered_tick(campaign_id, *, repository, dispatcher, now):
            recovered_campaign_ids.append(campaign_id)
            return {"status": "dispatched", "stop_reason": None}

        monkeypatch.setattr(
            autonomous_research_wakeup,
            "tick_autonomous_research_campaign",
            recovered_tick,
        )
        second = autonomous_research_wakeup.run_autonomous_research_wakeup(
            repository=repository,
            dispatcher=lambda **_kwargs: None,
            now=now + timedelta(minutes=1),
        )

        assert first["status"] == "completed"
        assert first["stop_reason"] == "wakeup_campaign_tick_failed"
        assert first["processed_count"] == 2
        assert first["outcome_counts"] == {"dispatched": 1, "failed": 1}
        assert ticked_campaign_ids == candidate_ids
        assert state_after_failure is not None
        assert state_after_failure.after_campaign_id is None
        assert state_after_failure.lease_token_digest is None
        assert second["status"] == "completed"
        assert recovered_campaign_ids == candidate_ids
    finally:
        session.close()


def test_wakeup_respects_the_existing_human_approval_gate():
    repository, session = build_repository()
    try:
        campaign = repository.create_campaign(
            program_id="program_example",
            name="Wakeup human approval campaign",
            autonomy_level="level_0_read_only",
            scope_status="in_scope",
            policy_text="Authorized local review only.",
            default_asset="local.example",
            created_by="operator",
            payload=runtime_campaign_payload(),
        )
        campaign = repository.update_campaign_status(campaign.id, "running")
        assert campaign is not None
        handoff = repository.create_campaign_task(
            campaign_id=campaign.id,
            task_type="validation_handoff",
            agent_type="validation_reviewer",
            title="Await human validation approval",
        )
        handoff = repository.update_campaign_task_status(
            handoff.id,
            "awaiting_approval",
        )
        dispatched_task_ids = []

        result = autonomous_research_wakeup.run_autonomous_research_wakeup(
            repository=repository,
            dispatcher=lambda *, campaign_task_id: dispatched_task_ids.append(
                campaign_task_id
            ),
            now=datetime(2026, 7, 19, tzinfo=UTC),
        )

        assert handoff is not None
        assert result["status"] == "completed"
        assert result["outcome_counts"] == {"awaiting_review": 1}
        assert dispatched_task_ids == []
        assert repository.get_campaign(campaign.id).status == "awaiting_review"
    finally:
        session.close()


def test_runtime_resumes_authorized_workspace_to_candidate_specific_handoff(
    tmp_path,
    monkeypatch,
):
    monkeypatch.setenv("STUDIO_WORKSPACE_ROOT", str(tmp_path))
    get_settings.cache_clear()
    repository, session = build_repository()
    session_factory = sessionmaker(bind=session.get_bind())
    try:
        workspace = create_workspace(tmp_path, name="runtime-restart")
        code_root = workspace.path / "code" / "target"
        code_root.mkdir()
        raw_source_marker = "runtime-restart-source-marker"
        (code_root / "routes.py").write_text(
            "\n".join(
                [
                    "from fastapi import APIRouter",
                    "",
                    "router = APIRouter()",
                    "",
                    '@router.post("/fetch")',
                    "def fetch_remote(target_url: str):",
                    f"    # {raw_source_marker}",
                    "    return fetch(target_url)",
                ]
            ),
            encoding="utf-8",
        )
        artifacts = {
            "scope": workspace.path / "scope" / "scope.yaml",
            "policy": workspace.path / "policy" / "policy.md",
            "api": workspace.path / "api" / "openapi.json",
            "har": workspace.path / "har" / "traffic.har",
        }
        artifacts["scope"].write_text(
            "in_scope:\n  - local.example\n",
            encoding="utf-8",
        )
        artifacts["policy"].write_text(
            "Authorized local review only. No live validation.",
            encoding="utf-8",
        )
        artifacts["api"].write_text(
            json.dumps(
                {
                    "openapi": "3.0.0",
                    "paths": {
                        "/fetch": {"post": {"operationId": "fetchRemote"}}
                    },
                }
            ),
            encoding="utf-8",
        )
        artifacts["har"].write_text(
            json.dumps(
                {
                    "log": {
                        "entries": [
                            {
                                "request": {
                                    "method": "POST",
                                    "url": "https://local.example/fetch",
                                }
                            }
                        ]
                    }
                }
            ),
            encoding="utf-8",
        )
        for kind, path in (
            ("scope", artifacts["scope"]),
            ("policy", artifacts["policy"]),
            ("code", code_root),
            ("api", artifacts["api"]),
            ("har", artifacts["har"]),
        ):
            import_workspace_artifact(
                workspace.path,
                StudioArtifactImport(kind=kind, source_path=str(path)),
            )
        snapshot = build_authorized_campaign_snapshot(workspace.path)
        campaign = repository.create_campaign(
            program_id=None,
            name="Persisted autonomous research campaign",
            autonomy_level="level_0_read_only",
            scope_status="in_scope",
            policy_text="Authorized local review only.",
            default_asset="local.example",
            created_by="operator",
            payload={
                "scope_guard_rule": {
                    "asset": "local.example",
                    "scope_status": "in_scope",
                    "automation": "none",
                    "allowed_validation": [],
                    "forbidden": [],
                    "human_approval_required": True,
                },
                "source_snapshot_digest": snapshot["source_snapshot_digest"],
                "workspace_snapshot": snapshot,
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
        campaign_id = campaign.id
        dispatched_task_ids = []
        tick_time = datetime.now(UTC)

        def dispatch_inline(*, campaign_task_id):
            dispatched_task_ids.append(campaign_task_id)
            return run_agent_task(campaign_task_id, repository=repository)

        expected_before_restart = [
            "campaign_observation",
            "attack_surface_mapping",
            "security_invariant_generation",
            "hypothesis_generation",
        ]
        for offset, task_type in enumerate(expected_before_restart):
            result = autonomous_research_runtime.tick_autonomous_research_campaign(
                campaign_id,
                repository=repository,
                dispatcher=dispatch_inline,
                now=tick_time + timedelta(seconds=61 * offset),
            )
            task = next(
                item
                for item in repository.list_campaign_tasks(campaign_id)
                if item.id == result["campaign_task_id"]
            )
            assert result["status"] == "dispatched", (
                f"{task_type}:{result['stop_reason']}:"
                + ",".join(
                    f"{item.task_type}={item.status}"
                    for item in repository.list_campaign_tasks(campaign_id)
                )
                + ":stages="
                + ",".join(
                    f"{stage.task_id}:{stage.stage_key}:{stage.status}"
                    for stage in repository.list_campaign_pipeline_stages(campaign_id)
                )
                + ":runs="
                + ",".join(
                    f"{run.task_id}:{run.status}"
                    for run in repository.list_campaign_agent_runs(campaign_id)
                )
            )
            assert task is not None
            assert task.task_type == task_type
            assert task.status == "completed", (
                f"{task_type}:{result['stop_reason']}:"
                + ",".join(
                    f"{item.task_type}={item.status}"
                    for item in repository.list_campaign_tasks(campaign_id)
                )
            )

        # Reopen the persistence boundary before consuming the saved pipeline run.
        session.close()
        session = session_factory()
        repository = DatabaseRepository(session)

        expected_after_restart = [
            "exploit_chain_reasoning",
            "variant_analysis",
            "deep_code_reasoning",
            "candidate_refutation",
            "finding_dedup_and_rank",
            "report_review",
        ]
        for offset, task_type in enumerate(
            expected_after_restart,
            start=len(expected_before_restart),
        ):
            result = autonomous_research_runtime.tick_autonomous_research_campaign(
                campaign_id,
                repository=repository,
                dispatcher=dispatch_inline,
                now=tick_time + timedelta(seconds=61 * offset),
            )
            task = next(
                item
                for item in repository.list_campaign_tasks(campaign_id)
                if item.id == result["campaign_task_id"]
            )
            assert result["status"] == "dispatched", (
                f"{task_type}:{result['stop_reason']}:"
                + ",".join(
                    f"{item.task_type}={item.status}"
                    for item in repository.list_campaign_tasks(campaign_id)
                )
                + ":stages="
                + ",".join(
                    f"{stage.task_id}:{stage.stage_key}:{stage.status}"
                    for stage in repository.list_campaign_pipeline_stages(campaign_id)
                )
                + ":runs="
                + ",".join(
                    f"{run.task_id}:{run.status}:{run.safety_gate_state}"
                    for run in repository.list_campaign_agent_runs(campaign_id)
                )
            )
            assert task is not None
            assert task.task_type == task_type
            assert task.status == "completed", (
                f"{task_type}:{result['stop_reason']}:"
                + ",".join(
                    f"{item.task_type}={item.status}"
                    for item in repository.list_campaign_tasks(campaign_id)
                )
            )

        waiting = autonomous_research_runtime.tick_autonomous_research_campaign(
            campaign_id,
            repository=repository,
            dispatcher=dispatch_inline,
            now=tick_time + timedelta(seconds=61 * 10),
        )
        runtime_tasks = [
            task
            for task in repository.list_campaign_tasks(campaign_id)
            if isinstance(task.payload, dict)
            and task.payload.get("runtime_schema") == "autonomous_research_v1"
        ]
        handoffs = [
            task
            for task in repository.list_campaign_tasks(campaign_id)
            if task.task_type == "validation_handoff"
        ]
        completed_stages = [
            stage
            for stage in repository.list_campaign_pipeline_stages(campaign_id)
            if stage.stage_key.startswith("autonomous_research:")
            and stage.status == "completed"
        ]
        candidate_refutation_task = next(
            task for task in runtime_tasks if task.task_type == "candidate_refutation"
        )
        exploit_chain_task = next(
            task for task in runtime_tasks if task.task_type == "exploit_chain_reasoning"
        )
        variant_analysis_task = next(
            task for task in runtime_tasks if task.task_type == "variant_analysis"
        )
        deep_code_reasoning_task = next(
            task for task in runtime_tasks if task.task_type == "deep_code_reasoning"
        )
        candidate_refutation_run = next(
            run
            for run in repository.list_campaign_agent_runs(campaign_id)
            if run.task_id == candidate_refutation_task.id
        )
        variant_analysis_ref = (
            f"variant_analysis_projection:{variant_analysis_task.id}"
        )
        deep_code_reasoning_ref = (
            f"deep_code_reasoning_projection:{deep_code_reasoning_task.id}"
        )
        candidate_hunter_projection_ref = (
            f"candidate_hunter_projection:{candidate_refutation_task.id}"
        )
        serialized_persistence = json.dumps(
            {
                "tasks": [task.payload for task in repository.list_campaign_tasks(campaign_id)],
                "stages": [stage.payload for stage in repository.list_campaign_pipeline_stages(campaign_id)],
            },
            sort_keys=True,
        )

        assert waiting["status"] == "awaiting_review"
        assert waiting["stop_reason"] == "human_review_required"
        assert {task.task_type for task in runtime_tasks} == {
            *expected_before_restart,
            *expected_after_restart,
        }
        assert len(runtime_tasks) == len(expected_before_restart) + len(
            expected_after_restart
        )
        assert len(dispatched_task_ids) == len(runtime_tasks)
        assert [stage.stage_key for stage in sorted(
            completed_stages,
            key=lambda stage: stage.stage_order,
        )] == [
            f"autonomous_research:{task_type}"
            for task_type in [*expected_before_restart, *expected_after_restart]
        ]
        assert all(stage.safety_gate_state == "allowed" for stage in completed_stages)
        assert variant_analysis_ref in variant_analysis_task.output_refs
        assert deep_code_reasoning_ref in deep_code_reasoning_task.output_refs
        assert variant_analysis_ref not in exploit_chain_task.output_refs
        assert deep_code_reasoning_ref not in exploit_chain_task.output_refs
        assert candidate_hunter_projection_ref in candidate_refutation_task.output_refs
        assert candidate_hunter_projection_ref in candidate_refutation_run.output_refs
        candidate_hunter_projection = candidate_refutation_run.payload[
            "candidate_hunter_projection"
        ]
        assert candidate_hunter_projection["projection_schema"] == (
            "runtime_candidate_hunter_projection_v1"
        )
        assert candidate_hunter_projection["pipeline_run_id"]
        assert candidate_hunter_projection["source_snapshot_digest"] == (
            snapshot["source_snapshot_digest"]
        )
        assert candidate_hunter_projection["execution_allowed"] is False
        assert candidate_hunter_projection["validation_allowed"] is False
        assert candidate_hunter_projection["report_submission_allowed"] is False
        assert len(handoffs) == 1
        assert handoffs[0].status == "awaiting_approval"
        assert handoffs[0].payload["candidate_ids"] == [
            handoffs[0].payload["candidate_id"]
        ]
        assert handoffs[0].payload["validation_allowed"] is False
        assert handoffs[0].payload["report_submission_allowed"] is False
        assert repository.get_campaign(campaign_id).status == "awaiting_review"
        assert raw_source_marker not in serialized_persistence

        candidate_refutation_run.payload = {
            **candidate_refutation_run.payload,
            "candidate_hunter_projection": {
                **candidate_hunter_projection,
                "candidate_hunter_state_digest": "0" * 64,
            },
        }
        repository.session.add(candidate_refutation_run)
        repository.session.commit()
        ranking_task = next(
            task for task in runtime_tasks if task.task_type == "finding_dedup_and_rank"
        )
        pipeline_run = repository.get_pipeline_run(
            ranking_task.payload["pipeline_run_id"]
        )

        verified_projection, stop_reason = (
            worker_tasks._runtime_candidate_hunter_projection_for_downstream(
                task=ranking_task,
                campaign=repository.get_campaign(campaign_id),
                pipeline_run=pipeline_run,
                repository=repository,
            )
        )

        assert verified_projection is None
        assert stop_reason == "candidate_hunter_projection_invalid"
    finally:
        session.close()
        get_settings.cache_clear()
