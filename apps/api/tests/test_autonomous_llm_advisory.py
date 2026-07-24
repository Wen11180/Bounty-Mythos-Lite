import json

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

import app.autonomous_research_runtime as autonomous_research_runtime
import app.worker.tasks as worker_tasks
from app.cross_source_candidate_generator import (
    CandidateModelConfig,
    CrossSourceGenerationResult,
    candidate_model_config_digest,
)
from app.db import Base
from app.repository import DatabaseRepository, seed_sample_data


SOURCE_SNAPSHOT_DIGEST = "sha256:" + "a" * 64
CHANGED_SOURCE_SNAPSHOT_DIGEST = "sha256:" + "b" * 64


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


def runtime_safety_fields():
    return {
        "execution_allowed": False,
        "dispatch_allowed": False,
        "validation_allowed": False,
        "candidate_promotion_allowed": False,
        "report_submission_allowed": False,
        "raw_payload_processed": False,
    }


def candidate_model_config():
    return CandidateModelConfig.model_validate(
        {"provider": "openai", "model": "advisory-test-model"}
    )


def create_campaign(repository, *, model_config):
    campaign = repository.create_campaign(
        program_id="program_example",
        name="Autonomous advisory campaign",
        autonomy_level="level_0_read_only",
        scope_status="in_scope",
        policy_text="Authorized local code review only.",
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
            "source_snapshot_digest": SOURCE_SNAPSHOT_DIGEST,
            "candidate_model": {
                "provider": model_config.provider.value,
                "model": model_config.model,
            },
            **runtime_safety_fields(),
        },
    )
    campaign = repository.update_campaign_status(campaign.id, "running")
    assert campaign is not None
    return campaign


def hypothesis():
    return {
        "hypothesis_id": "H-001",
        "vuln_type": "authorization_boundary",
        "priority_score": 80,
        "root_cause": "missing_object_ownership_check",
        "evidence_needed": ["Review the local ownership boundary."],
        "refutation_questions": ["Does observed middleware enforce ownership?"],
        "source_facts": [
            {
                "fact_ref": "api:GET:/records/{record_id}",
                "artifact_kind": "api",
                "fact_type": "route_handler",
                "route_method": "GET",
                "route_path": "/records/{record_id}",
                "source_path": "api/openapi.json",
                "symbol_name": "get_record",
            },
            {
                "fact_ref": "code:routes.py:get_record",
                "artifact_kind": "code",
                "fact_type": "authorization_gap_candidate",
                "route_method": "GET",
                "route_path": "/records/{record_id}",
                "source_path": "routes.py",
                "symbol_name": "get_record",
                "root_cause": "missing_object_ownership_check",
            },
            {
                "artifact_kind": "code",
                "fact_type": "authorization_gap_candidate",
                "source_path": "unbound.py",
            },
        ],
    }


def create_pipeline_run(repository, campaign):
    return repository.save_pipeline_run(
        program_id=campaign.program_id,
        asset=campaign.default_asset,
        policy_text=campaign.policy_text_hash,
        policy_text_is_hash=True,
        scope_status="in_scope",
        hypothesis_count=1,
        blocked_count=0,
        report_title=None,
        payload={"campaign_id": campaign.id, "hypotheses": [hypothesis()]},
    )


def create_advisory_task(repository, *, campaign, pipeline_run, model_config):
    return repository.create_campaign_task(
        campaign_id=campaign.id,
        task_type="cross_source_llm_advisory",
        agent_type="cross_source_reasoner_agent",
        title="Enrich existing hypotheses with bounded model advice",
        input_refs=[
            f"campaign:{campaign.id}",
            f"source_snapshot:{SOURCE_SNAPSHOT_DIGEST}",
            f"pipeline_run:{pipeline_run.id}",
            "candidate_model_config:"
            + candidate_model_config_digest(model_config),
        ],
        payload=autonomous_research_runtime._runtime_task_payload(
            campaign_id=campaign.id,
            task_type="cross_source_llm_advisory",
            source_snapshot_digest=SOURCE_SNAPSHOT_DIGEST,
            pipeline_run_id=pipeline_run.id,
            candidate_model_config=model_config,
        ),
    )


def complete_schema_failure_advisory(monkeypatch, repository, campaign, pipeline_run):
    model_config = candidate_model_config()
    task = create_advisory_task(
        repository,
        campaign=campaign,
        pipeline_run=pipeline_run,
        model_config=model_config,
    )
    raw_marker = "raw-model-response-marker"

    async def schema_failure(**_kwargs):
        return CrossSourceGenerationResult(
            model_status="needs_model_review",
            model_failure_reason="invalid_model_response",
            prompt_hash="1" * 64,
            model_latency_ms=7,
            model_request_key="2" * 64,
            model_response_digest="",
            model_response_schema="",
            model_reasoner="registry",
            model_replay_binding="not_applicable",
            baseline_count=1,
            proposed_count=0,
            accepted_candidates=[],
            working_candidates=[
                {
                    "origin": "baseline+model",
                    "candidate_id": "H-001",
                    "source_fact_refs": [
                        "api:GET:/records/{record_id}",
                        "code:routes.py:get_record",
                    ],
                    "evidence_requirements": [raw_marker],
                    "refutation_questions": ["Model-proposed review question."],
                    "model_priority_score": 95,
                }
            ],
        )

    monkeypatch.setattr(
        worker_tasks,
        "generate_cross_source_candidates",
        schema_failure,
    )
    monkeypatch.setattr(worker_tasks, "build_default_registry", lambda: object())

    result = worker_tasks._run_cross_source_llm_advisory_task(
        task=task,
        campaign=campaign,
        repository=repository,
        workspace_inputs={"code_files": []},
    )
    assert result["status"] == "completed"
    return task, raw_marker


def test_model_advisory_stage_is_optional_and_keeps_pipeline_order():
    disabled = [
        item["task_type"]
        for item in autonomous_research_runtime._runtime_work_items(None)
    ]
    enabled = [
        item["task_type"]
        for item in autonomous_research_runtime._runtime_work_items(
            candidate_model_config()
        )
    ]

    assert "cross_source_llm_advisory" not in disabled
    assert [item for item in enabled if item != "cross_source_llm_advisory"] == disabled
    assert enabled.index("cross_source_llm_advisory") == (
        enabled.index("hypothesis_generation") + 1
    )
    assert enabled.index("exploit_chain_reasoning") == (
        enabled.index("cross_source_llm_advisory") + 1
    )


def test_schema_failure_persists_empty_advisory_without_raw_model_content(monkeypatch):
    repository, session = build_repository()
    try:
        campaign = create_campaign(repository, model_config=candidate_model_config())
        pipeline_run = create_pipeline_run(repository, campaign)
        task, raw_marker = complete_schema_failure_advisory(
            monkeypatch,
            repository,
            campaign,
            pipeline_run,
        )
        projection_stage = next(
            stage
            for stage in repository.list_pipeline_stages_for_run(pipeline_run.id)
            if stage.task_id == task.id
            and stage.stage_key == "autonomous_cross_source_llm_advisory"
        )
        llm_runs = repository.list_llm_runs()

        assert projection_stage.payload["model_status"] == "needs_model_review"
        assert projection_stage.payload["model_failure_reason"] == "invalid_model_response"
        assert projection_stage.payload["advisories"] == []
        assert projection_stage.payload["advisory_count"] == 0
        assert projection_stage.payload["model_response_digest"] == ""
        assert projection_stage.payload["candidate_creation_allowed"] is False
        assert projection_stage.payload["execution_allowed"] is False
        assert projection_stage.payload["validation_allowed"] is False
        assert projection_stage.payload["report_submission_allowed"] is False
        assert len(llm_runs) == 1
        assert llm_runs[0].purpose == "autonomous_cross_source_advisory"
        assert llm_runs[0].mode == "live"
        assert raw_marker not in json.dumps(
            {
                "projection": projection_stage.payload,
                "llm_run": {
                    "provider": llm_runs[0].provider,
                    "model": llm_runs[0].model,
                    "prompt_hash": llm_runs[0].prompt_hash,
                    "error": llm_runs[0].error,
                    "safety_notes": llm_runs[0].safety_notes,
                },
            }
        )
    finally:
        session.close()


def test_refutation_requires_bound_unchanged_advisory_projection(monkeypatch):
    repository, session = build_repository()
    try:
        model_config = candidate_model_config()
        campaign = create_campaign(repository, model_config=model_config)
        pipeline_run = create_pipeline_run(repository, campaign)
        advisory_task, _ = complete_schema_failure_advisory(
            monkeypatch,
            repository,
            campaign,
            pipeline_run,
        )
        projection_ref = f"cross_source_llm_advisory_projection:{advisory_task.id}"
        refutation_task = repository.create_campaign_task(
            campaign_id=campaign.id,
            task_type="candidate_refutation",
            agent_type="candidate_hunter_agent",
            title="Refute candidate hypotheses from persisted evidence",
            input_refs=[
                f"campaign:{campaign.id}",
                f"source_snapshot:{SOURCE_SNAPSHOT_DIGEST}",
                f"pipeline_run:{pipeline_run.id}",
                projection_ref,
            ],
            payload=autonomous_research_runtime._runtime_task_payload(
                campaign_id=campaign.id,
                task_type="candidate_refutation",
                source_snapshot_digest=SOURCE_SNAPSHOT_DIGEST,
                pipeline_run_id=pipeline_run.id,
            ),
        )
        hypotheses = pipeline_run.payload["hypotheses"]

        projection, stop_reason = (
            worker_tasks._runtime_cross_source_llm_advisory_projection_for_refutation(
                task=refutation_task,
                campaign=campaign,
                pipeline_run=pipeline_run,
                hypotheses=hypotheses,
                workspace_inputs={"code_files": []},
                repository=repository,
            )
        )

        assert stop_reason is None
        assert projection is not None

        llm_run = repository.list_llm_runs()[0]
        llm_run.purpose = "general"
        session.add(llm_run)
        session.commit()
        projection, stop_reason = (
            worker_tasks._runtime_cross_source_llm_advisory_projection_for_refutation(
                task=refutation_task,
                campaign=campaign,
                pipeline_run=pipeline_run,
                hypotheses=hypotheses,
                workspace_inputs={"code_files": []},
                repository=repository,
            )
        )

        assert projection is None
        assert stop_reason == "candidate_model_advisory_projection_invalid"

        llm_run.purpose = "autonomous_cross_source_advisory"
        session.add(llm_run)
        session.commit()

        unbound_task = repository.create_campaign_task(
            campaign_id=campaign.id,
            task_type="candidate_refutation",
            agent_type="candidate_hunter_agent",
            title="Refute candidate hypotheses from persisted evidence",
            input_refs=[
                f"campaign:{campaign.id}",
                f"source_snapshot:{SOURCE_SNAPSHOT_DIGEST}",
                f"pipeline_run:{pipeline_run.id}",
            ],
            payload=autonomous_research_runtime._runtime_task_payload(
                campaign_id=campaign.id,
                task_type="candidate_refutation",
                source_snapshot_digest=SOURCE_SNAPSHOT_DIGEST,
                pipeline_run_id=pipeline_run.id,
            ),
        )
        projection, stop_reason = (
            worker_tasks._runtime_cross_source_llm_advisory_projection_for_refutation(
                task=unbound_task,
                campaign=campaign,
                pipeline_run=pipeline_run,
                hypotheses=hypotheses,
                workspace_inputs={"code_files": []},
                repository=repository,
            )
        )

        assert projection is None
        assert stop_reason == "candidate_model_advisory_projection_missing"

        original_payload = dict(refutation_task.payload)
        refutation_task.payload = {
            **original_payload,
            "source_snapshot_digest": CHANGED_SOURCE_SNAPSHOT_DIGEST,
        }
        session.add(refutation_task)
        session.commit()
        projection, stop_reason = (
            worker_tasks._runtime_cross_source_llm_advisory_projection_for_refutation(
                task=refutation_task,
                campaign=campaign,
                pipeline_run=pipeline_run,
                hypotheses=hypotheses,
                workspace_inputs={"code_files": []},
                repository=repository,
            )
        )

        assert projection is None
        assert stop_reason == "candidate_model_advisory_projection_missing"

        refutation_task.payload = original_payload
        session.add(refutation_task)
        campaign.payload = {
            **campaign.payload,
            "candidate_model": {"provider": "openai", "model": "changed-model"},
        }
        session.add(campaign)
        session.commit()
        projection, stop_reason = (
            worker_tasks._runtime_cross_source_llm_advisory_projection_for_refutation(
                task=refutation_task,
                campaign=campaign,
                pipeline_run=pipeline_run,
                hypotheses=hypotheses,
                workspace_inputs={"code_files": []},
                repository=repository,
            )
        )

        assert projection is None
        assert stop_reason == "candidate_model_config_changed"
    finally:
        session.close()


def test_model_advisory_only_enriches_existing_hypotheses():
    enriched = worker_tasks._apply_cross_source_llm_advisory(
        hypotheses=[hypothesis()],
        projection={
            "advisories": [
                {
                    "candidate_id": "H-001",
                    "source_fact_refs": [
                        "api:GET:/records/{record_id}",
                        "code:routes.py:get_record",
                    ],
                    "evidence_requirements": ["Review the local service boundary."],
                    "refutation_questions": ["Is authorization repeated in the service?"],
                    "model_priority_score": 95,
                },
                {
                    "candidate_id": "H-new",
                    "source_fact_refs": ["code:routes.py:get_record"],
                    "evidence_requirements": ["Untrusted new candidate."],
                    "refutation_questions": ["Untrusted new question."],
                    "model_priority_score": 100,
                },
            ]
        },
    )

    assert [candidate["hypothesis_id"] for candidate in enriched] == ["H-001"]
    assert enriched[0]["model_priority_score"] == 95
    assert "Review the local service boundary." in enriched[0]["evidence_needed"]
    assert "Is authorization repeated in the service?" in enriched[0][
        "refutation_questions"
    ]


def test_runtime_binds_completed_advisory_projection_to_refutation(monkeypatch):
    repository, session = build_repository()
    try:
        model_config = candidate_model_config()
        campaign = create_campaign(repository, model_config=model_config)
        pipeline_run = create_pipeline_run(repository, campaign)
        advisory_task = create_advisory_task(
            repository,
            campaign=campaign,
            pipeline_run=pipeline_run,
            model_config=model_config,
        )
        projection_ref = f"cross_source_llm_advisory_projection:{advisory_task.id}"
        advisory_task = repository.update_campaign_task_status(
            advisory_task.id,
            "completed",
            output_refs=[projection_ref],
        )
        assert advisory_task is not None
        captured = {}

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
        refutation_task = captured["task"]

        assert result == {"status": "dispatched"}
        assert refutation_task.input_refs == [
            f"campaign:{campaign.id}",
            f"source_snapshot:{SOURCE_SNAPSHOT_DIGEST}",
            f"pipeline_run:{pipeline_run.id}",
            projection_ref,
        ]
    finally:
        session.close()
