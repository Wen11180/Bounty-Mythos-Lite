from datetime import UTC, datetime, timedelta
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from pathlib import Path
from types import SimpleNamespace

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

import app.autonomous_research_runtime as autonomous_research_runtime
import app.candidate_hunter_loop as candidate_hunter_loop
import app.research_director.runtime as director_runtime
import app.worker.tasks as worker_tasks
from app.autonomous_research_runtime import (
    retry_autonomous_research_task,
    tick_autonomous_research_campaign,
)
from app.db import Base
from app.db_models import CampaignTaskRecord
from app.dependency_agent import build_dependency_input_manifest
from app.config import get_settings
from app.execution_registry import ExecutionAuthorizationDecision
from app.execution_registry.local_runner import RegisteredLocalToolRun
from app.repository import (
    AUTONOMOUS_RESEARCH_TASK_LEASE_SECONDS,
    DatabaseRepository,
    seed_sample_data,
)
from app.worker.tasks import run_agent_task
from app.studio_workspace import (
    StudioArtifactImport,
    build_authorized_campaign_snapshot,
    create_workspace,
    import_workspace_artifact,
)


SNAPSHOT_DIGEST = f"sha256:{'a' * 64}"


def _repository():
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    session = sessionmaker(bind=engine)()
    seed_sample_data(session)
    return DatabaseRepository(session), session


def _campaign(
    repository: DatabaseRepository,
    root: Path,
    *,
    allowed_tools: list[str] | None = None,
    asset: str = "local.example",
    source_snapshot_digest: str = SNAPSHOT_DIGEST,
    workspace_snapshot: dict | None = None,
):
    resolved_allowed_tools = (
        ["static_analyzer"] if allowed_tools is None else allowed_tools
    )
    campaign = repository.create_campaign(
        program_id=None,
        name="Lease-bound local analysis campaign",
        autonomy_level="level_1_local_validation",
        scope_status="in_scope",
        policy_text="Authorized local review only.",
        default_asset=asset,
        allowed_tools=resolved_allowed_tools,
        created_by="operator",
        payload={
            "source_snapshot_digest": source_snapshot_digest,
            "workspace_snapshot": workspace_snapshot or {"schema_version": "test"},
            "scope_guard_rule": {
                "asset": asset,
                "scope_status": "in_scope",
                "automation": "limited",
                "allowed_validation": ["static_analyzer"],
                "forbidden": [],
                "human_approval_required": False,
            },
            "saved_scope_guard": {"authorized_local_root": str(root)},
        },
    )
    updated = repository.update_campaign_status(campaign.id, "running")
    assert updated is not None
    return updated


def _workspace_inputs(root: Path):
    return {
        "source_snapshot_digest": SNAPSHOT_DIGEST,
        "authorized_local_root": str(root),
        "dependency_input_manifest": build_dependency_input_manifest(root),
    }


def _completed_local_run(tool_id: str) -> RegisteredLocalToolRun:
    return RegisteredLocalToolRun(
        tool_id=tool_id,
        status="completed",
        runner_status="semgrep_local_completed",
        command_hash=f"sha256:{'b' * 64}",
        command_executed=True,
        finding_count=1,
        advisory_findings=[
            {
                "rule_id": "mythos.local.ssrf-fetch",
                "path": "routes.py",
                "line": 12,
            }
        ],
        authorization=ExecutionAuthorizationDecision(
            eligible=True,
            reason="eligible",
            execution_tier="local",
        ),
        safety_gate_state="allowed",
    )


def test_campaign_helper_preserves_empty_tool_allowlist(tmp_path: Path):
    repository, session = _repository()
    try:
        campaign = _campaign(repository, tmp_path, allowed_tools=[])

        assert campaign.allowed_tools == []
    finally:
        session.close()


def _approve_local_tool_task(repository: DatabaseRepository, campaign_id: str) -> None:
    approvals = [
        approval
        for approval in repository.list_campaign_approval_records(campaign_id)
        if approval.approval_type == director_runtime.LOCAL_TOOL_APPROVAL_TYPE
    ]
    assert len(approvals) == 1
    approved = repository.decide_approval_record(
        approval_id=approvals[0].id,
        decision="approved",
        actor="operator",
        reason="Approved offline local static analysis.",
    )
    assert approved is not None


def test_local_dependency_sbom_run_persists_redacted_snapshot_bound_advisory(
    tmp_path: Path,
    monkeypatch,
):
    (tmp_path / "inputs").mkdir()
    (tmp_path / "package.json").write_text(
        '{"dependencies": {"lodash": "4.17.20"}}',
        encoding="utf-8",
    )
    (tmp_path / "inputs" / "index.js").write_text(
        "const lodash = require('lodash');\n",
        encoding="utf-8",
    )
    raw_marker = "dependency-artifact-description-must-not-persist"
    raw_secret = "token:DEPENDENCY_SECRET_MUST_NOT_PERSIST"
    (tmp_path / "inputs" / "dependencies.json").write_text(
        """{
  "components": [{
    "name": "lodash",
    "version": "4.17.20",
    "ecosystem": "npm",
    "known_advisory": true,
     "advisory_ids": ["OFFLINE-LODASH-1", "token:DEPENDENCY_SECRET_MUST_NOT_PERSIST"],
    "priority": "high",
    "description": "dependency-artifact-description-must-not-persist"
  }]
}""",
        encoding="utf-8",
    )
    repository, session = _repository()
    try:
        campaign = _campaign(
            repository,
            tmp_path,
            allowed_tools=["dependency_sbom_local"],
        )
        repository.upsert_campaign_budget(
            campaign_id=campaign.id,
            time_budget_minutes=30,
            token_budget=1000,
            tool_call_budget=1,
            validation_budget=1,
        )
        waiting = director_runtime.tick_campaign_local_execution(
            campaign=campaign,
            repository=repository,
            dispatcher=lambda **_kwargs: None,
            workspace_loader=lambda _snapshot: _workspace_inputs(tmp_path),
        )
        assert waiting is not None
        assert waiting["status"] == "awaiting_approval"
        _approve_local_tool_task(repository, campaign.id)
        dispatched = director_runtime.tick_campaign_local_execution(
            campaign=repository.get_campaign(campaign.id),
            repository=repository,
            dispatcher=lambda **_kwargs: None,
            workspace_loader=lambda _snapshot: _workspace_inputs(tmp_path),
        )
        assert dispatched is not None
        assert dispatched["status"] == "dispatched"

        monkeypatch.setattr(
            director_runtime,
            "load_authorized_campaign_inputs",
            lambda _snapshot: _workspace_inputs(tmp_path),
        )
        completed = run_agent_task(
            dispatched["campaign_task_id"],
            repository=repository,
        )

        artifacts = repository.list_artifacts(program_id=None, asset="local.example")
        artifact = next(
            item for item in artifacts if item.kind == "dependency_sbom_advisory"
        )
        scanner_run = repository.list_campaign_scanner_runs(campaign.id)[0]
        current_campaign = repository.get_campaign(campaign.id)
        assert current_campaign is not None
        rule = director_runtime._stored_scope_guard_rule(current_campaign)
        assert rule is not None
        context = director_runtime.build_campaign_research_director_context(
            campaign=current_campaign,
            rule=rule,
            repository=repository,
        )

        assert completed["status"] == "completed"
        assert artifact.provenance["source_snapshot_digest"] == SNAPSHOT_DIGEST
        assert artifact.provenance["tool_id"] == "dependency_sbom_local"
        assert artifact.payload_summary["schema_version"] == (
            "registered_local_dependency_sbom_advisory_v1"
        )
        assert artifact.derived_facts["dependency_advisories"] == [
            {
                "package": "lodash",
                "version": "4.17.20",
                "ecosystem": "npm",
                "advisory_id": "OFFLINE-LODASH-1",
                "priority": "high",
                "source_paths": ["inputs/index.js"],
            }
        ]
        assert scanner_run.tool_name == "dependency_sbom_local"
        assert scanner_run.finding_count == 1
        assert any(
            signal.signal_id.startswith(f"dependency_{artifact.id}_")
            for signal in context.signals
        )
        assert raw_marker not in str(
            [artifact.payload_summary, artifact.derived_facts, scanner_run.payload]
        )
        assert raw_secret not in str(
            [
                artifact.payload_summary,
                artifact.derived_facts,
                scanner_run.payload,
                [task.payload for task in repository.list_campaign_tasks(campaign.id)],
            ]
        )
    finally:
        session.close()


def test_dependency_snapshot_mutation_blocks_without_artifact_or_scanner_run(
    tmp_path: Path,
    monkeypatch,
):
    workspace_root = tmp_path / "workspaces"
    monkeypatch.setenv("STUDIO_WORKSPACE_ROOT", str(workspace_root))
    get_settings.cache_clear()
    workspace = create_workspace(workspace_root, name="dependency-snapshot-campaign")
    code_root = workspace.path / "code" / "target"
    code_root.mkdir()
    package_json = code_root / "package.json"
    package_json.write_text(
        '{"dependencies": {"lodash": "4.17.20"}}',
        encoding="utf-8",
    )
    inputs = code_root / "inputs"
    inputs.mkdir()
    (inputs / "index.js").write_text(
        "const lodash = require('lodash');\n",
        encoding="utf-8",
    )
    (inputs / "dependencies.json").write_text(
        '{"components": [{"name": "lodash", "version": "4.17.20", '
        '"known_advisory": true, "advisory_ids": ["OFFLINE-LODASH-1"]}]}',
        encoding="utf-8",
    )
    artifacts = {
        "scope": workspace.path / "scope" / "scope.yaml",
        "policy": workspace.path / "policy" / "policy.md",
        "api": workspace.path / "api" / "openapi.json",
        "har": workspace.path / "har" / "traffic.har",
    }
    artifacts["scope"].write_text("in_scope:\n  - api.example.test\n", encoding="utf-8")
    artifacts["policy"].write_text("Authorized local review only.", encoding="utf-8")
    artifacts["api"].write_text('{"openapi":"3.0.0","paths":{}}', encoding="utf-8")
    artifacts["har"].write_text('{"log":{"entries":[]}}', encoding="utf-8")
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
    repository, session = _repository()
    try:
        campaign = _campaign(
            repository,
            code_root,
            allowed_tools=["dependency_sbom_local"],
            asset="api.example.test",
            source_snapshot_digest=snapshot["source_snapshot_digest"],
            workspace_snapshot=snapshot,
        )
        repository.upsert_campaign_budget(
            campaign_id=campaign.id,
            time_budget_minutes=30,
            token_budget=1000,
            tool_call_budget=1,
            validation_budget=1,
        )
        waiting = director_runtime.tick_campaign_local_execution(
            campaign=campaign,
            repository=repository,
            dispatcher=lambda **_kwargs: None,
        )
        assert waiting is not None
        assert waiting["status"] == "awaiting_approval"
        _approve_local_tool_task(repository, campaign.id)
        dispatched = director_runtime.tick_campaign_local_execution(
            campaign=repository.get_campaign(campaign.id),
            repository=repository,
            dispatcher=lambda **_kwargs: None,
        )
        assert dispatched is not None
        assert dispatched["status"] == "dispatched"

        package_json.write_text(
            '{"dependencies": {"lodash": "4.17.21"}}',
            encoding="utf-8",
        )
        result = run_agent_task(dispatched["campaign_task_id"], repository=repository)

        assert result["status"] == "blocked"
        assert repository.list_artifacts(program_id=None, asset="api.example.test") == []
        assert repository.list_campaign_scanner_runs(campaign.id) == []
    finally:
        session.close()
        get_settings.cache_clear()


def test_local_tool_budget_excludes_read_only_agent_runs():
    repository = SimpleNamespace(
        get_campaign_budget=lambda _campaign_id: SimpleNamespace(tool_call_budget=2),
        list_campaign_agent_runs=lambda _campaign_id: [
            SimpleNamespace(safety_gate_state="allowed")
        ],
        list_campaign_scanner_runs=lambda _campaign_id: [
            SimpleNamespace(
                payload={
                    "research_director_tool_run": True,
                    "tool_call_consumed": True,
                }
            )
        ],
    )

    remaining = director_runtime.campaign_remaining_tool_calls(
        campaign=SimpleNamespace(id="campaign_tool_budget"),
        repository=repository,
    )

    assert remaining == 1


def test_local_tool_reservation_does_not_overrun_campaign_budget(tmp_path: Path):
    repository, session = _repository()
    try:
        campaign = _campaign(repository, tmp_path)
        repository.upsert_campaign_budget(
            campaign_id=campaign.id,
            time_budget_minutes=30,
            token_budget=1000,
            tool_call_budget=1,
            validation_budget=1,
        )

        def claim_running_task(plan_suffix: str):
            plan_digest = f"sha256:{plan_suffix * 64}"
            tool_id = "semgrep_local" if plan_suffix == "b" else "codeql_local"
            task = repository.create_campaign_task(
                campaign_id=campaign.id,
                task_type=director_runtime.LOCAL_TOOL_TASK_TYPE,
                agent_type="registered_local_tool",
                title="Run registered local analysis",
                payload={
                    "schema_version": director_runtime.LOCAL_TOOL_TASK_SCHEMA,
                    "execution_lease_required": True,
                    "research_plan_id": f"research_plan_{plan_suffix}",
                    "research_plan_digest": plan_digest,
                    "source_snapshot_digest": SNAPSHOT_DIGEST,
                    "tool_id": tool_id,
                },
            )
            running = repository.claim_campaign_task_execution(task.id)
            assert running is not None
            return running, plan_digest

        first_task, first_digest = claim_running_task("b")
        first_reservation = repository.reserve_campaign_local_tool_call(
            campaign_id=campaign.id,
            task_id=first_task.id,
            execution_claim_id=first_task.execution_claim_id,
            research_plan_id="research_plan_first",
            research_plan_digest=first_digest,
            source_snapshot_digest=SNAPSHOT_DIGEST,
            tool_id="semgrep_local",
        )
        assert first_reservation is not None
        assert (
            repository.finish_campaign_task_execution(
                task_id=first_task.id,
                execution_claim_id=first_task.execution_claim_id,
                task_status="completed",
                task_output_refs=[],
                agent_status="completed",
                agent_output_refs=[],
                safety_gate_state="allowed",
                stop_reason=None,
                payload=repository.local_tool_call_reservation_metadata(
                    task_id=first_task.id,
                    execution_claim_id=first_task.execution_claim_id,
                ),
            )
            is not None
        )

        second_task, second_digest = claim_running_task("c")
        second_reservation = repository.reserve_campaign_local_tool_call(
            campaign_id=campaign.id,
            task_id=second_task.id,
            execution_claim_id=second_task.execution_claim_id,
            research_plan_id="research_plan_second",
            research_plan_digest=second_digest,
            source_snapshot_digest=SNAPSHOT_DIGEST,
            tool_id="codeql_local",
        )

        assert second_reservation is None
        assert repository.campaign_local_tool_call_count(campaign.id) == 1
        budget = repository.get_campaign_budget(campaign.id)
        assert budget is not None
        assert budget.tool_calls_reserved == 1
        reservations = repository.list_campaign_local_tool_call_reservations(campaign.id)
        assert [reservation.task_id for reservation in reservations] == [first_task.id]
    finally:
        session.close()


def test_level_one_tick_dispatches_a_lease_bound_local_tool_and_resumes_research(
    tmp_path: Path,
    monkeypatch,
):
    repository, session = _repository()
    try:
        campaign = _campaign(repository, tmp_path)
        repository.upsert_campaign_budget(
            campaign_id=campaign.id,
            time_budget_minutes=30,
            token_budget=1000,
            tool_call_budget=2,
            validation_budget=1,
        )
        dispatched_ids: list[str] = []

        tick = director_runtime.tick_campaign_local_execution(
            campaign=campaign,
            repository=repository,
            dispatcher=lambda *, campaign_task_id: dispatched_ids.append(campaign_task_id),
            workspace_loader=lambda _snapshot: _workspace_inputs(tmp_path),
        )

        assert tick is not None
        assert tick["status"] == "awaiting_approval"
        assert tick["stop_reason"] == "human_approval_required"
        assert tick["execution_allowed"] is False
        assert tick["report_submission_allowed"] is False
        assert dispatched_ids == []

        local_task = repository.session.get(
            CampaignTaskRecord,
            tick["campaign_task_id"],
        )
        assert local_task is not None
        assert local_task.status == "awaiting_approval"
        assert local_task.payload["execution_lease_required"] is True
        assert local_task.payload["tool_id"] == "semgrep_local"
        approvals = repository.list_campaign_approval_records(campaign.id)
        assert len(approvals) == 1
        assert approvals[0].task_id == local_task.id
        assert approvals[0].status == "pending"
        assert approvals[0].requested_action == "semgrep_local"
        assert approvals[0].validation_mode == "static_analyzer"
        assert approvals[0].plan_digest == local_task.payload["research_plan_digest"]

        approved = repository.decide_approval_record(
            approval_id=approvals[0].id,
            decision="approved",
            actor="operator",
            reason="Approved offline local static analysis.",
        )
        assert approved is not None
        tick = director_runtime.tick_campaign_local_execution(
            campaign=repository.get_campaign(campaign.id),
            repository=repository,
            dispatcher=lambda *, campaign_task_id: dispatched_ids.append(campaign_task_id),
            workspace_loader=lambda _snapshot: _workspace_inputs(tmp_path),
        )
        assert tick is not None
        assert tick["status"] == "dispatched"
        assert dispatched_ids == [tick["campaign_task_id"]]

        local_task = repository.session.get(
            CampaignTaskRecord,
            tick["campaign_task_id"],
        )
        assert local_task is not None
        assert local_task.status == "dispatched"

        monkeypatch.setattr(
            director_runtime,
            "load_authorized_campaign_inputs",
            lambda _snapshot: _workspace_inputs(tmp_path),
        )
        monkeypatch.setattr(
            director_runtime,
            "run_registered_local_tool",
            lambda request: _completed_local_run(request.authorization.tool_id),
        )

        completed = run_agent_task(local_task.id, repository=repository)
        assert completed["status"] == "completed", completed

        persisted_task = repository.session.get(type(local_task), local_task.id)
        assert persisted_task is not None
        assert persisted_task.status == "completed"
        assert persisted_task.execution_claim_id is None
        scanner_runs = repository.list_campaign_scanner_runs(campaign.id)
        assert len(scanner_runs) == 1
        assert scanner_runs[0].payload["tool_call_consumed"] is True
        assert scanner_runs[0].payload["tool_call_reservation_agent_run_id"]
        assert repository.campaign_local_tool_call_count(campaign.id) == 1
        assert director_runtime.campaign_remaining_tool_calls(
            campaign=campaign,
            repository=repository,
        ) == 1
        artifacts = repository.list_artifacts(program_id=None, asset="local.example")
        assert len(artifacts) == 1
        assert artifacts[0].provenance["campaign_id"] == campaign.id
        assert "raw scanner message" not in str(artifacts[0])
        assert artifacts[0].derived_facts["candidate_promotion_allowed"] is False

        next_dispatches: list[str] = []
        follow_up = tick_autonomous_research_campaign(
            campaign.id,
            repository=repository,
            dispatcher=lambda *, campaign_task_id: next_dispatches.append(campaign_task_id),
        )
        assert follow_up["status"] == "dispatched"
        assert next_dispatches == [follow_up["campaign_task_id"]]
        next_task = repository.session.get(
            CampaignTaskRecord,
            follow_up["campaign_task_id"],
        )
        assert next_task is not None
        assert next_task.task_type == "campaign_observation"
    finally:
        session.close()


def test_completed_local_advisory_is_frozen_into_candidate_refutation(
    tmp_path: Path,
    monkeypatch,
):
    repository, session = _repository()
    try:
        source_file = tmp_path / "routes.py"
        source_content = "\n".join(
            [
                "from fastapi import APIRouter",
                "",
                "router = APIRouter()",
                "",
                "",
                '@router.post("/webhooks/test")',
                "def send_webhook(target_url: str):",
                "    request_url = target_url",
                "    # The test keeps this local-only.",
                "    # No network operation is executed.",
                "    # Static analysis identifies the following sink.",
                "    return fetch(request_url)",
            ]
        ) + "\n"
        source_file.write_text(source_content, encoding="utf-8")
        source_manifest = [
            {
                "source_path": source_file.name,
                "content_digest": sha256(source_content.encode("utf-8")).hexdigest(),
            }
        ]
        campaign = _campaign(repository, tmp_path, asset=str(tmp_path))
        repository.upsert_campaign_budget(
            campaign_id=campaign.id,
            time_budget_minutes=30,
            token_budget=1000,
            tool_call_budget=1,
            validation_budget=1,
        )
        waiting = director_runtime.tick_campaign_local_execution(
            campaign=campaign,
            repository=repository,
            dispatcher=lambda **_kwargs: None,
            workspace_loader=lambda _snapshot: _workspace_inputs(tmp_path),
        )
        assert waiting is not None
        assert waiting["status"] == "awaiting_approval"
        _approve_local_tool_task(repository, campaign.id)

        dispatched = director_runtime.tick_campaign_local_execution(
            campaign=repository.get_campaign(campaign.id),
            repository=repository,
            dispatcher=lambda **_kwargs: None,
            workspace_loader=lambda _snapshot: _workspace_inputs(tmp_path),
        )
        assert dispatched is not None
        assert dispatched["status"] == "dispatched"
        monkeypatch.setattr(
            director_runtime,
            "load_authorized_campaign_inputs",
            lambda _snapshot: _workspace_inputs(tmp_path),
        )
        monkeypatch.setattr(
            director_runtime,
            "run_registered_local_tool",
            lambda request: _completed_local_run(request.authorization.tool_id),
        )
        assert (
            run_agent_task(dispatched["campaign_task_id"], repository=repository)[
                "status"
            ]
            == "completed"
        )
        advisory = repository.list_artifacts(
            program_id=campaign.program_id,
            asset=campaign.default_asset,
        )[0]

        candidate = {
            "hypothesis_id": "H-001",
            "vuln_type": "ssrf",
            "location": "POST /webhooks/test",
            "priority_score": 70,
            "source_facts": [
                {
                    "artifact_kind": "code",
                    "fact_type": "authorization_gap_candidate",
                    "source_path": source_file.name,
                    "symbol_name": "send_webhook",
                    "route_method": "POST",
                    "route_path": "/webhooks/test",
                    "root_cause": "missing_ssrf_validation",
                },
                {
                    "artifact_kind": "api",
                    "fact_type": "api_surface",
                    "route_method": "POST",
                    "route_path": "/webhooks/test",
                },
                {"artifact_kind": "har", "fact_type": "har_context"},
            ],
        }
        pipeline_run = repository.save_pipeline_run(
            program_id=campaign.program_id,
            asset=campaign.default_asset,
            policy_text=campaign.policy_text_hash,
            policy_text_is_hash=True,
            scope_status="in_scope",
            hypothesis_count=1,
            blocked_count=0,
            report_title=None,
            payload={"campaign_id": campaign.id, "hypotheses": [candidate]},
        )
        codebase_map = repository.save_codebase_map(
            campaign_id=campaign.id,
            source_ref=SNAPSHOT_DIGEST,
            repository=str(tmp_path),
            commit_ref=None,
            status="completed",
            route_count=1,
            handler_count=1,
            model_count=0,
            authz_check_count=0,
            sensitive_sink_count=1,
            safety_gate_state="allowed",
            payload={"raw_payload_processed": False},
        )
        route_fact = repository.save_codebase_fact(
            codebase_map_id=codebase_map.id,
            campaign_id=campaign.id,
            fact_type="route_handler",
            source_path=source_file.name,
            symbol_name="send_webhook",
            route_method="POST",
            route_path="/webhooks/test",
            sensitivity_label="low",
            payload={"handler": "send_webhook", "line": 7},
        )
        sink_fact = repository.save_codebase_fact(
            codebase_map_id=codebase_map.id,
            campaign_id=campaign.id,
            fact_type="sensitive_sink",
            source_path=source_file.name,
            symbol_name="fetch",
            sensitivity_label="low",
            payload={"handler": "send_webhook", "line": 12},
        )
        preceding_stages = (
            ("campaign_observation", "orchestrator_agent", 0),
            ("attack_surface_mapping", "target_model_agent", 1),
            ("security_invariant_generation", "invariant_agent", 2),
            ("hypothesis_generation", "hypothesis_agent", 3),
            ("exploit_chain_reasoning", "vuln_chain_builder_agent", 5),
            ("variant_analysis", "variant_analysis_agent", 6),
            ("deep_code_reasoning", "deep_code_reasoning_agent", 7),
        )
        for task_type, agent_type, stage_order in preceding_stages:
            task = repository.create_campaign_task(
                campaign_id=campaign.id,
                task_type=task_type,
                agent_type=agent_type,
                title=task_type,
                input_refs=[
                    f"campaign:{campaign.id}",
                    f"source_snapshot:{SNAPSHOT_DIGEST}",
                    f"pipeline_run:{pipeline_run.id}",
                ],
                payload=autonomous_research_runtime._runtime_task_payload(
                    campaign_id=campaign.id,
                    task_type=task_type,
                    source_snapshot_digest=SNAPSHOT_DIGEST,
                    pipeline_run_id=pipeline_run.id,
                ),
            )
            task = repository.update_campaign_task_status(
                task.id,
                "completed",
                output_refs=[f"pipeline_run:{pipeline_run.id}"],
            )
            assert task is not None
            repository.save_pipeline_stage(
                pipeline_run_id=pipeline_run.id,
                campaign_id=campaign.id,
                task_id=task.id,
                stage_key=f"autonomous_research:{task_type}",
                stage_order=stage_order,
                status="completed",
                input_refs=task.input_refs,
                output_refs=task.output_refs,
                safety_gate_state="allowed",
                stop_reason=None,
                payload=autonomous_research_runtime._runtime_stage_payload(
                    campaign_id=campaign.id,
                    task_type=task_type,
                    source_snapshot_digest=SNAPSHOT_DIGEST,
                    outcome="completed",
                ),
            )

        refutation_tick = tick_autonomous_research_campaign(
            campaign.id,
            repository=repository,
            dispatcher=lambda **_kwargs: None,
            now=datetime.now(UTC) + timedelta(minutes=2),
        )
        assert refutation_tick["status"] == "dispatched"
        refutation_task = repository.session.get(
            CampaignTaskRecord,
            refutation_tick["campaign_task_id"],
        )
        assert refutation_task is not None
        assert refutation_task.task_type == "candidate_refutation"
        assert refutation_task.input_refs.count(f"artifact:{advisory.id}") == 1
        assert refutation_task.payload["candidate_promotion_allowed"] is False
        assert refutation_task.payload["report_submission_allowed"] is False

        captured: dict[str, object] = {}
        monkeypatch.setattr(
            worker_tasks,
            "_runtime_exploit_chain_projection",
            lambda **_kwargs: (None, None),
        )
        monkeypatch.setattr(
            worker_tasks,
            "_runtime_target_model_projection",
            lambda **_kwargs: (
                {
                    "fact_refs": [
                        f"codebase_fact:{route_fact.id}",
                        f"codebase_fact:{sink_fact.id}",
                    ]
                },
                None,
            ),
        )
        monkeypatch.setattr(
            worker_tasks,
            "_runtime_variant_analysis_projection_for_report",
            lambda **_kwargs: ({}, None, None),
        )
        monkeypatch.setattr(
            worker_tasks,
            "_runtime_deep_code_reasoning_projection_for_report",
            lambda **_kwargs: ({}, None, None),
        )
        original_build_observations = (
            candidate_hunter_loop.build_candidate_hunter_observations
        )

        def capture_observations(**kwargs):
            captured["static_advisory_facts"] = kwargs["static_advisory_facts"]
            observations = original_build_observations(**kwargs)
            captured["candidate_states"] = observations["candidate_states"]
            return observations

        monkeypatch.setattr(
            "app.candidate_hunter_loop.build_candidate_hunter_observations",
            capture_observations,
        )
        monkeypatch.setattr(
            worker_tasks,
            "load_authorized_campaign_inputs",
            lambda _snapshot: {
                "source_snapshot_digest": SNAPSHOT_DIGEST,
                "source_manifest": source_manifest,
                "authorized_local_root": str(tmp_path),
            },
        )

        result = run_agent_task(
            refutation_task.id,
            repository=repository,
        )

        assert result["status"] == "completed"
        facts = captured["static_advisory_facts"]
        advisory_fact_ref = (
            f"static_advisory:{advisory.id}:12:mythos.local.ssrf-fetch"
        )
        assert [fact["fact_ref"] for fact in facts] == [advisory_fact_ref]
        assert all(fact["artifact_kind"] == "static_advisory" for fact in facts)
        assert advisory_fact_ref in captured["candidate_states"][0]["source_fact_refs"]
        rerank_stage = max(
            (
                stage
                for stage in repository.list_pipeline_stages_for_run(pipeline_run.id)
                if stage.stage_key == "candidate_hunter_rerank"
            ),
            key=lambda stage: stage.payload["round"],
        )
        assert advisory_fact_ref in rerank_stage.payload["final_candidates"][0][
            "source_fact_refs"
        ]
    finally:
        session.close()


def test_autonomous_tick_routes_level_one_campaign_to_local_execution(
    tmp_path: Path,
    monkeypatch,
):
    repository, session = _repository()
    try:
        campaign = _campaign(repository, tmp_path)
        dispatched_ids: list[str] = []
        monkeypatch.setattr(
            director_runtime,
            "load_authorized_campaign_inputs",
            lambda _snapshot: _workspace_inputs(tmp_path),
        )

        result = tick_autonomous_research_campaign(
            campaign.id,
            repository=repository,
            dispatcher=lambda *, campaign_task_id: dispatched_ids.append(campaign_task_id),
        )

        assert result["status"] == "awaiting_approval"
        assert dispatched_ids == []
        _approve_local_tool_task(repository, campaign.id)
        result = tick_autonomous_research_campaign(
            campaign.id,
            repository=repository,
            dispatcher=lambda *, campaign_task_id: dispatched_ids.append(campaign_task_id),
        )
        assert result["status"] == "dispatched"
        assert result["execution_allowed"] is False
        assert dispatched_ids == [result["campaign_task_id"]]
        task = repository.session.get(CampaignTaskRecord, result["campaign_task_id"])
        assert task is not None
        assert task.task_type == director_runtime.LOCAL_TOOL_TASK_TYPE
        assert task.execution_claim_id is not None
    finally:
        session.close()


def test_expired_local_tool_lease_requires_human_review(tmp_path: Path, monkeypatch):
    repository, session = _repository()
    try:
        now = datetime(2026, 7, 22, tzinfo=UTC)
        campaign = _campaign(repository, tmp_path)
        dispatched_ids: list[str] = []

        dispatched = director_runtime.tick_campaign_local_execution(
            campaign=campaign,
            repository=repository,
            dispatcher=lambda *, campaign_task_id: dispatched_ids.append(campaign_task_id),
            workspace_loader=lambda _snapshot: _workspace_inputs(tmp_path),
            now=now,
        )
        assert dispatched is not None
        assert dispatched["status"] == "awaiting_approval"
        _approve_local_tool_task(repository, campaign.id)
        dispatched = director_runtime.tick_campaign_local_execution(
            campaign=repository.get_campaign(campaign.id),
            repository=repository,
            dispatcher=lambda *, campaign_task_id: dispatched_ids.append(campaign_task_id),
            workspace_loader=lambda _snapshot: _workspace_inputs(tmp_path),
            now=now,
        )
        assert dispatched is not None
        task = repository.session.get(CampaignTaskRecord, dispatched["campaign_task_id"])
        assert task is not None
        assert task.status == "dispatched"
        monkeypatch.setattr(
            director_runtime,
            "load_authorized_campaign_inputs",
            lambda _snapshot: _workspace_inputs(tmp_path),
        )

        recovered = director_runtime.tick_campaign_local_execution(
            campaign=repository.get_campaign(campaign.id),
            repository=repository,
            dispatcher=lambda *, campaign_task_id: dispatched_ids.append(campaign_task_id),
            workspace_loader=lambda _snapshot: _workspace_inputs(tmp_path),
            now=now + timedelta(seconds=AUTONOMOUS_RESEARCH_TASK_LEASE_SECONDS + 1),
        )

        persisted_task = repository.session.get(CampaignTaskRecord, task.id)
        failure_stages = [
            stage
            for stage in repository.list_campaign_pipeline_stages(campaign.id)
            if stage.stage_key == director_runtime.LOCAL_TOOL_FAILURE_STAGE_KEY
        ]
        agent_runs = repository.list_campaign_agent_runs(campaign.id)

        assert recovered is not None
        assert recovered["status"] == "awaiting_review"
        assert recovered["campaign_task_id"] == task.id
        assert recovered["stop_reason"] == "execution_lease_expired"
        assert persisted_task is not None
        assert persisted_task.status == "failed"
        assert persisted_task.execution_claim_id is None
        assert repository.get_campaign(campaign.id).status == "awaiting_review"
        assert dispatched_ids == [task.id]
        assert len(failure_stages) == 1
        assert failure_stages[0].status == "failed"
        assert (
            failure_stages[0].stage_order
            == director_runtime.LOCAL_TOOL_FAILURE_STAGE_ORDER
        )
        assert failure_stages[0].safety_gate_state == "blocked"
        assert failure_stages[0].stop_reason == "execution_lease_expired"
        assert failure_stages[0].payload["candidate_promotion_allowed"] is False
        assert any(
            run.task_id == task.id
            and run.status == "failed"
            and run.stop_reason == "execution_lease_expired"
            for run in agent_runs
        )

        reopened = repository.update_campaign_status(campaign.id, "running")
        assert reopened is not None
        repeated_recovery = director_runtime.tick_campaign_local_execution(
            campaign=reopened,
            repository=repository,
            dispatcher=lambda *, campaign_task_id: dispatched_ids.append(campaign_task_id),
            workspace_loader=lambda _snapshot: _workspace_inputs(tmp_path),
            now=now + timedelta(seconds=AUTONOMOUS_RESEARCH_TASK_LEASE_SECONDS + 2),
        )
        retry_dispatches: list[str] = []
        retry = retry_autonomous_research_task(
            campaign.id,
            task.id,
            repository=repository,
            dispatcher=lambda *, campaign_task_id: retry_dispatches.append(campaign_task_id),
        )
        retried_task = repository.session.get(CampaignTaskRecord, task.id)
        failure_stages = [
            stage
            for stage in repository.list_campaign_pipeline_stages(campaign.id)
            if stage.stage_key == director_runtime.LOCAL_TOOL_FAILURE_STAGE_KEY
        ]

        assert repeated_recovery is not None
        assert repeated_recovery["status"] == "awaiting_review"
        assert len(failure_stages) == 1
        assert retry["status"] == "dispatched"
        assert retry["campaign_task_id"] == task.id
        assert retry_dispatches == [task.id]
        assert retried_task is not None
        assert retried_task.status == "dispatched"
        assert retried_task.execution_claim_id is not None
        assert repository.get_campaign(campaign.id).status == "running"
    finally:
        session.close()


def test_local_tool_task_never_completes_after_lease_renewal_is_lost(
    tmp_path: Path,
    monkeypatch,
):
    repository, session = _repository()
    try:
        now = datetime(2026, 7, 22, tzinfo=UTC)
        campaign = _campaign(repository, tmp_path)
        dispatched = director_runtime.tick_campaign_local_execution(
            campaign=campaign,
            repository=repository,
            dispatcher=lambda **_kwargs: None,
            workspace_loader=lambda _snapshot: _workspace_inputs(tmp_path),
            now=now,
        )
        assert dispatched is not None
        assert dispatched["status"] == "awaiting_approval"
        _approve_local_tool_task(repository, campaign.id)
        dispatched = director_runtime.tick_campaign_local_execution(
            campaign=repository.get_campaign(campaign.id),
            repository=repository,
            dispatcher=lambda **_kwargs: None,
            workspace_loader=lambda _snapshot: _workspace_inputs(tmp_path),
            now=now,
        )
        assert dispatched is not None
        task = repository.claim_campaign_task_execution(
            dispatched["campaign_task_id"],
            now=now + timedelta(seconds=1),
        )
        assert task is not None
        assert task.status == "running"
        assert task.execution_claim_id is not None

        monkeypatch.setattr(
            repository,
            "renew_campaign_task_execution_lease",
            lambda *_args, **_kwargs: None,
        )
        completed = director_runtime._finish_local_task(
            task=task,
            repository=repository,
            task_status="completed",
            agent_status="completed",
            safety_gate_state="allowed",
            stop_reason=None,
            output_refs=[],
            payload={},
        )

        persisted_task = repository.session.get(CampaignTaskRecord, task.id)
        agent_runs = repository.list_campaign_agent_runs(campaign.id)

        assert completed == {
            "status": "awaiting_evidence",
            "task_id": task.id,
            "stop_reason": "execution_lease_lost",
        }
        assert persisted_task is not None
        assert persisted_task.status == "running"
        assert persisted_task.execution_claim_id == task.execution_claim_id
        assert any(
            run.id == task.execution_claim_id and run.status == "running"
            for run in agent_runs
        )
    finally:
        session.close()


def test_expired_prior_snapshot_local_task_does_not_block_current_snapshot(
    tmp_path: Path,
):
    repository, session = _repository()
    try:
        now = datetime(2026, 7, 22, tzinfo=UTC)
        current_snapshot_digest = f"sha256:{'b' * 64}"
        campaign = _campaign(repository, tmp_path)
        old_task = repository.create_campaign_task(
            campaign_id=campaign.id,
            task_type=director_runtime.LOCAL_TOOL_TASK_TYPE,
            agent_type="registered_local_tool",
            title="Run prior snapshot local analysis",
            payload={
                "schema_version": director_runtime.LOCAL_TOOL_TASK_SCHEMA,
                "execution_lease_required": True,
                "research_plan_id": "research_plan_prior_snapshot",
                "research_plan_digest": f"sha256:{'c' * 64}",
                "source_snapshot_digest": SNAPSHOT_DIGEST,
                "tool_id": "semgrep_local",
            },
        )
        dispatched = repository.dispatch_research_director_local_tool_task(
            task_id=old_task.id,
            agent_payload={"raw_payload_processed": False},
            now=now,
        )
        assert dispatched is not None
        dispatched_old_task, _agent_run = dispatched
        assert dispatched_old_task is not None
        assert dispatched_old_task.execution_lease_expires_at is not None

        campaign.payload = {
            **campaign.payload,
            "source_snapshot_digest": current_snapshot_digest,
        }
        repository.session.add(campaign)
        repository.session.commit()
        repository.session.refresh(campaign)

        result = director_runtime.tick_campaign_local_execution(
            campaign=campaign,
            repository=repository,
            dispatcher=lambda **_kwargs: None,
            workspace_loader=lambda _snapshot: {
                "source_snapshot_digest": current_snapshot_digest,
                "authorized_local_root": str(tmp_path),
            },
            now=dispatched_old_task.execution_lease_expires_at + timedelta(seconds=1),
        )
        persisted_old_task = repository.session.get(CampaignTaskRecord, old_task.id)
        failure_stages = [
            stage
            for stage in repository.list_campaign_pipeline_stages(campaign.id)
            if stage.stage_key == director_runtime.LOCAL_TOOL_FAILURE_STAGE_KEY
        ]

        assert result is not None
        assert result["status"] == "awaiting_approval"
        assert result["source_snapshot_digest"] == current_snapshot_digest
        assert persisted_old_task is not None
        assert persisted_old_task.status == "failed"
        assert repository.get_campaign(campaign.id).status == "running"
        assert len(failure_stages) == 1
        assert failure_stages[0].payload["source_snapshot_digest"] == SNAPSHOT_DIGEST
    finally:
        session.close()


def test_lost_lease_discards_local_tool_result_before_evidence_persistence(
    tmp_path: Path,
    monkeypatch,
):
    repository, session = _repository()
    try:
        now = datetime.now(UTC)
        campaign = _campaign(repository, tmp_path)
        repository.upsert_campaign_budget(
            campaign_id=campaign.id,
            time_budget_minutes=30,
            token_budget=1000,
            tool_call_budget=1,
            validation_budget=1,
        )
        dispatched_ids: list[str] = []
        dispatched = director_runtime.tick_campaign_local_execution(
            campaign=campaign,
            repository=repository,
            dispatcher=lambda *, campaign_task_id: dispatched_ids.append(campaign_task_id),
            workspace_loader=lambda _snapshot: _workspace_inputs(tmp_path),
            now=now,
        )
        assert dispatched is not None
        assert dispatched["status"] == "awaiting_approval"
        _approve_local_tool_task(repository, campaign.id)
        dispatched = director_runtime.tick_campaign_local_execution(
            campaign=repository.get_campaign(campaign.id),
            repository=repository,
            dispatcher=lambda *, campaign_task_id: dispatched_ids.append(campaign_task_id),
            workspace_loader=lambda _snapshot: _workspace_inputs(tmp_path),
            now=now,
        )
        assert dispatched is not None
        task_id = dispatched["campaign_task_id"]
        monkeypatch.setattr(
            director_runtime,
            "load_authorized_campaign_inputs",
            lambda _snapshot: _workspace_inputs(tmp_path),
        )

        def expire_lease_after_tool_run(request):
            running_task = repository.session.get(CampaignTaskRecord, task_id)
            assert running_task is not None
            assert running_task.execution_lease_expires_at is not None
            expired = repository.expire_campaign_task_execution(
                task_id,
                now=running_task.execution_lease_expires_at + timedelta(seconds=1),
            )
            assert expired is not None
            return _completed_local_run(request.authorization.tool_id)

        monkeypatch.setattr(
            director_runtime,
            "run_registered_local_tool",
            expire_lease_after_tool_run,
        )
        result = run_agent_task(task_id, repository=repository)
        persisted_task = repository.session.get(CampaignTaskRecord, task_id)
        local_run_stages = [
            stage
            for stage in repository.list_campaign_pipeline_stages(campaign.id)
            if stage.stage_key == "research_director_local_tool_run"
        ]

        assert result == {
            "status": "awaiting_evidence",
            "task_id": task_id,
            "stop_reason": "execution_lease_lost",
        }
        assert persisted_task is not None
        assert persisted_task.status == "failed"
        assert repository.list_campaign_scanner_runs(campaign.id) == []
        assert repository.list_artifacts(program_id=None, asset="local.example") == []
        assert local_run_stages == []
        reservation_runs = repository.list_campaign_local_tool_call_reservations(
            campaign.id
        )
        assert len(reservation_runs) == 1
        reservation_payload = reservation_runs[0].payload
        assert reservation_payload["tool_call_reserved"] is True
        assert reservation_payload["tool_call_reservation_task_id"] == task_id
        assert reservation_payload["tool_call_reservation_tool_id"] == "semgrep_local"
        assert reservation_payload["command_hash"] is None
        assert reservation_payload["finding_count"] == 0
        assert "advisory_findings" not in reservation_payload
        assert director_runtime.campaign_remaining_tool_calls(
            campaign=campaign,
            repository=repository,
        ) == 0
        budget = repository.get_campaign_budget(campaign.id)
        assert budget is not None
        assert budget.tool_calls_reserved == 1

        recovered = director_runtime.tick_campaign_local_execution(
            campaign=repository.get_campaign(campaign.id),
            repository=repository,
            dispatcher=lambda **_kwargs: None,
            workspace_loader=lambda _snapshot: _workspace_inputs(tmp_path),
            now=now + timedelta(seconds=AUTONOMOUS_RESEARCH_TASK_LEASE_SECONDS + 2),
        )
        assert recovered is not None
        assert recovered["status"] == "awaiting_review"
        assert recovered["stop_reason"] == "execution_lease_expired"
        retry = director_runtime.retry_campaign_local_tool_task(
            campaign.id,
            task_id,
            repository=repository,
            dispatcher=lambda *, campaign_task_id: dispatched_ids.append(campaign_task_id),
            workspace_loader=lambda _snapshot: _workspace_inputs(tmp_path),
            now=now + timedelta(seconds=AUTONOMOUS_RESEARCH_TASK_LEASE_SECONDS + 3),
        )
        assert retry["status"] == "awaiting_review"
        assert retry["stop_reason"] == "local_tool_execution_outcome_unknown"
        assert dispatched_ids == [task_id]
    finally:
        session.close()


def test_lost_lease_after_local_output_staging_rolls_back_advisory_evidence(
    tmp_path: Path,
    monkeypatch,
):
    repository, session = _repository()
    try:
        campaign = _campaign(repository, tmp_path)
        dispatched = director_runtime.tick_campaign_local_execution(
            campaign=campaign,
            repository=repository,
            dispatcher=lambda **_kwargs: None,
            workspace_loader=lambda _snapshot: _workspace_inputs(tmp_path),
        )
        assert dispatched is not None
        assert dispatched["status"] == "awaiting_approval"
        _approve_local_tool_task(repository, campaign.id)
        dispatched = director_runtime.tick_campaign_local_execution(
            campaign=repository.get_campaign(campaign.id),
            repository=repository,
            dispatcher=lambda **_kwargs: None,
            workspace_loader=lambda _snapshot: _workspace_inputs(tmp_path),
        )
        assert dispatched is not None
        task_id = dispatched["campaign_task_id"]
        monkeypatch.setattr(
            director_runtime,
            "load_authorized_campaign_inputs",
            lambda _snapshot: _workspace_inputs(tmp_path),
        )
        monkeypatch.setattr(
            director_runtime,
            "run_registered_local_tool",
            lambda request: _completed_local_run(request.authorization.tool_id),
        )
        original_record_stage = director_runtime._record_local_tool_run_stage

        def expire_lease_after_output_staging(**kwargs):
            stage = original_record_stage(**kwargs)
            task = repository.session.get(CampaignTaskRecord, task_id)
            assert task is not None
            task.execution_lease_expires_at = datetime.now(UTC) - timedelta(seconds=1)
            repository.session.flush()
            return stage

        monkeypatch.setattr(
            director_runtime,
            "_record_local_tool_run_stage",
            expire_lease_after_output_staging,
        )

        result = run_agent_task(task_id, repository=repository)
        persisted_task = repository.session.get(CampaignTaskRecord, task_id)
        local_run_stages = [
            stage
            for stage in repository.list_campaign_pipeline_stages(campaign.id)
            if stage.stage_key == "research_director_local_tool_run"
        ]

        assert result == {
            "status": "awaiting_evidence",
            "task_id": task_id,
            "stop_reason": "execution_lease_lost",
        }
        assert persisted_task is not None
        assert persisted_task.status == "running"
        assert repository.list_campaign_scanner_runs(campaign.id) == []
        assert repository.list_artifacts(program_id=None, asset="local.example") == []
        assert local_run_stages == []
    finally:
        session.close()


def test_static_coverage_continues_with_codeql_after_semgrep_advisory(
    tmp_path: Path,
):
    repository, session = _repository()
    try:
        campaign = repository.create_campaign(
            program_id=None,
            name="Multi-engine local analysis campaign",
            autonomy_level="level_1_local_validation",
            scope_status="in_scope",
            policy_text="Authorized local review only.",
            default_asset="local.example",
            allowed_tools=["static_analyzer", "codeql_local"],
            created_by="operator",
            payload={
                "source_snapshot_digest": SNAPSHOT_DIGEST,
                "scope_guard_rule": {
                    "asset": "local.example",
                    "scope_status": "in_scope",
                    "automation": "limited",
                    "allowed_validation": ["static_analyzer"],
                    "forbidden": [],
                    "human_approval_required": False,
                },
                "saved_scope_guard": {"authorized_local_root": str(tmp_path)},
            },
        )
        campaign = repository.update_campaign_status(campaign.id, "running")
        assert campaign is not None
        repository.upsert_campaign_budget(
            campaign_id=campaign.id,
            time_budget_minutes=30,
            token_budget=1000,
            tool_call_budget=2,
            validation_budget=1,
        )
        repository.save_artifact(
            program_id=None,
            asset=campaign.default_asset,
            kind="static_advisory",
            source_type="registered_local_tool",
            source_hash=f"sha256:{'c' * 64}",
            ingestion_status="advisory_only",
            provenance={
                "campaign_id": campaign.id,
                "tool_id": "semgrep_local",
                "source_snapshot_digest": SNAPSHOT_DIGEST,
            },
            payload_summary={"finding_count": 1},
            derived_facts={
                "advisory_findings": [
                    {
                        "rule_id": "mythos.local.ssrf-fetch",
                        "path": "routes.py",
                        "line": 12,
                    }
                ]
            },
        )
        repository.save_scanner_run(
            campaign_id=campaign.id,
            codebase_map_id=None,
            tool_name="semgrep_local",
            command_hash=f"sha256:{'d' * 64}",
            status="semgrep_local_completed",
            finding_count=1,
            candidate_count=0,
            summary="Advisory local run",
            safety_gate_state="allowed",
            payload={
                "research_director_tool_run": True,
                "tool_call_consumed": True,
                "command_executed": True,
                "source_snapshot_digest": SNAPSHOT_DIGEST,
            },
        )
        rule = director_runtime._stored_scope_guard_rule(campaign)
        assert rule is not None

        context = director_runtime.build_campaign_research_director_context(
            campaign=campaign,
            rule=rule,
            repository=repository,
        )
        coverage = next(
            signal
            for signal in context.signals
            if signal.signal_id == "source_snapshot_static_coverage"
        )
        plan = director_runtime.build_research_director_plan(context)

        assert coverage.tool_hints == ["semgrep_local", "codeql_local"]
        assert context.completed_action_ids == ["semgrep_local"]
        assert plan.action_kind == "local_tool"
        assert plan.action_id == "codeql_local"
    finally:
        session.close()


def test_local_execution_queues_codeql_after_semgrep_advisory(
    tmp_path: Path,
    monkeypatch,
):
    repository, session = _repository()
    try:
        campaign = _campaign(
            repository,
            tmp_path,
            allowed_tools=["static_analyzer", "codeql_local"],
        )
        repository.upsert_campaign_budget(
            campaign_id=campaign.id,
            time_budget_minutes=30,
            token_budget=1000,
            tool_call_budget=2,
            validation_budget=1,
        )
        first_tick = director_runtime.tick_campaign_local_execution(
            campaign=campaign,
            repository=repository,
            dispatcher=lambda **_kwargs: None,
            workspace_loader=lambda _snapshot: _workspace_inputs(tmp_path),
        )
        assert first_tick is not None
        assert first_tick["status"] == "awaiting_approval"
        _approve_local_tool_task(repository, campaign.id)
        first_tick = director_runtime.tick_campaign_local_execution(
            campaign=repository.get_campaign(campaign.id),
            repository=repository,
            dispatcher=lambda **_kwargs: None,
            workspace_loader=lambda _snapshot: _workspace_inputs(tmp_path),
        )
        assert first_tick is not None
        assert first_tick["status"] == "dispatched"

        monkeypatch.setattr(
            director_runtime,
            "load_authorized_campaign_inputs",
            lambda _snapshot: _workspace_inputs(tmp_path),
        )
        monkeypatch.setattr(
            director_runtime,
            "run_registered_local_tool",
            lambda request: _completed_local_run(request.authorization.tool_id),
        )
        completed = run_agent_task(
            first_tick["campaign_task_id"],
            repository=repository,
        )
        assert completed["status"] == "completed"

        second_tick = director_runtime.tick_campaign_local_execution(
            campaign=repository.get_campaign(campaign.id),
            repository=repository,
            dispatcher=lambda **_kwargs: None,
            workspace_loader=lambda _snapshot: _workspace_inputs(tmp_path),
        )
        assert second_tick is not None
        assert second_tick["status"] == "awaiting_approval"
        codeql_task = repository.session.get(
            CampaignTaskRecord,
            second_tick["campaign_task_id"],
        )
        assert codeql_task is not None
        assert codeql_task.payload["tool_id"] == "codeql_local"
        assert codeql_task.status == "awaiting_approval"
    finally:
        session.close()
