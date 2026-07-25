import asyncio
from datetime import UTC, datetime, timedelta
import importlib
import json
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.candidate_hunter_loop import run_candidate_hunter_loop
from app.control_center.contracts import (
    ControlCenterOverviewResponse,
    SanitizedEventSummary,
)
from app.control_center.service import build_control_center_overview
from app.control_center.events import stream_control_center_events
from app.db import Base, get_session
from app.main import _campaign_control_center_response, app
from app.repository import DatabaseRepository


client = TestClient(app)
NOW = datetime(2026, 7, 18, 12, 0, tzinfo=UTC)


def build_testing_session():
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    return sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


def _candidate_state(run_id: str) -> dict:
    return {
        "candidate_id": "H-001",
        "candidate_key": f"{run_id}:H-001",
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
        "observed_artifact_kinds": ["scope", "policy", "code", "api", "har"],
        "required_artifact_kinds": ["scope", "policy", "code", "api", "har"],
        "evidence_trace_status": "traceable",
        "priority_score": 80,
        "gap_evidence_ref": "code:code.py:read_record",
        "shared_root": "read_record",
        "shared_root_evidence_ref": "code:code.py:read_record",
    }


def _seed_live_overview(
    repository: DatabaseRepository,
    *,
    refuted: bool = False,
    evidence_pending: bool = False,
) -> tuple[str, str]:
    run = repository.save_pipeline_run(
        asset="local.test",
        policy_text="Synthetic local policy.",
        scope_status="in_scope",
        hypothesis_count=1,
        blocked_count=0,
        report_title="Candidate review draft",
        payload={
            "hypotheses": [],
            "report_draft": {
                "title": "Candidate review draft",
                "severity": "unknown",
                "scope_status": "in_scope",
                "safety_notes": ["submission_blocked"],
            },
        },
    )
    candidate_state = _candidate_state(run.id)
    if refuted:
        control_ref = "api:GET:/records/{record_id}:security_required"
        candidate_state["source_fact_refs"].append(control_ref)
        candidate_state["control_evidence_ref"] = control_ref
    candidate_states = [candidate_state]
    if evidence_pending:
        pending = _candidate_state(run.id)
        pending.update(
            candidate_id="H-002",
            candidate_key=f"{run.id}:H-002",
            root_cause_id="missing_tenant_guard:list_records",
            route={"method": "GET", "path": "/records"},
            shared_root="list_records",
            shared_root_evidence_ref="code:code.py:list_records",
            gap_evidence_ref="code:code.py:list_records",
            observed_artifact_kinds=["scope", "policy", "code", "api"],
            evidence_trace_status="needs_evidence",
        )
        pending["source_fact_refs"] = [
            ref for ref in pending["source_fact_refs"] if not ref.startswith("har:")
        ]
        candidate_states.append(pending)
    loop = run_candidate_hunter_loop(
        repository=repository,
        record=run,
        policy_text="Synthetic local policy.",
        candidates=[],
        observations={
            "candidate_states": candidate_states,
            "execution_allowed": False,
            "dispatch_allowed": False,
            "validation_allowed": False,
            "candidate_promotion_allowed": False,
            "report_submission_allowed": False,
            "raw_payload_processed": False,
        },
    )
    campaign_id = loop["campaign_id"]
    repository.upsert_campaign_budget(
        campaign_id=campaign_id,
        time_budget_minutes=60,
        token_budget=1000,
        tool_call_budget=10,
        validation_budget=2,
    )
    task = repository.create_campaign_task(
        campaign_id=campaign_id,
        task_type="report_chain_review",
        agent_type="report_agent",
        title="Review report chain",
        input_refs=[f"pipeline_run:{run.id}"],
        payload={"authorization": "Bearer secret-token", "raw_body": "private"},
    )
    repository.update_campaign_task_status(task.id, "running")
    repository.save_agent_run(
        campaign_id=campaign_id,
        task_id=task.id,
        agent_type="report_agent",
        status="running",
        input_refs=[f"campaign_task:{task.id}"],
        output_refs=[],
        tool_calls=[],
        safety_gate_state="allowed",
        stop_reason=None,
        payload={"cookie": "session=secret"},
    )
    approval = repository.create_approval_record(
        campaign_id=campaign_id,
        task_id=task.id,
        run_id=run.id,
        approval_type="validation_batch",
        actor="reviewer",
        reason="Review requested",
        requested_action="bounded_local_validation",
        safety_gate_state="awaiting_approval",
        payload={"password": "secret-password"},
    )
    approval.created_at = NOW - timedelta(minutes=10)
    approval.status = "approved"
    approval.decided_at = NOW
    repository.session.add(approval)
    repository.session.commit()
    repository.create_approval_record(
        campaign_id=campaign_id,
        task_id=task.id,
        run_id=run.id,
        approval_type="validation_batch",
        actor="reviewer",
        reason="Waiting for review",
        requested_action="bounded_local_validation",
        safety_gate_state="awaiting_approval",
        expires_at=NOW + timedelta(hours=1),
        payload={"headers": {"Authorization": "Bearer secret-token"}},
    )
    repository.save_validation_run(
        campaign_id=campaign_id,
        task_id=task.id,
        approval_id=None,
        validation_mode="local_lab",
        target_ref="local.test",
        status="planned",
        safety_gate_state="awaiting_approval",
        plan_digest="safe-plan-digest",
        approval_required=True,
        allowed_to_execute=False,
        evidence_ref_count=0,
        summary="Awaiting human approval",
        payload={"raw_body": "private", "authorization": "Bearer secret-token"},
    )
    repository.save_pipeline_stage(
        pipeline_run_id=run.id,
        campaign_id=campaign_id,
        task_id=task.id,
        stage_key="scope_guard_review",
        stage_order=10,
        status="blocked",
        input_refs=["policy:safe"],
        output_refs=[],
        safety_gate_state="blocked",
        stop_reason="approval_required",
        payload={"token": "secret-token", "raw_response_body": "private"},
    )
    return campaign_id, run.id


def test_overview_aggregates_only_durable_safe_state():
    testing_session = build_testing_session()
    with testing_session() as session:
        repository = DatabaseRepository(session)
        campaign_id, run_id = _seed_live_overview(repository)

        overview = build_control_center_overview(repository, now=NOW)

    assert overview.data_mode == "live"
    assert overview.generated_at == NOW
    assert len(overview.snapshot_version) == 64
    assert overview.empty_state is False
    assert overview.metrics.running_task_count == 1
    assert overview.metrics.retained_high_value_candidate_count == 1
    assert overview.metrics.approval_pressure_count == 1
    assert overview.metrics.safety_block_count == 1
    assert overview.research_quality.retention_rate == 1.0
    assert overview.research_quality.refutation_kill_rate == 0.0
    assert overview.research_quality.evidence_completeness == 1.0
    assert overview.research_quality.median_human_review_seconds == 600.0
    assert overview.candidates[0].campaign_id == campaign_id
    assert overview.candidates[0].pipeline_run_id == run_id
    assert overview.candidates[0].affected_endpoint == "GET /records/{record_id}"
    assert overview.report_readiness.available is True
    assert overview.report_readiness.status == "submission_blocked"
    assert overview.report_readiness.report_submission_allowed is False
    response_text = overview.model_dump_json()
    for unsafe in (
        "secret-token",
        "secret-password",
        "Authorization",
        "session=secret",
        "raw_response_body",
        "raw_body",
    ):
        assert unsafe not in response_text


def test_overview_empty_live_state_does_not_fabricate_quality_metrics():
    testing_session = build_testing_session()
    with testing_session() as session:
        overview = build_control_center_overview(DatabaseRepository(session), now=NOW)

    assert overview.data_mode == "live"
    assert overview.empty_state is True
    assert overview.metrics.running_task_count == 0
    assert overview.metrics.retained_high_value_candidate_count == 0
    assert overview.research_quality.retention_rate is None
    assert overview.research_quality.refutation_kill_rate is None
    assert overview.research_quality.evidence_completeness is None
    assert overview.research_quality.median_human_review_seconds is None
    assert overview.report_readiness.available is False
    assert overview.report_readiness.report_submission_allowed is False
    assert ControlCenterOverviewResponse.model_config["extra"] == "forbid"


def test_overview_includes_safe_autonomous_wakeup_health_without_lease_digest():
    testing_session = build_testing_session()
    lease_digest = "a" * 64
    with testing_session() as session:
        repository = DatabaseRepository(session)
        assert repository.claim_autonomous_research_wakeup(
            claim_token_digest=lease_digest,
            now=NOW,
        ) is not None

        overview = build_control_center_overview(repository, now=NOW)

    health = overview.autonomous_wakeup
    assert health is not None
    assert health.status == "active"
    assert health.last_heartbeat_at == NOW
    assert health.heartbeat_age_seconds == 0
    assert health.lease_active is True
    assert health.has_more_campaigns is False
    assert health.scheduled_interval_seconds == 60
    assert health.execution_allowed is False
    assert health.dispatch_allowed is False
    assert health.validation_allowed is False
    assert health.candidate_promotion_allowed is False
    assert health.report_submission_allowed is False
    assert lease_digest not in overview.model_dump_json()


def test_snapshot_version_ignores_elapsed_wakeup_age_between_heartbeats():
    testing_session = build_testing_session()
    with testing_session() as session:
        repository = DatabaseRepository(session)
        assert repository.claim_autonomous_research_wakeup(
            claim_token_digest="b" * 64,
            now=NOW,
        ) is not None

        first = build_control_center_overview(
            repository,
            now=NOW + timedelta(seconds=2),
        )
        second = build_control_center_overview(
            repository,
            now=NOW + timedelta(seconds=4),
        )

    assert first.autonomous_wakeup is not None
    assert second.autonomous_wakeup is not None
    assert first.autonomous_wakeup.heartbeat_age_seconds == 2
    assert second.autonomous_wakeup.heartbeat_age_seconds == 4
    assert first.snapshot_version == second.snapshot_version


def test_overview_quality_uses_generated_and_challenged_candidate_denominators():
    testing_session = build_testing_session()
    with testing_session() as session:
        repository = DatabaseRepository(session)
        _seed_live_overview(repository)
        _seed_live_overview(repository, refuted=True)

        overview = build_control_center_overview(repository, now=NOW)

    assert overview.metrics.retained_high_value_candidate_count == 1
    assert overview.research_quality.retention_rate == 0.5
    assert overview.research_quality.refutation_kill_rate == 0.5
    assert overview.research_quality.evidence_completeness == 1.0


def test_pending_evidence_candidate_counts_in_generated_population_and_evidence_quality():
    testing_session = build_testing_session()
    with testing_session() as session:
        repository = DatabaseRepository(session)
        _seed_live_overview(repository, evidence_pending=True)

        overview = build_control_center_overview(repository, now=NOW)

    assert overview.metrics.retained_high_value_candidate_count == 1
    assert overview.research_quality.retention_rate == 0.5
    assert overview.research_quality.refutation_kill_rate == 0.0
    assert overview.research_quality.evidence_completeness == 0.9


def test_invalid_candidate_hunter_stage_sequence_is_a_block_not_a_candidate():
    testing_session = build_testing_session()
    with testing_session() as session:
        repository = DatabaseRepository(session)
        campaign_id, run_id = _seed_live_overview(repository)
        task = repository.list_campaign_tasks(campaign_id)[0]
        repository.save_pipeline_stage(
            pipeline_run_id=run_id,
            campaign_id=campaign_id,
            task_id=task.id,
            stage_key="candidate_hunter_snapshot",
            stage_order=99,
            status="completed",
            input_refs=[],
            output_refs=[],
            safety_gate_state="safe",
            stop_reason=None,
            payload={"schema_version": "invalid-sequence"},
        )

        overview = build_control_center_overview(repository, now=NOW)

    assert overview.metrics.retained_high_value_candidate_count == 0
    assert overview.metrics.safety_block_count == 2
    assert overview.research_quality.retention_rate is None
    assert overview.research_quality.refutation_kill_rate is None


def test_operational_failures_and_budget_pressure_are_not_safety_blocks():
    testing_session = build_testing_session()
    with testing_session() as session:
        repository = DatabaseRepository(session)
        campaign = repository.create_campaign(
            program_id=None,
            name="Operational failure",
            autonomy_level="review_only",
            scope_status="in_scope",
            policy_text="Synthetic local policy.",
            default_asset="local.test",
            target_classes=["local_code"],
            allowed_tools=[],
            created_by="test",
        )
        repository.upsert_campaign_budget(
            campaign_id=campaign.id,
            time_budget_minutes=0,
            token_budget=0,
            tool_call_budget=0,
            validation_budget=0,
        )
        repository.update_campaign_status(campaign.id, "failed")
        repository.save_pipeline_stage(
            pipeline_run_id=None,
            campaign_id=campaign.id,
            task_id=None,
            stage_key="code_api_audit",
            stage_order=1,
            status="paused",
            input_refs=[],
            output_refs=[],
            safety_gate_state="blocked",
            stop_reason="budget_exhausted",
            payload={},
        )

        overview = build_control_center_overview(repository, now=NOW)

    assert overview.campaigns[0].blocked_reasons == [
        "campaign_failed",
        "budget_exhausted",
    ]
    assert overview.metrics.safety_block_count == 0


def test_overview_normalizes_sqlite_datetimes_to_aware_utc():
    testing_session = build_testing_session()
    with testing_session() as session:
        repository = DatabaseRepository(session)
        campaign_id, _ = _seed_live_overview(repository)
        task = repository.list_campaign_tasks(campaign_id)[0]
        task.created_at = datetime(2026, 7, 18, 10, 30)
        repository.session.add(task)
        repository.session.commit()

        overview = build_control_center_overview(
            repository,
            now=datetime(2026, 7, 18, 12, 0),
        )

    assert overview.generated_at == NOW
    task_event = next(event for event in overview.recent_events if event.event_id == task.id)
    assert task_event.occurred_at.utcoffset() == timedelta(0)
    assert task_event.occurred_at.tzinfo is not None

    with pytest.raises(ValidationError):
        SanitizedEventSummary(
            event_id="event",
            campaign_id=campaign_id,
            event_type="research_task",
            status="running",
            occurred_at=datetime(2026, 7, 18, 10, 30),
        )
    unsafe_overview = overview.model_dump()
    unsafe_overview["generated_at"] = datetime(2026, 7, 18, 12, 0)
    with pytest.raises(ValidationError):
        ControlCenterOverviewResponse.model_validate(unsafe_overview)


def test_overview_reuses_campaign_control_center_collections(monkeypatch):
    testing_session = build_testing_session()
    with testing_session() as session:
        repository = DatabaseRepository(session)
        _seed_live_overview(repository)
        calls = {
            "list_campaign_tasks": 0,
            "list_campaign_approval_records": 0,
            "list_campaign_pipeline_stages": 0,
        }
        for method_name in calls:
            original = getattr(repository, method_name)

            def tracked(*args, _method_name=method_name, _original=original, **kwargs):
                calls[_method_name] += 1
                return _original(*args, **kwargs)

            monkeypatch.setattr(repository, method_name, tracked)

        campaign = repository.list_campaigns()[0]
        _campaign_control_center_response(campaign, repository)
        baseline_calls = dict(calls)
        calls.update({method_name: 0 for method_name in calls})
        build_control_center_overview(repository, now=NOW)

    assert calls["list_campaign_approval_records"] == baseline_calls[
        "list_campaign_approval_records"
    ]
    assert calls["list_campaign_pipeline_stages"] == baseline_calls[
        "list_campaign_pipeline_stages"
    ]
    # Candidate Hunter owner validation performs one required task lookup per run.
    assert calls["list_campaign_tasks"] == baseline_calls["list_campaign_tasks"] + 1


def test_snapshot_version_changes_only_for_visible_safe_projection_changes():
    testing_session = build_testing_session()
    with testing_session() as session:
        repository = DatabaseRepository(session)
        campaign_id, _ = _seed_live_overview(repository)
        first = build_control_center_overview(repository, campaign_id=campaign_id, now=NOW)
        second = build_control_center_overview(
            repository,
            campaign_id=campaign_id,
            now=NOW + timedelta(minutes=1),
        )
        assert first.snapshot_version == second.snapshot_version

        task = repository.list_campaign_tasks(campaign_id)[0]
        task.payload = {
            "authorization": "Bearer changed-secret",
            "cookie": "changed=session",
            "raw_body": "changed-private-body",
        }
        repository.session.add(task)
        repository.session.commit()
        secret_only = build_control_center_overview(repository, campaign_id=campaign_id, now=NOW)
        assert secret_only.snapshot_version == first.snapshot_version
        assert "changed-secret" not in secret_only.model_dump_json()

        repository.update_campaign_task_status(task.id, "completed")
        visible_change = build_control_center_overview(
            repository,
            campaign_id=campaign_id,
            now=NOW,
        )
        assert visible_change.snapshot_version != first.snapshot_version


def test_overview_route_filters_campaign_and_returns_404_for_unknown_filter():
    testing_session = build_testing_session()

    def override_get_session():
        with testing_session() as session:
            yield session

    with testing_session() as session:
        campaign_id, _ = _seed_live_overview(DatabaseRepository(session))
        _seed_live_overview(DatabaseRepository(session), refuted=True)

    app.dependency_overrides[get_session] = override_get_session
    try:
        response = client.get(
            "/mythos/control-center/overview",
            params={"campaign_id": campaign_id},
        )
        unfiltered = client.get("/mythos/control-center/overview")
        unknown = client.get(
            "/mythos/control-center/overview",
            params={"campaign_id": "campaign_missing"},
        )
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == 200
    assert response.json()["campaigns"][0]["id"] == campaign_id
    assert unfiltered.status_code == 200
    assert len(unfiltered.json()["campaigns"]) == 2
    assert unknown.status_code == 404
    assert unknown.json()["detail"] == "Campaign not found"


def test_overview_route_returns_explicit_empty_live_state():
    testing_session = build_testing_session()

    def override_get_session():
        with testing_session() as session:
            yield session

    app.dependency_overrides[get_session] = override_get_session
    try:
        response = client.get("/mythos/control-center/overview")
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == 200
    body = response.json()
    assert body["data_mode"] == "live"
    assert body["empty_state"] is True
    assert body["research_quality"] == {
        "retention_rate": None,
        "refutation_kill_rate": None,
        "evidence_completeness": None,
        "median_human_review_seconds": None,
    }


def test_control_center_event_stream_emits_safe_digest_changes_and_keepalives():
    versions = ["a" * 64, "a" * 64, "a" * 64, "b" * 64]
    secrets = ["first-secret", "changed-secret", "changed-secret", "final-secret"]
    opened = []
    closed = []

    class TrackingSession:
        def __init__(self, index):
            self.index = index
            opened.append(index)

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            closed.append(self.index)

    def session_factory():
        return TrackingSession(len(opened))

    def overview_builder(_repository, *, campaign_id, now, campaign_response_builder=None):
        index = len(opened) - 1
        assert campaign_id == "campaign_1"
        assert now == NOW + timedelta(seconds=index)
        assert campaign_response_builder is None
        return SimpleNamespace(
            snapshot_version=versions[index],
            secret=secrets[index],
        )

    ticks = iter(NOW + timedelta(seconds=index) for index in range(4))

    async def collect_events():
        stream = stream_control_center_events(
            campaign_id="campaign_1",
            scope="campaign",
            session_factory=session_factory,
            now=lambda: next(ticks),
            sleep=lambda _seconds: asyncio.sleep(0),
            overview_builder=overview_builder,
        )
        chunks = [await anext(stream) for _ in range(4)]
        await stream.aclose()
        return chunks

    chunks = asyncio.run(collect_events())

    assert chunks[0].startswith(
        f"event: control-center-invalidated\nid: {'a' * 64}\nretry: 5000\n"
    )
    assert json.loads(chunks[0].split("data: ", 1)[1]) == {
        "snapshot_version": "a" * 64,
        "scope": "campaign",
        "changed": ["overview"],
    }
    assert chunks[1] == ": keepalive\n\n"
    assert chunks[2] == ": keepalive\n\n"
    assert f"id: {'b' * 64}" in chunks[3]
    assert "secret" not in "".join(chunks).lower()
    assert opened == [0, 1, 2, 3]
    assert closed == opened


def test_control_center_event_stream_uses_cursor_and_closes_before_cancellation():
    closed = []
    sleeping = asyncio.Event()

    class TrackingSession:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            closed.append(True)

    async def blocking_sleep(_seconds):
        sleeping.set()
        await asyncio.Future()

    def overview_builder(_repository, **_kwargs):
        return SimpleNamespace(snapshot_version="c" * 64)

    async def cancel_stream():
        stream = stream_control_center_events(
            cursor="c" * 64,
            session_factory=TrackingSession,
            now=lambda: NOW,
            sleep=blocking_sleep,
            overview_builder=overview_builder,
        )
        assert await anext(stream) == ": keepalive\n\n"
        pending = asyncio.create_task(anext(stream))
        await sleeping.wait()
        pending.cancel()
        with pytest.raises(asyncio.CancelledError):
            await pending
        await stream.aclose()

    asyncio.run(cancel_stream())
    assert closed == [True]


def test_control_center_events_route_is_bounded_filtered_and_unbuffered(monkeypatch):
    router_module = importlib.import_module("app.routers.control_center")
    testing_session = build_testing_session()
    calls = []
    preflight_session_closed = False

    def override_get_session():
        nonlocal preflight_session_closed
        try:
            with testing_session() as session:
                yield session
        finally:
            preflight_session_closed = True

    with testing_session() as session:
        campaign_id, _ = _seed_live_overview(DatabaseRepository(session))

    async def finite_stream(**kwargs):
        assert preflight_session_closed is True
        calls.append(kwargs)
        yield ": keepalive\n\n"

    event_routes = [
        route
        for route in app.routes
        if getattr(route, "path", None) == "/mythos/control-center/events"
        and "GET" in getattr(route, "methods", set())
    ]
    assert len(event_routes) == 1

    monkeypatch.setattr(router_module, "stream_control_center_events", finite_stream)
    app.dependency_overrides[get_session] = override_get_session
    try:
        response = client.get(
            "/mythos/control-center/events",
            params={"campaign_id": campaign_id, "cursor": "d" * 64},
        )
        invalid = client.get(
            "/mythos/control-center/events",
            params={"campaign_id": ""},
        )
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/event-stream")
    assert response.headers["cache-control"] == "no-cache"
    assert response.headers["x-accel-buffering"] == "no"
    assert response.text == ": keepalive\n\n"
    assert calls == [
        {
            "campaign_id": campaign_id,
            "cursor": "d" * 64,
            "scope": "campaign",
        }
    ]
    assert invalid.status_code == 422


def test_control_center_events_route_rejects_unknown_campaign_before_streaming(monkeypatch):
    router_module = importlib.import_module("app.routers.control_center")
    testing_session = build_testing_session()
    stream_started = False

    def override_get_session():
        with testing_session() as session:
            yield session

    async def finite_stream(**_kwargs):
        nonlocal stream_started
        stream_started = True
        yield ": keepalive\n\n"

    monkeypatch.setattr(router_module, "stream_control_center_events", finite_stream)
    app.dependency_overrides[get_session] = override_get_session
    try:
        response = client.get(
            "/mythos/control-center/events",
            params={"campaign_id": "campaign_missing"},
        )
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == 404
    assert response.json() == {"detail": "Campaign not found"}
    assert stream_started is False


def test_control_center_events_cors_preflight_allows_last_event_id_header():
    response = client.options(
        "/mythos/control-center/events",
        headers={
            "Origin": "http://127.0.0.1:3000",
            "Access-Control-Request-Method": "GET",
            "Access-Control-Request-Headers": "Last-Event-ID",
        },
    )

    assert response.status_code == 200
    assert response.headers["access-control-allow-origin"] == "http://127.0.0.1:3000"
    assert "last-event-id" in response.headers["access-control-allow-headers"].lower()
