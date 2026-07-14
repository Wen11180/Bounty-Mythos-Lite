from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app import black_box_hunter
from app.db import Base, get_session
from app.main import app
from app.repository import DatabaseRepository
from app.scope_guard import ScopeGuardRule


NOW = datetime(2026, 7, 14, 12, tzinfo=timezone.utc)


def _repository():
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    return DatabaseRepository(sessionmaker(bind=engine)())


def _lease():
    return black_box_hunter.BlackBoxExecutionLease(
        lease_id="lease_local_lab",
        asset="api.example.com",
        policy_digest="policy_sha256_local_lab",
        scope_digest="scope_sha256_local_lab",
        plan_digest="plan_sha256_local_lab",
        active_origins=["http://127.0.0.1"],
        passive_origins=[],
        account_aliases=["account_a", "account_b"],
        role_aliases=["member", "viewer"],
        allowed_actions=["read_only_replay", "reversible_update"],
        rollback_required=True,
        issued_at=NOW,
        expires_at=NOW + timedelta(days=365),
    )


def _workflow_model_and_plans():
    workflow_a = black_box_hunter.ObservedWorkflow(
        workflow_alias="workflow_a",
        session=black_box_hunter.SessionAlias(
            account_alias="account_a",
            role_alias="member",
            active=True,
        ),
        role_rank=2,
        steps=[
            black_box_hunter.WorkflowStep(
                workflow_index=1,
                origin="http://127.0.0.1",
                route_template="/widgets/{object}",
                method="GET",
                action="read_only_replay",
                state="active",
            ),
            black_box_hunter.WorkflowStep(
                workflow_index=2,
                origin="http://127.0.0.1",
                route_template="/widgets/{object}/state",
                method="PATCH",
                action="reversible_update",
                state="active",
            ),
        ],
        objects=[
            black_box_hunter.ObservedTestObject(
                alias="parent_a",
                owner_alias="account_a",
                state="active",
                reversible=True,
                provenance="demonstrated_normal_flow",
            ),
            black_box_hunter.ObservedTestObject(
                alias="parent_a_other",
                owner_alias="account_a",
                state="active",
                reversible=True,
                provenance="demonstrated_normal_flow",
            ),
            black_box_hunter.ObservedTestObject(
                alias="child_a",
                owner_alias="account_a",
                parent_alias="parent_a",
                state="active",
                reversible=True,
                provenance="demonstrated_normal_flow",
            ),
        ],
        baseline_stable=True,
        rollback_ready=True,
    )
    workflow_b = black_box_hunter.ObservedWorkflow(
        workflow_alias="workflow_b",
        session=black_box_hunter.SessionAlias(
            account_alias="account_b",
            role_alias="viewer",
            active=True,
        ),
        role_rank=1,
        steps=[
            black_box_hunter.WorkflowStep(
                workflow_index=1,
                origin="http://127.0.0.1",
                route_template="/widgets/{object}",
                method="GET",
                action="read_only_replay",
                state="active",
            )
        ],
        objects=[
            black_box_hunter.ObservedTestObject(
                alias="parent_b",
                owner_alias="account_b",
                state="active",
                reversible=True,
                provenance="demonstrated_normal_flow",
            )
        ],
        baseline_stable=True,
        rollback_ready=True,
    )
    model = black_box_hunter.ObservedWorkflowModel(
        workflows=[workflow_a, workflow_b]
    )
    return model, black_box_hunter.plan_differential_trials(model)


def _rule():
    return ScopeGuardRule(
        asset="api.example.com",
        scope_status="in_scope",
        automation="limited",
        allowed_validation=["black_box_differential"],
        forbidden=[],
        human_approval_required=True,
    )


def test_open_black_box_audit_resumes_one_owner_with_safe_initial_stages():
    from app.black_box_hunter.audit import open_black_box_audit

    repository = _repository()
    try:
        workflows, plans = _workflow_model_and_plans()

        owner = open_black_box_audit(
            repository=repository,
            rule=_rule(),
            lease=_lease(),
            workflows=workflows,
            plans=plans,
        )
        resumed = open_black_box_audit(
            repository=repository,
            rule=_rule(),
            lease=_lease(),
            workflows=workflows,
            plans=plans,
        )

        assert resumed == owner
        assert owner.validation_run_id
        validation_run = repository.get_validation_run(owner.validation_run_id)
        assert validation_run is not None
        assert validation_run.approval_required is True
        assert validation_run.allowed_to_execute is False
        stages = repository.list_campaign_pipeline_stages(owner.campaign_id)
        assert [stage.stage_key for stage in stages] == [
            "black_box_lease",
            "black_box_workflow",
            "black_box_plan",
        ]
        persisted = str([stage.payload for stage in stages])
        assert "authorization" not in persisted.lower()
        assert "cookie" not in persisted.lower()
        assert "widget_a" not in persisted
    finally:
        repository.session.close()


def _review_ready_evidence():
    def observation(**updates):
        payload = {
            "status_class": "2xx",
            "response_schema_fingerprint": "sha256:synthetic_schema",
            "timing_bucket": "synthetic",
            "canary_match": None,
            "structural_identity_match": True,
            "state_effect": False,
            "redacted": True,
        }
        payload.update(updates)
        return black_box_hunter.TrialObservation(**payload)

    return black_box_hunter.DifferentialEvidenceBundle(
        baseline_a=observation(),
        baseline_b=observation(),
        trial=observation(canary_match=True),
        owner_control=observation(),
        session_control=observation(),
        repeat=observation(canary_match=True),
        independent_repeat=True,
        rollback_required=False,
    )


def test_bounded_result_requires_preflight_then_closes_execution_and_resumes():
    from app.black_box_hunter.audit import (
        BlackBoxAuditError,
        open_black_box_audit,
        record_black_box_bounded_result,
    )

    repository = _repository()
    try:
        workflows, plans = _workflow_model_and_plans()
        owner = open_black_box_audit(
            repository=repository,
            rule=_rule(),
            lease=_lease(),
            workflows=workflows,
            plans=plans,
        )

        with pytest.raises(BlackBoxAuditError, match="preflight_passed_required"):
            record_black_box_bounded_result(
                repository=repository,
                validation_run_id=owner.validation_run_id,
                plan_index=0,
                evidence=_review_ready_evidence(),
            )

        approved = repository.decide_approval_record(
            approval_id=owner.approval_id,
            decision="approved",
            actor="human_reviewer",
            reason="Approved bounded local-lab result review.",
        )
        assert approved is not None
        preflight = repository.record_validation_run_preflight(
            owner.validation_run_id,
            allowed=True,
            reason="approved_validation_record",
        )
        assert preflight is not None
        assert preflight.status == "preflight_passed"
        assert preflight.allowed_to_execute is True

        result = record_black_box_bounded_result(
            repository=repository,
            validation_run_id=owner.validation_run_id,
            plan_index=0,
            evidence=_review_ready_evidence(),
        )
        resumed = record_black_box_bounded_result(
            repository=repository,
            validation_run_id=owner.validation_run_id,
            plan_index=0,
            evidence=_review_ready_evidence(),
        )

        assert resumed == result
        assert result.status == "review_ready"
        assert result.candidate is not None
        assert result.candidate["human_confirmed"] is False
        assert result.candidate["finding_promotion_allowed"] is False
        assert result.candidate["report_submission_allowed"] is False
        validation_run = repository.get_validation_run(owner.validation_run_id)
        assert validation_run is not None
        assert validation_run.status == "evidence_recorded"
        assert validation_run.allowed_to_execute is False
        assert validation_run.payload["black_box_bounded_result"]["execution_started"] is False
        stages = repository.list_campaign_pipeline_stages(owner.campaign_id)
        assert [stage.stage_key for stage in stages] == [
            "black_box_lease",
            "black_box_workflow",
            "black_box_plan",
            "black_box_trial",
            "black_box_decision",
        ]
    finally:
        repository.session.close()


def test_bounded_result_fails_closed_when_owner_approval_has_expired():
    from app.black_box_hunter.audit import (
        BlackBoxAuditError,
        open_black_box_audit,
        record_black_box_bounded_result,
    )

    repository = _repository()
    try:
        workflows, plans = _workflow_model_and_plans()
        owner = open_black_box_audit(
            repository=repository,
            rule=_rule(),
            lease=_lease(),
            workflows=workflows,
            plans=plans,
        )
        repository.decide_approval_record(
            approval_id=owner.approval_id,
            decision="approved",
            actor="human_reviewer",
            reason="Approved bounded local-lab result review.",
        )
        repository.record_validation_run_preflight(
            owner.validation_run_id,
            allowed=True,
            reason="approved_validation_record",
        )
        approval = next(
            record
            for record in repository.list_campaign_approval_records(owner.campaign_id)
            if record.id == owner.approval_id
        )
        approval.expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
        repository.session.add(approval)
        repository.session.commit()

        with pytest.raises(BlackBoxAuditError, match="active_approval_required"):
            record_black_box_bounded_result(
                repository=repository,
                validation_run_id=owner.validation_run_id,
                plan_index=0,
                evidence=_review_ready_evidence(),
            )

        stages = repository.list_campaign_pipeline_stages(owner.campaign_id)
        assert [stage.stage_key for stage in stages] == [
            "black_box_lease",
            "black_box_workflow",
            "black_box_plan",
        ]
    finally:
        repository.session.close()


def test_bounded_result_binds_candidate_to_the_selected_plan():
    from app.black_box_hunter.audit import (
        open_black_box_audit,
        record_black_box_bounded_result,
    )

    repository = _repository()
    try:
        workflows, plans = _workflow_model_and_plans()
        owner = open_black_box_audit(
            repository=repository,
            rule=_rule(),
            lease=_lease(),
            workflows=workflows,
            plans=plans,
        )
        repository.decide_approval_record(
            approval_id=owner.approval_id,
            decision="approved",
            actor="human_reviewer",
            reason="Approved bounded local-lab result review.",
        )
        repository.record_validation_run_preflight(
            owner.validation_run_id,
            allowed=True,
            reason="approved_validation_record",
        )

        result = record_black_box_bounded_result(
            repository=repository,
            validation_run_id=owner.validation_run_id,
            plan_index=3,
            evidence=_review_ready_evidence(),
        )

        assert result.status == "review_ready"
        assert result.candidate is not None
        assert result.candidate["plan_index"] == 3
        assert result.candidate["trial_class"] == "owned_parent_child_swap"
        assert result.evidence_refs == ["sanitized_parent_child_matrix"]
    finally:
        repository.session.close()


def test_unsupported_review_evidence_type_cannot_create_a_candidate():
    from app.black_box_hunter.audit import (
        open_black_box_audit,
        record_black_box_bounded_result,
    )

    repository = _repository()
    try:
        workflows, plans = _workflow_model_and_plans()
        owner = open_black_box_audit(
            repository=repository,
            rule=_rule(),
            lease=_lease(),
            workflows=workflows,
            plans=plans,
        )
        repository.decide_approval_record(
            approval_id=owner.approval_id,
            decision="approved",
            actor="human_reviewer",
            reason="Approved bounded local-lab result review.",
        )
        repository.record_validation_run_preflight(
            owner.validation_run_id,
            allowed=True,
            reason="approved_validation_record",
        )

        result = record_black_box_bounded_result(
            repository=repository,
            validation_run_id=owner.validation_run_id,
            plan_index=4,
            evidence=_review_ready_evidence(),
        )

        assert result.status == "reproduced"
        assert result.candidate is None
        assert result.evidence_refs == []
    finally:
        repository.session.close()


def test_review_ready_candidate_builds_submission_blocked_review_packet():
    from app.mythos_report import build_black_box_report_review_packet

    packet = build_black_box_report_review_packet(
        {
            "candidate_id": "black_box_candidate",
            "trial_class": "cross_account_object_swap",
            "vulnerability_type": "authorization_boundary",
            "route": {"method": "GET", "path": "/widgets/{object}"},
            "evidence_refs": ["sanitized_cross_account_diff"],
            "status": "review_ready",
            "human_review_required": True,
            "human_confirmed": False,
            "finding_promotion_allowed": False,
            "execution_allowed": False,
            "validation_allowed": False,
            "report_submission_allowed": False,
            "submission_blocked": True,
            "submitted": False,
            "next_allowed_action": "Human review of redacted differential evidence.",
        }
    )

    assert packet["candidate_id"] == "black_box_candidate"
    assert packet["submission_blocked"] is True
    assert packet["human_review_required"] is True
    assert packet["human_confirmed"] is False
    assert packet["finding_promotion_allowed"] is False
    assert packet["report_submission_allowed"] is False
    assert packet["submitted"] is False
    assert packet["evidence_refs"] == ["sanitized_cross_account_diff"]


def test_black_box_report_packet_rejects_any_non_sanitized_evidence_ref():
    from app.mythos_report import build_black_box_report_review_packet

    candidate = {
        "candidate_id": "black_box_candidate",
        "plan_index": 0,
        "trial_class": "cross_account_object_swap",
        "vulnerability_type": "authorization_boundary",
        "route": {"method": "GET", "path": "/widgets/{object}"},
        "evidence_refs": ["sanitized_cross_account_diff", "raw_http_request"],
        "status": "review_ready",
        "human_review_required": True,
        "human_confirmed": False,
        "finding_promotion_allowed": False,
        "execution_allowed": False,
        "validation_allowed": False,
        "report_submission_allowed": False,
        "submission_blocked": True,
        "submitted": False,
    }

    with pytest.raises(ValueError, match="sanitized_black_box_evidence_required"):
        build_black_box_report_review_packet(candidate)


def test_bounded_result_api_exposes_review_packet_without_submission_permission():
    from app.black_box_hunter.audit import open_black_box_audit

    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    testing_session = sessionmaker(bind=engine, expire_on_commit=False)
    with testing_session() as session:
        repository = DatabaseRepository(session)
        workflows, plans = _workflow_model_and_plans()
        owner = open_black_box_audit(
            repository=repository,
            rule=_rule(),
            lease=_lease(),
            workflows=workflows,
            plans=plans,
        )
        repository.decide_approval_record(
            approval_id=owner.approval_id,
            decision="approved",
            actor="human_reviewer",
            reason="Approved bounded local-lab result review.",
        )
        repository.record_validation_run_preflight(
            owner.validation_run_id,
            allowed=True,
            reason="approved_validation_record",
        )

    def override_get_session():
        with testing_session() as session:
            yield session

    app.dependency_overrides[get_session] = override_get_session
    try:
        client = TestClient(app)
        result_response = client.post(
            f"/mythos/black-box/validation-runs/{owner.validation_run_id}/bounded-results",
            json={
                "plan_index": 0,
                "evidence": _review_ready_evidence().model_dump(mode="json"),
            },
        )
        packet_response = client.get(
            f"/mythos/black-box/validation-runs/{owner.validation_run_id}/review-packet"
        )

        assert result_response.status_code == 200
        assert result_response.json()["status"] == "review_ready"
        assert packet_response.status_code == 200
        packet = packet_response.json()
        assert packet["submission_blocked"] is True
        assert packet["human_confirmed"] is False
        assert packet["finding_promotion_allowed"] is False
        assert packet["report_submission_allowed"] is False
        assert packet["submitted"] is False
    finally:
        app.dependency_overrides.clear()


def test_audit_projection_fails_closed_on_corrupt_terminal_stage():
    from app.black_box_hunter.audit import (
        BlackBoxAuditError,
        load_black_box_audit_projection,
        open_black_box_audit,
        record_black_box_bounded_result,
    )

    repository = _repository()
    try:
        workflows, plans = _workflow_model_and_plans()
        owner = open_black_box_audit(
            repository=repository,
            rule=_rule(),
            lease=_lease(),
            workflows=workflows,
            plans=plans,
        )
        repository.decide_approval_record(
            approval_id=owner.approval_id,
            decision="approved",
            actor="human_reviewer",
            reason="Approved bounded local-lab result review.",
        )
        repository.record_validation_run_preflight(
            owner.validation_run_id,
            allowed=True,
            reason="approved_validation_record",
        )
        record_black_box_bounded_result(
            repository=repository,
            validation_run_id=owner.validation_run_id,
            plan_index=0,
            evidence=_review_ready_evidence(),
        )

        decision_stage = next(
            stage
            for stage in repository.list_campaign_pipeline_stages(owner.campaign_id)
            if stage.stage_key == "black_box_decision"
        )
        decision_stage.payload = {
            **decision_stage.payload,
            "preflight_ref": "validation_run:wrong",
        }
        repository.session.add(decision_stage)
        repository.session.commit()

        with pytest.raises(BlackBoxAuditError):
            load_black_box_audit_projection(
                repository=repository,
                validation_run_id=owner.validation_run_id,
            )
    finally:
        repository.session.close()


def test_audit_projection_rejects_terminal_stages_without_bounded_result():
    from app.black_box_hunter.audit import (
        BlackBoxAuditError,
        load_black_box_audit_projection,
        open_black_box_audit,
        record_black_box_bounded_result,
    )

    repository = _repository()
    try:
        workflows, plans = _workflow_model_and_plans()
        owner = open_black_box_audit(
            repository=repository,
            rule=_rule(),
            lease=_lease(),
            workflows=workflows,
            plans=plans,
        )
        repository.decide_approval_record(
            approval_id=owner.approval_id,
            decision="approved",
            actor="human_reviewer",
            reason="Approved bounded local-lab result review.",
        )
        repository.record_validation_run_preflight(
            owner.validation_run_id,
            allowed=True,
            reason="approved_validation_record",
        )
        record_black_box_bounded_result(
            repository=repository,
            validation_run_id=owner.validation_run_id,
            plan_index=0,
            evidence=_review_ready_evidence(),
        )
        validation_run = repository.get_validation_run(owner.validation_run_id)
        assert validation_run is not None
        validation_run.payload = {
            key: value
            for key, value in validation_run.payload.items()
            if key != "black_box_bounded_result"
        }
        repository.session.add(validation_run)
        repository.session.commit()

        with pytest.raises(
            BlackBoxAuditError,
            match="terminal_stages_without_bounded_result",
        ):
            load_black_box_audit_projection(
                repository=repository,
                validation_run_id=owner.validation_run_id,
            )
    finally:
        repository.session.close()
