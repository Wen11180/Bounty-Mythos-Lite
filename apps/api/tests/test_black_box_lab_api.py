from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
from datetime import UTC, datetime, timedelta
from dataclasses import dataclass
from hashlib import sha256
from threading import Barrier

from fastapi.testclient import TestClient
import pytest
from pydantic import ValidationError
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app import main
from app.db import Base, get_session
from app.db_models import (
    ApprovalRecord,
    CampaignRecord,
    PipelineStageRecord,
    ValidationRunRecord,
)
from app.repository import DatabaseRepository


client = TestClient(main.app)


@dataclass(frozen=True)
class ApprovedLabValidationRun:
    validation_run_id: str
    approval_id: str
    pipeline_run_id: str
    mutate_binding: object
    testing_session: object

    def __iter__(self):
        yield self.validation_run_id
        yield self.approval_id
        yield self.mutate_binding


def _lease_preview_payload(**updates):
    payload = {
        "active_origin": "http://127.0.0.1:43110",
        "sessions": [
            {
                "session_alias": "session_a",
                "account_alias": "account_a",
                "role_alias": "member",
                "ready": True,
            },
            {
                "session_alias": "session_b",
                "account_alias": "account_b",
                "role_alias": "member",
                "ready": True,
            },
        ],
        "workflows": [
            {
                "workflow_alias": "read_widget_a",
                "session_alias": "session_a",
                "origin": "http://127.0.0.1:43110",
                "route_template": "/widgets/{object}",
                "method": "GET",
                "action": "read_only_replay",
                "object_aliases": ["widget_a"],
            }
        ],
    }
    payload.update(updates)
    return payload


def test_studio_black_box_lab_lease_preview_is_local_review_only():
    request = main.StudioBlackBoxLabLeasePreviewRequest(
        **_lease_preview_payload()
    )

    preview = main.build_studio_black_box_lab_lease_preview(request)

    assert preview.model_dump(mode="json") == {
        "profile": "local_lab",
        "active_origin": "http://127.0.0.1:43110",
        "session_aliases": ["session_a", "session_b"],
        "workflow_aliases": ["read_widget_a"],
        "sessions_ready": True,
        "trace_review_required": True,
        "human_approval_required": True,
        "execution_allowed": False,
        "persist_session_state": False,
        "blocked_actions": [
            "remote_origin",
            "credential_input",
            "session_persistence",
            "automatic_report_submission",
        ],
    }


def test_studio_black_box_lab_lease_preview_endpoint_returns_no_execution_grant():
    response = client.post(
        "/mythos/studio/black-box-lab/leases/preview",
        json=_lease_preview_payload(),
    )

    assert response.status_code == 200
    assert response.json()["profile"] == "local_lab"
    assert response.json()["execution_allowed"] is False
    assert response.json()["persist_session_state"] is False


@pytest.mark.parametrize(
    "response_model",
    (
        main.StudioBlackBoxLabRunApprovalResponse,
        main.StudioBlackBoxLabRunPreflightResponse,
    ),
)
@pytest.mark.parametrize(
    "unsafe_flag",
    (
        {"local_runner_dispatch_allowed": False},
        {"execution_allowed": True},
        {"report_submission_allowed": True},
    ),
)
def test_studio_black_box_lab_dispatch_contract_never_grants_execution_authority(
    response_model,
    unsafe_flag,
):
    response_fields = {
        "validation_run_id": "validation_run_example",
        "approval_id": "approval_example",
        "approved_session_alias": "session_b",
        "approved_workflow_alias": "read_widget_a",
        "complete_plan_digest": f"sha256:{'a' * 64}",
        "expires_at": "2026-07-20T00:00:00+00:00",
        "lease_digest": f"sha256:{'b' * 64}",
        "plan_digest": "plan_example",
        "scope_reference": f"sha256:{'c' * 64}",
    }

    with pytest.raises(ValidationError):
        response_model(**(response_fields | unsafe_flag))


def test_studio_black_box_lab_lease_preview_rejects_remote_or_credential_input():
    with pytest.raises(ValidationError, match="loopback_origin_required"):
        main.StudioBlackBoxLabLeasePreviewRequest(
            **_lease_preview_payload(active_origin="https://api.example.test")
        )

    with pytest.raises(ValidationError):
        main.StudioBlackBoxLabLeasePreviewRequest(
            **(_lease_preview_payload() | {"credential": "synthetic-value"})
        )


def test_studio_black_box_lab_rejects_concrete_routes_and_uppercase_fingerprints():
    concrete_workflow = _lease_preview_payload()["workflows"][0] | {
        "route_template": "/widgets/concrete-123"
    }
    with pytest.raises(ValidationError, match="normalized_route_template_required"):
        main.StudioBlackBoxLabLeasePreviewRequest(
            **(_lease_preview_payload() | {"workflows": [concrete_workflow]})
        )

    with pytest.raises(ValidationError, match="safe_trace_fingerprint_required"):
        main.StudioBlackBoxLabTraceReviewRequest(
            workflow_alias="read_widget_a",
            session_alias="session_a",
            route_template="/widgets/{object}",
            response_schema_fingerprint=f"sha256:{'A' * 64}",
            redacted=True,
        )


@pytest.mark.parametrize(
    ("field", "value", "reason"),
    [
        ("sessions", [], "exactly_two_lab_sessions_required"),
        ("workflows", [], "one_to_three_lab_workflows_required"),
        (
            "workflows",
            _lease_preview_payload()["workflows"] * 4,
            "one_to_three_lab_workflows_required",
        ),
    ],
)
def test_studio_black_box_lab_lease_preview_enforces_bounded_shape(
    field,
    value,
    reason,
):
    with pytest.raises(ValidationError, match=reason):
        main.StudioBlackBoxLabLeasePreviewRequest(
            **(_lease_preview_payload() | {field: value})
        )


@pytest.fixture
def approved_lab_validation_run():
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    testing_session = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)

    with testing_session() as session:
        repository = DatabaseRepository(session)
        campaign = repository.create_campaign(
            program_id=None,
            name="Local black-box lab",
            autonomy_level="level_2_test_account_validation",
            scope_status="in_scope",
            policy_text="Authorized loopback differential validation only.",
            default_asset="127.0.0.1:43110",
            target_classes=["local_lab"],
            allowed_tools=["black_box_differential"],
            created_by="operator",
            payload={
                "scope_guard_rule": {
                    "asset": "127.0.0.1:43110",
                    "scope_status": "in_scope",
                    "automation": "limited",
                    "allowed_validation": ["black_box_differential"],
                    "forbidden": ["DoS"],
                    "human_approval_required": True,
                }
            },
        )
        task = repository.create_campaign_task(
            campaign_id=campaign.id,
            task_type="validation",
            agent_type="local_lab",
            title="Bounded local lab plan",
        )
        pipeline_run = repository.save_pipeline_run(
            asset=campaign.default_asset,
            policy_text=campaign.policy_text_hash,
            policy_text_is_hash=True,
            scope_status="in_scope",
            hypothesis_count=0,
            blocked_count=0,
            report_title="Local lab",
            payload={
                "campaign_id": campaign.id,
                "report_draft": {
                    "scope_status": "in_scope",
                    "severity": "unconfirmed",
                    "title": "Local lab report preview",
                },
                "validation_gate": {"status": "awaiting_human_review"},
            },
        )
        plan_digest = "plan_sha256_local_lab"
        lease_request = main.StudioBlackBoxLabLeasePreviewRequest(
            **_lease_preview_payload()
        )
        scope_reference = main._studio_black_box_local_scope_digest(
            repository,
            campaign,
            campaign.default_asset,
        )
        lease_digest = main._studio_black_box_local_lease_digest(lease_request)
        approval_facts = {
            "local_lab_complete_plan": True,
            "lease_digest": lease_digest,
            "policy_digest": main._studio_black_box_remote_policy_digest(campaign),
            "scope_reference": scope_reference,
            "allowed_accounts": ["account_a", "account_b"],
            "allowed_roles": ["member"],
            "allowed_workflows": ["read_widget_a"],
        }
        approval = repository.create_approval_record(
            campaign_id=campaign.id,
            task_id=task.id,
            run_id=pipeline_run.id,
            approval_type="validation_batch",
            actor="operator",
            reason="Approve one bounded local-lab run.",
            scope_reference=scope_reference,
            requested_action="local_black_box_differential",
            asset=campaign.default_asset,
            validation_mode="black_box_differential",
            plan_digest=plan_digest,
            autonomy_level=campaign.autonomy_level,
            expires_at=datetime.now(UTC) + timedelta(minutes=15),
            payload=approval_facts,
        )
        validation_run = repository.save_validation_run(
            campaign_id=campaign.id,
            task_id=task.id,
            approval_id=approval.id,
            validation_mode="black_box_differential",
            target_ref=f"campaign:{campaign.id}",
            status="awaiting_approval",
            safety_gate_state="awaiting_approval",
            plan_digest=plan_digest,
            approval_required=True,
            allowed_to_execute=False,
            evidence_ref_count=0,
            summary="Awaiting local-lab approval.",
            payload={
                **approval_facts,
                "pipeline_run_id": pipeline_run.id,
            },
        )
        assert repository.decide_approval_record(
            approval_id=approval.id,
            decision="approved",
            actor="operator",
            reason="Local lab reviewed.",
        ) is not None
        assert repository.record_validation_run_preflight(
            validation_run.id,
            allowed=True,
            reason="approved_validation_record",
        ) is not None
        validation_run_id = validation_run.id
        approval_id = approval.id

    def _override_get_session():
        with testing_session() as session:
            yield session

    main.app.dependency_overrides[get_session] = _override_get_session
    try:
        def mutate_binding(kind: str) -> None:
            with testing_session() as mutation_session:
                stored_approval = mutation_session.get(ApprovalRecord, approval_id)
                stored_validation = mutation_session.get(
                    ValidationRunRecord,
                    validation_run_id,
                )
                stored_campaign = mutation_session.get(CampaignRecord, campaign.id)
                assert stored_approval is not None
                assert stored_validation is not None
                assert stored_campaign is not None
                if kind == "expiry":
                    stored_approval.expires_at = datetime.now(UTC) - timedelta(seconds=1)
                elif kind == "task":
                    stored_approval.task_id = None
                elif kind == "run":
                    stored_approval.run_id = "pipeline_run_changed"
                elif kind == "scope":
                    stored_approval.scope_reference = f"sha256:{'0' * 64}"
                elif kind == "policy":
                    stored_campaign.policy_text_hash = "0" * 64
                elif kind == "current_rule":
                    campaign_payload = dict(stored_campaign.payload)
                    rule = dict(campaign_payload["scope_guard_rule"])
                    rule["forbidden"] = ["black_box_differential"]
                    campaign_payload["scope_guard_rule"] = rule
                    stored_campaign.payload = campaign_payload
                elif kind == "plan":
                    stored_validation.plan_digest = "plan_changed"
                elif kind == "aliases":
                    approval_payload = dict(stored_approval.payload)
                    approval_payload["allowed_accounts"] = ["account_a"]
                    stored_approval.payload = approval_payload
                else:
                    raise AssertionError(f"unsupported mutation: {kind}")
                mutation_session.commit()

        yield ApprovedLabValidationRun(
            validation_run_id=validation_run_id,
            approval_id=approval_id,
            pipeline_run_id=pipeline_run.id,
            mutate_binding=mutate_binding,
            testing_session=testing_session,
        )
    finally:
        main.app.dependency_overrides.pop(get_session, None)
        engine.dispose()


def _run_approval_payload(validation_run_id: str, **updates):
    payload = {
        "validation_run_id": validation_run_id,
        "lease_preview": _lease_preview_payload(),
        "trace_review": [
            {
                "workflow_alias": "read_widget_a",
                "session_alias": "session_a",
                "route_template": "/widgets/{object}",
                "response_schema_fingerprint": f"sha256:{'a' * 64}",
                "redacted": True,
            }
        ],
        "operator_confirmed": True,
    }
    payload.update(updates)
    return payload


def _run_preflight_payload(approval_response: dict, complete_plan: dict | None = None):
    return {
        "approval_id": approval_response["approval_id"],
        "complete_plan_digest": approval_response["complete_plan_digest"],
        "lease_digest": approval_response["lease_digest"],
        "complete_plan": complete_plan
        or _run_approval_payload(approval_response["validation_run_id"]),
    }


def _bounded_result_payload(approval_response: dict, **updates):
    payload = {
        "exact_preflight": _run_preflight_payload(approval_response),
        "trace": {
            "aliases": {
                "account_alias": "account_b",
                "object_aliases": ["widget_a"],
                "role_alias": "member",
                "session_alias": "session_b",
                "workflow_alias": "read_widget_a",
            },
            "method": "GET",
            "parameters": [
                {
                    "location": "path",
                    "name": "object",
                    "value_type": "object_alias",
                }
            ],
            "response_schema_fingerprint": f"sha256:{'b' * 64}",
            "route_template": "/widgets/{object}",
            "status_class": "2xx",
            "timing_bucket": "under_100ms",
        },
    }
    payload.update(updates)
    return payload


def _atomic_bounded_projection(fingerprint: str = "b"):
    return {
        "aliases": {
            "account": "account_b",
            "objects": ["widget_a"],
            "role": "member",
            "runner": "session_b",
            "workflow": "read_widget_a",
        },
        "response_schema_fingerprint": f"sha256:{fingerprint * 64}",
        "status_class": "2xx",
        "timing_bucket": "under_100ms",
        "difference_labels": ["response_schema_changed"],
        "safe_counters": {
            "difference_count": 1,
            "object_alias_count": 1,
            "parameter_count": 1,
        },
    }


def _bounded_stage_id(pipeline_run_id: str, validation_run_id: str) -> str:
    identity = f"{pipeline_run_id}|{validation_run_id}|studio_black_box_bounded_result"
    return f"pipeline_stage_bounded_{sha256(identity.encode('utf-8')).hexdigest()[:48]}"


def _seed_atomic_bounded_result_database(database_path, validation_count: int = 1):
    engine = create_engine(
        f"sqlite:///{database_path}",
        connect_args={"check_same_thread": False, "timeout": 30},
    )
    Base.metadata.create_all(bind=engine)
    testing_session = sessionmaker(
        bind=engine,
        autoflush=False,
        expire_on_commit=False,
    )
    with testing_session() as session:
        repository = DatabaseRepository(session)
        campaign = repository.create_campaign(
            program_id=None,
            name="Atomic bounded result",
            autonomy_level="level_2_test_account_validation",
            scope_status="in_scope",
            policy_text="Authorized local atomic result test.",
            default_asset="127.0.0.1:43110",
            created_by="operator",
        )
        pipeline_run = repository.save_pipeline_run(
            asset=campaign.default_asset,
            policy_text=campaign.policy_text_hash,
            policy_text_is_hash=True,
            scope_status="in_scope",
            hypothesis_count=0,
            blocked_count=0,
            report_title="Atomic result",
            payload={
                "campaign_id": campaign.id,
                "unrelated_fact": {"preserved": True},
                "report_draft": {
                    "scope_status": "in_scope",
                    "severity": "unconfirmed",
                    "title": "Atomic result preview",
                },
                "validation_gate": {"status": "awaiting_human_review"},
            },
        )
        validation_ids = []
        for index in range(validation_count):
            task = repository.create_campaign_task(
                campaign_id=campaign.id,
                task_type="validation",
                agent_type="local_lab",
                title=f"Atomic bounded result {index}",
            )
            approval = repository.create_approval_record(
                campaign_id=campaign.id,
                task_id=task.id,
                run_id=pipeline_run.id,
                approval_type="validation_batch",
                actor="operator",
                reason="Approve atomic bounded result.",
                scope_reference=f"scope_{index}",
                requested_action="local_black_box_differential",
                asset=campaign.default_asset,
                validation_mode="black_box_differential",
                plan_digest=f"plan_{index}",
                autonomy_level=campaign.autonomy_level,
                expires_at=datetime.now(UTC) + timedelta(minutes=15),
            )
            validation_run = repository.save_validation_run(
                campaign_id=campaign.id,
                task_id=task.id,
                approval_id=approval.id,
                validation_mode="black_box_differential",
                target_ref=f"campaign:{campaign.id}",
                status="awaiting_approval",
                safety_gate_state="awaiting_approval",
                plan_digest=f"plan_{index}",
                approval_required=True,
                allowed_to_execute=False,
                evidence_ref_count=0,
                summary="Awaiting atomic result.",
                payload={"pipeline_run_id": pipeline_run.id},
            )
            assert repository.decide_approval_record(
                approval_id=approval.id,
                decision="approved",
                actor="operator",
                reason="Approved.",
            ) is not None
            validation_run.status = "preflight_passed"
            validation_run.safety_gate_state = "scope_guard_preflight_passed"
            validation_run.allowed_to_execute = True
            session.add(validation_run)
            session.commit()
            validation_ids.append(validation_run.id)
    return engine, testing_session, pipeline_run.id, validation_ids


def _concurrent_complete_plan_digest_bindings(tmp_path, digests):
    engine = create_engine(
        f"sqlite:///{tmp_path / 'complete-plan-binding.db'}",
        connect_args={"check_same_thread": False},
    )
    Base.metadata.create_all(bind=engine)
    testing_session = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
    with testing_session() as session:
        approval = DatabaseRepository(session).create_approval_record(
            approval_type="validation_batch",
            actor="operator",
            reason="Concurrent complete-plan binding test.",
            payload={"existing_fact": "preserved"},
        )
        approval_id = approval.id

    barrier = Barrier(len(digests))

    def bind(digest):
        with testing_session() as session:
            approval = session.get(ApprovalRecord, approval_id)
            assert approval is not None
            barrier.wait()
            return main._studio_black_box_local_bind_complete_plan_digest(
                approval,
                digest,
                repository=DatabaseRepository(session),
            )

    with ThreadPoolExecutor(max_workers=len(digests)) as executor:
        results = list(executor.map(bind, digests))
    with testing_session() as session:
        approval = session.get(ApprovalRecord, approval_id)
        assert approval is not None
        payload = approval.payload
    engine.dispose()
    return results, payload


def _bind_complete_plan_digest_once(payload, digest):
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    testing_session = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
    with testing_session() as session:
        repository = DatabaseRepository(session)
        approval = repository.create_approval_record(
            approval_type="validation_batch",
            actor="operator",
            reason="Complete-plan binding validation test.",
            payload={},
        )
        approval.payload = payload
        session.add(approval)
        session.commit()
        session.refresh(approval)
        result = main._studio_black_box_local_bind_complete_plan_digest(
            approval,
            digest,
            repository=repository,
        )
        final_payload = approval.payload
    engine.dispose()
    return result, final_payload


@pytest.mark.parametrize(
    "durable_value",
    [None, 7, "invalid", f"sha256:{'A' * 64}"],
)
def test_complete_plan_digest_existing_invalid_key_fails_closed(durable_value):
    payload = {
        "existing_fact": "preserved",
        "complete_plan_digest": durable_value,
    }

    result, final_payload = _bind_complete_plan_digest_once(
        payload,
        f"sha256:{'a' * 64}",
    )

    assert result is False
    assert final_payload == payload


@pytest.mark.parametrize(
    "digest",
    [None, 7, "invalid", f"sha256:{'A' * 64}", f"sha256:{'a' * 63}"],
)
def test_complete_plan_digest_invalid_input_fails_closed(digest):
    result, final_payload = _bind_complete_plan_digest_once(
        {"existing_fact": "preserved"},
        digest,
    )

    assert result is False
    assert final_payload == {"existing_fact": "preserved"}


@pytest.mark.parametrize("payload", [None, [], "invalid", 7])
def test_complete_plan_digest_non_object_payload_fails_closed(payload):
    result, final_payload = _bind_complete_plan_digest_once(
        payload,
        f"sha256:{'a' * 64}",
    )

    assert result is False
    assert final_payload == payload


def test_complete_plan_digest_first_binding_is_atomic_for_different_digests(tmp_path):
    first_digest = f"sha256:{'a' * 64}"
    second_digest = f"sha256:{'b' * 64}"

    results, payload = _concurrent_complete_plan_digest_bindings(
        tmp_path,
        [first_digest, second_digest],
    )

    assert results.count(True) == 1
    assert payload == {
        "existing_fact": "preserved",
        "complete_plan_digest": payload["complete_plan_digest"],
    }
    assert payload["complete_plan_digest"] in {first_digest, second_digest}


def test_complete_plan_digest_first_binding_is_idempotent_for_same_digest(tmp_path):
    digest = f"sha256:{'a' * 64}"

    results, payload = _concurrent_complete_plan_digest_bindings(
        tmp_path,
        [digest, digest],
    )

    assert results == [True, True]
    assert payload == {
        "existing_fact": "preserved",
        "complete_plan_digest": digest,
    }


def test_studio_black_box_lab_run_approval_binds_durable_preflight(
    approved_lab_validation_run,
):
    validation_run_id, approval_id, _ = approved_lab_validation_run

    response = client.post(
        "/mythos/studio/black-box-lab/runs/approve",
        json=_run_approval_payload(validation_run_id),
    )

    assert response.status_code == 200, response.text
    assert response.json() == {
        "approval_status": "approved",
        "validation_run_id": validation_run_id,
        "approval_id": approval_id,
        "approved_session_alias": "session_b",
        "approved_workflow_alias": "read_widget_a",
        "complete_plan_digest": response.json()["complete_plan_digest"],
        "expires_at": response.json()["expires_at"],
        "lease_digest": response.json()["lease_digest"],
        "plan_digest": "plan_sha256_local_lab",
        "scope_reference": response.json()["scope_reference"],
        "local_runner_dispatch_allowed": True,
        "execution_allowed": False,
        "report_submission_allowed": False,
        "reason": "bounded_local_lab_run_approved",
    }
    assert response.json()["lease_digest"].startswith("sha256:")
    assert response.json()["complete_plan_digest"].startswith("sha256:")
    assert response.json()["scope_reference"]
    assert datetime.fromisoformat(response.json()["expires_at"]) > datetime.now(UTC)
    with approved_lab_validation_run.testing_session() as session:
        durable_approval = session.get(ApprovalRecord, approval_id)
        assert durable_approval is not None
        assert (
            durable_approval.payload["complete_plan_digest"]
            == response.json()["complete_plan_digest"]
        )


def test_studio_black_box_lab_exact_preflight_returns_only_current_dispatch_facts(
    approved_lab_validation_run,
):
    validation_run_id, approval_id, _ = approved_lab_validation_run
    approval_response = client.post(
        "/mythos/studio/black-box-lab/runs/approve",
        json=_run_approval_payload(validation_run_id),
    ).json()

    response = client.post(
        "/mythos/studio/black-box-lab/runs/preflight",
        json=_run_preflight_payload(approval_response),
    )

    assert response.status_code == 200, response.text
    assert response.json() == {
        "validation_run_id": validation_run_id,
        "approval_id": approval_id,
        "approved_session_alias": "session_b",
        "approved_workflow_alias": "read_widget_a",
        "complete_plan_digest": approval_response["complete_plan_digest"],
        "expires_at": approval_response["expires_at"],
        "lease_digest": approval_response["lease_digest"],
        "plan_digest": "plan_sha256_local_lab",
        "scope_reference": approval_response["scope_reference"],
        "local_runner_dispatch_allowed": True,
        "execution_allowed": False,
        "report_submission_allowed": False,
    }


def test_studio_black_box_lab_complete_plan_digest_is_stable(
    approved_lab_validation_run,
):
    validation_run_id, _, _ = approved_lab_validation_run
    complete_plan = _run_approval_payload(validation_run_id)

    first = client.post(
        "/mythos/studio/black-box-lab/runs/approve",
        json=complete_plan,
    )
    second = client.post(
        "/mythos/studio/black-box-lab/runs/approve",
        json=complete_plan,
    )

    assert first.status_code == 200, first.text
    assert second.status_code == 200, second.text
    assert first.json()["complete_plan_digest"] == second.json()["complete_plan_digest"]


def test_studio_black_box_lab_exact_preflight_rejects_trace_fingerprint_mutation(
    approved_lab_validation_run,
):
    validation_run_id, _, _ = approved_lab_validation_run
    approval_response = client.post(
        "/mythos/studio/black-box-lab/runs/approve",
        json=_run_approval_payload(validation_run_id),
    ).json()
    changed_plan = _run_approval_payload(validation_run_id)
    changed_plan["trace_review"][0]["response_schema_fingerprint"] = (
        f"sha256:{'b' * 64}"
    )

    response = client.post(
        "/mythos/studio/black-box-lab/runs/preflight",
        json=_run_preflight_payload(approval_response, changed_plan),
    )

    assert response.status_code == 409
    assert response.json()["detail"] == "fresh_complete_local_plan_preflight_required"


def test_studio_black_box_lab_exact_preflight_rejects_recomputed_mutated_plan_digest(
    approved_lab_validation_run,
):
    validation_run_id, _, _ = approved_lab_validation_run
    approval_response = client.post(
        "/mythos/studio/black-box-lab/runs/approve",
        json=_run_approval_payload(validation_run_id),
    ).json()
    changed_plan = _run_approval_payload(validation_run_id)
    changed_plan["trace_review"][0]["response_schema_fingerprint"] = (
        f"sha256:{'b' * 64}"
    )
    payload = _run_preflight_payload(approval_response, changed_plan)
    payload["complete_plan_digest"] = main._studio_black_box_local_complete_plan_digest(
        main.StudioBlackBoxLabRunApprovalRequest(**changed_plan)
    )

    response = client.post(
        "/mythos/studio/black-box-lab/runs/preflight",
        json=payload,
    )

    assert response.status_code == 409
    assert response.json()["detail"] == "fresh_complete_local_plan_preflight_required"


@pytest.mark.parametrize(
    "mutation",
    ["expiry", "task", "run", "scope", "policy", "current_rule", "plan", "aliases"],
)
def test_studio_black_box_lab_exact_preflight_rejects_durable_drift(
    approved_lab_validation_run,
    mutation,
):
    validation_run_id, _, mutate_binding = approved_lab_validation_run
    approval_response = client.post(
        "/mythos/studio/black-box-lab/runs/approve",
        json=_run_approval_payload(validation_run_id),
    ).json()
    mutate_binding(mutation)

    response = client.post(
        "/mythos/studio/black-box-lab/runs/preflight",
        json=_run_preflight_payload(approval_response),
    )

    assert response.status_code == 409
    assert response.json()["detail"] == "fresh_complete_local_plan_preflight_required"


@pytest.mark.parametrize("changed", ["approval_id", "lease_digest", "alias", "readiness"])
def test_studio_black_box_lab_exact_preflight_rejects_request_drift(
    approved_lab_validation_run,
    changed,
):
    validation_run_id, _, _ = approved_lab_validation_run
    approval_response = client.post(
        "/mythos/studio/black-box-lab/runs/approve",
        json=_run_approval_payload(validation_run_id),
    ).json()
    complete_plan = _run_approval_payload(validation_run_id)
    payload = _run_preflight_payload(approval_response, complete_plan)
    if changed == "approval_id":
        payload["approval_id"] = "approval_changed"
    elif changed == "lease_digest":
        payload["lease_digest"] = f"sha256:{'0' * 64}"
    elif changed == "alias":
        complete_plan["lease_preview"]["sessions"][1]["account_alias"] = "account_changed"
    else:
        complete_plan["lease_preview"]["sessions"][1]["ready"] = False

    response = client.post(
        "/mythos/studio/black-box-lab/runs/preflight",
        json=payload,
    )

    assert response.status_code == 409
    assert response.json()["detail"] == "fresh_complete_local_plan_preflight_required"


def test_studio_black_box_lab_run_approval_requires_operator_confirmation(
    approved_lab_validation_run,
):
    validation_run_id, _, _ = approved_lab_validation_run

    response = client.post(
        "/mythos/studio/black-box-lab/runs/approve",
        json=_run_approval_payload(validation_run_id, operator_confirmed=False),
    )

    assert response.status_code == 409
    assert response.json() == {"detail": "operator_confirmation_required"}


def test_studio_black_box_lab_run_approval_requires_matching_redacted_trace(
    approved_lab_validation_run,
):
    validation_run_id, _, _ = approved_lab_validation_run
    mismatched_trace = _run_approval_payload(validation_run_id)["trace_review"]
    mismatched_trace[0]["workflow_alias"] = "different_workflow"

    response = client.post(
        "/mythos/studio/black-box-lab/runs/approve",
        json=_run_approval_payload(
            validation_run_id,
            trace_review=mismatched_trace,
        ),
    )

    assert response.status_code == 409
    assert response.json() == {"detail": "reviewed_trace_set_required"}


@pytest.mark.parametrize(
    "mutation",
    ["expiry", "task", "run", "scope", "policy", "current_rule", "plan", "aliases"],
)
def test_studio_black_box_lab_auto_dispatch_fails_closed_when_binding_changes(
    approved_lab_validation_run,
    mutation,
):
    validation_run_id, _, mutate_binding = approved_lab_validation_run
    mutate_binding(mutation)

    response = client.post(
        "/mythos/studio/black-box-lab/runs/approve",
        json=_run_approval_payload(validation_run_id),
    )

    assert response.status_code == 409
    assert response.json()["detail"] in {
        "fresh_complete_local_plan_approval_required",
        "local_lab_preflight_required",
    }


@pytest.mark.parametrize("changed", ["origin", "readiness", "aliases"])
def test_studio_black_box_lab_auto_dispatch_rejects_changed_plan_input(
    approved_lab_validation_run,
    changed,
):
    validation_run_id, _, _ = approved_lab_validation_run
    lease_preview = _lease_preview_payload()
    if changed == "origin":
        lease_preview["active_origin"] = "http://127.0.0.1:43111"
        lease_preview["workflows"][0]["origin"] = "http://127.0.0.1:43111"
    elif changed == "readiness":
        lease_preview["sessions"][1]["ready"] = False
    else:
        lease_preview["sessions"][1]["account_alias"] = "account_changed"

    response = client.post(
        "/mythos/studio/black-box-lab/runs/approve",
        json=_run_approval_payload(validation_run_id, lease_preview=lease_preview),
    )

    assert response.status_code == 409


def test_studio_black_box_lab_bounded_result_persists_only_safe_fields_and_refreshes_report(
    approved_lab_validation_run,
):
    approval_response = client.post(
        "/mythos/studio/black-box-lab/runs/approve",
        json=_run_approval_payload(approved_lab_validation_run.validation_run_id),
    )
    assert approval_response.status_code == 200, approval_response.text

    before = client.get(
        f"/mythos/pipeline/runs/{approved_lab_validation_run.pipeline_run_id}/report-preview"
    )
    assert before.status_code == 200, before.text
    assert not any(
        "Bounded local-lab result" in line
        for line in before.json()["sections"]["unverified_claims"]
    )
    before_overview = client.get("/mythos/control-center/overview")
    assert before_overview.status_code == 200, before_overview.text

    response = client.post(
        "/mythos/studio/black-box-lab/runs/bounded-result",
        json=_bounded_result_payload(approval_response.json()),
    )

    assert response.status_code == 200, response.text
    assert response.json() == {
        "campaign_id": response.json()["campaign_id"],
        "difference_labels": ["response_schema_changed"],
        "evidence_ref_count": 1,
        "execution_allowed": False,
        "human_review_required": True,
        "pipeline_run_id": approved_lab_validation_run.pipeline_run_id,
        "report_preview_refreshed": True,
        "report_submission_allowed": False,
        "result_digest": response.json()["result_digest"],
        "submission_blocked": True,
        "validation_run_id": approved_lab_validation_run.validation_run_id,
        "validation_status": "needs_evidence",
    }

    after = client.get(
        f"/mythos/pipeline/runs/{approved_lab_validation_run.pipeline_run_id}/report-preview"
    )
    assert after.status_code == 200, after.text
    assert after.json()["human_review_required"] is True
    assert after.json()["submission_blocked"] is True
    assert any(
        "Bounded local-lab result" in line
        for line in after.json()["sections"]["unverified_claims"]
    )
    after_overview = client.get("/mythos/control-center/overview")
    assert after_overview.status_code == 200, after_overview.text
    assert after_overview.json()["snapshot_version"] != before_overview.json()[
        "snapshot_version"
    ]
    assert after_overview.json()["report_readiness"]["human_review_required"] is True
    assert after_overview.json()["report_readiness"]["submission_blocked"] is True
    assert after_overview.json()["report_readiness"]["report_submission_allowed"] is False

    replay = client.post(
        "/mythos/studio/black-box-lab/runs/bounded-result",
        json=_bounded_result_payload(approval_response.json()),
    )
    assert replay.status_code == 200, replay.text
    assert replay.json()["result_digest"] == response.json()["result_digest"]
    changed_duplicate = _bounded_result_payload(approval_response.json())
    changed_duplicate["trace"]["response_schema_fingerprint"] = f"sha256:{'c' * 64}"
    mismatch = client.post(
        "/mythos/studio/black-box-lab/runs/bounded-result",
        json=changed_duplicate,
    )
    assert mismatch.status_code == 409
    assert mismatch.json()["detail"] == "bounded_result_request_mismatch"

    with approved_lab_validation_run.testing_session() as session:
        repository = DatabaseRepository(session)
        validation_run = repository.get_validation_run(
            approved_lab_validation_run.validation_run_id
        )
        pipeline_run = repository.get_pipeline_run(
            approved_lab_validation_run.pipeline_run_id
        )
        assert validation_run is not None
        assert pipeline_run is not None
        assert validation_run.allowed_to_execute is False
        assert validation_run.evidence_ref_count == 1
        assert validation_run.payload["black_box_bounded_result"]["execution_started"] is False
        stored_result = validation_run.payload["black_box_bounded_result"][
            "result_payload"
        ]
        assert "trace" not in stored_result
        assert stored_result["aliases"] == {
            "account": "account_b",
            "objects": ["widget_a"],
            "role": "member",
            "runner": "session_b",
            "workflow": "read_widget_a",
        }
        assert stored_result["response_schema_fingerprint"] == f"sha256:{'b' * 64}"
        assert stored_result["status_class"] == "2xx"
        assert stored_result["timing_bucket"] == "under_100ms"
        assert stored_result["difference_labels"] == ["response_schema_changed"]
        assert stored_result["safe_counters"] == {
            "difference_count": 1,
            "object_alias_count": 1,
            "parameter_count": 1,
        }
        assert stored_result["provenance_refs"] == [
            f"approval:{validation_run.approval_id}",
            f"pipeline_run:{pipeline_run.id}",
            f"validation_run:{validation_run.id}",
        ]
        pipeline_results = pipeline_run.payload["studio_black_box_bounded_results"]
        assert len(pipeline_results) == 1
        assert pipeline_results[0]["aliases"] == stored_result["aliases"]
        assert pipeline_results[0]["response_schema_fingerprint"] == stored_result[
            "response_schema_fingerprint"
        ]
        assert "raw_body" not in str(validation_run.payload)
        assert "raw_body" not in str(pipeline_run.payload)
        for forbidden_key in ("method", "parameters", "route_template"):
            assert forbidden_key not in stored_result
            assert forbidden_key not in pipeline_results[0]
        stages = [
            stage
            for stage in repository.list_pipeline_stages_for_run(pipeline_run.id)
            if stage.stage_key == "studio_black_box_bounded_result"
        ]
        assert len(stages) == 1
        assert stages[0].id == _bounded_stage_id(pipeline_run.id, validation_run.id)
        assert stages[0].payload["human_review_required"] is True
        assert stages[0].payload["report_submission_allowed"] is False
        pure_preview = main.build_report_preview_response(pipeline_run)
        assert not any(
            "Bounded local-lab result" in claim.text
            for claim in pure_preview.claim_ledger
        )

    bounded_claims = [
        claim
        for claim in after.json()["claim_ledger"]
        if "Bounded local-lab result" in claim["text"]
    ]
    assert len(bounded_claims) == 1
    assert bounded_claims[0]["claim_id"] == (
        f"claim_bounded_result_{response.json()['result_digest'].removeprefix('sha256:')}"
    )
    assert bounded_claims[0]["provenance_refs"] == [
        f"approval:{approved_lab_validation_run.approval_id}",
        f"pipeline_run:{approved_lab_validation_run.pipeline_run_id}",
        f"validation_run:{approved_lab_validation_run.validation_run_id}",
    ]



@pytest.mark.parametrize(
    ("field", "forged_value"),
    [
        ("approval_id", "approval_forged"),
        ("validation_run_id", "validation_run_forged"),
        ("result_digest", f"sha256:{'f' * 64}"),
        ("provenance_refs", ["approval:forged"]),
    ],
)
def test_report_preview_rejects_pipeline_bounded_result_forgery(
    approved_lab_validation_run,
    field,
    forged_value,
):
    approval_response = client.post(
        "/mythos/studio/black-box-lab/runs/approve",
        json=_run_approval_payload(approved_lab_validation_run.validation_run_id),
    )
    assert approval_response.status_code == 200, approval_response.text
    result_response = client.post(
        "/mythos/studio/black-box-lab/runs/bounded-result",
        json=_bounded_result_payload(approval_response.json()),
    )
    assert result_response.status_code == 200, result_response.text

    with approved_lab_validation_run.testing_session() as session:
        pipeline_run = DatabaseRepository(session).get_pipeline_run(
            approved_lab_validation_run.pipeline_run_id
        )
        assert pipeline_run is not None
        payload = dict(pipeline_run.payload)
        results = [dict(item) for item in payload["studio_black_box_bounded_results"]]
        results[0][field] = forged_value
        payload["studio_black_box_bounded_results"] = results
        pipeline_run.payload = payload
        session.add(pipeline_run)
        session.commit()

    preview = client.get(
        f"/mythos/pipeline/runs/{approved_lab_validation_run.pipeline_run_id}/report-preview"
    )
    assert preview.status_code == 200, preview.text
    assert preview.json()["human_review_required"] is True
    assert preview.json()["submission_blocked"] is True
    assert not any(
        "Bounded local-lab result" in claim["text"]
        for claim in preview.json()["claim_ledger"]
    )


@pytest.mark.parametrize(
    "corruption",
    [
        "missing_stage",
        "missing_validation",
        "missing_approval",
        "missing_digest",
        "stage_binding",
        "validation_binding",
        "approval_binding",
        "approval_timing",
        "digest_mismatch",
    ],
)
def test_report_preview_requires_complete_database_backed_bounded_result_provenance(
    approved_lab_validation_run,
    corruption,
):
    approval_response = client.post(
        "/mythos/studio/black-box-lab/runs/approve",
        json=_run_approval_payload(approved_lab_validation_run.validation_run_id),
    )
    assert approval_response.status_code == 200, approval_response.text
    result_response = client.post(
        "/mythos/studio/black-box-lab/runs/bounded-result",
        json=_bounded_result_payload(approval_response.json()),
    )
    assert result_response.status_code == 200, result_response.text

    with approved_lab_validation_run.testing_session() as session:
        repository = DatabaseRepository(session)
        validation_run = repository.get_validation_run(
            approved_lab_validation_run.validation_run_id
        )
        stage = repository.get_pipeline_stage(
            _bounded_stage_id(
                approved_lab_validation_run.pipeline_run_id,
                approved_lab_validation_run.validation_run_id,
            )
        )
        assert validation_run is not None
        assert stage is not None
        approval = session.get(ApprovalRecord, validation_run.approval_id)
        assert approval is not None
        if corruption == "missing_stage":
            session.delete(stage)
        elif corruption == "missing_validation":
            session.delete(validation_run)
        elif corruption == "missing_approval":
            session.delete(approval)
        elif corruption == "missing_digest":
            stage_payload = dict(stage.payload)
            stage_payload.pop("result_digest")
            stage.payload = stage_payload
        elif corruption == "stage_binding":
            stage.task_id = "task_forged"
        elif corruption == "validation_binding":
            validation_run.task_id = "task_forged"
        elif corruption == "approval_binding":
            approval.run_id = "pipeline_run_forged"
        elif corruption == "approval_timing":
            approval.decided_at = validation_run.finished_at + timedelta(seconds=1)
        else:
            stage_payload = dict(stage.payload)
            stage_payload["result_digest"] = f"sha256:{'e' * 64}"
            stage.payload = stage_payload
        session.commit()

    preview = client.get(
        f"/mythos/pipeline/runs/{approved_lab_validation_run.pipeline_run_id}/report-preview"
    )
    assert preview.status_code == 200, preview.text
    assert preview.json()["human_review_required"] is True
    assert preview.json()["submission_blocked"] is True
    assert not any(
        "Bounded local-lab result" in claim["text"]
        for claim in preview.json()["claim_ledger"]
    )


@pytest.mark.parametrize(
    "failure_point",
    ["pipeline_run", "validation_run", "pipeline_stage"],
)
def test_studio_bounded_result_atomic_write_rolls_back_every_internal_failure(
    approved_lab_validation_run,
    failure_point,
):
    with approved_lab_validation_run.testing_session() as session:
        repository = DatabaseRepository(session)
        pipeline_before = deepcopy(
            repository.get_pipeline_run(
                approved_lab_validation_run.pipeline_run_id
            ).payload
        )

        def fail_after(point: str) -> None:
            if point == failure_point:
                raise RuntimeError(f"injected_{point}_failure")

        with pytest.raises(RuntimeError, match=f"injected_{failure_point}_failure"):
            repository.record_studio_black_box_bounded_result_atomic(
                validation_run_id=approved_lab_validation_run.validation_run_id,
                pipeline_run_id=approved_lab_validation_run.pipeline_run_id,
                result_digest=f"sha256:{'e' * 64}",
                bounded_projection=_atomic_bounded_projection(),
                failure_injector=fail_after,
            )

    with approved_lab_validation_run.testing_session() as session:
        repository = DatabaseRepository(session)
        validation_run = repository.get_validation_run(
            approved_lab_validation_run.validation_run_id
        )
        pipeline_run = repository.get_pipeline_run(
            approved_lab_validation_run.pipeline_run_id
        )
        assert validation_run is not None
        assert pipeline_run is not None
        assert validation_run.status == "preflight_passed"
        assert validation_run.allowed_to_execute is True
        assert "black_box_bounded_result" not in validation_run.payload
        assert pipeline_run.payload == pipeline_before
        assert session.get(
            PipelineStageRecord,
            _bounded_stage_id(pipeline_run.id, validation_run.id),
        ) is None


@pytest.mark.parametrize("partial_piece", ["validation_run", "pipeline_run", "pipeline_stage"])
def test_studio_bounded_result_partial_replay_fails_closed(
    approved_lab_validation_run,
    partial_piece,
):
    result_digest = f"sha256:{'e' * 64}"
    with approved_lab_validation_run.testing_session() as session:
        validation_run = session.get(
            ValidationRunRecord,
            approved_lab_validation_run.validation_run_id,
        )
        assert validation_run is not None
        pipeline_run = DatabaseRepository(session).get_pipeline_run(
            approved_lab_validation_run.pipeline_run_id
        )
        assert pipeline_run is not None
        if partial_piece == "validation_run":
            validation_run.status = "needs_evidence"
            validation_run.allowed_to_execute = False
            payload = dict(validation_run.payload)
            payload["black_box_bounded_result"] = {
                "audit_digest": result_digest,
                "decision_status": "observed",
                "evidence_refs": ["sanitized_cross_account_diff"],
                "execution_started": False,
                "result_payload": {
                    "schema_version": "studio_black_box_bounded_result_v1",
                    "request_digest": result_digest,
                    **_atomic_bounded_projection(),
                    "provenance_refs": [
                        f"approval:{approved_lab_validation_run.approval_id}",
                        f"pipeline_run:{approved_lab_validation_run.pipeline_run_id}",
                        f"validation_run:{approved_lab_validation_run.validation_run_id}",
                    ],
                    "human_review_required": True,
                    "submission_blocked": True,
                    "execution_allowed": False,
                    "report_submission_allowed": False,
                    "raw_payload_processed": False,
                },
            }
            validation_run.payload = payload
        elif partial_piece == "pipeline_run":
            pipeline_payload = dict(pipeline_run.payload)
            pipeline_payload["studio_black_box_bounded_results"] = [
                {
                    "validation_run_id": validation_run.id,
                    "result_digest": result_digest,
                }
            ]
            pipeline_run.payload = pipeline_payload
        else:
            session.add(
                PipelineStageRecord(
                    id=_bounded_stage_id(pipeline_run.id, validation_run.id),
                    pipeline_run_id=pipeline_run.id,
                    campaign_id=validation_run.campaign_id,
                    task_id=validation_run.task_id,
                    stage_key="studio_black_box_bounded_result",
                    stage_order=0,
                    status="needs_evidence",
                    input_refs=[],
                    output_refs=[],
                    safety_gate_state="human_review_required",
                    stop_reason=None,
                    payload={"result_digest": result_digest},
                )
            )
        session.commit()

    with approved_lab_validation_run.testing_session() as session:
        repository = DatabaseRepository(session)
        with pytest.raises(ValueError, match="bounded_result_partial_state"):
            repository.record_studio_black_box_bounded_result_atomic(
                validation_run_id=approved_lab_validation_run.validation_run_id,
                pipeline_run_id=approved_lab_validation_run.pipeline_run_id,
                result_digest=result_digest,
                bounded_projection=_atomic_bounded_projection(),
            )

        pipeline_run = repository.get_pipeline_run(
            approved_lab_validation_run.pipeline_run_id
        )
        assert pipeline_run is not None
        if partial_piece != "pipeline_run":
            assert "studio_black_box_bounded_results" not in pipeline_run.payload
        if partial_piece != "pipeline_stage":
            assert session.get(
                PipelineStageRecord,
                _bounded_stage_id(
                    approved_lab_validation_run.pipeline_run_id,
                    approved_lab_validation_run.validation_run_id,
                ),
            ) is None


@pytest.mark.parametrize("same_digest", [True, False])
def test_studio_bounded_result_concurrent_writes_are_coherent(
    tmp_path,
    same_digest,
):
    engine, testing_session, pipeline_run_id, validation_ids = (
        _seed_atomic_bounded_result_database(tmp_path / "bounded-concurrent.db")
    )
    validation_run_id = validation_ids[0]
    barrier = Barrier(2)
    digests = [f"sha256:{'e' * 64}", f"sha256:{('e' if same_digest else 'f') * 64}"]

    def record(digest: str):
        with testing_session() as session:
            barrier.wait()
            try:
                result = DatabaseRepository(
                    session
                ).record_studio_black_box_bounded_result_atomic(
                    validation_run_id=validation_run_id,
                    pipeline_run_id=pipeline_run_id,
                    result_digest=digest,
                    bounded_projection=_atomic_bounded_projection(
                        "b" if digest == digests[0] else "c"
                    ),
                )
                return "ok", result[1].payload
            except ValueError as exc:
                return str(exc), None

    with ThreadPoolExecutor(max_workers=2) as executor:
        outcomes = list(executor.map(record, digests))

    with testing_session() as session:
        repository = DatabaseRepository(session)
        pipeline_run = repository.get_pipeline_run(pipeline_run_id)
        validation_run = repository.get_validation_run(validation_run_id)
        stages = [
            stage
            for stage in repository.list_pipeline_stages_for_run(pipeline_run_id)
            if stage.stage_key == "studio_black_box_bounded_result"
        ]
        assert pipeline_run is not None
        assert validation_run is not None
        assert len(pipeline_run.payload["studio_black_box_bounded_results"]) == 1
        assert len(stages) == 1
        assert stages[0].id == _bounded_stage_id(pipeline_run_id, validation_run_id)
        assert validation_run.status == "needs_evidence"
        assert pipeline_run.payload["unrelated_fact"] == {"preserved": True}
    engine.dispose()

    if same_digest:
        assert [outcome[0] for outcome in outcomes] == ["ok", "ok"]
    else:
        assert sorted(outcome[0] for outcome in outcomes) == [
            "bounded_result_request_mismatch",
            "ok",
        ]


def test_studio_bounded_result_concurrent_pipeline_appends_preserve_unrelated_payload(
    tmp_path,
):
    engine, testing_session, pipeline_run_id, validation_ids = (
        _seed_atomic_bounded_result_database(
            tmp_path / "bounded-pipeline-concurrent.db",
            validation_count=2,
        )
    )
    barrier = Barrier(2)

    def record(item: tuple[int, str]):
        index, validation_run_id = item
        with testing_session() as session:
            barrier.wait()
            DatabaseRepository(
                session
            ).record_studio_black_box_bounded_result_atomic(
                validation_run_id=validation_run_id,
                pipeline_run_id=pipeline_run_id,
                result_digest=f"sha256:{('e' if index == 0 else 'f') * 64}",
                bounded_projection=_atomic_bounded_projection(
                    "b" if index == 0 else "c"
                ),
            )

    with ThreadPoolExecutor(max_workers=2) as executor:
        list(executor.map(record, enumerate(validation_ids)))

    with testing_session() as session:
        repository = DatabaseRepository(session)
        pipeline_run = repository.get_pipeline_run(pipeline_run_id)
        assert pipeline_run is not None
        assert pipeline_run.payload["unrelated_fact"] == {"preserved": True}
        assert {
            result["validation_run_id"]
            for result in pipeline_run.payload["studio_black_box_bounded_results"]
        } == set(validation_ids)
        assert len(
            [
                stage
                for stage in repository.list_pipeline_stages_for_run(pipeline_run_id)
                if stage.stage_key == "studio_black_box_bounded_result"
            ]
        ) == 2
    engine.dispose()


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("raw_body", "synthetic body"),
        ("request_headers", {"authorization": "Bearer synthetic"}),
        ("response_body", {"password": "synthetic"}),
        ("cookies", {"session": "synthetic"}),
        ("credentials", {"token": "synthetic"}),
    ],
)
def test_studio_black_box_lab_bounded_result_rejects_raw_trace_material_without_mutation(
    approved_lab_validation_run,
    field,
    value,
):
    approval_response = client.post(
        "/mythos/studio/black-box-lab/runs/approve",
        json=_run_approval_payload(approved_lab_validation_run.validation_run_id),
    )
    assert approval_response.status_code == 200, approval_response.text
    payload = _bounded_result_payload(approval_response.json())
    payload["trace"][field] = value

    before = client.get(
        f"/mythos/pipeline/runs/{approved_lab_validation_run.pipeline_run_id}/report-preview"
    )
    assert before.status_code == 200, before.text

    response = client.post(
        "/mythos/studio/black-box-lab/runs/bounded-result",
        json=payload,
    )

    assert response.status_code == 422
    with approved_lab_validation_run.testing_session() as session:
        validation_run = DatabaseRepository(session).get_validation_run(
            approved_lab_validation_run.validation_run_id
        )
        assert validation_run is not None
        assert validation_run.status == "preflight_passed"
        assert "black_box_bounded_result" not in validation_run.payload
    after = client.get(
        f"/mythos/pipeline/runs/{approved_lab_validation_run.pipeline_run_id}/report-preview"
    )
    assert after.status_code == 200, after.text
    assert after.json() == before.json()


@pytest.mark.parametrize(
    "secret_alias",
    ["token_value", "cookie_value", "password_value", "secret_value"],
)
def test_studio_black_box_lab_bounded_result_rejects_secret_shaped_aliases_without_mutation(
    approved_lab_validation_run,
    secret_alias,
):
    approval_response = client.post(
        "/mythos/studio/black-box-lab/runs/approve",
        json=_run_approval_payload(approved_lab_validation_run.validation_run_id),
    )
    assert approval_response.status_code == 200, approval_response.text
    payload = _bounded_result_payload(approval_response.json())
    payload["trace"]["aliases"]["account_alias"] = secret_alias

    response = client.post(
        "/mythos/studio/black-box-lab/runs/bounded-result",
        json=payload,
    )

    assert response.status_code == 422
    with approved_lab_validation_run.testing_session() as session:
        validation_run = DatabaseRepository(session).get_validation_run(
            approved_lab_validation_run.validation_run_id
        )
        assert validation_run is not None
        assert validation_run.status == "preflight_passed"
        assert "black_box_bounded_result" not in validation_run.payload


def test_studio_black_box_lab_bounded_result_fails_closed_after_scope_drift(
    approved_lab_validation_run,
):
    approval_response = client.post(
        "/mythos/studio/black-box-lab/runs/approve",
        json=_run_approval_payload(approved_lab_validation_run.validation_run_id),
    )
    assert approval_response.status_code == 200, approval_response.text
    approved_lab_validation_run.mutate_binding("scope")

    response = client.post(
        "/mythos/studio/black-box-lab/runs/bounded-result",
        json=_bounded_result_payload(approval_response.json()),
    )

    assert response.status_code == 409
    with approved_lab_validation_run.testing_session() as session:
        validation_run = DatabaseRepository(session).get_validation_run(
            approved_lab_validation_run.validation_run_id
        )
        assert validation_run is not None
        assert validation_run.status == "blocked"
        assert "black_box_bounded_result" not in validation_run.payload
