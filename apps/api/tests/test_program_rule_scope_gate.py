from contextlib import contextmanager
from datetime import UTC, datetime, timedelta

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.db import Base, get_session
from app.main import app
from app.program_rule_intake.scope_resolver import (
    intersect_scope_guard_rules,
    resolve_effective_program_rule,
)
from app.repository import DatabaseRepository
from app.scope_guard import (
    ScopeGuardRule,
    ValidationRequest,
    evaluate_validation_request,
)


NOW = datetime(2026, 7, 16, 8, 0, tzinfo=UTC)


def build_repository():
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    session = sessionmaker(bind=engine, expire_on_commit=False)()
    return DatabaseRepository(session), session, engine


def scope_rule(
    asset,
    asset_kind,
    *,
    scope_status="in_scope",
    automation="limited",
    allowed_validation=None,
    prohibited=None,
    rate_limit=None,
):
    return {
        "canonical_asset": asset,
        "asset_kind": asset_kind,
        "source_evidence_refs": ["e" * 64],
        "scope_status": scope_status,
        "automation": automation,
        "allowed_validation": allowed_validation or [],
        "prohibited": prohibited or [],
        "rate_limit": rate_limit,
    }


def seed_approved_source(repository, *, rules, now=NOW):
    source = repository.create_program_rule_source(
        program_alias="scope_gate_program",
        registered_url="https://rules.example.com/program",
        now=now,
    )
    snapshot = repository.save_program_rule_snapshot(
        source_id=source.id,
        raw_aggregate_sha256="a" * 64,
        normalized_sha256="b" * 64,
        fetched_at=now,
        fetch_mode="static",
        content_types=["text/plain"],
        detected_language="en",
        extraction={
            "rules": [],
            "evidence": [],
            "linked_artifacts": [],
            "review_state": "ready",
            "review_issues": [],
            "ai_status": "not_requested",
            "ai_prompt_sha256": None,
            "ai_error_category": None,
        },
        evidence=[],
        linked_documents=[],
        openapi_candidates=[],
        ai_status="not_requested",
        review_status="pending",
        review_digest="c" * 64,
    )
    repository.update_program_rule_snapshot_review(
        source_id=source.id,
        snapshot_id=snapshot.id,
        review_status="approved",
        reviewer_alias="reviewer_1",
        reviewed_at=now,
    )
    repository.set_program_rule_source_snapshot_pointers(
        source_id=source.id,
        approved_snapshot_id=snapshot.id,
        pending_snapshot_id=None,
        updated_at=now,
    )
    source = repository.get_program_rule_source(source.id)
    source.fetch_status = "ok"
    source.last_check_at = now
    source.last_success_at = now
    source.next_check_at = now + timedelta(days=1)
    repository.session.add(source)
    repository.session.commit()
    repository.replace_program_scope_rules(
        program_id=source.program_id,
        source_id=source.id,
        approved_snapshot_id=snapshot.id,
        approval_digest=snapshot.review_digest,
        effective_at=now,
        rules=rules,
    )
    repository.project_program_rule_program_summary(
        program_id=source.program_id,
        scope_status="in_scope",
        automation="limited",
    )
    return source, snapshot


@contextmanager
def program_rule_api(*, rules=None, approved=True):
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    testing_session = sessionmaker(bind=engine, expire_on_commit=False)
    with testing_session() as session:
        repository = DatabaseRepository(session)
        api_now = datetime.now(UTC)
        if approved:
            source, snapshot = seed_approved_source(
                repository,
                rules=rules or [],
                now=api_now,
            )
        else:
            source = repository.create_program_rule_source(
                program_alias="scope_gate_program",
                registered_url="https://rules.example.com/program",
                now=api_now,
            )
            snapshot = None
            repository.project_program_rule_program_summary(
                program_id=source.program_id,
                scope_status="in_scope",
                automation="limited",
            )

    def override_get_session():
        with testing_session() as session:
            yield session

    app.dependency_overrides[get_session] = override_get_session
    try:
        with TestClient(app) as client:
            yield client, testing_session, source, snapshot
    finally:
        app.dependency_overrides.pop(get_session, None)
        engine.dispose()


def add_pending_replacement(repository, source, approved_snapshot):
    changed_at = source.last_success_at or datetime.now(UTC)
    replacement = repository.save_program_rule_snapshot(
        source_id=source.id,
        raw_aggregate_sha256="d" * 64,
        normalized_sha256="f" * 64,
        fetched_at=changed_at + timedelta(hours=1),
        fetch_mode="static",
        content_types=["text/plain"],
        detected_language="en",
        extraction={"rules": []},
        evidence=[],
        linked_documents=[],
        openapi_candidates=[],
        ai_status="not_requested",
        review_status="pending",
        review_digest="1" * 64,
    )
    repository.set_program_rule_source_snapshot_pointers(
        source_id=source.id,
        approved_snapshot_id=approved_snapshot.id,
        pending_snapshot_id=replacement.id,
        updated_at=changed_at + timedelta(hours=1),
    )
    return replacement


def test_resolver_matches_asset_kinds_by_specificity_and_segment_boundaries():
    repository, session, engine = build_repository()
    try:
        source, snapshot = seed_approved_source(
            repository,
            rules=[
                scope_rule(
                    "*.example.com",
                    "wildcard_host",
                    allowed_validation=["wildcard_check"],
                ),
                scope_rule(
                    "api.example.com",
                    "exact_host",
                    allowed_validation=["exact_check"],
                ),
                scope_rule(
                    "https://api.example.com/v1",
                    "url_prefix",
                    allowed_validation=["url_check"],
                    rate_limit={"requests": 5, "period": 1, "unit": "minute"},
                ),
                scope_rule(
                    "https://root.example.com/",
                    "url_prefix",
                    allowed_validation=["root_url_check"],
                ),
                scope_rule(
                    "/internal",
                    "api_base_path",
                    allowed_validation=["path_check"],
                ),
                scope_rule("/api", "api_base_path"),
                scope_rule("/api/v2", "api_base_path"),
            ],
        )

        url_match = resolve_effective_program_rule(
            repository,
            source.program_id,
            "https://api.example.com/v1/users",
            NOW,
        )
        assert url_match.reason is None
        assert url_match.rule.allowed_validation == ["url_check"]
        assert url_match.provenance.canonical_asset == "https://api.example.com/v1"
        assert url_match.provenance.approved_snapshot_id == snapshot.id
        assert url_match.provenance.rate_limit["requests"] == 5

        exact_match = resolve_effective_program_rule(
            repository,
            source.program_id,
            "api.example.com",
            NOW,
        )
        assert exact_match.rule.allowed_validation == ["exact_check"]

        wildcard_match = resolve_effective_program_rule(
            repository,
            source.program_id,
            "files.example.com",
            NOW,
        )
        assert wildcard_match.rule.allowed_validation == ["wildcard_check"]

        root_url_match = resolve_effective_program_rule(
            repository,
            source.program_id,
            "https://root.example.com/any/path",
            NOW,
        )
        assert root_url_match.rule.allowed_validation == ["root_url_check"]

        wildcard_apex = resolve_effective_program_rule(
            repository,
            source.program_id,
            "example.com",
            NOW,
        )
        assert wildcard_apex.rule is None
        assert wildcard_apex.reason == "program_rule_asset_not_matched"

        invalid_host = resolve_effective_program_rule(
            repository,
            source.program_id,
            "bad..example.com",
            NOW,
        )
        assert invalid_host.rule is None
        assert invalid_host.reason == "program_rule_asset_not_matched"

        path_match = resolve_effective_program_rule(
            repository,
            source.program_id,
            "https://other.test/internal/users",
            NOW,
        )
        assert path_match.rule.allowed_validation == ["path_check"]

        segment_boundary = resolve_effective_program_rule(
            repository,
            source.program_id,
            "https://api.example.com/v10",
            NOW,
        )
        assert segment_boundary.rule.allowed_validation == ["exact_check"]

        for ambiguous_path in (
            "https://api.example.com/v1/../admin",
            "https://api.example.com/v1/%2e%2e/admin",
            "https://api.example.com/v1%2fadmin",
            "/internal/../admin",
        ):
            ambiguous = resolve_effective_program_rule(
                repository,
                source.program_id,
                ambiguous_path,
                NOW,
            )
            assert ambiguous.rule is None
            assert ambiguous.reason == "program_rule_asset_not_matched"

        conflict = resolve_effective_program_rule(
            repository,
            source.program_id,
            "https://other.test/api/v2/users",
            NOW,
        )
        assert conflict.rule is None
        assert conflict.reason == "program_rule_equal_specificity_conflict"
    finally:
        session.close()
        engine.dispose()


def test_resolver_fails_closed_for_unapproved_changed_rejected_and_stale_sources():
    repository, session, engine = build_repository()
    try:
        source = repository.create_program_rule_source(
            program_alias="unapproved_program",
            registered_url="https://rules.example.com/program",
            now=NOW,
        )
        repository.project_program_rule_program_summary(
            program_id=source.program_id,
            scope_status="in_scope",
            automation="limited",
        )
        unapproved = resolve_effective_program_rule(
            repository,
            source.program_id,
            "api.example.com",
            NOW,
        )
        assert unapproved.reason == "program_rule_approval_required"
    finally:
        session.close()
        engine.dispose()

    repository, session, engine = build_repository()
    try:
        source, approved = seed_approved_source(
            repository,
            rules=[
                scope_rule(
                    "api.example.com",
                    "exact_host",
                    allowed_validation=["two_account_authorization_check"],
                )
            ],
        )
        replacement = repository.save_program_rule_snapshot(
            source_id=source.id,
            raw_aggregate_sha256="d" * 64,
            normalized_sha256="f" * 64,
            fetched_at=NOW + timedelta(hours=1),
            fetch_mode="static",
            content_types=["text/plain"],
            detected_language="en",
            extraction={"rules": []},
            evidence=[],
            linked_documents=[],
            openapi_candidates=[],
            ai_status="not_requested",
            review_status="pending",
            review_digest="1" * 64,
        )
        repository.set_program_rule_source_snapshot_pointers(
            source_id=source.id,
            approved_snapshot_id=approved.id,
            pending_snapshot_id=replacement.id,
            updated_at=NOW + timedelta(hours=1),
        )
        changed = resolve_effective_program_rule(
            repository,
            source.program_id,
            "api.example.com",
            NOW + timedelta(hours=1),
        )
        assert changed.reason == "program_rule_change_requires_review"

        repository.update_program_rule_snapshot_review(
            source_id=source.id,
            snapshot_id=replacement.id,
            review_status="rejected",
            reviewer_alias="reviewer_1",
            reviewed_at=NOW + timedelta(hours=1),
        )
        rejected = resolve_effective_program_rule(
            repository,
            source.program_id,
            "api.example.com",
            NOW + timedelta(hours=2),
        )
        assert rejected.reason == "program_rule_change_requires_review"

        repository.set_program_rule_source_snapshot_pointers(
            source_id=source.id,
            approved_snapshot_id=approved.id,
            pending_snapshot_id=None,
            updated_at=NOW + timedelta(hours=2),
        )
        source = repository.get_program_rule_source(source.id)
        source.last_success_at = NOW - timedelta(hours=72)
        repository.session.add(source)
        repository.session.commit()
        stale = resolve_effective_program_rule(
            repository,
            source.program_id,
            "api.example.com",
            NOW,
        )
        assert stale.reason == "program_rule_source_stale"
    finally:
        session.close()
        engine.dispose()


def test_resolver_allows_recent_failure_but_rules_still_fail_closed():
    repository, session, engine = build_repository()
    try:
        source, _ = seed_approved_source(
            repository,
            rules=[
                scope_rule(
                    "api.example.com",
                    "exact_host",
                    allowed_validation=["two_account_authorization_check"],
                    prohibited=["DoS"],
                ),
                scope_rule(
                    "blocked.example.com",
                    "exact_host",
                    scope_status="out_of_scope",
                ),
                scope_rule(
                    "review.example.com",
                    "exact_host",
                    scope_status="needs_review",
                ),
                scope_rule(
                    "manual.example.com",
                    "exact_host",
                    automation="none",
                    allowed_validation=["two_account_authorization_check"],
                ),
            ],
        )
        source = repository.get_program_rule_source(source.id)
        source.fetch_status = "failed"
        source.failure_code = "fetch_failed"
        source.last_success_at = NOW - timedelta(hours=1)
        repository.session.add(source)
        repository.session.commit()

        recent = resolve_effective_program_rule(
            repository,
            source.program_id,
            "api.example.com",
            NOW,
        )
        assert recent.reason is None
        assert recent.provenance.warning == "last_refresh_failed"
        forbidden = evaluate_validation_request(
            recent.rule,
            ValidationRequest(
                asset="api.example.com",
                validation_type="DoS",
                human_approved=True,
            ),
        )
        assert forbidden.reason == "forbidden_validation"

        out_of_scope = resolve_effective_program_rule(
            repository,
            source.program_id,
            "blocked.example.com",
            NOW,
        )
        assert evaluate_validation_request(
            out_of_scope.rule,
            ValidationRequest(
                asset="blocked.example.com",
                validation_type="two_account_authorization_check",
                human_approved=True,
            ),
        ).reason == "out_of_scope"

        needs_review = resolve_effective_program_rule(
            repository,
            source.program_id,
            "review.example.com",
            NOW,
        )
        assert evaluate_validation_request(
            needs_review.rule,
            ValidationRequest(
                asset="review.example.com",
                validation_type="two_account_authorization_check",
                human_approved=True,
            ),
        ).allowed is False

        no_automation = resolve_effective_program_rule(
            repository,
            source.program_id,
            "manual.example.com",
            NOW,
        )
        assert evaluate_validation_request(
            no_automation.rule,
            ValidationRequest(
                asset="manual.example.com",
                validation_type="two_account_authorization_check",
                human_approved=True,
            ),
        ).reason == "automation_not_allowed"

        absent = resolve_effective_program_rule(
            repository,
            source.program_id,
            "absent.test",
            NOW,
        )
        assert absent.reason == "program_rule_asset_not_matched"
    finally:
        session.close()
        engine.dispose()


def test_rule_intersection_can_only_narrow_stored_campaign_authority():
    stored = ScopeGuardRule(
        asset="api.example.com",
        scope_status="in_scope",
        automation="limited",
        allowed_validation=["first", "shared"],
        forbidden=["social_engineering"],
        human_approval_required=False,
    )
    current = ScopeGuardRule(
        asset="api.example.com",
        scope_status="in_scope",
        automation="limited",
        allowed_validation=["shared", "current_only"],
        forbidden=["DoS"],
        human_approval_required=True,
    )

    intersected = intersect_scope_guard_rules(
        stored,
        current,
        asset="api.example.com",
    )

    assert intersected.allowed_validation == ["shared"]
    assert intersected.forbidden == ["DoS", "social_engineering"]
    assert intersected.human_approval_required is True
    assert intersected.scope_status == "in_scope"

    mismatched = intersect_scope_guard_rules(
        stored,
        current,
        asset="other.example.com",
    )
    assert mismatched.scope_status == "out_of_scope"
    assert mismatched.allowed_validation == []


def test_campaign_creation_intersects_current_rule_and_stores_provenance():
    rules = [
        scope_rule(
            "api.example.com",
            "exact_host",
            allowed_validation=["two_account_authorization_check"],
            prohibited=["DoS"],
            rate_limit={"requests": 5, "period": 1, "unit": "minute"},
        )
    ]
    with program_rule_api(rules=rules) as (
        client,
        testing_session,
        source,
        snapshot,
    ):
        response = client.post(
            "/mythos/campaigns",
            json={
                "program_id": source.program_id,
                "name": "Current rule intersection",
                "autonomy_level": "level_2_test_account_validation",
                "scope_status": "in_scope",
                "policy_text": (
                    "In scope: api.example.com. Automation is limited. "
                    "Allowed testing: two-account authorization checks and "
                    "non-destructive business logic tests."
                ),
                "default_asset": "api.example.com",
            },
        )

        assert response.status_code == 200
        with testing_session() as session:
            campaign = DatabaseRepository(session).get_campaign(response.json()["id"])
            stored = campaign.payload["scope_guard_rule"]
            assert stored["allowed_validation"] == [
                "two_account_authorization_check"
            ]
            assert stored["forbidden"] == ["DoS", "destructive_testing"]
            assert stored["human_approval_required"] is True
            assert campaign.payload["program_rule_provenance"] == {
                "source_id": source.id,
                "approved_snapshot_id": snapshot.id,
                "approval_digest": "c" * 64,
                "canonical_asset": "api.example.com",
                "asset_kind": "exact_host",
                "evidence_refs": ["e" * 64],
                "rate_limit": {"requests": 5, "period": 1, "unit": "minute"},
                "warning": None,
            }


def test_campaign_creation_and_approval_record_fail_closed_on_current_source():
    with program_rule_api(approved=False) as (client, _, source, _):
        campaign = client.post(
            "/mythos/campaigns",
            json={
                "program_id": source.program_id,
                "name": "Unapproved source",
                "autonomy_level": "level_0_read_only",
                "scope_status": "in_scope",
                "policy_text": "In scope: api.example.com. Automation is limited.",
                "default_asset": "api.example.com",
            },
        )
        assert campaign.status_code == 409
        assert campaign.json() == {"detail": "program_rule_approval_required"}

    with program_rule_api(
        rules=[
            scope_rule(
                "api.example.com",
                "exact_host",
                allowed_validation=["two_account_authorization_check"],
            )
        ]
    ) as (client, _, source, _):
        approval = client.post(
            "/mythos/approval-records",
            json={
                "program_id": source.program_id,
                "asset": "outside.example.com",
                "validation_mode": "two_account_authorization_check",
                "plan_digest": "plan_digest",
                "requester": "reviewer_1",
                "reason": "Must match current approved scope.",
            },
        )
        assert approval.status_code == 409
        assert approval.json() == {"detail": "program_rule_asset_not_matched"}

        missing_asset = client.post(
            "/mythos/approval-records",
            json={
                "program_id": source.program_id,
                "plan_digest": "plan_digest",
                "requester": "reviewer_1",
                "reason": "A source-backed approval must identify its asset.",
            },
        )
        assert missing_asset.status_code == 409
        assert missing_asset.json() == {"detail": "program_rule_asset_required"}


def test_existing_campaign_runtime_intersects_current_rule_and_freezes_without_rewrite():
    rules = [
        scope_rule(
            "api.example.com",
            "exact_host",
            allowed_validation=["two_account_authorization_check"],
            prohibited=["DoS"],
        )
    ]
    with program_rule_api(rules=rules) as (
        client,
        testing_session,
        source,
        snapshot,
    ):
        stored_rule = {
            "asset": "api.example.com",
            "scope_status": "in_scope",
            "automation": "limited",
            "allowed_validation": [
                "two_account_authorization_check",
                "non_destructive_business_logic_test",
            ],
            "forbidden": [],
            "human_approval_required": True,
        }
        with testing_session() as session:
            repository = DatabaseRepository(session)
            campaign = repository.create_campaign(
                program_id=source.program_id,
                name="Existing campaign",
                autonomy_level="level_2_test_account_validation",
                scope_status="in_scope",
                policy_text="legacy policy",
                default_asset="api.example.com",
                created_by="operator",
                payload={"scope_guard_rule": stored_rule},
            )
            campaign_id = campaign.id

        widened = client.post(
            "/scope-guard/evaluate",
            json={
                "campaign_id": campaign_id,
                "request": {
                    "asset": "api.example.com",
                    "validation_type": "non_destructive_business_logic_test",
                    "human_approved": True,
                    "plan_digest": "plan_digest",
                },
            },
        )
        assert widened.status_code == 200
        assert widened.json() == {
            "allowed": False,
            "reason": "validation_not_allowed",
        }

        prohibited = client.post(
            "/scope-guard/evaluate",
            json={
                "campaign_id": campaign_id,
                "request": {
                    "asset": "api.example.com",
                    "validation_type": "DoS",
                    "human_approved": True,
                    "plan_digest": "plan_digest",
                },
            },
        )
        assert prohibited.json() == {
            "allowed": False,
            "reason": "forbidden_validation",
        }

        with testing_session() as session:
            repository = DatabaseRepository(session)
            add_pending_replacement(repository, source, snapshot)
        frozen = client.post(
            "/scope-guard/evaluate",
            json={
                "campaign_id": campaign_id,
                "request": {
                    "asset": "api.example.com",
                    "validation_type": "two_account_authorization_check",
                    "human_approved": True,
                    "plan_digest": "plan_digest",
                },
            },
        )
        assert frozen.json() == {
            "allowed": False,
            "reason": "program_rule_change_requires_review",
        }
        with testing_session() as session:
            campaign = DatabaseRepository(session).get_campaign(campaign_id)
            assert campaign.payload["scope_guard_rule"] == stored_rule


def test_validation_runtime_and_preflight_recheck_current_source():
    rules = [
        scope_rule(
            "api.example.com",
            "exact_host",
            allowed_validation=["two_account_authorization_check"],
        )
    ]
    with program_rule_api(rules=rules) as (
        client,
        testing_session,
        source,
        snapshot,
    ):
        with testing_session() as session:
            repository = DatabaseRepository(session)
            campaign = repository.create_campaign(
                program_id=source.program_id,
                name="Runtime source gate",
                autonomy_level="level_2_test_account_validation",
                scope_status="in_scope",
                policy_text="legacy policy",
                default_asset="api.example.com",
                created_by="operator",
                payload={
                    "scope_guard_rule": {
                        "asset": "api.example.com",
                        "scope_status": "in_scope",
                        "automation": "limited",
                        "allowed_validation": [
                            "two_account_authorization_check"
                        ],
                        "forbidden": [],
                        "human_approval_required": True,
                    }
                },
            )
            task = repository.create_campaign_task(
                campaign_id=campaign.id,
                task_type="report_chain_review",
                agent_type="report_agent",
                title="Review validation gate",
                input_refs=[f"campaign:{campaign.id}"],
            )
            approval = repository.create_approval_record(
                campaign_id=campaign.id,
                task_id=task.id,
                program_id=source.program_id,
                approval_type="validation_batch",
                actor="operator",
                reason="Approve scoped validation.",
                requested_action="two_account_authorization_check",
                asset="api.example.com",
                validation_mode="two_account_authorization_check",
                plan_digest="plan_digest_preflight",
                autonomy_level=campaign.autonomy_level,
                safety_gate_state="awaiting_approval",
            )
            validation = repository.save_validation_run(
                campaign_id=campaign.id,
                task_id=task.id,
                approval_id=approval.id,
                validation_mode="two_account_authorization_check",
                target_ref=f"campaign:{campaign.id}",
                status="planned",
                safety_gate_state="awaiting_approval",
                plan_digest="plan_digest_preflight",
                approval_required=True,
                allowed_to_execute=False,
                evidence_ref_count=0,
                summary="Awaiting approval.",
                payload={},
            )
            repository.decide_approval_record(
                approval_id=approval.id,
                decision="approved",
                actor="reviewer_1",
                reason="Approved for test accounts only.",
            )
            repository.record_validation_run_preflight(
                validation.id,
                allowed=True,
                reason="approved_validation_record",
            )
            validation_id = validation.id

        active = client.get(
            f"/mythos/campaigns/{campaign.id}/validation-runs"
        )
        assert active.status_code == 200
        assert active.json()[0]["allowed_to_execute"] is True

        with testing_session() as session:
            repository = DatabaseRepository(session)
            add_pending_replacement(repository, source, snapshot)

        frozen_runtime = client.get(
            f"/mythos/campaigns/{campaign.id}/validation-runs"
        )
        assert frozen_runtime.status_code == 200
        assert frozen_runtime.json()[0]["allowed_to_execute"] is False

        preflight = client.post(
            f"/mythos/validation-runs/{validation_id}/preflight"
        )
        assert preflight.status_code == 200
        assert preflight.json()["decision"] == {
            "allowed": False,
            "reason": "program_rule_change_requires_review",
        }
