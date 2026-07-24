from __future__ import annotations

from datetime import UTC, datetime, timedelta
from hashlib import sha256
from types import SimpleNamespace

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.db import Base, get_session
from app.main import app
from app.repository import DatabaseRepository, seed_sample_data
from app.autonomous_research_wakeup import build_autonomous_research_wakeup_health


client = TestClient(app)


def _testing_session():
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    factory = sessionmaker(bind=engine)
    with factory() as session:
        seed_sample_data(session)
    return factory


def test_wakeup_health_reports_liveness_without_leaking_lease_material():
    testing_session = _testing_session()

    def override_get_session():
        with testing_session() as session:
            yield session

    app.dependency_overrides[get_session] = override_get_session
    try:
        not_started = client.get("/mythos/campaigns/autonomous-wakeup-health")

        assert not_started.status_code == 200
        assert not_started.json() == {
            "status": "not_started",
            "last_heartbeat_at": None,
            "heartbeat_age_seconds": None,
            "lease_active": False,
            "lease_expires_at": None,
            "has_more_campaigns": False,
            "scheduled_interval_seconds": 60,
            "last_cycle_completed_at": None,
            "last_cycle_status": "not_finished",
            "last_cycle_stop_reason": None,
            "last_cycle_processed_count": 0,
            "last_cycle_outcome_counts": {},
            "execution_allowed": False,
            "dispatch_allowed": False,
            "validation_allowed": False,
            "candidate_promotion_allowed": False,
            "report_submission_allowed": False,
        }

        lease_digest = sha256(b"wakeup-health-test").hexdigest()
        with testing_session() as session:
            repository = DatabaseRepository(session)
            assert repository.claim_autonomous_research_wakeup(
                claim_token_digest=lease_digest,
                now=datetime.now(UTC),
            ) is not None

        active = client.get("/mythos/campaigns/autonomous-wakeup-health")

        assert active.status_code == 200
        assert set(active.json()) == set(not_started.json())
        assert active.json()["status"] == "active"
        assert active.json()["last_heartbeat_at"] is not None
        assert active.json()["lease_active"] is True
        assert active.json()["lease_expires_at"] is not None
        assert active.json()["heartbeat_age_seconds"] is not None
        assert lease_digest not in active.text
    finally:
        app.dependency_overrides.clear()


def test_wakeup_health_marks_expired_leases_and_stale_heartbeats():
    testing_session = _testing_session()

    def override_get_session():
        with testing_session() as session:
            yield session

    app.dependency_overrides[get_session] = override_get_session
    try:
        lease_digest = sha256(b"expired-wakeup-health-test").hexdigest()
        now = datetime.now(UTC)
        with testing_session() as session:
            repository = DatabaseRepository(session)
            assert repository.claim_autonomous_research_wakeup(
                claim_token_digest=lease_digest,
                now=now,
            ) is not None
            state = repository.get_autonomous_research_wakeup_state()
            assert state is not None
            state.lease_started_at = now - timedelta(seconds=2)
            state.lease_expires_at = now - timedelta(seconds=1)
            session.commit()

        expired = client.get("/mythos/campaigns/autonomous-wakeup-health")

        assert expired.status_code == 200
        assert expired.json()["status"] == "expired_lease"
        assert expired.json()["lease_active"] is False
        assert lease_digest not in expired.text

        with testing_session() as session:
            repository = DatabaseRepository(session)
            state = repository.get_autonomous_research_wakeup_state()
            assert state is not None
            state.lease_token_digest = None
            state.lease_started_at = None
            state.lease_expires_at = None
            state.updated_at = now - timedelta(seconds=181)
            session.commit()

        stale = client.get("/mythos/campaigns/autonomous-wakeup-health")

        assert stale.status_code == 200
        assert stale.json()["status"] == "stale"
        assert stale.json()["lease_active"] is False
    finally:
        app.dependency_overrides.clear()


def test_wakeup_health_exposes_a_safe_persisted_cycle_summary():
    testing_session = _testing_session()

    def override_get_session():
        with testing_session() as session:
            yield session

    app.dependency_overrides[get_session] = override_get_session
    try:
        now = datetime.now(UTC)
        lease_digest = sha256(b"safe-cycle-summary").hexdigest()
        with testing_session() as session:
            repository = DatabaseRepository(session)
            assert repository.claim_autonomous_research_wakeup(
                claim_token_digest=lease_digest,
                now=now,
            ) is not None
            assert repository.finish_autonomous_research_wakeup(
                claim_token_digest=lease_digest,
                after_campaign_id=None,
                now=now,
                last_cycle_status="failed",
                last_cycle_stop_reason="wakeup_candidate_query_failed",
                last_cycle_processed_count=0,
                last_cycle_outcome_counts={},
            )

        response = client.get("/mythos/campaigns/autonomous-wakeup-health")

        assert response.status_code == 200
        assert response.json()["status"] == "degraded"
        assert response.json()["last_cycle_status"] == "failed"
        assert response.json()["last_cycle_stop_reason"] == (
            "wakeup_candidate_query_failed"
        )
        assert response.json()["last_cycle_processed_count"] == 0
        assert response.json()["last_cycle_outcome_counts"] == {}
        assert lease_digest not in response.text
    finally:
        app.dependency_overrides.clear()


def test_wakeup_health_marks_invalid_lease_state_and_future_heartbeat_unhealthy():
    now = datetime(2026, 7, 22, tzinfo=UTC)

    invalid_lease = build_autonomous_research_wakeup_health(
        SimpleNamespace(
            updated_at=now,
            lease_token_digest="not-a-sha256-digest",
            lease_started_at=now,
            lease_expires_at=now + timedelta(seconds=60),
            after_campaign_id=None,
        ),
        now=now,
    )
    future_heartbeat = build_autonomous_research_wakeup_health(
        SimpleNamespace(
            updated_at=now + timedelta(seconds=1),
            lease_token_digest=None,
            lease_started_at=None,
            lease_expires_at=None,
            after_campaign_id=None,
        ),
        now=now,
    )

    assert invalid_lease["status"] == "invalid_lease"
    assert invalid_lease["lease_active"] is False
    assert "not-a-sha256-digest" not in str(invalid_lease)
    assert future_heartbeat["status"] == "stale"
    assert future_heartbeat["heartbeat_age_seconds"] is None


def test_wakeup_health_endpoint_does_not_repair_invalid_lease_state():
    testing_session = _testing_session()

    def override_get_session():
        with testing_session() as session:
            yield session

    app.dependency_overrides[get_session] = override_get_session
    try:
        now = datetime.now(UTC)
        with testing_session() as session:
            repository = DatabaseRepository(session)
            state = repository.get_autonomous_research_wakeup_state()
            if state is None:
                assert repository.claim_autonomous_research_wakeup(
                    claim_token_digest=sha256(b"invalid-health-state").hexdigest(),
                    now=now,
                ) is not None
                state = repository.get_autonomous_research_wakeup_state()
            assert state is not None
            state.lease_token_digest = "invalid-health-state"
            state.lease_started_at = now
            state.lease_expires_at = now + timedelta(seconds=60)
            state.updated_at = now
            session.commit()
            before = (
                state.lease_token_digest,
                state.lease_started_at,
                state.lease_expires_at,
                state.updated_at,
            )

        response = client.get("/mythos/campaigns/autonomous-wakeup-health")

        with testing_session() as session:
            state = DatabaseRepository(session).get_autonomous_research_wakeup_state()
            assert state is not None
            after = (
                state.lease_token_digest,
                state.lease_started_at,
                state.lease_expires_at,
                state.updated_at,
            )

        assert response.status_code == 200
        assert response.json()["status"] == "invalid_lease"
        assert response.json()["lease_active"] is False
        assert "invalid-health-state" not in response.text
        assert after == before
    finally:
        app.dependency_overrides.clear()
