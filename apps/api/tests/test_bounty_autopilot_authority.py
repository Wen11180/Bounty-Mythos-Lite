"""Phase 2 durable authorization and Autopilot campaign lifecycle tests."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from hashlib import sha256

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.bounty_autopilot.authority import (
    authorization_from_payload,
    build_campaign_authorization,
)
from app.bounty_autopilot.contracts import (
    ActiveHoursWindow,
    AutopilotBudgets,
    CampaignAuthorization,
    PolicyMode,
    RiskTier,
    campaign_authorization_payload,
)
from app.bounty_autopilot.recipes import default_recipe_registry
from app.db import Base, get_session
from app.main import app
from app.repository import DatabaseRepository, seed_sample_data


client = TestClient(app)


def _digest(seed: str) -> str:
    return f"sha256:{sha256(seed.encode('utf-8')).hexdigest()}"


def build_testing_session():
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    testing_session = sessionmaker(bind=engine)
    with testing_session() as session:
        seed_sample_data(session)
    return testing_session


def _auth_create(
    campaign_id: str = "campaign_placeholder",
    *,
    issued_at: datetime | None = None,
    expires_at: datetime | None = None,
    budgets: AutopilotBudgets | None = None,
) -> CampaignAuthorization:
    now = datetime.now(UTC)
    registry = default_recipe_registry()
    return CampaignAuthorization(
        campaign_id=campaign_id,
        scope_snapshot_id="scope_snap_1",
        scope_review_state="approved",
        scope_snapshot_digest=_digest("scope"),
        policy_digest=_digest("policy"),
        asset_ids=("asset_loopback_api",),
        account_aliases=("account_a", "account_b"),
        recipe_refs=(
            registry.require("passive_rule_snapshot_analysis", "1.0.0").ref,
            registry.require("lab_browser_mapping", "1.0.0").ref,
        ),
        max_automatic_risk=RiskTier.R2,
        policy_mode=PolicyMode.AUTHORIZED_LOCAL_LAB,
        network_profile="authorized_local_lab",
        allowed_method_classes=("passive", "read_only"),
        active_hours_utc=(
            ActiveHoursWindow(
                days_utc=(0, 1, 2, 3, 4, 5, 6),
                start_minute_utc=0,
                end_minute_utc=1440,
            ),
        ),
        budgets=budgets
        or AutopilotBudgets(
            max_requests=20,
            max_concurrency=1,
            max_response_bytes=100_000,
            max_duration_seconds=300,
            max_account_operations=2,
            max_cost_microusd=20_000,
        ),
        issued_at=issued_at or now,
        expires_at=expires_at or now + timedelta(hours=6),
        operator_identity="operator_alice",
    )


def test_create_autopilot_campaign_writes_immutable_authorization():
    testing_session = build_testing_session()

    def override_get_session():
        with testing_session() as session:
            yield session

    app.dependency_overrides[get_session] = override_get_session
    try:
        with testing_session() as session:
            program_id = DatabaseRepository(session).list_programs()[0].id
        auth_payload = campaign_authorization_payload(_auth_create())
        # campaign_id is rewritten by server
        auth_payload.pop("campaign_id", None)
        response = client.post(
            "/mythos/campaigns",
            json={
                "program_id": program_id,
                "name": "Autopilot Lab",
                "autonomy_level": "level_0_read_only",
                "scope_status": "in_scope",
                "policy_text": (
                    "Asset: asset_loopback_api\n"
                    "Scope: in_scope\n"
                    "Automation: limited\n"
                    "Allowed: local_code_review\n"
                ),
                "default_asset": "asset_loopback_api",
                "created_by": "operator_alice",
                "campaign_mode": "bounty_autopilot",
                "autopilot_authorization": auth_payload,
            },
        )
        assert response.status_code == 200, response.text
        body = response.json()
        assert body["campaign_mode"] == "bounty_autopilot"
        assert body["current_authorization_digest"]
        with testing_session() as session:
            repository = DatabaseRepository(session)
            auth = repository.get_current_campaign_authorization(body["id"])
            assert auth is not None
            assert auth.is_current is True
            typed = authorization_from_payload(auth.payload)
            assert typed.authorization_digest == auth.authorization_digest
            assert typed.campaign_id == body["id"]
    finally:
        app.dependency_overrides.clear()


def test_authorization_cannot_be_edited_in_place_creates_successor():
    testing_session = build_testing_session()
    with testing_session() as session:
        repository = DatabaseRepository(session)
        program = repository.list_programs()[0]
        campaign = repository.create_campaign(
            program_id=program.id,
            name="auth-succession",
            autonomy_level="level_0_read_only",
            scope_status="in_scope",
            policy_text="policy",
            default_asset="asset_loopback_api",
            created_by="operator_alice",
            campaign_mode="bounty_autopilot",
            payload={"scope_guard_rule": {
                "asset": "asset_loopback_api",
                "scope_status": "in_scope",
                "automation": "limited",
                "allowed_validation": ["local_code_review"],
                "forbidden": [],
                "human_approval_required": False,
            }},
        )
        first = build_campaign_authorization(_auth_create(campaign.id))
        first_row = repository.create_campaign_authorization(
            campaign_id=campaign.id,
            authorization_payload=campaign_authorization_payload(first),
        )
        second_create = _auth_create(
            campaign.id,
            budgets=AutopilotBudgets(
                max_requests=10,
                max_concurrency=1,
                max_response_bytes=50_000,
                max_duration_seconds=300,
                max_account_operations=2,
                max_cost_microusd=10_000,
            ),
        )
        second = build_campaign_authorization(second_create)
        second_row = repository.create_campaign_authorization(
            campaign_id=campaign.id,
            authorization_payload=campaign_authorization_payload(second),
        )
        rows = repository.list_campaign_authorizations(campaign.id)
        assert len(rows) == 2
        refreshed_first = repository.session.get(type(first_row), first_row.id)
        assert refreshed_first is not None
        assert refreshed_first.is_current is False
        assert refreshed_first.revoked_at is not None
        assert second_row.is_current is True
        assert second_row.generation == 2
        assert first_row.payload["budgets"]["max_requests"] == 20


def test_start_autopilot_uses_autonomous_runtime_only(monkeypatch):
    testing_session = build_testing_session()
    calls: list[str] = []

    def fake_tick_campaign(*_args, **_kwargs):
        calls.append("legacy")
        return {"status": "ok"}

    def fake_tick_auto(*_args, **_kwargs):
        calls.append("auto")
        return {"status": "ok"}

    monkeypatch.setattr("app.main.tick_campaign", fake_tick_campaign)
    monkeypatch.setattr("app.main.tick_autonomous_research_campaign", fake_tick_auto)

    def override_get_session():
        with testing_session() as session:
            yield session

    app.dependency_overrides[get_session] = override_get_session
    try:
        with testing_session() as session:
            repository = DatabaseRepository(session)
            program = repository.list_programs()[0]
            campaign = repository.create_campaign(
                program_id=program.id,
                name="auto-start",
                autonomy_level="level_0_read_only",
                scope_status="in_scope",
                policy_text="policy",
                default_asset="asset_loopback_api",
                created_by="operator_alice",
                campaign_mode="bounty_autopilot",
                payload={
                    "scope_guard_rule": {
                        "asset": "asset_loopback_api",
                        "scope_status": "in_scope",
                        "automation": "limited",
                        "allowed_validation": ["local_code_review"],
                        "forbidden": [],
                        "human_approval_required": False,
                    }
                },
            )
            auth = build_campaign_authorization(_auth_create(campaign.id))
            repository.create_campaign_authorization(
                campaign_id=campaign.id,
                authorization_payload=campaign_authorization_payload(auth),
            )
            campaign_id = campaign.id

        response = client.post(f"/mythos/campaigns/{campaign_id}/start")
        assert response.status_code == 200, response.text
        assert calls == ["auto"]
        with testing_session() as session:
            campaign = DatabaseRepository(session).get_campaign(campaign_id)
            assert campaign is not None
            assert campaign.status == "running"
            assert isinstance(campaign.payload, dict)
            assert str(campaign.payload.get("source_snapshot_digest", "")).startswith(
                "sha256:"
            )
    finally:
        app.dependency_overrides.clear()


def test_start_legacy_still_uses_tick_campaign(monkeypatch):
    testing_session = build_testing_session()
    calls: list[str] = []

    def fake_tick_campaign(*_args, **_kwargs):
        calls.append("legacy")
        return {"status": "ok"}

    def fake_tick_auto(*_args, **_kwargs):
        calls.append("auto")
        return {"status": "ok"}

    monkeypatch.setattr("app.main.tick_campaign", fake_tick_campaign)
    monkeypatch.setattr("app.main.tick_autonomous_research_campaign", fake_tick_auto)

    def override_get_session():
        with testing_session() as session:
            yield session

    app.dependency_overrides[get_session] = override_get_session
    try:
        with testing_session() as session:
            repository = DatabaseRepository(session)
            program = repository.list_programs()[0]
            campaign = repository.create_campaign(
                program_id=program.id,
                name="legacy-start",
                autonomy_level="level_0_read_only",
                scope_status="in_scope",
                policy_text="policy",
                default_asset="asset_loopback_api",
                created_by="operator",
                campaign_mode="legacy",
                payload={
                    "scope_guard_rule": {
                        "asset": "asset_loopback_api",
                        "scope_status": "in_scope",
                        "automation": "limited",
                        "allowed_validation": ["local_code_review"],
                        "forbidden": [],
                        "human_approval_required": False,
                    }
                },
            )
            campaign_id = campaign.id
        response = client.post(f"/mythos/campaigns/{campaign_id}/start")
        assert response.status_code == 200, response.text
        assert calls == ["legacy"]
    finally:
        app.dependency_overrides.clear()


def test_start_refuses_missing_or_expired_authorization():
    testing_session = build_testing_session()

    def override_get_session():
        with testing_session() as session:
            yield session

    app.dependency_overrides[get_session] = override_get_session
    try:
        with testing_session() as session:
            repository = DatabaseRepository(session)
            program = repository.list_programs()[0]
            campaign = repository.create_campaign(
                program_id=program.id,
                name="missing-auth",
                autonomy_level="level_0_read_only",
                scope_status="in_scope",
                policy_text="policy",
                default_asset="asset_loopback_api",
                created_by="operator",
                campaign_mode="bounty_autopilot",
                payload={
                    "scope_guard_rule": {
                        "asset": "asset_loopback_api",
                        "scope_status": "in_scope",
                        "automation": "limited",
                        "allowed_validation": ["local_code_review"],
                        "forbidden": [],
                        "human_approval_required": False,
                    }
                },
            )
            campaign_id = campaign.id
        response = client.post(f"/mythos/campaigns/{campaign_id}/start")
        assert response.status_code == 409
        assert response.json()["detail"] == "authorization_missing"

        with testing_session() as session:
            repository = DatabaseRepository(session)
            now = datetime.now(UTC)
            expired = _auth_create(
                campaign_id,
                issued_at=now - timedelta(hours=2),
                expires_at=now - timedelta(minutes=1),
            )
            built = build_campaign_authorization(expired)
            repository.create_campaign_authorization(
                campaign_id=campaign_id,
                authorization_payload=campaign_authorization_payload(built),
            )
        response = client.post(f"/mythos/campaigns/{campaign_id}/start")
        assert response.status_code == 409
        assert response.json()["detail"] == "authorization_expired"
    finally:
        app.dependency_overrides.clear()


def test_authority_not_derived_from_autonomy_level_alone():
    testing_session = build_testing_session()
    with testing_session() as session:
        repository = DatabaseRepository(session)
        program = repository.list_programs()[0]
        campaign = repository.create_campaign(
            program_id=program.id,
            name="no-trust-autonomy",
            autonomy_level="level_1_local_validation",
            scope_status="in_scope",
            policy_text="policy",
            default_asset="asset_loopback_api",
            created_by="operator",
            campaign_mode="bounty_autopilot",
            payload={},
        )
        assert campaign.autonomy_level == "level_1_local_validation"
        assert repository.get_current_campaign_authorization(campaign.id) is None


def test_start_rejects_authorization_record_digest_drift(monkeypatch):
    testing_session = build_testing_session()
    monkeypatch.setattr(
        "app.main.tick_autonomous_research_campaign",
        lambda *_args, **_kwargs: {"status": "ok"},
    )

    def override_get_session():
        with testing_session() as session:
            yield session

    app.dependency_overrides[get_session] = override_get_session
    try:
        with testing_session() as session:
            repository = DatabaseRepository(session)
            program = repository.list_programs()[0]
            campaign = repository.create_campaign(
                program_id=program.id,
                name="digest-drift",
                autonomy_level="level_0_read_only",
                scope_status="in_scope",
                policy_text="policy",
                default_asset="asset_loopback_api",
                created_by="operator_alice",
                campaign_mode="bounty_autopilot",
                payload={
                    "scope_guard_rule": {
                        "asset": "asset_loopback_api",
                        "scope_status": "in_scope",
                        "automation": "limited",
                        "allowed_validation": ["local_code_review"],
                        "forbidden": [],
                        "human_approval_required": False,
                    }
                },
            )
            authorization = build_campaign_authorization(_auth_create(campaign.id))
            row = repository.create_campaign_authorization(
                campaign_id=campaign.id,
                authorization_payload=campaign_authorization_payload(authorization),
            )
            row.authorization_digest = _digest("tampered-record-column")
            repository.session.commit()
            campaign_id = campaign.id

        response = client.post(f"/mythos/campaigns/{campaign_id}/start")

        assert response.status_code == 409
        assert response.json()["detail"] == "authorization_digest_invalid"
    finally:
        app.dependency_overrides.clear()
