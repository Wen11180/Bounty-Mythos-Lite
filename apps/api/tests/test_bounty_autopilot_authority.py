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
    AuthorizationBudget,
    CampaignAuthorizationCreate,
    PolicyMode,
    RecipeRef,
    RiskTier,
)
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


def _auth_create(campaign_id: str = "campaign_placeholder") -> CampaignAuthorizationCreate:
    return CampaignAuthorizationCreate(
        campaign_id=campaign_id,
        scope_snapshot_id="scope_snap_1",
        scope_snapshot_digest=_digest("scope"),
        policy_digest=_digest("policy"),
        asset_ids=("asset_loopback_api",),
        account_aliases=("account_a", "account_b"),
        recipe_refs=(
            RecipeRef(recipe_id="passive_rule_snapshot_analysis", version="1.0"),
            RecipeRef(recipe_id="lab_browser_mapping", version="1.0"),
        ),
        risk_ceiling=RiskTier.R2,
        active_hours_utc=tuple(range(24)),
        budget=AuthorizationBudget(
            max_requests=20,
            max_concurrent_requests=1,
            max_response_bytes=100_000,
            max_duration_seconds=1800,
            max_accounts=2,
            max_cost_units=20,
        ),
        expires_at=datetime.now(UTC) + timedelta(hours=6),
        operator_id="operator_alice",
        policy_mode=PolicyMode.AUTHORIZED_LOCAL_LAB,
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
        policy_text = (
            "Asset: asset_loopback_api\n"
            "Scope: in_scope\n"
            "Automation: limited\n"
            "Allowed: local_code_review\n"
        )
        auth_payload = {
            **_auth_create().model_dump(mode="json"),
            "policy_digest": _digest(policy_text),
        }
        # campaign_id is rewritten by server
        auth_payload.pop("campaign_id", None)
        response = client.post(
            "/mythos/campaigns",
            json={
                "program_id": program_id,
                "name": "Autopilot Lab",
                "autonomy_level": "level_0_read_only",
                "scope_status": "in_scope",
                "policy_text": policy_text,
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
            authorization_payload=first.model_dump(mode="json"),
        )
        second_create = _auth_create(campaign.id)
        # change budget to force new digest
        second_create = CampaignAuthorizationCreate(
            **{
                **second_create.model_dump(mode="json"),
                "budget": AuthorizationBudget(
                    max_requests=10,
                    max_concurrent_requests=1,
                    max_response_bytes=50_000,
                    max_duration_seconds=900,
                    max_accounts=2,
                    max_cost_units=10,
                ).model_dump(mode="json"),
            }
        )
        second = build_campaign_authorization(second_create)
        second_row = repository.create_campaign_authorization(
            campaign_id=campaign.id,
            authorization_payload=second.model_dump(mode="json"),
        )
        rows = repository.list_campaign_authorizations(campaign.id)
        assert len(rows) == 2
        refreshed_first = repository.session.get(type(first_row), first_row.id)
        assert refreshed_first is not None
        assert refreshed_first.is_current is False
        assert refreshed_first.revoked_at is not None
        assert second_row.is_current is True
        assert second_row.generation == 2
        assert first_row.payload["budget"]["max_requests"] == 20


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
                authorization_payload=auth.model_dump(mode="json"),
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
            expired = CampaignAuthorizationCreate(
                **{
                    **_auth_create(campaign_id).model_dump(mode="json"),
                    "expires_at": (datetime.now(UTC) - timedelta(minutes=1)).isoformat(),
                }
            )
            built = build_campaign_authorization(expired)
            repository.create_campaign_authorization(
                campaign_id=campaign_id,
                authorization_payload=built.model_dump(mode="json"),
            )
        response = client.post(f"/mythos/campaigns/{campaign_id}/start")
        assert response.status_code == 409
        assert response.json()["detail"] == "authorization_expired"
    finally:
        app.dependency_overrides.clear()


def test_start_and_resume_require_current_policy_digest():
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
                name="stale-policy-auth",
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
            authorization = build_campaign_authorization(_auth_create(campaign_id))
            repository.create_campaign_authorization(
                campaign_id=campaign_id,
                authorization_payload=authorization.model_dump(mode="json"),
            )
            campaign.policy_text_hash = _digest("different-policy").removeprefix(
                "sha256:"
            )
            session.commit()

        for action in ("start", "resume"):
            response = client.post(f"/mythos/campaigns/{campaign_id}/{action}")
            assert response.status_code == 409
            assert response.json()["detail"] == "authorization_policy_stale"
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
