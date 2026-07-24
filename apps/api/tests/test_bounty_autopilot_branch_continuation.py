"""Durable, branch-bound plan-materialization continuation tests."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from hashlib import sha256

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.autonomous_research_runtime import (
    select_autonomous_research_work,
    tick_autonomous_research_campaign,
)
from app.bounty_autopilot.asset_admission import (
    AssetProvenance,
    ScopeMatcher,
    decide_admission,
    parse_asset_url,
)
from app.bounty_autopilot.branches import BranchStatus, ResearchBranch
from app.bounty_autopilot.contracts import (
    ActiveHoursWindow,
    AutopilotBudgets,
    CampaignAuthorization,
    PolicyMode,
    RiskTier,
    campaign_authorization_payload,
)
from app.bounty_autopilot.recipes import default_recipe_registry
from app.db import Base
from app.repository import DatabaseRepository, seed_sample_data
from app.worker.tasks import run_agent_task


def _digest(seed: str) -> str:
    return "sha256:" + sha256(seed.encode("utf-8")).hexdigest()


def _repository() -> tuple[DatabaseRepository, object]:
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    session = sessionmaker(bind=engine)()
    seed_sample_data(session)
    return DatabaseRepository(session), session


def _branch_ready_campaign(repository: DatabaseRepository):
    scope_digest = _digest("scope")
    source_digest = _digest("source")
    identity = parse_asset_url(
        "https://lab.local/api", provenance=AssetProvenance.SEED
    )
    admission = decide_admission(
        identity,
        ScopeMatcher(
            include_hosts=("lab.local",),
            include_path_prefixes=("/api",),
            scope_snapshot_digest=scope_digest,
        ),
    )
    program = repository.list_programs()[0]
    campaign = repository.create_campaign(
        program_id=program.id,
        name="branch-continuation",
        autonomy_level="level_0_read_only",
        scope_status="in_scope",
        policy_text="policy",
        default_asset=admission.asset_id,
        created_by="operator_alice",
        campaign_mode="bounty_autopilot",
        payload={
            "source_snapshot_digest": source_digest,
            "scope_snapshot_digest": scope_digest,
            "scope_guard_rule": {
                "asset": admission.asset_id,
                "scope_status": "in_scope",
                "automation": "limited",
                "allowed_validation": ["local_code_review"],
                "forbidden": [],
                "human_approval_required": False,
            },
        },
    )
    repository.update_campaign_status(campaign.id, "running")
    campaign = repository.get_campaign(campaign.id)
    assert campaign is not None

    recipe = default_recipe_registry().require("passive_rule_snapshot_analysis", "1.0.0")
    authorization = CampaignAuthorization(
        campaign_id=campaign.id,
        scope_snapshot_id="scope_snapshot_1",
        scope_review_state="approved",
        scope_snapshot_digest=scope_digest,
        policy_digest=_digest("policy"),
        asset_ids=(admission.asset_id,),
        account_aliases=("account_a", "account_b"),
        recipe_refs=(recipe.ref,),
        max_automatic_risk=RiskTier.R0,
        policy_mode=PolicyMode.PASSIVE_ONLY,
        network_profile="none",
        allowed_method_classes=("passive",),
        active_hours_utc=(
            ActiveHoursWindow(days_utc=(0, 1, 2, 3, 4, 5, 6), start_minute_utc=0, end_minute_utc=1440),
        ),
        budgets=AutopilotBudgets(
            max_requests=10,
            max_concurrency=1,
            max_response_bytes=1024,
            max_duration_seconds=30,
            max_account_operations=1,
            max_cost_microusd=1000,
        ),
        issued_at=datetime.now(UTC),
        expires_at=datetime.now(UTC) + timedelta(hours=1),
        operator_identity="operator_alice",
    )
    repository.create_campaign_authorization(
        campaign_id=campaign.id,
        authorization_payload=campaign_authorization_payload(authorization),
    )
    repository.upsert_campaign_asset_admission(
        campaign_id=campaign.id,
        admission=admission.model_dump(mode="json"),
    )
    repository.create_research_branch(
        campaign_id=campaign.id,
        branch=ResearchBranch(
            branch_id="branch_ready",
            campaign_id=campaign.id,
            asset_id=admission.asset_id,
            status=BranchStatus.QUEUED,
            priority=50,
            recipe_ref=recipe.ref,
            risk_tier=RiskTier.R0,
        ).model_dump(mode="json"),
    )
    handoff = repository.create_campaign_task(
        campaign_id=campaign.id,
        task_type="validation_handoff",
        agent_type="human_review",
        title="Existing validation review",
        payload={"raw_payload_processed": False},
    )
    repository.update_campaign_task_status(handoff.id, "awaiting_approval")
    return campaign, authorization, recipe


def test_selected_branch_creates_one_bound_awaiting_plan_handoff_without_execution():
    repository, session = _repository()
    try:
        campaign, authorization, recipe = _branch_ready_campaign(repository)

        selection = select_autonomous_research_work(
            campaign=campaign,
            repository=repository,
        )

        assert selection["task_type"] == "autopilot_branch_continuation"
        assert selection["agent_type"] == "branch_plan_agent"
        assert selection["branch_id"] == "branch_ready"
        assert selection["authorization_digest"] == authorization.authorization_digest
        assert selection["scope_snapshot_digest"] == authorization.scope_snapshot_digest
        assert selection["asset_id"]
        assert selection["recipe_ref"] == recipe.ref.model_dump(mode="json")

        dispatched: list[str] = []
        tick = tick_autonomous_research_campaign(
            campaign.id,
            repository=repository,
            dispatcher=lambda *, campaign_task_id: dispatched.append(campaign_task_id),
        )

        assert tick["status"] == "dispatched"
        assert len(dispatched) == 1
        task = next(
            item
            for item in repository.list_campaign_tasks(campaign.id)
            if item.task_type == "autopilot_branch_continuation"
        )
        assert task.payload["branch_id"] == "branch_ready"
        assert task.payload["authorization_digest"] == authorization.authorization_digest
        assert task.payload["scope_snapshot_digest"] == authorization.scope_snapshot_digest
        assert task.payload["recipe_ref"] == recipe.ref.model_dump(mode="json")

        completed = run_agent_task(task.id, repository=repository)

        assert completed["status"] == "completed"
        branch = next(
            item
            for item in repository.list_research_branches(campaign.id)
            if item.branch_id == "branch_ready"
        )
        assert branch.status == "awaiting_human"
        assert branch.stop_reason == "awaiting_plan"
        plan_handoffs = [
            item
            for item in repository.list_campaign_tasks(campaign.id)
            if item.task_type == "autopilot_plan_materialization"
        ]
        assert len(plan_handoffs) == 1
        assert plan_handoffs[0].status == "awaiting_approval"
        assert (
            plan_handoffs[0].payload["schema_version"]
            == "autopilot-plan-materialization/v1"
        )
        assert plan_handoffs[0].payload["authorization_digest"] == authorization.authorization_digest
        assert plan_handoffs[0].payload["recipe_ref"] == recipe.ref.model_dump(mode="json")
        assert repository.list_execution_leases(campaign.id) == []
        assert repository.list_execution_request_ledger(campaign.id) == []

        session.expire_all()
        resumed = run_agent_task(task.id, repository=repository)
        assert resumed["status"] == "completed"
        assert len(
            [
                item
                for item in repository.list_campaign_tasks(campaign.id)
                if item.task_type == "autopilot_plan_materialization"
            ]
        ) == 1
    finally:
        session.close()


def test_branch_continuation_revalidates_current_authorization_before_handoff():
    repository, session = _repository()
    try:
        campaign, authorization, _recipe = _branch_ready_campaign(repository)
        dispatched: list[str] = []
        tick = tick_autonomous_research_campaign(
            campaign.id,
            repository=repository,
            dispatcher=lambda *, campaign_task_id: dispatched.append(campaign_task_id),
        )
        assert tick["status"] == "dispatched"
        task_id = dispatched[0]
        changed = authorization.model_copy(update={"policy_digest": _digest("changed-policy")})
        repository.create_campaign_authorization(
            campaign_id=campaign.id,
            authorization_payload=campaign_authorization_payload(changed),
        )

        blocked = run_agent_task(task_id, repository=repository)

        assert blocked["status"] == "blocked"
        assert blocked["stop_reason"] == "authorization_changed"
        assert not [
            item
            for item in repository.list_campaign_tasks(campaign.id)
            if item.task_type == "autopilot_plan_materialization"
        ]
    finally:
        session.close()


def test_branch_handoff_rolls_back_when_execution_lease_expires_at_finish(monkeypatch):
    repository, session = _repository()
    try:
        campaign, _authorization, _recipe = _branch_ready_campaign(repository)
        dispatched: list[str] = []
        tick = tick_autonomous_research_campaign(
            campaign.id,
            repository=repository,
            dispatcher=lambda *, campaign_task_id: dispatched.append(campaign_task_id),
        )
        assert tick["status"] == "dispatched"
        task = next(
            item
            for item in repository.list_campaign_tasks(campaign.id)
            if item.id == dispatched[0]
        )
        original_finish = repository.finish_campaign_task_execution

        def expire_before_finish(**kwargs):
            claimed_task = session.get(type(task), kwargs["task_id"])
            assert claimed_task is not None
            claimed_task.execution_lease_expires_at = datetime.now(UTC) - timedelta(seconds=1)
            return original_finish(**kwargs)

        monkeypatch.setattr(
            repository,
            "finish_campaign_task_execution",
            expire_before_finish,
        )

        result = run_agent_task(task.id, repository=repository)

        assert result["stop_reason"] == "execution_lease_lost"
        session.expire_all()
        branch = repository.get_research_branch(
            campaign_id=campaign.id,
            branch_id="branch_ready",
        )
        assert branch is not None
        assert branch.status == "queued"
        assert branch.stop_reason is None
        assert not [
            item
            for item in repository.list_campaign_tasks(campaign.id)
            if item.task_type == "autopilot_plan_materialization"
        ]
    finally:
        session.close()


def test_awaiting_review_runs_only_the_bound_branch_continuation():
    repository, session = _repository()
    try:
        campaign, _authorization, _recipe = _branch_ready_campaign(repository)
        repository.update_campaign_status(campaign.id, "awaiting_review")

        selection = select_autonomous_research_work(
            campaign=repository.get_campaign(campaign.id),
            repository=repository,
        )

        assert selection["task_type"] == "autopilot_branch_continuation"
        dispatched: list[str] = []
        tick = tick_autonomous_research_campaign(
            campaign.id,
            repository=repository,
            dispatcher=lambda *, campaign_task_id: dispatched.append(campaign_task_id),
        )

        assert tick["status"] == "dispatched"
        task = next(
            item
            for item in repository.list_campaign_tasks(campaign.id)
            if item.id == dispatched[0]
        )
        assert task.task_type == "autopilot_branch_continuation"
        completed = run_agent_task(task.id, repository=repository)
        assert completed["status"] == "completed"
        assert repository.get_campaign(campaign.id).status == "awaiting_review"
    finally:
        session.close()
