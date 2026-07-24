"""Phase 3 independent research branch selection tests."""

from __future__ import annotations

import pytest

from app.bounty_autopilot.branches import (
    BranchBudgetCounters,
    BranchLimits,
    BranchStatus,
    ResearchBranch,
    select_next_branch,
    transition_branch,
)
from app.bounty_autopilot.contracts import RecipeRef, RiskTier
from app.bounty_autopilot.recipes import default_recipe_registry


def _limits() -> BranchLimits:
    return BranchLimits(
        campaign_max_requests=100,
        campaign_max_time_seconds=3600,
        campaign_max_cost_units=100,
        per_asset_max_requests=20,
        per_account_max_requests=10,
        per_hypothesis_max_requests=10,
    )


def _branch(
    branch_id: str,
    *,
    status: BranchStatus = BranchStatus.QUEUED,
    priority: int = 50,
    asset_id: str = "asset_a",
    risk_tier: RiskTier = RiskTier.R0,
    hypothesis_id: str | None = None,
    account_aliases: tuple[str, ...] = (),
    requests_used: int = 0,
) -> ResearchBranch:
    return ResearchBranch(
        branch_id=branch_id,
        campaign_id="campaign_1",
        asset_id=asset_id,
        status=status,
        priority=priority,
        recipe_ref=default_recipe_registry()
        .require("passive_rule_snapshot_analysis", "1.0.0")
        .ref,
        risk_tier=risk_tier,
        hypothesis_id=hypothesis_id,
        account_aliases=account_aliases,
        budget=BranchBudgetCounters(requests_used=requests_used),
        version=1,
    )


def test_branch_states_are_explicit():
    expected = {
        "queued",
        "active",
        "parked",
        "awaiting_r3",
        "awaiting_human",
        "blocked",
        "completed",
        "closed",
    }
    assert {status.value for status in BranchStatus} == expected


def test_waf_parked_or_r3_waiting_does_not_stop_eligible_lab_branch():
    branches = [
        _branch("b_parked", status=BranchStatus.PARKED, priority=99, asset_id="asset_waf"),
        _branch(
            "b_r3",
            status=BranchStatus.AWAITING_R3,
            priority=98,
            risk_tier=RiskTier.R3,
            asset_id="asset_r3",
        ),
        _branch(
            "b_lab",
            status=BranchStatus.QUEUED,
            priority=10,
            risk_tier=RiskTier.R1,
            asset_id="asset_lab",
        ),
    ]
    selection = select_next_branch(
        branches,
        limits=_limits(),
        admitted_asset_ids={"asset_lab", "asset_waf", "asset_r3"},
    )
    assert selection.selected_branch_id == "b_lab"
    assert selection.reason == "selected"
    assert set(selection.visible_waiting_branch_ids) == {"b_parked", "b_r3"}


def test_limits_participate_in_next_branch_selection():
    branches = [
        _branch("b_asset_cap", priority=90, asset_id="asset_hot"),
        _branch("b_ok", priority=10, asset_id="asset_ok"),
    ]
    selection = select_next_branch(
        branches,
        limits=_limits(),
        asset_requests={"asset_hot": 20},
        admitted_asset_ids={"asset_hot", "asset_ok"},
    )
    assert selection.selected_branch_id == "b_ok"

    campaign_exhausted = select_next_branch(
        branches,
        limits=_limits(),
        campaign_requests_used=100,
        admitted_asset_ids={"asset_hot", "asset_ok"},
    )
    assert campaign_exhausted.selected_branch_id is None
    assert campaign_exhausted.reason == "no_eligible_branch"


def test_equal_priority_selection_is_stable_by_branch_id():
    branches = [
        _branch("b_z", priority=50),
        _branch("b_a", priority=50),
        _branch("b_m", priority=50),
    ]
    selection = select_next_branch(
        branches,
        limits=_limits(),
        admitted_asset_ids={"asset_a"},
    )
    assert selection.selected_branch_id == "b_a"


def test_retry_cannot_duplicate_successful_predecessor_transition():
    branch = _branch("b1", status=BranchStatus.COMPLETED)
    with pytest.raises(ValueError, match="duplicate_completed_transition"):
        transition_branch(
            branch,
            new_status=BranchStatus.COMPLETED,
            expected_version=1,
        )


def test_policy_drift_freezes_without_rewriting_branch_history():
    original = _branch("b1", status=BranchStatus.ACTIVE, priority=80)
    selection = select_next_branch(
        [original],
        limits=_limits(),
        policy_drift=True,
        admitted_asset_ids={"asset_a"},
    )
    assert selection.selected_branch_id is None
    assert selection.frozen_for_policy_drift is True
    assert selection.reason == "policy_drift_freeze"
    assert original.status is BranchStatus.ACTIVE
    assert original.version == 1


def test_transition_requires_expected_version():
    branch = _branch("b1")
    with pytest.raises(ValueError, match="branch_version_conflict"):
        transition_branch(
            branch,
            new_status=BranchStatus.ACTIVE,
            expected_version=99,
        )
    next_branch = transition_branch(
        branch,
        new_status=BranchStatus.ACTIVE,
        expected_version=1,
    )
    assert next_branch.status is BranchStatus.ACTIVE
    assert next_branch.version == 2


def test_r3_and_r4_branches_are_not_auto_selected():
    branches = [
        _branch("b_r3", priority=99, risk_tier=RiskTier.R3),
        _branch("b_r4", priority=98, risk_tier=RiskTier.R4),
        _branch("b_r0", priority=1, risk_tier=RiskTier.R0),
    ]
    selection = select_next_branch(
        branches,
        limits=_limits(),
        admitted_asset_ids={"asset_a"},
    )
    assert selection.selected_branch_id == "b_r0"


def test_non_admitted_assets_are_skipped():
    branches = [
        _branch("b1", asset_id="asset_pending", priority=99),
        _branch("b2", asset_id="asset_ok", priority=1),
    ]
    selection = select_next_branch(
        branches,
        limits=_limits(),
        admitted_asset_ids={"asset_ok"},
    )
    assert selection.selected_branch_id == "b2"


def test_empty_admitted_asset_set_fails_closed():
    selection = select_next_branch(
        [_branch("b1", asset_id="asset_pending", priority=99)],
        limits=_limits(),
        admitted_asset_ids=set(),
    )

    assert selection.selected_branch_id is None
    assert selection.reason == "no_eligible_branch"

def test_repository_persists_asset_admission_and_branch_transitions():
    from datetime import UTC, datetime

    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    from sqlalchemy.pool import StaticPool

    from app.bounty_autopilot.asset_admission import (
        AssetProvenance,
        ScopeMatcher,
        decide_admission,
        parse_asset_url,
    )
    from app.db import Base
    from app.repository import DatabaseRepository, seed_sample_data

    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    Session = sessionmaker(bind=engine)
    with Session() as session:
        seed_sample_data(session)
        repo = DatabaseRepository(session)
        program = repo.list_programs()[0]
        campaign = repo.create_campaign(
            program_id=program.id,
            name="branch-persist",
            autonomy_level="level_0_read_only",
            scope_status="in_scope",
            policy_text="policy",
            default_asset="lab.local",
            created_by="operator_alice",
            campaign_mode="bounty_autopilot",
        )
        campaign_id = campaign.id
        scope = "sha256:" + ("d" * 64)
        identity = parse_asset_url(
            "https://lab.local/", provenance=AssetProvenance.SEED
        )
        admission = decide_admission(
            identity,
            ScopeMatcher(
                include_hosts=("lab.local",),
                include_path_prefixes=("/",),
                scope_snapshot_digest=scope,
            ),
            seen_at=datetime.now(UTC).isoformat(),
        )
        asset = repo.upsert_campaign_asset_admission(
            campaign_id=campaign_id,
            admission=admission.model_dump(mode="json"),
        )
        assert asset.admission_decision == "admitted"
        admitted = repo.list_admitted_campaign_asset_ids(
            campaign_id, scope_snapshot_digest=scope
        )
        assert admission.asset_id in admitted

        branch = ResearchBranch(
            branch_id="branch_repo_1",
            campaign_id=campaign_id,
            asset_id=admission.asset_id,
            status=BranchStatus.QUEUED,
            priority=40,
            risk_tier=RiskTier.R0,
        )
        created = repo.create_research_branch(
            campaign_id=campaign_id,
            branch=branch.model_dump(mode="json"),
        )
        assert created.version == 1
        updated = repo.transition_research_branch(
            campaign_id=campaign_id,
            branch_id="branch_repo_1",
            new_status="active",
            expected_version=1,
        )
        assert updated.status == "active"
        assert updated.version == 2
