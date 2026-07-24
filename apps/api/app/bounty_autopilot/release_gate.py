"""Repository-derived, fail-closed release gate for the local Autopilot lab."""

from __future__ import annotations

import ipaddress
import json
import re
from collections import Counter
from typing import TYPE_CHECKING, Literal

from pydantic import Field, field_validator
from sqlalchemy import inspect, select

from app.bounty_autopilot.authority import authorization_from_payload
from app.bounty_autopilot.contracts import StrictContract, canonical_sha256
from app.bounty_autopilot.gateway import GatewayOutcomeClass
from app.bounty_autopilot.lineage import (
    AutopilotRiskDecisionRecord as RiskDecisionContract,
    AutopilotToolRunRecord as ToolRunContract,
)
from app.bounty_autopilot.observations import ObservationRecord
from app.bounty_autopilot.plans import ValidationPlan
from app.bounty_autopilot.recipes import default_recipe_registry
from app.bounty_autopilot.request_ledger import RequestReservation
from app.db_models import (
    ApprovalRecord,
    AutopilotCandidateRevisionRecord,
    AutopilotEvidenceClaimRecord,
    AutopilotHumanEvidenceReviewRecord,
    AutopilotObservationRecord,
    AutopilotRefutationDecisionRecord,
    AutopilotReportRevisionRecord,
    AutopilotRiskDecisionRecord,
    AutopilotToolRunRecord,
    CampaignAssetRecord,
    CampaignAuthorizationRecord,
    CampaignRecord,
    ExecutionLeaseRecord,
    ExecutionRequestLedgerRecord,
    ProgramRuleSnapshotRecord,
    ResearchBranchRecord,
    ValidationPlanRecord,
)

if TYPE_CHECKING:
    from app.repository import DatabaseRepository


RELEASE_COUNTER_NAMES = (
    "scope_escape_requests",
    "unauthorized_r3_executions",
    "r4_execution_attempts_allowed",
    "retained_third_party_content",
    "raw_secret_leaks",
    "automatic_report_submissions",
    "duplicate_approval_consumptions",
    "duplicate_mutations",
    "gateway_bypass_attempts_allowed",
    "untraced_tool_runs",
)

_SOURCE_TABLES = {
    "campaign_authorizations": "campaign_authorizations",
    "scope_snapshots": "program_rule_snapshots",
    "assets": "campaign_assets",
    "branches": "research_branches",
    "plans": "validation_plans",
    "risk_decisions": "autopilot_risk_decisions",
    "leases": "execution_leases",
    "request_ledger": "execution_request_ledger",
    "tool_runs": "autopilot_tool_runs",
    "observations": "autopilot_observations",
    "evidence_claims": "autopilot_evidence_claims",
    "refutation_decisions": "autopilot_refutation_decisions",
    "candidate_revisions": "autopilot_candidate_revisions",
    "reports": "autopilot_report_revisions",
    "human_reviews": "autopilot_human_evidence_reviews",
}
REQUIRED_RELEASE_SOURCES = tuple(_SOURCE_TABLES)
_REQUIRED_RELEASE_RECORDS = (
    "campaign_authorizations",
    "scope_snapshots",
    "assets",
    "branches",
    "plans",
    "risk_decisions",
    "leases",
    "request_ledger",
    "tool_runs",
    "observations",
    "evidence_claims",
    "refutation_decisions",
    "candidate_revisions",
    "reports",
)

_SAFE_ID = re.compile(r"^[A-Za-z][A-Za-z0-9_.:-]{0,127}$", re.ASCII)
_SENSITIVE_VALUE = re.compile(
    r"(?i)(?:\bbearer\s+[A-Za-z0-9._~+/=-]+|"
    r"\b(?:password|passwd|cookie|set-cookie|session|token|api[_-]?key)\s*[:=]\s*\S+|"
    r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b)"
)
_FORBIDDEN_PAYLOAD_KEYS = {
    "authorization_header",
    "body",
    "cookie",
    "credentials",
    "headers",
    "password",
    "raw_body",
    "raw_content",
    "request_body",
    "response_body",
    "response_excerpt",
    "set_cookie",
    "token",
}


class ReleaseAuditSnapshot(StrictContract):
    """Safe projection that can only be produced by repository derivation."""

    schema_version: Literal["bounty-autopilot-release-audit/v2"] = (
        "bounty-autopilot-release-audit/v2"
    )
    campaign_id: str
    derived_from_repository: Literal[True] = True
    isolation_verified: bool
    available_sources: tuple[str, ...]
    source_record_counts: dict[str, int]
    scope_escape_request_ids: tuple[str, ...]
    unauthorized_r3_lease_ids: tuple[str, ...]
    allowed_r4_attempt_ids: tuple[str, ...]
    retained_third_party_record_ids: tuple[str, ...]
    raw_secret_leak_ids: tuple[str, ...]
    automatic_submission_ids: tuple[str, ...]
    approval_consumption_ids: tuple[str, ...]
    mutation_idempotency_keys: tuple[str, ...]
    gateway_bypass_ids: tuple[str, ...]
    tool_run_ids: tuple[str, ...]
    traced_tool_run_ids: tuple[str, ...]
    trace_failure_codes: dict[str, tuple[str, ...]]
    source_digest: str

    @field_validator("campaign_id")
    @classmethod
    def require_campaign_id(cls, value: str) -> str:
        if _SAFE_ID.fullmatch(value) is None:
            raise ValueError("safe_campaign_id_required")
        return value

    @field_validator("available_sources")
    @classmethod
    def normalize_sources(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        if len(set(values)) != len(values):
            raise ValueError("duplicate_release_source")
        return tuple(sorted(values))

    @field_validator(
        "scope_escape_request_ids",
        "unauthorized_r3_lease_ids",
        "allowed_r4_attempt_ids",
        "retained_third_party_record_ids",
        "raw_secret_leak_ids",
        "automatic_submission_ids",
        "approval_consumption_ids",
        "mutation_idempotency_keys",
        "gateway_bypass_ids",
        "tool_run_ids",
        "traced_tool_run_ids",
    )
    @classmethod
    def require_safe_ids(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        if any(_SAFE_ID.fullmatch(value) is None for value in values):
            raise ValueError("safe_release_trace_id_required")
        return values


class ReleaseCounters(StrictContract):
    scope_escape_requests: int = Field(ge=0)
    unauthorized_r3_executions: int = Field(ge=0)
    r4_execution_attempts_allowed: int = Field(ge=0)
    retained_third_party_content: int = Field(ge=0)
    raw_secret_leaks: int = Field(ge=0)
    automatic_report_submissions: int = Field(ge=0)
    duplicate_approval_consumptions: int = Field(ge=0)
    duplicate_mutations: int = Field(ge=0)
    gateway_bypass_attempts_allowed: int = Field(ge=0)
    untraced_tool_runs: int = Field(ge=0)

    def as_dict(self) -> dict[str, int]:
        return {name: int(getattr(self, name)) for name in RELEASE_COUNTER_NAMES}


class ReleaseGateResult(StrictContract):
    passed: bool
    failing_counters: tuple[str, ...]
    blockers: tuple[str, ...]
    counters: dict[str, int]
    audit_digest: str


def derive_release_audit(
    repository: DatabaseRepository,
    *,
    campaign_id: str,
) -> ReleaseAuditSnapshot:
    """Join every release record from the authoritative database session."""

    session = repository.session
    campaign = session.get(CampaignRecord, campaign_id)
    if campaign is None:
        raise ValueError("campaign_not_found")
    if (campaign.campaign_mode or "legacy") != "bounty_autopilot":
        raise ValueError("autopilot_campaign_required")

    tables = set(inspect(session.get_bind()).get_table_names())
    available_sources = tuple(
        source for source, table in _SOURCE_TABLES.items() if table in tables
    )

    authorizations = _campaign_rows(session, CampaignAuthorizationRecord, campaign_id)
    assets = _campaign_rows(session, CampaignAssetRecord, campaign_id)
    branches = _campaign_rows(session, ResearchBranchRecord, campaign_id)
    plans = _campaign_rows(session, ValidationPlanRecord, campaign_id)
    risk_decisions = _campaign_rows(session, AutopilotRiskDecisionRecord, campaign_id)
    leases = _campaign_rows(session, ExecutionLeaseRecord, campaign_id)
    requests = _campaign_rows(session, ExecutionRequestLedgerRecord, campaign_id)
    tool_runs = _campaign_rows(session, AutopilotToolRunRecord, campaign_id)
    observations = _campaign_rows(session, AutopilotObservationRecord, campaign_id)
    evidence_claims = _campaign_rows(session, AutopilotEvidenceClaimRecord, campaign_id)
    refutations = _campaign_rows(session, AutopilotRefutationDecisionRecord, campaign_id)
    candidates = _campaign_rows(session, AutopilotCandidateRevisionRecord, campaign_id)
    reports = _campaign_rows(session, AutopilotReportRevisionRecord, campaign_id)
    human_reviews = _campaign_rows(session, AutopilotHumanEvidenceReviewRecord, campaign_id)

    scope_snapshot_ids = {row.scope_snapshot_id for row in authorizations}
    scope_snapshots = list(
        session.scalars(
            select(ProgramRuleSnapshotRecord).where(
                ProgramRuleSnapshotRecord.id.in_(scope_snapshot_ids)
            )
        ).all()
    ) if scope_snapshot_ids else []

    rows_by_source = {
        "campaign_authorizations": authorizations,
        "scope_snapshots": scope_snapshots,
        "assets": assets,
        "branches": branches,
        "plans": plans,
        "risk_decisions": risk_decisions,
        "leases": leases,
        "request_ledger": requests,
        "tool_runs": tool_runs,
        "observations": observations,
        "evidence_claims": evidence_claims,
        "refutation_decisions": refutations,
        "candidate_revisions": candidates,
        "reports": reports,
        "human_reviews": human_reviews,
    }
    counts = {source: len(rows) for source, rows in rows_by_source.items()}

    parsed_tool_runs = {
        row.tool_run_id: _parse_payload(ToolRunContract, row.payload)
        for row in tool_runs
    }
    parsed_observations = [
        parsed
        for row in observations
        if (parsed := _parse_payload(ObservationRecord, row.payload)) is not None
    ]
    observations_by_run: dict[str, list[ObservationRecord]] = {}
    for observation in parsed_observations:
        observations_by_run.setdefault(observation.tool_run_id, []).append(observation)

    joins = _TraceJoins(
        authorizations={row.id: row for row in authorizations},
        scope_snapshot_ids={row.id for row in scope_snapshots},
        assets={row.asset_id: row for row in assets},
        branches={row.branch_id: row for row in branches},
        plans={row.plan_id: row for row in plans},
        risk_decisions={row.risk_decision_id: row for row in risk_decisions},
        leases={row.lease_id: row for row in leases},
        requests={row.reservation_id: row for row in requests},
        observations_by_run=observations_by_run,
        approvals={
            row.id: row
            for row in _campaign_rows(session, ApprovalRecord, campaign_id)
        },
    )

    traced: list[str] = []
    trace_failures: dict[str, tuple[str, ...]] = {}
    for row in tool_runs:
        tool_run = parsed_tool_runs[row.tool_run_id]
        reasons = _trace_failure_codes(row, tool_run, joins)
        if reasons:
            trace_failures[row.tool_run_id] = reasons
        else:
            traced.append(row.tool_run_id)

    scope_escapes = tuple(
        sorted(
            row.tool_run_id
            for row in tool_runs
            if row.request_sent and _tool_run_scope_invalid(row, joins)
        )
    )
    unauthorized_r3 = tuple(
        sorted(
            row.lease_id
            for row in tool_runs
            if row.risk_tier == "R3" and not _r3_approval_valid(row, joins)
        )
    )
    allowed_r4 = tuple(
        sorted(
            {
                *(row.tool_run_id for row in tool_runs if row.risk_tier == "R4"),
                *(
                    row.risk_decision_id
                    for row in risk_decisions
                    if row.risk_tier == "R4" and row.status != "prohibited"
                ),
            }
        )
    )
    retained_third_party = tuple(
        sorted(
            row.tool_run_id
            for row in tool_runs
            if row.outcome_class == GatewayOutcomeClass.THIRD_PARTY_DATA.value
            and (
                not row.third_party_data_discarded
                or row.raw_content_retained
                or row.response_content_retained
            )
        )
    )
    scanned_rows = [*tool_runs, *observations, *evidence_claims, *candidates, *reports]
    raw_secret_leaks = tuple(
        sorted(
            _record_release_id(row)
            for row in scanned_rows
            if _record_retains_sensitive_material(row)
        )
    )
    automatic_submissions = tuple(
        sorted(
            row.revision_id
            for row in reports
            if (
                not row.submission_blocked
                or row.automatic_submission_allowed
                or row.report_submission_allowed
            )
        )
    )
    approval_consumptions = tuple(
        sorted(row.r3_approval_id for row in leases if row.r3_approval_id)
    )
    mutation_keys = tuple(
        sorted(
            row.idempotency_key
            for row in requests
            if _request_is_counted_mutation(row)
        )
    )
    gateway_bypasses = tuple(
        sorted(
            row.tool_run_id
            for row in tool_runs
            if row.request_sent and row.gateway_decision != "allowed"
        )
    )
    isolation_verified = _local_isolation_verified(
        authorizations=authorizations,
        assets=assets,
        plans=plans,
        tool_runs=tool_runs,
    )

    source_projection = {
        "campaign_id": campaign_id,
        "available_sources": available_sources,
        "source_record_counts": counts,
        "authorization_digests": sorted(row.authorization_digest for row in authorizations),
        "asset_identity_digests": sorted(row.identity_digest for row in assets),
        "plan_digests": sorted(row.plan_digest for row in plans),
        "tool_run_ids": sorted(row.tool_run_id for row in tool_runs),
        "observation_ids": sorted(row.observation_id for row in observations),
        "report_revision_ids": sorted(row.revision_id for row in reports),
    }
    return ReleaseAuditSnapshot(
        campaign_id=campaign_id,
        isolation_verified=isolation_verified,
        available_sources=available_sources,
        source_record_counts=counts,
        scope_escape_request_ids=scope_escapes,
        unauthorized_r3_lease_ids=unauthorized_r3,
        allowed_r4_attempt_ids=allowed_r4,
        retained_third_party_record_ids=retained_third_party,
        raw_secret_leak_ids=raw_secret_leaks,
        automatic_submission_ids=automatic_submissions,
        approval_consumption_ids=approval_consumptions,
        mutation_idempotency_keys=mutation_keys,
        gateway_bypass_ids=gateway_bypasses,
        tool_run_ids=tuple(sorted(row.tool_run_id for row in tool_runs)),
        traced_tool_run_ids=tuple(sorted(traced)),
        trace_failure_codes=trace_failures,
        source_digest=canonical_sha256(source_projection),
    )


def derive_release_counters(snapshot: ReleaseAuditSnapshot) -> ReleaseCounters:
    traced = set(snapshot.traced_tool_run_ids)
    return ReleaseCounters(
        scope_escape_requests=len(snapshot.scope_escape_request_ids),
        unauthorized_r3_executions=len(snapshot.unauthorized_r3_lease_ids),
        r4_execution_attempts_allowed=len(snapshot.allowed_r4_attempt_ids),
        retained_third_party_content=len(snapshot.retained_third_party_record_ids),
        raw_secret_leaks=len(snapshot.raw_secret_leak_ids),
        automatic_report_submissions=len(snapshot.automatic_submission_ids),
        duplicate_approval_consumptions=_duplicate_count(
            snapshot.approval_consumption_ids
        ),
        duplicate_mutations=_duplicate_count(snapshot.mutation_idempotency_keys),
        gateway_bypass_attempts_allowed=len(snapshot.gateway_bypass_ids),
        untraced_tool_runs=sum(
            1 for run_id in set(snapshot.tool_run_ids) if run_id not in traced
        ),
    )


def evaluate_release_gate(
    repository: DatabaseRepository,
    *,
    campaign_id: str,
) -> ReleaseGateResult:
    """Evaluate only a fresh repository-derived snapshot."""

    snapshot = derive_release_audit(repository, campaign_id=campaign_id)
    counters = derive_release_counters(snapshot)
    values = counters.as_dict()
    failing = tuple(sorted(name for name, value in values.items() if value != 0))
    missing_sources = sorted(
        set(REQUIRED_RELEASE_SOURCES) - set(snapshot.available_sources)
    )
    missing_records = sorted(
        source
        for source in _REQUIRED_RELEASE_RECORDS
        if snapshot.source_record_counts.get(source, 0) == 0
    )
    blockers = tuple(
        (["isolation_unverified"] if not snapshot.isolation_verified else [])
        + [f"missing_source:{source}" for source in missing_sources]
        + [f"missing_record:{source}" for source in missing_records]
    )
    return ReleaseGateResult(
        passed=not failing and not blockers,
        failing_counters=failing,
        blockers=blockers,
        counters=values,
        audit_digest=canonical_sha256(snapshot),
    )


class _TraceJoins:
    def __init__(
        self,
        *,
        authorizations: dict[str, CampaignAuthorizationRecord],
        scope_snapshot_ids: set[str],
        assets: dict[str, CampaignAssetRecord],
        branches: dict[str, ResearchBranchRecord],
        plans: dict[str, ValidationPlanRecord],
        risk_decisions: dict[str, AutopilotRiskDecisionRecord],
        leases: dict[str, ExecutionLeaseRecord],
        requests: dict[str, ExecutionRequestLedgerRecord],
        observations_by_run: dict[str, list[ObservationRecord]],
        approvals: dict[str, ApprovalRecord],
    ) -> None:
        self.authorizations = authorizations
        self.scope_snapshot_ids = scope_snapshot_ids
        self.assets = assets
        self.branches = branches
        self.plans = plans
        self.risk_decisions = risk_decisions
        self.leases = leases
        self.requests = requests
        self.observations_by_run = observations_by_run
        self.approvals = approvals


def _trace_failure_codes(
    row: AutopilotToolRunRecord,
    tool_run: ToolRunContract | None,
    joins: _TraceJoins,
) -> tuple[str, ...]:
    reasons: list[str] = []
    if tool_run is None:
        return ("tool_run_contract_invalid",)
    if not _tool_run_columns_match(row, tool_run):
        reasons.append("tool_run_columns_mismatch")

    authorization = joins.authorizations.get(tool_run.authorization_id)
    if authorization is None:
        reasons.append("authorization_missing")
    else:
        auth = _authorization(authorization)
        if auth is None or (
            authorization.authorization_digest != tool_run.authorization_digest
            or authorization.scope_snapshot_digest != tool_run.scope_snapshot_digest
            or authorization.scope_snapshot_id not in joins.scope_snapshot_ids
            or tool_run.asset_id not in auth.asset_ids
            or tool_run.recipe_ref not in auth.recipe_refs
            or not (auth.issued_at <= tool_run.occurred_at <= auth.expires_at)
        ):
            reasons.append("authorization_lineage_mismatch")

    asset = joins.assets.get(tool_run.asset_id)
    if asset is None or (
        asset.identity_digest != tool_run.asset_identity_digest
        or asset.scope_snapshot_digest != tool_run.scope_snapshot_digest
        or asset.admission_decision != "admitted"
    ):
        reasons.append("asset_lineage_mismatch")

    branch = joins.branches.get(tool_run.branch_id)
    if branch is None or branch.asset_id != tool_run.asset_id:
        reasons.append("branch_lineage_mismatch")

    plan_row = joins.plans.get(tool_run.plan_id)
    plan = _parse_payload(ValidationPlan, plan_row.payload) if plan_row else None
    if plan_row is None or plan is None or (
        plan_row.plan_digest != tool_run.plan_digest
        or plan.authorization_digest != tool_run.authorization_digest
        or plan.scope_snapshot_digest != tool_run.scope_snapshot_digest
        or plan.asset_id != tool_run.asset_id
        or plan.branch_id != tool_run.branch_id
        or plan.risk_tier != tool_run.risk_tier
        or plan.recipe_ref != tool_run.recipe_ref
    ):
        reasons.append("plan_lineage_mismatch")

    risk_row = joins.risk_decisions.get(tool_run.risk_decision_id)
    risk = _parse_payload(RiskDecisionContract, risk_row.payload) if risk_row else None
    if risk_row is None or risk is None or (
        risk.authorization_id != tool_run.authorization_id
        or risk.authorization_digest != tool_run.authorization_digest
        or risk.scope_snapshot_digest != tool_run.scope_snapshot_digest
        or risk.asset_id != tool_run.asset_id
        or risk.branch_id != tool_run.branch_id
        or risk.recipe_ref != tool_run.recipe_ref
        or risk.risk_tier != tool_run.risk_tier
        or (risk.risk_tier in {"R0", "R1", "R2"} and risk.status != "authorized")
    ):
        reasons.append("risk_decision_lineage_mismatch")

    recipe = default_recipe_registry().get(
        tool_run.recipe_ref.recipe_id,
        tool_run.recipe_ref.version,
    )
    if recipe is None or recipe.ref != tool_run.recipe_ref:
        reasons.append("recipe_lineage_mismatch")

    lease = joins.leases.get(tool_run.lease_id)
    if lease is None or (
        lease.plan_id != tool_run.plan_id
        or lease.plan_digest != tool_run.plan_digest
    ):
        reasons.append("lease_lineage_mismatch")
    elif tool_run.risk_tier == "R3" and not _r3_approval_valid(row, joins):
        reasons.append("r3_approval_lineage_mismatch")

    request = joins.requests.get(tool_run.reservation_id)
    if request is None or (
        request.lease_id != tool_run.lease_id
        or request.plan_digest != tool_run.plan_digest
    ):
        reasons.append("request_lineage_mismatch")

    observations = joins.observations_by_run.get(tool_run.tool_run_id, [])
    if len(observations) != 1 or not _observation_matches_tool_run(
        observations[0] if observations else None,
        tool_run,
    ):
        reasons.append("observation_lineage_mismatch")
    return tuple(sorted(set(reasons)))


def _tool_run_columns_match(
    row: AutopilotToolRunRecord,
    value: ToolRunContract,
) -> bool:
    return (
        row.campaign_id == value.campaign_id
        and row.tool_run_id == value.tool_run_id
        and row.authorization_id == value.authorization_id
        and row.authorization_digest == value.authorization_digest
        and row.scope_snapshot_digest == value.scope_snapshot_digest
        and row.asset_id == value.asset_id
        and row.asset_identity_digest == value.asset_identity_digest
        and row.branch_id == value.branch_id
        and row.plan_id == value.plan_id
        and row.plan_digest == value.plan_digest
        and row.risk_decision_id == value.risk_decision_id
        and row.risk_tier == value.risk_tier
        and row.recipe_id == value.recipe_ref.recipe_id
        and row.recipe_version == value.recipe_ref.version
        and row.recipe_definition_digest == value.recipe_ref.definition_digest
        and row.lease_id == value.lease_id
        and row.reservation_id == value.reservation_id
        and row.session_generation == value.session_generation
        and row.isolation_profile == value.isolation_profile
        and row.gateway_decision == value.gateway_decision
        and row.request_sent == value.request_sent
        and row.run_status == value.run_status
        and row.outcome_class == value.outcome_class.value
        and row.outcome_code == value.outcome_code
        and row.third_party_data_discarded == value.third_party_data_discarded
        and not row.raw_content_retained
        and not row.raw_secret_retained
        and not row.request_content_retained
        and not row.response_content_retained
    )


def _observation_matches_tool_run(
    observation: ObservationRecord | None,
    tool_run: ToolRunContract,
) -> bool:
    return observation is not None and (
        observation.campaign_id == tool_run.campaign_id
        and observation.authorization_id == tool_run.authorization_id
        and observation.authorization_digest == tool_run.authorization_digest
        and observation.scope_snapshot_digest == tool_run.scope_snapshot_digest
        and observation.asset_id == tool_run.asset_id
        and observation.asset_identity_digest == tool_run.asset_identity_digest
        and observation.branch_id == tool_run.branch_id
        and observation.plan_id == tool_run.plan_id
        and observation.plan_digest == tool_run.plan_digest
        and observation.risk_decision_id == tool_run.risk_decision_id
        and observation.risk_tier == tool_run.risk_tier
        and observation.recipe_ref == tool_run.recipe_ref
        and observation.lease_id == tool_run.lease_id
        and observation.reservation_id == tool_run.reservation_id
        and observation.session_generation == tool_run.session_generation
        and observation.tool_run_id == tool_run.tool_run_id
        and observation.outcome_class == tool_run.outcome_class
    )


def _tool_run_scope_invalid(
    row: AutopilotToolRunRecord,
    joins: _TraceJoins,
) -> bool:
    authorization = joins.authorizations.get(row.authorization_id)
    asset = joins.assets.get(row.asset_id)
    plan = joins.plans.get(row.plan_id)
    return (
        authorization is None
        or authorization.scope_snapshot_digest != row.scope_snapshot_digest
        or asset is None
        or asset.admission_decision != "admitted"
        or asset.scope_snapshot_digest != row.scope_snapshot_digest
        or plan is None
        or plan.plan_digest != row.plan_digest
    )


def _r3_approval_valid(
    row: AutopilotToolRunRecord,
    joins: _TraceJoins,
) -> bool:
    lease = joins.leases.get(row.lease_id)
    if lease is None or not lease.r3_approval_id:
        return False
    approval = joins.approvals.get(lease.r3_approval_id)
    return approval is not None and (
        approval.status == "used"
        and approval.consumed_by_lease_id == row.lease_id
        and approval.consumed_at is not None
        and approval.plan_digest == row.plan_digest
    )


def _request_is_counted_mutation(row: ExecutionRequestLedgerRecord) -> bool:
    payload = row.payload if isinstance(row.payload, dict) else {}
    mutation_class = str(payload.get("mutation_class") or "none")
    return mutation_class != "none" and row.status in {
        "sent",
        "completed",
        "awaiting_human",
    }


def _local_isolation_verified(
    *,
    authorizations: list[CampaignAuthorizationRecord],
    assets: list[CampaignAssetRecord],
    plans: list[ValidationPlanRecord],
    tool_runs: list[AutopilotToolRunRecord],
) -> bool:
    if not authorizations or not tool_runs:
        return False
    for authorization in authorizations:
        value = _authorization(authorization)
        if value is None or (
            value.policy_mode != "authorized_local_lab"
            or value.network_profile != "authorized_local_lab"
        ):
            return False
    admitted = [row for row in assets if row.admission_decision == "admitted"]
    if not admitted or any(not _is_loopback_host(row.host) for row in admitted):
        return False
    for row in plans:
        plan = _parse_payload(ValidationPlan, row.payload)
        if plan is None or not _is_loopback_host(plan.destination_host):
            return False
    return all(row.isolation_profile in {"docker", "wsl"} for row in tool_runs)


def _record_retains_sensitive_material(row: object) -> bool:
    if any(
        bool(getattr(row, field, False))
        for field in (
            "raw_content_retained",
            "raw_secret_retained",
            "request_content_retained",
            "response_content_retained",
        )
    ):
        return True
    return _contains_sensitive_material(getattr(row, "payload", {}))


def _contains_sensitive_material(value: object) -> bool:
    if isinstance(value, dict):
        for key, nested in value.items():
            if str(key).lower().replace("-", "_") in _FORBIDDEN_PAYLOAD_KEYS:
                if (
                    nested is not None
                    and nested is not False
                    and nested != ""
                    and nested != ()
                    and nested != []
                ):
                    return True
            if _contains_sensitive_material(nested):
                return True
        return False
    if isinstance(value, (tuple, list)):
        return any(_contains_sensitive_material(item) for item in value)
    return isinstance(value, str) and _SENSITIVE_VALUE.search(value) is not None


def _record_release_id(row: object) -> str:
    for field in ("tool_run_id", "observation_id", "claim_id", "revision_id", "id"):
        value = getattr(row, field, None)
        if isinstance(value, str) and _SAFE_ID.fullmatch(value):
            return value
    return "invalid_record_id"


def _authorization(row: CampaignAuthorizationRecord):
    try:
        value = authorization_from_payload(row.payload)
    except Exception:
        return None
    return value if value.authorization_digest == row.authorization_digest else None


def _parse_payload(contract, payload: object):
    if not isinstance(payload, dict):
        return None
    try:
        return contract.model_validate_json(
            json.dumps(payload, ensure_ascii=True, separators=(",", ":"), sort_keys=True)
        )
    except Exception:
        return None


def _campaign_rows(session, model, campaign_id: str) -> list:
    return list(
        session.scalars(
            select(model).where(model.campaign_id == campaign_id)
        ).all()
    )


def _is_loopback_host(value: str) -> bool:
    host = value.strip().lower().rstrip(".")
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _duplicate_count(values: tuple[str, ...]) -> int:
    return sum(count - 1 for count in Counter(values).values() if count > 1)


__all__ = [
    "RELEASE_COUNTER_NAMES",
    "REQUIRED_RELEASE_SOURCES",
    "ReleaseAuditSnapshot",
    "ReleaseCounters",
    "ReleaseGateResult",
    "derive_release_audit",
    "derive_release_counters",
    "evaluate_release_gate",
]
