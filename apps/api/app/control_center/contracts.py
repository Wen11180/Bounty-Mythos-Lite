from datetime import UTC, datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator


class StrictResponseModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class OperationalMetrics(StrictResponseModel):
    running_task_count: int = Field(ge=0)
    retained_high_value_candidate_count: int = Field(ge=0)
    approval_pressure_count: int = Field(ge=0)
    safety_block_count: int = Field(ge=0)


class AgentStageSummary(StrictResponseModel):
    stage: str
    status: str
    record_count: int = Field(ge=0)


class AuthorizedAssetSummary(StrictResponseModel):
    campaign_id: str
    asset: str
    scope_status: str
    campaign_status: str


class CampaignOverviewSummary(StrictResponseModel):
    id: str
    name: str
    status: str
    scope_status: str
    safe_next_action: str
    blocked_reasons: list[str] = Field(default_factory=list)


class CandidateQueueSummary(StrictResponseModel):
    candidate_id: str
    campaign_id: str
    pipeline_run_id: str
    rank: int = Field(ge=1, le=5)
    vuln_type: str
    affected_endpoint: str
    affected_code_path: str | None = None
    evidence_trace_status: str
    human_validation_readiness: str
    report_submission_allowed: Literal[False] = False


class ResearchQualitySummary(StrictResponseModel):
    retention_rate: float | None = Field(default=None, ge=0, le=1)
    refutation_kill_rate: float | None = Field(default=None, ge=0, le=1)
    evidence_completeness: float | None = Field(default=None, ge=0, le=1)
    median_human_review_seconds: float | None = Field(default=None, ge=0)


class AutonomousWakeupHealthSummary(StrictResponseModel):
    status: Literal[
        "not_started",
        "active",
        "healthy",
        "degraded",
        "expired_lease",
        "invalid_lease",
        "stale",
    ]
    last_heartbeat_at: datetime | None = None
    heartbeat_age_seconds: int | None = Field(default=None, ge=0)
    lease_active: bool
    lease_expires_at: datetime | None = None
    has_more_campaigns: bool
    scheduled_interval_seconds: int = Field(ge=1)
    last_cycle_completed_at: datetime | None = None
    last_cycle_status: Literal["not_finished", "completed", "failed"]
    last_cycle_stop_reason: Literal[
        "wakeup_candidate_invalid",
        "wakeup_candidate_query_failed",
        "wakeup_campaign_tick_failed",
    ] | None = None
    last_cycle_processed_count: int = Field(ge=0)
    last_cycle_outcome_counts: dict[str, int] = Field(default_factory=dict)
    execution_allowed: Literal[False] = False
    dispatch_allowed: Literal[False] = False
    validation_allowed: Literal[False] = False
    candidate_promotion_allowed: Literal[False] = False
    report_submission_allowed: Literal[False] = False


class ReportReadinessSummary(StrictResponseModel):
    available: bool
    status: str
    pipeline_run_id: str | None = None
    title: str | None = None
    claim_count: int | None = Field(default=None, ge=0)
    evidence_ref_count: int | None = Field(default=None, ge=0)
    human_review_required: bool
    submission_blocked: bool
    report_submission_allowed: Literal[False] = False


class SanitizedEventSummary(StrictResponseModel):
    event_id: str
    campaign_id: str
    event_type: str
    status: str
    occurred_at: datetime

    @field_validator("occurred_at")
    @classmethod
    def require_aware_utc(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("occurred_at must be timezone-aware")
        return value.astimezone(UTC)


class ControlCenterOverviewResponse(StrictResponseModel):
    data_mode: Literal["live"]
    generated_at: datetime
    snapshot_version: str = Field(pattern=r"^[0-9a-f]{64}$")
    empty_state: bool
    metrics: OperationalMetrics
    agent_stages: list[AgentStageSummary] = Field(default_factory=list)
    authorized_assets: list[AuthorizedAssetSummary] = Field(default_factory=list)
    campaigns: list[CampaignOverviewSummary] = Field(default_factory=list)
    candidates: list[CandidateQueueSummary] = Field(default_factory=list)
    research_quality: ResearchQualitySummary
    autonomous_wakeup: AutonomousWakeupHealthSummary | None = None
    report_readiness: ReportReadinessSummary
    recent_events: list[SanitizedEventSummary] = Field(default_factory=list)

    @field_validator("generated_at")
    @classmethod
    def require_aware_utc(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("generated_at must be timezone-aware")
        return value.astimezone(UTC)
