from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime
from hashlib import sha256
import json
from statistics import median
from typing import Any

from app.candidate_hunter_loop import (
    REQUIRED_ARTIFACT_KINDS,
    STAGE_KEYS as CANDIDATE_HUNTER_STAGE_KEYS,
    load_candidate_hunter_projection,
)
from app.mythos_report import build_report_preview_response, safe_preview_text
from app.repository import DatabaseRepository

from .contracts import (
    AgentStageSummary,
    AuthorizedAssetSummary,
    CampaignOverviewSummary,
    CandidateQueueSummary,
    ControlCenterOverviewResponse,
    OperationalMetrics,
    ReportReadinessSummary,
    ResearchQualitySummary,
    SanitizedEventSummary,
)


ACTIVE_TASK_STATUSES = {"dispatched", "in_progress", "running"}
PENDING_APPROVAL_STATUSES = {"pending", "requested"}
SAFETY_BLOCK_REASONS = {
    "policy_blocked",
    "report_chain_unsafe",
    "scope_not_in_scope",
}
SAFETY_BLOCK_STAGE_KEYS = {
    "policy_review",
    "safety_review",
    "scope_guard_review",
}
STAGE_GROUPS = {
    "policy": ("policy", "scope_guard", "intake"),
    "target_modeling": ("target", "surface", "codebase_map"),
    "code_api_audit": ("audit", "scanner", "candidate_hunter_snapshot"),
    "refutation": ("refutation", "candidate_hunter_decision", "candidate_hunter_rerank"),
    "report_drafting": ("report", "finding_promotion"),
}
SAFE_EVIDENCE_KINDS = set(REQUIRED_ARTIFACT_KINDS)


class ControlCenterCampaignNotFound(LookupError):
    pass


CampaignResponseBuilder = Callable[[Any, DatabaseRepository], Any]


def build_control_center_overview(
    repository: DatabaseRepository,
    campaign_id: str | None = None,
    *,
    now: datetime | None = None,
    campaign_response_builder: CampaignResponseBuilder | None = None,
) -> ControlCenterOverviewResponse:
    generated_at = _as_utc(now or datetime.now(UTC))
    campaigns = repository.list_campaigns()
    if campaign_id is not None:
        campaign = repository.get_campaign(campaign_id)
        if campaign is None:
            raise ControlCenterCampaignNotFound(campaign_id)
        campaigns = [campaign]

    response_builder = campaign_response_builder or _default_campaign_response_builder()
    controls = [response_builder(campaign, repository) for campaign in campaigns]
    tasks = [task for control in controls for task in control.tasks]
    approvals = [approval for control in controls for approval in control.approvals]
    stages = [stage for control in controls for stage in control.pipeline_stages]

    pipeline_run_campaigns = _pipeline_run_campaigns(stages)
    hunter_run_campaigns = _hunter_run_campaigns(stages)
    (
        candidates,
        generated_count,
        challenged_count,
        refuted_count,
        evidence_counts,
        invalid_run_count,
    ) = _candidate_projection_summaries(repository, hunter_run_campaigns)
    blocked_reason_count = _safety_block_count(controls, stages) + invalid_run_count
    approval_pressure_count = sum(
        approval.status in PENDING_APPROVAL_STATUSES
        and _approval_is_active(approval.expires_at, generated_at)
        for approval in approvals
    )
    review_seconds = [
        max(
            (_as_utc(approval.decided_at) - _as_utc(approval.created_at)).total_seconds(),
            0,
        )
        for approval in approvals
        if approval.decided_at is not None
    ]
    evidence_satisfied, evidence_required = evidence_counts

    overview = ControlCenterOverviewResponse(
        data_mode="live",
        generated_at=generated_at,
        snapshot_version="0" * 64,
        empty_state=not campaigns,
        metrics=OperationalMetrics(
            running_task_count=sum(task.status in ACTIVE_TASK_STATUSES for task in tasks),
            retained_high_value_candidate_count=len(candidates),
            approval_pressure_count=approval_pressure_count,
            safety_block_count=blocked_reason_count,
        ),
        agent_stages=_agent_stage_summaries(stages),
        authorized_assets=[
            AuthorizedAssetSummary(
                campaign_id=control.campaign.id,
                asset=control.campaign.default_asset,
                scope_status=control.campaign.scope_status,
                campaign_status=control.campaign.status,
            )
            for control in controls
        ],
        campaigns=[
            CampaignOverviewSummary(
                id=control.campaign.id,
                name=control.campaign.name,
                status=control.campaign.status,
                scope_status=control.campaign.scope_status,
                safe_next_action=control.safe_next_action,
                blocked_reasons=control.blocked_reasons,
            )
            for control in controls
        ],
        candidates=candidates,
        research_quality=ResearchQualitySummary(
            retention_rate=_ratio(len(candidates), generated_count),
            refutation_kill_rate=_ratio(refuted_count, challenged_count),
            evidence_completeness=_ratio(evidence_satisfied, evidence_required),
            median_human_review_seconds=(
                float(median(review_seconds)) if review_seconds else None
            ),
        ),
        report_readiness=_latest_report_readiness(repository, pipeline_run_campaigns),
        recent_events=_recent_events(tasks, stages),
    )
    overview.snapshot_version = _snapshot_version(overview)
    return overview


def _default_campaign_response_builder() -> CampaignResponseBuilder:
    from app.main import _campaign_control_center_response

    return _campaign_control_center_response


def _hunter_run_campaigns(stages: list[Any]) -> dict[str, str]:
    return {
        stage.pipeline_run_id: stage.campaign_id
        for stage in stages
        if stage.pipeline_run_id
        and stage.campaign_id
        and stage.stage_key in CANDIDATE_HUNTER_STAGE_KEYS
    }


def _pipeline_run_campaigns(stages: list[Any]) -> dict[str, str]:
    return {
        stage.pipeline_run_id: stage.campaign_id
        for stage in stages
        if stage.pipeline_run_id and stage.campaign_id
    }


def _candidate_projection_summaries(
    repository: DatabaseRepository,
    run_campaigns: dict[str, str],
) -> tuple[list[CandidateQueueSummary], int, int, int, tuple[int, int], int]:
    summaries = []
    generated_count = 0
    challenged_count = 0
    refuted_count = 0
    evidence_satisfied = 0
    evidence_required = 0
    invalid_run_count = 0
    for run_id, campaign_id in sorted(run_campaigns.items()):
        projection = load_candidate_hunter_projection(
            repository=repository,
            pipeline_run_id=run_id,
        )
        if projection.get("status") != "ready":
            invalid_run_count += 1
            continue
        decisions = projection["candidate_decisions"]
        candidate_states = _latest_validated_candidate_states(
            repository,
            run_id,
            projection,
        )
        generated_ids = {
            candidate_id
            for candidate in candidate_states
            if (candidate_id := _safe_candidate_id(candidate))
        }
        generated_ids.update(
            candidate_id
            for decision in decisions
            if (candidate_id := _safe_candidate_id(decision))
        )
        generated_count += len(generated_ids)
        challenged_count += sum(
            isinstance(decision, dict)
            and decision.get("disposition")
            in {"retained", "refuted", "deduplicated", "suppressed"}
            for decision in decisions
        )
        refuted_count += sum(
            isinstance(decision, dict) and decision.get("disposition") == "refuted"
            for decision in decisions
        )
        for candidate in candidate_states:
            required_kinds = _safe_string_set(
                candidate.get("required_artifact_kinds")
            ).intersection(SAFE_EVIDENCE_KINDS)
            if not required_kinds:
                continue
            observed_kinds = _safe_string_set(
                candidate.get("observed_artifact_kinds")
            ).intersection(SAFE_EVIDENCE_KINDS)
            evidence_satisfied += len(required_kinds.intersection(observed_kinds))
            evidence_required += len(required_kinds)
        for candidate in projection["final_candidates"]:
            route = candidate.get("route") if isinstance(candidate.get("route"), dict) else {}
            method = safe_preview_text(route.get("method", ""))
            path = safe_preview_text(route.get("path", ""))
            summaries.append(
                CandidateQueueSummary(
                    candidate_id=safe_preview_text(candidate.get("candidate_id", "candidate")),
                    campaign_id=campaign_id,
                    pipeline_run_id=run_id,
                    rank=candidate["rank"],
                    vuln_type=safe_preview_text(candidate.get("vuln_type", "unknown")),
                    affected_endpoint=safe_preview_text(f"{method} {path}".strip()),
                    affected_code_path=(
                        safe_preview_text(candidate["affected_code_path"])
                        if candidate.get("affected_code_path")
                        else None
                    ),
                    evidence_trace_status=safe_preview_text(
                        candidate.get("evidence_trace_status", "unknown")
                    ),
                    human_validation_readiness=safe_preview_text(
                        candidate.get("human_validation_readiness", "unknown")
                    ),
                    report_submission_allowed=False,
                )
            )
    summaries.sort(key=lambda item: (item.rank, item.candidate_id, item.pipeline_run_id))
    return (
        summaries,
        generated_count,
        challenged_count,
        refuted_count,
        (evidence_satisfied, evidence_required),
        invalid_run_count,
    )


def _latest_report_readiness(
    repository: DatabaseRepository,
    run_campaigns: dict[str, str],
) -> ReportReadinessSummary:
    records = [
        record
        for run_id in run_campaigns
        if (record := repository.get_pipeline_run(run_id)) is not None
    ]
    records.sort(key=lambda record: (record.created_at, record.id), reverse=True)
    for record in records:
        try:
            preview = build_report_preview_response(record)
        except ValueError:
            continue
        return ReportReadinessSummary(
            available=True,
            status="submission_blocked" if preview.submission_blocked else "human_review_required",
            pipeline_run_id=record.id,
            title=preview.title,
            claim_count=len(preview.claim_ledger),
            evidence_ref_count=len(preview.evidence_refs),
            human_review_required=preview.human_review_required,
            submission_blocked=preview.submission_blocked,
            report_submission_allowed=False,
        )
    return ReportReadinessSummary(
        available=False,
        status="unavailable",
        human_review_required=True,
        submission_blocked=True,
        report_submission_allowed=False,
    )


def _agent_stage_summaries(stages: list[Any]) -> list[AgentStageSummary]:
    summaries = []
    for stage_name, markers in STAGE_GROUPS.items():
        matching = [stage for stage in stages if any(marker in stage.stage_key for marker in markers)]
        statuses = {stage.status for stage in matching}
        if statuses.intersection({"blocked", "failed", "paused"}):
            status = "blocked"
        elif statuses.intersection({"running", "dispatched", "in_progress"}):
            status = "running"
        elif matching and statuses == {"completed"}:
            status = "completed"
        elif matching:
            status = "waiting"
        else:
            status = "not_started"
        summaries.append(
            AgentStageSummary(stage=stage_name, status=status, record_count=len(matching))
        )
    return summaries


def _recent_events(tasks: list[Any], stages: list[Any]) -> list[SanitizedEventSummary]:
    events = [
        SanitizedEventSummary(
            event_id=task.id,
            campaign_id=task.campaign_id,
            event_type="research_task",
            status=safe_preview_text(task.status),
            occurred_at=_as_utc(task.created_at),
        )
        for task in tasks
    ]
    events.extend(
        SanitizedEventSummary(
            event_id=stage.id,
            campaign_id=stage.campaign_id,
            event_type="pipeline_stage",
            status=safe_preview_text(stage.status),
            occurred_at=_as_utc(stage.created_at),
        )
        for stage in stages
        if stage.campaign_id
    )
    events.sort(key=lambda event: (event.occurred_at, event.event_id), reverse=True)
    return events[:20]


def _approval_is_active(expires_at: datetime | str | None, now: datetime) -> bool:
    if expires_at is None:
        return True
    return _as_utc(expires_at) > _as_utc(now)


def _latest_validated_candidate_states(
    repository: DatabaseRepository,
    run_id: str,
    projection: dict[str, Any],
) -> list[dict[str, Any]]:
    stage_refs = projection.get("audit", {}).get("stage_refs", [])
    snapshot_refs = [
        ref
        for ref in stage_refs
        if isinstance(ref, dict) and ref.get("stage_key") == "candidate_hunter_snapshot"
    ]
    if not snapshot_refs:
        return []
    latest_ref = max(snapshot_refs, key=lambda ref: ref.get("round", 0))
    stage_by_id = {
        stage.id: stage
        for stage in repository.list_pipeline_stages_for_run(run_id)
        if stage.stage_key in CANDIDATE_HUNTER_STAGE_KEYS
    }
    stage = stage_by_id.get(latest_ref.get("stage_id"))
    payload = stage.payload if stage is not None and isinstance(stage.payload, dict) else {}
    candidates = payload.get("snapshot_candidates")
    if not isinstance(candidates, list):
        return []
    return [candidate for candidate in candidates if isinstance(candidate, dict)]


def _safe_candidate_id(value: Any) -> str:
    if not isinstance(value, dict):
        return ""
    candidate_id = value.get("candidate_id")
    return candidate_id if isinstance(candidate_id, str) and candidate_id else ""


def _safe_string_set(value: Any) -> set[str]:
    if not isinstance(value, list):
        return set()
    return {item for item in value if isinstance(item, str) and item}


def _safety_block_count(controls: list[Any], stages: list[Any]) -> int:
    blocks = {
        (control.campaign.id, reason)
        for control in controls
        for reason in control.blocked_reasons
        if reason in SAFETY_BLOCK_REASONS
    }
    blocks.update(
        (stage.campaign_id, stage.id)
        for stage in stages
        if stage.campaign_id
        and stage.stage_key in SAFETY_BLOCK_STAGE_KEYS
        and stage.status == "blocked"
        and stage.safety_gate_state == "blocked"
    )
    return len(blocks)


def _as_utc(value: datetime | str) -> datetime:
    parsed = datetime.fromisoformat(value) if isinstance(value, str) else value
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        return parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def _ratio(numerator: int, denominator: int) -> float | None:
    return round(numerator / denominator, 4) if denominator else None


def _snapshot_version(overview: ControlCenterOverviewResponse) -> str:
    safe_projection = overview.model_dump(mode="json")
    safe_projection.pop("generated_at", None)
    safe_projection.pop("snapshot_version", None)
    canonical = json.dumps(
        safe_projection,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    )
    return sha256(canonical.encode("utf-8")).hexdigest()
