"""Pipeline run endpoints (list, get, report preview).

The dry-run endpoint and the more complex routes (claim review decisions,
finding candidates, observation/manual-result endpoints) remain in main.py
pending extraction of their supporting helper functions.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.db import get_session
from app.db_models import PipelineRunRecord
from app.mythos_report import ReportPreviewResponse
from app.repository import DatabaseRepository
from app.routers._shared import _build_report_preview_response_or_404
from app.schemas import MythosPipelineRunDetail, MythosPipelineRunSummary

router = APIRouter(prefix="/mythos/pipeline", tags=["pipeline"])


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _count_evidence_items(payload: dict) -> int:
    evidence_bundle = payload.get("evidence_bundle")
    if not isinstance(evidence_bundle, dict):
        return 0
    items = evidence_bundle.get("items")
    return len(items) if isinstance(items, list) else 0


def _pipeline_run_summary(
    record: PipelineRunRecord,
    repository: DatabaseRepository | None = None,
) -> MythosPipelineRunSummary:
    payload = record.payload
    return MythosPipelineRunSummary(
        id=record.id,
        program_id=record.program_id,
        asset=record.asset,
        policy_text_hash=record.policy_text_hash,
        scope_status=record.scope_status,
        hypothesis_count=record.hypothesis_count,
        blocked_count=record.blocked_count,
        evidence_count=_count_evidence_items(payload),
        report_title=record.report_title,
        created_at=record.created_at.isoformat(),
        timeline=payload.get("timeline", []),
        artifact=payload.get("artifact"),
        validation_gate=payload.get("validation_gate"),
        hunter_intelligence=payload.get("hunter_intelligence"),
        safety_gate_summary=(
            payload.get("safety_gate_summary")
            if isinstance(payload.get("safety_gate_summary"), dict)
            else {}
        ),
        audit_gate_summary=(
            payload.get("audit_gate_summary")
            if isinstance(payload.get("audit_gate_summary"), dict)
            else {}
        ),
        timeline_stage_summary=(
            payload.get("timeline_stage_summary")
            if isinstance(payload.get("timeline_stage_summary"), list)
            else []
        ),
    )


def _pipeline_run_detail(
    record: PipelineRunRecord,
    repository: DatabaseRepository,
) -> MythosPipelineRunDetail:
    summary = _pipeline_run_summary(record, repository)
    payload = record.payload if isinstance(record.payload, dict) else {}
    return MythosPipelineRunDetail(
        id=summary.id,
        program_id=summary.program_id,
        asset=summary.asset,
        policy_text_hash=summary.policy_text_hash,
        scope_status=summary.scope_status,
        hypothesis_count=summary.hypothesis_count,
        blocked_count=summary.blocked_count,
        evidence_count=summary.evidence_count,
        report_title=summary.report_title,
        created_at=summary.created_at,
        timeline=summary.timeline,
        artifact=summary.artifact,
        validation_gate=summary.validation_gate,
        hunter_intelligence=summary.hunter_intelligence,
        evidence_support_summary=summary.evidence_support_summary,
        closed_loop_summary=summary.closed_loop_summary,
        payload=payload,
    )


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

# NOTE: /dry-run stays in main.py — it saves artifacts + pipeline run records
# and depends on ~30 helper functions not yet extracted.

@router.get("/runs", response_model=list[MythosPipelineRunSummary])
def list_mythos_pipeline_runs(
    session: Session = Depends(get_session),
) -> list[MythosPipelineRunSummary]:
    repository = DatabaseRepository(session)
    return [
        _pipeline_run_summary(record, repository)
        for record in repository.list_pipeline_runs()
    ]


@router.get("/runs/{run_id}", response_model=MythosPipelineRunDetail)
def get_mythos_pipeline_run(
    run_id: str,
    session: Session = Depends(get_session),
) -> MythosPipelineRunDetail:
    repository = DatabaseRepository(session)
    record = repository.get_pipeline_run(run_id)
    if record is None:
        raise HTTPException(status_code=404, detail="Pipeline run not found")
    return _pipeline_run_detail(record, repository)


@router.get("/runs/{run_id}/report-preview", response_model=ReportPreviewResponse)
def get_mythos_pipeline_report_preview(
    run_id: str,
    session: Session = Depends(get_session),
) -> ReportPreviewResponse:
    repository = DatabaseRepository(session)
    record = repository.get_pipeline_run(run_id)
    if record is None:
        raise HTTPException(status_code=404, detail="Pipeline run not found")
    return _build_report_preview_response_or_404(record, repository)
