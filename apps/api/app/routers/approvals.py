"""Approval-record endpoints."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.db import get_session
from app.db_models import ApprovalRecord
from app.repository import APPROVAL_TERMINAL_STATUSES, DatabaseRepository, approval_record_is_active
from app.routers._responses import approval_record_response
from app.routers._shared import _program_or_404_in_scope, _raise_if_campaign_scoped_run_not_in_scope
from app.schemas import ApprovalDecisionRequest, ApprovalRecordRequest, ApprovalRecordResponse

router = APIRouter(tags=["approvals"])


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _decide_approval_record_response(
    approval_id: str,
    request: ApprovalDecisionRequest,
    session: Session,
) -> ApprovalRecordResponse:
    repository = DatabaseRepository(session)
    current_record = repository.session.get(ApprovalRecord, approval_id)
    if current_record is None:
        raise HTTPException(status_code=404, detail="Approval record not found")
    if current_record.status in APPROVAL_TERMINAL_STATUSES:
        raise HTTPException(status_code=409, detail="Approval record already terminal")
    if current_record.status == request.decision and current_record.decided_at is not None:
        raise HTTPException(status_code=409, detail="Approval record already decided")
    if request.decision == "approved" and not approval_record_is_active(current_record):
        raise HTTPException(status_code=409, detail="Approval record expired")
    if request.decision == "approved" and current_record.program_id is not None:
        _program_or_404_in_scope(
            repository,
            current_record.program_id,
            asset=current_record.asset,
            validation_type=current_record.validation_mode,
            enforce_current_rule=True,
        )
    if request.decision == "approved" and current_record.campaign_id is not None:
        campaign = repository.get_campaign(current_record.campaign_id)
        if campaign is None:
            raise HTTPException(status_code=404, detail="Campaign not found")
        if campaign.scope_status != "in_scope":
            raise HTTPException(status_code=409, detail="scope_not_in_scope")
    record = repository.decide_approval_record(
        approval_id=approval_id,
        decision=request.decision,
        actor=request.actor,
        reason=request.reason,
    )
    return approval_record_response(record)


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@router.post("/mythos/approval-records", response_model=ApprovalRecordResponse)
def create_approval_record(
    request: ApprovalRecordRequest,
    session: Session = Depends(get_session),
) -> ApprovalRecordResponse:
    repository = DatabaseRepository(session)
    if request.program_id is not None:
        _program_or_404_in_scope(
            repository,
            request.program_id,
            asset=request.asset,
            validation_type=request.validation_mode,
            enforce_current_rule=True,
        )
    if request.run_id is not None:
        if repository.get_pipeline_run(request.run_id) is None:
            raise HTTPException(status_code=404, detail="Pipeline run not found")
        _raise_if_campaign_scoped_run_not_in_scope(repository, request.run_id)
    record = repository.create_approval_record(
        run_id=request.run_id,
        program_id=request.program_id,
        asset=request.asset,
        validation_mode=request.validation_mode,
        plan_digest=request.plan_digest,
        expires_at=request.expires_at,
        requester=request.requester,
        reason=request.reason,
        status="requested",
    )
    return approval_record_response(record)


@router.get("/mythos/approval-records", response_model=list[ApprovalRecordResponse])
def list_approval_records(
    run_id: str | None = None,
    session: Session = Depends(get_session),
) -> list[ApprovalRecordResponse]:
    return [
        approval_record_response(record)
        for record in DatabaseRepository(session).list_approval_records(run_id=run_id)
    ]


@router.post(
    "/mythos/approval-records/{approval_id}/decisions",
    response_model=ApprovalRecordResponse,
)
def decide_approval_record(
    approval_id: str,
    request: ApprovalDecisionRequest,
    session: Session = Depends(get_session),
) -> ApprovalRecordResponse:
    return _decide_approval_record_response(approval_id, request, session)


@router.post(
    "/mythos/approvals/{approval_id}/decisions",
    response_model=ApprovalRecordResponse,
)
def decide_mythos_approval(
    approval_id: str,
    request: ApprovalDecisionRequest,
    session: Session = Depends(get_session),
) -> ApprovalRecordResponse:
    return _decide_approval_record_response(approval_id, request, session)
