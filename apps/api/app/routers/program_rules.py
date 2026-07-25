"""Program-rule intake endpoints (sources, snapshots, claims)."""

from __future__ import annotations

import json

from fastapi import APIRouter, Depends, HTTPException
from pydantic import ValidationError
from sqlalchemy.orm import Session

from app.config import get_settings
from app.db import get_session
from app.program_rule_intake.advisory import build_configured_program_rule_advisory
from app.program_rule_intake.contracts import (
    NormalizedRuleDocument,
    ProgramRuleClaimCompleteRequest,
    ProgramRuleClaimFailRequest,
    ProgramRuleClaimNormalizeRequest,
    ProgramRuleClaimNextResult,
    ProgramRuleRegistrationRequest,
    ProgramRuleSnapshotDiff,
    ProgramRuleSnapshotProjection,
    ProgramRuleSourceProjection,
    ProgramScopeRuleProjection,
    SnapshotReviewRequest,
)
from app.program_rule_intake.service import (
    ProgramRuleBrowserRenderRequired,
    ProgramRuleClaimRejected,
    ProgramRuleConflict,
    ProgramRuleCooldown,
    ProgramRuleIntakeError,
    ProgramRuleIntakeService,
    ProgramRuleNotFound,
    ProgramRuleValidationError,
)
from app.repository import DatabaseRepository

router = APIRouter(tags=["program-rules"])


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _program_rule_intake_service(session: Session) -> ProgramRuleIntakeService:
    settings = get_settings()
    return ProgramRuleIntakeService(
        DatabaseRepository(session),
        advisory_extractor=build_configured_program_rule_advisory(settings),
    )


def _raise_program_rule_http_error(error: ProgramRuleIntakeError) -> None:
    if isinstance(error, ProgramRuleCooldown):
        raise HTTPException(
            status_code=429,
            detail="Program rule manual refresh is cooling down",
            headers={"Retry-After": str(error.retry_after_seconds)},
        )
    if isinstance(error, ProgramRuleNotFound):
        raise HTTPException(status_code=404, detail="Program rule resource not found")
    if isinstance(error, ProgramRuleBrowserRenderRequired):
        raise HTTPException(status_code=422, detail="browser_render_required")
    if isinstance(error, ProgramRuleValidationError):
        raise HTTPException(status_code=422, detail="Program rule request is invalid")
    if isinstance(error, ProgramRuleClaimRejected):
        raise HTTPException(status_code=409, detail="Program rule claim is invalid")
    if isinstance(error, ProgramRuleConflict):
        raise HTTPException(status_code=409, detail="Program rule state conflict")
    raise HTTPException(status_code=400, detail="Program rule request failed")


def _review_program_rule_snapshot(
    *,
    source_id: str,
    snapshot_id: str,
    decision: str,
    request: SnapshotReviewRequest,
    session: Session,
) -> ProgramRuleSnapshotProjection:
    try:
        return _program_rule_intake_service(session).review_snapshot(
            source_id=source_id,
            snapshot_id=snapshot_id,
            decision=decision,
            reviewer_alias=request.reviewer_alias,
            expected_review_digest=request.expected_review_digest,
            operator_confirmed=request.operator_confirmed,
        )
    except ProgramRuleIntakeError as error:
        _raise_program_rule_http_error(error)


# ---------------------------------------------------------------------------
# Source CRUD
# ---------------------------------------------------------------------------

@router.post("/program-rule-sources", response_model=ProgramRuleSourceProjection, status_code=201)
def register_program_rule_source(
    request: ProgramRuleRegistrationRequest,
    session: Session = Depends(get_session),
) -> ProgramRuleSourceProjection:
    try:
        return _program_rule_intake_service(session).register_source(
            program_alias=request.program_alias,
            public_rule_url=request.public_rule_url,
        )
    except ProgramRuleIntakeError as error:
        _raise_program_rule_http_error(error)


@router.get("/program-rule-sources", response_model=list[ProgramRuleSourceProjection])
def list_program_rule_sources(
    session: Session = Depends(get_session),
) -> list[ProgramRuleSourceProjection]:
    return _program_rule_intake_service(session).list_sources()


@router.get("/program-rule-sources/{source_id}", response_model=ProgramRuleSourceProjection)
def get_program_rule_source(
    source_id: str,
    session: Session = Depends(get_session),
) -> ProgramRuleSourceProjection:
    try:
        return _program_rule_intake_service(session).get_source(source_id)
    except ProgramRuleIntakeError as error:
        _raise_program_rule_http_error(error)


@router.post(
    "/program-rule-sources/{source_id}/refresh",
    response_model=ProgramRuleSourceProjection,
    status_code=202,
)
def refresh_program_rule_source(
    source_id: str,
    session: Session = Depends(get_session),
) -> ProgramRuleSourceProjection:
    try:
        return _program_rule_intake_service(session).request_refresh(source_id)
    except ProgramRuleIntakeError as error:
        _raise_program_rule_http_error(error)


@router.get(
    "/program-rule-sources/{source_id}/snapshots",
    response_model=list[ProgramRuleSnapshotProjection],
)
def list_program_rule_source_snapshots(
    source_id: str,
    session: Session = Depends(get_session),
) -> list[ProgramRuleSnapshotProjection]:
    try:
        return _program_rule_intake_service(session).list_snapshots(source_id)
    except ProgramRuleIntakeError as error:
        _raise_program_rule_http_error(error)


@router.get(
    "/program-rule-sources/{source_id}/snapshots/{snapshot_id}/diff",
    response_model=ProgramRuleSnapshotDiff,
)
def get_program_rule_snapshot_diff(
    source_id: str,
    snapshot_id: str,
    session: Session = Depends(get_session),
) -> ProgramRuleSnapshotDiff:
    try:
        return _program_rule_intake_service(session).get_snapshot_diff(source_id, snapshot_id)
    except ProgramRuleIntakeError as error:
        _raise_program_rule_http_error(error)


@router.post(
    "/program-rule-sources/{source_id}/snapshots/{snapshot_id}/approve",
    response_model=ProgramRuleSnapshotProjection,
)
def approve_program_rule_snapshot(
    source_id: str,
    snapshot_id: str,
    request: SnapshotReviewRequest,
    session: Session = Depends(get_session),
) -> ProgramRuleSnapshotProjection:
    return _review_program_rule_snapshot(
        source_id=source_id,
        snapshot_id=snapshot_id,
        decision="approved",
        request=request,
        session=session,
    )


@router.post(
    "/program-rule-sources/{source_id}/snapshots/{snapshot_id}/reject",
    response_model=ProgramRuleSnapshotProjection,
)
def reject_program_rule_snapshot(
    source_id: str,
    snapshot_id: str,
    request: SnapshotReviewRequest,
    session: Session = Depends(get_session),
) -> ProgramRuleSnapshotProjection:
    return _review_program_rule_snapshot(
        source_id=source_id,
        snapshot_id=snapshot_id,
        decision="rejected",
        request=request,
        session=session,
    )


@router.get(
    "/programs/{program_id}/scope-rules",
    response_model=list[ProgramScopeRuleProjection],
)
def list_program_scope_rules(
    program_id: str,
    session: Session = Depends(get_session),
) -> list[ProgramScopeRuleProjection]:
    try:
        return _program_rule_intake_service(session).list_scope_rules(program_id)
    except ProgramRuleIntakeError as error:
        _raise_program_rule_http_error(error)


# ---------------------------------------------------------------------------
# Studio fetch-worker claims
# ---------------------------------------------------------------------------

@router.post(
    "/mythos/studio/program-rule-fetch/claims/next",
    response_model=ProgramRuleClaimNextResult,
)
def claim_next_program_rule_source(
    session: Session = Depends(get_session),
) -> ProgramRuleClaimNextResult:
    return _program_rule_intake_service(session).claim_next()


@router.post(
    "/mythos/studio/program-rule-fetch/claims/{claim_id}/normalize",
    response_model=NormalizedRuleDocument,
)
def normalize_program_rule_claim_document(
    claim_id: str,
    request: ProgramRuleClaimNormalizeRequest,
    session: Session = Depends(get_session),
) -> NormalizedRuleDocument:
    try:
        return _program_rule_intake_service(session).normalize_claim_document(
            claim_id=claim_id,
            source_id=request.source_id,
            claim_token=request.claim_token,
            envelope=request.document,
        )
    except ProgramRuleIntakeError as error:
        _raise_program_rule_http_error(error)


@router.post(
    "/mythos/studio/program-rule-fetch/claims/{claim_id}/complete",
    response_model=ProgramRuleSnapshotProjection,
)
async def complete_program_rule_claim(
    claim_id: str,
    request: ProgramRuleClaimCompleteRequest,
    session: Session = Depends(get_session),
) -> ProgramRuleSnapshotProjection:
    try:
        documents = [
            NormalizedRuleDocument.model_validate_json(
                json.dumps(document, separators=(",", ":"))
            )
            for document in request.documents
        ]
        return await _program_rule_intake_service(session).complete_claim(
            claim_id=claim_id,
            source_id=request.source_id,
            claim_token=request.claim_token,
            documents=documents,
        )
    except ValidationError:
        raise HTTPException(status_code=422, detail="Program rule request is invalid")
    except ProgramRuleIntakeError as error:
        _raise_program_rule_http_error(error)


@router.post(
    "/mythos/studio/program-rule-fetch/claims/{claim_id}/fail",
    response_model=ProgramRuleSourceProjection,
)
def fail_program_rule_claim(
    claim_id: str,
    request: ProgramRuleClaimFailRequest,
    session: Session = Depends(get_session),
) -> ProgramRuleSourceProjection:
    try:
        return _program_rule_intake_service(session).fail_claim(
            claim_id=claim_id,
            source_id=request.source_id,
            claim_token=request.claim_token,
            failure_code=request.failure_code.value,
        )
    except ProgramRuleIntakeError as error:
        _raise_program_rule_http_error(error)
