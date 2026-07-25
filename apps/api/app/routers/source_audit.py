"""Source-audit scan endpoint."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.db import get_session
from app.repository import DatabaseRepository
from app.routers._shared import _build_report_preview_response_or_404
from app.schemas import SourceAuditScanRequest, SourceAuditScanResponse
from app.source_audit import SourceAuditBlocked, run_source_audit, save_source_audit_pipeline_run
from app.studio_workspace import resolve_configured_workspace_artifact
from app.mythos_report import safe_preview_text, safe_string_list

router = APIRouter(prefix="/mythos/source-audit", tags=["source-audit"])


def _read_source_audit_policy_text(scope_path: str) -> str:
    from pathlib import Path
    try:
        return Path(scope_path).read_text(encoding="utf-8-sig")
    except OSError:
        return "source audit scope policy unavailable"


@router.post("/scans", response_model=SourceAuditScanResponse)
def run_mythos_source_audit_scan(
    request: SourceAuditScanRequest,
    session: Session = Depends(get_session),
) -> SourceAuditScanResponse:
    from app.routers._shared import _program_or_404_in_scope
    repository = DatabaseRepository(session)
    if request.program_id is not None:
        _program_or_404_in_scope(repository, request.program_id)
    try:
        repo_path = resolve_configured_workspace_artifact(request.repo_path, kind="code")
        scope_path = resolve_configured_workspace_artifact(request.scope_path, kind="scope")
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail="source_audit_artifact_not_found") from exc
    try:
        result = run_source_audit(
            str(repo_path),
            str(scope_path),
            patch_diff_metadata=request.patch_diff_metadata,
        )
    except SourceAuditBlocked as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc

    record = save_source_audit_pipeline_run(
        repository=repository,
        result=result,
        policy_text=(
            request.policy_text
            if request.policy_text is not None
            else _read_source_audit_policy_text(str(scope_path))
        ),
        program_id=request.program_id,
    )
    preview = _build_report_preview_response_or_404(record, repository)
    payload = record.payload if isinstance(record.payload, dict) else {}
    artifact = payload.get("artifact") if isinstance(payload, dict) else {}
    artifact_id = artifact.get("artifact_id") if isinstance(artifact, dict) else ""
    safety_notes = payload.get("safety_notes") or []
    safety_gate_summary = payload.get("safety_gate_summary") or {}
    timeline_stage_summary = payload.get("timeline_stage_summary") or []
    audit_gate_summary = payload.get("audit_gate_summary") or {}
    return SourceAuditScanResponse(
        run_id=record.id,
        artifact_id=safe_preview_text(artifact_id),
        report_title=safe_preview_text(record.report_title or preview.title),
        scope_status=safe_preview_text(record.scope_status),
        hypothesis_count=record.hypothesis_count,
        submission_blocked=preview.submission_blocked,
        safety_notes=safe_string_list(safety_notes),
        safety_gate_summary=safety_gate_summary if isinstance(safety_gate_summary, dict) else {},
        audit_gate_summary=audit_gate_summary if isinstance(audit_gate_summary, dict) else {},
        timeline_stage_summary=timeline_stage_summary if isinstance(timeline_stage_summary, list) else [],
    )
