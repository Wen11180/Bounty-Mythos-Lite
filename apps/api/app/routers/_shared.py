"""Shared helpers used by multiple router modules.

These functions were extracted from main.py and are imported by individual
router files instead of being duplicated.
"""

from __future__ import annotations

from datetime import UTC, datetime

from fastapi import HTTPException
from sqlalchemy.orm import Session

from app.db_models import PipelineRunRecord
from app.llm.base import LLMResponse
from app.mythos_report import ReportPreviewResponse, build_report_preview_response
from app.program_rule_intake.scope_resolver import resolve_effective_program_rule
from app.repository import DatabaseRepository
from app.scope_guard import ScopeGuardRule, ValidationRequest, evaluate_validation_request


# ---------------------------------------------------------------------------
# Program / scope helpers
# ---------------------------------------------------------------------------

def _program_or_404_in_scope(
    repository: DatabaseRepository,
    program_id: str,
    *,
    asset: str | None = None,
    validation_type: str | None = None,
    enforce_current_rule: bool = False,
):
    program = repository.get_program(program_id)
    if program is None:
        raise HTTPException(status_code=404, detail="Program not found")
    if program.scope_status != "in_scope":
        raise HTTPException(status_code=409, detail="scope_not_in_scope")
    if enforce_current_rule and asset is None and any(
        source.program_id == program_id
        for source in repository.list_program_rule_sources()
    ):
        raise HTTPException(status_code=409, detail="program_rule_asset_required")
    if asset is not None:
        resolution = resolve_effective_program_rule(
            repository,
            program_id,
            asset,
            datetime.now(UTC),
        )
        if resolution.source_backed:
            if resolution.reason is not None or resolution.rule is None:
                raise HTTPException(
                    status_code=409,
                    detail=resolution.reason or "program_rule_not_authorizing",
                )
            if validation_type is None:
                raise HTTPException(
                    status_code=409,
                    detail="program_rule_validation_type_required",
                )
            decision = evaluate_validation_request(
                resolution.rule,
                ValidationRequest(
                    asset=asset,
                    validation_type=validation_type,
                    human_approved=True,
                ),
            )
            if not decision.allowed:
                raise HTTPException(status_code=409, detail=decision.reason)
    return program


# ---------------------------------------------------------------------------
# Pipeline run / scope helpers
# ---------------------------------------------------------------------------

def _raise_if_campaign_scoped_run_not_in_scope(
    repository: DatabaseRepository,
    run_id: str,
) -> None:
    run = repository.get_pipeline_run(run_id)
    if run is None:
        raise HTTPException(status_code=404, detail="Pipeline run not found")
    if run.scope_status != "in_scope":
        raise HTTPException(status_code=409, detail="scope_not_in_scope")
    if _campaign_scoped_run_has_out_of_scope_campaign(repository, run_id):
        raise HTTPException(status_code=409, detail="scope_not_in_scope")


def _campaign_scoped_run_has_out_of_scope_campaign(
    repository: DatabaseRepository,
    run_id: str,
) -> bool:
    campaign_ids = {
        stage.campaign_id
        for stage in repository.list_pipeline_stages_for_run(run_id)
        if stage.campaign_id
        and stage.stage_key == "campaign_report_preview"
    }
    for campaign_id in campaign_ids:
        campaign = repository.get_campaign(campaign_id)
        if campaign is not None and campaign.scope_status != "in_scope":
            return True
    return False


def _build_report_preview_response_or_404(
    record: PipelineRunRecord,
    repository: DatabaseRepository,
) -> ReportPreviewResponse:
    try:
        return build_report_preview_response(
            record,
            trusted_bounded_result_claims=(
                repository.load_trusted_bounded_result_claims(record.id)
            ),
        )
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


# ---------------------------------------------------------------------------
# LLM audit helpers
# ---------------------------------------------------------------------------

def _llm_audit_safety_notes(response: LLMResponse) -> list[str]:
    notes = [
        "prompt_hash_only",
        "no_prompt_storage",
        "provider_response_not_fact",
    ]
    if response.mode == "dry_run":
        notes.append("dry_run_no_provider_call")
    if response.error:
        notes.append("provider_error_recorded")
    return notes
