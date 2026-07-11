from datetime import UTC, datetime
from hashlib import sha256
import json
import re
from typing import Any
from urllib.parse import urlparse
from uuid import uuid4

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.db_models import (
    AgentRunRecord,
    ApprovalRecord,
    ArtifactRecord,
    CampaignBudgetRecord,
    CampaignRecord,
    CampaignTaskRecord,
    CodebaseFactRecord,
    CodebaseMapRecord,
    FindingRecord,
    LearningSignalRecord,
    LLMRunRecord,
    PipelineStageRecord,
    PipelineRunRecord,
    ProgramRecord,
    ReportRecord,
    ScannerRunRecord,
    ValidationRunRecord,
)
from app.models import Finding, Program, ReportDraft
from app.sample_data import FINDINGS, PROGRAMS, REPORTS


REDACTED = "[REDACTED]"
TOKEN_USAGE_KEYS = {"input_tokens", "output_tokens", "token_usage", "total_tokens"}
EMAIL_PATTERN = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE)
JWT_PATTERN = re.compile(
    r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"
)
_VALIDATION_MANUAL_RESULT_STATUSES = {
    "evidence_recorded",
    "refuted",
    "needs_evidence",
}
_VALIDATION_APPROVAL_PRESERVED_STATUSES = {
    "preflight_passed",
    *_VALIDATION_MANUAL_RESULT_STATUSES,
}
_VALIDATION_APPROVAL_BUDGET_STATUSES = {
    "ready",
    "preflight_passed",
    *_VALIDATION_MANUAL_RESULT_STATUSES,
}
APPROVAL_TERMINAL_STATUSES = {"denied", "revoked", "expired", "used"}
APPROVAL_DECISION_STATUSES = {"approved", *APPROVAL_TERMINAL_STATUSES}
APPROVAL_INITIAL_STATUSES = {"pending", "requested"}
_SECURITY_IMPACT_OBSERVATION_TYPES = {
    "request_response_diff",
    "role_matrix_observation",
}
_REPORT_SAFE_REVIEW_EVIDENCE_REFS = {
    "local_code_reference",
    "log_ref",
    "request_response_diff",
    "sanitized_cross_account_diff",
    "sanitized_parent_child_matrix",
    "role_matrix_snapshot",
    "sanitized_request_response",
    "sanitized_role_matrix",
    "screenshot_ref",
}
_REQUEST_TRACE_EVIDENCE_REFS = {
    "request_response_diff",
    "sanitized_cross_account_diff",
    "sanitized_request_response",
}
_CORROBORATING_EVIDENCE_REFS = _REPORT_SAFE_REVIEW_EVIDENCE_REFS - _REQUEST_TRACE_EVIDENCE_REFS


class DatabaseRepository:
    def __init__(self, session: Session):
        self.session = session

    def list_programs(self) -> list[Program]:
        records = self.session.scalars(select(ProgramRecord).order_by(ProgramRecord.id)).all()
        return [_program_from_record(record) for record in records]

    def get_program(self, program_id: str) -> Program | None:
        record = self.session.get(ProgramRecord, program_id)
        if record is None:
            return None
        return _program_from_record(record)

    def create_program(self, program: Program) -> Program:
        record = _program_to_record(program)
        self.session.add(record)
        self.session.commit()
        self.session.refresh(record)
        return _program_from_record(record)

    def list_findings(self) -> list[Finding]:
        records = self.session.scalars(select(FindingRecord).order_by(FindingRecord.id)).all()
        return [_finding_from_record(record) for record in records]

    def get_finding(self, finding_id: str) -> Finding | None:
        record = self.session.get(FindingRecord, finding_id)
        if record is None:
            return None
        return _finding_from_record(record)

    def save_finding_candidate(
        self,
        *,
        id: str,
        program_id: str | None,
        program: str,
        asset: str,
        title: str,
        vuln_type: str,
        severity_estimate: str,
        confidence: float,
        scope_status: str,
        policy_status: str,
        broken_invariant: str,
        validation_status: str,
        refutation_status: str,
        duplicate_likelihood: str,
        submission_recommendation: str,
        evidence_refs: list[str],
        operating_reasons: list[str] | None = None,
    ) -> FindingRecord:
        existing = self.session.get(FindingRecord, id)
        if existing is not None:
            return existing

        record = FindingRecord(
            id=id,
            program_id=program_id,
            program=_safe_display_value(program),
            asset=_safe_display_value(asset),
            title=_safe_display_value(title),
            vuln_type=_safe_display_value(vuln_type),
            severity_estimate=_safe_display_value(severity_estimate),
            confidence=max(0, min(1, confidence)),
            scope_status=_safe_display_value(scope_status),
            policy_status=_safe_display_value(policy_status),
            broken_invariant=_safe_display_value(broken_invariant),
            validation_status=_safe_display_value(validation_status),
            refutation_status=_safe_display_value(refutation_status),
            duplicate_likelihood=_safe_display_value(duplicate_likelihood),
            submission_recommendation=_safe_display_value(submission_recommendation),
            evidence_refs=_safe_display_value(evidence_refs),
            operating_reasons=_safe_display_value(operating_reasons or []),
        )
        self.session.add(record)
        self.session.commit()
        self.session.refresh(record)
        return record

    def list_reports(self) -> list[ReportDraft]:
        records = self.session.scalars(select(ReportRecord).order_by(ReportRecord.id)).all()
        return [_report_from_record(record) for record in records]

    def get_report(self, report_id: str) -> ReportDraft | None:
        record = self.session.get(ReportRecord, report_id)
        if record is None:
            return None
        return _report_from_record(record)

    def save_llm_run(
        self,
        *,
        provider: str,
        model: str,
        purpose: str,
        prompt_hash: str,
        mode: str,
        latency_ms: int | None,
        error: str | None,
        safety_notes: list[str],
    ) -> LLMRunRecord:
        record = LLMRunRecord(
            id=f"llm_run_{uuid4().hex}",
            provider=_safe_display_value(provider),
            model=_safe_display_value(model),
            purpose=_safe_display_value(purpose),
            prompt_hash=prompt_hash,
            mode=_safe_display_value(mode),
            latency_ms=latency_ms,
            error=_safe_display_value(error),
            safety_notes=_safe_display_value(safety_notes),
        )
        self.session.add(record)
        self.session.commit()
        self.session.refresh(record)
        return record

    def list_llm_runs(self) -> list[LLMRunRecord]:
        return self.session.scalars(
            select(LLMRunRecord).order_by(
                LLMRunRecord.created_at.desc(),
                LLMRunRecord.id.desc(),
            )
        ).all()

    def save_artifact(
        self,
        *,
        program_id: str | None,
        asset: str,
        kind: str,
        source_type: str,
        source_hash: str,
        ingestion_status: str,
        provenance: dict,
        payload_summary: dict,
        derived_facts: dict,
    ) -> ArtifactRecord:
        existing_query = select(ArtifactRecord).where(
            ArtifactRecord.source_hash == source_hash
        )
        if program_id is None:
            existing_query = existing_query.where(ArtifactRecord.program_id.is_(None))
        else:
            existing_query = existing_query.where(ArtifactRecord.program_id == program_id)
        existing = self.session.scalars(existing_query).first()
        if existing is not None:
            existing.provenance = _append_duplicate_import_provenance(
                existing.provenance,
                provenance,
            )
            self.session.add(existing)
            self.session.commit()
            self.session.refresh(existing)
            return existing

        safety = _artifact_safety_metadata(
            provenance=provenance,
            payload_summary=payload_summary,
            derived_facts=derived_facts,
        )
        safe_provenance = dict(_safe_display_value(provenance))
        safe_provenance["safety"] = safety
        record = ArtifactRecord(
            id=f"artifact_{uuid4().hex}",
            program_id=program_id,
            asset=_safe_asset_value(asset),
            kind=kind,
            source_type=source_type,
            source_hash=source_hash,
            ingestion_status=ingestion_status,
            provenance=safe_provenance,
            payload_summary=_safe_display_value(payload_summary),
            derived_facts=_safe_display_value(derived_facts),
        )
        self.session.add(record)
        self.session.commit()
        self.session.refresh(record)
        return record

    def list_artifacts(
        self,
        *,
        program_id: str | None = None,
        asset: str | None = None,
        source_type: str | None = None,
        ingestion_status: str | None = None,
        provenance_ref: str | None = None,
        fact_type: str | None = None,
        usage_type: str | None = None,
        usage_run_id: str | None = None,
        sensitivity_label: str | None = None,
        redaction_status: str | None = None,
        report_chain_allowed: bool | None = None,
    ) -> list[ArtifactRecord]:
        query = select(ArtifactRecord)
        if program_id is not None:
            query = query.where(ArtifactRecord.program_id == program_id)
        if source_type is not None:
            query = query.where(ArtifactRecord.source_type == source_type)
        if ingestion_status is not None:
            query = query.where(ArtifactRecord.ingestion_status == ingestion_status)
        records = self.session.scalars(
            query.order_by(
                ArtifactRecord.created_at.desc(),
                ArtifactRecord.id.desc(),
            )
        ).all()
        if asset is not None:
            safe_asset = _safe_asset_value(asset)
            records = [
                record
                for record in records
                if _safe_asset_value(record.asset) == safe_asset
            ]
        if (
            provenance_ref is None
            and fact_type is None
            and usage_type is None
            and usage_run_id is None
            and sensitivity_label is None
            and redaction_status is None
            and report_chain_allowed is None
        ):
            return records
        return [
            record
            for record in records
            if _artifact_matches_provenance_filter(
                record,
                provenance_ref=provenance_ref,
                fact_type=fact_type,
            )
            and _artifact_matches_usage_filter(
                record,
                usage_type=usage_type,
                usage_run_id=usage_run_id,
            )
            and _artifact_matches_safety_filter(
                record,
                sensitivity_label=sensitivity_label,
                redaction_status=redaction_status,
                report_chain_allowed=report_chain_allowed,
            )
        ]

    def get_artifact(self, artifact_id: str) -> ArtifactRecord | None:
        return self.session.get(ArtifactRecord, artifact_id)

    def append_artifact_usage_records(
        self,
        *,
        artifact_id: str,
        usage_records: list[dict],
    ) -> ArtifactRecord | None:
        record = self.get_artifact(artifact_id)
        if record is None:
            return None

        provenance = dict(record.provenance)
        existing_usage_records = provenance.get("usage_records", [])
        if not isinstance(existing_usage_records, list):
            existing_usage_records = []

        updated_usage_records = list(existing_usage_records)
        usage_identities = {
            _artifact_usage_identity(record)
            for record in updated_usage_records
            if isinstance(record, dict)
        }
        for usage_record in usage_records:
            safe_usage_record = _safe_display_value(usage_record)
            usage_identity = (
                _artifact_usage_identity(safe_usage_record)
                if isinstance(safe_usage_record, dict)
                else None
            )
            if usage_identity is not None and usage_identity in usage_identities:
                continue
            if safe_usage_record not in updated_usage_records:
                updated_usage_records.append(safe_usage_record)
                if usage_identity is not None:
                    usage_identities.add(usage_identity)

        provenance["usage_records"] = updated_usage_records
        record.provenance = provenance
        self.session.add(record)
        self.session.commit()
        self.session.refresh(record)
        return record

    def save_pipeline_run(
        self,
        *,
        program_id: str | None = None,
        asset: str,
        policy_text: str,
        scope_status: str,
        hypothesis_count: int,
        blocked_count: int,
        report_title: str | None,
        payload: dict,
    ) -> PipelineRunRecord:
        record = PipelineRunRecord(
            id=f"pipeline_run_{uuid4().hex}",
            program_id=program_id,
            asset=asset,
            policy_text_hash=sha256(policy_text.encode("utf-8")).hexdigest(),
            scope_status=scope_status,
            hypothesis_count=hypothesis_count,
            blocked_count=blocked_count,
            report_title=report_title,
            payload=_initial_pipeline_payload(payload),
        )
        self.session.add(record)
        self.session.commit()
        self.session.refresh(record)
        return record

    def list_pipeline_runs(self) -> list[PipelineRunRecord]:
        return self.session.scalars(
            select(PipelineRunRecord).order_by(
                PipelineRunRecord.created_at.desc(),
                PipelineRunRecord.id.desc(),
            )
        ).all()

    def get_pipeline_run(self, run_id: str) -> PipelineRunRecord | None:
        return self.session.get(PipelineRunRecord, run_id)

    def append_claim_review_decision(
        self,
        *,
        run_id: str,
        decision: dict,
        claim_type: str | None = None,
        evidence_refs_supported: bool = False,
    ) -> PipelineRunRecord | None:
        record = self.get_pipeline_run(run_id)
        if record is None:
            return None
        if (
            decision.get("decision") == "confirmed_observed_fact"
            and claim_type != "observed_fact"
        ):
            return None
        if (
            decision.get("decision") == "confirmed_observed_fact"
            and not evidence_refs_supported
        ):
            return None
        if (
            decision.get("decision") == "confirmed_observed_fact"
            and not _claim_review_has_evidence_support(record.payload, decision)
        ):
            return None

        payload = dict(record.payload)
        existing_decisions = payload.get("claim_review_decisions", [])
        decisions = existing_decisions if isinstance(existing_decisions, list) else []
        payload["claim_review_decisions"] = decisions + [_safe_display_value(decision)]
        record.payload = payload
        self.session.add(record)
        self.session.commit()
        self.session.refresh(record)
        return record

    def append_manual_observation(
        self,
        *,
        run_id: str,
        observation: dict,
        claim_exists: bool = False,
        claim_type: str | None = None,
    ) -> PipelineRunRecord | None:
        record = self.get_pipeline_run(run_id)
        if record is None:
            return None
        if not claim_exists:
            return None
        if (
            observation.get("observation_type") in _SECURITY_IMPACT_OBSERVATION_TYPES
            and claim_type != "observed_fact"
        ):
            return None
        if (
            observation.get("observation_type") in _SECURITY_IMPACT_OBSERVATION_TYPES
            and not _manual_observation_has_supported_evidence_refs(
                record.payload,
                observation,
            )
        ):
            return None

        safe_observation = _safe_display_value(observation)
        payload = dict(record.payload)
        existing_observations = payload.get("manual_observations", [])
        observations = existing_observations if isinstance(existing_observations, list) else []
        payload["manual_observations"] = observations + [safe_observation]

        workspace = payload.get("validation_workspace")
        if isinstance(workspace, dict):
            workspace = dict(workspace)
            workspace_observations = workspace.get("manual_observations", [])
            workspace["manual_observations"] = (
                workspace_observations if isinstance(workspace_observations, list) else []
            ) + [safe_observation]
            payload["validation_workspace"] = workspace

        record.payload = payload
        self.session.add(record)
        self.session.commit()
        self.session.refresh(record)
        return record

    def list_pipeline_runs_for_program(self, program_id: str) -> list[PipelineRunRecord]:
        return self.session.scalars(
            select(PipelineRunRecord)
            .where(PipelineRunRecord.program_id == program_id)
            .order_by(
                PipelineRunRecord.created_at.desc(),
                PipelineRunRecord.id.desc(),
            )
        ).all()

    def create_campaign(
        self,
        *,
        program_id: str | None,
        name: str,
        autonomy_level: str,
        scope_status: str,
        policy_text: str,
        default_asset: str,
        target_classes: list[str] | None = None,
        allowed_tools: list[str] | None = None,
        created_by: str,
        payload: dict | None = None,
    ) -> CampaignRecord:
        record = CampaignRecord(
            id=f"campaign_{uuid4().hex}",
            program_id=program_id,
            name=_safe_display_value(name),
            autonomy_level=_safe_display_value(autonomy_level),
            scope_status=_safe_display_value(scope_status),
            policy_text_hash=sha256(policy_text.encode("utf-8")).hexdigest(),
            default_asset=_safe_asset_value(default_asset),
            target_classes=_safe_display_value(target_classes or []),
            allowed_tools=_safe_display_value(allowed_tools or []),
            created_by=_safe_display_value(created_by),
            status="draft",
            payload=_safe_display_value(payload or {}),
        )
        self.session.add(record)
        self.session.commit()
        self.session.refresh(record)
        return record

    def list_campaigns(self) -> list[CampaignRecord]:
        return self.session.scalars(
            select(CampaignRecord).order_by(
                CampaignRecord.created_at.desc(),
                CampaignRecord.id.desc(),
            )
        ).all()

    def get_campaign(self, campaign_id: str) -> CampaignRecord | None:
        return self.session.get(CampaignRecord, campaign_id)

    def update_campaign_status(self, campaign_id: str, status: str) -> CampaignRecord | None:
        record = self.get_campaign(campaign_id)
        if record is None:
            return None
        safe_status = _safe_display_value(status)
        payload = dict(record.payload) if isinstance(record.payload, dict) else {}
        now = datetime.now(UTC)
        if safe_status == "running":
            payload.setdefault("budget_started_at", now.isoformat())
            paused_at = _payload_datetime(payload.get("budget_paused_at"))
            if paused_at is not None:
                paused_seconds = payload.get("budget_paused_seconds", 0)
                if not isinstance(paused_seconds, (int, float)) or isinstance(
                    paused_seconds, bool
                ):
                    paused_seconds = 0
                payload["budget_paused_seconds"] = max(
                    0,
                    paused_seconds + (now - paused_at).total_seconds(),
                )
                payload.pop("budget_paused_at", None)
        elif safe_status == "paused" and record.status == "running":
            payload.setdefault("budget_paused_at", now.isoformat())
        record.status = safe_status
        record.payload = payload
        self.session.add(record)
        self.session.commit()
        self.session.refresh(record)
        return record

    def get_campaign_budget(self, campaign_id: str) -> CampaignBudgetRecord | None:
        return self.session.scalars(
            select(CampaignBudgetRecord).where(CampaignBudgetRecord.campaign_id == campaign_id)
        ).first()

    def upsert_campaign_budget(
        self,
        *,
        campaign_id: str,
        time_budget_minutes: int | None,
        token_budget: int | None,
        tool_call_budget: int | None,
        validation_budget: int | None,
    ) -> CampaignBudgetRecord:
        existing = self.session.scalars(
            select(CampaignBudgetRecord).where(CampaignBudgetRecord.campaign_id == campaign_id)
        ).first()
        if existing is None:
            existing = CampaignBudgetRecord(
                id=f"campaign_budget_{uuid4().hex}",
                campaign_id=campaign_id,
            )
        existing.time_budget_minutes = time_budget_minutes
        existing.token_budget = token_budget
        existing.tool_call_budget = tool_call_budget
        existing.validation_budget = validation_budget
        existing.status = "active"
        self.session.add(existing)
        self.session.commit()
        self.session.refresh(existing)
        return existing

    def create_campaign_task(
        self,
        *,
        campaign_id: str,
        task_type: str,
        agent_type: str,
        title: str,
        input_refs: list[str] | None = None,
        payload: dict | None = None,
    ) -> CampaignTaskRecord:
        record = CampaignTaskRecord(
            id=f"campaign_task_{uuid4().hex}",
            campaign_id=campaign_id,
            task_type=_safe_display_value(task_type),
            agent_type=_safe_display_value(agent_type),
            title=_safe_display_value(title),
            status="queued",
            input_refs=_safe_display_value(input_refs or []),
            output_refs=[],
            payload=_safe_display_value(payload or {}),
        )
        self.session.add(record)
        self.session.commit()
        self.session.refresh(record)
        return record

    def list_campaign_tasks(self, campaign_id: str) -> list[CampaignTaskRecord]:
        return self.session.scalars(
            select(CampaignTaskRecord)
            .where(CampaignTaskRecord.campaign_id == campaign_id)
            .order_by(
                CampaignTaskRecord.created_at.desc(),
                CampaignTaskRecord.id.desc(),
            )
        ).all()

    def update_campaign_task_status(
        self,
        task_id: str,
        status: str,
        *,
        output_refs: list[str] | None = None,
    ) -> CampaignTaskRecord | None:
        record = self.session.get(CampaignTaskRecord, task_id)
        if record is None:
            return None
        record.status = _safe_display_value(status)
        if output_refs is not None:
            record.output_refs = _safe_display_value(output_refs)
        self.session.add(record)
        self.session.commit()
        self.session.refresh(record)
        return record

    def save_agent_run(
        self,
        *,
        campaign_id: str | None,
        task_id: str | None,
        agent_type: str,
        status: str,
        input_refs: list[str] | None = None,
        output_refs: list[str] | None = None,
        tool_calls: list[dict] | None = None,
        safety_gate_state: str,
        stop_reason: str | None,
        payload: dict | None = None,
    ) -> AgentRunRecord:
        record = AgentRunRecord(
            id=f"agent_run_{uuid4().hex}",
            campaign_id=campaign_id,
            task_id=task_id,
            agent_type=_safe_display_value(agent_type),
            status=_safe_display_value(status),
            input_refs=_safe_display_value(input_refs or []),
            output_refs=_safe_display_value(output_refs or []),
            tool_calls=_safe_display_value(tool_calls or []),
            safety_gate_state=_safe_display_value(safety_gate_state),
            stop_reason=_safe_display_value(stop_reason),
            payload=_safe_display_value(payload or {}),
            finished_at=datetime.now(UTC) if status in {"completed", "failed", "blocked"} else None,
        )
        self.session.add(record)
        self.session.commit()
        self.session.refresh(record)
        return record

    def finish_agent_run(
        self,
        run_id: str,
        *,
        status: str,
        output_refs: list[str] | None = None,
        safety_gate_state: str | None = None,
        stop_reason: str | None = None,
        payload: dict | None = None,
    ) -> AgentRunRecord | None:
        record = self.session.get(AgentRunRecord, run_id)
        if record is None:
            return None
        record.status = _safe_display_value(status)
        if output_refs is not None:
            record.output_refs = _safe_display_value(output_refs)
        if safety_gate_state is not None:
            record.safety_gate_state = _safe_display_value(safety_gate_state)
        record.stop_reason = _safe_display_value(stop_reason)
        if payload is not None:
            record.payload = _safe_display_value(payload)
        record.finished_at = datetime.now(UTC)
        self.session.add(record)
        self.session.commit()
        self.session.refresh(record)
        return record

    def find_active_agent_run_for_task(self, task_id: str) -> AgentRunRecord | None:
        return self.session.scalars(
            select(AgentRunRecord)
            .where(AgentRunRecord.task_id == task_id)
            .where(AgentRunRecord.status.in_(("dispatched", "running", "awaiting_approval")))
            .order_by(
                AgentRunRecord.created_at.desc(),
                AgentRunRecord.id.desc(),
            )
        ).first()

    def list_campaign_agent_runs(self, campaign_id: str) -> list[AgentRunRecord]:
        return self.session.scalars(
            select(AgentRunRecord)
            .where(AgentRunRecord.campaign_id == campaign_id)
            .order_by(
                AgentRunRecord.created_at.desc(),
                AgentRunRecord.id.desc(),
            )
        ).all()

    def create_approval_record(
        self,
        *,
        campaign_id: str | None = None,
        task_id: str | None = None,
        run_id: str | None = None,
        program_id: str | None = None,
        approval_type: str = "validation_batch",
        actor: str | None = None,
        requester: str | None = None,
        reason: str,
        scope_reference: str | None = None,
        requested_action: str | None = None,
        asset: str | None = None,
        validation_mode: str | None = None,
        plan_digest: str | None = None,
        autonomy_level: str | None = None,
        safety_gate_state: str = "awaiting_approval",
        status: str | None = None,
        expires_at: datetime | None = None,
        payload: dict | None = None,
    ) -> ApprovalRecord:
        record = ApprovalRecord(
            id=f"approval_{uuid4().hex}",
            campaign_id=campaign_id,
            task_id=task_id,
            run_id=run_id,
            program_id=program_id,
            approval_type=_safe_display_value(approval_type),
            actor=_safe_display_value(actor or requester or "unknown"),
            reason=_safe_display_value(reason),
            scope_reference=_safe_display_value(scope_reference),
            requested_action=_safe_display_value(requested_action),
            asset=_safe_asset_value(asset) if asset is not None else None,
            validation_mode=_safe_display_value(validation_mode),
            plan_digest=_safe_display_value(plan_digest),
            autonomy_level=_safe_display_value(autonomy_level),
            safety_gate_state=_safe_display_value(safety_gate_state),
            status=_approval_initial_status(status, campaign_id=campaign_id),
            expires_at=expires_at,
            payload=_safe_display_value(payload or {}),
        )
        self.session.add(record)
        self.session.commit()
        self.session.refresh(record)
        return record

    def decide_approval_record(
        self,
        *,
        approval_id: str,
        decision: str,
        actor: str,
        reason: str,
    ) -> ApprovalRecord | None:
        record = self.session.get(ApprovalRecord, approval_id)
        if record is None:
            return None
        if decision not in APPROVAL_DECISION_STATUSES:
            return None
        if record.status in APPROVAL_TERMINAL_STATUSES:
            return None
        if record.status == decision and record.decided_at is not None:
            return None
        if decision == "approved" and not approval_record_is_active(record):
            return None
        record.status = _safe_display_value(decision)
        record.decided_by = _safe_display_value(actor)
        record.decision_reason = _safe_display_value(reason)
        record.decided_at = datetime.now(UTC)
        self.session.add(record)
        self._sync_validation_runs_for_approval_decision(record)
        self.session.commit()
        self.session.refresh(record)
        return record

    def _sync_validation_runs_for_approval_decision(self, approval: ApprovalRecord) -> None:
        if approval.campaign_id is None:
            return
        if approval.validation_mode is None or approval.plan_digest is None:
            return
        if approval.asset is None:
            return

        query = (
            select(ValidationRunRecord)
            .where(ValidationRunRecord.approval_required.is_(True))
            .where(ValidationRunRecord.validation_mode == approval.validation_mode)
            .where(ValidationRunRecord.plan_digest == approval.plan_digest)
            .where(
                (ValidationRunRecord.allowed_to_execute.is_(False))
                | (ValidationRunRecord.approval_id == approval.id)
            )
        )
        query = query.where(ValidationRunRecord.campaign_id == approval.campaign_id)
        if approval.task_id is not None:
            query = query.where(ValidationRunRecord.task_id == approval.task_id)
        else:
            query = query.where(ValidationRunRecord.task_id.is_(None))

        validation_budget = _payload_int(approval.payload, "validation_budget")
        reserved_count = self._approval_validation_budget_used(approval.id)
        for validation_run in self.session.scalars(query).all():
            if not self._validation_run_asset_matches_approval(validation_run, approval):
                continue
            if not self._validation_run_scope_reference_matches_approval(
                validation_run,
                approval,
            ):
                continue
            if not self._validation_run_allowed_accounts_match_approval(
                validation_run,
                approval,
            ):
                continue
            if (
                approval.status == "approved"
                and validation_run.approval_id != approval.id
                and validation_budget is not None
                and reserved_count >= validation_budget
            ):
                continue
            validation_run.approval_id = approval.id
            if approval.status == "approved":
                if validation_run.status not in _VALIDATION_APPROVAL_PRESERVED_STATUSES:
                    validation_run.status = "ready"
                    validation_run.safety_gate_state = "approved_validation_record"
                    validation_run.allowed_to_execute = False
                elif validation_run.status in _VALIDATION_MANUAL_RESULT_STATUSES:
                    validation_run.allowed_to_execute = False
                else:
                    validation_run.allowed_to_execute = True
            else:
                if validation_run.status not in _VALIDATION_MANUAL_RESULT_STATUSES:
                    validation_run.status = "blocked"
                    validation_run.safety_gate_state = "blocked"
                validation_run.allowed_to_execute = False
                validation_run.finished_at = datetime.now(UTC)
            self.session.add(validation_run)
            if (
                approval.status == "approved"
                and validation_run.status in _VALIDATION_APPROVAL_BUDGET_STATUSES
            ):
                reserved_count += 1

    def _approval_validation_budget_used(self, approval_id: str) -> int:
        records = self.session.scalars(
            select(ValidationRunRecord).where(ValidationRunRecord.approval_id == approval_id)
        ).all()
        return sum(
            1
            for record in records
            if record.status in _VALIDATION_APPROVAL_BUDGET_STATUSES
        )

    def _validation_run_asset_matches_approval(
        self,
        validation_run: ValidationRunRecord,
        approval: ApprovalRecord,
    ) -> bool:
        if approval.asset is None:
            return False

        validation_asset = validation_run.target_ref
        if validation_run.target_ref == f"campaign:{validation_run.campaign_id}":
            campaign = self.session.get(CampaignRecord, validation_run.campaign_id)
            if campaign is None:
                return False
            validation_asset = campaign.default_asset

        return _safe_asset_value(validation_asset) == _safe_asset_value(approval.asset)

    def _validation_run_scope_reference_matches_approval(
        self,
        validation_run: ValidationRunRecord,
        approval: ApprovalRecord,
    ) -> bool:
        if approval.scope_reference is None:
            return True
        payload = validation_run.payload if isinstance(validation_run.payload, dict) else {}
        return payload.get("scope_reference") == approval.scope_reference

    def _validation_run_allowed_accounts_match_approval(
        self,
        validation_run: ValidationRunRecord,
        approval: ApprovalRecord,
    ) -> bool:
        approval_accounts = _payload_string_set(approval.payload, "allowed_accounts")
        if not approval_accounts:
            return True
        validation_accounts = _payload_string_set(
            validation_run.payload,
            "allowed_accounts",
        )
        return bool(validation_accounts) and validation_accounts <= approval_accounts

    def list_approval_records(self, *, run_id: str | None = None) -> list[ApprovalRecord]:
        query = select(ApprovalRecord)
        if run_id is not None:
            query = query.where(ApprovalRecord.run_id == run_id)
        return self.session.scalars(
            query.order_by(
                ApprovalRecord.created_at.desc(),
                ApprovalRecord.id.desc(),
            )
        ).all()

    def list_campaign_approval_records(self, campaign_id: str) -> list[ApprovalRecord]:
        return self.session.scalars(
            select(ApprovalRecord)
            .where(ApprovalRecord.campaign_id == campaign_id)
            .order_by(
                ApprovalRecord.created_at.desc(),
                ApprovalRecord.id.desc(),
            )
        ).all()

    def find_approved_validation_record(
        self,
        *,
        asset: str,
        validation_mode: str,
        plan_digest: str | None,
        campaign_id: str | None = None,
        task_id: str | None = None,
        run_id: str | None = None,
    ) -> ApprovalRecord | None:
        query = (
            select(ApprovalRecord)
            .where(ApprovalRecord.status == "approved")
            .where(ApprovalRecord.asset == _safe_asset_value(asset))
            .where(ApprovalRecord.validation_mode == _safe_display_value(validation_mode))
            .where(ApprovalRecord.plan_digest == _safe_display_value(plan_digest))
        )
        if campaign_id is not None:
            query = query.where(ApprovalRecord.campaign_id == _safe_display_value(campaign_id))
        else:
            query = query.where(ApprovalRecord.campaign_id.is_(None))
        if task_id is not None:
            query = query.where(ApprovalRecord.task_id == _safe_display_value(task_id))
        else:
            query = query.where(ApprovalRecord.task_id.is_(None))
        if run_id is not None:
            query = query.where(ApprovalRecord.run_id == _safe_display_value(run_id))
        else:
            query = query.where(ApprovalRecord.run_id.is_(None))
        now = datetime.now(UTC)
        records = self.session.scalars(
            query.order_by(
                ApprovalRecord.decided_at.desc(),
                ApprovalRecord.created_at.desc(),
                ApprovalRecord.id.desc(),
            )
        ).all()
        return next(
            (
                record for record in records
                if record.expires_at is None or _as_utc(record.expires_at) > now
            ),
            None,
        )

    def save_pipeline_stage(
        self,
        *,
        pipeline_run_id: str | None,
        campaign_id: str | None,
        task_id: str | None,
        stage_key: str,
        stage_order: int,
        status: str,
        input_refs: list[str] | None = None,
        output_refs: list[str] | None = None,
        safety_gate_state: str,
        stop_reason: str | None,
        payload: dict | None = None,
    ) -> PipelineStageRecord:
        safe_payload = _safe_display_value(payload or {})
        existing = _existing_pipeline_stage_for_idempotency_key(
            self.session,
            pipeline_run_id=pipeline_run_id,
            campaign_id=campaign_id,
            task_id=task_id,
            stage_key=stage_key,
            payload=safe_payload,
        )
        if existing is not None:
            return existing
        record = PipelineStageRecord(
            id=f"pipeline_stage_{uuid4().hex}",
            pipeline_run_id=pipeline_run_id,
            campaign_id=campaign_id,
            task_id=task_id,
            stage_key=_safe_display_value(stage_key),
            stage_order=stage_order,
            status=_safe_display_value(status),
            input_refs=_safe_display_value(input_refs or []),
            output_refs=_safe_display_value(output_refs or []),
            safety_gate_state=_safe_display_value(safety_gate_state),
            stop_reason=_safe_display_value(stop_reason),
            payload=safe_payload,
        )
        self.session.add(record)
        self.session.commit()
        self.session.refresh(record)
        return record

    def get_pipeline_stage(self, stage_id: str) -> PipelineStageRecord | None:
        return self.session.get(PipelineStageRecord, stage_id)

    def update_pipeline_stage_status(
        self,
        stage_id: str,
        *,
        status: str,
        safety_gate_state: str,
        stop_reason: str | None,
        payload: dict | None = None,
    ) -> PipelineStageRecord | None:
        record = self.get_pipeline_stage(stage_id)
        if record is None:
            return None
        record.status = _safe_display_value(status)
        record.safety_gate_state = _safe_display_value(safety_gate_state)
        record.stop_reason = _safe_display_value(stop_reason)
        if payload is not None:
            record.payload = _safe_display_value(payload)
        self.session.add(record)
        self.session.commit()
        self.session.refresh(record)
        return record

    def list_campaign_pipeline_stages(self, campaign_id: str) -> list[PipelineStageRecord]:
        return self.session.scalars(
            select(PipelineStageRecord)
            .where(PipelineStageRecord.campaign_id == campaign_id)
            .order_by(
                PipelineStageRecord.stage_order,
                PipelineStageRecord.created_at.desc(),
                PipelineStageRecord.id.desc(),
            )
        ).all()

    def list_pipeline_stages_for_run(self, pipeline_run_id: str) -> list[PipelineStageRecord]:
        return self.session.scalars(
            select(PipelineStageRecord)
            .where(PipelineStageRecord.pipeline_run_id == pipeline_run_id)
            .order_by(
                PipelineStageRecord.stage_order,
                PipelineStageRecord.created_at.desc(),
                PipelineStageRecord.id.desc(),
            )
        ).all()

    def save_codebase_map(
        self,
        *,
        campaign_id: str,
        source_ref: str,
        repository: str,
        commit_ref: str | None,
        status: str,
        route_count: int,
        handler_count: int,
        model_count: int,
        authz_check_count: int,
        sensitive_sink_count: int,
        provenance_refs: list[str] | None = None,
        safety_gate_state: str,
        payload: dict | None = None,
    ) -> CodebaseMapRecord:
        record = CodebaseMapRecord(
            id=f"codebase_map_{uuid4().hex}",
            campaign_id=campaign_id,
            source_ref=_safe_display_value(source_ref),
            repository=_safe_display_value(repository),
            commit_ref=_safe_display_value(commit_ref),
            status=_safe_display_value(status),
            route_count=max(0, route_count),
            handler_count=max(0, handler_count),
            model_count=max(0, model_count),
            authz_check_count=max(0, authz_check_count),
            sensitive_sink_count=max(0, sensitive_sink_count),
            provenance_refs=_safe_display_value(provenance_refs or []),
            safety_gate_state=_safe_display_value(safety_gate_state),
            payload=_safe_display_value(payload or {}),
        )
        self.session.add(record)
        self.session.commit()
        self.session.refresh(record)
        return record

    def list_campaign_codebase_maps(self, campaign_id: str) -> list[CodebaseMapRecord]:
        return self.session.scalars(
            select(CodebaseMapRecord)
            .where(CodebaseMapRecord.campaign_id == campaign_id)
            .order_by(
                CodebaseMapRecord.created_at.desc(),
                CodebaseMapRecord.id.desc(),
            )
        ).all()

    def save_codebase_fact(
        self,
        *,
        codebase_map_id: str,
        campaign_id: str,
        fact_type: str,
        source_path: str,
        symbol_name: str | None = None,
        route_method: str | None = None,
        route_path: str | None = None,
        authz_hint: str | None = None,
        sensitivity_label: str,
        provenance_refs: list[str] | None = None,
        payload: dict | None = None,
    ) -> CodebaseFactRecord:
        record = CodebaseFactRecord(
            id=f"codebase_fact_{uuid4().hex}",
            codebase_map_id=codebase_map_id,
            campaign_id=campaign_id,
            fact_type=_safe_display_value(fact_type),
            source_path=_safe_source_path(source_path),
            symbol_name=_safe_display_value(symbol_name),
            route_method=_safe_display_value(route_method),
            route_path=_safe_display_value(route_path),
            authz_hint=_safe_display_value(authz_hint),
            sensitivity_label=_safe_display_value(sensitivity_label),
            provenance_refs=_safe_display_value(provenance_refs or []),
            payload=_safe_display_value(payload or {}),
        )
        self.session.add(record)
        self.session.commit()
        self.session.refresh(record)
        return record

    def list_codebase_facts(self, codebase_map_id: str) -> list[CodebaseFactRecord]:
        return self.session.scalars(
            select(CodebaseFactRecord)
            .where(CodebaseFactRecord.codebase_map_id == codebase_map_id)
            .order_by(
                CodebaseFactRecord.fact_type,
                CodebaseFactRecord.source_path,
                CodebaseFactRecord.id,
            )
        ).all()

    def list_campaign_codebase_facts(self, campaign_id: str) -> list[CodebaseFactRecord]:
        return self.session.scalars(
            select(CodebaseFactRecord)
            .where(CodebaseFactRecord.campaign_id == campaign_id)
            .order_by(
                CodebaseFactRecord.fact_type,
                CodebaseFactRecord.source_path,
                CodebaseFactRecord.id,
            )
        ).all()

    def save_scanner_run(
        self,
        *,
        campaign_id: str,
        codebase_map_id: str | None,
        tool_name: str,
        command_hash: str,
        status: str,
        finding_count: int,
        candidate_count: int,
        summary: str,
        safety_gate_state: str,
        payload: dict | None = None,
    ) -> ScannerRunRecord:
        record = ScannerRunRecord(
            id=f"scanner_run_{uuid4().hex}",
            campaign_id=campaign_id,
            codebase_map_id=codebase_map_id,
            tool_name=_safe_display_value(tool_name),
            command_hash=_safe_display_value(command_hash),
            status=_safe_display_value(status),
            finding_count=max(0, finding_count),
            candidate_count=max(0, candidate_count),
            summary=_safe_display_value(summary),
            safety_gate_state=_safe_display_value(safety_gate_state),
            payload=_safe_display_value(payload or {}),
        )
        self.session.add(record)
        self.session.commit()
        self.session.refresh(record)
        return record

    def list_campaign_scanner_runs(self, campaign_id: str) -> list[ScannerRunRecord]:
        return self.session.scalars(
            select(ScannerRunRecord)
            .where(ScannerRunRecord.campaign_id == campaign_id)
            .order_by(
                ScannerRunRecord.created_at.desc(),
                ScannerRunRecord.id.desc(),
            )
        ).all()

    def save_validation_run(
        self,
        *,
        campaign_id: str,
        task_id: str | None,
        approval_id: str | None,
        validation_mode: str,
        target_ref: str,
        status: str,
        safety_gate_state: str,
        plan_digest: str | None,
        approval_required: bool,
        allowed_to_execute: bool,
        evidence_ref_count: int,
        summary: str,
        payload: dict | None = None,
    ) -> ValidationRunRecord:
        safe_payload = _safe_display_value(payload or {})
        existing = _existing_validation_run_for_idempotency_key(
            self.session,
            campaign_id=campaign_id,
            task_id=task_id,
            validation_mode=validation_mode,
            target_ref=target_ref,
            plan_digest=plan_digest,
            payload=safe_payload,
        )
        if existing is not None:
            return existing
        gated_without_approval = approval_required and approval_id is None
        gated_status = "awaiting_approval" if gated_without_approval else _safe_display_value(status)
        gated_allowed_to_execute = _validation_initial_allowed_to_execute(
            allowed_to_execute,
            approval_required=approval_required,
            status=gated_status,
        )
        record = ValidationRunRecord(
            id=f"validation_run_{uuid4().hex}",
            campaign_id=campaign_id,
            task_id=task_id,
            approval_id=approval_id,
            validation_mode=_safe_display_value(validation_mode),
            target_ref=_safe_source_path(target_ref),
            status=gated_status,
            safety_gate_state="awaiting_approval"
            if gated_without_approval
            else _safe_display_value(safety_gate_state),
            plan_digest=_safe_display_value(plan_digest),
            approval_required=approval_required,
            allowed_to_execute=gated_allowed_to_execute and not gated_without_approval,
            evidence_ref_count=max(0, evidence_ref_count),
            summary=_safe_display_value(summary),
            payload=safe_payload,
        )
        self.session.add(record)
        self.session.commit()
        self.session.refresh(record)
        return record

    def list_campaign_validation_runs(self, campaign_id: str) -> list[ValidationRunRecord]:
        return self.session.scalars(
            select(ValidationRunRecord)
            .where(ValidationRunRecord.campaign_id == campaign_id)
            .order_by(
                ValidationRunRecord.created_at.desc(),
                ValidationRunRecord.id.desc(),
            )
        ).all()

    def get_validation_run(self, validation_run_id: str) -> ValidationRunRecord | None:
        return self.session.get(ValidationRunRecord, validation_run_id)

    def record_validation_run_preflight(
        self,
        validation_run_id: str,
        *,
        allowed: bool,
        reason: str,
    ) -> ValidationRunRecord | None:
        record = self.get_validation_run(validation_run_id)
        if record is None:
            return None
        if record.status in _VALIDATION_MANUAL_RESULT_STATUSES:
            return None
        if allowed and record.status not in {"ready", "preflight_passed"}:
            allowed = False
            reason = "validation_run_not_ready"
        if allowed:
            record.status = "preflight_passed"
            record.safety_gate_state = "scope_guard_preflight_passed"
            record.allowed_to_execute = True
        else:
            if record.status not in _VALIDATION_MANUAL_RESULT_STATUSES:
                record.status = "blocked"
                record.safety_gate_state = "blocked"
            record.allowed_to_execute = False
            record.finished_at = datetime.now(UTC)
        payload = dict(record.payload)
        payload["scope_guard_preflight"] = _safe_display_value({
            "allowed": allowed,
            "reason": reason,
        })
        record.payload = payload
        self.session.add(record)
        self.session.commit()
        self.session.refresh(record)
        return record

    def record_validation_run_manual_result(
        self,
        validation_run_id: str,
        *,
        outcome: str,
        reviewer: str,
        summary: str,
        evidence_refs: list[str],
    ) -> ValidationRunRecord | None:
        record = self.get_validation_run(validation_run_id)
        if record is None:
            return None
        if record.status != "preflight_passed" or not record.allowed_to_execute:
            return None

        safe_outcome = _safe_display_value(outcome)
        safe_evidence_refs = _safe_display_value(evidence_refs)
        safe_evidence_ref_count = _safe_evidence_ref_count(safe_evidence_refs)
        validation_result_review = _validation_result_review(
            outcome=safe_outcome,
            summary=summary,
            evidence_refs=safe_evidence_refs,
            safe_evidence_ref_count=safe_evidence_ref_count,
        )
        record.status = _validation_result_status(
            safe_outcome,
            safe_evidence_ref_count=safe_evidence_ref_count,
        )
        record.safety_gate_state = _validation_result_safety_gate(
            safe_outcome,
            safe_evidence_ref_count=safe_evidence_ref_count,
        )
        record.allowed_to_execute = False
        record.evidence_ref_count = safe_evidence_ref_count
        record.summary = _safe_display_value(f"Manual validation result recorded: {safe_outcome}")
        record.finished_at = datetime.now(UTC)

        payload = dict(record.payload)
        payload["manual_result"] = _safe_display_value({
            "outcome": safe_outcome,
            "reviewer": reviewer,
            "summary": summary,
            "evidence_refs": safe_evidence_refs,
            "safe_evidence_ref_count": safe_evidence_ref_count,
            "recorded_at": record.finished_at.isoformat(),
            "execution_started": False,
        })
        payload["validation_result_review"] = validation_result_review
        record.payload = payload
        self.session.add(record)
        self.session.commit()
        self.session.refresh(record)
        return record

    def save_learning_signal(
        self,
        *,
        program_id: str,
        playbook_id: str,
        outcome: str,
        surface_key: str | None,
        notes: str,
        bounty_amount: int | None = None,
        severity_delta: str | None = None,
        evidence_quality: str | None = None,
        triager_feedback: str | None = None,
        target_relationships: list[str] | None = None,
        reuse_identical: bool = True,
    ) -> LearningSignalRecord:
        identity_hash = (
            _learning_signal_identity_hash(
                program_id=program_id,
                playbook_id=playbook_id,
                outcome=outcome,
                surface_key=surface_key,
                notes=notes,
                bounty_amount=bounty_amount,
                severity_delta=severity_delta,
                evidence_quality=evidence_quality,
                triager_feedback=triager_feedback,
                target_relationships=target_relationships or [],
            )
            if reuse_identical
            else None
        )
        if identity_hash is not None:
            existing = self.session.scalar(
                select(LearningSignalRecord).where(
                    LearningSignalRecord.identity_hash == identity_hash
                )
            )
            if existing is not None:
                return existing
        record = LearningSignalRecord(
            id=f"learning_signal_{uuid4().hex}",
            identity_hash=identity_hash,
            program_id=program_id,
            playbook_id=playbook_id,
            outcome=outcome,
            surface_key=_safe_display_value(surface_key),
            notes=_safe_display_value(notes),
            bounty_amount=bounty_amount,
            severity_delta=_safe_display_value(severity_delta),
            evidence_quality=_safe_display_value(evidence_quality),
            triager_feedback=_safe_display_value(triager_feedback),
            target_relationships=_safe_display_value(target_relationships or []),
        )
        self.session.add(record)
        try:
            self.session.commit()
        except IntegrityError:
            self.session.rollback()
            if identity_hash is None:
                raise
            existing = self.session.scalar(
                select(LearningSignalRecord).where(
                    LearningSignalRecord.identity_hash == identity_hash
                )
            )
            if existing is None:
                raise
            return existing
        self.session.refresh(record)
        return record

    def list_learning_signals(self, program_id: str) -> list[LearningSignalRecord]:
        return self.session.scalars(
            select(LearningSignalRecord)
            .where(LearningSignalRecord.program_id == program_id)
            .order_by(
                LearningSignalRecord.created_at.desc(),
                LearningSignalRecord.id.desc(),
            )
        ).all()

    def list_all_learning_signals(self) -> list[LearningSignalRecord]:
        return self.session.scalars(
            select(LearningSignalRecord).order_by(
                LearningSignalRecord.created_at.desc(),
                LearningSignalRecord.id.desc(),
            )
        ).all()


def seed_sample_data(session: Session) -> None:
    for program in PROGRAMS:
        if session.get(ProgramRecord, program.id) is None:
            session.add(_program_to_record(program))

    for finding in FINDINGS:
        if session.get(FindingRecord, finding.id) is None:
            program_id = next((program.id for program in PROGRAMS if program.name == finding.program), None)
            session.add(_finding_to_record(finding, program_id))

    for report in REPORTS:
        if session.get(ReportRecord, report.id) is None:
            session.add(_report_to_record(report))

    session.commit()


def _artifact_matches_provenance_filter(
    record: ArtifactRecord,
    *,
    provenance_ref: str | None,
    fact_type: str | None,
) -> bool:
    if provenance_ref is None and fact_type is None:
        return True

    for edge in _iter_provenance_edges(record.derived_facts):
        if provenance_ref is not None and edge.get("ref") != provenance_ref:
            continue
        if fact_type is not None and edge.get("fact_type") != fact_type:
            continue
        return True

    if fact_type is not None:
        return False
    return provenance_ref in set(_iter_provenance_refs(record.derived_facts))


def _artifact_matches_usage_filter(
    record: ArtifactRecord,
    *,
    usage_type: str | None,
    usage_run_id: str | None,
) -> bool:
    if usage_type is None and usage_run_id is None:
        return True

    usage_records = record.provenance.get("usage_records", [])
    if not isinstance(usage_records, list):
        return False

    for usage_record in usage_records:
        if not isinstance(usage_record, dict):
            continue
        if usage_type is not None and usage_record.get("usage_type") != usage_type:
            continue
        if usage_run_id is not None and usage_record.get("run_id") != usage_run_id:
            continue
        return True
    return False


def _artifact_usage_identity(usage_record: dict) -> tuple[str, str, str, str] | None:
    usage_type = usage_record.get("usage_type")
    run_id = usage_record.get("run_id")
    if not isinstance(usage_type, str) or not isinstance(run_id, str):
        return None

    ref = usage_record.get("ref")
    if isinstance(ref, str):
        return (usage_type, run_id, "ref", ref)

    for field in (
        "learning_signal_id",
        "finding_id",
        "candidate_id",
        "claim_id",
        "observation_id",
        "validation_run_id",
    ):
        value = usage_record.get(field)
        if isinstance(value, str):
            return (usage_type, run_id, field, value)
    return None


def _existing_pipeline_stage_for_idempotency_key(
    session: Session,
    *,
    pipeline_run_id: str | None,
    campaign_id: str | None,
    task_id: str | None,
    stage_key: str,
    payload: dict,
) -> PipelineStageRecord | None:
    idempotency_key = payload.get("idempotency_key")
    if not isinstance(idempotency_key, str) or idempotency_key == REDACTED:
        return None

    query = (
        select(PipelineStageRecord)
        .where(PipelineStageRecord.stage_key == _safe_display_value(stage_key))
        .where(PipelineStageRecord.payload["idempotency_key"].as_string() == idempotency_key)
    )
    if pipeline_run_id is None:
        query = query.where(PipelineStageRecord.pipeline_run_id.is_(None))
    else:
        query = query.where(PipelineStageRecord.pipeline_run_id == pipeline_run_id)
    if campaign_id is None:
        query = query.where(PipelineStageRecord.campaign_id.is_(None))
    else:
        query = query.where(PipelineStageRecord.campaign_id == campaign_id)
    if task_id is None:
        query = query.where(PipelineStageRecord.task_id.is_(None))
    else:
        query = query.where(PipelineStageRecord.task_id == task_id)

    return session.scalars(
        query.order_by(
            PipelineStageRecord.stage_order,
            PipelineStageRecord.created_at,
            PipelineStageRecord.id,
        )
    ).first()


def _existing_validation_run_for_idempotency_key(
    session: Session,
    *,
    campaign_id: str,
    task_id: str | None,
    validation_mode: str,
    target_ref: str,
    plan_digest: str | None,
    payload: dict,
) -> ValidationRunRecord | None:
    idempotency_key = payload.get("idempotency_key")
    if not isinstance(idempotency_key, str) or idempotency_key == REDACTED:
        return None

    query = (
        select(ValidationRunRecord)
        .where(ValidationRunRecord.campaign_id == campaign_id)
        .where(ValidationRunRecord.validation_mode == _safe_display_value(validation_mode))
        .where(ValidationRunRecord.target_ref == _safe_source_path(target_ref))
        .where(ValidationRunRecord.payload["idempotency_key"].as_string() == idempotency_key)
    )
    if task_id is None:
        query = query.where(ValidationRunRecord.task_id.is_(None))
    else:
        query = query.where(ValidationRunRecord.task_id == task_id)
    if plan_digest is None:
        query = query.where(ValidationRunRecord.plan_digest.is_(None))
    else:
        query = query.where(ValidationRunRecord.plan_digest == _safe_display_value(plan_digest))

    return session.scalars(
        query.order_by(
            ValidationRunRecord.created_at,
            ValidationRunRecord.id,
        )
    ).first()


def _artifact_matches_safety_filter(
    record: ArtifactRecord,
    *,
    sensitivity_label: str | None,
    redaction_status: str | None,
    report_chain_allowed: bool | None,
) -> bool:
    if sensitivity_label is None and redaction_status is None and report_chain_allowed is None:
        return True

    safety = record.provenance.get("safety")
    if not isinstance(safety, dict):
        return False
    if sensitivity_label is not None and safety.get("sensitivity_label") != sensitivity_label:
        return False
    if redaction_status is not None and safety.get("redaction_status") != redaction_status:
        return False
    if report_chain_allowed is not None and safety.get("report_chain_allowed") is not report_chain_allowed:
        return False
    return True


def _append_duplicate_import_provenance(
    current: dict,
    duplicate: dict,
) -> dict:
    updated = dict(current)
    duplicate_imports = updated.get("duplicate_imports", [])
    if not isinstance(duplicate_imports, list):
        duplicate_imports = []
    safe_duplicate = _safe_display_value(duplicate)
    if safe_duplicate in duplicate_imports:
        return updated
    updated["duplicate_imports"] = [
        *duplicate_imports,
        safe_duplicate,
    ]
    return updated


def _artifact_safety_metadata(
    *,
    provenance: dict,
    payload_summary: dict,
    derived_facts: dict,
) -> dict:
    blockers = []
    source = {
        "provenance": provenance,
        "payload_summary": payload_summary,
        "derived_facts": derived_facts,
    }
    if _contains_secret_like_value(source):
        blockers.append("contains_secret_like_value")
    if _contains_real_user_data_risk(source):
        blockers.append("contains_real_user_data_risk")

    return {
        "sensitivity_label": "sensitive" if blockers else "low",
        "redaction_status": "redacted" if blockers else "clean",
        "report_chain_allowed": not blockers,
        "safety_blockers": blockers,
    }


def _contains_secret_like_value(value: Any) -> bool:
    if isinstance(value, str):
        return _is_secret_like(value)
    if isinstance(value, dict):
        if _structured_secret_pair_value_keys(value):
            return True
        for key, nested_value in value.items():
            if _is_secret_key(str(key)):
                return True
            if _contains_secret_like_value(nested_value):
                return True
    elif isinstance(value, (list, tuple, set)):
        return any(_contains_secret_like_value(item) for item in value)
    return False


def _contains_real_user_data_risk(value: Any) -> bool:
    if isinstance(value, str):
        normalized = value.lower().replace("-", " ")
        return any(
            marker in normalized
            for marker in (
                "real user data",
                "customer data",
                "production user",
                "live user",
                "personal data",
                "pii",
            )
        )
    if isinstance(value, dict):
        for key, nested_value in value.items():
            normalized_key = str(key).lower().replace("-", "_")
            if normalized_key in {"real_user_data", "customer_data", "pii"}:
                return True
            if _contains_real_user_data_risk(nested_value):
                return True
    elif isinstance(value, (list, tuple, set)):
        return any(_contains_real_user_data_risk(item) for item in value)
    return False


def _iter_provenance_edges(value: Any) -> list[dict]:
    edges: list[dict] = []
    if isinstance(value, dict):
        raw_edges = value.get("provenance_edges")
        if isinstance(raw_edges, list):
            edges.extend(edge for edge in raw_edges if isinstance(edge, dict))
        for nested_value in value.values():
            edges.extend(_iter_provenance_edges(nested_value))
    elif isinstance(value, list):
        for item in value:
            edges.extend(_iter_provenance_edges(item))
    return edges


def _iter_provenance_refs(value: Any) -> list[str]:
    refs: list[str] = []
    if isinstance(value, dict):
        raw_refs = value.get("provenance_refs")
        if isinstance(raw_refs, list):
            refs.extend(str(ref) for ref in raw_refs)
        for nested_value in value.values():
            refs.extend(_iter_provenance_refs(nested_value))
    elif isinstance(value, list):
        for item in value:
            refs.extend(_iter_provenance_refs(item))
    return refs


def _program_to_record(program: Program) -> ProgramRecord:
    return ProgramRecord(
        id=program.id,
        name=program.name,
        platform=program.platform,
        bounty_range=program.bounty_range,
        scope_status=program.scope_status.value,
        automation=program.automation,
        testing_accounts=program.testing_accounts,
        api_docs=program.api_docs,
        public_code=program.public_code,
        duplicate_risk=program.duplicate_risk,
        priority=program.priority,
    )


def _finding_to_record(finding: Finding, program_id: str | None) -> FindingRecord:
    return FindingRecord(
        id=finding.id,
        program_id=program_id,
        program=finding.program,
        asset=finding.asset,
        title=finding.title,
        vuln_type=finding.vuln_type,
        severity_estimate=finding.severity_estimate,
        confidence=finding.confidence,
        scope_status=finding.scope_status.value,
        policy_status=finding.policy_status.value,
        broken_invariant=finding.broken_invariant,
        validation_status=finding.validation_status.value,
        refutation_status=finding.refutation_status,
        duplicate_likelihood=finding.duplicate_likelihood,
        submission_recommendation=finding.submission_recommendation,
        evidence_refs=finding.evidence_refs,
        operating_reasons=finding.operating_reasons,
    )


def _report_to_record(report: ReportDraft) -> ReportRecord:
    return ReportRecord(
        id=report.id,
        finding_id=report.finding_id,
        title=report.title,
        draft=report.draft,
    )


def _without_policy_text(value):
    if isinstance(value, dict):
        return {
            key: REDACTED
            if _is_secret_key(str(key))
            else _without_policy_text(item)
            for key, item in value.items()
            if key != "policy_text"
        }
    if isinstance(value, list):
        return [_without_policy_text(item) for item in value]
    return _safe_display_value(value)


def _initial_pipeline_payload(payload: dict) -> dict:
    safe_payload = _without_policy_text(payload)
    if not isinstance(safe_payload, dict):
        return {}
    return {
        key: value
        for key, value in safe_payload.items()
        if key not in {"manual_observations", "claim_review_decisions"}
    }


def _safe_source_path(value: str) -> str:
    path = value.split("?", 1)[0].split("#", 1)[0]
    return _safe_display_value(path)


def _safe_asset_value(value: str) -> str:
    text = value.strip()
    parsed = urlparse(text)
    if parsed.netloc:
        host = parsed.hostname or parsed.netloc
        try:
            port = parsed.port
        except ValueError:
            port = None
        if port is not None:
            host = f"{host}:{port}"
        text = f"{host}{parsed.path}"
    else:
        text = text.split("?", 1)[0].split("#", 1)[0]
    return _safe_display_value(text.rstrip("/") or text)


def _payload_string_set(payload: dict, key: str) -> set[str]:
    values = payload.get(key) if isinstance(payload, dict) else None
    if not isinstance(values, list):
        return set()
    return {value for value in values if isinstance(value, str) and value}


def _claim_review_has_evidence_support(payload: dict, decision: dict) -> bool:
    refs = _safe_evidence_refs(decision.get("evidence_refs", []))
    claim_id = _safe_display_value(decision.get("claim_id", ""))
    if refs:
        return set(refs) <= _supported_claim_review_refs(payload, claim_id)

    return bool(_manual_observation_refs_for_claim(payload, claim_id))


def _safe_evidence_refs(values: Any) -> list[str]:
    if not isinstance(values, list):
        return []
    return [
        ref
        for ref in (_safe_display_value(value) for value in values)
        if isinstance(ref, str) and ref and ref != REDACTED
    ]


def _supported_claim_review_refs(payload: dict, claim_id: str) -> set[str]:
    return {
        *_REPORT_SAFE_REVIEW_EVIDENCE_REFS,
        *_evidence_bundle_refs(payload),
        *_manual_observation_refs_for_claim(payload, claim_id),
    }


def _manual_observation_has_supported_evidence_refs(
    payload: dict,
    observation: dict,
) -> bool:
    refs = _safe_evidence_refs(observation.get("evidence_refs", []))
    if not refs:
        return True
    return set(refs) <= _supported_manual_observation_refs(payload)


def _supported_manual_observation_refs(payload: dict) -> set[str]:
    return {
        *_REPORT_SAFE_REVIEW_EVIDENCE_REFS,
        *_evidence_bundle_refs(payload),
    }


def _evidence_bundle_refs(payload: dict) -> set[str]:
    bundle = payload.get("evidence_bundle") if isinstance(payload, dict) else None
    items = bundle.get("items", []) if isinstance(bundle, dict) else []
    if not isinstance(items, list):
        return set()
    refs: set[str] = set()
    for item in items:
        if not isinstance(item, dict):
            continue
        refs.update(
            ref
            for ref in _safe_evidence_refs([item.get("type", "")])
            if ref in _REPORT_SAFE_REVIEW_EVIDENCE_REFS
        )
    return refs


def _manual_observation_refs_for_claim(payload: dict, claim_id: str) -> set[str]:
    observations = payload.get("manual_observations", []) if isinstance(payload, dict) else []
    if not claim_id or not isinstance(observations, list):
        return set()
    supported_refs = _supported_manual_observation_refs(payload)
    refs: set[str] = set()
    for observation in observations:
        if not isinstance(observation, dict):
            continue
        if observation.get("observation_type") not in _SECURITY_IMPACT_OBSERVATION_TYPES:
            continue
        if _safe_display_value(observation.get("claim_id", "")) != claim_id:
            continue
        refs.update(
            ref
            for ref in _safe_evidence_refs(observation.get("evidence_refs", []))
            if ref in supported_refs
        )
    return refs


def _payload_int(payload: dict, key: str) -> int | None:
    value = payload.get(key) if isinstance(payload, dict) else None
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def _payload_datetime(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return None
    return _as_utc(parsed)


def approval_record_is_active(approval: ApprovalRecord) -> bool:
    if approval.expires_at is None:
        return True
    return _as_utc(approval.expires_at) > datetime.now(UTC)


def _approval_initial_status(status: str | None, *, campaign_id: str | None) -> str:
    if status in APPROVAL_INITIAL_STATUSES:
        return status
    return "pending" if campaign_id is not None else "requested"


def _safe_display_value(value: Any) -> Any:
    if isinstance(value, str):
        return (
            REDACTED
            if _is_secret_like(value) or _contains_real_user_data_risk(value)
            else value
        )
    if isinstance(value, list):
        return [_safe_display_value(item) for item in value]
    if isinstance(value, tuple):
        return tuple(_safe_display_value(item) for item in value)
    if isinstance(value, dict):
        structured_secret_value_keys = _structured_secret_pair_value_keys(value)
        return {
            _safe_display_key(key): REDACTED
            if _is_secret_key(str(key))
            or _is_structured_secret_value_key(key, structured_secret_value_keys)
            else _safe_display_value(nested_value)
            for key, nested_value in value.items()
        }
    return value


def _safe_display_key(value: Any) -> Any:
    if isinstance(value, str) and (
        _is_secret_like(value) or _contains_real_user_data_risk(value)
    ):
        return REDACTED
    return value


def _learning_signal_identity_hash(
    *,
    program_id: str,
    playbook_id: str,
    outcome: str,
    surface_key: str | None,
    notes: str,
    bounty_amount: int | None,
    severity_delta: str | None,
    evidence_quality: str | None,
    triager_feedback: str | None,
    target_relationships: list[str],
) -> str | None:
    safe_values = {
        "program_id": program_id,
        "playbook_id": playbook_id,
        "outcome": outcome,
        "surface_key": _safe_display_value(surface_key),
        "notes": _safe_display_value(notes),
        "bounty_amount": bounty_amount,
        "severity_delta": _safe_display_value(severity_delta),
        "evidence_quality": _safe_display_value(evidence_quality),
        "triager_feedback": _safe_display_value(triager_feedback),
        "target_relationships": _safe_display_value(target_relationships),
    }
    original_values = {
        "program_id": program_id,
        "playbook_id": playbook_id,
        "outcome": outcome,
        "surface_key": surface_key,
        "notes": notes,
        "bounty_amount": bounty_amount,
        "severity_delta": severity_delta,
        "evidence_quality": evidence_quality,
        "triager_feedback": triager_feedback,
        "target_relationships": target_relationships,
    }
    if safe_values != original_values:
        return None
    encoded = json.dumps(safe_values, sort_keys=True, separators=(",", ":"))
    return sha256(encoded.encode("utf-8")).hexdigest()


def _is_secret_key(value: str) -> bool:
    normalized = value.lower().replace("-", "_")
    if normalized in TOKEN_USAGE_KEYS:
        return False
    return any(
        marker in normalized
        for marker in (
            "authorization",
            "api_key",
            "apikey",
            "cookie",
            "token",
            "secret",
            "password",
            "credential",
            "session",
        )
    )


def _structured_secret_pair_value_keys(value: dict) -> set[str]:
    value_keys = {
        key.lower()
        for key in value
        if isinstance(key, str) and key.lower() in {"value", "contents"}
    }
    if not value_keys:
        return set()
    for identifier_key in ("name", "key"):
        identifier = value.get(identifier_key)
        if isinstance(identifier, str) and _is_secret_key(identifier):
            return value_keys
    return set()


def _is_structured_secret_value_key(key: Any, sensitive_keys: set[str]) -> bool:
    return isinstance(key, str) and key.lower() in sensitive_keys


def _is_secret_like(value: str) -> bool:
    normalized = value.lower()
    secret_markers = (
        "authorization:",
        "api-key:",
        "api_key=",
        "bearer ",
        "cookie:",
        "secret=",
        "set-cookie:",
        "session=",
        "sk-",
        "token=",
        "x-api-key:",
    )
    return (
        any(marker in normalized for marker in secret_markers)
        or re.search(
            (
                r"\b(?:[a-z0-9]+[_-])*"
                r"(?:password|passwd|pwd|credential|token|secret|session|cookie|api[_-]?key)"
                r"\s*[:=]"
            ),
            normalized,
        )
        is not None
        or EMAIL_PATTERN.search(value) is not None
        or JWT_PATTERN.search(value) is not None
    )


def _safe_evidence_ref_count(evidence_refs: Any) -> int:
    if not isinstance(evidence_refs, list):
        return 0
    return len(
        {
            evidence_ref
            for evidence_ref in evidence_refs
            if _is_report_safe_evidence_ref(evidence_ref)
        }
    )


def _is_report_safe_evidence_ref(value: Any) -> bool:
    return (
        isinstance(value, str)
        and value != REDACTED
        and value in _REPORT_SAFE_REVIEW_EVIDENCE_REFS
    )


def _contains_redacted_value(value: Any) -> bool:
    if value == REDACTED:
        return True
    if isinstance(value, (list, tuple)):
        return any(_contains_redacted_value(item) for item in value)
    if isinstance(value, dict):
        return any(_contains_redacted_value(item) for item in value.values())
    return False


def _has_diverse_safe_evidence_refs(evidence_refs: Any) -> bool:
    if not isinstance(evidence_refs, list):
        return False
    safe_refs = {
        evidence_ref
        for evidence_ref in evidence_refs
        if _is_report_safe_evidence_ref(evidence_ref)
    }
    return bool(
        safe_refs & _REQUEST_TRACE_EVIDENCE_REFS
        and safe_refs & _CORROBORATING_EVIDENCE_REFS
    )


def _validation_result_review(
    *,
    outcome: str,
    summary: str,
    evidence_refs: Any,
    safe_evidence_ref_count: int,
) -> dict:
    evidence_ref_list = evidence_refs if isinstance(evidence_refs, list) else []
    unsafe_evidence_ref_count = sum(
        1
        for ref in evidence_ref_list
        if not _is_report_safe_evidence_ref(ref)
    )
    redaction_required = (
        _safe_display_value(summary) == REDACTED
        or _contains_redacted_value(evidence_ref_list)
    )
    unsupported_evidence_ref_present = unsafe_evidence_ref_count > 0
    diverse_safe_evidence_refs = _has_diverse_safe_evidence_refs(evidence_ref_list)

    quality_score = 0
    quality_reasons = ["manual_result_recorded"]
    if outcome == "observed":
        quality_score += 25
    elif outcome == "refuted":
        quality_score += 15
        quality_reasons.append("claim_refuted")
    else:
        quality_reasons.append("needs_more_evidence")

    if safe_evidence_ref_count > 0:
        quality_score += min(40, safe_evidence_ref_count * 20)
        quality_reasons.append("has_report_safe_evidence")
    else:
        quality_reasons.append("missing_report_safe_evidence")

    if redaction_required:
        quality_reasons.append("sensitive_material_redacted")
        quality_reasons.append("promotion_blocked_by_redaction_review")
    else:
        quality_score += 15
        quality_reasons.append("clean_redaction_review")
    if unsupported_evidence_ref_present:
        quality_reasons.append("unsupported_evidence_refs")
        quality_reasons.append("promotion_blocked_by_unsupported_evidence")

    if (
        outcome == "observed"
        and safe_evidence_ref_count >= 3
        and diverse_safe_evidence_refs
        and not redaction_required
        and not unsupported_evidence_ref_present
    ):
        evidence_quality = "strong"
    elif outcome == "observed" and safe_evidence_ref_count > 0:
        evidence_quality = "adequate"
    else:
        evidence_quality = "weak"

    promotion_review_ready = (
        outcome == "observed"
        and evidence_quality == "strong"
        and not redaction_required
        and not unsupported_evidence_ref_present
    )
    if (
        outcome == "observed"
        and safe_evidence_ref_count > 0
        and not promotion_review_ready
        and not redaction_required
        and not unsupported_evidence_ref_present
    ):
        quality_reasons.append("promotion_blocked_by_insufficient_evidence")
        if safe_evidence_ref_count >= 3 and not diverse_safe_evidence_refs:
            quality_reasons.append("promotion_blocked_by_low_evidence_diversity")

    return {
        "source_type": "manual_safe_observation",
        "redaction_status": "redacted" if redaction_required else "clean",
        "evidence_quality": evidence_quality,
        "quality_score": min(100, quality_score),
        "promotion_review_ready": promotion_review_ready,
        "quality_reasons": quality_reasons,
        "safe_evidence_ref_count": safe_evidence_ref_count,
        "unsafe_evidence_ref_count": max(0, unsafe_evidence_ref_count),
    }


def _validation_result_status(outcome: str, *, safe_evidence_ref_count: int) -> str:
    if outcome == "refuted":
        return "refuted"
    if outcome == "needs_more_evidence" or safe_evidence_ref_count == 0:
        return "needs_evidence"
    return "evidence_recorded"


def _validation_result_safety_gate(outcome: str, *, safe_evidence_ref_count: int) -> str:
    if outcome == "refuted":
        return "manual_refutation_recorded"
    if outcome == "needs_more_evidence" or safe_evidence_ref_count == 0:
        return "manual_evidence_gap_recorded"
    return "manual_evidence_recorded"


def _validation_initial_allowed_to_execute(
    allowed_to_execute: bool,
    *,
    approval_required: bool,
    status: str,
) -> bool:
    if approval_required and status != "preflight_passed":
        return False
    return allowed_to_execute


def _program_from_record(record: ProgramRecord) -> Program:
    return Program(
        id=record.id,
        name=record.name,
        platform=record.platform,
        bounty_range=record.bounty_range,
        scope_status=record.scope_status,
        automation=record.automation,
        testing_accounts=record.testing_accounts,
        api_docs=record.api_docs,
        public_code=record.public_code,
        duplicate_risk=record.duplicate_risk,
        priority=record.priority,
    )


def _finding_from_record(record: FindingRecord) -> Finding:
    return Finding(
        id=record.id,
        program=record.program,
        asset=record.asset,
        title=record.title,
        vuln_type=record.vuln_type,
        severity_estimate=record.severity_estimate,
        confidence=record.confidence,
        scope_status=record.scope_status,
        policy_status=record.policy_status,
        broken_invariant=record.broken_invariant,
        validation_status=record.validation_status,
        refutation_status=record.refutation_status,
        duplicate_likelihood=record.duplicate_likelihood,
        submission_recommendation=record.submission_recommendation,
        evidence_refs=record.evidence_refs,
        operating_reasons=record.operating_reasons,
    )


def _report_from_record(record: ReportRecord) -> ReportDraft:
    return ReportDraft(
        id=record.id,
        finding_id=record.finding_id,
        title=record.title,
        draft=record.draft,
    )
