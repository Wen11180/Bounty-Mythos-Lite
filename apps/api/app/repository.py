from datetime import UTC, datetime
from hashlib import sha256
import re
from typing import Any
from uuid import uuid4

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db_models import (
    AgentRunRecord,
    ApprovalRecord,
    ArtifactRecord,
    CampaignBudgetRecord,
    CampaignRecord,
    CampaignTaskRecord,
    FindingRecord,
    LearningSignalRecord,
    LLMRunRecord,
    PipelineStageRecord,
    PipelineRunRecord,
    ProgramRecord,
    ReportRecord,
)
from app.models import Finding, Program, ReportDraft
from app.sample_data import FINDINGS, PROGRAMS, REPORTS


REDACTED = "[REDACTED]"
EMAIL_PATTERN = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE)
JWT_PATTERN = re.compile(
    r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"
)


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
        existing = self.session.scalars(
            select(ArtifactRecord).where(ArtifactRecord.source_hash == source_hash)
        ).first()
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
            asset=asset,
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
        if asset is not None:
            query = query.where(ArtifactRecord.asset == asset)
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
        for usage_record in usage_records:
            safe_usage_record = _safe_display_value(usage_record)
            if safe_usage_record not in updated_usage_records:
                updated_usage_records.append(safe_usage_record)

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
            payload=_without_policy_text(payload),
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
    ) -> PipelineRunRecord | None:
        record = self.get_pipeline_run(run_id)
        if record is None:
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
    ) -> PipelineRunRecord | None:
        record = self.get_pipeline_run(run_id)
        if record is None:
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
            default_asset=_safe_display_value(default_asset),
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
        record.status = _safe_display_value(status)
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
            asset=_safe_display_value(asset),
            validation_mode=_safe_display_value(validation_mode),
            plan_digest=_safe_display_value(plan_digest),
            autonomy_level=_safe_display_value(autonomy_level),
            safety_gate_state=_safe_display_value(safety_gate_state),
            status=status or ("pending" if campaign_id is not None else "requested"),
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
        record.status = _safe_display_value(decision)
        record.decided_by = _safe_display_value(actor)
        record.decision_reason = _safe_display_value(reason)
        record.decided_at = datetime.now(UTC)
        self.session.add(record)
        self.session.commit()
        self.session.refresh(record)
        return record

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
            payload=_safe_display_value(payload or {}),
        )
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
    ) -> LearningSignalRecord:
        record = LearningSignalRecord(
            id=f"learning_signal_{uuid4().hex}",
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
        self.session.commit()
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
        return {
            key: REDACTED
            if _is_secret_key(str(key))
            else _safe_display_value(nested_value)
            for key, nested_value in value.items()
        }
    return value


def _is_secret_key(value: str) -> bool:
    normalized = value.lower().replace("-", "_")
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
        )
    )


def _is_secret_like(value: str) -> bool:
    normalized = value.lower()
    secret_markers = (
        "authorization:",
        "bearer ",
        "cookie:",
        "set-cookie:",
        "session=",
        "sk-",
    )
    return (
        any(marker in normalized for marker in secret_markers)
        or EMAIL_PATTERN.search(value) is not None
        or JWT_PATTERN.search(value) is not None
    )


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
