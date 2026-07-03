from hashlib import sha256
from typing import Any
from uuid import uuid4

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db_models import ArtifactRecord, FindingRecord, PipelineRunRecord, ProgramRecord, ReportRecord
from app.models import Finding, Program, ReportDraft
from app.sample_data import FINDINGS, PROGRAMS, REPORTS


REDACTED = "[REDACTED]"


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

    def list_reports(self) -> list[ReportDraft]:
        records = self.session.scalars(select(ReportRecord).order_by(ReportRecord.id)).all()
        return [_report_from_record(record) for record in records]

    def get_report(self, report_id: str) -> ReportDraft | None:
        record = self.session.get(ReportRecord, report_id)
        if record is None:
            return None
        return _report_from_record(record)

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
            return existing

        record = ArtifactRecord(
            id=f"artifact_{uuid4().hex}",
            program_id=program_id,
            asset=asset,
            kind=kind,
            source_type=source_type,
            source_hash=source_hash,
            ingestion_status=ingestion_status,
            provenance=_safe_display_value(provenance),
            payload_summary=_safe_display_value(payload_summary),
            derived_facts=_safe_display_value(derived_facts),
        )
        self.session.add(record)
        self.session.commit()
        self.session.refresh(record)
        return record

    def list_artifacts(self) -> list[ArtifactRecord]:
        return self.session.scalars(
            select(ArtifactRecord).order_by(
                ArtifactRecord.created_at.desc(),
                ArtifactRecord.id.desc(),
            )
        ).all()

    def get_artifact(self, artifact_id: str) -> ArtifactRecord | None:
        return self.session.get(ArtifactRecord, artifact_id)

    def save_pipeline_run(
        self,
        *,
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
            key: _without_policy_text(item)
            for key, item in value.items()
            if key != "policy_text"
        }
    if isinstance(value, list):
        return [_without_policy_text(item) for item in value]
    return value


def _safe_display_value(value: Any) -> Any:
    if isinstance(value, str):
        return REDACTED if _is_secret_like(value) else value
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
            "token",
            "secret",
            "password",
            "credential",
        )
    )


def _is_secret_like(value: str) -> bool:
    normalized = value.lower()
    return "authorization:" in normalized or "bearer " in normalized or "sk-" in value


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
    )


def _report_from_record(record: ReportRecord) -> ReportDraft:
    return ReportDraft(
        id=record.id,
        finding_id=record.finding_id,
        title=record.title,
        draft=record.draft,
    )
