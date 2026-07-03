from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db_models import FindingRecord, ProgramRecord, ReportRecord
from app.models import Finding, Program, ReportDraft
from app.sample_data import FINDINGS, PROGRAMS, REPORTS


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
