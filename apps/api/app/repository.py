from datetime import UTC, datetime, timedelta
from hashlib import sha256
import json
import re
import secrets
from collections.abc import Callable
from copy import deepcopy
from typing import Any
from urllib.parse import urlparse
from uuid import uuid4

from sqlalchemy import and_, case, func, or_, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.bounded_result_claims import TrustedBoundedResultClaim
from app.db_models import (
    AgentRunRecord,
    ApprovalRecord,
    ArtifactRecord,
    AutopilotCandidateRevisionRecord,
    AutopilotEvidenceClaimRecord,
    AutopilotHumanEvidenceReviewRecord,
    AutopilotObservationRecord,
    AutopilotRefutationDecisionRecord,
    AutopilotReportRevisionRecord,
    AutopilotRiskDecisionRecord,
    AutopilotToolRunRecord,
    AutonomousResearchWakeupStateRecord,
    CampaignAuthorizationRecord,
    CampaignAssetRecord,
    CampaignAssetAdmissionEventRecord,
    CampaignBudgetRecord,
    CampaignLocalToolExecutionSlotRecord,
    CampaignRecord,
    CampaignTaskRecord,
    CodebaseFactRecord,
    CodebaseMapRecord,
    ExecutionLeaseRecord,
    ExecutionRequestLedgerRecord,
    FindingRecord,
    LearningSignalRecord,
    LLMRunRecord,
    PipelineStageRecord,
    PipelineRunRecord,
    ProgramRuleSnapshotRecord,
    ProgramRuleSourceRecord,
    ProgramScopeRuleRecord,
    ProgramRecord,
    ReportRecord,
    ResearchBranchRecord,
    ScannerRunRecord,
    ValidationPlanRecord,
    ValidationRunRecord,
)
from app.models import Finding, Program, ReportDraft
from app.program_rule_intake.contracts import canonicalize_public_https_url
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
_PROGRAM_RULE_ALIAS_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
AUTONOMOUS_RESEARCH_WAKEUP_PAGE_SIZE = 20
AUTONOMOUS_RESEARCH_WAKEUP_LEASE_SECONDS = 120
_LOCAL_TOOL_CALL_RESERVATION_SCHEMA = "research_director_tool_call_reservation_v1"
_LOCAL_TOOL_CALL_RESERVATION_MARKER = "research_director_tool_call_reservation"
_LOCAL_TOOL_CALL_RESERVATION_METADATA_KEYS = (
    _LOCAL_TOOL_CALL_RESERVATION_MARKER,
    "tool_call_reserved",
    "tool_call_reservation_schema",
    "tool_call_reservation_campaign_id",
    "tool_call_reservation_task_id",
    "tool_call_reservation_agent_run_id",
    "tool_call_reservation_research_plan_id",
    "tool_call_reservation_research_plan_digest",
    "tool_call_reservation_source_snapshot_digest",
    "tool_call_reservation_tool_id",
)
AUTONOMOUS_RESEARCH_WAKEUP_INTERVAL_SECONDS = 60
AUTONOMOUS_RESEARCH_TASK_LEASE_SECONDS = 900
_AUTONOMOUS_RESEARCH_RUNTIME_SCHEMA = "autonomous_research_v1"
_CANDIDATE_HUNTER_EVIDENCE_TASK_TYPE = "candidate_hunter_evidence_inspection"
_CANDIDATE_HUNTER_EVIDENCE_TASK_SCHEMA = "candidate_hunter_evidence_task_v1"
_RESEARCH_DIRECTOR_LOCAL_TOOL_TASK_TYPE = "research_director_local_tool_run"
_RESEARCH_DIRECTOR_LOCAL_TOOL_TASK_SCHEMA = "research_director_local_tool_run_v1"
_LOCAL_TOOL_EXECUTION_SLOT_LEGACY_MARKER = "local_tool_execution_slot_legacy"
_AUTONOMOUS_RESEARCH_WAKEUP_STATE_ID = "autonomous_research_wakeup"
_AUTONOMOUS_RESEARCH_WAKEUP_FINAL_STATUSES = frozenset({"completed", "failed"})
_AUTONOMOUS_RESEARCH_WAKEUP_STOP_REASONS = frozenset(
    {
        "wakeup_candidate_invalid",
        "wakeup_candidate_query_failed",
        "wakeup_campaign_tick_failed",
    }
)
_AUTONOMOUS_RESEARCH_WAKEUP_OUTCOME_STATUS_PATTERN = re.compile(
    r"^[a-z][a-z0-9_:-]{0,127}$"
)
_PROGRAM_RULE_RAW_HTML_PATTERN = re.compile(
    r"<!doctype\s+html|</?html(?:\s|>)|</?body(?:\s|>)",
    re.IGNORECASE,
)
_PROGRAM_RULE_FORBIDDEN_KEYS = {
    "authorization",
    "bodybase64",
    "browserstate",
    "components",
    "cookie",
    "cookies",
    "customeremail",
    "customerid",
    "customername",
    "customerphone",
    "examples",
    "har",
    "headers",
    "localstorage",
    "openapi",
    "parameters",
    "pii",
    "rawbody",
    "rawhtml",
    "rawopenapi",
    "requestbody",
    "requestheaders",
    "responsebody",
    "responseheaders",
    "responses",
    "schemas",
    "securityschemes",
    "sessionstorage",
    "setcookie",
    "storagestate",
    "swagger",
    "useremail",
    "userid",
    "username",
    "userphone",
}


def _campaign_task_requires_execution_lease(
    record: CampaignTaskRecord,
    payload: dict,
) -> bool:
    return payload.get("runtime_schema") == _AUTONOMOUS_RESEARCH_RUNTIME_SCHEMA or (
        record.task_type == _CANDIDATE_HUNTER_EVIDENCE_TASK_TYPE
        and payload.get("schema_version") == _CANDIDATE_HUNTER_EVIDENCE_TASK_SCHEMA
        and payload.get("execution_lease_required") is True
    ) or _is_research_director_local_tool_task(record, payload)


def _is_research_director_local_tool_task(
    record: CampaignTaskRecord,
    payload: dict,
) -> bool:
    return (
        record.task_type == _RESEARCH_DIRECTOR_LOCAL_TOOL_TASK_TYPE
        and payload.get("schema_version") == _RESEARCH_DIRECTOR_LOCAL_TOOL_TASK_SCHEMA
        and payload.get("execution_lease_required") is True
    )


def _research_director_local_tool_source_snapshot_digest(
    payload: dict,
) -> str | None:
    source_snapshot_digest = payload.get("source_snapshot_digest")
    if (
        not isinstance(source_snapshot_digest, str)
        or len(source_snapshot_digest) != 71
        or not source_snapshot_digest.startswith("sha256:")
        or _SHA256_PATTERN.fullmatch(source_snapshot_digest.removeprefix("sha256:"))
        is None
    ):
        return None
    return source_snapshot_digest


def _campaign_local_tool_execution_slot_id(
    *,
    campaign_id: str,
    source_snapshot_digest: str,
) -> str:
    identity = f"{campaign_id}:{source_snapshot_digest}".encode("utf-8")
    return f"local_tool_slot_{sha256(identity).hexdigest()}"


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

    def create_program_rule_source(
        self,
        *,
        program_alias: str,
        registered_url: str,
        now: datetime,
    ) -> ProgramRuleSourceRecord:
        safe_alias = _program_rule_safe_alias(program_alias)
        safe_registered_url = _program_rule_safe_text(registered_url)
        canonical_url = _program_rule_safe_text(
            canonicalize_public_https_url(safe_registered_url)
        )
        existing = self.session.scalar(
            select(ProgramRuleSourceRecord).where(
                ProgramRuleSourceRecord.canonical_url == canonical_url
            )
        )
        if existing is not None:
            return existing

        identity_digest = sha256(canonical_url.encode("utf-8")).hexdigest()
        source_id = f"program_rule_source_{identity_digest[:32]}"
        program_id = f"public_url_program_{identity_digest[:32]}"
        timestamp = _as_utc(now)
        program = self.session.get(ProgramRecord, program_id)
        if program is None:
            self.session.add(
                ProgramRecord(
                    id=program_id,
                    name=safe_alias,
                    platform="public_url",
                    bounty_range="unknown",
                    scope_status="needs_review",
                    automation="needs_review",
                    testing_accounts="not_provided",
                    api_docs="not_provided",
                    public_code="not_provided",
                    duplicate_risk="unknown",
                    priority="unranked",
                )
            )
        record = ProgramRuleSourceRecord(
            id=source_id,
            program_id=program_id,
            program_alias=safe_alias,
            registered_url=safe_registered_url,
            canonical_url=canonical_url,
            refresh_interval_seconds=86_400,
            fetch_status="scheduled",
            next_check_at=timestamp,
            failure_count=0,
            created_at=timestamp,
            updated_at=timestamp,
        )
        self.session.add(record)
        try:
            self.session.commit()
        except IntegrityError:
            self.session.rollback()
            existing = self.session.scalar(
                select(ProgramRuleSourceRecord).where(
                    ProgramRuleSourceRecord.canonical_url == canonical_url
                )
            )
            if existing is None:
                raise
            return existing
        self.session.refresh(record)
        return record

    def list_program_rule_sources(self) -> list[ProgramRuleSourceRecord]:
        return self.session.scalars(
            select(ProgramRuleSourceRecord).order_by(ProgramRuleSourceRecord.id)
        ).all()

    def get_program_rule_source(
        self,
        source_id: str,
    ) -> ProgramRuleSourceRecord | None:
        return self.session.get(ProgramRuleSourceRecord, source_id)

    def get_program_rule_source_by_canonical_url(
        self,
        canonical_url: str,
    ) -> ProgramRuleSourceRecord | None:
        canonical = canonicalize_public_https_url(canonical_url)
        return self.session.scalar(
            select(ProgramRuleSourceRecord).where(
                ProgramRuleSourceRecord.canonical_url == canonical
            )
        )

    def schedule_program_rule_source_refresh(
        self,
        *,
        source_id: str,
        now: datetime,
        manual: bool,
    ) -> ProgramRuleSourceRecord | None:
        record = self.session.get(ProgramRuleSourceRecord, source_id)
        if record is None:
            return None
        timestamp = _as_utc(now)
        claim_is_live = (
            record.claim_id is not None
            and record.claim_token_digest is not None
            and record.claim_expires_at is not None
            and _as_utc(record.claim_expires_at) > timestamp
        )
        if not claim_is_live:
            record.fetch_status = "scheduled"
            record.next_check_at = timestamp
        if manual:
            record.last_manual_refresh_at = timestamp
        record.updated_at = timestamp
        self.session.add(record)
        self.session.commit()
        self.session.refresh(record)
        return record

    def claim_next_due_program_rule_source(
        self,
        *,
        claim_id: str,
        claim_token_digest: str,
        now: datetime,
    ) -> ProgramRuleSourceRecord | None:
        if not isinstance(claim_id, str) or not claim_id or len(claim_id) > 100:
            raise ValueError("program-rule claim identifier is invalid")
        _program_rule_sha256(claim_token_digest)
        timestamp = _as_utc(now)
        expires_at = timestamp + timedelta(minutes=15)
        claimable = or_(
            and_(
                ProgramRuleSourceRecord.claim_id.is_(None),
                ProgramRuleSourceRecord.claim_token_digest.is_(None),
            ),
            and_(
                ProgramRuleSourceRecord.claim_expires_at.is_not(None),
                ProgramRuleSourceRecord.claim_expires_at <= timestamp,
            ),
        )
        candidate_id = (
            select(ProgramRuleSourceRecord.id)
            .where(
                ProgramRuleSourceRecord.next_check_at <= timestamp,
                claimable,
            )
            .order_by(
                ProgramRuleSourceRecord.next_check_at,
                ProgramRuleSourceRecord.id,
            )
            .limit(1)
            .scalar_subquery()
        )
        statement = (
            update(ProgramRuleSourceRecord)
            .where(
                ProgramRuleSourceRecord.id == candidate_id,
                ProgramRuleSourceRecord.next_check_at <= timestamp,
                claimable,
            )
            .values(
                fetch_status="fetching",
                claim_id=claim_id,
                claim_token_digest=claim_token_digest,
                claim_started_at=timestamp,
                claim_expires_at=expires_at,
                updated_at=timestamp,
            )
            .execution_options(synchronize_session=False)
        )
        result = self.session.execute(statement)
        self.session.commit()
        if result.rowcount != 1:
            return None
        self.session.expire_all()
        return self.session.scalar(
            select(ProgramRuleSourceRecord).where(
                ProgramRuleSourceRecord.claim_id == claim_id,
                ProgramRuleSourceRecord.claim_token_digest == claim_token_digest,
                ProgramRuleSourceRecord.claim_started_at == timestamp,
            )
        )

    def get_active_program_rule_source_claim(
        self,
        *,
        source_id: str,
        claim_id: str,
        claim_token_digest: str,
        now: datetime,
    ) -> ProgramRuleSourceRecord | None:
        if _SHA256_PATTERN.fullmatch(claim_token_digest) is None:
            return None
        return self.session.scalar(
            select(ProgramRuleSourceRecord).where(
                ProgramRuleSourceRecord.id == source_id,
                ProgramRuleSourceRecord.fetch_status == "fetching",
                ProgramRuleSourceRecord.claim_id == claim_id,
                ProgramRuleSourceRecord.claim_token_digest == claim_token_digest,
                ProgramRuleSourceRecord.claim_expires_at.is_not(None),
                ProgramRuleSourceRecord.claim_expires_at > _as_utc(now),
            )
        )

    def finish_program_rule_source_claim(
        self,
        *,
        source_id: str,
        claim_id: str,
        claim_token_digest: str,
        now: datetime,
        next_check_at: datetime,
        succeeded: bool,
        failure_code: str | None = None,
    ) -> ProgramRuleSourceRecord | None:
        if _SHA256_PATTERN.fullmatch(claim_token_digest) is None:
            return None
        timestamp = _as_utc(now)
        values: dict[str, Any] = {
            "fetch_status": "ok" if succeeded else "failed",
            "last_check_at": timestamp,
            "next_check_at": _as_utc(next_check_at),
            "failure_code": None
            if succeeded
            else _program_rule_safe_text(failure_code or "fetch_failed"),
            "claim_id": None,
            "claim_token_digest": None,
            "claim_started_at": None,
            "claim_expires_at": None,
            "updated_at": timestamp,
        }
        if succeeded:
            values["last_success_at"] = timestamp
            values["failure_count"] = 0
        else:
            values["failure_count"] = ProgramRuleSourceRecord.failure_count + 1
        statement = (
            update(ProgramRuleSourceRecord)
            .where(
                ProgramRuleSourceRecord.id == source_id,
                ProgramRuleSourceRecord.fetch_status == "fetching",
                ProgramRuleSourceRecord.claim_id == claim_id,
                ProgramRuleSourceRecord.claim_token_digest == claim_token_digest,
                ProgramRuleSourceRecord.claim_expires_at.is_not(None),
                ProgramRuleSourceRecord.claim_expires_at > timestamp,
            )
            .values(**values)
            .execution_options(synchronize_session=False)
        )
        result = self.session.execute(statement)
        self.session.commit()
        if result.rowcount != 1:
            return None
        self.session.expire_all()
        return self.session.get(ProgramRuleSourceRecord, source_id)

    def find_program_rule_snapshot(
        self,
        source_id: str,
        normalized_sha256: str,
    ) -> ProgramRuleSnapshotRecord | None:
        _program_rule_sha256(normalized_sha256)
        return self.session.scalar(
            select(ProgramRuleSnapshotRecord).where(
                ProgramRuleSnapshotRecord.source_id == source_id,
                ProgramRuleSnapshotRecord.normalized_sha256 == normalized_sha256,
            )
        )

    def get_program_rule_snapshot(
        self,
        snapshot_id: str,
    ) -> ProgramRuleSnapshotRecord | None:
        return self.session.get(ProgramRuleSnapshotRecord, snapshot_id)

    def save_program_rule_snapshot(
        self,
        *,
        source_id: str,
        raw_aggregate_sha256: str,
        normalized_sha256: str,
        fetched_at: datetime,
        fetch_mode: str,
        content_types: list[str],
        detected_language: str,
        extraction: dict,
        evidence: list[dict],
        linked_documents: list[dict],
        openapi_candidates: list[dict],
        ai_status: str,
        review_status: str,
        review_digest: str,
    ) -> ProgramRuleSnapshotRecord:
        if self.session.get(ProgramRuleSourceRecord, source_id) is None:
            raise ValueError("program-rule source does not exist")
        _program_rule_sha256(raw_aggregate_sha256)
        _program_rule_sha256(normalized_sha256)
        _program_rule_sha256(review_digest)
        existing = self.find_program_rule_snapshot(source_id, normalized_sha256)
        if existing is not None:
            return existing

        safe_content_types = _program_rule_safe_json(content_types)
        safe_extraction = _program_rule_safe_json(extraction)
        safe_evidence = _program_rule_safe_json(evidence)
        safe_linked_documents = _program_rule_safe_json(linked_documents)
        safe_openapi_candidates = _program_rule_safe_json(openapi_candidates)
        snapshot_digest = sha256(
            f"{source_id}\0{normalized_sha256}".encode("utf-8")
        ).hexdigest()
        record = ProgramRuleSnapshotRecord(
            id=f"program_rule_snapshot_{snapshot_digest[:32]}",
            source_id=source_id,
            raw_aggregate_sha256=raw_aggregate_sha256,
            normalized_sha256=normalized_sha256,
            fetched_at=_as_utc(fetched_at),
            fetch_mode=_program_rule_safe_text(fetch_mode),
            content_types=safe_content_types,
            detected_language=_program_rule_safe_text(detected_language),
            extraction=safe_extraction,
            evidence=safe_evidence,
            linked_documents=safe_linked_documents,
            openapi_candidates=safe_openapi_candidates,
            ai_status=_program_rule_safe_text(ai_status),
            review_status=_program_rule_safe_text(review_status),
            review_digest=review_digest,
            execution_allowed=False,
            lease_grant_allowed=False,
            scope_change_allowed=False,
            review_bypass_allowed=False,
            report_submission_allowed=False,
            created_at=_as_utc(fetched_at),
        )
        self.session.add(record)
        try:
            self.session.commit()
        except IntegrityError:
            self.session.rollback()
            existing = self.find_program_rule_snapshot(source_id, normalized_sha256)
            if existing is None:
                raise
            return existing
        self.session.refresh(record)
        return record

    def list_program_rule_snapshots(
        self,
        source_id: str,
    ) -> list[ProgramRuleSnapshotRecord]:
        return self.session.scalars(
            select(ProgramRuleSnapshotRecord)
            .where(ProgramRuleSnapshotRecord.source_id == source_id)
            .order_by(
                ProgramRuleSnapshotRecord.fetched_at.desc(),
                ProgramRuleSnapshotRecord.id.desc(),
            )
        ).all()

    def update_program_rule_snapshot_review(
        self,
        *,
        source_id: str,
        snapshot_id: str,
        review_status: str,
        reviewer_alias: str,
        reviewed_at: datetime,
    ) -> ProgramRuleSnapshotRecord | None:
        record = self.session.get(ProgramRuleSnapshotRecord, snapshot_id)
        if record is None or record.source_id != source_id:
            return None
        if review_status not in {"approved", "rejected"}:
            raise ValueError("program-rule review status is invalid")
        record.review_status = review_status
        record.reviewer_alias = _program_rule_safe_alias(reviewer_alias)
        record.reviewed_at = _as_utc(reviewed_at)
        self.session.add(record)
        self.session.commit()
        self.session.refresh(record)
        return record

    def set_program_rule_source_snapshot_pointers(
        self,
        *,
        source_id: str,
        approved_snapshot_id: str | None,
        pending_snapshot_id: str | None,
        updated_at: datetime,
    ) -> ProgramRuleSourceRecord | None:
        source = self.session.get(ProgramRuleSourceRecord, source_id)
        if source is None:
            return None
        for snapshot_id in (approved_snapshot_id, pending_snapshot_id):
            if snapshot_id is None:
                continue
            snapshot = self.session.get(ProgramRuleSnapshotRecord, snapshot_id)
            if snapshot is None or snapshot.source_id != source_id:
                raise ValueError("snapshot pointer is invalid for program-rule source")
        source.approved_snapshot_id = approved_snapshot_id
        source.pending_snapshot_id = pending_snapshot_id
        source.updated_at = _as_utc(updated_at)
        self.session.add(source)
        self.session.commit()
        self.session.refresh(source)
        return source

    def replace_program_scope_rules(
        self,
        *,
        program_id: str,
        source_id: str,
        approved_snapshot_id: str,
        approval_digest: str,
        effective_at: datetime,
        rules: list[dict],
    ) -> list[ProgramScopeRuleRecord]:
        _program_rule_sha256(approval_digest)
        source = self.session.get(ProgramRuleSourceRecord, source_id)
        snapshot = self.session.get(ProgramRuleSnapshotRecord, approved_snapshot_id)
        if (
            source is None
            or source.program_id != program_id
            or snapshot is None
            or snapshot.source_id != source_id
            or self.session.get(ProgramRecord, program_id) is None
        ):
            raise ValueError("program-rule scope relationship is invalid")

        desired = sorted(
            (_program_scope_rule_values(rule) for rule in rules),
            key=lambda value: value["canonical_asset"],
        )
        if len({value["canonical_asset"] for value in desired}) != len(desired):
            raise ValueError("program-rule scope assets must be unique")
        existing = self.list_program_scope_rules(
            program_id,
            approved_snapshot_id=approved_snapshot_id,
        )
        if existing:
            if not _program_scope_rules_match(
                existing,
                desired,
                approval_digest=approval_digest,
            ):
                raise ValueError("approved program scope rules are immutable")
            return existing

        timestamp = _as_utc(effective_at)
        records = []
        for values in desired:
            rule_digest = sha256(
                f"{approved_snapshot_id}\0{values['canonical_asset']}".encode("utf-8")
            ).hexdigest()
            records.append(
                ProgramScopeRuleRecord(
                    id=f"program_scope_rule_{rule_digest[:32]}",
                    program_id=program_id,
                    source_id=source_id,
                    approved_snapshot_id=approved_snapshot_id,
                    approval_digest=approval_digest,
                    effective_at=timestamp,
                    **values,
                )
            )
        self.session.add_all(records)
        try:
            self.session.commit()
        except IntegrityError:
            self.session.rollback()
            existing = self.list_program_scope_rules(
                program_id,
                approved_snapshot_id=approved_snapshot_id,
            )
            if not _program_scope_rules_match(
                existing,
                desired,
                approval_digest=approval_digest,
            ):
                raise
            return existing
        for record in records:
            self.session.refresh(record)
        return records

    def list_program_scope_rules(
        self,
        program_id: str,
        *,
        approved_snapshot_id: str | None = None,
    ) -> list[ProgramScopeRuleRecord]:
        query = select(ProgramScopeRuleRecord).where(
            ProgramScopeRuleRecord.program_id == program_id
        )
        if approved_snapshot_id is not None:
            query = query.where(
                ProgramScopeRuleRecord.approved_snapshot_id == approved_snapshot_id
            )
        return self.session.scalars(
            query.order_by(
                ProgramScopeRuleRecord.effective_at.desc(),
                ProgramScopeRuleRecord.canonical_asset,
            )
        ).all()

    def project_program_rule_program_summary(
        self,
        *,
        program_id: str,
        scope_status: str,
        automation: str,
    ) -> Program | None:
        record = self.session.get(ProgramRecord, program_id)
        if record is None:
            return None
        if scope_status not in {"in_scope", "out_of_scope", "needs_review"}:
            raise ValueError("program scope status is invalid")
        record.scope_status = scope_status
        record.automation = _program_rule_safe_text(automation)
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
        commit: bool = True,
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
            if commit:
                self.session.commit()
                self.session.refresh(existing)
            else:
                self.session.flush()
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
        if commit:
            self.session.commit()
            self.session.refresh(record)
        else:
            self.session.flush()
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
        policy_text_is_hash: bool = False,
        scope_status: str,
        hypothesis_count: int,
        blocked_count: int,
        report_title: str | None,
        payload: dict,
    ) -> PipelineRunRecord:
        policy_text_hash = (
            _validated_policy_text_hash(policy_text)
            if policy_text_is_hash
            else sha256(policy_text.encode("utf-8")).hexdigest()
        )
        record = PipelineRunRecord(
            id=f"pipeline_run_{uuid4().hex}",
            program_id=program_id,
            asset=asset,
            policy_text_hash=policy_text_hash,
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

    def load_trusted_bounded_result_claims(
        self,
        pipeline_run_id: str,
    ) -> tuple[TrustedBoundedResultClaim, ...]:
        pipeline_run = self.get_pipeline_run(pipeline_run_id)
        if pipeline_run is None:
            return ()
        claims = [
            claim
            for stage in self.list_pipeline_stages_for_run(pipeline_run_id)
            if stage.stage_key == "studio_black_box_bounded_result"
            and (
                claim := _trusted_bounded_result_claim(
                    session=self.session,
                    pipeline_run=pipeline_run,
                    stage=stage,
                )
            )
            is not None
        ]
        return tuple(claims[:5])

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

    def record_studio_black_box_bounded_result_atomic(
        self,
        *,
        validation_run_id: str,
        pipeline_run_id: str,
        result_digest: str,
        bounded_projection: dict,
        failure_injector: Callable[[str], None] | None = None,
    ) -> tuple[ValidationRunRecord, PipelineRunRecord, PipelineStageRecord]:
        projection = _studio_bounded_result_projection(bounded_projection)
        if not _studio_bounded_result_digest(result_digest):
            raise ValueError("bounded_result_digest_invalid")
        stage_id = _studio_bounded_result_stage_id(
            pipeline_run_id,
            validation_run_id,
        )
        dialect = self.session.get_bind().dialect.name
        hook = failure_injector or (lambda _point: None)

        for _attempt in range(3):
            try:
                pipeline_query = select(PipelineRunRecord).where(
                    PipelineRunRecord.id == pipeline_run_id
                )
                validation_query = select(ValidationRunRecord).where(
                    ValidationRunRecord.id == validation_run_id
                )
                if dialect == "postgresql":
                    pipeline_query = pipeline_query.with_for_update()
                    validation_query = validation_query.with_for_update()
                pipeline_run = self.session.scalar(pipeline_query)
                validation_run = self.session.scalar(validation_query)
                if pipeline_run is None or validation_run is None:
                    raise ValueError("bounded_result_binding_invalid")
                validation_payload = (
                    validation_run.payload
                    if isinstance(validation_run.payload, dict)
                    else {}
                )
                approval_query = select(ApprovalRecord).where(
                    ApprovalRecord.id == validation_run.approval_id
                )
                if dialect == "postgresql":
                    approval_query = approval_query.with_for_update()
                approval = (
                    self.session.scalar(approval_query)
                    if validation_run.approval_id
                    else None
                )
                if (
                    approval is None
                    or validation_run.campaign_id != approval.campaign_id
                    or validation_run.task_id != approval.task_id
                    or approval.run_id != pipeline_run.id
                    or validation_payload.get("pipeline_run_id") != pipeline_run.id
                ):
                    raise ValueError("bounded_result_binding_invalid")

                provenance_refs = [
                    f"approval:{approval.id}",
                    f"pipeline_run:{pipeline_run.id}",
                    f"validation_run:{validation_run.id}",
                ]
                result_payload = {
                    "schema_version": "studio_black_box_bounded_result_v1",
                    "request_digest": result_digest,
                    **projection,
                    "provenance_refs": provenance_refs,
                    "human_review_required": True,
                    "submission_blocked": True,
                    "execution_allowed": False,
                    "report_submission_allowed": False,
                    "raw_payload_processed": False,
                }
                pipeline_result = {
                    "schema_version": "studio_black_box_bounded_result_v1",
                    "approval_id": approval.id,
                    "validation_run_id": validation_run.id,
                    "result_digest": result_digest,
                    **projection,
                    "provenance_refs": provenance_refs,
                    "human_review_required": True,
                    "submission_blocked": True,
                    "execution_allowed": False,
                    "report_submission_allowed": False,
                }
                stage_payload = {
                    **pipeline_result,
                    "pipeline_run_id": pipeline_run.id,
                    "raw_payload_processed": False,
                }
                stage = self.session.get(PipelineStageRecord, stage_id)
                replay_state = _studio_bounded_result_replay_state(
                    validation_run=validation_run,
                    pipeline_run=pipeline_run,
                    stage=stage,
                    result_payload=result_payload,
                    pipeline_result=pipeline_result,
                    stage_payload=stage_payload,
                )
                if replay_state == "match":
                    assert stage is not None
                    self.session.rollback()
                    stored_validation = self.get_validation_run(validation_run_id)
                    stored_pipeline = self.get_pipeline_run(pipeline_run_id)
                    stored_stage = self.session.get(PipelineStageRecord, stage_id)
                    assert stored_validation is not None
                    assert stored_pipeline is not None
                    assert stored_stage is not None
                    return stored_validation, stored_pipeline, stored_stage
                if replay_state == "partial":
                    raise ValueError("bounded_result_partial_state")
                if replay_state == "mismatch":
                    raise ValueError("bounded_result_request_mismatch")
                if (
                    validation_run.status != "preflight_passed"
                    or validation_run.allowed_to_execute is not True
                    or approval.status != "approved"
                    or not approval_record_is_active(approval)
                ):
                    raise ValueError("fresh_complete_local_plan_preflight_required")

                pipeline_payload = (
                    pipeline_run.payload if isinstance(pipeline_run.payload, dict) else {}
                )
                existing_results = pipeline_payload.get(
                    "studio_black_box_bounded_results",
                    [],
                )
                if not isinstance(existing_results, list):
                    raise ValueError("bounded_result_partial_state")
                next_pipeline_payload = dict(pipeline_payload)
                next_pipeline_payload["studio_black_box_bounded_results"] = [
                    *existing_results,
                    pipeline_result,
                ]
                if dialect == "sqlite":
                    pipeline_update = self.session.execute(
                        update(PipelineRunRecord)
                        .where(
                            PipelineRunRecord.id == pipeline_run.id,
                            PipelineRunRecord.payload == pipeline_payload,
                        )
                        .values(payload=next_pipeline_payload)
                        .execution_options(synchronize_session=False)
                    )
                    if pipeline_update.rowcount != 1:
                        self.session.rollback()
                        continue
                    self.session.expire(pipeline_run)
                else:
                    pipeline_run.payload = next_pipeline_payload
                    self.session.add(pipeline_run)
                    self.session.flush()
                hook("pipeline_run")

                recorded_at = datetime.now(UTC)
                next_validation_payload = dict(validation_payload)
                next_validation_payload["black_box_bounded_result"] = {
                    "audit_digest": result_digest,
                    "decision_status": "observed",
                    "evidence_refs": ["sanitized_cross_account_diff"],
                    "execution_started": False,
                    "result_payload": result_payload,
                    "recorded_at": recorded_at.isoformat(),
                }
                validation_update = self.session.execute(
                    update(ValidationRunRecord)
                    .where(
                        ValidationRunRecord.id == validation_run.id,
                        ValidationRunRecord.status == "preflight_passed",
                        ValidationRunRecord.allowed_to_execute.is_(True),
                    )
                    .values(
                        status="needs_evidence",
                        safety_gate_state="black_box_needs_evidence",
                        allowed_to_execute=False,
                        evidence_ref_count=1,
                        summary="Bounded black-box result recorded: observed",
                        finished_at=recorded_at,
                        payload=next_validation_payload,
                    )
                    .execution_options(synchronize_session=False)
                )
                if validation_update.rowcount != 1:
                    self.session.rollback()
                    continue
                self.session.expire(validation_run)
                hook("validation_run")

                stage = PipelineStageRecord(
                    id=stage_id,
                    pipeline_run_id=pipeline_run.id,
                    campaign_id=validation_run.campaign_id,
                    task_id=validation_run.task_id,
                    stage_key="studio_black_box_bounded_result",
                    stage_order=len(self.list_pipeline_stages_for_run(pipeline_run.id)),
                    status="needs_evidence",
                    input_refs=[
                        f"approval:{approval.id}",
                        f"validation_run:{validation_run.id}",
                    ],
                    output_refs=["sanitized_cross_account_diff"],
                    safety_gate_state="human_review_required",
                    stop_reason=None,
                    payload=stage_payload,
                )
                self.session.add(stage)
                self.session.flush()
                hook("pipeline_stage")
                self.session.commit()
                self.session.expire_all()
                stored_validation = self.get_validation_run(validation_run_id)
                stored_pipeline = self.get_pipeline_run(pipeline_run_id)
                stored_stage = self.session.get(PipelineStageRecord, stage_id)
                if (
                    stored_validation is None
                    or stored_pipeline is None
                    or stored_stage is None
                ):
                    raise ValueError("bounded_result_partial_state")
                return stored_validation, stored_pipeline, stored_stage
            except Exception:
                self.session.rollback()
                raise
        raise ValueError("bounded_result_concurrent_update")

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
        campaign_mode: str = "legacy",
    ) -> CampaignRecord:
        mode = _safe_display_value(campaign_mode or "legacy")
        if mode not in {"legacy", "bounty_autopilot"}:
            raise ValueError("unsupported_campaign_mode")
        record = CampaignRecord(
            id=f"campaign_{uuid4().hex}",
            program_id=program_id,
            name=_safe_display_value(name),
            campaign_mode=mode,
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


    def create_campaign_authorization(
        self,
        *,
        campaign_id: str,
        authorization_payload: dict,
        issued_at: datetime | None = None,
    ) -> CampaignAuthorizationRecord:
        """Persist one immutable authorization generation and mark it current."""

        from app.bounty_autopilot.authority import (
            AuthorizationValidationError,
            authorization_from_payload,
        )

        try:
            auth = authorization_from_payload(authorization_payload)
        except Exception as exc:  # noqa: BLE001 - map to typed reason
            raise ValueError("authorization_payload_invalid") from exc
        if auth.campaign_id != campaign_id:
            raise ValueError("authorization_campaign_mismatch")

        campaign = self.get_campaign(campaign_id)
        if campaign is None:
            raise ValueError("campaign_not_found")

        current_rows = self.session.scalars(
            select(CampaignAuthorizationRecord).where(
                CampaignAuthorizationRecord.campaign_id == campaign_id,
                CampaignAuthorizationRecord.is_current.is_(True),
            )
        ).all()
        next_generation = 1
        max_generation = self.session.scalar(
            select(func.max(CampaignAuthorizationRecord.generation)).where(
                CampaignAuthorizationRecord.campaign_id == campaign_id
            )
        )
        if max_generation is not None:
            next_generation = int(max_generation) + 1
        now = issued_at or datetime.now(UTC)
        for row in current_rows:
            row.is_current = False
            row.revoked_at = now
            row.revocation_reason = "superseded"

        record = CampaignAuthorizationRecord(
            id=f"campauth_{uuid4().hex}",
            campaign_id=campaign_id,
            generation=next_generation,
            schema_version=auth.schema_version,
            authorization_digest=auth.authorization_digest,
            scope_snapshot_id=auth.scope_snapshot_id,
            scope_snapshot_digest=auth.scope_snapshot_digest,
            policy_digest=auth.policy_digest,
            operator_id=auth.operator_identity,
            payload=authorization_payload,
            is_current=True,
            issued_at=auth.issued_at,
            expires_at=auth.expires_at,
            revoked_at=None,
            revocation_reason=None,
        )
        self.session.add(record)
        self.session.commit()
        self.session.refresh(record)
        return record

    def get_current_campaign_authorization(
        self,
        campaign_id: str,
    ) -> CampaignAuthorizationRecord | None:
        return self.session.scalar(
            select(CampaignAuthorizationRecord)
            .where(
                CampaignAuthorizationRecord.campaign_id == campaign_id,
                CampaignAuthorizationRecord.is_current.is_(True),
                CampaignAuthorizationRecord.revoked_at.is_(None),
            )
            .order_by(CampaignAuthorizationRecord.generation.desc())
        )

    def list_campaign_authorizations(
        self,
        campaign_id: str,
    ) -> list[CampaignAuthorizationRecord]:
        return list(
            self.session.scalars(
                select(CampaignAuthorizationRecord)
                .where(CampaignAuthorizationRecord.campaign_id == campaign_id)
                .order_by(CampaignAuthorizationRecord.generation.desc())
            ).all()
        )

    def revoke_campaign_authorization(
        self,
        *,
        campaign_id: str,
        authorization_id: str,
        reason: str,
        revoked_at: datetime | None = None,
    ) -> CampaignAuthorizationRecord | None:
        record = self.session.get(CampaignAuthorizationRecord, authorization_id)
        if record is None or record.campaign_id != campaign_id:
            return None
        now = revoked_at or datetime.now(UTC)
        record.is_current = False
        record.revoked_at = now
        record.revocation_reason = _safe_display_value(reason)[:255]
        self.session.commit()
        self.session.refresh(record)
        return record

    def upsert_campaign_asset_admission(
        self,
        *,
        campaign_id: str,
        admission: dict,
        now: datetime | None = None,
    ) -> CampaignAssetRecord:
        """Persist latest asset admission and append an immutable event."""

        from app.bounty_autopilot.asset_admission import AssetAdmissionRecord

        record_model = AssetAdmissionRecord.model_validate_json(
            json.dumps(admission, ensure_ascii=True, separators=(",", ":"), sort_keys=True)
        )
        timestamp = now or datetime.now(UTC)
        existing = self.session.scalar(
            select(CampaignAssetRecord).where(
                CampaignAssetRecord.campaign_id == campaign_id,
                CampaignAssetRecord.asset_id == record_model.asset_id,
            )
        )
        network = record_model.network.model_dump(mode="json")
        if existing is None:
            existing = CampaignAssetRecord(
                id=f"campasset_{uuid4().hex}",
                campaign_id=campaign_id,
                asset_id=record_model.asset_id,
                identity_digest=record_model.identity_digest,
                scheme=record_model.identity.scheme,
                host=record_model.identity.host,
                port=record_model.identity.port,
                path_authority=record_model.identity.path_authority,
                provenance=record_model.identity.provenance.value,
                admission_decision=record_model.decision.value,
                scope_snapshot_digest=record_model.scope_snapshot_digest,
                network_identity=network,
                source=record_model.source,
                reason=record_model.reason,
                first_seen_at=timestamp,
                last_seen_at=timestamp,
                payload={},
                created_at=timestamp,
                updated_at=timestamp,
            )
            self.session.add(existing)
        else:
            existing.identity_digest = record_model.identity_digest
            existing.scheme = record_model.identity.scheme
            existing.host = record_model.identity.host
            existing.port = record_model.identity.port
            existing.path_authority = record_model.identity.path_authority
            existing.provenance = record_model.identity.provenance.value
            existing.admission_decision = record_model.decision.value
            existing.scope_snapshot_digest = record_model.scope_snapshot_digest
            existing.network_identity = network
            existing.source = record_model.source
            existing.reason = record_model.reason
            existing.last_seen_at = timestamp
            existing.updated_at = timestamp

        event = CampaignAssetAdmissionEventRecord(
            id=f"assetadm_{uuid4().hex}",
            campaign_id=campaign_id,
            asset_id=record_model.asset_id,
            identity_digest=record_model.identity_digest,
            decision=record_model.decision.value,
            scope_snapshot_digest=record_model.scope_snapshot_digest,
            network_identity=network,
            source=record_model.source,
            reason=record_model.reason,
            recorded_at=timestamp,
            payload={},
        )
        self.session.add(event)
        self.session.commit()
        self.session.refresh(existing)
        return existing

    def list_campaign_assets(self, campaign_id: str) -> list[CampaignAssetRecord]:
        return list(
            self.session.scalars(
                select(CampaignAssetRecord)
                .where(CampaignAssetRecord.campaign_id == campaign_id)
                .order_by(CampaignAssetRecord.asset_id.asc())
            ).all()
        )

    def list_admitted_campaign_asset_ids(
        self,
        campaign_id: str,
        *,
        scope_snapshot_digest: str,
    ) -> set[str]:
        rows = self.session.scalars(
            select(CampaignAssetRecord).where(
                CampaignAssetRecord.campaign_id == campaign_id,
                CampaignAssetRecord.admission_decision == "admitted",
                CampaignAssetRecord.scope_snapshot_digest == scope_snapshot_digest,
            )
        ).all()
        return {row.asset_id for row in rows}

    def create_research_branch(
        self,
        *,
        campaign_id: str,
        branch: dict,
        now: datetime | None = None,
    ) -> ResearchBranchRecord:
        from app.bounty_autopilot.branches import ResearchBranch

        model = ResearchBranch.model_validate_json(
            json.dumps(branch, ensure_ascii=True, separators=(",", ":"), sort_keys=True)
        )
        if model.campaign_id != campaign_id:
            raise ValueError("branch_campaign_mismatch")
        timestamp = now or datetime.now(UTC)
        record = ResearchBranchRecord(
            id=f"rbranch_{uuid4().hex}",
            campaign_id=campaign_id,
            branch_id=model.branch_id,
            asset_id=model.asset_id,
            status=model.status.value,
            priority=model.priority,
            risk_tier=model.risk_tier,
            hypothesis_id=model.hypothesis_id,
            parent_signal_id=None,
            recipe_id=model.recipe_ref.recipe_id if model.recipe_ref else None,
            recipe_version=model.recipe_ref.version if model.recipe_ref else None,
            account_aliases=list(model.account_aliases),
            budget_counters=model.budget.model_dump(mode="json"),
            stop_reason=model.stop_reason,
            version=model.version,
            payload={},
            created_at=timestamp,
            updated_at=timestamp,
        )
        self.session.add(record)
        self.session.commit()
        self.session.refresh(record)
        return record

    def list_research_branches(self, campaign_id: str) -> list[ResearchBranchRecord]:
        return list(
            self.session.scalars(
                select(ResearchBranchRecord)
                .where(ResearchBranchRecord.campaign_id == campaign_id)
                .order_by(
                    ResearchBranchRecord.priority.desc(),
                    ResearchBranchRecord.branch_id.asc(),
                )
            ).all()
        )

    def get_research_branch(
        self,
        *,
        campaign_id: str,
        branch_id: str,
    ) -> ResearchBranchRecord | None:
        return self.session.scalar(
            select(ResearchBranchRecord).where(
                ResearchBranchRecord.campaign_id == campaign_id,
                ResearchBranchRecord.branch_id == branch_id,
            )
        )

    def transition_research_branch(
        self,
        *,
        campaign_id: str,
        branch_id: str,
        new_status: str,
        expected_version: int,
        stop_reason: str | None = None,
        now: datetime | None = None,
    ) -> ResearchBranchRecord:
        from app.bounty_autopilot.branches import (
            BranchBudgetCounters,
            BranchStatus,
            ResearchBranch,
            transition_branch,
        )
        from app.bounty_autopilot.contracts import RiskTier
        from app.bounty_autopilot.recipes import default_recipe_registry

        record = self.get_research_branch(
            campaign_id=campaign_id,
            branch_id=branch_id,
        )
        if record is None:
            raise ValueError("branch_not_found")
        recipe_ref = None
        if record.recipe_id and record.recipe_version:
            recipe = default_recipe_registry().get(
                record.recipe_id,
                record.recipe_version,
            )
            recipe_ref = recipe.ref if recipe is not None else None
        budget_payload = record.budget_counters if isinstance(record.budget_counters, dict) else {}
        current = ResearchBranch(
            branch_id=record.branch_id,
            campaign_id=record.campaign_id,
            asset_id=record.asset_id,
            status=BranchStatus(record.status),
            priority=record.priority,
            recipe_ref=recipe_ref,
            risk_tier=record.risk_tier,
            hypothesis_id=record.hypothesis_id,
            account_aliases=tuple(record.account_aliases or ()),
            budget=BranchBudgetCounters.model_validate_json(
                json.dumps(
                    budget_payload or {},
                    ensure_ascii=True,
                    separators=(",", ":"),
                    sort_keys=True,
                )
            ),
            stop_reason=record.stop_reason,
            version=record.version,
        )
        updated = transition_branch(
            current,
            new_status=BranchStatus(new_status),
            expected_version=expected_version,
            stop_reason=stop_reason,
        )
        timestamp = now or datetime.now(UTC)
        record.status = updated.status.value
        record.stop_reason = updated.stop_reason
        record.version = updated.version
        record.updated_at = timestamp
        self.session.commit()
        self.session.refresh(record)
        return record

    def materialize_autopilot_branch_plan_handoff(
        self,
        *,
        campaign_id: str,
        branch_id: str,
        expected_branch_version: int,
        authorization_id: str,
        authorization_digest: str,
        scope_snapshot_digest: str,
        source_snapshot_digest: str,
        asset_id: str,
        recipe_ref: dict,
        risk_tier: str,
        hypothesis_id: str | None,
        handoff_id: str,
        handoff_input_refs: list[str],
        handoff_payload: dict,
        now: datetime | None = None,
    ) -> tuple[ResearchBranchRecord, CampaignTaskRecord]:
        """Atomically bind one selected branch to a human plan-materialization handoff."""

        from app.bounty_autopilot.authority import (
            AuthorizationValidationError,
            authorization_from_payload,
            validate_current_authorization,
        )
        from app.bounty_autopilot.contracts import RecipeRef
        from app.bounty_autopilot.recipes import default_recipe_registry

        timestamp = now or datetime.now(UTC)
        campaign = self.get_campaign(campaign_id)
        campaign_payload = (
            campaign.payload
            if campaign is not None and isinstance(campaign.payload, dict)
            else {}
        )
        if campaign is None:
            raise ValueError("campaign_not_found")
        if campaign_payload.get("source_snapshot_digest") != source_snapshot_digest:
            raise ValueError("source_snapshot_changed")
        if not any(
            task.task_type == "validation_handoff"
            and task.status == "awaiting_approval"
            for task in self.list_campaign_tasks(campaign_id)
        ):
            raise ValueError("validation_handoff_not_awaiting_approval")
        auth_record = self.get_current_campaign_authorization(campaign_id)
        if auth_record is None:
            raise ValueError("authorization_missing")
        if (
            auth_record.id != authorization_id
            or auth_record.authorization_digest != authorization_digest
            or auth_record.scope_snapshot_digest != scope_snapshot_digest
        ):
            raise ValueError("authorization_changed")
        try:
            authorization = authorization_from_payload(auth_record.payload)
            if authorization.authorization_digest != auth_record.authorization_digest:
                raise ValueError("authorization_digest_invalid")
            validate_current_authorization(
                authorization,
                now=timestamp,
                expected_scope_snapshot_digest=scope_snapshot_digest,
            )
        except AuthorizationValidationError as exc:
            raise ValueError(exc.reason) from exc
        except ValueError:
            raise
        except Exception as exc:  # noqa: BLE001 - persisted authority is fail-closed
            raise ValueError("authorization_digest_invalid") from exc

        try:
            bound_recipe = RecipeRef.model_validate(recipe_ref)
        except Exception as exc:  # noqa: BLE001 - task payload is an immutable contract
            raise ValueError("branch_recipe_invalid") from exc
        if asset_id not in authorization.asset_ids:
            raise ValueError("authorization_asset_not_allowed")
        if bound_recipe not in authorization.recipe_refs:
            raise ValueError("authorization_recipe_not_allowed")
        if asset_id not in self.list_admitted_campaign_asset_ids(
            campaign_id,
            scope_snapshot_digest=scope_snapshot_digest,
        ):
            raise ValueError("asset_not_admitted")

        branch = self.get_research_branch(
            campaign_id=campaign_id,
            branch_id=branch_id,
        )
        if branch is None:
            raise ValueError("branch_not_found")
        registered_recipe = (
            default_recipe_registry().get(branch.recipe_id, branch.recipe_version)
            if branch.recipe_id and branch.recipe_version
            else None
        )
        if (
            branch.asset_id != asset_id
            or branch.risk_tier != risk_tier
            or branch.hypothesis_id != hypothesis_id
            or registered_recipe is None
            or registered_recipe.ref != bound_recipe
        ):
            raise ValueError("branch_changed")
        if branch.status in {"queued", "active"}:
            if branch.version != expected_branch_version:
                raise ValueError("branch_changed")
            branch.status = "awaiting_human"
            branch.stop_reason = "awaiting_plan"
            branch.version += 1
            branch.updated_at = timestamp
        elif (
            branch.status != "awaiting_human"
            or branch.version != expected_branch_version + 1
        ):
            raise ValueError("branch_changed")

        handoff = self.session.get(CampaignTaskRecord, handoff_id)
        if handoff is None:
            handoff = CampaignTaskRecord(
                id=_safe_display_value(handoff_id),
                campaign_id=campaign_id,
                task_type="autopilot_plan_materialization",
                agent_type="human_plan_reviewer",
                title="Materialize immutable plan for selected research branch",
                status="awaiting_approval",
                input_refs=_safe_display_value(handoff_input_refs),
                output_refs=[],
                payload=_safe_display_value(handoff_payload),
            )
            self.session.add(handoff)
        elif not (
            handoff.campaign_id == campaign_id
            and handoff.task_type == "autopilot_plan_materialization"
            and handoff.agent_type == "human_plan_reviewer"
            and handoff.title == "Materialize immutable plan for selected research branch"
            and handoff.status == "awaiting_approval"
            and handoff.input_refs == handoff_input_refs
            and handoff.output_refs == []
            and handoff.payload == handoff_payload
        ):
            raise ValueError("plan_handoff_integrity_invalid")

        try:
            self.session.flush()
        except IntegrityError:
            self.session.rollback()
            raise ValueError("plan_handoff_integrity_invalid") from None
        return branch, handoff

    def create_validation_plan(
        self,
        *,
        campaign_id: str,
        plan_payload: dict,
        now: datetime | None = None,
    ) -> ValidationPlanRecord:
        """Persist an immutable validation plan (digest-bound payload)."""

        from app.bounty_autopilot.plans import ValidationPlan, build_validation_plan

        # Prefer re-building so digest is server-validated.
        if "plan_digest" in plan_payload and "recipe_ref" in plan_payload:
            try:
                plan = ValidationPlan.model_validate_json(
                    json.dumps(
                        plan_payload,
                        ensure_ascii=True,
                        separators=(",", ":"),
                        sort_keys=True,
                    )
                )
            except Exception:
                plan = build_validation_plan(**{
                    k: v for k, v in plan_payload.items() if k != "plan_digest"
                })
        else:
            plan = build_validation_plan(**plan_payload)
        if plan.campaign_id != campaign_id:
            raise ValueError("campaign_id_mismatch")
        existing = self.session.scalar(
            select(ValidationPlanRecord).where(
                ValidationPlanRecord.campaign_id == campaign_id,
                ValidationPlanRecord.plan_id == plan.plan_id,
            )
        )
        if existing is not None:
            if existing.plan_digest != plan.plan_digest:
                raise ValueError("plan_immutable_digest_conflict")
            return existing
        timestamp = now or datetime.now(UTC)
        record = ValidationPlanRecord(
            id=f"vplan_{uuid4().hex}",
            campaign_id=campaign_id,
            plan_id=plan.plan_id,
            plan_digest=plan.plan_digest,
            branch_id=plan.branch_id,
            asset_id=plan.asset_id,
            risk_tier=plan.risk_tier,
            status="ready",
            payload=plan.model_dump(mode="json"),
            created_at=timestamp,
        )
        self.session.add(record)
        self.session.commit()
        self.session.refresh(record)
        return record

    def materialize_validation_plan_from_handoff(
        self,
        *,
        campaign_id: str,
        handoff_id: str,
        plan,
        actor: str,
        now: datetime | None = None,
    ) -> ValidationPlanRecord:
        from app.bounty_autopilot.plans import ValidationPlan

        if not isinstance(plan, ValidationPlan):
            raise TypeError("ValidationPlan required")
        if plan.campaign_id != campaign_id:
            raise ValueError("campaign_id_mismatch")
        existing = self.get_validation_plan(
            campaign_id=campaign_id,
            plan_id=plan.plan_id,
        )
        if existing is not None:
            if existing.plan_digest != plan.plan_digest:
                raise ValueError("plan_immutable_digest_conflict")
            reason = self.validation_plan_materialization_stop_reason(
                campaign_id=campaign_id,
                plan=plan,
                handoff_id=handoff_id,
                require_completed=True,
                now=now,
            )
            if reason is not None:
                raise ValueError(reason)
            return existing

        reason = self.validation_plan_materialization_stop_reason(
            campaign_id=campaign_id,
            plan=plan,
            handoff_id=handoff_id,
            require_completed=False,
            now=now,
        )
        if reason is not None:
            raise ValueError(reason)

        timestamp = now or datetime.now(UTC)
        handoff = self.session.get(CampaignTaskRecord, handoff_id)
        branch = self.get_research_branch(
            campaign_id=campaign_id,
            branch_id=plan.branch_id,
        )
        assert handoff is not None
        assert branch is not None
        record = ValidationPlanRecord(
            id=f"vplan_{uuid4().hex}",
            campaign_id=campaign_id,
            plan_id=plan.plan_id,
            plan_digest=plan.plan_digest,
            branch_id=plan.branch_id,
            asset_id=plan.asset_id,
            risk_tier=plan.risk_tier,
            status="awaiting_r3" if plan.risk_tier == "R3" else "ready",
            payload=plan.model_dump(mode="json"),
            created_at=timestamp,
        )
        handoff.status = "completed"
        handoff.output_refs = [
            f"validation_plan:{plan.plan_id}",
            f"operator_alias:{_safe_display_value(actor)}",
        ]
        branch.status = "awaiting_r3" if plan.risk_tier == "R3" else "queued"
        branch.stop_reason = "awaiting_r3" if plan.risk_tier == "R3" else None
        branch.version += 1
        branch.updated_at = timestamp
        self.session.add_all((record, handoff, branch))
        try:
            self.session.commit()
        except IntegrityError:
            self.session.rollback()
            existing = self.get_validation_plan(
                campaign_id=campaign_id,
                plan_id=plan.plan_id,
            )
            if existing is None or existing.plan_digest != plan.plan_digest:
                raise ValueError("plan_materialization_conflict") from None
            reason = self.validation_plan_materialization_stop_reason(
                campaign_id=campaign_id,
                plan=plan,
                handoff_id=handoff_id,
                require_completed=True,
                now=timestamp,
            )
            if reason is not None:
                raise ValueError(reason) from None
            return existing
        self.session.refresh(record)
        return record

    def validation_plan_materialization_stop_reason(
        self,
        *,
        campaign_id: str,
        plan,
        handoff_id: str | None = None,
        require_completed: bool,
        now: datetime | None = None,
    ) -> str | None:
        from app.bounty_autopilot.authority import (
            AuthorizationValidationError,
            authorization_from_payload,
            validate_current_authorization,
        )
        from app.bounty_autopilot.lineage import (
            AutopilotRiskDecisionRecord as RiskDecisionContract,
        )
        from app.bounty_autopilot.plans import ValidationPlan
        from app.bounty_autopilot.recipes import default_recipe_registry

        if not isinstance(plan, ValidationPlan) or plan.campaign_id != campaign_id:
            return "validation_plan_invalid"
        campaign = self.get_campaign(campaign_id)
        if campaign is None:
            return "campaign_not_found"
        if (campaign.campaign_mode or "legacy") != "bounty_autopilot":
            return "autopilot_campaign_required"
        if self.campaign_is_emergency_stopped(campaign_id):
            return "emergency_stopped"

        handoffs = [
            task
            for task in self.list_campaign_tasks(campaign_id)
            if task.task_type == "autopilot_plan_materialization"
            and (handoff_id is None or task.id == handoff_id)
            and (
                f"validation_plan:{plan.plan_id}" in (task.output_refs or [])
                if require_completed
                else task.status == "awaiting_approval"
            )
        ]
        if not handoffs:
            return "plan_handoff_not_found"
        if len(handoffs) != 1:
            return "plan_handoff_ambiguous"
        handoff = handoffs[0]
        if require_completed and handoff.status != "completed":
            return "plan_handoff_not_completed"
        payload = handoff.payload if isinstance(handoff.payload, dict) else {}

        authorization_record = self.get_current_campaign_authorization(campaign_id)
        if authorization_record is None:
            return "authorization_missing"
        try:
            authorization = authorization_from_payload(authorization_record.payload)
            if authorization.authorization_digest != authorization_record.authorization_digest:
                return "authorization_digest_invalid"
            validate_current_authorization(
                authorization,
                now=now or datetime.now(UTC),
                expected_scope_snapshot_digest=plan.scope_snapshot_digest,
            )
        except AuthorizationValidationError as exc:
            return exc.reason
        except Exception:  # noqa: BLE001 - persisted authority is fail-closed
            return "authorization_digest_invalid"
        if (
            payload.get("schema_version") != "autopilot-plan-materialization/v1"
            or payload.get("human_approval_required") is not True
            or payload.get("campaign_id") != campaign_id
            or payload.get("branch_id") != plan.branch_id
            or payload.get("authorization_id") != authorization_record.id
            or payload.get("authorization_digest") != plan.authorization_digest
            or payload.get("scope_snapshot_digest") != plan.scope_snapshot_digest
            or payload.get("asset_id") != plan.asset_id
            or payload.get("recipe_ref") != plan.recipe_ref.model_dump(mode="json")
            or payload.get("risk_tier") != plan.risk_tier
            or payload.get("hypothesis_id") != plan.hypothesis_id
        ):
            return "plan_handoff_binding_mismatch"
        if (
            plan.authorization_digest != authorization.authorization_digest
            or plan.asset_id not in authorization.asset_ids
            or plan.recipe_ref not in authorization.recipe_refs
            or any(alias not in authorization.account_aliases for alias in plan.account_aliases)
        ):
            return "plan_authorization_mismatch"

        recipe = default_recipe_registry().get(
            plan.recipe_ref.recipe_id,
            plan.recipe_ref.version,
        )
        if recipe is None or recipe.ref != plan.recipe_ref:
            return "registered_recipe_required"
        if len(plan.account_aliases) != recipe.required_account_aliases:
            return "recipe_account_alias_count_mismatch"
        if (
            plan.max_requests > min(recipe.max_budgets.max_requests, authorization.budgets.max_requests)
            or plan.max_response_bytes
            > min(
                recipe.max_budgets.max_response_bytes,
                authorization.budgets.max_response_bytes,
            )
            or plan.max_duration_seconds
            > min(
                recipe.max_budgets.max_duration_seconds,
                authorization.budgets.max_duration_seconds,
            )
        ):
            return "plan_budget_exceeded"
        if "read_only" in recipe.method_classes and any(
            method not in {"GET", "HEAD", "OPTIONS"} for method in plan.methods
        ):
            return "plan_method_not_allowed"

        asset = self.session.scalar(
            select(CampaignAssetRecord).where(
                CampaignAssetRecord.campaign_id == campaign_id,
                CampaignAssetRecord.asset_id == plan.asset_id,
            )
        )
        if asset is None or (
            asset.admission_decision != "admitted"
            or asset.scope_snapshot_digest != plan.scope_snapshot_digest
            or asset.scheme != plan.destination_scheme
            or asset.host != plan.destination_host
            or asset.port != plan.destination_port
            or not _path_is_within_authority(
                plan.destination_path,
                asset.path_authority,
            )
        ):
            return "plan_asset_not_current"

        branch = self.get_research_branch(
            campaign_id=campaign_id,
            branch_id=plan.branch_id,
        )
        expected_branch_version = payload.get("branch_version")
        expected_status = "awaiting_r3" if require_completed and plan.risk_tier == "R3" else (
            "queued" if require_completed else "awaiting_human"
        )
        if branch is None or (
            branch.asset_id != plan.asset_id
            or branch.status != expected_status
            or branch.risk_tier != plan.risk_tier
            or branch.hypothesis_id != plan.hypothesis_id
            or branch.recipe_id != plan.recipe_ref.recipe_id
            or branch.recipe_version != plan.recipe_ref.version
            or not isinstance(expected_branch_version, int)
            or branch.version
            != expected_branch_version + (2 if require_completed else 1)
        ):
            return "plan_branch_not_current"

        required_risk_status = (
            "awaiting_exact_approval" if plan.risk_tier == "R3" else "authorized"
        )
        for row in self.list_autopilot_risk_decisions(campaign_id):
            try:
                decision = RiskDecisionContract.model_validate_json(
                    json.dumps(
                        row.payload,
                        ensure_ascii=True,
                        separators=(",", ":"),
                        sort_keys=True,
                    )
                )
            except Exception:  # noqa: BLE001 - malformed lineage never grants authority
                continue
            if (
                decision.authorization_id == authorization_record.id
                and decision.authorization_digest == plan.authorization_digest
                and decision.scope_snapshot_digest == plan.scope_snapshot_digest
                and decision.asset_id == plan.asset_id
                and decision.branch_id == plan.branch_id
                and decision.recipe_ref == plan.recipe_ref
                and decision.risk_tier == plan.risk_tier
                and decision.status == required_risk_status
            ):
                return None
        return "risk_decision_missing"

    def get_validation_plan(
        self,
        *,
        campaign_id: str,
        plan_id: str,
    ) -> ValidationPlanRecord | None:
        return self.session.scalar(
            select(ValidationPlanRecord).where(
                ValidationPlanRecord.campaign_id == campaign_id,
                ValidationPlanRecord.plan_id == plan_id,
            )
        )

    def list_validation_plans(self, campaign_id: str) -> list[ValidationPlanRecord]:
        return list(
            self.session.scalars(
                select(ValidationPlanRecord)
                .where(ValidationPlanRecord.campaign_id == campaign_id)
                .order_by(ValidationPlanRecord.created_at.desc())
            ).all()
        )

    def campaign_is_emergency_stopped(self, campaign_id: str) -> bool:
        campaign = self.session.get(CampaignRecord, campaign_id)
        return campaign is None or self._campaign_record_is_emergency_stopped(campaign)

    @staticmethod
    def _campaign_record_is_emergency_stopped(campaign: CampaignRecord) -> bool:
        if campaign.status in {"stopped", "emergency_stopped"}:
            return True
        payload = campaign.payload if isinstance(campaign.payload, dict) else {}
        return bool(payload.get("emergency_stopped"))

    def _lock_autopilot_campaign(
        self,
        campaign_id: str,
    ) -> CampaignRecord | None:
        return self.session.scalar(
            select(CampaignRecord)
            .where(CampaignRecord.id == campaign_id)
            .with_for_update()
            .execution_options(populate_existing=True)
        )

    def _claim_autopilot_execution_authority(self, campaign_id: str) -> bool:
        campaign = self._lock_autopilot_campaign(campaign_id)
        if campaign is None or self._campaign_record_is_emergency_stopped(campaign):
            return False
        claimed = self.session.execute(
            update(CampaignRecord)
            .where(
                CampaignRecord.id == campaign_id,
                CampaignRecord.status.not_in(("stopped", "emergency_stopped")),
            )
            .values(status=CampaignRecord.status)
        )
        return claimed.rowcount == 1

    def issue_execution_lease(
        self,
        *,
        campaign_id: str,
        plan_id: str,
        lease_id: str | None = None,
        authorization_digest: str,
        scope_snapshot_digest: str,
        authorization_recipe_allowed: bool,
        policy_mode: str,
        approval_id: str | None = None,
        now: datetime | None = None,
    ) -> tuple[bool, str, ExecutionLeaseRecord | None]:
        """Atomically re-check authority and issue a durable lease."""

        from app.bounty_autopilot.contracts import PolicyMode, RecipeRef, RiskTier
        from app.bounty_autopilot.leases import (
            ExecutionLease,
            LeaseStatus,
            execution_lease_authority_stop_reason,
            issue_execution_lease as pure_issue,
        )
        from app.bounty_autopilot.plans import ValidationPlan

        timestamp = now or datetime.now(UTC)
        now_iso = timestamp.isoformat()
        if self.campaign_is_emergency_stopped(campaign_id):
            return False, "emergency_stopped", None

        plan_record = self.get_validation_plan(campaign_id=campaign_id, plan_id=plan_id)
        if plan_record is None:
            return False, "plan_not_found", None
        plan = ValidationPlan.model_validate_json(
            json.dumps(
                plan_record.payload,
                ensure_ascii=True,
                separators=(",", ":"),
                sort_keys=True,
            )
        )

        authority_stop_reason = execution_lease_authority_stop_reason(
            plan=plan,
            policy_mode=policy_mode,
            authorization_recipe_allowed=authorization_recipe_allowed,
            authorization_digest=authorization_digest,
            scope_snapshot_digest=scope_snapshot_digest,
        )
        if authority_stop_reason is not None:
            return False, authority_stop_reason, None

        lease_key = lease_id or f"lease_{uuid4().hex}"
        existing = self.session.scalar(
            select(ExecutionLeaseRecord).where(
                ExecutionLeaseRecord.campaign_id == campaign_id,
                ExecutionLeaseRecord.lease_id == lease_key,
            )
        )
        if existing is not None:
            try:
                persisted_lease = ExecutionLease.model_validate_json(
                    json.dumps(
                        existing.payload,
                        ensure_ascii=True,
                        separators=(",", ":"),
                        sort_keys=True,
                    )
                )
            except Exception:  # noqa: BLE001 - persisted authority is fail-closed
                return False, "lease_integrity_invalid", None
            if (
                existing.status != LeaseStatus.ACTIVE.value
                or persisted_lease.status != LeaseStatus.ACTIVE
                or existing.revoked_at is not None
            ):
                return False, "lease_not_active", None
            if (
                plan_record.status != "issued"
                or existing.lease_id != persisted_lease.lease_id
                or existing.plan_id != persisted_lease.plan_id
                or existing.plan_digest != persisted_lease.plan_digest
                or existing.r3_approval_id != persisted_lease.r3_approval_id
                or persisted_lease.lease_id != lease_key
                or persisted_lease.plan_id != plan.plan_id
                or persisted_lease.plan_digest != plan.plan_digest
                or persisted_lease.campaign_id != campaign_id
                or persisted_lease.authorization_digest != authorization_digest
                or persisted_lease.scope_snapshot_digest != scope_snapshot_digest
                or persisted_lease.asset_id != plan.asset_id
                or persisted_lease.branch_id != plan.branch_id
                or persisted_lease.recipe_ref != plan.recipe_ref
                or persisted_lease.risk_tier != plan.risk_tier
                or persisted_lease.max_requests != plan.max_requests
            ):
                return False, "lease_integrity_invalid", None
            if plan.risk_tier == RiskTier.R3:
                if not approval_id or approval_id != persisted_lease.r3_approval_id:
                    return False, "approval_lease_mismatch", None
                approval = self.session.get(ApprovalRecord, approval_id)
                if (
                    approval is None
                    or approval.campaign_id != campaign_id
                    or approval.plan_digest != plan.plan_digest
                    or approval.status != "used"
                    or approval.consumed_at is None
                    or approval.consumed_by_lease_id != lease_key
                ):
                    return False, "approval_lease_mismatch", None
            if not self._claim_autopilot_execution_authority(campaign_id):
                self.session.rollback()
                return False, "emergency_stopped", None
            self.session.commit()
            self.session.refresh(existing)
            if existing.status != LeaseStatus.ACTIVE.value or existing.revoked_at is not None:
                return False, "lease_not_active", None
            return True, "already_issued", existing

        # Durable single-use R3 consumption via CAS.
        approval_token = None
        approval_store = None
        if plan.risk_tier == "R3":
            if not approval_id:
                return False, "r3_approval_required", None
            approval = self.session.get(ApprovalRecord, approval_id)
            if approval is None:
                return False, "approval_not_found", None
            if approval.campaign_id != campaign_id:
                return False, "approval_campaign_mismatch", None
            if approval.consumed_at is not None or approval.consumed_by_lease_id is not None:
                return False, "approval_already_consumed", None
            if approval.status not in {"approved", "used"}:
                return False, "approval_not_approved", None
            if approval.status == "used":
                return False, "approval_already_consumed", None
            expires_at = approval.expires_at
            if expires_at is not None:
                if expires_at.tzinfo is None:
                    expires_at = expires_at.replace(tzinfo=UTC)
                if expires_at <= timestamp:
                    return False, "approval_expired", None
            if approval.plan_digest and approval.plan_digest != plan.plan_digest:
                return False, "approval_plan_mismatch", None
            payload = approval.payload if isinstance(approval.payload, dict) else {}
            # Prefer call-time authority digests; payload may redaction-safe-filter
            # keys that contain "authorization" / "token".
            token_scope = scope_snapshot_digest
            token_auth = authorization_digest
            nonce = approval.single_use_nonce_digest
            if not nonce:
                candidate = payload.get("nonce_digest")
                if isinstance(candidate, str) and candidate.startswith("sha256:"):
                    nonce = candidate
            if not nonce:
                return False, "approval_nonce_required", None
            from app.bounty_autopilot.leases import ApprovalStore, R3ApprovalToken

            approval_token = R3ApprovalToken(
                approval_id=approval.id,
                plan_digest=plan.plan_digest,
                scope_snapshot_digest=token_scope,
                authorization_digest=token_auth,
                account_aliases=tuple(payload.get("account_aliases") or ()),
                nonce_digest=nonce,
                expires_at=(
                    approval.expires_at.isoformat()
                    if approval.expires_at is not None
                    else (timestamp + timedelta(hours=1)).isoformat()
                ),
            )
            approval_store = ApprovalStore()
            approval_store.put(approval_token)

        result = pure_issue(
            plan=plan,
            policy_mode=policy_mode,
            authorization_recipe_allowed=authorization_recipe_allowed,
            authorization_digest=authorization_digest,
            scope_snapshot_digest=scope_snapshot_digest,
            lease_id=lease_key,
            now_iso=now_iso,
            emergency_stopped=False,
            approval_store=approval_store,
            approval_token=approval_token,
        )
        if not result.allowed or result.lease is None:
            return False, result.reason, None

        if not self._claim_autopilot_execution_authority(campaign_id):
            self.session.rollback()
            return False, "emergency_stopped", None

        if plan.risk_tier == "R3" and approval_id:
            cas = self.session.execute(
                update(ApprovalRecord)
                .where(ApprovalRecord.id == approval_id)
                .where(ApprovalRecord.consumed_at.is_(None))
                .where(ApprovalRecord.status == "approved")
                .values(
                    consumed_at=timestamp,
                    consumed_by_lease_id=lease_key,
                    status="used",
                )
            )
            if cas.rowcount != 1:
                self.session.rollback()
                existing = self.session.scalar(
                    select(ExecutionLeaseRecord).where(
                        ExecutionLeaseRecord.campaign_id == campaign_id,
                        ExecutionLeaseRecord.lease_id == lease_key,
                    )
                )
                if existing is not None:
                    return self.issue_execution_lease(
                        campaign_id=campaign_id,
                        plan_id=plan_id,
                        lease_id=lease_key,
                        authorization_digest=authorization_digest,
                        scope_snapshot_digest=scope_snapshot_digest,
                        authorization_recipe_allowed=authorization_recipe_allowed,
                        policy_mode=policy_mode,
                        approval_id=approval_id,
                        now=timestamp,
                    )
                return False, "approval_already_consumed", None

        lease = result.lease
        record = ExecutionLeaseRecord(
            id=f"lease_row_{uuid4().hex}",
            campaign_id=campaign_id,
            lease_id=lease.lease_id,
            plan_id=lease.plan_id,
            plan_digest=lease.plan_digest,
            status=lease.status.value,
            r3_approval_id=lease.r3_approval_id,
            payload=lease.model_dump(mode="json"),
            created_at=timestamp,
            revoked_at=None,
        )
        self.session.add(record)
        plan_record.status = "issued"
        try:
            self.session.commit()
        except IntegrityError:
            self.session.rollback()
            existing = self.session.scalar(
                select(ExecutionLeaseRecord).where(
                    ExecutionLeaseRecord.campaign_id == campaign_id,
                    ExecutionLeaseRecord.lease_id == lease_key,
                )
            )
            if existing is not None:
                return self.issue_execution_lease(
                    campaign_id=campaign_id,
                    plan_id=plan_id,
                    lease_id=lease_key,
                    authorization_digest=authorization_digest,
                    scope_snapshot_digest=scope_snapshot_digest,
                    authorization_recipe_allowed=authorization_recipe_allowed,
                    policy_mode=policy_mode,
                    approval_id=approval_id,
                    now=timestamp,
                )
            raise
        self.session.refresh(record)
        return True, "issued", record

    def list_execution_leases(
        self,
        campaign_id: str,
        *,
        status: str | None = None,
    ) -> list[ExecutionLeaseRecord]:
        statement = select(ExecutionLeaseRecord).where(
            ExecutionLeaseRecord.campaign_id == campaign_id
        )
        if status is not None:
            statement = statement.where(ExecutionLeaseRecord.status == status)
        return list(
            self.session.scalars(
                statement.order_by(ExecutionLeaseRecord.created_at.desc())
            ).all()
        )

    def get_execution_lease(
        self,
        *,
        campaign_id: str,
        lease_id: str,
    ) -> ExecutionLeaseRecord | None:
        return self.session.scalar(
            select(ExecutionLeaseRecord).where(
                ExecutionLeaseRecord.campaign_id == campaign_id,
                ExecutionLeaseRecord.lease_id == lease_id,
            )
        )

    def reserve_execution_request(
        self,
        *,
        campaign_id: str,
        lease_id: str,
        reservation_payload: dict,
        now: datetime | None = None,
    ) -> ExecutionRequestLedgerRecord:
        """Reserve a request under an active lease with idempotency."""

        from app.bounty_autopilot.leases import ExecutionLease, LeaseStatus
        from app.bounty_autopilot.request_ledger import RequestReservation

        timestamp = now or datetime.now(UTC)
        if self.campaign_is_emergency_stopped(campaign_id):
            raise ValueError("emergency_stopped")
        lease_record = self.get_execution_lease(campaign_id=campaign_id, lease_id=lease_id)
        if lease_record is None:
            raise ValueError("lease_not_found")
        if lease_record.status != LeaseStatus.ACTIVE.value:
            raise ValueError("lease_not_active")
        lease = ExecutionLease.model_validate_json(
            json.dumps(
                lease_record.payload,
                ensure_ascii=True,
                separators=(",", ":"),
                sort_keys=True,
            )
        )
        reservation = RequestReservation.model_validate_json(
            json.dumps(
                reservation_payload,
                ensure_ascii=True,
                separators=(",", ":"),
                sort_keys=True,
            )
        )
        if reservation.lease_id != lease_id:
            raise ValueError("lease_mismatch")
        if reservation.plan_digest != lease.plan_digest:
            raise ValueError("plan_digest_mismatch")

        if not self._claim_autopilot_execution_authority(campaign_id):
            self.session.rollback()
            raise ValueError("emergency_stopped")

        existing = self.session.scalar(
            select(ExecutionRequestLedgerRecord).where(
                ExecutionRequestLedgerRecord.campaign_id == campaign_id,
                ExecutionRequestLedgerRecord.lease_id == lease_id,
                ExecutionRequestLedgerRecord.idempotency_key == reservation.idempotency_key,
            )
        )
        if existing is not None:
            self.session.commit()
            self.session.refresh(existing)
            return existing

        # Budget from current ledger counts.
        reserved_count = self.session.scalar(
            select(func.count())
            .select_from(ExecutionRequestLedgerRecord)
            .where(
                ExecutionRequestLedgerRecord.campaign_id == campaign_id,
                ExecutionRequestLedgerRecord.lease_id == lease_id,
                ExecutionRequestLedgerRecord.status.in_(
                    ["reserved", "sent", "completed", "awaiting_human"]
                ),
            )
        ) or 0
        if reserved_count >= lease.max_requests:
            self.session.rollback()
            raise ValueError("request_budget_exhausted")

        record = ExecutionRequestLedgerRecord(
            id=f"req_{uuid4().hex}",
            campaign_id=campaign_id,
            reservation_id=reservation.reservation_id,
            lease_id=lease_id,
            plan_digest=reservation.plan_digest,
            idempotency_key=reservation.idempotency_key,
            status=reservation.status.value,
            payload=reservation.model_dump(mode="json"),
            created_at=timestamp,
            completed_at=None,
        )
        # Update lease reserved counter in payload.
        payload = dict(lease_record.payload or {})
        payload["requests_reserved"] = int(payload.get("requests_reserved") or 0) + 1
        lease_record.payload = payload
        self.session.add(record)
        try:
            self.session.commit()
        except IntegrityError:
            self.session.rollback()
            existing = self.session.scalar(
                select(ExecutionRequestLedgerRecord).where(
                    ExecutionRequestLedgerRecord.campaign_id == campaign_id,
                    ExecutionRequestLedgerRecord.lease_id == lease_id,
                    ExecutionRequestLedgerRecord.idempotency_key
                    == reservation.idempotency_key,
                )
            )
            if existing is not None:
                return existing
            raise
        self.session.refresh(record)
        return record

    def authorize_execution_request(
        self,
        *,
        campaign_id: str,
        lease_id: str,
        reservation_id: str,
        method: str,
        scheme: str,
        host: str,
        port: int,
        path: str,
        body_digest: str | None,
        mutation_class: str,
        resolved_ips: tuple[str, ...],
        cname_chain: tuple[str, ...],
        is_redirect: bool = False,
        is_subresource: bool = False,
        now: datetime | None = None,
    ):
        """Atomically bind a pre-send decision to current durable authority."""

        from app.bounty_autopilot.authority import (
            AuthorizationValidationError,
            authorization_from_payload,
            validate_current_authorization,
        )
        from app.bounty_autopilot.gateway import (
            GatewayAuthorizeDecision,
            GatewayAuthorizeRequest,
            GatewayDecisionStatus,
            GatewayOutcomeClass,
            authorize_gateway_request,
        )
        from app.bounty_autopilot.leases import ExecutionLease, LeaseStatus
        from app.bounty_autopilot.plans import ValidationPlan
        from app.bounty_autopilot.recipes import default_recipe_registry
        from app.bounty_autopilot.request_ledger import (
            RequestReservation,
            RequestReservationStatus,
        )

        timestamp = now or datetime.now(UTC)
        if not self._claim_autopilot_execution_authority(campaign_id):
            self.session.rollback()
            raise ValueError("emergency_stopped")
        try:
            authorization_record = self.get_current_campaign_authorization(campaign_id)
            if authorization_record is None:
                raise ValueError("authorization_missing")
            try:
                authorization = authorization_from_payload(
                    authorization_record.payload
                )
                if (
                    authorization.authorization_digest
                    != authorization_record.authorization_digest
                ):
                    raise AuthorizationValidationError(
                        "authorization_digest_invalid"
                    )
                validate_current_authorization(authorization, now=timestamp)
            except AuthorizationValidationError as exc:
                raise ValueError(exc.reason) from exc
            except Exception as exc:  # noqa: BLE001 - persisted authority fails closed
                raise ValueError("authorization_digest_invalid") from exc

            lease_record = self.get_execution_lease(
                campaign_id=campaign_id,
                lease_id=lease_id,
            )
            if lease_record is None:
                raise ValueError("lease_not_found")
            plan_record = self.get_validation_plan(
                campaign_id=campaign_id,
                plan_id=lease_record.plan_id,
            )
            if plan_record is None:
                raise ValueError("plan_not_found")
            reservation_record = self.session.scalar(
                select(ExecutionRequestLedgerRecord).where(
                    ExecutionRequestLedgerRecord.campaign_id == campaign_id,
                    ExecutionRequestLedgerRecord.lease_id == lease_id,
                    ExecutionRequestLedgerRecord.reservation_id == reservation_id,
                )
            )
            if reservation_record is None:
                raise ValueError("reservation_not_found")
            if reservation_record.status != RequestReservationStatus.RESERVED.value:
                raise ValueError("reservation_not_reserved")
            asset = self.session.scalar(
                select(CampaignAssetRecord).where(
                    CampaignAssetRecord.campaign_id == campaign_id,
                    CampaignAssetRecord.asset_id == plan_record.asset_id,
                )
            )
            if asset is None:
                raise ValueError("asset_not_found")

            try:
                plan = ValidationPlan.model_validate_json(
                    json.dumps(
                        plan_record.payload,
                        ensure_ascii=True,
                        separators=(",", ":"),
                        sort_keys=True,
                    )
                )
                lease = ExecutionLease.model_validate_json(
                    json.dumps(
                        lease_record.payload,
                        ensure_ascii=True,
                        separators=(",", ":"),
                        sort_keys=True,
                    )
                )
                reservation = RequestReservation.model_validate_json(
                    json.dumps(
                        reservation_record.payload,
                        ensure_ascii=True,
                        separators=(",", ":"),
                        sort_keys=True,
                    )
                )
            except Exception as exc:  # noqa: BLE001 - persisted lineage fails closed
                raise ValueError("gateway_lineage_invalid") from exc

            recipe = default_recipe_registry().get(
                plan.recipe_ref.recipe_id,
                plan.recipe_ref.version,
            )
            materialization_reason = self.validation_plan_materialization_stop_reason(
                campaign_id=campaign_id,
                plan=plan,
                require_completed=True,
                now=timestamp,
            )
            if materialization_reason is not None:
                raise ValueError(materialization_reason)
            if (
                plan_record.status != "issued"
                or lease_record.status != LeaseStatus.ACTIVE.value
                or lease_record.revoked_at is not None
                or lease.status is not LeaseStatus.ACTIVE
                or lease.campaign_id != campaign_id
                or lease.lease_id != lease_id
                or lease.plan_id != plan.plan_id
                or lease.plan_digest != plan.plan_digest
                or lease.authorization_digest != authorization.authorization_digest
                or lease.scope_snapshot_digest != authorization.scope_snapshot_digest
                or plan.authorization_digest != authorization.authorization_digest
                or plan.scope_snapshot_digest != authorization.scope_snapshot_digest
                or plan.asset_id != asset.asset_id
                or plan.asset_id not in authorization.asset_ids
                or recipe is None
                or recipe.ref != plan.recipe_ref
                or plan.recipe_ref not in authorization.recipe_refs
                or asset.admission_decision != "admitted"
                or asset.scope_snapshot_digest != authorization.scope_snapshot_digest
                or reservation.status is not RequestReservationStatus.RESERVED
                or reservation.reservation_id != reservation_id
                or reservation.lease_id != lease_id
                or reservation.plan_id != plan.plan_id
                or reservation.plan_digest != plan.plan_digest
                or reservation.destination_host.lower() != host.lower()
                or reservation.destination_port != port
                or reservation.destination_path != path
                or reservation.method != method.upper()
                or reservation.mutation_class != mutation_class
                or reservation.body_digest != body_digest
                or plan.destination_scheme != scheme
            ):
                raise ValueError("gateway_lineage_invalid")

            network_identity = (
                asset.network_identity
                if isinstance(asset.network_identity, dict)
                else {}
            )
            expected_ips = tuple(
                sorted(set(network_identity.get("resolved_ips") or ()))
            )
            actual_ips = tuple(sorted(set(resolved_ips)))
            expected_cnames = tuple(
                str(item).lower().rstrip(".")
                for item in network_identity.get("cname_chain") or ()
            )
            actual_cnames = tuple(
                str(item).lower().rstrip(".") for item in cname_chain
            )
            if actual_ips != expected_ips or actual_cnames != expected_cnames:
                decision = GatewayAuthorizeDecision(
                    status=GatewayDecisionStatus.BLOCKED,
                    reason="network_identity_mismatch",
                    outcome_class=GatewayOutcomeClass.DNS_REBIND,
                )
            else:
                url_host = f"[{host}]" if ":" in host and not host.startswith("[") else host
                decision = authorize_gateway_request(
                    plan=plan,
                    lease=lease,
                    request=GatewayAuthorizeRequest(
                        url=f"{scheme}://{url_host}:{port}{path}",
                        method=method,
                        body_digest=body_digest,
                        is_redirect=is_redirect,
                        is_subresource=is_subresource,
                        resolved_ips=resolved_ips,
                    ),
                    policy_mode=authorization.policy_mode,
                    admitted_asset_id=asset.asset_id,
                    current_scope_snapshot_digest=authorization.scope_snapshot_digest,
                    asset_identity_digest_current=True,
                    allowed_methods=plan.methods,
                    emergency_stopped=False,
                )

            if decision.status is GatewayDecisionStatus.ALLOWED:
                reservation_record.status = RequestReservationStatus.SENT.value
                reservation_payload = dict(reservation_record.payload or {})
                reservation_payload["status"] = RequestReservationStatus.SENT.value
                reservation_record.payload = reservation_payload
            self.session.commit()
            return decision
        except Exception:
            self.session.rollback()
            raise

    def complete_execution_request(
        self,
        *,
        campaign_id: str,
        reservation_id: str,
        outcome: str,
        now: datetime | None = None,
    ) -> ExecutionRequestLedgerRecord:
        from app.bounty_autopilot.request_ledger import RequestReservationStatus

        timestamp = now or datetime.now(UTC)
        record = self.session.scalar(
            select(ExecutionRequestLedgerRecord).where(
                ExecutionRequestLedgerRecord.campaign_id == campaign_id,
                ExecutionRequestLedgerRecord.reservation_id == reservation_id,
            )
        )
        if record is None:
            raise ValueError("reservation_not_found")
        if record.status == RequestReservationStatus.COMPLETED.value:
            return record
        try:
            status = RequestReservationStatus(outcome)
        except ValueError as exc:
            raise ValueError("invalid_outcome") from exc
        record.status = status.value
        payload = dict(record.payload or {})
        payload["status"] = status.value
        record.payload = payload
        if status in {
            RequestReservationStatus.COMPLETED,
            RequestReservationStatus.AWAITING_HUMAN,
            RequestReservationStatus.EXPIRED,
            RequestReservationStatus.REVOKED,
            RequestReservationStatus.NO_SEND_FAILURE,
        }:
            record.completed_at = timestamp
        self.session.commit()
        self.session.refresh(record)
        return record

    def emergency_stop_campaign(
        self,
        *,
        campaign_id: str,
        actor: str,
        reason: str,
        now: datetime | None = None,
    ) -> dict:
        """Stop campaign, revoke active leases, release safe unused reservations."""

        timestamp = now or datetime.now(UTC)
        result = self._apply_emergency_stop(
            campaign_id=campaign_id,
            actor=actor,
            reason=reason,
            timestamp=timestamp,
        )
        self.session.commit()
        return result

    def prepare_autopilot_emergency_stop(
        self,
        *,
        campaign_id: str,
        actor: str,
        reason: str,
        now: datetime | None = None,
    ) -> dict:
        timestamp = now or datetime.now(UTC)
        if self.get_campaign(campaign_id) is None:
            raise ValueError("campaign_not_found")
        if self.campaign_is_emergency_stopped(campaign_id):
            raise ValueError("campaign_already_stopped")
        nonce = secrets.token_urlsafe(32)
        nonce_digest = f"sha256:{sha256(nonce.encode('utf-8')).hexdigest()}"
        expires_at = timestamp + timedelta(minutes=2)
        self.create_approval_record(
            campaign_id=campaign_id,
            approval_type="autopilot_emergency_stop_confirmation",
            actor=actor,
            reason=reason,
            requested_action="autopilot_emergency_stop",
            safety_gate_state="awaiting_confirmation",
            status="pending",
            expires_at=expires_at,
            payload={
                "confirmation_actor": actor,
                "confirmation_reason": reason,
            },
            single_use_nonce_digest=nonce_digest,
        )
        return {
            "confirmation_nonce": nonce,
            "expires_at": expires_at.isoformat(),
        }

    def confirm_autopilot_emergency_stop(
        self,
        *,
        campaign_id: str,
        actor: str,
        reason: str,
        confirmation_nonce: str,
        now: datetime | None = None,
    ) -> dict:
        timestamp = now or datetime.now(UTC)
        campaign = self._lock_autopilot_campaign(campaign_id)
        if campaign is None or self._campaign_record_is_emergency_stopped(campaign):
            self.session.rollback()
            raise ValueError("campaign_already_stopped")
        nonce_digest = (
            f"sha256:{sha256(confirmation_nonce.encode('utf-8')).hexdigest()}"
        )
        confirmation = self.session.scalar(
            select(ApprovalRecord).where(
                ApprovalRecord.campaign_id == campaign_id,
                ApprovalRecord.approval_type
                == "autopilot_emergency_stop_confirmation",
                ApprovalRecord.single_use_nonce_digest == nonce_digest,
                ApprovalRecord.status.in_(("pending", "requested")),
                ApprovalRecord.decided_at.is_(None),
                ApprovalRecord.consumed_at.is_(None),
                ApprovalRecord.expires_at.is_not(None),
                ApprovalRecord.expires_at > timestamp,
            )
        )
        payload = (
            confirmation.payload
            if confirmation is not None and isinstance(confirmation.payload, dict)
            else {}
        )
        if confirmation is None or (
            payload.get("confirmation_actor") != actor
            or payload.get("confirmation_reason") != reason
        ):
            raise ValueError("emergency_stop_confirmation_invalid")
        consumed = self.session.execute(
            update(ApprovalRecord)
            .where(ApprovalRecord.id == confirmation.id)
            .where(ApprovalRecord.status.in_(("pending", "requested")))
            .where(ApprovalRecord.decided_at.is_(None))
            .where(ApprovalRecord.consumed_at.is_(None))
            .values(
                status="used",
                decided_by=actor,
                decision_reason=reason,
                decided_at=timestamp,
                consumed_at=timestamp,
                consumed_by_lease_id="emergency_stop",
            )
        )
        if consumed.rowcount != 1:
            self.session.rollback()
            raise ValueError("emergency_stop_confirmation_consumed")
        try:
            result = self._apply_emergency_stop(
                campaign_id=campaign_id,
                actor=actor,
                reason=reason,
                timestamp=timestamp,
            )
            self.session.commit()
        except Exception:
            self.session.rollback()
            raise
        return result

    def _apply_emergency_stop(
        self,
        *,
        campaign_id: str,
        actor: str,
        reason: str,
        timestamp: datetime,
    ) -> dict:
        campaign = self._lock_autopilot_campaign(campaign_id)
        if campaign is None:
            raise ValueError("campaign_not_found")
        payload = dict(campaign.payload or {})
        payload["emergency_stopped"] = True
        payload["emergency_stopped_at"] = timestamp.isoformat()
        payload["emergency_stopped_by"] = actor
        payload["emergency_stop_reason"] = reason
        campaign.payload = payload
        campaign.status = "stopped"

        revoked_leases = 0
        for lease in self.session.scalars(
            select(ExecutionLeaseRecord).where(
                ExecutionLeaseRecord.campaign_id == campaign_id,
                ExecutionLeaseRecord.status == "active",
            )
        ).all():
            lease.status = "revoked"
            lease.revoked_at = timestamp
            lease_payload = dict(lease.payload or {})
            lease_payload["status"] = "revoked"
            lease_payload["emergency_stopped"] = True
            lease.payload = lease_payload
            revoked_leases += 1

        released_reservations = 0
        for reservation in self.session.scalars(
            select(ExecutionRequestLedgerRecord).where(
                ExecutionRequestLedgerRecord.campaign_id == campaign_id,
                ExecutionRequestLedgerRecord.status == "reserved",
            )
        ).all():
            reservation.status = "revoked"
            reservation.completed_at = timestamp
            res_payload = dict(reservation.payload or {})
            res_payload["status"] = "revoked"
            reservation.payload = res_payload
            released_reservations += 1

        return {
            "campaign_id": campaign_id,
            "status": "stopped",
            "revoked_leases": revoked_leases,
            "released_reservations": released_reservations,
            "emergency_stopped": True,
            "actor": actor,
            "reason": reason,
        }

    def steer_autopilot_branch(
        self,
        *,
        campaign_id: str,
        branch_id: str,
        directive: str,
        reason: str,
        priority: int | None = None,
        hypothesis_guidance: str | None = None,
        now: datetime | None = None,
    ) -> dict:
        from app.bounty_autopilot.authority import (
            AuthorizationValidationError,
            authorization_from_payload,
            validate_current_authorization,
        )
        from app.bounty_autopilot.recipes import default_recipe_registry

        if self.campaign_is_emergency_stopped(campaign_id):
            raise ValueError("emergency_stopped")
        authorization_record = self.get_current_campaign_authorization(campaign_id)
        if authorization_record is None:
            raise ValueError("authorization_missing")
        try:
            authorization = authorization_from_payload(authorization_record.payload)
            validate_current_authorization(authorization, now=now or datetime.now(UTC))
        except AuthorizationValidationError as exc:
            raise ValueError(exc.reason) from exc
        branch = self.get_research_branch(
            campaign_id=campaign_id,
            branch_id=branch_id,
        )
        if branch is None:
            raise ValueError("branch_not_found")
        if branch.status in {"completed", "closed"}:
            raise ValueError("branch_not_steerable")
        recipe = (
            default_recipe_registry().get(branch.recipe_id, branch.recipe_version)
            if branch.recipe_id and branch.recipe_version
            else None
        )
        if (
            branch.asset_id not in authorization.asset_ids
            or recipe is None
            or recipe.ref not in authorization.recipe_refs
            or branch.asset_id
            not in self.list_admitted_campaign_asset_ids(
                campaign_id,
                scope_snapshot_digest=authorization.scope_snapshot_digest,
            )
        ):
            raise ValueError("branch_authority_stale")

        timestamp = now or datetime.now(UTC)
        payload = dict(branch.payload or {})
        if directive == "set_priority":
            if priority is None or not 0 <= priority <= 100 or hypothesis_guidance is not None:
                raise ValueError("set_priority_value_required")
            branch.priority = priority
        elif directive == "add_hypothesis_guidance":
            if priority is not None or not hypothesis_guidance:
                raise ValueError("hypothesis_guidance_value_required")
            safe_guidance = _safe_display_value(hypothesis_guidance)
            if safe_guidance != hypothesis_guidance:
                raise ValueError("unsafe_hypothesis_guidance")
            history = list(payload.get("hypothesis_guidance") or [])
            history.append(
                {
                    "guidance": safe_guidance,
                    "reason": _safe_display_value(reason),
                    "recorded_at": timestamp.isoformat(),
                }
            )
            payload["hypothesis_guidance"] = history[-20:]
            branch.payload = payload
        else:
            raise ValueError("unsupported_steering_directive")
        branch.version += 1
        branch.updated_at = timestamp
        self.session.add(branch)
        self.session.commit()
        self.session.refresh(branch)
        return {
            "campaign_id": campaign_id,
            "branch_id": branch.branch_id,
            "directive": directive,
            "priority": branch.priority,
            "branch_version": branch.version,
            "status": "recorded",
            "candidate_promotion_allowed": False,
            "report_submission_allowed": False,
        }

    def build_autopilot_pod_grant(
        self,
        *,
        campaign_id: str,
        lease_id: str,
        pod_id: str,
        now: datetime | None = None,
    ) -> dict:
        from app.bounty_autopilot.authority import (
            AuthorizationValidationError,
            authorization_from_payload,
            validate_current_authorization,
        )
        from app.bounty_autopilot.leases import ExecutionLease, LeaseStatus
        from app.bounty_autopilot.plans import ValidationPlan

        if re.fullmatch(r"[A-Za-z][A-Za-z0-9_.:-]{0,127}", pod_id) is None:
            raise ValueError("safe_pod_id_required")
        timestamp = now or datetime.now(UTC)
        if self.campaign_is_emergency_stopped(campaign_id):
            raise ValueError("emergency_stopped")
        authorization_record = self.get_current_campaign_authorization(campaign_id)
        lease_row = self.get_execution_lease(
            campaign_id=campaign_id,
            lease_id=lease_id,
        )
        if authorization_record is None:
            raise ValueError("authorization_missing")
        if lease_row is None:
            raise ValueError("lease_not_found")
        plan_row = self.get_validation_plan(
            campaign_id=campaign_id,
            plan_id=lease_row.plan_id,
        )
        if plan_row is None:
            raise ValueError("plan_not_found")
        try:
            authorization = authorization_from_payload(authorization_record.payload)
            validate_current_authorization(
                authorization,
                now=timestamp,
                expected_scope_snapshot_digest=lease_row.payload.get(
                    "scope_snapshot_digest"
                ),
            )
            lease = ExecutionLease.model_validate_json(
                json.dumps(
                    lease_row.payload,
                    ensure_ascii=True,
                    separators=(",", ":"),
                    sort_keys=True,
                )
            )
            plan = ValidationPlan.model_validate_json(
                json.dumps(
                    plan_row.payload,
                    ensure_ascii=True,
                    separators=(",", ":"),
                    sort_keys=True,
                )
            )
        except AuthorizationValidationError as exc:
            raise ValueError(exc.reason) from exc
        except Exception as exc:  # noqa: BLE001 - persisted authority is fail-closed
            raise ValueError("pod_grant_lineage_invalid") from exc
        materialization_reason = self.validation_plan_materialization_stop_reason(
            campaign_id=campaign_id,
            plan=plan,
            require_completed=True,
            now=timestamp,
        )
        if materialization_reason is not None:
            raise ValueError(materialization_reason)
        asset = self.session.scalar(
            select(CampaignAssetRecord).where(
                CampaignAssetRecord.campaign_id == campaign_id,
                CampaignAssetRecord.asset_id == plan.asset_id,
            )
        )
        if asset is None:
            raise ValueError("asset_not_found")
        if (
            authorization.policy_mode != "authorized_local_lab"
            or authorization.network_profile != "authorized_local_lab"
            or lease_row.status != LeaseStatus.ACTIVE.value
            or lease.status is not LeaseStatus.ACTIVE
            or lease_row.revoked_at is not None
            or lease.plan_digest != plan.plan_digest
            or lease.authorization_digest != authorization.authorization_digest
            or lease.scope_snapshot_digest != authorization.scope_snapshot_digest
            or lease.asset_id != asset.asset_id
        ):
            raise ValueError("pod_grant_lineage_invalid")
        if plan.container_profile not in {"docker_readonly_v1", "wsl_readonly_v1"}:
            raise ValueError("pod_isolation_profile_required")

        expires_at = min(
            authorization.expires_at,
            timestamp + timedelta(seconds=min(plan.max_duration_seconds, 3600)),
        )
        if expires_at <= timestamp:
            raise ValueError("pod_grant_expired")
        grant_digest = sha256(
            f"{campaign_id}:{pod_id}:{lease_id}:{plan.plan_digest}".encode("utf-8")
        ).hexdigest()
        return {
            "schema_version": "bounty-autopilot-pod-grant/v1",
            "grant_id": f"pod_grant_{grant_digest[:32]}",
            "campaign_id": campaign_id,
            "pod_id": pod_id,
            "authorization_id": authorization_record.id,
            "authorization_digest": authorization.authorization_digest,
            "scope_snapshot_digest": authorization.scope_snapshot_digest,
            "asset_id": asset.asset_id,
            "asset_identity_digest": asset.identity_digest,
            "branch_id": plan.branch_id,
            "plan_id": plan.plan_id,
            "plan_digest": plan.plan_digest,
            "lease_id": lease.lease_id,
            "lease_status": lease.status.value,
            "recipe_ref": plan.recipe_ref.model_dump(mode="json"),
            "policy_mode": authorization.policy_mode,
            "network_profile": "gateway_only_v1",
            "container_profile": plan.container_profile,
            "issued_at": timestamp.isoformat(),
            "expires_at": expires_at.isoformat(),
            "report_submission_allowed": False,
        }

    def decide_autopilot_r3_approval(
        self,
        *,
        campaign_id: str,
        approval_id: str,
        decision: str,
        actor: str,
        reason: str,
        now: datetime | None = None,
    ) -> ApprovalRecord:
        from app.bounty_autopilot.plans import ValidationPlan

        timestamp = now or datetime.now(UTC)
        approval = self.session.get(ApprovalRecord, approval_id)
        if approval is None or approval.campaign_id != campaign_id:
            raise ValueError("approval_not_found")
        if approval.approval_type != "r3_exact_plan":
            raise ValueError("autopilot_r3_approval_required")
        if decision not in {"approved", "denied"}:
            raise ValueError("approval_decision_invalid")
        if (
            approval.status not in {"pending", "requested"}
            or approval.decided_at is not None
            or approval.consumed_at is not None
            or approval.expires_at is None
            or _as_utc(approval.expires_at) <= _as_utc(timestamp)
            or not approval.single_use_nonce_digest
        ):
            raise ValueError("approval_not_active")
        plan_row = self.session.scalar(
            select(ValidationPlanRecord).where(
                ValidationPlanRecord.campaign_id == campaign_id,
                ValidationPlanRecord.plan_digest == approval.plan_digest,
            )
        )
        if plan_row is None:
            raise ValueError("approval_plan_not_found")
        try:
            plan = ValidationPlan.model_validate_json(
                json.dumps(
                    plan_row.payload,
                    ensure_ascii=True,
                    separators=(",", ":"),
                    sort_keys=True,
                )
            )
        except Exception as exc:  # noqa: BLE001 - persisted plan is fail-closed
            raise ValueError("approval_plan_invalid") from exc
        payload = approval.payload if isinstance(approval.payload, dict) else {}
        exact_diff = payload.get("exact_diff")
        if (
            plan.risk_tier != "R3"
            or plan.r3_approval_id != approval.id
            or approval.scope_reference != plan.scope_snapshot_digest
            or approval.asset != plan.asset_id
            or approval.validation_mode != plan.recipe_ref.recipe_id
            or approval.requested_action != "autopilot_r3_exact_plan"
            or sorted(payload.get("account_aliases") or [])
            != sorted(plan.account_aliases)
            or not isinstance(exact_diff, list)
            or not exact_diff
        ):
            raise ValueError("approval_exact_plan_mismatch")
        materialization_reason = self.validation_plan_materialization_stop_reason(
            campaign_id=campaign_id,
            plan=plan,
            require_completed=True,
            now=timestamp,
        )
        if materialization_reason is not None:
            raise ValueError(materialization_reason)

        result = self.session.execute(
            update(ApprovalRecord)
            .where(ApprovalRecord.id == approval.id)
            .where(ApprovalRecord.status.in_(("pending", "requested")))
            .where(ApprovalRecord.decided_at.is_(None))
            .where(ApprovalRecord.consumed_at.is_(None))
            .values(
                status=decision,
                decided_by=actor,
                decision_reason=reason,
                decided_at=timestamp,
                safety_gate_state=(
                    "exact_plan_approved" if decision == "approved" else "denied"
                ),
            )
        )
        if result.rowcount != 1:
            self.session.rollback()
            raise ValueError("approval_decision_conflict")
        self.session.commit()
        decided = self.session.get(ApprovalRecord, approval.id)
        assert decided is not None
        return decided

    def append_autopilot_risk_decision(self, decision):
        from app.bounty_autopilot.lineage import (
            AutopilotRiskDecisionRecord as RiskDecisionContract,
        )

        if not isinstance(decision, RiskDecisionContract):
            raise TypeError("AutopilotRiskDecisionRecord required")
        payload = decision.model_dump(mode="json")
        return self._append_autopilot_lineage_row(
            model=AutopilotRiskDecisionRecord,
            identity_field="risk_decision_id",
            identity_value=decision.risk_decision_id,
            prefix="risk_row",
            payload=payload,
            values={
                "campaign_id": decision.campaign_id,
                "risk_decision_id": decision.risk_decision_id,
                "authorization_id": decision.authorization_id,
                "authorization_digest": decision.authorization_digest,
                "scope_snapshot_digest": decision.scope_snapshot_digest,
                "asset_id": decision.asset_id,
                "branch_id": decision.branch_id,
                "recipe_id": decision.recipe_ref.recipe_id,
                "recipe_version": decision.recipe_ref.version,
                "recipe_definition_digest": decision.recipe_ref.definition_digest,
                "risk_tier": decision.risk_tier,
                "status": decision.status,
                "reason_code": decision.reason_code,
                "created_at": decision.decided_at,
            },
        )

    def append_autopilot_tool_run(self, tool_run):
        from app.bounty_autopilot.lineage import (
            AutopilotToolRunRecord as ToolRunContract,
        )

        if not isinstance(tool_run, ToolRunContract):
            raise TypeError("AutopilotToolRunRecord required")
        payload = tool_run.model_dump(mode="json")
        return self._append_autopilot_lineage_row(
            model=AutopilotToolRunRecord,
            identity_field="tool_run_id",
            identity_value=tool_run.tool_run_id,
            prefix="tool_run_row",
            payload=payload,
            values={
                "campaign_id": tool_run.campaign_id,
                "tool_run_id": tool_run.tool_run_id,
                "authorization_id": tool_run.authorization_id,
                "authorization_digest": tool_run.authorization_digest,
                "scope_snapshot_digest": tool_run.scope_snapshot_digest,
                "asset_id": tool_run.asset_id,
                "asset_identity_digest": tool_run.asset_identity_digest,
                "branch_id": tool_run.branch_id,
                "plan_id": tool_run.plan_id,
                "plan_digest": tool_run.plan_digest,
                "risk_decision_id": tool_run.risk_decision_id,
                "risk_tier": tool_run.risk_tier,
                "recipe_id": tool_run.recipe_ref.recipe_id,
                "recipe_version": tool_run.recipe_ref.version,
                "recipe_definition_digest": tool_run.recipe_ref.definition_digest,
                "lease_id": tool_run.lease_id,
                "reservation_id": tool_run.reservation_id,
                "session_generation": tool_run.session_generation,
                "isolation_profile": tool_run.isolation_profile,
                "gateway_decision": tool_run.gateway_decision,
                "request_sent": tool_run.request_sent,
                "run_status": tool_run.run_status,
                "outcome_class": tool_run.outcome_class.value,
                "outcome_code": tool_run.outcome_code,
                "third_party_data_discarded": tool_run.third_party_data_discarded,
                "raw_content_retained": False,
                "raw_secret_retained": False,
                "request_content_retained": False,
                "response_content_retained": False,
                "created_at": tool_run.occurred_at,
            },
        )

    def create_autopilot_observation(self, observation):
        from app.bounty_autopilot.observations import ObservationRecord

        if not isinstance(observation, ObservationRecord):
            raise TypeError("ObservationRecord required")
        payload = observation.model_dump(mode="json")
        return self._append_autopilot_lineage_row(
            model=AutopilotObservationRecord,
            identity_field="observation_id",
            identity_value=observation.observation_id,
            prefix="obs_row",
            payload=payload,
            values={
                "campaign_id": observation.campaign_id,
                "observation_id": observation.observation_id,
                "branch_id": observation.branch_id,
                "plan_digest": observation.plan_digest,
                "grade": observation.grade.value,
                "outcome_class": observation.outcome_class.value,
                "created_at": observation.occurred_at,
            },
        )

    def append_autopilot_evidence_claim(self, claim):
        from app.bounty_autopilot.lineage import EvidenceClaimRecord

        if not isinstance(claim, EvidenceClaimRecord):
            raise TypeError("EvidenceClaimRecord required")
        payload = claim.model_dump(mode="json")
        return self._append_autopilot_lineage_row(
            model=AutopilotEvidenceClaimRecord,
            identity_field="claim_id",
            identity_value=claim.claim_id,
            prefix="claim_row",
            payload=payload,
            values={
                "campaign_id": claim.campaign_id,
                "claim_id": claim.claim_id,
                "hypothesis_id": claim.hypothesis_id,
                "observation_ids": list(claim.observation_ids),
                "evidence_grade": claim.evidence_grade.value,
                "lineage_digest": claim.lineage_digest,
                "summary_code": claim.summary_code,
                "created_at": claim.created_at,
            },
        )

    def append_autopilot_refutation_decision(self, decision):
        from app.bounty_autopilot.lineage import RefutationDecisionRecord

        if not isinstance(decision, RefutationDecisionRecord):
            raise TypeError("RefutationDecisionRecord required")
        payload = decision.model_dump(mode="json")
        return self._append_autopilot_lineage_row(
            model=AutopilotRefutationDecisionRecord,
            identity_field="decision_id",
            identity_value=decision.decision_id,
            prefix="refutation_row",
            payload=payload,
            values={
                "campaign_id": decision.campaign_id,
                "decision_id": decision.decision_id,
                "case_id": decision.case_id,
                "hypothesis_id": decision.hypothesis_id,
                "branch_id": decision.branch_id,
                "observation_ids": list(decision.observation_ids),
                "lineage_digest": decision.lineage_digest,
                "verdict": decision.verdict.value,
                "created_at": decision.created_at,
            },
        )

    def append_autopilot_candidate_revision(self, revision):
        from app.bounty_autopilot.lineage import CandidateRevisionRecord

        if not isinstance(revision, CandidateRevisionRecord):
            raise TypeError("CandidateRevisionRecord required")
        payload = revision.model_dump(mode="json")
        return self._append_autopilot_lineage_row(
            model=AutopilotCandidateRevisionRecord,
            identity_field="revision_id",
            identity_value=revision.revision_id,
            prefix="candidate_revision_row",
            payload=payload,
            values={
                "campaign_id": revision.campaign_id,
                "revision_id": revision.revision_id,
                "candidate_id": revision.candidate_id,
                "hypothesis_id": revision.hypothesis_id,
                "branch_id": revision.branch_id,
                "evidence_claim_ids": list(revision.evidence_claim_ids),
                "refutation_decision_id": revision.refutation_decision_id,
                "judge_verdict": revision.judge_verdict.value,
                "lineage_digest": revision.lineage_digest,
                "confirmed": False,
                "candidate_promotion_allowed": False,
                "report_submission_allowed": False,
                "created_at": revision.created_at,
            },
        )

    def append_autopilot_report_revision(self, revision):
        from app.bounty_autopilot.lineage import ReportRevisionRecord

        if not isinstance(revision, ReportRevisionRecord):
            raise TypeError("ReportRevisionRecord required")
        payload = revision.model_dump(mode="json")
        return self._append_autopilot_lineage_row(
            model=AutopilotReportRevisionRecord,
            identity_field="revision_id",
            identity_value=revision.revision_id,
            prefix="report_revision_row",
            payload=payload,
            values={
                "campaign_id": revision.campaign_id,
                "revision_id": revision.revision_id,
                "report_id": revision.report_id,
                "candidate_id": revision.candidate_id,
                "evidence_claim_ids": list(revision.evidence_claim_ids),
                "lineage_digest": revision.lineage_digest,
                "evidence_grade": revision.evidence_grade.value,
                "submission_blocked": True,
                "automatic_submission_allowed": False,
                "report_submission_allowed": False,
                "created_at": revision.created_at,
            },
        )

    def append_autopilot_human_evidence_review(self, review):
        from app.bounty_autopilot.lineage import HumanEvidenceReviewRecord

        if not isinstance(review, HumanEvidenceReviewRecord):
            raise TypeError("HumanEvidenceReviewRecord required")
        payload = review.model_dump(mode="json")
        return self._append_autopilot_lineage_row(
            model=AutopilotHumanEvidenceReviewRecord,
            identity_field="review_id",
            identity_value=review.review_id,
            prefix="human_review_row",
            payload=payload,
            values={
                "campaign_id": review.campaign_id,
                "review_id": review.review_id,
                "hypothesis_id": review.hypothesis_id,
                "observation_ids": list(review.observation_ids),
                "grade": review.grade.value,
                "decision_code": review.decision_code,
                "reviewer_alias": review.reviewer_alias,
                "automated_source": False,
                "candidate_promotion_allowed": False,
                "report_submission_allowed": False,
                "created_at": review.reviewed_at,
            },
        )

    def _append_autopilot_lineage_row(
        self,
        *,
        model,
        identity_field: str,
        identity_value: str,
        prefix: str,
        payload: dict,
        values: dict,
    ):
        campaign_id = values["campaign_id"]
        if self.get_campaign(campaign_id) is None:
            raise ValueError("campaign_not_found")
        existing = self.session.scalar(
            select(model).where(
                model.campaign_id == campaign_id,
                getattr(model, identity_field) == identity_value,
            )
        )
        if existing is not None:
            if existing.payload != payload:
                raise ValueError("lineage_record_conflict")
            return existing

        row = model(id=f"{prefix}_{uuid4().hex}", payload=payload, **values)
        self.session.add(row)
        try:
            self.session.commit()
        except IntegrityError:
            self.session.rollback()
            existing = self.session.scalar(
                select(model).where(
                    model.campaign_id == campaign_id,
                    getattr(model, identity_field) == identity_value,
                )
            )
            if existing is None or existing.payload != payload:
                raise ValueError("lineage_record_conflict") from None
            return existing
        self.session.refresh(row)
        return row


    def list_execution_request_ledger(
        self,
        campaign_id: str,
    ) -> list[ExecutionRequestLedgerRecord]:
        return list(
            self.session.scalars(
                select(ExecutionRequestLedgerRecord)
                .where(ExecutionRequestLedgerRecord.campaign_id == campaign_id)
                .order_by(ExecutionRequestLedgerRecord.created_at.desc())
            ).all()
        )

    def list_autopilot_observations(
        self,
        campaign_id: str,
    ) -> list[AutopilotObservationRecord]:
        return list(
            self.session.scalars(
                select(AutopilotObservationRecord)
                .where(AutopilotObservationRecord.campaign_id == campaign_id)
                .order_by(AutopilotObservationRecord.created_at.desc())
            ).all()
        )

    def list_autopilot_risk_decisions(self, campaign_id: str):
        return self._list_autopilot_lineage_rows(
            AutopilotRiskDecisionRecord, campaign_id
        )

    def list_autopilot_tool_runs(self, campaign_id: str):
        return self._list_autopilot_lineage_rows(AutopilotToolRunRecord, campaign_id)

    def list_autopilot_evidence_claims(self, campaign_id: str):
        return self._list_autopilot_lineage_rows(
            AutopilotEvidenceClaimRecord, campaign_id
        )

    def list_autopilot_refutation_decisions(self, campaign_id: str):
        return self._list_autopilot_lineage_rows(
            AutopilotRefutationDecisionRecord, campaign_id
        )

    def list_autopilot_candidate_revisions(self, campaign_id: str):
        return self._list_autopilot_lineage_rows(
            AutopilotCandidateRevisionRecord, campaign_id
        )

    def list_autopilot_report_revisions(self, campaign_id: str):
        return self._list_autopilot_lineage_rows(
            AutopilotReportRevisionRecord, campaign_id
        )

    def list_autopilot_human_evidence_reviews(self, campaign_id: str):
        return self._list_autopilot_lineage_rows(
            AutopilotHumanEvidenceReviewRecord, campaign_id
        )

    def _list_autopilot_lineage_rows(self, model, campaign_id: str):
        return list(
            self.session.scalars(
                select(model)
                .where(model.campaign_id == campaign_id)
                .order_by(model.created_at.desc(), model.id.desc())
            ).all()
        )

    def list_campaigns(self) -> list[CampaignRecord]:
        return self.session.scalars(
            select(CampaignRecord).order_by(
                CampaignRecord.created_at.desc(),
                CampaignRecord.id.desc(),
            )
        ).all()

    def list_autonomous_wakeup_campaigns(
        self,
        *,
        after_id: str | None = None,
    ) -> list[dict[str, str]]:
        statement = select(
            CampaignRecord.id,
            CampaignRecord.autonomy_level,
            CampaignRecord.scope_status,
            CampaignRecord.status,
        ).where(
            CampaignRecord.autonomy_level.in_(
                {"level_0_read_only", "level_1_local_validation"}
            ),
            CampaignRecord.scope_status == "in_scope",
            CampaignRecord.status == "running",
        )
        if after_id is not None:
            statement = statement.where(CampaignRecord.id > after_id)
        rows = self.session.execute(
            statement
            .order_by(CampaignRecord.id.asc())
            .limit(AUTONOMOUS_RESEARCH_WAKEUP_PAGE_SIZE)
        ).all()
        return [
            {
                "id": row.id,
                "autonomy_level": row.autonomy_level,
                "scope_status": row.scope_status,
                "status": row.status,
            }
            for row in rows
        ]

    def get_autonomous_research_wakeup_state(
        self,
    ) -> AutonomousResearchWakeupStateRecord | None:
        return self.session.get(
            AutonomousResearchWakeupStateRecord,
            _AUTONOMOUS_RESEARCH_WAKEUP_STATE_ID,
        )

    def claim_autonomous_research_wakeup(
        self,
        *,
        claim_token_digest: str,
        now: datetime,
    ) -> dict[str, str | None] | None:
        if _SHA256_PATTERN.fullmatch(claim_token_digest) is None:
            return None
        timestamp = _as_utc(now)
        state = self.get_autonomous_research_wakeup_state()
        if state is None:
            state = AutonomousResearchWakeupStateRecord(
                id=_AUTONOMOUS_RESEARCH_WAKEUP_STATE_ID,
                execution_allowed=False,
                validation_allowed=False,
                report_submission_allowed=False,
                created_at=timestamp,
                updated_at=timestamp,
            )
            self.session.add(state)
            try:
                self.session.commit()
            except IntegrityError:
                self.session.rollback()

        claimable = or_(
            AutonomousResearchWakeupStateRecord.lease_token_digest.is_(None),
            and_(
                AutonomousResearchWakeupStateRecord.lease_expires_at.is_not(None),
                AutonomousResearchWakeupStateRecord.lease_expires_at <= timestamp,
            ),
        )
        due = or_(
            AutonomousResearchWakeupStateRecord.next_due_at.is_(None),
            AutonomousResearchWakeupStateRecord.next_due_at <= timestamp,
        )
        result = self.session.execute(
            update(AutonomousResearchWakeupStateRecord)
            .where(
                AutonomousResearchWakeupStateRecord.id
                == _AUTONOMOUS_RESEARCH_WAKEUP_STATE_ID,
                claimable,
                due,
            )
            .values(
                lease_token_digest=claim_token_digest,
                lease_started_at=timestamp,
                lease_expires_at=timestamp
                + timedelta(seconds=AUTONOMOUS_RESEARCH_WAKEUP_LEASE_SECONDS),
                next_due_at=timestamp
                + timedelta(seconds=AUTONOMOUS_RESEARCH_WAKEUP_INTERVAL_SECONDS),
                updated_at=timestamp,
            )
            .execution_options(synchronize_session=False)
        )
        self.session.commit()
        if result.rowcount != 1:
            self.session.expire_all()
            state = self.get_autonomous_research_wakeup_state()
            if (
                state is not None
                and state.lease_token_digest is None
                and state.next_due_at is not None
                and _as_utc(state.next_due_at) > timestamp
            ):
                return {"status": "not_due", "after_campaign_id": None}
            return {"status": "lease_held", "after_campaign_id": None}
        self.session.expire_all()
        state = self.get_autonomous_research_wakeup_state()
        if state is None or state.lease_token_digest != claim_token_digest:
            return {"status": "lease_held", "after_campaign_id": None}
        return {"status": "claimed", "after_campaign_id": state.after_campaign_id}

    def finish_autonomous_research_wakeup(
        self,
        *,
        claim_token_digest: str,
        after_campaign_id: str | None,
        now: datetime,
        last_cycle_status: str | None = None,
        last_cycle_stop_reason: str | None = None,
        last_cycle_processed_count: int | None = None,
        last_cycle_outcome_counts: dict[str, int] | None = None,
    ) -> bool:
        if (
            _SHA256_PATTERN.fullmatch(claim_token_digest) is None
            or (
                after_campaign_id is not None
                and (
                    not isinstance(after_campaign_id, str)
                    or not after_campaign_id
                    or len(after_campaign_id) > 100
                )
            )
        ):
            return False
        cycle_summary = _autonomous_research_wakeup_cycle_summary(
            status=last_cycle_status,
            stop_reason=last_cycle_stop_reason,
            processed_count=last_cycle_processed_count,
            outcome_counts=last_cycle_outcome_counts,
        )
        if cycle_summary is None and any(
            value is not None
            for value in (
                last_cycle_status,
                last_cycle_stop_reason,
                last_cycle_processed_count,
                last_cycle_outcome_counts,
            )
        ):
            return False
        timestamp = _as_utc(now)
        values: dict[str, Any] = {
            "after_campaign_id": after_campaign_id,
            "lease_token_digest": None,
            "lease_started_at": None,
            "lease_expires_at": None,
            "updated_at": timestamp,
        }
        if cycle_summary is not None:
            values.update(
                last_cycle_completed_at=timestamp,
                last_cycle_status=cycle_summary["status"],
                last_cycle_stop_reason=cycle_summary["stop_reason"],
                last_cycle_processed_count=cycle_summary["processed_count"],
                last_cycle_outcome_counts=cycle_summary["outcome_counts"],
            )
        result = self.session.execute(
            update(AutonomousResearchWakeupStateRecord)
            .where(
                AutonomousResearchWakeupStateRecord.id
                == _AUTONOMOUS_RESEARCH_WAKEUP_STATE_ID,
                AutonomousResearchWakeupStateRecord.lease_token_digest
                == claim_token_digest,
                AutonomousResearchWakeupStateRecord.lease_expires_at.is_not(None),
                AutonomousResearchWakeupStateRecord.lease_expires_at > timestamp,
            )
            .values(**values)
            .execution_options(synchronize_session=False)
        )
        self.session.commit()
        self.session.expire_all()
        return result.rowcount == 1
    def renew_autonomous_research_wakeup(
        self,
        *,
        claim_token_digest: str,
        now: datetime,
    ) -> bool:
        if _SHA256_PATTERN.fullmatch(claim_token_digest) is None:
            return False
        timestamp = _as_utc(now)
        result = self.session.execute(
            update(AutonomousResearchWakeupStateRecord)
            .where(
                AutonomousResearchWakeupStateRecord.id
                == _AUTONOMOUS_RESEARCH_WAKEUP_STATE_ID,
                AutonomousResearchWakeupStateRecord.lease_token_digest
                == claim_token_digest,
                AutonomousResearchWakeupStateRecord.lease_expires_at.is_not(None),
                AutonomousResearchWakeupStateRecord.lease_expires_at > timestamp,
            )
            .values(
                lease_expires_at=timestamp
                + timedelta(seconds=AUTONOMOUS_RESEARCH_WAKEUP_LEASE_SECONDS),
                updated_at=timestamp,
            )
            .execution_options(synchronize_session=False)
        )
        self.session.commit()
        self.session.expire_all()
        return result.rowcount == 1

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
        elif safe_status in {"paused", "awaiting_review"} and record.status == "running":
            payload.setdefault("budget_paused_at", now.isoformat())
        record.status = safe_status
        record.payload = payload
        self.session.add(record)
        self.session.commit()
        self.session.refresh(record)
        return record

    def transition_campaign_status_if_currently(
        self,
        campaign_id: str,
        status: str,
        *,
        allowed_current_statuses: set[str],
    ) -> CampaignRecord | None:
        record = self.get_campaign(campaign_id)
        if record is None:
            return None
        safe_status = _safe_display_value(status)
        safe_allowed_statuses = {
            _safe_display_value(value) for value in allowed_current_statuses
        }
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
        result = self.session.execute(
            update(CampaignRecord)
            .where(
                CampaignRecord.id == campaign_id,
                CampaignRecord.status.in_(safe_allowed_statuses),
            )
            .values(
                status=safe_status,
                payload=_safe_display_value(payload),
            )
            .execution_options(synchronize_session=False)
        )
        self.session.commit()
        if result.rowcount != 1:
            self.session.expire_all()
            return None
        self.session.expire_all()
        return self.get_campaign(campaign_id)

    def refresh_completed_campaign_snapshot(
        self,
        *,
        campaign_id: str,
        expected_source_snapshot_digest: str,
        payload: dict,
    ) -> CampaignRecord | None:
        record = self.get_campaign(campaign_id)
        current_payload = record.payload if record is not None else None
        if (
            record is None
            or record.status != "completed"
            or not isinstance(current_payload, dict)
            or current_payload.get("source_snapshot_digest")
            != expected_source_snapshot_digest
        ):
            return None

        updated_payload = _safe_display_value(payload)
        if not isinstance(updated_payload, dict):
            return None
        now = datetime.now(UTC)
        updated_payload.setdefault("budget_started_at", now.isoformat())
        paused_at = _payload_datetime(updated_payload.get("budget_paused_at"))
        if paused_at is not None:
            paused_seconds = updated_payload.get("budget_paused_seconds", 0)
            if not isinstance(paused_seconds, (int, float)) or isinstance(
                paused_seconds, bool
            ):
                paused_seconds = 0
            updated_payload["budget_paused_seconds"] = max(
                0,
                paused_seconds + (now - paused_at).total_seconds(),
            )
            updated_payload.pop("budget_paused_at", None)

        result = self.session.execute(
            update(CampaignRecord)
            .where(
                CampaignRecord.id == campaign_id,
                CampaignRecord.status == "completed",
            )
            .values(status="running", payload=updated_payload)
            .execution_options(synchronize_session=False)
        )
        self.session.commit()
        if result.rowcount != 1:
            self.session.expire_all()
            return None
        self.session.expire_all()
        return self.get_campaign(campaign_id)

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

    def list_campaign_local_tool_call_reservations(
        self,
        campaign_id: str,
    ) -> list[AgentRunRecord]:
        return [
            run
            for run in self.list_campaign_agent_runs(campaign_id)
            if _is_local_tool_call_reservation(run.payload)
        ]

    def campaign_local_tool_call_count(self, campaign_id: str) -> int:
        budget = self.get_campaign_budget(campaign_id)
        durable_count = max(
            0,
            int(getattr(budget, "tool_calls_reserved", 0) or 0),
        )
        reservation_count = len(
            self.list_campaign_local_tool_call_reservations(campaign_id)
        )
        legacy_scanner_count = sum(
            _is_legacy_local_tool_call_consumption(run.payload)
            for run in self.list_campaign_scanner_runs(campaign_id)
        )
        return max(durable_count, reservation_count + legacy_scanner_count)

    def campaign_task_has_local_tool_call_reservation(self, task_id: str) -> bool:
        return any(
            _is_local_tool_call_reservation(run.payload)
            for run in self.session.scalars(
                select(AgentRunRecord).where(AgentRunRecord.task_id == task_id)
            ).all()
        )

    def local_tool_call_reservation_metadata(
        self,
        *,
        task_id: str,
        execution_claim_id: str | None,
    ) -> dict[str, object]:
        if not execution_claim_id:
            return {}
        run = self.session.get(AgentRunRecord, execution_claim_id)
        payload = run.payload if run is not None and isinstance(run.payload, dict) else {}
        if (
            run is None
            or run.task_id != task_id
            or not _is_local_tool_call_reservation(payload)
        ):
            return {}
        return {
            key: payload[key]
            for key in _LOCAL_TOOL_CALL_RESERVATION_METADATA_KEYS
            if key in payload
        }

    def reserve_campaign_local_tool_call(
        self,
        *,
        campaign_id: str,
        task_id: str,
        execution_claim_id: str | None,
        research_plan_id: str,
        research_plan_digest: str,
        source_snapshot_digest: str,
        tool_id: str,
        now: datetime | None = None,
    ) -> AgentRunRecord | None:
        """Atomically reserve one local-tool call before starting the tool process."""
        if not execution_claim_id:
            return None

        timestamp = now or datetime.now(UTC)
        agent_run = self.session.get(AgentRunRecord, execution_claim_id)
        if (
            agent_run is None
            or agent_run.campaign_id != campaign_id
            or agent_run.task_id != task_id
            or agent_run.status != "running"
        ):
            return None

        existing_payload = (
            dict(agent_run.payload) if isinstance(agent_run.payload, dict) else {}
        )
        if _is_local_tool_call_reservation(existing_payload):
            if (
                existing_payload.get("tool_call_reservation_campaign_id") != campaign_id
                or existing_payload.get("tool_call_reservation_task_id") != task_id
                or existing_payload.get("tool_call_reservation_agent_run_id")
                != execution_claim_id
            ):
                return None
            return agent_run

        reservation_payload = {
            **existing_payload,
            _LOCAL_TOOL_CALL_RESERVATION_MARKER: True,
            "tool_call_reserved": True,
            "tool_call_reservation_schema": _LOCAL_TOOL_CALL_RESERVATION_SCHEMA,
            "tool_call_reservation_campaign_id": campaign_id,
            "tool_call_reservation_task_id": task_id,
            "tool_call_reservation_agent_run_id": execution_claim_id,
            "tool_call_reservation_research_plan_id": research_plan_id,
            "tool_call_reservation_research_plan_digest": research_plan_digest,
            "tool_call_reservation_source_snapshot_digest": source_snapshot_digest,
            "tool_call_reservation_tool_id": tool_id,
            "execution_allowed": False,
            "dispatch_allowed": False,
            "validation_allowed": False,
            "candidate_promotion_allowed": False,
            "report_submission_allowed": False,
            "raw_payload_processed": False,
        }
        active_lease = (
            select(CampaignTaskRecord.id)
            .where(CampaignTaskRecord.id == task_id)
            .where(CampaignTaskRecord.campaign_id == campaign_id)
            .where(CampaignTaskRecord.status == "running")
            .where(CampaignTaskRecord.execution_claim_id == execution_claim_id)
            .where(CampaignTaskRecord.execution_lease_expires_at > timestamp)
            .exists()
        )
        accounted_call_count = len(
            self.list_campaign_local_tool_call_reservations(campaign_id)
        ) + sum(
            _is_legacy_local_tool_call_consumption(run.payload)
            for run in self.list_campaign_scanner_runs(campaign_id)
        )
        budget = self.get_campaign_budget(campaign_id)

        try:
            if budget is not None:
                stored_count = func.coalesce(
                    CampaignBudgetRecord.tool_calls_reserved,
                    0,
                )
                effective_count = case(
                    (stored_count < accounted_call_count, accounted_call_count),
                    else_=stored_count,
                )
                budget_update = (
                    update(CampaignBudgetRecord)
                    .where(CampaignBudgetRecord.id == budget.id)
                    .where(
                        or_(
                            CampaignBudgetRecord.tool_call_budget.is_(None),
                            effective_count < CampaignBudgetRecord.tool_call_budget,
                        )
                    )
                    .values(tool_calls_reserved=effective_count + 1)
                    .execution_options(synchronize_session=False)
                )
                if self.session.execute(budget_update).rowcount != 1:
                    self.session.rollback()
                    self.session.expire_all()
                    return None

            agent_update = (
                update(AgentRunRecord)
                .where(AgentRunRecord.id == execution_claim_id)
                .where(AgentRunRecord.campaign_id == campaign_id)
                .where(AgentRunRecord.task_id == task_id)
                .where(AgentRunRecord.status == "running")
                .where(active_lease)
                .values(payload=_safe_display_value(reservation_payload))
                .execution_options(synchronize_session=False)
            )
            if self.session.execute(agent_update).rowcount != 1:
                self.session.rollback()
                self.session.expire_all()
                return None
            self.session.commit()
        except Exception:
            self.session.rollback()
            self.session.expire_all()
            raise

        self.session.expire_all()
        return self.session.get(AgentRunRecord, execution_claim_id)

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

    def claim_campaign_task(
        self,
        *,
        task_id: str,
        campaign_id: str,
        task_type: str,
        agent_type: str,
        title: str,
        input_refs: list[str] | None = None,
        payload: dict | None = None,
    ) -> tuple[CampaignTaskRecord, bool]:
        existing = self.session.get(CampaignTaskRecord, task_id)
        if existing is not None:
            return existing, False

        record = CampaignTaskRecord(
            id=_safe_display_value(task_id),
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
        try:
            self.session.commit()
        except IntegrityError:
            self.session.rollback()
            existing = self.session.get(CampaignTaskRecord, task_id)
            if existing is not None:
                return existing, False
            raise
        self.session.refresh(record)
        return record, True

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
        execution_claim_id: str | None = None,
        expected_execution_statuses: set[str] | None = None,
    ) -> CampaignTaskRecord | None:
        if execution_claim_id is not None:
            values: dict[str, Any] = {
                "status": _safe_display_value(status),
                "execution_claim_id": None,
                "execution_lease_expires_at": None,
            }
            if output_refs is not None:
                values["output_refs"] = _safe_display_value(output_refs)
            result = self.session.execute(
                update(CampaignTaskRecord)
                .where(CampaignTaskRecord.id == task_id)
                .where(
                    CampaignTaskRecord.status.in_(
                        expected_execution_statuses or {"running"}
                    )
                )
                .where(CampaignTaskRecord.execution_claim_id == execution_claim_id)
                .values(**values)
            )
            if result.rowcount != 1:
                self.session.commit()
                self.session.expire_all()
                return None
            self.session.commit()
            self.session.expire_all()
            return self.session.get(CampaignTaskRecord, task_id)

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

    def transition_campaign_task_status_if_currently(
        self,
        task_id: str,
        status: str,
        *,
        allowed_current_statuses: set[str],
        require_unclaimed_execution: bool = False,
    ) -> CampaignTaskRecord | None:
        safe_status = _safe_display_value(status)
        safe_allowed_statuses = {
            _safe_display_value(value) for value in allowed_current_statuses
        }
        transition = update(CampaignTaskRecord).where(
            CampaignTaskRecord.id == task_id,
            CampaignTaskRecord.status.in_(safe_allowed_statuses),
        )
        if require_unclaimed_execution:
            transition = transition.where(
                CampaignTaskRecord.execution_claim_id.is_(None)
            )
        result = self.session.execute(
            transition.values(status=safe_status).execution_options(
                synchronize_session=False
            )
        )
        self.session.commit()
        self.session.expire_all()
        if result.rowcount != 1:
            return None
        return self.session.get(CampaignTaskRecord, task_id)

    def mark_campaign_task_dispatched(
        self,
        task_id: str,
        *,
        execution_claim_id: str,
        now: datetime | None = None,
    ) -> CampaignTaskRecord | None:
        self.session.expire_all()
        record = self.session.get(CampaignTaskRecord, task_id)
        if record is None:
            return None
        payload = record.payload if isinstance(record.payload, dict) else {}
        if _is_research_director_local_tool_task(record, payload):
            return None
        timestamp = now or datetime.now(UTC)
        result = self.session.execute(
            update(CampaignTaskRecord)
            .where(CampaignTaskRecord.id == task_id)
            .where(CampaignTaskRecord.status.in_({"queued", "ready"}))
            .values(
                status="dispatched",
                execution_claim_id=_safe_display_value(execution_claim_id),
                execution_heartbeat_at=timestamp,
                execution_lease_expires_at=(
                    timestamp + timedelta(seconds=AUTONOMOUS_RESEARCH_TASK_LEASE_SECONDS)
                ),
            )
            .execution_options(synchronize_session=False)
        )
        if result.rowcount != 1:
            self.session.commit()
            self.session.expire_all()
            return None
        self.session.commit()
        self.session.expire_all()
        return self.session.get(CampaignTaskRecord, task_id)

    def _ensure_campaign_local_tool_execution_slot(
        self,
        *,
        campaign_id: str,
        source_snapshot_digest: str,
    ) -> CampaignLocalToolExecutionSlotRecord:
        slot_id = _campaign_local_tool_execution_slot_id(
            campaign_id=campaign_id,
            source_snapshot_digest=source_snapshot_digest,
        )
        existing = self.session.get(CampaignLocalToolExecutionSlotRecord, slot_id)
        if existing is not None:
            return existing
        slot = CampaignLocalToolExecutionSlotRecord(
            id=slot_id,
            campaign_id=campaign_id,
            source_snapshot_digest=source_snapshot_digest,
            active_task_id=None,
            active_execution_claim_id=None,
            legacy_active_task_count=0,
        )
        self.session.add(slot)
        try:
            self.session.commit()
        except IntegrityError:
            self.session.rollback()
            existing = self.session.scalar(
                select(CampaignLocalToolExecutionSlotRecord).where(
                    CampaignLocalToolExecutionSlotRecord.campaign_id == campaign_id,
                    CampaignLocalToolExecutionSlotRecord.source_snapshot_digest
                    == source_snapshot_digest,
                )
            )
            if existing is not None:
                return existing
            raise
        self.session.refresh(slot)
        return slot

    def _release_campaign_local_tool_execution_slot(
        self,
        *,
        campaign_id: str,
        source_snapshot_digest: str,
        task_id: str,
        execution_claim_id: str,
        legacy_task: bool,
    ) -> bool:
        if legacy_task:
            result = self.session.execute(
                update(CampaignLocalToolExecutionSlotRecord)
                .where(CampaignLocalToolExecutionSlotRecord.campaign_id == campaign_id)
                .where(
                    CampaignLocalToolExecutionSlotRecord.source_snapshot_digest
                    == source_snapshot_digest
                )
                .where(
                    CampaignLocalToolExecutionSlotRecord.legacy_active_task_count
                    > 0
                )
                .values(
                    legacy_active_task_count=(
                        CampaignLocalToolExecutionSlotRecord.legacy_active_task_count
                        - 1
                    )
                )
                .execution_options(synchronize_session=False)
            )
        else:
            result = self.session.execute(
                update(CampaignLocalToolExecutionSlotRecord)
                .where(CampaignLocalToolExecutionSlotRecord.campaign_id == campaign_id)
                .where(
                    CampaignLocalToolExecutionSlotRecord.source_snapshot_digest
                    == source_snapshot_digest
                )
                .where(CampaignLocalToolExecutionSlotRecord.active_task_id == task_id)
                .where(
                    CampaignLocalToolExecutionSlotRecord.active_execution_claim_id
                    == execution_claim_id
                )
                .values(
                    active_task_id=None,
                    active_execution_claim_id=None,
                )
                .execution_options(synchronize_session=False)
            )
        return result.rowcount == 1

    def _mark_research_director_local_tool_task_dispatched(
        self,
        *,
        record: CampaignTaskRecord,
        execution_claim_id: str,
        now: datetime | None,
        agent_run_payload: dict | None = None,
    ) -> CampaignTaskRecord | None:
        timestamp = now or datetime.now(UTC)
        safe_execution_claim_id = _safe_display_value(execution_claim_id)
        payload = record.payload if isinstance(record.payload, dict) else {}
        source_snapshot_digest = _research_director_local_tool_source_snapshot_digest(
            payload
        )
        if source_snapshot_digest is None:
            return None
        self._ensure_campaign_local_tool_execution_slot(
            campaign_id=record.campaign_id,
            source_snapshot_digest=source_snapshot_digest,
        )
        task_values: dict[str, Any] = {
            "status": "dispatched",
            "execution_claim_id": safe_execution_claim_id,
            "execution_heartbeat_at": timestamp,
            "execution_lease_expires_at": (
                timestamp + timedelta(seconds=AUTONOMOUS_RESEARCH_TASK_LEASE_SECONDS)
            ),
        }
        if payload.get(_LOCAL_TOOL_EXECUTION_SLOT_LEGACY_MARKER) is True:
            task_payload = dict(payload)
            task_payload.pop(_LOCAL_TOOL_EXECUTION_SLOT_LEGACY_MARKER, None)
            task_values["payload"] = _safe_display_value(task_payload)
        task_result = self.session.execute(
            update(CampaignTaskRecord)
            .where(CampaignTaskRecord.id == record.id)
            .where(CampaignTaskRecord.campaign_id == record.campaign_id)
            .where(
                CampaignTaskRecord.status.in_(
                    {"queued", "ready", "awaiting_approval"}
                )
            )
            .where(CampaignTaskRecord.execution_claim_id.is_(None))
            .values(**task_values)
            .execution_options(synchronize_session=False)
        )
        if task_result.rowcount != 1:
            self.session.rollback()
            self.session.expire_all()
            return None
        if agent_run_payload is not None:
            self.session.add(
                AgentRunRecord(
                    id=safe_execution_claim_id,
                    campaign_id=record.campaign_id,
                    task_id=record.id,
                    agent_type=record.agent_type,
                    status="dispatched",
                    input_refs=[f"campaign_task:{record.id}"],
                    output_refs=[],
                    tool_calls=[],
                    safety_gate_state="allowed",
                    stop_reason=None,
                    payload=_safe_display_value(agent_run_payload),
                )
            )
        slot_result = self.session.execute(
            update(CampaignLocalToolExecutionSlotRecord)
            .where(CampaignLocalToolExecutionSlotRecord.campaign_id == record.campaign_id)
            .where(
                CampaignLocalToolExecutionSlotRecord.source_snapshot_digest
                == source_snapshot_digest
            )
            .where(CampaignLocalToolExecutionSlotRecord.active_task_id.is_(None))
            .where(
                CampaignLocalToolExecutionSlotRecord.active_execution_claim_id.is_(None)
            )
            .where(CampaignLocalToolExecutionSlotRecord.legacy_active_task_count == 0)
            .values(
                active_task_id=record.id,
                active_execution_claim_id=safe_execution_claim_id,
            )
            .execution_options(synchronize_session=False)
        )
        if slot_result.rowcount != 1:
            self.session.rollback()
            self.session.expire_all()
            return None
        self.session.commit()
        self.session.expire_all()
        return self.session.get(CampaignTaskRecord, record.id)

    def dispatch_research_director_local_tool_task(
        self,
        *,
        task_id: str,
        agent_payload: dict,
        now: datetime | None = None,
    ) -> tuple[CampaignTaskRecord, AgentRunRecord] | None:
        self.session.expire_all()
        record = self.session.get(CampaignTaskRecord, task_id)
        if record is None:
            return None
        payload = record.payload if isinstance(record.payload, dict) else {}
        if (
            not _is_research_director_local_tool_task(record, payload)
            or record.status not in {"queued", "ready", "awaiting_approval"}
            or record.execution_claim_id is not None
            or self.find_active_agent_run_for_task(record.id) is not None
        ):
            return None
        execution_claim_id = f"agent_run_{uuid4().hex}"
        dispatched_task = self._mark_research_director_local_tool_task_dispatched(
            record=record,
            execution_claim_id=execution_claim_id,
            now=now,
            agent_run_payload=agent_payload,
        )
        if dispatched_task is None:
            return None
        agent_run = self.session.get(AgentRunRecord, execution_claim_id)
        if agent_run is None:
            return None
        return dispatched_task, agent_run

    def claim_failed_campaign_task_retry(
        self,
        task_id: str,
    ) -> CampaignTaskRecord | None:
        result = self.session.execute(
            update(CampaignTaskRecord)
            .where(CampaignTaskRecord.id == task_id)
            .where(CampaignTaskRecord.status == "failed")
            .where(CampaignTaskRecord.execution_claim_id.is_(None))
            .where(CampaignTaskRecord.execution_lease_expires_at.is_(None))
            .values(
                status="queued",
                execution_heartbeat_at=None,
            )
            .execution_options(synchronize_session=False)
        )
        self.session.commit()
        self.session.expire_all()
        if result.rowcount != 1:
            return None
        return self.session.get(CampaignTaskRecord, task_id)

    def fail_unclaimed_campaign_task(
        self,
        task_id: str,
        *,
        stop_reason: str,
        now: datetime | None = None,
    ) -> CampaignTaskRecord | None:
        timestamp = now or datetime.now(UTC)
        result = self.session.execute(
            update(CampaignTaskRecord)
            .where(CampaignTaskRecord.id == task_id)
            .where(CampaignTaskRecord.status.in_({"queued", "ready"}))
            .where(CampaignTaskRecord.execution_claim_id.is_(None))
            .values(
                status="failed",
                execution_heartbeat_at=None,
                execution_lease_expires_at=None,
            )
            .execution_options(synchronize_session=False)
        )
        if result.rowcount != 1:
            self.session.commit()
            self.session.expire_all()
            return None
        self.session.execute(
            update(AgentRunRecord)
            .where(AgentRunRecord.task_id == task_id)
            .where(
                AgentRunRecord.status.in_(
                    ("dispatched", "running", "awaiting_approval")
                )
            )
            .values(
                status="failed",
                safety_gate_state="blocked",
                stop_reason=_safe_display_value(stop_reason),
                finished_at=timestamp,
            )
        )
        self.session.commit()
        self.session.expire_all()
        return self.session.get(CampaignTaskRecord, task_id)

    def fail_incomplete_campaign_task_execution(
        self,
        task_id: str,
        *,
        stop_reason: str,
        now: datetime | None = None,
    ) -> CampaignTaskRecord | None:
        timestamp = now or datetime.now(UTC)
        result = self.session.execute(
            update(CampaignTaskRecord)
            .where(CampaignTaskRecord.id == task_id)
            .where(CampaignTaskRecord.status.in_({"dispatched", "running"}))
            .where(
                or_(
                    CampaignTaskRecord.execution_claim_id.is_(None),
                    CampaignTaskRecord.execution_lease_expires_at.is_(None),
                )
            )
            .values(
                status="failed",
                execution_claim_id=None,
                execution_heartbeat_at=None,
                execution_lease_expires_at=None,
            )
            .execution_options(synchronize_session=False)
        )
        if result.rowcount != 1:
            self.session.commit()
            self.session.expire_all()
            return None
        self.session.execute(
            update(AgentRunRecord)
            .where(AgentRunRecord.task_id == task_id)
            .where(AgentRunRecord.status.in_(("dispatched", "running")))
            .values(
                status="failed",
                safety_gate_state="blocked",
                stop_reason=_safe_display_value(stop_reason),
                finished_at=timestamp,
            )
        )
        self.session.commit()
        self.session.expire_all()
        return self.session.get(CampaignTaskRecord, task_id)

    def complete_autonomous_validation_handoff_review(
        self,
        *,
        campaign_id: str,
        task_id: str,
        pipeline_run_id: str,
        input_refs: list[str],
        payload: dict,
    ) -> tuple[CampaignTaskRecord, PipelineStageRecord] | None:
        result = self._complete_autonomous_validation_handoff_review(
            campaign_id=campaign_id,
            task_id=task_id,
            pipeline_run_id=pipeline_run_id,
            input_refs=input_refs,
            payload=payload,
            manual_validation=None,
        )
        return result[:2] if result is not None else None

    def complete_autonomous_validation_handoff_review_with_manual_validation(
        self,
        *,
        campaign_id: str,
        task_id: str,
        pipeline_run_id: str,
        input_refs: list[str],
        payload: dict,
        manual_validation: dict[str, Any],
    ) -> tuple[
        CampaignTaskRecord,
        PipelineStageRecord,
        ApprovalRecord,
        ValidationRunRecord,
    ] | None:
        result = self._complete_autonomous_validation_handoff_review(
            campaign_id=campaign_id,
            task_id=task_id,
            pipeline_run_id=pipeline_run_id,
            input_refs=input_refs,
            payload=payload,
            manual_validation=manual_validation,
        )
        if result is None or result[2] is None or result[3] is None:
            return None
        return result[0], result[1], result[2], result[3]

    def _complete_autonomous_validation_handoff_review(
        self,
        *,
        campaign_id: str,
        task_id: str,
        pipeline_run_id: str,
        input_refs: list[str],
        payload: dict,
        manual_validation: dict[str, Any] | None,
    ) -> tuple[
        CampaignTaskRecord,
        PipelineStageRecord,
        ApprovalRecord | None,
        ValidationRunRecord | None,
    ] | None:
        campaign = self.session.get(CampaignRecord, campaign_id)
        approval = None
        validation_run = None
        output_refs = [f"campaign_task:{_safe_display_value(task_id)}"]
        if manual_validation is not None:
            if campaign is None:
                return None
            approval = ApprovalRecord(
                id=f"approval_{uuid4().hex}",
                campaign_id=campaign_id,
                task_id=task_id,
                run_id=_safe_display_value(pipeline_run_id),
                program_id=campaign.program_id,
                approval_type="validation_batch",
                actor=_safe_display_value(manual_validation["reviewer"]),
                reason=_safe_display_value(manual_validation["approval_reason"]),
                scope_reference=_safe_display_value(
                    manual_validation["scope_reference"]
                ),
                requested_action="manual_validation_preflight",
                asset=_safe_asset_value(manual_validation["asset"]),
                validation_mode=_safe_display_value(manual_validation["validation_mode"]),
                plan_digest=_safe_display_value(manual_validation["plan_digest"]),
                autonomy_level=_safe_display_value(campaign.autonomy_level),
                safety_gate_state="awaiting_approval",
                status="requested",
                payload=_safe_display_value(manual_validation["approval_payload"]),
            )
            validation_payload = dict(manual_validation["validation_payload"])
            validation_payload["approval_record_id"] = approval.id
            validation_run = ValidationRunRecord(
                id=f"validation_run_{uuid4().hex}",
                campaign_id=campaign_id,
                task_id=task_id,
                approval_id=approval.id,
                validation_mode=_safe_display_value(manual_validation["validation_mode"]),
                target_ref=_safe_source_path(manual_validation["target_ref"]),
                status="awaiting_approval",
                safety_gate_state="awaiting_approval",
                plan_digest=_safe_display_value(manual_validation["plan_digest"]),
                approval_required=True,
                allowed_to_execute=False,
                evidence_ref_count=0,
                summary=_safe_display_value(manual_validation["summary"]),
                payload=_safe_display_value(validation_payload),
            )
            output_refs.extend(
                [f"approval:{approval.id}", f"validation_run:{validation_run.id}"]
            )
        review_stage = PipelineStageRecord(
            id=f"pipeline_stage_{uuid4().hex}",
            pipeline_run_id=_safe_display_value(pipeline_run_id),
            campaign_id=_safe_display_value(campaign_id),
            task_id=_safe_display_value(task_id),
            stage_key="autonomous_validation_handoff_review",
            stage_order=41,
            status="completed",
            input_refs=_safe_display_value(input_refs),
            output_refs=output_refs,
            safety_gate_state="human_review_completed",
            stop_reason=None,
            payload=_safe_display_value(payload),
        )
        campaign_result = self.session.execute(
            update(CampaignRecord)
            .where(
                CampaignRecord.id == campaign_id,
                CampaignRecord.status.in_({"awaiting_review", "paused"}),
            )
            .values(status="reviewing")
            .execution_options(synchronize_session=False)
        )
        if campaign_result.rowcount != 1:
            self.session.rollback()
            self.session.expire_all()
            return None
        task_result = self.session.execute(
            update(CampaignTaskRecord)
            .where(
                CampaignTaskRecord.id == task_id,
                CampaignTaskRecord.campaign_id == campaign_id,
                CampaignTaskRecord.task_type == "validation_handoff",
                CampaignTaskRecord.status == "awaiting_approval",
            )
            .values(
                status="completed",
                output_refs=_safe_display_value([f"pipeline_stage:{review_stage.id}"]),
            )
            .execution_options(synchronize_session=False)
        )
        if task_result.rowcount != 1:
            self.session.rollback()
            self.session.expire_all()
            return None

        self.session.add(review_stage)
        if approval is not None and validation_run is not None:
            self.session.add_all([approval, validation_run])
        remaining_handoff = self.session.scalar(
            select(CampaignTaskRecord.id)
            .where(
                CampaignTaskRecord.campaign_id == campaign_id,
                CampaignTaskRecord.task_type == "validation_handoff",
                CampaignTaskRecord.status == "awaiting_approval",
            )
            .limit(1)
        )
        if remaining_handoff is None:
            final_campaign_status = "completed"
        else:
            final_campaign_status = "awaiting_review"
        self.session.execute(
            update(CampaignRecord)
            .where(
                CampaignRecord.id == campaign_id,
                CampaignRecord.status == "reviewing",
            )
            .values(status=final_campaign_status)
            .execution_options(synchronize_session=False)
        )
        try:
            self.session.commit()
        except Exception:
            self.session.rollback()
            raise
        self.session.expire_all()
        reviewed_task = self.session.get(CampaignTaskRecord, task_id)
        reviewed_stage = self.session.get(PipelineStageRecord, review_stage.id)
        if reviewed_task is None or reviewed_stage is None:
            return None
        if approval is None or validation_run is None:
            return reviewed_task, reviewed_stage, None, None
        reviewed_approval = self.session.get(ApprovalRecord, approval.id)
        reviewed_validation_run = self.session.get(ValidationRunRecord, validation_run.id)
        if reviewed_approval is None or reviewed_validation_run is None:
            return None
        return reviewed_task, reviewed_stage, reviewed_approval, reviewed_validation_run

    def claim_campaign_task_execution(
        self,
        task_id: str,
        *,
        now: datetime | None = None,
    ) -> CampaignTaskRecord | None:
        self.session.expire_all()
        record = self.session.get(CampaignTaskRecord, task_id)
        if record is None:
            return None
        payload = record.payload if isinstance(record.payload, dict) else {}
        if _is_research_director_local_tool_task(record, payload):
            return self._claim_research_director_local_tool_task_execution(
                record=record,
                now=now,
            )
        if _campaign_task_requires_execution_lease(record, payload):
            return self._claim_autonomous_research_task_execution(
                record=record,
                now=now,
            )

        result = self.session.execute(
            update(CampaignTaskRecord)
            .where(
                CampaignTaskRecord.id == task_id,
                CampaignTaskRecord.status.in_({"queued", "ready", "dispatched"}),
            )
            .values(status="running")
        )
        if result.rowcount != 1:
            self.session.commit()
            self.session.expire_all()
            return None
        record = self.session.get(CampaignTaskRecord, task_id)
        if record is None:
            self.session.commit()
            return None
        if self.find_active_agent_run_for_task(task_id) is None:
            self.session.add(
                AgentRunRecord(
                    id=f"agent_run_{uuid4().hex}",
                    campaign_id=record.campaign_id,
                    task_id=record.id,
                    agent_type=record.agent_type,
                    status="running",
                    input_refs=[f"campaign_task:{record.id}"],
                    output_refs=[],
                    tool_calls=[],
                    safety_gate_state="allowed",
                    stop_reason=None,
                    payload={
                        "worker_execution_claim": True,
                        "raw_payload_processed": False,
                    },
                )
            )
        self.session.commit()
        self.session.refresh(record)
        return record

    def _claim_research_director_local_tool_task_execution(
        self,
        *,
        record: CampaignTaskRecord,
        now: datetime | None,
    ) -> CampaignTaskRecord | None:
        timestamp = now or datetime.now(UTC)
        payload = record.payload if isinstance(record.payload, dict) else {}
        source_snapshot_digest = _research_director_local_tool_source_snapshot_digest(
            payload
        )
        if source_snapshot_digest is None:
            return None
        self._ensure_campaign_local_tool_execution_slot(
            campaign_id=record.campaign_id,
            source_snapshot_digest=source_snapshot_digest,
        )
        if record.status == "dispatched":
            execution_claim_id = record.execution_claim_id
            if not execution_claim_id:
                return None
            task_result = self.session.execute(
                update(CampaignTaskRecord)
                .where(CampaignTaskRecord.id == record.id)
                .where(CampaignTaskRecord.status == "dispatched")
                .where(CampaignTaskRecord.execution_claim_id == execution_claim_id)
                .where(CampaignTaskRecord.execution_lease_expires_at > timestamp)
                .values(
                    status="running",
                    execution_heartbeat_at=timestamp,
                    execution_lease_expires_at=(
                        timestamp
                        + timedelta(seconds=AUTONOMOUS_RESEARCH_TASK_LEASE_SECONDS)
                    ),
                )
                .execution_options(synchronize_session=False)
            )
            if task_result.rowcount != 1:
                self.session.rollback()
                self.session.expire_all()
                return None
            agent_result = self.session.execute(
                update(AgentRunRecord)
                .where(AgentRunRecord.id == execution_claim_id)
                .where(AgentRunRecord.task_id == record.id)
                .where(AgentRunRecord.status == "dispatched")
                .values(status="running")
                .execution_options(synchronize_session=False)
            )
            if agent_result.rowcount != 1:
                self.session.rollback()
                self.session.expire_all()
                return None
            if payload.get(_LOCAL_TOOL_EXECUTION_SLOT_LEGACY_MARKER) is not True:
                slot_result = self.session.execute(
                    update(CampaignLocalToolExecutionSlotRecord)
                    .where(
                        CampaignLocalToolExecutionSlotRecord.campaign_id
                        == record.campaign_id
                    )
                    .where(
                        CampaignLocalToolExecutionSlotRecord.source_snapshot_digest
                        == source_snapshot_digest
                    )
                    .where(
                        CampaignLocalToolExecutionSlotRecord.active_task_id == record.id
                    )
                    .where(
                        CampaignLocalToolExecutionSlotRecord.active_execution_claim_id
                        == execution_claim_id
                    )
                    .values(
                        active_task_id=record.id,
                        active_execution_claim_id=execution_claim_id,
                    )
                    .execution_options(synchronize_session=False)
                )
                if slot_result.rowcount != 1:
                    self.session.rollback()
                    self.session.expire_all()
                    return None
            self.session.commit()
            self.session.expire_all()
            return self.session.get(CampaignTaskRecord, record.id)

        if record.status not in {"queued", "ready", "awaiting_approval"}:
            return None
        if record.execution_claim_id is not None:
            return None
        if self.find_active_agent_run_for_task(record.id) is not None:
            return None
        execution_claim_id = f"agent_run_{uuid4().hex}"
        task_values: dict[str, Any] = {
            "status": "running",
            "execution_claim_id": execution_claim_id,
            "execution_heartbeat_at": timestamp,
            "execution_lease_expires_at": (
                timestamp + timedelta(seconds=AUTONOMOUS_RESEARCH_TASK_LEASE_SECONDS)
            ),
        }
        if payload.get(_LOCAL_TOOL_EXECUTION_SLOT_LEGACY_MARKER) is True:
            task_payload = dict(payload)
            task_payload.pop(_LOCAL_TOOL_EXECUTION_SLOT_LEGACY_MARKER, None)
            task_values["payload"] = _safe_display_value(task_payload)
        task_result = self.session.execute(
            update(CampaignTaskRecord)
            .where(CampaignTaskRecord.id == record.id)
            .where(CampaignTaskRecord.campaign_id == record.campaign_id)
            .where(CampaignTaskRecord.status.in_({"queued", "ready", "awaiting_approval"}))
            .where(CampaignTaskRecord.execution_claim_id.is_(None))
            .values(**task_values)
            .execution_options(synchronize_session=False)
        )
        if task_result.rowcount != 1:
            self.session.rollback()
            self.session.expire_all()
            return None
        self.session.add(
            AgentRunRecord(
                id=execution_claim_id,
                campaign_id=record.campaign_id,
                task_id=record.id,
                agent_type=record.agent_type,
                status="running",
                input_refs=[f"campaign_task:{record.id}"],
                output_refs=[],
                tool_calls=[],
                safety_gate_state="allowed",
                stop_reason=None,
                payload={
                    "research_director_local_execution_claim": True,
                    "raw_payload_processed": False,
                },
            )
        )
        slot_result = self.session.execute(
            update(CampaignLocalToolExecutionSlotRecord)
            .where(
                CampaignLocalToolExecutionSlotRecord.campaign_id
                == record.campaign_id
            )
            .where(
                CampaignLocalToolExecutionSlotRecord.source_snapshot_digest
                == source_snapshot_digest
            )
            .where(CampaignLocalToolExecutionSlotRecord.active_task_id.is_(None))
            .where(
                CampaignLocalToolExecutionSlotRecord.active_execution_claim_id.is_(None)
            )
            .where(CampaignLocalToolExecutionSlotRecord.legacy_active_task_count == 0)
            .values(
                active_task_id=record.id,
                active_execution_claim_id=execution_claim_id,
            )
            .execution_options(synchronize_session=False)
        )
        if slot_result.rowcount != 1:
            self.session.rollback()
            self.session.expire_all()
            return None
        self.session.commit()
        self.session.expire_all()
        return self.session.get(CampaignTaskRecord, record.id)

    def _claim_autonomous_research_task_execution(
        self,
        *,
        record: CampaignTaskRecord,
        now: datetime | None,
    ) -> CampaignTaskRecord | None:
        timestamp = now or datetime.now(UTC)
        payload = record.payload if isinstance(record.payload, dict) else {}
        agent_payload = (
            {
                "worker_execution_claim": True,
                "raw_payload_processed": False,
            }
            if record.task_type == _CANDIDATE_HUNTER_EVIDENCE_TASK_TYPE
            else {
                "research_director_local_execution_claim": True,
                "raw_payload_processed": False,
            }
            if record.task_type == _RESEARCH_DIRECTOR_LOCAL_TOOL_TASK_TYPE
            else {
                "runtime_execution_claim": True,
                "raw_payload_processed": False,
            }
        )
        active_run = self.find_active_agent_run_for_task(record.id)
        if (
            record.execution_claim_id is not None
            and active_run is not None
            and active_run.id != record.execution_claim_id
        ):
            return None
        if record.execution_claim_id is not None:
            execution_claim_id = record.execution_claim_id
        elif active_run is not None:
            execution_claim_id = active_run.id
        else:
            execution_claim_id = f"agent_run_{uuid4().hex}"
        claimable_status = or_(
            CampaignTaskRecord.status.in_(("queued", "ready")),
            and_(
                CampaignTaskRecord.status == "dispatched",
                CampaignTaskRecord.execution_lease_expires_at > timestamp,
            ),
        )
        result = self.session.execute(
            update(CampaignTaskRecord)
            .where(CampaignTaskRecord.id == record.id)
            .where(claimable_status)
            .values(
                status="running",
                execution_claim_id=execution_claim_id,
                execution_heartbeat_at=timestamp,
                execution_lease_expires_at=(
                    timestamp + timedelta(seconds=AUTONOMOUS_RESEARCH_TASK_LEASE_SECONDS)
                ),
            )
            .execution_options(synchronize_session=False)
        )
        if result.rowcount != 1:
            self.session.commit()
            self.session.expire_all()
            return None
        if active_run is None:
            self.session.add(
                AgentRunRecord(
                    id=execution_claim_id,
                    campaign_id=record.campaign_id,
                    task_id=record.id,
                    agent_type=record.agent_type,
                    status="running",
                    input_refs=[f"campaign_task:{record.id}"],
                    output_refs=[],
                    tool_calls=[],
                    safety_gate_state="allowed",
                    stop_reason=None,
                    payload=agent_payload,
                )
            )
        else:
            self.session.execute(
                update(AgentRunRecord)
                .where(AgentRunRecord.id == active_run.id)
                .where(AgentRunRecord.status == "dispatched")
                .values(status="running")
            )
        self.session.commit()
        self.session.expire_all()
        return self.session.get(CampaignTaskRecord, record.id)

    def renew_campaign_task_execution_lease(
        self,
        task_id: str,
        *,
        execution_claim_id: str | None,
        now: datetime | None = None,
    ) -> CampaignTaskRecord | None:
        if not execution_claim_id:
            return None
        timestamp = now or datetime.now(UTC)
        result = self.session.execute(
            update(CampaignTaskRecord)
            .where(CampaignTaskRecord.id == task_id)
            .where(CampaignTaskRecord.status == "running")
            .where(CampaignTaskRecord.execution_claim_id == execution_claim_id)
            .where(CampaignTaskRecord.execution_lease_expires_at > timestamp)
            .values(
                execution_heartbeat_at=timestamp,
                execution_lease_expires_at=(
                    timestamp + timedelta(seconds=AUTONOMOUS_RESEARCH_TASK_LEASE_SECONDS)
                ),
            )
            .execution_options(synchronize_session=False)
        )
        if result.rowcount != 1:
            self.session.commit()
            self.session.expire_all()
            return None
        self.session.commit()
        self.session.expire_all()
        return self.session.get(CampaignTaskRecord, task_id)

    def expire_campaign_task_execution(
        self,
        task_id: str,
        *,
        now: datetime | None = None,
    ) -> CampaignTaskRecord | None:
        timestamp = now or datetime.now(UTC)
        self.session.expire_all()
        record = self.session.get(CampaignTaskRecord, task_id)
        if (
            record is None
            or record.status not in {"dispatched", "running"}
            or not record.execution_claim_id
            or record.execution_lease_expires_at is None
            or _as_utc(record.execution_lease_expires_at) > _as_utc(timestamp)
        ):
            return None
        execution_claim_id = record.execution_claim_id
        payload = record.payload if isinstance(record.payload, dict) else {}
        source_snapshot_digest = (
            _research_director_local_tool_source_snapshot_digest(payload)
            if _is_research_director_local_tool_task(record, payload)
            else None
        )
        output_refs = list(record.output_refs) if isinstance(record.output_refs, list) else []
        agent_run_ref = f"agent_run:{execution_claim_id}"
        if agent_run_ref not in output_refs:
            output_refs.append(agent_run_ref)
        result = self.session.execute(
            update(CampaignTaskRecord)
            .where(CampaignTaskRecord.id == task_id)
            .where(CampaignTaskRecord.status.in_(("dispatched", "running")))
            .where(CampaignTaskRecord.execution_claim_id == execution_claim_id)
            .where(CampaignTaskRecord.execution_lease_expires_at <= timestamp)
            .values(
                status="failed",
                output_refs=_safe_display_value(output_refs),
                execution_claim_id=None,
                execution_lease_expires_at=None,
            )
            .execution_options(synchronize_session=False)
        )
        if result.rowcount != 1:
            self.session.commit()
            self.session.expire_all()
            return None
        self.session.execute(
            update(AgentRunRecord)
            .where(AgentRunRecord.id == execution_claim_id)
            .where(AgentRunRecord.task_id == task_id)
            .where(AgentRunRecord.status.in_(("dispatched", "running")))
            .values(
                status="failed",
                safety_gate_state="blocked",
                stop_reason="execution_lease_expired",
                finished_at=timestamp,
            )
        )
        if source_snapshot_digest is not None:
            if not self._release_campaign_local_tool_execution_slot(
                campaign_id=record.campaign_id,
                source_snapshot_digest=source_snapshot_digest,
                task_id=task_id,
                execution_claim_id=execution_claim_id,
                legacy_task=(
                    payload.get(_LOCAL_TOOL_EXECUTION_SLOT_LEGACY_MARKER) is True
                ),
            ):
                self.session.rollback()
                self.session.expire_all()
                return None
        self.session.commit()
        self.session.expire_all()
        return self.session.get(CampaignTaskRecord, task_id)

    def finish_campaign_task_execution(
        self,
        *,
        task_id: str,
        execution_claim_id: str | None,
        task_status: str,
        task_output_refs: list[str],
        agent_status: str,
        agent_output_refs: list[str],
        safety_gate_state: str,
        stop_reason: str | None,
        payload: dict,
        expected_execution_statuses: set[str] | None = None,
        additional_records: list[object] | None = None,
        require_active_execution_lease: bool = False,
    ) -> tuple[CampaignTaskRecord, AgentRunRecord] | None:
        if not execution_claim_id:
            return None
        record = self.session.get(CampaignTaskRecord, task_id)
        if record is None:
            return None
        payload_for_slot = record.payload if isinstance(record.payload, dict) else {}
        source_snapshot_digest = (
            _research_director_local_tool_source_snapshot_digest(payload_for_slot)
            if _is_research_director_local_tool_task(record, payload_for_slot)
            else None
        )
        timestamp = datetime.now(UTC)
        task_update = (
            update(CampaignTaskRecord)
            .where(CampaignTaskRecord.id == task_id)
            .where(
                CampaignTaskRecord.status.in_(
                    expected_execution_statuses or {"running"}
                )
            )
            .where(CampaignTaskRecord.execution_claim_id == execution_claim_id)
            .values(
                status=_safe_display_value(task_status),
                output_refs=_safe_display_value(task_output_refs),
                execution_claim_id=None,
                execution_lease_expires_at=None,
            )
            .execution_options(synchronize_session=False)
        )
        if require_active_execution_lease:
            task_update = task_update.where(
                CampaignTaskRecord.execution_lease_expires_at > timestamp
            )
        task_result = self.session.execute(task_update)
        if task_result.rowcount != 1:
            self.session.rollback()
            self.session.expire_all()
            return None
        agent_result = self.session.execute(
            update(AgentRunRecord)
            .where(AgentRunRecord.id == execution_claim_id)
            .where(AgentRunRecord.task_id == task_id)
            .where(AgentRunRecord.status.in_(("dispatched", "running")))
            .values(
                status=_safe_display_value(agent_status),
                output_refs=_safe_display_value(agent_output_refs),
                safety_gate_state=_safe_display_value(safety_gate_state),
                stop_reason=_safe_display_value(stop_reason),
                payload=_safe_display_value(payload),
                finished_at=timestamp,
            )
        )
        if agent_result.rowcount != 1:
            self.session.rollback()
            self.session.expire_all()
            return None
        if source_snapshot_digest is not None:
            if not self._release_campaign_local_tool_execution_slot(
                campaign_id=record.campaign_id,
                source_snapshot_digest=source_snapshot_digest,
                task_id=task_id,
                execution_claim_id=execution_claim_id,
                legacy_task=(
                    payload_for_slot.get(_LOCAL_TOOL_EXECUTION_SLOT_LEGACY_MARKER)
                    is True
                ),
            ):
                self.session.rollback()
                self.session.expire_all()
                return None
        if additional_records:
            self.session.add_all(additional_records)
        try:
            self.session.commit()
        except Exception:
            self.session.rollback()
            self.session.expire_all()
            raise
        self.session.expire_all()
        task = self.session.get(CampaignTaskRecord, task_id)
        agent_run = self.session.get(AgentRunRecord, execution_claim_id)
        if task is None or agent_run is None:
            return None
        return task, agent_run

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
        approval_id: str | None = None,
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
        single_use_nonce_digest: str | None = None,
    ) -> ApprovalRecord:
        record_id = _safe_display_value(approval_id) if approval_id is not None else (
            f"approval_{uuid4().hex}"
        )
        record = ApprovalRecord(
            id=record_id,
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
            single_use_nonce_digest=_safe_display_value(single_use_nonce_digest)
            if single_use_nonce_digest is not None
            else None,
        )
        self.session.add(record)
        try:
            self.session.commit()
        except IntegrityError:
            self.session.rollback()
            if approval_id is None:
                raise
            existing = self.session.get(ApprovalRecord, record_id)
            if existing is not None:
                return existing
            raise
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
        stage_id: str | None = None,
        stage_key: str,
        stage_order: int,
        status: str,
        input_refs: list[str] | None = None,
        output_refs: list[str] | None = None,
        safety_gate_state: str,
        stop_reason: str | None,
        payload: dict | None = None,
        strict_idempotency: bool = False,
        commit: bool = True,
    ) -> PipelineStageRecord:
        safe_payload = _safe_display_value(payload or {})
        safe_stage_key = _safe_display_value(stage_key)
        safe_status = _safe_display_value(status)
        safe_input_refs = _safe_display_value(input_refs or [])
        safe_output_refs = _safe_display_value(output_refs or [])
        safe_safety_gate_state = _safe_display_value(safety_gate_state)
        safe_stop_reason = _safe_display_value(stop_reason)
        if strict_idempotency and stage_id is None:
            raise ValueError("pipeline_stage_id_required")
        record_id = stage_id or f"pipeline_stage_{uuid4().hex}"
        match_kwargs = {
            "pipeline_run_id": pipeline_run_id,
            "campaign_id": campaign_id,
            "task_id": task_id,
            "stage_key": safe_stage_key,
            "stage_order": stage_order,
            "status": safe_status,
            "input_refs": safe_input_refs,
            "output_refs": safe_output_refs,
            "safety_gate_state": safe_safety_gate_state,
            "stop_reason": safe_stop_reason,
            "payload": safe_payload,
        }
        existing = _existing_pipeline_stage_for_idempotency_key(
            self.session,
            pipeline_run_id=pipeline_run_id,
            campaign_id=campaign_id,
            task_id=task_id,
            stage_key=stage_key,
            payload=safe_payload,
        )
        if existing is not None:
            if strict_idempotency and (
                existing.id != record_id
                or not _pipeline_stage_matches_save_request(existing, **match_kwargs)
            ):
                raise ValueError("pipeline_stage_id_conflict")
            return existing
        existing = self.session.get(PipelineStageRecord, record_id)
        if existing is not None:
            if not _pipeline_stage_matches_save_request(existing, **match_kwargs):
                raise ValueError("pipeline_stage_id_conflict")
            return existing
        record = PipelineStageRecord(
            id=record_id,
            pipeline_run_id=pipeline_run_id,
            campaign_id=campaign_id,
            task_id=task_id,
            stage_key=safe_stage_key,
            stage_order=stage_order,
            status=safe_status,
            input_refs=safe_input_refs,
            output_refs=safe_output_refs,
            safety_gate_state=safe_safety_gate_state,
            stop_reason=safe_stop_reason,
            payload=safe_payload,
        )
        self.session.add(record)
        try:
            if commit:
                self.session.commit()
            else:
                self.session.flush()
        except IntegrityError:
            self.session.rollback()
            existing = self.session.get(PipelineStageRecord, record_id)
            if existing is None:
                raise
            if not _pipeline_stage_matches_save_request(existing, **match_kwargs):
                raise ValueError("pipeline_stage_id_conflict")
            return existing
        if commit:
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
        record_payload = record.payload if isinstance(record.payload, dict) else {}
        if (
            record.stage_key.startswith("black_box_")
            and record_payload.get("schema_version")
            in {"black_box_audit_v1", "black_box_audit_v2"}
        ):
            raise ValueError("append_only_black_box_audit_stage")
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
        commit: bool = True,
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
        if commit:
            self.session.commit()
            self.session.refresh(record)
        else:
            self.session.flush()
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

    def record_validation_run_bounded_result(
        self,
        validation_run_id: str,
        *,
        audit_digest: str,
        decision_status: str,
        evidence_refs: list[str],
        payload: dict,
    ) -> ValidationRunRecord | None:
        record = self.get_validation_run(validation_run_id)
        if record is None:
            return None
        if record.status != "preflight_passed" or not record.allowed_to_execute:
            return None
        terminal_state = {
            "review_ready": ("evidence_recorded", "black_box_review_ready"),
            "refuted": ("refuted", "black_box_refuted"),
            "hypothesis": ("needs_evidence", "black_box_needs_evidence"),
            "observed": ("needs_evidence", "black_box_needs_evidence"),
            "reproduced": ("needs_evidence", "black_box_needs_evidence"),
            "inconclusive": ("needs_evidence", "black_box_inconclusive"),
        }.get(_safe_display_value(decision_status))
        if terminal_state is None:
            return None

        safe_evidence_refs = _safe_display_value(evidence_refs)
        safe_evidence_ref_count = _safe_evidence_ref_count(safe_evidence_refs)
        record.status, record.safety_gate_state = terminal_state
        record.allowed_to_execute = False
        record.evidence_ref_count = safe_evidence_ref_count
        record.summary = _safe_display_value(
            f"Bounded black-box result recorded: {decision_status}"
        )
        record.finished_at = datetime.now(UTC)
        record_payload = dict(record.payload)
        record_payload["black_box_bounded_result"] = _safe_display_value(
            {
                "audit_digest": audit_digest,
                "decision_status": decision_status,
                "evidence_refs": safe_evidence_refs,
                "execution_started": False,
                "result_payload": payload,
                "recorded_at": record.finished_at.isoformat(),
            }
        )
        record.payload = record_payload
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
        field_pilot_feedback: dict | None = None,
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
                field_pilot_feedback=field_pilot_feedback,
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
            field_pilot_feedback=_safe_display_value(field_pilot_feedback),
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


def _pipeline_stage_matches_save_request(
    stage: PipelineStageRecord,
    *,
    pipeline_run_id: str | None,
    campaign_id: str | None,
    task_id: str | None,
    stage_key: str,
    stage_order: int,
    status: str,
    input_refs: list[str],
    output_refs: list[str],
    safety_gate_state: str,
    stop_reason: str | None,
    payload: dict,
) -> bool:
    return (
        stage.pipeline_run_id == pipeline_run_id
        and stage.campaign_id == campaign_id
        and stage.task_id == task_id
        and stage.stage_key == stage_key
        and stage.stage_order == stage_order
        and stage.status == status
        and stage.input_refs == input_refs
        and stage.output_refs == output_refs
        and stage.safety_gate_state == safety_gate_state
        and stage.stop_reason == stop_reason
        and stage.payload == payload
    )


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
    if all(updated.get(key) == value for key, value in safe_duplicate.items()):
        return updated
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


def _program_rule_safe_alias(value: str) -> str:
    if not isinstance(value, str) or _PROGRAM_RULE_ALIAS_PATTERN.fullmatch(value) is None:
        raise ValueError("program-rule alias is invalid")
    return value


def _program_rule_sha256(value: str) -> str:
    if not isinstance(value, str) or _SHA256_PATTERN.fullmatch(value) is None:
        raise ValueError("program-rule digest is invalid")
    return value


def _program_rule_safe_text(value: str) -> str:
    if not isinstance(value, str) or not value or len(value) > 2048:
        raise ValueError("program-rule payload is not safe to persist")
    safe = _program_rule_safe_json(value)
    if not isinstance(safe, str):
        raise ValueError("program-rule payload is not safe to persist")
    return safe


def _program_rule_safe_json(value: Any) -> Any:
    safe = _program_rule_redacted_value(value)
    if safe != value or _program_rule_contains_forbidden_material(value):
        raise ValueError("program-rule payload is not safe to persist")
    try:
        json.dumps(safe, ensure_ascii=False, allow_nan=False)
    except (TypeError, ValueError):
        raise ValueError("program-rule payload is not safe to persist") from None
    return safe


def _program_rule_redacted_value(value: Any) -> Any:
    if isinstance(value, str):
        return REDACTED if _is_secret_like(value) else value
    if isinstance(value, list):
        return [_program_rule_redacted_value(item) for item in value]
    if isinstance(value, tuple):
        return tuple(_program_rule_redacted_value(item) for item in value)
    if isinstance(value, dict):
        structured_secret_value_keys = _structured_secret_pair_value_keys(value)
        return {
            key: REDACTED
            if _is_secret_key(str(key))
            or _is_structured_secret_value_key(key, structured_secret_value_keys)
            else _program_rule_redacted_value(nested_value)
            for key, nested_value in value.items()
        }
    return value


def _program_rule_contains_forbidden_material(value: Any) -> bool:
    if isinstance(value, str):
        return _PROGRAM_RULE_RAW_HTML_PATTERN.search(value) is not None
    if isinstance(value, (list, tuple)):
        return any(_program_rule_contains_forbidden_material(item) for item in value)
    if not isinstance(value, dict):
        return False
    for key, nested_value in value.items():
        if not isinstance(key, str):
            return True
        normalized_key = re.sub(r"[^a-z0-9]", "", key.lower())
        if normalized_key in _PROGRAM_RULE_FORBIDDEN_KEYS:
            return True
        if _program_rule_contains_forbidden_material(nested_value):
            return True
    return False


def _program_scope_rule_values(rule: dict) -> dict:
    expected_keys = {
        "canonical_asset",
        "asset_kind",
        "source_evidence_refs",
        "scope_status",
        "automation",
        "allowed_validation",
        "prohibited",
        "rate_limit",
    }
    if not isinstance(rule, dict) or set(rule) != expected_keys:
        raise ValueError("program-rule scope payload is invalid")
    return {
        "canonical_asset": _program_rule_safe_text(rule["canonical_asset"]),
        "asset_kind": _program_rule_safe_text(rule["asset_kind"]),
        "source_evidence_refs": _program_rule_safe_json(
            rule["source_evidence_refs"]
        ),
        "scope_status": _program_rule_safe_text(rule["scope_status"]),
        "automation": _program_rule_safe_text(rule["automation"]),
        "allowed_validation": _program_rule_safe_json(rule["allowed_validation"]),
        "prohibited": _program_rule_safe_json(rule["prohibited"]),
        "rate_limit": _program_rule_safe_json(rule["rate_limit"]),
    }


def _program_scope_rules_match(
    records: list[ProgramScopeRuleRecord],
    desired: list[dict],
    *,
    approval_digest: str,
) -> bool:
    if len(records) != len(desired):
        return False
    actual = [
        {
            "canonical_asset": record.canonical_asset,
            "asset_kind": record.asset_kind,
            "source_evidence_refs": record.source_evidence_refs,
            "scope_status": record.scope_status,
            "automation": record.automation,
            "allowed_validation": record.allowed_validation,
            "prohibited": record.prohibited,
            "rate_limit": record.rate_limit,
        }
        for record in sorted(records, key=lambda item: item.canonical_asset)
    ]
    return actual == desired and all(
        record.approval_digest == approval_digest for record in records
    )


def _is_local_tool_call_reservation(value: object) -> bool:
    return (
        isinstance(value, dict)
        and value.get(_LOCAL_TOOL_CALL_RESERVATION_MARKER) is True
        and value.get("tool_call_reserved") is True
        and value.get("tool_call_reservation_schema")
        == _LOCAL_TOOL_CALL_RESERVATION_SCHEMA
    )


def _is_legacy_local_tool_call_consumption(value: object) -> bool:
    return (
        isinstance(value, dict)
        and value.get("research_director_tool_run") is True
        and value.get("tool_call_consumed") is True
        and not isinstance(value.get("tool_call_reservation_agent_run_id"), str)
    )


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


def _studio_bounded_result_digest(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 71
        and value.startswith("sha256:")
        and _SHA256_PATTERN.fullmatch(value.removeprefix("sha256:")) is not None
    )


def _studio_bounded_result_projection(value: object) -> dict:
    if not isinstance(value, dict) or set(value) != {
        "aliases",
        "response_schema_fingerprint",
        "status_class",
        "timing_bucket",
        "difference_labels",
        "safe_counters",
    }:
        raise ValueError("bounded_result_projection_invalid")
    aliases = value.get("aliases")
    counters = value.get("safe_counters")
    differences = value.get("difference_labels")
    if (
        not isinstance(aliases, dict)
        or set(aliases) != {"account", "objects", "role", "runner", "workflow"}
        or not isinstance(aliases.get("objects"), list)
        or not aliases["objects"]
        or any(not _studio_bounded_result_alias(item) for item in aliases["objects"])
        or any(
            not _studio_bounded_result_alias(aliases.get(key))
            for key in ("account", "role", "runner", "workflow")
        )
        or not _studio_bounded_result_digest(value.get("response_schema_fingerprint"))
        or value.get("status_class") not in {"1xx", "2xx", "3xx", "4xx", "5xx"}
        or value.get("timing_bucket")
        not in {"under_100ms", "under_500ms", "under_2s", "over_2s"}
        or not isinstance(differences, list)
        or not differences
        or any(
            item not in {"response_schema_changed", "response_schema_unchanged"}
            for item in differences
        )
        or not isinstance(counters, dict)
        or set(counters)
        != {"difference_count", "object_alias_count", "parameter_count"}
        or any(
            not isinstance(item, int) or isinstance(item, bool) or item < 0
            for item in counters.values()
        )
        or counters["difference_count"] != len(differences)
        or counters["object_alias_count"] != len(aliases["objects"])
        or _safe_display_value(value) != value
    ):
        raise ValueError("bounded_result_projection_invalid")
    return deepcopy(value)


def _studio_bounded_result_alias(value: object) -> bool:
    return (
        isinstance(value, str)
        and 1 <= len(value) <= 64
        and value[0].isalpha()
        and all(character.isalnum() or character in {"_", "-"} for character in value)
        and not any(
            marker in value.lower()
            for marker in (
                "authorization",
                "cookie",
                "credential",
                "password",
                "secret",
                "token",
            )
        )
    )


def _studio_bounded_result_stage_id(
    pipeline_run_id: str,
    validation_run_id: str,
) -> str:
    identity = (
        f"{pipeline_run_id}|{validation_run_id}|studio_black_box_bounded_result"
    )
    digest = sha256(identity.encode("utf-8")).hexdigest()[:48]
    return f"pipeline_stage_bounded_{digest}"


def _trusted_bounded_result_claim(
    *,
    session: Session,
    pipeline_run: PipelineRunRecord,
    stage: PipelineStageRecord,
) -> TrustedBoundedResultClaim | None:
    if (
        stage.stage_key != "studio_black_box_bounded_result"
        or not isinstance(stage.input_refs, list)
        or len(stage.input_refs) != 2
        or not all(isinstance(ref, str) for ref in stage.input_refs)
        or not stage.input_refs[0].startswith("approval:")
        or not stage.input_refs[1].startswith("validation_run:")
    ):
        return None
    approval_id = stage.input_refs[0].removeprefix("approval:")
    validation_run_id = stage.input_refs[1].removeprefix("validation_run:")
    validation_run = session.get(ValidationRunRecord, validation_run_id)
    approval = session.get(ApprovalRecord, approval_id)
    if validation_run is None or approval is None:
        return None

    pipeline_payload = (
        pipeline_run.payload if isinstance(pipeline_run.payload, dict) else {}
    )
    validation_payload = (
        validation_run.payload if isinstance(validation_run.payload, dict) else {}
    )
    bounded_result = validation_payload.get("black_box_bounded_result")
    result_payload = (
        bounded_result.get("result_payload")
        if isinstance(bounded_result, dict)
        else None
    )
    stage_payload = stage.payload if isinstance(stage.payload, dict) else {}
    result_digest = stage_payload.get("result_digest")
    if not isinstance(result_payload, dict) or not _studio_bounded_result_digest(
        result_digest
    ):
        return None
    try:
        projection = _studio_bounded_result_projection(
            {
                key: stage_payload.get(key)
                for key in (
                    "aliases",
                    "response_schema_fingerprint",
                    "status_class",
                    "timing_bucket",
                    "difference_labels",
                    "safe_counters",
                )
            }
        )
    except ValueError:
        return None

    provenance_refs = (
        f"approval:{approval.id}",
        f"pipeline_run:{pipeline_run.id}",
        f"validation_run:{validation_run.id}",
    )
    pipeline_result = {
        "schema_version": "studio_black_box_bounded_result_v1",
        "approval_id": approval.id,
        "validation_run_id": validation_run.id,
        "result_digest": result_digest,
        **projection,
        "provenance_refs": list(provenance_refs),
        "human_review_required": True,
        "submission_blocked": True,
        "execution_allowed": False,
        "report_submission_allowed": False,
    }
    expected_result_payload = {
        "schema_version": "studio_black_box_bounded_result_v1",
        "request_digest": result_digest,
        **projection,
        "provenance_refs": list(provenance_refs),
        "human_review_required": True,
        "submission_blocked": True,
        "execution_allowed": False,
        "report_submission_allowed": False,
        "raw_payload_processed": False,
    }
    expected_stage_payload = {
        **pipeline_result,
        "pipeline_run_id": pipeline_run.id,
        "raw_payload_processed": False,
    }
    recorded_at = (
        bounded_result.get("recorded_at")
        if isinstance(bounded_result, dict)
        else None
    )
    recorded_datetime = _payload_datetime(recorded_at)
    if (
        pipeline_run.scope_status != "in_scope"
        or pipeline_payload.get("campaign_id") != validation_run.campaign_id
        or validation_run.approval_id != approval.id
        or validation_run.campaign_id != approval.campaign_id
        or validation_run.task_id != approval.task_id
        or validation_run.validation_mode != approval.validation_mode
        or validation_run.plan_digest != approval.plan_digest
        or validation_run.approval_required is not True
        or validation_run.safety_gate_state != "black_box_needs_evidence"
        or validation_payload.get("pipeline_run_id") != pipeline_run.id
        or approval.run_id != pipeline_run.id
        or approval.status != "approved"
        or approval.decided_at is None
        or validation_run.finished_at is None
        or recorded_datetime is None
        or stage.id
        != _studio_bounded_result_stage_id(pipeline_run.id, validation_run.id)
        or stage.pipeline_run_id != pipeline_run.id
        or stage.campaign_id != validation_run.campaign_id
        or stage.task_id != validation_run.task_id
        or result_payload != expected_result_payload
        or _studio_bounded_result_replay_state(
            validation_run=validation_run,
            pipeline_run=pipeline_run,
            stage=stage,
            result_payload=expected_result_payload,
            pipeline_result=pipeline_result,
            stage_payload=expected_stage_payload,
        )
        != "match"
        or not (
            _as_utc(pipeline_run.created_at)
            <= _as_utc(approval.created_at)
            <= _as_utc(approval.decided_at)
            <= recorded_datetime
            == _as_utc(validation_run.finished_at)
            <= _as_utc(stage.created_at)
        )
        or (
            approval.expires_at is not None
            and _as_utc(approval.expires_at) < recorded_datetime
        )
    ):
        return None

    return TrustedBoundedResultClaim(
        claim_id=f"claim_bounded_result_{result_digest.removeprefix('sha256:')}",
        text=(
            "Bounded local-lab result "
            f"({projection['status_class']}, {projection['timing_bucket']}) was recorded; "
            "human review remains required."
        ),
        provenance_refs=provenance_refs,
    )


def _studio_bounded_result_replay_state(
    *,
    validation_run: ValidationRunRecord,
    pipeline_run: PipelineRunRecord,
    stage: PipelineStageRecord | None,
    result_payload: dict,
    pipeline_result: dict,
    stage_payload: dict,
) -> str:
    validation_payload = (
        validation_run.payload if isinstance(validation_run.payload, dict) else {}
    )
    validation_result = validation_payload.get("black_box_bounded_result")
    pipeline_payload = (
        pipeline_run.payload if isinstance(pipeline_run.payload, dict) else {}
    )
    raw_results = pipeline_payload.get("studio_black_box_bounded_results", [])
    if not isinstance(raw_results, list):
        return "partial"
    matching_results = [
        item
        for item in raw_results
        if isinstance(item, dict)
        and item.get("validation_run_id") == validation_run.id
    ]
    present = [
        isinstance(validation_result, dict),
        bool(matching_results),
        stage is not None,
    ]
    if not any(present):
        return "fresh"
    if not all(present) or len(matching_results) != 1:
        return "partial"
    recorded_at = validation_result.get("recorded_at")
    expected_validation_result = {
        "audit_digest": result_payload["request_digest"],
        "decision_status": "observed",
        "evidence_refs": ["sanitized_cross_account_diff"],
        "execution_started": False,
        "result_payload": result_payload,
        "recorded_at": recorded_at,
    }
    if (
        not isinstance(recorded_at, str)
        or validation_result != expected_validation_result
        or matching_results[0] != pipeline_result
        or stage is None
        or stage.pipeline_run_id != pipeline_run.id
        or stage.campaign_id != validation_run.campaign_id
        or stage.task_id != validation_run.task_id
        or stage.stage_key != "studio_black_box_bounded_result"
        or stage.status != "needs_evidence"
        or stage.input_refs
        != [
            f"approval:{pipeline_result['approval_id']}",
            f"validation_run:{validation_run.id}",
        ]
        or stage.output_refs != ["sanitized_cross_account_diff"]
        or stage.safety_gate_state != "human_review_required"
        or stage.stop_reason is not None
        or stage.payload != stage_payload
        or validation_run.status != "needs_evidence"
        or validation_run.allowed_to_execute is not False
        or validation_run.evidence_ref_count != 1
    ):
        return "mismatch"
    return "match"


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
    field_pilot_feedback: dict | None,
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
    if field_pilot_feedback is not None:
        safe_values["field_pilot_feedback"] = _safe_display_value(field_pilot_feedback)
        original_values["field_pilot_feedback"] = field_pilot_feedback
    if safe_values != original_values:
        return None
    if field_pilot_feedback is not None:
        engagement_alias = field_pilot_feedback.get("engagement_alias")
        candidate_alias = field_pilot_feedback.get("candidate_alias")
        if (
            field_pilot_feedback.get("schema_version")
            != "black_box_field_pilot_v1"
            or not isinstance(engagement_alias, str)
            or not isinstance(candidate_alias, str)
        ):
            return None
        safe_values = {
            "identity_kind": "black_box_field_pilot_candidate_v1",
            "program_id": program_id,
            "engagement_alias": engagement_alias,
            "candidate_alias": candidate_alias,
        }
    encoded = json.dumps(safe_values, sort_keys=True, separators=(",", ":"))
    return sha256(encoded.encode("utf-8")).hexdigest()


def _is_secret_key(value: str) -> bool:
    normalized = value.lower().replace("-", "_")
    if normalized in TOKEN_USAGE_KEYS or normalized in {
        "authorization_digest",
        "authorization_id",
    }:
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
        "token=",
        "x-api-key:",
    )
    # Require word-boundary + alnum after "sk-" so OpenAI-style keys match
    # (sk-proj-..., sk-test...) without false-positives on path segments like
    # "task-authz" (contains the substring "sk-").
    return (
        any(marker in normalized for marker in secret_markers)
        or re.search(r"\bsk-[a-z0-9]", normalized) is not None
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


def _validated_policy_text_hash(value: str) -> str:
    normalized = value.lower()
    if len(normalized) != 64 or any(
        character not in "0123456789abcdef" for character in normalized
    ):
        raise ValueError("policy_text_hash_invalid")
    return normalized


def _path_is_within_authority(path: str, authority: str) -> bool:
    if not path.startswith("/") or not authority.startswith("/"):
        return False
    if authority == "/":
        return True
    prefix = authority.rstrip("/")
    return path == prefix or path.startswith(f"{prefix}/")


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


def _autonomous_research_wakeup_cycle_summary(
    *,
    status: str | None,
    stop_reason: str | None,
    processed_count: int | None,
    outcome_counts: dict[str, int] | None,
) -> dict[str, Any] | None:
    if status is None:
        return None
    if (
        status not in _AUTONOMOUS_RESEARCH_WAKEUP_FINAL_STATUSES
        or stop_reason not in {None, *_AUTONOMOUS_RESEARCH_WAKEUP_STOP_REASONS}
        or not isinstance(processed_count, int)
        or isinstance(processed_count, bool)
        or processed_count < 0
        or processed_count > AUTONOMOUS_RESEARCH_WAKEUP_PAGE_SIZE
        or not isinstance(outcome_counts, dict)
    ):
        return None
    normalized_counts: dict[str, int] = {}
    for outcome_status, count in outcome_counts.items():
        if (
            not isinstance(outcome_status, str)
            or _AUTONOMOUS_RESEARCH_WAKEUP_OUTCOME_STATUS_PATTERN.fullmatch(
                outcome_status
            )
            is None
            or not isinstance(count, int)
            or isinstance(count, bool)
            or count < 0
            or count > AUTONOMOUS_RESEARCH_WAKEUP_PAGE_SIZE
        ):
            return None
        normalized_counts[outcome_status] = count
    if sum(normalized_counts.values()) != processed_count:
        return None
    return {
        "status": status,
        "stop_reason": stop_reason,
        "processed_count": processed_count,
        "outcome_counts": dict(sorted(normalized_counts.items())),
    }
