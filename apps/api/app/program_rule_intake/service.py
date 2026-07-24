"""Stateful coordinator for safe public program-rule intake."""

from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from hashlib import sha256
import hmac
import json
import math
import re
import secrets
from typing import Any
from uuid import uuid4

from app.db_models import ProgramRuleSnapshotRecord, ProgramRuleSourceRecord
from app.program_rule_intake.contracts import (
    AIStatus,
    AssetKind,
    AutomationStatus,
    BrowserRuleDocumentEnvelope,
    CandidateRuleModification,
    CandidateScopeStatus,
    DeterministicExtractionResult,
    EffectiveScopeStatus,
    ExtractionReviewState,
    FetchFailureCode,
    FetchStatus,
    NormalizedRuleDocument,
    ProgramRuleClaimNextResult,
    ProgramRuleFetchClaim,
    ProgramRuleSnapshotDiff,
    ProgramRuleSnapshotProjection,
    ProgramRuleSourceProjection,
    ProgramScopeRuleProjection,
    SnapshotReviewStatus,
    StaticRuleDocumentEnvelope,
    canonicalize_public_https_url,
    is_same_origin,
)
from app.program_rule_intake.extractor import (
    AdvisoryRuleExtractor,
    extract_deterministic_rules,
    merge_advisory_rules,
    parse_advisory_rule_result,
)
from app.program_rule_intake.normalizer import (
    BrowserRenderRequiredError,
    DocumentNormalizationError,
    normalize_rule_document,
)
from app.repository import DatabaseRepository


MAX_DOCUMENTS = 8
MAX_NORMALIZED_CORPUS_BYTES = 2 * 1024 * 1024
MANUAL_REFRESH_COOLDOWN = timedelta(minutes=5)
SOURCE_STALE_AFTER = timedelta(hours=72)
REFRESH_INTERVAL = timedelta(days=1)
_CONTENT_TYPES_BY_KIND = {
    "html": {"text/html"},
    "text": {"text/plain"},
    "json": {"application/json"},
    "yaml": {"application/yaml", "application/x-yaml", "text/yaml"},
}
_SAFE_ALIAS = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z")


class ProgramRuleIntakeError(ValueError):
    """Base domain error with a non-sensitive stable category."""


class ProgramRuleValidationError(ProgramRuleIntakeError):
    pass


class ProgramRuleBrowserRenderRequired(ProgramRuleValidationError):
    pass


class ProgramRuleConflict(ProgramRuleIntakeError):
    pass


class ProgramRuleNotFound(ProgramRuleIntakeError):
    pass


class ProgramRuleClaimRejected(ProgramRuleConflict):
    pass


class ProgramRuleCooldown(ProgramRuleConflict):
    def __init__(self, retry_after_seconds: int):
        super().__init__("program-rule manual refresh is cooling down")
        self.retry_after_seconds = retry_after_seconds


class ProgramRuleIntakeService:
    def __init__(
        self,
        repository: DatabaseRepository,
        *,
        clock: Callable[[], datetime] | None = None,
        token_factory: Callable[[], str] | None = None,
        claim_id_factory: Callable[[], str] | None = None,
        advisory_extractor: AdvisoryRuleExtractor | None = None,
    ):
        self.repository = repository
        self._clock = clock or (lambda: datetime.now(UTC))
        self._token_factory = token_factory or (lambda: secrets.token_urlsafe(32))
        self._claim_id_factory = claim_id_factory or (
            lambda: f"claim_{uuid4().hex}"
        )
        self._advisory_extractor = advisory_extractor

    def register_source(
        self,
        *,
        program_alias: str,
        public_rule_url: str,
    ) -> ProgramRuleSourceProjection:
        try:
            canonical_url = canonicalize_public_https_url(public_rule_url)
        except ValueError:
            raise ProgramRuleValidationError("public program rule URL is invalid") from None
        if self.repository.get_program_rule_source_by_canonical_url(canonical_url) is not None:
            raise ProgramRuleConflict("program rule source already exists")
        try:
            record = self.repository.create_program_rule_source(
                program_alias=program_alias,
                registered_url=public_rule_url,
                now=self._now(),
            )
        except ValueError:
            raise ProgramRuleValidationError("program rule source is invalid") from None
        return self._source_projection(record)

    def list_sources(self) -> list[ProgramRuleSourceProjection]:
        return [
            self._source_projection(record)
            for record in self.repository.list_program_rule_sources()
        ]

    def get_source(self, source_id: str) -> ProgramRuleSourceProjection:
        record = self.repository.get_program_rule_source(source_id)
        if record is None:
            raise ProgramRuleNotFound("program rule source not found")
        return self._source_projection(record)

    def request_refresh(self, source_id: str) -> ProgramRuleSourceProjection:
        record = self.repository.get_program_rule_source(source_id)
        if record is None:
            raise ProgramRuleNotFound("program rule source not found")
        now = self._now()
        if record.last_manual_refresh_at is not None:
            elapsed = now - _as_utc(record.last_manual_refresh_at)
            if elapsed < MANUAL_REFRESH_COOLDOWN:
                remaining = MANUAL_REFRESH_COOLDOWN - max(elapsed, timedelta(0))
                raise ProgramRuleCooldown(max(1, math.ceil(remaining.total_seconds())))
        scheduled = self.repository.schedule_program_rule_source_refresh(
            source_id=source_id,
            now=now,
            manual=True,
        )
        if scheduled is None:
            raise ProgramRuleNotFound("program rule source not found")
        return self._source_projection(scheduled)

    def claim_next(self) -> ProgramRuleClaimNextResult:
        now = self._now()
        if not any(
            _source_is_due(record, now)
            for record in self.repository.list_program_rule_sources()
        ):
            return ProgramRuleClaimNextResult(
                claim=None,
                next_due_at=self._next_due_at(now),
            )
        token = self._token_factory()
        claim_id = self._claim_id_factory()
        if not isinstance(token, str) or not token:
            raise RuntimeError("program_rule_token_factory_invalid")
        claimed = self.repository.claim_next_due_program_rule_source(
            claim_id=claim_id,
            claim_token_digest=sha256(token.encode("utf-8")).hexdigest(),
            now=now,
        )
        if claimed is None:
            return ProgramRuleClaimNextResult(
                claim=None,
                next_due_at=self._next_due_at(now),
            )
        return ProgramRuleClaimNextResult(
            claim=ProgramRuleFetchClaim(
                claim_id=claim_id,
                source_id=claimed.id,
                claim_token=token,
                source_url=claimed.canonical_url,
                expires_at=claimed.claim_expires_at,
            ),
            next_due_at=None,
        )

    def normalize_claim_document(
        self,
        *,
        claim_id: str,
        source_id: str,
        claim_token: str,
        envelope: StaticRuleDocumentEnvelope | BrowserRuleDocumentEnvelope,
    ) -> NormalizedRuleDocument:
        source = self._validate_claim(
            claim_id=claim_id,
            source_id=source_id,
            claim_token=claim_token,
        )
        try:
            document_url = canonicalize_public_https_url(envelope.source_url)
        except ValueError:
            raise ProgramRuleValidationError("program rule document URL is invalid") from None
        if envelope.depth == 0:
            if document_url != source.canonical_url:
                raise ProgramRuleValidationError("root document does not match source")
        elif not is_same_origin(source.canonical_url, document_url):
            raise ProgramRuleValidationError("linked document is outside source origin")
        try:
            return normalize_rule_document(envelope)
        except BrowserRenderRequiredError:
            raise ProgramRuleBrowserRenderRequired(
                "browser_render_required"
            ) from None
        except (DocumentNormalizationError, ValueError):
            raise ProgramRuleValidationError("program rule document is invalid") from None

    async def complete_claim(
        self,
        *,
        claim_id: str,
        source_id: str,
        claim_token: str,
        documents: list[NormalizedRuleDocument],
    ) -> ProgramRuleSnapshotProjection:
        source = self._validate_claim(
            claim_id=claim_id,
            source_id=source_id,
            claim_token=claim_token,
        )
        corpus = _validate_corpus(source, documents)
        extraction = extract_deterministic_rules(corpus)
        extraction = await self._apply_advisory(corpus, extraction)
        normalized_digest = _corpus_digest(corpus)
        snapshot_id = _snapshot_id(source_id, normalized_digest)
        approved_snapshot = (
            self.repository.get_program_rule_snapshot(source.approved_snapshot_id)
            if source.approved_snapshot_id is not None
            else None
        )
        diff_values = _diff_values(
            _snapshot_extraction(approved_snapshot),
            extraction,
        )
        review_digest = _review_digest(
            source_id=source_id,
            snapshot_id=snapshot_id,
            normalized_digest=normalized_digest,
            approved_snapshot_id=source.approved_snapshot_id,
            diff_values=diff_values,
        )
        snapshot = self.repository.save_program_rule_snapshot(
            source_id=source_id,
            raw_aggregate_sha256=_raw_aggregate_digest(corpus),
            normalized_sha256=normalized_digest,
            fetched_at=self._now(),
            fetch_mode=(
                "browser" if any(item.raw_sha256 is None for item in corpus) else "static"
            ),
            content_types=sorted({item.content_type for item in corpus}),
            detected_language=(
                "en" if all(item.detected_language == "en" for item in corpus) else "unsupported"
            ),
            extraction=extraction.model_dump(mode="json"),
            evidence=[item.model_dump(mode="json") for item in extraction.evidence],
            linked_documents=[
                {
                    "url": item.source_url,
                    "depth": item.depth,
                    "kind": item.kind.value,
                    "content_type": item.content_type,
                    "raw_sha256": item.raw_sha256,
                    "normalized_sha256": item.normalized_sha256,
                }
                for item in corpus
                if item.depth == 1
            ],
            openapi_candidates=[
                item.model_dump(mode="json") for item in extraction.linked_artifacts
            ],
            ai_status=extraction.ai_status.value,
            review_status="pending",
            review_digest=review_digest,
        )
        latest_source = self.repository.get_program_rule_source(source_id)
        if latest_source is None:
            raise ProgramRuleNotFound("program rule source not found")
        if snapshot.id != latest_source.approved_snapshot_id:
            latest_source = self.repository.set_program_rule_source_snapshot_pointers(
                source_id=source_id,
                approved_snapshot_id=latest_source.approved_snapshot_id,
                pending_snapshot_id=snapshot.id,
                updated_at=self._now(),
            )
            if latest_source is None:
                raise ProgramRuleNotFound("program rule source not found")
            if latest_source.program_id is not None:
                self.repository.project_program_rule_program_summary(
                    program_id=latest_source.program_id,
                    scope_status="needs_review",
                    automation="needs_review",
                )
        finished = self.repository.finish_program_rule_source_claim(
            source_id=source_id,
            claim_id=claim_id,
            claim_token_digest=sha256(claim_token.encode("utf-8")).hexdigest(),
            now=self._now(),
            next_check_at=self._now() + REFRESH_INTERVAL,
            succeeded=True,
        )
        if finished is None:
            raise ProgramRuleClaimRejected("program rule claim is no longer active")
        return _snapshot_projection(snapshot)

    def fail_claim(
        self,
        *,
        claim_id: str,
        source_id: str,
        claim_token: str,
        failure_code: str,
    ) -> ProgramRuleSourceProjection:
        try:
            safe_failure_code = FetchFailureCode(failure_code)
        except ValueError:
            raise ProgramRuleValidationError("program rule failure code is invalid") from None
        self._validate_claim(
            claim_id=claim_id,
            source_id=source_id,
            claim_token=claim_token,
        )
        now = self._now()
        failed = self.repository.finish_program_rule_source_claim(
            source_id=source_id,
            claim_id=claim_id,
            claim_token_digest=sha256(claim_token.encode("utf-8")).hexdigest(),
            now=now,
            next_check_at=now + REFRESH_INTERVAL,
            succeeded=False,
            failure_code=safe_failure_code.value,
        )
        if failed is None:
            raise ProgramRuleClaimRejected("program rule claim is no longer active")
        return self._source_projection(failed)

    def list_snapshots(self, source_id: str) -> list[ProgramRuleSnapshotProjection]:
        source = self.repository.get_program_rule_source(source_id)
        if source is None:
            raise ProgramRuleNotFound("program rule source not found")
        return [
            _snapshot_projection(
                record,
                artifact_warning=self._artifact_warning(source, record),
            )
            for record in self.repository.list_program_rule_snapshots(source_id)
        ]

    def get_snapshot_diff(
        self,
        source_id: str,
        snapshot_id: str,
    ) -> ProgramRuleSnapshotDiff:
        source = self.repository.get_program_rule_source(source_id)
        snapshot = self.repository.get_program_rule_snapshot(snapshot_id)
        if source is None or snapshot is None or snapshot.source_id != source_id:
            raise ProgramRuleNotFound("program rule snapshot not found")
        approved_snapshot = _prior_approved_snapshot(
            self.repository.list_program_rule_snapshots(source_id),
            snapshot,
        )
        values = _diff_values(
            _snapshot_extraction(approved_snapshot),
            _snapshot_extraction(snapshot),
        )
        return ProgramRuleSnapshotDiff(
            source_id=source_id,
            approved_snapshot_id=(
                approved_snapshot.id if approved_snapshot is not None else None
            ),
            pending_snapshot_id=snapshot_id,
            review_digest=snapshot.review_digest,
            **values,
        )

    def review_snapshot(
        self,
        *,
        source_id: str,
        snapshot_id: str,
        decision: str,
        reviewer_alias: str,
        expected_review_digest: str,
        operator_confirmed: bool,
    ) -> ProgramRuleSnapshotProjection:
        if decision not in {"approved", "rejected"}:
            raise ProgramRuleValidationError("program rule review decision is invalid")
        if operator_confirmed is not True:
            raise ProgramRuleValidationError("program rule review confirmation is required")
        if (
            not isinstance(reviewer_alias, str)
            or _SAFE_ALIAS.fullmatch(reviewer_alias) is None
        ):
            raise ProgramRuleValidationError("program rule reviewer alias is invalid")
        source = self.repository.get_program_rule_source(source_id)
        snapshot = self.repository.get_program_rule_snapshot(snapshot_id)
        if source is None or snapshot is None or snapshot.source_id != source_id:
            raise ProgramRuleNotFound("program rule snapshot not found")
        if not hmac.compare_digest(snapshot.review_digest, expected_review_digest):
            raise ProgramRuleConflict("program rule review digest is stale")
        if snapshot.review_status != "pending":
            if (
                snapshot.review_status == decision
                and snapshot.reviewer_alias == reviewer_alias
            ):
                warning = None
                if decision == "approved":
                    warning = self._promote_openapi_candidates(
                        source=source,
                        snapshot=snapshot,
                        extraction=_snapshot_extraction(snapshot),
                    )
                return _snapshot_projection(snapshot, artifact_warning=warning)
            raise ProgramRuleConflict("program rule snapshot was already reviewed")
        if source.pending_snapshot_id != snapshot_id:
            raise ProgramRuleConflict("program rule snapshot is not pending")

        approved_snapshot = (
            self.repository.get_program_rule_snapshot(source.approved_snapshot_id)
            if source.approved_snapshot_id is not None
            else None
        )
        extraction = _snapshot_extraction(snapshot)
        diff_values = _diff_values(_snapshot_extraction(approved_snapshot), extraction)
        current_digest = _review_digest(
            source_id=source_id,
            snapshot_id=snapshot_id,
            normalized_digest=snapshot.normalized_sha256,
            approved_snapshot_id=source.approved_snapshot_id,
            diff_values=diff_values,
        )
        if not hmac.compare_digest(snapshot.review_digest, current_digest):
            raise ProgramRuleConflict("program rule review digest is stale")

        now = self._now()
        if decision == "approved":
            rules = _materializable_scope_rules(extraction)
            if source.program_id is None:
                raise ProgramRuleConflict("program rule source has no program")
            self.repository.replace_program_scope_rules(
                program_id=source.program_id,
                source_id=source_id,
                approved_snapshot_id=snapshot_id,
                approval_digest=snapshot.review_digest,
                effective_at=now,
                rules=rules,
            )
            reviewed = self.repository.update_program_rule_snapshot_review(
                source_id=source_id,
                snapshot_id=snapshot_id,
                review_status="approved",
                reviewer_alias=reviewer_alias,
                reviewed_at=now,
            )
            if reviewed is None:
                raise ProgramRuleNotFound("program rule snapshot not found")
            self.repository.set_program_rule_source_snapshot_pointers(
                source_id=source_id,
                approved_snapshot_id=snapshot_id,
                pending_snapshot_id=None,
                updated_at=now,
            )
            in_scope_rules = [
                rule for rule in rules if rule["scope_status"] == "in_scope"
            ]
            self.repository.project_program_rule_program_summary(
                program_id=source.program_id,
                scope_status="in_scope" if in_scope_rules else "needs_review",
                automation=(
                    _coarse_automation(in_scope_rules)
                    if in_scope_rules
                    else "needs_review"
                ),
            )
            artifact_warning = self._promote_openapi_candidates(
                source=source,
                snapshot=reviewed,
                extraction=extraction,
            )
        else:
            artifact_warning = None
            reviewed = self.repository.update_program_rule_snapshot_review(
                source_id=source_id,
                snapshot_id=snapshot_id,
                review_status="rejected",
                reviewer_alias=reviewer_alias,
                reviewed_at=now,
            )
            if reviewed is None:
                raise ProgramRuleNotFound("program rule snapshot not found")
            if source.program_id is not None:
                self.repository.project_program_rule_program_summary(
                    program_id=source.program_id,
                    scope_status="needs_review",
                    automation="needs_review",
                )
        return _snapshot_projection(reviewed, artifact_warning=artifact_warning)

    def list_scope_rules(self, program_id: str) -> list[ProgramScopeRuleProjection]:
        if self.repository.get_program(program_id) is None:
            raise ProgramRuleNotFound("program not found")
        source = next(
            (
                record
                for record in self.repository.list_program_rule_sources()
                if record.program_id == program_id
            ),
            None,
        )
        if source is None or source.approved_snapshot_id is None:
            return []
        effective_status, warning = self._effective_state(source)
        records = self.repository.list_program_scope_rules(
            program_id,
            approved_snapshot_id=source.approved_snapshot_id,
        )
        return [
            ProgramScopeRuleProjection(
                rule_id=record.id,
                program_id=record.program_id,
                source_id=record.source_id,
                approved_snapshot_id=record.approved_snapshot_id,
                canonical_asset=record.canonical_asset,
                asset_kind=AssetKind(record.asset_kind),
                source_evidence_refs=record.source_evidence_refs,
                scope_status=CandidateScopeStatus(record.scope_status),
                automation=AutomationStatus(record.automation),
                allowed_validation=record.allowed_validation,
                prohibited=record.prohibited,
                rate_limit=record.rate_limit,
                approval_digest=record.approval_digest,
                effective_at=record.effective_at,
                effective_scope_status=effective_status,
                warning=warning,
                execution_allowed=False,
                lease_grant_allowed=False,
                scope_change_allowed=False,
                review_bypass_allowed=False,
                report_submission_allowed=False,
            )
            for record in records
        ]

    def _promote_openapi_candidates(
        self,
        *,
        source: ProgramRuleSourceRecord,
        snapshot: ProgramRuleSnapshotRecord,
        extraction: DeterministicExtractionResult,
    ) -> str | None:
        if source.program_id is None:
            return None
        evidence_ids = {item.evidence_id for item in extraction.evidence}
        promotion_failed = False
        for candidate in extraction.linked_artifacts:
            if not set(candidate.evidence_ids).issubset(evidence_ids):
                continue
            try:
                self.repository.save_artifact(
                    program_id=source.program_id,
                    asset=candidate.url,
                    kind="openapi",
                    source_type="program_rule_link",
                    source_hash=candidate.normalized_sha256,
                    ingestion_status="approved",
                    provenance=_openapi_candidate_provenance(
                        source=source,
                        snapshot=snapshot,
                        evidence_refs=candidate.evidence_ids,
                    ),
                    payload_summary={
                        "url_sha256": candidate.url_sha256,
                        "normalized_sha256": candidate.normalized_sha256,
                    },
                    derived_facts=candidate.openapi_like,
                )
            except Exception:
                self._rollback_promotion_failure()
                promotion_failed = True
        if promotion_failed:
            return "openapi_promotion_pending"
        try:
            return self._artifact_warning(source, snapshot)
        except Exception:
            self._rollback_promotion_failure()
            return "openapi_promotion_pending"

    def _rollback_promotion_failure(self) -> None:
        try:
            self.repository.session.rollback()
        except Exception:
            pass

    def _artifact_warning(
        self,
        source: ProgramRuleSourceRecord,
        snapshot: ProgramRuleSnapshotRecord,
    ) -> str | None:
        if snapshot.review_status != "approved" or source.program_id is None:
            return None
        try:
            extraction = _snapshot_extraction(snapshot)
        except ProgramRuleConflict:
            return "openapi_promotion_pending"
        evidence_ids = {item.evidence_id for item in extraction.evidence}
        candidates = [
            candidate
            for candidate in extraction.linked_artifacts
            if set(candidate.evidence_ids).issubset(evidence_ids)
        ]
        if not candidates:
            return None
        artifacts = self.repository.list_artifacts(
            program_id=source.program_id,
            source_type="program_rule_link",
        )
        for candidate in candidates:
            expected_provenance = _openapi_candidate_provenance(
                source=source,
                snapshot=snapshot,
                evidence_refs=candidate.evidence_ids,
            )
            if not any(
                artifact.source_hash == candidate.normalized_sha256
                and _artifact_has_provenance(
                    artifact.provenance,
                    expected_provenance,
                )
                for artifact in artifacts
            ):
                return "openapi_promotion_pending"
        return None

    def _validate_claim(
        self,
        *,
        claim_id: str,
        source_id: str,
        claim_token: str,
    ) -> ProgramRuleSourceRecord:
        source = self.repository.get_program_rule_source(source_id)
        digest = sha256(claim_token.encode("utf-8")).hexdigest()
        if (
            source is None
            or source.fetch_status != "fetching"
            or source.claim_id != claim_id
            or source.claim_token_digest is None
            or source.claim_expires_at is None
            or _as_utc(source.claim_expires_at) <= self._now()
            or not hmac.compare_digest(source.claim_token_digest, digest)
        ):
            raise ProgramRuleClaimRejected("program rule claim is invalid")
        return source

    async def _apply_advisory(
        self,
        corpus: list[NormalizedRuleDocument],
        deterministic: DeterministicExtractionResult,
    ) -> DeterministicExtractionResult:
        if self._advisory_extractor is None:
            return deterministic
        normalized_corpus = "\n\n".join(item.visible_text for item in corpus)
        normalized_corpus = normalized_corpus.encode("utf-8")[: 64 * 1024].decode(
            "utf-8",
            errors="ignore",
        )
        prompt_sha256 = sha256(normalized_corpus.encode("utf-8")).hexdigest()
        try:
            raw = await self._advisory_extractor.extract(normalized_corpus)
        except Exception:
            return deterministic.model_copy(
                update={
                    "ai_status": AIStatus.UNAVAILABLE,
                    "ai_prompt_sha256": prompt_sha256,
                    "ai_error_category": "provider_unavailable",
                }
            )
        try:
            advisory = parse_advisory_rule_result(raw, corpus, deterministic)
            return merge_advisory_rules(deterministic, advisory).model_copy(
                update={
                    "ai_prompt_sha256": prompt_sha256,
                    "ai_error_category": None,
                }
            )
        except Exception:
            return deterministic.model_copy(
                update={
                    "ai_status": AIStatus.UNAVAILABLE,
                    "ai_prompt_sha256": prompt_sha256,
                    "ai_error_category": "invalid_output",
                }
            )

    def _source_projection(
        self,
        record: ProgramRuleSourceRecord,
    ) -> ProgramRuleSourceProjection:
        effective_status, warning = self._effective_state(record)
        return ProgramRuleSourceProjection(
            source_id=record.id,
            program_id=record.program_id,
            program_alias=record.program_alias,
            registered_url=record.registered_url,
            canonical_url=record.canonical_url,
            fetch_status=FetchStatus(record.fetch_status),
            effective_scope_status=effective_status,
            warning=warning,
            last_success_at=record.last_success_at,
            next_check_at=record.next_check_at,
            approved_snapshot_id=record.approved_snapshot_id,
            pending_snapshot_id=record.pending_snapshot_id,
        )

    def _effective_state(
        self,
        record: ProgramRuleSourceRecord,
    ) -> tuple[EffectiveScopeStatus, str | None]:
        warning = "last_refresh_failed" if record.fetch_status == "failed" else None
        if record.approved_snapshot_id is None:
            return EffectiveScopeStatus.NEEDS_REVIEW, warning
        if (
            record.pending_snapshot_id is not None
            and record.pending_snapshot_id != record.approved_snapshot_id
        ):
            return EffectiveScopeStatus.FROZEN, "policy_change_requires_review"
        if (
            record.last_success_at is None
            or self._now() - _as_utc(record.last_success_at) >= SOURCE_STALE_AFTER
        ):
            return EffectiveScopeStatus.FROZEN, "source_stale"
        if record.program_id is None or not any(
            rule.scope_status == "in_scope"
            for rule in self.repository.list_program_scope_rules(
                record.program_id,
                approved_snapshot_id=record.approved_snapshot_id,
            )
        ):
            return EffectiveScopeStatus.NEEDS_REVIEW, warning
        return EffectiveScopeStatus.ACTIVE, warning

    def _next_due_at(self, now: datetime) -> datetime | None:
        candidates = []
        for record in self.repository.list_program_rule_sources():
            if _claim_is_live(record, now):
                candidates.append(record.claim_expires_at)
            else:
                candidates.append(record.next_check_at)
        if not candidates:
            return None
        return min(candidates, key=_as_utc)

    def _now(self) -> datetime:
        return _as_utc(self._clock())


def _claim_is_live(record: ProgramRuleSourceRecord, now: datetime) -> bool:
    return (
        record.claim_id is not None
        and record.claim_token_digest is not None
        and record.claim_expires_at is not None
        and _as_utc(record.claim_expires_at) > now
    )


def _source_is_due(record: ProgramRuleSourceRecord, now: datetime) -> bool:
    return _as_utc(record.next_check_at) <= now and not _claim_is_live(record, now)


def _snapshot_extraction(
    snapshot: ProgramRuleSnapshotRecord | None,
) -> DeterministicExtractionResult:
    if snapshot is None:
        return DeterministicExtractionResult(
            rules=[],
            evidence=[],
            linked_artifacts=[],
            review_state=ExtractionReviewState.READY,
            review_issues=[],
            ai_status=AIStatus.NOT_REQUESTED,
        )
    try:
        return DeterministicExtractionResult.model_validate_json(
            json.dumps(snapshot.extraction, separators=(",", ":"))
        )
    except ValueError:
        raise ProgramRuleConflict("stored program rule snapshot is invalid") from None


def _diff_values(
    approved: DeterministicExtractionResult,
    pending: DeterministicExtractionResult,
) -> dict[str, Any]:
    approved_rules = {
        (rule.asset, rule.asset_kind.value): rule for rule in approved.rules
    }
    pending_rules = {
        (rule.asset, rule.asset_kind.value): rule for rule in pending.rules
    }
    added_identities = sorted(set(pending_rules) - set(approved_rules))
    removed_identities = sorted(set(approved_rules) - set(pending_rules))
    modified = []
    for identity in sorted(set(approved_rules) & set(pending_rules)):
        before = approved_rules[identity]
        after = pending_rules[identity]
        if before.model_dump(mode="json") != after.model_dump(mode="json"):
            modified.append(
                CandidateRuleModification(
                    asset=after.asset,
                    before=before,
                    after=after,
                )
            )

    approved_prohibitions = {
        value for rule in approved.rules for value in rule.prohibited
    }
    pending_prohibitions = {
        value for rule in pending.rules for value in rule.prohibited
    }
    approved_artifacts = {
        (item.url, item.normalized_sha256): item for item in approved.linked_artifacts
    }
    pending_artifacts = {
        (item.url, item.normalized_sha256): item for item in pending.linked_artifacts
    }
    return {
        "added_rules": [pending_rules[identity] for identity in added_identities],
        "removed_rules": [
            approved_rules[identity] for identity in removed_identities
        ],
        "modified_rules": modified,
        "added_prohibitions": sorted(
            pending_prohibitions - approved_prohibitions
        ),
        "removed_prohibitions": sorted(
            approved_prohibitions - pending_prohibitions
        ),
        "added_linked_artifacts": [
            pending_artifacts[identity]
            for identity in sorted(set(pending_artifacts) - set(approved_artifacts))
        ],
        "removed_linked_artifacts": [
            approved_artifacts[identity]
            for identity in sorted(set(approved_artifacts) - set(pending_artifacts))
        ],
    }


def _materializable_scope_rules(
    extraction: DeterministicExtractionResult,
) -> list[dict]:
    evidence_ids = {item.evidence_id for item in extraction.evidence}
    materialized = []
    for rule in extraction.rules:
        advisory_review_only = (
            bool(rule.review_issues)
            and set(rule.review_issues).issubset({"advisory_ai"})
        )
        if (
            (
                rule.review_state != ExtractionReviewState.READY
                and not advisory_review_only
            )
            or rule.scope_status == CandidateScopeStatus.NEEDS_REVIEW
        ):
            continue
        references = set(rule.scope_evidence_ids) | set(
            rule.automation_evidence_ids
        )
        prohibited_references = {
            reference
            for value in rule.prohibited
            for reference in rule.prohibited_evidence_ids.get(value, [])
        }
        if any(
            not rule.prohibited_evidence_ids.get(value)
            for value in rule.prohibited
        ):
            continue
        references.update(prohibited_references)
        if rule.rate_limit is not None:
            references.update(rule.rate_limit.evidence_ids)
        if (
            not rule.scope_evidence_ids
            or not references.issubset(evidence_ids)
        ):
            continue
        if rule.scope_status == CandidateScopeStatus.IN_SCOPE and (
            rule.automation == AutomationStatus.NEEDS_REVIEW
            or not rule.automation_evidence_ids
            or rule.rate_limit is None
            or not rule.rate_limit.evidence_ids
        ):
            continue
        materialized.append(
            {
                "canonical_asset": rule.asset,
                "asset_kind": rule.asset_kind.value,
                "source_evidence_refs": sorted(references),
                "scope_status": rule.scope_status.value,
                "automation": rule.automation.value,
                "allowed_validation": rule.allowed_validation,
                "prohibited": rule.prohibited,
                "rate_limit": (
                    rule.rate_limit.model_dump(mode="json")
                    if rule.rate_limit is not None
                    else None
                ),
            }
        )
    return materialized


def _coarse_automation(rules: list[dict]) -> str:
    values = {rule["automation"] for rule in rules}
    if "none" in values:
        return "none"
    if values == {"limited"}:
        return "limited"
    return "needs_review"


def _validate_corpus(
    source: ProgramRuleSourceRecord,
    documents: list[NormalizedRuleDocument],
) -> list[NormalizedRuleDocument]:
    if not 1 <= len(documents) <= MAX_DOCUMENTS:
        raise ProgramRuleValidationError("program rule corpus size is invalid")
    ordered = sorted(documents, key=lambda item: (item.depth, item.source_url))
    if len({item.source_url for item in ordered}) != len(ordered):
        raise ProgramRuleValidationError("program rule corpus contains duplicates")
    roots = [item for item in ordered if item.depth == 0]
    if len(roots) != 1 or roots[0].source_url != source.canonical_url:
        raise ProgramRuleValidationError("program rule corpus root is invalid")
    eligible = {item.url for item in roots[0].eligible_links}
    normalized_bytes = 0
    for document in ordered:
        if not is_same_origin(source.canonical_url, document.source_url):
            raise ProgramRuleValidationError("program rule corpus origin is invalid")
        if document.depth == 1 and document.source_url not in eligible:
            raise ProgramRuleValidationError("program rule linked document is not eligible")
        if not hmac.compare_digest(
            document.normalized_sha256,
            _normalized_document_digest(document),
        ):
            raise ProgramRuleValidationError("program rule document digest is invalid")
        if document.content_type not in _CONTENT_TYPES_BY_KIND[document.kind.value]:
            raise ProgramRuleValidationError(
                "program rule document content type is invalid"
            )
        if document.detected_language != _detect_language(document.visible_text):
            raise ProgramRuleValidationError(
                "program rule document language is invalid"
            )
        normalized_bytes += len(document.visible_text.encode("utf-8"))
        normalized_bytes += len(
            json.dumps(
                {
                    "tables": document.tables,
                    "list_items": document.list_items,
                    "eligible_links": [
                        item.model_dump(mode="json") for item in document.eligible_links
                    ],
                    "openapi_like": document.openapi_like,
                },
                ensure_ascii=False,
                separators=(",", ":"),
            ).encode("utf-8")
        )
    if normalized_bytes > MAX_NORMALIZED_CORPUS_BYTES:
        raise ProgramRuleValidationError("program rule corpus exceeds normalized limit")
    return ordered


def _normalized_document_digest(document: NormalizedRuleDocument) -> str:
    payload = {
        "kind": document.kind.value,
        "visible_text": document.visible_text,
        "tables": document.tables,
        "list_items": document.list_items,
        "eligible_links": [
            item.model_dump(mode="json") for item in document.eligible_links
        ],
        "openapi_like": document.openapi_like,
    }
    canonical = json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    return sha256(canonical.encode("utf-8")).hexdigest()


def _detect_language(text: str) -> str:
    letters = [character for character in text if character.isalpha()]
    if not letters:
        return "unsupported"
    ascii_letters = sum(character.isascii() for character in letters)
    return "en" if ascii_letters / len(letters) >= 0.9 else "unsupported"


def _prior_approved_snapshot(
    snapshots: list[ProgramRuleSnapshotRecord],
    target: ProgramRuleSnapshotRecord,
) -> ProgramRuleSnapshotRecord | None:
    target_fetched_at = _as_utc(target.fetched_at)
    target_reviewed_at = (
        _as_utc(target.reviewed_at) if target.reviewed_at is not None else None
    )
    candidates = [
        snapshot
        for snapshot in snapshots
        if snapshot.id != target.id
        and snapshot.review_status == "approved"
        and _as_utc(snapshot.fetched_at) <= target_fetched_at
        and (
            target_reviewed_at is None
            or snapshot.reviewed_at is not None
            and _as_utc(snapshot.reviewed_at) <= target_reviewed_at
        )
    ]
    if not candidates:
        return None
    return max(
        candidates,
        key=lambda snapshot: (
            _as_utc(snapshot.fetched_at),
            _as_utc(snapshot.reviewed_at)
            if snapshot.reviewed_at is not None
            else datetime.min.replace(tzinfo=UTC),
            snapshot.id,
        ),
    )


def _corpus_digest(documents: list[NormalizedRuleDocument]) -> str:
    canonical = json.dumps(
        [
            {
                "source_url": item.source_url,
                "depth": item.depth,
                "kind": item.kind.value,
                "normalized_sha256": item.normalized_sha256,
            }
            for item in documents
        ],
        sort_keys=True,
        separators=(",", ":"),
    )
    return sha256(canonical.encode("utf-8")).hexdigest()


def _raw_aggregate_digest(documents: list[NormalizedRuleDocument]) -> str:
    canonical = json.dumps(
        [
            {
                "source_url": item.source_url,
                "raw_sha256": item.raw_sha256,
            }
            for item in documents
        ],
        sort_keys=True,
        separators=(",", ":"),
    )
    return sha256(canonical.encode("utf-8")).hexdigest()


def _snapshot_id(source_id: str, normalized_digest: str) -> str:
    digest = sha256(f"{source_id}\0{normalized_digest}".encode("utf-8")).hexdigest()
    return f"program_rule_snapshot_{digest[:32]}"


def _review_digest(
    *,
    source_id: str,
    snapshot_id: str,
    normalized_digest: str,
    approved_snapshot_id: str | None,
    diff_values: dict[str, Any],
) -> str:
    canonical_diff = {
        key: [
            item.model_dump(mode="json") if hasattr(item, "model_dump") else item
            for item in value
        ]
        if isinstance(value, list)
        else value
        for key, value in diff_values.items()
    }
    canonical = json.dumps(
        {
            "source_id": source_id,
            "snapshot_id": snapshot_id,
            "normalized_sha256": normalized_digest,
            "approved_snapshot_id": approved_snapshot_id,
            "diff": canonical_diff,
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    return sha256(canonical.encode("utf-8")).hexdigest()


def _openapi_candidate_provenance(
    *,
    source: ProgramRuleSourceRecord,
    snapshot: ProgramRuleSnapshotRecord,
    evidence_refs: list[str],
) -> dict[str, Any]:
    return {
        "program_id": source.program_id,
        "source_id": source.id,
        "snapshot_id": snapshot.id,
        "approval_digest": snapshot.review_digest,
        "evidence_refs": evidence_refs,
        "authority": {
            "execution_allowed": False,
            "lease_grant_allowed": False,
            "scope_change_allowed": False,
            "review_bypass_allowed": False,
            "report_submission_allowed": False,
        },
    }


def _artifact_has_provenance(
    provenance: dict[str, Any],
    expected: dict[str, Any],
) -> bool:
    entries = [provenance]
    duplicate_imports = provenance.get("duplicate_imports", [])
    if isinstance(duplicate_imports, list):
        entries.extend(item for item in duplicate_imports if isinstance(item, dict))
    return any(
        all(entry.get(key) == value for key, value in expected.items())
        for entry in entries
    )


def _snapshot_projection(
    record: ProgramRuleSnapshotRecord,
    *,
    artifact_warning: str | None = None,
) -> ProgramRuleSnapshotProjection:
    return ProgramRuleSnapshotProjection(
        snapshot_id=record.id,
        source_id=record.source_id,
        raw_aggregate_sha256=record.raw_aggregate_sha256,
        normalized_sha256=record.normalized_sha256,
        fetched_at=record.fetched_at,
        fetch_mode=record.fetch_mode,
        content_types=record.content_types,
        detected_language=record.detected_language,
        extraction=record.extraction,
        evidence=record.evidence,
        linked_documents=record.linked_documents,
        openapi_candidates=record.openapi_candidates,
        ai_status=AIStatus(record.ai_status),
        review_status=SnapshotReviewStatus(record.review_status),
        reviewer_alias=record.reviewer_alias,
        reviewed_at=record.reviewed_at,
        review_digest=record.review_digest,
        artifact_warning=artifact_warning,
        execution_allowed=False,
        lease_grant_allowed=False,
        scope_change_allowed=False,
        review_bypass_allowed=False,
        report_submission_allowed=False,
    )


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


__all__ = [
    "ProgramRuleBrowserRenderRequired",
    "ProgramRuleClaimRejected",
    "ProgramRuleConflict",
    "ProgramRuleCooldown",
    "ProgramRuleIntakeError",
    "ProgramRuleIntakeService",
    "ProgramRuleNotFound",
    "ProgramRuleValidationError",
]
