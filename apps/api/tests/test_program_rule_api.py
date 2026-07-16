import asyncio
import base64
from datetime import UTC, datetime, timedelta
from hashlib import sha256
import json
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.db import Base, get_session
from app.db_models import ProgramRuleSnapshotRecord
from app.program_rule_intake.contracts import StaticRuleDocumentEnvelope
from app.program_rule_intake.service import (
    ProgramRuleClaimRejected,
    ProgramRuleConflict,
    ProgramRuleCooldown,
    ProgramRuleIntakeService,
    ProgramRuleValidationError,
)
from app.repository import DatabaseRepository
from app.main import app
from app.llm.base import LLMMode, LLMResponse, ProviderName
from app.program_rule_intake.advisory import (
    ProgramRuleAdvisoryUnavailable,
    RegistryProgramRuleAdvisoryExtractor,
    build_configured_program_rule_advisory,
)


FIXTURE_ROOT = Path(__file__).parent / "fixtures" / "program_rule_intake"


class MutableClock:
    def __init__(self, value):
        self.value = value

    def __call__(self):
        return self.value


class ValueFactory:
    def __init__(self, *values):
        self.values = iter(values)

    def __call__(self):
        return next(self.values)


class FakeAdvisoryExtractor:
    def __init__(self, response="", *, error=None):
        self.response = response
        self.error = error
        self.inputs = []

    async def extract(self, normalized_corpus):
        self.inputs.append(normalized_corpus)
        if self.error is not None:
            raise self.error
        return self.response


def build_service(
    *,
    now=None,
    tokens=("claim-token-1",),
    claim_ids=("claim_1",),
    advisory_extractor=None,
):
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    session = sessionmaker(bind=engine, expire_on_commit=False)()
    clock = MutableClock(now or datetime(2026, 7, 16, 8, 0, tzinfo=UTC))
    repository = DatabaseRepository(session)
    service = ProgramRuleIntakeService(
        repository,
        clock=clock,
        token_factory=ValueFactory(*tokens),
        claim_id_factory=ValueFactory(*claim_ids),
        advisory_extractor=advisory_extractor,
    )
    return service, repository, session, engine, clock


def fixture_envelope(name, content_type, *, source_url, depth):
    raw = (FIXTURE_ROOT / name).read_bytes()
    return StaticRuleDocumentEnvelope(
        source_url=source_url,
        depth=depth,
        content_type=content_type,
        mode="static",
        body_base64=base64.b64encode(raw).decode("ascii"),
        raw_sha256=sha256(raw).hexdigest(),
        charset="utf-8",
    )


@pytest.fixture
def program_rule_client():
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    testing_session = sessionmaker(bind=engine, expire_on_commit=False)

    def override_get_session():
        with testing_session() as session:
            yield session

    app.dependency_overrides[get_session] = override_get_session
    try:
        with TestClient(app) as client:
            yield client, testing_session
    finally:
        app.dependency_overrides.pop(get_session, None)
        engine.dispose()


def test_service_registration_refresh_and_claim_protocol_are_fail_closed():
    service, repository, session, engine, clock = build_service()
    try:
        source = service.register_source(
            program_alias="example_program",
            public_rule_url="https://EXAMPLE.com:443/rules",
        )

        assert source.canonical_url == "https://example.com/rules"
        assert source.fetch_status == "scheduled"
        assert source.effective_scope_status == "needs_review"
        assert source.program_id is not None
        assert repository.get_program(source.program_id).scope_status == "needs_review"
        with pytest.raises(ProgramRuleConflict):
            service.register_source(
                program_alias="duplicate_program",
                public_rule_url="https://example.com/rules",
            )
        with pytest.raises(ProgramRuleValidationError):
            service.register_source(
                program_alias="bad_program",
                public_rule_url="http://example.com/rules",
            )

        refreshed = service.request_refresh(source.source_id)
        assert refreshed.next_check_at == clock.value.replace(tzinfo=None)
        with pytest.raises(ProgramRuleCooldown) as cooldown:
            service.request_refresh(source.source_id)
        assert cooldown.value.retry_after_seconds == 300

        claim_result = service.claim_next()
        assert claim_result.claim is not None
        claim = claim_result.claim
        assert claim.source_id == source.source_id
        assert claim.claim_id == "claim_1"
        assert claim.claim_token == "claim-token-1"
        assert claim.source_url == "https://example.com/rules"
        assert claim.expires_at == (clock.value + timedelta(minutes=15)).replace(
            tzinfo=None
        )
        assert claim.limits.max_documents == 8
        assert claim.limits.max_document_bytes == 2 * 1024 * 1024
        assert claim.limits.max_total_bytes == 8 * 1024 * 1024
        assert claim.limits.max_depth == 1

        stored = repository.get_program_rule_source(source.source_id)
        assert stored.claim_token_digest == sha256(b"claim-token-1").hexdigest()
        assert "claim-token-1" not in "|".join(
            str(getattr(stored, column.name))
            for column in stored.__table__.columns
        )
        operator_payload = json.dumps(
            [item.model_dump(mode="json") for item in service.list_sources()]
        )
        assert "claim-token-1" not in operator_payload
        assert "claim_token" not in operator_payload

        unavailable = service.claim_next()
        assert unavailable.claim is None
        assert unavailable.next_due_at == claim.expires_at
    finally:
        session.close()
        engine.dispose()


def test_service_normalize_requires_live_claim_and_never_persists_raw_input():
    service, repository, session, engine, clock = build_service()
    try:
        source = service.register_source(
            program_alias="normalize_program",
            public_rule_url="https://example.com/rules",
        )
        claim = service.claim_next().claim
        envelope = fixture_envelope(
            "policy.html",
            "text/html; charset=utf-8",
            source_url=source.canonical_url,
            depth=0,
        )

        with pytest.raises(ProgramRuleClaimRejected):
            service.normalize_claim_document(
                claim_id=claim.claim_id,
                source_id=source.source_id,
                claim_token="wrong-token",
                envelope=envelope,
            )
        cross_origin = envelope.model_copy(
            update={"source_url": "https://other.example/rules"}
        )
        with pytest.raises(ProgramRuleValidationError):
            service.normalize_claim_document(
                claim_id=claim.claim_id,
                source_id=source.source_id,
                claim_token=claim.claim_token,
                envelope=cross_origin,
            )

        document = service.normalize_claim_document(
            claim_id=claim.claim_id,
            source_id=source.source_id,
            claim_token=claim.claim_token,
            envelope=envelope,
        )
        serialized = document.model_dump_json()
        assert document.source_url == source.canonical_url
        assert "RAW_HTML_SENTINEL" not in serialized
        assert "top-secret-token" not in serialized
        assert "secret-cookie" not in serialized
        assert "security@example.com" not in serialized
        assert session.scalar(select(ProgramRuleSnapshotRecord)) is None

        clock.value += timedelta(minutes=15)
        with pytest.raises(ProgramRuleClaimRejected):
            service.normalize_claim_document(
                claim_id=claim.claim_id,
                source_id=source.source_id,
                claim_token=claim.claim_token,
                envelope=envelope,
            )
    finally:
        session.close()
        engine.dispose()


def test_service_complete_creates_one_content_addressed_pending_snapshot():
    service, repository, session, engine, clock = build_service(
        tokens=("claim-token-1", "claim-token-2"),
        claim_ids=("claim_1", "claim_2"),
    )
    try:
        source = service.register_source(
            program_alias="complete_program",
            public_rule_url="https://example.com/rules",
        )
        claim = service.claim_next().claim
        policy_envelope = fixture_envelope(
            "policy.html",
            "text/html; charset=utf-8",
            source_url=source.canonical_url,
            depth=0,
        )
        openapi_envelope = fixture_envelope(
            "openapi.yaml",
            "application/yaml",
            source_url="https://example.com/openapi.yaml",
            depth=1,
        )
        documents = [
            service.normalize_claim_document(
                claim_id=claim.claim_id,
                source_id=source.source_id,
                claim_token=claim.claim_token,
                envelope=policy_envelope,
            ),
            service.normalize_claim_document(
                claim_id=claim.claim_id,
                source_id=source.source_id,
                claim_token=claim.claim_token,
                envelope=openapi_envelope,
            ),
        ]

        snapshot = asyncio.run(
            service.complete_claim(
                claim_id=claim.claim_id,
                source_id=source.source_id,
                claim_token=claim.claim_token,
                documents=documents,
            )
        )

        assert snapshot.review_status == "pending"
        assert snapshot.execution_allowed is False
        assert snapshot.lease_grant_allowed is False
        assert snapshot.scope_change_allowed is False
        assert snapshot.review_bypass_allowed is False
        assert snapshot.report_submission_allowed is False
        stored_source = repository.get_program_rule_source(source.source_id)
        assert stored_source.fetch_status == "ok"
        assert stored_source.pending_snapshot_id == snapshot.snapshot_id
        assert stored_source.approved_snapshot_id is None
        assert stored_source.claim_id is None
        assert stored_source.next_check_at == (
            clock.value + timedelta(days=1)
        ).replace(tzinfo=None)
        assert len(repository.list_program_rule_snapshots(source.source_id)) == 1

        persisted = json.dumps(
            snapshot.model_dump(mode="json"),
            sort_keys=True,
        )
        for forbidden in (
            "RAW_HTML_SENTINEL",
            "top-secret-token",
            "secret-cookie",
            "security@example.com",
            "This raw description must not enter",
            "bearerAuth",
        ):
            assert forbidden not in persisted

        clock.value += timedelta(days=1)
        repeated_claim = service.claim_next().claim
        repeated_documents = [
            service.normalize_claim_document(
                claim_id=repeated_claim.claim_id,
                source_id=source.source_id,
                claim_token=repeated_claim.claim_token,
                envelope=policy_envelope,
            ),
            service.normalize_claim_document(
                claim_id=repeated_claim.claim_id,
                source_id=source.source_id,
                claim_token=repeated_claim.claim_token,
                envelope=openapi_envelope,
            ),
        ]
        repeated = asyncio.run(
            service.complete_claim(
                claim_id=repeated_claim.claim_id,
                source_id=source.source_id,
                claim_token=repeated_claim.claim_token,
                documents=repeated_documents,
            )
        )
        assert repeated.snapshot_id == snapshot.snapshot_id
        assert repeated.review_status == "pending"
        assert len(repository.list_program_rule_snapshots(source.source_id)) == 1
    finally:
        session.close()
        engine.dispose()


@pytest.mark.parametrize(
    "metadata_update",
    [
        {"detected_language": "en"},
        {"content_type": "application/json"},
    ],
)
def test_service_complete_rejects_tampered_normalized_metadata(metadata_update):
    service, repository, session, engine, clock = build_service()
    try:
        source = service.register_source(
            program_alias="tampered_metadata_program",
            public_rule_url="https://example.com/rules",
        )
        claim = service.claim_next().claim
        document = service.normalize_claim_document(
            claim_id=claim.claim_id,
            source_id=source.source_id,
            claim_token=claim.claim_token,
            envelope=fixture_envelope(
                "non_english.txt",
                "text/plain",
                source_url=source.canonical_url,
                depth=0,
            ),
        )
        assert document.detected_language == "unsupported"

        with pytest.raises(ProgramRuleValidationError):
            asyncio.run(
                service.complete_claim(
                    claim_id=claim.claim_id,
                    source_id=source.source_id,
                    claim_token=claim.claim_token,
                    documents=[document.model_copy(update=metadata_update)],
                )
            )

        assert repository.list_program_rule_snapshots(source.source_id) == []
        assert repository.get_program_rule_source(source.source_id).claim_id == (
            claim.claim_id
        )
    finally:
        session.close()
        engine.dispose()


def test_service_fail_rejects_unknown_reason_and_consumes_only_valid_claim():
    service, repository, session, engine, clock = build_service()
    try:
        source = service.register_source(
            program_alias="failure_program",
            public_rule_url="https://failure.example/rules",
        )
        claim = service.claim_next().claim

        with pytest.raises(ProgramRuleValidationError):
            service.fail_claim(
                claim_id=claim.claim_id,
                source_id=source.source_id,
                claim_token=claim.claim_token,
                failure_code="arbitrary_failure",
            )
        assert repository.get_program_rule_source(source.source_id).claim_id == claim.claim_id
        with pytest.raises(ProgramRuleClaimRejected):
            service.fail_claim(
                claim_id=claim.claim_id,
                source_id=source.source_id,
                claim_token="wrong-token",
                failure_code="fetch_failed",
            )

        failed = service.fail_claim(
            claim_id=claim.claim_id,
            source_id=source.source_id,
            claim_token=claim.claim_token,
            failure_code="fetch_failed",
        )
        assert failed.fetch_status == "failed"
        assert failed.warning == "last_refresh_failed"
        stored = repository.get_program_rule_source(source.source_id)
        assert stored.failure_count == 1
        assert stored.failure_code == "fetch_failed"
        assert stored.claim_id is None
        assert stored.next_check_at == (clock.value + timedelta(days=1)).replace(
            tzinfo=None
        )
    finally:
        session.close()
        engine.dispose()


def test_service_diff_review_materializes_only_evidence_backed_rules_and_artifacts():
    service, repository, session, engine, clock = build_service(
        tokens=("claim-token-1", "claim-token-2", "claim-token-3"),
        claim_ids=("claim_1", "claim_2", "claim_3"),
    )
    try:
        source = service.register_source(
            program_alias="review_program",
            public_rule_url="https://example.com/rules",
        )
        claim = service.claim_next().claim
        policy = service.normalize_claim_document(
            claim_id=claim.claim_id,
            source_id=source.source_id,
            claim_token=claim.claim_token,
            envelope=fixture_envelope(
                "policy.html",
                "text/html; charset=utf-8",
                source_url=source.canonical_url,
                depth=0,
            ),
        )
        openapi = service.normalize_claim_document(
            claim_id=claim.claim_id,
            source_id=source.source_id,
            claim_token=claim.claim_token,
            envelope=fixture_envelope(
                "openapi.yaml",
                "application/yaml",
                source_url="https://example.com/openapi.yaml",
                depth=1,
            ),
        )
        pending = asyncio.run(
            service.complete_claim(
                claim_id=claim.claim_id,
                source_id=source.source_id,
                claim_token=claim.claim_token,
                documents=[policy, openapi],
            )
        )

        diff = service.get_snapshot_diff(source.source_id, pending.snapshot_id)
        assert diff.approved_snapshot_id is None
        assert diff.pending_snapshot_id == pending.snapshot_id
        assert [rule.asset for rule in diff.added_rules] == ["api.example.com"]
        assert diff.removed_rules == []
        assert diff.modified_rules == []
        assert diff.added_prohibitions == ["DoS"]
        assert diff.review_digest == pending.review_digest
        assert diff.execution_allowed is False
        with pytest.raises(ProgramRuleConflict):
            service.review_snapshot(
                source_id=source.source_id,
                snapshot_id=pending.snapshot_id,
                decision="approved",
                reviewer_alias="reviewer_1",
                expected_review_digest="0" * 64,
                operator_confirmed=True,
            )
        with pytest.raises(ProgramRuleValidationError):
            service.review_snapshot(
                source_id=source.source_id,
                snapshot_id=pending.snapshot_id,
                decision="approved",
                reviewer_alias="invalid reviewer alias",
                expected_review_digest=pending.review_digest,
                operator_confirmed=True,
            )
        assert repository.list_program_scope_rules(source.program_id) == []
        assert repository.list_artifacts(
            program_id=source.program_id,
            source_type="program_rule_url",
        ) == []

        approved = service.review_snapshot(
            source_id=source.source_id,
            snapshot_id=pending.snapshot_id,
            decision="approved",
            reviewer_alias="reviewer_1",
            expected_review_digest=pending.review_digest,
            operator_confirmed=True,
        )
        assert approved.review_status == "approved"
        current_source = service.get_source(source.source_id)
        assert current_source.approved_snapshot_id == pending.snapshot_id
        assert current_source.pending_snapshot_id is None
        assert current_source.effective_scope_status == "active"
        program = repository.get_program(source.program_id)
        assert program.scope_status == "in_scope"

        rules = service.list_scope_rules(source.program_id)
        assert len(rules) == 1
        assert rules[0].canonical_asset == "api.example.com"
        assert rules[0].scope_status == "in_scope"
        assert rules[0].rate_limit["requests"] == 5
        assert rules[0].source_evidence_refs
        assert rules[0].execution_allowed is False
        assert rules[0].lease_grant_allowed is False
        assert rules[0].scope_change_allowed is False
        assert rules[0].review_bypass_allowed is False
        assert rules[0].report_submission_allowed is False
        artifacts = repository.list_artifacts(
            program_id=source.program_id,
            source_type="program_rule_url",
        )
        assert len(artifacts) == 1
        assert artifacts[0].derived_facts == {
            "paths": {
                "/v1/teams/{team_id}/invite": {"post": {}},
                "/v1/users/{user_id}": {"get": {}},
            }
        }

        identical = service.review_snapshot(
            source_id=source.source_id,
            snapshot_id=pending.snapshot_id,
            decision="approved",
            reviewer_alias="reviewer_1",
            expected_review_digest=pending.review_digest,
            operator_confirmed=True,
        )
        assert identical.reviewed_at == approved.reviewed_at
        with pytest.raises(ProgramRuleConflict):
            service.review_snapshot(
                source_id=source.source_id,
                snapshot_id=pending.snapshot_id,
                decision="rejected",
                reviewer_alias="reviewer_1",
                expected_review_digest=pending.review_digest,
                operator_confirmed=True,
            )

        clock.value += timedelta(days=1)
        changed_claim = service.claim_next().claim
        changed_raw = (
            b"In scope: api.example.com\n"
            b"Automation is limited to 3 requests per minute.\n"
            b"Denial of service is prohibited."
        )
        changed_document = service.normalize_claim_document(
            claim_id=changed_claim.claim_id,
            source_id=source.source_id,
            claim_token=changed_claim.claim_token,
            envelope=StaticRuleDocumentEnvelope(
                source_url=source.canonical_url,
                depth=0,
                content_type="text/plain",
                mode="static",
                body_base64=base64.b64encode(changed_raw).decode("ascii"),
                raw_sha256=sha256(changed_raw).hexdigest(),
                charset="utf-8",
            ),
        )
        replacement = asyncio.run(
            service.complete_claim(
                claim_id=changed_claim.claim_id,
                source_id=source.source_id,
                claim_token=changed_claim.claim_token,
                documents=[changed_document],
            )
        )
        assert replacement.snapshot_id != approved.snapshot_id
        assert service.get_source(source.source_id).effective_scope_status == "frozen"
        changed_diff = service.get_snapshot_diff(source.source_id, replacement.snapshot_id)
        assert len(changed_diff.modified_rules) == 1
        assert changed_diff.modified_rules[0].before.rate_limit.requests == 5
        assert changed_diff.modified_rules[0].after.rate_limit.requests == 3

        rejected = service.review_snapshot(
            source_id=source.source_id,
            snapshot_id=replacement.snapshot_id,
            decision="rejected",
            reviewer_alias="reviewer_1",
            expected_review_digest=replacement.review_digest,
            operator_confirmed=True,
        )
        assert rejected.review_status == "rejected"
        rejected_source = service.get_source(source.source_id)
        assert rejected_source.pending_snapshot_id == replacement.snapshot_id
        assert rejected_source.approved_snapshot_id == approved.snapshot_id
        assert rejected_source.effective_scope_status == "frozen"
        assert service.list_scope_rules(source.program_id)[0].rate_limit["requests"] == 5

        clock.value += timedelta(days=1)
        final_claim = service.claim_next().claim
        final_raw = (
            b"In scope: api.example.com\n"
            b"Automation is limited to 2 requests per minute.\n"
            b"Denial of service is prohibited."
        )
        final_document = service.normalize_claim_document(
            claim_id=final_claim.claim_id,
            source_id=source.source_id,
            claim_token=final_claim.claim_token,
            envelope=StaticRuleDocumentEnvelope(
                source_url=source.canonical_url,
                depth=0,
                content_type="text/plain",
                mode="static",
                body_base64=base64.b64encode(final_raw).decode("ascii"),
                raw_sha256=sha256(final_raw).hexdigest(),
                charset="utf-8",
            ),
        )
        final_pending = asyncio.run(
            service.complete_claim(
                claim_id=final_claim.claim_id,
                source_id=source.source_id,
                claim_token=final_claim.claim_token,
                documents=[final_document],
            )
        )
        final_approved = service.review_snapshot(
            source_id=source.source_id,
            snapshot_id=final_pending.snapshot_id,
            decision="approved",
            reviewer_alias="reviewer_1",
            expected_review_digest=final_pending.review_digest,
            operator_confirmed=True,
        )
        historical_diff = service.get_snapshot_diff(
            source.source_id,
            final_approved.snapshot_id,
        )
        assert historical_diff.approved_snapshot_id == approved.snapshot_id
        assert len(historical_diff.modified_rules) == 1
        assert historical_diff.modified_rules[0].before.rate_limit.requests == 5
        assert historical_diff.modified_rules[0].after.rate_limit.requests == 2
    finally:
        session.close()
        engine.dispose()


def test_recent_failure_warns_but_seventy_two_hour_staleness_freezes_approval():
    service, repository, session, engine, clock = build_service(
        tokens=("claim-token-1", "claim-token-2"),
        claim_ids=("claim_1", "claim_2"),
    )
    try:
        source = service.register_source(
            program_alias="stale_program",
            public_rule_url="https://example.com/rules",
        )
        claim = service.claim_next().claim
        document = service.normalize_claim_document(
            claim_id=claim.claim_id,
            source_id=source.source_id,
            claim_token=claim.claim_token,
            envelope=fixture_envelope(
                "policy.html",
                "text/html; charset=utf-8",
                source_url=source.canonical_url,
                depth=0,
            ),
        )
        pending = asyncio.run(
            service.complete_claim(
                claim_id=claim.claim_id,
                source_id=source.source_id,
                claim_token=claim.claim_token,
                documents=[document],
            )
        )
        service.review_snapshot(
            source_id=source.source_id,
            snapshot_id=pending.snapshot_id,
            decision="approved",
            reviewer_alias="reviewer_1",
            expected_review_digest=pending.review_digest,
            operator_confirmed=True,
        )

        clock.value += timedelta(days=1)
        failure_claim = service.claim_next().claim
        failed = service.fail_claim(
            claim_id=failure_claim.claim_id,
            source_id=source.source_id,
            claim_token=failure_claim.claim_token,
            failure_code="fetch_failed",
        )
        assert failed.effective_scope_status == "active"
        assert failed.warning == "last_refresh_failed"

        clock.value += timedelta(hours=48)
        stale = service.get_source(source.source_id)
        assert stale.effective_scope_status == "frozen"
        assert stale.warning == "source_stale"
    finally:
        session.close()
        engine.dispose()


@pytest.mark.parametrize("advisory_case", ["valid", "invalid", "provider_failure"])
def test_advisory_ai_is_bounded_optional_and_cannot_block_deterministic_output(
    advisory_case,
):
    advisory = FakeAdvisoryExtractor(
        "not-json provider prose",
        error=(
            RuntimeError("provider-secret-must-not-persist")
            if advisory_case == "provider_failure"
            else None
        ),
    )
    service, repository, session, engine, clock = build_service(
        advisory_extractor=advisory,
    )
    try:
        source = service.register_source(
            program_alias="advisory_program",
            public_rule_url="https://example.com/rules",
        )
        claim = service.claim_next().claim
        document = service.normalize_claim_document(
            claim_id=claim.claim_id,
            source_id=source.source_id,
            claim_token=claim.claim_token,
            envelope=fixture_envelope(
                "policy.html",
                "text/html; charset=utf-8",
                source_url=source.canonical_url,
                depth=0,
            ),
        )
        if advisory_case == "valid":
            advisory.response = json.dumps(
                {
                    "rules": [
                        {
                            "asset": "api.example.com",
                            "asset_kind": "exact_host",
                            "scope_status": "in_scope",
                            "automation": "limited",
                            "prohibited": ["DoS"],
                            "rate_limit": {
                                "requests": 5,
                                "period": 1,
                                "unit": "minute",
                            },
                            "evidence": [
                                {
                                    "document_sha256": document.normalized_sha256,
                                    "locator": "table:0:1",
                                    "excerpt": "In scope | api.example.com",
                                },
                                {
                                    "document_sha256": document.normalized_sha256,
                                    "locator": "list:1",
                                    "excerpt": (
                                        "Automation is limited to 5 requests per minute."
                                    ),
                                },
                                {
                                    "document_sha256": document.normalized_sha256,
                                    "locator": "list:0",
                                    "excerpt": "Denial of service is prohibited.",
                                },
                            ],
                        }
                    ]
                }
            )
        snapshot = asyncio.run(
            service.complete_claim(
                claim_id=claim.claim_id,
                source_id=source.source_id,
                claim_token=claim.claim_token,
                documents=[document],
            )
        )

        assert len(snapshot.extraction["rules"]) == 1
        assert snapshot.extraction["rules"][0]["asset"] == "api.example.com"
        assert advisory.inputs
        assert len(advisory.inputs[0].encode("utf-8")) <= 64 * 1024
        assert snapshot.extraction["ai_prompt_sha256"] == sha256(
            advisory.inputs[0].encode("utf-8")
        ).hexdigest()
        if advisory_case == "valid":
            assert snapshot.ai_status == "ok"
            assert snapshot.extraction["ai_error_category"] is None
            assert "advisory_ai_review_required" in snapshot.extraction["review_issues"]
            service.review_snapshot(
                source_id=source.source_id,
                snapshot_id=snapshot.snapshot_id,
                decision="approved",
                reviewer_alias="reviewer_1",
                expected_review_digest=snapshot.review_digest,
                operator_confirmed=True,
            )
            assert len(service.list_scope_rules(source.program_id)) == 1
        elif advisory_case == "invalid":
            assert snapshot.ai_status == "unavailable"
            assert snapshot.extraction["ai_error_category"] == "invalid_output"
            assert snapshot.extraction["review_state"] == "ready"
        else:
            assert snapshot.ai_status == "unavailable"
            assert snapshot.extraction["ai_error_category"] == "provider_unavailable"
            assert "provider-secret-must-not-persist" not in snapshot.model_dump_json()
    finally:
        session.close()
        engine.dispose()


def test_operator_program_rule_api_registers_lists_and_coalesces_refresh(
    program_rule_client,
):
    client, _ = program_rule_client
    registered = client.post(
        "/program-rule-sources",
        json={
            "program_alias": "api_program",
            "public_rule_url": "https://EXAMPLE.com:443/rules",
        },
    )
    assert registered.status_code == 201
    source = registered.json()
    assert source["canonical_url"] == "https://example.com/rules"
    assert source["effective_scope_status"] == "needs_review"
    assert source["fetch_status"] == "scheduled"

    duplicate = client.post(
        "/program-rule-sources",
        json={
            "program_alias": "duplicate_program",
            "public_rule_url": "https://example.com/rules",
        },
    )
    invalid = client.post(
        "/program-rule-sources",
        json={
            "program_alias": "bad_program",
            "public_rule_url": "http://example.com/rules",
        },
    )
    assert duplicate.status_code == 409
    assert invalid.status_code == 422

    listed = client.get("/program-rule-sources")
    fetched = client.get(f"/program-rule-sources/{source['source_id']}")
    assert listed.status_code == 200
    assert fetched.status_code == 200
    operator_json = json.dumps([listed.json(), fetched.json()])
    assert "claim_token" not in operator_json
    assert "claim_id" not in operator_json

    refreshed = client.post(
        f"/program-rule-sources/{source['source_id']}/refresh"
    )
    cooled_down = client.post(
        f"/program-rule-sources/{source['source_id']}/refresh"
    )
    assert refreshed.status_code == 202
    assert cooled_down.status_code == 429
    assert 1 <= int(cooled_down.headers["Retry-After"]) <= 300
    assert client.get("/program-rule-sources/missing").status_code == 404


def test_claim_api_normalizes_completes_reviews_and_never_grants_authority(
    program_rule_client,
):
    client, testing_session = program_rule_client
    source = client.post(
        "/program-rule-sources",
        json={
            "program_alias": "claim_api_program",
            "public_rule_url": "https://example.com/rules",
        },
    ).json()
    claim_response = client.post(
        "/mythos/studio/program-rule-fetch/claims/next",
        json={},
    )
    assert claim_response.status_code == 200
    claim = claim_response.json()["claim"]
    assert claim["source_id"] == source["source_id"]
    assert claim["claim_token"]
    assert claim["limits"]["max_documents"] == 8

    envelope = fixture_envelope(
        "policy.html",
        "text/html; charset=utf-8",
        source_url=source["canonical_url"],
        depth=0,
    )
    normalized = client.post(
        f"/mythos/studio/program-rule-fetch/claims/{claim['claim_id']}/normalize",
        json={
            "source_id": source["source_id"],
            "claim_token": claim["claim_token"],
            "document": envelope.model_dump(mode="json"),
        },
    )
    assert normalized.status_code == 200
    assert "body_base64" not in normalized.text
    assert "RAW_HTML_SENTINEL" not in normalized.text
    wrong_token = client.post(
        f"/mythos/studio/program-rule-fetch/claims/{claim['claim_id']}/normalize",
        json={
            "source_id": source["source_id"],
            "claim_token": "wrong-token",
            "document": envelope.model_dump(mode="json"),
        },
    )
    assert wrong_token.status_code == 409

    completed = client.post(
        f"/mythos/studio/program-rule-fetch/claims/{claim['claim_id']}/complete",
        json={
            "source_id": source["source_id"],
            "claim_token": claim["claim_token"],
            "documents": [normalized.json()],
        },
    )
    assert completed.status_code == 200
    snapshot = completed.json()
    assert snapshot["review_status"] == "pending"
    for field in (
        "execution_allowed",
        "lease_grant_allowed",
        "scope_change_allowed",
        "review_bypass_allowed",
        "report_submission_allowed",
    ):
        assert snapshot[field] is False

    snapshots = client.get(
        f"/program-rule-sources/{source['source_id']}/snapshots"
    )
    diff = client.get(
        f"/program-rule-sources/{source['source_id']}/snapshots/"
        f"{snapshot['snapshot_id']}/diff"
    )
    assert snapshots.status_code == 200
    assert diff.status_code == 200
    assert diff.json()["review_digest"] == snapshot["review_digest"]

    approved = client.post(
        f"/program-rule-sources/{source['source_id']}/snapshots/"
        f"{snapshot['snapshot_id']}/approve",
        json={
            "reviewer_alias": "reviewer_1",
            "expected_review_digest": snapshot["review_digest"],
            "operator_confirmed": True,
        },
    )
    assert approved.status_code == 200
    assert approved.json()["review_status"] == "approved"
    rules = client.get(f"/programs/{source['program_id']}/scope-rules")
    assert rules.status_code == 200
    assert rules.json()[0]["canonical_asset"] == "api.example.com"
    assert all(
        rule["execution_allowed"] is False
        and rule["lease_grant_allowed"] is False
        and rule["scope_change_allowed"] is False
        and rule["review_bypass_allowed"] is False
        and rule["report_submission_allowed"] is False
        for rule in rules.json()
    )

    with testing_session() as session:
        from app.db_models import ApprovalRecord

        assert session.scalar(select(ApprovalRecord)) is None
    operator_payload = client.get("/program-rule-sources").text
    assert claim["claim_token"] not in operator_payload
    assert "claim_token" not in operator_payload


def test_claim_api_returns_fixed_browser_render_required_signal(
    program_rule_client,
):
    client, _ = program_rule_client
    source = client.post(
        "/program-rule-sources",
        json={
            "program_alias": "browser_fallback_program",
            "public_rule_url": "https://example.com/rules",
        },
    ).json()
    claim = client.post(
        "/mythos/studio/program-rule-fetch/claims/next",
        json={},
    ).json()["claim"]
    envelope = fixture_envelope(
        "policy.html",
        "text/html",
        source_url=source["canonical_url"],
        depth=0,
    ).model_copy(update={"charset": "windows-1252"})

    fallback = client.post(
        f"/mythos/studio/program-rule-fetch/claims/{claim['claim_id']}/normalize",
        json={
            "source_id": source["source_id"],
            "claim_token": claim["claim_token"],
            "document": envelope.model_dump(mode="json"),
        },
    )

    assert fallback.status_code == 422
    assert fallback.json() == {"detail": "browser_render_required"}

    retry = client.post(
        f"/mythos/studio/program-rule-fetch/claims/{claim['claim_id']}/normalize",
        json={
            "source_id": source["source_id"],
            "claim_token": claim["claim_token"],
            "document": fixture_envelope(
                "policy.html",
                "text/html",
                source_url=source["canonical_url"],
                depth=0,
            ).model_dump(mode="json"),
        },
    )
    assert retry.status_code == 200


def test_claim_request_validation_never_echoes_raw_body_or_token(
    program_rule_client,
):
    client, _ = program_rule_client
    source = client.post(
        "/program-rule-sources",
        json={
            "program_alias": "validation_api_program",
            "public_rule_url": "https://example.com/rules",
        },
    ).json()
    claim = client.post(
        "/mythos/studio/program-rule-fetch/claims/next",
        json={},
    ).json()["claim"]
    raw_marker = "RAW_BODY_SECRET_MUST_NOT_ECHO"
    token_marker = "RAW_CLAIM_TOKEN_MUST_NOT_ECHO"

    invalid = client.post(
        f"/mythos/studio/program-rule-fetch/claims/{claim['claim_id']}/normalize",
        json={
            "source_id": source["source_id"],
            "claim_token": token_marker,
            "document": {
                "source_url": source["canonical_url"],
                "depth": 0,
                "content_type": "text/html",
                "mode": "static",
                "body_base64": raw_marker,
                "raw_sha256": "not-a-digest",
                "charset": "utf-8",
                "unexpected": True,
            },
        },
    )
    assert invalid.status_code == 422
    assert invalid.json() == {"detail": "Program rule request is invalid"}
    assert raw_marker not in invalid.text
    assert token_marker not in invalid.text


def test_registry_advisory_adapter_is_off_without_config_and_has_no_tool_surface():
    class FakeRegistry:
        def __init__(self, *, error=None):
            self.error = error
            self.request = None

        async def generate(self, request):
            self.request = request
            return LLMResponse(
                provider=request.provider,
                model=request.model,
                text='{"rules":[]}' if self.error is None else "",
                mode=LLMMode.LIVE,
                prompt_hash="a" * 64,
                latency_ms=1,
                error=self.error,
            )

    disabled = build_configured_program_rule_advisory(
        SimpleNamespace(
            program_rule_ai_provider="openai",
            program_rule_ai_model="",
            openai_api_key="configured-key",
            anthropic_api_key=None,
            deepseek_api_key=None,
        ),
        registry=FakeRegistry(),
    )
    missing_key = build_configured_program_rule_advisory(
        SimpleNamespace(
            program_rule_ai_provider="openai",
            program_rule_ai_model="model-name",
            openai_api_key=None,
            anthropic_api_key=None,
            deepseek_api_key=None,
        ),
        registry=FakeRegistry(),
    )
    assert disabled is None
    assert missing_key is None

    registry = FakeRegistry()
    adapter = RegistryProgramRuleAdvisoryExtractor(
        registry,
        provider=ProviderName.OPENAI,
        model="model-name",
    )
    result = asyncio.run(adapter.extract("in scope: api.example.com"))
    assert result == '{"rules":[]}'
    assert registry.request.temperature == 0
    assert registry.request.mode == LLMMode.LIVE
    assert registry.request.purpose == "program_rule_advisory_extraction"
    assert "untrusted" in registry.request.system_prompt.lower()
    assert not hasattr(registry.request, "tools")

    unavailable = RegistryProgramRuleAdvisoryExtractor(
        FakeRegistry(error="provider failed"),
        provider=ProviderName.OPENAI,
        model="model-name",
    )
    with pytest.raises(ProgramRuleAdvisoryUnavailable):
        asyncio.run(unavailable.extract("safe normalized corpus"))


def test_approved_missing_controls_snapshot_remains_non_authorizing():
    service, repository, session, engine, clock = build_service()
    try:
        source = service.register_source(
            program_alias="missing_controls_program",
            public_rule_url="https://example.com/rules",
        )
        claim = service.claim_next().claim
        raw = b"In scope: files.example.com"
        document = service.normalize_claim_document(
            claim_id=claim.claim_id,
            source_id=source.source_id,
            claim_token=claim.claim_token,
            envelope=StaticRuleDocumentEnvelope(
                source_url=source.canonical_url,
                depth=0,
                content_type="text/plain",
                mode="static",
                body_base64=base64.b64encode(raw).decode("ascii"),
                raw_sha256=sha256(raw).hexdigest(),
                charset="utf-8",
            ),
        )
        pending = asyncio.run(
            service.complete_claim(
                claim_id=claim.claim_id,
                source_id=source.source_id,
                claim_token=claim.claim_token,
                documents=[document],
            )
        )
        assert set(pending.extraction["review_issues"]) >= {
            "automation_not_stated",
            "rate_limit_not_stated",
        }

        approved = service.review_snapshot(
            source_id=source.source_id,
            snapshot_id=pending.snapshot_id,
            decision="approved",
            reviewer_alias="reviewer_1",
            expected_review_digest=pending.review_digest,
            operator_confirmed=True,
        )
        assert approved.review_status == "approved"
        assert service.list_scope_rules(source.program_id) == []
        assert service.get_source(source.source_id).effective_scope_status == (
            "needs_review"
        )
        assert repository.get_program(source.program_id).scope_status == "needs_review"
    finally:
        session.close()
        engine.dispose()


def test_claim_order_is_oldest_due_and_manual_refresh_coalesces_live_work():
    service, repository, session, engine, clock = build_service(
        tokens=("claim-token-1", "claim-token-2"),
        claim_ids=("claim_1", "claim_2"),
    )
    try:
        oldest = service.register_source(
            program_alias="oldest_program",
            public_rule_url="https://oldest.example/rules",
        )
        clock.value += timedelta(minutes=1)
        newer = service.register_source(
            program_alias="newer_program",
            public_rule_url="https://newer.example/rules",
        )

        first_claim = service.claim_next().claim
        assert first_claim.source_id == oldest.source_id
        refreshed = service.request_refresh(oldest.source_id)
        assert refreshed.fetch_status == "fetching"
        stored_oldest = repository.get_program_rule_source(oldest.source_id)
        assert stored_oldest.claim_id == first_claim.claim_id
        with pytest.raises(ProgramRuleCooldown):
            service.request_refresh(oldest.source_id)

        second_claim = service.claim_next().claim
        assert second_claim.source_id == newer.source_id
    finally:
        session.close()
        engine.dispose()
