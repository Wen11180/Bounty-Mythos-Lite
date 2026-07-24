import base64
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from hashlib import sha256
import json
from pathlib import Path
from threading import Barrier

import pytest
from sqlalchemy import create_engine, event, inspect, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.db import Base
import app.db_models as db_models
from app.repository import DatabaseRepository
from app.program_rule_intake.contracts import StaticRuleDocumentEnvelope
from app.program_rule_intake.extractor import extract_deterministic_rules
from app.program_rule_intake.normalizer import normalize_rule_document


FIXTURE_ROOT = Path(__file__).parent / "fixtures" / "program_rule_intake"


def build_session():
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )

    @event.listens_for(engine, "connect")
    def enable_foreign_keys(dbapi_connection, _connection_record):
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()

    Base.metadata.create_all(bind=engine)
    return sessionmaker(bind=engine, expire_on_commit=False)(), engine


def program_record(program_id):
    return db_models.ProgramRecord(
        id=program_id,
        name="Example Program",
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


def source_record(source_id, program_id, canonical_url, *, interval=86_400):
    now = datetime(2026, 7, 16, tzinfo=UTC)
    return db_models.ProgramRuleSourceRecord(
        id=source_id,
        program_id=program_id,
        program_alias=f"alias_{source_id}",
        registered_url=canonical_url,
        canonical_url=canonical_url,
        refresh_interval_seconds=interval,
        fetch_status="scheduled",
        next_check_at=now,
        created_at=now,
        updated_at=now,
    )


def snapshot_record(snapshot_id, source_id, normalized_sha256, **permissions):
    now = datetime(2026, 7, 16, tzinfo=UTC)
    return db_models.ProgramRuleSnapshotRecord(
        id=snapshot_id,
        source_id=source_id,
        raw_aggregate_sha256="a" * 64,
        normalized_sha256=normalized_sha256,
        fetched_at=now,
        fetch_mode="static",
        content_types=["text/html"],
        detected_language="en",
        extraction={"rules": []},
        evidence=[],
        linked_documents=[],
        openapi_candidates=[],
        ai_status="not_requested",
        review_status="pending",
        review_digest="c" * 64,
        created_at=now,
        **permissions,
    )


def scope_rule_record(rule_id, program_id, source_id, snapshot_id, asset):
    return db_models.ProgramScopeRuleRecord(
        id=rule_id,
        program_id=program_id,
        source_id=source_id,
        approved_snapshot_id=snapshot_id,
        canonical_asset=asset,
        asset_kind="exact_host",
        source_evidence_refs=["evidence_1"],
        scope_status="in_scope",
        automation="limited",
        allowed_validation=[],
        prohibited=["DoS"],
        rate_limit={"requests": 5, "period": 1, "unit": "minute"},
        approval_digest="d" * 64,
        effective_at=datetime(2026, 7, 16, tzinfo=UTC),
    )


def safe_snapshot_values(source_id, normalized_sha256="b" * 64):
    return {
        "source_id": source_id,
        "raw_aggregate_sha256": "a" * 64,
        "normalized_sha256": normalized_sha256,
        "fetched_at": datetime(2026, 7, 16, tzinfo=UTC),
        "fetch_mode": "static",
        "content_types": ["text/html", "application/json"],
        "detected_language": "en",
        "extraction": {
            "rules": [
                {
                    "asset": "api.example.com",
                    "asset_kind": "exact_host",
                    "scope_status": "in_scope",
                    "automation": "limited",
                    "allowed_validation": [],
                    "prohibited": ["DoS"],
                    "rate_limit": {
                        "requests": 5,
                        "period": 1,
                        "unit": "minute",
                        "evidence_ids": ["e" * 64],
                    },
                    "scope_evidence_ids": ["e" * 64],
                }
            ],
            "review_state": "ready",
            "review_issues": [],
        },
        "evidence": [
            {
                "evidence_id": "e" * 64,
                "document_sha256": "f" * 64,
                "locator": "paragraph:1",
                "excerpt": (
                    "api.example.com is in scope; limit 5 requests per minute; "
                    "do not access real user data."
                ),
            }
        ],
        "linked_documents": [
            {
                "url": "https://example.com/openapi.json",
                "normalized_sha256": "1" * 64,
                "evidence_ids": ["e" * 64],
            }
        ],
        "openapi_candidates": [
            {
                "kind": "openapi",
                "url": "https://example.com/openapi.json",
                "url_sha256": "2" * 64,
                "normalized_sha256": "1" * 64,
                "openapi_like": {"paths": {"/v1/items": {"get": {}}}},
                "evidence_ids": ["e" * 64],
                "promotion_allowed": False,
            }
        ],
        "ai_status": "not_requested",
        "review_status": "pending",
        "review_digest": "c" * 64,
    }


def test_program_rule_orm_schema_matches_migration_and_omits_raw_secrets():
    session, engine = build_session()
    try:
        tables = set(inspect(engine).get_table_names())
        assert {
            "program_rule_sources",
            "program_rule_snapshots",
            "program_scope_rules",
        } <= tables

        source_columns = db_models.ProgramRuleSourceRecord.__table__.c
        snapshot_columns = db_models.ProgramRuleSnapshotRecord.__table__.c
        assert source_columns.next_check_at.type.timezone is True
        assert snapshot_columns.fetched_at.type.timezone is True
        assert "claim_token_digest" in source_columns
        assert "claim_token" not in source_columns
        assert "raw_body" not in snapshot_columns
        assert "raw_html" not in snapshot_columns
        assert "authorization" not in snapshot_columns
        assert "cookie" not in snapshot_columns
    finally:
        session.close()
        engine.dispose()


def test_source_constraints_fix_interval_and_uniqueness():
    session, engine = build_session()
    try:
        session.add_all([program_record("program_1"), program_record("program_2")])
        session.commit()
        session.add(source_record("source_1", "program_1", "https://example.com/rules"))
        session.commit()

        session.add(source_record("source_2", "program_2", "https://example.com/rules"))
        with pytest.raises(IntegrityError):
            session.commit()
        session.rollback()

        session.add(source_record("source_3", "program_1", "https://other.example/rules"))
        with pytest.raises(IntegrityError):
            session.commit()
        session.rollback()

        session.add(
            source_record(
                "source_4",
                "program_2",
                "https://other.example/rules",
                interval=60,
            )
        )
        with pytest.raises(IntegrityError):
            session.commit()
    finally:
        session.rollback()
        session.close()
        engine.dispose()


def test_snapshot_constraints_are_content_addressed_and_permissions_stay_false():
    session, engine = build_session()
    try:
        session.add(program_record("program_1"))
        session.add(source_record("source_1", "program_1", "https://example.com/rules"))
        session.commit()

        snapshot = snapshot_record("snapshot_1", "source_1", "b" * 64)
        session.add(snapshot)
        session.commit()
        assert snapshot.execution_allowed is False
        assert snapshot.lease_grant_allowed is False
        assert snapshot.scope_change_allowed is False
        assert snapshot.review_bypass_allowed is False
        assert snapshot.report_submission_allowed is False

        session.add(snapshot_record("snapshot_2", "source_1", "b" * 64))
        with pytest.raises(IntegrityError):
            session.commit()
        session.rollback()

        session.add(
            snapshot_record(
                "snapshot_3",
                "source_1",
                "e" * 64,
                execution_allowed=True,
            )
        )
        with pytest.raises(IntegrityError):
            session.commit()
    finally:
        session.rollback()
        session.close()
        engine.dispose()


def test_scope_rule_constraints_bind_program_source_snapshot_and_asset():
    session, engine = build_session()
    try:
        session.add(program_record("program_1"))
        session.add(source_record("source_1", "program_1", "https://example.com/rules"))
        session.commit()
        session.add(snapshot_record("snapshot_1", "source_1", "b" * 64))
        session.commit()
        session.add(
            scope_rule_record(
                "rule_1",
                "program_1",
                "source_1",
                "snapshot_1",
                "api.example.com",
            )
        )
        session.commit()

        session.add(
            scope_rule_record(
                "rule_2",
                "program_1",
                "source_1",
                "snapshot_1",
                "api.example.com",
            )
        )
        with pytest.raises(IntegrityError):
            session.commit()
        session.rollback()

        session.add(
            scope_rule_record(
                "rule_3",
                "missing_program",
                "source_1",
                "snapshot_1",
                "files.example.com",
            )
        )
        with pytest.raises(IntegrityError):
            session.commit()
    finally:
        session.rollback()
        session.close()
        engine.dispose()


def test_repository_registration_is_deterministic_and_starts_fail_closed():
    session, engine = build_session()
    try:
        repository = DatabaseRepository(session)
        now = datetime(2026, 7, 16, 8, 0, tzinfo=UTC)

        first = repository.create_program_rule_source(
            program_alias="example_program",
            registered_url="https://EXAMPLE.com:443/rules",
            now=now,
        )
        repeated = repository.create_program_rule_source(
            program_alias="ignored_duplicate_alias",
            registered_url="https://example.com/rules",
            now=now + timedelta(minutes=1),
        )

        assert repeated.id == first.id
        assert repeated.program_id == first.program_id
        assert first.canonical_url == "https://example.com/rules"
        assert first.refresh_interval_seconds == 86_400
        assert first.fetch_status == "scheduled"
        assert first.next_check_at == now.replace(tzinfo=None)
        assert repository.get_program_rule_source(first.id).id == first.id
        assert [item.id for item in repository.list_program_rule_sources()] == [first.id]

        program = repository.get_program(first.program_id)
        assert program is not None
        assert program.name == "example_program"
        assert program.platform == "public_url"
        assert program.scope_status == "needs_review"
        assert program.automation == "needs_review"
        assert program.testing_accounts == "not_provided"
        assert program.api_docs == "not_provided"
        assert program.public_code == "not_provided"
        with pytest.raises(ValueError, match="not safe to persist"):
            repository.create_program_rule_source(
                program_alias="unsafe_program",
                registered_url="https://example.net/rules?email=user@example.net",
                now=now,
            )
    finally:
        session.close()
        engine.dispose()


def test_repository_claims_due_source_once_and_reclaims_only_after_expiry(tmp_path):
    database_path = tmp_path / "program-rule-claims.db"
    engine = create_engine(
        f"sqlite+pysqlite:///{database_path}",
        connect_args={"check_same_thread": False, "timeout": 10},
    )

    @event.listens_for(engine, "connect")
    def enable_foreign_keys(dbapi_connection, _connection_record):
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()

    Base.metadata.create_all(bind=engine)
    session_factory = sessionmaker(bind=engine, expire_on_commit=False)
    now = datetime(2026, 7, 16, 8, 0, tzinfo=UTC)
    setup_session = session_factory()
    source = DatabaseRepository(setup_session).create_program_rule_source(
        program_alias="race_program",
        registered_url="https://race.example/rules",
        now=now,
    )
    setup_session.close()
    barrier = Barrier(2)

    def attempt_claim(index):
        session = session_factory()
        try:
            barrier.wait()
            return DatabaseRepository(session).claim_next_due_program_rule_source(
                claim_id=f"claim_{index}",
                claim_token_digest=sha256(f"token_{index}".encode()).hexdigest(),
                now=now,
            )
        finally:
            session.close()

    try:
        with ThreadPoolExecutor(max_workers=2) as executor:
            results = list(executor.map(attempt_claim, (1, 2)))

        winners = [result for result in results if result is not None]
        assert len(winners) == 1
        winner = winners[0]
        assert winner.id == source.id
        assert winner.fetch_status == "fetching"
        assert winner.claim_expires_at == (now + timedelta(minutes=15)).replace(
            tzinfo=None
        )

        live_session = session_factory()
        try:
            live_repository = DatabaseRepository(live_session)
            assert (
                live_repository.claim_next_due_program_rule_source(
                    claim_id="claim_live_replacement",
                    claim_token_digest="9" * 64,
                    now=now + timedelta(minutes=14),
                )
                is None
            )
            reclaimed = live_repository.claim_next_due_program_rule_source(
                claim_id="claim_after_expiry",
                claim_token_digest="8" * 64,
                now=now + timedelta(minutes=15),
            )
            assert reclaimed is not None
            assert reclaimed.claim_id == "claim_after_expiry"
        finally:
            live_session.close()
    finally:
        engine.dispose()


def test_claim_validation_rejects_wrong_cross_source_expired_and_consumed_claims():
    session, engine = build_session()
    try:
        repository = DatabaseRepository(session)
        now = datetime(2026, 7, 16, 8, 0, tzinfo=UTC)
        first = repository.create_program_rule_source(
            program_alias="first_program",
            registered_url="https://first.example/rules",
            now=now,
        )
        second = repository.create_program_rule_source(
            program_alias="second_program",
            registered_url="https://second.example/rules",
            now=now + timedelta(days=1),
        )
        raw_token = "raw-claim-token-must-never-be-stored"
        token_digest = sha256(raw_token.encode()).hexdigest()
        claimed = repository.claim_next_due_program_rule_source(
            claim_id="claim_first",
            claim_token_digest=token_digest,
            now=now,
        )

        assert claimed is not None
        assert claimed.claim_token_digest == token_digest
        stored_values = "|".join(
            str(getattr(claimed, column.name))
            for column in db_models.ProgramRuleSourceRecord.__table__.columns
        )
        assert raw_token not in stored_values
        assert (
            repository.get_active_program_rule_source_claim(
                source_id=first.id,
                claim_id="claim_first",
                claim_token_digest="0" * 64,
                now=now,
            )
            is None
        )
        assert (
            repository.get_active_program_rule_source_claim(
                source_id=second.id,
                claim_id="claim_first",
                claim_token_digest=token_digest,
                now=now,
            )
            is None
        )
        assert (
            repository.finish_program_rule_source_claim(
                source_id=first.id,
                claim_id="claim_first",
                claim_token_digest="0" * 64,
                now=now,
                next_check_at=now + timedelta(days=1),
                succeeded=True,
            )
            is None
        )

        finished = repository.finish_program_rule_source_claim(
            source_id=first.id,
            claim_id="claim_first",
            claim_token_digest=token_digest,
            now=now,
            next_check_at=now + timedelta(days=1),
            succeeded=True,
        )
        assert finished is not None
        assert finished.fetch_status == "ok"
        assert finished.claim_id is None
        assert finished.claim_token_digest is None
        assert (
            repository.finish_program_rule_source_claim(
                source_id=first.id,
                claim_id="claim_first",
                claim_token_digest=token_digest,
                now=now,
                next_check_at=now + timedelta(days=1),
                succeeded=False,
                failure_code="fetch_failed",
            )
            is None
        )

        first.next_check_at = now
        session.add(first)
        session.commit()
        expired = repository.claim_next_due_program_rule_source(
            claim_id="claim_expired",
            claim_token_digest="7" * 64,
            now=now,
        )
        assert expired is not None
        expiry = now + timedelta(minutes=15)
        assert (
            repository.get_active_program_rule_source_claim(
                source_id=first.id,
                claim_id="claim_expired",
                claim_token_digest="7" * 64,
                now=expiry,
            )
            is None
        )
        assert (
            repository.finish_program_rule_source_claim(
                source_id=first.id,
                claim_id="claim_expired",
                claim_token_digest="7" * 64,
                now=expiry,
                next_check_at=expiry + timedelta(days=1),
                succeeded=False,
                failure_code="fetch_failed",
            )
            is None
        )
    finally:
        session.close()
        engine.dispose()


def test_snapshot_save_is_content_addressed_and_preserves_rejected_review():
    session, engine = build_session()
    try:
        repository = DatabaseRepository(session)
        now = datetime(2026, 7, 16, 8, 0, tzinfo=UTC)
        source = repository.create_program_rule_source(
            program_alias="snapshot_program",
            registered_url="https://snapshot.example/rules",
            now=now,
        )
        snapshot = repository.save_program_rule_snapshot(
            **safe_snapshot_values(source.id)
        )
        rejected = repository.update_program_rule_snapshot_review(
            source_id=source.id,
            snapshot_id=snapshot.id,
            review_status="rejected",
            reviewer_alias="reviewer_1",
            reviewed_at=now + timedelta(minutes=1),
        )
        duplicate_values = safe_snapshot_values(source.id)
        duplicate_values["extraction"] = {"rules": []}
        duplicate = repository.save_program_rule_snapshot(**duplicate_values)

        assert rejected is not None
        assert duplicate.id == snapshot.id
        assert duplicate.review_status == "rejected"
        assert duplicate.reviewer_alias == "reviewer_1"
        assert duplicate.extraction == snapshot.extraction
        assert repository.find_program_rule_snapshot(source.id, "b" * 64).id == snapshot.id
        assert [item.id for item in repository.list_program_rule_snapshots(source.id)] == [
            snapshot.id
        ]

        other = repository.create_program_rule_source(
            program_alias="other_snapshot_program",
            registered_url="https://other-snapshot.example/rules",
            now=now,
        )
        other_snapshot = repository.save_program_rule_snapshot(
            **safe_snapshot_values(other.id, "d" * 64)
        )
        with pytest.raises(ValueError, match="snapshot pointer is invalid"):
            repository.set_program_rule_source_snapshot_pointers(
                source_id=source.id,
                approved_snapshot_id=other_snapshot.id,
                pending_snapshot_id=None,
                updated_at=now,
            )
    finally:
        session.close()
        engine.dispose()


def test_normalized_fixture_snapshot_persists_only_redacted_bounded_facts():
    session, engine = build_session()
    try:
        repository = DatabaseRepository(session)
        now = datetime(2026, 7, 16, 8, 0, tzinfo=UTC)
        source = repository.create_program_rule_source(
            program_alias="fixture_program",
            registered_url="https://example.com/rules",
            now=now,
        )

        policy_raw = (FIXTURE_ROOT / "policy.html").read_bytes()
        policy = normalize_rule_document(
            StaticRuleDocumentEnvelope(
                source_url="https://example.com/rules",
                depth=0,
                content_type="text/html; charset=utf-8",
                mode="static",
                body_base64=base64.b64encode(policy_raw).decode("ascii"),
                raw_sha256=sha256(policy_raw).hexdigest(),
                charset="utf-8",
            )
        )
        openapi_raw = (FIXTURE_ROOT / "openapi.yaml").read_bytes()
        openapi = normalize_rule_document(
            StaticRuleDocumentEnvelope(
                source_url="https://example.com/openapi.yaml",
                depth=1,
                content_type="application/yaml",
                mode="static",
                body_base64=base64.b64encode(openapi_raw).decode("ascii"),
                raw_sha256=sha256(openapi_raw).hexdigest(),
                charset="utf-8",
            )
        )
        extraction = extract_deterministic_rules([policy, openapi])
        normalized_digest = sha256(
            f"{policy.normalized_sha256}:{openapi.normalized_sha256}".encode()
        ).hexdigest()
        snapshot = repository.save_program_rule_snapshot(
            source_id=source.id,
            raw_aggregate_sha256=sha256(policy_raw + openapi_raw).hexdigest(),
            normalized_sha256=normalized_digest,
            fetched_at=now,
            fetch_mode="static",
            content_types=[policy.content_type, openapi.content_type],
            detected_language=policy.detected_language,
            extraction=extraction.model_dump(mode="json"),
            evidence=[item.model_dump(mode="json") for item in extraction.evidence],
            linked_documents=[
                {
                    "url": openapi.source_url,
                    "normalized_sha256": openapi.normalized_sha256,
                    "evidence_ids": extraction.linked_artifacts[0].evidence_ids,
                }
            ],
            openapi_candidates=[
                item.model_dump(mode="json") for item in extraction.linked_artifacts
            ],
            ai_status=extraction.ai_status,
            review_status="pending",
            review_digest="c" * 64,
        )

        persisted = json.dumps(
            {
                "extraction": snapshot.extraction,
                "evidence": snapshot.evidence,
                "linked_documents": snapshot.linked_documents,
                "openapi_candidates": snapshot.openapi_candidates,
            },
            sort_keys=True,
        )
        for forbidden in (
            "RAW_HTML_SENTINEL",
            "form-secret",
            "top-secret-token",
            "secret-cookie",
            "security@example.com",
            "hidden-token@example.com",
            "This raw description must not enter",
            "bearerAuth",
            "securitySchemes",
        ):
            assert forbidden not in persisted
        assert snapshot.openapi_candidates[0]["openapi_like"] == {
            "paths": {
                "/v1/teams/{team_id}/invite": {"post": {}},
                "/v1/users/{user_id}": {"get": {}},
            }
        }
    finally:
        session.close()
        engine.dispose()


def test_snapshot_repository_rejects_raw_or_sensitive_persistence_payloads():
    session, engine = build_session()
    try:
        repository = DatabaseRepository(session)
        now = datetime(2026, 7, 16, 8, 0, tzinfo=UTC)
        source = repository.create_program_rule_source(
            program_alias="safety_program",
            registered_url="https://safety.example/rules",
            now=now,
        )
        values = safe_snapshot_values(source.id)
        values["extraction"] = {
            "raw_html": "<!doctype html><html>RAW_HTML_SENTINEL</html>",
            "authorization": "Bearer live-secret",
            "query_url": "https://safety.example/rules?token=live-query-secret",
            "browser_state": {"cookies": ["live-cookie"]},
            "raw_openapi": {
                "openapi": "3.1.0",
                "paths": {"/users": {"get": {"responses": {}}}},
                "components": {"schemas": {"User": {"example": "real user"}}},
            },
        }

        with pytest.raises(ValueError) as error:
            repository.save_program_rule_snapshot(**values)

        assert str(error.value) == "program-rule payload is not safe to persist"
        persisted = json.dumps(
            session.execute(
                select(db_models.ProgramRuleSnapshotRecord.__table__)
            ).mappings().all(),
            default=str,
        )
        for forbidden in (
            "RAW_HTML_SENTINEL",
            "live-secret",
            "live-query-secret",
            "live-cookie",
            '"openapi": "3.1.0"',
            '"components"',
            '"responses"',
        ):
            assert forbidden not in persisted
    finally:
        session.close()
        engine.dispose()


def test_scope_rule_repository_keeps_history_immutable_and_projects_program():
    session, engine = build_session()
    try:
        repository = DatabaseRepository(session)
        now = datetime(2026, 7, 16, 8, 0, tzinfo=UTC)
        source = repository.create_program_rule_source(
            program_alias="rules_program",
            registered_url="https://rules.example/policy",
            now=now,
        )
        first_snapshot = repository.save_program_rule_snapshot(
            **safe_snapshot_values(source.id, "b" * 64)
        )
        second_snapshot = repository.save_program_rule_snapshot(
            **safe_snapshot_values(source.id, "d" * 64)
        )
        first_rule = {
            "canonical_asset": "api.rules.example",
            "asset_kind": "exact_host",
            "source_evidence_refs": ["e" * 64],
            "scope_status": "in_scope",
            "automation": "limited",
            "allowed_validation": [],
            "prohibited": ["DoS"],
            "rate_limit": {"requests": 5, "period": 1, "unit": "minute"},
        }
        second_rule = {
            **first_rule,
            "rate_limit": {"requests": 3, "period": 1, "unit": "minute"},
        }

        first_rows = repository.replace_program_scope_rules(
            program_id=source.program_id,
            source_id=source.id,
            approved_snapshot_id=first_snapshot.id,
            approval_digest="3" * 64,
            effective_at=now,
            rules=[first_rule],
        )
        repeated_rows = repository.replace_program_scope_rules(
            program_id=source.program_id,
            source_id=source.id,
            approved_snapshot_id=first_snapshot.id,
            approval_digest="3" * 64,
            effective_at=now,
            rules=[first_rule],
        )
        assert repeated_rows[0].id == first_rows[0].id

        with pytest.raises(ValueError, match="scope rules are immutable"):
            repository.replace_program_scope_rules(
                program_id=source.program_id,
                source_id=source.id,
                approved_snapshot_id=first_snapshot.id,
                approval_digest="3" * 64,
                effective_at=now,
                rules=[second_rule],
            )

        repository.replace_program_scope_rules(
            program_id=source.program_id,
            source_id=source.id,
            approved_snapshot_id=second_snapshot.id,
            approval_digest="4" * 64,
            effective_at=now + timedelta(days=1),
            rules=[second_rule],
        )
        repository.set_program_rule_source_snapshot_pointers(
            source_id=source.id,
            approved_snapshot_id=second_snapshot.id,
            pending_snapshot_id=None,
            updated_at=now + timedelta(days=1),
        )
        projected = repository.project_program_rule_program_summary(
            program_id=source.program_id,
            scope_status="in_scope",
            automation="limited",
        )

        all_rows = repository.list_program_scope_rules(source.program_id)
        current_rows = repository.list_program_scope_rules(
            source.program_id,
            approved_snapshot_id=second_snapshot.id,
        )
        assert len(all_rows) == 2
        assert len(current_rows) == 1
        assert current_rows[0].rate_limit["requests"] == 3
        assert first_rows[0].id in {row.id for row in all_rows}
        assert projected is not None
        assert projected.scope_status == "in_scope"
        assert projected.automation == "limited"
    finally:
        session.close()
        engine.dispose()
