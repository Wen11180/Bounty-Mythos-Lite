from hashlib import sha256
import json
from pathlib import Path

from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.db import Base
from app.db_models import ProgramRecord
from app.repository import DatabaseRepository, seed_sample_data


def build_session():
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    return sessionmaker(bind=engine)()


def _load_json(value):
    return json.loads(value) if isinstance(value, str) else value


def test_save_artifact_persists_safe_summary_and_is_listed():
    session = build_session()
    try:
        seed_sample_data(session)
        repository = DatabaseRepository(session)
        source_hash = sha256(b"postman collection v1").hexdigest()
        fake_api_key = "sk" + "-live-secret"

        saved = repository.save_artifact(
            program_id="program_example",
            asset="api.example.com",
            kind="postman",
            source_type="manual_upload",
            source_hash=source_hash,
            ingestion_status="normalized",
            provenance={
                "imported_by": "dry_run",
                "source_name": "example.postman_collection.json",
            },
            payload_summary={
                "endpoint_count": 2,
                "sample_request": "Authorization: Bearer live-token",
                "metadata": {"api_key": fake_api_key},
            },
            derived_facts={
                "paths": ["/files/{file_id}/export", "/files/{file_id}"],
                "notes": ["Bearer live-token"],
            },
        )

        fetched = repository.get_artifact(saved.id)
        artifacts = repository.list_artifacts()

        assert fetched is not None
        assert fetched.id == saved.id
        assert fetched.program_id == "program_example"
        assert fetched.asset == "api.example.com"
        assert fetched.kind == "postman"
        assert fetched.source_type == "manual_upload"
        assert fetched.source_hash == source_hash
        assert fetched.ingestion_status == "normalized"
        assert fetched.provenance == {
            "imported_by": "dry_run",
            "source_name": "example.postman_collection.json",
            "safety": {
                "sensitivity_label": "sensitive",
                "redaction_status": "redacted",
                "report_chain_allowed": False,
                "safety_blockers": ["contains_secret_like_value"],
            },
        }
        assert fetched.payload_summary == {
            "endpoint_count": 2,
            "sample_request": "[REDACTED]",
            "metadata": {"api_key": "[REDACTED]"},
        }
        assert fetched.derived_facts == {
            "paths": ["/files/{file_id}/export", "/files/{file_id}"],
            "notes": ["[REDACTED]"],
        }
        assert fetched.created_at is not None
        assert [artifact.id for artifact in artifacts] == [saved.id]

        session.expire_all()
        record = session.execute(
            text(
                "select payload_summary, derived_facts from artifacts "
                "where id = :id"
            ),
            {"id": saved.id},
        ).mappings().one()
        serialized_display_payload = json.dumps(
            {
                "payload_summary": _load_json(record["payload_summary"]),
                "derived_facts": _load_json(record["derived_facts"]),
            }
        )
        assert "live-token" not in serialized_display_payload
        assert fake_api_key not in serialized_display_payload
    finally:
        session.close()


def test_save_artifact_records_safety_classification_for_sensitive_material():
    session = build_session()
    try:
        repository = DatabaseRepository(session)

        clean = repository.save_artifact(
            program_id=None,
            asset="api.example.com",
            kind="notes",
            source_type="manual_upload",
            source_hash=sha256(b"clean notes").hexdigest(),
            ingestion_status="normalized",
            provenance={"source_name": "clean-notes.md"},
            payload_summary={"endpoint_count": 1},
            derived_facts={"paths": ["/files/{file_id}/export"]},
        )
        sensitive = repository.save_artifact(
            program_id=None,
            asset="api.example.com",
            kind="har",
            source_type="manual_upload",
            source_hash=sha256(b"sensitive har").hexdigest(),
            ingestion_status="normalized",
            provenance={"source_name": "capture.har"},
            payload_summary={
                "request": "Authorization: Bearer live-token",
                "headers": {"cookie": "session=live-cookie"},
                "email": "alice@example.com",
            },
            derived_facts={
                "notes": [
                    "customer data appeared in response body",
                    (
                        "eyJhbGciOiJIUzI1NiJ9."
                        "eyJzdWIiOiIxMjM0NTY3ODkwIn0."
                        "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
                    ),
                    "session=secondary-live-cookie",
                ],
                "paths": ["/files/{file_id}/export"],
            },
        )

        fetched_clean = repository.get_artifact(clean.id)
        fetched_sensitive = repository.get_artifact(sensitive.id)

        assert fetched_clean is not None
        assert fetched_sensitive is not None
        assert fetched_clean.provenance["safety"] == {
            "sensitivity_label": "low",
            "redaction_status": "clean",
            "report_chain_allowed": True,
            "safety_blockers": [],
        }
        assert fetched_sensitive.provenance["safety"] == {
            "sensitivity_label": "sensitive",
            "redaction_status": "redacted",
            "report_chain_allowed": False,
            "safety_blockers": [
                "contains_secret_like_value",
                "contains_real_user_data_risk",
            ],
        }
        serialized_sensitive = json.dumps(
            {
                "provenance": fetched_sensitive.provenance,
                "payload_summary": fetched_sensitive.payload_summary,
                "derived_facts": fetched_sensitive.derived_facts,
            }
        )
        assert "live-token" not in serialized_sensitive
        assert "live-cookie" not in serialized_sensitive
        assert "alice@example.com" not in serialized_sensitive
        assert "eyJhbGciOiJIUzI1NiJ9" not in serialized_sensitive
        assert "secondary-live-cookie" not in serialized_sensitive
    finally:
        session.close()


def test_save_artifact_returns_existing_record_for_duplicate_source_hash():
    session = build_session()
    try:
        repository = DatabaseRepository(session)
        source_hash = sha256(b"same source").hexdigest()

        first = repository.save_artifact(
            program_id=None,
            asset="api.example.com",
            kind="openapi",
            source_type="manual_upload",
            source_hash=source_hash,
            ingestion_status="normalized",
            provenance={"source_name": "first-openapi.json"},
            payload_summary={"endpoint_count": 1},
            derived_facts={"paths": ["/v1/files"]},
        )
        duplicate = repository.save_artifact(
            program_id=None,
            asset="api.example.com",
            kind="openapi",
            source_type="manual_upload",
            source_hash=source_hash,
            ingestion_status="normalized",
            provenance={"source_name": "second-openapi.json"},
            payload_summary={"endpoint_count": 99},
            derived_facts={"paths": ["/v2/changed"]},
        )
        repeated_duplicate = repository.save_artifact(
            program_id=None,
            asset="api.example.com",
            kind="openapi",
            source_type="manual_upload",
            source_hash=source_hash,
            ingestion_status="normalized",
            provenance={"source_name": "second-openapi.json"},
            payload_summary={"endpoint_count": 99},
            derived_facts={"paths": ["/v2/changed"]},
        )

        session.expire_all()
        fetched = repository.get_artifact(first.id)
        artifacts = repository.list_artifacts()

        assert duplicate.id == first.id
        assert repeated_duplicate.id == first.id
        assert fetched is not None
        assert fetched.provenance == {
            "source_name": "first-openapi.json",
            "safety": {
                "sensitivity_label": "low",
                "redaction_status": "clean",
                "report_chain_allowed": True,
                "safety_blockers": [],
            },
            "duplicate_imports": [{"source_name": "second-openapi.json"}],
        }
        assert fetched.payload_summary == {"endpoint_count": 1}
        assert fetched.derived_facts == {"paths": ["/v1/files"]}
        assert [artifact.id for artifact in artifacts] == [first.id]
    finally:
        session.close()


def test_save_artifact_redacts_structured_har_and_postman_secret_pairs():
    session = build_session()
    try:
        repository = DatabaseRepository(session)
        raw_authorization = "DUMMY-RAW-AUTH-123"
        raw_cookie = "DUMMY-RAW-COOKIE-456"
        raw_api_key = "DUMMY-RAW-API-789"
        raw_access_token = "DUMMY-RAW-TOKEN-012"

        saved = repository.save_artifact(
            program_id=None,
            asset="api.example.com",
            kind="har",
            source_type="manual_upload",
            source_hash=sha256(b"structured har postman secrets").hexdigest(),
            ingestion_status="normalized",
            provenance={"source_name": "traffic.har"},
            payload_summary={
                "headers": [
                    {"name": "Authorization", "value": raw_authorization},
                    {"name": "X-Trace-Id", "value": "safe-trace"},
                ],
                "cookies": [{"name": "session", "value": raw_cookie}],
                "postman_headers": [{"key": "x-api-key", "value": raw_api_key}],
            },
            derived_facts={
                "postman_variables": [
                    {"key": "access_token", "contents": raw_access_token}
                ]
            },
        )

        fetched = repository.get_artifact(saved.id)
        assert fetched is not None
        assert fetched.provenance["safety"] == {
            "sensitivity_label": "sensitive",
            "redaction_status": "redacted",
            "report_chain_allowed": False,
            "safety_blockers": ["contains_secret_like_value"],
        }
        assert fetched.payload_summary["headers"] == [
            {"name": "Authorization", "value": "[REDACTED]"},
            {"name": "X-Trace-Id", "value": "safe-trace"},
        ]
        assert fetched.payload_summary["cookies"] == "[REDACTED]"
        assert fetched.payload_summary["postman_headers"] == [
            {"key": "x-api-key", "value": "[REDACTED]"}
        ]
        assert fetched.derived_facts["postman_variables"] == [
            {"key": "access_token", "contents": "[REDACTED]"}
        ]

        session.expire_all()
        record = session.execute(
            text(
                "select provenance, payload_summary, derived_facts from artifacts "
                "where id = :id"
            ),
            {"id": saved.id},
        ).mappings().one()
        persisted = json.dumps(
            {
                "provenance": _load_json(record["provenance"]),
                "payload_summary": _load_json(record["payload_summary"]),
                "derived_facts": _load_json(record["derived_facts"]),
            }
        )
        for raw_secret in (
            raw_authorization,
            raw_cookie,
            raw_api_key,
            raw_access_token,
        ):
            assert raw_secret not in persisted
    finally:
        session.close()


def test_save_artifact_keeps_secret_parameter_names_without_secret_values_clean():
    session = build_session()
    try:
        repository = DatabaseRepository(session)

        saved = repository.save_artifact(
            program_id=None,
            asset="api.example.com",
            kind="openapi",
            source_type="manual_upload",
            source_hash=sha256(b"openapi parameter definition").hexdigest(),
            ingestion_status="normalized",
            provenance={"source_name": "openapi.json"},
            payload_summary={
                "parameter": {"name": "Authorization", "in": "header"}
            },
            derived_facts={"paths": ["/v1/files"]},
        )

        fetched = repository.get_artifact(saved.id)
        assert fetched is not None
        assert fetched.provenance["safety"] == {
            "sensitivity_label": "low",
            "redaction_status": "clean",
            "report_chain_allowed": True,
            "safety_blockers": [],
        }
        assert fetched.payload_summary["parameter"] == {
            "name": "Authorization",
            "in": "header",
        }
    finally:
        session.close()


def test_save_artifact_scopes_duplicate_source_hashes_to_the_same_program():
    session = build_session()
    try:
        seed_sample_data(session)
        session.add(
            ProgramRecord(
                id="program_other",
                name="Other Program",
                platform="local",
                bounty_range="n/a",
                scope_status="in_scope",
                automation="none",
                testing_accounts="not_provided",
                api_docs="provided",
                public_code="provided",
                duplicate_risk="unknown",
                priority="medium",
            )
        )
        session.commit()
        repository = DatabaseRepository(session)
        source_hash = sha256(b"program scoped source").hexdigest()

        first = repository.save_artifact(
            program_id="program_example",
            asset="api.example.com",
            kind="openapi",
            source_type="manual_upload",
            source_hash=source_hash,
            ingestion_status="normalized",
            provenance={"source_name": "program-example.json"},
            payload_summary={"endpoint_count": 1},
            derived_facts={"paths": ["/v1/files"]},
        )
        duplicate = repository.save_artifact(
            program_id="program_example",
            asset="api.example.com",
            kind="openapi",
            source_type="manual_upload",
            source_hash=source_hash,
            ingestion_status="normalized",
            provenance={"source_name": "program-example-copy.json"},
            payload_summary={"endpoint_count": 99},
            derived_facts={"paths": ["/v2/changed"]},
        )
        other_program = repository.save_artifact(
            program_id="program_other",
            asset="api.example.com",
            kind="openapi",
            source_type="manual_upload",
            source_hash=source_hash,
            ingestion_status="normalized",
            provenance={"source_name": "program-other.json"},
            payload_summary={"endpoint_count": 2},
            derived_facts={"paths": ["/v1/files"]},
        )
        unscoped = repository.save_artifact(
            program_id=None,
            asset="api.example.com",
            kind="openapi",
            source_type="manual_upload",
            source_hash=source_hash,
            ingestion_status="normalized",
            provenance={"source_name": "unscoped.json"},
            payload_summary={"endpoint_count": 3},
            derived_facts={"paths": ["/v1/files"]},
        )

        assert duplicate.id == first.id
        assert other_program.id != first.id
        assert other_program.program_id == "program_other"
        assert unscoped.id not in {first.id, other_program.id}
        assert unscoped.program_id is None
        assert {artifact.id for artifact in repository.list_artifacts()} == {
            first.id,
            other_program.id,
            unscoped.id,
        }
    finally:
        session.close()


def test_artifact_program_scope_migration_upgrades_legacy_unnamed_unique_constraint(
    tmp_path,
    monkeypatch,
):
    database_path = tmp_path / "legacy-artifacts.db"
    database_url = f"sqlite:///{database_path}"
    engine = create_engine(database_url)
    with engine.begin() as connection:
        connection.execute(
            text(
                """
                create table programs (
                    id varchar(100) not null primary key
                )
                """
            )
        )
        connection.execute(
            text(
                """
                create table artifacts (
                    id varchar(100) not null primary key,
                    program_id varchar(100),
                    asset varchar(255) not null,
                    kind varchar(50) not null,
                    source_type varchar(50) not null,
                    source_hash varchar(100) not null,
                    ingestion_status varchar(50) not null,
                    provenance json not null,
                    payload_summary json not null,
                    derived_facts json not null,
                    created_at datetime not null,
                    unique (source_hash),
                    foreign key(program_id) references programs(id)
                )
                """
            )
        )
    engine.dispose()

    monkeypatch.setenv("DATABASE_URL", database_url)
    api_root = Path(__file__).resolve().parents[1]
    config = Config(str(api_root / "alembic.ini"))
    config.set_main_option("script_location", str(api_root / "migrations"))
    command.stamp(config, "0010_learning_signal_identity_hash")
    command.upgrade(config, "head")

    inspector = inspect(create_engine(database_url))
    unique_constraints = inspector.get_unique_constraints("artifacts")
    assert any(
        constraint["name"] == "uq_artifacts_program_source_hash"
        and constraint["column_names"] == ["program_id", "source_hash"]
        for constraint in unique_constraints
    )
    assert not any(
        constraint["column_names"] == ["source_hash"]
        for constraint in unique_constraints
    )


def test_append_artifact_usage_records_deduplicates_by_closed_loop_identity():
    session = build_session()
    try:
        repository = DatabaseRepository(session)
        artifact = repository.save_artifact(
            program_id="program_example",
            asset="api.example.com",
            kind="openapi",
            source_type="dry_run_inline",
            source_hash=sha256(b"usage identity").hexdigest(),
            ingestion_status="normalized",
            provenance={"source_name": "openapi.json"},
            payload_summary={"endpoint_count": 1},
            derived_facts={"paths": ["/files/{file_id}/export"]},
        )

        first = repository.append_artifact_usage_records(
            artifact_id=artifact.id,
            usage_records=[
                {
                    "usage_type": "learning_signal",
                    "ref": "learning_signal:learning_signal_1",
                    "run_id": "pipeline_run_1",
                    "stage": "mythos_brain",
                    "learning_signal_id": "learning_signal_1",
                    "note": "Authorization: Bearer live-token",
                }
            ],
        )
        repeated = repository.append_artifact_usage_records(
            artifact_id=artifact.id,
            usage_records=[
                {
                    "usage_type": "learning_signal",
                    "ref": "learning_signal:learning_signal_1",
                    "run_id": "pipeline_run_1",
                    "stage": "mythos_brain",
                    "learning_signal_id": "learning_signal_1",
                    "evidence_quality": "strong",
                }
            ],
        )

        assert first is not None
        assert repeated is not None
        usage_records = repeated.provenance["usage_records"]
        assert usage_records == [
            {
                "usage_type": "learning_signal",
                "ref": "learning_signal:learning_signal_1",
                "run_id": "pipeline_run_1",
                "stage": "mythos_brain",
                "learning_signal_id": "learning_signal_1",
                "note": "[REDACTED]",
            }
        ]
        assert "live-token" not in json.dumps(repeated.provenance)
    finally:
        session.close()


def test_list_artifacts_filters_by_structured_provenance_edge():
    session = build_session()
    try:
        repository = DatabaseRepository(session)
        file_artifact = repository.save_artifact(
            program_id=None,
            asset="api.example.com",
            kind="openapi",
            source_type="dry_run_inline",
            source_hash=sha256(b"file artifact").hexdigest(),
            ingestion_status="normalized",
            provenance={"source_name": "file-openapi.json"},
            payload_summary={"endpoint_count": 1},
            derived_facts={
                "sensitive_actions": [
                    {
                        "action": "export",
                        "provenance_edges": [
                            {
                                "ref": "openapi.paths./files/{file_id}/export.get",
                                "source_type": "openapi",
                                "stage": "target_model",
                                "source_path": "/files/{file_id}/export",
                                "source_method": "get",
                                "fact_type": "sensitive_action",
                            }
                        ],
                    }
                ]
            },
        )
        repository.save_artifact(
            program_id=None,
            asset="api.example.com",
            kind="openapi",
            source_type="dry_run_inline",
            source_hash=sha256(b"team artifact").hexdigest(),
            ingestion_status="normalized",
            provenance={"source_name": "team-openapi.json"},
            payload_summary={"endpoint_count": 1},
            derived_facts={
                "sensitive_actions": [
                    {
                        "action": "invite",
                        "provenance_edges": [
                            {
                                "ref": "openapi.paths./teams/{team_id}/invite.post",
                                "source_type": "openapi",
                                "stage": "target_model",
                                "source_path": "/teams/{team_id}/invite",
                                "source_method": "post",
                                "fact_type": "sensitive_action",
                            }
                        ],
                    }
                ]
            },
        )

        artifacts = repository.list_artifacts(
            provenance_ref="openapi.paths./files/{file_id}/export.get",
            fact_type="sensitive_action",
        )

        assert [artifact.id for artifact in artifacts] == [file_artifact.id]
    finally:
        session.close()


def test_list_artifacts_filters_by_program_asset_source_type_and_status():
    session = build_session()
    try:
        repository = DatabaseRepository(session)
        matching = repository.save_artifact(
            program_id="program_example",
            asset="api.example.com",
            kind="openapi",
            source_type="dry_run_inline",
            source_hash=sha256(b"matching artifact").hexdigest(),
            ingestion_status="normalized",
            provenance={"source_name": "matching-openapi.json"},
            payload_summary={"endpoint_count": 1},
            derived_facts={"paths": ["/files/{file_id}/export"]},
        )
        repository.save_artifact(
            program_id="other_program",
            asset="api.example.com",
            kind="openapi",
            source_type="dry_run_inline",
            source_hash=sha256(b"other program").hexdigest(),
            ingestion_status="normalized",
            provenance={"source_name": "other-program.json"},
            payload_summary={"endpoint_count": 1},
            derived_facts={"paths": ["/files/{file_id}/export"]},
        )
        repository.save_artifact(
            program_id="program_example",
            asset="app.example.com",
            kind="openapi",
            source_type="manual_upload",
            source_hash=sha256(b"other source").hexdigest(),
            ingestion_status="failed",
            provenance={"source_name": "other-source.json"},
            payload_summary={"endpoint_count": 1},
            derived_facts={"paths": ["/teams/{team_id}"]},
        )

        artifacts = repository.list_artifacts(
            program_id="program_example",
            asset="api.example.com",
            source_type="dry_run_inline",
            ingestion_status="normalized",
        )

        assert [artifact.id for artifact in artifacts] == [matching.id]
    finally:
        session.close()


def test_list_artifacts_matches_safe_asset_without_query_broadening_scope():
    session = build_session()
    try:
        repository = DatabaseRepository(session)
        matching = repository.save_artifact(
            program_id="program_example",
            asset="https://api.example.com/path?session=secret",
            kind="openapi",
            source_type="dry_run_inline",
            source_hash=sha256(b"matching path artifact").hexdigest(),
            ingestion_status="normalized",
            provenance={"source_name": "matching-openapi.json"},
            payload_summary={"endpoint_count": 1},
            derived_facts={"paths": ["/path"]},
        )
        repository.save_artifact(
            program_id="program_example",
            asset="https://api.example.com/other?session=secret",
            kind="openapi",
            source_type="dry_run_inline",
            source_hash=sha256(b"other path artifact").hexdigest(),
            ingestion_status="normalized",
            provenance={"source_name": "other-path-openapi.json"},
            payload_summary={"endpoint_count": 1},
            derived_facts={"paths": ["/other"]},
        )
        repository.save_artifact(
            program_id="program_example",
            asset="https://evil.example.com/path?session=secret",
            kind="openapi",
            source_type="dry_run_inline",
            source_hash=sha256(b"other host artifact").hexdigest(),
            ingestion_status="normalized",
            provenance={"source_name": "other-host-openapi.json"},
            payload_summary={"endpoint_count": 1},
            derived_facts={"paths": ["/path"]},
        )

        artifacts = repository.list_artifacts(
            program_id="program_example",
            asset="api.example.com/path?session=secret",
        )

        assert matching.asset == "api.example.com/path"
        assert [artifact.id for artifact in artifacts] == [matching.id]
        assert "session=secret" not in json.dumps(
            [
                {
                    "asset": artifact.asset,
                    "provenance": artifact.provenance,
                    "payload_summary": artifact.payload_summary,
                    "derived_facts": artifact.derived_facts,
                }
                for artifact in artifacts
            ]
        )
    finally:
        session.close()


def test_list_artifacts_filters_by_safety_metadata():
    session = build_session()
    try:
        repository = DatabaseRepository(session)
        safe_artifact = repository.save_artifact(
            program_id=None,
            asset="api.example.com",
            kind="notes",
            source_type="manual_upload",
            source_hash=sha256(b"safe notes").hexdigest(),
            ingestion_status="normalized",
            provenance={"source_name": "safe-notes.md"},
            payload_summary={"endpoint_count": 1},
            derived_facts={"paths": ["/files/{file_id}/export"]},
        )
        sensitive_artifact = repository.save_artifact(
            program_id=None,
            asset="api.example.com",
            kind="har",
            source_type="manual_upload",
            source_hash=sha256(b"sensitive capture").hexdigest(),
            ingestion_status="normalized",
            provenance={"source_name": "sensitive.har"},
            payload_summary={"header": "Authorization: Bearer live-token"},
            derived_facts={"notes": ["customer data in fixture"]},
        )

        sensitive_artifacts = repository.list_artifacts(
            sensitivity_label="sensitive",
            redaction_status="redacted",
            report_chain_allowed=False,
        )
        safe_artifacts = repository.list_artifacts(
            sensitivity_label="low",
            report_chain_allowed=True,
        )

        assert [artifact.id for artifact in sensitive_artifacts] == [sensitive_artifact.id]
        assert [artifact.id for artifact in safe_artifacts] == [safe_artifact.id]
    finally:
        session.close()
