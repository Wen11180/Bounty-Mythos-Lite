from hashlib import sha256
import json

from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.db import Base
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
