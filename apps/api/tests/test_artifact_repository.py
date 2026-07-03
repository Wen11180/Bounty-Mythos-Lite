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

        session.expire_all()
        fetched = repository.get_artifact(first.id)
        artifacts = repository.list_artifacts()

        assert duplicate.id == first.id
        assert fetched is not None
        assert fetched.provenance == {"source_name": "first-openapi.json"}
        assert fetched.payload_summary == {"endpoint_count": 1}
        assert fetched.derived_facts == {"paths": ["/v1/files"]}
        assert [artifact.id for artifact in artifacts] == [first.id]
    finally:
        session.close()
