from hashlib import sha256
import json

from sqlalchemy import create_engine
from sqlalchemy import text
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.db import Base
from app.repository import DatabaseRepository


def build_session():
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    return sessionmaker(bind=engine)()


def test_save_pipeline_run_persists_payload_and_is_listed():
    session = build_session()
    try:
        repository = DatabaseRepository(session)
        payload = {
            "scope_rule": {"scope_status": "in_scope"},
            "hypotheses": [{"id": "hypothesis-1"}],
            "report_draft": {"title": "Private file export bypass"},
        }

        saved = repository.save_pipeline_run(
            asset="api.example.com",
            policy_text="In scope: api.example.com. Automation limited.",
            scope_status="in_scope",
            hypothesis_count=1,
            blocked_count=1,
            report_title="Private file export bypass",
            payload=payload,
        )

        fetched = repository.get_pipeline_run(saved.id)
        runs = repository.list_pipeline_runs()

        assert fetched is not None
        assert fetched.id == saved.id
        assert fetched.asset == "api.example.com"
        assert fetched.payload == payload
        assert fetched.created_at is not None
        assert [run.id for run in runs] == [saved.id]
    finally:
        session.close()


def test_save_pipeline_run_hashes_policy_text_without_storing_plaintext():
    session = build_session()
    try:
        repository = DatabaseRepository(session)
        policy_text = "SECRET POLICY: api.example.com is in scope."

        saved = repository.save_pipeline_run(
            asset="api.example.com",
            policy_text=policy_text,
            scope_status="in_scope",
            hypothesis_count=0,
            blocked_count=0,
            report_title=None,
            payload={
                "policy_text": policy_text,
                "nested": {"policy_text": policy_text, "kept": True},
            },
        )

        session.expire_all()
        record = session.execute(
            text(
                "select id, policy_text_hash, payload from pipeline_runs "
                "where id = :id"
            ),
            {"id": saved.id},
        ).mappings().one()

        assert "policy_text" not in record
        assert record["policy_text_hash"] == sha256(policy_text.encode("utf-8")).hexdigest()
        payload = json.loads(record["payload"])
        serialized_payload = json.dumps(payload)
        assert "policy_text" not in payload
        assert "policy_text" not in payload["nested"]
        assert policy_text not in serialized_payload
    finally:
        session.close()
