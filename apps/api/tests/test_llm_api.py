import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.config import get_settings
from app.db import Base, get_session
from app.main import app
from app.repository import DatabaseRepository


client = TestClient(app)


def override_session():
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    testing_session = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)

    def _override_get_session():
        with testing_session() as session:
            yield session

    return _override_get_session, testing_session


@pytest.fixture(autouse=True)
def clear_llm_api_key_env(monkeypatch):
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("DEEPSEEK_API_KEY", raising=False)
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


def test_llm_generate_defaults_to_dry_run_without_api_key():
    response = client.post(
        "/internal/llm/generate",
        json={"provider": "openai", "model": "gpt-5.1", "prompt": "summarize"},
    )

    assert response.status_code == 200
    body = response.json()
    assert body["provider"] == "openai"
    assert body["model"] == "gpt-5.1"
    assert body["text"] == "[dry_run:openai:gpt-5.1] mock response"
    assert body["mode"] == "dry_run"
    assert len(body["prompt_hash"]) == 64
    assert body["latency_ms"] >= 0
    assert body["error"] is None
    assert "summarize" not in body.values()


def test_llm_generate_live_missing_key_returns_clear_error():
    response = client.post(
        "/internal/llm/generate",
        json={
            "provider": "openai",
            "model": "gpt-5.1",
            "prompt": "summarize",
            "mode": "live",
        },
    )

    assert response.status_code == 503
    body = response.json()
    assert body["detail"]["provider"] == "openai"
    assert body["detail"]["model"] == "gpt-5.1"
    assert body["detail"]["text"] == ""
    assert body["detail"]["mode"] == "live"
    assert len(body["detail"]["prompt_hash"]) == 64
    assert body["detail"]["latency_ms"] >= 0
    assert body["detail"]["error"] == "OPENAI_API_KEY is not configured"


def test_llm_generate_rejects_unknown_provider():
    response = client.post(
        "/internal/llm/generate",
        json={"provider": "unknown", "model": "x", "prompt": "summarize"},
    )

    assert response.status_code == 422


def test_llm_generate_persists_audit_record_without_prompt_text():
    override, testing_session = override_session()
    app.dependency_overrides[get_session] = override
    try:
        response = client.post(
            "/internal/llm/generate",
            json={
                "provider": "openai",
                "model": "gpt-5.1",
                "prompt": "Authorization: Bearer live-token; summarize this run",
                "purpose": "hunter_operating_loop",
            },
        )

        assert response.status_code == 200
        body = response.json()

        with testing_session() as session:
            records = DatabaseRepository(session).list_llm_runs()

        assert len(records) == 1
        record = records[0]
        assert record.provider == "openai"
        assert record.model == "gpt-5.1"
        assert record.mode == "dry_run"
        assert record.purpose == "hunter_operating_loop"
        assert record.prompt_hash == body["prompt_hash"]
        assert record.latency_ms >= 0
        assert record.error is None
        assert "no_prompt_storage" in record.safety_notes
        assert "live-token" not in str(record.__dict__)
    finally:
        app.dependency_overrides.clear()
