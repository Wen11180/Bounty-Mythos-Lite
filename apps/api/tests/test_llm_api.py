import pytest
from fastapi.testclient import TestClient

from app.config import get_settings
from app.main import app


client = TestClient(app)


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
