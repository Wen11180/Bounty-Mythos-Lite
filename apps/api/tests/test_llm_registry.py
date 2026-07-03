import pytest

from app.llm.base import LLMMode, LLMRequest, LLMResponse, ProviderName
from app.llm.registry import LLMRegistry, UnknownProviderError


class StubProvider:
    name = ProviderName.OPENAI

    def __init__(self):
        self.requests = []

    async def generate(self, request: LLMRequest) -> LLMResponse:
        self.requests.append(request)
        return LLMResponse(
            provider=self.name,
            model=request.model,
            text=f"{request.model}: {request.prompt}",
            mode=request.mode,
            prompt_hash="stub-hash",
            latency_ms=1,
            error=None,
        )


@pytest.mark.anyio
async def test_registry_defaults_to_dry_run_without_calling_provider():
    provider = StubProvider()
    registry = LLMRegistry({ProviderName.OPENAI: provider})

    response = await registry.generate(
        LLMRequest(provider=ProviderName.OPENAI, model="gpt-5.1", prompt="summarize")
    )

    assert response.provider == ProviderName.OPENAI
    assert response.model == "gpt-5.1"
    assert response.mode == LLMMode.DRY_RUN
    assert response.text == "[dry_run:openai:gpt-5.1] mock response"
    assert len(response.prompt_hash) == 64
    assert response.latency_ms >= 0
    assert response.error is None
    assert provider.requests == []


@pytest.mark.anyio
async def test_registry_dry_run_does_not_build_lazy_provider():
    def build_provider():
        raise AssertionError("dry_run should not build the live provider")

    registry = LLMRegistry({ProviderName.OPENAI: build_provider})

    response = await registry.generate(
        LLMRequest(provider=ProviderName.OPENAI, model="gpt-5.1", prompt="summarize")
    )

    assert response.mode == LLMMode.DRY_RUN
    assert response.error is None


@pytest.mark.anyio
async def test_registry_routes_live_request_to_selected_provider():
    provider = StubProvider()
    registry = LLMRegistry({ProviderName.OPENAI: provider})

    response = await registry.generate(
        LLMRequest(
            provider=ProviderName.OPENAI,
            model="gpt-5.1",
            prompt="summarize",
            mode=LLMMode.LIVE,
        )
    )

    assert response.text == "gpt-5.1: summarize"
    assert response.mode == LLMMode.LIVE
    assert provider.requests[0].provider == ProviderName.OPENAI


@pytest.mark.anyio
async def test_registry_rejects_unknown_provider():
    registry = LLMRegistry({})

    with pytest.raises(UnknownProviderError):
        await registry.generate(
            LLMRequest(provider=ProviderName.DEEPSEEK, model="deepseek-chat", prompt="x")
        )
