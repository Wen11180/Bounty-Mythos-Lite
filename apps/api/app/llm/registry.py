from collections.abc import Callable, Mapping
from hashlib import sha256
from time import perf_counter

from app.config import get_settings
from app.llm.base import LLMMode, LLMProvider, LLMRequest, LLMResponse, ProviderName


ProviderFactory = Callable[[], LLMProvider]


class UnknownProviderError(ValueError):
    pass


class LLMRegistry:
    def __init__(self, providers: Mapping[ProviderName, LLMProvider | ProviderFactory]):
        self._providers = dict(providers)

    async def generate(self, request: LLMRequest) -> LLMResponse:
        started_at = perf_counter()
        prompt_hash = hash_prompt(request.prompt)
        provider_or_factory = self._providers.get(request.provider)
        if provider_or_factory is None:
            raise UnknownProviderError(f"Unknown LLM provider: {request.provider}")

        if request.mode == LLMMode.DRY_RUN:
            return LLMResponse(
                provider=request.provider,
                model=request.model,
                text=f"[dry_run:{request.provider}:{request.model}] mock response",
                mode=request.mode,
                prompt_hash=prompt_hash,
                latency_ms=elapsed_ms(started_at),
                error=None,
            )

        provider = (
            provider_or_factory
            if hasattr(provider_or_factory, "generate")
            else provider_or_factory()
        )
        try:
            response = await provider.generate(request)
        except RuntimeError as exc:
            return LLMResponse(
                provider=request.provider,
                model=request.model,
                text="",
                mode=request.mode,
                prompt_hash=prompt_hash,
                latency_ms=elapsed_ms(started_at),
                error=str(exc),
            )
        return response.model_copy(
            update={
                "mode": request.mode,
                "prompt_hash": prompt_hash,
                "latency_ms": elapsed_ms(started_at),
                "error": None,
            }
        )


def hash_prompt(prompt: str) -> str:
    return sha256(prompt.encode("utf-8")).hexdigest()


def elapsed_ms(started_at: float) -> int:
    return round((perf_counter() - started_at) * 1000)


def build_default_registry() -> LLMRegistry:
    settings = get_settings()
    return LLMRegistry(
        {
            ProviderName.OPENAI: lambda: _build_openai_provider(settings.openai_api_key),
            ProviderName.CLAUDE: lambda: _build_claude_provider(settings.anthropic_api_key),
            ProviderName.DEEPSEEK: lambda: _build_deepseek_provider(settings.deepseek_api_key),
        }
    )


def _build_openai_provider(api_key: str | None) -> LLMProvider:
    from app.llm.openai_provider import OpenAIProvider

    return OpenAIProvider(api_key)


def _build_claude_provider(api_key: str | None) -> LLMProvider:
    from app.llm.claude_provider import ClaudeProvider

    return ClaudeProvider(api_key)


def _build_deepseek_provider(api_key: str | None) -> LLMProvider:
    from app.llm.deepseek_provider import DeepSeekProvider

    return DeepSeekProvider(api_key)
