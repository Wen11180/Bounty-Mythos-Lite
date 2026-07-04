from abc import ABC, abstractmethod
from enum import StrEnum

from pydantic import BaseModel, Field


class ProviderName(StrEnum):
    OPENAI = "openai"
    CLAUDE = "claude"
    DEEPSEEK = "deepseek"


class LLMMode(StrEnum):
    DRY_RUN = "dry_run"
    LIVE = "live"


class LLMRequest(BaseModel):
    provider: ProviderName
    model: str
    prompt: str = Field(min_length=1)
    purpose: str = Field(default="general", max_length=100)
    mode: LLMMode = LLMMode.DRY_RUN
    system_prompt: str | None = None
    temperature: float = Field(default=0.2, ge=0, le=2)
    max_tokens: int = Field(default=1024, ge=1, le=32000)


class LLMResponse(BaseModel):
    provider: ProviderName
    model: str
    text: str
    mode: LLMMode
    prompt_hash: str
    latency_ms: int
    error: str | None = None


class LLMProvider(ABC):
    name: ProviderName

    @abstractmethod
    async def generate(self, request: LLMRequest) -> LLMResponse:
        """Generate text with the selected model provider."""
