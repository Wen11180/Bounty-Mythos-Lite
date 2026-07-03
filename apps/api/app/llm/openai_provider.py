from openai import AsyncOpenAI

from app.llm.base import LLMMode, LLMProvider, LLMRequest, LLMResponse, ProviderName


class OpenAIProvider(LLMProvider):
    name = ProviderName.OPENAI

    def __init__(self, api_key: str | None):
        self.api_key = api_key

    async def generate(self, request: LLMRequest) -> LLMResponse:
        if not self.api_key:
            raise RuntimeError("OPENAI_API_KEY is not configured")

        client = AsyncOpenAI(api_key=self.api_key)
        response = await client.responses.create(
            model=request.model,
            input=request.prompt,
            instructions=request.system_prompt,
            temperature=request.temperature,
            max_output_tokens=request.max_tokens,
        )
        return LLMResponse(
            provider=self.name,
            model=request.model,
            text=response.output_text,
            mode=LLMMode.LIVE,
            prompt_hash="",
            latency_ms=0,
            error=None,
        )
