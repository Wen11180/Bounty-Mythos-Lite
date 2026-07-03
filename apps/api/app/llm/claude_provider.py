from anthropic import AsyncAnthropic

from app.llm.base import LLMMode, LLMProvider, LLMRequest, LLMResponse, ProviderName


class ClaudeProvider(LLMProvider):
    name = ProviderName.CLAUDE

    def __init__(self, api_key: str | None):
        self.api_key = api_key

    async def generate(self, request: LLMRequest) -> LLMResponse:
        if not self.api_key:
            raise RuntimeError("ANTHROPIC_API_KEY is not configured")

        client = AsyncAnthropic(api_key=self.api_key)
        system = request.system_prompt or None
        message = await client.messages.create(
            model=request.model,
            max_tokens=request.max_tokens,
            temperature=request.temperature,
            system=system,
            messages=[{"role": "user", "content": request.prompt}],
        )
        text = "".join(block.text for block in message.content if block.type == "text")
        return LLMResponse(
            provider=self.name,
            model=request.model,
            text=text,
            mode=LLMMode.LIVE,
            prompt_hash="",
            latency_ms=0,
            error=None,
        )
