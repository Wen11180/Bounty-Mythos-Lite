from openai import AsyncOpenAI

from app.llm.base import LLMMode, LLMProvider, LLMRequest, LLMResponse, ProviderName


class DeepSeekProvider(LLMProvider):
    name = ProviderName.DEEPSEEK

    def __init__(self, api_key: str | None):
        self.api_key = api_key

    async def generate(self, request: LLMRequest) -> LLMResponse:
        if not self.api_key:
            raise RuntimeError("DEEPSEEK_API_KEY is not configured")

        client = AsyncOpenAI(api_key=self.api_key, base_url="https://api.deepseek.com")
        response = await client.chat.completions.create(
            model=request.model,
            temperature=request.temperature,
            max_tokens=request.max_tokens,
            messages=[
                *(
                    [{"role": "system", "content": request.system_prompt}]
                    if request.system_prompt
                    else []
                ),
                {"role": "user", "content": request.prompt},
            ],
        )
        content = response.choices[0].message.content or ""
        return LLMResponse(
            provider=self.name,
            model=request.model,
            text=content,
            mode=LLMMode.LIVE,
            prompt_hash="",
            latency_ms=0,
            error=None,
        )
