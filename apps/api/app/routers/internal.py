"""Internal endpoints (LLM proxy)."""

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.db import get_session
from app.llm.base import LLMRequest, LLMResponse
from app.llm.registry import UnknownProviderError, build_default_registry
from app.repository import DatabaseRepository
from app.routers._shared import _llm_audit_safety_notes

router = APIRouter(prefix="/internal", tags=["internal"])


@router.post("/llm/generate", response_model=LLMResponse)
async def generate_with_llm(
    request: LLMRequest,
    session: Session = Depends(get_session),
) -> LLMResponse:
    registry = build_default_registry()
    try:
        response = await registry.generate(request)
    except UnknownProviderError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    DatabaseRepository(session).save_llm_run(
        provider=response.provider,
        model=response.model,
        purpose=request.purpose,
        prompt_hash=response.prompt_hash,
        mode=response.mode,
        latency_ms=response.latency_ms,
        error=response.error,
        safety_notes=_llm_audit_safety_notes(response),
    )
    if response.error:
        raise HTTPException(status_code=503, detail=response.model_dump(mode="json"))
    return response
