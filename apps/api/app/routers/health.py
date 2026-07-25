"""Health and capability endpoints."""

from fastapi import APIRouter

from app.execution_registry import ToolCapability, default_execution_registry

router = APIRouter()


@router.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "service": "bounty-mythos-api"}


@router.get("/mythos/execution-capabilities", response_model=list[ToolCapability])
def list_mythos_execution_capabilities() -> list[ToolCapability]:
    """Expose registered tool metadata without granting execution authority."""
    return default_execution_registry().list_capabilities()
