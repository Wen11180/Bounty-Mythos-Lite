"""Artifact endpoints."""

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.db import get_session
from app.repository import DatabaseRepository
from app.routers._responses import artifact_response
from app.schemas import ArtifactResponse

router = APIRouter(prefix="/mythos/artifacts", tags=["artifacts"])


@router.get("", response_model=list[ArtifactResponse])
def list_mythos_artifacts(
    program_id: str | None = None,
    asset: str | None = None,
    source_type: str | None = None,
    ingestion_status: str | None = None,
    provenance_ref: str | None = None,
    fact_type: str | None = None,
    usage_type: str | None = None,
    usage_run_id: str | None = None,
    sensitivity_label: str | None = None,
    redaction_status: str | None = None,
    report_chain_allowed: bool | None = None,
    session: Session = Depends(get_session),
) -> list[ArtifactResponse]:
    return [
        artifact_response(record)
        for record in DatabaseRepository(session).list_artifacts(
            program_id=program_id,
            asset=asset,
            source_type=source_type,
            ingestion_status=ingestion_status,
            provenance_ref=provenance_ref,
            fact_type=fact_type,
            usage_type=usage_type,
            usage_run_id=usage_run_id,
            sensitivity_label=sensitivity_label,
            redaction_status=redaction_status,
            report_chain_allowed=report_chain_allowed,
        )
    ]


@router.get("/{artifact_id}", response_model=ArtifactResponse)
def get_mythos_artifact(
    artifact_id: str,
    session: Session = Depends(get_session),
) -> ArtifactResponse:
    record = DatabaseRepository(session).get_artifact(artifact_id)
    if record is None:
        raise HTTPException(status_code=404, detail="Artifact not found")
    return artifact_response(record)
