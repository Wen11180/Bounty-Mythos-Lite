"""Control-center endpoints (overview + SSE event stream)."""

from fastapi import APIRouter, Depends, Header, HTTPException, Query
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session

from app.control_center import (
    ControlCenterCampaignNotFound,
    ControlCenterOverviewResponse,
    build_control_center_overview,
)
from app.control_center.events import stream_control_center_events
from app.db import get_session
from app.repository import DatabaseRepository

router = APIRouter(prefix="/mythos/control-center", tags=["control-center"])


# NOTE: /overview is registered in main.py until campaigns.py is extracted
# (it needs _campaign_control_center_response from the campaign domain).

@router.get("/events")
def get_mythos_control_center_events(
    campaign_id: str | None = Query(
        default=None,
        min_length=1,
        max_length=128,
        pattern=r"^[A-Za-z0-9_.:-]+$",
    ),
    cursor: str | None = Query(default=None, pattern=r"^[0-9a-f]{64}$"),
    last_event_id: str | None = Header(
        default=None,
        alias="Last-Event-ID",
        pattern=r"^[0-9a-f]{64}$",
    ),
    session: Session = Depends(get_session, scope="function"),
) -> StreamingResponse:
    if campaign_id and DatabaseRepository(session).get_campaign(campaign_id) is None:
        raise HTTPException(status_code=404, detail="Campaign not found")
    resolved_cursor = cursor or last_event_id
    scope = "campaign" if campaign_id else "global"
    return StreamingResponse(
        stream_control_center_events(
            campaign_id=campaign_id,
            cursor=resolved_cursor,
            scope=scope,
        ),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )
