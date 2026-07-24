from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator, Awaitable, Callable
from datetime import UTC, datetime
import json
from typing import Any, Literal

from app.db import get_session_factory
from app.repository import DatabaseRepository

from .service import CampaignResponseBuilder, build_control_center_overview


ControlCenterEventScope = Literal["global", "campaign", "studio"]
Sleep = Callable[[float], Awaitable[None]]


async def stream_control_center_events(
    campaign_id: str | None = None,
    cursor: str | None = None,
    scope: ControlCenterEventScope = "global",
    *,
    session_factory: Callable[[], Any] | None = None,
    clock: Callable[[], datetime] | None = None,
    now: Callable[[], datetime] | None = None,
    sleep: Sleep = asyncio.sleep,
    overview_builder: Callable[..., Any] = build_control_center_overview,
    campaign_response_builder: CampaignResponseBuilder | None = None,
    poll_interval_seconds: float = 2.0,
) -> AsyncIterator[str]:
    factory = session_factory or get_session_factory()
    current_version = cursor
    tick_clock = clock or now or (lambda: datetime.now(UTC))

    while True:
        with factory() as session:
            overview = overview_builder(
                DatabaseRepository(session),
                campaign_id=campaign_id,
                now=tick_clock(),
                campaign_response_builder=campaign_response_builder,
            )
            next_version = overview.snapshot_version

        if next_version == current_version:
            yield ": keepalive\n\n"
        else:
            current_version = next_version
            data = json.dumps(
                {
                    "snapshot_version": next_version,
                    "scope": scope,
                    "changed": ["overview"],
                },
                ensure_ascii=True,
                separators=(",", ":"),
            )
            yield (
                "event: control-center-invalidated\n"
                f"id: {next_version}\n"
                "retry: 5000\n"
                f"data: {data}\n\n"
            )

        await sleep(poll_interval_seconds)
