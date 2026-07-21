from collections import Counter
from collections.abc import Callable
from datetime import UTC, datetime
from hashlib import sha256
import re
from uuid import uuid4

from app.autonomous_research_runtime import tick_autonomous_research_campaign
from app.repository import (
    AUTONOMOUS_RESEARCH_WAKEUP_LEASE_SECONDS,
    AUTONOMOUS_RESEARCH_WAKEUP_PAGE_SIZE,
    DatabaseRepository,
)


WAKEUP_LEASE_SECONDS = AUTONOMOUS_RESEARCH_WAKEUP_LEASE_SECONDS
_SAFE_STATUS_PATTERN = re.compile(r"[a-z][a-z0-9_:-]{0,127}")
_SAFETY_FIELDS = {
    "execution_allowed": False,
    "dispatch_allowed": False,
    "validation_allowed": False,
    "candidate_promotion_allowed": False,
    "report_submission_allowed": False,
}


def _wakeup_timestamp(now: datetime | None) -> datetime:
    return now or datetime.now(UTC)


def _finish_wakeup(
    *,
    repository: DatabaseRepository,
    claim_token_digest: str,
    after_campaign_id: str | None,
    now: datetime | None,
) -> bool:
    return repository.finish_autonomous_research_wakeup(
        claim_token_digest=claim_token_digest,
        after_campaign_id=after_campaign_id,
        now=_wakeup_timestamp(now),
    )


def run_autonomous_research_wakeup(
    *,
    repository: DatabaseRepository,
    dispatcher: Callable[..., object],
    now: datetime | None = None,
) -> dict:
    timestamp = _wakeup_timestamp(now)
    claim_token_digest = sha256(uuid4().hex.encode("ascii")).hexdigest()
    claim = repository.claim_autonomous_research_wakeup(
        claim_token_digest=claim_token_digest,
        now=timestamp,
    )
    if claim is None:
        return _wakeup_result(
            status="lease_held",
            stop_reason="wakeup_lease_held",
        )

    after_campaign_id = claim["after_campaign_id"]
    try:
        candidates = repository.list_autonomous_wakeup_campaigns(
            after_id=after_campaign_id,
        )
    except Exception:
        repository.session.rollback()
        if not _finish_wakeup(
            repository=repository,
            claim_token_digest=claim_token_digest,
            after_campaign_id=after_campaign_id,
            now=now,
        ):
            return _wakeup_result(status="lease_lost", stop_reason="wakeup_lease_lost")
        return _wakeup_result(status="failed", stop_reason="wakeup_candidate_query_failed")

    outcome_counts: Counter[str] = Counter()
    tick_failed = False
    for candidate in candidates:
        tick_timestamp = _wakeup_timestamp(now)
        if not repository.renew_autonomous_research_wakeup(
            claim_token_digest=claim_token_digest,
            now=tick_timestamp,
        ):
            return _wakeup_result(
                status="lease_lost",
                stop_reason="wakeup_lease_lost",
                processed_count=sum(outcome_counts.values()),
                outcome_counts=outcome_counts,
            )
        campaign_id = candidate.get("id")
        if not isinstance(campaign_id, str) or not campaign_id:
            if not _finish_wakeup(
                repository=repository,
                claim_token_digest=claim_token_digest,
                after_campaign_id=after_campaign_id,
                now=now,
            ):
                return _wakeup_result(
                    status="lease_lost",
                    stop_reason="wakeup_lease_lost",
                    processed_count=sum(outcome_counts.values()),
                    outcome_counts=outcome_counts,
                )
            return _wakeup_result(
                status="failed",
                stop_reason="wakeup_candidate_invalid",
                processed_count=sum(outcome_counts.values()),
                outcome_counts=outcome_counts,
            )
        try:
            outcome = tick_autonomous_research_campaign(
                campaign_id,
                repository=repository,
                dispatcher=dispatcher,
                now=tick_timestamp,
            )
        except Exception:
            # A bad campaign must not starve the remaining safe wakeup page.
            repository.session.rollback()
            tick_failed = True
            outcome_counts["failed"] += 1
            continue
        outcome_counts[_safe_status(outcome.get("status"))] += 1

    next_after_campaign_id = (
        candidates[-1]["id"]
        if len(candidates) == AUTONOMOUS_RESEARCH_WAKEUP_PAGE_SIZE
        else None
    )
    if not _finish_wakeup(
        repository=repository,
        claim_token_digest=claim_token_digest,
        after_campaign_id=next_after_campaign_id,
        now=now,
    ):
        return _wakeup_result(
            status="lease_lost",
            stop_reason="wakeup_lease_lost",
            processed_count=sum(outcome_counts.values()),
            outcome_counts=outcome_counts,
        )
    return _wakeup_result(
        status="completed",
        stop_reason="wakeup_campaign_tick_failed" if tick_failed else None,
        processed_count=sum(outcome_counts.values()),
        outcome_counts=outcome_counts,
    )


def _wakeup_result(
    *,
    status: str,
    stop_reason: str | None,
    processed_count: int = 0,
    outcome_counts: Counter[str] | None = None,
) -> dict:
    return {
        "status": status,
        "stop_reason": stop_reason,
        "processed_count": processed_count,
        "outcome_counts": dict(sorted((outcome_counts or {}).items())),
        **_SAFETY_FIELDS,
    }


def _safe_status(value: object) -> str:
    if isinstance(value, str) and _SAFE_STATUS_PATTERN.fullmatch(value):
        return value
    return "invalid_tick_result"


__all__ = ["WAKEUP_LEASE_SECONDS", "run_autonomous_research_wakeup"]
