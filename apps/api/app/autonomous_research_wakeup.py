from collections import Counter
from collections.abc import Callable
from datetime import UTC, datetime
from hashlib import sha256
import re
from threading import Event, Lock, Thread
from typing import Any
from uuid import uuid4

from sqlalchemy.orm import sessionmaker

from app.autonomous_research_runtime import tick_autonomous_research_campaign
from app.repository import (
    AUTONOMOUS_RESEARCH_WAKEUP_INTERVAL_SECONDS,
    AUTONOMOUS_RESEARCH_WAKEUP_LEASE_SECONDS,
    AUTONOMOUS_RESEARCH_WAKEUP_PAGE_SIZE,
    DatabaseRepository,
)


WAKEUP_LEASE_SECONDS = AUTONOMOUS_RESEARCH_WAKEUP_LEASE_SECONDS
WAKEUP_INTERVAL_SECONDS = AUTONOMOUS_RESEARCH_WAKEUP_INTERVAL_SECONDS
WAKEUP_HEALTH_STALE_AFTER_SECONDS = WAKEUP_INTERVAL_SECONDS * 3
_SAFE_STATUS_PATTERN = re.compile(r"[a-z][a-z0-9_:-]{0,127}")
_SHA256_DIGEST_PATTERN = re.compile(r"[a-f0-9]{64}")
_FINAL_CYCLE_STATUSES = frozenset({"completed", "failed"})
_FINAL_CYCLE_STOP_REASONS = frozenset(
    {
        "wakeup_candidate_invalid",
        "wakeup_candidate_query_failed",
        "wakeup_campaign_tick_failed",
    }
)
_SAFETY_FIELDS = {
    "execution_allowed": False,
    "dispatch_allowed": False,
    "validation_allowed": False,
    "candidate_promotion_allowed": False,
    "report_submission_allowed": False,
}
_IN_MEMORY_WAKEUP_LOCK = Lock()


class _WakeupLeaseHeartbeat:
    def __init__(
        self,
        *,
        repository: DatabaseRepository,
        claim_token_digest: str,
    ) -> None:
        self._claim_token_digest = claim_token_digest
        self._session_factory = sessionmaker(
            bind=repository.session.get_bind(),
            autoflush=False,
            expire_on_commit=False,
        )
        self._stopped = Event()
        self._lease_lost = Event()
        self._thread: Thread | None = None

    def start(self) -> None:
        self._thread = Thread(
            target=self._renew_until_stopped,
            daemon=True,
            name="autonomous-research-wakeup-heartbeat",
        )
        self._thread.start()

    def stop(self) -> bool:
        self._stopped.set()
        if self._thread is not None:
            self._thread.join()
        return not self._lease_lost.is_set()

    def _renew_until_stopped(self) -> None:
        while not self._stopped.wait(_wakeup_lease_heartbeat_interval_seconds()):
            try:
                with self._session_factory() as session:
                    renewed = DatabaseRepository(
                        session
                    ).renew_autonomous_research_wakeup(
                        claim_token_digest=self._claim_token_digest,
                        now=datetime.now(UTC),
                    )
            except Exception:
                # A transient database lock must not falsely declare a lost lease.
                # The next heartbeat or the owner check after the tick is authoritative.
                continue
            if not renewed:
                self._lease_lost.set()
                return


def _wakeup_lease_heartbeat_interval_seconds() -> float:
    return max(0.1, WAKEUP_LEASE_SECONDS / 3)


def _start_wakeup_lease_heartbeat(
    *,
    repository: DatabaseRepository,
    claim_token_digest: str,
    now: datetime | None,
) -> _WakeupLeaseHeartbeat | None:
    if now is not None or _uses_ephemeral_sqlite(repository):
        return None
    heartbeat = _WakeupLeaseHeartbeat(
        repository=repository,
        claim_token_digest=claim_token_digest,
    )
    heartbeat.start()
    return heartbeat


def _uses_ephemeral_sqlite(repository: DatabaseRepository) -> bool:
    bind = repository.session.get_bind()
    engine = getattr(bind, "engine", bind)
    url = getattr(engine, "url", None)
    return (
        getattr(getattr(engine, "dialect", None), "name", None) == "sqlite"
        and getattr(url, "database", None) in {None, "", ":memory:"}
    )


def _wakeup_timestamp(now: datetime | None) -> datetime:
    return now or datetime.now(UTC)


def build_autonomous_research_wakeup_health(
    state: object | None,
    *,
    now: datetime | None = None,
) -> dict[str, Any]:
    timestamp = _as_utc(_wakeup_timestamp(now))
    if state is None:
        return _wakeup_health_result(
            status="not_started",
            last_heartbeat_at=None,
            heartbeat_age_seconds=None,
            lease_active=False,
            lease_expires_at=None,
            has_more_campaigns=False,
            last_cycle=_last_cycle_summary(None),
        )

    last_heartbeat = _safe_timestamp(getattr(state, "updated_at", None))
    lease_started_at = _safe_timestamp(getattr(state, "lease_started_at", None))
    lease_expires_at = _safe_timestamp(getattr(state, "lease_expires_at", None))
    lease_token_digest = getattr(state, "lease_token_digest", None)
    lease_fields_present = any(
        value is not None
        for value in (
            lease_token_digest,
            getattr(state, "lease_started_at", None),
            getattr(state, "lease_expires_at", None),
        )
    )
    lease_is_valid = (
        isinstance(lease_token_digest, str)
        and _SHA256_DIGEST_PATTERN.fullmatch(lease_token_digest) is not None
        and lease_started_at is not None
        and lease_expires_at is not None
        and lease_started_at <= timestamp
        and lease_started_at <= lease_expires_at
    )
    lease_active = lease_is_valid and lease_expires_at > timestamp
    heartbeat_is_future = (
        last_heartbeat is not None and last_heartbeat > timestamp
    )
    heartbeat_age_seconds = (
        max(0, int((timestamp - last_heartbeat).total_seconds()))
        if last_heartbeat is not None and not heartbeat_is_future
        else None
    )
    last_cycle = _last_cycle_summary(state)
    if lease_fields_present and not lease_is_valid:
        status = "invalid_lease"
    elif heartbeat_is_future:
        status = "stale"
    elif lease_active:
        status = "active"
    elif (
        last_cycle["status"] == "failed"
        or last_cycle["stop_reason"] is not None
    ):
        status = "degraded"
    elif lease_fields_present:
        status = "expired_lease"
    elif (
        heartbeat_age_seconds is not None
        and heartbeat_age_seconds <= WAKEUP_HEALTH_STALE_AFTER_SECONDS
    ):
        status = "healthy"
    else:
        status = "stale"
    return _wakeup_health_result(
        status=status,
        last_heartbeat_at=last_heartbeat,
        heartbeat_age_seconds=heartbeat_age_seconds,
        lease_active=lease_active,
        lease_expires_at=lease_expires_at,
        has_more_campaigns=bool(getattr(state, "after_campaign_id", None)),
        last_cycle=last_cycle,
    )


def _wakeup_health_result(
    *,
    status: str,
    last_heartbeat_at: datetime | None,
    heartbeat_age_seconds: int | None,
    lease_active: bool,
    lease_expires_at: datetime | None,
    has_more_campaigns: bool,
    last_cycle: dict[str, Any],
) -> dict[str, Any]:
    return {
        "status": status,
        "last_heartbeat_at": (
            last_heartbeat_at.isoformat() if last_heartbeat_at is not None else None
        ),
        "heartbeat_age_seconds": heartbeat_age_seconds,
        "lease_active": lease_active,
        "lease_expires_at": (
            lease_expires_at.isoformat() if lease_expires_at is not None else None
        ),
        "has_more_campaigns": has_more_campaigns,
        "scheduled_interval_seconds": WAKEUP_INTERVAL_SECONDS,
        "last_cycle_completed_at": last_cycle["completed_at"],
        "last_cycle_status": last_cycle["status"],
        "last_cycle_stop_reason": last_cycle["stop_reason"],
        "last_cycle_processed_count": last_cycle["processed_count"],
        "last_cycle_outcome_counts": last_cycle["outcome_counts"],
        **_SAFETY_FIELDS,
    }


def _last_cycle_summary(state: object | None) -> dict[str, Any]:
    if state is None:
        return {
            "completed_at": None,
            "status": "not_finished",
            "stop_reason": None,
            "processed_count": 0,
            "outcome_counts": {},
        }
    status = getattr(state, "last_cycle_status", None)
    stop_reason = getattr(state, "last_cycle_stop_reason", None)
    processed_count = getattr(state, "last_cycle_processed_count", None)
    outcome_counts = getattr(state, "last_cycle_outcome_counts", None)
    completed_at = _safe_timestamp(getattr(state, "last_cycle_completed_at", None))
    if (
        status not in _FINAL_CYCLE_STATUSES
        or stop_reason not in {None, *_FINAL_CYCLE_STOP_REASONS}
        or not isinstance(processed_count, int)
        or isinstance(processed_count, bool)
        or processed_count < 0
        or processed_count > AUTONOMOUS_RESEARCH_WAKEUP_PAGE_SIZE
        or not isinstance(outcome_counts, dict)
    ):
        return {
            "completed_at": None,
            "status": "not_finished",
            "stop_reason": None,
            "processed_count": 0,
            "outcome_counts": {},
        }
    safe_counts: dict[str, int] = {}
    for outcome_status, count in outcome_counts.items():
        if (
            not isinstance(outcome_status, str)
            or _SAFE_STATUS_PATTERN.fullmatch(outcome_status) is None
            or not isinstance(count, int)
            or isinstance(count, bool)
            or count < 0
            or count > AUTONOMOUS_RESEARCH_WAKEUP_PAGE_SIZE
        ):
            return {
                "completed_at": None,
                "status": "not_finished",
                "stop_reason": None,
                "processed_count": 0,
                "outcome_counts": {},
            }
        safe_counts[outcome_status] = count
    if sum(safe_counts.values()) != processed_count or completed_at is None:
        return {
            "completed_at": None,
            "status": "not_finished",
            "stop_reason": None,
            "processed_count": 0,
            "outcome_counts": {},
        }
    return {
        "completed_at": completed_at.isoformat(),
        "status": status,
        "stop_reason": stop_reason,
        "processed_count": processed_count,
        "outcome_counts": dict(sorted(safe_counts.items())),
    }


def _safe_timestamp(value: object) -> datetime | None:
    return _as_utc(value) if isinstance(value, datetime) else None


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def _finish_wakeup(
    *,
    repository: DatabaseRepository,
    claim_token_digest: str,
    after_campaign_id: str | None,
    now: datetime | None,
    result: dict | None = None,
) -> bool:
    values: dict[str, Any] = {
        "claim_token_digest": claim_token_digest,
        "after_campaign_id": after_campaign_id,
        "now": _wakeup_timestamp(now),
    }
    if result is not None:
        values.update(
            last_cycle_status=result.get("status"),
            last_cycle_stop_reason=result.get("stop_reason"),
            last_cycle_processed_count=result.get("processed_count"),
            last_cycle_outcome_counts=result.get("outcome_counts"),
        )
    return repository.finish_autonomous_research_wakeup(
        **values,
    )


def run_autonomous_research_wakeup(
    *,
    repository: DatabaseRepository,
    dispatcher: Callable[..., object],
    now: datetime | None = None,
) -> dict:
    if not _uses_ephemeral_sqlite(repository):
        return _run_autonomous_research_wakeup(
            repository=repository,
            dispatcher=dispatcher,
            now=now,
        )
    if not _IN_MEMORY_WAKEUP_LOCK.acquire(blocking=False):
        return _wakeup_result(
            status="lease_held",
            stop_reason="wakeup_lease_held",
        )
    try:
        # An in-memory SQLite database cannot supply an independent heartbeat
        # session. The process lock owns this local cycle, so keep one timestamp
        # for its conditional lease updates.
        process_cycle_timestamp = now or datetime.now(UTC)
        return _run_autonomous_research_wakeup(
            repository=repository,
            dispatcher=dispatcher,
            now=now,
            lease_now=process_cycle_timestamp,
        )
    finally:
        _IN_MEMORY_WAKEUP_LOCK.release()


def _run_autonomous_research_wakeup(
    *,
    repository: DatabaseRepository,
    dispatcher: Callable[..., object],
    now: datetime | None = None,
    lease_now: datetime | None = None,
) -> dict:
    lease_clock = lease_now if lease_now is not None else now
    timestamp = _wakeup_timestamp(lease_clock)
    claim_token_digest = sha256(uuid4().hex.encode("ascii")).hexdigest()
    claim = repository.claim_autonomous_research_wakeup(
        claim_token_digest=claim_token_digest,
        now=timestamp,
    )
    if claim is not None and claim["status"] == "not_due":
        return _wakeup_result(
            status="not_due",
            stop_reason="wakeup_not_due",
        )
    if claim is None or claim["status"] != "claimed":
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
        result = _wakeup_result(
            status="failed",
            stop_reason="wakeup_candidate_query_failed",
        )
        if not _finish_wakeup(
            repository=repository,
            claim_token_digest=claim_token_digest,
            after_campaign_id=after_campaign_id,
            now=lease_clock,
            result=result,
        ):
            return _wakeup_result(status="lease_lost", stop_reason="wakeup_lease_lost")
        return result

    outcome_counts: Counter[str] = Counter()
    tick_failed = False
    for candidate in candidates:
        tick_timestamp = _wakeup_timestamp(now)
        lease_timestamp = _wakeup_timestamp(lease_clock)
        if not repository.renew_autonomous_research_wakeup(
            claim_token_digest=claim_token_digest,
            now=lease_timestamp,
        ):
            return _wakeup_result(
                status="lease_lost",
                stop_reason="wakeup_lease_lost",
                processed_count=sum(outcome_counts.values()),
                outcome_counts=outcome_counts,
            )
        campaign_id = candidate.get("id")
        if not isinstance(campaign_id, str) or not campaign_id:
            result = _wakeup_result(
                status="failed",
                stop_reason="wakeup_candidate_invalid",
                processed_count=sum(outcome_counts.values()),
                outcome_counts=outcome_counts,
            )
            if not _finish_wakeup(
                repository=repository,
                claim_token_digest=claim_token_digest,
                after_campaign_id=after_campaign_id,
                now=lease_clock,
                result=result,
            ):
                return _wakeup_result(
                    status="lease_lost",
                    stop_reason="wakeup_lease_lost",
                    processed_count=sum(outcome_counts.values()),
                    outcome_counts=outcome_counts,
                )
            return result
        try:
            heartbeat = _start_wakeup_lease_heartbeat(
                repository=repository,
                claim_token_digest=claim_token_digest,
                now=now,
            )
        except Exception:
            return _wakeup_result(
                status="lease_lost",
                stop_reason="wakeup_lease_lost",
                processed_count=sum(outcome_counts.values()),
                outcome_counts=outcome_counts,
            )

        tick_failed_for_candidate = False
        heartbeat_kept_lease = True
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
            tick_failed_for_candidate = True
            outcome_counts["failed"] += 1
        else:
            outcome_counts[_safe_status(outcome.get("status"))] += 1
        finally:
            if heartbeat is not None:
                heartbeat_kept_lease = heartbeat.stop()

        if heartbeat is not None and (
            not heartbeat_kept_lease
            or not repository.renew_autonomous_research_wakeup(
                claim_token_digest=claim_token_digest,
                now=_wakeup_timestamp(lease_clock),
            )
        ):
            return _wakeup_result(
                status="lease_lost",
                stop_reason="wakeup_lease_lost",
                processed_count=sum(outcome_counts.values()),
                outcome_counts=outcome_counts,
            )
        if tick_failed_for_candidate:
            continue

    next_after_campaign_id = (
        candidates[-1]["id"]
        if len(candidates) == AUTONOMOUS_RESEARCH_WAKEUP_PAGE_SIZE
        else None
    )
    result = _wakeup_result(
        status="completed",
        stop_reason="wakeup_campaign_tick_failed" if tick_failed else None,
        processed_count=sum(outcome_counts.values()),
        outcome_counts=outcome_counts,
    )
    if not _finish_wakeup(
        repository=repository,
        claim_token_digest=claim_token_digest,
        after_campaign_id=next_after_campaign_id,
        now=lease_clock,
        result=result,
    ):
        return _wakeup_result(
            status="lease_lost",
            stop_reason="wakeup_lease_lost",
            processed_count=sum(outcome_counts.values()),
            outcome_counts=outcome_counts,
        )
    return result


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


__all__ = [
    "WAKEUP_HEALTH_STALE_AFTER_SECONDS",
    "WAKEUP_INTERVAL_SECONDS",
    "WAKEUP_LEASE_SECONDS",
    "build_autonomous_research_wakeup_health",
    "run_autonomous_research_wakeup",
]
