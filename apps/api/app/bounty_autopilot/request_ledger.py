"""Request reservation ledger for Autopilot execution."""

from __future__ import annotations

from enum import Enum
from typing import Literal

from pydantic import Field, field_validator, model_validator

from app.bounty_autopilot.contracts import DIGEST_PATTERN, StrictContract
from app.bounty_autopilot.leases import ExecutionLease, LeaseStatus


class RequestReservationStatus(str, Enum):
    RESERVED = "reserved"
    SENT = "sent"
    COMPLETED = "completed"
    EXPIRED = "expired"
    REVOKED = "revoked"
    AWAITING_HUMAN = "awaiting_human"
    NO_SEND_FAILURE = "no_send_failure"


class RequestReservation(StrictContract):
    reservation_id: str = Field(min_length=1, max_length=128)
    lease_id: str
    plan_id: str
    plan_digest: str
    destination_host: str
    destination_port: int = Field(ge=1, le=65535)
    destination_path: str
    method: str
    mutation_class: str
    body_digest: str | None = None
    idempotency_key: str = Field(min_length=1, max_length=128)
    status: RequestReservationStatus = RequestReservationStatus.RESERVED
    remaining_request_budget: int = Field(ge=0)
    candidate_promotion_allowed: Literal[False] = False
    report_submission_allowed: Literal[False] = False

    @field_validator("plan_digest")
    @classmethod
    def require_plan_digest(cls, value: str) -> str:
        if DIGEST_PATTERN.fullmatch(value) is None:
            raise ValueError("plan_digest_required")
        return value

    @field_validator("body_digest")
    @classmethod
    def require_body_digest(cls, value: str | None) -> str | None:
        if value is not None and DIGEST_PATTERN.fullmatch(value) is None:
            raise ValueError("body_digest_invalid")
        return value

    @field_validator("method")
    @classmethod
    def normalize_method(cls, value: str) -> str:
        method = value.upper()
        if method not in {"GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE"}:
            raise ValueError("unknown_http_method")
        return method


class RequestLedger:
    """Process-local ledger used by unit tests and pure validation paths."""

    def __init__(self) -> None:
        self._by_id: dict[str, RequestReservation] = {}
        self._by_idempotency: dict[tuple[str, str], str] = {}

    def reserve(
        self,
        *,
        lease: ExecutionLease,
        reservation: RequestReservation,
    ) -> RequestReservation:
        if lease.status is not LeaseStatus.ACTIVE or lease.emergency_stopped:
            raise ValueError("lease_not_active")
        if reservation.lease_id != lease.lease_id:
            raise ValueError("lease_mismatch")
        if reservation.plan_digest != lease.plan_digest:
            raise ValueError("plan_digest_mismatch")
        if lease.requests_reserved >= lease.max_requests:
            raise ValueError("request_budget_exhausted")
        key = (lease.lease_id, reservation.idempotency_key)
        existing_id = self._by_idempotency.get(key)
        if existing_id is not None:
            return self._by_id[existing_id]
        self._by_id[reservation.reservation_id] = reservation
        self._by_idempotency[key] = reservation.reservation_id
        return reservation

    def complete(
        self,
        reservation_id: str,
        *,
        outcome: RequestReservationStatus,
    ) -> RequestReservation:
        current = self._by_id.get(reservation_id)
        if current is None:
            raise ValueError("reservation_not_found")
        if current.status is RequestReservationStatus.COMPLETED:
            return current
        updated = current.model_copy(update={"status": outcome})
        self._by_id[reservation_id] = updated
        return updated

    def get(self, reservation_id: str) -> RequestReservation | None:
        return self._by_id.get(reservation_id)

    def may_retry(self, reservation_id: str, *, method: str) -> bool:
        current = self._by_id.get(reservation_id)
        if current is None:
            return False
        if current.status is RequestReservationStatus.AWAITING_HUMAN:
            return False
        if current.status is RequestReservationStatus.NO_SEND_FAILURE:
            return method.upper() in {"GET", "HEAD", "OPTIONS"}
        return False


__all__ = [
    "RequestLedger",
    "RequestReservation",
    "RequestReservationStatus",
]
