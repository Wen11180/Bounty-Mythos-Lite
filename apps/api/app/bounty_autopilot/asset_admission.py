"""Deterministic asset identity and fail-closed admission for Autopilot."""

from __future__ import annotations

import ipaddress
import json
import re
from enum import Enum
from hashlib import sha256
from typing import Literal
from urllib.parse import urlsplit

from pydantic import Field, field_validator

from app.bounty_autopilot.contracts import StrictContract


_ASSET_ID_PATTERN = re.compile(r"^asset_[0-9a-f]{32}$")


def _is_canonical_path(path: str) -> bool:
    """Accept only a literal URL path with unambiguous segment boundaries."""

    if not path.startswith("/"):
        return False
    if any(char in path for char in ("\\", "?", "#", "\x00", "%")):
        return False
    return not any(segment in {".", ".."} for segment in path.split("/"))


class AssetProvenance(str, Enum):
    SEED = "seed"
    DISCOVERED = "discovered"
    LINKED = "linked"


class AdmissionDecision(str, Enum):
    ADMITTED = "admitted"
    EXCLUDED = "excluded"
    NEEDS_SCOPE_REVIEW = "needs_scope_review"
    IDENTITY_STALE = "identity_stale"


class AssetIdentity(StrictContract):
    scheme: Literal["http", "https"]
    host: str = Field(min_length=1, max_length=253)
    port: int = Field(ge=1, le=65535)
    path_authority: str = Field(min_length=1, max_length=1024)
    provenance: AssetProvenance

    @field_validator("host")
    @classmethod
    def normalize_host(cls, value: str) -> str:
        host = value.strip().lower().rstrip(".")
        if not host or " " in host or "/" in host:
            raise ValueError("invalid_host")
        return host

    @field_validator("path_authority")
    @classmethod
    def normalize_path(cls, value: str) -> str:
        path = value if value.startswith("/") else f"/{value}"
        if not _is_canonical_path(path):
            raise ValueError("unsafe_path_prefix")
        return path or "/"


class ScopeMatcher(StrictContract):
    include_hosts: tuple[str, ...] = Field(default_factory=tuple, max_length=64)
    exclude_hosts: tuple[str, ...] = Field(default_factory=tuple, max_length=64)
    include_path_prefixes: tuple[str, ...] = Field(default_factory=tuple, max_length=64)
    exclude_path_prefixes: tuple[str, ...] = Field(default_factory=tuple, max_length=64)
    scope_snapshot_digest: str = Field(min_length=1, max_length=100)

    @field_validator(
        "include_hosts",
        "exclude_hosts",
        "include_path_prefixes",
        "exclude_path_prefixes",
        mode="before",
    )
    @classmethod
    def as_tuple(cls, value):
        if value is None:
            return ()
        if isinstance(value, list):
            return tuple(value)
        return value


class NetworkIdentityObservation(StrictContract):
    dns_names: tuple[str, ...] = Field(default_factory=tuple, max_length=32)
    cname_chain: tuple[str, ...] = Field(default_factory=tuple, max_length=16)
    resolved_ips: tuple[str, ...] = Field(default_factory=tuple, max_length=32)

    @field_validator("resolved_ips")
    @classmethod
    def validate_ips(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        normalized: list[str] = []
        for value in values:
            ip = ipaddress.ip_address(value)
            normalized.append(str(ip))
        return tuple(sorted(set(normalized)))

    @field_validator("dns_names", "cname_chain", mode="before")
    @classmethod
    def as_tuple(cls, value):
        if value is None:
            return ()
        if isinstance(value, list):
            return tuple(value)
        return value


class AssetAdmissionRecord(StrictContract):
    asset_id: str
    identity: AssetIdentity
    identity_digest: str
    decision: AdmissionDecision
    scope_snapshot_digest: str
    network: NetworkIdentityObservation
    source: str = Field(min_length=1, max_length=64)
    first_seen_at: str = Field(min_length=1, max_length=64)
    last_seen_at: str = Field(min_length=1, max_length=64)
    reason: str = Field(min_length=1, max_length=128)

    @field_validator("asset_id")
    @classmethod
    def require_asset_id(cls, value: str) -> str:
        if _ASSET_ID_PATTERN.fullmatch(value) is None:
            raise ValueError("invalid_asset_id")
        return value


def canonicalize_asset_identity(identity: AssetIdentity) -> dict:
    return {
        "scheme": identity.scheme,
        "host": identity.host,
        "port": identity.port,
        "path_authority": identity.path_authority,
        "provenance": identity.provenance.value,
    }


def compute_identity_digest(identity: AssetIdentity) -> str:
    payload = canonicalize_asset_identity(identity)
    serialized = json.dumps(payload, ensure_ascii=True, separators=(",", ":"), sort_keys=True)
    return f"sha256:{sha256(serialized.encode('utf-8')).hexdigest()}"


def compute_asset_id(identity: AssetIdentity) -> str:
    digest = compute_identity_digest(identity).removeprefix("sha256:")
    return f"asset_{digest[:32]}"


def parse_asset_url(
    url: str,
    *,
    provenance: AssetProvenance,
    default_path: str = "/",
) -> AssetIdentity:
    parsed = urlsplit(url.strip())
    if parsed.scheme not in {"http", "https"}:
        raise ValueError("unsupported_scheme")
    if not parsed.hostname:
        raise ValueError("host_required")
    if parsed.query or parsed.fragment:
        raise ValueError("unsafe_path_prefix")
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    path = parsed.path or default_path
    return AssetIdentity(
        scheme=parsed.scheme,  # type: ignore[arg-type]
        host=parsed.hostname,
        port=port,
        path_authority=path,
        provenance=provenance,
    )


def _host_matches(pattern: str, host: str) -> bool | None:
    pattern = pattern.strip().lower().rstrip(".")
    host = host.strip().lower().rstrip(".")
    if not pattern or not host:
        return None
    if pattern.startswith("*.") and pattern.count("*") == 1:
        suffix = pattern[1:]
        return host.endswith(suffix)
    if "*" in pattern:
        return None
    return pattern == host


def _path_matches(prefix: str, path: str) -> bool | None:
    if not _is_canonical_path(prefix) or not _is_canonical_path(path):
        return None
    normalized = prefix.rstrip("/") or "/"
    if path == normalized:
        return True
    return normalized == "/" or path.startswith(f"{normalized}/")


def decide_admission(
    identity: AssetIdentity,
    matcher: ScopeMatcher,
    *,
    network: NetworkIdentityObservation | None = None,
    previous_identity_digest: str | None = None,
    ownership_known: bool = True,
    scope_snapshot_digest: str | None = None,
    seen_at: str = "1970-01-01T00:00:00+00:00",
) -> AssetAdmissionRecord:
    """Fail-closed admission. Discovery never implies admission."""

    network = network or NetworkIdentityObservation()
    identity_digest = compute_identity_digest(identity)
    asset_id = compute_asset_id(identity)

    if (
        scope_snapshot_digest is not None
        and scope_snapshot_digest != matcher.scope_snapshot_digest
    ):
        decision, reason = AdmissionDecision.NEEDS_SCOPE_REVIEW, "stale_scope"
    elif previous_identity_digest is not None and previous_identity_digest != identity_digest:
        decision, reason = AdmissionDecision.IDENTITY_STALE, "identity_changed"
    elif not ownership_known:
        decision, reason = AdmissionDecision.NEEDS_SCOPE_REVIEW, "unknown_ownership"
    else:
        decision, reason = _match_scope(identity, matcher)

    return AssetAdmissionRecord(
        asset_id=asset_id,
        identity=identity,
        identity_digest=identity_digest,
        decision=decision,
        scope_snapshot_digest=matcher.scope_snapshot_digest,
        network=network,
        source=identity.provenance.value,
        first_seen_at=seen_at,
        last_seen_at=seen_at,
        reason=reason,
    )


def _match_scope(
    identity: AssetIdentity,
    matcher: ScopeMatcher,
) -> tuple[AdmissionDecision, str]:
    for pattern in matcher.exclude_hosts:
        matched = _host_matches(pattern, identity.host)
        if matched is None:
            return AdmissionDecision.NEEDS_SCOPE_REVIEW, "ambiguous_wildcard"
        if matched:
            return AdmissionDecision.EXCLUDED, "exact_exclusion"

    for prefix in matcher.exclude_path_prefixes:
        matched = _path_matches(prefix, identity.path_authority)
        if matched is None:
            return AdmissionDecision.NEEDS_SCOPE_REVIEW, "unsafe_path_prefix"
        if matched:
            return AdmissionDecision.EXCLUDED, "exact_exclusion"

    if matcher.include_hosts:
        host_hit = False
        for pattern in matcher.include_hosts:
            matched = _host_matches(pattern, identity.host)
            if matched is None:
                return AdmissionDecision.NEEDS_SCOPE_REVIEW, "ambiguous_wildcard"
            if matched:
                host_hit = True
        if not host_hit:
            return AdmissionDecision.EXCLUDED, "host_not_included"

    if matcher.include_path_prefixes:
        path_hit = False
        for prefix in matcher.include_path_prefixes:
            matched = _path_matches(prefix, identity.path_authority)
            if matched is None:
                return AdmissionDecision.NEEDS_SCOPE_REVIEW, "unsafe_path_prefix"
            if matched:
                path_hit = True
        if not path_hit:
            return AdmissionDecision.EXCLUDED, "path_not_included"

    if not matcher.include_hosts and not matcher.include_path_prefixes:
        return AdmissionDecision.NEEDS_SCOPE_REVIEW, "empty_scope"

    return AdmissionDecision.ADMITTED, "admitted"


def is_active_plan_asset_eligible(
    record: AssetAdmissionRecord,
    *,
    current_scope_snapshot_digest: str,
) -> bool:
    return (
        record.decision is AdmissionDecision.ADMITTED
        and record.scope_snapshot_digest == current_scope_snapshot_digest
    )


__all__ = [
    "AdmissionDecision",
    "AssetAdmissionRecord",
    "AssetIdentity",
    "AssetProvenance",
    "NetworkIdentityObservation",
    "ScopeMatcher",
    "compute_asset_id",
    "compute_identity_digest",
    "decide_admission",
    "is_active_plan_asset_eligible",
    "parse_asset_url",
]
