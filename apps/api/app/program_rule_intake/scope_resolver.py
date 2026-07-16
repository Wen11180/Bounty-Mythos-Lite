"""Fail-closed resolution of approved public program rules for Scope Guard."""

from datetime import UTC, datetime, timedelta
import re
from typing import Any
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict

from app.db_models import ProgramScopeRuleRecord
from app.program_rule_intake.contracts import canonicalize_public_https_url
from app.repository import DatabaseRepository
from app.scope_guard import ScopeGuardRule


SOURCE_STALE_AFTER = timedelta(hours=72)
_SPECIFICITY = {
    "wildcard_host": 1,
    "exact_host": 2,
    "api_base_path": 3,
    "url_prefix": 4,
}
_ENCODED_PATH_AMBIGUITY = re.compile(r"%(?:2e|2f|5c)", re.IGNORECASE)


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class EffectiveRuleProvenance(_StrictModel):
    source_id: str
    approved_snapshot_id: str
    approval_digest: str
    canonical_asset: str
    asset_kind: str
    evidence_refs: list[str]
    rate_limit: dict[str, Any] | None
    warning: str | None = None


class EffectiveProgramRuleResolution(_StrictModel):
    source_backed: bool
    rule: ScopeGuardRule | None = None
    provenance: EffectiveRuleProvenance | None = None
    reason: str | None = None


def resolve_effective_program_rule(
    repository: DatabaseRepository,
    program_id: str,
    asset: str,
    now: datetime,
) -> EffectiveProgramRuleResolution:
    """Resolve only the current approved, non-stale rule for one asset."""

    sources = [
        source
        for source in repository.list_program_rule_sources()
        if source.program_id == program_id
    ]
    if not sources:
        return EffectiveProgramRuleResolution(source_backed=False)
    if len(sources) != 1:
        return _blocked("program_rule_source_conflict")
    source = sources[0]

    if source.approved_snapshot_id is None:
        return _blocked("program_rule_approval_required")
    if (
        source.pending_snapshot_id is not None
        and source.pending_snapshot_id != source.approved_snapshot_id
    ):
        return _blocked("program_rule_change_requires_review")
    timestamp = _as_utc(now)
    if (
        source.last_success_at is None
        or _as_utc(source.last_success_at) > timestamp
        or timestamp - _as_utc(source.last_success_at) >= SOURCE_STALE_AFTER
    ):
        return _blocked("program_rule_source_stale")

    snapshot = repository.get_program_rule_snapshot(source.approved_snapshot_id)
    if (
        snapshot is None
        or snapshot.source_id != source.id
        or snapshot.review_status != "approved"
    ):
        return _blocked("program_rule_approval_required")

    records = repository.list_program_scope_rules(
        program_id,
        approved_snapshot_id=snapshot.id,
    )
    if not records:
        return _blocked("program_rule_rule_not_authorizing")
    if any(
        record.source_id != source.id
        or record.approval_digest != snapshot.review_digest
        or not record.source_evidence_refs
        for record in records
    ):
        return _blocked("program_rule_provenance_invalid")

    matches = [
        (_SPECIFICITY[record.asset_kind], record)
        for record in records
        if record.asset_kind in _SPECIFICITY and _record_matches_asset(record, asset)
    ]
    if not matches:
        return _blocked("program_rule_asset_not_matched")
    highest_specificity = max(specificity for specificity, _ in matches)
    winners = [
        record
        for specificity, record in matches
        if specificity == highest_specificity
    ]
    if len(winners) != 1:
        return _blocked("program_rule_equal_specificity_conflict")

    selected = winners[0]
    warning = "last_refresh_failed" if source.fetch_status == "failed" else None
    return EffectiveProgramRuleResolution(
        source_backed=True,
        rule=ScopeGuardRule(
            asset=asset,
            scope_status=selected.scope_status,
            automation=selected.automation,
            allowed_validation=sorted(set(selected.allowed_validation)),
            forbidden=sorted(set(selected.prohibited)),
            human_approval_required=True,
        ),
        provenance=EffectiveRuleProvenance(
            source_id=source.id,
            approved_snapshot_id=snapshot.id,
            approval_digest=selected.approval_digest,
            canonical_asset=selected.canonical_asset,
            asset_kind=selected.asset_kind,
            evidence_refs=sorted(set(selected.source_evidence_refs)),
            rate_limit=selected.rate_limit,
            warning=warning,
        ),
    )


def intersect_scope_guard_rules(
    stored: ScopeGuardRule,
    current: ScopeGuardRule,
    *,
    asset: str,
) -> ScopeGuardRule:
    """Intersect a stored/caller rule with current authority without widening."""

    asset_matches = stored.asset == asset and current.asset == asset
    if not asset_matches or "out_of_scope" in {
        stored.scope_status,
        current.scope_status,
    }:
        scope_status = "out_of_scope"
    elif stored.scope_status == current.scope_status == "in_scope":
        scope_status = "in_scope"
    else:
        scope_status = "needs_review"

    if stored.automation == current.automation:
        automation = stored.automation
    elif "none" in {stored.automation, current.automation}:
        automation = "none"
    else:
        automation = "needs_review"

    allowed_validation = sorted(
        set(stored.allowed_validation) & set(current.allowed_validation)
    )
    if not asset_matches or scope_status != "in_scope":
        allowed_validation = []
    return ScopeGuardRule(
        asset=asset,
        scope_status=scope_status,
        automation=automation,
        allowed_validation=allowed_validation,
        forbidden=sorted(set(stored.forbidden) | set(current.forbidden)),
        human_approval_required=(
            stored.human_approval_required or current.human_approval_required
        ),
    )


def _blocked(reason: str) -> EffectiveProgramRuleResolution:
    return EffectiveProgramRuleResolution(
        source_backed=True,
        reason=reason,
    )


def _record_matches_asset(record: ProgramScopeRuleRecord, asset: str) -> bool:
    if record.asset_kind == "exact_host":
        return _asset_host(asset) == record.canonical_asset.lower()
    if record.asset_kind == "wildcard_host":
        host = _asset_host(asset)
        suffix = record.canonical_asset[2:].lower()
        return host is not None and host != suffix and host.endswith(f".{suffix}")
    if record.asset_kind == "url_prefix":
        return _url_prefix_matches(record.canonical_asset, asset)
    if record.asset_kind == "api_base_path":
        path = _asset_path(asset)
        return path is not None and _path_prefix_matches(
            record.canonical_asset,
            path,
        )
    return False


def _asset_host(asset: str) -> str | None:
    parsed = _canonical_asset_url(asset)
    if parsed is not None:
        return parsed.hostname
    if (
        not isinstance(asset, str)
        or not asset
        or any(character in asset for character in "/\\?#@:")
    ):
        return None
    try:
        host = urlsplit(canonicalize_public_https_url(f"https://{asset}/")).hostname
    except ValueError:
        return None
    return host if host is not None and "." in host else None


def _asset_path(asset: str) -> str | None:
    parsed = _canonical_asset_url(asset)
    if parsed is not None:
        return parsed.path or "/"
    if not isinstance(asset, str) or not asset.startswith("/"):
        return None
    try:
        parsed_path = urlsplit(asset)
    except ValueError:
        return None
    if parsed_path.scheme or parsed_path.netloc or parsed_path.fragment:
        return None
    path = parsed_path.path or "/"
    return path if _scope_path_is_safe(path) else None


def _canonical_asset_url(asset: str):
    if not isinstance(asset, str) or not asset.lower().startswith("https://"):
        return None
    try:
        parsed = urlsplit(canonicalize_public_https_url(asset))
    except ValueError:
        return None
    return parsed if _scope_path_is_safe(parsed.path or "/") else None


def _url_prefix_matches(prefix: str, asset: str) -> bool:
    candidate = _canonical_asset_url(asset)
    if candidate is None:
        return False
    expected = _canonical_asset_url(prefix)
    if expected is None:
        return False
    if (
        candidate.scheme,
        candidate.hostname,
        candidate.port or 443,
    ) != (
        expected.scheme,
        expected.hostname,
        expected.port or 443,
    ):
        return False
    if expected.query and candidate.query != expected.query:
        return False
    return _path_prefix_matches(expected.path, candidate.path)


def _path_prefix_matches(prefix: str, path: str) -> bool:
    normalized_prefix = prefix.rstrip("/") or "/"
    normalized_path = path.rstrip("/") or "/"
    if normalized_prefix == "/":
        return normalized_path.startswith("/")
    return normalized_path == normalized_prefix or normalized_path.startswith(
        f"{normalized_prefix}/"
    )


def _scope_path_is_safe(path: str) -> bool:
    return (
        "\\" not in path
        and _ENCODED_PATH_AMBIGUITY.search(path) is None
        and not any(segment in {".", ".."} for segment in path.split("/"))
    )


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


__all__ = [
    "EffectiveProgramRuleResolution",
    "EffectiveRuleProvenance",
    "intersect_scope_guard_rules",
    "resolve_effective_program_rule",
]
