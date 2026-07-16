"""Pure contracts shared by program-rule intake layers."""

import ipaddress
import re
import unicodedata
from datetime import datetime
from enum import Enum
from typing import Annotated, Any, Literal
from urllib.parse import SplitResult, parse_qsl, urljoin, urlsplit, urlunsplit

from pydantic import BaseModel, ConfigDict, Field, StringConstraints


MAX_PUBLIC_URL_LENGTH = 2048
Sha256 = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{64}$")]
SafeAlias = Annotated[
    str,
    StringConstraints(pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$"),
]
BoundedProjectionText = Annotated[str, StringConstraints(max_length=8192)]


class StrictContract(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class FetchStatus(str, Enum):
    SCHEDULED = "scheduled"
    FETCHING = "fetching"
    OK = "ok"
    BROWSER_RENDER_REQUIRED = "browser_render_required"
    FAILED = "failed"


class SnapshotReviewStatus(str, Enum):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"


class EffectiveScopeStatus(str, Enum):
    NEEDS_REVIEW = "needs_review"
    ACTIVE = "active"
    FROZEN = "frozen"


class DocumentKind(str, Enum):
    HTML = "html"
    TEXT = "text"
    JSON = "json"
    YAML = "yaml"


class LinkState(str, Enum):
    ELIGIBLE = "eligible"
    REJECTED = "rejected"


class AIStatus(str, Enum):
    NOT_REQUESTED = "not_requested"
    OK = "ok"
    UNAVAILABLE = "unavailable"
    REJECTED = "rejected"


class FetchFailureCode(str, Enum):
    DNS_REJECTED = "dns_rejected"
    REDIRECT_REJECTED = "redirect_rejected"
    CONTENT_REJECTED = "content_rejected"
    BUDGET_EXCEEDED = "budget_exceeded"
    BROWSER_UNAVAILABLE = "browser_unavailable"
    FETCH_FAILED = "fetch_failed"


class CandidateScopeStatus(str, Enum):
    IN_SCOPE = "in_scope"
    OUT_OF_SCOPE = "out_of_scope"
    NEEDS_REVIEW = "needs_review"


class AutomationStatus(str, Enum):
    NONE = "none"
    LIMITED = "limited"
    NEEDS_REVIEW = "needs_review"


class AssetKind(str, Enum):
    EXACT_HOST = "exact_host"
    WILDCARD_HOST = "wildcard_host"
    URL_PREFIX = "url_prefix"
    API_BASE_PATH = "api_base_path"


class RateLimitUnit(str, Enum):
    SECOND = "second"
    MINUTE = "minute"
    HOUR = "hour"
    DAY = "day"


class ExtractionReviewState(str, Enum):
    READY = "ready"
    NEEDS_REVIEW = "needs_review"


class ResponsePermissions(StrictContract):
    execution_allowed: Literal[False] = False
    lease_grant_allowed: Literal[False] = False
    scope_change_allowed: Literal[False] = False
    review_bypass_allowed: Literal[False] = False
    report_submission_allowed: Literal[False] = False


class EvidenceExcerpt(StrictContract):
    evidence_id: Sha256
    document_sha256: Sha256
    locator: str = Field(min_length=1, max_length=200)
    excerpt: str = Field(min_length=1, max_length=500)


class SnapshotReviewRequest(StrictContract):
    reviewer_alias: SafeAlias
    expected_review_digest: Sha256
    operator_confirmed: Literal[True]


class BrowserAnchorInput(StrictContract):
    text: BoundedProjectionText
    href: str = Field(min_length=1, max_length=MAX_PUBLIC_URL_LENGTH)
    is_attachment: bool = False


class RuleDocumentEnvelope(StrictContract):
    source_url: str = Field(min_length=1, max_length=MAX_PUBLIC_URL_LENGTH)
    depth: Literal[0, 1]
    content_type: str = Field(min_length=1, max_length=100)


class StaticRuleDocumentEnvelope(RuleDocumentEnvelope):
    mode: Literal["static"]
    body_base64: str = Field(min_length=1, max_length=3_000_000)
    raw_sha256: Sha256
    charset: str | None = Field(default=None, max_length=40)


class BrowserRuleDocumentEnvelope(RuleDocumentEnvelope):
    mode: Literal["browser"]
    visible_strings: list[BoundedProjectionText]
    tables: list[list[list[BoundedProjectionText]]]
    list_items: list[BoundedProjectionText]
    anchors: list[BrowserAnchorInput]


RuleDocumentEnvelopeInput = Annotated[
    StaticRuleDocumentEnvelope | BrowserRuleDocumentEnvelope,
    Field(discriminator="mode"),
]


class ProgramRuleRegistrationRequest(StrictContract):
    program_alias: SafeAlias
    public_rule_url: str = Field(min_length=1, max_length=MAX_PUBLIC_URL_LENGTH)


class ProgramRuleClaimNormalizeRequest(StrictContract):
    source_id: str = Field(min_length=1, max_length=128)
    claim_token: str = Field(min_length=1, max_length=512)
    document: RuleDocumentEnvelopeInput


class ProgramRuleClaimFailRequest(StrictContract):
    source_id: str = Field(min_length=1, max_length=128)
    claim_token: str = Field(min_length=1, max_length=512)
    failure_code: FetchFailureCode


class NormalizedDocumentLink(StrictContract):
    state: Literal[LinkState.ELIGIBLE] = LinkState.ELIGIBLE
    url: str = Field(min_length=1, max_length=MAX_PUBLIC_URL_LENGTH)
    text: str = Field(max_length=500)
    locator: str = Field(min_length=1, max_length=200)
    depth: Literal[1] = 1


class NormalizedRuleDocument(StrictContract):
    source_url: str = Field(min_length=1, max_length=MAX_PUBLIC_URL_LENGTH)
    depth: Literal[0, 1]
    kind: DocumentKind
    content_type: str = Field(min_length=1, max_length=100)
    raw_sha256: Sha256 | None
    normalized_sha256: Sha256
    detected_language: Literal["en", "unsupported"]
    visible_text: str = Field(max_length=524_288)
    tables: list[list[list[BoundedProjectionText]]]
    list_items: list[BoundedProjectionText]
    eligible_links: list[NormalizedDocumentLink]
    openapi_like: dict[str, Any] | None = None


class ProgramRuleClaimCompleteRequest(StrictContract):
    source_id: str = Field(min_length=1, max_length=128)
    claim_token: str = Field(min_length=1, max_length=512)
    documents: list[dict[str, Any]] = Field(min_length=1, max_length=8)


class StructuredRateLimit(StrictContract):
    requests: int = Field(gt=0, le=1_000_000)
    period: int = Field(default=1, gt=0, le=86_400)
    unit: RateLimitUnit
    evidence_ids: list[Sha256] = Field(min_length=1)


class CandidateScopeRule(StrictContract):
    asset: str = Field(min_length=1, max_length=2048)
    asset_kind: AssetKind
    specificity: int = Field(ge=1, le=4)
    scope_status: CandidateScopeStatus
    automation: AutomationStatus
    allowed_validation: list[str]
    prohibited: list[str]
    rate_limit: StructuredRateLimit | None
    scope_evidence_ids: list[Sha256] = Field(min_length=1)
    automation_evidence_ids: list[Sha256]
    prohibited_evidence_ids: dict[str, list[Sha256]]
    review_state: ExtractionReviewState
    review_issues: list[str]
    human_approval_required: Literal[True] = True


class LinkedArtifactCandidate(StrictContract):
    kind: Literal["openapi"] = "openapi"
    url: str = Field(min_length=1, max_length=MAX_PUBLIC_URL_LENGTH)
    url_sha256: Sha256
    normalized_sha256: Sha256
    openapi_like: dict[str, Any]
    evidence_ids: list[Sha256] = Field(min_length=1)
    promotion_allowed: Literal[False] = False


class DeterministicExtractionResult(StrictContract):
    rules: list[CandidateScopeRule]
    evidence: list[EvidenceExcerpt]
    linked_artifacts: list[LinkedArtifactCandidate]
    review_state: ExtractionReviewState
    review_issues: list[str]
    ai_status: AIStatus = AIStatus.NOT_REQUESTED
    ai_prompt_sha256: Sha256 | None = None
    ai_error_category: Literal["provider_unavailable", "invalid_output"] | None = None


class AdvisoryEvidenceClaim(StrictContract):
    document_sha256: Sha256
    locator: str = Field(min_length=1, max_length=200)
    excerpt: str = Field(min_length=1, max_length=500)


class AdvisoryRateLimitClaim(StrictContract):
    requests: int = Field(gt=0, le=1_000_000)
    period: int = Field(default=1, gt=0, le=86_400)
    unit: RateLimitUnit


class AdvisoryRuleClaim(StrictContract):
    asset: str = Field(min_length=1, max_length=2048)
    asset_kind: AssetKind
    scope_status: CandidateScopeStatus
    automation: AutomationStatus
    prohibited: list[str]
    rate_limit: AdvisoryRateLimitClaim | None
    evidence: list[AdvisoryEvidenceClaim] = Field(min_length=1, max_length=20)


class AdvisoryRuleOutput(StrictContract):
    rules: list[AdvisoryRuleClaim] = Field(max_length=100)


class AdvisoryParsedResult(StrictContract):
    rules: list[CandidateScopeRule]
    evidence: list[EvidenceExcerpt]
    ai_status: Literal[AIStatus.OK] = AIStatus.OK


class ProgramRuleSourceProjection(StrictContract):
    source_id: str = Field(min_length=1, max_length=128)
    program_id: str | None = Field(default=None, max_length=128)
    program_alias: SafeAlias
    registered_url: str = Field(min_length=1, max_length=MAX_PUBLIC_URL_LENGTH)
    canonical_url: str = Field(min_length=1, max_length=MAX_PUBLIC_URL_LENGTH)
    fetch_status: FetchStatus
    effective_scope_status: EffectiveScopeStatus
    warning: str | None = Field(default=None, max_length=500)
    last_success_at: datetime | None
    next_check_at: datetime
    approved_snapshot_id: str | None = Field(default=None, max_length=128)
    pending_snapshot_id: str | None = Field(default=None, max_length=128)


class ProgramRuleClaimLimits(StrictContract):
    max_documents: Literal[8] = 8
    max_document_bytes: Literal[2_097_152] = 2_097_152
    max_total_bytes: Literal[8_388_608] = 8_388_608
    max_normalized_corpus_bytes: Literal[2_097_152] = 2_097_152
    document_timeout_seconds: Literal[10] = 10
    max_depth: Literal[1] = 1


class ProgramRuleFetchClaim(StrictContract):
    claim_id: str = Field(min_length=1, max_length=100)
    source_id: str = Field(min_length=1, max_length=128)
    claim_token: str = Field(min_length=1, max_length=512)
    source_url: str = Field(min_length=1, max_length=MAX_PUBLIC_URL_LENGTH)
    expires_at: datetime
    limits: ProgramRuleClaimLimits = Field(default_factory=ProgramRuleClaimLimits)


class ProgramRuleClaimNextResult(StrictContract):
    claim: ProgramRuleFetchClaim | None
    next_due_at: datetime | None


class ProgramRuleSnapshotProjection(ResponsePermissions):
    snapshot_id: str = Field(min_length=1, max_length=128)
    source_id: str = Field(min_length=1, max_length=128)
    raw_aggregate_sha256: Sha256
    normalized_sha256: Sha256
    fetched_at: datetime
    fetch_mode: str = Field(min_length=1, max_length=50)
    content_types: list[str]
    detected_language: str = Field(min_length=1, max_length=50)
    extraction: dict[str, Any]
    evidence: list[dict[str, Any]]
    linked_documents: list[dict[str, Any]]
    openapi_candidates: list[dict[str, Any]]
    ai_status: AIStatus
    review_status: SnapshotReviewStatus
    reviewer_alias: str | None = Field(default=None, max_length=100)
    reviewed_at: datetime | None
    review_digest: Sha256
    artifact_warning: Literal["openapi_promotion_pending"] | None = None


class ProgramScopeRuleProjection(ResponsePermissions):
    rule_id: str = Field(min_length=1, max_length=128)
    program_id: str = Field(min_length=1, max_length=128)
    source_id: str = Field(min_length=1, max_length=128)
    approved_snapshot_id: str = Field(min_length=1, max_length=128)
    canonical_asset: str = Field(min_length=1, max_length=MAX_PUBLIC_URL_LENGTH)
    asset_kind: AssetKind
    source_evidence_refs: list[Sha256]
    scope_status: CandidateScopeStatus
    automation: AutomationStatus
    allowed_validation: list[str]
    prohibited: list[str]
    rate_limit: dict[str, Any] | None
    approval_digest: Sha256
    effective_at: datetime
    effective_scope_status: EffectiveScopeStatus
    warning: str | None = Field(default=None, max_length=500)


class CandidateRuleModification(StrictContract):
    asset: str = Field(min_length=1, max_length=2048)
    before: CandidateScopeRule
    after: CandidateScopeRule


class ProgramRuleSnapshotDiff(ResponsePermissions):
    source_id: str = Field(min_length=1, max_length=128)
    approved_snapshot_id: str | None = Field(default=None, max_length=128)
    pending_snapshot_id: str = Field(min_length=1, max_length=128)
    added_rules: list[CandidateScopeRule]
    removed_rules: list[CandidateScopeRule]
    modified_rules: list[CandidateRuleModification]
    added_prohibitions: list[str]
    removed_prohibitions: list[str]
    added_linked_artifacts: list[LinkedArtifactCandidate]
    removed_linked_artifacts: list[LinkedArtifactCandidate]
    review_digest: Sha256

_DNS_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z")
_ENCODED_CONTROL = re.compile(r"%(?:0[0-9a-f]|1[0-9a-f]|7f)", re.IGNORECASE)
_JWT = re.compile(r"[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{2,}\.[A-Za-z0-9_-]{6,}\Z")
_SECRET_QUERY_KEYS = {
    "accesstoken",
    "apikey",
    "auth",
    "authorization",
    "cookie",
    "credential",
    "jwt",
    "password",
    "secret",
    "session",
    "sessionid",
    "token",
}
_SECRET_VALUE_PREFIXES = (
    "basic ",
    "bearer ",
    "ghp_",
    "github_pat_",
    "sk-",
    "xoxb-",
    "xoxp-",
)


def canonicalize_public_https_url(value: str) -> str:
    """Return the canonical syntax for a public HTTPS document URL."""

    if not isinstance(value, str) or not value or len(value) > MAX_PUBLIC_URL_LENGTH:
        raise ValueError("public rule URL is invalid")
    if _has_unsafe_url_character(value):
        raise ValueError("public rule URL is invalid")
    if "\\" in value or "#" in value or _ENCODED_CONTROL.search(value):
        raise ValueError("public rule URL is invalid")

    try:
        parsed = urlsplit(value)
        hostname_value = parsed.hostname
        port = parsed.port
    except (UnicodeError, ValueError):
        raise ValueError("public rule URL is invalid") from None

    if (
        parsed.scheme.lower() != "https"
        or not parsed.netloc
        or hostname_value is None
        or parsed.username is not None
        or parsed.password is not None
        or "@" in parsed.netloc
    ):
        raise ValueError("public rule URL must be an absolute HTTPS URL")

    hostname = _canonicalize_hostname(hostname_value)
    _reject_secret_query(parsed.query)
    host = f"[{hostname}]" if ":" in hostname else hostname
    netloc = host if port in (None, 443) else f"{host}:{port}"
    canonical = urlunsplit(("https", netloc, parsed.path or "/", parsed.query, ""))
    if len(canonical) > MAX_PUBLIC_URL_LENGTH:
        raise ValueError("public rule URL is invalid")
    return canonical


def is_same_origin(source: str, candidate: str) -> bool:
    """Compare the canonical scheme, hostname, and effective port."""

    source_parts = _canonical_parts(source)
    candidate_parts = _canonical_parts(candidate)
    return (
        source_parts.scheme,
        source_parts.hostname,
        source_parts.port or 443,
    ) == (
        candidate_parts.scheme,
        candidate_parts.hostname,
        candidate_parts.port or 443,
    )


def resolve_public_same_origin_link(
    source: str,
    href: str,
    *,
    source_depth: int,
    is_attachment: bool = False,
) -> str | None:
    """Resolve one explicit public link without permitting a second hop."""

    if source_depth != 0 or is_attachment or not isinstance(href, str) or not href:
        return None
    if _has_unsafe_url_character(href):
        return None
    if href.startswith("//"):
        return None

    try:
        href_parts = urlsplit(href)
    except ValueError:
        return None
    if href_parts.scheme and href_parts.scheme.lower() != "https":
        return None
    if href_parts.netloc and not href_parts.scheme:
        return None

    try:
        canonical_source = canonicalize_public_https_url(source)
        candidate = canonicalize_public_https_url(urljoin(canonical_source, href))
    except ValueError:
        return None
    return candidate if is_same_origin(canonical_source, candidate) else None


def _canonical_parts(value: str) -> SplitResult:
    return urlsplit(canonicalize_public_https_url(value))


def _has_unsafe_url_character(value: str) -> bool:
    return any(
        character.isspace()
        or ord(character) < 32
        or ord(character) == 127
        or unicodedata.category(character).startswith("C")
        for character in value
    )


def _canonicalize_hostname(value: str) -> str:
    if "%" in value or value.startswith(".") or value.endswith(".") or ".." in value:
        raise ValueError("public rule URL hostname is invalid")

    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        try:
            hostname = value.encode("idna").decode("ascii").lower()
        except UnicodeError:
            raise ValueError("public rule URL hostname is invalid") from None
        if len(hostname) > 253 or any(
            not _DNS_LABEL.fullmatch(label) for label in hostname.split(".")
        ):
            raise ValueError("public rule URL hostname is invalid")
        return hostname
    return address.compressed


def _reject_secret_query(query: str) -> None:
    try:
        pairs = parse_qsl(query, keep_blank_values=True, strict_parsing=False)
    except ValueError:
        raise ValueError("public rule URL query is invalid") from None

    for key, value in pairs:
        normalized_key = re.sub(r"[^a-z0-9]", "", key.lower())
        lowered_value = value.lower()
        if normalized_key in _SECRET_QUERY_KEYS:
            raise ValueError("public rule URL query may not contain secrets")
        if lowered_value.startswith(_SECRET_VALUE_PREFIXES) or _JWT.fullmatch(value):
            raise ValueError("public rule URL query may not contain secrets")
