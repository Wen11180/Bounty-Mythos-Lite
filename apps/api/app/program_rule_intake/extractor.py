"""Deterministic, evidence-backed extraction from normalized rule documents."""

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Protocol, runtime_checkable
from urllib.parse import urlsplit, urlunsplit

from pydantic import ValidationError

from app.policy_ingestion import parse_policy_text
from app.program_rule_intake.contracts import (
    AIStatus,
    AdvisoryParsedResult,
    AdvisoryRuleClaim,
    AdvisoryRuleOutput,
    AssetKind,
    AutomationStatus,
    CandidateScopeRule,
    CandidateScopeStatus,
    DeterministicExtractionResult,
    EvidenceExcerpt,
    ExtractionReviewState,
    LinkedArtifactCandidate,
    NormalizedRuleDocument,
    RateLimitUnit,
    StructuredRateLimit,
    canonicalize_public_https_url,
)
from app.program_rule_intake.normalizer import (
    create_evidence_excerpt,
    redact_untrusted_text,
)


_URL = re.compile(r"https://[^\s\"'<>\],)]+", re.IGNORECASE)
_HOST = re.compile(
    r"(?<![A-Za-z0-9*.-])(?:\*\.)?(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,63}"
    r"(?![A-Za-z0-9*.-])",
    re.IGNORECASE,
)
_WILDCARD_TOKEN = re.compile(
    r"(?<![A-Za-z0-9.-])[A-Za-z0-9.*-]*\*[A-Za-z0-9.*-]*"
    r"(?:\.[A-Za-z0-9*-]+)+",
    re.IGNORECASE,
)
_API_PATH = re.compile(
    r"(?<![A-Za-z0-9])/(?:api|v\d+)(?:/[A-Za-z0-9_.{}:-]+)*",
    re.IGNORECASE,
)
_RATE = re.compile(
    r"\b(\d{1,7})\s*(?:requests?|reqs?)\s*(?:per|/)\s*"
    r"(?:(\d{1,5})\s*)?(seconds?|minutes?|hours?|days?)\b",
    re.IGNORECASE,
)
_PROHIBITED_PATTERNS = {
    "DoS": ("denial of service", " dos "),
    "credential_stuffing": ("credential stuffing", "credential-stuffing"),
    "social_engineering": ("social engineering", "social-engineering"),
    "destructive_testing": ("destructive testing", "destructive validation"),
    "real_user_data_access": ("real user data", "customer data"),
}
_SPECIFICITY = {
    AssetKind.WILDCARD_HOST: 1,
    AssetKind.EXACT_HOST: 2,
    AssetKind.API_BASE_PATH: 3,
    AssetKind.URL_PREFIX: 4,
}


@dataclass(frozen=True)
class _Chunk:
    document: NormalizedRuleDocument
    locator: str
    text: str


@dataclass(frozen=True)
class _ScopeSignal:
    asset: str
    asset_kind: AssetKind
    status: CandidateScopeStatus
    evidence_id: str
    signal_strength: int


class _EvidenceRegistry:
    def __init__(self) -> None:
        self._items: dict[str, EvidenceExcerpt] = {}

    def add(self, chunk: _Chunk) -> str:
        evidence = create_evidence_excerpt(
            chunk.document.normalized_sha256,
            chunk.locator,
            chunk.text,
        )
        self._items[evidence.evidence_id] = evidence
        return evidence.evidence_id

    def values(self) -> list[EvidenceExcerpt]:
        return [self._items[key] for key in sorted(self._items)]


class AdvisoryResultError(ValueError):
    """Advisory output failed the closed schema or evidence checks."""


@runtime_checkable
class AdvisoryRuleExtractor(Protocol):
    async def extract(self, normalized_corpus: str) -> str:
        """Return JSON-only advisory rule proposals for untrusted text."""


def extract_deterministic_rules(
    documents: list[NormalizedRuleDocument],
) -> DeterministicExtractionResult:
    """Extract conservative candidate rules from already normalized documents."""

    evidence = _EvidenceRegistry()
    review_issues: set[str] = set()
    signals: list[_ScopeSignal] = []
    policy_documents = [document for document in documents if document.openapi_like is None]

    for document in policy_documents:
        if document.detected_language == "unsupported":
            review_issues.add("unsupported_language")
        document_signals, ambiguous = _scope_signals(document, evidence)
        signals.extend(document_signals)
        if ambiguous:
            review_issues.add("ambiguous_wildcard")

    signals.extend(_policy_parser_signals(policy_documents, signals, evidence))
    chunks = [chunk for document in policy_documents for chunk in _document_chunks(document)]
    automation, automation_evidence, automation_issues = _extract_automation(chunks, evidence)
    review_issues.update(automation_issues)
    rate_limit, rate_issues = _extract_rate_limit(chunks, evidence)
    review_issues.update(rate_issues)
    prohibited, prohibited_evidence = _extract_prohibitions(chunks, evidence)

    if automation == AutomationStatus.NEEDS_REVIEW:
        review_issues.add("automation_not_stated")
    if rate_limit is None and "conflicting_rate_limits" not in review_issues:
        review_issues.add("rate_limit_not_stated")
    if not signals:
        review_issues.add("no_scope_assets")

    grouped: dict[tuple[str, AssetKind], list[_ScopeSignal]] = {}
    for signal in signals:
        grouped.setdefault((signal.asset, signal.asset_kind), []).append(signal)

    rules: list[CandidateScopeRule] = []
    for (asset, asset_kind), asset_signals in sorted(
        grouped.items(),
        key=lambda item: (-_SPECIFICITY[item[0][1]], item[0][0]),
    ):
        strongest = max(signal.signal_strength for signal in asset_signals)
        effective_signals = [
            signal for signal in asset_signals if signal.signal_strength == strongest
        ]
        statuses = {signal.status for signal in effective_signals}
        local_issues: set[str] = set()
        if {
            CandidateScopeStatus.IN_SCOPE,
            CandidateScopeStatus.OUT_OF_SCOPE,
        }.issubset(statuses):
            status = CandidateScopeStatus.OUT_OF_SCOPE
            local_issues.add("conflicting_scope")
            review_issues.add("conflicting_scope")
        elif CandidateScopeStatus.OUT_OF_SCOPE in statuses:
            status = CandidateScopeStatus.OUT_OF_SCOPE
        elif CandidateScopeStatus.IN_SCOPE in statuses:
            status = CandidateScopeStatus.IN_SCOPE
        else:
            status = CandidateScopeStatus.NEEDS_REVIEW
            local_issues.add("scope_needs_review")
            review_issues.add("scope_needs_review")

        scope_evidence_ids = sorted(
            {signal.evidence_id for signal in effective_signals}
        )
        allowed_validation = _allowed_validation(policy_documents, asset)
        combined_issues = sorted(local_issues | review_issues)
        rule_state = (
            ExtractionReviewState.NEEDS_REVIEW
            if combined_issues or status == CandidateScopeStatus.NEEDS_REVIEW
            else ExtractionReviewState.READY
        )
        rules.append(
            CandidateScopeRule(
                asset=asset,
                asset_kind=asset_kind,
                specificity=_SPECIFICITY[asset_kind],
                scope_status=status,
                automation=automation,
                allowed_validation=allowed_validation,
                prohibited=prohibited,
                rate_limit=rate_limit,
                scope_evidence_ids=scope_evidence_ids,
                automation_evidence_ids=automation_evidence,
                prohibited_evidence_ids=prohibited_evidence,
                review_state=rule_state,
                review_issues=combined_issues,
            )
        )

    linked_artifacts = _linked_openapi_candidates(documents, evidence)
    result_issues = sorted(review_issues)
    if result_issues:
        rules = [
            rule.model_copy(
                update={
                    "review_state": ExtractionReviewState.NEEDS_REVIEW,
                    "review_issues": sorted(
                        set(rule.review_issues) | set(result_issues)
                    ),
                }
            )
            for rule in rules
        ]
    return DeterministicExtractionResult(
        rules=rules,
        evidence=evidence.values(),
        linked_artifacts=linked_artifacts,
        review_state=(
            ExtractionReviewState.NEEDS_REVIEW
            if result_issues
            else ExtractionReviewState.READY
        ),
        review_issues=result_issues,
        ai_status=AIStatus.NOT_REQUESTED,
    )


def parse_advisory_rule_result(
    raw_result: str,
    documents: list[NormalizedRuleDocument],
    deterministic: DeterministicExtractionResult,
) -> AdvisoryParsedResult:
    """Validate JSON-only advisory output against normalized source evidence."""

    if not isinstance(raw_result, str) or len(raw_result.encode("utf-8")) > 256 * 1024:
        raise AdvisoryResultError("advisory result is invalid")
    try:
        output = AdvisoryRuleOutput.model_validate_json(raw_result)
    except (ValidationError, ValueError):
        raise AdvisoryResultError("advisory result is invalid") from None

    documents_by_digest = {document.normalized_sha256: document for document in documents}
    parsed_rules: list[CandidateScopeRule] = []
    parsed_evidence: dict[str, EvidenceExcerpt] = {}
    seen_identities: set[tuple[str, AssetKind]] = set()
    for claim in output.rules:
        canonical_asset = _canonical_advisory_asset(claim.asset, claim.asset_kind)
        if canonical_asset is None or canonical_asset != claim.asset:
            raise AdvisoryResultError("advisory asset is invalid")
        identity = (canonical_asset, claim.asset_kind)
        if identity in seen_identities:
            raise AdvisoryResultError("advisory result contains duplicate assets")
        seen_identities.add(identity)

        evidence_ids: list[str] = []
        evidence_texts: list[str] = []
        for evidence_claim in claim.evidence:
            document = documents_by_digest.get(evidence_claim.document_sha256)
            if document is None:
                raise AdvisoryResultError("advisory evidence document is unknown")
            source_text = _locator_text(document, evidence_claim.locator)
            if (
                source_text is None
                or evidence_claim.excerpt not in source_text
                or redact_untrusted_text(evidence_claim.excerpt) != evidence_claim.excerpt
            ):
                raise AdvisoryResultError("advisory evidence is not source-backed")
            evidence = create_evidence_excerpt(
                document.normalized_sha256,
                evidence_claim.locator,
                evidence_claim.excerpt,
            )
            parsed_evidence[evidence.evidence_id] = evidence
            evidence_ids.append(evidence.evidence_id)
            evidence_texts.append(evidence_claim.excerpt)

        _validate_advisory_claim_support(claim, canonical_asset, evidence_texts)
        if _widens_deterministic_out_of_scope(
            deterministic.rules,
            canonical_asset,
            claim.asset_kind,
            claim.scope_status,
        ):
            raise AdvisoryResultError("advisory result cannot widen out-of-scope rules")

        unique_evidence_ids = sorted(set(evidence_ids))
        rate_limit = None
        if claim.rate_limit is not None:
            rate_limit = StructuredRateLimit(
                requests=claim.rate_limit.requests,
                period=claim.rate_limit.period,
                unit=claim.rate_limit.unit,
                evidence_ids=unique_evidence_ids,
            )
        prohibited = _validate_prohibited_values(claim.prohibited)
        parsed_rules.append(
            CandidateScopeRule(
                asset=canonical_asset,
                asset_kind=claim.asset_kind,
                specificity=_SPECIFICITY[claim.asset_kind],
                scope_status=claim.scope_status,
                automation=claim.automation,
                allowed_validation=[],
                prohibited=prohibited,
                rate_limit=rate_limit,
                scope_evidence_ids=unique_evidence_ids,
                automation_evidence_ids=(
                    unique_evidence_ids
                    if claim.automation != AutomationStatus.NEEDS_REVIEW
                    else []
                ),
                prohibited_evidence_ids={
                    value: unique_evidence_ids for value in prohibited
                },
                review_state=ExtractionReviewState.NEEDS_REVIEW,
                review_issues=["advisory_ai"],
            )
        )

    return AdvisoryParsedResult(
        rules=sorted(
            parsed_rules,
            key=lambda rule: (-rule.specificity, rule.asset),
        ),
        evidence=[parsed_evidence[key] for key in sorted(parsed_evidence)],
        ai_status=AIStatus.OK,
    )


def merge_advisory_rules(
    deterministic: DeterministicExtractionResult,
    advisory: AdvisoryParsedResult,
) -> DeterministicExtractionResult:
    """Merge advisory candidates without granting a new execution permission."""

    merged = {
        (rule.asset, rule.asset_kind): rule
        for rule in deterministic.rules
    }
    for advisory_rule in advisory.rules:
        identity = (advisory_rule.asset, advisory_rule.asset_kind)
        current = merged.get(identity)
        merged[identity] = (
            advisory_rule
            if current is None
            else _merge_candidate_rule(current, advisory_rule)
        )

    evidence = {item.evidence_id: item for item in deterministic.evidence}
    evidence.update({item.evidence_id: item for item in advisory.evidence})
    review_issues = sorted(
        set(deterministic.review_issues) | {"advisory_ai_review_required"}
    )
    return DeterministicExtractionResult(
        rules=sorted(
            merged.values(),
            key=lambda rule: (-rule.specificity, rule.asset),
        ),
        evidence=[evidence[key] for key in sorted(evidence)],
        linked_artifacts=deterministic.linked_artifacts,
        review_state=ExtractionReviewState.NEEDS_REVIEW,
        review_issues=review_issues,
        ai_status=AIStatus.OK,
    )


def _scope_signals(
    document: NormalizedRuleDocument,
    evidence: _EvidenceRegistry,
) -> tuple[list[_ScopeSignal], bool]:
    signals: list[_ScopeSignal] = []
    ambiguous = False
    if document.kind.value in {"json", "yaml"}:
        try:
            structured = json.loads(document.visible_text)
        except json.JSONDecodeError:
            return [], False
        for key, value, locator in _walk_scope_values(structured):
            status = _scope_status(key)
            values = value if isinstance(value, list) else [value]
            for index, item in enumerate(values):
                if not isinstance(item, str):
                    continue
                chunk = _Chunk(document, f"{locator}:{index}", f"{key}: {item}")
                extracted, item_ambiguous = _assets_from_text(item)
                ambiguous = ambiguous or item_ambiguous
                signals.extend(
                    _signals_from_assets(
                        extracted,
                        status,
                        chunk,
                        evidence,
                        force_review=document.detected_language == "unsupported",
                    )
                )
        return signals, ambiguous

    for chunk in _document_chunks(document):
        extracted, chunk_ambiguous = _assets_from_text(chunk.text)
        ambiguous = ambiguous or chunk_ambiguous
        if not extracted:
            continue
        signals.extend(
            _signals_from_assets(
                extracted,
                _scope_status(chunk.text),
                chunk,
                evidence,
                force_review=document.detected_language == "unsupported",
            )
        )
    return signals, ambiguous


def _walk_scope_values(
    value: object,
    locator: str = "json",
) -> list[tuple[str, object, str]]:
    matches: list[tuple[str, object, str]] = []
    if isinstance(value, dict):
        for key, item in value.items():
            normalized_key = re.sub(r"[^a-z]", " ", key.lower())
            child_locator = f"{locator}.{key}"
            if "scope" in normalized_key and (
                "in" in normalized_key.split() or "out" in normalized_key.split()
            ):
                matches.append((key, item, child_locator))
            else:
                matches.extend(_walk_scope_values(item, child_locator))
    elif isinstance(value, list):
        for index, item in enumerate(value):
            matches.extend(_walk_scope_values(item, f"{locator}:{index}"))
    return matches


def _signals_from_assets(
    assets: list[tuple[str, AssetKind]],
    status: CandidateScopeStatus,
    chunk: _Chunk,
    evidence: _EvidenceRegistry,
    *,
    force_review: bool,
) -> list[_ScopeSignal]:
    evidence_id = evidence.add(chunk)
    return [
        _ScopeSignal(
            asset=asset,
            asset_kind=kind,
            status=CandidateScopeStatus.NEEDS_REVIEW if force_review else status,
            evidence_id=evidence_id,
            signal_strength=2,
        )
        for asset, kind in assets
    ]


def _policy_parser_signals(
    documents: list[NormalizedRuleDocument],
    existing: list[_ScopeSignal],
    evidence: _EvidenceRegistry,
) -> list[_ScopeSignal]:
    added: list[_ScopeSignal] = []
    identities = {(signal.asset, signal.asset_kind) for signal in existing}
    for asset, asset_kind in sorted(identities, key=lambda item: item[0]):
        for document in documents:
            if document.detected_language != "en" or asset not in document.visible_text:
                continue
            parsed = parse_policy_text(document.visible_text, asset)
            if parsed.scope_status == "needs_review":
                continue
            status = CandidateScopeStatus(parsed.scope_status)
            chunk = _asset_context_chunk(document, asset, "policy-parser")
            added.append(
                _ScopeSignal(
                    asset=asset,
                    asset_kind=asset_kind,
                    status=status,
                    evidence_id=evidence.add(chunk),
                    signal_strength=1,
                )
            )
    return added


def _allowed_validation(
    documents: list[NormalizedRuleDocument],
    asset: str,
) -> list[str]:
    allowed: set[str] = set()
    for document in documents:
        if document.detected_language == "en" and asset in document.visible_text:
            allowed.update(parse_policy_text(document.visible_text, asset).allowed_validation)
    return sorted(allowed)


def _assets_from_text(text: str) -> tuple[list[tuple[str, AssetKind]], bool]:
    assets: list[tuple[str, AssetKind]] = []
    masked = list(text)
    ambiguous = False

    for match in _WILDCARD_TOKEN.finditer(text):
        token = match.group(0).strip(".,;:()[]{}\"'")
        for index in range(match.start(), match.end()):
            masked[index] = " "
        if token.startswith("*.") and token.count("*") == 1:
            canonical = _canonical_wildcard(token)
            if canonical is not None:
                assets.append((canonical, AssetKind.WILDCARD_HOST))
        else:
            ambiguous = True

    for match in _URL.finditer("".join(masked)):
        token = match.group(0).rstrip("./,;:)")
        for index in range(match.start(), match.end()):
            masked[index] = " "
        canonical = _canonical_url_prefix(token)
        if canonical is not None:
            assets.append((canonical, AssetKind.URL_PREFIX))

    remaining = "".join(masked)
    for match in _HOST.finditer(remaining):
        canonical = _canonical_exact_host(match.group(0))
        if canonical is not None:
            assets.append((canonical, AssetKind.EXACT_HOST))

    for match in _API_PATH.finditer(remaining):
        path = re.sub(r"/+", "/", match.group(0)).rstrip(".,;:)/") or "/"
        assets.append((path, AssetKind.API_BASE_PATH))

    return sorted(set(assets), key=lambda item: (-_SPECIFICITY[item[1]], item[0])), ambiguous


def _canonical_url_prefix(value: str) -> str | None:
    try:
        canonical = canonicalize_public_https_url(value)
    except ValueError:
        return None
    parsed = urlsplit(canonical)
    if parsed.query:
        return None
    path = parsed.path.rstrip("/") or "/"
    return urlunsplit(("https", parsed.netloc, path, "", ""))


def _canonical_exact_host(value: str) -> str | None:
    try:
        parsed = urlsplit(canonicalize_public_https_url(f"https://{value}/"))
    except ValueError:
        return None
    return parsed.hostname


def _canonical_wildcard(value: str) -> str | None:
    host = _canonical_exact_host(value[2:])
    return f"*.{host}" if host is not None else None


def _scope_status(text: str) -> CandidateScopeStatus:
    normalized = re.sub(r"[_-]+", " ", text.lower())
    if any(
        marker in normalized
        for marker in ("out of scope", "excluded", "not in scope", "not allowed")
    ):
        return CandidateScopeStatus.OUT_OF_SCOPE
    if "in scope" in normalized or "allowed" in normalized:
        return CandidateScopeStatus.IN_SCOPE
    return CandidateScopeStatus.NEEDS_REVIEW


def _document_chunks(document: NormalizedRuleDocument) -> list[_Chunk]:
    chunks = [
        _Chunk(document, f"text:{index}", line)
        for index, line in enumerate(document.visible_text.splitlines())
        if line.strip()
    ]
    chunks.extend(
        _Chunk(document, f"table:{table_index}:{row_index}", " | ".join(row))
        for table_index, table in enumerate(document.tables)
        for row_index, row in enumerate(table)
        if any(row)
    )
    chunks.extend(
        _Chunk(document, f"list:{index}", item)
        for index, item in enumerate(document.list_items)
        if item
    )
    return chunks


def _asset_context_chunk(
    document: NormalizedRuleDocument,
    asset: str,
    prefix: str,
) -> _Chunk:
    index = document.visible_text.find(asset)
    start = max(0, index - 160)
    end = min(len(document.visible_text), index + len(asset) + 160)
    locator = f"{prefix}:{hashlib.sha256(asset.encode('utf-8')).hexdigest()[:12]}"
    return _Chunk(document, locator, document.visible_text[start:end])


def _extract_automation(
    chunks: list[_Chunk],
    evidence: _EvidenceRegistry,
) -> tuple[AutomationStatus, list[str], set[str]]:
    signals: dict[AutomationStatus, set[str]] = {}
    for chunk in chunks:
        lowered = chunk.text.lower()
        status = None
        if "no automation" in lowered or (
            "automat" in lowered and any(word in lowered for word in ("prohibited", "forbidden"))
        ):
            status = AutomationStatus.NONE
        elif "automat" in lowered and any(word in lowered for word in ("limited", "rate limit")):
            status = AutomationStatus.LIMITED
        if status is not None:
            signals.setdefault(status, set()).add(evidence.add(chunk))

    if len(signals) > 1:
        ids = sorted({item for values in signals.values() for item in values})
        return AutomationStatus.NEEDS_REVIEW, ids, {"conflicting_automation"}
    if signals:
        status = next(iter(signals))
        return status, sorted(signals[status]), set()
    return AutomationStatus.NEEDS_REVIEW, [], set()


def _extract_rate_limit(
    chunks: list[_Chunk],
    evidence: _EvidenceRegistry,
) -> tuple[StructuredRateLimit | None, set[str]]:
    rates: dict[tuple[int, int, RateLimitUnit], set[str]] = {}
    for chunk in chunks:
        for match in _RATE.finditer(chunk.text):
            requests = int(match.group(1))
            period = int(match.group(2) or "1")
            unit = RateLimitUnit(match.group(3).lower().rstrip("s"))
            rates.setdefault((requests, period, unit), set()).add(evidence.add(chunk))
    if len(rates) > 1:
        return None, {"conflicting_rate_limits"}
    if not rates:
        return None, set()
    (requests, period, unit), evidence_ids = next(iter(rates.items()))
    return (
        StructuredRateLimit(
            requests=requests,
            period=period,
            unit=unit,
            evidence_ids=sorted(evidence_ids),
        ),
        set(),
    )


def _extract_prohibitions(
    chunks: list[_Chunk],
    evidence: _EvidenceRegistry,
) -> tuple[list[str], dict[str, list[str]]]:
    found: dict[str, set[str]] = {}
    for chunk in chunks:
        lowered = f" {chunk.text.lower()} "
        if not any(
            marker in lowered
            for marker in ("prohibited", "forbidden", "do not", "no ", '"prohibited"')
        ):
            continue
        for value, patterns in _PROHIBITED_PATTERNS.items():
            if any(pattern in lowered for pattern in patterns):
                found.setdefault(value, set()).add(evidence.add(chunk))
    ordered = [value for value in _PROHIBITED_PATTERNS if value in found]
    return ordered, {value: sorted(found[value]) for value in ordered}


def _linked_openapi_candidates(
    documents: list[NormalizedRuleDocument],
    evidence: _EvidenceRegistry,
) -> list[LinkedArtifactCandidate]:
    openapi_documents = {
        document.source_url: document
        for document in documents
        if document.depth == 1 and document.openapi_like is not None
    }
    candidates: dict[str, LinkedArtifactCandidate] = {}
    for document in documents:
        for link in document.eligible_links:
            linked = openapi_documents.get(link.url)
            if linked is None or linked.openapi_like is None:
                continue
            chunk = _Chunk(document, link.locator, link.text or "Linked OpenAPI document")
            evidence_id = evidence.add(chunk)
            candidates[link.url] = LinkedArtifactCandidate(
                url=link.url,
                url_sha256=hashlib.sha256(link.url.encode("utf-8")).hexdigest(),
                normalized_sha256=linked.normalized_sha256,
                openapi_like=linked.openapi_like,
                evidence_ids=[evidence_id],
            )
    return [candidates[url] for url in sorted(candidates)]


def _canonical_advisory_asset(value: str, kind: AssetKind) -> str | None:
    if kind == AssetKind.EXACT_HOST:
        return _canonical_exact_host(value)
    if kind == AssetKind.WILDCARD_HOST:
        if not value.startswith("*.") or value.count("*") != 1:
            return None
        return _canonical_wildcard(value)
    if kind == AssetKind.URL_PREFIX:
        return _canonical_url_prefix(value)
    if kind == AssetKind.API_BASE_PATH:
        if _API_PATH.fullmatch(value) is None:
            return None
        return re.sub(r"/+", "/", value).rstrip("/") or "/"
    return None


def _locator_text(
    document: NormalizedRuleDocument,
    locator: str,
) -> str | None:
    text_match = re.fullmatch(r"text:(\d+)", locator)
    if text_match:
        lines = document.visible_text.splitlines()
        index = int(text_match.group(1))
        return lines[index] if index < len(lines) else None

    table_match = re.fullmatch(r"table:(\d+):(\d+)", locator)
    if table_match:
        table_index, row_index = map(int, table_match.groups())
        if table_index < len(document.tables) and row_index < len(
            document.tables[table_index]
        ):
            return " | ".join(document.tables[table_index][row_index])
        return None

    list_match = re.fullmatch(r"list:(\d+)", locator)
    if list_match:
        index = int(list_match.group(1))
        return document.list_items[index] if index < len(document.list_items) else None

    anchor_match = re.fullmatch(r"anchor:(\d+)", locator)
    if anchor_match:
        return next(
            (
                link.text
                for link in document.eligible_links
                if link.locator == locator
            ),
            None,
        )
    return None


def _validate_advisory_claim_support(
    claim: AdvisoryRuleClaim,
    canonical_asset: str,
    evidence_texts: list[str],
) -> None:
    if not any(canonical_asset in text for text in evidence_texts):
        raise AdvisoryResultError("advisory asset is not present in evidence")

    evidence_text = "\n".join(evidence_texts)
    normalized = re.sub(r"[_-]+", " ", evidence_text.lower())
    if claim.scope_status == CandidateScopeStatus.IN_SCOPE and not any(
        canonical_asset in text
        and (
            "in scope" in re.sub(r"[_-]+", " ", text.lower())
            or "allowed" in text.lower()
        )
        for text in evidence_texts
    ):
        raise AdvisoryResultError("advisory in-scope claim lacks evidence")
    if claim.scope_status == CandidateScopeStatus.OUT_OF_SCOPE and not any(
        canonical_asset in text
        and any(
            marker in re.sub(r"[_-]+", " ", text.lower())
            for marker in ("out of scope", "excluded", "not in scope", "not allowed")
        )
        for text in evidence_texts
    ):
        raise AdvisoryResultError("advisory out-of-scope claim lacks evidence")

    if claim.automation == AutomationStatus.LIMITED and not (
        "automat" in normalized and any(
            marker in normalized for marker in ("limited", "rate limit")
        )
    ):
        raise AdvisoryResultError("advisory automation claim lacks evidence")
    if claim.automation == AutomationStatus.NONE and not (
        "no automation" in normalized
        or (
            "automat" in normalized
            and any(marker in normalized for marker in ("prohibited", "forbidden"))
        )
    ):
        raise AdvisoryResultError("advisory automation claim lacks evidence")

    if claim.rate_limit is not None:
        expected = (
            claim.rate_limit.requests,
            claim.rate_limit.period,
            claim.rate_limit.unit,
        )
        actual = {
            (
                int(match.group(1)),
                int(match.group(2) or "1"),
                RateLimitUnit(match.group(3).lower().rstrip("s")),
            )
            for match in _RATE.finditer(evidence_text)
        }
        if expected not in actual:
            raise AdvisoryResultError("advisory rate limit lacks evidence")

    prohibited = _validate_prohibited_values(claim.prohibited)
    for value in prohibited:
        if not any(
            any(
                pattern in f" {text.lower()} "
                for pattern in _PROHIBITED_PATTERNS[value]
            )
            and any(
                marker in text.lower()
                for marker in ("prohibited", "forbidden", "do not", "no ")
            )
            for text in evidence_texts
        ):
            raise AdvisoryResultError("advisory prohibition lacks evidence")


def _validate_prohibited_values(values: list[str]) -> list[str]:
    if len(values) != len(set(values)) or any(
        value not in _PROHIBITED_PATTERNS for value in values
    ):
        raise AdvisoryResultError("advisory prohibition is invalid")
    return [value for value in _PROHIBITED_PATTERNS if value in values]


def _widens_deterministic_out_of_scope(
    deterministic_rules: list[CandidateScopeRule],
    asset: str,
    asset_kind: AssetKind,
    status: CandidateScopeStatus,
) -> bool:
    if status != CandidateScopeStatus.IN_SCOPE:
        return False
    return any(
        rule.scope_status == CandidateScopeStatus.OUT_OF_SCOPE
        and _rule_covers_asset(rule, asset, asset_kind)
        for rule in deterministic_rules
    )


def _rule_covers_asset(
    rule: CandidateScopeRule,
    asset: str,
    asset_kind: AssetKind,
) -> bool:
    if rule.asset_kind == AssetKind.EXACT_HOST:
        if asset_kind == AssetKind.EXACT_HOST:
            return rule.asset == asset
        if asset_kind == AssetKind.URL_PREFIX:
            return urlsplit(asset).hostname == rule.asset
        return False

    if rule.asset_kind == AssetKind.WILDCARD_HOST:
        base = rule.asset[2:]
        candidate_host = None
        if asset_kind == AssetKind.EXACT_HOST:
            candidate_host = asset
        elif asset_kind == AssetKind.WILDCARD_HOST:
            candidate_host = asset[2:]
        elif asset_kind == AssetKind.URL_PREFIX:
            candidate_host = urlsplit(asset).hostname
        return bool(candidate_host) and (
            candidate_host == base or candidate_host.endswith(f".{base}")
        )

    if rule.asset_kind == AssetKind.URL_PREFIX and asset_kind == AssetKind.URL_PREFIX:
        return asset == rule.asset or asset.startswith(f"{rule.asset.rstrip('/')}/")
    if rule.asset_kind == AssetKind.API_BASE_PATH and asset_kind == AssetKind.API_BASE_PATH:
        return asset == rule.asset or asset.startswith(f"{rule.asset.rstrip('/')}/")
    return False


def _merge_candidate_rule(
    deterministic: CandidateScopeRule,
    advisory: CandidateScopeRule,
) -> CandidateScopeRule:
    if CandidateScopeStatus.OUT_OF_SCOPE in {
        deterministic.scope_status,
        advisory.scope_status,
    }:
        scope_status = CandidateScopeStatus.OUT_OF_SCOPE
    elif deterministic.scope_status != CandidateScopeStatus.NEEDS_REVIEW:
        scope_status = deterministic.scope_status
    else:
        scope_status = advisory.scope_status

    automation = (
        deterministic.automation
        if deterministic.automation != AutomationStatus.NEEDS_REVIEW
        else advisory.automation
    )
    prohibited = [
        value
        for value in _PROHIBITED_PATTERNS
        if value in set(deterministic.prohibited) | set(advisory.prohibited)
    ]
    prohibited_evidence: dict[str, list[str]] = {}
    for value in prohibited:
        prohibited_evidence[value] = sorted(
            set(deterministic.prohibited_evidence_ids.get(value, []))
            | set(advisory.prohibited_evidence_ids.get(value, []))
        )

    return CandidateScopeRule(
        asset=deterministic.asset,
        asset_kind=deterministic.asset_kind,
        specificity=deterministic.specificity,
        scope_status=scope_status,
        automation=automation,
        allowed_validation=deterministic.allowed_validation,
        prohibited=prohibited,
        rate_limit=deterministic.rate_limit or advisory.rate_limit,
        scope_evidence_ids=sorted(
            set(deterministic.scope_evidence_ids)
            | set(advisory.scope_evidence_ids)
        ),
        automation_evidence_ids=sorted(
            set(deterministic.automation_evidence_ids)
            | set(advisory.automation_evidence_ids)
        ),
        prohibited_evidence_ids=prohibited_evidence,
        review_state=ExtractionReviewState.NEEDS_REVIEW,
        review_issues=sorted(
            set(deterministic.review_issues)
            | set(advisory.review_issues)
            | {"advisory_ai"}
        ),
    )


__all__ = [
    "AdvisoryResultError",
    "AdvisoryRuleExtractor",
    "extract_deterministic_rules",
    "merge_advisory_rules",
    "parse_advisory_rule_result",
]
