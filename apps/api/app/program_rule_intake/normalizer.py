"""Bounded, redacting normalization of untrusted public rule documents."""

import base64
import binascii
import hashlib
import hmac
import json
import math
import re
from html.parser import HTMLParser

import yaml
from yaml.tokens import AliasToken, AnchorToken

from app.program_rule_intake.contracts import (
    BrowserRuleDocumentEnvelope,
    DocumentKind,
    EvidenceExcerpt,
    NormalizedDocumentLink,
    NormalizedRuleDocument,
    StaticRuleDocumentEnvelope,
    canonicalize_public_https_url,
    resolve_public_same_origin_link,
)


MAX_DOCUMENT_BYTES = 2 * 1024 * 1024
MAX_NORMALIZED_TEXT = 512 * 1024
_SUPPORTED_CHARSETS = {"ascii", "us-ascii", "utf-8", "utf8"}
_EMAIL = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE)
_JWT = re.compile(r"\b[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{2,}\.[A-Za-z0-9_-]{6,}\b")
_AUTHORIZATION = re.compile(
    r"\bauthorization\s*:\s*(?:bearer|basic)\s+[^\s,;]+",
    re.IGNORECASE,
)
_COOKIE = re.compile(r"\bcookie\s*:\s*[^\r\n]+", re.IGNORECASE)
_SENSITIVE_VALUE = re.compile(
    r"\b(?:api[_ -]?key|access[_ -]?token|token|password|secret|session(?:id)?|"
    r"(?:customer|user)[_ -]?(?:id|email|name|phone|address))\s*[:=]\s*[^\s,;]+",
    re.IGNORECASE,
)


class DocumentNormalizationError(ValueError):
    """The bounded document cannot be safely normalized."""


class BrowserRenderRequiredError(DocumentNormalizationError):
    """Static HTML needs safe browser projection instead of byte decoding."""


def normalize_rule_document(
    envelope: StaticRuleDocumentEnvelope | BrowserRuleDocumentEnvelope,
) -> NormalizedRuleDocument:
    """Normalize one bounded document without retaining a raw body."""

    source_url = canonicalize_public_https_url(envelope.source_url)
    kind, content_type = _document_kind(envelope.content_type)
    if isinstance(envelope, BrowserRuleDocumentEnvelope):
        return _normalize_browser_projection(
            envelope,
            source_url=source_url,
            kind=kind,
            content_type=content_type,
        )

    raw = _decode_static_body(envelope)
    text = _decode_text(raw, envelope.charset, kind)
    openapi_like = None
    if kind == DocumentKind.HTML:
        parser = _parse_html(text, source_url, envelope.depth)
        visible_text = _join_visible_text(parser.text_parts)
        tables = [
            [[_bounded_projection_text(cell) for cell in row] for row in table]
            for table in parser.tables
        ]
        list_items = [_bounded_projection_text(item) for item in parser.list_items]
        eligible_links = parser.eligible_links
    elif kind == DocumentKind.TEXT:
        visible_text = _join_visible_text(text.splitlines())
        tables = []
        list_items = []
        eligible_links = []
    else:
        structured = _load_structured(text, kind)
        openapi_like = _reduce_linked_openapi(structured, envelope.depth)
        if openapi_like is None:
            safe_payload = _redact_structure(structured)
        else:
            marker = structured.get("openapi") or structured.get("swagger")
            safe_payload = {"openapi": str(marker), **openapi_like}
        visible_text = _canonical_structured_text(safe_payload)
        tables = []
        list_items = []
        eligible_links = []

    normalized_sha256 = _normalized_digest(
        kind=kind,
        visible_text=visible_text,
        tables=tables,
        list_items=list_items,
        eligible_links=eligible_links,
        openapi_like=openapi_like,
    )
    return NormalizedRuleDocument(
        source_url=source_url,
        depth=envelope.depth,
        kind=kind,
        content_type=content_type,
        raw_sha256=envelope.raw_sha256,
        normalized_sha256=normalized_sha256,
        detected_language=_detect_language(visible_text),
        visible_text=visible_text,
        tables=tables,
        list_items=list_items,
        eligible_links=eligible_links,
        openapi_like=openapi_like,
    )


def _normalize_browser_projection(
    envelope: BrowserRuleDocumentEnvelope,
    *,
    source_url: str,
    kind: DocumentKind,
    content_type: str,
) -> NormalizedRuleDocument:
    if kind != DocumentKind.HTML:
        raise DocumentNormalizationError("browser projection must be HTML")

    visible_text = _join_visible_text(envelope.visible_strings)
    tables = [
        [[_bounded_projection_text(cell) for cell in row] for row in table]
        for table in envelope.tables
    ]
    list_items = [_bounded_projection_text(item) for item in envelope.list_items]
    eligible_links: list[NormalizedDocumentLink] = []
    for index, anchor in enumerate(envelope.anchors):
        resolved = resolve_public_same_origin_link(
            source_url,
            anchor.href,
            source_depth=envelope.depth,
            is_attachment=anchor.is_attachment,
        )
        if resolved is not None:
            eligible_links.append(
                NormalizedDocumentLink(
                    url=resolved,
                    text=redact_untrusted_text(anchor.text)[:500],
                    locator=f"anchor:{index}",
                )
            )

    _ensure_projection_bound(visible_text, tables, list_items, eligible_links)
    normalized_sha256 = _normalized_digest(
        kind=kind,
        visible_text=visible_text,
        tables=tables,
        list_items=list_items,
        eligible_links=eligible_links,
        openapi_like=None,
    )
    return NormalizedRuleDocument(
        source_url=source_url,
        depth=envelope.depth,
        kind=kind,
        content_type=content_type,
        raw_sha256=None,
        normalized_sha256=normalized_sha256,
        detected_language=_detect_language(visible_text),
        visible_text=visible_text,
        tables=tables,
        list_items=list_items,
        eligible_links=eligible_links,
        openapi_like=None,
    )


def create_evidence_excerpt(
    document_sha256: str,
    locator: str,
    text: str,
) -> EvidenceExcerpt:
    """Create a stable, redacted evidence back-reference."""

    excerpt = redact_untrusted_text(text)[:500]
    evidence_id = hashlib.sha256(
        f"{document_sha256}\n{locator}\n{excerpt}".encode("utf-8")
    ).hexdigest()
    return EvidenceExcerpt(
        evidence_id=evidence_id,
        document_sha256=document_sha256,
        locator=locator,
        excerpt=excerpt,
    )


def redact_untrusted_text(value: str) -> str:
    """Remove common secret and personal-data shapes from untrusted text."""

    redacted = _AUTHORIZATION.sub("Authorization: [REDACTED]", value)
    redacted = _COOKIE.sub("Cookie: [REDACTED]", redacted)
    redacted = _SENSITIVE_VALUE.sub("[REDACTED]", redacted)
    redacted = _JWT.sub("[REDACTED]", redacted)
    redacted = _EMAIL.sub("[REDACTED]", redacted)
    return re.sub(r"[ \t\f\v]+", " ", redacted).strip()


def _document_kind(content_type: str) -> tuple[DocumentKind, str]:
    media_type = content_type.split(";", 1)[0].strip().lower()
    if media_type == "text/html":
        return DocumentKind.HTML, media_type
    if media_type == "text/plain":
        return DocumentKind.TEXT, media_type
    if media_type == "application/json":
        return DocumentKind.JSON, media_type
    if media_type in {"application/yaml", "application/x-yaml", "text/yaml"}:
        return DocumentKind.YAML, media_type
    raise DocumentNormalizationError("document content type is unsupported")


def _decode_static_body(envelope: StaticRuleDocumentEnvelope) -> bytes:
    try:
        raw = base64.b64decode(envelope.body_base64, validate=True)
    except (binascii.Error, ValueError):
        raise DocumentNormalizationError("document body encoding is invalid") from None
    if len(raw) > MAX_DOCUMENT_BYTES:
        raise DocumentNormalizationError("document body exceeds the byte limit")
    actual_digest = hashlib.sha256(raw).hexdigest()
    if not hmac.compare_digest(actual_digest, envelope.raw_sha256):
        raise DocumentNormalizationError("document body digest does not match")
    return raw


def _decode_text(raw: bytes, charset: str | None, kind: DocumentKind) -> str:
    normalized_charset = (charset or "utf-8").strip().lower()
    if normalized_charset not in _SUPPORTED_CHARSETS:
        if kind == DocumentKind.HTML:
            raise BrowserRenderRequiredError("HTML charset needs browser rendering")
        raise DocumentNormalizationError("document charset is unsupported")
    codec = "ascii" if normalized_charset in {"ascii", "us-ascii"} else "utf-8"
    try:
        return raw.decode(codec, errors="strict")
    except UnicodeDecodeError:
        if kind == DocumentKind.HTML:
            raise BrowserRenderRequiredError("HTML decoding needs browser rendering") from None
        raise DocumentNormalizationError("document is not valid UTF-8 or ASCII") from None


def _join_visible_text(parts: list[str]) -> str:
    visible_text = "\n".join(
        redacted
        for part in parts
        if (redacted := redact_untrusted_text(part))
    )
    if len(visible_text.encode("utf-8")) > MAX_NORMALIZED_TEXT:
        raise DocumentNormalizationError("normalized document exceeds the text limit")
    return visible_text


def _bounded_projection_text(value: str) -> str:
    redacted = redact_untrusted_text(value)
    if len(redacted) > 8192:
        raise DocumentNormalizationError("normalized structure item exceeds the limit")
    return redacted


def _parse_html(text: str, source_url: str, source_depth: int) -> "_VisibleHTMLParser":
    parser = _VisibleHTMLParser(source_url, source_depth)
    try:
        parser.feed(text)
        parser.close()
    except (ValueError, AssertionError):
        raise DocumentNormalizationError("HTML document is malformed") from None
    return parser


def _load_structured(text: str, kind: DocumentKind) -> object:
    try:
        if kind == DocumentKind.JSON:
            return json.loads(text)
        tokens = yaml.scan(text, Loader=yaml.SafeLoader)
        if any(isinstance(token, (AliasToken, AnchorToken)) for token in tokens):
            raise DocumentNormalizationError("YAML aliases and anchors are unsupported")
        documents = list(yaml.safe_load_all(text))
        if len(documents) != 1:
            raise DocumentNormalizationError("YAML must contain exactly one document")
        return documents[0]
    except DocumentNormalizationError:
        raise
    except (json.JSONDecodeError, yaml.YAMLError, UnicodeError, ValueError):
        raise DocumentNormalizationError("structured document is invalid") from None


def _redact_structure(value: object, depth: int = 0) -> object:
    if depth > 32:
        raise DocumentNormalizationError("structured document is too deeply nested")
    if value is None or isinstance(value, (bool, int)):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise DocumentNormalizationError("structured document contains a non-finite number")
        return value
    if isinstance(value, str):
        return redact_untrusted_text(value)
    if isinstance(value, list):
        return [_redact_structure(item, depth + 1) for item in value]
    if isinstance(value, dict):
        result: dict[str, object] = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise DocumentNormalizationError("structured document keys must be strings")
            if _is_sensitive_key(key):
                result[key] = "[REDACTED]"
            else:
                result[key] = _redact_structure(item, depth + 1)
        return result
    raise DocumentNormalizationError("structured document contains an unsupported value")


def _is_sensitive_key(value: str) -> bool:
    normalized = re.sub(r"[^a-z0-9]", "", value.lower())
    return normalized in {
        "accesstoken",
        "apikey",
        "auth",
        "authorization",
        "cookie",
        "credential",
        "customeremail",
        "customerid",
        "customername",
        "customerphone",
        "jwt",
        "password",
        "secret",
        "session",
        "sessionid",
        "token",
        "useremail",
        "userid",
        "username",
        "userphone",
    }


def _reduce_linked_openapi(value: object, depth: int) -> dict | None:
    if depth != 1 or not isinstance(value, dict):
        return None
    marker = value.get("openapi") or value.get("swagger")
    if not isinstance(marker, (str, int, float)):
        return None
    paths = value.get("paths")
    if not isinstance(paths, dict):
        raise DocumentNormalizationError("OpenAPI paths must be an object")
    if any(not isinstance(path, str) for path in paths):
        raise DocumentNormalizationError("OpenAPI path keys must be strings")

    reduced_paths: dict[str, dict[str, dict]] = {}
    methods = {"delete", "get", "head", "options", "patch", "post", "put"}
    for path in sorted(paths):
        path_item = paths[path]
        if not isinstance(path, str) or not path.startswith("/") or not isinstance(path_item, dict):
            continue
        safe_methods = {
            method.lower(): {}
            for method in path_item
            if isinstance(method, str) and method.lower() in methods
        }
        if safe_methods:
            reduced_paths[path] = dict(sorted(safe_methods.items()))
    return {"paths": reduced_paths}


def _canonical_structured_text(value: object) -> str:
    text = json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )
    if len(text.encode("utf-8")) > MAX_NORMALIZED_TEXT:
        raise DocumentNormalizationError("normalized document exceeds the text limit")
    return text


def _normalized_digest(
    *,
    kind: DocumentKind,
    visible_text: str,
    tables: list[list[list[str]]],
    list_items: list[str],
    eligible_links: list[NormalizedDocumentLink],
    openapi_like: dict | None,
) -> str:
    payload = {
        "kind": kind.value,
        "visible_text": visible_text,
        "tables": tables,
        "list_items": list_items,
        "eligible_links": [link.model_dump(mode="json") for link in eligible_links],
        "openapi_like": openapi_like,
    }
    canonical = json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _ensure_projection_bound(
    visible_text: str,
    tables: list[list[list[str]]],
    list_items: list[str],
    eligible_links: list[NormalizedDocumentLink],
) -> None:
    projection = json.dumps(
        {
            "visible_text": visible_text,
            "tables": tables,
            "list_items": list_items,
            "eligible_links": [link.model_dump(mode="json") for link in eligible_links],
        },
        ensure_ascii=False,
        separators=(",", ":"),
    )
    if len(projection.encode("utf-8")) > MAX_NORMALIZED_TEXT:
        raise DocumentNormalizationError("browser projection exceeds the text limit")


def _detect_language(text: str) -> str:
    letters = [character for character in text if character.isalpha()]
    if not letters:
        return "unsupported"
    ascii_letters = sum(character.isascii() for character in letters)
    return "en" if ascii_letters / len(letters) >= 0.9 else "unsupported"


class _VisibleHTMLParser(HTMLParser):
    _EXCLUDED_TAGS = {"form", "noscript", "script", "style"}
    _VOID_TAGS = {
        "area",
        "base",
        "br",
        "col",
        "embed",
        "hr",
        "img",
        "input",
        "link",
        "meta",
        "param",
        "source",
        "track",
        "wbr",
    }

    def __init__(self, source_url: str, source_depth: int) -> None:
        super().__init__(convert_charrefs=True)
        self.source_url = source_url
        self.source_depth = source_depth
        self.text_parts: list[str] = []
        self.tables: list[list[list[str]]] = []
        self.list_items: list[str] = []
        self.eligible_links: list[NormalizedDocumentLink] = []
        self._suppressed_tags: list[str] = []
        self._table: list[list[str]] | None = None
        self._row: list[str] | None = None
        self._cell_parts: list[str] | None = None
        self._list_parts: list[str] | None = None
        self._anchor: dict[str, object] | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        tag = tag.lower()
        attributes = {key.lower(): value for key, value in attrs}
        if self._suppressed_tags:
            if tag not in self._VOID_TAGS:
                self._suppressed_tags.append(tag)
            return
        if tag in self._EXCLUDED_TAGS or _is_hidden(attributes):
            if tag not in self._VOID_TAGS:
                self._suppressed_tags.append(tag)
            return

        if tag == "table":
            self._table = []
        elif tag == "tr" and self._table is not None:
            self._row = []
        elif tag in {"td", "th"} and self._row is not None:
            self._cell_parts = []
        elif tag == "li":
            self._list_parts = []
        elif tag == "a":
            self._anchor = {
                "href": attributes.get("href"),
                "download": "download" in attributes,
                "parts": [],
            }

    def handle_endtag(self, tag: str) -> None:
        tag = tag.lower()
        if self._suppressed_tags:
            if tag in self._suppressed_tags:
                while self._suppressed_tags:
                    opened = self._suppressed_tags.pop()
                    if opened == tag:
                        break
            return

        if tag in {"td", "th"} and self._cell_parts is not None:
            cell = _collapse_parts(self._cell_parts)
            if self._row is not None:
                self._row.append(cell)
            self._cell_parts = None
        elif tag == "tr" and self._row is not None:
            if self._table is not None and any(self._row):
                self._table.append(self._row)
            self._row = None
        elif tag == "table" and self._table is not None:
            if self._table:
                self.tables.append(self._table)
            self._table = None
        elif tag == "li" and self._list_parts is not None:
            item = _collapse_parts(self._list_parts)
            if item:
                self.list_items.append(item)
            self._list_parts = None
        elif tag == "a" and self._anchor is not None:
            self._finish_anchor()

    def handle_data(self, data: str) -> None:
        if self._suppressed_tags:
            return
        text = re.sub(r"\s+", " ", data).strip()
        if not text:
            return
        self.text_parts.append(text)
        if self._cell_parts is not None:
            self._cell_parts.append(text)
        if self._list_parts is not None:
            self._list_parts.append(text)
        if self._anchor is not None:
            parts = self._anchor["parts"]
            assert isinstance(parts, list)
            parts.append(text)

    def _finish_anchor(self) -> None:
        assert self._anchor is not None
        href = self._anchor["href"]
        parts = self._anchor["parts"]
        is_attachment = self._anchor["download"]
        if isinstance(href, str) and isinstance(parts, list) and isinstance(is_attachment, bool):
            resolved = resolve_public_same_origin_link(
                self.source_url,
                href,
                source_depth=self.source_depth,
                is_attachment=is_attachment,
            )
            if resolved is not None:
                self.eligible_links.append(
                    NormalizedDocumentLink(
                        url=resolved,
                        text=redact_untrusted_text(_collapse_parts(parts))[:500],
                        locator=f"anchor:{len(self.eligible_links)}",
                    )
                )
        self._anchor = None


def _collapse_parts(parts: list[str]) -> str:
    return re.sub(r"\s+", " ", " ".join(parts)).strip()


def _is_hidden(attributes: dict[str, str | None]) -> bool:
    return "hidden" in attributes or (attributes.get("aria-hidden") or "").lower() == "true"


__all__ = [
    "BrowserRenderRequiredError",
    "DocumentNormalizationError",
    "MAX_DOCUMENT_BYTES",
    "MAX_NORMALIZED_TEXT",
    "create_evidence_excerpt",
    "normalize_rule_document",
    "redact_untrusted_text",
]
