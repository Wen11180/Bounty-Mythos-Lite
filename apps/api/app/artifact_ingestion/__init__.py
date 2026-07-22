import re
from typing import Any
from urllib.parse import urlparse

from pydantic import BaseModel


HTTP_METHODS = {"get", "post", "put", "patch", "delete", "options", "head"}
SBOM_SEVERITY_ORDER = {
    "critical": 4,
    "high": 3,
    "medium": 2,
    "low": 1,
    "info": 0,
    "unknown": 0,
}
SBOM_SAFE_VALUE_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+/@:-]{0,159}")
SBOM_UNSAFE_MARKERS = (
    "authorization",
    "cookie",
    "token",
    "secret",
    "password",
    "credential",
)


class ArtifactInput(BaseModel):
    kind: str
    payload: dict


class NormalizedArtifact(BaseModel):
    kind: str
    openapi_like: dict


def normalize_openapi(openapi: dict) -> dict:
    paths: dict = {}
    for path, path_item in openapi.get("paths", {}).items():
        clean_path = _clean_path(str(path))
        if clean_path and isinstance(path_item, dict):
            paths.setdefault(clean_path, {}).update(path_item)
    return {"paths": paths}


def normalize_postman(collection: dict) -> dict:
    paths: dict = {}
    for item in _walk_postman_items(collection.get("item", [])):
        request = item.get("request")
        if not isinstance(request, dict):
            continue

        method = _normalize_method(request.get("method"))
        path = _extract_postman_path(request.get("url"))
        if method and path:
            paths.setdefault(path, {})[method] = {}

    return {"paths": paths}


def normalize_har(har: dict) -> dict:
    paths: dict = {}
    log = har.get("log", {})
    entries = log.get("entries", []) if isinstance(log, dict) else []

    for entry in entries:
        if not isinstance(entry, dict):
            continue

        request = entry.get("request", {})
        if not isinstance(request, dict):
            continue

        method = _normalize_method(request.get("method"))
        path = _path_from_raw_url(request.get("url"))
        if method and path:
            paths.setdefault(path, {})[method] = {}

    return {"paths": paths}


def normalize_notes(notes: dict) -> dict:
    return _normalize_text_artifact(notes, "notes")


def normalize_code_excerpt(code_excerpt: dict) -> dict:
    return _normalize_text_artifact(code_excerpt, "code_excerpt")


def normalize_policy(policy: dict) -> dict:
    return _normalize_text_artifact(policy, "policy")


def normalize_sarif(sarif: dict) -> dict:
    paths = _extract_paths_from_text(_collect_sarif_text(sarif), "sarif")
    for uri in _collect_sarif_uris(sarif):
        path = _path_from_source_uri(uri)
        if path is None:
            continue
        method = _infer_method_from_path(path)
        paths.setdefault(path, {})[method] = {
            "operationId": _operation_id("sarif", method, path),
        }
    return {"paths": paths}


def extract_sbom_dependency_signals(payload: dict[str, Any]) -> list[dict[str, str]]:
    """Return a bounded, redaction-safe CycloneDX dependency projection."""
    components = payload.get("components")
    if not isinstance(components, list):
        return []

    vulnerabilities = _sbom_vulnerabilities_by_reference(payload)
    signals: list[dict[str, str]] = []
    seen: set[tuple[str, str, str, str]] = set()
    for component in components:
        if not isinstance(component, dict) or component.get("type") not in {None, "library"}:
            continue
        package_name = _safe_sbom_value(component.get("name"))
        if not package_name:
            continue
        package_version = _safe_sbom_value(component.get("version"), allow_empty=True)
        purl = component.get("purl") if isinstance(component.get("purl"), str) else ""
        bom_ref = component.get("bom-ref") if isinstance(component.get("bom-ref"), str) else ""
        vulnerability = _select_sbom_vulnerability(
            [
                item
                for reference in (purl, bom_ref)
                if reference
                for item in vulnerabilities.get(reference, [])
            ]
        )
        ecosystem = _safe_sbom_value(_sbom_purl_ecosystem(purl), allow_empty=True)
        signal = {
            "package_name": package_name,
            "package_version": package_version,
            "ecosystem": ecosystem,
        }
        if vulnerability:
            signal.update(vulnerability)
        dedupe_key = (
            signal["package_name"],
            signal["package_version"],
            signal["ecosystem"],
            signal.get("vulnerability_id", ""),
        )
        if dedupe_key in seen:
            continue
        seen.add(dedupe_key)
        signals.append(signal)
    return signals[:100]


def normalize_artifact(kind: str, payload: dict) -> NormalizedArtifact:
    normalized_kind = kind.lower()
    if normalized_kind == "openapi":
        openapi_like = normalize_openapi(payload)
    elif normalized_kind == "postman":
        openapi_like = normalize_postman(payload)
    elif normalized_kind == "har":
        openapi_like = normalize_har(payload)
    elif normalized_kind == "notes":
        openapi_like = normalize_notes(payload)
    elif normalized_kind == "code_excerpt":
        openapi_like = normalize_code_excerpt(payload)
    elif normalized_kind == "policy":
        openapi_like = normalize_policy(payload)
    elif normalized_kind == "sarif":
        openapi_like = normalize_sarif(payload)
    else:
        raise ValueError(f"Unsupported artifact kind: {kind}")

    return NormalizedArtifact(kind=normalized_kind, openapi_like=openapi_like)


def _normalize_text_artifact(payload: dict, source: str) -> dict:
    return {"paths": _extract_paths_from_text(_text_payload(payload), source)}


def _sbom_vulnerabilities_by_reference(payload: dict[str, Any]) -> dict[str, list[dict[str, str]]]:
    values = payload.get("vulnerabilities")
    if not isinstance(values, list):
        return {}
    by_reference: dict[str, list[dict[str, str]]] = {}
    for vulnerability in values:
        if not isinstance(vulnerability, dict):
            continue
        vulnerability_id = _safe_sbom_value(vulnerability.get("id"))
        if not vulnerability_id:
            continue
        severity = _sbom_vulnerability_severity(vulnerability)
        signal = {"vulnerability_id": vulnerability_id}
        if severity:
            signal["severity"] = severity
        affects = vulnerability.get("affects")
        if not isinstance(affects, list):
            continue
        for affected in affects:
            reference = affected.get("ref") if isinstance(affected, dict) else None
            if isinstance(reference, str) and reference:
                by_reference.setdefault(reference, []).append(signal)
    return by_reference


def _select_sbom_vulnerability(values: list[dict[str, str]]) -> dict[str, str]:
    if not values:
        return {}
    return dict(
        sorted(
            values,
            key=lambda value: (
                -SBOM_SEVERITY_ORDER.get(value.get("severity", "unknown"), 0),
                value.get("vulnerability_id", ""),
            ),
        )[0]
    )


def _sbom_vulnerability_severity(vulnerability: dict[str, Any]) -> str:
    ratings = vulnerability.get("ratings")
    if not isinstance(ratings, list):
        return ""
    for rating in ratings:
        severity = rating.get("severity") if isinstance(rating, dict) else None
        if not isinstance(severity, str):
            continue
        normalized = severity.strip().lower()
        if normalized in SBOM_SEVERITY_ORDER:
            return normalized
    return ""


def _sbom_purl_ecosystem(purl: str) -> str:
    match = re.match(r"^pkg:([^/]+)", purl, flags=re.IGNORECASE)
    return match.group(1).lower() if match else ""


def _safe_sbom_value(value: object, *, allow_empty: bool = False) -> str:
    if not isinstance(value, str):
        return ""
    text = value.strip()
    if not text:
        return "" if allow_empty else ""
    if (
        not SBOM_SAFE_VALUE_PATTERN.fullmatch(text)
        or any(marker in text.lower() for marker in SBOM_UNSAFE_MARKERS)
    ):
        return ""
    return text


def _text_payload(payload: dict) -> str:
    values = []
    for key in ("text", "content", "body", "notes", "markdown"):
        value = payload.get(key)
        if isinstance(value, str):
            values.append(value)
    return "\n".join(values)


def _extract_paths_from_text(text: str, source: str) -> dict:
    paths: dict = {}
    for match in re.finditer(
        r"\b(GET|POST|PUT|PATCH|DELETE|OPTIONS|HEAD)\s+([^\s,;\"'`]+)",
        text,
        flags=re.IGNORECASE,
    ):
        method = match.group(1).lower()
        path = _clean_path(match.group(2))
        if path:
            paths.setdefault(path, {})[method] = {
                "operationId": _operation_id(source, method, path),
            }

    for match in re.finditer(
        r"\.(get|post|put|patch|delete|options|head)\(\s*[\"']([^\"']+)[\"']",
        text,
        flags=re.IGNORECASE,
    ):
        method = match.group(1).lower()
        path = _clean_path(match.group(2))
        if path:
            paths.setdefault(path, {})[method] = {
                "operationId": _operation_id(source, method, path),
            }
    return paths


def _collect_sarif_text(value: object) -> str:
    texts: list[str] = []
    _collect_sarif_text_values(value, texts)
    return "\n".join(texts)


def _collect_sarif_text_values(value: object, texts: list[str]) -> None:
    if isinstance(value, dict):
        for key, nested_value in value.items():
            if key in {"text", "markdown"} and isinstance(nested_value, str):
                texts.append(nested_value)
            else:
                _collect_sarif_text_values(nested_value, texts)
    elif isinstance(value, list):
        for item in value:
            _collect_sarif_text_values(item, texts)


def _collect_sarif_uris(value: object) -> list[str]:
    uris: list[str] = []
    _collect_sarif_uri_values(value, uris)
    return uris


def _collect_sarif_uri_values(value: object, uris: list[str]) -> None:
    if isinstance(value, dict):
        for key, nested_value in value.items():
            if key == "uri" and isinstance(nested_value, str):
                uris.append(nested_value)
            else:
                _collect_sarif_uri_values(nested_value, uris)
    elif isinstance(value, list):
        for item in value:
            _collect_sarif_uri_values(item, uris)


def _path_from_source_uri(uri: str) -> str | None:
    path = uri.split("?", 1)[0].split("#", 1)[0].replace("\\", "/")
    path = re.sub(r"\.[A-Za-z0-9]+$", "", path)
    segments = [segment for segment in path.split("/") if segment and segment not in {"src", "app"}]
    if not segments or "{" not in "/".join(segments):
        return None
    return _ensure_leading_slash("/".join(segments))


def _clean_path(value: str) -> str | None:
    parsed = urlparse(value)
    path = parsed.path if parsed.path else value.split("?", 1)[0].split("#", 1)[0]
    path = path.strip().rstrip(".:)")
    if not path.startswith("/"):
        return None
    return path


def _operation_id(source: str, method: str, path: str) -> str:
    suffix = re.sub(r"[^a-zA-Z0-9]+", "_", path.replace("{", "").replace("}", "")).strip("_")
    return f"{source}_{method}_{suffix}" if suffix else f"{source}_{method}_root"


def _infer_method_from_path(path: str) -> str:
    lowered = path.lower()
    if any(term in lowered for term in ("refund", "invite", "share", "checkout", "payment")):
        return "post"
    if any(term in lowered for term in ("delete", "remove")):
        return "delete"
    return "get"


def _walk_postman_items(items: list) -> list[dict]:
    requests = []
    for item in items:
        if not isinstance(item, dict):
            continue
        if "request" in item:
            requests.append(item)
        nested_items = item.get("item")
        if isinstance(nested_items, list):
            requests.extend(_walk_postman_items(nested_items))
    return requests


def _extract_postman_path(url: object) -> str | None:
    if isinstance(url, str):
        return _path_from_raw_url(url)

    if not isinstance(url, dict):
        return None

    raw = url.get("raw")
    if isinstance(raw, str):
        return _path_from_raw_url(raw)

    path = url.get("path")
    if isinstance(path, list):
        return _ensure_leading_slash("/".join(str(segment).strip("/") for segment in path))
    if isinstance(path, str):
        return _ensure_leading_slash(path)

    return None


def _normalize_method(method: object) -> str | None:
    if not isinstance(method, str):
        return None

    normalized = method.lower()
    if normalized not in HTTP_METHODS:
        return None
    return normalized


def _path_from_raw_url(url: object) -> str | None:
    if not isinstance(url, str):
        return None

    parsed = urlparse(url)
    path = parsed.path if parsed.scheme or parsed.netloc else url.split("?", 1)[0].split("#", 1)[0]
    return _ensure_leading_slash(path) if path else None


def _ensure_leading_slash(path: str) -> str:
    return path if path.startswith("/") else f"/{path}"


__all__ = [
    "ArtifactInput",
    "NormalizedArtifact",
    "extract_sbom_dependency_signals",
    "normalize_artifact",
    "normalize_code_excerpt",
    "normalize_har",
    "normalize_notes",
    "normalize_openapi",
    "normalize_policy",
    "normalize_postman",
    "normalize_sarif",
]
