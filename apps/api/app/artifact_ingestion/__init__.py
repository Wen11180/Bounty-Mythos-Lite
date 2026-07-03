from urllib.parse import urlparse

from pydantic import BaseModel


HTTP_METHODS = {"get", "post", "put", "patch", "delete", "options", "head"}


class ArtifactInput(BaseModel):
    kind: str
    payload: dict


class NormalizedArtifact(BaseModel):
    kind: str
    openapi_like: dict


def normalize_openapi(openapi: dict) -> dict:
    return {"paths": openapi.get("paths", {})}


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


def normalize_artifact(kind: str, payload: dict) -> NormalizedArtifact:
    normalized_kind = kind.lower()
    if normalized_kind == "openapi":
        openapi_like = normalize_openapi(payload)
    elif normalized_kind == "postman":
        openapi_like = normalize_postman(payload)
    elif normalized_kind == "har":
        openapi_like = normalize_har(payload)
    else:
        raise ValueError(f"Unsupported artifact kind: {kind}")

    return NormalizedArtifact(kind=normalized_kind, openapi_like=openapi_like)


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
    "normalize_artifact",
    "normalize_har",
    "normalize_openapi",
    "normalize_postman",
]
