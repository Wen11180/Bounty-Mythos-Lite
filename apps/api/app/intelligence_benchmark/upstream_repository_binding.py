from __future__ import annotations

import hashlib
import http.client
import json
import re
import ssl
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urlsplit

from app.intelligence_benchmark.corpus_provenance import (
    audit_candidate_hunter_corpus,
)


AUDIT_VERSION = "candidate_hunter_upstream_binding_audit_v1"
VERIFIER_VERSION = "1.0.0"
GITHUB_API_HOST = "api.github.com"
GITHUB_API_PORT = 443
DEFAULT_TIMEOUT_SECONDS = 10
DEFAULT_MAX_RESPONSE_BYTES = 1_000_000
_REPOSITORY_PATH = re.compile(
    r"^/repos/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$"
)
_COMMIT_PATH = re.compile(
    r"^/repos/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+"
    r"/git/commits/[0-9a-f]{40}$"
)
_REVISION = re.compile(r"^[0-9a-f]{40}$")


class GitHubBindingTransportError(RuntimeError):
    def __init__(self, reason: str):
        self.reason = reason
        super().__init__(reason)


class GitHubRESTTransport:
    def __init__(
        self,
        *,
        connection_factory: Callable[..., Any] = http.client.HTTPSConnection,
        timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS,
        max_response_bytes: int = DEFAULT_MAX_RESPONSE_BYTES,
    ):
        self._connection_factory = connection_factory
        self._timeout_seconds = timeout_seconds
        self._max_response_bytes = max_response_bytes
        self._tls_context = ssl.create_default_context()

    def get_json(
        self,
        path: str,
        *,
        token: str | None = None,
    ) -> dict[str, Any]:
        if not (
            _REPOSITORY_PATH.fullmatch(path)
            or _COMMIT_PATH.fullmatch(path)
        ):
            raise GitHubBindingTransportError("github_api_path_rejected")
        if token and (
            "\r" in token
            or "\n" in token
            or len(token) > 4096
        ):
            raise GitHubBindingTransportError("github_token_rejected")

        connection = None
        try:
            connection = self._connection_factory(
                GITHUB_API_HOST,
                GITHUB_API_PORT,
                timeout=self._timeout_seconds,
                context=self._tls_context,
            )
            headers = {
                "Accept": "application/vnd.github+json",
                "Accept-Encoding": "identity",
                "User-Agent": "Bounty-Mythos-Lite-Upstream-Binding-Audit",
                "X-GitHub-Api-Version": "2022-11-28",
            }
            if token:
                headers["Authorization"] = f"Bearer {token}"
            connection.request("GET", path, headers=headers)
            response = connection.getresponse()
            if 300 <= response.status < 400:
                raise GitHubBindingTransportError(
                    "github_redirect_rejected"
                )
            if response.status != 200:
                raise GitHubBindingTransportError(
                    "github_http_status_rejected"
                )
            content_type = response.getheader("Content-Type") or ""
            if not content_type.lower().startswith("application/json"):
                raise GitHubBindingTransportError("github_json_required")
            content_length = response.getheader("Content-Length")
            if content_length:
                try:
                    declared_length = int(content_length)
                except ValueError as error:
                    raise GitHubBindingTransportError(
                        "github_content_length_invalid"
                    ) from error
                if (
                    declared_length < 0
                    or declared_length > self._max_response_bytes
                ):
                    raise GitHubBindingTransportError(
                        "github_response_too_large"
                    )
            payload = response.read(self._max_response_bytes + 1)
            if len(payload) > self._max_response_bytes:
                raise GitHubBindingTransportError(
                    "github_response_too_large"
                )
            try:
                value = json.loads(payload.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as error:
                raise GitHubBindingTransportError(
                    "github_json_invalid"
                ) from error
            if not isinstance(value, dict):
                raise GitHubBindingTransportError(
                    "github_json_object_required"
                )
            return value
        except GitHubBindingTransportError:
            raise
        except Exception as error:
            raise GitHubBindingTransportError(
                "github_transport_failed"
            ) from error
        finally:
            if connection is not None:
                try:
                    connection.close()
                except Exception:
                    pass


def audit_candidate_hunter_upstream_binding(
    fixture_root: str | Path,
    *,
    transport: Any | None = None,
    github_token: str | None = None,
) -> dict[str, Any]:
    root = Path(fixture_root).resolve()
    failures: list[dict[str, str]] = []
    case_results: list[dict[str, Any]] = []
    offline_before = audit_candidate_hunter_corpus(root)
    offline_digest = _text(offline_before.get("audit_digest"))

    if offline_before.get("status") != "passed":
        failures.append(
            _issue("offline_provenance", "offline_provenance_audit_failed")
        )
        return _build_report(
            root=root,
            offline_digest=offline_digest,
            case_results=case_results,
            failures=failures,
        )
    if not offline_digest:
        failures.append(
            _issue(
                "offline_provenance.audit_digest",
                "offline_provenance_audit_digest_missing",
            )
        )
        return _build_report(
            root=root,
            offline_digest=offline_digest,
            case_results=case_results,
            failures=failures,
        )

    historical_case_ids = {
        _text(result.get("case_id"))
        for result in offline_before.get("case_results", [])
        if (
            isinstance(result, dict)
            and result.get("historical_evidence_verified") is True
        )
    }
    historical_case_ids.discard("")
    if not historical_case_ids:
        failures.append(
            _issue("corpus.cases", "historical_case_required")
        )
        return _build_report(
            root=root,
            offline_digest=offline_digest,
            case_results=case_results,
            failures=failures,
        )

    manifest = _read_json_object(
        root / "suite-manifest.json",
        "suite_manifest",
        failures,
    )
    entries = manifest.get("cases")
    if not isinstance(entries, list):
        failures.append(_issue("suite_manifest.cases", "must_be_list"))
        entries = []
    entry_by_case_id = {
        _text(entry.get("case_id")): entry
        for entry in entries
        if isinstance(entry, dict) and _text(entry.get("case_id"))
    }
    live_transport = transport or GitHubRESTTransport()

    for case_id in sorted(historical_case_ids):
        entry = entry_by_case_id.get(case_id)
        if entry is None:
            failures.append(
                _issue(case_id, "historical_case_manifest_entry_missing")
            )
            continue
        case_result, case_failures = _audit_case_binding(
            root=root,
            case_id=case_id,
            entry=entry,
            transport=live_transport,
            github_token=github_token,
        )
        case_results.append(case_result)
        failures.extend(case_failures)

    offline_after = audit_candidate_hunter_corpus(root)
    if (
        offline_after.get("status") != "passed"
        or _text(offline_after.get("audit_digest")) != offline_digest
    ):
        failures.append(
            _issue(
                "offline_provenance.audit_digest",
                "corpus_changed_during_binding_audit",
            )
        )

    return _build_report(
        root=root,
        offline_digest=offline_digest,
        case_results=case_results,
        failures=failures,
    )


def _audit_case_binding(
    *,
    root: Path,
    case_id: str,
    entry: dict[str, Any],
    transport: Any,
    github_token: str | None,
) -> tuple[dict[str, Any], list[dict[str, str]]]:
    failures: list[dict[str, str]] = []
    case_root = _resolve_under(
        root,
        _text(entry.get("path")),
        f"{case_id}.path",
        failures,
        require_directory=True,
    )
    metadata = (
        _read_json_object(
            case_root / "case.json",
            f"{case_id}.case_metadata",
            failures,
        )
        if case_root is not None
        else {}
    )
    provenance = metadata.get("provenance")
    if not isinstance(provenance, dict):
        failures.append(
            _issue(f"{case_id}.provenance", "must_be_object")
        )
        provenance = {}
    repository = provenance.get("repository")
    if not isinstance(repository, dict):
        failures.append(
            _issue(f"{case_id}.provenance.repository", "must_be_object")
        )
        repository = {}

    canonical_repository = _text(repository.get("canonical_url"))
    repository_identity = _parse_github_repository(canonical_repository)
    source_reference = repository.get("source_reference")
    if not isinstance(source_reference, dict):
        failures.append(
            _issue(
                f"{case_id}.provenance.repository.source_reference",
                "must_be_object",
            )
        )
        source_reference = {}
    source_path = (
        _resolve_under(
            case_root,
            _text(source_reference.get("path")),
            f"{case_id}.repository_source",
            failures,
            require_directory=False,
        )
        if case_root is not None
        else None
    )
    source = (
        _read_json_object(
            source_path,
            f"{case_id}.repository_source",
            failures,
        )
        if source_path is not None
        else {}
    )
    repository_node_id = _text(source.get("node_id"))
    root_repository_node_id = _text(
        source.get("root_repository_node_id")
    )

    vulnerable_commit_bound = False
    fixed_commit_bound = False
    if repository_identity is None:
        failures.append(
            _issue(
                f"{case_id}.canonical_repository",
                "canonical_github_repository_required",
            )
        )
    elif not failures:
        owner, repository_name = repository_identity
        api_root = (
            f"https://{GITHUB_API_HOST}/repos/{owner}/{repository_name}"
        )
        repository_path = f"/repos/{owner}/{repository_name}"
        try:
            live_repository = _fetch_json(
                transport,
                repository_path,
                token=github_token,
            )
        except Exception as error:
            failures.append(
                _issue(
                    f"{case_id}.repository",
                    _transport_reason(error),
                )
            )
        else:
            _verify_repository(
                case_id=case_id,
                live=live_repository,
                source=source,
                owner=owner,
                repository_name=repository_name,
                canonical_repository=canonical_repository,
                api_root=api_root,
                failures=failures,
            )
            vulnerable_commit_bound = _verify_commit(
                case_id=case_id,
                label="vulnerable_commit",
                revision=_text(provenance.get("vulnerable_revision")),
                tree_oid=_text(provenance.get("vulnerable_tree_oid")),
                owner=owner,
                repository_name=repository_name,
                api_root=api_root,
                transport=transport,
                github_token=github_token,
                failures=failures,
            )
            fixed_commit_bound = _verify_commit(
                case_id=case_id,
                label="fixed_commit",
                revision=_text(provenance.get("fixed_revision")),
                tree_oid=_text(provenance.get("fixed_tree_oid")),
                owner=owner,
                repository_name=repository_name,
                api_root=api_root,
                transport=transport,
                github_token=github_token,
                failures=failures,
            )

    unique_failures = _unique_issues(failures)
    verified = (
        not unique_failures
        and vulnerable_commit_bound
        and fixed_commit_bound
    )
    return (
        {
            "case_id": case_id,
            "binding_level": (
                "live_github_verified"
                if verified
                else "operator_attested"
            ),
            "canonical_repository": canonical_repository,
            "repository_node_id": repository_node_id,
            "root_repository_node_id": root_repository_node_id,
            "vulnerable_commit_bound": vulnerable_commit_bound,
            "fixed_commit_bound": fixed_commit_bound,
            "failure_reasons": sorted(
                {failure["reason"] for failure in unique_failures}
            ),
        },
        unique_failures,
    )


def _verify_repository(
    *,
    case_id: str,
    live: dict[str, Any],
    source: dict[str, Any],
    owner: str,
    repository_name: str,
    canonical_repository: str,
    api_root: str,
    failures: list[dict[str, str]],
) -> None:
    expected_full_name = f"{owner}/{repository_name}"
    repository_node_id = _text(source.get("node_id"))
    root_repository_node_id = _text(
        source.get("root_repository_node_id")
    )
    if _text(live.get("node_id")) != repository_node_id:
        failures.append(
            _issue(
                f"{case_id}.repository.node_id",
                "repository_node_id_mismatch",
            )
        )
    if (
        _text(live.get("full_name")) != expected_full_name
        or _text(live.get("html_url")) != canonical_repository
        or _text(live.get("url")) != api_root
        or _text(source.get("canonical_url")) != canonical_repository
        or _text(source.get("source_api")) != api_root
    ):
        failures.append(
            _issue(
                f"{case_id}.repository.identity",
                "repository_identity_mismatch",
            )
        )
    if live.get("private") is not False:
        failures.append(
            _issue(
                f"{case_id}.repository.private",
                "private_repository_not_allowed",
            )
        )
    declared_fork = source.get("fork")
    if not isinstance(declared_fork, bool) or live.get("fork") is not declared_fork:
        failures.append(
            _issue(
                f"{case_id}.repository.fork",
                "repository_fork_status_mismatch",
            )
        )
        return
    if not declared_fork:
        if root_repository_node_id != repository_node_id:
            failures.append(
                _issue(
                    f"{case_id}.repository.root_node_id",
                    "root_repository_node_id_mismatch",
                )
            )
        return

    live_source = live.get("source")
    if not isinstance(live_source, dict):
        failures.append(
            _issue(
                f"{case_id}.repository.source",
                "fork_source_identity_invalid",
            )
        )
        return
    source_full_name = _text(live_source.get("full_name"))
    source_identity = _split_full_name(source_full_name)
    if source_identity is None:
        failures.append(
            _issue(
                f"{case_id}.repository.source",
                "fork_source_identity_invalid",
            )
        )
        return
    source_owner, source_repository_name = source_identity
    source_api_root = (
        f"https://{GITHUB_API_HOST}/repos/"
        f"{source_owner}/{source_repository_name}"
    )
    source_web_root = (
        f"https://github.com/{source_owner}/{source_repository_name}"
    )
    if (
        _text(live_source.get("node_id")) != root_repository_node_id
        or _text(live_source.get("url")) != source_api_root
        or _text(live_source.get("html_url")) != source_web_root
        or live_source.get("fork") is not False
    ):
        failures.append(
            _issue(
                f"{case_id}.repository.source",
                "fork_source_identity_invalid",
            )
        )


def _verify_commit(
    *,
    case_id: str,
    label: str,
    revision: str,
    tree_oid: str,
    owner: str,
    repository_name: str,
    api_root: str,
    transport: Any,
    github_token: str | None,
    failures: list[dict[str, str]],
) -> bool:
    if not _REVISION.fullmatch(revision) or not _REVISION.fullmatch(tree_oid):
        failures.append(
            _issue(f"{case_id}.{label}", "commit_reference_invalid")
        )
        return False
    path = (
        f"/repos/{owner}/{repository_name}/git/commits/{revision}"
    )
    try:
        live = _fetch_json(transport, path, token=github_token)
    except Exception as error:
        failures.append(
            _issue(f"{case_id}.{label}", _transport_reason(error))
        )
        return False

    expected_api_url = f"{api_root}/git/commits/{revision}"
    expected_html_url = (
        f"https://github.com/{owner}/{repository_name}/commit/{revision}"
    )
    identity_matches = (
        _text(live.get("sha")) == revision
        and bool(_text(live.get("node_id")))
        and _text(live.get("url")) == expected_api_url
        and _text(live.get("html_url")) == expected_html_url
    )
    if not identity_matches:
        failures.append(
            _issue(f"{case_id}.{label}", "commit_identity_mismatch")
        )

    tree = live.get("tree")
    tree_matches = (
        isinstance(tree, dict)
        and _text(tree.get("sha")) == tree_oid
        and _text(tree.get("url")) == f"{api_root}/git/trees/{tree_oid}"
    )
    if not tree_matches:
        failures.append(
            _issue(f"{case_id}.{label}.tree", "commit_tree_mismatch")
        )
    return identity_matches and tree_matches


def _build_report(
    *,
    root: Path,
    offline_digest: str,
    case_results: list[dict[str, Any]],
    failures: list[dict[str, str]],
) -> dict[str, Any]:
    unique_failures = _unique_issues(failures)
    passed = bool(case_results) and not unique_failures
    report = {
        "version": AUDIT_VERSION,
        "verifier_version": VERIFIER_VERSION,
        "status": "passed" if passed else "failed",
        "fixture_root": str(root),
        "offline_provenance_audit_digest": offline_digest,
        "binding_level": (
            "live_github_verified" if passed else "operator_attested"
        ),
        "capability_level": "lab",
        "source_repository_binding_verified": passed,
        "runtime_isolation_verified": False,
        "benchmark_evaluation_allowed": False,
        "case_results": case_results,
        "failures": unique_failures,
    }
    report["audit_digest"] = _audit_digest(report)
    return report


def _read_json_object(
    path: Path,
    label: str,
    failures: list[dict[str, str]],
) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        failures.append(_issue(label, "unreadable_json"))
        return {}
    if not isinstance(value, dict):
        failures.append(_issue(label, "must_be_object"))
        return {}
    return value


def _resolve_under(
    root: Path,
    relative_path: str,
    label: str,
    failures: list[dict[str, str]],
    *,
    require_directory: bool,
) -> Path | None:
    try:
        resolved_root = root.resolve(strict=True)
        requested = Path(relative_path)
        if (
            not relative_path
            or requested.is_absolute()
            or ".." in requested.parts
        ):
            raise ValueError
        candidate = resolved_root
        for part in requested.parts:
            candidate /= part
            if candidate.is_symlink() or (
                hasattr(candidate, "is_junction")
                and candidate.is_junction()
            ):
                raise ValueError
        candidate = candidate.resolve(strict=True)
        candidate.relative_to(resolved_root)
    except (OSError, ValueError):
        failures.append(
            _issue(label, "path_missing_or_outside_corpus")
        )
        return None
    if require_directory and not candidate.is_dir():
        failures.append(_issue(label, "directory_required"))
        return None
    if not require_directory and not candidate.is_file():
        failures.append(_issue(label, "file_required"))
        return None
    return candidate


def _parse_github_repository(value: str) -> tuple[str, str] | None:
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError:
        return None
    if (
        parsed.scheme != "https"
        or parsed.hostname != "github.com"
        or port not in (None, 443)
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or "%" in parsed.path
    ):
        return None
    parts = parsed.path.strip("/").split("/")
    if len(parts) != 2 or parsed.path != f"/{parts[0]}/{parts[1]}":
        return None
    return _split_full_name(f"{parts[0]}/{parts[1]}")


def _split_full_name(value: str) -> tuple[str, str] | None:
    parts = value.split("/")
    if (
        len(parts) != 2
        or not all(
            part
            and part not in {".", ".."}
            and re.fullmatch(r"[A-Za-z0-9_.-]+", part)
            for part in parts
        )
    ):
        return None
    return parts[0], parts[1]


def _transport_reason(error: Exception) -> str:
    if isinstance(error, GitHubBindingTransportError):
        return error.reason
    return "github_transport_failed"


def _fetch_json(
    transport: Any,
    path: str,
    *,
    token: str | None,
) -> dict[str, Any]:
    for attempt in range(2):
        try:
            return transport.get_json(path, token=token)
        except GitHubBindingTransportError as error:
            if error.reason != "github_transport_failed" or attempt == 1:
                raise
    raise GitHubBindingTransportError("github_transport_failed")


def _issue(path: str, reason: str) -> dict[str, str]:
    return {"path": path, "reason": reason}


def _unique_issues(
    issues: list[dict[str, str]],
) -> list[dict[str, str]]:
    unique: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for issue in issues:
        key = (issue["path"], issue["reason"])
        if key not in seen:
            unique.append(issue)
            seen.add(key)
    return unique


def _text(value: Any) -> str:
    return value.strip() if isinstance(value, str) else ""


def _audit_digest(report: dict[str, Any]) -> str:
    stable = {
        key: value
        for key, value in report.items()
        if key not in {"fixture_root", "audit_digest"}
    }
    payload = json.dumps(
        stable,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(payload).hexdigest()


__all__ = [
    "AUDIT_VERSION",
    "GitHubBindingTransportError",
    "GitHubRESTTransport",
    "VERIFIER_VERSION",
    "audit_candidate_hunter_upstream_binding",
]
