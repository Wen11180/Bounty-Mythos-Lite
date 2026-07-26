from __future__ import annotations

import json
import os
import shutil
from copy import deepcopy
from pathlib import Path

import pytest

from app import cli
from app.intelligence_benchmark import upstream_repository_binding as binding
from app.intelligence_benchmark.upstream_repository_binding import (
    GitHubBindingTransportError,
    GitHubRESTTransport,
    audit_candidate_hunter_upstream_binding,
)


FIXTURE_ROOT = Path(__file__).parent / "fixtures"
PILOT_CORPUS = FIXTURE_ROOT / "candidate_hunter_repository_history_pilot"
CASE_ID = "rhp-a7c9"


class FakeTransport:
    def __init__(self, responses: dict[str, dict]):
        self.responses = responses
        self.calls: list[tuple[str, str | None]] = []

    def get_json(self, path: str, *, token: str | None = None) -> dict:
        self.calls.append((path, token))
        response = self.responses[path]
        if isinstance(response, Exception):
            raise response
        return deepcopy(response)


class FakeHTTPResponse:
    def __init__(
        self,
        *,
        status: int = 200,
        body: bytes = b"{}",
        content_type: str = "application/json; charset=utf-8",
        content_length: str | None = None,
    ):
        self.status = status
        self.body = body
        self.headers = {
            "Content-Type": content_type,
            "Content-Length": content_length,
        }

    def getheader(self, name: str) -> str | None:
        return self.headers.get(name)

    def read(self, amount: int) -> bytes:
        return self.body[:amount]


class FakeHTTPSConnection:
    def __init__(
        self,
        response: FakeHTTPResponse,
        *,
        request_error: Exception | None = None,
    ):
        self.response = response
        self.request_error = request_error
        self.requests: list[tuple[str, str, dict[str, str]]] = []
        self.closed = False

    def request(
        self,
        method: str,
        path: str,
        *,
        headers: dict[str, str],
    ) -> None:
        self.requests.append((method, path, headers))
        if self.request_error is not None:
            raise self.request_error

    def getresponse(self) -> FakeHTTPResponse:
        return self.response

    def close(self) -> None:
        self.closed = True


@pytest.fixture
def offline_provenance_pass(monkeypatch: pytest.MonkeyPatch):
    report = {
        "status": "passed",
        "audit_digest": "sha256:offline-provenance",
        "case_results": [
            {
                "case_id": CASE_ID,
                "historical_evidence_verified": True,
            }
        ],
    }
    monkeypatch.setattr(
        binding,
        "audit_candidate_hunter_corpus",
        lambda _fixture_root: deepcopy(report),
    )
    return report


def test_live_binding_verifies_repository_and_both_commits(
    offline_provenance_pass: dict,
):
    responses = _pilot_responses()
    transport = FakeTransport(responses)

    report = audit_candidate_hunter_upstream_binding(
        PILOT_CORPUS,
        transport=transport,
        github_token="test-token",
    )

    assert report["status"] == "passed"
    assert report["binding_level"] == "live_github_verified"
    assert report["capability_level"] == "lab"
    assert report["source_repository_binding_verified"] is True
    assert report["runtime_isolation_verified"] is False
    assert report["benchmark_evaluation_allowed"] is False
    assert report["case_results"] == [
        {
            "case_id": CASE_ID,
            "binding_level": "live_github_verified",
            "canonical_repository": "https://github.com/fastify/fast-uri",
            "repository_node_id": "R_kgDOGP5HDg",
            "root_repository_node_id": "R_kgDOGP5HDg",
            "vulnerable_commit_bound": True,
            "fixed_commit_bound": True,
            "failure_reasons": [],
        }
    ]
    assert [path for path, _token in transport.calls] == [
        "/repos/fastify/fast-uri",
        (
            "/repos/fastify/fast-uri/git/commits/"
            "dcdf690b71a7bb3a19887ada65a9ab160d83bcc0"
        ),
        (
            "/repos/fastify/fast-uri/git/commits/"
            "876ce79b662c3e5015e4e7dffe6f37752ad34f35"
        ),
    ]
    assert all(token == "test-token" for _path, token in transport.calls)
    assert "test-token" not in json.dumps(report)


def test_live_binding_retries_one_transient_transport_failure(
    offline_provenance_pass: dict,
):
    class TransientTransport(FakeTransport):
        def __init__(self, responses: dict[str, dict]):
            super().__init__(responses)
            self.failed_once = False

        def get_json(
            self,
            path: str,
            *,
            token: str | None = None,
        ) -> dict:
            if not self.failed_once:
                self.failed_once = True
                self.calls.append((path, token))
                raise GitHubBindingTransportError(
                    "github_transport_failed"
                )
            return super().get_json(path, token=token)

    transport = TransientTransport(_pilot_responses())

    report = audit_candidate_hunter_upstream_binding(
        PILOT_CORPUS,
        transport=transport,
    )

    assert report["status"] == "passed"
    assert [path for path, _token in transport.calls].count(
        "/repos/fastify/fast-uri"
    ) == 2


def test_live_binding_retries_three_transient_transport_failures(
    offline_provenance_pass: dict,
):
    class TransientTransport(FakeTransport):
        def __init__(self, responses: dict[str, dict]):
            super().__init__(responses)
            self.remaining_failures = 3

        def get_json(
            self,
            path: str,
            *,
            token: str | None = None,
        ) -> dict:
            if self.remaining_failures:
                self.remaining_failures -= 1
                self.calls.append((path, token))
                raise GitHubBindingTransportError(
                    "github_transport_failed"
                )
            return super().get_json(path, token=token)

    transport = TransientTransport(_pilot_responses())

    report = audit_candidate_hunter_upstream_binding(
        PILOT_CORPUS,
        transport=transport,
    )

    assert report["status"] == "passed"
    assert [path for path, _token in transport.calls].count(
        "/repos/fastify/fast-uri"
    ) == 4


def test_live_binding_fails_when_commit_url_points_at_another_repository(
    offline_provenance_pass: dict,
):
    responses = _pilot_responses()
    path = (
        "/repos/fastify/fast-uri/git/commits/"
        "dcdf690b71a7bb3a19887ada65a9ab160d83bcc0"
    )
    responses[path]["url"] = (
        "https://api.github.com/repos/attacker/mirror/git/commits/"
        "dcdf690b71a7bb3a19887ada65a9ab160d83bcc0"
    )

    report = audit_candidate_hunter_upstream_binding(
        PILOT_CORPUS,
        transport=FakeTransport(responses),
    )

    assert report["status"] == "failed"
    assert "commit_identity_mismatch" in _reasons(report)
    assert report["source_repository_binding_verified"] is False
    assert report["binding_level"] == "operator_attested"
    assert report["capability_level"] == "lab"


def test_live_binding_fails_when_commit_tree_differs(
    offline_provenance_pass: dict,
):
    responses = _pilot_responses()
    path = (
        "/repos/fastify/fast-uri/git/commits/"
        "876ce79b662c3e5015e4e7dffe6f37752ad34f35"
    )
    responses[path]["tree"]["sha"] = "0" * 40

    report = audit_candidate_hunter_upstream_binding(
        PILOT_CORPUS,
        transport=FakeTransport(responses),
    )

    assert report["status"] == "failed"
    assert "commit_tree_mismatch" in _reasons(report)


def test_live_binding_fails_when_repository_node_id_differs(
    offline_provenance_pass: dict,
):
    responses = _pilot_responses()
    responses["/repos/fastify/fast-uri"]["node_id"] = "R_attacker"

    report = audit_candidate_hunter_upstream_binding(
        PILOT_CORPUS,
        transport=FakeTransport(responses),
    )

    assert report["status"] == "failed"
    assert "repository_node_id_mismatch" in _reasons(report)


def test_live_binding_fails_when_fork_source_identity_is_inconsistent(
    tmp_path: Path,
    offline_provenance_pass: dict,
):
    corpus_root = Path(shutil.copytree(PILOT_CORPUS, tmp_path / "pilot"))
    source_path = (
        corpus_root
        / "cases"
        / CASE_ID
        / "provenance"
        / "repository-source.json"
    )
    source = _read_json(source_path)
    source["fork"] = True
    source["root_repository_node_id"] = "R_root"
    _write_json(source_path, source)
    responses = _pilot_responses()
    responses["/repos/fastify/fast-uri"].update(
        {
            "fork": True,
            "source": {
                "node_id": "R_root",
                "full_name": "upstream/project",
                "html_url": "https://github.com/attacker/not-project",
                "url": "https://api.github.com/repos/upstream/project",
                "fork": False,
            },
        }
    )

    report = audit_candidate_hunter_upstream_binding(
        corpus_root,
        transport=FakeTransport(responses),
    )

    assert report["status"] == "failed"
    assert "fork_source_identity_invalid" in _reasons(report)


def test_live_binding_never_calls_network_when_offline_provenance_fails(
    monkeypatch: pytest.MonkeyPatch,
):
    monkeypatch.setattr(
        binding,
        "audit_candidate_hunter_corpus",
        lambda _fixture_root: {
            "status": "failed",
            "audit_digest": "sha256:failed",
            "case_results": [],
        },
    )
    transport = FakeTransport({})

    report = audit_candidate_hunter_upstream_binding(
        PILOT_CORPUS,
        transport=transport,
    )

    assert report["status"] == "failed"
    assert transport.calls == []
    assert "offline_provenance_audit_failed" in _reasons(report)


def test_live_binding_fails_if_corpus_changes_during_network_verification(
    monkeypatch: pytest.MonkeyPatch,
):
    reports = iter(
        [
            {
                "status": "passed",
                "audit_digest": "sha256:before",
                "case_results": [
                    {
                        "case_id": CASE_ID,
                        "historical_evidence_verified": True,
                    }
                ],
            },
            {
                "status": "passed",
                "audit_digest": "sha256:after",
                "case_results": [
                    {
                        "case_id": CASE_ID,
                        "historical_evidence_verified": True,
                    }
                ],
            },
        ]
    )
    monkeypatch.setattr(
        binding,
        "audit_candidate_hunter_corpus",
        lambda _fixture_root: next(reports),
    )

    report = audit_candidate_hunter_upstream_binding(
        PILOT_CORPUS,
        transport=FakeTransport(_pilot_responses()),
    )

    assert report["status"] == "failed"
    assert "corpus_changed_during_binding_audit" in _reasons(report)


def test_transport_rejects_unapproved_api_path_before_connecting():
    connections = []
    transport = GitHubRESTTransport(
        connection_factory=lambda *args, **kwargs: connections.append(
            (args, kwargs)
        )
    )

    with pytest.raises(
        GitHubBindingTransportError,
        match="github_api_path_rejected",
    ):
        transport.get_json("https://attacker.example/repos/x/y")

    assert connections == []


def test_transport_uses_fixed_github_tls_origin_and_bounded_headers():
    response = FakeHTTPResponse(body=b'{"ok": true}')
    connection = FakeHTTPSConnection(response)
    factory_calls = []

    def factory(host: str, port: int, **kwargs):
        factory_calls.append((host, port, kwargs))
        return connection

    transport = GitHubRESTTransport(
        connection_factory=factory,
        timeout_seconds=7,
    )

    result = transport.get_json(
        "/repos/fastify/fast-uri",
        token="secret-token",
    )

    assert result == {"ok": True}
    assert factory_calls[0][0:2] == ("api.github.com", 443)
    assert factory_calls[0][2]["timeout"] == 7
    assert factory_calls[0][2]["context"].check_hostname is True
    method, path, headers = connection.requests[0]
    assert (method, path) == ("GET", "/repos/fastify/fast-uri")
    assert headers["Authorization"] == "Bearer secret-token"
    assert headers["Accept-Encoding"] == "identity"
    assert connection.closed is True


@pytest.mark.parametrize(
    ("response", "reason"),
    [
        (
            FakeHTTPResponse(status=302),
            "github_redirect_rejected",
        ),
        (
            FakeHTTPResponse(
                body=b"<html>not json</html>",
                content_type="text/html",
            ),
            "github_json_required",
        ),
        (
            FakeHTTPResponse(body=b"{"),
            "github_json_invalid",
        ),
        (
            FakeHTTPResponse(body=b"[]"),
            "github_json_object_required",
        ),
        (
            FakeHTTPResponse(
                body=b'{"long": "payload"}',
                content_length="9999",
            ),
            "github_response_too_large",
        ),
    ],
)
def test_transport_fails_closed_on_untrusted_response(
    response: FakeHTTPResponse,
    reason: str,
):
    connection = FakeHTTPSConnection(response)
    transport = GitHubRESTTransport(
        connection_factory=lambda *args, **kwargs: connection,
        max_response_bytes=64,
    )

    with pytest.raises(GitHubBindingTransportError, match=reason):
        transport.get_json("/repos/fastify/fast-uri")


def test_transport_error_never_exposes_token():
    token = "github-token-must-not-leak"
    connection = FakeHTTPSConnection(
        FakeHTTPResponse(),
        request_error=RuntimeError(token),
    )
    transport = GitHubRESTTransport(
        connection_factory=lambda *args, **kwargs: connection,
    )

    with pytest.raises(GitHubBindingTransportError) as exc_info:
        transport.get_json(
            "/repos/fastify/fast-uri",
            token=token,
        )

    assert token not in str(exc_info.value)
    assert exc_info.value.reason == "github_transport_failed"


def test_cli_writes_json_and_returns_nonzero_for_unverified_binding(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    output_path = tmp_path / "binding.json"
    monkeypatch.setattr(
        cli,
        "audit_candidate_hunter_upstream_binding",
        lambda fixture_root, github_token=None: {
            "status": "failed",
            "binding_level": "operator_attested",
            "source_repository_binding_verified": False,
        },
    )
    monkeypatch.setenv("GITHUB_TOKEN", "must-not-appear")

    exit_code = cli.main(
        [
            "candidate-hunter-upstream-binding-audit",
            "--fixture-root",
            str(PILOT_CORPUS),
            "--output",
            str(output_path),
        ]
    )

    assert exit_code == 1
    assert _read_json(output_path)["binding_level"] == "operator_attested"
    assert "must-not-appear" not in output_path.read_text(encoding="utf-8")


@pytest.mark.skipif(
    os.getenv("MYTHOS_RUN_LIVE_GITHUB_BINDING") != "1",
    reason="set MYTHOS_RUN_LIVE_GITHUB_BINDING=1 for the bounded live pilot",
)
def test_live_github_binding_pilot():
    report = audit_candidate_hunter_upstream_binding(
        PILOT_CORPUS,
        github_token=os.getenv("GITHUB_TOKEN"),
    )

    assert report["status"] == "passed"
    assert report["binding_level"] == "live_github_verified"
    assert report["source_repository_binding_verified"] is True
    assert report["capability_level"] == "lab"
    assert report["benchmark_evaluation_allowed"] is False


def _pilot_responses() -> dict[str, dict]:
    vulnerable_sha = "dcdf690b71a7bb3a19887ada65a9ab160d83bcc0"
    fixed_sha = "876ce79b662c3e5015e4e7dffe6f37752ad34f35"
    return {
        "/repos/fastify/fast-uri": {
            "full_name": "fastify/fast-uri",
            "node_id": "R_kgDOGP5HDg",
            "html_url": "https://github.com/fastify/fast-uri",
            "url": "https://api.github.com/repos/fastify/fast-uri",
            "fork": False,
            "private": False,
        },
        f"/repos/fastify/fast-uri/git/commits/{vulnerable_sha}": (
            _commit_response(
                vulnerable_sha,
                "2aaab29a2ce6bab4a2764218fc6e13f2d4dbb57a",
            )
        ),
        f"/repos/fastify/fast-uri/git/commits/{fixed_sha}": _commit_response(
            fixed_sha,
            "0c7199ad752f77a4d05d3974b7a0f24f7e21aab8",
        ),
    }


def _commit_response(sha: str, tree_sha: str) -> dict:
    api_root = "https://api.github.com/repos/fastify/fast-uri"
    web_root = "https://github.com/fastify/fast-uri"
    return {
        "sha": sha,
        "node_id": f"C_{sha}",
        "url": f"{api_root}/git/commits/{sha}",
        "html_url": f"{web_root}/commit/{sha}",
        "tree": {
            "sha": tree_sha,
            "url": f"{api_root}/git/trees/{tree_sha}",
        },
    }


def _reasons(report: dict) -> set[str]:
    return {failure["reason"] for failure in report["failures"]}


def _read_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _write_json(path: Path, value: dict) -> None:
    path.write_text(json.dumps(value, indent=2), encoding="utf-8")
