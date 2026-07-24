import base64
import hashlib
import json
from pathlib import Path

from app.program_rule_intake.contracts import StaticRuleDocumentEnvelope
from app.program_rule_intake.extractor import extract_deterministic_rules
from app.program_rule_intake.normalizer import normalize_rule_document
from app.program_rule_intake.service import _diff_values


FIXTURE_ROOT = Path(__file__).parent / "fixtures" / "program_rule_intake"
ROOT_URL = "https://rules.example.test/program"
OPENAPI_URL = "https://rules.example.test/openapi.yaml"
FORBIDDEN_OUTPUT = (
    "RAW_HTML_SENTINEL",
    "FIXTURE_SECRET",
    "Authorization:",
    "Cookie:",
    "eyJ",
    "customer@example.test",
    "raw_openapi_example",
)


def test_versioned_release_extraction_matches_reviewed_gold():
    extraction, documents = _release_extraction("release-policy-v1.html")

    assert extraction.model_dump(mode="json") == _load_json(
        "expected-release-extraction-v1.json"
    )
    _assert_complete_evidence(extraction, documents)
    _assert_safe_output(extraction.model_dump_json())


def test_versioned_policy_change_matches_reviewed_diff_gold():
    approved, _ = _release_extraction("release-policy-v1.html")
    pending, pending_documents = _release_extraction("release-policy-v2.html")
    actual = json.loads(
        json.dumps(
            _diff_values(approved, pending),
            default=lambda value: value.model_dump(mode="json"),
            sort_keys=True,
        )
    )

    assert actual == _load_json("expected-release-diff-v1-v2.json")
    _assert_complete_evidence(pending, pending_documents)
    _assert_safe_output(json.dumps(actual, sort_keys=True))


def test_release_gold_contains_only_synthetic_review_safe_values():
    for name in (
        "expected-release-extraction-v1.json",
        "expected-release-diff-v1-v2.json",
    ):
        text = (FIXTURE_ROOT / name).read_text(encoding="utf-8")
        assert ".example.com" not in text
        assert "http://" not in text
        _assert_safe_output(text)


def _release_extraction(policy_name):
    documents = [
        _normalize_fixture(policy_name, ROOT_URL, "text/html", depth=0),
        _normalize_fixture(
            "release-openapi-v1.yaml",
            OPENAPI_URL,
            "application/yaml",
            depth=1,
        ),
    ]
    return extract_deterministic_rules(documents), documents


def _normalize_fixture(name, source_url, content_type, *, depth):
    raw = (FIXTURE_ROOT / name).read_bytes()
    return normalize_rule_document(
        StaticRuleDocumentEnvelope(
            mode="static",
            source_url=source_url,
            depth=depth,
            content_type=content_type,
            charset="utf-8",
            body_base64=base64.b64encode(raw).decode("ascii"),
            raw_sha256=hashlib.sha256(raw).hexdigest(),
        )
    )


def _load_json(name):
    return json.loads((FIXTURE_ROOT / name).read_text(encoding="utf-8"))


def _assert_complete_evidence(extraction, documents):
    document_digests = {document.normalized_sha256 for document in documents}
    evidence = {item.evidence_id: item for item in extraction.evidence}
    assert evidence
    assert all(item.document_sha256 in document_digests for item in evidence.values())
    assert all(0 < len(item.excerpt) <= 500 for item in evidence.values())

    for rule in extraction.rules:
        refs = set(rule.scope_evidence_ids) | set(rule.automation_evidence_ids)
        for values in rule.prohibited_evidence_ids.values():
            refs.update(values)
        if rule.rate_limit is not None:
            refs.update(rule.rate_limit.evidence_ids)
        assert refs
        assert refs <= evidence.keys()
    for artifact in extraction.linked_artifacts:
        assert set(artifact.evidence_ids) <= evidence.keys()


def _assert_safe_output(value):
    for marker in FORBIDDEN_OUTPUT:
        assert marker not in value
