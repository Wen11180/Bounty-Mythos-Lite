"""Phase 3 asset identity and fail-closed admission tests."""

from __future__ import annotations

import pytest

from app.bounty_autopilot.asset_admission import (
    AdmissionDecision,
    AssetIdentity,
    AssetProvenance,
    NetworkIdentityObservation,
    ScopeMatcher,
    compute_asset_id,
    compute_identity_digest,
    decide_admission,
    is_active_plan_asset_eligible,
    parse_asset_url,
)


def _matcher(**updates) -> ScopeMatcher:
    payload = {
        "include_hosts": ("lab.local", "*.lab.local"),
        "exclude_hosts": (),
        "include_path_prefixes": ("/",),
        "exclude_path_prefixes": (),
        "scope_snapshot_digest": "sha256:" + ("a" * 64),
    }
    payload.update(updates)
    return ScopeMatcher(**payload)


def test_seed_discovered_linked_assets_have_deterministic_ids():
    seed = parse_asset_url("https://lab.local:8443/api", provenance=AssetProvenance.SEED)
    discovered = parse_asset_url(
        "https://lab.local:8443/api", provenance=AssetProvenance.DISCOVERED
    )
    linked = AssetIdentity(
        scheme="https",
        host="lab.local",
        port=8443,
        path_authority="/api",
        provenance=AssetProvenance.LINKED,
    )

    assert compute_asset_id(seed).startswith("asset_")
    assert len(compute_asset_id(seed)) == len("asset_") + 32
    assert compute_asset_id(seed) != compute_asset_id(discovered)
    assert compute_asset_id(discovered) != compute_asset_id(linked)
    assert compute_identity_digest(seed) == compute_identity_digest(
        parse_asset_url("https://lab.local:8443/api", provenance=AssetProvenance.SEED)
    )


def test_exact_exclusion_overrides_wildcard_inclusion():
    matcher = _matcher(
        include_hosts=("*.lab.local",),
        exclude_hosts=("admin.lab.local",),
    )
    identity = parse_asset_url(
        "https://admin.lab.local/api", provenance=AssetProvenance.DISCOVERED
    )
    record = decide_admission(identity, matcher)
    assert record.decision is AdmissionDecision.EXCLUDED
    assert record.reason == "exact_exclusion"


def test_wildcard_host_inclusion_does_not_include_the_apex_host():
    matcher = _matcher(include_hosts=("*.lab.local",), exclude_hosts=())
    apex = parse_asset_url("https://lab.local/api", provenance=AssetProvenance.SEED)
    child = parse_asset_url("https://api.lab.local/api", provenance=AssetProvenance.SEED)

    assert decide_admission(apex, matcher).decision is AdmissionDecision.EXCLUDED
    assert decide_admission(child, matcher).decision is AdmissionDecision.ADMITTED


def test_ambiguous_wildcard_and_conflicting_cases_need_scope_review():
    identity = parse_asset_url("https://a.lab.local/", provenance=AssetProvenance.SEED)

    ambiguous = decide_admission(
        identity,
        _matcher(include_hosts=("*lab.local",), exclude_hosts=()),
    )
    assert ambiguous.decision is AdmissionDecision.NEEDS_SCOPE_REVIEW
    assert ambiguous.reason == "ambiguous_wildcard"

    unsafe_path = decide_admission(
        identity,
        _matcher(include_path_prefixes=("/../secret",)),
    )
    assert unsafe_path.decision is AdmissionDecision.NEEDS_SCOPE_REVIEW
    assert unsafe_path.reason == "unsafe_path_prefix"

    stale = decide_admission(
        identity,
        _matcher(),
        scope_snapshot_digest="sha256:" + ("b" * 64),
    )
    assert stale.decision is AdmissionDecision.NEEDS_SCOPE_REVIEW
    assert stale.reason == "stale_scope"

    unknown = decide_admission(identity, _matcher(), ownership_known=False)
    assert unknown.decision is AdmissionDecision.NEEDS_SCOPE_REVIEW
    assert unknown.reason == "unknown_ownership"


def test_discovery_never_implies_admission_and_active_plan_requires_admitted():
    identity = parse_asset_url(
        "https://out.example/", provenance=AssetProvenance.DISCOVERED
    )
    record = decide_admission(identity, _matcher(include_hosts=("lab.local",)))
    assert record.decision is not AdmissionDecision.ADMITTED
    assert not is_active_plan_asset_eligible(
        record, current_scope_snapshot_digest=_matcher().scope_snapshot_digest
    )

    admitted_identity = parse_asset_url(
        "https://lab.local/", provenance=AssetProvenance.SEED
    )
    admitted = decide_admission(admitted_identity, _matcher())
    assert admitted.decision is AdmissionDecision.ADMITTED
    assert is_active_plan_asset_eligible(
        admitted, current_scope_snapshot_digest=admitted.scope_snapshot_digest
    )
    assert not is_active_plan_asset_eligible(
        admitted, current_scope_snapshot_digest="sha256:" + ("c" * 64)
    )


def test_admission_records_network_identity_without_response_content():
    identity = parse_asset_url("https://lab.local/", provenance=AssetProvenance.SEED)
    network = NetworkIdentityObservation(
        dns_names=("lab.local",),
        cname_chain=("cdn.lab.local",),
        resolved_ips=("127.0.0.1", "10.0.0.2"),
    )
    record = decide_admission(identity, _matcher(), network=network)
    assert record.network.dns_names == ("lab.local",)
    assert record.network.cname_chain == ("cdn.lab.local",)
    assert record.network.resolved_ips == ("10.0.0.2", "127.0.0.1")
    dumped = record.model_dump()
    assert "response" not in dumped
    assert "body" not in dumped
    assert "content" not in dumped


def test_identity_change_invalidates_eligibility():
    identity = parse_asset_url("https://lab.local/", provenance=AssetProvenance.SEED)
    previous = compute_identity_digest(identity)
    changed = AssetIdentity(
        scheme="https",
        host="lab.local",
        port=443,
        path_authority="/v2",
        provenance=AssetProvenance.SEED,
    )
    record = decide_admission(
        changed,
        _matcher(),
        previous_identity_digest=previous,
    )
    assert record.decision is AdmissionDecision.IDENTITY_STALE
    assert record.reason == "identity_changed"
    assert not is_active_plan_asset_eligible(
        record, current_scope_snapshot_digest=_matcher().scope_snapshot_digest
    )


def test_parse_asset_url_rejects_unsupported_scheme():
    with pytest.raises(ValueError, match="unsupported_scheme"):
        parse_asset_url("ftp://lab.local/", provenance=AssetProvenance.SEED)


def test_path_scope_matching_uses_segment_boundaries_and_canonical_paths():
    matcher = _matcher(include_path_prefixes=("/api",))
    sibling = AssetIdentity(
        scheme="https",
        host="lab.local",
        port=443,
        path_authority="/api2",
        provenance=AssetProvenance.SEED,
    )
    assert decide_admission(sibling, matcher).decision is AdmissionDecision.EXCLUDED

    for url in (
        "https://lab.local/api?op=delete",
        "https://lab.local/api#hidden",
        "https://lab.local/api%2Fother",
    ):
        with pytest.raises(ValueError, match="unsafe_path_prefix"):
            parse_asset_url(url, provenance=AssetProvenance.SEED)
