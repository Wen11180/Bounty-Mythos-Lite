from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from app.bounty_autopilot.contracts import (
    ActiveHoursWindow,
    AutopilotBudgets,
    CampaignAuthorization,
    RecipeRef,
    campaign_authorization_from_payload,
    campaign_authorization_digest,
    campaign_authorization_payload,
    canonical_sha256,
)
from app.bounty_autopilot.recipes import default_recipe_registry


NOW = datetime(2026, 7, 24, 12, 0, tzinfo=timezone.utc)
DIGEST_A = "sha256:" + ("a" * 64)
DIGEST_B = "sha256:" + ("b" * 64)


def _budget(**updates: int) -> AutopilotBudgets:
    values = {
        "max_requests": 8,
        "max_concurrency": 1,
        "max_response_bytes": 131_072,
        "max_duration_seconds": 120,
        "max_account_operations": 4,
        "max_cost_microusd": 500_000,
    }
    values.update(updates)
    return AutopilotBudgets(**values)


def _payload() -> dict:
    registry = default_recipe_registry()
    return {
        "campaign_id": "campaign_lab_1",
        "scope_snapshot_id": "scope_snapshot_1",
        "scope_review_state": "approved",
        "scope_snapshot_digest": DIGEST_A,
        "policy_digest": DIGEST_B,
        "asset_ids": ("asset_api", "asset_web"),
        "account_aliases": ("owned_alpha", "owned_beta"),
        "recipe_refs": (
            registry.require("lab_browser_mapping", "1.0.0").ref,
            registry.require("passive_rule_snapshot_analysis", "1.0.0").ref,
        ),
        "max_automatic_risk": "R2",
        "policy_mode": "authorized_local_lab",
        "network_profile": "authorized_local_lab",
        "allowed_method_classes": ("read_only", "passive"),
        "active_hours_utc": (
            ActiveHoursWindow(
                days_utc=(0, 1, 2, 3, 4, 5, 6),
                start_minute_utc=0,
                end_minute_utc=1440,
            ),
        ),
        "budgets": _budget(),
        "issued_at": NOW,
        "expires_at": datetime(2026, 7, 31, 12, 0, tzinfo=timezone.utc),
        "operator_identity": "operator.local",
    }


def test_campaign_authorization_requires_every_authority_binding():
    payload = _payload()
    required = {
        "campaign_id",
        "scope_snapshot_id",
        "scope_review_state",
        "scope_snapshot_digest",
        "policy_digest",
        "asset_ids",
        "account_aliases",
        "recipe_refs",
        "max_automatic_risk",
        "policy_mode",
        "network_profile",
        "allowed_method_classes",
        "active_hours_utc",
        "budgets",
        "issued_at",
        "expires_at",
        "operator_identity",
    }

    for field in required:
        incomplete = dict(payload)
        incomplete.pop(field)
        with pytest.raises(ValidationError):
            CampaignAuthorization(**incomplete)


def test_authorization_digest_is_canonical_and_authority_sensitive():
    first_payload = _payload()
    second_payload = _payload()
    second_payload["asset_ids"] = tuple(reversed(second_payload["asset_ids"]))
    second_payload["account_aliases"] = tuple(
        reversed(second_payload["account_aliases"])
    )
    second_payload["recipe_refs"] = tuple(reversed(second_payload["recipe_refs"]))
    second_payload["allowed_method_classes"] = tuple(
        reversed(second_payload["allowed_method_classes"])
    )

    first = CampaignAuthorization(**first_payload)
    reordered = CampaignAuthorization(**second_payload)
    changed_payload = _payload()
    changed_payload["max_automatic_risk"] = "R1"
    changed = CampaignAuthorization(**changed_payload)

    assert campaign_authorization_digest(first) == campaign_authorization_digest(
        reordered
    )
    assert campaign_authorization_digest(first).startswith("sha256:")
    assert len(campaign_authorization_digest(first)) == 71
    assert campaign_authorization_digest(first) != campaign_authorization_digest(
        changed
    )


def test_authorization_digest_preserves_timestamp_microseconds():
    first_payload = _payload()
    first_payload["issued_at"] = NOW.replace(microsecond=1)
    second_payload = _payload()
    second_payload["issued_at"] = NOW.replace(microsecond=2)

    assert campaign_authorization_digest(
        CampaignAuthorization(**first_payload)
    ) != campaign_authorization_digest(CampaignAuthorization(**second_payload))


def test_every_changeable_authority_field_changes_the_digest():
    registry = default_recipe_registry()
    original = CampaignAuthorization(**_payload())
    changes = {
        "campaign_id": "campaign_lab_2",
        "scope_snapshot_id": "scope_snapshot_2",
        "scope_snapshot_digest": "sha256:" + ("c" * 64),
        "policy_digest": "sha256:" + ("d" * 64),
        "asset_ids": ("asset_api", "asset_extra", "asset_web"),
        "account_aliases": ("owned_alpha", "owned_gamma"),
        "recipe_refs": (
            registry.require("passive_artifact_analysis", "1.0.0").ref,
        ),
        "max_automatic_risk": "R1",
        "policy_mode": "passive_only",
        "network_profile": "none",
        "allowed_method_classes": ("passive",),
        "active_hours_utc": (
            ActiveHoursWindow(
                days_utc=(0, 1, 2, 3, 4, 5, 6),
                start_minute_utc=1,
                end_minute_utc=1440,
            ),
        ),
        "budgets": _budget(max_requests=7),
        "issued_at": NOW.replace(microsecond=1),
        "expires_at": datetime(2026, 7, 30, 12, 0, tzinfo=timezone.utc),
        "operator_identity": "other.operator",
    }

    for field, value in changes.items():
        changed_payload = _payload()
        changed_payload[field] = value
        changed = CampaignAuthorization(**changed_payload)
        assert changed.authorization_digest != original.authorization_digest, field


def test_authorization_round_trips_through_a_jsonb_style_payload():
    authorization = CampaignAuthorization(**_payload())

    stored_payload = campaign_authorization_payload(authorization)
    restored = campaign_authorization_from_payload(stored_payload)

    assert restored == authorization
    assert restored.authorization_digest == authorization.authorization_digest
    assert "authorization_digest" not in stored_payload


def test_canonical_hash_preserves_a_real_recipe_ref_definition_digest():
    first = RecipeRef(
        recipe_id="lab_browser_mapping",
        version="1.0.0",
        definition_digest=DIGEST_A,
    )
    second = RecipeRef(
        recipe_id="lab_browser_mapping",
        version="1.0.0",
        definition_digest=DIGEST_B,
    )

    assert canonical_sha256(first) != canonical_sha256(second)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("asset_ids", ()),
        ("account_aliases", ("owned_alpha", "owned_alpha")),
        (
            "budgets",
            {
                "max_requests": 0,
                "max_concurrency": 1,
                "max_response_bytes": 131_072,
                "max_duration_seconds": 120,
                "max_account_operations": 4,
                "max_cost_microusd": 500_000,
            },
        ),
    ],
)
def test_authorization_rejects_empty_duplicate_or_unbounded_contracts(
    field: str, value: object
):
    payload = _payload()
    payload[field] = value

    with pytest.raises(ValidationError):
        CampaignAuthorization(**payload)


@pytest.mark.parametrize(
    ("recipe_id", "version", "definition_digest"),
    [
        ("missing_recipe", "1.0.0", DIGEST_A),
        ("lab_browser_mapping", "9.9.9", DIGEST_A),
        ("lab_browser_mapping", "1.0.0", DIGEST_A),
    ],
)
def test_authorization_rejects_unknown_or_digest_drifted_recipe_refs(
    recipe_id: str, version: str, definition_digest: str
):
    payload = _payload()
    payload["recipe_refs"] = (
        {
            "recipe_id": recipe_id,
            "version": version,
            "definition_digest": definition_digest,
        },
    )

    with pytest.raises(ValidationError):
        CampaignAuthorization(**payload)


def test_authorization_contract_is_frozen_and_rejects_extra_fields():
    authorization = CampaignAuthorization(**_payload())

    with pytest.raises(ValidationError):
        authorization.operator_identity = "other.operator"

    with pytest.raises(ValidationError):
        CampaignAuthorization(**_payload(), caller_claimed_allowed=True)
