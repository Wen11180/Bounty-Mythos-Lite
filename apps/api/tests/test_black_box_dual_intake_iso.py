from __future__ import annotations

from app.intelligence_benchmark.black_box_har_golden import (
    assert_intake_isomorphism,
    default_fixture_root,
)


def test_dual_intake_iso_retain():
    result = assert_intake_isomorphism(
        default_fixture_root() / "retain_bola_widgets"
    )
    assert result["passed"] is True
    assert result["har_plan_classes"] == result["demo_plan_classes"]


def test_dual_intake_iso_refute():
    result = assert_intake_isomorphism(
        default_fixture_root() / "refute_guarded_widgets"
    )
    assert result["passed"] is True
    assert result["failures"] == []
