from __future__ import annotations

import json
from pathlib import Path

from app.human_residual_gate import (
    GATE_HOLD,
    GATE_READY_FOR_REVIEW,
    GATE_REJECTED,
    attach_human_residual_gates_to_bridge_result,
    build_human_residual_gate,
    load_package_residual_checklist,
    residual_checklist_from_bundle,
)


def test_load_package_residual_checklist_missing_is_absent(tmp_path: Path):
    bundle = load_package_residual_checklist(tmp_path)
    assert bundle["present"] is False
    assert bundle["items"] == []
    assert bundle["execution_allowed"] is False
    assert bundle["report_submission_allowed"] is False
    assert bundle["confirmed_vulnerability"] is False


def test_load_package_residual_checklist_from_extract_md(tmp_path: Path):
    extract = tmp_path / "_extract"
    extract.mkdir()
    (extract / "RESIDUAL_CHECKLIST.md").write_text(
        """# Residual checklist

| ID | Question | Static status |
| --- | --- | --- |
| LAB-R1 | User input reaches fetch? | **yes (intentional)** |
| LAB-R2 | Guard present? | **absent (intentional)** |
| LAB-R3 | Teaching only? | **held** |
| LAB-R4 | Soft residual still open? | **not checked** |

Live residual: none required.
""",
        encoding="utf-8",
    )
    # secret-looking residual under residual/ should be skipped
    residual_dir = tmp_path / "inputs" / "residual"
    residual_dir.mkdir(parents=True)
    (residual_dir / "token_secret.json").write_text(
        json.dumps({"items": [{"question": "should skip"}]}),
        encoding="utf-8",
    )

    bundle = load_package_residual_checklist(tmp_path)
    assert bundle["present"] is True
    assert any("RESIDUAL_CHECKLIST.md" in s["path"] for s in bundle["sources"])
    items = residual_checklist_from_bundle(bundle)
    assert len(items) == 4
    by_id = {item["item_id"]: item for item in items}
    assert by_id["LAB-R1"]["status"] == "waived"
    assert by_id["LAB-R2"]["status"] == "waived"
    assert by_id["LAB-R3"]["status"] == "answered"
    assert by_id["LAB-R4"]["status"] == "open"
    assert bundle["execution_allowed"] is False
    assert all("should skip" not in str(item.get("question")) for item in items)
    assert any("blocked_filename" in s for s in bundle["skipped"])


def test_load_package_residual_checklist_from_inputs_json(tmp_path: Path):
    inputs = tmp_path / "inputs"
    inputs.mkdir()
    (inputs / "residual.json").write_text(
        json.dumps(
            {
                "items": [
                    {
                        "item_id": "R-JSON-1",
                        "question": "Is ownership enforced?",
                        "status": "open",
                    },
                    {
                        "item_id": "R-JSON-2",
                        "question": "Is live validation avoided?",
                        "status": "answered",
                    },
                ]
            }
        ),
        encoding="utf-8",
    )
    bundle = load_package_residual_checklist(tmp_path)
    assert bundle["present"] is True
    items = residual_checklist_from_bundle(bundle)
    assert items[0]["item_id"] == "R-JSON-1"
    assert items[0]["status"] == "open"
    assert items[1]["status"] == "answered"


def test_attach_uses_package_residual_checklist(tmp_path: Path):
    extract = tmp_path / "_extract"
    extract.mkdir()
    (extract / "RESIDUAL_CHECKLIST.md").write_text(
        """# Residual

| ID | Question | Static status |
| --- | --- | --- |
| PKG-R1 | Package question from file? | **not checked** |
| PKG-R2 | Already held by static audit? | **held** |
""",
        encoding="utf-8",
    )
    bridge = {
        "package_id": "pkg-file",
        "package_root": str(tmp_path),
        "drafts": [
            {
                "candidate_id": "H-1",
                "root_cause_id": "missing_ssrf_validation:x",
                "execution_allowed": False,
                "validation_allowed": False,
                "report_submission_allowed": False,
                "confirmed_vulnerability": False,
                "multi_engine_verdict": {
                    "status": "local_static_consistent",
                    "candidate_id": "H-1",
                    "confirmed_vulnerability": False,
                },
                "report_draft": {"title": "Possible SSRF"},
            }
        ],
        "multi_engine_verdicts": [],
        "submission_blocked": True,
    }
    out = attach_human_residual_gates_to_bridge_result(bridge)
    assert out["residual_checklist_present"] is True
    assert out["report_submission_allowed"] is False
    gate = out["human_residual_gates"][0]
    assert gate["status"] == GATE_HOLD
    assert gate["open_residual_count"] == 1
    questions = [item["question"] for item in gate["residual_items"]]
    assert "Package question from file?" in questions
    assert any(item["status"] == "answered" for item in gate["residual_items"])


def test_attach_to_bridge_result_defaults_without_file():
    bridge = {
        "package_id": "pkg",
        "drafts": [
            {
                "candidate_id": "H-1",
                "root_cause_id": "missing_ssrf_validation:x",
                "refutation_questions": ["Is SSRF validation present?"],
                "execution_allowed": False,
                "validation_allowed": False,
                "report_submission_allowed": False,
                "confirmed_vulnerability": False,
                "multi_engine_verdict": {
                    "status": "local_static_consistent",
                    "candidate_id": "H-1",
                    "review_questions": ["Has live validation been avoided?"],
                    "confirmed_vulnerability": False,
                },
                "report_draft": {"title": "Possible SSRF"},
            }
        ],
        "multi_engine_verdicts": [],
        "submission_blocked": True,
    }
    out = attach_human_residual_gates_to_bridge_result(bridge)
    assert out["report_submission_allowed"] is False
    assert out["confirmed_vulnerability"] is False
    assert len(out["human_residual_gates"]) == 1
    assert out["drafts"][0]["human_residual_gate"]["status"] == GATE_HOLD
    assert out["drafts"][0]["report_submission_allowed"] is False


def test_hold_when_open_residuals():
    gate = build_human_residual_gate(
        package_id="pkg",
        candidate={"candidate_id": "H-1", "root_cause_id": "missing_ssrf_validation:x"},
        multi_engine_verdict={
            "status": "local_static_consistent",
            "candidate_id": "H-1",
            "confirmed_vulnerability": False,
        },
        residual_checklist=["Is ownership enforced?", "Is live validation avoided?"],
    )
    assert gate.status == GATE_HOLD
    assert gate.open_residual_count == 2
    assert gate.report_submission_allowed is False
    assert gate.confirmed_vulnerability is False
    assert gate.execution_allowed is False


def test_ready_when_residuals_answered_and_human_approved():
    gate = build_human_residual_gate(
        package_id="pkg",
        candidate={"candidate_id": "H-2"},
        multi_engine_verdict={"status": "local_static_consistent", "candidate_id": "H-2"},
        residual_checklist=[
            {"item_id": "R-01", "question": "q1", "status": "answered"},
            {"item_id": "R-02", "question": "q2", "status": "waived"},
        ],
        human_approved=True,
    )
    assert gate.status == GATE_READY_FOR_REVIEW
    assert gate.open_residual_count == 0
    assert gate.human_approved is True
    assert gate.report_submission_allowed is False


def test_blocked_on_unsafe_flags():
    from app.human_residual_gate import GATE_BLOCKED

    gate = build_human_residual_gate(
        candidate={"candidate_id": "H-3", "execution_allowed": True},
        multi_engine_verdict={"status": "needs_human_review"},
        residual_checklist=[],
        scope_allowed=False,
    )
    assert gate.status == GATE_BLOCKED
    assert "scope_not_allowed" in gate.blocked_reasons
    assert "candidate_execution_allowed_true" in gate.blocked_reasons


def test_rejected_on_human_reject():
    gate = build_human_residual_gate(
        candidate={"candidate_id": "H-4"},
        multi_engine_verdict={"status": "false_positive_likely"},
        human_rejected=True,
    )
    assert gate.status == GATE_REJECTED
    assert gate.report_submission_allowed is False