from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.db import Base
from app.human_residual_gate import (
    GATE_READY_FOR_REVIEW,
    GATE_REJECTED,
    attach_human_residual_gates_to_bridge_result,
)
from app.human_review_approvals import (
    APPROVAL_KIND_PATCH,
    APPROVAL_KIND_RESIDUAL,
    STATUS_APPROVED,
    STATUS_REJECTED_FP,
    build_human_review_approval,
    decide_human_review_approval,
    load_package_human_review_approvals,
    patch_context_from_approval,
    persist_human_review_approval,
    residual_flags_from_approval,
    human_review_approval_from_db_record,
    select_approval_for_candidate,
)
from app.patch_suggestion import attach_patch_suggestions_to_bridge_result
from app.repository import DatabaseRepository


def _bridge_with_draft(package_id: str = "pkg") -> dict:
    return {
        "package_id": package_id,
        "drafts": [
            {
                "candidate_id": "H-1",
                "root_cause_id": "missing_ssrf_validation:x",
                "vuln_type": "ssrf",
                "affected_code_path": "app/fetch.py",
                "route": {"method": "GET", "path": "/proxy"},
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


def test_build_and_decide_residual_never_unlocks_execution():
    req = build_human_review_approval(
        approval_kind=APPROVAL_KIND_RESIDUAL,
        package_id="pkg",
        candidate_id="H-1",
        actor="reviewer",
        reason="Need residual review; Authorization: Bearer live-token-xyz",
        status="requested",
    )
    assert req.status == "requested"
    assert req.reason == "[REDACTED]"
    assert req.execution_allowed is False
    assert req.report_submission_allowed is False

    decided = decide_human_review_approval(
        req,
        decision="approved",
        actor="lead",
        reason="Residuals cleared with local evidence",
    )
    assert decided.status == STATUS_APPROVED
    flags = residual_flags_from_approval(decided)
    assert flags["human_approved"] is True
    assert flags["human_rejected"] is False
    assert decided.execution_allowed is False
    assert decided.validation_allowed is False
    assert decided.report_submission_allowed is False
    assert decided.confirmed_vulnerability is False
    assert decided.patch_ready is False
    assert decided.auto_pr_allowed is False


def test_reject_fp_maps_to_human_rejected():
    rec = build_human_review_approval(
        approval_kind="residual",
        status="rejected_fp",
        package_id="pkg",
        candidate_id="H-2",
    )
    flags = residual_flags_from_approval(rec)
    assert flags["human_rejected"] is True
    assert flags["human_approved"] is False
    assert rec.report_submission_allowed is False


def test_candidate_specific_approval_cannot_authorize_a_different_candidate():
    approval = build_human_review_approval(
        approval_kind=APPROVAL_KIND_RESIDUAL,
        status="approved",
        package_id="pkg",
        candidate_id="H-001",
    )

    selected = select_approval_for_candidate(
        [approval],
        approval_kind=APPROVAL_KIND_RESIDUAL,
        package_id="pkg",
        candidate_id="H-009",
    )

    assert selected is None


def test_patch_approval_never_sets_patch_ready():
    rec = build_human_review_approval(
        approval_kind=APPROVAL_KIND_PATCH,
        status="approved",
        package_id="pkg",
        candidate_id="H-1",
    )
    ctx = patch_context_from_approval(rec)
    assert ctx["patch_review_accepted"] is True
    assert ctx["human_patch_reviewed"] is True
    assert ctx["patch_ready"] is False
    assert ctx["auto_pr_allowed"] is False
    assert rec.patch_ready is False
    assert rec.auto_pr_allowed is False
    assert rec.pr_opened is False


def test_expired_approval_fail_closed():
    past = datetime.now(UTC) - timedelta(hours=1)
    rec = build_human_review_approval(
        approval_kind=APPROVAL_KIND_RESIDUAL,
        status="approved",
        expires_at=past,
        package_id="pkg",
    )
    flags = residual_flags_from_approval(rec)
    assert flags["human_approved"] is False
    assert flags["active"] is False


def test_load_package_approvals(tmp_path: Path):
    inputs = tmp_path / "inputs"
    inputs.mkdir()
    (inputs / "human_review_approvals.json").write_text(
        json.dumps(
            {
                "approvals": [
                    {
                        "approval_kind": "residual_review",
                        "status": "approved",
                        "candidate_id": "H-1",
                        "actor": "human",
                        "reason": "cleared residuals",
                    },
                    {
                        "approval_kind": "patch_review",
                        "status": "approved",
                        "candidate_id": "H-1",
                        "actor": "human",
                        "reason": "advisory ok",
                    },
                ]
            }
        ),
        encoding="utf-8",
    )
    # secret-looking filename skipped
    residual_dir = inputs / "approvals"
    residual_dir.mkdir()
    (residual_dir / "token_secret.json").write_text(
        json.dumps({"approvals": [{"approval_kind": "residual_review", "status": "approved"}]}),
        encoding="utf-8",
    )

    bundle = load_package_human_review_approvals(tmp_path)
    assert bundle["present"] is True
    assert len(bundle["approvals"]) == 2
    assert any("blocked_filename" in s for s in bundle["skipped"])
    assert bundle["execution_allowed"] is False
    assert bundle["patch_ready"] is False
    assert bundle["report_submission_allowed"] is False


def test_attach_residual_gate_uses_durable_approval(tmp_path: Path):
    inputs = tmp_path / "inputs"
    inputs.mkdir()
    (inputs / "human_review_approvals.json").write_text(
        json.dumps(
            {
                "approvals": [
                    {
                        "approval_kind": "residual_review",
                        "status": "approved",
                        "candidate_id": "H-1",
                        "actor": "human",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    bridge = _bridge_with_draft(tmp_path.name)
    bridge["package_root"] = str(tmp_path)
    # residuals all answered so approved can mark ready
    out = attach_human_residual_gates_to_bridge_result(
        bridge,
        package_root=tmp_path,
        residual_checklist=[
            {"item_id": "R1", "question": "q1", "status": "answered"},
        ],
    )
    assert out["report_submission_allowed"] is False
    assert out["execution_allowed"] is False
    assert out["confirmed_vulnerability"] is False
    assert out["human_review_approvals_present"] is True
    gate = out["human_residual_gates"][0]
    assert gate["human_approved"] is True
    assert gate["status"] == GATE_READY_FOR_REVIEW
    assert gate["report_submission_allowed"] is False


def test_attach_residual_gate_reject_fp(tmp_path: Path):
    inputs = tmp_path / "inputs"
    inputs.mkdir()
    (inputs / "human_review_approvals.json").write_text(
        json.dumps(
            {
                "approvals": [
                    {
                        "approval_kind": "residual_review",
                        "status": "rejected_fp",
                        "candidate_id": "H-1",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    out = attach_human_residual_gates_to_bridge_result(
        _bridge_with_draft(tmp_path.name),
        package_root=tmp_path,
        residual_checklist=[],
    )
    gate = out["human_residual_gates"][0]
    assert gate["status"] == GATE_REJECTED
    assert out["report_submission_allowed"] is False


def test_attach_patch_suggestion_stamps_review_context(tmp_path: Path):
    inputs = tmp_path / "inputs"
    inputs.mkdir()
    (inputs / "human_review_approvals.json").write_text(
        json.dumps(
            {
                "approvals": [
                    {
                        "approval_kind": "patch_review",
                        "status": "approved",
                        "candidate_id": "H-1",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    bridge = _bridge_with_draft(tmp_path.name)
    bridge["package_root"] = str(tmp_path)
    out = attach_patch_suggestions_to_bridge_result(
        bridge,
        package_root=tmp_path,
    )
    assert out["patch_suggestion_present"] is True
    assert out["auto_pr_allowed"] is False
    assert out["patch_ready"] is False
    assert out["report_submission_allowed"] is False
    sug = out["patch_suggestions"][0]
    assert sug["human_patch_reviewed"] is True
    assert sug["patch_review_accepted"] is True
    assert sug["patch_ready"] is False
    assert sug["auto_pr_allowed"] is False
    assert sug["exploit_poc_included"] is False


def test_persist_and_rehydrate_via_repository():
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    session = Session()
    repo = DatabaseRepository(session)

    approval = build_human_review_approval(
        approval_kind=APPROVAL_KIND_RESIDUAL,
        package_id="pkg",
        candidate_id="H-1",
        actor="reviewer",
        reason="residual cleared",
        status="approved",
        decided_by="reviewer",
        decision_reason="ok",
    )
    db = persist_human_review_approval(repo, approval)
    assert db.id.startswith("approval_")
    assert db.approval_type == APPROVAL_KIND_RESIDUAL
    assert db.payload.get("execution_allowed") is False
    assert db.payload.get("report_submission_allowed") is False
    assert db.payload.get("patch_ready") is False

    rehydrated = human_review_approval_from_db_record(db)
    assert rehydrated.approval_kind == APPROVAL_KIND_RESIDUAL
    flags = residual_flags_from_approval(rehydrated)
    assert flags["human_approved"] is True
    assert rehydrated.execution_allowed is False
    assert rehydrated.report_submission_allowed is False

    # rejected_fp maps through payload
    fp = build_human_review_approval(
        approval_kind=APPROVAL_KIND_RESIDUAL,
        status=STATUS_REJECTED_FP,
        package_id="pkg",
        candidate_id="H-9",
        actor="reviewer",
        reason="fp",
    )
    db_fp = persist_human_review_approval(repo, fp)
    re_fp = human_review_approval_from_db_record(db_fp)
    assert residual_flags_from_approval(re_fp)["human_rejected"] is True

def test_attach_counters_and_status(tmp_path: Path):
    inputs = tmp_path / "inputs"
    inputs.mkdir()
    (inputs / "human_review_approvals.json").write_text(
        json.dumps(
            {
                "approvals": [
                    {
                        "approval_kind": "residual_review",
                        "status": "approved",
                        "candidate_id": "H-1",
                        "actor": "human",
                        "reason": "cleared residuals",
                    },
                    {
                        "approval_kind": "patch_review",
                        "status": "approved",
                        "candidate_id": "H-1",
                        "actor": "human",
                        "reason": "advisory ok",
                    },
                ]
            }
        ),
        encoding="utf-8",
    )
    bridge = _bridge_with_draft()
    from app.human_review_approvals import attach_human_review_approvals_to_bridge_result

    out = attach_human_review_approvals_to_bridge_result(
        bridge,
        package_root=tmp_path,
    )
    assert out["human_review_approvals_present"] is True
    assert out["human_review_approvals_status"] == "human_review_approvals_ready"
    assert out["human_review_approvals_count"] == 2
    assert out["human_review_approvals_decided_count"] == 2
    assert out["human_review_approvals_residual_count"] == 1
    assert out["human_review_approvals_patch_count"] == 1
    assert out["human_review_approvals_approved_count"] == 2
    assert out["patch_ready"] is False
    assert out["report_submission_allowed"] is False
    assert out["execution_allowed"] is False
    assert out["finding_promotion_allowed"] is False
    summary = out["human_review_approvals_summary"]
    assert summary["decided_count"] == 2
    assert summary["patch_ready"] is False


def test_attach_empty_status_without_package():
    from app.human_review_approvals import attach_human_review_approvals_to_bridge_result

    out = attach_human_review_approvals_to_bridge_result(_bridge_with_draft())
    assert out["human_review_approvals_present"] is False
    assert out["human_review_approvals_status"] == "human_review_approvals_empty"
    assert out["human_review_approvals_count"] == 0
    assert out["report_submission_allowed"] is False

def test_mev_signal_from_human_review_approvals():
    from app.multi_engine_verifier import (
        ENGINE_HUMAN_REVIEW_APPROVALS,
        build_multi_engine_verdict,
        signal_from_human_review_approvals,
    )

    ready = signal_from_human_review_approvals(
        {
            "status": "human_review_approvals_ready",
            "human_review_approvals_status": "human_review_approvals_ready",
            "human_review_approvals_count": 2,
            "human_review_approvals_decided_count": 2,
            "human_review_approvals_residual_count": 1,
            "human_review_approvals_patch_count": 1,
            "present": True,
            "approvals": [
                {"approval_kind": "residual_review", "status": "approved"},
                {"approval_kind": "patch_review", "status": "approved"},
            ],
        }
    )
    assert ready is not None
    assert ready["status"] == "ready"
    blocked = signal_from_human_review_approvals(
        {
            "present": True,
            "approvals": [],
            "execution_allowed": True,
        }
    )
    assert blocked is not None
    assert blocked["status"] == "blocked"
    assert "human_review_approvals_unsafe_flags_forced_block" in blocked["notes"]

    verdict = build_multi_engine_verdict(
        candidate={"candidate_id": "H-001"},
        human_review_approvals_signal=ready,
    )
    engines = {e.engine for e in verdict.engines}
    assert ENGINE_HUMAN_REVIEW_APPROVALS in engines
    assert verdict.execution_allowed is False
    assert verdict.confirmed_vulnerability is False
    assert verdict.report_submission_allowed is False


def test_scheduler_t018():
    from app.industrial_scheduler import build_industrial_scheduler_plan

    plan = build_industrial_scheduler_plan({"findings": []})
    task_by_id = {t.task_id: t for t in plan.dag_tasks}
    assert "T-018" in task_by_id
    assert task_by_id["T-018"].agent == "human_review_approvals_agent"
    assert task_by_id["T-018"].execution_allowed is False
    assert task_by_id["T-018"].requires_human_review is True
    assert plan.human_review_approvals.patch_ready is False
    assert plan.human_review_approvals.report_submission_allowed is False
    assert plan.human_review_approvals.execution_allowed is False
    batch_ids = {b.batch_id for b in plan.parallel_batches}
    assert "B-015" in batch_ids
