from __future__ import annotations

from pathlib import Path
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.db import Base, get_session
from app.main import app
from app.repository import seed_sample_data
from app.residual_patch_decision_api import (
    ResidualPatchDecisionCreate,
    create_residual_patch_decision,
    decide_residual_patch_decision,
    list_residual_patch_decisions,
    to_decision_view,
)
from app.human_review_approvals import build_human_review_approval


client = TestClient(app)


def build_testing_session_override():
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    testing_session = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
    with testing_session() as session:
        seed_sample_data(session)

    def _override_get_session():
        with testing_session() as session:
            yield session

    return testing_session, _override_get_session


def test_module_create_decide_never_unlocks():
    created = create_residual_patch_decision(
        ResidualPatchDecisionCreate(
            approval_kind="residual_review",
            package_id="pkg",
            candidate_id="H-1",
            actor="reviewer",
            reason="Need residual; Authorization: Bearer live-token",
            persist=False,
        ),
        repository=None,
    )
    assert created.status == "requested"
    assert created.execution_allowed is False
    assert created.report_submission_allowed is False
    assert created.patch_ready is False
    assert "live-token" not in created.reason

    decided = decide_residual_patch_decision(
        approval_id=created.approval_id,
        body={"decision": "approved", "actor": "lead", "reason": "cleared"},
        current=created.model_dump(),
        repository=None,
    )
    assert decided.status == "approved"
    assert decided.residual_flags["human_approved"] is True
    assert decided.execution_allowed is False
    assert decided.validation_allowed is False
    assert decided.report_submission_allowed is False
    assert decided.confirmed_vulnerability is False
    assert decided.patch_ready is False
    assert decided.auto_pr_allowed is False

    patch = create_residual_patch_decision(
        {
            "approval_kind": "patch",
            "package_id": "pkg",
            "candidate_id": "H-1",
            "persist": False,
        },
        repository=None,
    )
    patch_dec = decide_residual_patch_decision(
        approval_id=patch.approval_id,
        body={"decision": "approved", "actor": "lead"},
        current=patch.model_dump(),
    )
    assert patch_dec.patch_context["patch_review_accepted"] is True
    assert patch_dec.patch_ready is False
    assert patch_dec.auto_pr_allowed is False
    assert patch_dec.pr_opened is False


def test_to_decision_view_forces_safety():
    rec = build_human_review_approval(
        approval_kind="patch_review",
        status="approved",
        package_id="pkg",
        candidate_id="H-2",
    )
    view = to_decision_view(rec)
    assert view.patch_ready is False
    assert view.auto_pr_allowed is False
    assert view.report_submission_allowed is False
    assert view.execution_allowed is False


def test_api_create_list_decide_residual():
    testing_session, override_get_session = build_testing_session_override()
    app.dependency_overrides[get_session] = override_get_session
    try:
        create_response = client.post(
            "/mythos/factory/residual-patch-decisions",
            json={
                "approval_kind": "residual_review",
                "package_id": "my-local-ssrf-retain",
                "candidate_id": "H-001",
                "actor": "reviewer",
                "reason": "Residual review request; cookie: live-cookie",
                "persist": True,
            },
        )
        assert create_response.status_code == 200, create_response.text
        created = create_response.json()
        assert created["approval_kind"] == "residual_review"
        assert created["status"] == "requested"
        assert created["execution_allowed"] is False
        assert created["report_submission_allowed"] is False
        assert created["patch_ready"] is False
        assert "live-cookie" not in str(created)
        approval_id = created["approval_id"]
        assert approval_id

        listed = client.get(
            "/mythos/factory/residual-patch-decisions",
            params={"package_id": "my-local-ssrf-retain", "approval_kind": "residual_review"},
        )
        assert listed.status_code == 200
        ids = [item["approval_id"] for item in listed.json()]
        assert approval_id in ids

        got = client.get(f"/mythos/factory/residual-patch-decisions/{approval_id}")
        assert got.status_code == 200
        assert got.json()["candidate_id"] == "H-001"

        decide = client.post(
            f"/mythos/factory/residual-patch-decisions/{approval_id}/decisions",
            json={
                "decision": "approved",
                "actor": "lead_reviewer",
                "reason": "Local static residuals cleared",
            },
        )
        assert decide.status_code == 200, decide.text
        decided = decide.json()
        assert decided["status"] == "approved"
        assert decided["residual_flags"]["human_approved"] is True
        assert decided["execution_allowed"] is False
        assert decided["validation_allowed"] is False
        assert decided["report_submission_allowed"] is False
        assert decided["confirmed_vulnerability"] is False
        assert decided["patch_ready"] is False
        assert decided["auto_pr_allowed"] is False
    finally:
        app.dependency_overrides.clear()


def test_api_patch_rejected_fp_never_patch_ready():
    testing_session, override_get_session = build_testing_session_override()
    app.dependency_overrides[get_session] = override_get_session
    try:
        create_response = client.post(
            "/mythos/factory/residual-patch-decisions",
            json={
                "approval_kind": "patch_review",
                "package_id": "pkg",
                "candidate_id": "H-9",
                "actor": "reviewer",
                "reason": "patch advisory review",
                "persist": True,
            },
        )
        assert create_response.status_code == 200
        approval_id = create_response.json()["approval_id"]
        decide = client.post(
            f"/mythos/factory/residual-patch-decisions/{approval_id}/decisions",
            json={"decision": "rejected_fp", "actor": "lead", "reason": "false positive"},
        )
        assert decide.status_code == 200, decide.text
        body = decide.json()
        assert body["status"] == "rejected_fp"
        assert body["patch_context"]["patch_review_rejected"] is True
        assert body["patch_ready"] is False
        assert body["auto_pr_allowed"] is False
        assert body["report_submission_allowed"] is False
    finally:
        app.dependency_overrides.clear()


def test_api_rejects_unknown_kind():
    testing_session, override_get_session = build_testing_session_override()
    app.dependency_overrides[get_session] = override_get_session
    try:
        resp = client.post(
            "/mythos/factory/residual-patch-decisions",
            json={
                "approval_kind": "validation_batch",
                "package_id": "pkg",
                "actor": "x",
                "reason": "nope",
            },
        )
        assert resp.status_code == 400
        assert "unsupported_approval_kind" in resp.json()["detail"]
    finally:
        app.dependency_overrides.clear()


def test_list_package_offline_optional():
    # package may or may not have offline approvals; call must not unlock
    views = list_residual_patch_decisions(
        repository=None,
        package_root="authorized_packages/my-local-ssrf-retain",
        package_id="my-local-ssrf-retain",
    )
    for v in views:
        assert v.execution_allowed is False
        assert v.report_submission_allowed is False
        assert v.patch_ready is False



def test_snapshot_export_import_attach_safety(tmp_path: Path):
    from app.residual_patch_decision_api import (
        STATUS_READY,
        STATUS_WRITTEN,
        STATUS_IMPORTED,
        attach_residual_patch_decision_api_to_bridge_result,
        build_residual_patch_decision_snapshot,
        export_residual_patch_decision_snapshot,
        import_residual_patch_decisions_to_package,
    )

    inputs = tmp_path / "inputs"
    inputs.mkdir(parents=True)
    (inputs / "human_review_approvals.json").write_text(
        '''
{
  "approvals": [
    {
      "approval_id": "apr-residual-1",
      "approval_kind": "residual_review",
      "status": "approved",
      "package_id": "pkg-lab",
      "candidate_id": "H-001",
      "actor": "reviewer",
      "reason": "offline residual; Authorization: Bearer secret-token",
      "decided_by": "lead",
      "decided_at": "2026-07-12T00:00:00Z"
    },
    {
      "approval_id": "apr-patch-1",
      "approval_kind": "patch_review",
      "status": "approved",
      "package_id": "pkg-lab",
      "candidate_id": "H-001",
      "actor": "reviewer",
      "reason": "advisory patch accepted",
      "decided_by": "lead",
      "decided_at": "2026-07-12T00:00:01Z"
    }
  ],
  "execution_allowed": false,
  "report_submission_allowed": false,
  "patch_ready": false
}
'''.strip()
        + "\n",
        encoding="utf-8",
    )

    snap = build_residual_patch_decision_snapshot(
        package_id="pkg-lab",
        package_root=tmp_path,
    )
    assert snap["status"] == STATUS_READY
    assert snap["decision_count"] == 2
    assert snap["decided_count"] == 2
    assert snap["residual_count"] == 1
    assert snap["patch_count"] == 1
    assert snap["execution_allowed"] is False
    assert snap["patch_ready"] is False
    assert snap["report_submission_allowed"] is False
    assert "secret-token" not in str(snap)

    blocked = export_residual_patch_decision_snapshot(
        snap,
        package_root=tmp_path,
        human_allow_export_write=False,
    )
    assert blocked["export_written"] is False

    written = export_residual_patch_decision_snapshot(
        snap,
        package_root=tmp_path,
        human_allow_export_write=True,
    )
    assert written["export_written"] is True
    assert written["export_count"] == 3
    assert written["status"] == STATUS_WRITTEN
    export_root = tmp_path / "_export" / "residual_patch_decision_api"
    assert export_root.is_dir()
    stamps = list(export_root.iterdir())
    assert stamps
    assert (stamps[0] / "snapshot.json").is_file()
    assert (stamps[0] / "decisions.json").is_file()
    assert (stamps[0] / "summary.json").is_file()

    other = tmp_path / "other-pkg"
    other.mkdir()
    imported = import_residual_patch_decisions_to_package(
        written,
        package_root=other,
        human_allow_import_write=True,
    )
    assert imported["import_written"] is True
    assert imported["status"] == STATUS_IMPORTED
    assert imported["decision_count"] == 2
    assert imported["execution_allowed"] is False
    assert imported["patch_ready"] is False
    target = other / "inputs" / "human_review_approvals.json"
    assert target.is_file()
    body = target.read_text(encoding="utf-8")
    assert "apr-residual-1" in body
    assert "secret-token" not in body

    bridge = {
        "package_id": "pkg-lab",
        "package_root": str(tmp_path),
        "submission_blocked": True,
        "drafts": [],
        "human_review_approvals": snap["decisions"],
        "human_review_approvals_present": True,
        "human_review_approvals_status": "human_review_approvals_ready",
        "human_review_approvals_count": 2,
        "human_review_approvals_decided_count": 2,
        "human_review_approvals_residual_count": 1,
        "human_review_approvals_patch_count": 1,
    }
    out = attach_residual_patch_decision_api_to_bridge_result(
        bridge,
        package_root=tmp_path,
        human_allow_export_write=False,
    )
    assert out["residual_patch_decision_api_present"] is True
    assert out["residual_patch_decision_api_status"] == STATUS_READY
    assert out["residual_patch_decision_api_count"] == 2
    assert out["residual_patch_decision_api_decided_count"] == 2
    assert out["residual_patch_decision_api_residual_count"] == 1
    assert out["residual_patch_decision_api_patch_count"] == 1
    assert out["residual_patch_decision_api_export_written"] is False
    assert out["execution_allowed"] is False
    assert out["validation_allowed"] is False
    assert out["report_submission_allowed"] is False
    assert out["confirmed_vulnerability"] is False
    assert out["patch_ready"] is False
    assert out["auto_pr_allowed"] is False
    assert out["submission_blocked"] is True


def test_mev_signal_residual_patch_decision_api():
    from app.multi_engine_verifier import (
        ENGINE_RESIDUAL_PATCH_DECISION_API,
        signal_from_residual_patch_decision_api,
        deepen_multi_engine_verdict,
    )

    empty = signal_from_residual_patch_decision_api(
        {"status": "residual_patch_decision_api_empty", "decision_count": 0}
    )
    assert empty is not None
    assert empty["status"] in {"empty", "ready", "pending"}

    ready = signal_from_residual_patch_decision_api(
        {
            "status": "residual_patch_decision_api_ready",
            "decision_count": 2,
            "decided_count": 2,
            "residual_count": 1,
            "patch_count": 1,
            "export_written": False,
            "execution_allowed": False,
        }
    )
    assert ready["status"] == "ready"
    assert "residual_patch_decision_api:decided" in ready["evidence_refs"]

    blocked = signal_from_residual_patch_decision_api(
        {
            "status": "residual_patch_decision_api_ready",
            "decision_count": 1,
            "patch_ready": True,
        }
    )
    assert blocked["status"] == "blocked"

    deep = deepen_multi_engine_verdict(
        {"candidate_id": "H-1", "engines": [], "status": "needs_human_review"},
        candidate={"candidate_id": "H-1"},
        residual_patch_decision_api={
            "status": "residual_patch_decision_api_ready",
            "decision_count": 1,
            "decided_count": 1,
            "execution_allowed": False,
        },
    )
    names = [e.engine for e in deep.engines]
    assert ENGINE_RESIDUAL_PATCH_DECISION_API in names
