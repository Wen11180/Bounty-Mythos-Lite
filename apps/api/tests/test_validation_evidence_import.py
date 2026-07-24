from types import SimpleNamespace

import pytest

import app.main as main_module


class _RepositoryMustNotBeUsed:
    def __getattr__(self, name: str):
        raise AssertionError(f"unsafe validation evidence reached repository.{name}")


class _Session:
    def __init__(self, records: dict[str, object]):
        self._records = records

    def get(self, _model: object, record_id: str):
        return self._records.get(record_id)


class _StageRecordingRepository:
    def __init__(self, *, campaign: object, records: dict[str, object]):
        self._campaign = campaign
        self.session = _Session(records)
        self.saved_stages: list[dict] = []

    def get_campaign(self, campaign_id: str):
        return self._campaign if campaign_id == self._campaign.id else None

    def save_pipeline_stage(self, **kwargs):
        self.saved_stages.append(kwargs)


def _validation_run(
    *,
    status: str = "evidence_recorded",
    safety_gate_state: str,
    approval_required: bool = True,
    evidence_ref_count: int = 1,
    execution_started: bool = False,
    outcome: str = "observed",
    include_safe_evidence_ref_count: bool = True,
) -> SimpleNamespace:
    manual_result = {
        "outcome": outcome,
        "execution_started": execution_started,
    }
    if include_safe_evidence_ref_count:
        manual_result["safe_evidence_ref_count"] = evidence_ref_count
    return SimpleNamespace(
        task_id="campaign_task_validation_handoff",
        status=status,
        safety_gate_state=safety_gate_state,
        approval_required=approval_required,
        allowed_to_execute=False,
        evidence_ref_count=evidence_ref_count,
        payload={
            "source": "autonomous_validation_handoff",
            "pipeline_run_id": "pipeline_run_001",
            "handoff_task_id": "campaign_task_validation_handoff",
            "source_snapshot_digest": "sha256:" + "a" * 64,
            "approval_required": True,
            "allowed_to_execute": False,
            "execution_allowed": False,
            "dispatch_allowed": False,
            "validation_allowed": False,
            "candidate_promotion_allowed": False,
            "report_submission_allowed": False,
            "raw_payload_processed": False,
            "manual_result": manual_result,
        },
    )


@pytest.mark.parametrize(
    (
        "status",
        "safety_gate_state",
        "approval_required",
        "evidence_ref_count",
        "execution_started",
        "outcome",
        "include_safe_evidence_ref_count",
    ),
    (
        ("evidence_recorded", "manual_refutation_recorded", True, 1, False, "observed", True),
        ("evidence_recorded", "manual_evidence_recorded", False, 1, False, "observed", True),
        ("evidence_recorded", "manual_evidence_recorded", True, 0, False, "observed", True),
        ("evidence_recorded", "manual_evidence_recorded", True, 1, True, "observed", True),
        ("refuted", "manual_refutation_recorded", True, 1, False, "observed", True),
        ("needs_evidence", "manual_evidence_gap_recorded", True, 0, False, "observed", False),
    ),
)
def test_validation_evidence_import_rejects_inconsistent_terminal_record_before_repository_access(
    status: str,
    safety_gate_state: str,
    approval_required: bool,
    evidence_ref_count: int,
    execution_started: bool,
    outcome: str,
    include_safe_evidence_ref_count: bool,
):
    main_module._record_autonomous_validation_evidence_import_stage(
        _RepositoryMustNotBeUsed(),
        _validation_run(
            status=status,
            safety_gate_state=safety_gate_state,
            approval_required=approval_required,
            evidence_ref_count=evidence_ref_count,
            execution_started=execution_started,
            outcome=outcome,
            include_safe_evidence_ref_count=include_safe_evidence_ref_count,
        ),
    )


def _safe_validation_handoff(*, candidate_ids: list[str] | None = None):
    source_snapshot_digest = "sha256:" + "a" * 64
    campaign = SimpleNamespace(
        id="campaign_001",
        default_asset="api.example.test",
        policy_text_hash="b" * 64,
        payload={"source_snapshot_digest": source_snapshot_digest},
        scope_status="in_scope",
    )
    report_task = SimpleNamespace(
        id="campaign_task_report",
        campaign_id=campaign.id,
        task_type="report_review",
        status="completed",
    )
    task = SimpleNamespace(
        id="campaign_task_validation_handoff",
        campaign_id=campaign.id,
        task_type="validation_handoff",
        status="completed",
        input_refs=[
            "pipeline_run:pipeline_run_001",
            f"campaign_task:{report_task.id}",
        ],
        payload={
            "schema_version": "autonomous_validation_handoff_v1",
            "pipeline_run_id": "pipeline_run_001",
            "report_review_task_id": report_task.id,
            "source_snapshot_digest": source_snapshot_digest,
            "candidate_ids": candidate_ids or ["candidate-a"],
            "submission_blocked": True,
            "human_review_required": True,
            "approval_required": True,
            "allowed_to_execute": False,
            "execution_allowed": False,
            "dispatch_allowed": False,
            "validation_allowed": False,
            "candidate_promotion_allowed": False,
            "report_submission_allowed": False,
            "raw_payload_processed": False,
        },
    )
    pipeline_run = SimpleNamespace(
        id="pipeline_run_001",
        asset=campaign.default_asset,
        scope_status="in_scope",
        policy_text_hash=campaign.policy_text_hash,
        payload={"campaign_id": campaign.id},
    )
    repository = SimpleNamespace(
        get_pipeline_run=lambda run_id: pipeline_run if run_id == pipeline_run.id else None,
        session=_Session({report_task.id: report_task}),
    )
    return campaign, task, pipeline_run, repository


@pytest.mark.parametrize(
    "mutation",
    ("candidate_ids", "source_snapshot_digest", "policy_text_hash"),
)
def test_autonomous_validation_handoff_rejects_unbound_candidate_snapshot_or_policy(
    mutation: str,
):
    campaign, task, pipeline_run, repository = _safe_validation_handoff()

    if mutation == "candidate_ids":
        task.payload["candidate_ids"] = ["candidate-a", "candidate-a"]
    elif mutation == "source_snapshot_digest":
        task.payload["source_snapshot_digest"] = "not-a-source-snapshot"
        campaign.payload["source_snapshot_digest"] = "not-a-source-snapshot"
    else:
        pipeline_run.policy_text_hash = "c" * 64

    assert not main_module._is_safe_autonomous_validation_handoff(
        repository,
        campaign,
        task,
    )


def test_validation_evidence_import_rejects_candidate_ids_that_do_not_match_handoff(
    monkeypatch,
):
    campaign, handoff, _pipeline_run, _repository = _safe_validation_handoff(
        candidate_ids=["candidate-b"]
    )
    approval = SimpleNamespace(id="approval_001")
    validation_run = _validation_run(
        safety_gate_state="manual_evidence_recorded",
    )
    validation_run.id = "validation_run_001"
    validation_run.campaign_id = campaign.id
    validation_run.approval_id = approval.id
    validation_run.payload["candidate_ids"] = ["candidate-a"]
    repository = _StageRecordingRepository(
        campaign=campaign,
        records={handoff.id: handoff, approval.id: approval},
    )
    monkeypatch.setattr(
        main_module,
        "_is_safe_autonomous_validation_handoff",
        lambda *_args: True,
    )
    monkeypatch.setattr(
        main_module,
        "_validation_run_approval_matches",
        lambda **_kwargs: True,
    )

    main_module._record_autonomous_validation_evidence_import_stage(
        repository,
        validation_run,
    )

    assert repository.saved_stages == []
