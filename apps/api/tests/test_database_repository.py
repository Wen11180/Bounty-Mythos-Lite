from datetime import UTC, datetime, timedelta

from sqlalchemy import create_engine, inspect
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.db import Base
from app.repository import DatabaseRepository, seed_sample_data


def build_session():
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    return sessionmaker(bind=engine)(), engine


def test_database_schema_includes_core_tables():
    session, engine = build_session()
    try:
        tables = set(inspect(engine).get_table_names())
    finally:
        session.close()

    assert {"programs", "findings", "reports", "llm_runs", "approval_records"} <= tables
    assert {
        "campaigns",
        "campaign_budgets",
        "campaign_tasks",
        "agent_runs",
        "approval_records",
        "pipeline_stages",
        "codebase_maps",
        "codebase_facts",
        "scanner_runs",
        "validation_runs",
    } <= tables


def test_repository_reads_seeded_programs_findings_and_reports():
    session, _ = build_session()
    try:
        seed_sample_data(session)
        repository = DatabaseRepository(session)

        programs = repository.list_programs()
        findings = repository.list_findings()
        reports = repository.list_reports()

        assert programs[0].name == "Example Program"
        assert findings[0].id == "finding_2026_001"
        assert findings[0].evidence_refs == ["evidence/request-user-a-to-user-b-metadata.json"]
        assert reports[0].finding_id == "finding_2026_001"
    finally:
        session.close()


def test_repository_records_approval_audit_without_sensitive_reasons():
    session, _ = build_session()
    try:
        repository = DatabaseRepository(session)

        record = repository.create_approval_record(
            run_id="pipeline_run_1",
            program_id="program_example",
            asset="api.example.com",
            validation_mode="two_account_authorization_check",
            plan_digest="plan_sha256_1",
            requester="lead_reviewer",
            reason="Authorization: Bearer live-token was checked locally.",
        )

        decided = repository.decide_approval_record(
            approval_id=record.id,
            decision="approved",
            actor="lead_reviewer",
            reason="Approved for test accounts only; cookie: live-cookie.",
        )

        assert decided is not None
        assert decided.status == "approved"
        assert decided.reason == "[REDACTED]"
        assert decided.decision_reason == "[REDACTED]"
        assert decided.decided_by == "lead_reviewer"
        assert decided.decided_at is not None
        assert [item.id for item in repository.list_approval_records(run_id="pipeline_run_1")] == [
            record.id
        ]
    finally:
        session.close()


def test_repository_does_not_reopen_terminal_approval_record():
    session, _ = build_session()
    try:
        repository = DatabaseRepository(session)

        record = repository.create_approval_record(
            run_id="pipeline_run_1",
            program_id="program_example",
            asset="api.example.com",
            validation_mode="two_account_authorization_check",
            plan_digest="plan_sha256_1",
            requester="lead_reviewer",
            reason="Need approval for test-account validation.",
        )
        denied = repository.decide_approval_record(
            approval_id=record.id,
            decision="denied",
            actor="lead_reviewer",
            reason="Denied until scope evidence is clearer.",
        )

        reopened = repository.decide_approval_record(
            approval_id=record.id,
            decision="approved",
            actor="lead_reviewer",
            reason="Trying to reopen a terminal approval.",
        )
        stored = repository.session.get(type(record), record.id)

        assert denied is not None
        assert reopened is None
        assert stored.status == "denied"
        assert stored.decided_by == "lead_reviewer"
        assert stored.decision_reason == "Denied until scope evidence is clearer."
    finally:
        session.close()


def test_repository_does_not_approve_expired_approval_record():
    session, _ = build_session()
    try:
        repository = DatabaseRepository(session)

        record = repository.create_approval_record(
            run_id="pipeline_run_1",
            program_id="program_example",
            asset="api.example.com",
            validation_mode="two_account_authorization_check",
            plan_digest="plan_sha256_1",
            expires_at=datetime.now(UTC) - timedelta(minutes=1),
            requester="lead_reviewer",
            reason="Approval window already elapsed.",
        )

        decided = repository.decide_approval_record(
            approval_id=record.id,
            decision="approved",
            actor="lead_reviewer",
            reason="Trying to approve after expiry.",
        )
        stored = repository.session.get(type(record), record.id)

        assert decided is None
        assert stored.status == "requested"
        assert stored.decided_by is None
        assert stored.decision_reason is None
        assert stored.decided_at is None
    finally:
        session.close()


def test_repository_rejects_unknown_approval_decision():
    session, _ = build_session()
    try:
        repository = DatabaseRepository(session)

        record = repository.create_approval_record(
            run_id="pipeline_run_1",
            program_id="program_example",
            asset="api.example.com",
            validation_mode="two_account_authorization_check",
            plan_digest="plan_sha256_1",
            requester="lead_reviewer",
            reason="Need approval for test-account validation.",
        )

        decided = repository.decide_approval_record(
            approval_id=record.id,
            decision="force_approved",
            actor="lead_reviewer",
            reason="Trying to invent an approval state.",
        )
        stored = repository.session.get(type(record), record.id)

        assert decided is None
        assert stored.status == "requested"
        assert stored.decided_by is None
        assert stored.decision_reason is None
        assert stored.decided_at is None
    finally:
        session.close()


def test_repository_normalizes_unknown_initial_approval_status():
    session, _ = build_session()
    try:
        repository = DatabaseRepository(session)

        record = repository.create_approval_record(
            run_id="pipeline_run_1",
            program_id="program_example",
            asset="api.example.com",
            validation_mode="two_account_authorization_check",
            plan_digest="plan_sha256_1",
            requester="lead_reviewer",
            reason="Need approval for test-account validation.",
            status="force_approved",
        )

        assert record.status == "requested"
        assert record.decided_by is None
        assert record.decision_reason is None
        assert record.decided_at is None
    finally:
        session.close()


def test_repository_does_not_confirm_claim_without_observed_claim_context():
    session, _ = build_session()
    try:
        repository = DatabaseRepository(session)
        run = repository.save_pipeline_run(
            program_id="program_example",
            asset="api.example.com",
            policy_text="Testing allowed",
            scope_status="in_scope",
            hypothesis_count=1,
            blocked_count=0,
            report_title="Draft report",
            payload={},
        )

        updated = repository.append_claim_review_decision(
            run_id=run.id,
            decision={
                "claim_id": "claim_unverified_1",
                "decision": "confirmed_observed_fact",
                "reviewer": "lead_reviewer",
                "rationale": "Trying to confirm without observed claim context.",
                "evidence_refs": ["sanitized_request_response"],
                "reviewed_at": datetime.now(UTC).isoformat(),
            },
        )
        stored = repository.get_pipeline_run(run.id)

        assert updated is None
        assert stored is not None
        assert stored.payload.get("claim_review_decisions") is None
    finally:
        session.close()


def test_repository_does_not_confirm_claim_without_supported_evidence_refs():
    session, _ = build_session()
    try:
        repository = DatabaseRepository(session)
        run = repository.save_pipeline_run(
            program_id="program_example",
            asset="api.example.com",
            policy_text="Testing allowed",
            scope_status="in_scope",
            hypothesis_count=1,
            blocked_count=0,
            report_title="Draft report",
            payload={},
        )

        updated = repository.append_claim_review_decision(
            run_id=run.id,
            decision={
                "claim_id": "claim_observed_fact_1",
                "decision": "confirmed_observed_fact",
                "reviewer": "lead_reviewer",
                "rationale": "Trying to confirm without supported evidence refs.",
                "evidence_refs": ["unsupported_ref"],
                "reviewed_at": datetime.now(UTC).isoformat(),
            },
            claim_type="observed_fact",
        )
        stored = repository.get_pipeline_run(run.id)

        assert updated is None
        assert stored is not None
        assert stored.payload.get("claim_review_decisions") is None
    finally:
        session.close()


def test_repository_does_not_confirm_claim_without_evidence_support_signal():
    session, _ = build_session()
    try:
        repository = DatabaseRepository(session)
        run = repository.save_pipeline_run(
            program_id="program_example",
            asset="api.example.com",
            policy_text="Testing allowed",
            scope_status="in_scope",
            hypothesis_count=1,
            blocked_count=0,
            report_title="Draft report",
            payload={},
        )

        updated = repository.append_claim_review_decision(
            run_id=run.id,
            decision={
                "claim_id": "claim_observed_fact_1",
                "decision": "confirmed_observed_fact",
                "reviewer": "lead_reviewer",
                "rationale": "Trying to confirm without any evidence signal.",
                "evidence_refs": [],
                "reviewed_at": datetime.now(UTC).isoformat(),
            },
            claim_type="observed_fact",
            evidence_refs_supported=True,
        )
        stored = repository.get_pipeline_run(run.id)

        assert updated is None
        assert stored is not None
        assert stored.payload.get("claim_review_decisions") is None
    finally:
        session.close()


def test_repository_does_not_confirm_claim_with_unsupported_ref_even_when_marked_supported():
    session, _ = build_session()
    try:
        repository = DatabaseRepository(session)
        run = repository.save_pipeline_run(
            program_id="program_example",
            asset="api.example.com",
            policy_text="Testing allowed",
            scope_status="in_scope",
            hypothesis_count=1,
            blocked_count=0,
            report_title="Draft report",
            payload={},
        )

        updated = repository.append_claim_review_decision(
            run_id=run.id,
            decision={
                "claim_id": "claim_observed_fact_1",
                "decision": "confirmed_observed_fact",
                "reviewer": "lead_reviewer",
                "rationale": "Trying to confirm with arbitrary safe-looking ref.",
                "evidence_refs": ["unsupported_ref"],
                "reviewed_at": datetime.now(UTC).isoformat(),
            },
            claim_type="observed_fact",
            evidence_refs_supported=True,
        )
        stored = repository.get_pipeline_run(run.id)

        assert updated is None
        assert stored is not None
        assert stored.payload.get("claim_review_decisions") is None
    finally:
        session.close()


def test_repository_does_not_confirm_claim_with_plain_manual_observation_ref():
    session, _ = build_session()
    try:
        repository = DatabaseRepository(session)
        run = repository.save_pipeline_run(
            program_id="program_example",
            asset="api.example.com",
            policy_text="Testing allowed",
            scope_status="in_scope",
            hypothesis_count=1,
            blocked_count=0,
            report_title="Draft report",
            payload={
                "manual_observations": [
                    {
                        "observation_id": "manual_observation_plain",
                        "claim_id": "claim_observed_fact_1",
                        "observation_type": "manual_observation",
                        "evidence_refs": ["sanitized_response_403"],
                    },
                ],
            },
        )

        updated = repository.append_claim_review_decision(
            run_id=run.id,
            decision={
                "claim_id": "claim_observed_fact_1",
                "decision": "confirmed_observed_fact",
                "reviewer": "lead_reviewer",
                "rationale": "Trying to confirm from a plain manual note.",
                "evidence_refs": ["sanitized_response_403"],
                "reviewed_at": datetime.now(UTC).isoformat(),
            },
            claim_type="observed_fact",
            evidence_refs_supported=True,
        )
        stored = repository.get_pipeline_run(run.id)

        assert updated is None
        assert stored is not None
        assert stored.payload.get("claim_review_decisions") is None
    finally:
        session.close()


def test_repository_does_not_confirm_claim_without_refs_from_plain_manual_observation():
    session, _ = build_session()
    try:
        repository = DatabaseRepository(session)
        run = repository.save_pipeline_run(
            program_id="program_example",
            asset="api.example.com",
            policy_text="Testing allowed",
            scope_status="in_scope",
            hypothesis_count=1,
            blocked_count=0,
            report_title="Draft report",
            payload={
                "manual_observations": [
                    {
                        "observation_id": "manual_observation_plain",
                        "claim_id": "claim_observed_fact_1",
                        "observation_type": "manual_observation",
                        "evidence_refs": ["sanitized_response_403"],
                    },
                ],
            },
        )

        updated = repository.append_claim_review_decision(
            run_id=run.id,
            decision={
                "claim_id": "claim_observed_fact_1",
                "decision": "confirmed_observed_fact",
                "reviewer": "lead_reviewer",
                "rationale": "Trying to confirm from a plain manual note.",
                "evidence_refs": [],
                "reviewed_at": datetime.now(UTC).isoformat(),
            },
            claim_type="observed_fact",
            evidence_refs_supported=True,
        )
        stored = repository.get_pipeline_run(run.id)

        assert updated is None
        assert stored is not None
        assert stored.payload.get("claim_review_decisions") is None
    finally:
        session.close()


def test_repository_does_not_confirm_claim_without_refs_from_unsupported_impact_observation():
    session, _ = build_session()
    try:
        repository = DatabaseRepository(session)
        run = repository.save_pipeline_run(
            program_id="program_example",
            asset="api.example.com",
            policy_text="Testing allowed",
            scope_status="in_scope",
            hypothesis_count=1,
            blocked_count=0,
            report_title="Draft report",
            payload={
                "manual_observations": [
                    {
                        "observation_id": "manual_observation_forged_impact",
                        "claim_id": "claim_observed_fact_1",
                        "observation_type": "request_response_diff",
                        "evidence_refs": ["unsupported_screenshot_ref"],
                    },
                ],
            },
        )

        updated = repository.append_claim_review_decision(
            run_id=run.id,
            decision={
                "claim_id": "claim_observed_fact_1",
                "decision": "confirmed_observed_fact",
                "reviewer": "lead_reviewer",
                "rationale": "Trying to confirm from unsupported impact evidence.",
                "evidence_refs": [],
                "reviewed_at": datetime.now(UTC).isoformat(),
            },
            claim_type="observed_fact",
            evidence_refs_supported=True,
        )
        stored = repository.get_pipeline_run(run.id)

        assert updated is None
        assert stored is not None
        assert stored.payload.get("claim_review_decisions") is None
    finally:
        session.close()


def test_repository_does_not_append_manual_observation_without_claim_context():
    session, _ = build_session()
    try:
        repository = DatabaseRepository(session)
        run = repository.save_pipeline_run(
            program_id="program_example",
            asset="api.example.com",
            policy_text="Testing allowed",
            scope_status="in_scope",
            hypothesis_count=1,
            blocked_count=0,
            report_title="Draft report",
            payload={
                "validation_workspace": {
                    "manual_observations": [],
                },
            },
        )

        updated = repository.append_manual_observation(
            run_id=run.id,
            observation={
                "observation_id": "manual_observation_without_claim",
                "claim_id": "claim_unknown",
                "observation_type": "request_response_diff",
                "observer": "lead_reviewer",
                "observation": "Trying to attach evidence without claim context.",
                "evidence_refs": ["sanitized_request_response"],
                "safety_notes": ["test_accounts_only"],
                "created_at": datetime.now(UTC).isoformat(),
            },
        )
        stored = repository.get_pipeline_run(run.id)

        assert updated is None
        assert stored is not None
        assert stored.payload.get("manual_observations") is None
        assert stored.payload["validation_workspace"]["manual_observations"] == []
    finally:
        session.close()


def test_repository_does_not_append_impact_observation_without_observed_claim_context():
    session, _ = build_session()
    try:
        repository = DatabaseRepository(session)
        run = repository.save_pipeline_run(
            program_id="program_example",
            asset="api.example.com",
            policy_text="Testing allowed",
            scope_status="in_scope",
            hypothesis_count=1,
            blocked_count=0,
            report_title="Draft report",
            payload={},
        )

        updated = repository.append_manual_observation(
            run_id=run.id,
            observation={
                "observation_id": "manual_observation_non_observed_impact",
                "claim_id": "claim_unverified_1",
                "observation_type": "request_response_diff",
                "observer": "lead_reviewer",
                "observation": "Trying to attach impact to an unverified claim.",
                "evidence_refs": ["sanitized_request_response"],
                "safety_notes": ["test_accounts_only"],
                "created_at": datetime.now(UTC).isoformat(),
            },
            claim_exists=True,
        )
        stored = repository.get_pipeline_run(run.id)

        assert updated is None
        assert stored is not None
        assert stored.payload.get("manual_observations") is None
    finally:
        session.close()


def test_repository_does_not_append_impact_observation_with_unsupported_ref():
    session, _ = build_session()
    try:
        repository = DatabaseRepository(session)
        run = repository.save_pipeline_run(
            program_id="program_example",
            asset="api.example.com",
            policy_text="Testing allowed",
            scope_status="in_scope",
            hypothesis_count=1,
            blocked_count=0,
            report_title="Draft report",
            payload={
                "validation_workspace": {
                    "manual_observations": [],
                },
            },
        )

        updated = repository.append_manual_observation(
            run_id=run.id,
            observation={
                "observation_id": "manual_observation_unsupported_ref",
                "claim_id": "claim_observed_fact_1",
                "observation_type": "request_response_diff",
                "observer": "lead_reviewer",
                "observation": "Trying to promote an arbitrary evidence ref.",
                "evidence_refs": ["unsupported_ref"],
                "safety_notes": ["test_accounts_only"],
                "created_at": datetime.now(UTC).isoformat(),
            },
            claim_exists=True,
            claim_type="observed_fact",
        )
        stored = repository.get_pipeline_run(run.id)

        assert updated is None
        assert stored is not None
        assert stored.payload.get("manual_observations") is None
        assert stored.payload["validation_workspace"]["manual_observations"] == []
    finally:
        session.close()


def test_repository_persists_campaign_core_records_with_safety_redaction():
    session, _ = build_session()
    try:
        seed_sample_data(session)
        repository = DatabaseRepository(session)

        campaign = repository.create_campaign(
            program_id="program_example",
            name="Authorized IDOR research",
            autonomy_level="level_1_local_validation",
            scope_status="in_scope",
            policy_text="Testing allowed. Authorization: Bearer secret-token",
            default_asset="api.example.com",
            target_classes=["idor"],
            allowed_tools=["static_analyzer"],
            created_by="operator@example.com",
            payload={
                "authorization": "Bearer secret-token",
                "Authorization: Bearer key-secret": "header name was pasted as key",
                "customer@example.com": "fixture reviewer",
                "notes": "local only",
            },
        )
        budget = repository.upsert_campaign_budget(
            campaign_id=campaign.id,
            time_budget_minutes=60,
            token_budget=10000,
            tool_call_budget=50,
            validation_budget=3,
        )
        task = repository.create_campaign_task(
            campaign_id=campaign.id,
            task_type="hypothesis_generation",
            agent_type="hypothesis_agent",
            title="Generate IDOR hypotheses",
            input_refs=["artifact_1"],
            payload={"cookie": "session=secret", "safe": "candidate only"},
        )
        agent_run = repository.save_agent_run(
            campaign_id=campaign.id,
            task_id=task.id,
            agent_type="hypothesis_agent",
            status="completed",
            input_refs=["artifact_1"],
            output_refs=["hypothesis_1"],
            tool_calls=[{"tool": "static_analyzer", "token": "secret"}],
            safety_gate_state="allowed",
            stop_reason=None,
            payload={"result": "candidate_not_confirmed"},
        )
        approval = repository.create_approval_record(
            campaign_id=campaign.id,
            task_id=task.id,
            approval_type="validation_batch",
            actor="operator",
            reason="Approve fixture validation only; cookie: session=secret",
            scope_reference="program-policy",
            requested_action="local_fixture_validation",
            autonomy_level="level_1_local_validation",
            safety_gate_state="awaiting_approval",
            payload={"authorization": "Bearer secret-token"},
        )
        stage = repository.save_pipeline_stage(
            pipeline_run_id=None,
            campaign_id=campaign.id,
            task_id=task.id,
            stage_key="hypotheses",
            stage_order=1,
            status="completed",
            input_refs=["artifact_1"],
            output_refs=["hypothesis_1"],
            safety_gate_state="allowed",
            stop_reason=None,
            payload={"summary": "generated one candidate"},
        )

        assert campaign.policy_text_hash
        assert campaign.payload["authorization"] == "[REDACTED]"
        assert "key-secret" not in str(campaign.payload)
        assert "customer@example.com" not in str(campaign.payload)
        assert campaign.created_by == "[REDACTED]"
        assert budget.status == "active"
        assert task.payload["cookie"] == "[REDACTED]"
        assert agent_run.tool_calls[0]["token"] == "[REDACTED]"
        assert approval.reason == "[REDACTED]"
        assert approval.status == "pending"
        assert stage.stage_key == "hypotheses"

        assert repository.get_campaign(campaign.id).id == campaign.id
        assert repository.list_campaigns()[0].id == campaign.id
        assert repository.list_campaign_tasks(campaign.id)[0].id == task.id
        assert repository.list_campaign_agent_runs(campaign.id)[0].id == agent_run.id
        assert repository.list_campaign_approval_records(campaign.id)[0].id == approval.id
    finally:
        session.close()


def test_campaign_status_tracks_budget_runtime_across_pause_and_resume():
    session, _ = build_session()
    try:
        seed_sample_data(session)
        repository = DatabaseRepository(session)
        campaign = repository.create_campaign(
            program_id="program_example",
            name="Budget runtime tracking",
            autonomy_level="level_0_read_only",
            scope_status="in_scope",
            policy_text="Testing allowed",
            default_asset="api.example.com",
            created_by="operator",
        )

        running = repository.update_campaign_status(campaign.id, "running")
        assert running is not None
        started_at = running.payload["budget_started_at"]
        assert datetime.fromisoformat(started_at).tzinfo is not None

        paused = repository.update_campaign_status(campaign.id, "paused")
        assert paused is not None
        assert paused.payload["budget_started_at"] == started_at
        assert "budget_paused_at" in paused.payload

        resumed = repository.update_campaign_status(campaign.id, "running")
        assert resumed is not None
        assert resumed.payload["budget_started_at"] == started_at
        assert "budget_paused_at" not in resumed.payload
        assert resumed.payload["budget_paused_seconds"] >= 0
    finally:
        session.close()


def test_update_pipeline_stage_status_preserves_legacy_stage_updates():
    session, _ = build_session()
    try:
        repository = DatabaseRepository(session)
        stage = repository.save_pipeline_stage(
            pipeline_run_id=None,
            campaign_id=None,
            task_id=None,
            stage_key="validation_manual_result",
            stage_order=1,
            status="recorded",
            input_refs=[],
            output_refs=[],
            safety_gate_state="manual_review",
            stop_reason=None,
            payload={"execution_started": False},
        )

        updated = repository.update_pipeline_stage_status(
            stage.id,
            status="reviewed",
            safety_gate_state="human_review_complete",
            stop_reason=None,
            payload={"execution_started": False, "reviewed": True},
        )

        assert updated is not None
        assert updated.status == "reviewed"
        assert updated.safety_gate_state == "human_review_complete"
        assert updated.payload == {
            "execution_started": False,
            "reviewed": True,
        }
    finally:
        session.close()


def test_repository_stores_campaign_default_asset_without_query_secret():
    session, _ = build_session()
    try:
        repository = DatabaseRepository(session)

        campaign = repository.create_campaign(
            program_id="program_example",
            name="Asset normalization campaign",
            autonomy_level="level_0_read_only",
            scope_status="in_scope",
            policy_text="Testing allowed",
            default_asset="https://api.example.com/path?session=secret",
            created_by="operator",
        )

        assert campaign.default_asset == "api.example.com/path"
        assert "session=secret" not in str(campaign.default_asset)
    finally:
        session.close()

def test_repository_keeps_local_path_with_task_authz_segment():
    """Path segments like 'task-authz' must not trip OpenAI-style sk- key detection."""
    from app.repository import _is_secret_like, _safe_asset_value

    package_segment = "my-gh-vikunja-task-authz-lab"
    assert _is_secret_like(package_segment) is False
    assert _is_secret_like("task-authz") is False
    assert _is_secret_like("sk-proj-abcdefghijklmnop") is True

    local_path = (
        r"C:\Users\Administrator\Desktop\Bounty Mythos-Lite\apps\api"
        r"\.pytest-tmp\operator-trial-workspaces\my-gh-vikunja-task-authz-lab"
        r"\workspace-x\code\source"
    )
    assert _safe_asset_value(local_path) == local_path

    session, _ = build_session()
    try:
        repository = DatabaseRepository(session)
        campaign = repository.create_campaign(
            program_id="program_example",
            name="Local path campaign",
            autonomy_level="level_0_read_only",
            scope_status="in_scope",
            policy_text="Testing allowed",
            default_asset=local_path,
            created_by="operator",
        )
        assert campaign.default_asset == local_path
        assert campaign.default_asset != "[REDACTED]"
    finally:
        session.close()


def test_repository_reuses_pipeline_stage_with_same_idempotency_key():
    session, _ = build_session()
    try:
        repository = DatabaseRepository(session)
        campaign = repository.create_campaign(
            program_id="program_example",
            name="Stage idempotency campaign",
            autonomy_level="level_1_local_validation",
            scope_status="in_scope",
            policy_text="Testing allowed",
            default_asset="api.example.com",
            created_by="operator",
        )
        task = repository.create_campaign_task(
            campaign_id=campaign.id,
            task_type="research_queue_review",
            agent_type="human_research_reviewer",
            title="Review candidate",
        )

        first = repository.save_pipeline_stage(
            pipeline_run_id=None,
            campaign_id=campaign.id,
            task_id=task.id,
            stage_key="research_task_review_plan",
            stage_order=1,
            status="auto_drafted",
            input_refs=[f"campaign:{campaign.id}"],
            output_refs=["research_plan:plan_1"],
            safety_gate_state="advisory_plan_only",
            stop_reason=None,
            payload={
                "idempotency_key": "research_plan:plan_1",
                "summary": "first safe summary",
            },
        )
        repeated = repository.save_pipeline_stage(
            pipeline_run_id=None,
            campaign_id=campaign.id,
            task_id=task.id,
            stage_key="research_task_review_plan",
            stage_order=99,
            status="completed",
            input_refs=[f"campaign:{campaign.id}", "Authorization: Bearer secret-token"],
            output_refs=["research_plan:plan_1", "extra"],
            safety_gate_state="changed",
            stop_reason="changed",
            payload={
                "idempotency_key": "research_plan:plan_1",
                "summary": "second payload should not overwrite",
            },
        )
        different = repository.save_pipeline_stage(
            pipeline_run_id=None,
            campaign_id=campaign.id,
            task_id=task.id,
            stage_key="research_task_review_plan",
            stage_order=2,
            status="auto_drafted",
            input_refs=[f"campaign:{campaign.id}"],
            output_refs=["research_plan:plan_2"],
            safety_gate_state="advisory_plan_only",
            stop_reason=None,
            payload={"idempotency_key": "research_plan:plan_2"},
        )
        stages = repository.list_campaign_pipeline_stages(campaign.id)

        assert repeated.id == first.id
        assert repeated.status == "auto_drafted"
        assert repeated.stage_order == 1
        assert repeated.output_refs == ["research_plan:plan_1"]
        assert repeated.payload == {
            "idempotency_key": "research_plan:plan_1",
            "summary": "first safe summary",
        }
        assert different.id != first.id
        assert [stage.id for stage in stages] == [first.id, different.id]
        assert "secret-token" not in str(stages)
        assert "Authorization" not in str(stages)
    finally:
        session.close()


def test_repository_updates_campaign_task_and_finishes_agent_run_safely():
    session, _ = build_session()
    try:
        seed_sample_data(session)
        repository = DatabaseRepository(session)
        campaign = repository.create_campaign(
            program_id="program_example",
            name="Agent lifecycle campaign",
            autonomy_level="level_0_read_only",
            scope_status="in_scope",
            policy_text="Testing allowed",
            default_asset="api.example.com",
            created_by="operator",
        )
        task = repository.create_campaign_task(
            campaign_id=campaign.id,
            task_type="campaign_observation",
            agent_type="orchestrator_agent",
            title="Observe authorized state",
            input_refs=["campaign"],
        )
        agent_run = repository.save_agent_run(
            campaign_id=campaign.id,
            task_id=task.id,
            agent_type="orchestrator_agent",
            status="dispatched",
            input_refs=[f"campaign_task:{task.id}"],
            output_refs=[],
            tool_calls=[],
            safety_gate_state="allowed",
            stop_reason=None,
            payload={},
        )

        updated_task = repository.update_campaign_task_status(
            task.id,
            "completed",
            output_refs=[f"agent_run:{agent_run.id}"],
        )
        finished_run = repository.finish_agent_run(
            agent_run.id,
            status="completed",
            output_refs=["campaign_observation:summary"],
            safety_gate_state="allowed",
            stop_reason="observation_recorded",
            payload={"authorization": "Bearer secret-token"},
        )

        assert updated_task is not None
        assert updated_task.status == "completed"
        assert updated_task.output_refs == [f"agent_run:{agent_run.id}"]

        assert finished_run is not None
        assert finished_run.status == "completed"
        assert finished_run.output_refs == ["campaign_observation:summary"]
        assert finished_run.safety_gate_state == "allowed"
        assert finished_run.stop_reason == "observation_recorded"
        assert finished_run.finished_at is not None
        assert finished_run.payload["authorization"] == "[REDACTED]"
    finally:
        session.close()


def test_repository_finds_active_agent_run_for_task():
    session, _ = build_session()
    try:
        seed_sample_data(session)
        repository = DatabaseRepository(session)
        campaign = repository.create_campaign(
            program_id="program_example",
            name="Agent reconciliation campaign",
            autonomy_level="level_0_read_only",
            scope_status="in_scope",
            policy_text="Testing allowed",
            default_asset="api.example.com",
            created_by="operator",
        )
        task = repository.create_campaign_task(
            campaign_id=campaign.id,
            task_type="campaign_observation",
            agent_type="orchestrator_agent",
            title="Observe authorized state",
            input_refs=["campaign"],
        )
        completed_run = repository.save_agent_run(
            campaign_id=campaign.id,
            task_id=task.id,
            agent_type="orchestrator_agent",
            status="completed",
            input_refs=[f"campaign_task:{task.id}"],
            output_refs=[],
            tool_calls=[],
            safety_gate_state="allowed",
            stop_reason=None,
            payload={},
        )
        active_run = repository.save_agent_run(
            campaign_id=campaign.id,
            task_id=task.id,
            agent_type="orchestrator_agent",
            status="dispatched",
            input_refs=[f"campaign_task:{task.id}"],
            output_refs=[],
            tool_calls=[],
            safety_gate_state="allowed",
            stop_reason=None,
            payload={},
        )

        found = repository.find_active_agent_run_for_task(task.id)

        assert completed_run.status == "completed"
        assert found is not None
        assert found.id == active_run.id
    finally:
        session.close()


def test_repository_persists_codebase_and_scanner_fact_layer_safely():
    session, _ = build_session()
    try:
        seed_sample_data(session)
        repository = DatabaseRepository(session)
        campaign = repository.create_campaign(
            program_id="program_example",
            name="Code map campaign",
            autonomy_level="level_0_read_only",
            scope_status="in_scope",
            policy_text="Testing allowed",
            default_asset="api.example.com",
            created_by="operator",
        )

        codebase_map = repository.save_codebase_map(
            campaign_id=campaign.id,
            source_ref="artifact:repo_snapshot",
            repository="authorized/service",
            commit_ref="abc123",
            status="mapped",
            route_count=2,
            handler_count=2,
            model_count=1,
            authz_check_count=1,
            sensitive_sink_count=1,
            provenance_refs=["artifact:repo_snapshot"],
            safety_gate_state="allowed",
            payload={"authorization": "Bearer secret-token", "summary": "routes only"},
        )
        fact = repository.save_codebase_fact(
            codebase_map_id=codebase_map.id,
            campaign_id=campaign.id,
            fact_type="route_handler",
            source_path="apps/api/users.py?token=secret-token",
            symbol_name="get_user",
            route_method="GET",
            route_path="/users/{id}",
            authz_hint="owner_or_admin",
            sensitivity_label="low",
            provenance_refs=["codebase_map:route:1"],
            payload={"cookie": "session=secret", "line": 42},
        )
        scanner_run = repository.save_scanner_run(
            campaign_id=campaign.id,
            codebase_map_id=codebase_map.id,
            tool_name="semgrep",
            command_hash="sha256:scanner-command",
            status="candidate_findings",
            finding_count=2,
            candidate_count=2,
            summary="Static candidates only; Authorization: Bearer secret-token",
            safety_gate_state="allowed",
            payload={"raw_stdout": "token=secret-token"},
        )

        maps = repository.list_campaign_codebase_maps(campaign.id)
        facts = repository.list_codebase_facts(codebase_map.id)
        scanner_runs = repository.list_campaign_scanner_runs(campaign.id)

        assert maps[0].id == codebase_map.id
        assert maps[0].payload["authorization"] == "[REDACTED]"
        assert facts[0].id == fact.id
        assert facts[0].source_path == "apps/api/users.py"
        assert facts[0].payload["cookie"] == "[REDACTED]"
        assert scanner_runs[0].id == scanner_run.id
        assert scanner_runs[0].summary == "[REDACTED]"
        assert scanner_runs[0].payload["raw_stdout"] == "[REDACTED]"
    finally:
        session.close()


def test_repository_records_validation_runs_with_approval_gate_safety():
    session, _ = build_session()
    try:
        seed_sample_data(session)
        repository = DatabaseRepository(session)
        campaign = repository.create_campaign(
            program_id="program_example",
            name="Validation campaign",
            autonomy_level="level_1_local_validation",
            scope_status="in_scope",
            policy_text="Testing allowed",
            default_asset="api.example.com",
            created_by="operator",
        )
        task = repository.create_campaign_task(
            campaign_id=campaign.id,
            task_type="validation_planning",
            agent_type="validation_harness_agent",
            title="Plan validation",
            input_refs=["hypothesis:1"],
        )

        gated_run = repository.save_validation_run(
            campaign_id=campaign.id,
            task_id=task.id,
            approval_id=None,
            validation_mode="two_account_authorization_check",
            target_ref="candidate:idor?token=secret-token",
            status="ready",
            safety_gate_state="allowed",
            plan_digest="plan_digest_1",
            approval_required=True,
            allowed_to_execute=True,
            evidence_ref_count=0,
            summary="Needs two test accounts; Authorization: Bearer secret-token",
            payload={"raw_request": "Cookie: session=secret"},
        )
        local_run = repository.save_validation_run(
            campaign_id=campaign.id,
            task_id=task.id,
            approval_id=None,
            validation_mode="static_local_check",
            target_ref="codebase_fact:route_1",
            status="ready",
            safety_gate_state="allowed",
            plan_digest="plan_digest_2",
            approval_required=False,
            allowed_to_execute=True,
            evidence_ref_count=1,
            summary="Static local check against authorized code.",
            payload={"command": "semgrep --config local"},
        )

        runs = repository.list_campaign_validation_runs(campaign.id)

        assert [run.id for run in runs] == [local_run.id, gated_run.id]
        assert gated_run.status == "awaiting_approval"
        assert gated_run.allowed_to_execute is False
        assert gated_run.target_ref == "candidate:idor"
        assert gated_run.summary == "[REDACTED]"
        assert gated_run.payload["raw_request"] == "[REDACTED]"
        assert local_run.status == "ready"
        assert local_run.allowed_to_execute is True
        assert local_run.evidence_ref_count == 1
    finally:
        session.close()


def test_repository_does_not_create_approval_required_ready_run_as_executable():
    session, _ = build_session()
    try:
        seed_sample_data(session)
        repository = DatabaseRepository(session)
        campaign = repository.create_campaign(
            program_id="program_example",
            name="Validation preflight gate campaign",
            autonomy_level="level_2_test_account_validation",
            scope_status="in_scope",
            policy_text="Testing allowed",
            default_asset="api.example.com",
            created_by="operator",
        )
        task = repository.create_campaign_task(
            campaign_id=campaign.id,
            task_type="validation_planning",
            agent_type="validation_harness_agent",
            title="Plan validation",
            input_refs=["hypothesis:1"],
        )
        approval = repository.create_approval_record(
            campaign_id=campaign.id,
            task_id=task.id,
            program_id=campaign.program_id,
            approval_type="validation_batch",
            actor="operator",
            reason="Approve test-account validation.",
            requested_action="two_account_authorization_check",
            asset=campaign.default_asset,
            validation_mode="two_account_authorization_check",
            plan_digest="plan_digest_ready_not_executable",
            autonomy_level=campaign.autonomy_level,
            safety_gate_state="awaiting_approval",
        )

        validation_run = repository.save_validation_run(
            campaign_id=campaign.id,
            task_id=task.id,
            approval_id=approval.id,
            validation_mode="two_account_authorization_check",
            target_ref=f"campaign:{campaign.id}",
            status="ready",
            safety_gate_state="approved_validation_record",
            plan_digest="plan_digest_ready_not_executable",
            approval_required=True,
            allowed_to_execute=True,
            evidence_ref_count=0,
            summary="Ready but still needs Scope Guard preflight.",
            payload={},
        )

        assert validation_run.status == "ready"
        assert validation_run.safety_gate_state == "approved_validation_record"
        assert validation_run.allowed_to_execute is False
    finally:
        session.close()


def test_repository_reuses_validation_run_with_same_idempotency_key():
    session, _ = build_session()
    try:
        seed_sample_data(session)
        repository = DatabaseRepository(session)
        campaign = repository.create_campaign(
            program_id="program_example",
            name="Validation idempotency campaign",
            autonomy_level="level_2_test_account_validation",
            scope_status="in_scope",
            policy_text="Testing allowed",
            default_asset="api.example.com",
            created_by="operator",
        )
        task = repository.create_campaign_task(
            campaign_id=campaign.id,
            task_type="report_chain_review",
            agent_type="report_agent",
            title="Review validation gate",
            input_refs=[f"campaign:{campaign.id}"],
        )

        first = repository.save_validation_run(
            campaign_id=campaign.id,
            task_id=task.id,
            approval_id=None,
            validation_mode="two_account_authorization_check",
            target_ref=f"campaign:{campaign.id}",
            status="planned",
            safety_gate_state="awaiting_approval",
            plan_digest="validation_idempotency_plan",
            approval_required=True,
            allowed_to_execute=False,
            evidence_ref_count=0,
            summary="First validation gate",
            payload={"idempotency_key": "validation:plan_1"},
        )
        repeated = repository.save_validation_run(
            campaign_id=campaign.id,
            task_id=task.id,
            approval_id="approval_should_not_overwrite",
            validation_mode="two_account_authorization_check",
            target_ref=f"campaign:{campaign.id}",
            status="preflight_passed",
            safety_gate_state="scope_guard_preflight_passed",
            plan_digest="validation_idempotency_plan",
            approval_required=False,
            allowed_to_execute=True,
            evidence_ref_count=3,
            summary="Replay should not overwrite",
            payload={
                "idempotency_key": "validation:plan_1",
                "authorization": "Bearer secret-token",
            },
        )
        different = repository.save_validation_run(
            campaign_id=campaign.id,
            task_id=task.id,
            approval_id=None,
            validation_mode="two_account_authorization_check",
            target_ref=f"campaign:{campaign.id}",
            status="planned",
            safety_gate_state="awaiting_approval",
            plan_digest="validation_idempotency_plan",
            approval_required=True,
            allowed_to_execute=False,
            evidence_ref_count=0,
            summary="Second validation gate",
            payload={"idempotency_key": "validation:plan_2"},
        )
        runs = repository.list_campaign_validation_runs(campaign.id)

        assert repeated.id == first.id
        assert repeated.status == "awaiting_approval"
        assert repeated.approval_id is None
        assert repeated.allowed_to_execute is False
        assert repeated.evidence_ref_count == 0
        assert repeated.summary == "First validation gate"
        assert repeated.payload == {"idempotency_key": "validation:plan_1"}
        assert different.id != first.id
        assert {run.id for run in runs} == {first.id, different.id}
        assert "secret-token" not in str(runs)
        assert "Authorization" not in str(runs)
    finally:
        session.close()


def test_repository_preflight_cannot_reopen_blocked_validation_run():
    session, _ = build_session()
    try:
        seed_sample_data(session)
        repository = DatabaseRepository(session)
        campaign = repository.create_campaign(
            program_id="program_example",
            name="Blocked preflight campaign",
            autonomy_level="level_2_test_account_validation",
            scope_status="in_scope",
            policy_text="Testing allowed",
            default_asset="api.example.com",
            created_by="operator",
        )
        task = repository.create_campaign_task(
            campaign_id=campaign.id,
            task_type="validation_planning",
            agent_type="validation_harness_agent",
            title="Plan validation",
            input_refs=["hypothesis:1"],
        )
        validation_run = repository.save_validation_run(
            campaign_id=campaign.id,
            task_id=task.id,
            approval_id=None,
            validation_mode="two_account_authorization_check",
            target_ref=f"campaign:{campaign.id}",
            status="blocked",
            safety_gate_state="blocked",
            plan_digest="plan_digest_blocked_preflight",
            approval_required=True,
            allowed_to_execute=False,
            evidence_ref_count=0,
            summary="Blocked validation",
            payload={},
        )
        validation_run.status = "blocked"
        validation_run.safety_gate_state = "blocked"
        validation_run.allowed_to_execute = False
        session.add(validation_run)
        session.commit()

        repository.record_validation_run_preflight(
            validation_run.id,
            allowed=True,
            reason="approved_validation_record",
        )

        run = repository.session.get(type(validation_run), validation_run.id)
        assert run.status == "blocked"
        assert run.safety_gate_state == "blocked"
        assert run.allowed_to_execute is False
        assert run.payload["scope_guard_preflight"] == {
            "allowed": False,
            "reason": "validation_run_not_ready",
        }
    finally:
        session.close()


def test_repository_repeated_approval_preserves_preflight_passed_validation_run():
    session, _ = build_session()
    try:
        seed_sample_data(session)
        repository = DatabaseRepository(session)
        campaign = repository.create_campaign(
            program_id="program_example",
            name="Preflight preservation campaign",
            autonomy_level="level_2_test_account_validation",
            scope_status="in_scope",
            policy_text="Testing allowed",
            default_asset="api.example.com",
            created_by="operator",
        )
        task = repository.create_campaign_task(
            campaign_id=campaign.id,
            task_type="report_chain_review",
            agent_type="report_agent",
            title="Review validation gate",
            input_refs=[f"campaign:{campaign.id}"],
        )
        approval = repository.create_approval_record(
            campaign_id=campaign.id,
            task_id=task.id,
            program_id=campaign.program_id,
            approval_type="validation_batch",
            actor="operator",
            reason="Approve test-account validation.",
            requested_action="two_account_authorization_check",
            asset=campaign.default_asset,
            validation_mode="two_account_authorization_check",
            plan_digest="plan_digest_preflight_preserved",
            autonomy_level=campaign.autonomy_level,
            safety_gate_state="awaiting_approval",
        )
        validation_run = repository.save_validation_run(
            campaign_id=campaign.id,
            task_id=task.id,
            approval_id=None,
            validation_mode="two_account_authorization_check",
            target_ref=f"campaign:{campaign.id}",
            status="planned",
            safety_gate_state="awaiting_approval",
            plan_digest="plan_digest_preflight_preserved",
            approval_required=True,
            allowed_to_execute=False,
            evidence_ref_count=0,
            summary="Awaiting approval",
            payload={},
        )

        repository.decide_approval_record(
            approval_id=approval.id,
            decision="approved",
            actor="lead_reviewer",
            reason="Approved for preflight.",
        )
        repository.record_validation_run_preflight(
            validation_run.id,
            allowed=True,
            reason="approved_validation_record",
        )
        repository.decide_approval_record(
            approval_id=approval.id,
            decision="approved",
            actor="lead_reviewer",
            reason="Repeated approval should not erase preflight.",
        )

        run = repository.session.get(type(validation_run), validation_run.id)
        assert run.status == "preflight_passed"
        assert run.safety_gate_state == "scope_guard_preflight_passed"
        assert run.allowed_to_execute is True
    finally:
        session.close()


def test_repository_replayed_approved_decision_does_not_rewrite_audit_or_resync_runs():
    session, _ = build_session()
    try:
        seed_sample_data(session)
        repository = DatabaseRepository(session)
        campaign = repository.create_campaign(
            program_id="program_example",
            name="Repository approved replay campaign",
            autonomy_level="level_2_test_account_validation",
            scope_status="in_scope",
            policy_text="Testing allowed",
            default_asset="api.example.com",
            created_by="operator",
        )
        task = repository.create_campaign_task(
            campaign_id=campaign.id,
            task_type="report_chain_review",
            agent_type="report_agent",
            title="Review validation gate",
            input_refs=[f"campaign:{campaign.id}"],
        )
        approval = repository.create_approval_record(
            campaign_id=campaign.id,
            task_id=task.id,
            program_id=campaign.program_id,
            approval_type="validation_batch",
            actor="operator",
            reason="Approve test-account validation.",
            requested_action="two_account_authorization_check",
            asset=campaign.default_asset,
            validation_mode="two_account_authorization_check",
            plan_digest="repository_approval_replay_plan",
            autonomy_level=campaign.autonomy_level,
            safety_gate_state="awaiting_approval",
        )
        first_run = repository.save_validation_run(
            campaign_id=campaign.id,
            task_id=task.id,
            approval_id=None,
            validation_mode="two_account_authorization_check",
            target_ref=f"campaign:{campaign.id}",
            status="planned",
            safety_gate_state="awaiting_approval",
            plan_digest="repository_approval_replay_plan",
            approval_required=True,
            allowed_to_execute=False,
            evidence_ref_count=0,
            summary="Awaiting approval",
            payload={},
        )

        approved = repository.decide_approval_record(
            approval_id=approval.id,
            decision="approved",
            actor="lead_reviewer",
            reason="Approved for preflight.",
        )
        original_decided_by = approved.decided_by
        original_decision_reason = approved.decision_reason
        original_decided_at = approved.decided_at
        late_run = repository.save_validation_run(
            campaign_id=campaign.id,
            task_id=task.id,
            approval_id=None,
            validation_mode="two_account_authorization_check",
            target_ref=f"campaign:{campaign.id}",
            status="planned",
            safety_gate_state="awaiting_approval",
            plan_digest="repository_approval_replay_plan",
            approval_required=True,
            allowed_to_execute=False,
            evidence_ref_count=0,
            summary="Late run must not be unlocked by replay",
            payload={},
        )

        replayed = repository.decide_approval_record(
            approval_id=approval.id,
            decision="approved",
            actor="replay_actor",
            reason="Trying to replay approval.",
        )

        stored_approval = repository.session.get(type(approval), approval.id)
        stored_first_run = repository.session.get(type(first_run), first_run.id)
        stored_late_run = repository.session.get(type(late_run), late_run.id)
        assert replayed is None
        assert stored_approval.status == "approved"
        assert stored_approval.decided_by == original_decided_by
        assert stored_approval.decision_reason == original_decision_reason
        assert stored_approval.decided_at == original_decided_at
        assert stored_first_run.approval_id == approval.id
        assert stored_first_run.status == "ready"
        assert stored_late_run.approval_id is None
        assert stored_late_run.status == "awaiting_approval"
        assert stored_late_run.allowed_to_execute is False
    finally:
        session.close()


def test_repository_approval_decision_does_not_grant_execution_before_preflight():
    session, _ = build_session()
    try:
        seed_sample_data(session)
        repository = DatabaseRepository(session)
        campaign = repository.create_campaign(
            program_id="program_example",
            name="Approval is not execution permission campaign",
            autonomy_level="level_2_test_account_validation",
            scope_status="in_scope",
            policy_text="Testing allowed",
            default_asset="api.example.com",
            created_by="operator",
        )
        task = repository.create_campaign_task(
            campaign_id=campaign.id,
            task_type="report_chain_review",
            agent_type="report_agent",
            title="Review validation gate",
            input_refs=[f"campaign:{campaign.id}"],
        )
        approval = repository.create_approval_record(
            campaign_id=campaign.id,
            task_id=task.id,
            program_id=campaign.program_id,
            approval_type="validation_batch",
            actor="operator",
            reason="Approve test-account validation.",
            requested_action="two_account_authorization_check",
            asset=campaign.default_asset,
            validation_mode="two_account_authorization_check",
            plan_digest="plan_digest_approval_not_execution",
            autonomy_level=campaign.autonomy_level,
            safety_gate_state="awaiting_approval",
        )
        validation_run = repository.save_validation_run(
            campaign_id=campaign.id,
            task_id=task.id,
            approval_id=None,
            validation_mode="two_account_authorization_check",
            target_ref=f"campaign:{campaign.id}",
            status="planned",
            safety_gate_state="awaiting_approval",
            plan_digest="plan_digest_approval_not_execution",
            approval_required=True,
            allowed_to_execute=False,
            evidence_ref_count=0,
            summary="Awaiting approval",
            payload={},
        )

        repository.decide_approval_record(
            approval_id=approval.id,
            decision="approved",
            actor="lead_reviewer",
            reason="Approved for preflight review only.",
        )

        run = repository.session.get(type(validation_run), validation_run.id)
        assert run.approval_id == approval.id
        assert run.status == "ready"
        assert run.safety_gate_state == "approved_validation_record"
        assert run.allowed_to_execute is False
    finally:
        session.close()


def test_repository_global_approval_decision_does_not_sync_campaign_bound_validation_run():
    session, _ = build_session()
    try:
        seed_sample_data(session)
        repository = DatabaseRepository(session)
        campaign = repository.create_campaign(
            program_id="program_example",
            name="Scoped validation run campaign",
            autonomy_level="level_2_test_account_validation",
            scope_status="in_scope",
            policy_text="Testing allowed",
            default_asset="api.example.com",
            created_by="operator",
        )
        task = repository.create_campaign_task(
            campaign_id=campaign.id,
            task_type="report_chain_review",
            agent_type="report_agent",
            title="Review validation gate",
            input_refs=[f"campaign:{campaign.id}"],
        )
        approval = repository.create_approval_record(
            program_id=campaign.program_id,
            approval_type="validation_batch",
            actor="operator",
            reason="Approve only unscoped validation records.",
            requested_action="two_account_authorization_check",
            asset=campaign.default_asset,
            validation_mode="two_account_authorization_check",
            plan_digest="global_approval_must_not_sync_scoped_run",
            autonomy_level=campaign.autonomy_level,
            safety_gate_state="awaiting_approval",
        )
        validation_run = repository.save_validation_run(
            campaign_id=campaign.id,
            task_id=task.id,
            approval_id=None,
            validation_mode="two_account_authorization_check",
            target_ref=f"campaign:{campaign.id}",
            status="planned",
            safety_gate_state="awaiting_approval",
            plan_digest="global_approval_must_not_sync_scoped_run",
            approval_required=True,
            allowed_to_execute=False,
            evidence_ref_count=0,
            summary="Awaiting campaign-bound approval",
            payload={},
        )

        repository.decide_approval_record(
            approval_id=approval.id,
            decision="approved",
            actor="lead_reviewer",
            reason="Approved globally, not for this campaign task.",
        )

        run = repository.session.get(type(validation_run), validation_run.id)
        assert run.approval_id is None
        assert run.status == "awaiting_approval"
        assert run.safety_gate_state == "awaiting_approval"
        assert run.allowed_to_execute is False
    finally:
        session.close()


def test_repository_approval_decision_requires_matching_allowed_accounts():
    session, _ = build_session()
    try:
        seed_sample_data(session)
        repository = DatabaseRepository(session)
        campaign = repository.create_campaign(
            program_id="program_example",
            name="Allowed account binding campaign",
            autonomy_level="level_2_test_account_validation",
            scope_status="in_scope",
            policy_text="Testing allowed",
            default_asset="api.example.com",
            created_by="operator",
        )
        task = repository.create_campaign_task(
            campaign_id=campaign.id,
            task_type="report_chain_review",
            agent_type="report_agent",
            title="Review validation gate",
            input_refs=[f"campaign:{campaign.id}"],
        )
        approval = repository.create_approval_record(
            campaign_id=campaign.id,
            task_id=task.id,
            program_id=campaign.program_id,
            approval_type="validation_batch",
            actor="operator",
            reason="Approve only the selected test accounts.",
            requested_action="two_account_authorization_check",
            asset=campaign.default_asset,
            validation_mode="two_account_authorization_check",
            plan_digest="plan_digest_allowed_accounts",
            autonomy_level=campaign.autonomy_level,
            safety_gate_state="awaiting_approval",
            payload={"allowed_accounts": ["owner_test", "member_test"]},
        )
        validation_run = repository.save_validation_run(
            campaign_id=campaign.id,
            task_id=task.id,
            approval_id=None,
            validation_mode="two_account_authorization_check",
            target_ref=f"campaign:{campaign.id}",
            status="planned",
            safety_gate_state="awaiting_approval",
            plan_digest="plan_digest_allowed_accounts",
            approval_required=True,
            allowed_to_execute=False,
            evidence_ref_count=0,
            summary="Awaiting approval",
            payload={"allowed_accounts": ["owner_test", "outside_test"]},
        )

        repository.decide_approval_record(
            approval_id=approval.id,
            decision="approved",
            actor="lead_reviewer",
            reason="Approved for selected test accounts.",
        )

        run = repository.session.get(type(validation_run), validation_run.id)
        assert run.approval_id is None
        assert run.status == "awaiting_approval"
        assert run.safety_gate_state == "awaiting_approval"
        assert run.allowed_to_execute is False
    finally:
        session.close()


def test_repository_approval_decision_respects_approval_validation_budget():
    session, _ = build_session()
    try:
        seed_sample_data(session)
        repository = DatabaseRepository(session)
        campaign = repository.create_campaign(
            program_id="program_example",
            name="Approval validation budget campaign",
            autonomy_level="level_2_test_account_validation",
            scope_status="in_scope",
            policy_text="Testing allowed",
            default_asset="api.example.com",
            created_by="operator",
        )
        task = repository.create_campaign_task(
            campaign_id=campaign.id,
            task_type="report_chain_review",
            agent_type="report_agent",
            title="Review validation gate",
            input_refs=[f"campaign:{campaign.id}"],
        )
        approval = repository.create_approval_record(
            campaign_id=campaign.id,
            task_id=task.id,
            program_id=campaign.program_id,
            approval_type="validation_batch",
            actor="operator",
            reason="Approve one validation run.",
            requested_action="two_account_authorization_check",
            asset=campaign.default_asset,
            validation_mode="two_account_authorization_check",
            plan_digest="plan_digest_approval_budget",
            autonomy_level=campaign.autonomy_level,
            safety_gate_state="awaiting_approval",
            payload={"validation_budget": 1},
        )
        first_run = repository.save_validation_run(
            campaign_id=campaign.id,
            task_id=task.id,
            approval_id=None,
            validation_mode="two_account_authorization_check",
            target_ref=f"campaign:{campaign.id}",
            status="planned",
            safety_gate_state="awaiting_approval",
            plan_digest="plan_digest_approval_budget",
            approval_required=True,
            allowed_to_execute=False,
            evidence_ref_count=0,
            summary="First run awaiting approval",
            payload={},
        )
        second_run = repository.save_validation_run(
            campaign_id=campaign.id,
            task_id=task.id,
            approval_id=None,
            validation_mode="two_account_authorization_check",
            target_ref=f"campaign:{campaign.id}",
            status="planned",
            safety_gate_state="awaiting_approval",
            plan_digest="plan_digest_approval_budget",
            approval_required=True,
            allowed_to_execute=False,
            evidence_ref_count=0,
            summary="Second run should stay gated",
            payload={},
        )

        repository.decide_approval_record(
            approval_id=approval.id,
            decision="approved",
            actor="lead_reviewer",
            reason="Approved one validation run only.",
        )

        first = repository.session.get(type(first_run), first_run.id)
        second = repository.session.get(type(second_run), second_run.id)
        bound_runs = [
            run for run in (first, second)
            if run.approval_id == approval.id and run.status == "ready"
        ]
        gated_runs = [
            run for run in (first, second)
            if run.approval_id is None and run.status == "awaiting_approval"
        ]
        assert len(bound_runs) == 1
        assert len(gated_runs) == 1
    finally:
        session.close()


def test_repository_repeated_approval_preserves_manual_validation_result():
    session, _ = build_session()
    try:
        seed_sample_data(session)
        repository = DatabaseRepository(session)
        campaign = repository.create_campaign(
            program_id="program_example",
            name="Manual result preservation campaign",
            autonomy_level="level_2_test_account_validation",
            scope_status="in_scope",
            policy_text="Testing allowed",
            default_asset="api.example.com",
            created_by="operator",
        )
        task = repository.create_campaign_task(
            campaign_id=campaign.id,
            task_type="report_chain_review",
            agent_type="report_agent",
            title="Review validation gate",
            input_refs=[f"campaign:{campaign.id}"],
        )
        approval = repository.create_approval_record(
            campaign_id=campaign.id,
            task_id=task.id,
            program_id=campaign.program_id,
            approval_type="validation_batch",
            actor="operator",
            reason="Approve test-account validation.",
            requested_action="two_account_authorization_check",
            asset=campaign.default_asset,
            validation_mode="two_account_authorization_check",
            plan_digest="plan_digest_manual_result_preserved",
            autonomy_level=campaign.autonomy_level,
            safety_gate_state="awaiting_approval",
        )
        validation_run = repository.save_validation_run(
            campaign_id=campaign.id,
            task_id=task.id,
            approval_id=None,
            validation_mode="two_account_authorization_check",
            target_ref=f"campaign:{campaign.id}",
            status="planned",
            safety_gate_state="awaiting_approval",
            plan_digest="plan_digest_manual_result_preserved",
            approval_required=True,
            allowed_to_execute=False,
            evidence_ref_count=0,
            summary="Awaiting approval",
            payload={},
        )

        repository.decide_approval_record(
            approval_id=approval.id,
            decision="approved",
            actor="lead_reviewer",
            reason="Approved for manual result.",
        )
        repository.record_validation_run_preflight(
            validation_run.id,
            allowed=True,
            reason="approved_validation_record",
        )
        repository.record_validation_run_manual_result(
            validation_run.id,
            outcome="observed",
            reviewer="lead_reviewer",
            summary="Observed redacted evidence.",
            evidence_refs=["sanitized_request_response"],
        )
        repository.decide_approval_record(
            approval_id=approval.id,
            decision="approved",
            actor="lead_reviewer",
            reason="Repeated approval should not reopen evidence.",
        )

        run = repository.session.get(type(validation_run), validation_run.id)
        assert run.status == "evidence_recorded"
        assert run.safety_gate_state == "manual_evidence_recorded"
        assert run.allowed_to_execute is False
        assert run.evidence_ref_count == 1
    finally:
        session.close()


def test_repository_manual_result_requires_active_preflight_permission():
    session, _ = build_session()
    try:
        seed_sample_data(session)
        repository = DatabaseRepository(session)
        campaign = repository.create_campaign(
            program_id="program_example",
            name="Stale preflight repository campaign",
            autonomy_level="level_2_test_account_validation",
            scope_status="in_scope",
            policy_text="Testing allowed",
            default_asset="api.example.com",
            created_by="operator",
        )
        task = repository.create_campaign_task(
            campaign_id=campaign.id,
            task_type="report_chain_review",
            agent_type="report_agent",
            title="Review validation gate",
            input_refs=[f"campaign:{campaign.id}"],
        )
        validation_run = repository.save_validation_run(
            campaign_id=campaign.id,
            task_id=task.id,
            approval_id=None,
            validation_mode="two_account_authorization_check",
            target_ref=f"campaign:{campaign.id}",
            status="preflight_passed",
            safety_gate_state="scope_guard_preflight_passed",
            plan_digest="plan_digest_stale_manual_result",
            approval_required=False,
            allowed_to_execute=False,
            evidence_ref_count=0,
            summary="Stale preflight",
            payload={},
        )

        updated = repository.record_validation_run_manual_result(
            validation_run.id,
            outcome="observed",
            reviewer="lead_reviewer",
            summary="Should not record stale preflight.",
            evidence_refs=["sanitized_request_response"],
        )

        run = repository.session.get(type(validation_run), validation_run.id)
        assert updated is None
        assert run.status == "preflight_passed"
        assert run.safety_gate_state == "scope_guard_preflight_passed"
        assert run.allowed_to_execute is False
        assert "manual_result" not in run.payload
    finally:
        session.close()


def test_repository_preflight_after_manual_result_does_not_mutate_audit_state():
    session, _ = build_session()
    try:
        seed_sample_data(session)
        repository = DatabaseRepository(session)
        campaign = repository.create_campaign(
            program_id="program_example",
            name="Repository preflight after manual result campaign",
            autonomy_level="level_2_test_account_validation",
            scope_status="in_scope",
            policy_text="Testing allowed",
            default_asset="api.example.com",
            created_by="operator",
        )
        task = repository.create_campaign_task(
            campaign_id=campaign.id,
            task_type="report_chain_review",
            agent_type="report_agent",
            title="Review validation gate",
            input_refs=[f"campaign:{campaign.id}"],
        )
        validation_run = repository.save_validation_run(
            campaign_id=campaign.id,
            task_id=task.id,
            approval_id=None,
            validation_mode="two_account_authorization_check",
            target_ref=f"campaign:{campaign.id}",
            status="preflight_passed",
            safety_gate_state="scope_guard_preflight_passed",
            plan_digest="repository_preflight_after_manual_result",
            approval_required=False,
            allowed_to_execute=True,
            evidence_ref_count=0,
            summary="Preflight passed",
            payload={
                "scope_guard_preflight": {
                    "allowed": True,
                    "reason": "human_controlled_preflight",
                },
            },
        )
        repository.record_validation_run_manual_result(
            validation_run.id,
            outcome="observed",
            reviewer="lead_reviewer",
            summary="Observed redacted evidence.",
            evidence_refs=["sanitized_request_response"],
        )
        run = repository.session.get(type(validation_run), validation_run.id)
        original_status = run.status
        original_safety_gate_state = run.safety_gate_state
        original_allowed_to_execute = run.allowed_to_execute
        original_finished_at = run.finished_at
        original_payload = dict(run.payload)

        updated = repository.record_validation_run_preflight(
            validation_run.id,
            allowed=True,
            reason="late_preflight_replay",
        )

        run = repository.session.get(type(validation_run), validation_run.id)
        assert updated is None
        assert run.status == original_status
        assert run.safety_gate_state == original_safety_gate_state
        assert run.allowed_to_execute == original_allowed_to_execute
        assert run.finished_at == original_finished_at
        assert run.payload == original_payload
    finally:
        session.close()


def test_repository_revoked_approval_preserves_manual_validation_result_audit_state():
    session, _ = build_session()
    try:
        seed_sample_data(session)
        repository = DatabaseRepository(session)
        campaign = repository.create_campaign(
            program_id="program_example",
            name="Manual result revoked approval campaign",
            autonomy_level="level_2_test_account_validation",
            scope_status="in_scope",
            policy_text="Testing allowed",
            default_asset="api.example.com",
            created_by="operator",
        )
        task = repository.create_campaign_task(
            campaign_id=campaign.id,
            task_type="report_chain_review",
            agent_type="report_agent",
            title="Review validation gate",
            input_refs=[f"campaign:{campaign.id}"],
        )
        approval = repository.create_approval_record(
            campaign_id=campaign.id,
            task_id=task.id,
            program_id=campaign.program_id,
            approval_type="validation_batch",
            actor="operator",
            reason="Approve test-account validation.",
            requested_action="two_account_authorization_check",
            asset=campaign.default_asset,
            validation_mode="two_account_authorization_check",
            plan_digest="plan_digest_manual_result_revoked",
            autonomy_level=campaign.autonomy_level,
            safety_gate_state="awaiting_approval",
        )
        validation_run = repository.save_validation_run(
            campaign_id=campaign.id,
            task_id=task.id,
            approval_id=None,
            validation_mode="two_account_authorization_check",
            target_ref=f"campaign:{campaign.id}",
            status="planned",
            safety_gate_state="awaiting_approval",
            plan_digest="plan_digest_manual_result_revoked",
            approval_required=True,
            allowed_to_execute=False,
            evidence_ref_count=0,
            summary="Awaiting approval",
            payload={},
        )

        repository.decide_approval_record(
            approval_id=approval.id,
            decision="approved",
            actor="lead_reviewer",
            reason="Approved for manual result.",
        )
        repository.record_validation_run_preflight(
            validation_run.id,
            allowed=True,
            reason="approved_validation_record",
        )
        repository.record_validation_run_manual_result(
            validation_run.id,
            outcome="observed",
            reviewer="lead_reviewer",
            summary="Observed redacted evidence.",
            evidence_refs=["sanitized_request_response"],
        )
        repository.decide_approval_record(
            approval_id=approval.id,
            decision="revoked",
            actor="lead_reviewer",
            reason="Approval revoked after evidence was recorded.",
        )

        run = repository.session.get(type(validation_run), validation_run.id)
        assert run.status == "evidence_recorded"
        assert run.safety_gate_state == "manual_evidence_recorded"
        assert run.allowed_to_execute is False
        assert run.evidence_ref_count == 1
        assert "manual_result" in run.payload
    finally:
        session.close()


def test_repository_redacted_only_manual_validation_result_stays_needs_evidence():
    session, _ = build_session()
    try:
        seed_sample_data(session)
        repository = DatabaseRepository(session)
        campaign = repository.create_campaign(
            program_id="program_example",
            name="Manual result redacted-only campaign",
            autonomy_level="level_2_test_account_validation",
            scope_status="in_scope",
            policy_text="Testing allowed",
            default_asset="api.example.com",
            created_by="operator",
        )
        task = repository.create_campaign_task(
            campaign_id=campaign.id,
            task_type="report_chain_review",
            agent_type="report_agent",
            title="Review validation gate",
            input_refs=[f"campaign:{campaign.id}"],
        )
        approval = repository.create_approval_record(
            campaign_id=campaign.id,
            task_id=task.id,
            program_id=campaign.program_id,
            approval_type="validation_batch",
            actor="operator",
            reason="Approve test-account validation.",
            requested_action="two_account_authorization_check",
            asset=campaign.default_asset,
            validation_mode="two_account_authorization_check",
            plan_digest="plan_digest_manual_result_redacted_only",
            autonomy_level=campaign.autonomy_level,
            safety_gate_state="awaiting_approval",
        )
        validation_run = repository.save_validation_run(
            campaign_id=campaign.id,
            task_id=task.id,
            approval_id=None,
            validation_mode="two_account_authorization_check",
            target_ref=f"campaign:{campaign.id}",
            status="planned",
            safety_gate_state="awaiting_approval",
            plan_digest="plan_digest_manual_result_redacted_only",
            approval_required=True,
            allowed_to_execute=False,
            evidence_ref_count=0,
            summary="Awaiting approval",
            payload={},
        )

        repository.decide_approval_record(
            approval_id=approval.id,
            decision="approved",
            actor="lead_reviewer",
            reason="Approved for manual result.",
        )
        repository.record_validation_run_preflight(
            validation_run.id,
            allowed=True,
            reason="approved_validation_record",
        )
        repository.record_validation_run_manual_result(
            validation_run.id,
            outcome="observed",
            reviewer="lead_reviewer",
            summary="Observed only sensitive evidence refs.",
            evidence_refs=[
                "Authorization: Bearer secret-token",
                "Cookie: session=secret",
            ],
        )
        repository.decide_approval_record(
            approval_id=approval.id,
            decision="approved",
            actor="lead_reviewer",
            reason="Repeated approval should not reopen evidence.",
        )

        run = repository.session.get(type(validation_run), validation_run.id)
        assert run.status == "needs_evidence"
        assert run.safety_gate_state == "manual_evidence_gap_recorded"
        assert run.allowed_to_execute is False
        assert run.evidence_ref_count == 0
        assert "secret-token" not in str(run.payload)
        assert "session=secret" not in str(run.payload)
    finally:
        session.close()


def test_repository_manual_validation_result_records_sanitized_quality_review():
    session, _ = build_session()
    try:
        seed_sample_data(session)
        repository = DatabaseRepository(session)
        campaign = repository.create_campaign(
            program_id="program_example",
            name="Manual result quality review campaign",
            autonomy_level="level_2_test_account_validation",
            scope_status="in_scope",
            policy_text="Testing allowed",
            default_asset="api.example.com",
            created_by="operator",
        )
        task = repository.create_campaign_task(
            campaign_id=campaign.id,
            task_type="report_chain_review",
            agent_type="report_agent",
            title="Review validation result normalization",
            input_refs=[f"campaign:{campaign.id}"],
        )
        approval = repository.create_approval_record(
            campaign_id=campaign.id,
            task_id=task.id,
            program_id=campaign.program_id,
            approval_type="validation_batch",
            actor="operator",
            reason="Approve local fixture validation.",
            requested_action="two_account_authorization_check",
            asset=campaign.default_asset,
            validation_mode="two_account_authorization_check",
            plan_digest="plan_digest_manual_result_quality_review",
            autonomy_level=campaign.autonomy_level,
            safety_gate_state="awaiting_approval",
        )
        validation_run = repository.save_validation_run(
            campaign_id=campaign.id,
            task_id=task.id,
            approval_id=None,
            validation_mode="two_account_authorization_check",
            target_ref=f"campaign:{campaign.id}",
            status="planned",
            safety_gate_state="awaiting_approval",
            plan_digest="plan_digest_manual_result_quality_review",
            approval_required=True,
            allowed_to_execute=False,
            evidence_ref_count=0,
            summary="Awaiting approval",
            payload={},
        )

        repository.decide_approval_record(
            approval_id=approval.id,
            decision="approved",
            actor="lead_reviewer",
            reason="Approved for local fixture validation.",
        )
        repository.record_validation_run_preflight(
            validation_run.id,
            allowed=True,
            reason="approved_validation_record",
        )
        repository.record_validation_run_manual_result(
            validation_run.id,
            outcome="observed",
            reviewer="lead_reviewer",
            summary="Observed fixture diff only. Authorization: Bearer secret-token",
            evidence_refs=[
                "sanitized_request_response",
                "local_code_reference",
                "contains real_user_data from customer@example.com",
            ],
        )

        run = repository.session.get(type(validation_run), validation_run.id)
        review = run.payload["validation_result_review"]
        assert review == {
            "source_type": "manual_safe_observation",
            "redaction_status": "redacted",
            "evidence_quality": "adequate",
            "quality_score": 65,
            "promotion_review_ready": False,
            "quality_reasons": [
                "manual_result_recorded",
                "has_report_safe_evidence",
                "sensitive_material_redacted",
                "promotion_blocked_by_redaction_review",
                "unsupported_evidence_refs",
                "promotion_blocked_by_unsupported_evidence",
            ],
            "safe_evidence_ref_count": 2,
            "unsafe_evidence_ref_count": 1,
        }
        assert "secret-token" not in str(run.payload)
        assert "customer@example.com" not in str(run.payload)
    finally:
        session.close()


def test_repository_manual_validation_result_scores_clean_fixture_evidence_without_execution():
    session, _ = build_session()
    try:
        seed_sample_data(session)
        repository = DatabaseRepository(session)
        campaign = repository.create_campaign(
            program_id="program_example",
            name="Clean fixture evidence campaign",
            autonomy_level="level_1_local_validation",
            scope_status="in_scope",
            policy_text="Local fixture validation allowed",
            default_asset="api.example.com",
            created_by="operator",
        )
        validation_run = repository.save_validation_run(
            campaign_id=campaign.id,
            task_id=None,
            approval_id=None,
            validation_mode="fixture_replay",
            target_ref=f"campaign:{campaign.id}",
            status="preflight_passed",
            safety_gate_state="scope_guard_preflight_passed",
            plan_digest="fixture_replay_plan",
            approval_required=False,
            allowed_to_execute=True,
            evidence_ref_count=0,
            summary="Ready for local fixture observation",
            payload={},
        )

        repository.record_validation_run_manual_result(
            validation_run.id,
            outcome="observed",
            reviewer="fixture_reviewer",
            summary="Observed fixture replay with sanitized request and role matrix refs.",
            evidence_refs=[
                "sanitized_request_response",
                "local_code_reference",
                "role_matrix_snapshot",
            ],
        )

        run = repository.session.get(type(validation_run), validation_run.id)
        assert run.status == "evidence_recorded"
        assert run.allowed_to_execute is False
        assert run.payload["manual_result"]["execution_started"] is False
        assert run.payload["validation_result_review"] == {
            "source_type": "manual_safe_observation",
            "redaction_status": "clean",
            "evidence_quality": "strong",
            "quality_score": 80,
            "promotion_review_ready": True,
            "quality_reasons": [
                "manual_result_recorded",
                "has_report_safe_evidence",
                "clean_redaction_review",
            ],
            "safe_evidence_ref_count": 3,
            "unsafe_evidence_ref_count": 0,
        }
    finally:
        session.close()


def test_repository_manual_validation_result_requires_strong_evidence_for_promotion_review():
    session, _ = build_session()
    try:
        seed_sample_data(session)
        repository = DatabaseRepository(session)
        campaign = repository.create_campaign(
            program_id="program_example",
            name="Thin fixture evidence campaign",
            autonomy_level="level_1_local_validation",
            scope_status="in_scope",
            policy_text="Local fixture validation allowed",
            default_asset="api.example.com",
            created_by="operator",
        )
        validation_run = repository.save_validation_run(
            campaign_id=campaign.id,
            task_id=None,
            approval_id=None,
            validation_mode="fixture_replay",
            target_ref=f"campaign:{campaign.id}",
            status="preflight_passed",
            safety_gate_state="scope_guard_preflight_passed",
            plan_digest="fixture_replay_plan",
            approval_required=False,
            allowed_to_execute=True,
            evidence_ref_count=0,
            summary="Ready for local fixture observation",
            payload={},
        )

        repository.record_validation_run_manual_result(
            validation_run.id,
            outcome="observed",
            reviewer="fixture_reviewer",
            summary="Observed fixture replay with one sanitized request ref.",
            evidence_refs=["sanitized_request_response"],
        )

        run = repository.session.get(type(validation_run), validation_run.id)
        review = run.payload["validation_result_review"]
        assert run.status == "evidence_recorded"
        assert run.allowed_to_execute is False
        assert review["redaction_status"] == "clean"
        assert review["evidence_quality"] == "adequate"
        assert review["promotion_review_ready"] is False
        assert "promotion_blocked_by_insufficient_evidence" in review["quality_reasons"]
        assert review["safe_evidence_ref_count"] == 1
        assert review["unsafe_evidence_ref_count"] == 0
    finally:
        session.close()


def test_repository_manual_validation_result_does_not_score_duplicate_safe_refs_as_strong():
    session, _ = build_session()
    try:
        seed_sample_data(session)
        repository = DatabaseRepository(session)
        campaign = repository.create_campaign(
            program_id="program_example",
            name="Duplicate fixture evidence campaign",
            autonomy_level="level_1_local_validation",
            scope_status="in_scope",
            policy_text="Local fixture validation allowed",
            default_asset="api.example.com",
            created_by="operator",
        )
        validation_run = repository.save_validation_run(
            campaign_id=campaign.id,
            task_id=None,
            approval_id=None,
            validation_mode="fixture_replay",
            target_ref=f"campaign:{campaign.id}",
            status="preflight_passed",
            safety_gate_state="scope_guard_preflight_passed",
            plan_digest="fixture_replay_plan",
            approval_required=False,
            allowed_to_execute=True,
            evidence_ref_count=0,
            summary="Ready for local fixture observation",
            payload={},
        )

        repository.record_validation_run_manual_result(
            validation_run.id,
            outcome="observed",
            reviewer="fixture_reviewer",
            summary="Observed fixture replay with repeated sanitized request refs.",
            evidence_refs=[
                "sanitized_request_response",
                "sanitized_request_response",
                "sanitized_request_response",
            ],
        )

        run = repository.session.get(type(validation_run), validation_run.id)
        review = run.payload["validation_result_review"]
        assert run.status == "evidence_recorded"
        assert run.evidence_ref_count == 1
        assert review["evidence_quality"] == "adequate"
        assert review["promotion_review_ready"] is False
        assert "promotion_blocked_by_insufficient_evidence" in review["quality_reasons"]
        assert review["safe_evidence_ref_count"] == 1
        assert review["unsafe_evidence_ref_count"] == 0
    finally:
        session.close()


def test_repository_manual_validation_result_requires_diverse_safe_refs_for_promotion_review():
    session, _ = build_session()
    try:
        seed_sample_data(session)
        repository = DatabaseRepository(session)
        campaign = repository.create_campaign(
            program_id="program_example",
            name="Single evidence category campaign",
            autonomy_level="level_1_local_validation",
            scope_status="in_scope",
            policy_text="Local fixture validation allowed",
            default_asset="api.example.com",
            created_by="operator",
        )
        validation_run = repository.save_validation_run(
            campaign_id=campaign.id,
            task_id=None,
            approval_id=None,
            validation_mode="fixture_replay",
            target_ref=f"campaign:{campaign.id}",
            status="preflight_passed",
            safety_gate_state="scope_guard_preflight_passed",
            plan_digest="fixture_replay_plan",
            approval_required=False,
            allowed_to_execute=True,
            evidence_ref_count=0,
            summary="Ready for local fixture observation",
            payload={},
        )

        repository.record_validation_run_manual_result(
            validation_run.id,
            outcome="observed",
            reviewer="fixture_reviewer",
            summary="Observed fixture replay with only request trace style refs.",
            evidence_refs=[
                "sanitized_request_response",
                "request_response_diff",
                "sanitized_cross_account_diff",
            ],
        )

        run = repository.session.get(type(validation_run), validation_run.id)
        review = run.payload["validation_result_review"]
        assert run.status == "evidence_recorded"
        assert run.evidence_ref_count == 3
        assert review["evidence_quality"] == "adequate"
        assert review["promotion_review_ready"] is False
        assert "promotion_blocked_by_insufficient_evidence" in review["quality_reasons"]
        assert "promotion_blocked_by_low_evidence_diversity" in review["quality_reasons"]
        assert review["safe_evidence_ref_count"] == 3
        assert review["unsafe_evidence_ref_count"] == 0
    finally:
        session.close()


def test_repository_manual_validation_result_treats_non_string_refs_as_unsupported():
    session, _ = build_session()
    try:
        seed_sample_data(session)
        repository = DatabaseRepository(session)
        campaign = repository.create_campaign(
            program_id="program_example",
            name="Malformed evidence refs campaign",
            autonomy_level="level_1_local_validation",
            scope_status="in_scope",
            policy_text="Local fixture validation allowed",
            default_asset="api.example.com",
            created_by="operator",
        )
        validation_run = repository.save_validation_run(
            campaign_id=campaign.id,
            task_id=None,
            approval_id=None,
            validation_mode="fixture_replay",
            target_ref=f"campaign:{campaign.id}",
            status="preflight_passed",
            safety_gate_state="scope_guard_preflight_passed",
            plan_digest="fixture_replay_plan",
            approval_required=False,
            allowed_to_execute=True,
            evidence_ref_count=0,
            summary="Ready for local fixture observation",
            payload={},
        )

        repository.record_validation_run_manual_result(
            validation_run.id,
            outcome="observed",
            reviewer="fixture_reviewer",
            summary="Observed fixture replay with malformed evidence refs.",
            evidence_refs=[
                "sanitized_request_response",
                {"type": "local_code_reference", "Authorization": "Bearer fixture-secret"},
                123,
                None,
            ],
        )

        run = repository.session.get(type(validation_run), validation_run.id)
        review = run.payload["validation_result_review"]
        assert run.status == "evidence_recorded"
        assert run.evidence_ref_count == 1
        assert review["redaction_status"] == "redacted"
        assert review["evidence_quality"] == "adequate"
        assert review["promotion_review_ready"] is False
        assert "sensitive_material_redacted" in review["quality_reasons"]
        assert "promotion_blocked_by_redaction_review" in review["quality_reasons"]
        assert "unsupported_evidence_refs" in review["quality_reasons"]
        assert "promotion_blocked_by_unsupported_evidence" in review["quality_reasons"]
        assert review["safe_evidence_ref_count"] == 1
        assert review["unsafe_evidence_ref_count"] == 3
        assert "fixture-secret" not in str(run.payload)
    finally:
        session.close()


def test_repository_manual_validation_result_redacts_x_api_key_header():
    session, _ = build_session()
    try:
        seed_sample_data(session)
        repository = DatabaseRepository(session)
        campaign = repository.create_campaign(
            program_id="program_example",
            name="API key header redaction campaign",
            autonomy_level="level_1_local_validation",
            scope_status="in_scope",
            policy_text="Local fixture validation allowed",
            default_asset="api.example.com",
            created_by="operator",
        )
        validation_run = repository.save_validation_run(
            campaign_id=campaign.id,
            task_id=None,
            approval_id=None,
            validation_mode="fixture_replay",
            target_ref=f"campaign:{campaign.id}",
            status="preflight_passed",
            safety_gate_state="scope_guard_preflight_passed",
            plan_digest="fixture_replay_plan",
            approval_required=False,
            allowed_to_execute=True,
            evidence_ref_count=0,
            summary="Ready for local fixture observation",
            payload={},
        )

        repository.record_validation_run_manual_result(
            validation_run.id,
            outcome="observed",
            reviewer="fixture_reviewer",
            summary="Observed fixture replay. X-API-Key: secret-fixture-key",
            evidence_refs=[
                "sanitized_request_response",
                "local_code_reference",
                "role_matrix_snapshot",
            ],
        )

        run = repository.session.get(type(validation_run), validation_run.id)
        review = run.payload["validation_result_review"]
        assert review["redaction_status"] == "redacted"
        assert review["promotion_review_ready"] is False
        assert "sensitive_material_redacted" in review["quality_reasons"]
        assert "promotion_blocked_by_redaction_review" in review["quality_reasons"]
        assert "secret-fixture-key" not in str(run.payload)
        assert "X-API-Key" not in str(run.payload)
    finally:
        session.close()


def test_repository_does_not_unlock_validation_run_for_mismatched_approval_asset():
    session, _ = build_session()
    try:
        seed_sample_data(session)
        repository = DatabaseRepository(session)
        campaign = repository.create_campaign(
            program_id="program_example",
            name="Asset mismatch validation campaign",
            autonomy_level="level_2_test_account_validation",
            scope_status="in_scope",
            policy_text="Testing allowed",
            default_asset="api.example.com",
            created_by="operator",
        )
        task = repository.create_campaign_task(
            campaign_id=campaign.id,
            task_type="report_chain_review",
            agent_type="report_agent",
            title="Review validation gate",
            input_refs=[f"campaign:{campaign.id}"],
        )
        approval = repository.create_approval_record(
            campaign_id=campaign.id,
            task_id=task.id,
            program_id=campaign.program_id,
            approval_type="validation_batch",
            actor="operator",
            reason="Approve different asset",
            requested_action="two_account_authorization_check",
            asset="other.example.com",
            validation_mode="two_account_authorization_check",
            plan_digest="plan_digest_asset_mismatch",
            autonomy_level=campaign.autonomy_level,
            safety_gate_state="awaiting_approval",
        )
        validation_run = repository.save_validation_run(
            campaign_id=campaign.id,
            task_id=task.id,
            approval_id=None,
            validation_mode="two_account_authorization_check",
            target_ref=f"campaign:{campaign.id}",
            status="planned",
            safety_gate_state="awaiting_approval",
            plan_digest="plan_digest_asset_mismatch",
            approval_required=True,
            allowed_to_execute=False,
            evidence_ref_count=0,
            summary="Awaiting approval",
            payload={},
        )

        repository.decide_approval_record(
            approval_id=approval.id,
            decision="approved",
            actor="lead_reviewer",
            reason="Approved for other asset only.",
        )

        run = repository.session.get(type(validation_run), validation_run.id)
        assert run.approval_id is None
        assert run.status == "awaiting_approval"
        assert run.safety_gate_state == "awaiting_approval"
        assert run.allowed_to_execute is False
    finally:
        session.close()


def test_repository_matches_approval_asset_after_safe_url_normalization():
    session, _ = build_session()
    try:
        seed_sample_data(session)
        repository = DatabaseRepository(session)
        campaign = repository.create_campaign(
            program_id="program_example",
            name="Normalized approval asset campaign",
            autonomy_level="level_2_test_account_validation",
            scope_status="in_scope",
            policy_text="Testing allowed",
            default_asset="https://api.example.com/path?session=secret",
            created_by="operator",
        )
        task = repository.create_campaign_task(
            campaign_id=campaign.id,
            task_type="report_chain_review",
            agent_type="report_agent",
            title="Review validation gate",
            input_refs=[f"campaign:{campaign.id}"],
        )
        approval = repository.create_approval_record(
            campaign_id=campaign.id,
            task_id=task.id,
            program_id=campaign.program_id,
            approval_type="validation_batch",
            actor="operator",
            reason="Approve default campaign asset",
            requested_action="two_account_authorization_check",
            asset="https://api.example.com/path?session=secret",
            validation_mode="two_account_authorization_check",
            plan_digest="plan_digest_normalized_asset",
            autonomy_level=campaign.autonomy_level,
            safety_gate_state="awaiting_approval",
        )
        validation_run = repository.save_validation_run(
            campaign_id=campaign.id,
            task_id=task.id,
            approval_id=None,
            validation_mode="two_account_authorization_check",
            target_ref=f"campaign:{campaign.id}",
            status="planned",
            safety_gate_state="awaiting_approval",
            plan_digest="plan_digest_normalized_asset",
            approval_required=True,
            allowed_to_execute=False,
            evidence_ref_count=0,
            summary="Awaiting approval",
            payload={},
        )

        repository.decide_approval_record(
            approval_id=approval.id,
            decision="approved",
            actor="lead_reviewer",
            reason="Approved for normalized default asset.",
        )

        run = repository.session.get(type(validation_run), validation_run.id)
        refreshed_approval = repository.session.get(type(approval), approval.id)
        assert refreshed_approval.asset == "api.example.com/path"
        assert "session=secret" not in str(refreshed_approval.asset)
        assert run.approval_id == approval.id
        assert run.status == "ready"
        assert run.safety_gate_state == "approved_validation_record"
        assert run.allowed_to_execute is False
    finally:
        session.close()


def test_repository_matches_approval_asset_to_validation_target_ref_when_present():
    session, _ = build_session()
    try:
        seed_sample_data(session)
        repository = DatabaseRepository(session)
        campaign = repository.create_campaign(
            program_id="program_example",
            name="Target ref mismatch campaign",
            autonomy_level="level_2_test_account_validation",
            scope_status="in_scope",
            policy_text="Testing allowed",
            default_asset="api.example.com",
            created_by="operator",
        )
        task = repository.create_campaign_task(
            campaign_id=campaign.id,
            task_type="report_chain_review",
            agent_type="report_agent",
            title="Review validation gate",
            input_refs=[f"campaign:{campaign.id}"],
        )
        approval = repository.create_approval_record(
            campaign_id=campaign.id,
            task_id=task.id,
            program_id=campaign.program_id,
            approval_type="validation_batch",
            actor="operator",
            reason="Approve default campaign asset",
            requested_action="two_account_authorization_check",
            asset=campaign.default_asset,
            validation_mode="two_account_authorization_check",
            plan_digest="plan_digest_target_mismatch",
            autonomy_level=campaign.autonomy_level,
            safety_gate_state="awaiting_approval",
        )
        validation_run = repository.save_validation_run(
            campaign_id=campaign.id,
            task_id=task.id,
            approval_id=None,
            validation_mode="two_account_authorization_check",
            target_ref="other.example.com",
            status="planned",
            safety_gate_state="awaiting_approval",
            plan_digest="plan_digest_target_mismatch",
            approval_required=True,
            allowed_to_execute=False,
            evidence_ref_count=0,
            summary="Awaiting approval",
            payload={},
        )

        repository.decide_approval_record(
            approval_id=approval.id,
            decision="approved",
            actor="lead_reviewer",
            reason="Approved for default asset only.",
        )

        run = repository.session.get(type(validation_run), validation_run.id)
        assert run.approval_id is None
        assert run.status == "awaiting_approval"
        assert run.safety_gate_state == "awaiting_approval"
        assert run.allowed_to_execute is False
    finally:
        session.close()
