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
            payload={"authorization": "Bearer secret-token", "notes": "local only"},
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
