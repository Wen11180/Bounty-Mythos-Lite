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
