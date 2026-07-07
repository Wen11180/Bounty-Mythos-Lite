from pathlib import Path
import json

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.cli import main as cli_main
from app.db import Base
from app.mythos_agent import (
    AgentGoal,
    get_agent_gates,
    get_agent_next,
    get_agent_status,
    record_agent_review_note,
    run_agent_goal,
)
from app.repository import DatabaseRepository, seed_sample_data


def build_repository():
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    session = sessionmaker(bind=engine)()
    seed_sample_data(session)
    return DatabaseRepository(session), session


def write_authorized_repo(tmp_path: Path) -> tuple[Path, Path]:
    repo = tmp_path / "target"
    repo.mkdir()
    (repo / "routes.py").write_text(
        "\n".join(
            [
                "from fastapi import APIRouter",
                "router = APIRouter()",
                '@router.get("/files/{file_id}/export")',
                "def export_file(file_id: str):",
                "    return send_file(file_id)",
            ]
        ),
        encoding="utf-8",
    )
    scope = tmp_path / "scope.yaml"
    scope.write_text(f"allowed_repos:\n  - {repo}\n", encoding="utf-8")
    return repo, scope


def test_agent_runner_creates_campaign_and_stops_at_human_review_gate(tmp_path):
    repo, scope = write_authorized_repo(tmp_path)
    repository, session = build_repository()
    try:
        result = run_agent_goal(
            AgentGoal(
                goal="Run a bounded safe research loop",
                repo_path=repo,
                scope_path=scope,
                max_steps=6,
            ),
            repository=repository,
        )

        assert result.status == "awaiting_human_review"
        assert result.campaign_id is not None
        assert result.stop_reasons == ["validation_approval_required"]
        assert any(step.action == "create_campaign" for step in result.steps)
        assert any(step.action == "campaign_tick" for step in result.steps)
        assert any(step.action == "review_gate" for step in result.steps)
        assert "execution_allowed: false" in result.to_text()
        receipt = result.to_dict()
        assert receipt["status"] == "awaiting_human_review"
        assert receipt["goal"] == "Run a bounded safe research loop"
        assert receipt["repo_path"] == str(repo.resolve())
        assert receipt["scope_path"] == str(scope.resolve())
        assert receipt["next_actions"] == ["review_validation_queue"]
        assert receipt["execution_allowed"] is False
        assert "send_file(file_id)" not in json.dumps(receipt)

        campaign = repository.get_campaign(result.campaign_id)
        assert campaign is not None
        assert campaign.status == "running"
        facts = repository.list_campaign_codebase_facts(result.campaign_id)
        assert any(fact.route_path == "/files/{file_id}/export" for fact in facts)
        approvals = repository.list_campaign_approval_records(result.campaign_id)
        validation_runs = repository.list_campaign_validation_runs(result.campaign_id)
        assert approvals
        assert validation_runs
        assert all(run.allowed_to_execute is False for run in validation_runs)
    finally:
        session.close()


def test_agent_runner_blocks_unallowlisted_repo_without_campaign(tmp_path):
    repo = tmp_path / "target"
    repo.mkdir()
    scope = tmp_path / "scope.yaml"
    scope.write_text("allowed_repos:\n  - C:/different/repo\n", encoding="utf-8")
    repository, session = build_repository()
    try:
        result = run_agent_goal(
            AgentGoal(
                goal="Run a bounded safe research loop",
                repo_path=repo,
                scope_path=scope,
            ),
            repository=repository,
        )

        assert result.status == "blocked"
        assert result.campaign_id is None
        assert result.stop_reasons == ["repo_not_allowlisted"]
        assert repository.list_campaigns() == []
    finally:
        session.close()


def test_cli_agent_runs_bounded_loop_with_sqlite_database(tmp_path, capsys):
    repo, scope = write_authorized_repo(tmp_path)
    database_path = tmp_path / "agent.sqlite"
    receipt_path = tmp_path / "agent-receipt.json"

    exit_code = cli_main(
        [
            "agent",
            "--repo",
            str(repo),
            "--scope",
            str(scope),
            "--goal",
            "Run a bounded safe research loop",
            "--database-url",
            f"sqlite:///{database_path.as_posix()}",
            "--max-steps",
            "6",
            "--receipt-output",
            str(receipt_path),
        ]
    )

    captured = capsys.readouterr()
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    assert exit_code == 0
    assert "mythos agent" in captured.out
    assert "status: awaiting_human_review" in captured.out
    assert "stop_reasons: validation_approval_required" in captured.out
    assert "execution_allowed: false" in captured.out
    assert receipt["status"] == "awaiting_human_review"
    assert receipt["next_actions"] == ["review_validation_queue"]


def test_cli_agent_resumes_from_receipt_without_creating_new_campaign(tmp_path, capsys):
    repo, scope = write_authorized_repo(tmp_path)
    database_path = tmp_path / "agent.sqlite"
    receipt_path = tmp_path / "agent-receipt.json"
    resumed_receipt_path = tmp_path / "agent-resumed-receipt.json"

    first_exit_code = cli_main(
        [
            "agent",
            "--repo",
            str(repo),
            "--scope",
            str(scope),
            "--goal",
            "Run a bounded safe research loop",
            "--database-url",
            f"sqlite:///{database_path.as_posix()}",
            "--max-steps",
            "6",
            "--receipt-output",
            str(receipt_path),
        ]
    )
    capsys.readouterr()
    first_receipt = json.loads(receipt_path.read_text(encoding="utf-8"))

    second_exit_code = cli_main(
        [
            "agent",
            "--database-url",
            f"sqlite:///{database_path.as_posix()}",
            "--resume-from",
            str(receipt_path),
            "--receipt-output",
            str(resumed_receipt_path),
        ]
    )

    captured = capsys.readouterr()
    resumed_receipt = json.loads(resumed_receipt_path.read_text(encoding="utf-8"))
    assert first_exit_code == 0
    assert second_exit_code == 0
    assert resumed_receipt["campaign_id"] == first_receipt["campaign_id"]
    assert resumed_receipt["status"] == "awaiting_human_review"
    assert resumed_receipt["next_actions"] == ["review_validation_queue"]
    assert "create_campaign" not in captured.out


def test_agent_status_summarizes_human_gates_from_campaign_state(tmp_path):
    repo, scope = write_authorized_repo(tmp_path)
    repository, session = build_repository()
    try:
        result = run_agent_goal(
            AgentGoal(
                goal="Run a bounded safe research loop",
                repo_path=repo,
                scope_path=scope,
                max_steps=6,
            ),
            repository=repository,
        )

        status = get_agent_status(
            campaign_id=result.campaign_id,
            repository=repository,
            goal=result.goal,
            repo_path=result.repo_path,
            scope_path=result.scope_path,
        )

        assert status.status == "awaiting_human_review"
        assert status.pending_approval_count == 1
        assert status.awaiting_validation_count == 1
        assert status.next_actions == ["review_validation_queue"]
        assert status.execution_allowed is False
        assert status.to_dict()["pending_approval_count"] == 1
    finally:
        session.close()


def test_cli_agent_status_reads_receipt_without_running_new_steps(tmp_path, capsys):
    repo, scope = write_authorized_repo(tmp_path)
    database_path = tmp_path / "agent.sqlite"
    receipt_path = tmp_path / "agent-receipt.json"

    cli_main(
        [
            "agent",
            "--repo",
            str(repo),
            "--scope",
            str(scope),
            "--goal",
            "Run a bounded safe research loop",
            "--database-url",
            f"sqlite:///{database_path.as_posix()}",
            "--max-steps",
            "6",
            "--receipt-output",
            str(receipt_path),
        ]
    )
    capsys.readouterr()

    exit_code = cli_main(
        [
            "agent-status",
            "--database-url",
            f"sqlite:///{database_path.as_posix()}",
            "--resume-from",
            str(receipt_path),
        ]
    )

    captured = capsys.readouterr()
    assert exit_code == 0
    assert "mythos agent status" in captured.out
    assert "status: awaiting_human_review" in captured.out
    assert "pending_approval_count: 1" in captured.out
    assert "awaiting_validation_count: 1" in captured.out
    assert "next_actions: review_validation_queue" in captured.out
    assert "create_campaign" not in captured.out


def test_agent_gates_lists_reviewable_approval_and_validation_details(tmp_path):
    repo, scope = write_authorized_repo(tmp_path)
    repository, session = build_repository()
    try:
        result = run_agent_goal(
            AgentGoal(
                goal="Run a bounded safe research loop",
                repo_path=repo,
                scope_path=scope,
                max_steps=6,
            ),
            repository=repository,
        )

        gates = get_agent_gates(campaign_id=result.campaign_id, repository=repository)

        assert len(gates.approvals) == 1
        assert len(gates.validation_runs) == 1
        approval = gates.approvals[0]
        validation_run = gates.validation_runs[0]
        assert approval["id"].startswith("approval_")
        assert approval["status"] == "pending"
        assert approval["validation_mode"] == "two_account_authorization_check"
        assert approval["plan_digest"] == validation_run["plan_digest"]
        assert validation_run["id"].startswith("validation_run_")
        assert validation_run["status"] == "awaiting_approval"
        assert validation_run["target_ref"]
        assert validation_run["execution_allowed"] is False
        assert gates.to_dict()["execution_allowed"] is False
    finally:
        session.close()


def test_agent_review_note_records_human_note_without_approving_gate(tmp_path):
    repo, scope = write_authorized_repo(tmp_path)
    repository, session = build_repository()
    try:
        result = run_agent_goal(
            AgentGoal(
                goal="Run a bounded safe research loop",
                repo_path=repo,
                scope_path=scope,
                max_steps=6,
            ),
            repository=repository,
        )
        gates = get_agent_gates(campaign_id=result.campaign_id, repository=repository)
        gate_ref = f"approval:{gates.approvals[0]['id']}"

        note = record_agent_review_note(
            campaign_id=result.campaign_id,
            gate_ref=gate_ref,
            reviewer="lead_reviewer",
            decision="needs_evidence",
            note="Need sanitized role matrix before approval.",
            repository=repository,
        )

        stages = repository.list_campaign_pipeline_stages(result.campaign_id)
        approvals = repository.list_campaign_approval_records(result.campaign_id)
        validation_runs = repository.list_campaign_validation_runs(result.campaign_id)
        assert note.status == "recorded"
        assert note.execution_allowed is False
        assert note.approval_allowed is False
        assert note.stage_id in {stage.id for stage in stages}
        assert any(
            stage.stage_key == "agent_gate_review_note"
            and stage.input_refs == [gate_ref]
            and stage.safety_gate_state == "human_review_recorded"
            and stage.payload["decision"] == "needs_evidence"
            and stage.payload["execution_allowed"] is False
            and stage.payload["approval_allowed"] is False
            for stage in stages
        )
        assert all(approval.status == "pending" for approval in approvals)
        assert all(run.allowed_to_execute is False for run in validation_runs)
    finally:
        session.close()


def test_agent_gates_summarizes_existing_review_notes(tmp_path):
    repo, scope = write_authorized_repo(tmp_path)
    repository, session = build_repository()
    try:
        result = run_agent_goal(
            AgentGoal(
                goal="Run a bounded safe research loop",
                repo_path=repo,
                scope_path=scope,
                max_steps=6,
            ),
            repository=repository,
        )
        gates = get_agent_gates(campaign_id=result.campaign_id, repository=repository)
        gate_ref = f"approval:{gates.approvals[0]['id']}"
        record_agent_review_note(
            campaign_id=result.campaign_id,
            gate_ref=gate_ref,
            reviewer="lead_reviewer",
            decision="needs_evidence",
            note="Need sanitized role matrix before approval.",
            repository=repository,
        )
        second_note = record_agent_review_note(
            campaign_id=result.campaign_id,
            gate_ref=gate_ref,
            reviewer="security_owner",
            decision="ready_for_approval_review",
            note="Sanitized evidence is attached.",
            repository=repository,
        )

        updated_gates = get_agent_gates(campaign_id=result.campaign_id, repository=repository)

        approval = updated_gates.approvals[0]
        assert approval["review_note_count"] == 2
        assert approval["latest_review_note"] == {
            "stage_id": second_note.stage_id,
            "reviewer": "security_owner",
            "decision": "ready_for_approval_review",
        }
        assert "Sanitized evidence is attached." not in json.dumps(updated_gates.to_dict())
        approvals = repository.list_campaign_approval_records(result.campaign_id)
        validation_runs = repository.list_campaign_validation_runs(result.campaign_id)
        assert all(approval_record.status == "pending" for approval_record in approvals)
        assert all(run.allowed_to_execute is False for run in validation_runs)
    finally:
        session.close()


def test_agent_next_recommends_review_note_for_unreviewed_gate(tmp_path):
    repo, scope = write_authorized_repo(tmp_path)
    repository, session = build_repository()
    try:
        result = run_agent_goal(
            AgentGoal(
                goal="Run a bounded safe research loop",
                repo_path=repo,
                scope_path=scope,
                max_steps=6,
            ),
            repository=repository,
        )
        gates = get_agent_gates(campaign_id=result.campaign_id, repository=repository)
        approval_id = gates.approvals[0]["id"]

        next_step = get_agent_next(
            campaign_id=result.campaign_id,
            repository=repository,
            goal=result.goal,
            repo_path=result.repo_path,
            scope_path=result.scope_path,
        )

        assert next_step.status == "awaiting_human_review"
        assert next_step.execution_allowed is False
        assert next_step.approval_allowed is False
        assert next_step.actions[0]["action"] == "inspect_gates"
        assert next_step.actions[1] == {
            "action": "write_review_note",
            "gate_ref": f"approval:{approval_id}",
            "reason": "gate_has_no_review_note",
        }
        approvals = repository.list_campaign_approval_records(result.campaign_id)
        validation_runs = repository.list_campaign_validation_runs(result.campaign_id)
        assert all(approval.status == "pending" for approval in approvals)
        assert all(run.allowed_to_execute is False for run in validation_runs)
    finally:
        session.close()


def test_agent_next_recommends_evidence_review_after_gate_note(tmp_path):
    repo, scope = write_authorized_repo(tmp_path)
    repository, session = build_repository()
    try:
        result = run_agent_goal(
            AgentGoal(
                goal="Run a bounded safe research loop",
                repo_path=repo,
                scope_path=scope,
                max_steps=6,
            ),
            repository=repository,
        )
        gates = get_agent_gates(campaign_id=result.campaign_id, repository=repository)
        gate_ref = f"approval:{gates.approvals[0]['id']}"
        record_agent_review_note(
            campaign_id=result.campaign_id,
            gate_ref=gate_ref,
            reviewer="lead_reviewer",
            decision="needs_evidence",
            note="Need sanitized role matrix before approval.",
            repository=repository,
        )

        next_step = get_agent_next(
            campaign_id=result.campaign_id,
            repository=repository,
            goal=result.goal,
            repo_path=result.repo_path,
            scope_path=result.scope_path,
        )

        assert next_step.actions[0]["action"] == "inspect_gates"
        assert next_step.actions[1] == {
            "action": "collect_redacted_evidence",
            "gate_ref": gate_ref,
            "reason": "latest_review_decision_needs_evidence",
        }
        assert "Need sanitized role matrix before approval." not in json.dumps(
            next_step.to_dict()
        )
    finally:
        session.close()


def test_cli_agent_gates_reads_receipt_and_prints_gate_ids(tmp_path, capsys):
    repo, scope = write_authorized_repo(tmp_path)
    database_path = tmp_path / "agent.sqlite"
    receipt_path = tmp_path / "agent-receipt.json"

    cli_main(
        [
            "agent",
            "--repo",
            str(repo),
            "--scope",
            str(scope),
            "--goal",
            "Run a bounded safe research loop",
            "--database-url",
            f"sqlite:///{database_path.as_posix()}",
            "--max-steps",
            "6",
            "--receipt-output",
            str(receipt_path),
        ]
    )
    capsys.readouterr()

    exit_code = cli_main(
        [
            "agent-gates",
            "--database-url",
            f"sqlite:///{database_path.as_posix()}",
            "--resume-from",
            str(receipt_path),
        ]
    )

    captured = capsys.readouterr()
    assert exit_code == 0
    assert "mythos agent gates" in captured.out
    assert "approval_" in captured.out
    assert "validation_run_" in captured.out
    assert "two_account_authorization_check" in captured.out
    assert "execution_allowed: false" in captured.out


def test_cli_agent_review_note_records_note_from_receipt(tmp_path, capsys):
    repo, scope = write_authorized_repo(tmp_path)
    database_path = tmp_path / "agent.sqlite"
    receipt_path = tmp_path / "agent-receipt.json"

    cli_main(
        [
            "agent",
            "--repo",
            str(repo),
            "--scope",
            str(scope),
            "--goal",
            "Run a bounded safe research loop",
            "--database-url",
            f"sqlite:///{database_path.as_posix()}",
            "--max-steps",
            "6",
            "--receipt-output",
            str(receipt_path),
        ]
    )
    capsys.readouterr()
    gates_exit_code = cli_main(
        [
            "agent-gates",
            "--database-url",
            f"sqlite:///{database_path.as_posix()}",
            "--resume-from",
            str(receipt_path),
        ]
    )
    gates_output = capsys.readouterr().out
    approval_id = next(
        line.split("id: ", 1)[1].split(";", 1)[0]
        for line in gates_output.splitlines()
        if "approval_" in line
    )

    exit_code = cli_main(
        [
            "agent-review-note",
            "--database-url",
            f"sqlite:///{database_path.as_posix()}",
            "--resume-from",
            str(receipt_path),
            "--gate-ref",
            f"approval:{approval_id}",
            "--reviewer",
            "lead_reviewer",
            "--decision",
            "needs_evidence",
            "--note",
            "Need sanitized role matrix before approval.",
        ]
    )

    captured = capsys.readouterr()
    assert gates_exit_code == 0
    assert exit_code == 0
    assert "mythos agent review note" in captured.out
    assert "status: recorded" in captured.out
    assert f"gate_ref: approval:{approval_id}" in captured.out
    assert "execution_allowed: false" in captured.out
    assert "approval_allowed: false" in captured.out


def test_cli_agent_gates_shows_review_note_summary_without_note_body(tmp_path, capsys):
    repo, scope = write_authorized_repo(tmp_path)
    database_path = tmp_path / "agent.sqlite"
    receipt_path = tmp_path / "agent-receipt.json"

    cli_main(
        [
            "agent",
            "--repo",
            str(repo),
            "--scope",
            str(scope),
            "--goal",
            "Run a bounded safe research loop",
            "--database-url",
            f"sqlite:///{database_path.as_posix()}",
            "--max-steps",
            "6",
            "--receipt-output",
            str(receipt_path),
        ]
    )
    capsys.readouterr()
    cli_main(
        [
            "agent-gates",
            "--database-url",
            f"sqlite:///{database_path.as_posix()}",
            "--resume-from",
            str(receipt_path),
        ]
    )
    gates_output = capsys.readouterr().out
    approval_id = next(
        line.split("id: ", 1)[1].split(";", 1)[0]
        for line in gates_output.splitlines()
        if "approval_" in line
    )
    cli_main(
        [
            "agent-review-note",
            "--database-url",
            f"sqlite:///{database_path.as_posix()}",
            "--resume-from",
            str(receipt_path),
            "--gate-ref",
            f"approval:{approval_id}",
            "--reviewer",
            "lead_reviewer",
            "--decision",
            "needs_evidence",
            "--note",
            "Need sanitized role matrix before approval.",
        ]
    )
    capsys.readouterr()

    exit_code = cli_main(
        [
            "agent-gates",
            "--database-url",
            f"sqlite:///{database_path.as_posix()}",
            "--resume-from",
            str(receipt_path),
        ]
    )

    captured = capsys.readouterr()
    assert exit_code == 0
    assert "review_note_count: 1" in captured.out
    assert "latest_review_decision: needs_evidence" in captured.out
    assert "latest_review_reviewer: lead_reviewer" in captured.out
    assert "Need sanitized role matrix before approval." not in captured.out


def test_cli_agent_next_reads_receipt_and_prints_recommendations(tmp_path, capsys):
    repo, scope = write_authorized_repo(tmp_path)
    database_path = tmp_path / "agent.sqlite"
    receipt_path = tmp_path / "agent-receipt.json"

    cli_main(
        [
            "agent",
            "--repo",
            str(repo),
            "--scope",
            str(scope),
            "--goal",
            "Run a bounded safe research loop",
            "--database-url",
            f"sqlite:///{database_path.as_posix()}",
            "--max-steps",
            "6",
            "--receipt-output",
            str(receipt_path),
        ]
    )
    capsys.readouterr()

    exit_code = cli_main(
        [
            "agent-next",
            "--database-url",
            f"sqlite:///{database_path.as_posix()}",
            "--resume-from",
            str(receipt_path),
        ]
    )

    captured = capsys.readouterr()
    assert exit_code == 0
    assert "mythos agent next" in captured.out
    assert "status: awaiting_human_review" in captured.out
    assert "execution_allowed: false" in captured.out
    assert "approval_allowed: false" in captured.out
    assert "recommended_actions:" in captured.out
    assert "inspect_gates" in captured.out
    assert "write_review_note" in captured.out
    assert "approval_" in captured.out
