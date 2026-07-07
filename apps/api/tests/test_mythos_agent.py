from pathlib import Path
import json

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.cli import main as cli_main
from app.db import Base
from app.mythos_agent import AgentGoal, run_agent_goal
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
