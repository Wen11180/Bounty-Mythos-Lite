from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.db import create_tables
from app.deep_research import build_knowledge_artifact
from app.mythos_agent import AgentGoal, run_agent_goal
from app.mythos_chat import run_terminal_chat
from app.repository import DatabaseRepository
from app.source_audit import (
    SourceAuditBlocked,
    run_source_audit,
    save_source_audit_pipeline_run,
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="aegis")
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan = subparsers.add_parser("scan")
    scan.add_argument("--repo", required=True)
    scan.add_argument("--scope", required=True)
    scan.add_argument("--output")
    scan.add_argument("--findings-output")
    scan.add_argument("--audit-log")
    scan.add_argument("--crs-plan-output")
    scan.add_argument("--v2-plan-output")
    scan.add_argument("--v3-plan-output")
    scan.add_argument("--v4-plan-output")
    scan.add_argument("--knowledge-output")
    scan.add_argument("--patch-diff-metadata")
    scan.add_argument("--pipeline-db")
    scan.add_argument("--pipeline-run-output")
    subparsers.add_parser("chat")
    agent = subparsers.add_parser("agent")
    agent.add_argument("--repo", required=True)
    agent.add_argument("--scope", required=True)
    agent.add_argument("--goal", required=True)
    agent.add_argument("--database-url", required=True)
    agent.add_argument("--campaign-id")
    agent.add_argument("--max-steps", type=int, default=6)

    args = parser.parse_args(argv)
    if args.command == "chat":
        return run_terminal_chat()
    if args.command == "agent":
        return run_agent_command(args)
    if args.command != "scan":
        parser.error("unsupported command")
    if args.pipeline_run_output and not args.pipeline_db:
        parser.error("--pipeline-run-output requires --pipeline-db")

    try:
        result = run_source_audit(
            args.repo,
            args.scope,
            patch_diff_metadata=_read_json_metadata(args.patch_diff_metadata),
        )
    except SourceAuditBlocked as error:
        print(f"source audit blocked: {error}", file=sys.stderr)
        return 2

    if args.output:
        Path(args.output).write_text(result.report_markdown, encoding="utf-8")
    else:
        print(result.report_markdown)
    if args.findings_output:
        Path(args.findings_output).write_text(
            json.dumps(result.finding_json, indent=2),
            encoding="utf-8",
        )
    if args.audit_log:
        Path(args.audit_log).write_text(
            json.dumps(result.audit_log, indent=2),
            encoding="utf-8",
        )
    if args.crs_plan_output:
        Path(args.crs_plan_output).write_text(
            json.dumps(result.crs_fuzzing.to_dict(), indent=2),
            encoding="utf-8",
        )
    if args.v2_plan_output:
        Path(args.v2_plan_output).write_text(
            json.dumps(result.authorized_bug_bounty.to_dict(), indent=2),
            encoding="utf-8",
        )
    if args.v3_plan_output:
        Path(args.v3_plan_output).write_text(
            json.dumps(result.industrial_scheduler.to_dict(), indent=2),
            encoding="utf-8",
        )
    if args.v4_plan_output:
        Path(args.v4_plan_output).write_text(
            json.dumps(result.deep_research.to_dict(), indent=2),
            encoding="utf-8",
        )
    if args.knowledge_output:
        Path(args.knowledge_output).write_text(
            json.dumps(build_knowledge_artifact(result.deep_research).to_dict(), indent=2),
            encoding="utf-8",
        )
    if args.pipeline_db:
        run = persist_source_audit_pipeline_run(
            database_url=args.pipeline_db,
            scope_path=args.scope,
            result=result,
        )
        if args.pipeline_run_output:
            Path(args.pipeline_run_output).write_text(
                json.dumps(
                    _build_pipeline_run_receipt(args=args, run=run),
                    indent=2,
                ),
                encoding="utf-8",
            )
    return 0


def run_agent_command(args) -> int:
    engine = create_engine(args.database_url, **_engine_kwargs(args.database_url))
    create_tables(engine)
    SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
    with SessionLocal() as session:
        result = run_agent_goal(
            AgentGoal(
                goal=args.goal,
                repo_path=Path(args.repo),
                scope_path=Path(args.scope),
                campaign_id=args.campaign_id,
                max_steps=args.max_steps,
            ),
            repository=DatabaseRepository(session),
        )
    print(result.to_text())
    return 0


def persist_source_audit_pipeline_run(*, database_url: str, scope_path: str, result):
    engine = create_engine(database_url, **_engine_kwargs(database_url))
    create_tables(engine)
    SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
    with SessionLocal() as session:
        repository = DatabaseRepository(session)
        return save_source_audit_pipeline_run(
            repository=repository,
            result=result,
            policy_text=_read_policy_text(scope_path),
        )


def _engine_kwargs(database_url: str) -> dict:
    if database_url.startswith("sqlite"):
        return {"connect_args": {"check_same_thread": False}}
    return {}


def _read_policy_text(scope_path: str) -> str:
    try:
        return Path(scope_path).read_text(encoding="utf-8-sig")
    except OSError:
        return "source audit scope policy unavailable"


def _read_json_metadata(path: str | None) -> dict | None:
    if path is None:
        return None
    data = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    return data if isinstance(data, dict) else {}


def _build_pipeline_run_receipt(*, args, run) -> dict:
    written_outputs = {
        key: value
        for key, value in {
            "report": args.output,
            "findings": args.findings_output,
            "audit_log": args.audit_log,
            "crs_plan": args.crs_plan_output,
            "v2_plan": args.v2_plan_output,
            "v3_plan": args.v3_plan_output,
            "v4_plan": args.v4_plan_output,
            "knowledge": args.knowledge_output,
        }.items()
        if value
    }
    timeline = run.payload.get("timeline", [])
    timeline_stages = []
    for stage in timeline if isinstance(timeline, list) else []:
        if not isinstance(stage, dict):
            continue
        boundary = (
            stage.get("details", {})
            .get("agent_boundary", {})
            if isinstance(stage.get("details"), dict)
            else {}
        )
        timeline_stages.append(
            {
                "name": stage.get("name"),
                "status": stage.get("status"),
                "execution_allowed": boundary.get("execution_allowed", False),
                "human_review_required": boundary.get(
                    "requires_human_review",
                    False,
                ),
            }
        )
    return {
        "run_id": run.id,
        "written_outputs": written_outputs,
        "safety_gate_summary": {
            "scope_guard_required": True,
            "execution_allowed": False,
            "human_review_required": bool(
                run.payload.get("report_draft", {}).get("human_review_required", True)
            ),
            "auto_submit_allowed": bool(
                run.payload.get("report_draft", {}).get("auto_submit_allowed", False)
            ),
        },
        "audit_gate_summary": run.payload.get("audit_gate_summary", {}),
        "timeline_stages": timeline_stages,
    }


if __name__ == "__main__":
    raise SystemExit(main())
