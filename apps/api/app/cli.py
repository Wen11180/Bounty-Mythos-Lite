from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.db import ensure_database_schema
from app.deep_research import build_knowledge_artifact
from app.intelligence_benchmark import (
    build_studio_expectations_template,
    evaluate_candidate_hunter_release_v1,
    evaluate_studio_candidates,
)
from app.mythos_agent import (
    AgentGoal,
    get_agent_gates,
    get_agent_next,
    get_agent_status,
    record_agent_review_note,
    run_agent_goal,
)
from app.mythos_chat import run_terminal_chat
from app.repository import DatabaseRepository
from app.black_box_hunter.browser_demo_intake import (
    run_browser_demo_local_lab_pipeline,
    run_browser_demo_plan_only_pipeline,
)
from app.black_box_hunter.local_lab_pipeline import run_har_local_lab_pipeline
from app.intelligence_benchmark.black_box_har_golden import (
    BlackBoxHarGoldenError,
    default_fixture_root,
    run_all_har_golden_packages,
    run_har_golden_package,
)
from app.intelligence_benchmark.black_box_leadership_gate import (
    BlackBoxLeadershipGateError,
    run_black_box_leadership_gate,
)
from app.intelligence_benchmark.ab_leadership_gate import (
    AbLeadershipGateError,
    run_ab_leadership_gate,
)
from app.intelligence_benchmark.human_hour_scorecard import (
    HumanHourScorecardError,
    run_human_hour_scorecard,
)
from app.intelligence_benchmark.human_hour_calibration import (
    HumanHourCalibrationError,
    run_human_hour_calibration_gate,
)
from app.intelligence_benchmark.lab_leadership_rollup import (
    LabLeadershipRollupError,
    run_lab_leadership_rollup,
)
from app.intelligence_benchmark.authorized_live_calibration import (
    AuthorizedLiveCalibrationError,
    run_authorized_live_calibration_gate,
)
from app.intelligence_benchmark.multilang_production_breadth import (
    run_multilang_production_breadth_gate,
)
from app.intelligence_benchmark.authorized_research_track_record_export import (
    TrackRecordExportError,
    build_demo_session_notes,
    export_research_track_record,
)
from app.intelligence_benchmark.commercial_delivery_bundle import (
    build_commercial_delivery_bundle,
    evaluate_anti_auto_exploit_narrative,
)
from app.intelligence_benchmark.capture_research_session_track_record import (
    CaptureResearchSessionError,
    capture_research_session_track_record,
)
from app.intelligence_benchmark.prepare_research_session_package import (
    PrepareResearchSessionError,
    prepare_research_session_package,
)
from app.intelligence_benchmark.track_record_path_resolver import (
    resolve_attached_track_record_paths,
)
from app.intelligence_benchmark.corpus_provenance import (
    CAPABILITY_LEVELS,
    audit_candidate_hunter_corpus,
    capability_level_meets,
)
from app.black_box_hunter.remote_observe_gate import (
    run_browser_demo_remote_fail_closed_pipeline,
    run_har_remote_fail_closed_pipeline,
)
from app.black_box_hunter.studio_trace_intake import (
    run_studio_trace_local_lab_pipeline,
    run_studio_trace_plan_only_pipeline,
)
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
    agent.add_argument("--repo")
    agent.add_argument("--scope")
    agent.add_argument("--goal")
    agent.add_argument("--database-url", required=True)
    agent.add_argument("--campaign-id")
    agent.add_argument("--max-steps", type=int, default=6)
    agent.add_argument("--receipt-output")
    agent.add_argument("--resume-from")
    status = subparsers.add_parser("agent-status")
    status.add_argument("--database-url", required=True)
    status.add_argument("--campaign-id")
    status.add_argument("--resume-from")
    next_step = subparsers.add_parser("agent-next")
    next_step.add_argument("--database-url", required=True)
    next_step.add_argument("--campaign-id")
    next_step.add_argument("--resume-from")
    gates = subparsers.add_parser("agent-gates")
    gates.add_argument("--database-url", required=True)
    gates.add_argument("--campaign-id")
    gates.add_argument("--resume-from")
    review_note = subparsers.add_parser("agent-review-note")
    review_note.add_argument("--database-url", required=True)
    review_note.add_argument("--campaign-id")
    review_note.add_argument("--resume-from")
    review_note.add_argument("--gate-ref", required=True)
    review_note.add_argument("--reviewer", required=True)
    review_note.add_argument("--decision", required=True)
    review_note.add_argument("--note", required=True)
    studio_eval = subparsers.add_parser("studio-eval")
    studio_eval.add_argument("--candidates", required=True)
    studio_eval.add_argument("--expectations", required=True)
    studio_eval.add_argument("--output")
    studio_eval_template = subparsers.add_parser("studio-eval-template")
    studio_eval_template.add_argument("--candidates", required=True)
    studio_eval_template.add_argument("--output")
    candidate_hunter_release_eval = subparsers.add_parser(
        "candidate-hunter-release-eval"
    )
    candidate_hunter_release_eval.add_argument("--hunter-output", required=True)
    candidate_hunter_release_eval.add_argument("--gold", required=True)
    candidate_hunter_release_eval.add_argument("--output")
    candidate_hunter_corpus_audit = subparsers.add_parser(
        "candidate-hunter-corpus-audit"
    )
    candidate_hunter_corpus_audit.add_argument("--fixture-root", required=True)
    candidate_hunter_corpus_audit.add_argument(
        "--require-level",
        choices=CAPABILITY_LEVELS,
        default="lab",
    )
    candidate_hunter_corpus_audit.add_argument("--output")
    black_box_lab = subparsers.add_parser(
        "black-box-lab",
        help="Run dual-role HAR through local-lab observation only (no remote).",
    )
    black_box_lab.add_argument("--har-a", required=True, help="Role A HAR JSON path")
    black_box_lab.add_argument("--har-b", required=True, help="Role B HAR JSON path")
    black_box_lab.add_argument(
        "--mode",
        default="bola",
        choices=["bola", "guarded", "shared", "expired_session", "unstable"],
        help="Synthetic local lab behavior mode",
    )
    black_box_lab.add_argument("--out", required=True, help="Safe JSON result path")
    black_box_lab.add_argument(
        "--trial-class",
        default="cross_account_object_swap",
        help="Differential trial class to observe (default: cross_account_object_swap)",
    )
    black_box_lab.add_argument(
        "--role-a-alias",
        default="member",
        help="Display role alias for HAR A (default: member)",
    )
    black_box_lab.add_argument(
        "--role-b-alias",
        default="viewer",
        help="Display role alias for HAR B (default: viewer)",
    )
    black_box_lab.add_argument(
        "--role-a-rank",
        type=int,
        default=10,
        help="Privilege rank for role A (default: 10)",
    )
    black_box_lab.add_argument(
        "--role-b-rank",
        type=int,
        default=1,
        help="Privilege rank for role B (default: 1)",
    )
    black_box_lab.add_argument(
        "--account-a",
        default="account_a",
        help="Account alias bound to HAR A (local lab requires account_a)",
    )
    black_box_lab.add_argument(
        "--account-b",
        default="account_b",
        help="Account alias bound to HAR B (local lab requires account_b)",
    )
    black_box_golden = subparsers.add_parser(
        "black-box-golden",
        help="Run dual-role HAR golden packages through local-lab quality gate.",
    )
    black_box_golden.add_argument(
        "--package",
        help="Path to one golden package directory containing manifest.json",
    )
    black_box_golden.add_argument(
        "--all",
        action="store_true",
        help="Run every package under the golden fixture root",
    )
    black_box_golden.add_argument(
        "--root",
        help="Golden fixture root (default: tests/fixtures/black_box_har_golden)",
    )
    black_box_golden.add_argument(
        "--out",
        help="Safe JSON result path for a single --package run",
    )
    black_box_golden.add_argument(
        "--out-dir",
        help="Directory for per-package JSON when using --all",
    )
    black_box_leadership = subparsers.add_parser(
        "black-box-leadership-gate",
        help="Run golden + dual-intake iso leadership metrics for the black-box lab slice.",
    )
    black_box_leadership.add_argument(
        "--root",
        help="Golden fixture root (default: tests/fixtures/black_box_har_golden)",
    )
    black_box_leadership.add_argument(
        "--out",
        required=True,
        help="Safe JSON leadership summary path",
    )
    ab_leadership = subparsers.add_parser(
        "ab-leadership-gate",
        help="Run A+B falsification leadership metrics on synthetic hard scenarios.",
    )
    ab_leadership.add_argument(
        "--out",
        required=True,
        help="Safe JSON A+B leadership summary path",
    )
    human_hour = subparsers.add_parser(
        "human-hour-scorecard",
        help="Run authorized-lab human-hour quality proxies (synthetic A+B corpus only).",
    )
    human_hour.add_argument(
        "--out",
        required=True,
        help="Safe JSON human-hour scorecard path",
    )
    human_hour.add_argument(
        "--simulated-hours",
        type=float,
        default=1.0,
        help="Simulated human research hour budget for density proxy (default 1.0).",
    )
    human_hour_cal = subparsers.add_parser(
        "human-hour-calibration",
        help="Calibrate redacted authorized review minutes against lab human-hour proxies.",
    )
    human_hour_cal.add_argument(
        "--out",
        required=True,
        help="Safe JSON calibration summary path",
    )
    human_hour_cal.add_argument(
        "--log",
        help="Optional redacted review-log JSON path (default: synthetic fixture)",
    )
    live_cal = subparsers.add_parser(
        "authorized-live-calibration",
        help="Authorized live track-record calibration (human-confirmed, no auto-attack).",
    )
    live_cal.add_argument(
        "--out",
        required=True,
        help="Safe JSON authorized live calibration summary path",
    )
    live_cal.add_argument(
        "--log",
        help="Optional redacted authorized live outcome log JSON/JSONL path",
    )
    delivery = subparsers.add_parser(
        "delivery-readiness",
        help="Run lab leadership rollup + live-infra gate for commercial delivery checklist.",
    )
    delivery.add_argument(
        "--out",
        required=True,
        help="Safe JSON delivery readiness summary path",
    )
    delivery.add_argument(
        "--log",
        help="Optional redacted human-hour review log path for calibration component",
    )
    delivery.add_argument(
        "--live-log",
        help="Optional redacted authorized live outcome log path",
    )
    lab_rollup = subparsers.add_parser(
        "lab-leadership-rollup",
        help="Aggregate black-box + A+B + human-hour lab leadership gates (lab claim only).",
    )
    lab_rollup.add_argument(
        "--out",
        required=True,
        help="Safe JSON lab leadership rollup path",
    )
    lab_rollup.add_argument(
        "--root",
        help="Optional black-box golden fixture root",
    )
    lab_rollup.add_argument(
        "--simulated-hours",
        type=float,
        default=1.0,
        help="Simulated human research hour budget for density proxy (default 1.0).",
    )
    lab_rollup.add_argument(
        "--log",
        help="Optional redacted review-log JSON path for calibration (default: synthetic fixture)",
    )
    multilang_breadth = subparsers.add_parser(
        "multilang-production-breadth",
        help="Run lab multilang language×pattern breadth gate (beyond held-outs).",
    )
    multilang_breadth.add_argument(
        "--out",
        required=True,
        help="Safe JSON multilang production breadth summary path",
    )
    market_scoreboard = subparsers.add_parser(
        "market-leadership-scoreboard",
        help="Aggregate remaining market-leadership gaps + attach protocol (honest claims only).",
    )
    market_scoreboard.add_argument(
        "--out",
        required=True,
        help="Safe JSON market leadership scoreboard path",
    )
    market_scoreboard.add_argument(
        "--log",
        help="Optional redacted human-hour review log path",
    )
    market_scoreboard.add_argument(
        "--live-log",
        help="Optional redacted authorized live outcome log path",
    )
    commercial_bundle = subparsers.add_parser(
        "commercial-delivery-bundle",
        help=(
            "Build customer-facing commercial delivery bundle + anti-auto-exploit "
            "proof (never unlocks attack/submit)."
        ),
    )
    commercial_bundle.add_argument(
        "--out-dir",
        required=True,
        help="Directory for commercial delivery artifacts",
    )
    commercial_bundle.add_argument(
        "--out",
        help="Optional manifest JSON path (defaults to out-dir/manifest.json)",
    )
    commercial_bundle.add_argument(
        "--log",
        help="Optional redacted human-hour review log path",
    )
    commercial_bundle.add_argument(
        "--live-log",
        help="Optional redacted authorized live outcome log path",
    )
    commercial_bundle.add_argument(
        "--human-allow-write",
        action="store_true",
        help="Explicit human gate required before writing bundle files",
    )
    export_track = subparsers.add_parser(
        "export-research-track-record",
        help=(
            "Export redacted live + human-hour packages from research-session "
            "approvals/notes/wall-clock (never auto-attacks or auto-submits)."
        ),
    )
    export_track.add_argument(
        "--out-dir",
        help="Directory to write live/HH export packages (requires --human-allow-export-write)",
    )
    export_track.add_argument(
        "--out",
        help="Optional manifest JSON path (defaults to out-dir manifest or stdout summary only)",
    )
    export_track.add_argument(
        "--session-notes",
        help="JSON file: list of session notes or {entries:[...]}",
    )
    export_track.add_argument(
        "--approvals",
        help="JSON file: approvals list or approvals bundle",
    )
    export_track.add_argument(
        "--package-root",
        help="Optional authorized package root with human-review approvals",
    )
    export_track.add_argument(
        "--wall-clock-json",
        help="Optional wall-clock multi-hour runner JSON export",
    )
    export_track.add_argument("--program-handle", default="research-session")
    export_track.add_argument("--package-id", default="")
    export_track.add_argument("--package-label", default="")
    export_track.add_argument("--program-authorization-id", default="")
    export_track.add_argument("--language-family", default="unknown")
    export_track.add_argument(
        "--evaluation-top-k",
        type=int,
        help="Optional K for operator-attested precision@K calculation",
    )
    export_track.add_argument(
        "--declare-real-package",
        action="store_true",
        help=(
            "Mark export as authorized_redacted_real (requires --program-authorization-id "
            "and non-synthetic/non-template inputs)"
        ),
    )
    export_track.add_argument(
        "--human-allow-export-write",
        action="store_true",
        help="Explicit human gate required before writing export files",
    )
    export_track.add_argument(
        "--demo",
        action="store_true",
        help="Use synthetic demo session notes (never flips has_real_*)",
    )
    capture_track = subparsers.add_parser(
        "capture-research-session-track-record",
        help=(
            "Discover package-root session notes/wall-clock/residual approvals, "
            "export live+HH packages, optionally re-score market "
            "(never auto-attacks or auto-submits)."
        ),
    )
    capture_track.add_argument(
        "--package-root",
        required=True,
        help="Authorized research package root to discover capture artifacts from",
    )
    capture_track.add_argument(
        "--out-dir",
        required=True,
        help="Directory to write export packages + capture_manifest.json",
    )
    capture_track.add_argument(
        "--out",
        help="Optional capture manifest JSON path (defaults to out-dir/capture_manifest.json)",
    )
    capture_track.add_argument(
        "--session-notes",
        help="Optional explicit session notes JSON (else discover under package-root)",
    )
    capture_track.add_argument(
        "--wall-clock-json",
        help="Optional explicit wall-clock runner JSON (else discover under package-root)",
    )
    capture_track.add_argument("--program-handle", default="")
    capture_track.add_argument("--package-id", default="")
    capture_track.add_argument("--package-label", default="")
    capture_track.add_argument("--program-authorization-id", default="")
    capture_track.add_argument("--language-family", default="unknown")
    capture_track.add_argument("--hypothesis-class", default="authorization")
    capture_track.add_argument("--vuln-family", default="idor")
    capture_track.add_argument(
        "--evaluation-top-k",
        type=int,
        help="Optional K for operator-attested precision@K calculation",
    )
    capture_track.add_argument(
        "--declare-real-package",
        action="store_true",
        help=(
            "Mark export as authorized_redacted_real (requires --program-authorization-id "
            "and non-synthetic/non-template inputs)"
        ),
    )
    capture_track.add_argument(
        "--human-allow-export-write",
        action="store_true",
        help="Explicit human gate required before writing capture/export files",
    )
    capture_track.add_argument(
        "--rescore-market",
        action="store_true",
        default=True,
        help="Re-score market with exported packages (default: on)",
    )
    capture_track.add_argument(
        "--no-rescore-market",
        action="store_true",
        help="Skip market re-score after export",
    )
    capture_track.add_argument(
        "--publish-drop-dir",
        action="store_true",
        help="Copy exports into authorized_track_records (or --drop-dir) for auto-attach",
    )
    capture_track.add_argument(
        "--drop-dir",
        help="Optional track-record drop directory (default: authorized_track_records)",
    )
    prepare_pkg = subparsers.add_parser(
        "prepare-research-session-package",
        help=(
            "Scaffold a research-session package root for capture "
            "(never fabricates real has_real_* outcomes)."
        ),
    )
    prepare_pkg.add_argument(
        "--package-root",
        required=True,
        help="Directory to create/scaffold as research package root",
    )
    prepare_pkg.add_argument("--program-handle", default="")
    prepare_pkg.add_argument("--program-authorization-id", default="")
    prepare_pkg.add_argument(
        "--no-synthetic-examples",
        action="store_true",
        help="Do not write example session_notes / wall_clock examples",
    )
    prepare_pkg.add_argument(
        "--human-allow-write",
        action="store_true",
        help="Explicit human gate required before writing package files",
    )
    prepare_pkg.add_argument(
        "--out",
        help="Optional prepare manifest JSON path",
    )
    black_box_demo = subparsers.add_parser(
        "black-box-demo",
        help="Run dual-session Browser Demo packages through plan-only or local-lab observe.",
    )
    black_box_demo.add_argument(
        "--demo-a",
        required=True,
        help="Role A browser-demo JSON package path",
    )
    black_box_demo.add_argument(
        "--demo-b",
        required=True,
        help="Role B browser-demo JSON package path",
    )
    black_box_demo.add_argument(
        "--mode",
        default="bola",
        choices=["bola", "guarded", "shared", "expired_session", "unstable"],
        help="Synthetic local lab behavior mode (ignored with --plan-only)",
    )
    black_box_demo.add_argument(
        "--plan-only",
        action="store_true",
        help="Emit plan-only candidates without local-lab observation",
    )
    black_box_demo.add_argument("--out", required=True, help="Safe JSON result path")
    black_box_demo.add_argument(
        "--trial-class",
        default="cross_account_object_swap",
        help="Differential trial class to observe (default: cross_account_object_swap)",
    )
    black_box_remote_gate = subparsers.add_parser(
        "black-box-remote-gate",
        help=(
            "Dual-intake plan-only + remote fail-closed gate "
            "(no HTTP; no real target required)."
        ),
    )
    black_box_remote_gate.add_argument("--har-a", help="Role A HAR JSON path")
    black_box_remote_gate.add_argument("--har-b", help="Role B HAR JSON path")
    black_box_remote_gate.add_argument(
        "--demo-a",
        help="Role A browser-demo JSON package path",
    )
    black_box_remote_gate.add_argument(
        "--demo-b",
        help="Role B browser-demo JSON package path",
    )
    black_box_remote_gate.add_argument("--out", required=True, help="Safe JSON result path")
    black_box_remote_gate.add_argument(
        "--account-a",
        default="account_a",
        help="Account alias for role A (HAR path; default account_a)",
    )
    black_box_remote_gate.add_argument(
        "--account-b",
        default="account_b",
        help="Account alias for role B (HAR path; default account_b)",
    )
    black_box_studio = subparsers.add_parser(
        "black-box-studio-traces",
        help=(
            "Run Studio Playwright recording export through plan-only "
            "or local-lab observe (no remote HTTP)."
        ),
    )
    black_box_studio.add_argument(
        "--recording",
        required=True,
        help="Studio recording export JSON (studio_recording_export_v1)",
    )
    black_box_studio.add_argument(
        "--mode",
        default="bola",
        choices=["bola", "guarded", "shared", "expired_session", "unstable"],
        help="Synthetic local lab behavior mode (ignored with --plan-only)",
    )
    black_box_studio.add_argument(
        "--plan-only",
        action="store_true",
        help="Emit plan-only candidates without local-lab observation",
    )
    black_box_studio.add_argument("--out", required=True, help="Safe JSON result path")
    black_box_studio.add_argument(
        "--trial-class",
        default="cross_account_object_swap",
        help="Differential trial class to observe (default: cross_account_object_swap)",
    )

    args = parser.parse_args(argv)
    if args.command == "chat":
        return run_terminal_chat()
    if args.command == "studio-eval":
        return run_studio_eval_command(args)
    if args.command == "studio-eval-template":
        return run_studio_eval_template_command(args)
    if args.command == "candidate-hunter-release-eval":
        return run_candidate_hunter_release_eval_command(args)
    if args.command == "candidate-hunter-corpus-audit":
        return run_candidate_hunter_corpus_audit_command(args)
    if args.command == "black-box-lab":
        return run_black_box_lab_command(args)
    if args.command == "black-box-golden":
        return run_black_box_golden_command(args)
    if args.command == "black-box-leadership-gate":
        return run_black_box_leadership_gate_command(args)
    if args.command == "ab-leadership-gate":
        return run_ab_leadership_gate_command(args)
    if args.command == "human-hour-scorecard":
        return run_human_hour_scorecard_command(args)
    if args.command == "human-hour-calibration":
        return run_human_hour_calibration_command(args)
    if args.command == "authorized-live-calibration":
        return run_authorized_live_calibration_command(args)
    if args.command == "delivery-readiness":
        return run_delivery_readiness_command(args)
    if args.command == "lab-leadership-rollup":
        return run_lab_leadership_rollup_command(args)
    if args.command == "multilang-production-breadth":
        return run_multilang_production_breadth_command(args)
    if args.command == "market-leadership-scoreboard":
        return run_market_leadership_scoreboard_command(args)
    if args.command == "commercial-delivery-bundle":
        return run_commercial_delivery_bundle_command(args)
    if args.command == "export-research-track-record":
        return run_export_research_track_record_command(args)
    if args.command == "capture-research-session-track-record":
        return run_capture_research_session_track_record_command(args)
    if args.command == "prepare-research-session-package":
        return run_prepare_research_session_package_command(args)
    if args.command == "black-box-demo":
        return run_black_box_demo_command(args)
    if args.command == "black-box-remote-gate":
        return run_black_box_remote_gate_command(args)
    if args.command == "black-box-studio-traces":
        return run_black_box_studio_traces_command(args)
    if args.command == "agent":
        return run_agent_command(args)
    if args.command == "agent-status":
        return run_agent_status_command(args)
    if args.command == "agent-next":
        return run_agent_next_command(args)
    if args.command == "agent-gates":
        return run_agent_gates_command(args)
    if args.command == "agent-review-note":
        return run_agent_review_note_command(args)
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


def run_agent_gates_command(args) -> int:
    resume = _read_agent_resume(args.resume_from)
    campaign_id = args.campaign_id or resume.get("campaign_id")
    engine = create_engine(args.database_url, **_engine_kwargs(args.database_url))
    ensure_database_schema(engine)
    SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
    with SessionLocal() as session:
        gates = get_agent_gates(
            campaign_id=campaign_id,
            repository=DatabaseRepository(session),
        )
    print(gates.to_text())
    return 0


def run_agent_next_command(args) -> int:
    resume = _read_agent_resume(args.resume_from)
    campaign_id = args.campaign_id or resume.get("campaign_id")
    engine = create_engine(args.database_url, **_engine_kwargs(args.database_url))
    ensure_database_schema(engine)
    SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
    with SessionLocal() as session:
        next_step = get_agent_next(
            campaign_id=campaign_id,
            repository=DatabaseRepository(session),
            goal=str(resume.get("goal", "")),
            repo_path=str(resume.get("repo_path", "")),
            scope_path=str(resume.get("scope_path", "")),
        )
    print(next_step.to_text())
    return 0


def run_agent_review_note_command(args) -> int:
    resume = _read_agent_resume(args.resume_from)
    campaign_id = args.campaign_id or resume.get("campaign_id")
    engine = create_engine(args.database_url, **_engine_kwargs(args.database_url))
    ensure_database_schema(engine)
    SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
    with SessionLocal() as session:
        review_note = record_agent_review_note(
            campaign_id=campaign_id,
            gate_ref=args.gate_ref,
            reviewer=args.reviewer,
            decision=args.decision,
            note=args.note,
            repository=DatabaseRepository(session),
        )
    print(review_note.to_text())
    return 0 if review_note.status == "recorded" else 2


def run_studio_eval_command(args) -> int:
    result = evaluate_studio_candidates(
        _read_json_file(args.candidates),
        _read_json_file(args.expectations),
    )
    result_json = json.dumps(result, indent=2)
    if args.output:
        Path(args.output).write_text(result_json, encoding="utf-8")
    else:
        print(result_json)
    if result["status"] == "passed":
        print("Studio benchmark passed")
        return 0
    print("Studio benchmark failed", file=sys.stderr)
    return 1


def run_studio_eval_template_command(args) -> int:
    template = build_studio_expectations_template(_read_json_file(args.candidates))
    template_json = json.dumps(template, indent=2)
    if args.output:
        Path(args.output).write_text(template_json, encoding="utf-8")
        print("Studio benchmark template written")
    else:
        print(template_json)
    return 0


def run_candidate_hunter_release_eval_command(args) -> int:
    result = evaluate_candidate_hunter_release_v1(
        _read_json_file(args.hunter_output),
        _read_json_file(args.gold),
    )
    result_json = json.dumps(result, indent=2)
    if args.output:
        Path(args.output).write_text(result_json, encoding="utf-8")
    else:
        print(result_json)
    if result["status"] == "passed":
        print("Candidate Hunter release benchmark passed")
        return 0
    print("Candidate Hunter release benchmark failed", file=sys.stderr)
    return 1


def run_candidate_hunter_corpus_audit_command(args) -> int:
    report = audit_candidate_hunter_corpus(args.fixture_root)
    requirement_met = (
        report["status"] == "passed"
        and capability_level_meets(report["proven_level"], args.require_level)
    )
    report = {
        **report,
        "required_level": args.require_level,
        "requirement_met": requirement_met,
    }
    report_json = json.dumps(report, indent=2)
    if args.output:
        Path(args.output).write_text(report_json, encoding="utf-8")
    else:
        print(report_json)
    if requirement_met:
        print("Candidate Hunter corpus audit passed", file=sys.stderr)
        return 0
    print("Candidate Hunter corpus audit failed", file=sys.stderr)
    return 1


def run_black_box_remote_gate_command(args) -> int:
    """Plan-only dual intake + remote fail-closed gate. Never sends HTTP."""
    has_har = bool(args.har_a or args.har_b)
    has_demo = bool(args.demo_a or args.demo_b)
    if has_har and has_demo:
        print(
            "black-box-remote-gate: provide either HAR pair or demo pair, not both",
            file=sys.stderr,
        )
        return 2
    if has_har and not (args.har_a and args.har_b):
        print("black-box-remote-gate: --har-a and --har-b are both required", file=sys.stderr)
        return 2
    if has_demo and not (args.demo_a and args.demo_b):
        print(
            "black-box-remote-gate: --demo-a and --demo-b are both required",
            file=sys.stderr,
        )
        return 2
    if not has_har and not has_demo:
        print(
            "black-box-remote-gate: provide --har-a/--har-b or --demo-a/--demo-b",
            file=sys.stderr,
        )
        return 2

    try:
        if has_har:
            har_a = _read_json_file(args.har_a)
            har_b = _read_json_file(args.har_b)
            if not isinstance(har_a, dict) or not isinstance(har_b, dict):
                print(
                    "black-box-remote-gate: HAR files must be JSON objects",
                    file=sys.stderr,
                )
                return 2
            result = run_har_remote_fail_closed_pipeline(
                {"role_a": har_a, "role_b": har_b},
                profile_enabled=False,
                account_aliases={
                    "role_a": args.account_a,
                    "role_b": args.account_b,
                },
                role_aliases={"role_a": "member", "role_b": "viewer"},
                role_ranks={"role_a": 10, "role_b": 1},
            )
        else:
            demo_a = _read_json_file(args.demo_a)
            demo_b = _read_json_file(args.demo_b)
            if not isinstance(demo_a, dict) or not isinstance(demo_b, dict):
                print(
                    "black-box-remote-gate: demo packages must be JSON objects",
                    file=sys.stderr,
                )
                return 2
            result = run_browser_demo_remote_fail_closed_pipeline(
                demo_a,
                demo_b,
                profile_enabled=False,
            )
    except (OSError, ValueError, json.JSONDecodeError, TypeError, KeyError) as error:
        print(f"black-box-remote-gate failed: {error}", file=sys.stderr)
        return 2

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(result, indent=2), encoding="utf-8")
    total = len(result.get("candidates") or [])
    print(
        f"black-box-remote-gate wrote {out_path} "
        f"(source={result.get('source')}, mode={result.get('mode')}, "
        f"candidates={total}, http_requests_attempted="
        f"{result.get('http_requests_attempted')}, "
        f"execution_allowed={result.get('execution_allowed')})"
    )
    return 0


def run_black_box_demo_command(args) -> int:
    """Dual-session Browser Demo packages -> plan-only or local-lab observe."""
    try:
        demo_a = _read_json_file(args.demo_a)
        demo_b = _read_json_file(args.demo_b)
        if not isinstance(demo_a, dict) or not isinstance(demo_b, dict):
            print(
                "black-box-demo: demo packages must be JSON objects",
                file=sys.stderr,
            )
            return 2
        if args.plan_only:
            result = run_browser_demo_plan_only_pipeline(demo_a, demo_b)
        else:
            result = run_browser_demo_local_lab_pipeline(
                demo_a,
                demo_b,
                mode=args.mode,
                local_lab=True,
                trial_classes={args.trial_class},
            )
    except (OSError, ValueError, json.JSONDecodeError, TypeError, KeyError) as error:
        print(f"black-box-demo failed: {error}", file=sys.stderr)
        return 2

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(result, indent=2), encoding="utf-8")
    retained = len(result.get("retained_candidates") or [])
    total = len(result.get("candidates") or [])
    mode_label = "plan_only" if args.plan_only else result.get("lab_mode")
    print(
        f"black-box-demo wrote {out_path} "
        f"(source=browser_demo, mode={mode_label}, retained={retained}/{total}, "
        f"execution_allowed={result.get('execution_allowed')})"
    )
    return 0


def run_black_box_studio_traces_command(args) -> int:
    """Studio recording export -> plan-only or local-lab observe. No remote HTTP."""
    try:
        export = _read_json_file(args.recording)
        if not isinstance(export, dict):
            print(
                "black-box-studio-traces: recording must be a JSON object",
                file=sys.stderr,
            )
            return 2
        if args.plan_only:
            result = run_studio_trace_plan_only_pipeline(export)
        else:
            result = run_studio_trace_local_lab_pipeline(
                export,
                mode=args.mode,
                local_lab=True,
                trial_classes={args.trial_class},
            )
    except (OSError, ValueError, json.JSONDecodeError, TypeError, KeyError) as error:
        print(f"black-box-studio-traces failed: {error}", file=sys.stderr)
        return 2

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(result, indent=2), encoding="utf-8")
    retained = len(result.get("retained_candidates") or [])
    total = len(result.get("candidates") or [])
    mode_label = "plan_only" if args.plan_only else result.get("lab_mode")
    print(
        f"black-box-studio-traces wrote {out_path} "
        f"(source=studio_playwright, mode={mode_label}, retained={retained}/{total}, "
        f"execution_allowed={result.get('execution_allowed')})"
    )
    return 0


def run_black_box_golden_command(args) -> int:
    try:
        if args.all and args.package:
            print(
                "black-box-golden: provide either --package or --all, not both",
                file=sys.stderr,
            )
            return 2
        if not args.all and not args.package:
            print(
                "black-box-golden: --package or --all is required",
                file=sys.stderr,
            )
            return 2

        root = Path(args.root) if args.root else default_fixture_root()
        if args.all:
            result = run_all_har_golden_packages(root)
            if args.out_dir:
                out_dir = Path(args.out_dir)
                out_dir.mkdir(parents=True, exist_ok=True)
                for item in result.get("results") or []:
                    package_id = str(item.get("package_id") or "package")
                    path = out_dir / f"{package_id}.json"
                    path.write_text(json.dumps(item, indent=2), encoding="utf-8")
                summary_path = out_dir / "gate-summary.json"
                summary_path.write_text(json.dumps(result, indent=2), encoding="utf-8")
                print(
                    f"black-box-golden wrote {summary_path} "
                    f"(passed={result.get('passed')}, "
                    f"failed={result.get('failed_packages')})"
                )
            elif args.out:
                out_path = Path(args.out)
                out_path.parent.mkdir(parents=True, exist_ok=True)
                out_path.write_text(json.dumps(result, indent=2), encoding="utf-8")
                print(
                    f"black-box-golden wrote {out_path} "
                    f"(passed={result.get('passed')}, "
                    f"failed={result.get('failed_packages')})"
                )
            else:
                print(
                    "black-box-golden: --out or --out-dir is required with --all",
                    file=sys.stderr,
                )
                return 2
            return 0 if result.get("passed") else 1

        if not args.out:
            print("black-box-golden: --out is required with --package", file=sys.stderr)
            return 2
        result = run_har_golden_package(Path(args.package))
        out_path = Path(args.out)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(result, indent=2), encoding="utf-8")
        gate_passed = bool(result.get("gate", {}).get("passed"))
        safe = bool(result.get("safety", {}).get("safe"))
        print(
            f"black-box-golden wrote {out_path} "
            f"(package={result.get('package_id')}, "
            f"gate_passed={gate_passed}, safe={safe})"
        )
        return 0 if gate_passed and safe else 1
    except (OSError, ValueError, json.JSONDecodeError, TypeError, KeyError, BlackBoxHarGoldenError) as error:
        print(f"black-box-golden failed: {error}", file=sys.stderr)
        return 2


def run_black_box_leadership_gate_command(args) -> int:
    try:
        root = Path(args.root) if args.root else default_fixture_root()
        result = run_black_box_leadership_gate(root)
        out_path = Path(args.out)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(result, indent=2), encoding="utf-8")
        metrics = result.get("metrics") or {}
        print(
            f"black-box-leadership-gate wrote {out_path} "
            f"(passed={result.get('passed')}, "
            f"packages={result.get('package_count')}, "
            f"golden={metrics.get('golden_pass_rate')}, "
            f"safety={metrics.get('safety_rate')}, "
            f"iso={metrics.get('iso_pass_rate')})"
        )
        return 0 if result.get("passed") else 1
    except (
        OSError,
        ValueError,
        json.JSONDecodeError,
        TypeError,
        KeyError,
        BlackBoxHarGoldenError,
        BlackBoxLeadershipGateError,
    ) as error:
        print(f"black-box-leadership-gate failed: {error}", file=sys.stderr)
        return 2




def run_ab_leadership_gate_command(args) -> int:
    try:
        result = run_ab_leadership_gate()
        out_path = Path(args.out)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(result, indent=2), encoding="utf-8")
        metrics = result.get("metrics") or {}
        print(
            f"ab-leadership-gate wrote {out_path} "
            f"(passed={result.get('passed')}, "
            f"scenarios={result.get('scenario_count')}, "
            f"falsify={metrics.get('falsify_coverage')}, "
            f"safety={metrics.get('safety_rate')})"
        )
        return 0 if result.get("passed") else 1
    except (
        OSError,
        ValueError,
        json.JSONDecodeError,
        TypeError,
        KeyError,
        AbLeadershipGateError,
    ) as error:
        print(f"ab-leadership-gate failed: {error}", file=sys.stderr)
        return 2


def run_human_hour_scorecard_command(args) -> int:
    try:
        result = run_human_hour_scorecard(
            simulated_human_hours=float(getattr(args, "simulated_hours", 1.0) or 1.0),
        )
        out_path = Path(args.out)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(result, indent=2), encoding="utf-8")
        metrics = result.get("metrics") or {}
        print(
            f"human-hour-scorecard wrote {out_path} "
            f"(passed={result.get('passed')}, "
            f"review_ready={result.get('review_ready_count')}, "
            f"per_hour={metrics.get('review_ready_per_sim_hour')}, "
            f"safety={metrics.get('safety_rate')})"
        )
        return 0 if result.get("passed") else 1
    except (
        OSError,
        ValueError,
        json.JSONDecodeError,
        TypeError,
        KeyError,
        HumanHourScorecardError,
        AbLeadershipGateError,
    ) as error:
        print(f"human-hour-scorecard failed: {error}", file=sys.stderr)
        return 2


def run_human_hour_calibration_command(args) -> int:
    try:
        log_path = Path(args.log) if getattr(args, "log", None) else None
        result = run_human_hour_calibration_gate(log_path=log_path)
        out_path = Path(args.out)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(result, indent=2), encoding="utf-8")
        metrics = result.get("metrics") or {}
        print(
            f"human-hour-calibration wrote {out_path} "
            f"(passed={result.get('passed')}, "
            f"entries={(result.get('measured') or {}).get('entry_count')}, "
            f"min_per_ready={metrics.get('minutes_per_review_ready')}, "
            f"safety={metrics.get('safety_rate')})"
        )
        return 0 if result.get("passed") else 1
    except (
        OSError,
        ValueError,
        json.JSONDecodeError,
        TypeError,
        KeyError,
        HumanHourCalibrationError,
        HumanHourScorecardError,
        AbLeadershipGateError,
    ) as error:
        print(f"human-hour-calibration failed: {error}", file=sys.stderr)
        return 2



def run_authorized_live_calibration_command(args) -> int:
    try:
        log_path = Path(args.log) if getattr(args, "log", None) else None
        result = run_authorized_live_calibration_gate(log_path=log_path)
        out_path = Path(args.out)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(result, indent=2), encoding="utf-8")
        metrics = result.get("metrics") or {}
        print(
            f"authorized-live-calibration wrote {out_path} "
            f"(passed={result.get('passed')}, "
            f"entries={(result.get('measured') or {}).get('entry_count')}, "
            f"safety={metrics.get('safety_rate')})"
        )
        return 0 if result.get("passed") else 1
    except (
        OSError,
        ValueError,
        json.JSONDecodeError,
        TypeError,
        KeyError,
        AuthorizedLiveCalibrationError,
    ) as error:
        print(f"authorized-live-calibration failed: {error}", file=sys.stderr)
        return 2


def run_delivery_readiness_command(args) -> int:
    """Commercial delivery readiness: lab rollup + live-infra + explicit non-claims."""
    try:
        from app.intelligence_benchmark.lab_leadership_rollup import (
            run_lab_leadership_rollup,
        )

        attached = resolve_attached_track_record_paths(
            live_log=getattr(args, "live_log", None),
            human_hour_log=getattr(args, "log", None),
        )
        cal_log = (
            Path(attached["human_hour_log"])
            if attached.get("human_hour_log")
            else None
        )
        live_log = (
            Path(attached["live_log"]) if attached.get("live_log") else None
        )
        lab = run_lab_leadership_rollup(calibration_log=cal_log)
        live = run_authorized_live_calibration_gate(log_path=live_log)
        breadth = run_multilang_production_breadth_gate()
        gaps: list[str] = []
        if not lab.get("passed"):
            gaps.append("lab_leadership_rollup")
        if not live.get("passed"):
            gaps.append("authorized_live_calibration_infra")
        if not breadth.get("passed"):
            gaps.append("multilang_production_breadth")

        ab = (lab.get("component_results") or {}).get("ab_leadership") or {}
        hh_comp = (lab.get("component_results") or {}).get("human_hour_calibration") or {}
        live_measured = live.get("measured") if isinstance(live.get("measured"), dict) else {}
        track = live_measured.get("track_record_summary") or {}
        has_real_live_wall = bool(track.get("has_real_wall_clock_logs"))
        has_real_hh_wall = bool(hh_comp.get("has_real_human_hour_wall_clock_logs"))
        has_real_wall = has_real_live_wall or has_real_hh_wall
        has_real_valid = bool(track.get("has_real_live_valid_report_outcomes"))
        breadth_beyond = bool(breadth.get("beyond_held_out") and breadth.get("passed"))

        # Honest commercial gaps: only drop when evidence truly closes them.
        remaining: list[str] = []
        if not has_real_wall:
            remaining.append("real_authorized_program_wall_clock_logs")
        if not has_real_valid:
            remaining.append("real_live_valid_report_outcomes")
        if not breadth_beyond:
            remaining.append("production_multilang_sast_breadth_beyond_held_outs")

        result = {
            "schema_version": "delivery_readiness_v1",
            "claim_scope": "lab_plus_live_infra_readiness",
            "passed": not gaps,
            "gaps": gaps,
            "remaining_for_full_market_leadership": remaining,
            "lab_passed": lab.get("passed"),
            "live_infra_passed": live.get("passed"),
            "multilang_breadth_passed": breadth.get("passed"),
            "lab_scenario_count": ab.get("scenario_count"),
            "progress": {
                "ab_scenario_count": ab.get("scenario_count"),
                "multilang_held_out_families": [
                    "java",
                    "go",
                    "rails",
                    "csharp",
                    "php",
                    "kotlin",
                    "rust",
                    "scala",
                    "typescript",
                    "python",
                ],
                "multilang_production_breadth": {
                    "passed": breadth.get("passed"),
                    "beyond_held_out": breadth.get("beyond_held_out"),
                    "languages_hit": breadth.get("languages_hit") or [],
                    "patterns_hit": breadth.get("patterns_hit") or [],
                    "cells_ok": breadth.get("cells_ok"),
                    "cells_total": breadth.get("cells_total"),
                    "metrics": breadth.get("metrics") or {},
                },
                "live_track_record_infra": {
                    "entry_count": live_measured.get("entry_count"),
                    "language_families": live_measured.get("language_families") or [],
                    "outcome_counts": (track.get("outcome_counts") or {}),
                    "wall_clock_entries": track.get("wall_clock_entries") or 0,
                    "has_real_wall_clock_logs": has_real_live_wall,
                    "has_real_live_valid_report_outcomes": has_real_valid,
                },
                "human_hour_real_signals": {
                    "has_real_human_hour_wall_clock_logs": has_real_hh_wall,
                    "source_kind": hh_comp.get("source_kind"),
                    "wall_clock_entry_count": hh_comp.get("wall_clock_entry_count") or 0,
                },
                "real_wall_clock_closed_by": (
                    "live_package"
                    if has_real_live_wall
                    else ("human_hour_package" if has_real_hh_wall else None)
                ),
                "commercial_package": {
                    "safety_gates_locked": True,
                    "execution_allowed": False,
                    "report_submission_allowed": False,
                    "auto_attack_allowed": False,
                    "anti_auto_exploit_positioned": True,
                    "attach_protocol_ready": True,
                    "runbook": "docs/product/commercial-delivery-runbook.md",
                    "scoreboard_commands": [
                        "lab-leadership-rollup",
                        "multilang-production-breadth",
                        "human-hour-calibration",
                        "authorized-live-calibration",
                        "delivery-readiness",
                        "market-leadership-scoreboard",
                        "export-research-track-record",
                        "capture-research-session-track-record",
                        "prepare-research-session-package",
                        "commercial-delivery-bundle",
                    ],
                },
                "closed_this_wave": [
                    "kotlin_spring_ownership_held_out",
                    "csharp_service_layer_held_out",
                    "php_controller_ownership_held_out",
                    "rust_axum_ownership_held_out",
                    "scala_spring_ownership_held_out",
                    "human_hour_multilang_kotlin_csharp_php_rust_scala",
                    "live_track_record_summary_fields",
                    "multilang_production_breadth_beyond_held_outs",
                    "human_hour_real_package_protocol",
                    "commercial_delivery_runbook_and_scoreboard",
                    "research_session_track_record_export",
                ],
            },
            "execution_allowed": False,
            "report_submission_allowed": False,
            "auto_attack_allowed": False,
            "positioning": {
                "lead_with": "falsify_first_auditable_research_factory",
                "do_not_claim": [
                    "auto_exploit",
                    "xbow_live_ranking",
                    "live_bounty_top1_from_lab_alone",
                ],
                "anti_auto_exploit": (
                    "Autonomous exploitation is an intentional non-goal. "
                    "Compete on falsify-first candidate quality, auditable evidence, "
                    "and human-gated validation/report drafts."
                ),
                "narrative": (
                    "Mythos-Lite is a lawful, falsify-first vulnerability research factory. "
                    "It intentionally refuses autonomous exploitation and auto-submission; "
                    "value is high-precision candidates with refutation cards and human gates. "
                    "Lab held-outs cover Java/Go/Rails/C#/PHP/Kotlin/Rust/Scala ownership "
                    "boundaries plus a production-shaped language×pattern breadth matrix; "
                    "full market leadership still requires real authorized wall-clock logs "
                    "and real live valid-report outcomes."
                ),
            },
            "non_claims": list(live.get("non_claims") or [])
            + list(lab.get("non_claims") or [])
            + list(breadth.get("non_claims") or []),
        }
        out_path = Path(args.out)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(result, indent=2), encoding="utf-8")
        print(
            f"delivery-readiness wrote {out_path} "
            f"(passed={result.get('passed')}, "
            f"lab={result.get('lab_passed')}, "
            f"live_infra={result.get('live_infra_passed')}, "
            f"breadth={result.get('multilang_breadth_passed')}, "
            f"remaining={len(remaining)})"
        )
        return 0 if result.get("passed") else 1
    except Exception as error:  # noqa: BLE001 - CLI boundary
        print(f"delivery-readiness failed: {error}", file=sys.stderr)
        return 2


def run_lab_leadership_rollup_command(args) -> int:
    try:
        root = Path(args.root) if getattr(args, "root", None) else None
        log_path = Path(args.log) if getattr(args, "log", None) else None
        result = run_lab_leadership_rollup(
            black_box_root=root,
            simulated_human_hours=float(getattr(args, "simulated_hours", 1.0) or 1.0),
            calibration_log=log_path,
        )
        out_path = Path(args.out)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(result, indent=2), encoding="utf-8")
        print(
            f"lab-leadership-rollup wrote {out_path} "
            f"(passed={result.get('passed')}, "
            f"failures={result.get('failures')})"
        )
        return 0 if result.get("passed") else 1
    except (
        OSError,
        ValueError,
        json.JSONDecodeError,
        TypeError,
        KeyError,
        LabLeadershipRollupError,
        BlackBoxLeadershipGateError,
        AbLeadershipGateError,
        HumanHourScorecardError,
        HumanHourCalibrationError,
    ) as error:
        print(f"lab-leadership-rollup failed: {error}", file=sys.stderr)
        return 2



def run_multilang_production_breadth_command(args) -> int:
    try:
        result = run_multilang_production_breadth_gate()
        out_path = Path(args.out)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(result, indent=2), encoding="utf-8")
        metrics = result.get("metrics") or {}
        print(
            f"multilang-production-breadth wrote {out_path} "
            f"(passed={result.get('passed')}, "
            f"beyond_held_out={result.get('beyond_held_out')}, "
            f"langs={len(result.get('languages_hit') or [])}, "
            f"matrix={metrics.get('matrix_coverage_rate')})"
        )
        return 0 if result.get("passed") else 1
    except (
        OSError,
        ValueError,
        json.JSONDecodeError,
        TypeError,
        KeyError,
    ) as error:
        print(f"multilang-production-breadth failed: {error}", file=sys.stderr)
        return 2





def run_export_research_track_record_command(args) -> int:
    """Export redacted live/HH packages from research-session artifacts."""
    try:
        session_notes = None
        if getattr(args, "demo", False):
            session_notes = build_demo_session_notes()
        elif getattr(args, "session_notes", None):
            raw = _read_json_file(args.session_notes)
            if isinstance(raw, list):
                session_notes = [e for e in raw if isinstance(e, dict)]
            elif isinstance(raw, dict) and isinstance(raw.get("entries"), list):
                session_notes = [e for e in raw["entries"] if isinstance(e, dict)]
            else:
                print(
                    "export-research-track-record: session-notes must be list or {entries:[...]}",
                    file=sys.stderr,
                )
                return 2

        approvals = None
        approvals_bundle = None
        if getattr(args, "approvals", None):
            raw = _read_json_file(args.approvals)
            if isinstance(raw, list):
                approvals = [e for e in raw if isinstance(e, dict)]
            elif isinstance(raw, dict):
                if isinstance(raw.get("approvals"), list):
                    approvals_bundle = raw
                else:
                    approvals = [raw]
            else:
                print(
                    "export-research-track-record: approvals must be list or object",
                    file=sys.stderr,
                )
                return 2

        wall_clock_runner = None
        if getattr(args, "wall_clock_json", None):
            wall_clock_runner = _read_json_file(args.wall_clock_json)
            if not isinstance(wall_clock_runner, dict):
                print(
                    "export-research-track-record: wall-clock-json must be object",
                    file=sys.stderr,
                )
                return 2

        result = export_research_track_record(
            approvals=approvals,
            approvals_bundle=approvals_bundle,
            package_root=getattr(args, "package_root", None),
            wall_clock_runner=wall_clock_runner,
            session_notes=session_notes,
            program_handle=str(getattr(args, "program_handle", "") or "research-session"),
            package_id=str(getattr(args, "package_id", "") or ""),
            package_label=str(getattr(args, "package_label", "") or ""),
            program_authorization_id=str(
                getattr(args, "program_authorization_id", "") or ""
            )
            or None,
            declare_real_package=bool(getattr(args, "declare_real_package", False)),
            language_family=str(getattr(args, "language_family", "unknown") or "unknown"),
            evaluation_top_k=getattr(args, "evaluation_top_k", None),
            human_allow_export_write=bool(
                getattr(args, "human_allow_export_write", False)
            ),
            out_dir=getattr(args, "out_dir", None),
        )

        out_path = getattr(args, "out", None)
        if out_path:
            path = Path(out_path)
            path.parent.mkdir(parents=True, exist_ok=True)
            slim = {
                k: v
                for k, v in result.items()
                if k not in {"live_package", "human_hour_package"}
            }
            # Keep packages when writing explicit --out for machine follow-up.
            slim["live_package"] = result.get("live_package")
            slim["human_hour_package"] = result.get("human_hour_package")
            path.write_text(json.dumps(slim, indent=2), encoding="utf-8")
            print(
                f"export-research-track-record wrote {path} "
                f"(source_kind={result.get('source_kind')}, "
                f"live={result.get('live_entry_count')}, "
                f"hh={result.get('human_hour_entry_count')}, "
                f"export_written={result.get('export_written')})"
            )
        else:
            print(
                f"export-research-track-record ok "
                f"(source_kind={result.get('source_kind')}, "
                f"live={result.get('live_entry_count')}, "
                f"hh={result.get('human_hour_entry_count')}, "
                f"export_written={result.get('export_written')}, "
                f"summary={result.get('summary')})"
            )
        return 0
    except TrackRecordExportError as error:
        print(f"export-research-track-record failed: {error}", file=sys.stderr)
        return 2
    except (OSError, ValueError, json.JSONDecodeError, TypeError, KeyError) as error:
        print(f"export-research-track-record failed: {error}", file=sys.stderr)
        return 2






def run_prepare_research_session_package_command(args) -> int:
    """Scaffold a research-session package root for later capture."""
    try:
        if not getattr(args, "human_allow_write", False):
            print(
                "prepare-research-session-package requires --human-allow-write",
                file=sys.stderr,
            )
            return 2
        result = prepare_research_session_package(
            package_root=args.package_root,
            program_handle=str(getattr(args, "program_handle", "") or ""),
            program_authorization_id=str(
                getattr(args, "program_authorization_id", "") or ""
            ),
            include_synthetic_examples=not bool(
                getattr(args, "no_synthetic_examples", False)
            ),
            human_allow_write=True,
        )
        out_path = getattr(args, "out", None)
        if out_path:
            path = Path(out_path)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(
                json.dumps(result, indent=2, ensure_ascii=False) + "\n",
                encoding="utf-8",
            )
        print(
            f"prepare-research-session-package wrote {result.get('package_root')} "
            f"(files={len(result.get('written') or [])})"
        )
        return 0
    except PrepareResearchSessionError as error:
        print(f"prepare-research-session-package failed: {error}", file=sys.stderr)
        return 2
    except (OSError, ValueError, TypeError) as error:
        print(f"prepare-research-session-package failed: {error}", file=sys.stderr)
        return 2


def run_capture_research_session_track_record_command(args) -> int:
    """Discover package artifacts, export live/HH packages, optional market re-score."""
    try:
        if not getattr(args, "human_allow_export_write", False):
            print(
                "capture-research-session-track-record requires "
                "--human-allow-export-write",
                file=sys.stderr,
            )
            return 2
        rescore = not bool(getattr(args, "no_rescore_market", False))
        if getattr(args, "rescore_market", False) is False:
            rescore = False
        result = capture_research_session_track_record(
            package_root=args.package_root,
            out_dir=args.out_dir,
            program_authorization_id=str(
                getattr(args, "program_authorization_id", "") or ""
            )
            or None,
            declare_real_package=bool(getattr(args, "declare_real_package", False)),
            program_handle=str(getattr(args, "program_handle", "") or ""),
            package_id=str(getattr(args, "package_id", "") or ""),
            package_label=str(getattr(args, "package_label", "") or ""),
            language_family=str(getattr(args, "language_family", "unknown") or "unknown"),
            hypothesis_class=str(
                getattr(args, "hypothesis_class", "authorization") or "authorization"
            ),
            vuln_family=str(getattr(args, "vuln_family", "idor") or "idor"),
            evaluation_top_k=getattr(args, "evaluation_top_k", None),
            human_allow_export_write=True,
            rescore_market=rescore,
            session_notes_path=getattr(args, "session_notes", None),
            wall_clock_path=getattr(args, "wall_clock_json", None),
            publish_drop_dir=bool(getattr(args, "publish_drop_dir", False)),
            drop_dir=getattr(args, "drop_dir", None),
        )
        out_path = getattr(args, "out", None)
        if out_path:
            path = Path(out_path)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(
                json.dumps(result, indent=2, ensure_ascii=False) + "\n",
                encoding="utf-8",
            )
            printed = path
        else:
            printed = Path(args.out_dir) / "capture_manifest.json"
        remaining = result.get("remaining_for_full_market_leadership") or []
        closed = result.get("closed_market_gaps") or []
        export = result.get("export") or {}
        print(
            f"capture-research-session-track-record wrote {printed} "
            f"(source_kind={export.get('source_kind')}, "
            f"live={export.get('live_entry_count')}, "
            f"hh={export.get('human_hour_entry_count')}, "
            f"remaining={len(remaining)}, closed={len(closed)}, "
            f"passed={result.get('passed')})"
        )
        return 0 if result.get("passed") else 1
    except CaptureResearchSessionError as error:
        print(
            f"capture-research-session-track-record failed: {error}",
            file=sys.stderr,
        )
        return 2
    except TrackRecordExportError as error:
        print(
            f"capture-research-session-track-record failed: {error}",
            file=sys.stderr,
        )
        return 2
    except (OSError, ValueError, json.JSONDecodeError, TypeError, KeyError) as error:
        print(
            f"capture-research-session-track-record failed: {error}",
            file=sys.stderr,
        )
        return 2


def run_commercial_delivery_bundle_command(args) -> int:
    """Write customer-facing commercial delivery bundle + anti-auto-exploit proof."""
    try:
        if not getattr(args, "human_allow_write", False):
            print(
                "commercial-delivery-bundle requires --human-allow-write",
                file=sys.stderr,
            )
            return 2
        cal_log = Path(args.log) if getattr(args, "log", None) else None
        live_log = Path(args.live_log) if getattr(args, "live_log", None) else None
        out_dir = Path(args.out_dir)
        manifest = build_commercial_delivery_bundle(
            out_dir=out_dir,
            calibration_log=cal_log,
            live_log=live_log,
            human_allow_write=True,
        )
        if getattr(args, "out", None):
            out_path = Path(args.out)
            out_path.parent.mkdir(parents=True, exist_ok=True)
            out_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
        remaining = manifest.get("remaining_for_full_market_leadership") or []
        closed = manifest.get("closed_market_gaps") or []
        print(
            f"commercial-delivery-bundle wrote {out_dir} "
            f"(passed={manifest.get('passed')}, remaining={len(remaining)}, "
            f"closed={len(closed)})"
        )
        return 0 if manifest.get("passed") else 1
    except ValueError as error:
        print(f"commercial-delivery-bundle failed: {error}", file=sys.stderr)
        return 2
    except Exception as error:  # noqa: BLE001 - CLI boundary
        print(f"commercial-delivery-bundle failed: {error}", file=sys.stderr)
        return 2


def run_market_leadership_scoreboard_command(args) -> int:
    """Honest market-leadership scoreboard: what is closed vs still needs real packages."""
    try:
        # Reuse delivery-readiness assembly by invoking the same underlying gates.
        class _Args:
            pass

        proxy = _Args()
        proxy.out = args.out
        proxy.log = getattr(args, "log", None)
        proxy.live_log = getattr(args, "live_log", None)
        # Build scoreboard without double-writing via delivery command internals.
        from app.intelligence_benchmark.lab_leadership_rollup import (
            run_lab_leadership_rollup,
        )

        attached = resolve_attached_track_record_paths(
            live_log=getattr(args, "live_log", None),
            human_hour_log=getattr(args, "log", None),
        )
        cal_log = (
            Path(attached["human_hour_log"])
            if attached.get("human_hour_log")
            else None
        )
        live_log = (
            Path(attached["live_log"]) if attached.get("live_log") else None
        )
        lab = run_lab_leadership_rollup(calibration_log=cal_log)
        live = run_authorized_live_calibration_gate(log_path=live_log)
        breadth = run_multilang_production_breadth_gate()
        ab = (lab.get("component_results") or {}).get("ab_leadership") or {}
        hh = (lab.get("component_results") or {}).get("human_hour_calibration") or {}
        live_measured = live.get("measured") if isinstance(live.get("measured"), dict) else {}
        track = live_measured.get("track_record_summary") or {}
        has_real_live_wall = bool(track.get("has_real_wall_clock_logs"))
        has_real_hh_wall = bool(hh.get("has_real_human_hour_wall_clock_logs"))
        has_real_wall = has_real_live_wall or has_real_hh_wall
        has_real_valid = bool(track.get("has_real_live_valid_report_outcomes"))
        breadth_beyond = bool(breadth.get("beyond_held_out") and breadth.get("passed"))
        remaining: list[str] = []
        if not has_real_wall:
            remaining.append("real_authorized_program_wall_clock_logs")
        if not has_real_valid:
            remaining.append("real_live_valid_report_outcomes")
        if not breadth_beyond:
            remaining.append("production_multilang_sast_breadth_beyond_held_outs")
        closed = []
        if breadth_beyond:
            closed.append("production_multilang_sast_breadth_beyond_held_outs")
        if has_real_wall:
            closed.append("real_authorized_program_wall_clock_logs")
        if has_real_valid:
            closed.append("real_live_valid_report_outcomes")

        anti_proof = evaluate_anti_auto_exploit_narrative(
            payload={
                "lab": lab,
                "live": live,
                "breadth": breadth,
                "execution_allowed": False,
                "report_submission_allowed": False,
                "auto_attack_allowed": False,
            }
        )
        packaging_ready = bool(
            lab.get("passed")
            and live.get("passed")
            and breadth.get("passed")
            and anti_proof.get("passed")
            and breadth_beyond
        )
        if packaging_ready:
            closed.append("commercial_delivery_packaging")
        if anti_proof.get("passed"):
            closed.append("anti_auto_exploit_narrative")

        result = {
            "schema_version": "market_leadership_scoreboard_v1",
            "claim_scope": "honest_market_gap_scoreboard",
            "passed": bool(lab.get("passed") and live.get("passed") and breadth.get("passed")),
            "lab_passed": lab.get("passed"),
            "live_infra_passed": live.get("passed"),
            "multilang_breadth_passed": breadth.get("passed"),
            "lab_scenario_count": ab.get("scenario_count"),
            "remaining_for_full_market_leadership": remaining,
            "closed_market_gaps": closed,
            "signals": {
                "has_real_wall_clock_logs": has_real_wall,
                "has_real_live_wall_clock_logs": has_real_live_wall,
                "has_real_human_hour_wall_clock_logs": has_real_hh_wall,
                "has_real_live_valid_report_outcomes": has_real_valid,
                "multilang_beyond_held_out": breadth_beyond,
                "commercial_packaging_ready": packaging_ready,
                "anti_auto_exploit_proven": bool(anti_proof.get("passed")),
            },
            "anti_auto_exploit": anti_proof,
            "path_resolution": attached,
            "attach_protocol": {
                "export_command": "export-research-track-record",
                "capture_command": "capture-research-session-track-record",
                "prepare_command": "prepare-research-session-package",
                "drop_dir": "authorized_track_records",
                "env_live": "MYTHOS_LIVE_TRACK_RECORD",
                "env_human_hour": "MYTHOS_HUMAN_HOUR_TRACK_RECORD",
                "bundle_command": "commercial-delivery-bundle",
                "export_note": (
                    "Prefer capture-research-session-track-record from authorized "
                    "package-root (session notes/wall-clock/residual approvals); "
                    "or export-research-track-record with explicit artifacts. "
                    "Synthetic never flips has_real_*; real requires "
                    "--declare-real-package and --program-authorization-id."
                ),
                "live_template": (
                    "app/intelligence_benchmark/fixtures/templates/"
                    "authorized_wall_clock_and_outcomes.template.json"
                ),
                "human_hour_requirements": [
                    "source_kind=authorized_redacted_real",
                    "program_authorization_id",
                    "wall_clock_minutes on one or more entries",
                    "execution_allowed=false",
                    "report_submission_allowed=false",
                    "no secrets/tokens/cookies",
                ],
                "live_requirements": [
                    "source_kind=authorized_redacted_real",
                    "program_authorization_id",
                    "wall_clock_minutes for wall-clock gap",
                    "human_confirmed_valid + report_outcome_ref for valid-report gap",
                    "authorized=true",
                    "human_confirmed=true",
                    "no auto-submit",
                ],
            },
            "positioning": {
                "lead_with": "falsify_first_auditable_research_factory",
                "anti_auto_exploit": (
                    "Autonomous exploitation is an intentional non-goal. "
                    "Compete on falsify-first candidate quality, auditable evidence, "
                    "and human-gated validation/report drafts."
                ),
                "do_not_claim": [
                    "auto_exploit",
                    "xbow_live_ranking",
                    "live_bounty_top1_from_lab_alone",
                    "full_commercial_multilang_sast_replacement",
                ],
            },
            "execution_allowed": False,
            "report_submission_allowed": False,
            "auto_attack_allowed": False,
            "non_claims": [
                "Does not claim live bounty program superiority.",
                "Does not claim XBOW ranking.",
                "Lab gates are necessary but not sufficient for live TOP1.",
            ],
            "runbook": "docs/product/commercial-delivery-runbook.md",
        }
        out_path = Path(args.out)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(result, indent=2), encoding="utf-8")
        print(
            f"market-leadership-scoreboard wrote {out_path} "
            f"(passed={result.get('passed')}, remaining={len(remaining)}, "
            f"closed={len(closed)})"
        )
        return 0 if result.get("passed") else 1
    except Exception as error:  # noqa: BLE001 - CLI boundary
        print(f"market-leadership-scoreboard failed: {error}", file=sys.stderr)
        return 2


def run_black_box_lab_command(args) -> int:
    """Dual-role HAR -> local-lab observe only. Never opens remote targets."""
    try:
        har_a = _read_json_file(args.har_a)
        har_b = _read_json_file(args.har_b)
        if not isinstance(har_a, dict) or not isinstance(har_b, dict):
            print("black-box-lab: HAR files must be JSON objects", file=sys.stderr)
            return 2
        result = run_har_local_lab_pipeline(
            {"role_a": har_a, "role_b": har_b},
            mode=args.mode,
            local_lab=True,
            trial_classes={args.trial_class},
            account_aliases={
                "role_a": args.account_a,
                "role_b": args.account_b,
            },
            role_aliases={
                "role_a": args.role_a_alias,
                "role_b": args.role_b_alias,
            },
            role_ranks={
                "role_a": args.role_a_rank,
                "role_b": args.role_b_rank,
            },
        )
    except (OSError, ValueError, json.JSONDecodeError, TypeError, KeyError) as error:
        print(f"black-box-lab failed: {error}", file=sys.stderr)
        return 2

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(result, indent=2), encoding="utf-8")
    retained = len(result.get("retained_candidates") or [])
    total = len(result.get("candidates") or [])
    print(
        f"black-box-lab wrote {out_path} "
        f"(mode={result.get('lab_mode')}, retained={retained}/{total}, "
        f"execution_allowed={result.get('execution_allowed')})"
    )
    return 0


def run_agent_status_command(args) -> int:
    resume = _read_agent_resume(args.resume_from)
    campaign_id = args.campaign_id or resume.get("campaign_id")
    engine = create_engine(args.database_url, **_engine_kwargs(args.database_url))
    ensure_database_schema(engine)
    SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
    with SessionLocal() as session:
        status = get_agent_status(
            campaign_id=campaign_id,
            repository=DatabaseRepository(session),
            goal=str(resume.get("goal", "")),
            repo_path=str(resume.get("repo_path", "")),
            scope_path=str(resume.get("scope_path", "")),
        )
    print(status.to_text())
    return 0


def run_agent_command(args) -> int:
    resume = _read_agent_resume(args.resume_from)
    repo = args.repo or resume.get("repo_path")
    scope = args.scope or resume.get("scope_path")
    goal = args.goal or resume.get("goal")
    campaign_id = args.campaign_id or resume.get("campaign_id")
    if not repo or not scope or not goal:
        raise SystemExit("--repo, --scope, and --goal are required unless --resume-from supplies them")

    engine = create_engine(args.database_url, **_engine_kwargs(args.database_url))
    ensure_database_schema(engine)
    SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
    with SessionLocal() as session:
        result = run_agent_goal(
            AgentGoal(
                goal=goal,
                repo_path=Path(repo),
                scope_path=Path(scope),
                campaign_id=campaign_id,
                max_steps=args.max_steps,
            ),
            repository=DatabaseRepository(session),
        )
    if args.receipt_output:
        Path(args.receipt_output).write_text(
            json.dumps(result.to_dict(), indent=2),
            encoding="utf-8",
        )
    print(result.to_text())
    return 0


def _read_agent_resume(path: str | None) -> dict:
    if path is None:
        return {}
    data = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    return data if isinstance(data, dict) else {}


def persist_source_audit_pipeline_run(*, database_url: str, scope_path: str, result):
    engine = create_engine(database_url, **_engine_kwargs(database_url))
    ensure_database_schema(engine)
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
    data = _read_json_file(path)
    return data if isinstance(data, dict) else {}


def _read_json_file(path: str) -> object:
    data = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    return data


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
