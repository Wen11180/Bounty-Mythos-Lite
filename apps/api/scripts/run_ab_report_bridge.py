"""Build submission-blocked report draft bundles from A+B package trials.

Does not perform live validation or report submission.
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

ROOT = Path(__file__).resolve().parents[3]
if str(ROOT / "apps" / "api") not in sys.path:
    sys.path.insert(0, str(ROOT / "apps" / "api"))

from app.db import Base
from app.intelligence_benchmark.candidate_report_bridge import (
    bridge_operator_trial_result,
)
from app.human_residual_gate import attach_human_residual_gates_to_bridge_result
from app.patch_suggestion import attach_patch_suggestions_to_bridge_result
from app.human_review_approvals import attach_human_review_approvals_to_bridge_result
from app.residual_patch_decision_api import attach_residual_patch_decision_api_to_bridge_result
from app.intake_agent import attach_intake_profile_to_bridge_result
from app.dependency_agent import attach_dependency_profile_to_bridge_result
from app.residual_runner import attach_residual_runner_to_bridge_result
from app.semgrep_runner import attach_semgrep_runner_to_bridge_result
from app.codeql_runner import attach_codeql_runner_to_bridge_result
from app.crs_fuzzing import attach_crs_fuzzing_to_bridge_result
from app.local_fuzz_sandbox import attach_local_fuzz_sandbox_to_bridge_result
from app.local_fuzz_runner import attach_local_fuzz_runner_to_bridge_result
from app.crash_triage import attach_crash_triage_to_bridge_result
from app.crash_regression import attach_crash_regression_to_bridge_result
from app.crash_codepath import attach_crash_codepath_to_bridge_result
from app.protocol_aware_fuzzing import attach_protocol_aware_fuzzing_to_bridge_result
from app.patch_diff_learner import attach_patch_diff_learner_to_bridge_result
from app.variant_analysis import attach_variant_analysis_to_bridge_result
from app.vuln_chain_builder import attach_vuln_chain_builder_to_bridge_result
from app.deep_code_reasoning import attach_deep_code_reasoning_to_bridge_result
from app.human_gate_dry_run import attach_human_gate_dry_run_to_bridge_result
from app.agent_memory import attach_agent_memory_to_bridge_result
from app.finding_dedup_risk import attach_finding_dedup_risk_to_bridge_result
from app.continuous_scan import attach_continuous_scan_to_bridge_result
from app.patch_validation import attach_patch_validation_to_bridge_result
from app.deep_research import attach_deep_research_to_bridge_result
from app.long_horizon import attach_long_horizon_to_bridge_result
from app.knowledge_base import attach_knowledge_base_to_bridge_result
from app.multi_hour_agent_loop import attach_multi_hour_agent_loop_to_bridge_result
from app.wall_clock_multi_hour_runner import attach_wall_clock_multi_hour_runner_to_bridge_result
from app.authorized_web_api import attach_authorized_web_api_to_bridge_result
from app.patch_agent import attach_patch_industrial_loop_to_bridge_result
from app.patch_pr_workflow import attach_patch_pr_workflow_to_bridge_result
from app.multi_engine_verifier import attach_deeper_multi_engine_to_bridge_result
from app.intelligence_benchmark.release_runner import (
    run_candidate_hunter_authorized_lab_package,
)


def _session():
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine)()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--package-root",
        action="append",
        dest="package_roots",
        required=True,
        type=Path,
        help="Authorized package directory. Repeatable.",
    )
    parser.add_argument(
        "--allow-local-semgrep",
        action="store_true",
        default=False,
        help="Explicit human flag: run local Semgrep CLI on package roots only (offline rules; no remote registries).",
    )
    parser.add_argument(
        "--allow-local-codeql",
        action="store_true",
        default=False,
        help="Explicit human flag: run local CodeQL CLI on package roots only (pre-built local DB + suite; no remote packs).",
    )
    parser.add_argument(
        "--allow-patch-pr-export-write",
        action="store_true",
        default=False,
        help="Explicit human flag: write local patch PR export files under package _export/patch_pr/ (still never opens PR/git).",
    )
    parser.add_argument(
        "--allow-crs-harness-write",
        action="store_true",
        default=False,
        help="Explicit human flag: write local CRS harness sketches under package _export/crs_harness/ (still never executes fuzzers).",
    )
    parser.add_argument(
        "--allow-local-fuzz-sandbox-write",
        action="store_true",
        default=False,
        help="Explicit human flag: write local fuzz sandbox recipes under package _export/fuzz_sandbox/ (still never executes fuzzers).",
    )
    parser.add_argument(
        "--allow-local-fuzz-run",
        action="store_true",
        help="Compatibility flag only: records operator intent but remains plan-only; target code never runs in-process.",
    )
    parser.add_argument(
        "--allow-crash-triage",
        action="store_true",
        help="Compatibility flag only: classify/dedupe crash metadata plan-only; reproduction requires an isolated runner.",
    )
    parser.add_argument(
        "--allow-crash-regression-export",
        action="store_true",
        help="Optional: write crash residual regression plans under package _export/crash_regression/ (still never auto-runs tests).",
    )
    parser.add_argument(
        "--allow-crash-codepath-export",
        action="store_true",
        help="Optional: write advisory crash code-path links under package _export/crash_codepath/ (static only; never promote).",
    )

    parser.add_argument(
        "--allow-protocol-aware-fuzzing-export",
        action="store_true",
        default=False,
        help="Optional: write protocol grammar/seed plans under package _export/protocol_aware_fuzzing/ (still never executes fuzzers).",
    )
    parser.add_argument(
        "--allow-patch-diff-learner-export",
        action="store_true",
        default=False,
        help="Optional: write learned patch-diff patterns under package _export/patch_diff_learner/ (still never applies patches or opens PRs).",
    )
    parser.add_argument(
        "--allow-variant-analysis-export",
        action="store_true",
        default=False,
        help="Optional: write variant search plans under package _export/variant_analysis/ (still never exploits, promotes, or submits).",
    )
    parser.add_argument(
        "--allow-vuln-chain-builder-export",
        action="store_true",
        default=False,
        help="Optional: write multi-stage vuln chain plans under package _export/vuln_chain_builder/ (still never exploits, promotes, or submits).",
    )
    parser.add_argument(
        "--allow-deep-code-reasoning-export",
        action="store_true",
        default=False,
        help="Optional: write permission/cross-file deep code reasoning plans under package _export/deep_code_reasoning/ (still never exploits, promotes, or submits).",
    )
    parser.add_argument(
        "--allow-human-gate-dry-run-export",
        action="store_true",
        help="Optional: write offline human-gate dry-run checkpoints under package _export/human_gate_dry_run/ (never probes H1/submits).",
    )
    parser.add_argument(
        "--allow-agent-memory-export",
        action="store_true",
        help="Optional: write advisory agent memory under package _export/agent_memory/ (ranking only; never execute/submit).",
    )
    parser.add_argument(
        "--allow-finding-dedup-risk-export",
        action="store_true",
        help="Optional: write finding dedup clusters + risk queue under package _export/finding_dedup_risk/ (plan only; never promote/submit).",
    )
    parser.add_argument(
        "--allow-continuous-scan-export",
        action="store_true",
        help="Optional: write continuous-scan cadence plan under package _export/continuous_scan/ (never auto-scans).",
    )
    parser.add_argument(
        "--allow-patch-validation-export",
        action="store_true",
        help="Optional: write patch-validation recheck plan under package _export/patch_validation/ (never live-validates).",
    )
    parser.add_argument(
        "--allow-deep-research-export",
        action="store_true",
        help="Optional: write V4 deep-research plan under package _export/deep_research/ (never executes/exploits/submits).",
    )
    parser.add_argument(
        "--allow-long-horizon-export",
        action="store_true",
        help="Optional: write V4 long-horizon path-switch plan under package _export/long_horizon/ (never auto-switches/executes).",
    )
    parser.add_argument(
        "--allow-knowledge-base-export",
        action="store_true",
        help="Optional: write section-7 structured knowledge catalog under package _export/knowledge_base/ (never grants ranking/execute).",
    )
    parser.add_argument(
        "--allow-multi-hour-agent-loop-export",
        action="store_true",
        help="Optional: write multi-hour session plan under package _export/multi_hour_agent_loop/ (never auto-ticks/executes).",
    )
    parser.add_argument(
        "--allow-wall-clock-multi-hour-runner-export",
        action="store_true",
        help="Optional: write wall-clock tick ledger under package _export/wall_clock_multi_hour_runner/ (never auto-ticks/executes).",
    )
    parser.add_argument(
        "--allow-residual-patch-decision-api-export",
        action="store_true",
        help="Optional: write residual/patch decision snapshot under package _export/residual_patch_decision_api/ (never unlocks gates).",
    )
    parser.add_argument("--md-name", default="hunter-ab-report-bridge.md")
    parser.add_argument("--json-name", default="hunter-ab-report-bridge.json")
    parser.add_argument(
        "--workspace-root",
        type=Path,
        default=ROOT / "apps" / "api" / ".pytest-tmp" / "report-bridge-workspaces",
    )
    args = parser.parse_args()

    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    session = _session()
    packages = []
    for package_root in args.package_roots:
        trial = run_candidate_hunter_authorized_lab_package(
            package_root,
            session=session,
            workspace_root=args.workspace_root / package_root.name,
        )
        bridged = bridge_operator_trial_result(trial)
        bridged = attach_human_residual_gates_to_bridge_result(
            bridged,
            package_root=package_root,
            trial_result=trial,
        )
        bridged = attach_patch_suggestions_to_bridge_result(
            bridged,
            package_root=package_root,
        )
        bridged = attach_human_review_approvals_to_bridge_result(
            bridged,
            package_root=package_root,
            trial_result=trial,
        )
        bridged = attach_residual_patch_decision_api_to_bridge_result(
            bridged,
            package_root=package_root,
            human_allow_export_write=bool(args.allow_residual_patch_decision_api_export),
        )
        bridged = attach_intake_profile_to_bridge_result(
            bridged,
            package_root=package_root,
        )
        bridged = attach_dependency_profile_to_bridge_result(
            bridged,
            package_root=package_root,
        )
        bridged = attach_residual_runner_to_bridge_result(
            bridged,
            package_root=package_root,
            trial_result=trial,
        )
        bridged = attach_semgrep_runner_to_bridge_result(
            bridged,
            package_root=package_root,
            human_allow_local_semgrep=bool(args.allow_local_semgrep),
        )
        bridged = attach_codeql_runner_to_bridge_result(
            bridged,
            package_root=package_root,
            human_allow_local_codeql=bool(args.allow_local_codeql),
        )
        bridged = attach_crs_fuzzing_to_bridge_result(
            bridged,
            package_root=package_root,
            human_allow_harness_write=bool(args.allow_crs_harness_write),
        )
        bridged = attach_local_fuzz_sandbox_to_bridge_result(
            bridged,
            package_root=package_root,
            human_allow_sandbox_write=bool(args.allow_local_fuzz_sandbox_write),
        )
        bridged = attach_protocol_aware_fuzzing_to_bridge_result(
            bridged,
            package_root=package_root,
            human_allow_export_write=bool(args.allow_protocol_aware_fuzzing_export),
        )
        bridged = attach_local_fuzz_runner_to_bridge_result(
            bridged,
            package_root=package_root,
            human_allow_local_fuzz_run=bool(args.allow_local_fuzz_run),
        )
        bridged = attach_crash_triage_to_bridge_result(
            bridged,
            package_root=package_root,
            human_allow_crash_triage=bool(args.allow_crash_triage),
        )
        bridged = attach_crash_codepath_to_bridge_result(
            bridged,
            package_root=package_root,
            human_allow_export_write=bool(args.allow_crash_codepath_export),
        )
        bridged = attach_crash_regression_to_bridge_result(
            bridged,
            package_root=package_root,
            human_allow_export_write=bool(args.allow_crash_regression_export),
        )
        bridged = attach_authorized_web_api_to_bridge_result(
            bridged,
            package_root=package_root,
        )
        bridged = attach_patch_industrial_loop_to_bridge_result(
            bridged,
            package_root=package_root,
        )
        bridged = attach_patch_pr_workflow_to_bridge_result(
            bridged,
            package_root=package_root,
            human_allow_export_write=bool(args.allow_patch_pr_export_write),
        )
        bridged = attach_patch_diff_learner_to_bridge_result(
            bridged,
            package_root=package_root,
            human_allow_export_write=bool(args.allow_patch_diff_learner_export),
        )
        bridged = attach_variant_analysis_to_bridge_result(
            bridged,
            package_root=package_root,
            human_allow_export_write=bool(args.allow_variant_analysis_export),
        )
        bridged = attach_vuln_chain_builder_to_bridge_result(
            bridged,
            package_root=package_root,
            human_allow_export_write=bool(args.allow_vuln_chain_builder_export),
        )
        bridged = attach_deep_code_reasoning_to_bridge_result(
            bridged,
            package_root=package_root,
            human_allow_export_write=bool(args.allow_deep_code_reasoning_export),
        )
        bridged = attach_finding_dedup_risk_to_bridge_result(
            bridged,
            package_root=package_root,
            human_allow_export_write=bool(args.allow_finding_dedup_risk_export),
        )
        bridged = attach_deeper_multi_engine_to_bridge_result(bridged)
        bridged = attach_human_gate_dry_run_to_bridge_result(
            bridged,
            package_root=package_root,
            human_allow_export_write=bool(args.allow_human_gate_dry_run_export),
        )
        bridged = attach_agent_memory_to_bridge_result(
            bridged,
            package_root=package_root,
            human_allow_export_write=bool(args.allow_agent_memory_export),
        )
        bridged = attach_continuous_scan_to_bridge_result(
            bridged,
            package_root=package_root,
            human_allow_export_write=bool(args.allow_continuous_scan_export),
        )
        bridged = attach_patch_validation_to_bridge_result(
            bridged,
            package_root=package_root,
            human_allow_export_write=bool(args.allow_patch_validation_export),
        )
        bridged = attach_deep_research_to_bridge_result(
            bridged,
            package_root=package_root,
            human_allow_export_write=bool(args.allow_deep_research_export),
        )
        bridged = attach_long_horizon_to_bridge_result(
            bridged,
            package_root=package_root,
            human_allow_export_write=bool(args.allow_long_horizon_export),
        )
        bridged = attach_knowledge_base_to_bridge_result(
            bridged,
            package_root=package_root,
            human_allow_export_write=bool(args.allow_knowledge_base_export),
        )
        bridged = attach_multi_hour_agent_loop_to_bridge_result(
            bridged,
            package_root=package_root,
            human_allow_export_write=bool(args.allow_multi_hour_agent_loop_export),
        )
        bridged = attach_wall_clock_multi_hour_runner_to_bridge_result(
            bridged,
            package_root=package_root,
            human_allow_export_write=bool(args.allow_wall_clock_multi_hour_runner_export),
        )
        # Re-deepen so multi-engine can include offline human-gate / memory / scan / patch-validation / deep-research / long-horizon / knowledge-base / multi-hour-loop / wall-clock-runner posture.
        bridged = attach_deeper_multi_engine_to_bridge_result(bridged)
        packages.append(bridged)
        gates = bridged.get("human_residual_gates") or []
        gate_statuses = sorted(
            {
                str(g.get("status") or "")
                for g in gates
                if isinstance(g, dict) and g.get("status")
            }
        )
        print(
            f"{bridged['package_id']}: retained={bridged['retained_count']} "
            f"drafts={bridged['draft_count']} submission_blocked={bridged['submission_blocked']} "
            f"advisory={bridged.get('advisory_bundle_present')} residual_file={bridged.get('residual_checklist_present')} residual_gates={gate_statuses or ['-']} "
            f"patch={bridged.get('patch_suggestion_present')} hreview={bridged.get('human_review_approvals_present')} intake={bridged.get('intake_profile_present')} langs={len(bridged.get('stack_languages') or [])} deps={bridged.get('sbom_component_count')} rrun={bridged.get('residual_runner_status')} rdone={bridged.get('residual_runner_completed_count')} sgrep={bridged.get('semgrep_runner_status')} sfind={bridged.get('semgrep_runner_finding_count')} cq={bridged.get('codeql_runner_status')} cfind={bridged.get('codeql_runner_finding_count')} crs={bridged.get('crs_fuzzing_status')} ccand={bridged.get('crs_fuzzing_candidate_count')} web={bridged.get('authorized_web_api_status')} wops={bridged.get('authorized_web_api_operation_count')} wdiff={bridged.get('authorized_web_api_role_diff_count')} ploop={bridged.get('patch_industrial_loop_status')} pitems={bridged.get('patch_industrial_loop_item_count')} ppr={bridged.get('patch_pr_workflow_status')} ppready={bridged.get('patch_pr_workflow_ready_count')} pprexport={bridged.get('patch_pr_export_written')} hexport={bridged.get('crs_fuzzing_harness_export_written')} hexpc={bridged.get('crs_fuzzing_harness_export_count')} fsb={bridged.get('local_fuzz_sandbox_status')} fsbe={bridged.get('local_fuzz_sandbox_export_written')} fsbc={bridged.get('local_fuzz_sandbox_export_count')} paf={bridged.get('protocol_aware_fuzzing_status')} pafn={bridged.get('protocol_aware_fuzzing_target_count')} pafg={bridged.get('protocol_aware_fuzzing_grammar_plan_count')} pafs={bridged.get('protocol_aware_fuzzing_seed_plan_count')} pafx={bridged.get('protocol_aware_fuzzing_export_written')} pdl={bridged.get('patch_diff_learner_status')} pdln={bridged.get('patch_diff_learner_pattern_count')} pdlx={bridged.get('patch_diff_learner_export_written')} va={bridged.get('variant_analysis_status')} van={bridged.get('variant_analysis_variant_count')} vas={bridged.get('variant_analysis_seed_count')} vax={bridged.get('variant_analysis_export_written')} vcb={bridged.get('vuln_chain_builder_status')} vcbn={bridged.get('vuln_chain_builder_chain_count')} vcbs={bridged.get('vuln_chain_builder_seed_count')} vcbx={bridged.get('vuln_chain_builder_export_written')} dcr={bridged.get('deep_code_reasoning_status')} dcrn={bridged.get('deep_code_reasoning_path_count')} dcrpm={bridged.get('deep_code_reasoning_permission_model_count')} dcrs={bridged.get('deep_code_reasoning_seed_count')} dcrx={bridged.get('deep_code_reasoning_export_written')} fdr={bridged.get('finding_dedup_risk_status')} fdrn={bridged.get('finding_dedup_risk_cluster_count')} fdrq={bridged.get('finding_dedup_risk_queue_count')} fdrs={bridged.get('finding_dedup_risk_seed_count')} fdrx={bridged.get('finding_dedup_risk_export_written')} lfr={bridged.get('local_fuzz_runner_status')} lfre={bridged.get('local_fuzz_runner_executed')} lfrc={bridged.get('local_fuzz_runner_crash_count')} ctr={bridged.get('crash_triage_status')} ctre={bridged.get('crash_triage_executed')} ctrc={bridged.get('crash_triage_cluster_count')} ctrep={bridged.get('crash_triage_reproducible_count')} creg={bridged.get('crash_regression_status')} cregn={bridged.get('crash_regression_suggestion_count')} cregx={bridged.get('crash_regression_export_written')} cregc={bridged.get('crash_regression_codepath_linked_count')} cpath={bridged.get('crash_codepath_status')} cpathn={bridged.get('crash_codepath_link_count')} cpathr={bridged.get('crash_codepath_resolved_count')} cpathx={bridged.get('crash_codepath_export_written')} mevdeep={bridged.get('multi_engine_deep')} mevenc={bridged.get('multi_engine_engine_count')} hg={bridged.get('human_gate_dry_run_status')} hgpass={bridged.get('human_gate_dry_run_pass_count')} hgfail={bridged.get('human_gate_dry_run_fail_count')} hgok={bridged.get('human_gate_dry_run_chain_complete')} hgsafe={bridged.get('human_gate_dry_run_chain_safe')} hgx={bridged.get('human_gate_dry_run_export_written')} amem={bridged.get('agent_memory_status')} amenn={bridged.get('agent_memory_entry_count')} amemfp={bridged.get('agent_memory_false_positive_pattern_count')} amemh={bridged.get('agent_memory_candidate_hint_count')} amemx={bridged.get('agent_memory_export_written')} cscan={bridged.get('continuous_scan_status')} cscann={bridged.get('continuous_scan_job_count')} cscanw={bridged.get('continuous_scan_watch_path_count')} cscanx={bridged.get('continuous_scan_export_written')} pval={bridged.get('patch_validation_status')} pvaln={bridged.get('patch_validation_item_count')} pvalr={bridged.get('patch_validation_ready_item_count')} pvals={bridged.get('patch_validation_step_count')} pvalx={bridged.get('patch_validation_export_written')} dres={bridged.get('deep_research_status')} dresc={bridged.get('deep_research_chain_count')} dresv={bridged.get('deep_research_variant_count')} dresu={bridged.get('deep_research_unresolved_refutation_count')} dresx={bridged.get('deep_research_export_written')} lhor={bridged.get('long_horizon_status')} lhorp={bridged.get('long_horizon_path_count')} lhors={bridged.get('long_horizon_switch_count')} lhori={bridged.get('long_horizon_iteration_count')} lhorx={bridged.get('long_horizon_export_written')} kbase={bridged.get('knowledge_base_status')} kbasep={bridged.get('knowledge_base_pattern_count')} kbasex={bridged.get('knowledge_base_export_written')} mhal={bridged.get('multi_hour_agent_loop_status')} mhalp={bridged.get('multi_hour_agent_loop_phase_count')} mhals={bridged.get('multi_hour_agent_loop_session_count')} mhalg={bridged.get('multi_hour_agent_loop_gate_count')} mhalx={bridged.get('multi_hour_agent_loop_export_written')} wclk={bridged.get('wall_clock_multi_hour_runner_status')} wclks={bridged.get('wall_clock_multi_hour_runner_slot_count')} wclkt={bridged.get('wall_clock_multi_hour_runner_tick_count')} wclkg={bridged.get('wall_clock_multi_hour_runner_stop_count')} wclkx={bridged.get('wall_clock_multi_hour_runner_export_written')} hreview={bridged.get('human_review_approvals_status')} hreviewn={bridged.get('human_review_approvals_count')} hreviewd={bridged.get('human_review_approvals_decided_count')} hreviewr={bridged.get('human_review_approvals_residual_count')} hreviewp={bridged.get('human_review_approvals_patch_count')} rpda={bridged.get('residual_patch_decision_api_status')} rpdan={bridged.get('residual_patch_decision_api_count')} rpdad={bridged.get('residual_patch_decision_api_decided_count')} rpdar={bridged.get('residual_patch_decision_api_residual_count')} rpdap={bridged.get('residual_patch_decision_api_patch_count')} rpdax={bridged.get('residual_patch_decision_api_export_written')}"
        )

    payload = {
        "generated_at": generated_at,
        "submission_blocked": True,
        "execution_allowed": False,
        "report_submission_allowed": False,
        "package_count": len(packages),
        "total_drafts": sum(item["draft_count"] for item in packages),
        "packages": packages,
    }

    docs = ROOT / "docs"
    docs.mkdir(exist_ok=True)
    json_path = docs / args.json_name
    md_path = docs / args.md_name
    json_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    md_path.write_text(_render_md(payload), encoding="utf-8")
    print(f"wrote {json_path}")
    print(f"wrote {md_path}")
    return 0


def _render_md(payload: dict) -> str:
    lines = [
        "# A+B Candidate → Report Draft Bridge",
        "",
        f"Generated: {payload['generated_at']}",
        "",
        "Safety: submission blocked; no live validation; hunter candidates remain unverified.",
        "",
        f"- packages: {payload['package_count']}",
        f"- total drafts: {payload['total_drafts']}",
        f"- report_submission_allowed: `{payload['report_submission_allowed']}`",
        "",
        "## Packages",
        "",
        "| package | retained | drafts | submission_blocked | multi_engine | residual_file | residual_gate | patch |",
        "| --- | --- | --- | --- | --- | --- | --- | --- |",
    ]
    for item in payload["packages"]:
        verdicts = item.get("multi_engine_verdicts") or []
        top_status = ",".join(
            sorted(
                {
                    str(v.get("status") or "")
                    for v in verdicts
                    if isinstance(v, dict) and v.get("status")
                }
            )
        ) or "-"
        residual_status = ",".join(
            sorted(
                {
                    str(g.get("status") or "")
                    for g in (item.get("human_residual_gates") or [])
                    if isinstance(g, dict) and g.get("status")
                }
            )
        ) or "-"
        lines.append(
            f"| `{item['package_id']}` | {item['retained_count']} | {item['draft_count']} | `{item['submission_blocked']}` | `{top_status}` | `{item.get('residual_checklist_present')}` | `{residual_status}` | `{item.get('patch_suggestion_present')}` |"
        )
    lines.append("")
    for item in payload["packages"]:
        lines.append(f"## {item['package_id']}")
        lines.append("")
        verdicts = [
            v for v in (item.get("multi_engine_verdicts") or []) if isinstance(v, dict)
        ]
        if verdicts:
            lines.append("Multi-engine verdicts (non-executing, not confirmed):")
            lines.append("")
            for verdict in verdicts:
                lines.append(
                    f"- `{verdict.get('candidate_id') or '-'}`: "
                    f"`{verdict.get('status')}` "
                    f"(agreement={verdict.get('agreement_score')}, "
                    f"confirmed={verdict.get('confirmed_vulnerability')})"
                )
            lines.append("")
        residual_gates = [
            g for g in (item.get("human_residual_gates") or []) if isinstance(g, dict)
        ]
        if residual_gates:
            lines.append("Human residual gates (submission still blocked):")
            lines.append("")
            for gate in residual_gates:
                lines.append(
                    f"- `{gate.get('candidate_id') or '-'}`: `{gate.get('status')}` "
                    f"(open={gate.get('open_residual_count')}, "
                    f"submit={gate.get('report_submission_allowed')})"
                )
            lines.append("")
        patch_suggestions = [
            p for p in (item.get("patch_suggestions") or []) if isinstance(p, dict)
        ]
        intake = item.get("intake_profile") if isinstance(item.get("intake_profile"), dict) else {}
        if intake:
            lines.append("Intake profile (advisory stack detection; no network):")
            lines.append(f"- status: {intake.get('status')}")
            lines.append(f"- languages: {', '.join(intake.get('language') or []) or '-'}")
            lines.append(f"- frameworks: {', '.join(intake.get('framework') or []) or '-'}")
            lines.append(f"- package_managers: {', '.join(intake.get('package_managers') or []) or '-'}")
            lines.append(f"- entrypoints: {len(intake.get('entrypoints') or [])}")
            lines.append(f"- auth_components: {len(intake.get('auth_components') or [])}")
            lines.append(f"- execution_allowed: {intake.get('execution_allowed')}")
            lines.append("")
        dep = item.get("dependency_profile") if isinstance(item.get("dependency_profile"), dict) else {}
        if dep:
            lines.append("Dependency / SBOM profile (local only; no live CVE lookup):")
            lines.append(f"- status: {dep.get('status')}")
            lines.append(f"- ecosystems: {', '.join(dep.get('ecosystems') or []) or '-'}")
            lines.append(f"- components: {dep.get('component_count')}")
            lines.append(f"- reachable: {dep.get('reachable_count')}")
            lines.append(f"- advisory_flagged: {dep.get('advisory_flagged_count')}")
            lines.append(f"- live_advisory_lookup: {dep.get('live_advisory_lookup')}")
            lines.append(f"- execution_allowed: {dep.get('execution_allowed')}")
            lines.append("")
        rruns = [r for r in (item.get("residual_runner_runs") or []) if isinstance(r, dict)]
        if rruns or item.get("residual_runner_present"):
            lines.append("Residual runner (local static only; requires residual_review approval):")
            lines.append(f"- aggregate_status: {item.get('residual_runner_status')}")
            lines.append(f"- completed_runs: {item.get('residual_runner_completed_count')}")
            for run in rruns[:3]:
                lines.append(
                    f"- candidate `{run.get('candidate_id') or '-'}`: "
                    f"`{run.get('status')}` planned={run.get('probes_planned')} "
                    f"done={run.get('probes_completed')} gaps={run.get('open_static_gaps')} "
                    f"approved={run.get('human_approved')} "
                    f"exec={run.get('execution_allowed')} live={run.get('live_validation_executed')}"
                )
            lines.append("")
        sgrep = item.get("semgrep_runner") if isinstance(item.get("semgrep_runner"), dict) else {}
        if sgrep or item.get("semgrep_runner_present"):
            lines.append("Local Semgrep runner (explicit human flag; package-root only; no remote rules):")
            lines.append(f"- status: {item.get('semgrep_runner_status') or sgrep.get('status')}")
            lines.append(f"- human_flag: {sgrep.get('human_allow_local_semgrep')}")
            lines.append(f"- command_executed: {sgrep.get('command_executed')}")
            lines.append(f"- findings: {item.get('semgrep_runner_finding_count') or sgrep.get('finding_count')}")
            lines.append(f"- binary_available: {sgrep.get('binary_available')}")
            lines.append(f"- remote_rules: {sgrep.get('remote_rules')}")
            lines.append(f"- execution_allowed: {sgrep.get('execution_allowed')}")
            lines.append("")
        cql = item.get("codeql_runner") if isinstance(item.get("codeql_runner"), dict) else {}
        if cql or item.get("codeql_runner_present"):
            lines.append("Local CodeQL runner (explicit human flag; package-root only; no remote packs):")
            lines.append(f"- status: {item.get('codeql_runner_status') or cql.get('status')}")
            lines.append(f"- human_flag: {cql.get('human_allow_local_codeql')}")
            lines.append(f"- command_executed: {cql.get('command_executed')}")
            lines.append(f"- findings: {item.get('codeql_runner_finding_count') or cql.get('finding_count')}")
            lines.append(f"- binary_available: {cql.get('binary_available')}")
            lines.append(f"- database_source: {cql.get('database_source')}")
            lines.append(f"- query_suite_source: {cql.get('query_suite_source')}")
            lines.append(f"- remote_packs: {cql.get('remote_packs')}")
            lines.append(f"- execution_allowed: {cql.get('execution_allowed')}")
            lines.append("")
        if item.get("multi_engine_deep") or item.get("multi_engine_verdicts"):
            lines.append("Deeper multi-engine verifier (local static agreement only; never exploit verification):")
            lines.append(f"- deep_stack_attached: {item.get('multi_engine_deep')}")
            lines.append(f"- engine_count: {item.get('multi_engine_engine_count')}")
            engines = item.get("multi_engine_engines") or []
            if engines:
                lines.append(f"- engines: {', '.join(str(e) for e in engines)}")
            for v in (item.get("multi_engine_verdicts") or [])[:5]:
                if not isinstance(v, dict):
                    continue
                lines.append(
                    f"- verdict {v.get('candidate_id') or '-'}: status={v.get('status')} "
                    f"agreement={v.get('agreement_score')} engines={v.get('engine_count') or len(v.get('engines') or [])} "
                    f"confirmed={v.get('confirmed_vulnerability')}"
                )
            lines.append("")
        crs = item.get("crs_fuzzing") if isinstance(item.get("crs_fuzzing"), dict) else {}
        if crs or item.get("crs_fuzzing_present"):
            lines.append("CRS/fuzz plan (plan-only; no auto execution):")
            lines.append(f"- status: {item.get('crs_fuzzing_status') or crs.get('status')}")
            lines.append(f"- candidates: {item.get('crs_fuzzing_candidate_count') or crs.get('candidate_count')}")
            lines.append(f"- harnesses: {item.get('crs_fuzzing_harness_count') or crs.get('harness_count')}")
            lines.append(f"- harness_export_written: {item.get('crs_fuzzing_harness_export_written') or crs.get('harness_export_written')}")
            lines.append(f"- harness_export_count: {item.get('crs_fuzzing_harness_export_count') or crs.get('harness_export_count')}")
            lines.append(f"- human_allow_harness_write: {crs.get('human_allow_harness_write')}")
            lines.append(f"- scanned_files: {crs.get('scanned_file_count')}")
            fuzzer = crs.get("fuzzer_plan") if isinstance(crs.get("fuzzer_plan"), dict) else {}
            lines.append(f"- fuzzer_status: {fuzzer.get('status')}")
            lines.append(f"- execution_allowed: {crs.get('execution_allowed')}")
            lines.append(f"- promotion_allowed: {(crs.get('crash_promotion_gate') or {}).get('promotion_allowed') if isinstance(crs.get('crash_promotion_gate'), dict) else False}")
            lines.append("")
        sandbox = item.get("local_fuzz_sandbox") if isinstance(item.get("local_fuzz_sandbox"), dict) else {}
        if sandbox or item.get("local_fuzz_sandbox_present"):
            lines.append("Local fuzz sandbox (plan/export only; never auto-run):")
            lines.append(f"- status: {item.get('local_fuzz_sandbox_status') or sandbox.get('status')}")
            lines.append(f"- targets: {item.get('local_fuzz_sandbox_target_count') or sandbox.get('target_count')}")
            lines.append(f"- sandbox_export_written: {item.get('local_fuzz_sandbox_export_written') or sandbox.get('sandbox_export_written')}")
            lines.append(f"- sandbox_export_count: {item.get('local_fuzz_sandbox_export_count') or sandbox.get('sandbox_export_count')}")
            lines.append(f"- human_allow_sandbox_write: {sandbox.get('human_allow_sandbox_write')}")
            lines.append(f"- process_spawn_allowed: {sandbox.get('process_spawn_allowed')}")
            lines.append(f"- execution_allowed: {sandbox.get('execution_allowed')}")
            lines.append(f"- crash_promotion_allowed: {sandbox.get('crash_promotion_allowed')}")
            lines.append("")


        paf = item.get("protocol_aware_fuzzing") if isinstance(item.get("protocol_aware_fuzzing"), dict) else {}
        if paf or item.get("protocol_aware_fuzzing_present"):
            lines.append("### Protocol-aware fuzzing (V4 plan-only)")
            lines.append(f"- status: {item.get('protocol_aware_fuzzing_status') or paf.get('status')}")
            lines.append(f"- targets: {item.get('protocol_aware_fuzzing_target_count') or paf.get('target_count')}")
            lines.append(f"- grammar_plans: {item.get('protocol_aware_fuzzing_grammar_plan_count') or paf.get('grammar_plan_count')}")
            lines.append(f"- seed_plans: {item.get('protocol_aware_fuzzing_seed_plan_count') or paf.get('seed_plan_count')}")
            lines.append(f"- export_written: {item.get('protocol_aware_fuzzing_export_written') or paf.get('export_written')}")
            lines.append(f"- process_spawn_allowed: {paf.get('process_spawn_allowed')}")
            lines.append(f"- execution_allowed: {paf.get('execution_allowed')}")
            lines.append("")

        pdl = item.get("patch_diff_learner") if isinstance(item.get("patch_diff_learner"), dict) else {}
        if pdl or item.get("patch_diff_learner_present"):
            lines.append("### Patch Diff Learner (V4 plan-only)")
            lines.append(f"- status: {item.get('patch_diff_learner_status') or pdl.get('status')}")
            lines.append(f"- patterns: {item.get('patch_diff_learner_pattern_count') or pdl.get('pattern_count')}")
            lines.append(f"- offline_diffs: {item.get('patch_diff_learner_offline_diff_count') or pdl.get('offline_diff_count')}")
            lines.append(f"- bridge_diffs: {item.get('patch_diff_learner_bridge_diff_count') or pdl.get('bridge_diff_count')}")
            lines.append(f"- export_written: {item.get('patch_diff_learner_export_written') or pdl.get('export_written')}")
            lines.append(f"- auto_pr_allowed: {pdl.get('auto_pr_allowed')}")
            lines.append(f"- patch_ready: {pdl.get('patch_ready')}")
            lines.append(f"- execution_allowed: {pdl.get('execution_allowed')}")
            lines.append("")

        va = item.get("variant_analysis") if isinstance(item.get("variant_analysis"), dict) else {}
        if va or item.get("variant_analysis_present"):
            lines.append("### Variant Analysis (V4 plan-only)")
            lines.append(f"- status: {item.get('variant_analysis_status') or va.get('status')}")
            lines.append(f"- variants: {item.get('variant_analysis_variant_count') or va.get('variant_count')}")
            lines.append(f"- seeds: {item.get('variant_analysis_seed_count') or va.get('seed_count')}")
            lines.append(f"- offline_hints: {item.get('variant_analysis_offline_hint_count') or va.get('offline_hint_count')}")
            lines.append(f"- export_written: {item.get('variant_analysis_export_written') or va.get('export_written')}")
            lines.append(f"- execution_allowed: {va.get('execution_allowed')}")
            lines.append(f"- confirmed_vulnerability: {va.get('confirmed_vulnerability')}")
            lines.append("")

        vcb = item.get("vuln_chain_builder") if isinstance(item.get("vuln_chain_builder"), dict) else {}
        if vcb or item.get("vuln_chain_builder_present"):
            lines.append("### Vulnerability Chain Builder (V4 plan-only)")
            lines.append(f"- status: {item.get('vuln_chain_builder_status') or vcb.get('status')}")
            lines.append(f"- chains: {item.get('vuln_chain_builder_chain_count') or vcb.get('chain_count')}")
            lines.append(f"- seeds: {item.get('vuln_chain_builder_seed_count') or vcb.get('seed_count')}")
            lines.append(f"- offline_hints: {item.get('vuln_chain_builder_offline_hint_count') or vcb.get('offline_hint_count')}")
            lines.append(f"- export_written: {item.get('vuln_chain_builder_export_written') or vcb.get('export_written')}")
            lines.append(f"- execution_allowed: {vcb.get('execution_allowed')}")
            lines.append(f"- confirmed_vulnerability: {vcb.get('confirmed_vulnerability')}")
            lines.append("")

        dcr = item.get("deep_code_reasoning") if isinstance(item.get("deep_code_reasoning"), dict) else {}
        if dcr or item.get("deep_code_reasoning_present"):
            lines.append("### Deep Code Reasoning (V4 plan-only)")
            lines.append(f"- status: {item.get('deep_code_reasoning_status') or dcr.get('status')}")
            lines.append(f"- paths: {item.get('deep_code_reasoning_path_count') if item.get('deep_code_reasoning_path_count') is not None else dcr.get('path_count')}")
            lines.append(f"- permission_models: {item.get('deep_code_reasoning_permission_model_count') if item.get('deep_code_reasoning_permission_model_count') is not None else dcr.get('permission_model_count')}")
            lines.append(f"- seeds: {item.get('deep_code_reasoning_seed_count') if item.get('deep_code_reasoning_seed_count') is not None else dcr.get('seed_count')}")
            lines.append(f"- export_written: {item.get('deep_code_reasoning_export_written') or dcr.get('export_written')}")
            lines.append(f"- execution_allowed: {dcr.get('execution_allowed')}")
            lines.append(f"- confirmed_vulnerability: {dcr.get('confirmed_vulnerability')}")
            lines.append("")

        runner = item.get("local_fuzz_runner") if isinstance(item.get("local_fuzz_runner"), dict) else {}
        if runner or item.get("local_fuzz_runner_present"):
            lines.append("Local fuzz target plan (in-process execution disabled; never promote):")
            lines.append(f"- status: {item.get('local_fuzz_runner_status') or runner.get('status')}")
            lines.append(f"- targets: {item.get('local_fuzz_runner_target_count') or runner.get('target_count')}")
            lines.append(f"- runnable: {item.get('local_fuzz_runner_runnable_count') or runner.get('runnable_target_count')}")
            lines.append(f"- executed: {item.get('local_fuzz_runner_executed') or runner.get('in_process_run_executed')}")
            lines.append(f"- crash_count: {item.get('local_fuzz_runner_crash_count') or runner.get('crash_count')}")
            lines.append(f"- crash_export_written: {item.get('local_fuzz_runner_export_written') or runner.get('crash_export_written')}")
            lines.append(f"- process_spawn_allowed: {runner.get('process_spawn_allowed')}")
            lines.append(f"- crash_promotion_allowed: {runner.get('crash_promotion_allowed')}")
            lines.append(f"- execution_allowed: {runner.get('execution_allowed')}")
            lines.append("")

        triage = item.get("crash_triage") if isinstance(item.get("crash_triage"), dict) else {}
        if triage or item.get("crash_triage_present"):
            lines.append("Crash triage (dedupe/minimize/root-cause advisory; never promote):")
            lines.append(f"- status: {item.get('crash_triage_status') or triage.get('status')}")
            lines.append(f"- input_crashes: {item.get('crash_triage_input_crash_count') or triage.get('input_crash_count')}")
            lines.append(f"- clusters: {item.get('crash_triage_cluster_count') or triage.get('unique_cluster_count')}")
            lines.append(f"- reproducible: {item.get('crash_triage_reproducible_count') or triage.get('reproducible_count')}")
            lines.append(f"- minimized: {item.get('crash_triage_minimized_count') or triage.get('minimized_count')}")
            lines.append(f"- executed: {item.get('crash_triage_executed') or triage.get('triage_executed')}")
            lines.append(f"- export_written: {item.get('crash_triage_export_written') or triage.get('triage_export_written')}")
            lines.append(f"- crash_promotion_allowed: {triage.get('crash_promotion_allowed')}")
            lines.append(f"- execution_allowed: {triage.get('execution_allowed')}")
            lines.append("")

        creg = item.get("crash_regression") if isinstance(item.get("crash_regression"), dict) else {}
        if creg or item.get("crash_regression_present"):
            lines.append("Crash residual regression (plan-only tests from triaged clusters; never auto-run):")
            lines.append(f"- status: {item.get('crash_regression_status') or creg.get('status')}")
            lines.append(f"- suggestions: {item.get('crash_regression_suggestion_count') or creg.get('suggestion_count')}")
            lines.append(f"- reproducible_linked: {item.get('crash_regression_reproducible_linked_count') or creg.get('reproducible_linked_count')}")
            lines.append(f"- minimized_linked: {item.get('crash_regression_minimized_linked_count') or creg.get('minimized_linked_count')}")
            lines.append(f"- codepath_linked: {item.get('crash_regression_codepath_linked_count') or creg.get('codepath_linked_count')}")
            lines.append(f"- export_written: {item.get('crash_regression_export_written') or creg.get('export_written')}")

        cpath = item.get("crash_codepath") if isinstance(item.get("crash_codepath"), dict) else {}
        if cpath or item.get("crash_codepath_present"):
            lines.append("### Crash code-path linking")
            lines.append(f"- status: {item.get('crash_codepath_status') or cpath.get('status')}")
            lines.append(f"- links: {item.get('crash_codepath_link_count') or cpath.get('link_count')}")
            lines.append(f"- resolved: {item.get('crash_codepath_resolved_count') or cpath.get('resolved_count')}")
            lines.append(f"- primary_paths: {item.get('crash_codepath_primary_path_count') or cpath.get('primary_path_count')}")
            lines.append(f"- export_written: {item.get('crash_codepath_export_written') or cpath.get('export_written')}")
            lines.append(f"- package_code_execution_allowed: {cpath.get('package_code_execution_allowed')}")
            lines.append(f"- crash_promotion_allowed: {cpath.get('crash_promotion_allowed')}")
            lines.append(f"- confirmed_vulnerability: {cpath.get('confirmed_vulnerability')}")
            lines.append("")

        web = item.get("authorized_web_api") if isinstance(item.get("authorized_web_api"), dict) else {}
        if web or item.get("authorized_web_api_present"):
            lines.append("Authorized Web/API plan (package ingest; plan-only; never live validate/submit):")
            lines.append(f"- status: {item.get('authorized_web_api_status') or web.get('status')}")
            lines.append(f"- operations: {item.get('authorized_web_api_operation_count') or web.get('operation_count')}")
            lines.append(f"- role_diffs: {item.get('authorized_web_api_role_diff_count') or web.get('role_diff_count')}")
            lines.append(f"- business_logic: {item.get('authorized_web_api_business_logic_count') or web.get('business_logic_count')}")
            lines.append(f"- execution_allowed: {web.get('execution_allowed')}")
            lines.append(f"- report_submission_allowed: {web.get('report_submission_allowed')}")
            lines.append("")
        ploop = item.get("patch_industrial_loop") if isinstance(item.get("patch_industrial_loop"), dict) else {}
        if ploop or item.get("patch_industrial_loop_present"):
            lines.append("Patch industrial loop (advisory sketches + planned regression only):")
            lines.append(f"- status: {item.get('patch_industrial_loop_status') or ploop.get('status')}")
            lines.append(f"- items: {item.get('patch_industrial_loop_item_count') or ploop.get('item_count')}")
            lines.append(f"- advisory: {item.get('patch_industrial_loop_advisory_count') or ploop.get('advisory_count')}")
            lines.append(f"- regression_plans: {ploop.get('regression_plans_count')}")
            lines.append(f"- code_context_hits: {ploop.get('code_context_hits')}")
            lines.append(f"- auto_pr_allowed: {ploop.get('auto_pr_allowed')}")
            lines.append(f"- patch_ready: {ploop.get('patch_ready')}")
            lines.append("")

        ppr = item.get("patch_pr_workflow") if isinstance(item.get("patch_pr_workflow"), dict) else {}
        if ppr or item.get("patch_pr_workflow_present"):
            lines.append("External patch PR workflow (plan/export only; never auto-PR/git/gh):")
            lines.append(f"- status: {item.get('patch_pr_workflow_status') or ppr.get('status')}")
            lines.append(f"- items: {item.get('patch_pr_workflow_item_count') or ppr.get('item_count')}")
            lines.append(f"- ready: {item.get('patch_pr_workflow_ready_count') or ppr.get('ready_count')}")
            lines.append(f"- exported: {item.get('patch_pr_workflow_exported_count') or ppr.get('exported_count')}")
            lines.append(f"- export_written: {item.get('patch_pr_export_written') or ppr.get('export_written')}")
            lines.append(f"- auto_pr_allowed: {ppr.get('auto_pr_allowed')}")
            lines.append(f"- pr_opened: {ppr.get('pr_opened')}")
            lines.append(f"- patch_ready: {ppr.get('patch_ready')}")
            lines.append("")

        if patch_suggestions:
            lines.append("Patch suggestions (advisory only; no auto-PR / no exploit PoC):")
            lines.append("")
            for patch in patch_suggestions:
                lines.append(
                    f"- `{patch.get('candidate_id') or '-'}`: `{patch.get('status')}` "
                    f"(auto_pr={patch.get('auto_pr_allowed')}, "
                    f"exploit_poc={patch.get('exploit_poc_included')}, "
                    f"submit={patch.get('report_submission_allowed')})"
                )
                for change in list(patch.get("suggested_changes") or [])[:3]:
                    if str(change).strip():
                        lines.append(f"  - {change}")
            lines.append("")
        if not item["drafts"]:
            lines.append("_No retained candidates; no report drafts._")
            lines.append("")
            continue
        for draft in item["drafts"]:
            rd = draft["report_draft"]
            mev = draft.get("multi_engine_verdict") or {}
            lines.extend(
                [
                    f"### {draft['candidate_id']} — {draft['root_cause_id']}",
                    "",
                    f"- route: `{draft['route']}`",
                    f"- status: `{draft['status']}`",
                    f"- multi_engine_verdict: `{mev.get('status') or '-'}`",
                    f"- confirmed_vulnerability: `{draft.get('confirmed_vulnerability')}`",
                    f"- human_review_required: `{draft['human_review_required']}`",
                    f"- submission_blocked: `{draft['submission_blocked']}`",
                    f"- title: {rd.get('title')}",
                    f"- next_allowed_action: {draft.get('next_allowed_action')}",
                    f"- safety_blockers: `{', '.join(draft.get('safety_blockers') or [])}`",
                    "",
                    "Validation plan steps:",
                    "",
                ]
            )
            for step in (draft.get("validation_plan") or {}).get("steps") or []:
                lines.append(f"- {step}")
            lines.append("")
            workspace = draft.get("validation_workspace") or {}
            if workspace:
                lines.extend(
                    [
                        "Validation workspace (prep only):",
                        "",
                        f"- status: `{workspace.get('status')}`",
                        f"- allowed_to_execute: `{workspace.get('allowed_to_execute')}`",
                        f"- human_approval_required: `{workspace.get('human_approval_required')}`",
                        f"- non_destructive_only: `{workspace.get('non_destructive_only')}`",
                        f"- no_real_user_data: `{workspace.get('no_real_user_data')}`",
                        "",
                    ]
                )
            lines.append("Refutation questions:")
            lines.append("")
            for q in draft.get("refutation_questions") or []:
                lines.append(f"- {q}")
            lines.append("")
        hg = item.get("human_gate_dry_run") if isinstance(item.get("human_gate_dry_run"), dict) else {}
        if hg or item.get("human_gate_dry_run_present"):
            lines.append("Human gate dry-run (offline e2e proof; never probes H1 / never auto-submits):")
            lines.append(f"- status: {item.get('human_gate_dry_run_status') or hg.get('status')}")
            lines.append(f"- checkpoints: {item.get('human_gate_dry_run_checkpoint_count') or hg.get('checkpoint_count')}")
            lines.append(f"- pass/fail: {item.get('human_gate_dry_run_pass_count') or hg.get('pass_count')}/{item.get('human_gate_dry_run_fail_count') or hg.get('fail_count')}")
            lines.append(f"- chain_complete: {item.get('human_gate_dry_run_chain_complete') if item.get('human_gate_dry_run_chain_complete') is not None else hg.get('chain_complete')}")
            lines.append(f"- chain_safe: {item.get('human_gate_dry_run_chain_safe') if item.get('human_gate_dry_run_chain_safe') is not None else hg.get('chain_safe')}")
            lines.append(f"- export_written: {item.get('human_gate_dry_run_export_written') or hg.get('export_written')}")
            lines.append(f"- report_submission_allowed: {hg.get('report_submission_allowed')}")
            lines.append("")
            for cp in list(hg.get("checkpoints") or [])[:12]:
                if not isinstance(cp, dict):
                    continue
                lines.append(
                    f"  - `{cp.get('checkpoint_id') or '-'}`: `{cp.get('status')}` - {cp.get('title') or ''}"
                )
            lines.append("")
        fdr = item.get("finding_dedup_risk") if isinstance(item.get("finding_dedup_risk"), dict) else {}
        if fdr or item.get("finding_dedup_risk_present"):
            lines.append("### Finding Dedup / Risk Prioritization")
            lines.append(f"- status: {item.get('finding_dedup_risk_status') or fdr.get('status')}")
            lines.append(f"- clusters: {item.get('finding_dedup_risk_cluster_count') if item.get('finding_dedup_risk_cluster_count') is not None else fdr.get('cluster_count')}")
            lines.append(f"- risk_queue: {item.get('finding_dedup_risk_queue_count') if item.get('finding_dedup_risk_queue_count') is not None else fdr.get('risk_queue_count')}")
            lines.append(f"- seeds: {item.get('finding_dedup_risk_seed_count') if item.get('finding_dedup_risk_seed_count') is not None else fdr.get('seed_count')}")
            lines.append(f"- export_written: {item.get('finding_dedup_risk_export_written') or fdr.get('export_written')}")

        amem = item.get("agent_memory") if isinstance(item.get("agent_memory"), dict) else {}
        if amem or item.get("agent_memory_present"):
            lines.append("Agent memory (V3 advisory ranking only; never grants execute/submit):")
            lines.append(f"- status: {item.get('agent_memory_status') or amem.get('status')}")
            lines.append(f"- entries: {item.get('agent_memory_entry_count') if item.get('agent_memory_entry_count') is not None else amem.get('entry_count')}")
            lines.append(f"- fp_patterns: {item.get('agent_memory_false_positive_pattern_count') if item.get('agent_memory_false_positive_pattern_count') is not None else amem.get('false_positive_pattern_count')}")
            lines.append(f"- candidate_hints: {item.get('agent_memory_candidate_hint_count') if item.get('agent_memory_candidate_hint_count') is not None else amem.get('candidate_hint_count')}")
            lines.append(f"- export_written: {item.get('agent_memory_export_written') or amem.get('export_written')}")
            lines.append(f"- ranking_permission_granted: {amem.get('ranking_permission_granted')}")
            lines.append(f"- report_submission_allowed: {amem.get('report_submission_allowed')}")
            lines.append("")
            for entry in list(amem.get("entries") or [])[:8]:
                if not isinstance(entry, dict):
                    continue
                lines.append(
                    f"  - `{entry.get('entry_id') or '-'}` [{entry.get('kind') or '-'}]: {entry.get('summary') or entry.get('topic') or ''}"
                )
            lines.append("")
        cscan = item.get("continuous_scan") if isinstance(item.get("continuous_scan"), dict) else {}
        if cscan or item.get("continuous_scan_present"):
            lines.append("Continuous scan (V3 cadence plan only; never auto-scans):")
            lines.append(f"- status: {item.get('continuous_scan_status') or cscan.get('status')}")
            lines.append(f"- jobs: {item.get('continuous_scan_job_count') if item.get('continuous_scan_job_count') is not None else cscan.get('job_count')}")
            lines.append(f"- watches: {item.get('continuous_scan_watch_path_count') if item.get('continuous_scan_watch_path_count') is not None else cscan.get('watch_path_count')}")
            lines.append(f"- cadence: {cscan.get('cadence')}")
            lines.append(f"- export_written: {item.get('continuous_scan_export_written') or cscan.get('export_written')}")
            lines.append(f"- auto_scan_allowed: {cscan.get('auto_scan_allowed')}")
            lines.append("")
            for job in list(cscan.get("jobs") or [])[:8]:
                if not isinstance(job, dict):
                    continue
                lines.append(f"  - `{job.get('job_id') or '-'}`: {job.get('title') or ''} ({job.get('method') or ''})")
            lines.append("")
        pval = item.get("patch_validation") if isinstance(item.get("patch_validation"), dict) else {}
        if pval or item.get("patch_validation_present"):
            lines.append("Patch validation (V3 non-destructive recheck plan; never live-validates):")
            lines.append(f"- status: {item.get('patch_validation_status') or pval.get('status')}")
            lines.append(f"- items: {item.get('patch_validation_item_count') if item.get('patch_validation_item_count') is not None else pval.get('item_count')}")
            lines.append(f"- ready: {item.get('patch_validation_ready_item_count') if item.get('patch_validation_ready_item_count') is not None else pval.get('ready_item_count')}")
            lines.append(f"- steps: {item.get('patch_validation_step_count') if item.get('patch_validation_step_count') is not None else pval.get('step_count')}")
            lines.append(f"- export_written: {item.get('patch_validation_export_written') or pval.get('export_written')}")
            lines.append(f"- patch_ready: {pval.get('patch_ready')}")
            lines.append(f"- live_validation_allowed: {pval.get('live_validation_allowed')}")
            lines.append("")
            for pv_item in list(pval.get("items") or [])[:6]:
                if not isinstance(pv_item, dict):
                    continue
                lines.append(
                    f"  - `{pv_item.get('item_id') or '-'}` cand=`{pv_item.get('candidate_id') or '-'}` status=`{pv_item.get('status') or '-'}`"
                )
            lines.append("")

        dres = item.get("deep_research") if isinstance(item.get("deep_research"), dict) else {}
        if dres or item.get("deep_research_present"):
            lines.append("### Deep Research (V4 plan-only)")
            lines.append(f"- status: {item.get('deep_research_status') or dres.get('status')}")
            lines.append(f"- chains: {item.get('deep_research_chain_count') if item.get('deep_research_chain_count') is not None else dres.get('chain_count')}")
            lines.append(f"- variants: {item.get('deep_research_variant_count') if item.get('deep_research_variant_count') is not None else dres.get('variant_count')}")
            lines.append(f"- unresolved_refutations: {item.get('deep_research_unresolved_refutation_count') if item.get('deep_research_unresolved_refutation_count') is not None else dres.get('unresolved_refutation_count')}")
            lines.append(f"- knowledge_updates: {item.get('deep_research_knowledge_update_count') if item.get('deep_research_knowledge_update_count') is not None else dres.get('knowledge_update_count')}")
            lines.append(f"- export_written: {item.get('deep_research_export_written') or dres.get('export_written')}")
            lines.append(f"- execution_allowed: {dres.get('execution_allowed')}")
            lines.append("")

        lhor = item.get("long_horizon") if isinstance(item.get("long_horizon"), dict) else {}
        if lhor or item.get("long_horizon_present"):
            lines.append("### Long Horizon (V4 plan-only)")
            lines.append(f"- status: {item.get('long_horizon_status') or lhor.get('status')}")
            lines.append(f"- paths: {item.get('long_horizon_path_count') if item.get('long_horizon_path_count') is not None else lhor.get('path_count')}")
            lines.append(f"- switches: {item.get('long_horizon_switch_count') if item.get('long_horizon_switch_count') is not None else lhor.get('switch_count')}")
            lines.append(f"- iterations: {item.get('long_horizon_iteration_count') if item.get('long_horizon_iteration_count') is not None else lhor.get('iteration_count')}")
            lines.append(f"- reflections: {item.get('long_horizon_reflection_count') if item.get('long_horizon_reflection_count') is not None else lhor.get('reflection_count')}")
            lines.append(f"- export_written: {item.get('long_horizon_export_written') or lhor.get('export_written')}")
            lines.append(f"- auto_path_switch_allowed: {lhor.get('auto_path_switch_allowed')}")
            lines.append(f"- execution_allowed: {lhor.get('execution_allowed')}")
            lines.append("")

        kbase = item.get("knowledge_base") if isinstance(item.get("knowledge_base"), dict) else {}
        if kbase or item.get("knowledge_base_present"):
            lines.append("### Knowledge Base (section-7 patterns)")
            lines.append(f"- status: {item.get('knowledge_base_status') or kbase.get('status')}")
            lines.append(f"- patterns: {item.get('knowledge_base_pattern_count') if item.get('knowledge_base_pattern_count') is not None else kbase.get('pattern_count')}")
            lines.append(f"- offline_artifacts: {item.get('knowledge_base_offline_artifact_count') if item.get('knowledge_base_offline_artifact_count') is not None else kbase.get('offline_artifact_count')}")
            lines.append(f"- derived: {item.get('knowledge_base_derived_pattern_count') if item.get('knowledge_base_derived_pattern_count') is not None else kbase.get('derived_pattern_count')}")
            lines.append(f"- export_written: {item.get('knowledge_base_export_written') or kbase.get('export_written')}")
            lines.append(f"- ranking_permission_granted: {kbase.get('ranking_permission_granted')}")
            lines.append(f"- execution_allowed: {kbase.get('execution_allowed')}")

        mhal = item.get("multi_hour_agent_loop") if isinstance(item.get("multi_hour_agent_loop"), dict) else {}
        if mhal or item.get("multi_hour_agent_loop_present"):
            lines.append("")
            lines.append("### Multi-Hour Agent Loop")
            lines.append(f"- status: {item.get('multi_hour_agent_loop_status') or mhal.get('status')}")
            lines.append(f"- phases: {item.get('multi_hour_agent_loop_phase_count') if item.get('multi_hour_agent_loop_phase_count') is not None else mhal.get('phase_count')}")
            lines.append(f"- sessions: {item.get('multi_hour_agent_loop_session_count') if item.get('multi_hour_agent_loop_session_count') is not None else mhal.get('session_count')}")
            lines.append(f"- human_gates: {item.get('multi_hour_agent_loop_gate_count') if item.get('multi_hour_agent_loop_gate_count') is not None else mhal.get('human_gate_count')}")
            lines.append(f"- handoffs: {item.get('multi_hour_agent_loop_handoff_count') if item.get('multi_hour_agent_loop_handoff_count') is not None else mhal.get('handoff_count')}")
            lines.append(f"- export_written: {item.get('multi_hour_agent_loop_export_written') or mhal.get('export_written')}")
            lines.append(f"- auto_tick_allowed: {mhal.get('auto_tick_allowed')}")
            lines.append(f"- execution_allowed: {mhal.get('execution_allowed')}")
            lines.append("")

        wclk = item.get("wall_clock_multi_hour_runner") if isinstance(item.get("wall_clock_multi_hour_runner"), dict) else {}
        if wclk or item.get("wall_clock_multi_hour_runner_present"):
            lines.append("")
            lines.append("### Wall-Clock Multi-Hour Runner")
            lines.append(f"- status: {item.get('wall_clock_multi_hour_runner_status') or wclk.get('status')}")
            lines.append(f"- slots: {item.get('wall_clock_multi_hour_runner_slot_count') if item.get('wall_clock_multi_hour_runner_slot_count') is not None else wclk.get('schedule_slot_count')}")
            lines.append(f"- ticks: {item.get('wall_clock_multi_hour_runner_tick_count') if item.get('wall_clock_multi_hour_runner_tick_count') is not None else wclk.get('tick_count')}")
            lines.append(f"- stop_conditions: {item.get('wall_clock_multi_hour_runner_stop_count') if item.get('wall_clock_multi_hour_runner_stop_count') is not None else wclk.get('stop_condition_count')}")
            lines.append(f"- export_written: {item.get('wall_clock_multi_hour_runner_export_written') or wclk.get('export_written')}")
            lines.append(f"- auto_tick_allowed: {wclk.get('auto_tick_allowed')}")
            lines.append(f"- execution_allowed: {wclk.get('execution_allowed')}")
            lines.append("")

        rpda = item.get("residual_patch_decision_api") if isinstance(item.get("residual_patch_decision_api"), dict) else {}
        if rpda or item.get("residual_patch_decision_api_present") or item.get("residual_patch_decision_api_status"):
            lines.append("")
            lines.append("### Residual Patch Decision API")
            lines.append(f"- status: {item.get('residual_patch_decision_api_status') or rpda.get('status')}")
            lines.append(f"- decisions: {item.get('residual_patch_decision_api_count') if item.get('residual_patch_decision_api_count') is not None else rpda.get('decision_count')}")
            lines.append(f"- decided: {item.get('residual_patch_decision_api_decided_count') if item.get('residual_patch_decision_api_decided_count') is not None else rpda.get('decided_count')}")
            lines.append(f"- residual: {item.get('residual_patch_decision_api_residual_count') if item.get('residual_patch_decision_api_residual_count') is not None else rpda.get('residual_count')}")
            lines.append(f"- patch: {item.get('residual_patch_decision_api_patch_count') if item.get('residual_patch_decision_api_patch_count') is not None else rpda.get('patch_count')}")
            lines.append(f"- export_written: {item.get('residual_patch_decision_api_export_written') or rpda.get('export_written')}")
            lines.append(f"- execution_allowed: {rpda.get('execution_allowed')}")
            lines.append(f"- patch_ready: {rpda.get('patch_ready')}")
            lines.append("")

    lines.extend(
        [
            "## Pass rule reminder",
            "",
            "- Drafts are not confirmed vulnerabilities.",
            "- multi_engine_verdict is local static agreement only; not exploit verification.",
            "- human_residual_gate never unlocks submission or live validation.",
            "- human_gate_dry_run never unlocks submission or live validation.",
            "- agent_memory is ranking/advisory only; never grants execute/submit/promote.",
            "- continuous_scan is cadence/plan only; never auto-scans public targets.",
            "- patch_validation is non-destructive recheck plan only; never live-validates or auto-PR.",
            "- deep_research is V4 multi-stage/variant plan only; never exploits, execute, or submit.",
            "- variant_analysis is V4 first-class sibling search plan only; never exploits, promote, or submit.",
            "- vuln_chain_builder is V4 first-class multi-stage chain plan only; never exploits, promote, or submit.",
            "- deep_code_reasoning is V4 first-class permission/cross-file plan only; never exploits, promote, or submit.",
            "- finding_dedup_risk is plan-only clusters + risk queue; never promotes, ranks as permission, or submits.",
            "- long_horizon is V4 path-switch/reflection plan only; never auto-switches, executes, or submits.",
            "- knowledge_base is section-7 structured pattern catalog only; never grants ranking/execute/submit.",
            "- multi_hour_agent_loop is multi-session budget/handoff plan only; never auto-ticks, executes, or submits.",
            "- wall_clock_multi_hour_runner is wall-clock schedule/tick-ledger only; never auto-ticks, executes, or submits.",
            "- residual_patch_decision_api is offline decision snapshot/export/import only; never unlocks execute/submit/patch_ready.",
            "- Submission remains blocked.",
            "- Teaching labs must not be treated as bounty submissions.",
            "",
        ]
    )
    return "\n".join(lines)


if __name__ == "__main__":
    raise SystemExit(main())
