"""Multi-engine verifier scaffold for beyond-A+B factory stages.

Lawful research only:
- Does not execute live validation or attacks
- Does not submit reports
- Does not promote model/scanner/hunter output to confirmed vulnerabilities
- Aggregates local static engines + human evidence prep for review

Engines (v0/v1 + deeper factory stack):
1. hunter_loop - retained/refuted dispositions from A+B candidate hunter
2. codebase_map - gap / control facts from static code mapping
3. report_bridge - submission-blocked draft readiness
4. human_evidence - optional redacted notes (never secrets)
5. semgrep_advisory - offline Semgrep/SARIF findings (advisory only)
6. codeql_advisory - offline CodeQL/SARIF findings (advisory only)
7. crs_fuzzing - plan-only parser/harness candidates (never executed)
8. residual_runner - local static residual probes under human approval
9. authorized_web_api - plan-only role-diff / API surface
10. human_residual_gate - human residual gate disposition
11. semgrep_runner / codeql_runner - local CLI runner posture (advisory)

Status machine (Verifier Agent subset):
  needs_verification
    -> local_static_consistent | needs_human_review | false_positive_likely | blocked
  Never emits verified_exploited or submission_ready.
"""

from __future__ import annotations

import re
from typing import Any

from pydantic import BaseModel, Field


VERDICT_NEEDS_VERIFICATION = "needs_verification"
VERDICT_LOCAL_STATIC_CONSISTENT = "local_static_consistent"
VERDICT_NEEDS_HUMAN_REVIEW = "needs_human_review"
VERDICT_FALSE_POSITIVE_LIKELY = "false_positive_likely"
VERDICT_BLOCKED = "blocked"

ENGINE_HUNTER = "hunter_loop"
ENGINE_CODEBASE_MAP = "codebase_map"
ENGINE_REPORT_BRIDGE = "report_bridge"
ENGINE_HUMAN_EVIDENCE = "human_evidence"
ENGINE_SEMGREP = "semgrep_advisory"
ENGINE_CODEQL = "codeql_advisory"
ENGINE_CRS_FUZZING = "crs_fuzzing"
ENGINE_LOCAL_FUZZ_SANDBOX = "local_fuzz_sandbox"
ENGINE_LOCAL_FUZZ_RUNNER = "local_fuzz_runner"
ENGINE_CRASH_TRIAGE = "crash_triage"
ENGINE_CRASH_REGRESSION = "crash_regression"
ENGINE_CRASH_CODEPATH = "crash_codepath"
ENGINE_PROTOCOL_AWARE_FUZZING = "protocol_aware_fuzzing"
ENGINE_PATCH_DIFF_LEARNER = "patch_diff_learner"
ENGINE_VARIANT_ANALYSIS = "variant_analysis"
ENGINE_VULN_CHAIN_BUILDER = "vuln_chain_builder"
ENGINE_DEEP_CODE_REASONING = "deep_code_reasoning"
ENGINE_FINDING_DEDUP_RISK = "finding_dedup_risk"
ENGINE_HUMAN_GATE_DRY_RUN = "human_gate_dry_run"
ENGINE_AGENT_MEMORY = "agent_memory"
ENGINE_CONTINUOUS_SCAN = "continuous_scan"
ENGINE_PATCH_VALIDATION = "patch_validation"
ENGINE_DEEP_RESEARCH = "deep_research"
ENGINE_LONG_HORIZON = "long_horizon"
ENGINE_KNOWLEDGE_BASE = "knowledge_base"
ENGINE_MULTI_HOUR_AGENT_LOOP = "multi_hour_agent_loop"
ENGINE_WALL_CLOCK_MULTI_HOUR_RUNNER = "wall_clock_multi_hour_runner"
ENGINE_HUMAN_REVIEW_APPROVALS = "human_review_approvals"
ENGINE_RESIDUAL_PATCH_DECISION_API = "residual_patch_decision_api"
ENGINE_RESIDUAL_RUNNER = "residual_runner"
ENGINE_AUTHORIZED_WEB_API = "authorized_web_api"
ENGINE_RESIDUAL_GATE = "human_residual_gate"
ENGINE_SEMGREP_RUNNER = "semgrep_runner"
ENGINE_CODEQL_RUNNER = "codeql_runner"

ALLOWED_VERDICTS = {
    VERDICT_NEEDS_VERIFICATION,
    VERDICT_LOCAL_STATIC_CONSISTENT,
    VERDICT_NEEDS_HUMAN_REVIEW,
    VERDICT_FALSE_POSITIVE_LIKELY,
    VERDICT_BLOCKED,
}


class EngineSignal(BaseModel):
    engine: str
    status: str
    supports_candidate: bool | None = None
    notes: list[str] = Field(default_factory=list)
    evidence_refs: list[str] = Field(default_factory=list)


class MultiEngineVerdict(BaseModel):
    status: str
    candidate_id: str = ""
    root_cause_id: str = ""
    engines: list[EngineSignal] = Field(default_factory=list)
    agreement_score: float = 0.0
    blocked_reasons: list[str] = Field(default_factory=list)
    review_questions: list[str] = Field(default_factory=list)
    next_allowed_action: str = "Human review of local evidence only."
    execution_allowed: bool = False
    validation_allowed: bool = False
    report_submission_allowed: bool = False
    finding_promotion_allowed: bool = False
    confirmed_vulnerability: bool = False
    safety_blockers: list[str] = Field(
        default_factory=lambda: [
            "execute_live_validation",
            "touch_real_user_data",
            "submit_report",
            "auto_promote_finding",
        ]
    )


class MultiEngineVerifierError(ValueError):
    pass


def build_multi_engine_verdict(
    *,
    candidate: dict[str, Any] | None = None,
    hunter_signal: dict[str, Any] | None = None,
    codebase_map_signal: dict[str, Any] | None = None,
    report_bridge_signal: dict[str, Any] | None = None,
    human_evidence_signal: dict[str, Any] | None = None,
    semgrep_signal: dict[str, Any] | None = None,
    codeql_signal: dict[str, Any] | None = None,
    crs_fuzzing_signal: dict[str, Any] | None = None,
    local_fuzz_sandbox_signal: dict[str, Any] | None = None,
    local_fuzz_runner_signal: dict[str, Any] | None = None,
    crash_triage_signal: dict[str, Any] | None = None,
    crash_regression_signal: dict[str, Any] | None = None,
    crash_codepath_signal: dict[str, Any] | None = None,
    protocol_aware_fuzzing_signal: dict[str, Any] | None = None,
    patch_diff_learner_signal: dict[str, Any] | None = None,
    variant_analysis_signal: dict[str, Any] | None = None,
    vuln_chain_builder_signal: dict[str, Any] | None = None,
    deep_code_reasoning_signal: dict[str, Any] | None = None,
    finding_dedup_risk_signal: dict[str, Any] | None = None,
    human_gate_dry_run_signal: dict[str, Any] | None = None,
    agent_memory_signal: dict[str, Any] | None = None,
    continuous_scan_signal: dict[str, Any] | None = None,
    patch_validation_signal: dict[str, Any] | None = None,
    deep_research_signal: dict[str, Any] | None = None,
    long_horizon_signal: dict[str, Any] | None = None,
    knowledge_base_signal: dict[str, Any] | None = None,
    multi_hour_agent_loop_signal: dict[str, Any] | None = None,
    wall_clock_multi_hour_runner_signal: dict[str, Any] | None = None,
    human_review_approvals_signal: dict[str, Any] | None = None,
    residual_patch_decision_api_signal: dict[str, Any] | None = None,
    residual_runner_signal: dict[str, Any] | None = None,
    authorized_web_api_signal: dict[str, Any] | None = None,
    residual_gate_signal: dict[str, Any] | None = None,
    semgrep_runner_signal: dict[str, Any] | None = None,
    codeql_runner_signal: dict[str, Any] | None = None,
    extra_engine_signals: list[dict[str, Any]] | None = None,
    scope_allowed: bool = True,
) -> MultiEngineVerdict:
    """Aggregate multi-engine signals into a non-executing verification verdict."""
    candidate = candidate if isinstance(candidate, dict) else {}
    candidate_id = str(candidate.get("candidate_id") or "")
    root_cause_id = str(candidate.get("root_cause_id") or "")

    blocked: list[str] = []
    if scope_allowed is False:
        blocked.append("scope_not_allowed")
    for flag, reason in (
        ("execution_allowed", "candidate_execution_allowed_true"),
        ("validation_allowed", "candidate_validation_allowed_true"),
        ("report_submission_allowed", "candidate_report_submission_allowed_true"),
    ):
        if candidate.get(flag) is True:
            blocked.append(reason)

    engines: list[EngineSignal] = []
    if hunter_signal is not None:
        engines.append(_normalize_engine(ENGINE_HUNTER, hunter_signal))
    if codebase_map_signal is not None:
        engines.append(_normalize_engine(ENGINE_CODEBASE_MAP, codebase_map_signal))
    if report_bridge_signal is not None:
        engines.append(_normalize_engine(ENGINE_REPORT_BRIDGE, report_bridge_signal))
    if human_evidence_signal is not None:
        engines.append(_normalize_engine(ENGINE_HUMAN_EVIDENCE, human_evidence_signal))
    if semgrep_signal is not None:
        engines.append(_normalize_engine(ENGINE_SEMGREP, semgrep_signal))
    if codeql_signal is not None:
        engines.append(_normalize_engine(ENGINE_CODEQL, codeql_signal))
    if crs_fuzzing_signal is not None:
        engines.append(_normalize_engine(ENGINE_CRS_FUZZING, crs_fuzzing_signal))
    if local_fuzz_sandbox_signal is not None:
        engines.append(_normalize_engine(ENGINE_LOCAL_FUZZ_SANDBOX, local_fuzz_sandbox_signal))
    if local_fuzz_runner_signal is not None:
        engines.append(_normalize_engine(ENGINE_LOCAL_FUZZ_RUNNER, local_fuzz_runner_signal))
    if crash_triage_signal is not None:
        engines.append(_normalize_engine(ENGINE_CRASH_TRIAGE, crash_triage_signal))
    if crash_regression_signal is not None:
        engines.append(_normalize_engine(ENGINE_CRASH_REGRESSION, crash_regression_signal))
    if crash_codepath_signal is not None:
        engines.append(_normalize_engine(ENGINE_CRASH_CODEPATH, crash_codepath_signal))
    if protocol_aware_fuzzing_signal is not None:
        engines.append(_normalize_engine(ENGINE_PROTOCOL_AWARE_FUZZING, protocol_aware_fuzzing_signal))
    if patch_diff_learner_signal is not None:
        engines.append(_normalize_engine(ENGINE_PATCH_DIFF_LEARNER, patch_diff_learner_signal))
    if variant_analysis_signal is not None:
        engines.append(_normalize_engine(ENGINE_VARIANT_ANALYSIS, variant_analysis_signal))
    if vuln_chain_builder_signal is not None:
        engines.append(_normalize_engine(ENGINE_VULN_CHAIN_BUILDER, vuln_chain_builder_signal))
    if deep_code_reasoning_signal is not None:
        engines.append(_normalize_engine(ENGINE_DEEP_CODE_REASONING, deep_code_reasoning_signal))
    if finding_dedup_risk_signal is not None:
        engines.append(_normalize_engine(ENGINE_FINDING_DEDUP_RISK, finding_dedup_risk_signal))
    if human_gate_dry_run_signal is not None:
        engines.append(_normalize_engine(ENGINE_HUMAN_GATE_DRY_RUN, human_gate_dry_run_signal))
    if agent_memory_signal is not None:
        engines.append(_normalize_engine(ENGINE_AGENT_MEMORY, agent_memory_signal))
    if continuous_scan_signal is not None:
        engines.append(_normalize_engine(ENGINE_CONTINUOUS_SCAN, continuous_scan_signal))
    if patch_validation_signal is not None:
        engines.append(_normalize_engine(ENGINE_PATCH_VALIDATION, patch_validation_signal))
    if deep_research_signal is not None:
        engines.append(_normalize_engine(ENGINE_DEEP_RESEARCH, deep_research_signal))
    if long_horizon_signal is not None:
        engines.append(_normalize_engine(ENGINE_LONG_HORIZON, long_horizon_signal))
    if knowledge_base_signal is not None:
        engines.append(_normalize_engine(ENGINE_KNOWLEDGE_BASE, knowledge_base_signal))
    if multi_hour_agent_loop_signal is not None:
        engines.append(_normalize_engine(ENGINE_MULTI_HOUR_AGENT_LOOP, multi_hour_agent_loop_signal))
    if wall_clock_multi_hour_runner_signal is not None:
        engines.append(_normalize_engine(ENGINE_WALL_CLOCK_MULTI_HOUR_RUNNER, wall_clock_multi_hour_runner_signal))
    if human_review_approvals_signal is not None:
        engines.append(_normalize_engine(ENGINE_HUMAN_REVIEW_APPROVALS, human_review_approvals_signal))
    if residual_patch_decision_api_signal is not None:
        engines.append(_normalize_engine(ENGINE_RESIDUAL_PATCH_DECISION_API, residual_patch_decision_api_signal))
    if residual_runner_signal is not None:
        engines.append(_normalize_engine(ENGINE_RESIDUAL_RUNNER, residual_runner_signal))
    if authorized_web_api_signal is not None:
        engines.append(_normalize_engine(ENGINE_AUTHORIZED_WEB_API, authorized_web_api_signal))
    if residual_gate_signal is not None:
        engines.append(_normalize_engine(ENGINE_RESIDUAL_GATE, residual_gate_signal))
    if semgrep_runner_signal is not None:
        engines.append(_normalize_engine(ENGINE_SEMGREP_RUNNER, semgrep_runner_signal))
    if codeql_runner_signal is not None:
        engines.append(_normalize_engine(ENGINE_CODEQL_RUNNER, codeql_runner_signal))
    for raw in extra_engine_signals or []:
        if not isinstance(raw, dict):
            continue
        name = str(raw.get("engine") or "").strip()
        if not name:
            continue
        engines.append(_normalize_engine(name, raw))

    # Knowledge-base entries remain visible for explanation and ranking, but do
    # not prove or refute a current candidate.
    candidate_decision_engines = [
        engine for engine in engines if engine.engine != ENGINE_KNOWLEDGE_BASE
    ]
    blocking_engines = [
        engine
        for engine in engines
        if engine.engine != ENGINE_KNOWLEDGE_BASE
        or "knowledge_base_unsafe_flags_forced_block" in engine.notes
    ]

    if not engines:
        return MultiEngineVerdict(
            status=VERDICT_NEEDS_VERIFICATION,
            candidate_id=candidate_id,
            root_cause_id=root_cause_id,
            engines=[],
            agreement_score=0.0,
            blocked_reasons=blocked or ["no_engine_signals"],
            review_questions=[
                "Provide at least one local engine signal (hunter, map, bridge, residual, CRS, Web/API, semgrep, or codeql).",
            ],
            next_allowed_action="Collect local static engine signals; do not execute live validation.",
        )

    if blocked:
        return MultiEngineVerdict(
            status=VERDICT_BLOCKED,
            candidate_id=candidate_id,
            root_cause_id=root_cause_id,
            engines=engines,
            agreement_score=_agreement_score(candidate_decision_engines),
            blocked_reasons=blocked,
            review_questions=[
                "Resolve safety/scope blockers before any human-controlled validation planning.",
            ],
            next_allowed_action="Stop. Clear blockers under Scope Guard; no execution.",
        )

    supports = [e for e in candidate_decision_engines if e.supports_candidate is True]
    opposes = [e for e in candidate_decision_engines if e.supports_candidate is False]
    unknown = [e for e in candidate_decision_engines if e.supports_candidate is None]
    agreement = _agreement_score(candidate_decision_engines)

    if any(e.status in {"blocked", "error"} for e in blocking_engines):
        status = (
            VERDICT_BLOCKED
            if any(e.status == "blocked" for e in blocking_engines)
            else VERDICT_NEEDS_HUMAN_REVIEW
        )
        return MultiEngineVerdict(
            status=status,
            candidate_id=candidate_id,
            root_cause_id=root_cause_id,
            engines=engines,
            agreement_score=agreement,
            blocked_reasons=[
                f"engine_{e.engine}_{e.status}"
                for e in blocking_engines
                if e.status in {"blocked", "error"}
            ],
            review_questions=_default_questions(candidate),
            next_allowed_action="Human review required due to engine error/block.",
        )

    if opposes and not supports:
        status = VERDICT_FALSE_POSITIVE_LIKELY
        next_action = "Treat as likely false positive; keep submission blocked."
    elif supports and not opposes and not unknown and agreement >= 1.0:
        status = VERDICT_LOCAL_STATIC_CONSISTENT
        next_action = (
            "Local engines agree this remains an unverified candidate worth human review. "
            "Do not execute live validation or submit a report."
        )
    elif supports and opposes:
        status = VERDICT_NEEDS_HUMAN_REVIEW
        next_action = "Engines disagree; human must reconcile before any validation planning."
    elif supports and unknown:
        status = VERDICT_NEEDS_HUMAN_REVIEW
        next_action = "Partial engine support only; gather remaining local evidence."
    else:
        status = VERDICT_NEEDS_VERIFICATION
        next_action = "Insufficient agreement; continue local static evidence collection."

    return MultiEngineVerdict(
        status=status,
        candidate_id=candidate_id,
        root_cause_id=root_cause_id,
        engines=engines,
        agreement_score=agreement,
        blocked_reasons=[],
        review_questions=_default_questions(candidate),
        next_allowed_action=next_action,
    )


def verdict_from_hunter_and_map(
    *,
    candidate: dict[str, Any],
    gap_root_causes: list[str] | None = None,
    control_refs: list[str] | None = None,
    report_submission_blocked: bool = True,
    scope_allowed: bool = True,
    semgrep_signal: dict[str, Any] | None = None,
    codeql_signal: dict[str, Any] | None = None,
    crs_fuzzing_signal: dict[str, Any] | None = None,
    local_fuzz_sandbox_signal: dict[str, Any] | None = None,
    local_fuzz_runner_signal: dict[str, Any] | None = None,
    crash_triage_signal: dict[str, Any] | None = None,
    residual_runner_signal: dict[str, Any] | None = None,
    authorized_web_api_signal: dict[str, Any] | None = None,
    residual_gate_signal: dict[str, Any] | None = None,
    semgrep_runner_signal: dict[str, Any] | None = None,
    codeql_runner_signal: dict[str, Any] | None = None,
) -> MultiEngineVerdict:
    """Convenience builder from hunter retained card + codebase map summaries."""
    disposition = str(candidate.get("disposition") or "").lower()
    root = str(candidate.get("root_cause_id") or "")
    gap_root_causes = [str(x) for x in (gap_root_causes or [])]
    control_refs = [str(x) for x in (control_refs or [])]

    if disposition in {"retained", "retain"}:
        hunter = {
            "status": "ready",
            "supports_candidate": True,
            "notes": [f"hunter_disposition={disposition}"],
            "evidence_refs": list(
                candidate.get("source_fact_refs")
                or candidate.get("evidence_refs")
                or []
            )[:12],
        }
    elif disposition in {
        "refuted",
        "refute",
        "deduplicated",
        "deduplicate",
        "suppress",
        "suppressed",
    }:
        hunter = {
            "status": "ready",
            "supports_candidate": False,
            "notes": [f"hunter_disposition={disposition}"],
            "evidence_refs": list(candidate.get("evidence_refs") or [])[:12],
        }
    else:
        hunter = {
            "status": "pending",
            "supports_candidate": None,
            "notes": [f"hunter_disposition={disposition or 'unknown'}"],
            "evidence_refs": [],
        }

    root_base = root.split(":")[0] if root else ""
    map_notes: list[str] = []
    if any(root == g or (root_base and g.startswith(root_base)) for g in gap_root_causes):
        map_support: bool | None = True
        map_notes.append("codebase_map_gap_matches_candidate_root")
    elif control_refs and disposition in {"refuted", "refute"}:
        map_support = False
        map_notes.append("codebase_map_control_present")
    elif control_refs and disposition in {"retained", "retain"}:
        map_support = False
        map_notes.append("codebase_map_control_conflicts_with_retain")
    elif gap_root_causes:
        map_support = False
        map_notes.append("codebase_map_gaps_do_not_match_root")
    else:
        map_support = None
        map_notes.append("codebase_map_no_gap_signal")

    map_signal = {
        "status": "ready",
        "supports_candidate": map_support,
        "notes": map_notes,
        "evidence_refs": control_refs[:12] + gap_root_causes[:12],
    }

    if not report_submission_blocked:
        bridge = {
            "status": "blocked",
            "supports_candidate": False,
            "notes": ["report_bridge_must_remain_submission_blocked"],
            "evidence_refs": [],
        }
    elif disposition in {"retained", "retain"}:
        # Bridge health for retained unverified candidates only
        bridge = {
            "status": "ready",
            "supports_candidate": True,
            "notes": ["submission_blocked", "not_a_confirmed_vulnerability"],
            "evidence_refs": [],
        }
    elif disposition in {
        "refuted",
        "refute",
        "deduplicated",
        "deduplicate",
        "suppress",
        "suppressed",
    }:
        bridge = {
            "status": "ready",
            "supports_candidate": False,
            "notes": ["submission_blocked", "hunter_not_retained"],
            "evidence_refs": [],
        }
    else:
        bridge = {
            "status": "ready",
            "supports_candidate": None,
            "notes": ["submission_blocked", "disposition_unknown"],
            "evidence_refs": [],
        }

    return build_multi_engine_verdict(
        candidate=candidate,
        hunter_signal=hunter,
        codebase_map_signal=map_signal,
        report_bridge_signal=bridge,
        semgrep_signal=semgrep_signal,
        codeql_signal=codeql_signal,
        crs_fuzzing_signal=crs_fuzzing_signal,
        local_fuzz_sandbox_signal=local_fuzz_sandbox_signal,
        local_fuzz_runner_signal=local_fuzz_runner_signal,
        crash_triage_signal=crash_triage_signal,
        residual_runner_signal=residual_runner_signal,
        authorized_web_api_signal=authorized_web_api_signal,
        residual_gate_signal=residual_gate_signal,
        semgrep_runner_signal=semgrep_runner_signal,
        codeql_runner_signal=codeql_runner_signal,
        scope_allowed=scope_allowed,
    )



def signal_from_crs_fuzzing(
    crs_fuzzing: dict[str, Any] | None,
    *,
    candidate: dict[str, Any] | None = None,
) -> dict[str, Any] | None:
    """Plan-only CRS signal; never implies fuzzer execution or confirmed vuln."""
    if not isinstance(crs_fuzzing, dict):
        return None
    if crs_fuzzing.get("execution_allowed") is True or crs_fuzzing.get("finding_promotion_allowed") is True:
        return {
            "status": "blocked",
            "supports_candidate": False,
            "notes": ["crs_unsafe_flags_forced_block"],
            "evidence_refs": [],
        }
    status_raw = str(crs_fuzzing.get("status") or "")
    candidates = list(crs_fuzzing.get("parser_candidates") or [])
    harnesses = list(crs_fuzzing.get("harness_plans") or [])
    count = int(crs_fuzzing.get("candidate_count") or len(candidates) or 0)
    notes = [
        f"crs_status={status_raw or 'unknown'}",
        f"crs_candidate_count={count}",
        "plan_only_no_fuzzer_execution",
    ]
    cand = candidate if isinstance(candidate, dict) else {}
    path = str(cand.get("affected_code_path") or cand.get("source_path") or "")
    path_l = path.lower()
    matched = False
    for item in candidates + harnesses:
        if not isinstance(item, dict):
            continue
        blob = " ".join(
            str(item.get(k) or "")
            for k in ("source_path", "symbol_name", "target_symbol", "reason")
        ).lower()
        if path_l and path_l.split(":")[-1] and path_l.split(":")[-1] in blob:
            matched = True
            break
        if any(tok and tok in blob for tok in _path_tokens(path_l)):
            matched = True
            break
    if status_raw in {"crs_fuzzing_package_missing", "crs_fuzzing_no_code_files"}:
        return {
            "status": "pending",
            "supports_candidate": None,
            "notes": notes + ["crs_package_or_code_missing"],
            "evidence_refs": [],
        }
    if count <= 0 and not matched:
        return {
            "status": "ready",
            "supports_candidate": None,
            "notes": notes + ["no_parser_candidates"],
            "evidence_refs": [],
        }
    if matched:
        supports: bool | None = True
        notes.append("crs_candidate_path_overlap")
    else:
        supports = None
        notes.append("crs_candidates_present_no_path_match")
    return {
        "status": "ready",
        "supports_candidate": supports,
        "notes": notes[:12],
        "evidence_refs": [
            f"crs:{c.get('symbol_name') or c.get('target_symbol') or 'candidate'}"
            for c in (candidates or harnesses)[:6]
            if isinstance(c, dict)
        ],
    }



def signal_from_local_fuzz_sandbox(
    local_fuzz_sandbox: dict[str, Any] | None,
    *,
    candidate: dict[str, Any] | None = None,
) -> dict[str, Any] | None:
    """Plan-only local fuzz sandbox signal; never implies fuzzer execution."""
    if not isinstance(local_fuzz_sandbox, dict):
        return None
    if (
        local_fuzz_sandbox.get("execution_allowed") is True
        or local_fuzz_sandbox.get("process_spawn_allowed") is True
        or local_fuzz_sandbox.get("finding_promotion_allowed") is True
        or local_fuzz_sandbox.get("crash_promotion_allowed") is True
    ):
        return {
            "status": "blocked",
            "supports_candidate": False,
            "notes": ["local_fuzz_sandbox_unsafe_flags_forced_block"],
            "evidence_refs": [],
        }
    status_raw = str(local_fuzz_sandbox.get("status") or "")
    targets = list(local_fuzz_sandbox.get("targets") or [])
    count = int(local_fuzz_sandbox.get("target_count") or len(targets) or 0)
    notes = [
        f"sandbox_status={status_raw or 'unknown'}",
        f"sandbox_target_count={count}",
        "plan_only_no_fuzzer_execution",
        f"export_written={bool(local_fuzz_sandbox.get('sandbox_export_written'))}",
    ]
    return {
        "status": "advisory" if count or status_raw else "empty",
        "supports_candidate": False,
        "notes": notes[:12],
        "evidence_refs": [
            f"sandbox:{t.get('target_symbol') or 'target'}"
            for t in targets[:6]
            if isinstance(t, dict)
        ],
    }



def signal_from_local_fuzz_runner(
    local_fuzz_runner: dict[str, Any] | None,
    *,
    candidate: dict[str, Any] | None = None,
) -> dict[str, Any] | None:
    """Map local fuzz runner posture into a multi-engine signal (never promotes)."""
    del candidate  # reserved for future candidate-aware weighting
    if not isinstance(local_fuzz_runner, dict):
        return None
    if (
        local_fuzz_runner.get("crash_promotion_allowed") is True
        or local_fuzz_runner.get("finding_promotion_allowed") is True
        or local_fuzz_runner.get("report_submission_allowed") is True
        or local_fuzz_runner.get("external_fuzzer_spawn_allowed") is True
        or local_fuzz_runner.get("process_spawn_allowed") is True
    ):
        return {
            "status": "blocked",
            "supports_candidate": False,
            "notes": ["local_fuzz_runner_unsafe_flags_forced_block"],
            "evidence_refs": [],
        }
    status_raw = str(local_fuzz_runner.get("status") or "")
    crash_count = int(local_fuzz_runner.get("crash_count") or 0)
    executed = bool(local_fuzz_runner.get("in_process_run_executed"))
    notes = [
        f"status={status_raw or 'unknown'}",
        f"executed={executed}",
        f"crash_count={crash_count}",
        f"runnable={int(local_fuzz_runner.get('runnable_target_count') or 0)}",
        "crash_promotion_blocked",
        "external_fuzzer_not_spawned",
    ]
    if status_raw or executed or crash_count:
        return {
            "status": "ready",
            "supports_candidate": None,
            "notes": notes,
            "evidence_refs": (
                ["local_fuzz_runner:crashes"] if crash_count else ["local_fuzz_runner:plan"]
            ),
        }
    return {
        "status": "empty",
        "supports_candidate": None,
        "notes": notes,
        "evidence_refs": [],
    }



def signal_from_crash_triage(
    crash_triage: dict[str, Any] | None,
    *,
    candidate: dict[str, Any] | None = None,
) -> dict[str, Any] | None:
    """Map crash triage posture into multi-engine signal (never promotes)."""
    del candidate
    if not isinstance(crash_triage, dict):
        return None
    if (
        crash_triage.get("crash_promotion_allowed") is True
        or crash_triage.get("finding_promotion_allowed") is True
        or crash_triage.get("report_submission_allowed") is True
        or crash_triage.get("process_spawn_allowed") is True
    ):
        return {
            "status": "blocked",
            "supports_candidate": False,
            "notes": ["crash_triage_unsafe_flags_forced_block"],
            "evidence_refs": [],
        }
    status_raw = str(crash_triage.get("status") or "")
    clusters = int(crash_triage.get("unique_cluster_count") or 0)
    repro = int(crash_triage.get("reproducible_count") or 0)
    mini = int(crash_triage.get("minimized_count") or 0)
    executed = bool(crash_triage.get("triage_executed"))
    notes = [
        f"status={status_raw or 'unknown'}",
        f"executed={executed}",
        f"clusters={clusters}",
        f"reproducible={repro}",
        f"minimized={mini}",
        "crash_promotion_blocked",
        "advisory_root_cause_only",
    ]
    if status_raw or executed or clusters:
        return {
            "status": "ready",
            "supports_candidate": None,
            "notes": notes,
            "evidence_refs": (
                ["crash_triage:clusters"] if clusters else ["crash_triage:plan"]
            ),
        }
    return {
        "status": "empty",
        "supports_candidate": None,
        "notes": notes,
        "evidence_refs": [],
    }



def signal_from_crash_regression(
    crash_regression: dict[str, Any] | None,
    *,
    candidate: dict[str, Any] | None = None,
) -> dict[str, Any] | None:
    """Map crash residual regression posture into multi-engine signal (never executes)."""
    del candidate
    if not isinstance(crash_regression, dict):
        return None
    if (
        crash_regression.get("crash_promotion_allowed") is True
        or crash_regression.get("finding_promotion_allowed") is True
        or crash_regression.get("report_submission_allowed") is True
        or crash_regression.get("test_auto_execute_allowed") is True
        or crash_regression.get("execution_allowed") is True
        or crash_regression.get("validation_allowed") is True
    ):
        return {
            "status": "blocked",
            "supports_candidate": False,
            "notes": ["crash_regression_unsafe_flags_forced_block"],
            "evidence_refs": [],
        }
    status_raw = str(crash_regression.get("status") or "")
    suggestions = int(
        crash_regression.get("suggestion_count")
        or len(crash_regression.get("suggestions") or [])
        or 0
    )
    repro = int(crash_regression.get("reproducible_linked_count") or 0)
    mini = int(crash_regression.get("minimized_linked_count") or 0)
    notes = [
        f"status={status_raw or 'unknown'}",
        f"suggestions={suggestions}",
        f"reproducible_linked={repro}",
        f"minimized_linked={mini}",
        "test_auto_execute_blocked",
        "plan_only_regression",
    ]
    if status_raw or suggestions:
        return {
            "status": "ready",
            "supports_candidate": None,
            "notes": notes,
            "evidence_refs": (
                ["crash_regression:suggestions"] if suggestions else ["crash_regression:plan"]
            ),
        }
    return {
        "status": "empty",
        "supports_candidate": None,
        "notes": notes,
        "evidence_refs": [],
    }




def signal_from_crash_codepath(
    crash_codepath: dict[str, Any] | None,
    *,
    candidate: dict[str, Any] | None = None,
) -> dict[str, Any] | None:
    """Map crash code-path linking posture into multi-engine signal (advisory only)."""
    del candidate
    if not isinstance(crash_codepath, dict):
        return None
    if (
        crash_codepath.get("crash_promotion_allowed") is True
        or crash_codepath.get("finding_promotion_allowed") is True
        or crash_codepath.get("report_submission_allowed") is True
        or crash_codepath.get("package_code_execution_allowed") is True
        or crash_codepath.get("execution_allowed") is True
        or crash_codepath.get("validation_allowed") is True
    ):
        return {
            "status": "blocked",
            "supports_candidate": False,
            "notes": ["crash_codepath_unsafe_flags_forced_block"],
            "evidence_refs": [],
        }
    status_raw = str(crash_codepath.get("status") or "")
    links = int(
        crash_codepath.get("link_count")
        or len(crash_codepath.get("links") or [])
        or 0
    )
    resolved = int(crash_codepath.get("resolved_count") or 0)
    primary = int(crash_codepath.get("primary_path_count") or 0)
    notes = [
        f"status={status_raw or 'unknown'}",
        f"links={links}",
        f"resolved={resolved}",
        f"primary_paths={primary}",
        "package_code_execution_blocked",
        "advisory_code_path_only",
    ]
    if status_raw or links:
        return {
            "status": "ready",
            "supports_candidate": None,
            "notes": notes,
            "evidence_refs": (
                ["crash_codepath:links"] if links else ["crash_codepath:plan"]
            ),
        }
    return {
        "status": "empty",
        "supports_candidate": None,
        "notes": notes,
        "evidence_refs": [],
    }



def signal_from_protocol_aware_fuzzing(
    protocol_aware_fuzzing: dict[str, Any] | None,
    *,
    candidate: dict[str, Any] | None = None,
) -> dict[str, Any] | None:
    """Plan-only protocol-aware fuzzing signal; never implies fuzzer execution."""
    del candidate
    if not isinstance(protocol_aware_fuzzing, dict):
        return None
    if (
        protocol_aware_fuzzing.get("execution_allowed") is True
        or protocol_aware_fuzzing.get("process_spawn_allowed") is True
        or protocol_aware_fuzzing.get("finding_promotion_allowed") is True
        or protocol_aware_fuzzing.get("crash_promotion_allowed") is True
        or protocol_aware_fuzzing.get("report_submission_allowed") is True
        or protocol_aware_fuzzing.get("validation_allowed") is True
        or protocol_aware_fuzzing.get("live_validation") is True
        or protocol_aware_fuzzing.get("network_access") is True
    ):
        return {
            "status": "blocked",
            "supports_candidate": False,
            "notes": ["protocol_aware_fuzzing_unsafe_flags_forced_block"],
            "evidence_refs": [],
        }
    status_raw = str(protocol_aware_fuzzing.get("status") or "")
    targets = list(protocol_aware_fuzzing.get("targets") or [])
    count = int(protocol_aware_fuzzing.get("target_count") or len(targets) or 0)
    grammar = int(protocol_aware_fuzzing.get("grammar_plan_count") or 0)
    seeds = int(protocol_aware_fuzzing.get("seed_plan_count") or 0)
    notes = [
        f"paf_status={status_raw or 'unknown'}",
        f"paf_target_count={count}",
        f"grammar_plans={grammar}",
        f"seed_plans={seeds}",
        "plan_only_no_protocol_fuzzer_execution",
        f"export_written={bool(protocol_aware_fuzzing.get('export_written'))}",
    ]
    return {
        "status": "advisory" if count or status_raw else "empty",
        "supports_candidate": False,
        "notes": notes[:12],
        "evidence_refs": [
            f"paf:{(t.get('target_symbol') if isinstance(t, dict) else None) or 'target'}"
            for t in targets[:6]
            if isinstance(t, dict)
        ],
    }

def signal_from_patch_diff_learner(
    patch_diff_learner: dict[str, Any] | None,
    *,
    candidate: dict[str, Any] | None = None,
) -> dict[str, Any] | None:
    """Plan-only patch-diff learner signal; never implies apply/PR/submit."""
    del candidate
    if not isinstance(patch_diff_learner, dict):
        return None
    if (
        patch_diff_learner.get("execution_allowed") is True
        or patch_diff_learner.get("process_spawn_allowed") is True
        or patch_diff_learner.get("finding_promotion_allowed") is True
        or patch_diff_learner.get("report_submission_allowed") is True
        or patch_diff_learner.get("validation_allowed") is True
        or patch_diff_learner.get("live_validation") is True
        or patch_diff_learner.get("network_access") is True
        or patch_diff_learner.get("auto_pr_allowed") is True
        or patch_diff_learner.get("patch_ready") is True
        or patch_diff_learner.get("pr_opened") is True
        or patch_diff_learner.get("confirmed_vulnerability") is True
    ):
        return {
            "status": "blocked",
            "supports_candidate": False,
            "notes": ["patch_diff_learner_unsafe_flags_forced_block"],
            "evidence_refs": [],
        }
    status_raw = str(patch_diff_learner.get("status") or "")
    patterns = list(patch_diff_learner.get("patterns") or [])
    count = int(patch_diff_learner.get("pattern_count") or len(patterns) or 0)
    offline_n = int(patch_diff_learner.get("offline_diff_count") or 0)
    bridge_n = int(patch_diff_learner.get("bridge_diff_count") or 0)
    notes = [
        f"pdl_status={status_raw or 'unknown'}",
        f"pdl_pattern_count={count}",
        f"offline_diffs={offline_n}",
        f"bridge_diffs={bridge_n}",
        "plan_only_no_patch_apply_or_auto_pr",
        f"export_written={bool(patch_diff_learner.get('export_written'))}",
    ]
    return {
        "status": "advisory" if count or ("ready" in status_raw or "written" in status_raw) else "empty",
        "supports_candidate": False,
        "notes": notes[:12],
        "evidence_refs": [
            f"pdl:{(p.get('source_ref') if isinstance(p, dict) else None) or 'pattern'}"
            for p in patterns[:6]
            if isinstance(p, dict)
        ],
    }


def signal_from_variant_analysis(
    variant_analysis: dict[str, Any] | None,
    *,
    candidate: dict[str, Any] | None = None,
) -> dict[str, Any] | None:
    """Plan-only variant analysis signal; never implies exploit/promote/submit."""
    del candidate
    if not isinstance(variant_analysis, dict):
        return None
    if (
        variant_analysis.get("execution_allowed") is True
        or variant_analysis.get("process_spawn_allowed") is True
        or variant_analysis.get("finding_promotion_allowed") is True
        or variant_analysis.get("report_submission_allowed") is True
        or variant_analysis.get("validation_allowed") is True
        or variant_analysis.get("live_validation") is True
        or variant_analysis.get("network_access") is True
        or variant_analysis.get("confirmed_vulnerability") is True
    ):
        return {
            "status": "blocked",
            "supports_candidate": False,
            "notes": ["variant_analysis_unsafe_flags_forced_block"],
            "evidence_refs": [],
        }
    status_raw = str(variant_analysis.get("status") or "")
    variants = list(variant_analysis.get("variants") or [])
    count = int(variant_analysis.get("variant_count") or len(variants) or 0)
    seed_n = int(variant_analysis.get("seed_count") or 0)
    offline_n = int(variant_analysis.get("offline_hint_count") or 0)
    notes = [
        f"va_status={status_raw or 'unknown'}",
        f"va_variant_count={count}",
        f"seed_count={seed_n}",
        f"offline_hints={offline_n}",
        "plan_only_no_variant_exploit_or_promote",
        f"export_written={bool(variant_analysis.get('export_written'))}",
    ]
    return {
        "status": "advisory" if count or ("ready" in status_raw or "written" in status_raw) else "empty",
        "supports_candidate": False,
        "notes": notes[:12],
        "evidence_refs": [
            f"va:{(v.get('variant_id') if isinstance(v, dict) else None) or 'variant'}"
            for v in variants[:6]
            if isinstance(v, dict)
        ],
    }


def signal_from_vuln_chain_builder(
    vuln_chain_builder: dict[str, Any] | None,
    *,
    candidate: dict[str, Any] | None = None,
) -> dict[str, Any] | None:
    """Plan-only vuln chain builder signal; never implies exploit/promote/submit."""
    del candidate
    if not isinstance(vuln_chain_builder, dict):
        return None
    if (
        vuln_chain_builder.get("execution_allowed") is True
        or vuln_chain_builder.get("process_spawn_allowed") is True
        or vuln_chain_builder.get("finding_promotion_allowed") is True
        or vuln_chain_builder.get("report_submission_allowed") is True
        or vuln_chain_builder.get("validation_allowed") is True
        or vuln_chain_builder.get("live_validation") is True
        or vuln_chain_builder.get("network_access") is True
        or vuln_chain_builder.get("confirmed_vulnerability") is True
    ):
        return {
            "status": "blocked",
            "supports_candidate": False,
            "notes": ["vuln_chain_builder_unsafe_flags_forced_block"],
            "evidence_refs": [],
        }
    status_raw = str(vuln_chain_builder.get("status") or "")
    chains = list(vuln_chain_builder.get("chains") or [])
    count = int(vuln_chain_builder.get("chain_count") or len(chains) or 0)
    seed_n = int(vuln_chain_builder.get("seed_count") or 0)
    offline_n = int(vuln_chain_builder.get("offline_hint_count") or 0)
    notes = [
        f"vcb_status={status_raw or 'unknown'}",
        f"vcb_chain_count={count}",
        f"seed_count={seed_n}",
        f"offline_hints={offline_n}",
        "plan_only_no_chain_exploit_or_promote",
        f"export_written={bool(vuln_chain_builder.get('export_written'))}",
    ]
    return {
        "status": "advisory" if count or ("ready" in status_raw or "written" in status_raw) else "empty",
        "supports_candidate": False,
        "notes": notes[:12],
        "evidence_refs": [
            f"vcb:{(c.get('chain_id') if isinstance(c, dict) else None) or 'chain'}"
            for c in chains[:6]
            if isinstance(c, dict)
        ],
    }


def signal_from_deep_code_reasoning(
    deep_code_reasoning: dict[str, Any] | None,
    *,
    candidate: dict[str, Any] | None = None,
) -> dict[str, Any] | None:
    """Plan-only deep code reasoning signal; never implies exploit/promote/submit."""
    del candidate
    if not isinstance(deep_code_reasoning, dict):
        return None
    if (
        deep_code_reasoning.get("execution_allowed") is True
        or deep_code_reasoning.get("process_spawn_allowed") is True
        or deep_code_reasoning.get("finding_promotion_allowed") is True
        or deep_code_reasoning.get("report_submission_allowed") is True
        or deep_code_reasoning.get("validation_allowed") is True
        or deep_code_reasoning.get("live_validation") is True
        or deep_code_reasoning.get("network_access") is True
        or deep_code_reasoning.get("confirmed_vulnerability") is True
    ):
        return {
            "status": "blocked",
            "supports_candidate": False,
            "notes": ["deep_code_reasoning_unsafe_flags_forced_block"],
            "evidence_refs": [],
        }
    status_raw = str(deep_code_reasoning.get("status") or "")
    paths = list(deep_code_reasoning.get("paths") or [])
    count = int(deep_code_reasoning.get("path_count") or len(paths) or 0)
    models = int(deep_code_reasoning.get("permission_model_count") or 0)
    seed_n = int(deep_code_reasoning.get("seed_count") or 0)
    offline_n = int(deep_code_reasoning.get("offline_hint_count") or 0)
    notes = [
        f"dcr_status={status_raw or 'unknown'}",
        f"dcr_path_count={count}",
        f"permission_model_count={models}",
        f"seed_count={seed_n}",
        f"offline_hints={offline_n}",
        "plan_only_no_reasoning_exploit_or_promote",
        f"export_written={bool(deep_code_reasoning.get('export_written'))}",
    ]
    return {
        "status": "advisory" if count or models or ("ready" in status_raw or "written" in status_raw) else "empty",
        "supports_candidate": False,
        "notes": notes,
        "evidence_refs": [f"deep_code_reasoning:path:{count}"],
        "confidence": "low",
    }



def signal_from_finding_dedup_risk(
    finding_dedup_risk: dict[str, Any] | None,
    *,
    candidate: dict[str, Any] | None = None,
) -> dict[str, Any] | None:
    """Map plan-only dedup/risk queue into multi-engine signal (advisory only)."""
    del candidate
    if not isinstance(finding_dedup_risk, dict):
        return None
    if (
        finding_dedup_risk.get("execution_allowed") is True
        or finding_dedup_risk.get("validation_allowed") is True
        or finding_dedup_risk.get("finding_promotion_allowed") is True
        or finding_dedup_risk.get("report_submission_allowed") is True
        or finding_dedup_risk.get("confirmed_vulnerability") is True
        or finding_dedup_risk.get("ranking_permission_granted") is True
        or finding_dedup_risk.get("live_validation") is True
        or finding_dedup_risk.get("network_access") is True
        or finding_dedup_risk.get("process_spawn_allowed") is True
    ):
        return {
            "status": "blocked",
            "supports_candidate": False,
            "notes": ["finding_dedup_risk_unsafe_flags_forced_block"],
            "evidence_refs": [],
        }
    status_raw = str(finding_dedup_risk.get("status") or "")
    clusters = int(finding_dedup_risk.get("cluster_count") or 0)
    queue_n = int(finding_dedup_risk.get("risk_queue_count") or 0)
    seeds = int(finding_dedup_risk.get("seed_count") or 0)
    notes = [
        f"status={status_raw or 'unknown'}",
        f"clusters={clusters}",
        f"risk_queue={queue_n}",
        f"seeds={seeds}",
        "plan_only_human_triage",
        "never_grants_ranking_execution_permission",
    ]
    if status_raw or clusters or queue_n:
        return {
            "status": "ready",
            "supports_candidate": None,
            "notes": notes,
            "evidence_refs": (
                [f"finding_dedup_risk:clusters:{clusters}"]
                if clusters
                else ["finding_dedup_risk:plan"]
            ),
        }
    return {
        "status": "empty",
        "supports_candidate": None,
        "notes": notes,
        "evidence_refs": [],
    }



def signal_from_human_gate_dry_run(
    human_gate_dry_run: dict[str, Any] | None,
    *,
    candidate: dict[str, Any] | None = None,
) -> dict[str, Any] | None:
    """Map offline human-gate dry-run posture into multi-engine signal (advisory only)."""
    if not isinstance(human_gate_dry_run, dict):
        return None
    if (
        human_gate_dry_run.get("report_submission_allowed") is True
        or human_gate_dry_run.get("execution_allowed") is True
        or human_gate_dry_run.get("validation_allowed") is True
        or human_gate_dry_run.get("confirmed_vulnerability") is True
        or human_gate_dry_run.get("finding_promotion_allowed") is True
        or human_gate_dry_run.get("crash_promotion_allowed") is True
        or human_gate_dry_run.get("live_validation") is True
        or human_gate_dry_run.get("network_access") is True
    ):
        return {
            "status": "blocked",
            "supports_candidate": False,
            "notes": ["human_gate_dry_run_unsafe_flags_forced_block"],
            "evidence_refs": [],
        }
    status_raw = str(human_gate_dry_run.get("status") or "")
    fail_n = int(human_gate_dry_run.get("fail_count") or 0)
    pass_n = int(human_gate_dry_run.get("pass_count") or 0)
    chain_safe = bool(human_gate_dry_run.get("chain_safe"))
    chain_complete = bool(human_gate_dry_run.get("chain_complete"))
    notes = [
        f"status={status_raw or 'unknown'}",
        f"pass={pass_n}",
        f"fail={fail_n}",
        f"chain_safe={chain_safe}",
        f"chain_complete={chain_complete}",
        "offline_only_never_h1_probe",
        "never_unlocks_submit",
    ]
    if fail_n > 0 or "safety_failure" in status_raw:
        return {
            "status": "blocked",
            "supports_candidate": False,
            "notes": notes + ["dry_run_safety_failures"],
            "evidence_refs": ["human_gate_dry_run:fail"],
        }
    if status_raw or pass_n:
        return {
            "status": "ready",
            "supports_candidate": None,
            "notes": notes,
            "evidence_refs": (
                ["human_gate_dry_run:chain"] if chain_complete and chain_safe else ["human_gate_dry_run:plan"]
            ),
        }
    return {
        "status": "empty",
        "supports_candidate": None,
        "notes": notes,
        "evidence_refs": [],
    }



def signal_from_agent_memory(
    agent_memory: dict[str, Any] | None,
    *,
    candidate: dict[str, Any] | None = None,
) -> dict[str, Any] | None:
    """Map advisory agent memory posture into multi-engine signal (ranking only)."""
    del candidate
    if not isinstance(agent_memory, dict):
        return None
    if (
        agent_memory.get("report_submission_allowed") is True
        or agent_memory.get("execution_allowed") is True
        or agent_memory.get("validation_allowed") is True
        or agent_memory.get("confirmed_vulnerability") is True
        or agent_memory.get("finding_promotion_allowed") is True
        or agent_memory.get("ranking_permission_granted") is True
        or agent_memory.get("live_validation") is True
        or agent_memory.get("network_access") is True
    ):
        return {
            "status": "blocked",
            "supports_candidate": False,
            "notes": ["agent_memory_unsafe_flags_forced_block"],
            "evidence_refs": [],
        }
    status_raw = str(agent_memory.get("status") or "")
    entry_n = int(agent_memory.get("entry_count") or 0)
    fp_n = int(agent_memory.get("false_positive_pattern_count") or 0)
    hint_n = int(agent_memory.get("candidate_hint_count") or 0)
    notes = [
        f"status={status_raw or 'unknown'}",
        f"entries={entry_n}",
        f"fp_patterns={fp_n}",
        f"hints={hint_n}",
        "advisory_ranking_only",
        "never_grants_execution_permission",
    ]
    if status_raw or entry_n or hint_n:
        return {
            "status": "ready",
            "supports_candidate": None,
            "notes": notes,
            "evidence_refs": (
                ["agent_memory:entries"] if entry_n else ["agent_memory:plan"]
            ),
        }
    return {
        "status": "empty",
        "supports_candidate": None,
        "notes": notes,
        "evidence_refs": [],
    }



def signal_from_continuous_scan(
    continuous_scan: dict[str, Any] | None,
    *,
    candidate: dict[str, Any] | None = None,
) -> dict[str, Any] | None:
    """Map advisory continuous-scan plan into multi-engine signal."""
    del candidate
    if not isinstance(continuous_scan, dict):
        return None
    if (
        continuous_scan.get("report_submission_allowed") is True
        or continuous_scan.get("execution_allowed") is True
        or continuous_scan.get("validation_allowed") is True
        or continuous_scan.get("auto_scan_allowed") is True
        or continuous_scan.get("confirmed_vulnerability") is True
        or continuous_scan.get("finding_promotion_allowed") is True
        or continuous_scan.get("network_access") is True
        or continuous_scan.get("live_validation") is True
    ):
        return {
            "status": "blocked",
            "supports_candidate": False,
            "notes": ["continuous_scan_unsafe_flags_forced_block"],
            "evidence_refs": [],
        }
    status_raw = str(continuous_scan.get("status") or "")
    job_n = int(continuous_scan.get("job_count") or 0)
    watch_n = int(continuous_scan.get("watch_path_count") or 0)
    notes = [
        f"status={status_raw or 'unknown'}",
        f"jobs={job_n}",
        f"watches={watch_n}",
        "plan_only_never_auto_scan",
    ]
    if status_raw or job_n:
        return {
            "status": "ready",
            "supports_candidate": None,
            "notes": notes,
            "evidence_refs": ["continuous_scan:jobs"] if job_n else ["continuous_scan:plan"],
        }
    return {
        "status": "empty",
        "supports_candidate": None,
        "notes": notes,
        "evidence_refs": [],
    }


def signal_from_patch_validation(
    patch_validation: dict[str, Any] | None,
    *,
    candidate: dict[str, Any] | None = None,
) -> dict[str, Any] | None:
    """Map advisory patch-validation plan into multi-engine signal."""
    del candidate
    if not isinstance(patch_validation, dict):
        return None
    if (
        patch_validation.get("report_submission_allowed") is True
        or patch_validation.get("execution_allowed") is True
        or patch_validation.get("validation_allowed") is True
        or patch_validation.get("live_validation_allowed") is True
        or patch_validation.get("patch_ready") is True
        or patch_validation.get("auto_pr_allowed") is True
        or patch_validation.get("confirmed_vulnerability") is True
        or patch_validation.get("finding_promotion_allowed") is True
        or patch_validation.get("network_access") is True
        or patch_validation.get("live_validation") is True
    ):
        return {
            "status": "blocked",
            "supports_candidate": False,
            "notes": ["patch_validation_unsafe_flags_forced_block"],
            "evidence_refs": [],
        }
    status_raw = str(patch_validation.get("status") or "")
    item_n = int(patch_validation.get("item_count") or 0)
    ready_n = int(patch_validation.get("ready_item_count") or 0)
    step_n = int(patch_validation.get("step_count") or 0)
    notes = [
        f"status={status_raw or 'unknown'}",
        f"items={item_n}",
        f"ready={ready_n}",
        f"steps={step_n}",
        "non_destructive_recheck_plan_only",
    ]
    if status_raw or item_n:
        return {
            "status": "ready",
            "supports_candidate": None,
            "notes": notes,
            "evidence_refs": ["patch_validation:items"] if item_n else ["patch_validation:plan"],
        }
    return {
        "status": "empty",
        "supports_candidate": None,
        "notes": notes,
        "evidence_refs": [],
    }





def signal_from_long_horizon(
    long_horizon: dict[str, Any] | None,
    *,
    candidate: dict[str, Any] | None = None,
) -> dict[str, Any] | None:
    """Advisory long-horizon path-switch signal; unsafe flags force blocked."""
    del candidate  # unused; candidate context reserved for future ranking
    if not isinstance(long_horizon, dict):
        return None
    if (
        long_horizon.get("report_submission_allowed") is True
        or long_horizon.get("execution_allowed") is True
        or long_horizon.get("validation_allowed") is True
        or long_horizon.get("confirmed_vulnerability") is True
        or long_horizon.get("finding_promotion_allowed") is True
        or long_horizon.get("ranking_permission_granted") is True
        or long_horizon.get("auto_path_switch_allowed") is True
        or long_horizon.get("network_access") is True
        or long_horizon.get("live_validation") is True
    ):
        return {
            "status": "blocked",
            "notes": ["long_horizon_unsafe_flags_forced_block"],
        }
    status_raw = str(long_horizon.get("status") or "")
    path_n = int(long_horizon.get("path_count") or 0)
    switch_n = int(long_horizon.get("switch_count") or 0)
    iter_n = int(long_horizon.get("iteration_count") or 0)
    if "missing" in status_raw:
        status = "blocked"
    elif path_n or switch_n or "ready" in status_raw or "written" in status_raw:
        status = "ready"
    elif "waiting" in status_raw or "empty" in status_raw:
        status = "needs_human_review"
    else:
        status = "ready" if (path_n or switch_n) else "needs_human_review"
    return {
        "status": status,
        "evidence_refs": ["long_horizon:paths"] if path_n else ["long_horizon:plan"],
        "notes": [
            f"paths={path_n}",
            f"switches={switch_n}",
            f"iterations={iter_n}",
            "plan_only_never_auto_path_switch",
        ],
        "confidence": "low",
    }

def signal_from_deep_research(
    deep_research: dict[str, Any] | None,
    *,
    candidate: dict[str, Any] | None = None,
) -> dict[str, Any] | None:
    """Map advisory V4 deep-research plan into multi-engine signal."""
    del candidate
    if not isinstance(deep_research, dict):
        return None
    if (
        deep_research.get("report_submission_allowed") is True
        or deep_research.get("execution_allowed") is True
        or deep_research.get("validation_allowed") is True
        or deep_research.get("confirmed_vulnerability") is True
        or deep_research.get("finding_promotion_allowed") is True
        or deep_research.get("ranking_permission_granted") is True
        or deep_research.get("network_access") is True
        or deep_research.get("live_validation") is True
    ):
        return {
            "status": "blocked",
            "supports_candidate": False,
            "notes": ["deep_research_unsafe_flags_forced_block"],
            "evidence_refs": [],
        }
    status_raw = str(deep_research.get("status") or "")
    chain_n = int(deep_research.get("chain_count") or 0)
    variant_n = int(deep_research.get("variant_count") or 0)
    unresolved_n = int(deep_research.get("unresolved_refutation_count") or 0)
    notes = [
        f"status={status_raw or 'unknown'}",
        f"chains={chain_n}",
        f"variants={variant_n}",
        f"unresolved_refutations={unresolved_n}",
        "deep_reasoning_plan_only_never_execute",
    ]
    if status_raw or chain_n or variant_n:
        return {
            "status": "ready",
            "supports_candidate": None,
            "notes": notes,
            "evidence_refs": ["deep_research:chains"] if chain_n else ["deep_research:plan"],
        }
    return {
        "status": "empty",
        "supports_candidate": None,
        "notes": notes,
        "evidence_refs": [],
    }

def signal_from_residual_runner(
    residual_runner: dict[str, Any] | None,
    *,
    candidate: dict[str, Any] | None = None,
) -> dict[str, Any] | None:
    if not isinstance(residual_runner, dict):
        return None
    if residual_runner.get("execution_allowed") is True or residual_runner.get("report_submission_allowed") is True:
        return {
            "status": "blocked",
            "supports_candidate": False,
            "notes": ["residual_runner_unsafe_flags"],
            "evidence_refs": [],
        }
    status_raw = str(
        residual_runner.get("status")
        or residual_runner.get("residual_runner_status")
        or ""
    )
    notes = [f"residual_runner_status={status_raw or 'unknown'}", "local_static_only"]
    completed = int(
        residual_runner.get("completed_count")
        or residual_runner.get("residual_runner_completed_count")
        or 0
    )
    runs = residual_runner.get("runs") if isinstance(residual_runner.get("runs"), list) else []
    matching_done = 0
    matching_open = 0
    for run in runs:
        if not isinstance(run, dict):
            continue
        st = str(run.get("status") or "")
        if "completed" in st:
            matching_done += 1
        if st in {"open", "planned", "residual_run_planned"}:
            matching_open += 1
    if "rejected" in status_raw or "fp" in status_raw:
        return {
            "status": "ready",
            "supports_candidate": False,
            "notes": notes + ["residual_rejected_or_fp"],
            "evidence_refs": [],
        }
    if "no_human_approval" in status_raw or status_raw.endswith("skipped_no_human_approval"):
        return {
            "status": "pending",
            "supports_candidate": None,
            "notes": notes + ["awaiting_residual_review_approval"],
            "evidence_refs": [],
        }
    if "completed" in status_raw or completed > 0 or matching_done > 0:
        return {
            "status": "ready",
            "supports_candidate": True,
            "notes": notes + [
                "local_static_residual_completed",
                f"completed={max(completed, matching_done)}",
            ],
            "evidence_refs": [f"residual_run:{i}" for i in range(min(matching_done or completed, 3))],
        }
    if "planned" in status_raw or matching_open:
        return {
            "status": "pending",
            "supports_candidate": None,
            "notes": notes + ["residual_planned_not_executed_as_live"],
            "evidence_refs": [],
        }
    return {
        "status": "ready",
        "supports_candidate": None,
        "notes": notes + ["residual_runner_no_decisive_signal"],
        "evidence_refs": [],
    }


def signal_from_authorized_web_api(
    web_api: dict[str, Any] | None,
    *,
    candidate: dict[str, Any] | None = None,
) -> dict[str, Any] | None:
    if not isinstance(web_api, dict):
        return None
    if web_api.get("execution_allowed") is True or web_api.get("report_submission_allowed") is True:
        return {
            "status": "blocked",
            "supports_candidate": False,
            "notes": ["web_api_unsafe_flags"],
            "evidence_refs": [],
        }
    status_raw = str(web_api.get("status") or "")
    ops = list(web_api.get("api_operations") or [])
    diffs = list(web_api.get("role_diff_plans") or [])
    op_count = int(web_api.get("operation_count") or len(ops) or 0)
    diff_count = int(web_api.get("role_diff_count") or len(diffs) or 0)
    notes = [
        f"web_api_status={status_raw or 'unknown'}",
        f"operations={op_count}",
        f"role_diffs={diff_count}",
        "plan_only_no_live_http",
    ]
    cand = candidate if isinstance(candidate, dict) else {}
    route = cand.get("route") if isinstance(cand.get("route"), dict) else {}
    path = str(route.get("path") or cand.get("affected_endpoint") or "")
    method = str(route.get("method") or "").upper()
    matched = False
    for item in diffs + ops:
        if not isinstance(item, dict):
            continue
        item_path = str(item.get("path") or item.get("endpoint") or item.get("route") or "")
        item_method = str(item.get("method") or "").upper()
        if path and path in item_path:
            if not method or not item_method or method == item_method:
                matched = True
                break
    if status_raw.endswith("missing") or status_raw.endswith("no_operations") or status_raw.endswith("no_scope_or_api"):
        return {
            "status": "pending",
            "supports_candidate": None,
            "notes": notes + ["web_api_surface_missing_or_empty"],
            "evidence_refs": [],
        }
    if matched:
        return {
            "status": "ready",
            "supports_candidate": True,
            "notes": notes + ["web_api_route_overlap"],
            "evidence_refs": [f"web:{method}:{path}"] if path else [],
        }
    if op_count or diff_count:
        return {
            "status": "ready",
            "supports_candidate": None,
            "notes": notes + ["web_api_surface_present_no_route_match"],
            "evidence_refs": [],
        }
    return {
        "status": "ready",
        "supports_candidate": None,
        "notes": notes,
        "evidence_refs": [],
    }


def signal_from_residual_gate(
    residual_gates: list[dict[str, Any]] | dict[str, Any] | None,
    *,
    candidate: dict[str, Any] | None = None,
) -> dict[str, Any] | None:
    if isinstance(residual_gates, dict):
        gates = [residual_gates]
    elif isinstance(residual_gates, list):
        gates = [g for g in residual_gates if isinstance(g, dict)]
    else:
        return None
    if not gates:
        return None
    cand = candidate if isinstance(candidate, dict) else {}
    cid = str(cand.get("candidate_id") or "")
    root = str(cand.get("root_cause_id") or "")
    matched = None
    for gate in gates:
        g_cid = str(gate.get("candidate_id") or "")
        g_root = str(gate.get("root_cause_id") or "")
        if cid and g_cid and g_cid == cid:
            matched = gate
            break
        if root and g_root and (g_root == root or root in g_root or g_root in root):
            matched = gate
            break
    gate = matched or gates[0]
    status_raw = str(gate.get("status") or "")
    notes = [f"residual_gate_status={status_raw or 'unknown'}"]
    if gate.get("report_submission_allowed") is True:
        return {
            "status": "blocked",
            "supports_candidate": False,
            "notes": notes + ["residual_gate_unsafe_submit_flag"],
            "evidence_refs": [],
        }
    if status_raw in {"human_rejected_or_fp", "rejected", "false_positive"}:
        return {
            "status": "ready",
            "supports_candidate": False,
            "notes": notes + ["human_residual_rejected_or_fp"],
            "evidence_refs": [str(gate.get("candidate_id") or "gate")],
        }
    if status_raw in {"ready_for_human_review"}:
        return {
            "status": "ready",
            "supports_candidate": True,
            "notes": notes + ["residual_ready_for_human_review_not_confirmed"],
            "evidence_refs": [str(gate.get("candidate_id") or "gate")],
        }
    if status_raw in {"blocked"}:
        return {
            "status": "blocked",
            "supports_candidate": False,
            "notes": notes + ["residual_gate_blocked"],
            "evidence_refs": [],
        }
    if status_raw in {"hold", "held", "awaiting_human"}:
        return {
            "status": "pending",
            "supports_candidate": None,
            "notes": notes + ["residual_gate_hold"],
            "evidence_refs": [],
        }
    return {
        "status": "ready",
        "supports_candidate": None,
        "notes": notes + ["residual_gate_nondecisive"],
        "evidence_refs": [],
    }


def signal_from_local_runner(
    runner: dict[str, Any] | None,
    *,
    engine_name: str,
) -> dict[str, Any] | None:
    """Semgrep/CodeQL local runner posture — advisory only, never live exploit."""
    if not isinstance(runner, dict):
        return None
    if runner.get("report_submission_allowed") is True or runner.get("confirmed_vulnerability") is True:
        return {
            "status": "blocked",
            "supports_candidate": False,
            "notes": [f"{engine_name}_unsafe_promotion_flags"],
            "evidence_refs": [],
        }
    status_raw = str(runner.get("status") or "")
    finding_count = int(
        runner.get("finding_count")
        or runner.get("semgrep_runner_finding_count")
        or runner.get("codeql_runner_finding_count")
        or 0
    )
    notes = [
        f"{engine_name}_status={status_raw or 'unknown'}",
        f"finding_count={finding_count}",
        "advisory_local_cli_only",
    ]
    if "skipped" in status_raw or "missing" in status_raw:
        return {
            "status": "pending",
            "supports_candidate": None,
            "notes": notes + ["runner_not_executed_or_skipped"],
            "evidence_refs": [],
        }
    if finding_count > 0:
        return {
            "status": "ready",
            "supports_candidate": True,
            "notes": notes + ["local_runner_findings_present_not_confirmed"],
            "evidence_refs": [f"{engine_name}:findings"],
        }
    if status_raw and "completed" in status_raw:
        return {
            "status": "ready",
            "supports_candidate": None,
            "notes": notes + ["local_runner_completed_no_findings"],
            "evidence_refs": [],
        }
    return {
        "status": "ready",
        "supports_candidate": None,
        "notes": notes,
        "evidence_refs": [],
    }



def signal_from_knowledge_base(
    knowledge_base: dict[str, Any] | None,
    *,
    candidate: dict[str, Any] | None = None,
) -> dict[str, Any] | None:
    """Advisory knowledge-base pattern catalog signal; unsafe flags force blocked."""
    del candidate  # unused; reserved for future ranking
    if not isinstance(knowledge_base, dict):
        return None
    if (
        knowledge_base.get("report_submission_allowed") is True
        or knowledge_base.get("execution_allowed") is True
        or knowledge_base.get("validation_allowed") is True
        or knowledge_base.get("confirmed_vulnerability") is True
        or knowledge_base.get("finding_promotion_allowed") is True
        or knowledge_base.get("ranking_permission_granted") is True
        or knowledge_base.get("auto_learn_live_sources") is True
        or knowledge_base.get("network_access") is True
        or knowledge_base.get("live_validation") is True
    ):
        return {
            "status": "blocked",
            "notes": ["knowledge_base_unsafe_flags_forced_block"],
        }
    status_raw = str(knowledge_base.get("status") or "")
    pattern_n = int(knowledge_base.get("pattern_count") or 0)
    if "missing" in status_raw:
        status = "needs_human_review"
    elif pattern_n or "ready" in status_raw or "written" in status_raw:
        status = "ready"
    elif "waiting" in status_raw or "empty" in status_raw:
        status = "needs_human_review"
    else:
        status = "ready" if pattern_n else "needs_human_review"
    return {
        "status": status,
        "evidence_refs": ["knowledge_base:patterns"] if pattern_n else ["knowledge_base:catalog"],
        "notes": [
            f"patterns={pattern_n}",
            "advisory_pattern_catalog_only",
            "never_grants_ranking_execution_permission",
        ],
        "confidence": "low",
    }







def signal_from_human_review_approvals(
    human_review_approvals: dict[str, Any] | list[dict[str, Any]] | None,
    *,
    candidate: dict[str, Any] | None = None,
) -> dict[str, Any] | None:
    """Map durable residual/patch human review approvals into multi-engine signal.

    Context/audit only. Unsafe unlock flags force blocked. Never patch_ready/submit.
    """
    del candidate
    if human_review_approvals is None:
        return None
    if isinstance(human_review_approvals, list):
        payload: dict[str, Any] = {
            "approvals": [a for a in human_review_approvals if isinstance(a, dict)],
            "present": bool(human_review_approvals),
        }
    elif isinstance(human_review_approvals, dict):
        payload = human_review_approvals
    else:
        return None

    if (
        payload.get("report_submission_allowed") is True
        or payload.get("execution_allowed") is True
        or payload.get("validation_allowed") is True
        or payload.get("confirmed_vulnerability") is True
        or payload.get("finding_promotion_allowed") is True
        or payload.get("auto_pr_allowed") is True
        or payload.get("patch_ready") is True
        or payload.get("pr_opened") is True
    ):
        return {
            "status": "blocked",
            "supports_candidate": False,
            "notes": ["human_review_approvals_unsafe_flags_forced_block"],
            "evidence_refs": [],
        }

    summary = payload.get("human_review_approvals_summary")
    if not isinstance(summary, dict):
        summary = payload.get("summary") if isinstance(payload.get("summary"), dict) else {}
    approvals = payload.get("approvals") or payload.get("human_review_approvals") or []
    if not isinstance(approvals, list):
        approvals = []
    approvals = [a for a in approvals if isinstance(a, dict)]

    status_raw = str(
        payload.get("human_review_approvals_status")
        or payload.get("status")
        or summary.get("status")
        or ""
    )
    count = int(
        payload.get("human_review_approvals_count")
        or summary.get("approval_count")
        or len(approvals)
        or 0
    )
    decided = int(
        payload.get("human_review_approvals_decided_count")
        or summary.get("decided_count")
        or 0
    )
    residual_n = int(
        payload.get("human_review_approvals_residual_count")
        or summary.get("residual_count")
        or 0
    )
    patch_n = int(
        payload.get("human_review_approvals_patch_count")
        or summary.get("patch_count")
        or 0
    )
    if decided == 0 and approvals:
        decided = sum(
            1
            for a in approvals
            if str(a.get("status") or "")
            in {
                "approved",
                "denied",
                "rejected_fp",
                "waived",
                "expired",
                "revoked",
            }
        )
    if residual_n == 0 and approvals:
        residual_n = sum(
            1
            for a in approvals
            if str(a.get("approval_kind") or "") in {"residual_review", "residual"}
        )
    if patch_n == 0 and approvals:
        patch_n = sum(
            1
            for a in approvals
            if str(a.get("approval_kind") or "") in {"patch_review", "patch"}
        )

    notes = [
        f"status={status_raw or 'unknown'}",
        f"approvals={count}",
        f"decided={decided}",
        f"residual={residual_n}",
        f"patch={patch_n}",
        "durable_human_review_context_only",
        "never_unlocks_execute_submit_or_patch_ready",
    ]
    present = bool(
        payload.get("present")
        or payload.get("human_review_approvals_present")
        or count
        or status_raw
    )
    if not present and not status_raw:
        return {
            "status": "empty",
            "supports_candidate": None,
            "notes": notes + ["no_package_approvals"],
            "evidence_refs": [],
        }
    if "empty" in status_raw and not count:
        eng_status = "empty"
    elif decided or "ready" in status_raw:
        eng_status = "ready"
    elif count or "pending" in status_raw:
        eng_status = "pending"
    else:
        eng_status = "ready" if count else "empty"
    return {
        "status": eng_status,
        "supports_candidate": None,
        "notes": notes,
        "evidence_refs": (
            ["human_review_approvals:decided"]
            if decided
            else (["human_review_approvals:present"] if count else ["human_review_approvals:audit"])
        ),
        "confidence": "low",
    }




def signal_from_residual_patch_decision_api(
    residual_patch_decision_api: dict[str, Any] | None,
    *,
    candidate: dict[str, Any] | None = None,
) -> dict[str, Any] | None:
    """Map offline residual/patch decision API snapshot into multi-engine signal.

    Context/audit only. Unsafe unlock flags force blocked. Never patch_ready/submit.
    """
    del candidate
    if not isinstance(residual_patch_decision_api, dict):
        return None
    payload = residual_patch_decision_api
    if (
        payload.get("report_submission_allowed") is True
        or payload.get("execution_allowed") is True
        or payload.get("validation_allowed") is True
        or payload.get("confirmed_vulnerability") is True
        or payload.get("finding_promotion_allowed") is True
        or payload.get("auto_pr_allowed") is True
        or payload.get("patch_ready") is True
        or payload.get("pr_opened") is True
    ):
        return {
            "status": "blocked",
            "supports_candidate": False,
            "notes": ["residual_patch_decision_api_unsafe_flags_forced_block"],
            "evidence_refs": [],
        }

    status_raw = str(payload.get("status") or payload.get("residual_patch_decision_api_status") or "")
    count = int(
        payload.get("decision_count")
        or payload.get("residual_patch_decision_api_count")
        or 0
    )
    decided = int(
        payload.get("decided_count")
        or payload.get("residual_patch_decision_api_decided_count")
        or 0
    )
    residual_n = int(
        payload.get("residual_count")
        or payload.get("residual_patch_decision_api_residual_count")
        or 0
    )
    patch_n = int(
        payload.get("patch_count")
        or payload.get("residual_patch_decision_api_patch_count")
        or 0
    )
    export_written = bool(
        payload.get("export_written")
        or payload.get("residual_patch_decision_api_export_written")
    )
    notes = [
        f"status={status_raw or 'unknown'}",
        f"decisions={count}",
        f"decided={decided}",
        f"residual={residual_n}",
        f"patch={patch_n}",
        f"export_written={export_written}",
        "offline_decision_snapshot_only",
        "never_unlocks_execute_submit_or_patch_ready",
    ]
    present = bool(
        payload.get("present")
        or payload.get("residual_patch_decision_api_present")
        or count
        or export_written
        or status_raw
    )
    if not present and not status_raw:
        return {
            "status": "empty",
            "supports_candidate": None,
            "notes": notes + ["no_decision_snapshot"],
            "evidence_refs": [],
        }
    if "empty" in status_raw and not count:
        eng_status = "empty"
    elif decided or "ready" in status_raw or "written" in status_raw or "imported" in status_raw:
        eng_status = "ready"
    elif count or "pending" in status_raw:
        eng_status = "pending"
    else:
        eng_status = "ready" if (count or export_written) else "empty"
    return {
        "status": eng_status,
        "supports_candidate": None,
        "notes": notes,
        "evidence_refs": (
            ["residual_patch_decision_api:decided"]
            if decided
            else (
                ["residual_patch_decision_api:export"]
                if export_written
                else (
                    ["residual_patch_decision_api:present"]
                    if count
                    else ["residual_patch_decision_api:audit"]
                )
            )
        ),
        "confidence": "low",
    }

def signal_from_wall_clock_multi_hour_runner(
    wall_clock_multi_hour_runner: dict[str, Any] | None,
    *,
    candidate: dict[str, Any] | None = None,
) -> dict[str, Any] | None:
    """Advisory wall-clock tick ledger signal; unsafe flags force blocked."""
    del candidate
    if not isinstance(wall_clock_multi_hour_runner, dict):
        return None
    if (
        wall_clock_multi_hour_runner.get("report_submission_allowed") is True
        or wall_clock_multi_hour_runner.get("execution_allowed") is True
        or wall_clock_multi_hour_runner.get("validation_allowed") is True
        or wall_clock_multi_hour_runner.get("confirmed_vulnerability") is True
        or wall_clock_multi_hour_runner.get("finding_promotion_allowed") is True
        or wall_clock_multi_hour_runner.get("ranking_permission_granted") is True
        or wall_clock_multi_hour_runner.get("auto_tick_allowed") is True
        or wall_clock_multi_hour_runner.get("auto_session_advance_allowed") is True
        or wall_clock_multi_hour_runner.get("network_access") is True
        or wall_clock_multi_hour_runner.get("live_validation") is True
    ):
        return {
            "status": "blocked",
            "notes": ["wall_clock_multi_hour_runner_unsafe_flags_forced_block"],
        }
    status_raw = str(wall_clock_multi_hour_runner.get("status") or "")
    tick_n = int(wall_clock_multi_hour_runner.get("tick_count") or 0)
    slot_n = int(wall_clock_multi_hour_runner.get("schedule_slot_count") or 0)
    if "missing" in status_raw:
        status = "blocked"
    elif tick_n or slot_n or "ready" in status_raw or "written" in status_raw:
        status = "ready"
    elif "waiting" in status_raw or "empty" in status_raw:
        status = "needs_human_review"
    else:
        status = "ready" if tick_n else "needs_human_review"
    return {
        "status": status,
        "evidence_refs": (
            ["wall_clock_multi_hour_runner:ticks"]
            if tick_n
            else ["wall_clock_multi_hour_runner:plan"]
        ),
        "notes": [
            f"ticks={tick_n}",
            f"slots={slot_n}",
            "advisory_wall_clock_tick_ledger_only",
            "never_auto_tick",
        ],
        "confidence": "low",
    }


def signal_from_multi_hour_agent_loop(
    multi_hour_agent_loop: dict[str, Any] | None,
    *,
    candidate: dict[str, Any] | None = None,
) -> dict[str, Any] | None:
    """Advisory multi-hour session plan signal; unsafe flags force blocked."""
    del candidate
    if not isinstance(multi_hour_agent_loop, dict):
        return None
    if (
        multi_hour_agent_loop.get("report_submission_allowed") is True
        or multi_hour_agent_loop.get("execution_allowed") is True
        or multi_hour_agent_loop.get("validation_allowed") is True
        or multi_hour_agent_loop.get("confirmed_vulnerability") is True
        or multi_hour_agent_loop.get("finding_promotion_allowed") is True
        or multi_hour_agent_loop.get("ranking_permission_granted") is True
        or multi_hour_agent_loop.get("auto_tick_allowed") is True
        or multi_hour_agent_loop.get("auto_session_advance_allowed") is True
        or multi_hour_agent_loop.get("network_access") is True
        or multi_hour_agent_loop.get("live_validation") is True
    ):
        return {
            "status": "blocked",
            "notes": ["multi_hour_agent_loop_unsafe_flags_forced_block"],
        }
    status_raw = str(multi_hour_agent_loop.get("status") or "")
    session_n = int(multi_hour_agent_loop.get("session_count") or 0)
    phase_n = int(multi_hour_agent_loop.get("phase_count") or 0)
    if "missing" in status_raw:
        status = "blocked"
    elif session_n or phase_n or "ready" in status_raw or "written" in status_raw:
        status = "ready"
    elif "waiting" in status_raw or "empty" in status_raw:
        status = "needs_human_review"
    else:
        status = "ready" if session_n else "needs_human_review"
    return {
        "status": status,
        "evidence_refs": ["multi_hour_agent_loop:sessions"] if session_n else ["multi_hour_agent_loop:plan"],
        "notes": [
            f"sessions={session_n}",
            f"phases={phase_n}",
            "advisory_multi_session_plan_only",
            "never_auto_tick",
        ],
        "confidence": "low",
    }


def deepen_multi_engine_verdict(
    base_verdict: dict[str, Any] | MultiEngineVerdict | None,
    *,
    candidate: dict[str, Any] | None = None,
    crs_fuzzing: dict[str, Any] | None = None,
    local_fuzz_sandbox: dict[str, Any] | None = None,
    local_fuzz_runner: dict[str, Any] | None = None,
    crash_triage: dict[str, Any] | None = None,
    crash_regression: dict[str, Any] | None = None,
    crash_codepath: dict[str, Any] | None = None,
    protocol_aware_fuzzing: dict[str, Any] | None = None,
    patch_diff_learner: dict[str, Any] | None = None,
    variant_analysis: dict[str, Any] | None = None,
    vuln_chain_builder: dict[str, Any] | None = None,
    deep_code_reasoning: dict[str, Any] | None = None,
    finding_dedup_risk: dict[str, Any] | None = None,
    human_gate_dry_run: dict[str, Any] | None = None,
    agent_memory: dict[str, Any] | None = None,
    continuous_scan: dict[str, Any] | None = None,
    patch_validation: dict[str, Any] | None = None,
    deep_research: dict[str, Any] | None = None,
    long_horizon: dict[str, Any] | None = None,
    knowledge_base: dict[str, Any] | None = None,
    multi_hour_agent_loop: dict[str, Any] | None = None,
    wall_clock_multi_hour_runner: dict[str, Any] | None = None,
    human_review_approvals: dict[str, Any] | list[dict[str, Any]] | None = None,
    residual_patch_decision_api: dict[str, Any] | None = None,
    residual_runner: dict[str, Any] | None = None,
    authorized_web_api: dict[str, Any] | None = None,
    residual_gates: list[dict[str, Any]] | dict[str, Any] | None = None,
    semgrep_runner: dict[str, Any] | None = None,
    codeql_runner: dict[str, Any] | None = None,
    scope_allowed: bool = True,
) -> MultiEngineVerdict:
    """Re-aggregate an existing verdict with deeper factory stack engines.

    Still never unlocks execution, validation, submission, or confirmed vulnerability.
    """
    if isinstance(base_verdict, MultiEngineVerdict):
        base = base_verdict.model_dump()
    elif isinstance(base_verdict, dict):
        base = dict(base_verdict)
    else:
        base = {}

    cand = candidate if isinstance(candidate, dict) else {}
    if not cand:
        cand = {
            "candidate_id": base.get("candidate_id") or "",
            "root_cause_id": base.get("root_cause_id") or "",
            "refutation_questions": base.get("review_questions") or [],
        }

    prior_by_engine: dict[str, dict[str, Any]] = {}
    for eng in base.get("engines") or []:
        if not isinstance(eng, dict):
            continue
        name = str(eng.get("engine") or "")
        if name:
            prior_by_engine[name] = eng

    def _prior(name: str) -> dict[str, Any] | None:
        return prior_by_engine.get(name)

    crs_signal = signal_from_crs_fuzzing(crs_fuzzing, candidate=cand)
    sandbox_signal = signal_from_local_fuzz_sandbox(local_fuzz_sandbox, candidate=cand)
    runner_signal = signal_from_local_fuzz_runner(local_fuzz_runner, candidate=cand)
    triage_signal = signal_from_crash_triage(crash_triage, candidate=cand)
    regression_signal = signal_from_crash_regression(crash_regression, candidate=cand)
    codepath_signal = signal_from_crash_codepath(crash_codepath, candidate=cand)
    paf_signal = signal_from_protocol_aware_fuzzing(protocol_aware_fuzzing, candidate=cand)
    pdl_signal = signal_from_patch_diff_learner(patch_diff_learner, candidate=cand)
    va_signal = signal_from_variant_analysis(variant_analysis, candidate=cand)
    vcb_signal = signal_from_vuln_chain_builder(vuln_chain_builder, candidate=cand)
    dcr_signal = signal_from_deep_code_reasoning(deep_code_reasoning, candidate=cand)
    fdr_signal = signal_from_finding_dedup_risk(finding_dedup_risk, candidate=cand)
    hg_signal = signal_from_human_gate_dry_run(human_gate_dry_run, candidate=cand)
    amem_signal = signal_from_agent_memory(agent_memory, candidate=cand)
    cscan_signal = signal_from_continuous_scan(continuous_scan, candidate=cand)
    pval_signal = signal_from_patch_validation(patch_validation, candidate=cand)
    dres_signal = signal_from_deep_research(deep_research, candidate=cand)
    lh_signal = signal_from_long_horizon(long_horizon, candidate=cand)
    kb_signal = signal_from_knowledge_base(knowledge_base, candidate=cand)
    mhal_signal = signal_from_multi_hour_agent_loop(multi_hour_agent_loop, candidate=cand)
    wclk_signal = signal_from_wall_clock_multi_hour_runner(wall_clock_multi_hour_runner, candidate=cand)
    hra_signal = signal_from_human_review_approvals(human_review_approvals, candidate=cand)
    rpda_signal = signal_from_residual_patch_decision_api(residual_patch_decision_api, candidate=cand)
    residual_signal = signal_from_residual_runner(residual_runner, candidate=cand)
    web_signal = signal_from_authorized_web_api(authorized_web_api, candidate=cand)
    gate_signal = signal_from_residual_gate(residual_gates, candidate=cand)
    sgrep_run = signal_from_local_runner(semgrep_runner, engine_name=ENGINE_SEMGREP_RUNNER)
    cql_run = signal_from_local_runner(codeql_runner, engine_name=ENGINE_CODEQL_RUNNER)

    verdict = build_multi_engine_verdict(
        candidate=cand,
        hunter_signal=_prior(ENGINE_HUNTER),
        codebase_map_signal=_prior(ENGINE_CODEBASE_MAP),
        report_bridge_signal=_prior(ENGINE_REPORT_BRIDGE),
        human_evidence_signal=_prior(ENGINE_HUMAN_EVIDENCE),
        semgrep_signal=_prior(ENGINE_SEMGREP),
        codeql_signal=_prior(ENGINE_CODEQL),
        crs_fuzzing_signal=crs_signal,
        local_fuzz_sandbox_signal=sandbox_signal,
        local_fuzz_runner_signal=runner_signal,
        crash_triage_signal=triage_signal,
        crash_regression_signal=regression_signal,
        crash_codepath_signal=codepath_signal,
        protocol_aware_fuzzing_signal=paf_signal,
        patch_diff_learner_signal=pdl_signal,
        variant_analysis_signal=va_signal,
        vuln_chain_builder_signal=vcb_signal,
        deep_code_reasoning_signal=dcr_signal,
        finding_dedup_risk_signal=fdr_signal,
        human_gate_dry_run_signal=hg_signal,
        agent_memory_signal=amem_signal,
        continuous_scan_signal=cscan_signal,
        patch_validation_signal=pval_signal,
        deep_research_signal=dres_signal,
        long_horizon_signal=lh_signal,
        knowledge_base_signal=kb_signal,
        multi_hour_agent_loop_signal=mhal_signal,
        wall_clock_multi_hour_runner_signal=wclk_signal,
        human_review_approvals_signal=hra_signal,
        residual_patch_decision_api_signal=rpda_signal,
        residual_runner_signal=residual_signal,
        authorized_web_api_signal=web_signal,
        residual_gate_signal=gate_signal,
        semgrep_runner_signal=sgrep_run,
        codeql_runner_signal=cql_run,
        scope_allowed=scope_allowed,
    )
    payload = verdict.model_dump()
    return MultiEngineVerdict(
        **{
            **payload,
            "execution_allowed": False,
            "validation_allowed": False,
            "report_submission_allowed": False,
            "finding_promotion_allowed": False,
            "confirmed_vulnerability": False,
        }
    )


def attach_deeper_multi_engine_to_bridge_result(
    bridge_result: dict[str, Any],
) -> dict[str, Any]:
    """Second-pass multi-engine deepen after CRS/residual/Web/API attaches.

    Updates multi_engine_verdicts and draft multi_engine_verdict fields in place.
    Never unlocks execute/submit/promote.
    """
    if not isinstance(bridge_result, dict):
        raise MultiEngineVerifierError("bridge_result_must_be_object")

    out = dict(bridge_result)
    crs = out.get("crs_fuzzing") if isinstance(out.get("crs_fuzzing"), dict) else None
    sandbox = out.get("local_fuzz_sandbox") if isinstance(out.get("local_fuzz_sandbox"), dict) else None
    runner = out.get("local_fuzz_runner") if isinstance(out.get("local_fuzz_runner"), dict) else None
    triage = out.get("crash_triage") if isinstance(out.get("crash_triage"), dict) else None
    regression = out.get("crash_regression") if isinstance(out.get("crash_regression"), dict) else None
    codepath = out.get("crash_codepath") if isinstance(out.get("crash_codepath"), dict) else None
    paf = out.get("protocol_aware_fuzzing") if isinstance(out.get("protocol_aware_fuzzing"), dict) else None
    pdl = out.get("patch_diff_learner") if isinstance(out.get("patch_diff_learner"), dict) else None
    va = out.get("variant_analysis") if isinstance(out.get("variant_analysis"), dict) else None
    vcb = out.get("vuln_chain_builder") if isinstance(out.get("vuln_chain_builder"), dict) else None
    dcr = out.get("deep_code_reasoning") if isinstance(out.get("deep_code_reasoning"), dict) else None
    fdrisk = out.get("finding_dedup_risk") if isinstance(out.get("finding_dedup_risk"), dict) else None
    hg_dry = out.get("human_gate_dry_run") if isinstance(out.get("human_gate_dry_run"), dict) else None
    amem = out.get("agent_memory") if isinstance(out.get("agent_memory"), dict) else None
    cscan = out.get("continuous_scan") if isinstance(out.get("continuous_scan"), dict) else None
    pval = out.get("patch_validation") if isinstance(out.get("patch_validation"), dict) else None
    dres = out.get("deep_research") if isinstance(out.get("deep_research"), dict) else None
    lh = out.get("long_horizon") if isinstance(out.get("long_horizon"), dict) else None
    kb = out.get("knowledge_base") if isinstance(out.get("knowledge_base"), dict) else None
    mhal = out.get("multi_hour_agent_loop") if isinstance(out.get("multi_hour_agent_loop"), dict) else None
    wclk = out.get("wall_clock_multi_hour_runner") if isinstance(out.get("wall_clock_multi_hour_runner"), dict) else None
    rpda = out.get("residual_patch_decision_api") if isinstance(out.get("residual_patch_decision_api"), dict) else None
    if rpda is None and (
        out.get("residual_patch_decision_api_status")
        or out.get("residual_patch_decision_api_present")
        or out.get("residual_patch_decision_api_count")
    ):
        rpda = {
            "status": out.get("residual_patch_decision_api_status"),
            "decision_count": out.get("residual_patch_decision_api_count"),
            "decided_count": out.get("residual_patch_decision_api_decided_count"),
            "residual_count": out.get("residual_patch_decision_api_residual_count"),
            "patch_count": out.get("residual_patch_decision_api_patch_count"),
            "export_written": out.get("residual_patch_decision_api_export_written"),
            "present": out.get("residual_patch_decision_api_present"),
            "execution_allowed": False,
            "validation_allowed": False,
            "report_submission_allowed": False,
            "confirmed_vulnerability": False,
            "auto_pr_allowed": False,
            "patch_ready": False,
            "pr_opened": False,
            "finding_promotion_allowed": False,
        }
    hra_payload = None
    if isinstance(out.get("human_review_approvals_summary"), dict):
        hra_payload = {
            **out["human_review_approvals_summary"],
            "human_review_approvals_status": out.get("human_review_approvals_status"),
            "human_review_approvals_count": out.get("human_review_approvals_count"),
            "human_review_approvals_decided_count": out.get("human_review_approvals_decided_count"),
            "human_review_approvals_residual_count": out.get("human_review_approvals_residual_count"),
            "human_review_approvals_patch_count": out.get("human_review_approvals_patch_count"),
            "human_review_approvals_present": out.get("human_review_approvals_present"),
            "approvals": out.get("human_review_approvals") or [],
            "present": bool(out.get("human_review_approvals_present")),
            "execution_allowed": False,
            "validation_allowed": False,
            "report_submission_allowed": False,
            "confirmed_vulnerability": False,
            "auto_pr_allowed": False,
            "patch_ready": False,
            "pr_opened": False,
            "finding_promotion_allowed": False,
        }
    elif isinstance(out.get("human_review_approvals_bundle"), dict):
        hra_payload = out.get("human_review_approvals_bundle")
    elif isinstance(out.get("human_review_approvals"), list):
        hra_payload = {
            "approvals": out.get("human_review_approvals"),
            "present": bool(out.get("human_review_approvals_present")),
            "human_review_approvals_status": out.get("human_review_approvals_status"),
            "human_review_approvals_count": out.get("human_review_approvals_count"),
            "human_review_approvals_decided_count": out.get("human_review_approvals_decided_count"),
            "execution_allowed": False,
            "validation_allowed": False,
            "report_submission_allowed": False,
            "confirmed_vulnerability": False,
            "auto_pr_allowed": False,
            "patch_ready": False,
        }
    residual = out.get("residual_runner") if isinstance(out.get("residual_runner"), dict) else None
    web = out.get("authorized_web_api") if isinstance(out.get("authorized_web_api"), dict) else None
    gates = out.get("human_residual_gates")
    if not isinstance(gates, list):
        gates = []
    sgrep = out.get("semgrep_runner") if isinstance(out.get("semgrep_runner"), dict) else None
    cql = out.get("codeql_runner") if isinstance(out.get("codeql_runner"), dict) else None

    def _deepen_one(base: dict[str, Any], candidate: dict[str, Any] | None) -> dict[str, Any]:
        deep = deepen_multi_engine_verdict(
            base,
            candidate=candidate,
            crs_fuzzing=crs,
            local_fuzz_sandbox=sandbox,
            local_fuzz_runner=runner,
            crash_triage=triage,
            crash_regression=regression,
            crash_codepath=codepath,
            protocol_aware_fuzzing=paf,
            patch_diff_learner=pdl,
            variant_analysis=va,
            vuln_chain_builder=vcb,
            deep_code_reasoning=dcr,
                finding_dedup_risk=fdrisk,
            human_gate_dry_run=hg_dry,
            agent_memory=amem,
            continuous_scan=cscan,
            patch_validation=pval,
            deep_research=dres,
            long_horizon=lh,
            knowledge_base=kb,
            multi_hour_agent_loop=mhal,
            wall_clock_multi_hour_runner=wclk,
            human_review_approvals=hra_payload,
            residual_patch_decision_api=rpda,
            residual_runner=residual,
            authorized_web_api=web,
            residual_gates=gates,
            semgrep_runner=sgrep,
            codeql_runner=cql,
            scope_allowed=True,
        )
        payload = deep.model_dump()
        payload["execution_allowed"] = False
        payload["validation_allowed"] = False
        payload["report_submission_allowed"] = False
        payload["finding_promotion_allowed"] = False
        payload["confirmed_vulnerability"] = False
        payload["deep_stack_attached"] = True
        payload["engine_count"] = len(payload.get("engines") or [])
        if base.get("advisory_attached"):
            payload["advisory_attached"] = True
        return payload

    deepened_verdicts: list[dict[str, Any]] = []
    for verdict in out.get("multi_engine_verdicts") or []:
        if not isinstance(verdict, dict):
            continue
        cand: dict[str, Any] = {
            "candidate_id": verdict.get("candidate_id") or "",
            "root_cause_id": verdict.get("root_cause_id") or "",
            "refutation_questions": verdict.get("review_questions") or [],
        }
        for draft in out.get("drafts") or []:
            if not isinstance(draft, dict):
                continue
            if str(draft.get("candidate_id") or "") == str(cand["candidate_id"]):
                cand = {
                    **cand,
                    "route": draft.get("route"),
                    "affected_code_path": draft.get("affected_code_path"),
                    "vuln_type": draft.get("vuln_type"),
                    "source_fact_refs": draft.get("source_fact_refs"),
                }
                break
        deepened_verdicts.append(_deepen_one(verdict, cand))

    if not deepened_verdicts and (crs or residual or web or gates or sgrep or cql or hg_dry):
        deepened_verdicts.append(
            _deepen_one(
                {
                    "candidate_id": str(out.get("package_id") or "package"),
                    "root_cause_id": "",
                    "engines": [],
                },
                {"candidate_id": str(out.get("package_id") or "package")},
            )
        )

    if deepened_verdicts:
        out["multi_engine_verdicts"] = deepened_verdicts
        by_cid = {
            str(v.get("candidate_id") or ""): v
            for v in deepened_verdicts
            if isinstance(v, dict)
        }
        drafts = []
        for draft in out.get("drafts") or []:
            if not isinstance(draft, dict):
                drafts.append(draft)
                continue
            d = dict(draft)
            cid = str(d.get("candidate_id") or "")
            if cid in by_cid:
                d["multi_engine_verdict"] = by_cid[cid]
            elif isinstance(d.get("multi_engine_verdict"), dict):
                d["multi_engine_verdict"] = _deepen_one(
                    d["multi_engine_verdict"],
                    {
                        "candidate_id": cid,
                        "root_cause_id": d.get("root_cause_id"),
                        "route": d.get("route"),
                        "affected_code_path": d.get("affected_code_path"),
                        "vuln_type": d.get("vuln_type"),
                        "source_fact_refs": d.get("source_fact_refs"),
                    },
                )
            drafts.append(d)
        out["drafts"] = drafts

    engine_names: set[str] = set()
    for v in out.get("multi_engine_verdicts") or []:
        if not isinstance(v, dict):
            continue
        for eng in v.get("engines") or []:
            if isinstance(eng, dict) and eng.get("engine"):
                engine_names.add(str(eng["engine"]))
    out["multi_engine_deep"] = True
    out["multi_engine_engine_count"] = len(engine_names)
    out["multi_engine_engines"] = sorted(engine_names)
    out["execution_allowed"] = False
    out["validation_allowed"] = False
    out["report_submission_allowed"] = False
    out["confirmed_vulnerability"] = False
    if out.get("submission_blocked") is not True:
        out["submission_blocked"] = True
    return out


def _path_tokens(path: str) -> list[str]:
    text = path.replace("\\", "/").lower()
    parts = re.split(r"[/:._\\-]+", text)
    return [p for p in parts if len(p) >= 4 and p not in {"code", "path", "src", "app", "missing"}]


def _normalize_engine(name: str, raw: dict[str, Any]) -> EngineSignal:
    if not isinstance(raw, dict):
        raise MultiEngineVerifierError(f"engine_signal_must_be_object:{name}")
    supports = raw.get("supports_candidate")
    if supports is not None and not isinstance(supports, bool):
        raise MultiEngineVerifierError(f"supports_candidate_must_be_bool_or_null:{name}")
    status = str(raw.get("status") or "ready")
    notes = [str(n) for n in (raw.get("notes") or []) if str(n).strip()]
    refs = [str(r) for r in (raw.get("evidence_refs") or []) if str(r).strip()]
    return EngineSignal(
        engine=name,
        status=status,
        supports_candidate=supports,
        notes=notes[:20],
        evidence_refs=refs[:20],
    )


def _agreement_score(engines: list[EngineSignal]) -> float:
    decided = [e for e in engines if e.supports_candidate is not None]
    if not decided:
        return 0.0
    true_n = sum(1 for e in decided if e.supports_candidate is True)
    false_n = sum(1 for e in decided if e.supports_candidate is False)
    majority = max(true_n, false_n)
    return round(majority / len(decided), 4)


def _default_questions(candidate: dict[str, Any]) -> list[str]:
    qs = [str(q) for q in (candidate.get("refutation_questions") or []) if str(q).strip()]
    if not qs:
        qs = [
            "Does local static evidence still show a missing control before the sensitive sink?",
            "Is there an alternate authorized control path not modeled in the package?",
        ]
    qs.append("Has any live validation been avoided (required default)?")
    return qs[:12]


__all__ = [
    "ALLOWED_VERDICTS",
    "ENGINE_AUTHORIZED_WEB_API",
    "ENGINE_CODEBASE_MAP",
    "ENGINE_CODEQL",
    "ENGINE_CODEQL_RUNNER",
    "ENGINE_CRS_FUZZING",
    "ENGINE_CRASH_REGRESSION",
    "ENGINE_CRASH_CODEPATH",
    "ENGINE_HUMAN_GATE_DRY_RUN",
    "ENGINE_AGENT_MEMORY",
    "ENGINE_CONTINUOUS_SCAN",
    "ENGINE_PATCH_VALIDATION",
    "ENGINE_DEEP_RESEARCH",
    "ENGINE_LONG_HORIZON",
    "ENGINE_KNOWLEDGE_BASE",
    "ENGINE_MULTI_HOUR_AGENT_LOOP",
    "ENGINE_WALL_CLOCK_MULTI_HOUR_RUNNER",
    "ENGINE_HUMAN_REVIEW_APPROVALS",
    "ENGINE_RESIDUAL_PATCH_DECISION_API",
    "ENGINE_LOCAL_FUZZ_SANDBOX",
    "ENGINE_HUMAN_EVIDENCE",
    "ENGINE_HUNTER",
    "ENGINE_REPORT_BRIDGE",
    "ENGINE_RESIDUAL_GATE",
    "ENGINE_RESIDUAL_RUNNER",
    "ENGINE_SEMGREP",
    "ENGINE_SEMGREP_RUNNER",
    "EngineSignal",
    "MultiEngineVerdict",
    "MultiEngineVerifierError",
    "VERDICT_BLOCKED",
    "VERDICT_FALSE_POSITIVE_LIKELY",
    "VERDICT_LOCAL_STATIC_CONSISTENT",
    "VERDICT_NEEDS_HUMAN_REVIEW",
    "VERDICT_NEEDS_VERIFICATION",
    "attach_deeper_multi_engine_to_bridge_result",
    "build_multi_engine_verdict",
    "deepen_multi_engine_verdict",
    "signal_from_authorized_web_api",
    "signal_from_crs_fuzzing",
    "signal_from_patch_diff_learner",
    "signal_from_variant_analysis",
    "signal_from_vuln_chain_builder",
    "signal_from_deep_code_reasoning",
    "signal_from_finding_dedup_risk",
    "signal_from_crash_regression",
    "signal_from_crash_codepath",
    "signal_from_human_gate_dry_run",
    "signal_from_agent_memory",
    "signal_from_continuous_scan",
    "signal_from_patch_validation",
    "signal_from_deep_research",
    "signal_from_long_horizon",
    "signal_from_knowledge_base",
    "signal_from_multi_hour_agent_loop",
    "signal_from_wall_clock_multi_hour_runner",
    "signal_from_human_review_approvals",
    "signal_from_residual_patch_decision_api",
    "signal_from_crash_triage",
    "signal_from_local_fuzz_sandbox",
    "signal_from_local_runner",
    "signal_from_residual_gate",
    "signal_from_residual_runner",
    "verdict_from_hunter_and_map",
]
