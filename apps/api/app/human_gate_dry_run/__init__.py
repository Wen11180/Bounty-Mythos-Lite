"""End-to-end human-gate dry-run for authorized packages (final-scheme Human Gate).

Lawful research only:
- Walks residual gate -> approvals -> report draft -> patch/PR context
- Proves every stage remains submission-blocked and non-executing
- Never calls HackerOne / never live-validates / never auto-submits
- Optional export under package _export/human_gate_dry_run/ with human flag

This proves the human-gate chain offline without requiring a live H1 token.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


STATUS_READY = "human_gate_dry_run_ready"
STATUS_EMPTY = "human_gate_dry_run_empty"
STATUS_PACKAGE_MISSING = "human_gate_dry_run_package_missing"
STATUS_BRIDGE_MISSING = "human_gate_dry_run_bridge_missing"
STATUS_WRITTEN = "human_gate_dry_run_export_written"
STATUS_FAILED_SAFETY = "human_gate_dry_run_safety_failure"

SAFETY_INVARIANTS = [
    "authorized_package_or_bridge_only",
    "no_public_target_scanning",
    "no_live_validation",
    "no_network_access",
    "no_automatic_report_submission",
    "no_hackerone_probe",
    "no_finding_promotion",
    "no_crash_promotion",
    "human_review_required_before_any_submit",
    "approvals_never_unlock_submit",
]

_UNSAFE_TRUE_KEYS = (
    "execution_allowed",
    "validation_allowed",
    "report_submission_allowed",
    "confirmed_vulnerability",
    "finding_promotion_allowed",
    "crash_promotion_allowed",
    "auto_pr_allowed",
    "pr_opened",
    "patch_ready",
    "test_auto_execute_allowed",
    "package_code_execution_allowed",
    "process_spawn_allowed",
    "network_access",
    "live_validation",
)


class HumanGateDryRunError(ValueError):
    """Raised when bridge attach receives invalid input."""


@dataclass(frozen=True)
class GateCheckpoint:
    checkpoint_id: str
    title: str
    status: str  # pass | fail | skip | warn
    observed: str = ""
    required: str = ""
    submission_still_blocked: bool = True
    notes: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class HumanGateDryRunResult:
    stage: str
    inspirations: list[str]
    execution_mode: str
    status: str
    package_id: str = ""
    package_root: str = ""
    checkpoints: list[GateCheckpoint] = field(default_factory=list)
    checkpoint_count: int = 0
    pass_count: int = 0
    fail_count: int = 0
    skip_count: int = 0
    warn_count: int = 0
    chain_complete: bool = False
    chain_safe: bool = False
    human_allow_export_write: bool = False
    export_written: bool = False
    export_count: int = 0
    export_root_relative: str = "_export/human_gate_dry_run"
    run_stamp: str = ""
    execution_allowed: bool = False
    validation_allowed: bool = False
    report_submission_allowed: bool = False
    confirmed_vulnerability: bool = False
    finding_promotion_allowed: bool = False
    crash_promotion_allowed: bool = False
    auto_pr_allowed: bool = False
    pr_opened: bool = False
    patch_ready: bool = False
    network_access: bool = False
    live_validation: bool = False
    process_spawn_allowed: bool = False
    safety_invariants: list[str] = field(default_factory=list)
    next_allowed_action: str = (
        "Human reviews dry-run checkpoints offline; Mythos never auto-submits."
    )
    notes: list[str] = field(default_factory=list)
    summary: str = ""

    def to_dict(self) -> dict[str, Any]:
        return _force_safety_dict(asdict(self))


def build_human_gate_dry_run(
    *,
    package_root: str | Path | None = None,
    package_id: str = "",
    bridge_result: dict[str, Any] | None = None,
    human_allow_export_write: bool = False,
) -> HumanGateDryRunResult:
    """Alias for dry-run builder (always non-executing)."""
    return run_human_gate_dry_run(
        package_root=package_root,
        package_id=package_id,
        bridge_result=bridge_result,
        human_allow_export_write=human_allow_export_write,
    )


def run_human_gate_dry_run(
    *,
    package_root: str | Path | None = None,
    package_id: str = "",
    bridge_result: dict[str, Any] | None = None,
    human_allow_export_write: bool = False,
) -> HumanGateDryRunResult:
    """Evaluate end-to-end human-gate chain on an authorized bridge payload."""
    root: Path | None = None
    root_s = ""
    if package_root is not None and str(package_root).strip():
        root = Path(package_root)
        root_s = str(root)
        if not root.is_dir():
            return _empty(
                status=STATUS_PACKAGE_MISSING,
                package_id=package_id,
                package_root=root_s,
                notes=["package_root_missing_or_not_directory"],
                human_allow_export_write=bool(human_allow_export_write),
            )

    bridge = bridge_result if isinstance(bridge_result, dict) else {}
    if not bridge:
        return _empty(
            status=STATUS_BRIDGE_MISSING if root else STATUS_EMPTY,
            package_id=package_id,
            package_root=root_s,
            notes=["bridge_result_absent_or_empty"],
            human_allow_export_write=bool(human_allow_export_write),
        )

    pid = package_id or str(bridge.get("package_id") or "")
    checkpoints = _evaluate_checkpoints(bridge, package_id=pid, package_root=root_s)
    pass_n = sum(1 for c in checkpoints if c.status == "pass")
    fail_n = sum(1 for c in checkpoints if c.status == "fail")
    skip_n = sum(1 for c in checkpoints if c.status == "skip")
    warn_n = sum(1 for c in checkpoints if c.status == "warn")
    chain_safe = fail_n == 0 and _bridge_is_submission_blocked(bridge)
    # Chain is "complete" when core gate stages were observed (not skipped as absent)
    core_ids = {
        "HG-01-package",
        "HG-02-submission-blocked",
        "HG-03-residual-gate",
        "HG-04-report-draft-safety",
        "HG-05-multi-engine-not-confirmed",
        "HG-09-global-safety-scrub",
    }
    core_pass = {c.checkpoint_id for c in checkpoints if c.status == "pass"}
    chain_complete = core_ids.issubset(core_pass) and chain_safe

    notes = [
        "offline_human_gate_dry_run",
        "never_probes_hackerone",
        "approvals_never_unlock_submit",
    ]
    if chain_complete:
        notes.append("core_gate_chain_complete_and_safe")
    if fail_n:
        notes.append("safety_failures_detected")

    export_written = False
    export_count = 0
    run_stamp = ""
    status = STATUS_FAILED_SAFETY if fail_n else STATUS_READY

    result = HumanGateDryRunResult(
        stage="v2_human_gate_dry_run",
        inspirations=["final-scheme-8.3", "final-scheme-V2-Human-Gate", "XBOW-process"],
        execution_mode="plan_only",
        status=status,
        package_id=pid,
        package_root=root_s or str(bridge.get("package_root") or ""),
        checkpoints=checkpoints,
        checkpoint_count=len(checkpoints),
        pass_count=pass_n,
        fail_count=fail_n,
        skip_count=skip_n,
        warn_count=warn_n,
        chain_complete=chain_complete,
        chain_safe=chain_safe,
        human_allow_export_write=bool(human_allow_export_write),
        safety_invariants=list(SAFETY_INVARIANTS),
        notes=notes,
        summary=_summary(pass_n, fail_n, skip_n, warn_n, chain_complete, chain_safe),
        next_allowed_action=(
            "Human reviews dry-run evidence; when H1 unblocked, reuse the same gates "
            "before any manual submission outside Mythos auto-submit."
            if chain_safe
            else "Fix failing checkpoints before considering any human submission path."
        ),
    )
    result = _force_safety(result)

    if human_allow_export_write and root is not None:
        written, count, stamp = _export_result(root, result)
        if written:
            result = _force_safety(
                HumanGateDryRunResult(
                    **{
                        **asdict(result),
                        "status": STATUS_WRITTEN if fail_n == 0 else STATUS_FAILED_SAFETY,
                        "export_written": True,
                        "export_count": count,
                        "run_stamp": stamp,
                        "notes": list(result.notes) + ["export_written_under_package_tmp"],
                    }
                )
            )
        else:
            result = _force_safety(
                HumanGateDryRunResult(
                    **{
                        **asdict(result),
                        "notes": list(result.notes) + ["export_skipped_or_failed"],
                    }
                )
            )
    elif human_allow_export_write and root is None:
        result = _force_safety(
            HumanGateDryRunResult(
                **{
                    **asdict(result),
                    "notes": list(result.notes) + ["export_requested_but_no_package_root"],
                }
            )
        )

    return result


def attach_human_gate_dry_run_to_bridge_result(
    bridge_result: dict[str, Any],
    *,
    package_root: str | Path | None = None,
    human_gate_dry_run: dict[str, Any] | HumanGateDryRunResult | None = None,
    human_allow_export_write: bool = False,
) -> dict[str, Any]:
    """Attach human-gate dry-run; never unlocks execute/promote/submit."""
    if not isinstance(bridge_result, dict):
        raise HumanGateDryRunError("bridge_result_must_be_object")

    package_id = str(bridge_result.get("package_id") or "")
    resolved_root = package_root or bridge_result.get("package_root")

    if isinstance(human_gate_dry_run, HumanGateDryRunResult):
        payload = human_gate_dry_run.to_dict()
    elif isinstance(human_gate_dry_run, dict):
        payload = _force_safety_dict(dict(human_gate_dry_run))
    else:
        payload = run_human_gate_dry_run(
            package_root=resolved_root,
            package_id=package_id,
            bridge_result=bridge_result,
            human_allow_export_write=bool(human_allow_export_write),
        ).to_dict()

    if not payload.get("package_id") and package_id:
        payload["package_id"] = package_id
    payload = _force_safety_dict(payload)

    out = dict(bridge_result)
    out["human_gate_dry_run"] = payload
    out["human_gate_dry_run_present"] = True
    out["human_gate_dry_run_status"] = str(payload.get("status") or STATUS_EMPTY)
    out["human_gate_dry_run_checkpoint_count"] = int(payload.get("checkpoint_count") or 0)
    out["human_gate_dry_run_pass_count"] = int(payload.get("pass_count") or 0)
    out["human_gate_dry_run_fail_count"] = int(payload.get("fail_count") or 0)
    out["human_gate_dry_run_chain_complete"] = bool(payload.get("chain_complete"))
    out["human_gate_dry_run_chain_safe"] = bool(payload.get("chain_safe"))
    out["human_gate_dry_run_export_written"] = bool(payload.get("export_written"))
    out["execution_allowed"] = False
    out["validation_allowed"] = False
    out["report_submission_allowed"] = False
    out["confirmed_vulnerability"] = False
    if out.get("submission_blocked") is not True:
        out["submission_blocked"] = True
    return out


def _evaluate_checkpoints(
    bridge: dict[str, Any],
    *,
    package_id: str,
    package_root: str,
) -> list[GateCheckpoint]:
    cps: list[GateCheckpoint] = []

    # HG-01 package identity
    pid = str(bridge.get("package_id") or package_id or "")
    cps.append(
        GateCheckpoint(
            checkpoint_id="HG-01-package",
            title="Authorized package identity present",
            status="pass" if pid else "fail",
            observed=pid or "missing",
            required="non-empty package_id",
            submission_still_blocked=_bridge_is_submission_blocked(bridge),
            notes=["package_context_only"],
        )
    )

    # HG-02 global submission blocked
    blocked = _bridge_is_submission_blocked(bridge)
    cps.append(
        GateCheckpoint(
            checkpoint_id="HG-02-submission-blocked",
            title="Package-level submission remains blocked",
            status="pass" if blocked else "fail",
            observed=f"submission_blocked={bridge.get('submission_blocked')} "
            f"report_submission_allowed={bridge.get('report_submission_allowed')}",
            required="submission_blocked is True AND report_submission_allowed is not True",
            submission_still_blocked=blocked,
        )
    )

    # HG-03 residual gate(s)
    gates = bridge.get("human_residual_gates") if isinstance(bridge.get("human_residual_gates"), list) else []
    gate_statuses = [
        str(g.get("status") or "")
        for g in gates
        if isinstance(g, dict)
    ]
    residual_present = bool(gates) or bool(bridge.get("residual_checklist_present"))
    residual_ok = residual_present and all(
        g.get("report_submission_allowed") is not True
        and g.get("execution_allowed") is not True
        and g.get("confirmed_vulnerability") is not True
        for g in gates
        if isinstance(g, dict)
    )
    if not residual_present:
        residual_status = "warn"
        residual_obs = "no residual gates/checklist attached"
    elif residual_ok:
        residual_status = "pass"
        residual_obs = f"gates={gate_statuses or ['-']}; residual_file={bridge.get('residual_checklist_present')}"
    else:
        residual_status = "fail"
        residual_obs = f"unsafe residual gate flags gates={gate_statuses}"
    cps.append(
        GateCheckpoint(
            checkpoint_id="HG-03-residual-gate",
            title="Human residual gate present and non-submitting",
            status=residual_status,
            observed=residual_obs,
            required="residual gate or checklist; never unlocks submit/execute",
            submission_still_blocked=blocked and residual_status != "fail",
        )
    )

    # HG-04 report drafts safety
    drafts = bridge.get("drafts") if isinstance(bridge.get("drafts"), list) else []
    draft_n = len([d for d in drafts if isinstance(d, dict)])
    draft_unsafe = any(
        d.get("report_submission_allowed") is True
        or d.get("execution_allowed") is True
        or d.get("confirmed_vulnerability") is True
        for d in drafts
        if isinstance(d, dict)
    )
    if draft_n == 0:
        draft_status = "pass"  # empty retain is valid; still blocked
        draft_obs = "draft_count=0 (empty retain OK if package submission blocked)"
    elif draft_unsafe:
        draft_status = "fail"
        draft_obs = f"draft_count={draft_n}; unsafe draft flags"
    else:
        draft_status = "pass"
        draft_obs = f"draft_count={draft_n}; all drafts non-submitting"
    cps.append(
        GateCheckpoint(
            checkpoint_id="HG-04-report-draft-safety",
            title="Report drafts stay submission-blocked",
            status=draft_status,
            observed=draft_obs,
            required="no draft sets report_submission_allowed/execution/confirmed true",
            submission_still_blocked=blocked and draft_status != "fail",
        )
    )

    # HG-05 multi-engine not confirmed
    mev_confirmed = False
    mev_count = 0
    for d in drafts:
        if not isinstance(d, dict):
            continue
        v = d.get("multi_engine_verdict")
        if isinstance(v, dict):
            mev_count += 1
            if v.get("confirmed_vulnerability") is True or v.get("execution_allowed") is True:
                mev_confirmed = True
    for v in bridge.get("multi_engine_verdicts") or []:
        if isinstance(v, dict):
            mev_count += 1
            if v.get("confirmed_vulnerability") is True or v.get("execution_allowed") is True:
                mev_confirmed = True
    if mev_count == 0 and draft_n == 0:
        mev_status = "pass"
        mev_obs = "no multi-engine payloads (empty retain OK)"
    elif mev_confirmed:
        mev_status = "fail"
        mev_obs = f"mev_payloads={mev_count}; confirmed/execution true"
    else:
        mev_status = "pass"
        mev_obs = f"mev_payloads={mev_count}; never confirmed; deep={bridge.get('multi_engine_deep')}"
    cps.append(
        GateCheckpoint(
            checkpoint_id="HG-05-multi-engine-not-confirmed",
            title="Multi-engine never confirms vulnerability",
            status=mev_status,
            observed=mev_obs,
            required="confirmed_vulnerability and execution_allowed remain false",
            submission_still_blocked=blocked and mev_status != "fail",
        )
    )

    # HG-06 residual/patch approvals never unlock
    approvals = bridge.get("human_review_approvals")
    if not isinstance(approvals, list):
        approvals = []
        bundle = bridge.get("human_review_approvals_bundle")
        if isinstance(bundle, dict) and isinstance(bundle.get("approvals"), list):
            approvals = bundle["approvals"]
    if not approvals and not bridge.get("human_review_approvals_present"):
        appr_status = "skip"
        appr_obs = "no durable approvals present (optional offline)"
    else:
        unsafe_appr = any(
            a.get("report_submission_allowed") is True
            or a.get("execution_allowed") is True
            or a.get("confirmed_vulnerability") is True
            or a.get("auto_pr_allowed") is True
            or a.get("patch_ready") is True
            for a in approvals
            if isinstance(a, dict)
        )
        appr_status = "fail" if unsafe_appr else "pass"
        appr_obs = f"approvals={len(approvals)}; present={bridge.get('human_review_approvals_present')}"
    cps.append(
        GateCheckpoint(
            checkpoint_id="HG-06-approvals-context-only",
            title="Human review approvals remain context-only",
            status=appr_status,
            observed=appr_obs,
            required="approvals never set submit/execute/confirmed/auto_pr/patch_ready",
            submission_still_blocked=blocked and appr_status != "fail",
            notes=["optional_offline_approvals"],
        )
    )

    # HG-07 patch / PR workflow blocked
    ppr_status_val = str(bridge.get("patch_pr_workflow_status") or "")
    ppr_export = bool(bridge.get("patch_pr_export_written"))
    ppr_ready = bridge.get("patch_pr_workflow_ready_count")
    unsafe_pr = (
        bridge.get("auto_pr_allowed") is True
        or bridge.get("pr_opened") is True
        or bridge.get("patch_ready") is True
    )
    if not ppr_status_val and bridge.get("patch_suggestion_present") is not True:
        pr_status = "skip"
        pr_obs = "patch/PR workflow not attached"
    elif unsafe_pr:
        pr_status = "fail"
        pr_obs = "auto_pr/pr_opened/patch_ready true"
    else:
        pr_status = "pass"
        pr_obs = f"ppr={ppr_status_val or '-'}; ready={ppr_ready}; export={ppr_export}"
    cps.append(
        GateCheckpoint(
            checkpoint_id="HG-07-patch-pr-blocked",
            title="Patch / external PR stay non-auto",
            status=pr_status,
            observed=pr_obs,
            required="auto_pr_allowed/pr_opened/patch_ready never true",
            submission_still_blocked=blocked and pr_status != "fail",
        )
    )

    # HG-08 crash residual stack never promotes
    crash_bits = [
        bridge.get("crash_triage"),
        bridge.get("crash_regression"),
        bridge.get("crash_codepath"),
        bridge.get("local_fuzz_runner"),
    ]
    crash_present = any(isinstance(x, dict) for x in crash_bits) or any(
        bridge.get(k)
        for k in (
            "crash_triage_present",
            "crash_regression_present",
            "crash_codepath_present",
            "local_fuzz_runner_present",
        )
    )
    crash_unsafe = False
    for x in crash_bits:
        if isinstance(x, dict) and (
            x.get("crash_promotion_allowed") is True
            or x.get("finding_promotion_allowed") is True
            or x.get("report_submission_allowed") is True
            or x.get("package_code_execution_allowed") is True
            or x.get("test_auto_execute_allowed") is True
        ):
            crash_unsafe = True
    if not crash_present:
        crash_status = "skip"
        crash_obs = "crash residual stack not attached"
    elif crash_unsafe:
        crash_status = "fail"
        crash_obs = "crash stack promotion/execute flags true"
    else:
        crash_status = "pass"
        crash_obs = (
            f"ctr={bridge.get('crash_triage_status')} "
            f"creg={bridge.get('crash_regression_status')} "
            f"cpath={bridge.get('crash_codepath_status')}"
        )
    cps.append(
        GateCheckpoint(
            checkpoint_id="HG-08-crash-stack-non-promote",
            title="Crash residual stack never promotes",
            status=crash_status,
            observed=crash_obs,
            required="promotion / package-code-exec / test-auto-run remain false",
            submission_still_blocked=blocked and crash_status != "fail",
        )
    )

    # HG-09 global scrub of unsafe true flags on bridge top-level
    unsafe_true = [k for k in _UNSAFE_TRUE_KEYS if bridge.get(k) is True]
    # submission_blocked should be True; not in unsafe list
    if unsafe_true:
        scrub_status = "fail"
        scrub_obs = f"unsafe_true={unsafe_true}"
    else:
        scrub_status = "pass"
        scrub_obs = "no top-level unsafe true flags"
    cps.append(
        GateCheckpoint(
            checkpoint_id="HG-09-global-safety-scrub",
            title="Top-level safety scrub",
            status=scrub_status,
            observed=scrub_obs,
            required="all high-risk allow flags false/absent",
            submission_still_blocked=blocked and scrub_status != "fail",
        )
    )

    # HG-10 next human action is non-submit auto
    next_actions = []
    for g in gates:
        if isinstance(g, dict) and g.get("next_allowed_action"):
            next_actions.append(str(g.get("next_allowed_action")))
    if bridge.get("next_allowed_action"):
        next_actions.append(str(bridge.get("next_allowed_action")))
    auto_submit_language = any(
        "auto-submit" in a.lower() or "automatically submit" in a.lower()
        for a in next_actions
    )
    if auto_submit_language:
        na_status = "fail"
        na_obs = "next action language suggests auto-submit"
    else:
        na_status = "pass"
        na_obs = (next_actions[0] if next_actions else "human residual review only")[:200]
    cps.append(
        GateCheckpoint(
            checkpoint_id="HG-10-human-next-action",
            title="Next allowed action remains human-controlled",
            status=na_status,
            observed=na_obs,
            required="no auto-submit language; human decides outside Mythos auto path",
            submission_still_blocked=blocked and na_status != "fail",
        )
    )

    return cps


def _bridge_is_submission_blocked(bridge: dict[str, Any]) -> bool:
    if bridge.get("report_submission_allowed") is True:
        return False
    if bridge.get("submission_blocked") is True:
        return True
    # fail-closed: missing submission_blocked treated as not proven blocked
    return False


def _summary(
    pass_n: int,
    fail_n: int,
    skip_n: int,
    warn_n: int,
    chain_complete: bool,
    chain_safe: bool,
) -> str:
    return (
        f"pass={pass_n} fail={fail_n} skip={skip_n} warn={warn_n}; "
        f"chain_complete={chain_complete}; chain_safe={chain_safe}"
    )


def _empty(
    *,
    status: str,
    package_id: str = "",
    package_root: str = "",
    notes: list[str] | None = None,
    human_allow_export_write: bool = False,
) -> HumanGateDryRunResult:
    return _force_safety(
        HumanGateDryRunResult(
            stage="v2_human_gate_dry_run",
            inspirations=["final-scheme-8.3", "final-scheme-V2-Human-Gate"],
            execution_mode="plan_only",
            status=status,
            package_id=package_id,
            package_root=package_root,
            human_allow_export_write=bool(human_allow_export_write),
            safety_invariants=list(SAFETY_INVARIANTS),
            notes=list(notes or []),
            chain_complete=False,
            chain_safe=False,
            summary="empty_or_missing_inputs",
        )
    )


def _force_safety(result: HumanGateDryRunResult) -> HumanGateDryRunResult:
    return HumanGateDryRunResult(
        stage=result.stage,
        inspirations=list(result.inspirations),
        execution_mode="plan_only",
        status=result.status,
        package_id=result.package_id,
        package_root=result.package_root,
        checkpoints=list(result.checkpoints),
        checkpoint_count=len(result.checkpoints),
        pass_count=result.pass_count,
        fail_count=result.fail_count,
        skip_count=result.skip_count,
        warn_count=result.warn_count,
        chain_complete=bool(result.chain_complete),
        chain_safe=bool(result.chain_safe) and result.fail_count == 0,
        human_allow_export_write=bool(result.human_allow_export_write),
        export_written=bool(result.export_written),
        export_count=int(result.export_count or 0),
        export_root_relative="_export/human_gate_dry_run",
        run_stamp=result.run_stamp,
        execution_allowed=False,
        validation_allowed=False,
        report_submission_allowed=False,
        confirmed_vulnerability=False,
        finding_promotion_allowed=False,
        crash_promotion_allowed=False,
        auto_pr_allowed=False,
        pr_opened=False,
        patch_ready=False,
        network_access=False,
        live_validation=False,
        process_spawn_allowed=False,
        safety_invariants=list(SAFETY_INVARIANTS),
        next_allowed_action=result.next_allowed_action,
        notes=list(result.notes),
        summary=result.summary,
    )


def _force_safety_dict(payload: dict[str, Any]) -> dict[str, Any]:
    out = dict(payload)
    out["execution_mode"] = "plan_only"
    for key in (
        "execution_allowed",
        "validation_allowed",
        "report_submission_allowed",
        "confirmed_vulnerability",
        "finding_promotion_allowed",
        "crash_promotion_allowed",
        "auto_pr_allowed",
        "pr_opened",
        "patch_ready",
        "network_access",
        "live_validation",
        "process_spawn_allowed",
    ):
        out[key] = False
    out["safety_invariants"] = list(SAFETY_INVARIANTS)
    # force checkpoint submission_still_blocked consistency on fails
    cps = out.get("checkpoints")
    if isinstance(cps, list):
        cleaned = []
        for c in cps:
            if not isinstance(c, dict):
                continue
            item = dict(c)
            if item.get("status") == "fail":
                item["submission_still_blocked"] = False
            cleaned.append(item)
        out["checkpoints"] = cleaned
        out["checkpoint_count"] = len(cleaned)
    if out.get("fail_count"):
        try:
            if int(out.get("fail_count") or 0) > 0:
                out["chain_safe"] = False
        except Exception:
            out["chain_safe"] = False
    return out


def _export_result(root: Path, result: HumanGateDryRunResult) -> tuple[bool, int, str]:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    export_root = (root / "_export" / "human_gate_dry_run" / stamp).resolve()
    try:
        export_root.relative_to(root.resolve())
    except ValueError:
        return False, 0, ""
    export_root.mkdir(parents=True, exist_ok=True)
    payload = result.to_dict()
    payload["export_stamp"] = stamp
    (export_root / "index.json").write_text(
        json.dumps(payload, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    lines = [
        "# Human gate dry-run (offline)",
        "",
        f"- package: `{result.package_id}`",
        f"- status: `{result.status}`",
        f"- chain_complete: `{result.chain_complete}`",
        f"- chain_safe: `{result.chain_safe}`",
        f"- summary: {result.summary}",
        "",
        "## Safety",
        "",
        "- report_submission_allowed: false",
        "- execution_allowed: false",
        "- confirmed_vulnerability: false",
        "- never probes HackerOne from this module",
        "",
        "## Checkpoints",
        "",
    ]
    for c in result.checkpoints:
        lines.append(f"### {c.checkpoint_id} — {c.title}")
        lines.append(f"- status: `{c.status}`")
        lines.append(f"- observed: {c.observed}")
        lines.append(f"- required: {c.required}")
        lines.append("")
    (export_root / "README.md").write_text("\n".join(lines), encoding="utf-8")
    return True, 1, stamp


__all__ = [
    "GateCheckpoint",
    "HumanGateDryRunError",
    "HumanGateDryRunResult",
    "STATUS_FAILED_SAFETY",
    "STATUS_READY",
    "STATUS_WRITTEN",
    "attach_human_gate_dry_run_to_bridge_result",
    "build_human_gate_dry_run",
    "run_human_gate_dry_run",
]
