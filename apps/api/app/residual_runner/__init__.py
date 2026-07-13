"""Human-approved residual runners — local static residual verification only.

Final-scheme Human Gate residual execution slice:
- Durable residual_review approval gates whether residual probes may run
- Probes are local/static only (package code + SOURCE_FACTS + offline fixtures)
- Never network, live validation, exploit payloads, or report submission
- Never unlocks execution_allowed / validation_allowed / report_submission_allowed
- Never sets confirmed_vulnerability or finding_promotion_allowed

Operator runbook automation seed (docs/hunter-ab-residual-runbook.md).
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

from app.human_residual_gate import (
    load_package_residual_checklist,
    residual_checklist_from_bundle,
)
from app.human_review_approvals import (
    APPROVAL_KIND_RESIDUAL,
    residual_flags_from_approval,
    resolve_human_review_approvals,
    select_approval_for_candidate,
)


STATUS_PLANNED = "residual_run_planned"
STATUS_COMPLETED = "residual_run_completed_local_static"
STATUS_SKIPPED_NO_APPROVAL = "skipped_no_human_approval"
STATUS_SKIPPED_REJECTED = "skipped_human_rejected_or_fp"
STATUS_SKIPPED_NO_ITEMS = "skipped_no_residual_items"
STATUS_BLOCKED = "blocked"
STATUS_EMPTY = "residual_runner_empty"

_MAX_FILES = 250
_MAX_FILE_BYTES = 256_000
_MAX_SNIFF = 48_000
_MAX_PROBES = 40

_SKIP_DIR_NAMES = {
    ".git", ".hg", ".svn", ".venv", "venv", "node_modules", "__pycache__",
    ".pytest_cache", ".mypy_cache", ".tox", "dist", "build", "coverage",
    ".idea", ".vscode", "target", "vendor",
}

_BLOCKED_NAME_PARTS = (
    "secret", "token", "cookie", "credential", "password", "apikey", "api_key",
)

_CODE_SUFFIXES = {
    ".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".py", ".go", ".rb", ".php",
    ".java", ".kt", ".rs", ".cs", ".md", ".json",
}

_CONTROL_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("ssrf_validate_url", re.compile(r"validateUrlForSSRF|isPrivateIP|isBlockedHostname|blocked.?hostname", re.I)),
    ("ssrf_fetch_sink", re.compile(r"\bfetch\s*\(|requests\.(get|post)|httpx\.|urllib\.request", re.I)),
    ("authz_can", re.compile(r"\bcan\?\(|authorize_[a-z_]+|current_user|requireAuth|hasPermission", re.I)),
    ("ownership_check", re.compile(r"owner(?:ship)?|user_id\s*==|created_by|belongs_to", re.I)),
    ("path_traversal_guard", re.compile(r"path\.normalize|realpath|safeJoin|basename\(|os\.path\.abspath", re.I)),
    ("mass_assign_guard", re.compile(r"allowed_fields|permit\(|only\(|exclude\(|safe_params|serializer\.fields", re.I)),
    ("injection_param", re.compile(r"parameterized|prepared.?statement|execute\(|raw\s+sql|f\".*SELECT", re.I)),
]

_QUESTION_HINTS: list[tuple[re.Pattern[str], list[str]]] = [
    (re.compile(r"ssrf|subscriberurl|outbound|fetch|webhook|private\s*ip|metadata", re.I),
     ["ssrf_validate_url", "ssrf_fetch_sink"]),
    (re.compile(r"authz|authoriz|permission|ownership|idor|cross.?unit|can\?", re.I),
     ["authz_can", "ownership_check"]),
    (re.compile(r"path|traversal|archive|download|file\s*path", re.I),
     ["path_traversal_guard"]),
    (re.compile(r"mass.?assign|over.?post|extra\s*field", re.I),
     ["mass_assign_guard"]),
    (re.compile(r"inject|sql|xss|command", re.I),
     ["injection_param"]),
]


class ResidualRunnerError(ValueError):
    pass


class ResidualProbePlan(BaseModel):
    probe_id: str
    residual_item_id: str
    question: str
    method: str = "local_static_code_search"
    control_tokens: list[str] = Field(default_factory=list)
    status: str = "planned"
    requires_human_approval: bool = True
    network_access: bool = False
    live_validation: bool = False


class ResidualProbeResult(BaseModel):
    probe_id: str
    residual_item_id: str
    question: str
    method: str = "local_static_code_search"
    status: str = "pending"
    observed: list[str] = Field(default_factory=list)
    evidence_refs: list[str] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)
    control_present: bool | None = None
    control_absent: bool | None = None
    residual_strength: str = "info"
    execution_allowed: bool = False
    validation_allowed: bool = False
    report_submission_allowed: bool = False
    confirmed_vulnerability: bool = False


class ResidualRunnerResult(BaseModel):
    status: str = STATUS_EMPTY
    package_id: str = ""
    package_root: str = ""
    candidate_id: str = ""
    human_approval_required: bool = True
    human_approved: bool = False
    human_rejected: bool = False
    approval_active: bool = False
    residual_item_count: int = 0
    probe_plan: list[ResidualProbePlan] = Field(default_factory=list)
    probe_results: list[ResidualProbeResult] = Field(default_factory=list)
    probes_planned: int = 0
    probes_completed: int = 0
    control_hits: int = 0
    open_static_gaps: int = 0
    sources: list[str] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)
    execution_allowed: bool = False
    validation_allowed: bool = False
    report_submission_allowed: bool = False
    confirmed_vulnerability: bool = False
    finding_promotion_allowed: bool = False
    network_access: bool = False
    live_validation_executed: bool = False
    next_allowed_action: str = (
        "Human-approved residual runner is local/static only; no live validation or submit."
    )
    safety_blockers: list[str] = Field(
        default_factory=lambda: [
            "execute_live_validation",
            "touch_real_user_data",
            "submit_report",
            "auto_promote_finding",
            "network_residual_probe",
        ]
    )
def build_residual_probe_plan(
    residual_items: list[dict[str, Any]] | list[Any] | None,
    *,
    candidate_id: str = "",
) -> list[ResidualProbePlan]:
    """Plan local residual probes from checklist items (always non-network)."""
    items = _normalize_items(residual_items)
    plans: list[ResidualProbePlan] = []
    for index, item in enumerate(items[:_MAX_PROBES], start=1):
        item_id = str(item.get("item_id") or f"R-{index:03d}")
        question = str(item.get("question") or "").strip()
        tokens = _tokens_for_question(question)
        plans.append(
            ResidualProbePlan(
                probe_id=f"RP-{candidate_id or 'pkg'}-{item_id}"[:80],
                residual_item_id=item_id,
                question=question,
                method="local_static_code_search",
                control_tokens=tokens,
                status="planned",
                requires_human_approval=True,
                network_access=False,
                live_validation=False,
            )
        )
    return plans


def run_residual_probes(
    *,
    package_root: str | Path | None = None,
    package_id: str = "",
    candidate_id: str = "",
    residual_items: list[dict[str, Any]] | list[Any] | None = None,
    residual_checklist_bundle: dict[str, Any] | None = None,
    human_approval: dict[str, Any] | Any | None = None,
    human_approved: bool | None = None,
    human_rejected: bool | None = None,
    authorized_code_files: list[dict[str, Any]] | None = None,
    scope_allowed: bool = True,
    force_plan_only: bool = False,
) -> ResidualRunnerResult:
    """Plan and optionally execute local residual probes behind human approval."""
    root: Path | None = None
    if package_root is not None and str(package_root).strip():
        root = Path(package_root).resolve()

    resolved_package_id = package_id
    if not resolved_package_id and root is not None:
        resolved_package_id = _read_package_id(root) or root.name

    if human_approval is not None:
        flags = residual_flags_from_approval(human_approval)
    else:
        flags = {
            "human_approved": False,
            "human_rejected": False,
            "residual_context_cleared": False,
            "has_decision": False,
            "active": False,
        }
    approved = bool(flags.get("human_approved"))
    rejected = bool(flags.get("human_rejected"))
    if human_approved is not None:
        approved = bool(human_approved)
    if human_rejected is not None:
        rejected = bool(human_rejected)

    items = _normalize_items(residual_items)
    if not items and residual_checklist_bundle is not None:
        items = residual_checklist_from_bundle(residual_checklist_bundle)
    if not items and root is not None:
        bundle = load_package_residual_checklist(root)
        items = residual_checklist_from_bundle(bundle)
        sources_seed = [
            str(s.get("path") or "")
            for s in (bundle.get("sources") or [])
            if isinstance(s, dict)
        ]
    else:
        sources_seed = []

    plan = build_residual_probe_plan(items, candidate_id=candidate_id)
    notes: list[str] = []
    sources = [s for s in sources_seed if s]

    if scope_allowed is False:
        return _force_safety(
            ResidualRunnerResult(
                status=STATUS_BLOCKED,
                package_id=resolved_package_id,
                package_root=str(root or ""),
                candidate_id=candidate_id,
                human_approval_required=True,
                human_approved=False,
                human_rejected=rejected,
                approval_active=bool(flags.get("active")),
                residual_item_count=len(items),
                probe_plan=plan,
                probes_planned=len(plan),
                notes=["scope_not_allowed"],
                next_allowed_action="Scope denied; residual runner blocked.",
            )
        )

    if rejected:
        return _force_safety(
            ResidualRunnerResult(
                status=STATUS_SKIPPED_REJECTED,
                package_id=resolved_package_id,
                package_root=str(root or ""),
                candidate_id=candidate_id,
                human_approval_required=True,
                human_approved=False,
                human_rejected=True,
                approval_active=bool(flags.get("active")),
                residual_item_count=len(items),
                probe_plan=plan,
                probes_planned=len(plan),
                notes=["human_rejected_or_fp"],
                next_allowed_action=(
                    "Human rejected residual as FP / not pursued; "
                    "do not run residual probes or submit."
                ),
            )
        )

    if not items:
        return _force_safety(
            ResidualRunnerResult(
                status=STATUS_SKIPPED_NO_ITEMS,
                package_id=resolved_package_id,
                package_root=str(root or ""),
                candidate_id=candidate_id,
                human_approval_required=True,
                human_approved=approved,
                human_rejected=False,
                approval_active=bool(flags.get("active")),
                residual_item_count=0,
                probe_plan=[],
                probes_planned=0,
                notes=["no_residual_items"],
                next_allowed_action="No residual checklist items; residual runner idle.",
            )
        )

    if not approved or force_plan_only:
        return _force_safety(
            ResidualRunnerResult(
                status=STATUS_SKIPPED_NO_APPROVAL if not approved else STATUS_PLANNED,
                package_id=resolved_package_id,
                package_root=str(root or ""),
                candidate_id=candidate_id,
                human_approval_required=True,
                human_approved=approved,
                human_rejected=False,
                approval_active=bool(flags.get("active")),
                residual_item_count=len(items),
                probe_plan=plan,
                probes_planned=len(plan),
                notes=["awaiting_residual_approval"] if not approved else ["plan_only_mode"],
                next_allowed_action=(
                    "Residual probes planned only. Obtain durable residual_review "
                    "approval before local static residual runner executes."
                    if not approved
                    else "Plan-only residual runner; no probe execution."
                ),
            )
        )

    offline_results, offline_sources, offline_notes = (
        _load_offline_residual_runs(root) if root else ([], [], [])
    )
    notes.extend(offline_notes)
    sources.extend(offline_sources)

    code_corpus = _collect_code_corpus(
        root=root,
        authorized_code_files=authorized_code_files,
    )
    if code_corpus:
        sources.append("local_code_corpus")
        notes.append(f"code_files_scanned={len(code_corpus)}")

    results: list[ResidualProbeResult] = []
    offline_by_id = {
        str(r.get("residual_item_id") or r.get("item_id") or ""): r
        for r in offline_results
        if isinstance(r, dict)
    }

    for probe in plan:
        offline = offline_by_id.get(probe.residual_item_id)
        if offline:
            results.append(_result_from_offline(probe, offline))
            continue
        results.append(_execute_local_static_probe(probe, code_corpus))

    completed = sum(1 for r in results if r.status in {"completed", "completed_offline"})
    control_hits = sum(1 for r in results if r.control_present is True)
    open_gaps = sum(
        1
        for r in results
        if r.control_absent is True or r.residual_strength == "strong_static_only"
    )

    return _force_safety(
        ResidualRunnerResult(
            status=STATUS_COMPLETED,
            package_id=resolved_package_id,
            package_root=str(root or ""),
            candidate_id=candidate_id,
            human_approval_required=True,
            human_approved=True,
            human_rejected=False,
            approval_active=True,
            residual_item_count=len(items),
            probe_plan=plan,
            probe_results=results,
            probes_planned=len(plan),
            probes_completed=completed,
            control_hits=control_hits,
            open_static_gaps=open_gaps,
            sources=_sorted_unique(sources)[:20],
            notes=notes[:40],
            next_allowed_action=(
                "Local residual static probes completed for human review. "
                "Still no live validation, finding promotion, or report submission."
            ),
        )
    )


def load_package_residual_runner(
    package_root: str | Path | None,
    *,
    candidate_id: str = "",
    human_approval: dict[str, Any] | Any | None = None,
    human_approved: bool | None = None,
    human_rejected: bool | None = None,
) -> dict[str, Any]:
    return run_residual_probes(
        package_root=package_root,
        candidate_id=candidate_id,
        human_approval=human_approval,
        human_approved=human_approved,
        human_rejected=human_rejected,
    ).model_dump()
def attach_residual_runner_to_bridge_result(
    bridge_result: dict[str, Any],
    *,
    package_root: str | Path | None = None,
    trial_result: dict[str, Any] | None = None,
    residual_runner: dict[str, Any] | ResidualRunnerResult | None = None,
    human_approvals: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Attach residual runner outcomes to report-bridge result (fail-closed)."""
    if not isinstance(bridge_result, dict):
        raise ResidualRunnerError("bridge_result_must_be_object")

    package_id = str(bridge_result.get("package_id") or "")
    resolved_root = package_root or bridge_result.get("package_root")
    trial_result = trial_result if isinstance(trial_result, dict) else {}

    approvals = human_approvals
    if approvals is None:
        approvals = resolve_human_review_approvals(
            package_root=resolved_root,
            trial_result=trial_result,
            bridge_result=bridge_result,
        )

    residual_items: list[dict[str, Any]] = []
    residual_bundle = bridge_result.get("residual_checklist_bundle")
    if isinstance(residual_bundle, dict):
        residual_items = residual_checklist_from_bundle(residual_bundle)
    if not residual_items and resolved_root is not None:
        residual_items = residual_checklist_from_bundle(
            load_package_residual_checklist(resolved_root)
        )

    runs: list[dict[str, Any]] = []
    drafts = bridge_result.get("drafts") if isinstance(bridge_result.get("drafts"), list) else []
    targets: list[dict[str, Any]] = []
    for draft in drafts:
        if isinstance(draft, dict):
            targets.append(draft)
    if not targets:
        targets.append({"candidate_id": "", "package_id": package_id})

    if residual_runner is not None:
        if isinstance(residual_runner, ResidualRunnerResult):
            runs.append(residual_runner.model_dump())
        elif isinstance(residual_runner, dict):
            runs.append(_force_safety_dict(dict(residual_runner)))
    else:
        seen_candidates: set[str] = set()
        for target in targets[:10]:
            cand_id = str(target.get("candidate_id") or "")
            key = cand_id or "__package__"
            if key in seen_candidates:
                continue
            seen_candidates.add(key)
            approval = select_approval_for_candidate(
                approvals or [],
                approval_kind=APPROVAL_KIND_RESIDUAL,
                candidate_id=cand_id,
                package_id=package_id,
            )
            run = run_residual_probes(
                package_root=resolved_root,
                package_id=package_id,
                candidate_id=cand_id,
                residual_items=residual_items,
                human_approval=approval,
            )
            runs.append(run.model_dump())

    if not runs:
        runs.append(
            _force_safety(
                ResidualRunnerResult(
                    status=STATUS_EMPTY,
                    package_id=package_id,
                    package_root=str(resolved_root or ""),
                )
            ).model_dump()
        )

    out = dict(bridge_result)
    out["residual_runner_runs"] = runs
    out["residual_runner_present"] = any(
        r.get("status")
        in {
            STATUS_COMPLETED,
            STATUS_PLANNED,
            STATUS_SKIPPED_NO_APPROVAL,
            STATUS_SKIPPED_REJECTED,
            STATUS_SKIPPED_NO_ITEMS,
            STATUS_BLOCKED,
        }
        for r in runs
        if isinstance(r, dict)
    )
    out["residual_runner_status"] = _aggregate_status(runs)
    out["residual_runner_completed_count"] = sum(
        1 for r in runs if isinstance(r, dict) and r.get("status") == STATUS_COMPLETED
    )
    out["execution_allowed"] = False
    out["validation_allowed"] = False
    out["report_submission_allowed"] = False
    out["confirmed_vulnerability"] = False
    if out.get("submission_blocked") is not True:
        out["submission_blocked"] = True

    first_by_cand = {
        str(r.get("candidate_id") or ""): r for r in runs if isinstance(r, dict)
    }
    new_drafts = []
    for draft in drafts:
        if not isinstance(draft, dict):
            new_drafts.append(draft)
            continue
        d = dict(draft)
        cand = str(d.get("candidate_id") or "")
        run = first_by_cand.get(cand) or first_by_cand.get("") or (runs[0] if runs else None)
        if isinstance(run, dict):
            d["residual_runner"] = {
                "status": run.get("status"),
                "probes_completed": run.get("probes_completed"),
                "control_hits": run.get("control_hits"),
                "open_static_gaps": run.get("open_static_gaps"),
                "human_approved": run.get("human_approved"),
                "execution_allowed": False,
                "report_submission_allowed": False,
                "confirmed_vulnerability": False,
            }
        d["execution_allowed"] = False
        d["validation_allowed"] = False
        d["report_submission_allowed"] = False
        d["confirmed_vulnerability"] = False
        new_drafts.append(d)
    if drafts:
        out["drafts"] = new_drafts
    return out


def _aggregate_status(runs: list[dict[str, Any]]) -> str:
    statuses = [str(r.get("status") or "") for r in runs if isinstance(r, dict)]
    if any(s == STATUS_COMPLETED for s in statuses):
        return STATUS_COMPLETED
    if any(s == STATUS_BLOCKED for s in statuses):
        return STATUS_BLOCKED
    if any(s == STATUS_SKIPPED_REJECTED for s in statuses):
        return STATUS_SKIPPED_REJECTED
    if any(s == STATUS_SKIPPED_NO_APPROVAL for s in statuses):
        return STATUS_SKIPPED_NO_APPROVAL
    if any(s == STATUS_PLANNED for s in statuses):
        return STATUS_PLANNED
    if any(s == STATUS_SKIPPED_NO_ITEMS for s in statuses):
        return STATUS_SKIPPED_NO_ITEMS
    return STATUS_EMPTY


def _normalize_items(
    residual_items: list[dict[str, Any]] | list[Any] | None,
) -> list[dict[str, Any]]:
    if not isinstance(residual_items, list):
        return []
    out: list[dict[str, Any]] = []
    for index, item in enumerate(residual_items, start=1):
        if isinstance(item, str) and item.strip():
            out.append(
                {
                    "item_id": f"R-{index:03d}",
                    "question": item.strip(),
                    "status": "open",
                }
            )
            continue
        if not isinstance(item, dict):
            continue
        question = str(
            item.get("question") or item.get("body") or item.get("text") or ""
        ).strip()
        if not question:
            continue
        out.append(
            {
                "item_id": str(item.get("item_id") or item.get("id") or f"R-{index:03d}"),
                "question": question,
                "status": str(item.get("status") or "open"),
                "evidence_refs": list(item.get("evidence_refs") or [])
                if isinstance(item.get("evidence_refs"), list)
                else [],
            }
        )
    return out[:_MAX_PROBES]


def _tokens_for_question(question: str) -> list[str]:
    tokens: list[str] = []
    for pattern, names in _QUESTION_HINTS:
        if pattern.search(question or ""):
            for name in names:
                if name not in tokens:
                    tokens.append(name)
    if not tokens:
        tokens = ["ssrf_validate_url", "ssrf_fetch_sink", "authz_can"]
    return tokens


def _collect_code_corpus(
    *,
    root: Path | None,
    authorized_code_files: list[dict[str, Any]] | None,
) -> list[tuple[str, str]]:
    corpus: list[tuple[str, str]] = []
    if isinstance(authorized_code_files, list):
        for item in authorized_code_files:
            if not isinstance(item, dict):
                continue
            path = item.get("path")
            content = item.get("content")
            if not isinstance(path, str) or not isinstance(content, str):
                continue
            if _name_blocked(path):
                continue
            corpus.append((path.replace("\\", "/"), content[:_MAX_SNIFF]))
    if root is not None and root.is_dir():
        for path in _iter_files(root, max_files=_MAX_FILES):
            if _name_blocked(path.name):
                continue
            if path.suffix.lower() not in _CODE_SUFFIXES and path.name.lower() not in {
                "source_facts.md",
                "residual_checklist.md",
            }:
                continue
            text = _safe_read_text(path)
            if text is None:
                continue
            rel = _rel_posix(root, path)
            corpus.append((rel, text[:_MAX_SNIFF]))
    seen: set[str] = set()
    unique: list[tuple[str, str]] = []
    for rel, text in corpus:
        if rel in seen:
            continue
        seen.add(rel)
        unique.append((rel, text))
    return unique[:_MAX_FILES]


def _execute_local_static_probe(
    probe: ResidualProbePlan,
    corpus: list[tuple[str, str]],
) -> ResidualProbeResult:
    patterns = [
        (name, pat)
        for name, pat in _CONTROL_PATTERNS
        if name in set(probe.control_tokens)
    ]
    if not patterns:
        patterns = list(_CONTROL_PATTERNS[:3])

    observed: list[str] = []
    evidence: list[str] = []
    present_flags: list[bool] = []

    for rel, text in corpus:
        for name, pat in patterns:
            for match in pat.finditer(text):
                line_no = text.count("\n", 0, match.start()) + 1
                line = text.splitlines()[line_no - 1] if line_no <= len(text.splitlines()) else ""
                stripped = line.strip()
                # Skip pure comments / markdown prose so teaching docs do not fake guards.
                if stripped.startswith("//") or stripped.startswith("#") or stripped.startswith("*"):
                    continue
                if rel.lower().endswith(".md") and name.endswith(("_url", "_guard", "_can", "_check", "_param")):
                    # Markdown facts may name controls without implementing them.
                    continue
                snippet = match.group(0)[:80]
                observed.append(f"{name}:{rel}:{line_no}:{snippet}")
                evidence.append(f"{rel}:{line_no}")
                present_flags.append(True)
                break

    guard_names = {
        "ssrf_validate_url",
        "authz_can",
        "ownership_check",
        "path_traversal_guard",
        "mass_assign_guard",
        "injection_param",
    }
    wanted_guards = [n for n, _ in patterns if n in guard_names]
    sink_hit = any(o.startswith("ssrf_fetch_sink:") for o in observed)
    guard_hit = any(any(o.startswith(g + ":") for o in observed) for g in wanted_guards)

    notes: list[str] = ["local_static_only", "no_network"]
    if not corpus:
        control_present: bool | None = None
        control_absent: bool | None = None
        residual_strength = "info"
        notes.append("no_code_corpus")
    elif wanted_guards and sink_hit and not guard_hit:
        control_present = False
        control_absent = True
        residual_strength = "strong_static_only"
        notes.append("sink_without_matching_guard_token")
    elif guard_hit:
        control_present = True
        control_absent = False
        residual_strength = "soft"
        notes.append("guard_token_observed")
    elif present_flags:
        control_present = True
        control_absent = False
        residual_strength = "soft"
    else:
        control_present = False
        control_absent = None
        residual_strength = "info"
        notes.append("no_token_hits")

    return ResidualProbeResult(
        probe_id=probe.probe_id,
        residual_item_id=probe.residual_item_id,
        question=probe.question,
        method=probe.method,
        status="completed",
        observed=observed[:20],
        evidence_refs=evidence[:20],
        notes=notes[:20],
        control_present=control_present,
        control_absent=control_absent,
        residual_strength=residual_strength,
    )


def _result_from_offline(
    probe: ResidualProbePlan, offline: dict[str, Any]
) -> ResidualProbeResult:
    present = offline.get("control_present")
    absent = offline.get("control_absent")
    return ResidualProbeResult(
        probe_id=probe.probe_id,
        residual_item_id=probe.residual_item_id,
        question=probe.question,
        method=str(offline.get("method") or "offline_residual_fixture"),
        status="completed_offline",
        observed=_as_str_list(offline.get("observed"))[:20],
        evidence_refs=_as_str_list(offline.get("evidence_refs"))[:20],
        notes=_as_str_list(
            offline.get("notes") or ["offline_residual_fixture", "no_network"]
        )[:20],
        control_present=bool(present) if present is not None else None,
        control_absent=bool(absent) if absent is not None else None,
        residual_strength=str(offline.get("residual_strength") or "info"),
    )


def _load_offline_residual_runs(
    root: Path | None,
) -> tuple[list[dict[str, Any]], list[str], list[str]]:
    if root is None or not root.is_dir():
        return [], [], []
    candidates = [
        root / "inputs" / "residual_runs.json",
        root / "inputs" / "residual_runner.json",
        root / "_extract" / "RESIDUAL_RUNS.json",
    ]
    residual_dir = root / "inputs" / "residual_runs"
    if residual_dir.is_dir():
        candidates.extend(sorted(p for p in residual_dir.glob("*.json") if p.is_file()))

    results: list[dict[str, Any]] = []
    sources: list[str] = []
    notes: list[str] = []
    for path in candidates:
        if not path.is_file():
            continue
        if _name_blocked(path.name):
            notes.append(f"skipped_blocked_name:{path.name}")
            continue
        try:
            path.resolve().relative_to(root)
        except Exception:
            notes.append(f"outside_package:{path.name}")
            continue
        text = _safe_read_text(path)
        if text is None:
            continue
        try:
            raw = json.loads(text)
        except json.JSONDecodeError:
            notes.append(f"invalid_json:{path.name}")
            continue
        if isinstance(raw, list):
            items = raw
        elif isinstance(raw, dict):
            items = raw.get("results") or raw.get("probes") or raw.get("items") or []
            if not isinstance(items, list):
                items = []
        else:
            continue
        for item in items:
            if isinstance(item, dict):
                results.append(item)
        rel = _rel_posix(root, path)
        sources.append(rel)
        notes.append(f"offline_residual_runs:{rel}")
    return results[:_MAX_PROBES], sources, notes


def _iter_files(root: Path, *, max_files: int) -> list[Path]:
    out: list[Path] = []
    scan_roots = [root / "inputs", root / "_extract", root / "_upstream", root]
    seen: set[str] = set()
    for base in scan_roots:
        if not base.exists() or base.is_file():
            continue
        for path in base.rglob("*"):
            if len(out) >= max_files:
                return out
            if not path.is_file():
                continue
            if any(part in _SKIP_DIR_NAMES for part in path.parts):
                continue
            try:
                path.resolve().relative_to(root.resolve())
            except Exception:
                continue
            key = str(path.resolve())
            if key in seen:
                continue
            seen.add(key)
            out.append(path)
    return out


def _safe_read_text(path: Path) -> str | None:
    try:
        if path.stat().st_size > _MAX_FILE_BYTES:
            return None
        return path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return None


def _read_package_id(root: Path) -> str:
    for rel in ("package.json", "gold.json", "STATUS.md"):
        path = root / rel
        if not path.is_file():
            continue
        if rel.endswith(".json"):
            text = _safe_read_text(path)
            if not text:
                continue
            try:
                data = json.loads(text)
            except json.JSONDecodeError:
                continue
            if isinstance(data, dict):
                for key in ("package_id", "id", "name"):
                    val = data.get(key)
                    if isinstance(val, str) and val.strip():
                        return val.strip()
    return root.name


def _name_blocked(name: str) -> bool:
    lower = name.lower()
    return any(part in lower for part in _BLOCKED_NAME_PARTS)


def _rel_posix(root: Path, path: Path) -> str:
    try:
        return str(path.resolve().relative_to(root.resolve())).replace("\\", "/")
    except Exception:
        return path.name


def _sorted_unique(values: Any) -> list[str]:
    if not isinstance(values, list):
        return []
    out: list[str] = []
    seen: set[str] = set()
    for value in values:
        if not isinstance(value, str):
            continue
        text = value.strip()
        if not text or text in seen:
            continue
        seen.add(text)
        out.append(text)
    return out


def _as_str_list(value: Any) -> list[str]:
    if isinstance(value, list):
        return [str(v).strip() for v in value if str(v).strip()]
    if isinstance(value, str) and value.strip():
        return [value.strip()]
    return []


def _force_safety(result: ResidualRunnerResult) -> ResidualRunnerResult:
    return ResidualRunnerResult.model_validate(_force_safety_dict(result.model_dump()))


def _force_safety_dict(payload: dict[str, Any]) -> dict[str, Any]:
    out = dict(payload)
    out["execution_allowed"] = False
    out["validation_allowed"] = False
    out["report_submission_allowed"] = False
    out["confirmed_vulnerability"] = False
    out["finding_promotion_allowed"] = False
    out["network_access"] = False
    out["live_validation_executed"] = False
    out["human_approval_required"] = True
    if not out.get("next_allowed_action"):
        out["next_allowed_action"] = (
            "Human-approved residual runner is local/static only; "
            "no live validation or submit."
        )
    results = out.get("probe_results")
    if isinstance(results, list):
        cleaned = []
        for item in results:
            if not isinstance(item, dict):
                cleaned.append(item)
                continue
            row = dict(item)
            row["execution_allowed"] = False
            row["validation_allowed"] = False
            row["report_submission_allowed"] = False
            row["confirmed_vulnerability"] = False
            cleaned.append(row)
        out["probe_results"] = cleaned
    return out


__all__ = [
    "STATUS_PLANNED",
    "STATUS_COMPLETED",
    "STATUS_SKIPPED_NO_APPROVAL",
    "STATUS_SKIPPED_REJECTED",
    "STATUS_SKIPPED_NO_ITEMS",
    "STATUS_BLOCKED",
    "STATUS_EMPTY",
    "ResidualRunnerError",
    "ResidualProbePlan",
    "ResidualProbeResult",
    "ResidualRunnerResult",
    "build_residual_probe_plan",
    "run_residual_probes",
    "load_package_residual_runner",
    "attach_residual_runner_to_bridge_result",
]