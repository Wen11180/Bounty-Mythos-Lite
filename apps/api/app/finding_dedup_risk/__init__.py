"""Finding Dedup + Risk Prioritization — first-class plan-only factory residual (final scheme V3).

Lawful research only:
- Cluster equivalent unverified candidates/findings for human triage
- Rank a risk queue for human review priority only
- Optional offline hints under package inputs/
- Optional export under package _export/finding_dedup_risk/ with human flag
- Never promotes findings, never executes validation, never submits reports
- Never grants ranking_permission that unlocks execute/submit
"""

from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


STATUS_READY = "finding_dedup_risk_plan_ready"
STATUS_EMPTY = "finding_dedup_risk_empty"
STATUS_PACKAGE_MISSING = "finding_dedup_risk_package_missing"
STATUS_WRITTEN = "finding_dedup_risk_export_written"
STATUS_BLOCKED_SCOPE = "finding_dedup_risk_blocked_scope"

SAFETY_INVARIANTS = [
    "authorized_package_or_bridge_only",
    "plan_only_dedup_and_risk_queue",
    "no_finding_promotion",
    "no_automatic_report_submission",
    "no_execution_permission",
    "no_live_validation",
    "no_network_access",
    "human_review_required_for_triage",
    "ranking_is_advisory_only",
    "no_export_write_without_human_flag",
]

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "unknown": 5}
_SECRET_HINTS = re.compile(
    r"(?i)(password|passwd|secret|token|api[_-]?key|authorization|cookie|session|bearer|"
    r"private[_-]?key|ssh-rsa|BEGIN [A-Z ]*PRIVATE)"
)
_MAX_ITEMS = 64
_MAX_CLUSTERS = 48
_MAX_QUEUE = 48
_OFFLINE_NAMES = (
    "finding_dedup.json",
    "finding_dedup_risk.json",
    "risk_prioritization.json",
    "dedup.json",
    "risk_queue.json",
)


class FindingDedupRiskError(ValueError):
    """Raised when bridge attach receives invalid input."""


@dataclass(frozen=True)
class FindingSeed:
    seed_id: str
    source: str
    vuln_type: str
    component: str
    root_cause: str
    evidence_ref: str
    endpoint: str
    title: str
    severity: str
    confidence: str
    disposition: str
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class FindingClusterPlan:
    cluster_id: str
    dedup_key: str
    seed_ids: list[str]
    representative_seed_id: str
    vuln_type: str
    component: str
    root_cause: str
    member_count: int
    status: str = "deduped_for_human_triage"
    evidence_refs: list[str] = field(default_factory=list)
    refutation_questions: list[str] = field(default_factory=list)
    execution_allowed: bool = False
    finding_promotion_allowed: bool = False

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["execution_allowed"] = False
        d["finding_promotion_allowed"] = False
        return d


@dataclass(frozen=True)
class RiskQueuePlanItem:
    queue_id: str
    seed_id: str
    cluster_id: str
    priority: int
    severity: str
    impact_score: int
    confidence_score: int
    evidence_quality_score: int
    duplicate_risk_score: int
    policy_risk_score: int
    composite_score: float
    reason: str
    human_review_only: bool = True
    ranking_permission_granted: bool = False
    execution_allowed: bool = False
    report_submission_allowed: bool = False

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["human_review_only"] = True
        d["ranking_permission_granted"] = False
        d["execution_allowed"] = False
        d["report_submission_allowed"] = False
        return d


@dataclass(frozen=True)
class FindingDedupRiskResult:
    stage: str
    inspirations: list[str]
    execution_mode: str
    status: str
    package_id: str = ""
    package_root: str = ""
    seeds: list[FindingSeed] = field(default_factory=list)
    seed_count: int = 0
    clusters: list[FindingClusterPlan] = field(default_factory=list)
    cluster_count: int = 0
    risk_queue: list[RiskQueuePlanItem] = field(default_factory=list)
    risk_queue_count: int = 0
    offline_hint_count: int = 0
    offline_artifact_present: bool = False
    human_allow_export_write: bool = False
    export_written: bool = False
    export_count: int = 0
    export_root_relative: str = "_export/finding_dedup_risk"
    run_stamp: str = ""
    execution_allowed: bool = False
    validation_allowed: bool = False
    report_submission_allowed: bool = False
    confirmed_vulnerability: bool = False
    finding_promotion_allowed: bool = False
    ranking_permission_granted: bool = False
    network_access: bool = False
    live_validation: bool = False
    process_spawn_allowed: bool = False
    safety_invariants: list[str] = field(default_factory=list)
    next_allowed_action: str = (
        "Human reviews dedup clusters and risk queue; Mythos never promotes or submits."
    )
    notes: list[str] = field(default_factory=list)
    summary: str = ""

    def to_dict(self) -> dict[str, Any]:
        return _force_safety_dict(asdict(self))
def build_finding_dedup_risk(
    *,
    package_root: str | Path | None = None,
    package_id: str = "",
    bridge_result: dict[str, Any] | None = None,
    human_allow_export_write: bool = False,
) -> FindingDedupRiskResult:
    return run_finding_dedup_risk(
        package_root=package_root,
        package_id=package_id,
        bridge_result=bridge_result,
        human_allow_export_write=human_allow_export_write,
    )


def run_finding_dedup_risk(
    *,
    package_root: str | Path | None = None,
    package_id: str = "",
    bridge_result: dict[str, Any] | None = None,
    human_allow_export_write: bool = False,
) -> FindingDedupRiskResult:
    """Build plan-only finding clusters + risk queue from package + bridge context."""
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
    pid = package_id or str(bridge.get("package_id") or "")
    scope_allowed = _scope_allowed(bridge, root)
    offline_hints, offline_present = _load_offline_hints(root)

    notes = [
        "plan_only_finding_dedup_and_risk_prioritization",
        "never_promotes_findings",
        "ranking_advisory_for_human_review_only",
    ]
    if not scope_allowed:
        return _empty(
            status=STATUS_BLOCKED_SCOPE,
            package_id=pid,
            package_root=root_s,
            notes=notes + ["scope_not_allowed"],
            human_allow_export_write=bool(human_allow_export_write),
        )

    seeds = _collect_seeds(bridge, offline_hints)
    if not seeds:
        return _empty(
            status=STATUS_EMPTY,
            package_id=pid,
            package_root=root_s,
            notes=notes + ["no_seeds_from_bridge_or_offline"],
            offline_hint_count=len(offline_hints),
            offline_artifact_present=offline_present,
            human_allow_export_write=bool(human_allow_export_write),
        )

    clusters = _build_clusters(seeds)
    queue = _build_risk_queue(seeds, clusters)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    status = STATUS_READY
    export_written = False
    export_count = 0
    if human_allow_export_write and root is not None and root.is_dir():
        export_written, export_count, export_note = _export_plan(
            root,
            FindingDedupRiskResult(
                stage="v3_finding_dedup_risk",
                inspirations=[
                    "final-scheme-Finding-Dedup",
                    "final-scheme-Risk-Prioritization",
                ],
                execution_mode="plan_only",
                status=STATUS_READY,
                package_id=pid,
                package_root=root_s,
                seeds=seeds,
                seed_count=len(seeds),
                clusters=clusters,
                cluster_count=len(clusters),
                risk_queue=queue,
                risk_queue_count=len(queue),
                offline_hint_count=len(offline_hints),
                offline_artifact_present=offline_present,
                human_allow_export_write=True,
                run_stamp=stamp,
                notes=notes,
                summary=_summary(len(seeds), len(clusters), len(queue)),
            ),
        )
        if export_written:
            status = STATUS_WRITTEN
            notes = notes + [export_note]

    result = FindingDedupRiskResult(
        stage="v3_finding_dedup_risk",
        inspirations=[
            "final-scheme-Finding-Dedup",
            "final-scheme-Risk-Prioritization",
        ],
        execution_mode="plan_only",
        status=status,
        package_id=pid,
        package_root=root_s,
        seeds=seeds,
        seed_count=len(seeds),
        clusters=clusters,
        cluster_count=len(clusters),
        risk_queue=queue,
        risk_queue_count=len(queue),
        offline_hint_count=len(offline_hints),
        offline_artifact_present=offline_present,
        human_allow_export_write=bool(human_allow_export_write),
        export_written=export_written,
        export_count=export_count,
        run_stamp=stamp,
        notes=notes,
        summary=_summary(len(seeds), len(clusters), len(queue)),
        safety_invariants=list(SAFETY_INVARIANTS),
    )
    return _force_safety(result)


def attach_finding_dedup_risk_to_bridge_result(
    bridge_result: dict[str, Any],
    *,
    package_root: str | Path | None = None,
    finding_dedup_risk: dict[str, Any] | FindingDedupRiskResult | None = None,
    human_allow_export_write: bool = False,
) -> dict[str, Any]:
    """Attach dedup clusters + risk queue; never unlocks execute/promote/submit."""
    if not isinstance(bridge_result, dict):
        raise FindingDedupRiskError("bridge_result_must_be_object")

    package_id = str(bridge_result.get("package_id") or "")
    resolved_root = package_root or bridge_result.get("package_root")

    if isinstance(finding_dedup_risk, FindingDedupRiskResult):
        payload = finding_dedup_risk.to_dict()
    elif isinstance(finding_dedup_risk, dict):
        payload = _force_safety_dict(dict(finding_dedup_risk))
    else:
        payload = run_finding_dedup_risk(
            package_root=resolved_root,
            package_id=package_id,
            bridge_result=bridge_result,
            human_allow_export_write=bool(human_allow_export_write),
        ).to_dict()

    if not payload.get("package_id") and package_id:
        payload["package_id"] = package_id
    payload = _force_safety_dict(payload)

    out = dict(bridge_result)
    out["finding_dedup_risk"] = payload
    out["finding_dedup_risk_present"] = True
    out["finding_dedup_risk_status"] = str(payload.get("status") or STATUS_EMPTY)
    out["finding_dedup_risk_cluster_count"] = int(payload.get("cluster_count") or 0)
    out["finding_dedup_risk_queue_count"] = int(payload.get("risk_queue_count") or 0)
    out["finding_dedup_risk_seed_count"] = int(payload.get("seed_count") or 0)
    out["finding_dedup_risk_export_written"] = bool(payload.get("export_written"))
    out["execution_allowed"] = False
    out["validation_allowed"] = False
    out["report_submission_allowed"] = False
    out["confirmed_vulnerability"] = False
    out["finding_promotion_allowed"] = False
    out["ranking_permission_granted"] = False
    if out.get("submission_blocked") is not True:
        out["submission_blocked"] = True
    return out


def _scope_allowed(bridge: dict[str, Any], root: Path | None) -> bool:
    if bridge.get("scope_blocked") is True or bridge.get("scope_allowed") is False:
        return False
    if bridge.get("package_id") or root is not None:
        return True
    if bridge:
        return True
    return False


def _load_offline_hints(root: Path | None) -> tuple[list[dict[str, Any]], bool]:
    if root is None or not root.is_dir():
        return [], False
    inputs = root / "inputs"
    if not inputs.is_dir():
        return [], False
    hints: list[dict[str, Any]] = []
    present = False
    for name in _OFFLINE_NAMES:
        path = inputs / name
        if not path.is_file():
            continue
        present = True
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            continue
        items: list[Any] = []
        if isinstance(raw, list):
            items = raw
        elif isinstance(raw, dict):
            for key in ("findings", "seeds", "items", "clusters", "risk_queue"):
                if isinstance(raw.get(key), list):
                    items.extend(raw[key])
            if not items:
                items = [raw]
        for item in items:
            if isinstance(item, dict):
                item = dict(item)
                item["_offline_source"] = name
                hints.append(item)
    return hints[:_MAX_ITEMS], present
def _collect_seeds(
    bridge: dict[str, Any],
    offline_hints: list[dict[str, Any]],
) -> list[FindingSeed]:
    seeds: list[FindingSeed] = []
    seen: set[str] = set()

    def _add(raw: dict[str, Any], source: str) -> None:
        seed = _seed_from_dict(raw, source=source)
        if seed is None:
            return
        key = seed.seed_id
        if key in seen:
            return
        seen.add(key)
        seeds.append(seed)

    for key in (
        "drafts",
        "retained_candidates",
        "candidates",
        "hypotheses",
        "findings",
        "confirmed_findings",
        "multi_engine_verdicts",
        "human_residual_gates",
    ):
        for item in _list_of_dicts(bridge.get(key)):
            _add(item, source=key)

    for nest_key in ("hunter_result", "report_bridge", "candidate_report"):
        nested = bridge.get(nest_key)
        if isinstance(nested, dict):
            for key in ("drafts", "candidates", "findings", "retained"):
                for item in _list_of_dicts(nested.get(key)):
                    _add(item, source=f"{nest_key}.{key}")

    for item in offline_hints:
        _add(item, source="offline:" + str(item.get("_offline_source") or "inputs"))

    return seeds[:_MAX_ITEMS]


def _seed_from_dict(raw: dict[str, Any], *, source: str) -> FindingSeed | None:
    if not isinstance(raw, dict):
        return None
    seed_id = _safe_text(
        raw.get("seed_id")
        or raw.get("candidate_id")
        or raw.get("finding_id")
        or raw.get("hypothesis_id")
        or raw.get("id")
        or "",
        "",
    )
    if not seed_id:
        vt = _safe_text(raw.get("vuln_type") or raw.get("type"), "unknown")
        ep = _safe_text(raw.get("affected_endpoint") or raw.get("endpoint"), "none")
        seed_id = f"seed-{vt}-{ep}"[:80]
    vuln_type = _safe_text(
        raw.get("vuln_type") or raw.get("type") or raw.get("family"), "unknown"
    ).lower()
    component = _safe_text(
        raw.get("affected_component")
        or raw.get("component")
        or raw.get("affected_code_path")
        or raw.get("route")
        or raw.get("module"),
        "unknown",
    )
    root_cause = _safe_text(
        raw.get("root_cause_id")
        or raw.get("root_cause")
        or raw.get("broken_invariant"),
        "unknown",
    )
    evidence_ref = ""
    if isinstance(raw.get("source_fact_refs"), list) and raw.get("source_fact_refs"):
        evidence_ref = _safe_text(raw["source_fact_refs"][0], "")
    elif isinstance(raw.get("evidence_refs"), list) and raw.get("evidence_refs"):
        evidence_ref = _safe_text(raw["evidence_refs"][0], "")
    else:
        evidence_ref = _safe_text(
            raw.get("evidence_ref") or raw.get("code_path") or "", "none"
        )
    if not evidence_ref:
        evidence_ref = "none"
    endpoint = _safe_text(
        raw.get("affected_endpoint") or raw.get("endpoint") or raw.get("route"),
        "none",
    )
    title = _safe_text(raw.get("title") or raw.get("summary") or seed_id, seed_id)
    severity = _safe_text(raw.get("severity") or raw.get("impact"), "info").lower()
    if severity not in SEVERITY_ORDER:
        severity = "info"
    confidence = _safe_text(
        raw.get("confidence") or raw.get("confidence_level"), "medium"
    ).lower()
    disposition = _safe_text(
        raw.get("disposition") or raw.get("status") or "unverified", "unverified"
    ).lower()
    notes = [_safe_text(n, "") for n in (raw.get("notes") or []) if _safe_text(n, "")]
    notes = [n for n in notes if n][:8]
    return FindingSeed(
        seed_id=_scrub_text(seed_id)[:120],
        source=_scrub_text(source)[:80],
        vuln_type=_scrub_text(vuln_type)[:80],
        component=_scrub_text(component)[:160],
        root_cause=_scrub_text(root_cause)[:120],
        evidence_ref=_scrub_text(evidence_ref)[:160],
        endpoint=_scrub_text(endpoint)[:160],
        title=_scrub_text(title)[:160],
        severity=severity,
        confidence=confidence,
        disposition=disposition,
        notes=notes,
    )


def _build_clusters(seeds: list[FindingSeed]) -> list[FindingClusterPlan]:
    grouped: dict[str, list[FindingSeed]] = {}
    for seed in seeds:
        key = _dedup_key(seed)
        grouped.setdefault(key, []).append(seed)
    clusters: list[FindingClusterPlan] = []
    for index, (key, members) in enumerate(grouped.items(), start=1):
        rep = members[0]
        clusters.append(
            FindingClusterPlan(
                cluster_id=f"FDC-{index:03d}",
                dedup_key=key,
                seed_ids=[m.seed_id for m in members],
                representative_seed_id=rep.seed_id,
                vuln_type=rep.vuln_type,
                component=rep.component,
                root_cause=rep.root_cause,
                member_count=len(members),
                evidence_refs=sorted(
                    {
                        m.evidence_ref
                        for m in members
                        if m.evidence_ref and m.evidence_ref != "none"
                    }
                )[:8],
                refutation_questions=[
                    "Are these members the same root cause under different labels?",
                    "Does one member already cover the others for human review?",
                    "Is any live validation still avoided (required default)?",
                ],
            )
        )
    return clusters[:_MAX_CLUSTERS]


def _build_risk_queue(
    seeds: list[FindingSeed],
    clusters: list[FindingClusterPlan],
) -> list[RiskQueuePlanItem]:
    cluster_by_seed: dict[str, FindingClusterPlan] = {}
    for cl in clusters:
        for sid in cl.seed_ids:
            cluster_by_seed[sid] = cl

    scored: list[tuple[float, RiskQueuePlanItem]] = []
    for seed in seeds:
        cl = cluster_by_seed.get(seed.seed_id)
        impact = 4 - min(SEVERITY_ORDER.get(seed.severity, 5), 4)
        conf_map = {"high": 3, "medium": 2, "low": 1, "unknown": 1}
        conf = conf_map.get(seed.confidence, 2)
        evidence_q = 3 if seed.evidence_ref and seed.evidence_ref != "none" else 1
        if seed.source.startswith("offline"):
            evidence_q = max(evidence_q, 2)
        dup = 1
        if cl and cl.member_count > 1:
            dup = min(3, cl.member_count)
        policy = 1
        if "retain" in seed.disposition or "ready" in seed.disposition:
            policy = 2
        if (
            "reject" in seed.disposition
            or "refut" in seed.disposition
            or "fp" in seed.disposition
        ):
            policy = 0
            impact = max(0, impact - 1)
        composite = float(
            impact * 40 + conf * 15 + evidence_q * 15 + policy * 10 - dup * 5
        )
        reason = (
            f"severity={seed.severity};confidence={seed.confidence};"
            f"evidence={evidence_q};dup={dup};policy={policy}"
        )
        item = RiskQueuePlanItem(
            queue_id=f"RQ-{seed.seed_id}"[:80],
            seed_id=seed.seed_id,
            cluster_id=cl.cluster_id if cl else "none",
            priority=0,
            severity=seed.severity,
            impact_score=impact,
            confidence_score=conf,
            evidence_quality_score=evidence_q,
            duplicate_risk_score=dup,
            policy_risk_score=policy,
            composite_score=composite,
            reason=reason,
        )
        scored.append((composite, item))

    scored.sort(key=lambda pair: (-pair[0], pair[1].seed_id))
    queue: list[RiskQueuePlanItem] = []
    for index, (_score, item) in enumerate(scored[:_MAX_QUEUE], start=1):
        queue.append(
            RiskQueuePlanItem(
                queue_id=item.queue_id,
                seed_id=item.seed_id,
                cluster_id=item.cluster_id,
                priority=index,
                severity=item.severity,
                impact_score=item.impact_score,
                confidence_score=item.confidence_score,
                evidence_quality_score=item.evidence_quality_score,
                duplicate_risk_score=item.duplicate_risk_score,
                policy_risk_score=item.policy_risk_score,
                composite_score=item.composite_score,
                reason=item.reason,
            )
        )
    return queue


def _dedup_key(seed: FindingSeed) -> str:
    """Key by component + vuln type + root cause + evidence ref (final-scheme)."""
    parts = [
        seed.vuln_type or "unknown",
        seed.component or "unknown",
        seed.root_cause or "unknown",
        seed.evidence_ref or "none",
    ]
    if parts[1] == "unknown" and parts[2] == "unknown":
        parts.append(seed.endpoint or seed.title or "none")
    return "|".join(_slug(p) for p in parts)
def _export_plan(root: Path, result: FindingDedupRiskResult) -> tuple[bool, int, str]:
    export_root = root / "_export" / "finding_dedup_risk"
    try:
        export_root.mkdir(parents=True, exist_ok=True)
        payload = result.to_dict()
        (export_root / "plan.json").write_text(
            json.dumps(payload, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        clusters_md = ["# Finding Dedup Clusters (plan only)", ""]
        for cl in result.clusters:
            clusters_md.append(f"## {cl.cluster_id}")
            clusters_md.append(f"- key: `{cl.dedup_key}`")
            clusters_md.append(f"- members: {', '.join(cl.seed_ids)}")
            clusters_md.append(f"- status: {cl.status}")
            clusters_md.append("")
        (export_root / "clusters.md").write_text(
            "\n".join(clusters_md) + "\n", encoding="utf-8"
        )
        queue_md = ["# Risk Queue (human review priority only)", ""]
        for item in result.risk_queue:
            queue_md.append(
                f"1. P{item.priority} `{item.seed_id}` sev={item.severity} "
                f"score={item.composite_score} cluster={item.cluster_id}"
            )
        (export_root / "risk_queue.md").write_text(
            "\n".join(queue_md) + "\n", encoding="utf-8"
        )
        readme = (
            "# Finding Dedup / Risk Prioritization export\n\n"
            "Plan only. Never promotes findings, never submits reports, "
            "never grants execution permission.\n"
        )
        (export_root / "README.md").write_text(readme, encoding="utf-8")
        return True, 4, "export_written_under_package__export_finding_dedup_risk"
    except Exception as exc:  # pragma: no cover - defensive
        return False, 0, f"export_failed:{type(exc).__name__}"


def _list_of_dicts(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, dict)]


def _summary(seeds: int, clusters: int, queue: int) -> str:
    return (
        f"plan-only dedup/risk: seeds={seeds} clusters={clusters} "
        f"queue={queue}; human triage only"
    )


def _empty(
    *,
    status: str,
    package_id: str = "",
    package_root: str = "",
    notes: list[str] | None = None,
    offline_hint_count: int = 0,
    offline_artifact_present: bool = False,
    human_allow_export_write: bool = False,
) -> FindingDedupRiskResult:
    return _force_safety(
        FindingDedupRiskResult(
            stage="v3_finding_dedup_risk",
            inspirations=[
                "final-scheme-Finding-Dedup",
                "final-scheme-Risk-Prioritization",
            ],
            execution_mode="plan_only",
            status=status,
            package_id=package_id,
            package_root=package_root,
            offline_hint_count=offline_hint_count,
            offline_artifact_present=offline_artifact_present,
            human_allow_export_write=human_allow_export_write,
            notes=list(notes or []),
            summary="empty_or_blocked_finding_dedup_risk_plan",
            safety_invariants=list(SAFETY_INVARIANTS),
        )
    )


def _force_safety(result: FindingDedupRiskResult) -> FindingDedupRiskResult:
    clusters = [
        FindingClusterPlan(
            cluster_id=c.cluster_id,
            dedup_key=c.dedup_key,
            seed_ids=list(c.seed_ids)[:_MAX_ITEMS],
            representative_seed_id=c.representative_seed_id,
            vuln_type=c.vuln_type,
            component=c.component,
            root_cause=c.root_cause,
            member_count=c.member_count,
            status=c.status or "deduped_for_human_triage",
            evidence_refs=list(c.evidence_refs)[:8],
            refutation_questions=list(c.refutation_questions)[:6],
            execution_allowed=False,
            finding_promotion_allowed=False,
        )
        for c in list(result.clusters or [])
    ]
    queue = [
        RiskQueuePlanItem(
            queue_id=q.queue_id,
            seed_id=q.seed_id,
            cluster_id=q.cluster_id,
            priority=q.priority,
            severity=q.severity,
            impact_score=q.impact_score,
            confidence_score=q.confidence_score,
            evidence_quality_score=q.evidence_quality_score,
            duplicate_risk_score=q.duplicate_risk_score,
            policy_risk_score=q.policy_risk_score,
            composite_score=q.composite_score,
            reason=q.reason,
            human_review_only=True,
            ranking_permission_granted=False,
            execution_allowed=False,
            report_submission_allowed=False,
        )
        for q in list(result.risk_queue or [])
    ]
    seeds = [
        FindingSeed(
            seed_id=s.seed_id,
            source=s.source,
            vuln_type=s.vuln_type,
            component=s.component,
            root_cause=s.root_cause,
            evidence_ref=s.evidence_ref,
            endpoint=s.endpoint,
            title=s.title,
            severity=s.severity,
            confidence=s.confidence,
            disposition=s.disposition,
            notes=list(s.notes)[:8],
        )
        for s in list(result.seeds or [])
    ]
    return FindingDedupRiskResult(
        stage="v3_finding_dedup_risk",
        inspirations=list(result.inspirations)
        or ["final-scheme-Finding-Dedup", "final-scheme-Risk-Prioritization"],
        execution_mode="plan_only",
        status=result.status,
        package_id=result.package_id,
        package_root=result.package_root,
        seeds=seeds,
        seed_count=len(seeds),
        clusters=clusters,
        cluster_count=len(clusters),
        risk_queue=queue,
        risk_queue_count=len(queue),
        offline_hint_count=result.offline_hint_count,
        offline_artifact_present=result.offline_artifact_present,
        human_allow_export_write=bool(result.human_allow_export_write),
        export_written=bool(result.export_written)
        and bool(result.human_allow_export_write),
        export_count=int(result.export_count or 0)
        if result.human_allow_export_write
        else 0,
        export_root_relative="_export/finding_dedup_risk",
        run_stamp=result.run_stamp,
        execution_allowed=False,
        validation_allowed=False,
        report_submission_allowed=False,
        confirmed_vulnerability=False,
        finding_promotion_allowed=False,
        ranking_permission_granted=False,
        network_access=False,
        live_validation=False,
        process_spawn_allowed=False,
        safety_invariants=list(SAFETY_INVARIANTS),
        next_allowed_action=(
            "Human reviews dedup clusters and risk queue; Mythos never promotes or submits."
        ),
        notes=list(result.notes or [])[:24],
        summary=result.summary or _summary(len(seeds), len(clusters), len(queue)),
    )


def _force_safety_dict(payload: dict[str, Any]) -> dict[str, Any]:
    out = dict(payload)
    out["execution_allowed"] = False
    out["validation_allowed"] = False
    out["report_submission_allowed"] = False
    out["confirmed_vulnerability"] = False
    out["finding_promotion_allowed"] = False
    out["ranking_permission_granted"] = False
    out["network_access"] = False
    out["live_validation"] = False
    out["process_spawn_allowed"] = False
    out["execution_mode"] = "plan_only"
    out["safety_invariants"] = list(SAFETY_INVARIANTS)
    out["next_allowed_action"] = (
        "Human reviews dedup clusters and risk queue; Mythos never promotes or submits."
    )
    for key in ("clusters", "risk_queue", "seeds"):
        items = out.get(key)
        if not isinstance(items, list):
            continue
        cleaned = []
        for item in items:
            if not isinstance(item, dict):
                continue
            d = dict(item)
            d["execution_allowed"] = False
            d["finding_promotion_allowed"] = False
            d["report_submission_allowed"] = False
            d["ranking_permission_granted"] = False
            d["human_review_only"] = True
            for text_key in ("title", "component", "evidence_ref", "reason", "endpoint"):
                if text_key in d:
                    d[text_key] = _scrub_text(str(d.get(text_key) or ""))
            cleaned.append(d)
        out[key] = cleaned
    if isinstance(out.get("clusters"), list):
        out["cluster_count"] = len(out["clusters"])
    else:
        out["cluster_count"] = int(out.get("cluster_count") or 0)
    if isinstance(out.get("risk_queue"), list):
        out["risk_queue_count"] = len(out["risk_queue"])
    else:
        out["risk_queue_count"] = int(out.get("risk_queue_count") or 0)
    if isinstance(out.get("seeds"), list):
        out["seed_count"] = len(out["seeds"])
    else:
        out["seed_count"] = int(out.get("seed_count") or 0)
    return out


def _safe_text(value: Any, default: str) -> str:
    if value is None:
        return default
    if not isinstance(value, str):
        value = str(value)
    text = value.strip()
    return text[:180] if text else default


def _scrub_text(value: str) -> str:
    text = str(value or "")
    if _SECRET_HINTS.search(text):
        return "[redacted]"
    return text[:240]


def _slug(value: str) -> str:
    text = re.sub(r"[^a-zA-Z0-9._-]+", "_", (value or "").strip().lower())
    return text[:80] or "none"


__all__ = [
    "STATUS_READY",
    "STATUS_EMPTY",
    "STATUS_PACKAGE_MISSING",
    "STATUS_WRITTEN",
    "STATUS_BLOCKED_SCOPE",
    "SAFETY_INVARIANTS",
    "FindingDedupRiskError",
    "FindingSeed",
    "FindingClusterPlan",
    "RiskQueuePlanItem",
    "FindingDedupRiskResult",
    "build_finding_dedup_risk",
    "run_finding_dedup_risk",
    "attach_finding_dedup_risk_to_bridge_result",
]
