"""Agent Memory — advisory historical signals for authorized packages (final-scheme V3).

Lawful research only:
- Ingest offline memory artifacts under package inputs/ (no network)
- Derive FP / retain / severity-hint signals from bridge residual + drafts
- Optional export under package _export/agent_memory/ with human flag
- Never grants execution / validation / submit / promote permission
- Never stores raw secrets, cookies, tokens, or real user data
"""

from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


STATUS_READY = "agent_memory_ready"
STATUS_EMPTY = "agent_memory_empty"
STATUS_PACKAGE_MISSING = "agent_memory_package_missing"
STATUS_WRITTEN = "agent_memory_export_written"

SAFETY_INVARIANTS = [
    "authorized_package_or_bridge_only",
    "no_public_target_scanning",
    "no_network_access",
    "no_raw_secrets_or_user_data",
    "no_automatic_report_submission",
    "no_finding_promotion",
    "advisory_ranking_only_never_execution_permission",
    "human_review_required_before_any_action_change",
    "no_export_write_without_human_flag",
]

_SECRET_HINTS = re.compile(
    r"(?i)(password|passwd|secret|token|api[_-]?key|authorization|cookie|session|bearer|private[_-]?key|ssh-rsa|BEGIN [A-Z ]*PRIVATE)"
)
_MAX_ENTRIES = 48
_MAX_HINTS = 24


class AgentMemoryError(ValueError):
    """Raised when bridge attach receives invalid input."""


@dataclass(frozen=True)
class MemoryEntry:
    entry_id: str
    kind: str  # false_positive_pattern | retain_signal | severity_hint | knowledge_pattern | residual_disposition
    topic: str
    summary: str
    source_ref: str
    confidence: str = "low"
    retained_fields: list[str] = field(default_factory=list)
    applies_to: list[str] = field(default_factory=list)
    false_positive_checks: list[str] = field(default_factory=list)
    human_review_required: bool = True
    execution_allowed: bool = False
    notes: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class CandidateMemoryHint:
    candidate_id: str
    root_cause_id: str
    rank_delta: int
    reason: str
    matched_entry_ids: list[str] = field(default_factory=list)
    action_hint: str = "human_review_priority_only"
    execution_allowed: bool = False
    report_submission_allowed: bool = False
    confirmed_vulnerability: bool = False


@dataclass(frozen=True)
class AgentMemoryResult:
    stage: str
    inspirations: list[str]
    execution_mode: str
    status: str
    package_id: str = ""
    package_root: str = ""
    entries: list[MemoryEntry] = field(default_factory=list)
    entry_count: int = 0
    false_positive_pattern_count: int = 0
    retain_signal_count: int = 0
    knowledge_pattern_count: int = 0
    candidate_hints: list[CandidateMemoryHint] = field(default_factory=list)
    candidate_hint_count: int = 0
    offline_artifact_count: int = 0
    human_allow_export_write: bool = False
    export_written: bool = False
    export_count: int = 0
    export_root_relative: str = "_export/agent_memory"
    run_stamp: str = ""
    execution_allowed: bool = False
    validation_allowed: bool = False
    report_submission_allowed: bool = False
    confirmed_vulnerability: bool = False
    finding_promotion_allowed: bool = False
    ranking_permission_granted: bool = False
    network_access: bool = False
    live_validation: bool = False
    safety_invariants: list[str] = field(default_factory=list)
    next_allowed_action: str = (
        "Human reviews advisory memory signals; Mythos never auto-executes or submits from memory."
    )
    notes: list[str] = field(default_factory=list)
    summary: str = ""

    def to_dict(self) -> dict[str, Any]:
        return _force_safety_dict(asdict(self))


def build_agent_memory(
    *,
    package_root: str | Path | None = None,
    package_id: str = "",
    bridge_result: dict[str, Any] | None = None,
    human_allow_export_write: bool = False,
) -> AgentMemoryResult:
    return run_agent_memory(
        package_root=package_root,
        package_id=package_id,
        bridge_result=bridge_result,
        human_allow_export_write=human_allow_export_write,
    )


def run_agent_memory(
    *,
    package_root: str | Path | None = None,
    package_id: str = "",
    bridge_result: dict[str, Any] | None = None,
    human_allow_export_write: bool = False,
) -> AgentMemoryResult:
    """Build advisory agent memory from package offline artifacts + bridge context."""
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

    offline_entries, offline_n = _load_offline_entries(root)
    derived = _derive_from_bridge(bridge, package_id=pid)
    entries = _merge_entries(offline_entries + derived)
    hints = _candidate_hints(bridge, entries)

    fp_n = sum(1 for e in entries if e.kind == "false_positive_pattern")
    retain_n = sum(1 for e in entries if e.kind in {"retain_signal", "residual_disposition"})
    know_n = sum(1 for e in entries if e.kind == "knowledge_pattern")

    notes = [
        "advisory_agent_memory_only",
        "never_grants_execution_permission",
        "no_raw_secrets_retained",
        "ranking_hints_do_not_unlock_submit",
    ]
    if not entries and not bridge:
        return _empty(
            status=STATUS_EMPTY,
            package_id=pid,
            package_root=root_s,
            notes=notes + ["no_offline_or_bridge_signals"],
            human_allow_export_write=bool(human_allow_export_write),
        )

    export_written = False
    export_count = 0
    run_stamp = ""
    status = STATUS_READY if entries or hints else STATUS_EMPTY

    result = AgentMemoryResult(
        stage="v3_agent_memory",
        inspirations=["MDASH", "final-scheme-V3", "final-scheme-7-knowledge"],
        execution_mode="plan_only",
        status=status,
        package_id=pid,
        package_root=root_s,
        entries=entries,
        entry_count=len(entries),
        false_positive_pattern_count=fp_n,
        retain_signal_count=retain_n,
        knowledge_pattern_count=know_n,
        candidate_hints=hints,
        candidate_hint_count=len(hints),
        offline_artifact_count=offline_n,
        human_allow_export_write=bool(human_allow_export_write),
        safety_invariants=list(SAFETY_INVARIANTS),
        notes=notes,
        summary=(
            f"entries={len(entries)} fp={fp_n} retain={retain_n} knowledge={know_n} "
            f"hints={len(hints)} offline_artifacts={offline_n}"
        ),
    )

    if human_allow_export_write and root is not None:
        written, count, stamp = _export_memory(root, result)
        if written:
            result = AgentMemoryResult(
                stage=result.stage,
                inspirations=list(result.inspirations),
                execution_mode=result.execution_mode,
                status=STATUS_WRITTEN,
                package_id=result.package_id,
                package_root=result.package_root,
                entries=list(result.entries),
                entry_count=result.entry_count,
                false_positive_pattern_count=result.false_positive_pattern_count,
                retain_signal_count=result.retain_signal_count,
                knowledge_pattern_count=result.knowledge_pattern_count,
                candidate_hints=list(result.candidate_hints),
                candidate_hint_count=result.candidate_hint_count,
                offline_artifact_count=result.offline_artifact_count,
                human_allow_export_write=True,
                export_written=True,
                export_count=count,
                export_root_relative=result.export_root_relative,
                run_stamp=stamp,
                safety_invariants=list(result.safety_invariants),
                next_allowed_action=result.next_allowed_action,
                notes=list(result.notes) + ["export_written_under_package_tmp"],
                summary=result.summary,
            )
            result = _force_safety(result)
        else:
            result = AgentMemoryResult(
                stage=result.stage,
                inspirations=list(result.inspirations),
                execution_mode=result.execution_mode,
                status=result.status,
                package_id=result.package_id,
                package_root=result.package_root,
                entries=list(result.entries),
                entry_count=result.entry_count,
                false_positive_pattern_count=result.false_positive_pattern_count,
                retain_signal_count=result.retain_signal_count,
                knowledge_pattern_count=result.knowledge_pattern_count,
                candidate_hints=list(result.candidate_hints),
                candidate_hint_count=result.candidate_hint_count,
                offline_artifact_count=result.offline_artifact_count,
                human_allow_export_write=True,
                export_written=False,
                export_count=0,
                export_root_relative=result.export_root_relative,
                run_stamp=result.run_stamp,
                safety_invariants=list(result.safety_invariants),
                next_allowed_action=result.next_allowed_action,
                notes=list(result.notes) + ["export_skipped_or_failed_still_advisory"],
                summary=result.summary,
            )
            result = _force_safety(result)
    elif human_allow_export_write and root is None:
        result = AgentMemoryResult(
            stage=result.stage,
            inspirations=list(result.inspirations),
            execution_mode=result.execution_mode,
            status=result.status,
            package_id=result.package_id,
            package_root=result.package_root,
            entries=list(result.entries),
            entry_count=result.entry_count,
            false_positive_pattern_count=result.false_positive_pattern_count,
            retain_signal_count=result.retain_signal_count,
            knowledge_pattern_count=result.knowledge_pattern_count,
            candidate_hints=list(result.candidate_hints),
            candidate_hint_count=result.candidate_hint_count,
            offline_artifact_count=result.offline_artifact_count,
            human_allow_export_write=True,
            export_written=False,
            export_count=0,
            export_root_relative=result.export_root_relative,
            run_stamp=result.run_stamp,
            safety_invariants=list(result.safety_invariants),
            next_allowed_action=result.next_allowed_action,
            notes=list(result.notes) + ["export_requested_but_no_package_root"],
            summary=result.summary,
        )
        result = _force_safety(result)

    return _force_safety(result)


def attach_agent_memory_to_bridge_result(
    bridge_result: dict[str, Any],
    *,
    package_root: str | Path | None = None,
    agent_memory: dict[str, Any] | AgentMemoryResult | None = None,
    human_allow_export_write: bool = False,
) -> dict[str, Any]:
    """Attach agent memory; never unlocks execute/promote/submit."""
    if not isinstance(bridge_result, dict):
        raise AgentMemoryError("bridge_result_must_be_object")

    package_id = str(bridge_result.get("package_id") or "")
    resolved_root = package_root or bridge_result.get("package_root")

    if isinstance(agent_memory, AgentMemoryResult):
        payload = agent_memory.to_dict()
    elif isinstance(agent_memory, dict):
        payload = _force_safety_dict(dict(agent_memory))
    else:
        payload = run_agent_memory(
            package_root=resolved_root,
            package_id=package_id,
            bridge_result=bridge_result,
            human_allow_export_write=bool(human_allow_export_write),
        ).to_dict()

    if not payload.get("package_id") and package_id:
        payload["package_id"] = package_id
    payload = _force_safety_dict(payload)

    out = dict(bridge_result)
    out["agent_memory"] = payload
    out["agent_memory_present"] = True
    out["agent_memory_status"] = str(payload.get("status") or STATUS_EMPTY)
    out["agent_memory_entry_count"] = int(payload.get("entry_count") or 0)
    out["agent_memory_false_positive_pattern_count"] = int(
        payload.get("false_positive_pattern_count") or 0
    )
    out["agent_memory_candidate_hint_count"] = int(payload.get("candidate_hint_count") or 0)
    out["agent_memory_export_written"] = bool(payload.get("export_written"))
    out["agent_memory_ranking_permission_granted"] = False
    out["execution_allowed"] = False
    out["validation_allowed"] = False
    out["report_submission_allowed"] = False
    out["confirmed_vulnerability"] = False
    if out.get("submission_blocked") is not True:
        out["submission_blocked"] = True
    return out


def _load_offline_entries(root: Path | None) -> tuple[list[MemoryEntry], int]:
    if root is None:
        return [], 0
    paths: list[Path] = []
    candidates = [
        root / "inputs" / "agent_memory.json",
        root / "inputs" / "memory.json",
        root / "inputs" / "knowledge.json",
    ]
    mem_dir = root / "inputs" / "memory"
    if mem_dir.is_dir():
        paths.extend(sorted(mem_dir.glob("*.json")))
    know_dir = root / "inputs" / "knowledge"
    if know_dir.is_dir():
        paths.extend(sorted(know_dir.glob("*.json")))
    for p in candidates:
        if p.is_file():
            paths.append(p)

    entries: list[MemoryEntry] = []
    artifact_n = 0
    seen_paths: set[str] = set()
    for path in paths:
        key = str(path.resolve()) if path.exists() else str(path)
        if key in seen_paths:
            continue
        seen_paths.add(key)
        if not path.is_file():
            continue
        artifact_n += 1
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            continue
        items: list[Any]
        if isinstance(raw, list):
            items = raw
        elif isinstance(raw, dict):
            if isinstance(raw.get("entries"), list):
                items = raw["entries"]
            elif isinstance(raw.get("patterns"), list):
                items = raw["patterns"]
            else:
                items = [raw]
        else:
            continue
        for i, item in enumerate(items, start=1):
            if not isinstance(item, dict):
                continue
            entry = _entry_from_dict(
                item,
                default_id=f"offline-{path.stem}-{i}",
                source_ref=f"inputs:{path.relative_to(root).as_posix()}" if root in path.parents or path.parent == root / "inputs" or True else path.name,
            )
            if entry is not None:
                # normalize source_ref to relative when possible
                try:
                    rel = path.relative_to(root).as_posix()
                    entry = MemoryEntry(
                        **{**asdict(entry), "source_ref": f"file:{rel}"}
                    )
                except Exception:
                    pass
                entries.append(entry)
            if len(entries) >= _MAX_ENTRIES:
                break
        if len(entries) >= _MAX_ENTRIES:
            break
    return entries[:_MAX_ENTRIES], artifact_n


def _entry_from_dict(
    item: dict[str, Any],
    *,
    default_id: str,
    source_ref: str,
) -> MemoryEntry | None:
    summary = _scrub_text(
        str(
            item.get("summary")
            or item.get("name")
            or item.get("title")
            or item.get("false_positive_reason")
            or item.get("root_cause_summary")
            or ""
        )
    )
    topic = _scrub_text(str(item.get("topic") or item.get("name") or item.get("pattern_id") or "memory_signal"))
    if not summary and not topic:
        return None
    kind = str(item.get("kind") or item.get("category") or "knowledge_pattern").strip()
    if kind in {"fp", "false_positive", "false-positive"}:
        kind = "false_positive_pattern"
    if kind in {"retain", "signal"}:
        kind = "retain_signal"
    if kind not in {
        "false_positive_pattern",
        "retain_signal",
        "severity_hint",
        "knowledge_pattern",
        "residual_disposition",
    }:
        kind = "knowledge_pattern"
    conf = str(item.get("confidence") or "low").lower()
    if conf not in {"low", "medium", "high"}:
        conf = "low"
    retained = [
        _scrub_text(str(x))
        for x in (item.get("retained_fields") or ["topic", "summary", "kind"])
        if str(x).strip()
    ][:12]
    applies = [_scrub_text(str(x)) for x in (item.get("applies_to") or []) if str(x).strip()][:12]
    fp_checks = [
        _scrub_text(str(x))
        for x in (item.get("false_positive_checks") or [])
        if str(x).strip()
    ][:12]
    return MemoryEntry(
        entry_id=_scrub_text(str(item.get("entry_id") or item.get("pattern_id") or default_id))[:80],
        kind=kind,
        topic=topic[:120],
        summary=(summary or topic)[:400],
        source_ref=_scrub_text(str(item.get("source_ref") or source_ref))[:200],
        confidence=conf,
        retained_fields=retained or ["topic", "summary", "kind"],
        applies_to=applies,
        false_positive_checks=fp_checks,
        human_review_required=True,
        execution_allowed=False,
        notes=["offline_or_derived_advisory"],
    )


def _derive_from_bridge(bridge: dict[str, Any], *, package_id: str) -> list[MemoryEntry]:
    entries: list[MemoryEntry] = []
    # residual gates dispositions
    gates = bridge.get("human_residual_gates") if isinstance(bridge.get("human_residual_gates"), list) else []
    for i, gate in enumerate(gates, start=1):
        if not isinstance(gate, dict):
            continue
        status = str(gate.get("status") or "")
        cid = str(gate.get("candidate_id") or gate.get("root_cause_id") or f"gate-{i}")
        if status in {"human_rejected_or_fp", "rejected", "false_positive"}:
            reason = _scrub_text(
                str(
                    gate.get("false_positive_reason")
                    or gate.get("reason")
                    or gate.get("notes")
                    or "human residual rejected or false-positive disposition"
                )
            )
            entries.append(
                MemoryEntry(
                    entry_id=f"fp-residual-{cid}"[:80],
                    kind="false_positive_pattern",
                    topic=f"residual_fp:{status}",
                    summary=reason[:400] or f"Residual gate disposition {status}",
                    source_ref=f"bridge:human_residual_gates:{cid}",
                    confidence="medium",
                    retained_fields=["status", "false_positive_reason", "candidate_id"],
                    applies_to=[_scrub_text(str(gate.get("vuln_type") or ""))],
                    false_positive_checks=["confirm control path still present on re-audit"],
                    notes=["derived_from_residual_gate"],
                )
            )
        elif status in {"ready_for_human_review", "hold", "held"}:
            entries.append(
                MemoryEntry(
                    entry_id=f"retain-residual-{cid}"[:80],
                    kind="residual_disposition",
                    topic=f"residual:{status}",
                    summary=f"Residual disposition {status} for {cid}; still submission-blocked.",
                    source_ref=f"bridge:human_residual_gates:{cid}",
                    confidence="low",
                    retained_fields=["status", "candidate_id"],
                    notes=["derived_from_residual_gate"],
                )
            )

    # drafts / multi-engine local consistency
    drafts = bridge.get("drafts") if isinstance(bridge.get("drafts"), list) else []
    for draft in drafts:
        if not isinstance(draft, dict):
            continue
        cid = str(draft.get("candidate_id") or "")
        root = str(draft.get("root_cause_id") or "")
        vtype = _scrub_text(str(draft.get("vuln_type") or draft.get("route") or "candidate"))
        mev = draft.get("multi_engine_verdict") if isinstance(draft.get("multi_engine_verdict"), dict) else {}
        mev_status = str(mev.get("status") or "")
        if mev_status:
            entries.append(
                MemoryEntry(
                    entry_id=f"mev-{cid or root or 'draft'}"[:80],
                    kind="retain_signal",
                    topic=f"mev:{mev_status}",
                    summary=f"Multi-engine status {mev_status} for {cid or root}; not confirmed vulnerability.",
                    source_ref=f"bridge:draft:{cid or root}",
                    confidence="low",
                    retained_fields=["multi_engine_status", "vuln_type", "candidate_id"],
                    applies_to=[vtype] if vtype else [],
                    notes=["derived_from_multi_engine"],
                )
            )
        # severity hint advisory only
        sev = str(draft.get("severity") or draft.get("severity_estimate") or "").lower()
        if sev in {"critical", "high", "medium", "low"}:
            entries.append(
                MemoryEntry(
                    entry_id=f"sev-{cid or root}"[:80],
                    kind="severity_hint",
                    topic=f"severity:{sev}",
                    summary=f"Advisory severity hint {sev} for {cid or root}.",
                    source_ref=f"bridge:draft:{cid or root}",
                    confidence="low",
                    retained_fields=["severity", "candidate_id"],
                    applies_to=[vtype] if vtype else [],
                    notes=["derived_from_draft_severity"],
                )
            )

    # package-level checklist / package id retain
    if package_id:
        entries.append(
            MemoryEntry(
                entry_id=f"pkg-{package_id}"[:80],
                kind="retain_signal",
                topic="package_context",
                summary=f"Memory scoped to authorized package {package_id}.",
                source_ref="bridge:package_id",
                confidence="high",
                retained_fields=["package_id"],
                notes=["package_scope_anchor"],
            )
        )

    return entries[:_MAX_ENTRIES]


def _merge_entries(entries: list[MemoryEntry]) -> list[MemoryEntry]:
    out: list[MemoryEntry] = []
    seen: set[str] = set()
    for e in entries:
        key = f"{e.kind}|{e.topic}|{e.summary[:80]}|{e.source_ref}"
        if key in seen:
            continue
        seen.add(key)
        out.append(
            MemoryEntry(
                **{
                    **asdict(e),
                    "execution_allowed": False,
                    "human_review_required": True,
                    "summary": _scrub_text(e.summary)[:400],
                    "topic": _scrub_text(e.topic)[:120],
                }
            )
        )
        if len(out) >= _MAX_ENTRIES:
            break
    return out


def _candidate_hints(
    bridge: dict[str, Any],
    entries: list[MemoryEntry],
) -> list[CandidateMemoryHint]:
    drafts = bridge.get("drafts") if isinstance(bridge.get("drafts"), list) else []
    if not drafts:
        return []
    fp_entries = [e for e in entries if e.kind == "false_positive_pattern"]
    hints: list[CandidateMemoryHint] = []
    for draft in drafts:
        if not isinstance(draft, dict):
            continue
        cid = str(draft.get("candidate_id") or "")
        root = str(draft.get("root_cause_id") or "")
        vtype = str(draft.get("vuln_type") or draft.get("route") or "").lower()
        text = " ".join(
            [
                cid,
                root,
                vtype,
                str(draft.get("title") or ""),
                str((draft.get("report_draft") or {}).get("title") if isinstance(draft.get("report_draft"), dict) else ""),
            ]
        ).lower()
        matched: list[str] = []
        rank_delta = 0
        reason_bits: list[str] = []
        for e in fp_entries:
            blob = f"{e.topic} {e.summary} {' '.join(e.applies_to)}".lower()
            if any(tok and tok in text for tok in blob.split() if len(tok) > 4) or (
                vtype and vtype in blob
            ):
                matched.append(e.entry_id)
                rank_delta -= 2
                reason_bits.append(f"fp_match:{e.entry_id}")
        # severity boost for high/critical still only ranking
        sev = str(draft.get("severity") or "").lower()
        if sev in {"critical", "high"}:
            rank_delta += 1
            reason_bits.append(f"severity_hint:{sev}")
        if not reason_bits:
            # still emit neutral hint when memory present
            if entries:
                rank_delta = 0
                reason_bits.append("memory_present_no_fp_match")
            else:
                continue
        hints.append(
            CandidateMemoryHint(
                candidate_id=cid,
                root_cause_id=root,
                rank_delta=rank_delta,
                reason=";".join(reason_bits)[:300],
                matched_entry_ids=matched[:8],
                action_hint="human_review_priority_only",
                execution_allowed=False,
                report_submission_allowed=False,
                confirmed_vulnerability=False,
            )
        )
        if len(hints) >= _MAX_HINTS:
            break
    return hints


def _export_memory(root: Path, result: AgentMemoryResult) -> tuple[bool, int, str]:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    export_root = root / "_export" / "agent_memory" / stamp
    try:
        export_root.mkdir(parents=True, exist_ok=True)
        payload = result.to_dict()
        (export_root / "index.json").write_text(
            json.dumps(payload, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        lines = [
            "# Agent Memory export (advisory only)",
            "",
            f"- package: `{result.package_id}`",
            f"- status: `{result.status}`",
            f"- entries: {result.entry_count}",
            f"- hints: {result.candidate_hint_count}",
            f"- summary: {result.summary}",
            "",
            "## Safety",
            "",
            "- report_submission_allowed: false",
            "- execution_allowed: false",
            "- ranking_permission_granted: false",
            "- no raw secrets",
            "",
            "## Entries",
            "",
        ]
        for e in result.entries[:24]:
            lines.append(f"### {e.entry_id} — {e.kind}")
            lines.append(f"- topic: {e.topic}")
            lines.append(f"- summary: {e.summary}")
            lines.append(f"- source: {e.source_ref}")
            lines.append("")
        (export_root / "README.md").write_text("\n".join(lines), encoding="utf-8")
        return True, 1, stamp
    except Exception:
        return False, 0, ""


def _scrub_text(value: str) -> str:
    text = " ".join(str(value or "").split())
    if _SECRET_HINTS.search(text):
        return "[redacted_secret_like_content]"
    return text


def _empty(
    *,
    status: str,
    package_id: str = "",
    package_root: str = "",
    notes: list[str] | None = None,
    human_allow_export_write: bool = False,
) -> AgentMemoryResult:
    return _force_safety(
        AgentMemoryResult(
            stage="v3_agent_memory",
            inspirations=["MDASH", "final-scheme-V3", "final-scheme-7-knowledge"],
            execution_mode="plan_only",
            status=status,
            package_id=package_id,
            package_root=package_root,
            human_allow_export_write=bool(human_allow_export_write),
            safety_invariants=list(SAFETY_INVARIANTS),
            notes=list(notes or []),
            summary="empty_or_missing_inputs",
        )
    )


def _coerce_entry(item: MemoryEntry | dict[str, Any]) -> MemoryEntry | None:
    if isinstance(item, MemoryEntry):
        return MemoryEntry(
            entry_id=str(item.entry_id),
            kind=str(item.kind),
            topic=_scrub_text(str(item.topic)),
            summary=_scrub_text(str(item.summary)),
            source_ref=str(item.source_ref),
            confidence=str(item.confidence or "low"),
            retained_fields=list(item.retained_fields or []),
            applies_to=list(item.applies_to or []),
            false_positive_checks=list(item.false_positive_checks or []),
            human_review_required=True,
            execution_allowed=False,
            notes=list(item.notes or []),
        )
    if not isinstance(item, dict):
        return None
    entry_id = str(item.get("entry_id") or "").strip()
    kind = str(item.get("kind") or "").strip() or "knowledge_pattern"
    if not entry_id:
        return None
    return MemoryEntry(
        entry_id=entry_id,
        kind=kind,
        topic=_scrub_text(str(item.get("topic") or "")),
        summary=_scrub_text(str(item.get("summary") or "")),
        source_ref=str(item.get("source_ref") or "agent_memory"),
        confidence=str(item.get("confidence") or "low"),
        retained_fields=[str(x) for x in (item.get("retained_fields") or []) if str(x).strip()],
        applies_to=[str(x) for x in (item.get("applies_to") or []) if str(x).strip()],
        false_positive_checks=[
            str(x) for x in (item.get("false_positive_checks") or []) if str(x).strip()
        ],
        human_review_required=True,
        execution_allowed=False,
        notes=[str(x) for x in (item.get("notes") or []) if str(x).strip()],
    )


def _coerce_hint(item: CandidateMemoryHint | dict[str, Any]) -> CandidateMemoryHint | None:
    if isinstance(item, CandidateMemoryHint):
        return CandidateMemoryHint(
            candidate_id=str(item.candidate_id),
            root_cause_id=str(item.root_cause_id),
            rank_delta=int(item.rank_delta or 0),
            reason=_scrub_text(str(item.reason)),
            matched_entry_ids=list(item.matched_entry_ids or []),
            action_hint="human_review_priority_only",
            execution_allowed=False,
            report_submission_allowed=False,
            confirmed_vulnerability=False,
        )
    if not isinstance(item, dict):
        return None
    candidate_id = str(item.get("candidate_id") or "").strip()
    if not candidate_id:
        return None
    return CandidateMemoryHint(
        candidate_id=candidate_id,
        root_cause_id=str(item.get("root_cause_id") or ""),
        rank_delta=int(item.get("rank_delta") or 0),
        reason=_scrub_text(str(item.get("reason") or "")),
        matched_entry_ids=[str(x) for x in (item.get("matched_entry_ids") or []) if str(x).strip()],
        action_hint="human_review_priority_only",
        execution_allowed=False,
        report_submission_allowed=False,
        confirmed_vulnerability=False,
    )


def _force_safety(result: AgentMemoryResult) -> AgentMemoryResult:
    entries = [e for e in (_coerce_entry(x) for x in list(result.entries or [])) if e is not None]
    hints = [h for h in (_coerce_hint(x) for x in list(result.candidate_hints or [])) if h is not None]
    return AgentMemoryResult(
        stage="v3_agent_memory",
        inspirations=list(result.inspirations) or ["MDASH", "final-scheme-V3"],
        execution_mode="plan_only",
        status=result.status,
        package_id=result.package_id,
        package_root=result.package_root,
        entries=entries,
        entry_count=len(entries),
        false_positive_pattern_count=sum(
            1 for e in entries if e.kind == "false_positive_pattern"
        ),
        retain_signal_count=sum(
            1 for e in entries if e.kind in {"retain_signal", "residual_disposition"}
        ),
        knowledge_pattern_count=sum(1 for e in entries if e.kind == "knowledge_pattern"),
        candidate_hints=hints,
        candidate_hint_count=len(hints),
        offline_artifact_count=int(result.offline_artifact_count or 0),
        human_allow_export_write=bool(result.human_allow_export_write),
        export_written=bool(result.export_written),
        export_count=int(result.export_count or 0),
        export_root_relative="_export/agent_memory",
        run_stamp=result.run_stamp,
        execution_allowed=False,
        validation_allowed=False,
        report_submission_allowed=False,
        confirmed_vulnerability=False,
        finding_promotion_allowed=False,
        ranking_permission_granted=False,
        network_access=False,
        live_validation=False,
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
        "ranking_permission_granted",
        "network_access",
        "live_validation",
    ):
        out[key] = False
    out["safety_invariants"] = list(SAFETY_INVARIANTS)
    # scrub nested entries
    cleaned_entries = []
    for e in out.get("entries") or []:
        if not isinstance(e, dict):
            continue
        ee = dict(e)
        ee["execution_allowed"] = False
        ee["human_review_required"] = True
        ee["summary"] = _scrub_text(str(ee.get("summary") or ""))
        ee["topic"] = _scrub_text(str(ee.get("topic") or ""))
        cleaned_entries.append(ee)
    out["entries"] = cleaned_entries
    out["entry_count"] = len(cleaned_entries)
    cleaned_hints = []
    for h in out.get("candidate_hints") or []:
        if not isinstance(h, dict):
            continue
        hh = dict(h)
        hh["execution_allowed"] = False
        hh["report_submission_allowed"] = False
        hh["confirmed_vulnerability"] = False
        hh["action_hint"] = "human_review_priority_only"
        cleaned_hints.append(hh)
    out["candidate_hints"] = cleaned_hints
    out["candidate_hint_count"] = len(cleaned_hints)
    return out


__all__ = [
    "AgentMemoryError",
    "AgentMemoryResult",
    "CandidateMemoryHint",
    "MemoryEntry",
    "STATUS_EMPTY",
    "STATUS_PACKAGE_MISSING",
    "STATUS_READY",
    "STATUS_WRITTEN",
    "attach_agent_memory_to_bridge_result",
    "build_agent_memory",
    "run_agent_memory",
]
