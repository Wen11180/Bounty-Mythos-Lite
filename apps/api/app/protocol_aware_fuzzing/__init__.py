"""Protocol-aware fuzzing planner — plan/export only under human gate.

Final-scheme V4 residual beyond nested deep_research._protocol_fuzzing_plans:
- Build protocol grammar / message-boundary / seed-corpus plans from CRS parser_candidates
- Optional offline package inputs/protocol*.json hints
- Optional write under package _export/protocol_aware_fuzzing/ with human flag
- Never spawns fuzzers, never network, never promotes crashes, never submits
- Never unlocks execution_allowed / validation_allowed / report_submission_allowed
"""

from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from app.crs_fuzzing import (
    STATUS_EMPTY as CRS_STATUS_EMPTY,
    STATUS_EMPTY_INPUT as CRS_STATUS_EMPTY_INPUT,
    STATUS_READY as CRS_STATUS_READY,
    STATUS_SKIPPED as CRS_STATUS_SKIPPED,
    build_crs_fuzzing_plan,
)


STATUS_READY = "protocol_aware_fuzzing_plan_ready"
STATUS_EMPTY = "protocol_aware_fuzzing_empty"
STATUS_SKIPPED = "protocol_aware_fuzzing_package_missing"
STATUS_NO_PARSERS = "protocol_aware_fuzzing_no_parsers"
STATUS_WRITTEN = "protocol_aware_fuzzing_export_written"

SAFETY_INVARIANTS = [
    "local_or_authorized_package_only",
    "no_public_target_scanning",
    "no_fuzzer_process_spawn",
    "no_network_access",
    "no_crash_promotion",
    "no_report_submission",
    "no_export_write_without_human_flag",
    "protocol_plan_export_local_package_only",
    "human_approval_required_before_any_run",
    "execution_always_blocked_in_planner",
    "grammar_plan_only_not_live_mutation",
]

_MAX_TARGETS = 24
_MAX_HINTS = 12
_MAX_SEEDS = 16
_MAX_QUESTIONS = 10

_PROTOCOL_HINT_RE = re.compile(r"^protocol.*\.json$", re.IGNORECASE)


class ProtocolAwareFuzzingError(ValueError):
    """Raised when bridge attach receives invalid input."""


@dataclass(frozen=True)
class ProtocolTargetPlan:
    target_symbol: str
    source_path: str
    candidate_type: str
    language: str = ""
    strategy: str = "derive_protocol_grammar_before_local_harness"
    grammar_plan: str = ""
    message_boundary_plan: str = ""
    seed_corpus_plan: list[str] = field(default_factory=list)
    harness_linkage_notes: list[str] = field(default_factory=list)
    human_questions: list[str] = field(default_factory=list)
    status: str = "planned"
    export_relative_path: str = ""
    written: bool = False
    execution_allowed: bool = False


@dataclass(frozen=True)
class ProtocolAwareFuzzingPlan:
    stage: str
    inspirations: list[str]
    execution_mode: str
    status: str
    package_id: str = ""
    package_root: str = ""
    targets: list[ProtocolTargetPlan] = field(default_factory=list)
    target_count: int = 0
    parser_source_count: int = 0
    offline_hint_count: int = 0
    grammar_plan_count: int = 0
    seed_plan_count: int = 0
    network_access: bool = False
    live_validation: bool = False
    process_spawn_allowed: bool = False
    execution_allowed: bool = False
    validation_allowed: bool = False
    report_submission_allowed: bool = False
    confirmed_vulnerability: bool = False
    finding_promotion_allowed: bool = False
    crash_promotion_allowed: bool = False
    human_approval_required_before_run: bool = True
    human_allow_export_write: bool = False
    export_written: bool = False
    export_count: int = 0
    export_root_relative: str = "_export/protocol_aware_fuzzing"
    safety_invariants: list[str] = field(default_factory=list)
    next_allowed_action: str = (
        "Review protocol grammar and seed plans offline; never run protocol fuzzers "
        "without explicit human approval and local sandbox."
    )
    notes: list[str] = field(default_factory=list)
    crs_status: str = ""
    human_questions: list[str] = field(default_factory=list)
    strategy_kinds: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return _force_safety_dict(asdict(self))
def build_protocol_aware_fuzzing_plan(
    *,
    package_root: str | Path | None = None,
    package_id: str = "",
    crs_fuzzing: dict[str, Any] | None = None,
    human_allow_export_write: bool = False,
) -> ProtocolAwareFuzzingPlan:
    notes: list[str] = [
        "plan_only",
        "no_fuzzer_execution",
        "protocol_grammar_and_seed_plan_only",
    ]
    root: Path | None = None
    if package_root is not None and str(package_root).strip():
        candidate = Path(package_root).resolve()
        if candidate.is_dir():
            root = candidate
        else:
            notes.append("package_root_not_a_directory")

    if root is None and not crs_fuzzing:
        return _empty_plan(
            status=STATUS_SKIPPED if package_root else STATUS_EMPTY,
            package_id=package_id,
            package_root=str(package_root or ""),
            notes=notes + ["no_package_root_and_no_crs_payload"],
            human_allow_export_write=bool(human_allow_export_write),
        )

    crs_payload = _resolve_crs_payload(
        crs_fuzzing=crs_fuzzing,
        package_root=root,
        package_id=package_id,
    )
    pkg_id = (
        package_id
        or str(crs_payload.get("package_id") or "")
        or (root.name if root is not None else "")
    )
    parsers = [
        p for p in list(crs_payload.get("parser_candidates") or []) if isinstance(p, dict)
    ]
    if not parsers:
        for h in list(crs_payload.get("harness_plans") or []):
            if not isinstance(h, dict):
                continue
            parsers.append(
                {
                    "symbol_name": h.get("target_symbol") or h.get("symbol_name") or "",
                    "source_path": h.get("source_path") or "",
                    "candidate_type": h.get("candidate_type") or "protocol_handler",
                    "language": h.get("language") or "",
                    "reason": "harness_plan_fallback",
                }
            )
    crs_status = str(crs_payload.get("status") or "")
    offline_hints = _load_offline_protocol_hints(root) if root is not None else []
    if offline_hints:
        notes.append(f"offline_protocol_hints={len(offline_hints)}")

    if not parsers and not offline_hints:
        empty_status = STATUS_NO_PARSERS
        if crs_status in {CRS_STATUS_SKIPPED, CRS_STATUS_EMPTY_INPUT}:
            empty_status = STATUS_SKIPPED if crs_status == CRS_STATUS_SKIPPED else STATUS_EMPTY
        elif crs_status in {CRS_STATUS_EMPTY, ""}:
            empty_status = STATUS_EMPTY if not root else STATUS_NO_PARSERS
        return _empty_plan(
            status=empty_status,
            package_id=pkg_id,
            package_root=str(root or package_root or ""),
            notes=notes + [
                "no_parser_candidates_or_protocol_hints",
                f"crs_status={crs_status or 'none'}",
            ],
            human_allow_export_write=bool(human_allow_export_write),
            crs_status=crs_status,
            parser_source_count=0,
            offline_hint_count=0,
        )

    targets = _build_targets(parsers=parsers, offline_hints=offline_hints)
    seed_total = sum(len(t.seed_corpus_plan) for t in targets)
    human_questions = _global_human_questions(targets)
    strategy_kinds = sorted(
        {t.strategy for t in targets if t.strategy}
        or {"derive_protocol_grammar_before_local_harness"}
    )

    plan = ProtocolAwareFuzzingPlan(
        stage="v4_protocol_aware_fuzzing",
        inspirations=[
            "Protocol-Aware Fuzzing",
            "Buttercup",
            "OSS-Fuzz",
            "grammar-based fuzzing",
            "deep_research_nested_stub_superseded",
        ],
        execution_mode="plan_only",
        status=STATUS_READY,
        package_id=pkg_id,
        package_root=str(root) if root is not None else str(package_root or ""),
        targets=targets,
        target_count=len(targets),
        parser_source_count=len(parsers),
        offline_hint_count=len(offline_hints),
        grammar_plan_count=sum(1 for t in targets if t.grammar_plan),
        seed_plan_count=seed_total,
        network_access=False,
        live_validation=False,
        process_spawn_allowed=False,
        execution_allowed=False,
        validation_allowed=False,
        report_submission_allowed=False,
        confirmed_vulnerability=False,
        finding_promotion_allowed=False,
        crash_promotion_allowed=False,
        human_approval_required_before_run=True,
        human_allow_export_write=bool(human_allow_export_write),
        export_written=False,
        export_count=0,
        export_root_relative="_export/protocol_aware_fuzzing",
        safety_invariants=list(SAFETY_INVARIANTS),
        next_allowed_action=(
            "Review protocol grammar/message-boundary/seed plans; optional human "
            "--allow-protocol-aware-fuzzing-export writes plan files only "
            "(never runs protocol fuzzers)."
        ),
        notes=notes + [
            f"crs_status={crs_status or 'ready'}",
            f"targets={len(targets)}",
            f"seeds={seed_total}",
        ],
        crs_status=crs_status or CRS_STATUS_READY,
        human_questions=human_questions,
        strategy_kinds=strategy_kinds,
    )
    plan = _force_safety_plan(plan)
    return _maybe_write_exports(
        plan,
        root=root,
        human_allow_export_write=bool(human_allow_export_write),
    )


def load_package_protocol_aware_fuzzing_plan(
    package_root: str | Path,
    *,
    package_id: str = "",
    crs_fuzzing: dict[str, Any] | None = None,
    human_allow_export_write: bool = False,
) -> dict[str, Any]:
    return build_protocol_aware_fuzzing_plan(
        package_root=package_root,
        package_id=package_id,
        crs_fuzzing=crs_fuzzing,
        human_allow_export_write=human_allow_export_write,
    ).to_dict()


def attach_protocol_aware_fuzzing_to_bridge_result(
    bridge_result: dict[str, Any],
    *,
    package_root: str | Path | None = None,
    crs_fuzzing: dict[str, Any] | None = None,
    protocol_aware_fuzzing: dict[str, Any] | ProtocolAwareFuzzingPlan | None = None,
    human_allow_export_write: bool = False,
) -> dict[str, Any]:
    """Attach plan-only protocol-aware fuzzing profile; never unlocks execute/submit."""
    if not isinstance(bridge_result, dict):
        raise ProtocolAwareFuzzingError("bridge_result_must_be_object")

    package_id = str(bridge_result.get("package_id") or "")
    resolved_root = package_root or bridge_result.get("package_root")
    crs_payload = crs_fuzzing
    if crs_payload is None and isinstance(bridge_result.get("crs_fuzzing"), dict):
        crs_payload = bridge_result.get("crs_fuzzing")

    if isinstance(protocol_aware_fuzzing, ProtocolAwareFuzzingPlan):
        payload = protocol_aware_fuzzing.to_dict()
    elif isinstance(protocol_aware_fuzzing, dict):
        payload = _force_safety_dict(dict(protocol_aware_fuzzing))
    else:
        payload = build_protocol_aware_fuzzing_plan(
            package_root=resolved_root,
            package_id=package_id,
            crs_fuzzing=crs_payload if isinstance(crs_payload, dict) else None,
            human_allow_export_write=bool(human_allow_export_write),
        ).to_dict()

    if not payload.get("package_id") and package_id:
        payload["package_id"] = package_id
    payload = _force_safety_dict(payload)

    out = dict(bridge_result)
    out["protocol_aware_fuzzing"] = payload
    out["protocol_aware_fuzzing_present"] = True
    out["protocol_aware_fuzzing_status"] = str(payload.get("status") or STATUS_EMPTY)
    out["protocol_aware_fuzzing_target_count"] = int(payload.get("target_count") or 0)
    out["protocol_aware_fuzzing_grammar_plan_count"] = int(
        payload.get("grammar_plan_count") or 0
    )
    out["protocol_aware_fuzzing_seed_plan_count"] = int(
        payload.get("seed_plan_count") or 0
    )
    out["protocol_aware_fuzzing_export_written"] = bool(payload.get("export_written"))
    out["protocol_aware_fuzzing_export_count"] = int(payload.get("export_count") or 0)
    out["protocol_aware_fuzzing_execution_allowed"] = False
    out["execution_allowed"] = False
    out["validation_allowed"] = False
    out["report_submission_allowed"] = False
    out["confirmed_vulnerability"] = False
    if out.get("submission_blocked") is not True:
        out["submission_blocked"] = True
    return out
def _resolve_crs_payload(
    *,
    crs_fuzzing: dict[str, Any] | None,
    package_root: Path | None,
    package_id: str,
) -> dict[str, Any]:
    if isinstance(crs_fuzzing, dict):
        return dict(crs_fuzzing)
    if package_root is not None:
        return build_crs_fuzzing_plan(
            package_root=package_root,
            package_id=package_id,
            human_allow_harness_write=False,
        ).to_dict()
    return {}


def _load_offline_protocol_hints(root: Path) -> list[dict[str, Any]]:
    hints: list[dict[str, Any]] = []
    inputs = root / "inputs"
    if not inputs.is_dir():
        return hints
    for path in sorted(inputs.iterdir()):
        if not path.is_file():
            continue
        if not _PROTOCOL_HINT_RE.match(path.name):
            continue
        if path.stat().st_size > 256_000:
            continue
        try:
            raw = path.read_text(encoding="utf-8-sig")
            data = json.loads(raw)
        except (OSError, UnicodeError, json.JSONDecodeError):
            continue
        if isinstance(data, dict):
            hints.append({**data, "_hint_file": path.name})
        elif isinstance(data, list):
            for item in data:
                if isinstance(item, dict):
                    hints.append({**item, "_hint_file": path.name})
        if len(hints) >= _MAX_HINTS:
            break
    return hints[:_MAX_HINTS]


def _build_targets(
    *,
    parsers: list[dict[str, Any]],
    offline_hints: list[dict[str, Any]],
) -> list[ProtocolTargetPlan]:
    targets: list[ProtocolTargetPlan] = []
    seen: set[tuple[str, str]] = set()

    for index, parser in enumerate(parsers, start=1):
        if len(targets) >= _MAX_TARGETS:
            break
        symbol = str(
            parser.get("symbol_name")
            or parser.get("target_symbol")
            or f"parser_{index}"
        ).strip() or f"parser_{index}"
        source = str(parser.get("source_path") or "").strip()
        key = (symbol, source)
        if key in seen:
            continue
        seen.add(key)
        ctype = str(parser.get("candidate_type") or "protocol_handler")
        language = str(parser.get("language") or "")
        hint = _match_hint(symbol, source, offline_hints)
        targets.append(
            _target_from_parser(
                symbol=symbol,
                source=source,
                candidate_type=ctype,
                language=language,
                hint=hint,
            )
        )

    for hint in offline_hints:
        if len(targets) >= _MAX_TARGETS:
            break
        symbol = str(
            hint.get("target_symbol")
            or hint.get("symbol_name")
            or hint.get("name")
            or ""
        ).strip()
        source = str(hint.get("source_path") or hint.get("path") or "").strip()
        if not symbol and not source:
            symbol = str(hint.get("_hint_file") or "offline_protocol_hint")
        key = (symbol or "hint", source)
        if key in seen:
            continue
        if any(
            t.target_symbol == symbol and (not source or t.source_path == source)
            for t in targets
        ):
            continue
        seen.add(key)
        targets.append(
            _target_from_parser(
                symbol=symbol or "offline_protocol_hint",
                source=source or f"inputs/{hint.get('_hint_file') or 'protocol.json'}",
                candidate_type=str(hint.get("candidate_type") or "offline_protocol_hint"),
                language=str(hint.get("language") or ""),
                hint=hint,
            )
        )
    return targets


def _match_hint(
    symbol: str,
    source: str,
    hints: list[dict[str, Any]],
) -> dict[str, Any] | None:
    symbol_l = symbol.lower()
    source_l = source.lower()
    for hint in hints:
        h_sym = str(
            hint.get("target_symbol") or hint.get("symbol_name") or hint.get("name") or ""
        ).lower()
        h_src = str(hint.get("source_path") or hint.get("path") or "").lower()
        if h_sym and h_sym == symbol_l:
            return hint
        if h_src and source_l and (h_src in source_l or source_l in h_src):
            return hint
    return None


def _target_from_parser(
    *,
    symbol: str,
    source: str,
    candidate_type: str,
    language: str,
    hint: dict[str, Any] | None,
) -> ProtocolTargetPlan:
    strategy = "derive_protocol_grammar_before_local_harness"
    if isinstance(hint, dict) and hint.get("strategy"):
        strategy = str(hint.get("strategy"))

    grammar = ""
    if isinstance(hint, dict):
        grammar = str(hint.get("grammar_plan") or hint.get("grammar") or "")
    if not grammar:
        grammar = (
            f"PLAN-ONLY grammar sketch for {symbol} ({candidate_type}): "
            f"1) identify framing/length/type fields; 2) model allowed enums and length bounds; "
            f"3) mark untrusted message boundaries before any sink; 4) never execute harness."
        )

    boundary = ""
    if isinstance(hint, dict):
        boundary = str(hint.get("message_boundary_plan") or hint.get("boundary_plan") or "")
    if not boundary:
        boundary = (
            f"Message-boundary plan for {symbol} @ {source or 'unknown'}: "
            f"split header/body/trailer; reject oversized lengths; keep local seeds only."
        )

    seeds: list[str] = []
    if isinstance(hint, dict):
        raw_seeds = hint.get("seed_corpus_plan") or hint.get("seeds") or []
        if isinstance(raw_seeds, list):
            seeds = [str(s) for s in raw_seeds if str(s).strip()][:_MAX_SEEDS]
        elif isinstance(raw_seeds, str) and raw_seeds.strip():
            seeds = [raw_seeds.strip()]
    if not seeds:
        seeds = [
            f"empty_payload_seed_for_{symbol}",
            f"minimal_header_only_seed_for_{symbol}",
            f"max_declared_length_edge_seed_for_{symbol}",
            f"unknown_type_enum_seed_for_{symbol}",
        ][:_MAX_SEEDS]

    linkage = [
        "link_to_crs_harness_plan_when_available",
        "link_to_local_fuzz_sandbox_recipe_when_available",
        "human_must_approve_before_any_local_run",
        "never_network_or_live_validation",
    ]
    if isinstance(hint, dict) and hint.get("_hint_file"):
        linkage.append(f"offline_hint_file={hint.get('_hint_file')}")

    questions = [
        f"Confirm {symbol} is an authorized local parser/protocol handler only.",
        "Confirm seed corpus contains no real user data, secrets, or production traffic.",
        "Confirm any future harness run stays local-only under explicit human approval.",
    ]
    if isinstance(hint, dict):
        for q in list(hint.get("human_questions") or [])[:4]:
            if isinstance(q, str) and q.strip():
                questions.append(q.strip())
    questions = questions[:_MAX_QUESTIONS]

    return ProtocolTargetPlan(
        target_symbol=symbol,
        source_path=source,
        candidate_type=candidate_type,
        language=language,
        strategy=strategy,
        grammar_plan=grammar,
        message_boundary_plan=boundary,
        seed_corpus_plan=seeds,
        harness_linkage_notes=linkage,
        human_questions=questions,
        status="planned",
        execution_allowed=False,
    )


def _global_human_questions(targets: list[ProtocolTargetPlan]) -> list[str]:
    questions = [
        "Are all protocol targets from authorized package code or offline inputs only?",
        "Do seed plans exclude production traffic, credentials, and personal data?",
        "Is execution still blocked until a separate explicit human approval?",
    ]
    for t in targets[:3]:
        for q in t.human_questions[:2]:
            if q not in questions:
                questions.append(q)
    return questions[:_MAX_QUESTIONS]
def _maybe_write_exports(
    plan: ProtocolAwareFuzzingPlan,
    *,
    root: Path | None,
    human_allow_export_write: bool,
) -> ProtocolAwareFuzzingPlan:
    notes = list(plan.notes)
    if not human_allow_export_write:
        notes.append("export_write_not_requested")
        return _rebuild_plan(plan, notes=notes, human_allow_export_write=False)

    if root is None:
        notes.append("export_write_requested_but_package_root_missing")
        return _rebuild_plan(plan, notes=notes, human_allow_export_write=True)

    if not plan.targets:
        notes.append("export_write_requested_but_no_targets")
        return _rebuild_plan(plan, notes=notes, human_allow_export_write=True)

    written_targets, export_count, any_written = _write_export_files(
        root=root,
        targets=list(plan.targets),
        package_id=plan.package_id or root.name,
        plan=plan,
    )
    notes.append("protocol_aware_fuzzing_export_write_attempted")
    status = plan.status
    next_action = plan.next_allowed_action
    if any_written:
        notes.append("protocol_aware_fuzzing_export_written")
        status = STATUS_WRITTEN
        next_action = (
            "Review exported protocol plans under package _export/protocol_aware_fuzzing/; "
            "Mythos still never spawns protocol fuzzers or promotes crashes."
        )
    else:
        notes.append("protocol_aware_fuzzing_export_write_produced_no_files")

    return _rebuild_plan(
        plan,
        targets=written_targets,
        notes=notes,
        status=status,
        next_allowed_action=next_action,
        human_allow_export_write=True,
        export_written=bool(any_written),
        export_count=int(export_count),
        export_root_relative="_export/protocol_aware_fuzzing",
    )


def _write_export_files(
    *,
    root: Path,
    targets: list[ProtocolTargetPlan],
    package_id: str,
    plan: ProtocolAwareFuzzingPlan,
) -> tuple[list[ProtocolTargetPlan], int, bool]:
    export_root = (root / "_export" / "protocol_aware_fuzzing").resolve()
    try:
        export_root.relative_to(root.resolve())
    except ValueError:
        return targets, 0, False

    export_root.mkdir(parents=True, exist_ok=True)
    written_targets: list[ProtocolTargetPlan] = []
    export_count = 0
    any_written = False

    index_payload = {
        "package_id": package_id,
        "status": "exported_plan_only",
        "target_count": len(targets),
        "execution_allowed": False,
        "process_spawn_allowed": False,
        "network_access": False,
        "live_validation": False,
        "crash_promotion_allowed": False,
        "report_submission_allowed": False,
        "confirmed_vulnerability": False,
        "safety_invariants": list(SAFETY_INVARIANTS),
        "crs_status": plan.crs_status,
    }
    (export_root / "index.json").write_text(
        json.dumps(index_payload, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    export_count += 1
    any_written = True

    for index, target in enumerate(targets, start=1):
        slug = _slug(f"{index:02d}-{target.target_symbol or 'target'}")
        target_dir = export_root / slug
        rel_dir = f"_export/protocol_aware_fuzzing/{slug}"
        target_dir.mkdir(parents=True, exist_ok=True)

        meta = {
            "package_id": package_id,
            "target_symbol": target.target_symbol,
            "source_path": target.source_path,
            "candidate_type": target.candidate_type,
            "language": target.language,
            "strategy": target.strategy,
            "status": "exported_plan_only",
            "execution_allowed": False,
            "process_spawn_allowed": False,
            "network_access": False,
            "live_validation": False,
            "crash_promotion_allowed": False,
            "report_submission_allowed": False,
            "confirmed_vulnerability": False,
            "export_relative_path": rel_dir,
            "seed_corpus_plan": list(target.seed_corpus_plan),
            "harness_linkage_notes": list(target.harness_linkage_notes),
            "human_questions": list(target.human_questions),
        }
        files = {
            "meta.json": json.dumps(meta, ensure_ascii=False, indent=2) + "\n",
            "grammar_plan.md": _render_grammar_md(target, package_id=package_id),
            "message_boundary_plan.md": _render_boundary_md(target, package_id=package_id),
            "seed_corpus_plan.md": _render_seeds_md(target, package_id=package_id),
            "README.md": _render_readme(target, package_id=package_id, export_dir=rel_dir),
        }
        for name, content in files.items():
            (target_dir / name).write_text(content, encoding="utf-8")
            export_count += 1
            any_written = True

        written_targets.append(
            ProtocolTargetPlan(
                target_symbol=target.target_symbol,
                source_path=target.source_path,
                candidate_type=target.candidate_type,
                language=target.language,
                strategy=target.strategy,
                grammar_plan=target.grammar_plan,
                message_boundary_plan=target.message_boundary_plan,
                seed_corpus_plan=list(target.seed_corpus_plan),
                harness_linkage_notes=list(target.harness_linkage_notes),
                human_questions=list(target.human_questions),
                status="exported_plan_only",
                export_relative_path=rel_dir,
                written=True,
                execution_allowed=False,
            )
        )

    return written_targets, export_count, any_written


def _render_grammar_md(target: ProtocolTargetPlan, *, package_id: str) -> str:
    return (
        f"# Protocol grammar plan (plan-only)\n\n"
        f"- package_id: `{package_id}`\n"
        f"- target: `{target.target_symbol}`\n"
        f"- source: `{target.source_path or 'unknown'}`\n"
        f"- candidate_type: `{target.candidate_type}`\n"
        f"- strategy: `{target.strategy}`\n"
        f"- execution_allowed: `false`\n\n"
        f"## Sketch\n\n{target.grammar_plan}\n\n"
        f"## Safety\n\n"
        f"- Never execute harness from this file.\n"
        f"- Never use production traffic as seeds.\n"
        f"- Human approval required before any local run.\n"
    )


def _render_boundary_md(target: ProtocolTargetPlan, *, package_id: str) -> str:
    return (
        f"# Message boundary plan (plan-only)\n\n"
        f"- package_id: `{package_id}`\n"
        f"- target: `{target.target_symbol}`\n\n"
        f"{target.message_boundary_plan}\n\n"
        f"execution_allowed=false process_spawn_allowed=false network_access=false\n"
    )


def _render_seeds_md(target: ProtocolTargetPlan, *, package_id: str) -> str:
    seed_lines = "\n".join(f"- {s}" for s in target.seed_corpus_plan) or "- (none)"
    return (
        f"# Seed corpus plan (plan-only)\n\n"
        f"- package_id: `{package_id}`\n"
        f"- target: `{target.target_symbol}`\n"
        f"- no_real_user_data\n"
        f"- no_secrets\n\n"
        f"## Planned seeds\n\n{seed_lines}\n\n"
        f"execution_allowed=false\n"
    )


def _render_readme(target: ProtocolTargetPlan, *, package_id: str, export_dir: str) -> str:
    questions = "\n".join(f"- {q}" for q in target.human_questions) or "- (none)"
    linkage = "\n".join(f"- {n}" for n in target.harness_linkage_notes) or "- (none)"
    return (
        f"# Protocol-aware fuzzing export\n\n"
        f"Package `{package_id}` target `{target.target_symbol}`.\n\n"
        f"Export dir: `{export_dir}`\n\n"
        f"This export is **plan-only**. Mythos never spawns protocol fuzzers, "
        f"never opens network sockets, and never promotes crashes from this folder.\n\n"
        f"## Linkage notes\n\n{linkage}\n\n"
        f"## Human questions\n\n{questions}\n"
    )
def _empty_plan(
    *,
    status: str,
    package_id: str = "",
    package_root: str = "",
    notes: list[str] | None = None,
    human_allow_export_write: bool = False,
    crs_status: str = "",
    parser_source_count: int = 0,
    offline_hint_count: int = 0,
) -> ProtocolAwareFuzzingPlan:
    return _force_safety_plan(
        ProtocolAwareFuzzingPlan(
            stage="v4_protocol_aware_fuzzing",
            inspirations=[
                "Protocol-Aware Fuzzing",
                "Buttercup",
                "OSS-Fuzz",
                "grammar-based fuzzing",
            ],
            execution_mode="plan_only",
            status=status,
            package_id=package_id,
            package_root=package_root,
            targets=[],
            target_count=0,
            parser_source_count=parser_source_count,
            offline_hint_count=offline_hint_count,
            grammar_plan_count=0,
            seed_plan_count=0,
            human_allow_export_write=bool(human_allow_export_write),
            safety_invariants=list(SAFETY_INVARIANTS),
            notes=list(notes or []),
            crs_status=crs_status,
            strategy_kinds=["derive_protocol_grammar_before_local_harness"],
            next_allowed_action=(
                "Add CRS parser candidates or offline inputs/protocol*.json; "
                "execution remains blocked."
            ),
        )
    )


def _rebuild_plan(
    plan: ProtocolAwareFuzzingPlan,
    *,
    targets: list[ProtocolTargetPlan] | None = None,
    notes: list[str] | None = None,
    status: str | None = None,
    next_allowed_action: str | None = None,
    human_allow_export_write: bool | None = None,
    export_written: bool | None = None,
    export_count: int | None = None,
    export_root_relative: str | None = None,
) -> ProtocolAwareFuzzingPlan:
    tgt = list(targets) if targets is not None else list(plan.targets)
    return _force_safety_plan(
        ProtocolAwareFuzzingPlan(
            stage=plan.stage,
            inspirations=list(plan.inspirations),
            execution_mode="plan_only",
            status=status if status is not None else plan.status,
            package_id=plan.package_id,
            package_root=plan.package_root,
            targets=tgt,
            target_count=len(tgt),
            parser_source_count=int(plan.parser_source_count or 0),
            offline_hint_count=int(plan.offline_hint_count or 0),
            grammar_plan_count=sum(1 for t in tgt if t.grammar_plan),
            seed_plan_count=sum(len(t.seed_corpus_plan) for t in tgt),
            human_allow_export_write=(
                bool(human_allow_export_write)
                if human_allow_export_write is not None
                else bool(plan.human_allow_export_write)
            ),
            export_written=(
                bool(export_written)
                if export_written is not None
                else bool(plan.export_written)
            ),
            export_count=(
                int(export_count)
                if export_count is not None
                else int(plan.export_count or 0)
            ),
            export_root_relative=(
                export_root_relative
                if export_root_relative is not None
                else plan.export_root_relative
            )
            or "_export/protocol_aware_fuzzing",
            safety_invariants=list(SAFETY_INVARIANTS),
            next_allowed_action=(
                next_allowed_action
                if next_allowed_action is not None
                else plan.next_allowed_action
            ),
            notes=list(notes) if notes is not None else list(plan.notes),
            crs_status=plan.crs_status,
            human_questions=list(plan.human_questions),
            strategy_kinds=list(plan.strategy_kinds),
        )
    )


def _slug(value: str) -> str:
    text = re.sub(r"[^a-zA-Z0-9._-]+", "-", value.strip().lower())
    text = re.sub(r"-{2,}", "-", text).strip("-")
    return (text or "target")[:80]


def _force_safety_plan(plan: ProtocolAwareFuzzingPlan) -> ProtocolAwareFuzzingPlan:
    safe_targets = [
        ProtocolTargetPlan(
            target_symbol=t.target_symbol,
            source_path=t.source_path,
            candidate_type=t.candidate_type,
            language=t.language,
            strategy=t.strategy or "derive_protocol_grammar_before_local_harness",
            grammar_plan=t.grammar_plan,
            message_boundary_plan=t.message_boundary_plan,
            seed_corpus_plan=list(t.seed_corpus_plan),
            harness_linkage_notes=list(t.harness_linkage_notes),
            human_questions=list(t.human_questions),
            status=t.status,
            export_relative_path=t.export_relative_path,
            written=bool(t.written),
            execution_allowed=False,
        )
        for t in plan.targets
    ]
    return ProtocolAwareFuzzingPlan(
        stage=plan.stage,
        inspirations=list(plan.inspirations),
        execution_mode="plan_only",
        status=plan.status,
        package_id=plan.package_id,
        package_root=plan.package_root,
        targets=safe_targets,
        target_count=len(safe_targets),
        parser_source_count=int(plan.parser_source_count or 0),
        offline_hint_count=int(plan.offline_hint_count or 0),
        grammar_plan_count=sum(1 for t in safe_targets if t.grammar_plan),
        seed_plan_count=sum(len(t.seed_corpus_plan) for t in safe_targets),
        network_access=False,
        live_validation=False,
        process_spawn_allowed=False,
        execution_allowed=False,
        validation_allowed=False,
        report_submission_allowed=False,
        confirmed_vulnerability=False,
        finding_promotion_allowed=False,
        crash_promotion_allowed=False,
        human_approval_required_before_run=True,
        human_allow_export_write=bool(plan.human_allow_export_write),
        export_written=bool(plan.export_written),
        export_count=int(plan.export_count or 0),
        export_root_relative=plan.export_root_relative or "_export/protocol_aware_fuzzing",
        safety_invariants=list(SAFETY_INVARIANTS),
        next_allowed_action=plan.next_allowed_action,
        notes=list(plan.notes),
        crs_status=plan.crs_status,
        human_questions=list(plan.human_questions),
        strategy_kinds=list(
            plan.strategy_kinds or ["derive_protocol_grammar_before_local_harness"]
        ),
    )


def _force_safety_dict(payload: dict[str, Any]) -> dict[str, Any]:
    payload = dict(payload)
    payload["execution_mode"] = "plan_only"
    payload["network_access"] = False
    payload["live_validation"] = False
    payload["process_spawn_allowed"] = False
    payload["execution_allowed"] = False
    payload["validation_allowed"] = False
    payload["report_submission_allowed"] = False
    payload["confirmed_vulnerability"] = False
    payload["finding_promotion_allowed"] = False
    payload["crash_promotion_allowed"] = False
    payload["human_approval_required_before_run"] = True
    payload["human_allow_export_write"] = bool(payload.get("human_allow_export_write"))
    payload["export_written"] = bool(payload.get("export_written"))
    payload["export_count"] = int(payload.get("export_count") or 0)
    payload["export_root_relative"] = str(
        payload.get("export_root_relative") or "_export/protocol_aware_fuzzing"
    )
    payload["safety_invariants"] = list(SAFETY_INVARIANTS)
    targets = payload.get("targets")
    if isinstance(targets, list):
        payload["target_count"] = len(targets)
        safe_targets: list[Any] = []
        for item in targets:
            if isinstance(item, dict):
                t = dict(item)
                t["execution_allowed"] = False
                safe_targets.append(t)
            else:
                safe_targets.append(item)
        payload["targets"] = safe_targets
    return payload


__all__ = [
    "STATUS_EMPTY",
    "STATUS_NO_PARSERS",
    "STATUS_READY",
    "STATUS_SKIPPED",
    "STATUS_WRITTEN",
    "ProtocolAwareFuzzingError",
    "ProtocolAwareFuzzingPlan",
    "ProtocolTargetPlan",
    "attach_protocol_aware_fuzzing_to_bridge_result",
    "build_protocol_aware_fuzzing_plan",
    "load_package_protocol_aware_fuzzing_plan",
]