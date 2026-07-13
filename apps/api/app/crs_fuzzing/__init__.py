"""CRS / fuzzing planner ? local authorized artifacts only, plan-only.

Final-scheme V1 CRS/Fuzz seed (Buttercup / OSS-Fuzz / AFL++ inspired):
- Detect parser / decoder / validator / protocol-handler candidates
- Emit harness + fuzzer plans that are never auto-executed
- Optional package_root ingest for authorized lab packages
- Crash promotion stays blocked until human-reviewed local evidence
- No process spawn, no network, no public target scanning
"""

from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any


PARSER_NAME_MARKERS = ("parse", "decode", "deserialize", "load", "read", "unmarshal", "fromjson")
VALIDATOR_NAME_MARKERS = ("validate", "verify", "check", "sanitize")
PROTOCOL_MARKERS = (
    "json.loads",
    "yaml.safe_load",
    "pickle.loads",
    "protobuf",
    "struct.unpack",
    "json.parse",
    "json.unmarshal",
    "msgpack",
    "cbor",
    "avro",
    "from_bytes",
    "read_exact",
)

SAFETY_INVARIANTS = [
    "local_or_authorized_artifacts_only",
    "no_public_target_scanning",
    "no_destructive_validation",
    "no_fuzzer_execution_without_human_approval",
    "no_crash_sample_submission",
    "no_network_access",
    "no_process_spawn_by_planner",
    "no_harness_write_without_human_flag",
    "harness_export_local_package_only",
    "no_fuzzer_execution_after_harness_write",
]

STATUS_READY = "crs_fuzzing_plan_ready"
STATUS_EMPTY = "crs_fuzzing_no_candidates"
STATUS_SKIPPED = "crs_fuzzing_package_missing"
STATUS_EMPTY_INPUT = "crs_fuzzing_no_code_files"
STATUS_HARNESS_WRITTEN = "crs_fuzzing_harness_export_written"

ENGINE_CRS_PLAN = "crs_fuzzing_plan"

_MAX_FILES = 200
_MAX_FILE_BYTES = 256_000
_MAX_CONTENT = 64_000
_MAX_CANDIDATES = 50
_CODE_SUFFIXES = {".py", ".pyi", ".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".go", ".java", ".rs"}
_SKIP_DIR_NAMES = {
    ".git",
    ".hg",
    ".svn",
    ".venv",
    "venv",
    "node_modules",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".tox",
    "dist",
    "build",
    "coverage",
    ".idea",
    ".vscode",
    "target",
    "vendor",
    ".mythos",
}


class CRSFuzzingError(ValueError):
    pass


@dataclass(frozen=True)
class ParserCandidate:
    source_path: str
    symbol_name: str
    candidate_type: str
    reason: str
    language: str = ""


@dataclass(frozen=True)
class HarnessPlan:
    target_symbol: str
    source_path: str
    harness_kind: str
    status: str
    safety_notes: list[str] = field(default_factory=list)
    harness_sketch: str = ""
    export_relative_path: str = ""
    written: bool = False


@dataclass(frozen=True)
class FuzzerPlan:
    engine: str
    status: str
    execution_allowed: bool
    command_preview: str
    safety_notes: list[str] = field(default_factory=list)
    seed_corpus_plan: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class CrashTriageSchema:
    status: str
    fields: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class CrashPromotionGate:
    status: str
    execution_allowed: bool
    promotion_allowed: bool
    approval_required: bool
    required_evidence: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class SanitizerConfig:
    enabled: list[str] = field(default_factory=list)
    status: str = "configured_for_future_local_runs"


@dataclass(frozen=True)
class RootCausePlaceholder:
    status: str
    required_inputs: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class RegressionSuggestion:
    target_symbol: str
    test_type: str
    suggestion: str


@dataclass(frozen=True)
class CRSFuzzingPlan:
    stage: str
    inspirations: list[str]
    execution_mode: str
    parser_candidates: list[ParserCandidate]
    harness_plans: list[HarnessPlan]
    fuzzer_plan: FuzzerPlan
    crash_triage: CrashTriageSchema
    crash_promotion_gate: CrashPromotionGate
    sanitizer_config: SanitizerConfig
    root_cause: RootCausePlaceholder
    regression_suggestions: list[RegressionSuggestion]
    safety_invariants: list[str]
    status: str = STATUS_READY
    package_id: str = ""
    package_root: str = ""
    scanned_file_count: int = 0
    candidate_count: int = 0
    harness_count: int = 0
    network_access: bool = False
    live_validation: bool = False
    execution_allowed: bool = False
    validation_allowed: bool = False
    report_submission_allowed: bool = False
    confirmed_vulnerability: bool = False
    finding_promotion_allowed: bool = False
    human_approval_required_before_run: bool = True
    human_allow_harness_write: bool = False
    harness_export_written: bool = False
    harness_export_count: int = 0
    harness_export_root_relative: str = "_export/crs_harness"
    next_allowed_action: str = (
        "Review harness plans locally; never execute fuzzers without explicit human approval."
    )
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        return _force_safety_dict(payload)


def build_crs_fuzzing_plan(
    authorized_code_files: list[dict[str, str]] | None = None,
    *,
    package_root: str | Path | None = None,
    package_id: str = "",
    human_allow_harness_write: bool = False,
) -> CRSFuzzingPlan:
    notes: list[str] = ["plan_only", "no_fuzzer_execution", "offline_package_artifacts_only"]
    files = list(authorized_code_files or [])
    root: Path | None = None
    if package_root is not None and str(package_root).strip():
        root = Path(package_root).resolve()
        if root.is_dir():
            if not files:
                files = collect_authorized_code_files(root)
                notes.append("code_files_from_package_root")
        else:
            notes.append("package_root_missing")

    resolved_id = package_id
    if not resolved_id and root is not None:
        resolved_id = _read_package_id(root) or root.name

    if root is not None and not root.is_dir() and not files:
        plan = _empty_plan(
            status=STATUS_SKIPPED,
            package_id=resolved_id,
            package_root=str(root or ""),
            notes=notes + ["package_root_missing"],
            next_action="Provide authorized package_root under local workspace.",
        )
        return plan

    if not files:
        plan = _empty_plan(
            status=STATUS_EMPTY_INPUT,
            package_id=resolved_id,
            package_root=str(root or ""),
            notes=notes + ["no_authorized_code_files"],
            next_action="Add authorized local code under package inputs/ or pass code files.",
        )
        return plan

    candidates = detect_parser_candidates(files)[:_MAX_CANDIDATES]
    harness_plans = [
        HarnessPlan(
            target_symbol=candidate.symbol_name,
            source_path=candidate.source_path,
            harness_kind="local_unit_harness",
            status="planned",
            safety_notes=[
                "generate_harness_only",
                "requires_human_approval_before_execution",
                "local_inputs_only",
                "no_network_in_harness",
            ],
            harness_sketch=_harness_sketch(candidate),
        )
        for candidate in candidates
    ]

    seed_corpus = [
        f"local seed corpus placeholder for {c.symbol_name} @ {c.source_path}"
        for c in candidates[:10]
    ]
    if candidates:
        command_preview = (
            "# PLAN ONLY ? do not run without human approval and local sandbox\n"
            f"# targets={len(candidates)} harnesses={len(harness_plans)}\n"
            "# example: afl-fuzz -i seeds -o findings -- ./harness @@\n"
            "# example: cargo +nightly fuzz run <target>  # still requires human approval\n"
            "execution_allowed=false"
        )
        status = STATUS_READY
        next_action = (
            "Human reviews harness sketches and seed plan; execution stays blocked "
            "until explicit approval and local-only sandbox."
        )
    else:
        command_preview = "not generated: no parser/decoder candidates detected"
        status = STATUS_EMPTY
        next_action = (
            "No CRS candidates in scanned files; keep static A+B path and residual review."
        )
        notes.append("no_parser_candidates")

    plan = CRSFuzzingPlan(
        stage="v1_crs_fuzzing_package_ingest",
        inspirations=["Buttercup", "ATLANTIS", "OSS-Fuzz", "AFL++"],
        execution_mode="plan_only",
        parser_candidates=candidates,
        harness_plans=harness_plans,
        fuzzer_plan=FuzzerPlan(
            engine="AFL++/libFuzzer/Jazzer candidate",
            status="not_executed",
            execution_allowed=False,
            command_preview=command_preview,
            safety_notes=[
                "no_process_spawn",
                "no_network_access",
                "no_destructive_validation",
                "human_approval_required",
            ],
            seed_corpus_plan=seed_corpus,
        ),
        crash_triage=CrashTriageSchema(
            status="schema_only",
            fields=[
                "crash_id",
                "target",
                "sanitizer",
                "crash_type",
                "reproducible",
                "minimized_input_ref",
                "needs_root_cause",
            ],
        ),
        crash_promotion_gate=CrashPromotionGate(
            status="blocked_until_reproducible_local_crash",
            execution_allowed=False,
            promotion_allowed=False,
            approval_required=True,
            required_evidence=[
                "local_reproducible_crash",
                "minimized_input_ref",
                "sanitized_sanitizer_trace",
                "human_review_decision",
            ],
        ),
        sanitizer_config=SanitizerConfig(enabled=["ASAN", "UBSAN"]),
        root_cause=RootCausePlaceholder(
            status="blocked_until_reproducible_crash",
            required_inputs=[
                "reproducible_crash",
                "minimized_input_ref",
                "sanitizer_trace",
                "local_source_context",
            ],
        ),
        regression_suggestions=[
            RegressionSuggestion(
                target_symbol=candidate.symbol_name,
                test_type="local_regression_test",
                suggestion=(
                    f"Add a local regression test around {candidate.symbol_name} "
                    "after a reproducible crash is confirmed."
                ),
            )
            for candidate in candidates
        ],
        safety_invariants=list(SAFETY_INVARIANTS),
        status=status,
        package_id=resolved_id,
        package_root=str(root or ""),
        scanned_file_count=len(files),
        candidate_count=len(candidates),
        harness_count=len(harness_plans),
        human_allow_harness_write=bool(human_allow_harness_write),
        harness_export_written=False,
        harness_export_count=0,
        notes=notes,
        next_allowed_action=next_action,
    )
    plan = _maybe_write_harness_exports(
        plan,
        root=root,
        human_allow_harness_write=bool(human_allow_harness_write),
    )
    return _force_safety_plan(plan)


def detect_parser_candidates(authorized_code_files: list[dict[str, str]]) -> list[ParserCandidate]:
    candidates: list[ParserCandidate] = []
    for item in authorized_code_files:
        source_path = item.get("path")
        content = item.get("content")
        if not isinstance(source_path, str) or not isinstance(content, str):
            continue
        content = content.lstrip("\ufeff")
        language = _language_for_path(source_path)
        for function_name in _function_names(content, language=language):
            candidate_type = _candidate_type(function_name)
            has_protocol_marker = _body_has_protocol_marker(
                content, function_name, language=language
            )
            if candidate_type is None and not has_protocol_marker:
                continue
            candidates.append(
                ParserCandidate(
                    source_path=source_path,
                    symbol_name=function_name,
                    candidate_type=candidate_type or "protocol_handler",
                    reason="parser_decoder_validator_candidate",
                    language=language,
                )
            )
    return _dedupe_candidates(candidates)


def collect_authorized_code_files(package_root: str | Path) -> list[dict[str, str]]:
    root = Path(package_root).resolve()
    if not root.is_dir():
        return []
    files: list[dict[str, str]] = []
    preferred = [
        root / "inputs",
        root / "_extract",
        root / "src",
        root / "app",
        root / "backend",
        root / "_upstream",
    ]
    scan_roots = [p for p in preferred if p.is_dir()]
    if not scan_roots:
        scan_roots = [root]

    for scan_root in scan_roots:
        for path in _iter_code_files(scan_root, package_root=root):
            if len(files) >= _MAX_FILES:
                break
            text = _safe_read_text(path)
            if text is None:
                continue
            try:
                rel = str(path.resolve().relative_to(root)).replace("\\", "/")
            except ValueError:
                continue
            files.append({"path": rel, "content": text})
        if len(files) >= _MAX_FILES:
            break
    return files


def load_package_crs_fuzzing_plan(
    package_root: str | Path | None,
    *,
    package_id: str = "",
    authorized_code_files: list[dict[str, str]] | None = None,
) -> dict[str, Any]:
    return build_crs_fuzzing_plan(
        authorized_code_files,
        package_root=package_root,
        package_id=package_id,
    ).to_dict()


def attach_crs_fuzzing_to_bridge_result(
    bridge_result: dict[str, Any],
    *,
    package_root: str | Path | None = None,
    authorized_code_files: list[dict[str, str]] | None = None,
    crs_fuzzing: dict[str, Any] | CRSFuzzingPlan | None = None,
    human_allow_harness_write: bool = False,
) -> dict[str, Any]:
    """Attach plan-only CRS/fuzz profile; never unlocks execute/submit."""
    if not isinstance(bridge_result, dict):
        raise CRSFuzzingError("bridge_result_must_be_object")

    package_id = str(bridge_result.get("package_id") or "")
    resolved_root = package_root or bridge_result.get("package_root")

    if isinstance(crs_fuzzing, CRSFuzzingPlan):
        payload = crs_fuzzing.to_dict()
    elif isinstance(crs_fuzzing, dict):
        payload = _force_safety_dict(dict(crs_fuzzing))
    else:
        payload = build_crs_fuzzing_plan(
            authorized_code_files,
            package_root=resolved_root,
            package_id=package_id,
            human_allow_harness_write=bool(human_allow_harness_write),
        ).to_dict()

    if not payload.get("package_id") and package_id:
        payload["package_id"] = package_id
    payload = _force_safety_dict(payload)

    out = dict(bridge_result)
    out["crs_fuzzing"] = payload
    out["crs_fuzzing_present"] = True
    out["crs_fuzzing_status"] = str(payload.get("status") or STATUS_EMPTY)
    out["crs_fuzzing_candidate_count"] = int(payload.get("candidate_count") or 0)
    out["crs_fuzzing_harness_count"] = int(payload.get("harness_count") or 0)
    out["crs_fuzzing_harness_export_written"] = bool(payload.get("harness_export_written"))
    out["crs_fuzzing_harness_export_count"] = int(payload.get("harness_export_count") or 0)
    out["crs_fuzzing_execution_allowed"] = False
    out["execution_allowed"] = False
    out["validation_allowed"] = False
    out["report_submission_allowed"] = False
    out["confirmed_vulnerability"] = False
    if out.get("submission_blocked") is not True:
        out["submission_blocked"] = True
    return out


def _empty_plan(
    *,
    status: str,
    package_id: str,
    package_root: str,
    notes: list[str],
    next_action: str,
) -> CRSFuzzingPlan:
    plan = CRSFuzzingPlan(
        stage="v1_crs_fuzzing_package_ingest",
        inspirations=["Buttercup", "ATLANTIS", "OSS-Fuzz", "AFL++"],
        execution_mode="plan_only",
        parser_candidates=[],
        harness_plans=[],
        fuzzer_plan=FuzzerPlan(
            engine="AFL++/libFuzzer/Jazzer candidate",
            status="not_executed",
            execution_allowed=False,
            command_preview="not generated until local harness and human approval exist",
            safety_notes=[
                "no_process_spawn",
                "no_network_access",
                "no_destructive_validation",
            ],
        ),
        crash_triage=CrashTriageSchema(
            status="schema_only",
            fields=[
                "crash_id",
                "target",
                "sanitizer",
                "crash_type",
                "reproducible",
                "minimized_input_ref",
                "needs_root_cause",
            ],
        ),
        crash_promotion_gate=CrashPromotionGate(
            status="blocked_until_reproducible_local_crash",
            execution_allowed=False,
            promotion_allowed=False,
            approval_required=True,
            required_evidence=[
                "local_reproducible_crash",
                "minimized_input_ref",
                "sanitized_sanitizer_trace",
                "human_review_decision",
            ],
        ),
        sanitizer_config=SanitizerConfig(enabled=["ASAN", "UBSAN"]),
        root_cause=RootCausePlaceholder(
            status="blocked_until_reproducible_crash",
            required_inputs=[
                "reproducible_crash",
                "minimized_input_ref",
                "sanitizer_trace",
                "local_source_context",
            ],
        ),
        regression_suggestions=[],
        safety_invariants=list(SAFETY_INVARIANTS),
        status=status,
        package_id=package_id,
        package_root=package_root,
        notes=list(notes),
        next_allowed_action=next_action,
    )
    return _force_safety_plan(plan)



def _maybe_write_harness_exports(
    plan: CRSFuzzingPlan,
    *,
    root: Path | None,
    human_allow_harness_write: bool,
) -> CRSFuzzingPlan:
    """Optional local harness sketch export under package _export/crs_harness/.

    Write-only handoff. Never executes fuzzers, never promotes crashes, never opens network.
    """
    notes = list(plan.notes)
    if not human_allow_harness_write:
        notes.append("harness_write_not_requested")
        return _rebuild_plan(plan, notes=notes)

    if root is None or not root.is_dir():
        notes.append("harness_write_requested_but_package_root_missing")
        return _rebuild_plan(plan, notes=notes, human_allow_harness_write=True)

    if not plan.harness_plans:
        notes.append("harness_write_requested_but_no_harness_plans")
        return _rebuild_plan(plan, notes=notes, human_allow_harness_write=True)

    written_plans, export_count, any_written = _write_harness_export_files(
        root=root,
        harness_plans=list(plan.harness_plans),
        package_id=plan.package_id or root.name,
    )
    notes.append("local_harness_export_write_attempted")
    status = plan.status
    next_action = plan.next_allowed_action
    if any_written:
        notes.append("local_harness_export_written")
        status = STATUS_HARNESS_WRITTEN
        next_action = (
            "Review exported harness sketches under package _export/crs_harness/; "
            "execution remains blocked until explicit human approval and local sandbox."
        )
    else:
        notes.append("local_harness_export_write_produced_no_files")

    return _rebuild_plan(
        plan,
        harness_plans=written_plans,
        notes=notes,
        status=status,
        next_allowed_action=next_action,
        human_allow_harness_write=True,
        harness_export_written=bool(any_written),
        harness_export_count=int(export_count),
        harness_export_root_relative="_export/crs_harness",
    )


def _write_harness_export_files(
    *,
    root: Path,
    harness_plans: list[HarnessPlan],
    package_id: str,
) -> tuple[list[HarnessPlan], int, bool]:
    export_root = (root / "_export" / "crs_harness").resolve()
    try:
        export_root.relative_to(root.resolve())
    except ValueError:
        return harness_plans, 0, False

    export_root.mkdir(parents=True, exist_ok=True)
    written_plans: list[HarnessPlan] = []
    export_count = 0
    any_written = False

    for index, harness in enumerate(harness_plans, start=1):
        slug = _slug(f"{index:02d}-{harness.target_symbol or 'target'}")
        target_dir = export_root / slug
        rel_dir = f"_export/crs_harness/{slug}"
        sketch = harness.harness_sketch or (
            f"# plan-only harness sketch for {harness.target_symbol}\n"
            f"# source: {harness.source_path}\n"
        )
        readme = _render_harness_readme(harness, package_id=package_id, export_dir=rel_dir)
        meta = {
            "package_id": package_id,
            "target_symbol": harness.target_symbol,
            "source_path": harness.source_path,
            "harness_kind": harness.harness_kind,
            "status": "exported_sketch_only",
            "execution_allowed": False,
            "export_relative_path": rel_dir,
            "safety": [
                "plan_only",
                "no_fuzzer_execution",
                "no_network",
                "no_crash_promotion",
                "human_approval_required_before_run",
            ],
        }
        seeds_readme = (
            "# Seed corpus placeholder\n\n"
            "Local-only seeds for a future human-approved fuzzer run.\n"
            "Do not point at production data or network sources.\n"
            "execution_allowed=false\n"
        )

        files = {
            "harness_sketch.txt": sketch if sketch.endswith("\n") else sketch + "\n",
            "README.md": readme if readme.endswith("\n") else readme + "\n",
            "meta.json": json.dumps(meta, ensure_ascii=False, indent=2) + "\n",
            "seeds/README.md": seeds_readme,
        }
        ok = True
        try:
            target_dir.mkdir(parents=True, exist_ok=True)
            (target_dir / "seeds").mkdir(parents=True, exist_ok=True)
            for rel_name, content in files.items():
                out_path = target_dir / rel_name
                out_path.parent.mkdir(parents=True, exist_ok=True)
                out_path.write_text(content, encoding="utf-8", newline="\n")
        except OSError:
            ok = False

        if ok:
            export_count += 1
            any_written = True
            written_plans.append(
                HarnessPlan(
                    target_symbol=harness.target_symbol,
                    source_path=harness.source_path,
                    harness_kind=harness.harness_kind,
                    status="exported_sketch_only",
                    safety_notes=list(harness.safety_notes)
                    + ["local_export_only", "no_execution_from_export"],
                    harness_sketch=sketch,
                    export_relative_path=rel_dir,
                    written=True,
                )
            )
        else:
            written_plans.append(
                HarnessPlan(
                    target_symbol=harness.target_symbol,
                    source_path=harness.source_path,
                    harness_kind=harness.harness_kind,
                    status=harness.status,
                    safety_notes=list(harness.safety_notes),
                    harness_sketch=harness.harness_sketch,
                    export_relative_path="",
                    written=False,
                )
            )

    return written_plans, export_count, any_written


def _render_harness_readme(
    harness: HarnessPlan,
    *,
    package_id: str,
    export_dir: str,
) -> str:
    return "\n".join(
        [
            f"# CRS harness export — {harness.target_symbol}",
            "",
            f"- package_id: `{package_id}`",
            f"- source_path: `{harness.source_path}`",
            f"- harness_kind: `{harness.harness_kind}`",
            f"- export_dir: `{export_dir}`",
            f"- status: exported sketch only (not executed)",
            "",
            "## Safety",
            "",
            "- execution_allowed=false",
            "- no process spawn by Mythos",
            "- no network",
            "- no crash promotion / report submission",
            "- human must approve any future local sandbox run outside this planner",
            "",
            "## Contents",
            "",
            "- `harness_sketch.txt` — advisory sketch only",
            "- `meta.json` — non-secret metadata",
            "- `seeds/README.md` — seed corpus placeholder",
            "",
            "Do not treat this export as a confirmed vulnerability or runnable exploit.",
            "",
        ]
    )


def _slug(value: str) -> str:
    text = re.sub(r"[^a-zA-Z0-9._-]+", "-", value.strip().lower())
    text = re.sub(r"-{2,}", "-", text).strip("-")
    return (text or "target")[:80]


def _rebuild_plan(
    plan: CRSFuzzingPlan,
    *,
    harness_plans: list[HarnessPlan] | None = None,
    notes: list[str] | None = None,
    status: str | None = None,
    next_allowed_action: str | None = None,
    human_allow_harness_write: bool | None = None,
    harness_export_written: bool | None = None,
    harness_export_count: int | None = None,
    harness_export_root_relative: str | None = None,
) -> CRSFuzzingPlan:
    plans = list(harness_plans) if harness_plans is not None else list(plan.harness_plans)
    return CRSFuzzingPlan(
        stage=plan.stage,
        inspirations=list(plan.inspirations),
        execution_mode="plan_only",
        parser_candidates=list(plan.parser_candidates),
        harness_plans=plans,
        fuzzer_plan=plan.fuzzer_plan,
        crash_triage=plan.crash_triage,
        crash_promotion_gate=plan.crash_promotion_gate,
        sanitizer_config=plan.sanitizer_config,
        root_cause=plan.root_cause,
        regression_suggestions=list(plan.regression_suggestions),
        safety_invariants=list(SAFETY_INVARIANTS),
        status=status if status is not None else plan.status,
        package_id=plan.package_id,
        package_root=plan.package_root,
        scanned_file_count=plan.scanned_file_count,
        candidate_count=plan.candidate_count,
        harness_count=len(plans),
        network_access=False,
        live_validation=False,
        execution_allowed=False,
        validation_allowed=False,
        report_submission_allowed=False,
        confirmed_vulnerability=False,
        finding_promotion_allowed=False,
        human_approval_required_before_run=True,
        human_allow_harness_write=(
            bool(human_allow_harness_write)
            if human_allow_harness_write is not None
            else bool(plan.human_allow_harness_write)
        ),
        harness_export_written=(
            bool(harness_export_written)
            if harness_export_written is not None
            else bool(plan.harness_export_written)
        ),
        harness_export_count=(
            int(harness_export_count)
            if harness_export_count is not None
            else int(plan.harness_export_count or 0)
        ),
        harness_export_root_relative=(
            harness_export_root_relative
            if harness_export_root_relative is not None
            else (plan.harness_export_root_relative or "_export/crs_harness")
        ),
        next_allowed_action=(
            next_allowed_action
            if next_allowed_action is not None
            else plan.next_allowed_action
        ),
        notes=list(notes) if notes is not None else list(plan.notes),
    )


def _harness_sketch(candidate: ParserCandidate) -> str:
    return (
        f"# plan-only harness sketch for {candidate.symbol_name}\n"
        f"# source: {candidate.source_path}\n"
        f"# type: {candidate.candidate_type}\n"
        f"# language: {candidate.language or 'unknown'}\n"
        "# 1) compile/import target under local sandbox only\n"
        "# 2) feed bytes from local seed corpus (no network)\n"
        "# 3) capture crashes with ASAN/UBSAN if applicable\n"
        "# 4) stop; never promote crash without human review\n"
        "execution_allowed=false\n"
    )


def _function_names(content: str, *, language: str = "") -> list[str]:
    names: list[str] = []
    patterns = [
        r"^\s*(?:async\s+)?def\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(",
        r"^\s*(?:export\s+)?(?:async\s+)?function\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(",
        r"^\s*(?:export\s+)?(?:const|let|var)\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?:async\s*)?\(",
        r"^\s*(?:export\s+)?(?:const|let|var)\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?:async\s+)?function\b",
        r"^\s*func\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(",
        r"^\s*(?:public|private|protected|static|final|synchronized|\s)*"
        r"(?:[\w.<>,\[\]]+\s+)+([A-Za-z_][A-Za-z0-9_]*)\s*\([^;]*\)\s*\{",
        r"^\s*(?:pub\s+)?(?:async\s+)?fn\s+([A-Za-z_][A-Za-z0-9_]*)\s*[<(]",
    ]
    # language-biased first pass is still multi-pattern for mixed snippets
    for pattern in patterns:
        for match in re.finditer(pattern, content, flags=re.MULTILINE):
            name = match.group(1)
            if name and name not in {"if", "for", "while", "switch", "catch", "return"}:
                names.append(name)
    # de-dupe preserve order
    seen: set[str] = set()
    out: list[str] = []
    for name in names:
        if name in seen:
            continue
        seen.add(name)
        out.append(name)
    return out


def _candidate_type(function_name: str) -> str | None:
    lowered = function_name.lower()
    if any(marker in lowered for marker in PARSER_NAME_MARKERS):
        return "parser"
    if any(marker in lowered for marker in VALIDATOR_NAME_MARKERS):
        return "validator"
    return None


def _body_has_protocol_marker(
    content: str, function_name: str, *, language: str = ""
) -> bool:
    markers = [
        f"def {function_name}",
        f"async def {function_name}",
        f"function {function_name}",
        f"async function {function_name}",
        f"func {function_name}",
        f"fn {function_name}",
        f"{function_name} =",
        f"{function_name}(",
    ]
    marker_index = -1
    for marker in markers:
        marker_index = content.find(marker)
        if marker_index >= 0:
            break
    if marker_index < 0:
        return False
    body = content[marker_index : marker_index + 1200].lower()
    return any(marker in body for marker in PROTOCOL_MARKERS)


def _dedupe_candidates(candidates: list[ParserCandidate]) -> list[ParserCandidate]:
    seen: set[tuple[str, str]] = set()
    deduped: list[ParserCandidate] = []
    for candidate in candidates:
        key = (candidate.source_path, candidate.symbol_name)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(candidate)
    return deduped


def _language_for_path(path: str) -> str:
    suffix = Path(path).suffix.lower()
    return {
        ".py": "python",
        ".pyi": "python",
        ".ts": "typescript",
        ".tsx": "typescript",
        ".js": "javascript",
        ".jsx": "javascript",
        ".mjs": "javascript",
        ".cjs": "javascript",
        ".go": "go",
        ".java": "java",
        ".rs": "rust",
    }.get(suffix, "unknown")


def _iter_code_files(scan_root: Path, *, package_root: Path) -> list[Path]:
    files: list[Path] = []
    if scan_root.is_file():
        return [scan_root] if scan_root.suffix.lower() in _CODE_SUFFIXES else []

    stack = [scan_root]
    while stack and len(files) < _MAX_FILES:
        current = stack.pop()
        try:
            entries = sorted(current.iterdir(), key=lambda p: p.name.lower())
        except OSError:
            continue
        for entry in entries:
            if len(files) >= _MAX_FILES:
                break
            if entry.is_dir():
                if entry.name in _SKIP_DIR_NAMES or entry.name.startswith("."):
                    continue
                try:
                    entry.resolve().relative_to(package_root.resolve())
                except ValueError:
                    continue
                stack.append(entry)
            elif entry.is_file():
                if entry.suffix.lower() not in _CODE_SUFFIXES:
                    continue
                try:
                    if entry.stat().st_size > _MAX_FILE_BYTES:
                        continue
                    entry.resolve().relative_to(package_root.resolve())
                except (OSError, ValueError):
                    continue
                files.append(entry)
    return files


def _safe_read_text(path: Path) -> str | None:
    try:
        if path.stat().st_size > _MAX_FILE_BYTES:
            return None
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    if len(text) > _MAX_CONTENT:
        text = text[:_MAX_CONTENT]
    return text


def _read_package_id(root: Path) -> str:
    for name in ("package.json", "gold.json", "STATUS.md"):
        path = root / name
        if not path.is_file():
            continue
        try:
            if name.endswith(".json"):
                data = json.loads(path.read_text(encoding="utf-8"))
                if isinstance(data, dict):
                    for key in ("package_id", "id", "name"):
                        if data.get(key):
                            return str(data[key])
        except Exception:
            continue
    return root.name


def _force_safety_plan(plan: CRSFuzzingPlan) -> CRSFuzzingPlan:
    # dataclasses are frozen; rebuild with forced safety via object.__setattr__ not allowed.
    # Convert via to_dict path is cleaner for attach; for plan object mutate by replace.
    return CRSFuzzingPlan(
        stage=plan.stage,
        inspirations=list(plan.inspirations),
        execution_mode="plan_only",
        parser_candidates=list(plan.parser_candidates),
        harness_plans=list(plan.harness_plans),
        fuzzer_plan=FuzzerPlan(
            engine=plan.fuzzer_plan.engine,
            status="not_executed",
            execution_allowed=False,
            command_preview=plan.fuzzer_plan.command_preview,
            safety_notes=list(plan.fuzzer_plan.safety_notes),
            seed_corpus_plan=list(plan.fuzzer_plan.seed_corpus_plan),
        ),
        crash_triage=plan.crash_triage,
        crash_promotion_gate=CrashPromotionGate(
            status=plan.crash_promotion_gate.status,
            execution_allowed=False,
            promotion_allowed=False,
            approval_required=True,
            required_evidence=list(plan.crash_promotion_gate.required_evidence),
        ),
        sanitizer_config=plan.sanitizer_config,
        root_cause=plan.root_cause,
        regression_suggestions=list(plan.regression_suggestions),
        safety_invariants=list(SAFETY_INVARIANTS),
        status=plan.status,
        package_id=plan.package_id,
        package_root=plan.package_root,
        scanned_file_count=plan.scanned_file_count,
        candidate_count=plan.candidate_count,
        harness_count=plan.harness_count,
        network_access=False,
        live_validation=False,
        execution_allowed=False,
        validation_allowed=False,
        report_submission_allowed=False,
        confirmed_vulnerability=False,
        finding_promotion_allowed=False,
        human_approval_required_before_run=True,
        human_allow_harness_write=bool(plan.human_allow_harness_write),
        harness_export_written=bool(plan.harness_export_written),
        harness_export_count=int(plan.harness_export_count or 0),
        harness_export_root_relative=plan.harness_export_root_relative or "_export/crs_harness",
        next_allowed_action=plan.next_allowed_action,
        notes=list(plan.notes),
    )


def _force_safety_dict(payload: dict[str, Any]) -> dict[str, Any]:
    payload = dict(payload)
    payload["execution_mode"] = "plan_only"
    payload["execution_allowed"] = False
    payload["validation_allowed"] = False
    payload["report_submission_allowed"] = False
    payload["confirmed_vulnerability"] = False
    payload["finding_promotion_allowed"] = False
    payload["network_access"] = False
    payload["live_validation"] = False
    payload["human_approval_required_before_run"] = True
    payload["human_allow_harness_write"] = bool(payload.get("human_allow_harness_write"))
    payload["harness_export_written"] = bool(payload.get("harness_export_written"))
    payload["harness_export_count"] = int(payload.get("harness_export_count") or 0)
    payload["harness_export_root_relative"] = str(
        payload.get("harness_export_root_relative") or "_export/crs_harness"
    )
    fuzzer = payload.get("fuzzer_plan")
    if isinstance(fuzzer, dict):
        fuzzer = dict(fuzzer)
        fuzzer["execution_allowed"] = False
        fuzzer["status"] = "not_executed"
        payload["fuzzer_plan"] = fuzzer
    gate = payload.get("crash_promotion_gate")
    if isinstance(gate, dict):
        gate = dict(gate)
        gate["execution_allowed"] = False
        gate["promotion_allowed"] = False
        gate["approval_required"] = True
        payload["crash_promotion_gate"] = gate
    return payload


__all__ = [
    "ENGINE_CRS_PLAN",
    "STATUS_EMPTY",
    "STATUS_EMPTY_INPUT",
    "STATUS_HARNESS_WRITTEN",
    "STATUS_READY",
    "STATUS_SKIPPED",
    "CRSFuzzingError",
    "CRSFuzzingPlan",
    "CrashPromotionGate",
    "CrashTriageSchema",
    "FuzzerPlan",
    "HarnessPlan",
    "ParserCandidate",
    "RegressionSuggestion",
    "RootCausePlaceholder",
    "SanitizerConfig",
    "attach_crs_fuzzing_to_bridge_result",
    "build_crs_fuzzing_plan",
    "collect_authorized_code_files",
    "detect_parser_candidates",
    "load_package_crs_fuzzing_plan",
]
