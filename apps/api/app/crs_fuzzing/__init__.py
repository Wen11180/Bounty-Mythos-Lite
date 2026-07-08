from __future__ import annotations

from dataclasses import asdict, dataclass, field
import re


PARSER_NAME_MARKERS = ("parse", "decode", "deserialize", "load", "read")
VALIDATOR_NAME_MARKERS = ("validate", "verify", "check")
PROTOCOL_MARKERS = ("json.loads", "yaml.safe_load", "pickle.loads", "protobuf", "struct.unpack")
SAFETY_INVARIANTS = [
    "local_or_authorized_artifacts_only",
    "no_public_target_scanning",
    "no_destructive_validation",
    "no_fuzzer_execution_without_human_approval",
    "no_crash_sample_submission",
]


@dataclass(frozen=True)
class ParserCandidate:
    source_path: str
    symbol_name: str
    candidate_type: str
    reason: str


@dataclass(frozen=True)
class HarnessPlan:
    target_symbol: str
    source_path: str
    harness_kind: str
    status: str
    safety_notes: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class FuzzerPlan:
    engine: str
    status: str
    execution_allowed: bool
    command_preview: str
    safety_notes: list[str] = field(default_factory=list)


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

    def to_dict(self) -> dict:
        return asdict(self)


def build_crs_fuzzing_plan(authorized_code_files: list[dict[str, str]]) -> CRSFuzzingPlan:
    candidates = detect_parser_candidates(authorized_code_files)
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
            ],
        )
        for candidate in candidates
    ]
    return CRSFuzzingPlan(
        stage="v1_crs_fuzzing",
        inspirations=["Buttercup", "ATLANTIS", "OSS-Fuzz", "AFL++"],
        execution_mode="plan_only",
        parser_candidates=candidates,
        harness_plans=harness_plans,
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
        regression_suggestions=[
            RegressionSuggestion(
                target_symbol=candidate.symbol_name,
                test_type="local_regression_test",
                suggestion=f"Add a local regression test around {candidate.symbol_name} after a reproducible crash is confirmed.",
            )
            for candidate in candidates
        ],
        safety_invariants=SAFETY_INVARIANTS,
    )


def detect_parser_candidates(authorized_code_files: list[dict[str, str]]) -> list[ParserCandidate]:
    candidates: list[ParserCandidate] = []
    for item in authorized_code_files:
        source_path = item.get("path")
        content = item.get("content")
        if not isinstance(source_path, str) or not isinstance(content, str):
            continue
        content = content.lstrip("\ufeff")
        for function_name in _function_names(content):
            candidate_type = _candidate_type(function_name)
            has_protocol_marker = _body_has_protocol_marker(content, function_name)
            if candidate_type is None and not has_protocol_marker:
                continue
            candidates.append(
                ParserCandidate(
                    source_path=source_path,
                    symbol_name=function_name,
                    candidate_type=candidate_type or "protocol_handler",
                    reason="parser_decoder_validator_candidate",
                )
            )
    return _dedupe_candidates(candidates)


def _function_names(content: str) -> list[str]:
    return [
        match.group(1)
        for match in re.finditer(
            r"^\s*(?:async\s+)?def\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(",
            content,
            flags=re.MULTILINE,
        )
    ]


def _candidate_type(function_name: str) -> str | None:
    lowered = function_name.lower()
    if any(marker in lowered for marker in PARSER_NAME_MARKERS):
        return "parser"
    if any(marker in lowered for marker in VALIDATOR_NAME_MARKERS):
        return "validator"
    return None


def _body_has_protocol_marker(content: str, function_name: str) -> bool:
    marker_index = content.find(f"def {function_name}")
    if marker_index < 0:
        marker_index = content.find(f"async def {function_name}")
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
