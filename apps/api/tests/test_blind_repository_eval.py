import asyncio
import json
from pathlib import Path

import pytest

from app.cross_source_candidate_generator import CandidateModelConfig
from app.intelligence_benchmark.blind_repository_eval import (
    BlindEvaluationError,
    load_blind_repository_input,
    run_blind_mechanism_eval,
    run_blind_real_model_eval,
    score_blind_prediction,
)
from app.llm.base import LLMMode, LLMResponse, ProviderName
from app.cli import main


ORACLE_CANARY = "oracle-canary-must-never-reach-the-model"
PILOT_CORPUS_ROOT = (
    Path(__file__).parent
    / "fixtures"
    / "candidate_hunter_repository_history_pilot"
)
PILOT_CASE_ROOT = PILOT_CORPUS_ROOT / "cases" / "rhp-a7c9"
PILOT_CASE_IDS = (
    "rhp-0c8a4",
    "rhp-3f6d2",
    "rhp-a7c9",
    "rhp-b94e1",
    "rhp-e27b5",
)


def _write_input_root(root: Path) -> Path:
    input_root = root / "input"
    snapshot = input_root / "vulnerable_snapshot"
    snapshot.mkdir(parents=True)
    (input_root / "policy.md").write_text(
        "# Offline benchmark\n"
        "Analyze only the vulnerable snapshot. Do not access the network or oracle.\n",
        encoding="utf-8",
    )
    (input_root / "scope.yaml").write_text(
        "version: candidate_hunter_offline_scope_v1\n"
        "authorization_basis: public_open_source_historical_snapshot\n"
        "authorized_repository: https://example.invalid/repository\n"
        "authorized_revision: 0123456789abcdef0123456789abcdef01234567\n"
        "network_access_allowed: false\n"
        "live_validation_allowed: false\n"
        "report_submission_allowed: false\n"
        "real_user_data_allowed: false\n",
        encoding="utf-8",
    )
    (snapshot / "index.js").write_text(
        "function parse(path) {\n"
        "  return escape(unescape(path))\n"
        "}\n"
        "module.exports = { parse }\n",
        encoding="utf-8",
    )
    oracle = root / "oracle"
    oracle.mkdir()
    (oracle / "leak-canary.txt").write_text(ORACLE_CANARY, encoding="utf-8")
    return input_root


def _write_oracle(case_root: Path) -> None:
    oracle = case_root / "oracle"
    oracle.mkdir(exist_ok=True)
    (oracle / "expected_root_cause.json").write_text(
        json.dumps(
            {
                "version": "candidate_hunter_historical_gold_v1",
                "case_id": "rhp-test",
                "risk_family": "path_traversal",
                "root_cause_id": (
                    "encoded-dot-segments-decoded-before-safe-path-normalization"
                ),
                "vulnerability_type": "CWE-22",
                "affected_files": ["index.js"],
                "root_cause": (
                    "Percent-encoded dot segments are decoded before safe path "
                    "normalization."
                ),
                "required_evidence": [
                    "Trace percent-encoded path bytes through parsing.",
                ],
            }
        ),
        encoding="utf-8",
    )
    (oracle / "evaluation.json").write_text(
        json.dumps(
            {
                "version": "candidate_hunter_historical_evaluation_v1",
                "case_id": "rhp-test",
                "gold_visibility": "evaluator_only",
                "candidate_limit": 5,
                "expected_disposition": "retain",
                "worth_local_validation": True,
                "network_validation_allowed": False,
                "report_submission_allowed": False,
                "deterministic_grader": {
                    "accepted_vulnerability_families": [
                        "path traversal",
                        "path_traversal",
                        "cwe-22",
                    ],
                    "affected_files_any_of": ["index.js"],
                    "root_cause_term_groups": [
                        ["percent encoded", "percent-encoded", "%2e"],
                        ["dot segment", "dot-segment"],
                        ["decode", "decoded", "unescape"],
                        ["normalize", "normalization"],
                    ],
                },
            }
        ),
        encoding="utf-8",
    )


def _tool_action(
    tool: str,
    *,
    purpose: str,
    arguments: dict,
) -> dict:
    return {
        "schema_version": "blind_repository_research_action_v1",
        "action": "tool",
        "tool": tool,
        "purpose": purpose,
        "hypothesis": (
            "Percent-encoded dot segments may become active path syntax."
        ),
        "arguments": arguments,
    }


def _finish_action(
    *,
    support_ref: str,
    falsification_ref: str,
    vulnerability_family: str = "path traversal",
    affected_file: str = "index.js",
    affected_symbol: str = "parse",
    root_cause_summary: str = (
        "Percent-encoded dot segments are decoded by unescape before "
        "path normalization."
    ),
) -> dict:
    return {
        "schema_version": "blind_repository_research_action_v1",
        "action": "finish",
        "candidates": [
            {
                "disposition": "unverified",
                "vulnerability_family": vulnerability_family,
                "affected_files": [affected_file],
                "affected_symbols": [affected_symbol],
                "root_cause_summary": root_cause_summary,
                "impact_rationale": (
                    "A caller that trusts normalized paths could resolve outside "
                    "the intended directory."
                ),
                "evidence_requirements": [
                    "Confirm the encoded path remains attacker-controlled.",
                ],
                "refutation_questions": [
                    "Does a later layer preserve reserved escapes as data?",
                ],
                "risk_estimate": "high",
                "support_evidence_refs": [support_ref],
                "falsification_evidence_refs": [falsification_ref],
                "strongest_counter_hypothesis": (
                    "A later serializer may preserve encoded dot segments."
                ),
            }
        ],
    }


class _ScriptedRegistry:
    def __init__(
        self,
        *,
        vulnerability_family: str = "path traversal",
        affected_file: str = "index.js",
        affected_symbol: str = "parse",
        root_cause_summary: str | None = None,
    ):
        self.requests = []
        self.vulnerability_family = vulnerability_family
        self.affected_file = affected_file
        self.affected_symbol = affected_symbol
        self.root_cause_summary = root_cause_summary

    async def generate(self, request):
        self.requests.append(request)
        prompt = json.loads(request.prompt)
        serialized_prompt = json.dumps(prompt)
        assert ORACLE_CANARY not in serialized_prompt
        assert "/oracle/" not in serialized_prompt.replace("\\", "/")
        if len(self.requests) == 1:
            payload = _tool_action(
                "read_file_range",
                purpose="support",
                arguments={
                    "source_path": self.affected_file,
                    "start_line": 1,
                    "end_line": 4,
                },
            )
        elif len(self.requests) == 2:
            payload = _tool_action(
                "search_code",
                purpose="falsification",
                arguments={"query": "preserve reserved escapes"},
            )
        else:
            support, falsification = prompt["tool_history"]
            payload = _finish_action(
                support_ref=support["evidence_ref"],
                falsification_ref=falsification["evidence_ref"],
                vulnerability_family=self.vulnerability_family,
                affected_file=self.affected_file,
                affected_symbol=self.affected_symbol,
                **(
                    {"root_cause_summary": self.root_cause_summary}
                    if self.root_cause_summary is not None
                    else {}
                ),
            )
        return LLMResponse(
            provider=request.provider,
            model=request.model,
            text=json.dumps(payload),
            mode=LLMMode.LIVE,
            prompt_hash="0" * 64,
            latency_ms=5,
            error=None,
        )


def _model_config() -> CandidateModelConfig:
    return CandidateModelConfig(
        provider=ProviderName.DEEPSEEK,
        model="test-model",
    )


def test_blind_mechanism_run_never_exposes_oracle_and_seals_prediction(
    tmp_path: Path,
):
    input_root = _write_input_root(tmp_path / "case")
    blind_input = load_blind_repository_input(
        input_root,
        case_id="rhp-test",
        suite="release",
    )
    registry = _ScriptedRegistry()

    envelope = asyncio.run(
        run_blind_mechanism_eval(
            blind_input,
            model_config=_model_config(),
            registry=registry,
        )
    )

    assert envelope["prediction"]["status"] == "completed"
    assert envelope["prediction"]["evidence_kind"] == "mechanism_only"
    assert envelope["prediction"]["oracle_accessed"] is False
    assert envelope["prediction"]["execution_allowed"] is False
    assert envelope["prediction"]["validation_allowed"] is False
    assert envelope["prediction"]["report_submission_allowed"] is False
    assert envelope["prediction_digest"].startswith("sha256:")
    assert ORACLE_CANARY not in json.dumps(envelope)
    assert len(registry.requests) == 3


def test_blind_input_rejects_unsafe_scope(tmp_path: Path):
    input_root = _write_input_root(tmp_path / "case")
    scope_path = input_root / "scope.yaml"
    scope_path.write_text(
        scope_path.read_text(encoding="utf-8").replace(
            "network_access_allowed: false",
            "network_access_allowed: true",
        ),
        encoding="utf-8",
    )

    with pytest.raises(BlindEvaluationError, match="unsafe_scope"):
        load_blind_repository_input(
            input_root,
            case_id="rhp-test",
            suite="release",
        )


def test_blind_input_rejects_symlinked_snapshot_file(tmp_path: Path):
    input_root = _write_input_root(tmp_path / "case")
    external = tmp_path / "external.js"
    external.write_text("module.exports = 'outside'\n", encoding="utf-8")
    linked = input_root / "vulnerable_snapshot" / "linked.js"
    try:
        linked.symlink_to(external)
    except (NotImplementedError, OSError) as exc:
        pytest.skip(f"symlinks unavailable: {exc}")

    with pytest.raises(BlindEvaluationError, match="snapshot_link_not_allowed"):
        load_blind_repository_input(
            input_root,
            case_id="rhp-test",
            suite="release",
        )


def test_blind_run_rejects_confirmation_claims_from_model(tmp_path: Path):
    blind_input = load_blind_repository_input(
        _write_input_root(tmp_path / "case"),
        case_id="rhp-test",
        suite="release",
    )

    envelope = asyncio.run(
        run_blind_mechanism_eval(
            blind_input,
            model_config=_model_config(),
            registry=_ScriptedRegistry(
                root_cause_summary=(
                    "Confirmed exploitable path traversal through decoded dot segments."
                )
            ),
        )
    )

    assert envelope["prediction"]["status"] == "invalid_action"
    assert envelope["prediction"]["candidates"] == []


def test_tampered_prediction_is_rejected_before_oracle_is_read(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    case_root = tmp_path / "case"
    input_root = _write_input_root(case_root)
    _write_oracle(case_root)
    blind_input = load_blind_repository_input(
        input_root,
        case_id="rhp-test",
        suite="release",
    )
    envelope = asyncio.run(
        run_blind_mechanism_eval(
            blind_input,
            model_config=_model_config(),
            registry=_ScriptedRegistry(),
        )
    )
    envelope["prediction"]["case_id"] = "rhp-tampered"
    oracle_read = False

    def fail_if_oracle_is_read(_case_root: Path):
        nonlocal oracle_read
        oracle_read = True
        raise AssertionError("oracle must remain unopened")

    monkeypatch.setattr(
        "app.intelligence_benchmark.blind_repository_eval._read_oracle",
        fail_if_oracle_is_read,
    )

    with pytest.raises(BlindEvaluationError, match="prediction_seal_mismatch"):
        score_blind_prediction(case_root, envelope)

    assert oracle_read is False


def test_scoring_is_deterministic_and_single_case_cannot_claim_benchmark(
    tmp_path: Path,
):
    case_root = tmp_path / "case"
    input_root = _write_input_root(case_root)
    _write_oracle(case_root)
    blind_input = load_blind_repository_input(
        input_root,
        case_id="rhp-test",
        suite="release",
    )
    envelope = asyncio.run(
        run_blind_mechanism_eval(
            blind_input,
            model_config=_model_config(),
            registry=_ScriptedRegistry(),
        )
    )

    first = score_blind_prediction(case_root, envelope)
    second = score_blind_prediction(case_root, envelope)

    assert first == second
    assert first["prediction_seal_verified"] is True
    assert first["oracle_accessed_after_seal"] is True
    assert first["metrics"]["found_at_k"] is True
    assert first["metrics"]["first_match_rank"] == 1
    assert first["metrics"]["root_cause_match"] is True
    assert first["metrics"]["location_match"] is True
    assert first["metrics"]["false_positive_rate"] == 0.0
    assert first["candidate_scores"][0]["rank"] == 1
    assert first["evidence_kind"] == "mechanism_only"
    assert first["pilot_evidence_ready"] is False
    assert first["benchmark_claim_allowed"] is False
    assert first["unknown_vulnerability_claim_allowed"] is False
    assert first["bounty_outcome_claim_allowed"] is False
    assert first["human_review_required"] is True


def test_real_model_wrapper_is_the_only_path_to_real_model_label(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    blind_input = load_blind_repository_input(
        _write_input_root(tmp_path / "case"),
        case_id="rhp-test",
        suite="release",
    )
    registry = _ScriptedRegistry()
    monkeypatch.setattr(
        "app.intelligence_benchmark.blind_repository_eval.build_default_registry",
        lambda: registry,
    )

    envelope = asyncio.run(
        run_blind_real_model_eval(
            blind_input,
            model_config=_model_config(),
        )
    )

    assert envelope["prediction"]["evidence_kind"] == "real_model"
    assert envelope["prediction"]["status"] == "completed"


@pytest.mark.parametrize("case_id", PILOT_CASE_IDS)
def test_each_committed_historical_case_fits_blind_input_without_oracle(
    case_id: str,
):
    case_root = PILOT_CORPUS_ROOT / "cases" / case_id
    blind_input = load_blind_repository_input(
        case_root / "input",
        case_id=case_id,
        suite="release",
    )
    advisory = json.loads(
        (case_root / "oracle" / "advisory.json").read_text(encoding="utf-8")
    )
    canary = (case_root / "oracle" / "leak-canary.txt").read_text(
        encoding="utf-8"
    )
    hunter_material = blind_input.model_dump_json()

    assert 1 <= len(blind_input.source_files) <= 200
    assert len(
        {source.source_path for source in blind_input.source_files}
    ) == len(blind_input.source_files)
    assert canary not in hunter_material
    assert advisory["id"] not in hunter_material
    assert advisory["cve_id"] not in hunter_material
    assert "/oracle/" not in hunter_material.replace("\\", "/")


@pytest.mark.parametrize("case_id", PILOT_CASE_IDS)
def test_each_committed_historical_grader_accepts_its_structured_gold(
    case_id: str,
):
    case_root = PILOT_CORPUS_ROOT / "cases" / case_id
    blind_input = load_blind_repository_input(
        case_root / "input",
        case_id=case_id,
        suite="release",
    )
    gold = json.loads(
        (case_root / "oracle" / "expected_root_cause.json").read_text(
            encoding="utf-8"
        )
    )
    evaluation = json.loads(
        (case_root / "oracle" / "evaluation.json").read_text(encoding="utf-8")
    )
    grader = evaluation["deterministic_grader"]
    registry = _ScriptedRegistry(
        vulnerability_family=grader["accepted_vulnerability_families"][0],
        affected_file=grader["affected_files_any_of"][0],
        affected_symbol=gold["affected_symbols"][0],
        root_cause_summary=" ".join(
            group[0] for group in grader["root_cause_term_groups"]
        ),
    )

    envelope = asyncio.run(
        run_blind_mechanism_eval(
            blind_input,
            model_config=_model_config(),
            registry=registry,
        )
    )
    score = score_blind_prediction(case_root, envelope)

    assert score["metrics"]["found_at_k"] is True
    assert score["metrics"]["first_match_rank"] == 1
    assert score["evidence_kind"] == "mechanism_only"
    assert score["pilot_evidence_ready"] is False
    assert score["benchmark_claim_allowed"] is False


def test_committed_historical_case_runs_blind_then_scores_after_seal():
    blind_input = load_blind_repository_input(
        PILOT_CASE_ROOT / "input",
        case_id="rhp-a7c9",
        suite="release",
    )
    registry = _ScriptedRegistry()

    envelope = asyncio.run(
        run_blind_mechanism_eval(
            blind_input,
            model_config=_model_config(),
            registry=registry,
        )
    )
    actual_canary = (
        PILOT_CASE_ROOT / "oracle" / "leak-canary.txt"
    ).read_text(encoding="utf-8")
    model_material = json.dumps(
        [json.loads(request.prompt) for request in registry.requests]
    )

    assert actual_canary not in model_material
    assert actual_canary not in json.dumps(envelope)
    evaluation = score_blind_prediction(PILOT_CASE_ROOT, envelope)
    assert evaluation["metrics"]["found_at_k"] is True
    assert evaluation["benchmark_claim_allowed"] is False


def test_blind_score_cli_verifies_sealed_prediction(tmp_path: Path):
    case_root = tmp_path / "rhp-test"
    input_root = _write_input_root(case_root)
    _write_oracle(case_root)
    envelope = asyncio.run(
        run_blind_mechanism_eval(
            load_blind_repository_input(
                input_root,
                case_id="rhp-test",
                suite="release",
            ),
            model_config=_model_config(),
            registry=_ScriptedRegistry(),
        )
    )
    prediction_path = tmp_path / "prediction.json"
    output_path = tmp_path / "evaluation-output.json"
    prediction_path.write_text(json.dumps(envelope), encoding="utf-8")

    exit_code = main(
        [
            "candidate-hunter-blind-score",
            "--case-root",
            str(case_root),
            "--prediction",
            str(prediction_path),
            "--output",
            str(output_path),
        ]
    )

    assert exit_code == 0
    result = json.loads(output_path.read_text(encoding="utf-8"))
    assert result["prediction_seal_verified"] is True
    assert result["benchmark_claim_allowed"] is False


def test_blind_run_cli_uses_real_model_wrapper(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    input_root = _write_input_root(tmp_path / "rhp-test")
    output_path = tmp_path / "prediction-output.json"
    calls = []

    async def fake_real_model_run(blind_input, *, model_config):
        calls.append((blind_input, model_config))
        return {
            "prediction": {
                "status": "completed",
                "evidence_kind": "real_model",
            },
            "prediction_digest": "sha256:" + "0" * 64,
        }

    monkeypatch.setattr(
        "app.cli.run_blind_real_model_eval",
        fake_real_model_run,
    )

    exit_code = main(
        [
            "candidate-hunter-blind-run",
            "--input-root",
            str(input_root),
            "--case-id",
            "rhp-test",
            "--suite",
            "release",
            "--provider",
            "deepseek",
            "--model",
            "deepseek-chat",
            "--output",
            str(output_path),
        ]
    )

    assert exit_code == 0
    assert len(calls) == 1
    assert calls[0][1].provider == ProviderName.DEEPSEEK
    assert calls[0][1].model == "deepseek-chat"
    result = json.loads(output_path.read_text(encoding="utf-8"))
    assert result["prediction"]["evidence_kind"] == "real_model"
