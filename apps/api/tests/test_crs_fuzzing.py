from app.crs_fuzzing import build_crs_fuzzing_plan


def test_build_crs_fuzzing_plan_detects_parser_candidate_and_stays_plan_only():
    plan = build_crs_fuzzing_plan(
        [
            {
                "path": "src/parser.py",
                "content": "\n".join(
                    [
                        "import json",
                        "",
                        "def parse_message(raw: bytes):",
                        "    return json.loads(raw.decode())",
                    ]
                ),
            }
        ]
    )

    assert plan.stage == "v1_crs_fuzzing"
    assert plan.inspirations == ["Buttercup", "ATLANTIS", "OSS-Fuzz", "AFL++"]
    assert plan.execution_mode == "plan_only"
    assert plan.parser_candidates[0].symbol_name == "parse_message"
    assert plan.parser_candidates[0].candidate_type == "parser"
    assert plan.harness_plans[0].target_symbol == "parse_message"
    assert plan.harness_plans[0].status == "planned"
    assert plan.fuzzer_plan.status == "not_executed"
    assert plan.fuzzer_plan.execution_allowed is False
    assert plan.crash_triage.status == "schema_only"
    assert plan.crash_promotion_gate.status == "blocked_until_reproducible_local_crash"
    assert plan.crash_promotion_gate.execution_allowed is False
    assert plan.crash_promotion_gate.promotion_allowed is False
    assert plan.crash_promotion_gate.approval_required is True
    assert plan.crash_promotion_gate.required_evidence == [
        "local_reproducible_crash",
        "minimized_input_ref",
        "sanitized_sanitizer_trace",
        "human_review_decision",
    ]
    assert plan.sanitizer_config.enabled == ["ASAN", "UBSAN"]
    assert plan.root_cause.status == "blocked_until_reproducible_crash"
    assert plan.regression_suggestions[0].test_type == "local_regression_test"
    assert "no_public_target_scanning" in plan.safety_invariants
    assert "no_destructive_validation" in plan.safety_invariants


def test_build_crs_fuzzing_plan_detects_decoder_and_validator_candidates():
    plan = build_crs_fuzzing_plan(
        [
            {
                "path": "src/codec.py",
                "content": "\n".join(
                    [
                        "def decode_frame(raw: bytes):",
                        "    return raw.decode()",
                        "",
                        "def validate_frame(frame: str):",
                        "    return frame.startswith('MYTHOS')",
                    ]
                ),
            }
        ]
    )

    candidates = {
        candidate.symbol_name: candidate.candidate_type
        for candidate in plan.parser_candidates
    }

    assert candidates == {
        "decode_frame": "parser",
        "validate_frame": "validator",
    }


def test_build_crs_fuzzing_plan_detects_protocol_handler_candidate_without_execution():
    plan = build_crs_fuzzing_plan(
        [
            {
                "path": "src/protocol.py",
                "content": "\n".join(
                    [
                        "import struct",
                        "",
                        "def handle_frame(raw: bytes):",
                        "    message_type, length = struct.unpack('!BH', raw[:3])",
                        "    return message_type, raw[3:3 + length]",
                    ]
                ),
            }
        ]
    )

    assert plan.parser_candidates[0].symbol_name == "handle_frame"
    assert plan.parser_candidates[0].candidate_type == "protocol_handler"
    assert plan.harness_plans[0].target_symbol == "handle_frame"
    assert plan.fuzzer_plan.status == "not_executed"
    assert plan.fuzzer_plan.execution_allowed is False
    assert plan.fuzzer_plan.command_preview == "not generated until local harness and human approval exist"
    assert "no_network_access" in plan.fuzzer_plan.safety_notes


def test_build_crs_fuzzing_plan_detects_bom_prefixed_parser_candidate():
    plan = build_crs_fuzzing_plan(
        [
            {
                "path": "src/codec.py",
                "content": "\ufeffdef decode_frame(raw: bytes):\n    return raw.decode()\n",
            }
        ]
    )

    assert plan.parser_candidates[0].symbol_name == "decode_frame"
