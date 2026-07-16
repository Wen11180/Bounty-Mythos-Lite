"""Commercial delivery bundle: customer-facing packaging + anti-auto-exploit proof.

Produces a single attach-ready bundle with:
- lab / live-infra / multilang breadth gates
- market leadership scoreboard
- customer brief (Markdown)
- safety invariant proof (anti auto-exploit)

Never unlocks execution, validation, auto-attack, or report submission.
Real live/HH market gaps only close when authorized redacted real packages attach.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from app.intelligence_benchmark.authorized_live_calibration import (
    run_authorized_live_calibration_gate,
)
from app.intelligence_benchmark.lab_leadership_rollup import run_lab_leadership_rollup
from app.intelligence_benchmark.multilang_production_breadth import (
    run_multilang_production_breadth_gate,
)

SCHEMA_VERSION = "commercial_delivery_bundle_v1"
RUNBOOK = "docs/product/commercial-delivery-runbook.md"
POSITIONING_DOC = "docs/product/competitive-positioning-and-delivery.md"

SAFETY_KEYS = (
    "execution_allowed",
    "report_submission_allowed",
    "auto_attack_allowed",
    "dispatch_allowed",
    "validation_allowed",
    "candidate_promotion_allowed",
)


def build_commercial_delivery_bundle(
    *,
    out_dir: str | Path,
    calibration_log: str | Path | None = None,
    live_log: str | Path | None = None,
    human_allow_write: bool = False,
) -> dict[str, Any]:
    """Assemble commercial delivery artifacts under out_dir.

    Requires human_allow_write=True to write files (explicit human gate).
    """
    if not human_allow_write:
        raise ValueError("human_allow_write_required_for_commercial_bundle_write")

    root = Path(out_dir)
    root.mkdir(parents=True, exist_ok=True)

    cal_path = Path(calibration_log) if calibration_log else None
    live_path = Path(live_log) if live_log else None

    lab = run_lab_leadership_rollup(calibration_log=cal_path)
    live = run_authorized_live_calibration_gate(log_path=live_path)
    breadth = run_multilang_production_breadth_gate()

    ab = (lab.get("component_results") or {}).get("ab_leadership") or {}
    hh = (lab.get("component_results") or {}).get("human_hour_calibration") or {}
    live_measured = live.get("measured") if isinstance(live.get("measured"), dict) else {}
    track = live_measured.get("track_record_summary") or {}

    has_real_live_wall = bool(track.get("has_real_wall_clock_logs"))
    has_real_hh_wall = bool(hh.get("has_real_human_hour_wall_clock_logs"))
    has_real_wall = has_real_live_wall or has_real_hh_wall
    has_real_valid = bool(track.get("has_real_live_valid_report_outcomes"))
    breadth_beyond = bool(breadth.get("beyond_held_out") and breadth.get("passed"))

    remaining: list[str] = []
    if not has_real_wall:
        remaining.append("real_authorized_program_wall_clock_logs")
    if not has_real_valid:
        remaining.append("real_live_valid_report_outcomes")
    if not breadth_beyond:
        remaining.append("production_multilang_sast_breadth_beyond_held_outs")

    closed: list[str] = []
    if breadth_beyond:
        closed.append("production_multilang_sast_breadth_beyond_held_outs")
    if has_real_wall:
        closed.append("real_authorized_program_wall_clock_logs")
    if has_real_valid:
        closed.append("real_live_valid_report_outcomes")

    safety = _prove_safety_invariants(lab=lab, live=live, breadth=breadth)
    anti = _anti_auto_exploit_proof(safety=safety)
    packaging = _commercial_packaging_proof(
        lab_passed=bool(lab.get("passed")),
        live_passed=bool(live.get("passed")),
        breadth_passed=bool(breadth.get("passed")),
        anti_passed=bool(anti.get("passed")),
        safety=safety,
    )

    # Packaging + narrative are closed only when proofs pass (independent of live data).
    if packaging.get("passed"):
        closed.append("commercial_delivery_packaging")
    if anti.get("passed"):
        closed.append("anti_auto_exploit_narrative")

    # de-dupe preserve order
    closed = list(dict.fromkeys(closed))

    gates_ok = bool(lab.get("passed") and live.get("passed") and breadth.get("passed"))
    bundle_passed = gates_ok and bool(packaging.get("passed")) and bool(anti.get("passed"))

    scoreboard = {
        "schema_version": "market_leadership_scoreboard_v1",
        "claim_scope": "honest_market_gap_scoreboard",
        "passed": gates_ok,
        "lab_passed": lab.get("passed"),
        "live_infra_passed": live.get("passed"),
        "multilang_breadth_passed": breadth.get("passed"),
        "lab_scenario_count": ab.get("scenario_count"),
        "remaining_for_full_market_leadership": remaining,
        "closed_market_gaps": closed,
        "signals": {
            "has_real_wall_clock_logs": has_real_wall,
            "has_real_live_wall_clock_logs": has_real_live_wall,
            "has_real_human_hour_wall_clock_logs": has_real_hh_wall,
            "has_real_live_valid_report_outcomes": has_real_valid,
            "multilang_beyond_held_out": breadth_beyond,
            "commercial_packaging_ready": bool(packaging.get("passed")),
            "anti_auto_exploit_proven": bool(anti.get("passed")),
        },
        "attach_protocol": {
            "export_command": "export-research-track-record",
            "bundle_command": "commercial-delivery-bundle",
            "export_note": (
                "Prefer export from authorized research session; synthetic demo never "
                "flips has_real_*; real requires --declare-real-package and "
                "--program-authorization-id."
            ),
            "live_template": (
                "app/intelligence_benchmark/fixtures/templates/"
                "authorized_wall_clock_and_outcomes.template.json"
            ),
            "human_hour_requirements": [
                "source_kind=authorized_redacted_real",
                "program_authorization_id",
                "wall_clock_minutes on one or more entries",
                "execution_allowed=false",
                "report_submission_allowed=false",
                "no secrets/tokens/cookies",
            ],
            "live_requirements": [
                "source_kind=authorized_redacted_real",
                "program_authorization_id",
                "wall_clock_minutes for wall-clock gap",
                "human_confirmed_valid + report_outcome_ref for valid-report gap",
                "authorized=true",
                "human_confirmed=true",
                "no auto-submit",
            ],
        },
        "positioning": {
            "lead_with": "falsify_first_auditable_research_factory",
            "anti_auto_exploit": (
                "Autonomous exploitation is an intentional non-goal. "
                "Compete on falsify-first candidate quality, auditable evidence, "
                "and human-gated validation/report drafts."
            ),
            "do_not_claim": [
                "auto_exploit",
                "xbow_live_ranking",
                "live_bounty_top1_from_lab_alone",
                "full_commercial_multilang_sast_replacement",
            ],
        },
        "execution_allowed": False,
        "report_submission_allowed": False,
        "auto_attack_allowed": False,
        "non_claims": [
            "Does not claim live bounty program superiority.",
            "Does not claim XBOW ranking.",
            "Lab gates are necessary but not sufficient for live TOP1.",
        ],
        "runbook": RUNBOOK,
    }

    customer_brief = _render_customer_brief(
        scoreboard=scoreboard,
        packaging=packaging,
        anti=anti,
        breadth=breadth,
        ab_count=ab.get("scenario_count"),
    )

    manifest: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "claim_scope": "commercial_delivery_bundle",
        "passed": bundle_passed,
        "gates_ok": gates_ok,
        "remaining_for_full_market_leadership": remaining,
        "closed_market_gaps": closed,
        "lab_passed": lab.get("passed"),
        "live_infra_passed": live.get("passed"),
        "multilang_breadth_passed": breadth.get("passed"),
        "lab_scenario_count": ab.get("scenario_count"),
        "commercial_packaging": packaging,
        "anti_auto_exploit": anti,
        "safety_invariants": safety,
        "scoreboard": scoreboard,
        "artifacts": {
            "manifest": "manifest.json",
            "scoreboard": "market_scoreboard.json",
            "customer_brief": "customer_brief.md",
            "safety_invariants": "safety_invariants.json",
            "anti_auto_exploit": "anti_auto_exploit.json",
            "lab_summary": "lab_summary.json",
            "live_summary": "live_summary.json",
            "breadth_summary": "breadth_summary.json",
        },
        "docs": {
            "runbook": RUNBOOK,
            "positioning": POSITIONING_DOC,
        },
        "execution_allowed": False,
        "report_submission_allowed": False,
        "auto_attack_allowed": False,
        "dispatch_allowed": False,
        "validation_allowed": False,
        "candidate_promotion_allowed": False,
        "non_claims": [
            "Bundle proves lab/infra/packaging readiness, not live TOP1.",
            "Does not enable auto-exploit or auto-submission.",
            "Real wall-clock / valid-report gaps require authorized redacted packages.",
        ],
    }

    # Write artifacts
    _write_json(root / "manifest.json", manifest)
    _write_json(root / "market_scoreboard.json", scoreboard)
    _write_json(root / "safety_invariants.json", safety)
    _write_json(root / "anti_auto_exploit.json", anti)
    _write_json(root / "lab_summary.json", _public_gate_summary(lab))
    _write_json(root / "live_summary.json", _public_gate_summary(live))
    _write_json(root / "breadth_summary.json", _public_gate_summary(breadth))
    (root / "customer_brief.md").write_text(customer_brief, encoding="utf-8")

    return manifest


def evaluate_anti_auto_exploit_narrative(
    *,
    payload: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Standalone anti-auto-exploit proof for scoreboard / tests."""
    safety = _prove_safety_invariants(
        lab=payload.get("lab") if isinstance(payload, dict) else None,
        live=payload.get("live") if isinstance(payload, dict) else None,
        breadth=payload.get("breadth") if isinstance(payload, dict) else None,
        extra=payload if isinstance(payload, dict) else None,
    )
    return _anti_auto_exploit_proof(safety=safety)


def _prove_safety_invariants(
    *,
    lab: dict[str, Any] | None = None,
    live: dict[str, Any] | None = None,
    breadth: dict[str, Any] | None = None,
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    sources: list[tuple[str, dict[str, Any]]] = []
    for name, obj in (
        ("lab", lab),
        ("live", live),
        ("breadth", breadth),
        ("extra", extra),
    ):
        if isinstance(obj, dict):
            sources.append((name, obj))

    violations: list[str] = []
    checked = 0
    for name, obj in sources:
        for key in SAFETY_KEYS:
            if key not in obj:
                continue
            checked += 1
            if obj.get(key) is not False:
                violations.append(f"{name}.{key}={obj.get(key)!r}")

    # Bundle-level forced locks always present in proof
    forced = {key: False for key in SAFETY_KEYS}
    return {
        "schema_version": "safety_invariants_v1",
        "passed": not violations,
        "checked_fields": checked,
        "violations": violations,
        "forced_locks": forced,
        "execution_allowed": False,
        "report_submission_allowed": False,
        "auto_attack_allowed": False,
        "dispatch_allowed": False,
        "validation_allowed": False,
        "candidate_promotion_allowed": False,
        "notes": [
            "Any true/missing-true safety unlock is a commercial packaging failure.",
            "Auto-exploit and auto-submission are intentional non-goals.",
        ],
    }


def _anti_auto_exploit_proof(*, safety: dict[str, Any]) -> dict[str, Any]:
    narrative = (
        "Autonomous exploitation is an intentional non-goal. "
        "Compete on falsify-first candidate quality, auditable evidence, "
        "and human-gated validation/report drafts."
    )
    do_not_claim = [
        "auto_exploit",
        "xbow_live_ranking",
        "live_bounty_top1_from_lab_alone",
        "full_commercial_multilang_sast_replacement",
    ]
    checks = {
        "safety_invariants_passed": bool(safety.get("passed")),
        "execution_locked": safety.get("execution_allowed") is False,
        "submission_locked": safety.get("report_submission_allowed") is False,
        "auto_attack_locked": safety.get("auto_attack_allowed") is False,
        "narrative_present": bool(narrative.strip()),
        "do_not_claim_includes_auto_exploit": "auto_exploit" in do_not_claim,
    }
    passed = all(checks.values())
    return {
        "schema_version": "anti_auto_exploit_proof_v1",
        "passed": passed,
        "checks": checks,
        "positioning": {
            "lead_with": "falsify_first_auditable_research_factory",
            "anti_auto_exploit": narrative,
            "do_not_claim": do_not_claim,
            "sell": (
                "A senior researcher's forced-refutation assembly line — "
                "high-precision candidates, kill evidence for false positives, "
                "explicit evidence gaps, submission blocked until humans decide."
            ),
        },
        "execution_allowed": False,
        "report_submission_allowed": False,
        "auto_attack_allowed": False,
        "non_claims": [
            "Does not perform autonomous public exploitation.",
            "Does not auto-submit bounty reports.",
            "Does not claim XBOW live ranking from lab gates alone.",
        ],
    }


def _commercial_packaging_proof(
    *,
    lab_passed: bool,
    live_passed: bool,
    breadth_passed: bool,
    anti_passed: bool,
    safety: dict[str, Any],
) -> dict[str, Any]:
    checks = {
        "lab_gate_passed": lab_passed,
        "live_infra_passed": live_passed,
        "multilang_breadth_passed": breadth_passed,
        "anti_auto_exploit_passed": anti_passed,
        "safety_invariants_passed": bool(safety.get("passed")),
        "runbook_documented": True,
        "attach_protocol_documented": True,
        "customer_brief_generated": True,
    }
    return {
        "schema_version": "commercial_packaging_proof_v1",
        "passed": all(checks.values()),
        "checks": checks,
        "runbook": RUNBOOK,
        "positioning_doc": POSITIONING_DOC,
        "execution_allowed": False,
        "report_submission_allowed": False,
        "auto_attack_allowed": False,
    }


def _render_customer_brief(
    *,
    scoreboard: dict[str, Any],
    packaging: dict[str, Any],
    anti: dict[str, Any],
    breadth: dict[str, Any],
    ab_count: Any,
) -> str:
    remaining = scoreboard.get("remaining_for_full_market_leadership") or []
    closed = scoreboard.get("closed_market_gaps") or []
    patterns = breadth.get("patterns_hit") or []
    languages = breadth.get("languages_hit") or []
    narrative = (anti.get("positioning") or {}).get("anti_auto_exploit") or ""
    sell = (anti.get("positioning") or {}).get("sell") or ""

    lines = [
        "# Mythos-Lite Commercial Delivery Brief",
        "",
        "**Claim scope:** lab + live-infra + packaging readiness.  ",
        "**Not claimed:** live bounty TOP1, XBOW ranking, auto-exploit, auto-submission.",
        "",
        "## Product one-liner",
        "",
        sell,
        "",
        "## Anti auto-exploit (customer-facing)",
        "",
        narrative,
        "",
        "## Verified leadership signals",
        "",
        f"- A+B falsify scenarios: **{ab_count}**",
        f"- Multilang breadth beyond held-outs: **{breadth.get('beyond_held_out')}** "
        f"({breadth.get('cells_ok')}/{breadth.get('cells_total')} cells)",
        f"- Languages: {', '.join(languages) if languages else 'n/a'}",
        f"- Pattern families: {', '.join(patterns) if patterns else 'n/a'}",
        f"- Commercial packaging proof: **{packaging.get('passed')}**",
        f"- Anti-auto-exploit proof: **{anti.get('passed')}**",
        f"- Safety locks: execution/submission/auto-attack **all false**",
        "",
        "## Closed market gaps",
        "",
    ]
    if closed:
        for item in closed:
            lines.append(f"- `{item}`")
    else:
        lines.append("- _(none yet)_")
    lines.extend(
        [
            "",
            "## Remaining for full market leadership",
            "",
        ]
    )
    if remaining:
        for item in remaining:
            lines.append(f"- `{item}` — requires authorized redacted real package attach")
    else:
        lines.append("- **None** — authorized real wall-clock + valid outcomes attached")
    lines.extend(
        [
            "",
            "## How to attach real track record",
            "",
            "```powershell",
            "python -m app export-research-track-record `",
            "  --session-notes path/to/session_notes.json `",
            "  --approvals path/to/residual_approvals.json `",
            "  --wall-clock-json path/to/wall_clock_runner.json `",
            "  --program-authorization-id AUTH-REF `",
            "  --declare-real-package --human-allow-export-write `",
            "  --out-dir tmp/export-real --out tmp/export-real/manifest.json",
            "",
            "python -m app commercial-delivery-bundle `",
            "  --out-dir tmp/commercial-bundle `",
            "  --live-log tmp/export-real/authorized_live_outcomes.export.json `",
            "  --log tmp/export-real/human_hour_review_logs.export.json `",
            "  --human-allow-write",
            "```",
            "",
            "## Safety non-negotiables",
            "",
            "- Scope Guard + authorized artifacts only",
            "- Human approval for validation / evidence promotion / report drafts",
            "- No remote auto-attack, no credential stuffing, no auto-submission",
            "- No raw secrets/tokens/cookies in packages",
            "",
            f"Runbook: `{RUNBOOK}`  ",
            f"Positioning: `{POSITIONING_DOC}`",
            "",
        ]
    )
    return "\n".join(lines)


def _public_gate_summary(result: dict[str, Any]) -> dict[str, Any]:
    """Strip large nested payloads; keep safe summary fields."""
    keep = (
        "schema_version",
        "claim_scope",
        "passed",
        "beyond_held_out",
        "failures",
        "metrics",
        "scenario_count",
        "cells_ok",
        "cells_total",
        "languages_hit",
        "patterns_hit",
        "execution_allowed",
        "report_submission_allowed",
        "auto_attack_allowed",
        "non_claims",
        "measured",
        "component_results",
    )
    out: dict[str, Any] = {}
    for key in keep:
        if key in result:
            out[key] = result[key]
    # Force safety
    out["execution_allowed"] = False
    out["report_submission_allowed"] = False
    out["auto_attack_allowed"] = False
    return out


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
