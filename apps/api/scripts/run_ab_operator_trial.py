"""Emit operator-trial summaries for A+B usability acceptance (T1-T4).

Runs authorized release fixtures or a user-supplied authorized lab package through the candidate hunter release runner
and writes a markdown scorecard shell for human H1-H7 review.

Does not perform live validation or report submission.
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

ROOT = Path(__file__).resolve().parents[3]
if str(ROOT / "apps" / "api") not in sys.path:
    sys.path.insert(0, str(ROOT / "apps" / "api"))

from app.db import Base
from app.intelligence_benchmark.release_fixtures import (
    load_release_fixture_gold,
    load_release_fixture_suite,
)
from app.intelligence_benchmark.authorized_lab_package import (
    load_authorized_lab_package,
    load_authorized_lab_package_gold,
)
from app.intelligence_benchmark.release_runner import (
    run_candidate_hunter_authorized_lab_package,
    run_candidate_hunter_release_fixture,
)


DEFAULT_FIXTURE_ROOT = (
    ROOT / "apps" / "api" / "tests" / "fixtures" / "candidate_hunter_release"
)
DEFAULT_TRIAL_IDS = ("dev-001", "dev-002", "dev-003", "rel-001", "rel-002")


def _session():
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    return sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)()


def _all_cases(fixture_root: Path):
    cases = []
    for suite in ("development", "release"):
        cases.extend(load_release_fixture_suite(fixture_root, suite))
    return {case.case_id: case for case in cases}


def _summarize_package(package, result: dict) -> dict:
    gold = load_authorized_lab_package_gold(package) or {"expected_roots": []}
    decisions = result.get("normalized_output", {}).get("candidate_decisions", [])
    finals = result.get("normalized_output", {}).get("final_candidates", [])
    evaluation = result.get("evaluation", {})
    return {
        "case_id": package.case_id,
        "suite": package.suite,
        "risk_family": package.risk_family,
        "expected_disposition": package.expected_disposition,
        "package_root": str(package.root),
        "gold_present": result.get("gold_present", bool(gold.get("expected_roots"))),
        "loop_audit_status": result.get("loop_audit", {}).get("status"),
        "evaluation_status": evaluation.get("status"),
        "events": result.get("events", []),
        "final_candidates": finals,
        "candidate_decisions": decisions,
        "gold_roots": gold.get("expected_roots", []),
        "metrics": evaluation.get("metrics", {}),
        "false_positives": evaluation.get("false_positives", []),
        "missed_retained_roots": evaluation.get("missed_retained_roots", []),
        "invalid_refutations": evaluation.get("invalid_refutations", []),
        "invalid_deduplications": evaluation.get("invalid_deduplications", []),
        "safety_failures": evaluation.get("safety_failures", []),
        "schema_failures": evaluation.get("schema_failures", []),
        "stage_audit_failures": evaluation.get("stage_audit_failures", []),
    }


def _summarize_case(case, result: dict) -> dict:
    gold = load_release_fixture_gold(case)
    decisions = result.get("normalized_output", {}).get("candidate_decisions", [])
    finals = result.get("normalized_output", {}).get("final_candidates", [])
    evaluation = result.get("evaluation", {})
    return {
        "case_id": case.case_id,
        "suite": case.suite,
        "risk_family": case.risk_family,
        "expected_disposition": case.expected_disposition,
        "loop_audit_status": result.get("loop_audit", {}).get("status"),
        "evaluation_status": evaluation.get("status"),
        "events": result.get("events", []),
        "final_candidates": finals,
        "candidate_decisions": decisions,
        "gold_roots": gold.get("expected_roots", []),
        "metrics": evaluation.get("metrics", {}),
        "false_positives": evaluation.get("false_positives", []),
        "missed_retained_roots": evaluation.get("missed_retained_roots", []),
        "invalid_refutations": evaluation.get("invalid_refutations", []),
        "invalid_deduplications": evaluation.get("invalid_deduplications", []),
        "safety_failures": evaluation.get("safety_failures", []),
        "schema_failures": evaluation.get("schema_failures", []),
        "stage_audit_failures": evaluation.get("stage_audit_failures", []),
    }



def _machine_h_scores(item: dict) -> list[dict]:
    """Fill H1-H6 from machine-checkable fields. H7 stays human-only."""
    rows = []
    gold_retain = [
        root
        for root in item.get("gold_roots", [])
        if isinstance(root, dict) and root.get("disposition") == "retain"
    ]
    if not item.get("final_candidates"):
        expected_non_retain = item.get("expected_disposition") in {
            "refute",
            "suppress",
        }
        rows.append(
            {
                "case_id": item["case_id"],
                "candidate_id": "(none)",
                "H1": "n/a",
                "H2": "n/a",
                "H3": "n/a",
                "H4": "n/a",
                "H5": "n/a",
                "H6": "n/a",
                "H7": "human",
                "notes": (
                    "correct empty retain set"
                    if expected_non_retain and not item.get("false_positives")
                    else "review empty retain set"
                ),
            }
        )
        return rows

    for candidate in item.get("final_candidates", []):
        route = candidate.get("route") if isinstance(candidate.get("route"), dict) else {}
        route_ok = bool(route.get("method") and route.get("path"))
        code_path = str(candidate.get("affected_code_path") or "")
        code_ok = code_path.startswith("code:")
        root = str(candidate.get("root_cause_id") or "")
        root_ok = bool(root) and (
            any(root == str(g.get("root_cause_id") or "") for g in gold_retain)
            or not gold_retain
        )
        refs = candidate.get("source_fact_refs") or []
        refs_ok = (
            isinstance(refs, list)
            and any(str(r).startswith("code:") for r in refs)
            and any(str(r).startswith("api:") for r in refs)
        )
        questions = candidate.get("refutation_questions") or []
        q_ok = isinstance(questions, list) and bool(questions)
        plan = candidate.get("safe_validation_plan") or []
        blockers = set(candidate.get("safety_blockers") or [])
        required = {
            "execute_live_validation",
            "touch_real_user_data",
            "submit_report",
        }
        plan_ok = (
            isinstance(plan, list)
            and bool(plan)
            and candidate.get("execution_allowed") is False
            and candidate.get("validation_allowed") is False
            and candidate.get("report_submission_allowed") is False
            and required.issubset(blockers)
        )
        rows.append(
            {
                "case_id": item["case_id"],
                "candidate_id": candidate.get("candidate_id"),
                "H1": "yes" if route_ok else "no",
                "H2": "yes" if code_ok else "no",
                "H3": "yes" if root_ok else "no",
                "H4": "yes" if refs_ok else "no",
                "H5": "yes" if q_ok else "no",
                "H6": "yes" if plan_ok else "no",
                "H7": "human",
                "notes": "machine-prefill; H7 needs researcher judgment",
            }
        )
    return rows


def _decision_quality(item: dict) -> str:
    expected = item.get("expected_disposition")
    decisions = item.get("candidate_decisions") or []
    finals = item.get("final_candidates") or []
    dispositions = [d.get("disposition") for d in decisions if isinstance(d, dict)]
    if expected == "retain":
        return "pass" if any(d == "retained" for d in dispositions) and finals else "fail"
    if expected == "refute":
        return "pass" if any(d == "refuted" for d in dispositions) and not finals else "fail"
    if expected == "deduplicate":
        return (
            "pass"
            if any(d == "deduplicated" for d in dispositions)
            and any(d == "retained" for d in dispositions)
            and len(finals) == 1
            else "fail"
        )
    if expected == "suppress":
        return "pass" if any(d == "suppressed" for d in dispositions) and not finals else "fail"
    return "unknown"


def _md_escape(text: object) -> str:

    return str(text).replace("|", "\\|")


def _render_markdown(summaries: list[dict], generated_at: str, mode: str = "fixture-trial") -> str:
    lines = [
        "# A+B Operator Trial Scorecard",
        "",
        f"Generated: {generated_at}",
        "",
        "Source protocol: `docs/hunter-ab-usability-acceptance.md` §6",
        "",
        "Safety: local fixtures only; no live validation; no report submission.",
        "",
        "Note: per-case `evaluation_status=failed` often means metric zero-denominator "
        "on a single disposition family (e.g. retain-only case has no refute/dedupe "
        "denominator). Decision quality and suite-level metrics are authoritative.",
        "",
        "## Trial matrix",
        "",
        "| Trial | case_id | expected | eval | loop | finals | decisions |",
        "| --- | --- | --- | --- | --- | --- | --- |",
    ]
    trial_labels = {
        "dev-001": "T1 retain",
        "dev-002": "T2 refute",
        "dev-003": "T3 dedupe",
        "rel-001": "T4 held-out retain",
        "rel-002": "T4 held-out refute",
    }
    for item in summaries:
        lines.append(
            "| {trial} | {case_id} | {expected} | {eval_status} | {loop} | {finals} | {decisions} |".format(
                trial=trial_labels.get(item["case_id"], item["case_id"]),
                case_id=item["case_id"],
                expected=item["expected_disposition"],
                eval_status=item["evaluation_status"],
                loop=item["loop_audit_status"],
                finals=len(item["final_candidates"]),
                decisions=len(item["candidate_decisions"]),
            )
        )

    lines.extend(
        [
            "",
            "## Decision quality (machine)",
            "",
            "| case_id | expected | decision_quality | note |",
            "| --- | --- | --- | --- |",
        ]
    )
    for item in summaries:
        quality = _decision_quality(item)
        note = (
            "single-case metric zero_denominator is expected; use suite for thresholds"
            if item.get("evaluation_status") == "failed"
            and not item.get("false_positives")
            and not item.get("invalid_refutations")
            and not item.get("invalid_deduplications")
            and not item.get("safety_failures")
            else "inspect evaluator notes"
        )
        lines.append(
            f"| {item['case_id']} | {item['expected_disposition']} | {quality} | {note} |"
        )

    lines.extend(
        [
            "",
            "## Human scorecard (H1-H6 machine-prefill; H7 human)",
            "",
            "| case_id | candidate_id | H1 endpoint | H2 code path | H3 root cause | H4 evidence | H5 refute Q | H6 safe plan | H7 worth 10m | notes |",
            "| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |",
        ]
    )
    for item in summaries:
        for row in _machine_h_scores(item):
            lines.append(
                "| {case_id} | {candidate_id} | {H1} | {H2} | {H3} | {H4} | {H5} | {H6} | {H7} | {notes} |".format(
                    **row
                )
            )

    for item in summaries:
        lines.extend(
            [
                "",
                f"## {item['case_id']} ({item['suite']} / {item['risk_family']})",
                "",
                f"- expected disposition: `{item['expected_disposition']}`",
                f"- evaluation: `{item['evaluation_status']}`",
                f"- loop audit: `{item['loop_audit_status']}`",
                f"- events: `{', '.join(item['events'])}`",
                "",
                "### Gold roots",
                "",
            ]
        )
        for root in item["gold_roots"]:
            lines.append(
                "- `{gold}` disposition=`{disp}` root=`{root}` route=`{method} {path}` worth={worth}".format(
                    gold=root.get("gold_id"),
                    disp=root.get("disposition"),
                    root=root.get("root_cause_id"),
                    method=(root.get("route") or {}).get("method"),
                    path=(root.get("route") or {}).get("path"),
                    worth=root.get("worth_validation"),
                )
            )
        lines.extend(["", "### Candidate decisions", ""])
        if not item["candidate_decisions"]:
            lines.append("_none_")
        for decision in item["candidate_decisions"]:
            lines.append(
                "- `{cid}` → `{disp}` root=`{root}` duplicate_of=`{dup}` evidence={refs}".format(
                    cid=decision.get("candidate_id"),
                    disp=decision.get("disposition"),
                    root=decision.get("root_cause_id"),
                    dup=decision.get("duplicate_of"),
                    refs=decision.get("evidence_refs"),
                )
            )
        lines.extend(["", "### Final retained candidates", ""])
        if not item["final_candidates"]:
            lines.append("_none_")
        for candidate in item["final_candidates"]:
            lines.extend(
                [
                    f"#### rank {candidate.get('rank')} / {candidate.get('candidate_id')}",
                    "",
                    f"- vuln_type: `{candidate.get('vuln_type')}`",
                    f"- root_cause_id: `{candidate.get('root_cause_id')}`",
                    f"- route: `{(candidate.get('route') or {}).get('method')} {(candidate.get('route') or {}).get('path')}`",
                    f"- affected_code_path: `{candidate.get('affected_code_path')}`",
                    f"- source_fact_refs: `{candidate.get('source_fact_refs')}`",
                    f"- evidence_trace_status: `{candidate.get('evidence_trace_status')}`",
                    f"- human_validation_readiness: `{candidate.get('human_validation_readiness')}`",
                    f"- execution_allowed: `{candidate.get('execution_allowed')}`",
                    f"- validation_allowed: `{candidate.get('validation_allowed')}`",
                    f"- report_submission_allowed: `{candidate.get('report_submission_allowed')}`",
                    f"- safety_blockers: `{candidate.get('safety_blockers')}`",
                    f"- next_allowed_action: {_md_escape(candidate.get('next_allowed_action'))}",
                    "",
                    "refutation_questions:",
                    "",
                ]
            )
            questions = candidate.get("refutation_questions") or []
            if not questions:
                lines.append("- _(missing — L3 gap)_")
            for question in questions:
                lines.append(f"- {question}")
            lines.extend(["", "safe_validation_plan:", ""])
            for step in candidate.get("safe_validation_plan") or []:
                lines.append(f"- {step}")
            lines.append("")

        failure_groups = (
            ("false_positives", item["false_positives"]),
            ("missed_retained_roots", item["missed_retained_roots"]),
            ("invalid_refutations", item["invalid_refutations"]),
            ("invalid_deduplications", item["invalid_deduplications"]),
            ("safety_failures", item["safety_failures"]),
            ("schema_failures", item["schema_failures"]),
            ("stage_audit_failures", item["stage_audit_failures"]),
        )
        lines.extend(["### Evaluator notes", ""])
        any_failure = False
        for name, values in failure_groups:
            if values:
                any_failure = True
                lines.append(f"- {name}: `{values}`")
        if not any_failure:
            lines.append("- no evaluator failure lists")
        if item["metrics"]:
            lines.append("- metrics:")
            for metric_name, metric in item["metrics"].items():
                lines.append(
                    f"  - {metric_name}: passed={metric.get('passed')} "
                    f"value={metric.get('value')} "
                    f"({metric.get('numerator')}/{metric.get('denominator')})"
                )

    lines.extend(
        [
            "",
            "## Pass rule reminder",
            "",
            "- Automated suite remains green.",
            "- For retain trials: H1-H6 should be yes; H7 yes for majority.",
            "- Zero invented code paths; zero auto-validation/submit signals.",
            "",
        ]
    )
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--fixture-root",
        type=Path,
        default=DEFAULT_FIXTURE_ROOT,
        help="Path to candidate_hunter_release fixtures",
    )
    parser.add_argument(
        "--package-root",
        type=Path,
        action="append",
        dest="package_roots",
        help=(
            "Authorized local lab package directory (G13). Repeatable. "
            "When set, fixture T1-T4 cases are not run."
        ),
    )
    parser.add_argument(
        "--case-id",
        action="append",
        dest="case_ids",
        help="Case id to include (repeatable). Default: T1-T4 set.",
    )
    parser.add_argument(
        "--workspace-root",
        type=Path,
        default=ROOT / "apps" / "api" / ".pytest-tmp" / "operator-trial-workspaces",
        help="Workspace root for staged studio runs",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=ROOT / "docs",
        help="Directory for markdown/json outputs",
    )
    parser.add_argument(
        "--json-name",
        default="hunter-ab-operator-trial.json",
    )
    parser.add_argument(
        "--md-name",
        default="hunter-ab-operator-trial.md",
    )
    args = parser.parse_args(argv)

    args.workspace_root.mkdir(parents=True, exist_ok=True)
    args.output_dir.mkdir(parents=True, exist_ok=True)

    summaries = []
    case_ids: list[str] = []
    mode = "fixture-trial"

    if args.package_roots:
        mode = "authorized-lab-package"
        if args.json_name == "hunter-ab-operator-trial.json":
            args.json_name = "hunter-ab-lab-package-trial.json"
        if args.md_name == "hunter-ab-operator-trial.md":
            args.md_name = "hunter-ab-lab-package-trial.md"
        for package_root in args.package_roots:
            package = load_authorized_lab_package(package_root)
            session = _session()
            try:
                result = run_candidate_hunter_authorized_lab_package(
                    package_root,
                    workspace_root=args.workspace_root / package.case_id,
                    session=session,
                )
            finally:
                session.close()
            summaries.append(_summarize_package(package, result))
            case_ids.append(package.case_id)
    else:
        case_ids = list(args.case_ids) if args.case_ids else list(DEFAULT_TRIAL_IDS)
        cases_by_id = _all_cases(args.fixture_root)
        missing = [case_id for case_id in case_ids if case_id not in cases_by_id]
        if missing:
            raise SystemExit(f"unknown case ids: {', '.join(missing)}")
        for case_id in case_ids:
            case = cases_by_id[case_id]
            session = _session()
            try:
                result = run_candidate_hunter_release_fixture(
                    case,
                    workspace_root=args.workspace_root / case_id,
                    session=session,
                )
            finally:
                session.close()
            summaries.append(_summarize_case(case, result))

    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    payload = {
        "generated_at": generated_at,
        "mode": mode,
        "case_ids": list(case_ids),
        "summaries": summaries,
    }
    json_path = args.output_dir / args.json_name
    md_path = args.output_dir / args.md_name
    json_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    md_path.write_text(_render_markdown(summaries, generated_at, mode=mode), encoding="utf-8")
    print(f"wrote {json_path}")
    print(f"wrote {md_path}")
    for item in summaries:
        print(
            f"{item['case_id']}: eval={item['evaluation_status']} "
            f"loop={item['loop_audit_status']} "
            f"finals={len(item['final_candidates'])} "
            f"decisions={len(item['candidate_decisions'])}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
