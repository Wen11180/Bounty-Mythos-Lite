from __future__ import annotations

from dataclasses import dataclass, field, replace
from hashlib import sha256
import json
from pathlib import Path
import subprocess
from typing import Protocol

from app.authorized_web_api import AuthorizedBugBountyPlan, build_authorized_bug_bounty_plan
from app.codebase_map import CodebaseFactCandidate, map_authorized_code_files
from app.crs_fuzzing import CRSFuzzingPlan, build_crs_fuzzing_plan
from app.deep_research import DeepResearchPlan, build_deep_research_plan
from app.industrial_scheduler import IndustrialSchedulerPlan, build_industrial_scheduler_plan
from app.mythos_report import build_report_preview_response
from app.validation_workspace import build_validation_workspace


SKIPPED_DIRECTORIES = {
    ".git",
    ".pytest_cache",
    ".venv",
    "__pycache__",
    "build",
    "dist",
    "node_modules",
}
CODE_EXTENSIONS = {".py", ".js", ".jsx", ".ts", ".tsx", ".go"}
MAX_FILE_BYTES = 80_000
MAX_AUTHORIZED_CODE_FILES = 80
SECRET_MARKERS = (
    "authorization:",
    "bearer ",
    "cookie:",
    "set-cookie:",
    "x-api-key:",
    "api_key",
    "access_token",
    "secret=",
    "token=",
    "sk-live",
    "sk-proj",
)


class SourceAuditBlocked(RuntimeError):
    pass


class SemgrepRunner(Protocol):
    def __call__(self, repo_path: Path) -> dict:
        ...


class CodeQLRunner(Protocol):
    def __call__(self, repo_path: Path) -> dict:
        ...


class LLMReviewer(Protocol):
    def __call__(self, context: dict) -> dict:
        ...


@dataclass(frozen=True)
class ScopeCheck:
    allowed: bool
    reason: str
    repo_path: str


@dataclass(frozen=True)
class IntakeProfile:
    languages: list[str] = field(default_factory=list)
    frameworks: list[str] = field(default_factory=list)
    package_managers: list[str] = field(default_factory=list)
    entrypoints: list[str] = field(default_factory=list)
    file_count: int = 0


@dataclass(frozen=True)
class StaticFinding:
    tool: str
    rule_id: str
    file: str
    line: int | None
    category: str
    confidence: str
    message: str


@dataclass(frozen=True)
class SemgrepScan:
    status: str
    findings: list[StaticFinding]
    summary: str


@dataclass(frozen=True)
class CodeQLScan:
    status: str
    summary: str


@dataclass(frozen=True)
class DependencyManifest:
    path: str
    ecosystem: str
    package_count: int
    packages: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class DependencySummary:
    manifests: list[DependencyManifest] = field(default_factory=list)

    @property
    def package_count(self) -> int:
        return sum(manifest.package_count for manifest in self.manifests)


@dataclass(frozen=True)
class VulnerabilityHypothesis:
    hypothesis_id: str
    vuln_type: str
    location: str
    reason: str
    evidence_needed: list[str]
    false_positive_checks: list[str]
    refutation_status: str
    priority_score: int
    ranking_reasons: list[str]
    safe_verification: bool
    risk: str


@dataclass(frozen=True)
class LLMReview:
    status: str
    summary: str


@dataclass(frozen=True)
class SourceAuditResult:
    scope: ScopeCheck
    intake: IntakeProfile
    dependencies: DependencySummary
    semgrep: SemgrepScan
    codeql: CodeQLScan
    hypotheses: list[VulnerabilityHypothesis]
    llm_review: LLMReview
    finding_json: list[dict]
    audit_log: list[dict]
    crs_fuzzing: CRSFuzzingPlan
    authorized_bug_bounty: AuthorizedBugBountyPlan
    industrial_scheduler: IndustrialSchedulerPlan
    deep_research: DeepResearchPlan
    report_markdown: str


def run_source_audit(
    repo_path: str | Path,
    scope_path: str | Path,
    *,
    semgrep_runner: SemgrepRunner | None = None,
    codeql_runner: CodeQLRunner | None = None,
    llm_reviewer: LLMReviewer | None = None,
    patch_diff_metadata: dict | None = None,
) -> SourceAuditResult:
    repo = Path(repo_path).resolve()
    scope = evaluate_source_scope(repo, Path(scope_path))
    if not scope.allowed:
        raise SourceAuditBlocked(scope.reason)

    authorized_files = collect_authorized_code_files(repo)
    codebase_map = map_authorized_code_files({"authorized_code_files": authorized_files})
    crs_fuzzing = build_crs_fuzzing_plan(authorized_files)
    authorized_bug_bounty = build_authorized_bug_bounty_plan(
        load_scope_policy(scope_path),
        authorized_files,
    )
    intake = build_intake_profile(repo, authorized_files, codebase_map.facts)
    dependencies = build_dependency_summary(repo)
    semgrep = build_semgrep_scan(
        semgrep_runner(repo) if semgrep_runner is not None else run_semgrep(repo)
    )
    codeql = build_codeql_scan(
        codeql_runner(repo) if codeql_runner is not None else run_codeql(repo)
    )
    hypotheses = build_source_hypotheses(codebase_map.facts, semgrep.findings)
    llm_review = build_llm_review(
        reviewer=llm_reviewer,
        intake=intake,
        semgrep=semgrep,
        hypotheses=hypotheses,
    )
    finding_json = build_finding_json(hypotheses, semgrep.findings, scope)
    industrial_scheduler = build_industrial_scheduler_plan(
        {
            "scope": {
                "allowed": scope.allowed,
                "reason": scope.reason,
            },
            "hypotheses": finding_json,
            "crs_fuzzing": crs_fuzzing.to_dict(),
            "authorized_bug_bounty": authorized_bug_bounty.to_dict(),
        }
    )
    deep_research = build_deep_research_plan(
        {
            "source_hypotheses": [
                {
                    "hypothesis_id": hypothesis.hypothesis_id,
                    "vuln_type": hypothesis.vuln_type,
                    "location": hypothesis.location,
                    "risk": hypothesis.risk,
                    "reason": hypothesis.reason,
                }
                for hypothesis in hypotheses
            ],
            "crs_fuzzing": crs_fuzzing.to_dict(),
            "authorized_bug_bounty": authorized_bug_bounty.to_dict(),
            "industrial_scheduler": industrial_scheduler.to_dict(),
            "patch_diff": patch_diff_metadata or {},
        }
    )
    audit_log = build_audit_log(
        scope=scope,
        intake=intake,
        dependencies=dependencies,
        semgrep=semgrep,
        codeql=codeql,
        hypotheses=hypotheses,
        llm_review=llm_review,
        crs_fuzzing=crs_fuzzing,
        authorized_bug_bounty=authorized_bug_bounty,
        industrial_scheduler=industrial_scheduler,
        deep_research=deep_research,
    )
    report = build_markdown_report(
        scope,
        intake,
        dependencies,
        semgrep,
        codeql,
        hypotheses,
        llm_review,
        crs_fuzzing,
        authorized_bug_bounty,
        industrial_scheduler,
        deep_research,
    )
    return SourceAuditResult(
        scope=scope,
        intake=intake,
        dependencies=dependencies,
        semgrep=semgrep,
        codeql=codeql,
        hypotheses=hypotheses,
        llm_review=llm_review,
        finding_json=finding_json,
        audit_log=audit_log,
        crs_fuzzing=crs_fuzzing,
        authorized_bug_bounty=authorized_bug_bounty,
        industrial_scheduler=industrial_scheduler,
        deep_research=deep_research,
        report_markdown=report,
    )


def save_source_audit_pipeline_run(
    *,
    repository,
    result: SourceAuditResult,
    policy_text: str,
    program_id: str | None = None,
):
    payload = build_source_audit_pipeline_payload(result)
    artifact_record = repository.save_artifact(
        program_id=program_id,
        asset=result.scope.repo_path,
        kind="source_audit",
        source_type="local_repository",
        source_hash=payload["artifact"]["digest"],
        ingestion_status="normalized",
        provenance={
            "source": "source audit CLI/importer",
            "repo_path": result.scope.repo_path,
            "scope_reason": result.scope.reason,
        },
        payload_summary=_source_audit_artifact_summary(result),
        derived_facts=_source_audit_derived_facts(result),
    )
    payload["artifact"] = _source_audit_artifact_payload(
        artifact_record,
        evidence_count=2,
    )
    scope_status = "in_scope" if result.scope.allowed else "blocked"
    record = repository.save_pipeline_run(
        program_id=program_id,
        asset=result.scope.repo_path,
        policy_text=policy_text,
        scope_status=scope_status,
        hypothesis_count=len(result.hypotheses),
        blocked_count=len(result.hypotheses),
        report_title=payload["report_draft"]["title"],
        payload=payload,
    )
    repository.append_artifact_usage_records(
        artifact_id=artifact_record.id,
        usage_records=_source_audit_usage_records(record, artifact_record.id),
    )
    return record


def build_source_audit_pipeline_payload(result: SourceAuditResult) -> dict:
    digest = _source_audit_digest(result)
    report_title = f"Source audit: {_repo_display_name(result.scope.repo_path)}"
    severity = _highest_hypothesis_risk(result.hypotheses)
    hypotheses = _source_audit_pipeline_hypotheses(result)
    first_hypothesis = hypotheses[0] if hypotheses else {}
    artifact_ref = f"source_audit:{digest[:16]}"
    refutation = {
        "status": "blocked",
        "reasons": ["human_approval_required"],
        "questions": [
            "Does local service-layer code enforce the missing boundary?",
            "Can sanitized local evidence prove impact without real user data?",
        ],
        "human_review_required": True,
    }
    validation_plan = {
        "status": "blocked",
        "human_approval_required": True,
        "steps": [
            "Review the local code path and attach sanitized evidence before promotion.",
            "Use only local fixtures or explicitly authorized test accounts.",
        ],
        "methods": ["local_code_review", "manual_evidence_review"],
    }
    validation_workspace = build_validation_workspace(
        validation_plan=validation_plan,
        scope_decision={
            "allowed": result.scope.allowed,
            "reason": result.scope.reason,
        },
        refutation=refutation,
        evidence_hints=[
            {
                "type": "local_code_reference",
                "purpose": "Attach redacted local code metadata before claim review.",
            },
            {
                "type": "request_response_diff",
                "purpose": "Attach sanitized local fixture evidence before promotion.",
            },
        ],
    ).model_dump(mode="json")

    payload = {
        "artifact_kind": "source_audit",
        "source_audit": {
            "repo_path": safe_display_text(result.scope.repo_path),
            "scope_reason": result.scope.reason,
            "semgrep": {
                "status": result.semgrep.status,
                "finding_count": len(result.semgrep.findings),
            },
            "codeql": {
                "status": result.codeql.status,
                "summary": result.codeql.summary,
            },
            "dependency_manifest_count": len(result.dependencies.manifests),
            "audit_event_count": len(result.audit_log),
        },
        "artifact": {
            "artifact_id": artifact_ref,
            "kind": "source_audit",
            "source_type": "local_repository",
            "source": "authorized_local_repository",
            "provenance": "source_audit",
            "summary": f"{len(result.hypotheses)} unverified source audit hypothesis/hypotheses.",
            "evidence_count": 2,
            "digest": digest,
            "sensitivity_label": "internal_research_metadata",
            "redaction_status": "redacted",
            "report_chain_allowed": True,
            "safety_blockers": [],
        },
        "target_model": _source_audit_target_model(result),
        "crs_fuzzing": result.crs_fuzzing.to_dict(),
        "authorized_bug_bounty": result.authorized_bug_bounty.to_dict(),
        "industrial_scheduler": result.industrial_scheduler.to_dict(),
        "deep_research": result.deep_research.to_dict(),
        "invariants": [
            {
                "invariant": _broken_invariant_for_hypothesis(hypothesis),
                "source": hypothesis.hypothesis_id,
            }
            for hypothesis in result.hypotheses
        ],
        "hypotheses": hypotheses,
        "refutation": refutation,
        "validation_plan": validation_plan,
        "validation_workspace": validation_workspace,
        "validation_gate": {
            "status": "awaiting_approval",
            "label": "human_review_required",
            "approval_required": True,
            "summary": "Source audit output is a hypothesis set; no validation or submission is allowed without human review.",
            "evidence_count": 2,
        },
        "evidence_bundle": {
            "items": [
                {
                    "type": "local_code_reference",
                    "content": {
                        "status": "redacted_reference_only",
                        "note": "Source audit stored metadata only, not raw source lines.",
                    },
                },
                {
                    "type": "log_ref",
                    "content": {
                        "status": "audit_log_summary",
                        "event_count": len(result.audit_log),
                    },
                },
            ],
            "safety_notes": [
                "local_artifact_only",
                "no_live_requests",
                "human_review_required",
            ],
        },
        "report_draft": {
            "title": report_title,
            "severity": severity,
            "scope_status": "in_scope" if result.scope.allowed else "blocked",
            "actual_result": (
                "Source audit generated unverified hypotheses only; attach sanitized "
                "manual evidence before promoting any claim."
            ),
            "human_review_required": True,
            "auto_submit_allowed": False,
            "safety_notes": [
                "submission_blocked",
                "human_review_required",
                "no_live_requests",
                "no_real_user_data",
            ],
        },
        "hunter_intelligence": {
            "top_recommendation": "needs_human_review",
            "assessments": [_source_audit_hunter_assessment(first_hypothesis, severity)],
        },
        "timeline": [
            {
                "name": "source_scope",
                "status": "completed" if result.scope.allowed else "blocked",
                "input_summary": "Local repository path checked against the source-audit allowlist.",
                "output_summary": result.scope.reason,
                "safety_notes": [
                    "scope_guard_required",
                    "local_files_only",
                ],
                "details": {
                    "agent_boundary": {
                        "role": "source_scope_guard",
                        "allowed_actions": ["evaluate_local_repo_allowlist"],
                        "blocked_actions": [
                            "scan_public_targets",
                            "execute_live_validation",
                            "touch_real_user_data",
                            "submit_report",
                            "bypass_scope_guard",
                        ],
                        "requires_human_review": False,
                        "execution_allowed": False,
                    }
                },
            },
            {
                "name": "source_intake",
                "status": "completed",
                "input_summary": f"{result.intake.file_count} authorized source file(s) indexed as metadata.",
                "output_summary": (
                    f"{len(result.intake.languages)} language(s), "
                    f"{len(result.intake.frameworks)} framework signal(s), "
                    f"{len(result.intake.entrypoints)} entrypoint(s)."
                ),
                "safety_notes": [
                    "raw_source_not_persisted",
                    "local_files_only",
                ],
                "details": {
                    "agent_boundary": {
                        "role": "source_intake",
                        "allowed_actions": ["summarize_local_code_metadata"],
                        "blocked_actions": [
                            "store_raw_source_lines",
                            "execute_live_validation",
                            "touch_real_user_data",
                            "submit_report",
                            "bypass_scope_guard",
                        ],
                        "requires_human_review": False,
                        "execution_allowed": False,
                    }
                },
            },
            {
                "name": "static_analysis",
                "status": result.semgrep.status,
                "input_summary": "Semgrep wrapper and dependency manifest discovery reviewed local files only.",
                "output_summary": (
                    f"{len(result.semgrep.findings)} static finding(s), "
                    f"{len(result.dependencies.manifests)} dependency manifest(s)."
                ),
                "safety_notes": [
                    "tool_output_unconfirmed",
                    "no_live_requests",
                ],
                "details": {
                    "agent_boundary": {
                        "role": "static_analysis",
                        "allowed_actions": ["run_or_record_local_static_analysis"],
                        "blocked_actions": [
                            "execute_live_validation",
                            "touch_real_user_data",
                            "submit_report",
                            "bypass_scope_guard",
                        ],
                        "requires_human_review": False,
                        "execution_allowed": False,
                    }
                },
            },
            {
                "name": "hypotheses",
                "status": "human_review_required",
                "input_summary": f"{len(result.hypotheses)} source-audit hypothesis/hypotheses generated from local evidence.",
                "output_summary": "All hypotheses remain unconfirmed and blocked from validation.",
                "safety_notes": [
                    "hypotheses_only",
                    "human_review_required",
                    "no_auto_validation",
                ],
                "details": {
                    "agent_boundary": {
                        "role": "source_hypothesis_builder",
                        "allowed_actions": ["rank_unverified_local_hypotheses"],
                        "blocked_actions": [
                            "execute_live_validation",
                            "touch_real_user_data",
                            "submit_report",
                            "bypass_scope_guard",
                        ],
                        "requires_human_review": True,
                        "execution_allowed": False,
                    }
                },
            },
            {
                "name": "crs_fuzzing",
                "status": result.crs_fuzzing.execution_mode,
                "input_summary": "Authorized local parser, decoder, and validator candidates reviewed for fuzzing suitability.",
                "output_summary": (
                    f"{len(result.crs_fuzzing.parser_candidates)} parser candidate(s), "
                    f"{len(result.crs_fuzzing.harness_plans)} harness plan(s), "
                    f"fuzzer status {result.crs_fuzzing.fuzzer_plan.status}."
                ),
                "safety_notes": [
                    "plan_only",
                    "no_fuzzer_execution_without_human_approval",
                    "local_artifacts_only",
                ],
                "details": {
                    "agent_boundary": _source_audit_stage_boundary(
                        role="crs_fuzzing_agent",
                        allowed_actions=["plan_local_harnesses", "prepare_crash_triage_schema"],
                        requires_human_review=True,
                    )
                },
            },
            {
                "name": "authorized_bug_bounty",
                "status": "human_review_required",
                "input_summary": "Bug bounty scope, API operations, and test-account roles modeled without storing secrets.",
                "output_summary": (
                    f"{len(result.authorized_bug_bounty.allowed_assets)} allowed asset(s), "
                    f"{len(result.authorized_bug_bounty.api_operations)} API operation(s), "
                    f"{len(result.authorized_bug_bounty.role_diff_plans)} role diff plan(s)."
                ),
                "safety_notes": [
                    "plan_only",
                    "human_gate_required",
                    "no_external_requests",
                    "no_credential_storage",
                ],
                "details": {
                    "agent_boundary": _source_audit_stage_boundary(
                        role="authorized_bug_bounty_agent",
                        allowed_actions=["model_authorized_assets", "plan_role_diff_review"],
                        requires_human_review=True,
                    )
                },
            },
            {
                "name": "industrial_scheduler",
                "status": result.industrial_scheduler.execution_mode,
                "input_summary": "V0-V2 outputs converted into a scope-checked multi-agent DAG plan.",
                "output_summary": (
                    f"{len(result.industrial_scheduler.dag_tasks)} task(s), "
                    f"{len(result.industrial_scheduler.parallel_batches)} parallel batch(es), "
                    f"{len(result.industrial_scheduler.risk_queue)} risk queue item(s)."
                ),
                "safety_notes": [
                    "plan_only_orchestration",
                    "no_unscoped_agent_execution",
                    "no_parallel_task_without_scope_check",
                ],
                "details": {
                    "agent_boundary": _source_audit_stage_boundary(
                        role="industrial_scheduler",
                        allowed_actions=["plan_scope_checked_dag", "rank_review_queue"],
                        requires_human_review=True,
                    )
                },
            },
            {
                "name": "deep_research",
                "status": "human_review_required",
                "input_summary": "Source hypotheses, CRS, V2, and V3 context used for deep reasoning plans.",
                "output_summary": (
                    f"{len(result.deep_research.vulnerability_chains)} chain(s), "
                    f"{len(result.deep_research.variant_analysis)} variant candidate(s), "
                    f"{len(result.deep_research.knowledge_updates)} advisory knowledge update(s)."
                ),
                "safety_notes": [
                    "deep_reasoning_plan_only",
                    "no_exploit_generation",
                    "human_review_required_before_validation",
                ],
                "details": {
                    "agent_boundary": _source_audit_stage_boundary(
                        role="deep_research_agent",
                        allowed_actions=["plan_vulnerability_chains", "plan_variant_analysis"],
                        requires_human_review=True,
                    )
                },
            },
            {
                "name": "report_draft",
                "status": "human_review_required",
                "input_summary": "Report preview built from sanitized artifact metadata and claim ledger.",
                "output_summary": "Submission remains blocked until human evidence review.",
                "safety_notes": [
                    "submission_blocked",
                    "human_review_required",
                    "no_auto_submission",
                ],
                "details": {
                    "agent_boundary": {
                        "role": "report_draft",
                        "allowed_actions": ["draft_sanitized_report_preview"],
                        "blocked_actions": [
                            "execute_live_validation",
                            "touch_real_user_data",
                            "submit_report",
                            "bypass_scope_guard",
                        ],
                        "requires_human_review": True,
                        "execution_allowed": False,
                    }
                },
            },
        ],
        "safety_notes": [
            "scope_guard_required",
            "local_files_only",
            "no_live_requests",
            "no_auto_submission",
        ],
    }
    payload["timeline_stage_summary"] = _source_audit_timeline_stage_summary(payload)
    payload["safety_gate_summary"] = _source_audit_safety_gate_summary(payload)
    payload["audit_gate_summary"] = _source_audit_audit_gate_summary(result.audit_log)
    return payload


def _source_audit_stage_boundary(
    *,
    role: str,
    allowed_actions: list[str],
    requires_human_review: bool,
) -> dict:
    return {
        "role": role,
        "allowed_actions": allowed_actions,
        "blocked_actions": [
            "execute_live_validation",
            "touch_real_user_data",
            "submit_report",
            "bypass_scope_guard",
        ],
        "requires_human_review": requires_human_review,
        "execution_allowed": False,
    }


def _source_audit_timeline_stage_summary(payload: dict) -> list[dict]:
    timeline = payload.get("timeline", [])
    summaries: list[dict] = []
    for stage in timeline if isinstance(timeline, list) else []:
        if not isinstance(stage, dict):
            continue
        details = stage.get("details")
        boundary = (
            details.get("agent_boundary", {})
            if isinstance(details, dict)
            else {}
        )
        summaries.append(
            {
                "name": stage.get("name"),
                "status": stage.get("status"),
                "execution_allowed": bool(boundary.get("execution_allowed", False)),
                "human_review_required": bool(
                    boundary.get("requires_human_review", False)
                ),
            }
        )
    return summaries


def _source_audit_safety_gate_summary(payload: dict) -> dict:
    timeline_summary = _source_audit_timeline_stage_summary(payload)
    report_draft = payload.get("report_draft")
    report_draft = report_draft if isinstance(report_draft, dict) else {}
    safety_notes = payload.get("safety_notes")
    safety_notes = safety_notes if isinstance(safety_notes, list) else []
    return {
        "scope_guard_required": "scope_guard_required" in safety_notes,
        "execution_allowed": any(
            stage["execution_allowed"] is True
            for stage in timeline_summary
        ),
        "human_review_required": bool(
            report_draft.get("human_review_required", True)
            or any(stage["human_review_required"] for stage in timeline_summary)
        ),
        "auto_submit_allowed": bool(report_draft.get("auto_submit_allowed", False)),
    }


def _source_audit_audit_gate_summary(audit_log: list[dict]) -> dict:
    events = {
        event.get("event"): event
        for event in audit_log
        if isinstance(event, dict)
    }
    crs = events.get("crs_fuzzing_planned", {})
    v2 = events.get("authorized_bug_bounty_planned", {})
    v3 = events.get("industrial_scheduler_planned", {})
    v4 = events.get("deep_research_planned", {})
    return {
        "crash_promotion_gate": crs.get("crash_promotion_gate"),
        "crash_promotion_allowed": bool(crs.get("crash_promotion_allowed", False)),
        "blocked_preflight_checks": v2.get("blocked_preflight_checks", []),
        "blocked_transition_guard_count": int(
            v3.get("blocked_transition_guard_count", 0)
        ),
        "unresolved_refutation_count": int(
            v4.get("unresolved_refutation_count", 0)
        ),
    }


def evaluate_source_scope(repo_path: Path, scope_path: Path) -> ScopeCheck:
    if not repo_path.exists() or not repo_path.is_dir():
        return ScopeCheck(False, "repo_not_found", str(repo_path))

    policy = load_scope_policy(scope_path)
    allowed_repos = [
        Path(value).expanduser().resolve()
        for value in policy.get("allowed_repos", [])
        if isinstance(value, str) and value.strip()
    ]
    if not allowed_repos:
        return ScopeCheck(False, "missing_repo_allowlist", str(repo_path))

    if any(_is_path_within(repo_path, allowed) for allowed in allowed_repos):
        return ScopeCheck(True, "authorized local repository", str(repo_path))

    return ScopeCheck(False, "repo_not_allowlisted", str(repo_path))


def load_scope_policy(scope_path: str | Path) -> dict:
    path = Path(scope_path)
    if not path.exists():
        return {"allowed_repos": []}

    content = path.read_text(encoding="utf-8-sig").strip()
    if not content:
        return {"allowed_repos": []}
    if content.startswith("{"):
        data = json.loads(content)
        return data if isinstance(data, dict) else {"allowed_repos": []}
    return _parse_minimal_scope_yaml(content)


def collect_authorized_code_files(repo_path: Path) -> list[dict[str, str]]:
    files: list[dict[str, str]] = []
    for path in sorted(repo_path.rglob("*")):
        if len(files) >= MAX_AUTHORIZED_CODE_FILES:
            break
        if not path.is_file() or _path_has_skipped_part(path):
            continue
        if path.suffix.lower() not in CODE_EXTENSIONS:
            continue
        try:
            if path.stat().st_size > MAX_FILE_BYTES:
                continue
            content = path.read_text(encoding="utf-8-sig")
        except UnicodeDecodeError:
            continue
        files.append(
            {
                "path": _repo_relative_path(repo_path, path),
                "content": content,
            }
        )
    return files


def build_intake_profile(
    repo_path: Path,
    authorized_files: list[dict[str, str]],
    facts: list[CodebaseFactCandidate],
) -> IntakeProfile:
    languages = _detect_languages(repo_path, authorized_files)
    package_managers = _detect_package_managers(repo_path)
    frameworks = _detect_frameworks(repo_path, authorized_files)
    entrypoints = sorted(
        {
            f"{fact.route_method or 'GET'} {fact.route_path}"
            for fact in facts
            if fact.fact_type == "route_handler" and fact.route_path
        }
    )
    return IntakeProfile(
        languages=languages,
        frameworks=frameworks,
        package_managers=package_managers,
        entrypoints=entrypoints,
        file_count=len(authorized_files),
    )


def build_dependency_summary(repo_path: Path) -> DependencySummary:
    manifests: list[DependencyManifest] = []
    package_json = repo_path / "package.json"
    if package_json.exists():
        packages = _package_json_dependencies(package_json)
        manifests.append(
            DependencyManifest(
                path="package.json",
                ecosystem="npm",
                package_count=len(packages),
                packages=packages,
            )
        )

    requirements = repo_path / "requirements.txt"
    if requirements.exists():
        packages = _requirements_dependencies(requirements)
        manifests.append(
            DependencyManifest(
                path="requirements.txt",
                ecosystem="python",
                package_count=len(packages),
                packages=packages,
            )
        )

    go_mod = repo_path / "go.mod"
    if go_mod.exists():
        packages = _go_mod_dependencies(go_mod)
        manifests.append(
            DependencyManifest(
                path="go.mod",
                ecosystem="go",
                package_count=len(packages),
                packages=packages,
            )
        )

    return DependencySummary(manifests=manifests)


def run_semgrep(repo_path: Path) -> dict:
    command = ["semgrep", "--json", "--config", "auto", str(repo_path)]
    try:
        completed = subprocess.run(
            command,
            check=False,
            capture_output=True,
            text=True,
            timeout=120,
        )
    except FileNotFoundError:
        return {"status": "skipped", "results": [], "summary": "semgrep_not_installed"}
    except OSError:
        return {"status": "skipped", "results": [], "summary": "semgrep_unavailable"}
    except subprocess.TimeoutExpired:
        return {"status": "failed", "results": [], "summary": "semgrep_timeout"}

    try:
        payload = json.loads(completed.stdout or "{}")
    except json.JSONDecodeError:
        return {"status": "failed", "results": [], "summary": "semgrep_invalid_json"}

    status = "completed" if completed.returncode in {0, 1} else "failed"
    return {
        "status": status,
        "results": payload.get("results", []),
        "summary": "semgrep_json_normalized",
    }


def run_codeql(repo_path: Path) -> dict:
    return {
        "status": "skipped",
        "summary": "codeql_runner_not_configured",
    }


def build_codeql_scan(payload: dict) -> CodeQLScan:
    return CodeQLScan(
        status=safe_display_text(str(payload.get("status", "skipped"))),
        summary=safe_display_text(str(payload.get("summary", "codeql_runner_not_configured"))),
    )


def build_semgrep_scan(payload: dict) -> SemgrepScan:
    status = str(payload.get("status", "completed"))
    findings = normalize_semgrep_json(payload)
    summary = str(payload.get("summary", f"{len(findings)} finding(s) normalized"))
    return SemgrepScan(status=status, findings=findings, summary=safe_display_text(summary))


def normalize_semgrep_json(payload: dict) -> list[StaticFinding]:
    findings: list[StaticFinding] = []
    results = payload.get("results", [])
    if not isinstance(results, list):
        return findings

    for item in results:
        if not isinstance(item, dict):
            continue
        extra = item.get("extra") if isinstance(item.get("extra"), dict) else {}
        metadata = extra.get("metadata") if isinstance(extra.get("metadata"), dict) else {}
        start = item.get("start") if isinstance(item.get("start"), dict) else {}
        findings.append(
            StaticFinding(
                tool="semgrep",
                rule_id=safe_display_text(str(item.get("check_id", "unknown"))),
                file=safe_display_text(str(item.get("path", "unknown"))),
                line=_safe_int(start.get("line")),
                category=safe_display_text(str(metadata.get("category", "security"))),
                confidence=safe_display_text(str(metadata.get("confidence", "unknown")).lower()),
                message=safe_display_text(str(extra.get("message", ""))),
            )
        )
    return findings


def build_source_hypotheses(
    facts: list[CodebaseFactCandidate],
    findings: list[StaticFinding],
) -> list[VulnerabilityHypothesis]:
    hypotheses: list[VulnerabilityHypothesis] = []
    for fact in facts:
        if fact.fact_type != "authorization_gap_candidate":
            continue
        location = _route_location(fact)
        hypotheses.append(
            VulnerabilityHypothesis(
                hypothesis_id=f"H-{len(hypotheses) + 1:03d}",
                vuln_type="authorization",
                location=location,
                reason=(
                    "Mapped route reaches a sensitive operation without an obvious "
                    "handler-level authorization check."
                ),
                evidence_needed=[
                    "review service-layer ownership checks",
                    "two authorized local or test-account fixtures",
                    "redacted request/response diff before report use",
                ],
                false_positive_checks=[
                    *_fact_refutation_reasons(fact),
                    "authorization may be enforced in middleware or dependency injection",
                    "service layer may enforce object ownership before returning data",
                    "route may only expose public or self-owned resources",
                ],
                refutation_status=_fact_refutation_status(fact),
                priority_score=_fact_priority_score(fact),
                ranking_reasons=_fact_ranking_reasons(fact),
                safe_verification=True,
                risk="high",
            )
        )

    for finding in findings:
        if finding.category == "security" and len(hypotheses) < 5:
            hypotheses.append(
                VulnerabilityHypothesis(
                    hypothesis_id=f"H-{len(hypotheses) + 1:03d}",
                    vuln_type=_finding_vuln_type(finding),
                    location=f"{finding.file}:{finding.line or 1}",
                    reason=f"Semgrep flagged {finding.rule_id}; needs human review before validation.",
                    evidence_needed=[
                        "confirm reachable user input path",
                        "review local code context without copying secrets",
                        "write a non-destructive regression test if confirmed",
                    ],
                    false_positive_checks=[
                        "scanner match may be unreachable from user-controlled input",
                        "framework or service layer may sanitize the value before use",
                        "impact may be limited to local-only or non-sensitive behavior",
                    ],
                    refutation_status=_finding_refutation_status(finding),
                    priority_score=_finding_priority_score(finding),
                    ranking_reasons=_finding_ranking_reasons(finding),
                    safe_verification=True,
                    risk=_finding_risk(finding),
                )
            )

    return _ranked_hypotheses(hypotheses)


def _fact_refutation_status(fact: CodebaseFactCandidate) -> str:
    payload = fact.payload if isinstance(fact.payload, dict) else {}
    requested_status = payload.get("refutation_status")
    if requested_status in {"refuted", "parked", "unverified"}:
        return requested_status
    if fact.sensitivity_label.lower() in {"low", "info"}:
        return "parked"
    return "unverified"


def _fact_refutation_reasons(fact: CodebaseFactCandidate) -> list[str]:
    payload = fact.payload if isinstance(fact.payload, dict) else {}
    reason = payload.get("refutation_reason")
    if isinstance(reason, str) and reason.strip():
        return [safe_display_text(reason)]
    return []


def _finding_refutation_status(finding: StaticFinding) -> str:
    signals = f"{finding.rule_id} {finding.category} {finding.message}".lower()
    if "false positive" in signals or "refuted" in signals:
        return "refuted"
    if _finding_risk(finding) == "low":
        return "parked"
    return "unverified"


def _ranked_hypotheses(
    hypotheses: list[VulnerabilityHypothesis],
) -> list[VulnerabilityHypothesis]:
    ranked = sorted(
        hypotheses,
        key=lambda hypothesis: (
            -hypothesis.priority_score,
            hypothesis.refutation_status,
            hypothesis.location,
        ),
    )
    return [
        replace(hypothesis, hypothesis_id=f"H-{index + 1:03d}")
        for index, hypothesis in enumerate(ranked)
    ]


def _fact_priority_score(fact: CodebaseFactCandidate) -> int:
    status = _fact_refutation_status(fact)
    return _priority_score(
        risk="high",
        refutation_status=status,
        traceable_bonus=8,
        evidence_count=3,
        false_positive_check_count=len(
            [
                *_fact_refutation_reasons(fact),
                "authorization may be enforced in middleware or dependency injection",
                "service layer may enforce object ownership before returning data",
                "route may only expose public or self-owned resources",
            ]
        ),
    )


def _fact_ranking_reasons(fact: CodebaseFactCandidate) -> list[str]:
    status = _fact_refutation_status(fact)
    return [
        "traceable_source_fact",
        "broken_invariant:authorization",
        "evidence_needed:3",
        "false_positive_checks:present",
        f"refutation_status:{status}",
        "risk:high",
    ]


def _finding_priority_score(finding: StaticFinding) -> int:
    return _priority_score(
        risk=_finding_risk(finding),
        refutation_status=_finding_refutation_status(finding),
        traceable_bonus=4,
        evidence_count=3,
        false_positive_check_count=3,
    )


def _finding_ranking_reasons(finding: StaticFinding) -> list[str]:
    risk = _finding_risk(finding)
    status = _finding_refutation_status(finding)
    return [
        "traceable_static_finding",
        f"broken_invariant:{_finding_vuln_type(finding)}",
        "evidence_needed:3",
        "false_positive_checks:present",
        f"refutation_status:{status}",
        f"risk:{risk}",
    ]


def _priority_score(
    *,
    risk: str,
    refutation_status: str,
    traceable_bonus: int,
    evidence_count: int,
    false_positive_check_count: int,
) -> int:
    risk_base = {
        "critical": 95,
        "high": 80,
        "medium": 60,
        "low": 35,
        "info": 20,
    }.get(risk.lower(), 25)
    refutation_adjustment = {
        "unverified": 10,
        "parked": -10,
        "refuted": -30,
    }.get(refutation_status, 0)
    evidence_bonus = min(evidence_count, 3)
    false_positive_bonus = min(false_positive_check_count, 4)

    return max(0, min(100, risk_base + traceable_bonus + evidence_bonus + false_positive_bonus + refutation_adjustment))


def build_llm_review(
    *,
    reviewer: LLMReviewer | None,
    intake: IntakeProfile,
    semgrep: SemgrepScan,
    hypotheses: list[VulnerabilityHypothesis],
) -> LLMReview:
    if reviewer is None:
        return LLMReview(
            status="skipped",
            summary="llm_reviewer_not_configured",
        )

    payload = reviewer(
        {
            "intake": {
                "languages": intake.languages,
                "frameworks": intake.frameworks,
                "entrypoints": intake.entrypoints,
            },
            "semgrep_findings": [
                {
                    "rule_id": finding.rule_id,
                    "file": finding.file,
                    "line": finding.line,
                    "category": finding.category,
                    "confidence": finding.confidence,
                    "message": finding.message,
                }
                for finding in semgrep.findings[:10]
            ],
            "hypotheses": [
                {
                    "hypothesis_id": hypothesis.hypothesis_id,
                    "vuln_type": hypothesis.vuln_type,
                    "location": hypothesis.location,
                    "risk": hypothesis.risk,
                    "reason": hypothesis.reason,
                    "priority_score": hypothesis.priority_score,
                    "ranking_reasons": hypothesis.ranking_reasons,
                }
                for hypothesis in hypotheses[:10]
            ],
        }
    )
    return LLMReview(
        status=safe_display_text(str(payload.get("status", "completed"))),
        summary=safe_display_text(str(payload.get("summary", ""))),
    )


def build_finding_json(
    hypotheses: list[VulnerabilityHypothesis],
    findings: list[StaticFinding],
    scope: ScopeCheck,
) -> list[dict]:
    finding_refs = [
        f"semgrep:{finding.rule_id}:{finding.file}:{finding.line or 1}"
        for finding in findings[:5]
    ]
    return [
        {
            "finding_id": hypothesis.hypothesis_id,
            "title": f"{hypothesis.vuln_type} hypothesis at {hypothesis.location}",
            "vuln_type": hypothesis.vuln_type,
            "severity": hypothesis.risk,
            "confidence": "low",
            "status": "unverified_hypothesis",
            "affected_endpoint": hypothesis.location if " " in hypothesis.location else None,
            "root_cause": hypothesis.reason,
            "safe_reproduction": {
                "environment": "local_or_authorized_test_env",
                "requires_human_review": True,
            },
            "evidence_needed": hypothesis.evidence_needed,
            "false_positive_checks": hypothesis.false_positive_checks,
            "refutation_status": hypothesis.refutation_status,
            "priority_score": hypothesis.priority_score,
            "ranking_reasons": hypothesis.ranking_reasons,
            "evidence": finding_refs,
            "suggested_fix": "Review the root authorization or input handling boundary and add regression coverage if confirmed.",
            "regression_test": "Add a non-destructive local regression test for the confirmed boundary.",
            "scope_confirmation": scope.reason,
        }
        for hypothesis in hypotheses
    ]


def _source_audit_digest(result: SourceAuditResult) -> str:
    payload = {
        "repo_path": result.scope.repo_path,
        "scope_reason": result.scope.reason,
        "hypotheses": [
            {
                "hypothesis_id": hypothesis.hypothesis_id,
                "vuln_type": hypothesis.vuln_type,
                "location": hypothesis.location,
                "risk": hypothesis.risk,
                "priority_score": hypothesis.priority_score,
                "ranking_reasons": hypothesis.ranking_reasons,
            }
            for hypothesis in result.hypotheses
        ],
        "semgrep": [
            {
                "rule_id": finding.rule_id,
                "file": finding.file,
                "line": finding.line,
            }
            for finding in result.semgrep.findings
        ],
    }
    return sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def _source_audit_artifact_summary(result: SourceAuditResult) -> dict:
    return {
        "repo_path": safe_display_text(result.scope.repo_path),
        "language_count": len(result.intake.languages),
        "framework_count": len(result.intake.frameworks),
        "entrypoint_count": len(result.intake.entrypoints),
        "dependency_manifest_count": len(result.dependencies.manifests),
        "semgrep_finding_count": len(result.semgrep.findings),
        "hypothesis_count": len(result.hypotheses),
    }


def _source_audit_derived_facts(result: SourceAuditResult) -> dict:
    return {
        "languages": result.intake.languages,
        "frameworks": result.intake.frameworks,
        "entrypoints": result.intake.entrypoints,
        "dependency_manifests": [
            {
                "path": manifest.path,
                "ecosystem": manifest.ecosystem,
                "package_count": manifest.package_count,
            }
            for manifest in result.dependencies.manifests
        ],
        "hypotheses": [
            {
                "hypothesis_id": hypothesis.hypothesis_id,
                "vuln_type": hypothesis.vuln_type,
                "location": hypothesis.location,
                "risk": hypothesis.risk,
            }
            for hypothesis in result.hypotheses
        ],
        "semgrep_findings": [
            {
                "rule_id": finding.rule_id,
                "file": finding.file,
                "line": finding.line,
                "confidence": finding.confidence,
            }
            for finding in result.semgrep.findings[:10]
        ],
    }


def _source_audit_artifact_payload(artifact_record, *, evidence_count: int) -> dict:
    safety = artifact_record.provenance.get("safety", {})
    if not isinstance(safety, dict):
        safety = {}
    return {
        "artifact_id": artifact_record.id,
        "kind": artifact_record.kind,
        "source_type": artifact_record.source_type,
        "source": "authorized_local_repository",
        "provenance": "source_audit",
        "summary": "Source audit metadata imported from an authorized local repository.",
        "evidence_count": evidence_count,
        "digest": artifact_record.source_hash,
        "sensitivity_label": safety.get("sensitivity_label", "low"),
        "redaction_status": safety.get("redaction_status", "clean"),
        "report_chain_allowed": safety.get("report_chain_allowed", False),
        "safety_blockers": safety.get("safety_blockers", []),
    }


def _source_audit_usage_records(record, artifact_id: str) -> list[dict]:
    usage_records = [
        {
            "usage_type": "pipeline_run",
            "ref": f"run:{record.id}",
            "run_id": record.id,
            "stage": "pipeline_persistence",
        }
    ]

    evidence_bundle = record.payload.get("evidence_bundle")
    evidence_items = evidence_bundle.get("items", []) if isinstance(evidence_bundle, dict) else []
    for index, item in enumerate(evidence_items, start=1):
        if not isinstance(item, dict):
            continue
        usage_records.append(
            {
                "usage_type": "evidence_bundle",
                "ref": f"evidence:{record.id}:{index}",
                "run_id": record.id,
                "stage": "evidence_model",
                "evidence_type": safe_display_text(str(item.get("type", "evidence_item"))),
            }
        )

    try:
        preview = build_report_preview_response(record)
    except ValueError:
        return usage_records
    for claim in preview.claim_ledger:
        if artifact_id not in claim.provenance_refs:
            continue
        usage_records.append(
            {
                "usage_type": "report_claim",
                "ref": f"claim:{claim.claim_id}",
                "run_id": record.id,
                "stage": "report_preview",
                "claim_id": claim.claim_id,
                "claim_type": claim.claim_type,
            }
        )
    return usage_records


def _repo_display_name(repo_path: str) -> str:
    name = Path(repo_path).name or "authorized repository"
    return safe_display_text(name)


def _highest_hypothesis_risk(hypotheses: list[VulnerabilityHypothesis]) -> str:
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    risks = [hypothesis.risk.lower() for hypothesis in hypotheses]
    if not risks:
        return "info"
    return sorted(risks, key=lambda risk: order.get(risk, 99))[0]


def _source_audit_pipeline_hypotheses(result: SourceAuditResult) -> list[dict]:
    return [
        {
            "hypothesis_id": hypothesis.hypothesis_id,
            "hypothesis": (
                f"{hypothesis.vuln_type} hypothesis at {hypothesis.location}: "
                f"{hypothesis.reason}"
            ),
            "vuln_type": hypothesis.vuln_type,
            "location": hypothesis.location,
            "risk_level": hypothesis.risk,
            "broken_invariant": _broken_invariant_for_hypothesis(hypothesis),
            "evidence_needed": hypothesis.evidence_needed,
            "false_positive_checks": hypothesis.false_positive_checks,
            "refutation_status": hypothesis.refutation_status,
            "priority_score": hypothesis.priority_score,
            "ranking_reasons": hypothesis.ranking_reasons,
            "validation_mode": _validation_mode_for_hypothesis(hypothesis),
            "policy_risk": "low",
            "source": "source_audit",
        }
        for hypothesis in result.hypotheses
    ]


def _source_audit_target_model(result: SourceAuditResult) -> dict:
    endpoints: list[dict] = []
    for hypothesis in result.hypotheses:
        if " " not in hypothesis.location:
            continue
        method, path = hypothesis.location.split(" ", 1)
        ref = f"source_audit.{hypothesis.hypothesis_id}"
        endpoints.append(
            {
                "method": method,
                "path": path,
                "operation_id": hypothesis.hypothesis_id,
                "provenance_refs": [ref],
                "provenance_edges": [
                    {
                        "ref": ref,
                        "source_type": "source_audit",
                        "stage": "source_audit_import",
                        "source_path": path,
                        "source_method": method.lower(),
                        "fact_type": "endpoint",
                    }
                ],
            }
        )
    return {
        "endpoints": endpoints,
        "objects": [],
        "sensitive_actions": [],
        "relationships": [],
    }


def _broken_invariant_for_hypothesis(hypothesis: VulnerabilityHypothesis) -> str:
    if hypothesis.vuln_type == "authorization":
        return "Sensitive object access must be constrained by authentication, role, and ownership checks."
    if hypothesis.vuln_type == "injection":
        return "User-controlled input must not reach a sink without structured validation."
    if hypothesis.vuln_type == "ssrf":
        return "Server-side outbound requests must not be controlled by untrusted input."
    return "Every source-audit claim needs local evidence, refutation, and human review before promotion."


def _validation_mode_for_hypothesis(hypothesis: VulnerabilityHypothesis) -> str:
    if hypothesis.vuln_type == "authorization":
        return "two_account_authorization_check"
    return "local_code_review"


def _source_audit_hunter_assessment(hypothesis: dict, severity: str) -> dict:
    vuln_type = str(hypothesis.get("vuln_type", "source_audit"))
    playbook_id = "bola_idor" if vuln_type == "authorization" else "generic_logic"
    playbook_label = (
        "BOLA / IDOR object boundary"
        if playbook_id == "bola_idor"
        else "Generic source audit candidate"
    )
    return {
        "hypothesis": safe_display_text(str(hypothesis.get("hypothesis", "Source audit hypothesis"))),
        "playbook_id": playbook_id,
        "playbook_label": playbook_label,
        "hunter_priority_score": _hunter_priority_for_severity(severity),
        "impact_score": _impact_for_severity(severity),
        "duplicate_risk_score": 10,
        "policy_risk_score": 10,
        "rejection_risk_score": 35,
        "recommendation": "needs_human_review",
        "next_action": "Review source-audit evidence and attach sanitized manual observations.",
        "reasons": [
            "source_audit_import",
            "unverified_hypothesis",
            "human_review_required",
        ],
        "evidence_focus": [
            "local_code_reference",
            "request_response_diff",
            "human_review_decision",
        ],
        "safety_notes": [
            "advisory_only",
            "no_live_requests",
            "no_auto_submission",
        ],
    }


def _impact_for_severity(severity: str) -> int:
    return {
        "critical": 90,
        "high": 75,
        "medium": 55,
        "low": 35,
    }.get(severity, 20)


def _hunter_priority_for_severity(severity: str) -> int:
    return max(30, _impact_for_severity(severity) - 5)


def build_audit_log(
    *,
    scope: ScopeCheck,
    intake: IntakeProfile,
    dependencies: DependencySummary,
    semgrep: SemgrepScan,
    codeql: CodeQLScan,
    hypotheses: list[VulnerabilityHypothesis],
    llm_review: LLMReview,
    crs_fuzzing: CRSFuzzingPlan,
    authorized_bug_bounty: AuthorizedBugBountyPlan,
    industrial_scheduler: IndustrialSchedulerPlan,
    deep_research: DeepResearchPlan,
) -> list[dict]:
    return [
        {
            "event": "scope_checked",
            "status": "allowed" if scope.allowed else "blocked",
            "reason": scope.reason,
            "repo_path": scope.repo_path,
        },
        {
            "event": "intake_profiled",
            "languages": intake.languages,
            "frameworks": intake.frameworks,
            "entrypoint_count": len(intake.entrypoints),
        },
        {
            "event": "dependencies_read",
            "manifest_count": len(dependencies.manifests),
            "package_count": dependencies.package_count,
        },
        {
            "event": "semgrep_scanned",
            "status": semgrep.status,
            "finding_count": len(semgrep.findings),
        },
        {
            "event": "codeql_checked",
            "status": codeql.status,
            "summary": codeql.summary,
        },
        {
            "event": "hypotheses_generated",
            "hypothesis_count": len(hypotheses),
        },
        {
            "event": "crs_fuzzing_planned",
            "execution_mode": crs_fuzzing.execution_mode,
            "parser_candidate_count": len(crs_fuzzing.parser_candidates),
            "harness_plan_count": len(crs_fuzzing.harness_plans),
            "fuzzer_status": crs_fuzzing.fuzzer_plan.status,
            "crash_promotion_gate": crs_fuzzing.crash_promotion_gate.status,
            "crash_promotion_allowed": crs_fuzzing.crash_promotion_gate.promotion_allowed,
        },
        {
            "event": "authorized_bug_bounty_planned",
            "execution_mode": authorized_bug_bounty.execution_mode,
            "allowed_asset_count": len(authorized_bug_bounty.allowed_assets),
            "api_operation_count": len(authorized_bug_bounty.api_operations),
            "role_model_count": len(authorized_bug_bounty.role_models),
            "human_gate": authorized_bug_bounty.human_gate.status,
            "blocked_preflight_checks": _blocked_preflight_checks(
                authorized_bug_bounty
            ),
        },
        {
            "event": "industrial_scheduler_planned",
            "execution_mode": industrial_scheduler.execution_mode,
            "task_count": len(industrial_scheduler.dag_tasks),
            "parallel_batch_count": len(industrial_scheduler.parallel_batches),
            "finding_cluster_count": len(industrial_scheduler.finding_clusters),
            "risk_queue_count": len(industrial_scheduler.risk_queue),
            "blocked_transition_guard_count": _blocked_transition_guard_count(
                industrial_scheduler
            ),
        },
        {
            "event": "deep_research_planned",
            "execution_mode": deep_research.execution_mode,
            "reasoning_item_count": len(deep_research.cross_file_reasoning),
            "chain_count": len(deep_research.vulnerability_chains),
            "variant_count": len(deep_research.variant_analysis),
            "unresolved_refutation_count": _unresolved_refutation_count(
                deep_research
            ),
            "knowledge_update_count": len(deep_research.knowledge_updates),
        },
        {
            "event": "llm_reviewed",
            "status": llm_review.status,
        },
        {
            "event": "report_generated",
            "format": "markdown",
            "finding_json_count": len(hypotheses),
        },
    ]


def build_markdown_report(
    scope: ScopeCheck,
    intake: IntakeProfile,
    dependencies: DependencySummary,
    semgrep: SemgrepScan,
    codeql: CodeQLScan,
    hypotheses: list[VulnerabilityHypothesis],
    llm_review: LLMReview,
    crs_fuzzing: CRSFuzzingPlan,
    authorized_bug_bounty: AuthorizedBugBountyPlan,
    industrial_scheduler: IndustrialSchedulerPlan,
    deep_research: DeepResearchPlan,
) -> str:
    lines = [
        "# Source Audit Report",
        "",
        "## Scope Confirmation",
        f"- Status: {'allowed' if scope.allowed else 'blocked'}",
        f"- Reason: {scope.reason}",
        f"- Repository: {scope.repo_path}",
        "- Safety: local files only; no network validation, exploit execution, or report submission.",
        "",
        "## Intake",
        f"- Languages: {_join_or_none(intake.languages)}",
        f"- Frameworks: {_join_or_none(intake.frameworks)}",
        f"- Package managers: {_join_or_none(intake.package_managers)}",
        f"- Code files reviewed: {intake.file_count}",
        f"- Entrypoints: {_join_or_none(intake.entrypoints)}",
        "",
        "## Dependencies",
        f"- Manifests: {len(dependencies.manifests)}",
        f"- Packages indexed: {dependencies.package_count}",
    ]
    for manifest in dependencies.manifests:
        lines.append(
            f"- {manifest.path} ({manifest.ecosystem}): {manifest.package_count} package(s)"
        )
    lines.extend(
        [
            "",
        "## Semgrep",
        f"- Status: {semgrep.status}",
        f"- Summary: {semgrep.summary}",
        f"- Findings normalized: {len(semgrep.findings)}",
        ]
    )
    for finding in semgrep.findings[:10]:
        lines.append(
            f"- {finding.rule_id} at {finding.file}:{finding.line or 1} "
            f"({finding.confidence}) - {finding.message or 'review required'}"
        )

    lines.extend(
        [
            "",
            "## CodeQL",
            f"- Status: {codeql.status}",
            f"- Summary: {codeql.summary}",
            "",
            "## CRS + Fuzzing",
            f"- Stage: {crs_fuzzing.stage}",
            f"- Inspirations: {_join_or_none(crs_fuzzing.inspirations)}",
            f"- Execution mode: {crs_fuzzing.execution_mode}",
            f"- Parser candidates: {len(crs_fuzzing.parser_candidates)}",
            f"- Harness plans: {len(crs_fuzzing.harness_plans)}",
            f"- Fuzzer status: {crs_fuzzing.fuzzer_plan.status}",
            f"- Crash triage: {crs_fuzzing.crash_triage.status}",
            f"- Crash promotion gate: {crs_fuzzing.crash_promotion_gate.status}",
            "- Safety: plan only; no fuzz execution, no public target scanning, no destructive validation.",
            "",
            "## Authorized Bug Bounty",
            f"- Stage: {authorized_bug_bounty.stage}",
            f"- Inspirations: {_join_or_none(authorized_bug_bounty.inspirations)}",
            f"- Execution mode: {authorized_bug_bounty.execution_mode}",
            f"- Allowed assets: {len(authorized_bug_bounty.allowed_assets)}",
            f"- API operations modeled: {len(authorized_bug_bounty.api_operations)}",
            f"- Test-account roles modeled: {len(authorized_bug_bounty.role_models)}",
            f"- Role diff plans: {len(authorized_bug_bounty.role_diff_plans)}",
            f"- Candidate issues: {len(authorized_bug_bounty.business_logic_candidates)}",
            f"- Human gate: {authorized_bug_bounty.human_gate.status}",
            f"- Validation preflight blocked checks: {_join_or_none(_blocked_preflight_checks(authorized_bug_bounty))}",
            "- Safety: plan only; no external requests, no credential storage, no report submission.",
            "",
            "## Industrial Scheduling",
            f"- Stage: {industrial_scheduler.stage}",
            f"- Inspirations: {_join_or_none(industrial_scheduler.inspirations)}",
            f"- Execution mode: {industrial_scheduler.execution_mode}",
            f"- DAG tasks: {len(industrial_scheduler.dag_tasks)}",
            f"- Parallel batches: {len(industrial_scheduler.parallel_batches)}",
            f"- Finding clusters: {len(industrial_scheduler.finding_clusters)}",
            f"- Risk queue items: {len(industrial_scheduler.risk_queue)}",
            f"- Continuous scan: {industrial_scheduler.continuous_scan.status}",
            f"- Patch validation: {industrial_scheduler.patch_validation.status}",
            f"- Lifecycle transition guards: {_blocked_transition_guard_count(industrial_scheduler)} blocked",
            "- Safety: plan only; no unscoped agent execution, no automatic report submission.",
            "",
            "## Deep Research",
            f"- Stage: {deep_research.stage}",
            f"- Inspirations: {_join_or_none(deep_research.inspirations)}",
            f"- Execution mode: {deep_research.execution_mode}",
            f"- Permission model: {deep_research.permission_model.status}",
            f"- Cross-file reasoning items: {len(deep_research.cross_file_reasoning)}",
            f"- Vulnerability chains: {len(deep_research.vulnerability_chains)}",
            f"- Variant candidates: {len(deep_research.variant_analysis)}",
            f"- Protocol-aware fuzzing plans: {len(deep_research.protocol_aware_fuzzing)}",
            f"- Evidence graph nodes: {len(deep_research.evidence_graph.nodes)}",
            f"- Knowledge queue items: {len(deep_research.knowledge_consolidation_queue)}",
            f"- Knowledge updates: {len(deep_research.knowledge_updates)}",
            f"- Refutation matrix: {_unresolved_refutation_count(deep_research)} unresolved chain(s) require human review",
            "- Safety: plan only; no exploit generation, no validation without human review.",
            "",
            "## Hypotheses",
        ]
    )
    if not hypotheses:
        lines.append("- No high-signal vulnerability hypotheses generated from the current inputs.")
    for hypothesis in hypotheses:
        lines.extend(
            [
                f"### {hypothesis.hypothesis_id}: {hypothesis.vuln_type}",
                f"- Location: {hypothesis.location}",
                f"- Risk: {hypothesis.risk}",
                f"- Priority score: {hypothesis.priority_score}",
                f"- Ranking reasons: {_join_or_none(hypothesis.ranking_reasons)}",
                f"- Reason: {hypothesis.reason}",
                f"- Safe verification: {'yes' if hypothesis.safe_verification else 'no'}",
                f"- Evidence needed: {_join_or_none(hypothesis.evidence_needed)}",
                f"- False positive checks: {_join_or_none(hypothesis.false_positive_checks)}",
                f"- Refutation status: {hypothesis.refutation_status}",
            ]
        )

    lines.extend(
        [
            "",
            "## LLM Review",
            f"- Status: {llm_review.status}",
            f"- Summary: {llm_review.summary}",
        ]
    )
    lines.extend(
        [
            "",
            "## Human Review Gate",
            "- Treat every item as an unverified hypothesis until reviewed with redacted evidence.",
            "- Do not submit reports automatically.",
            "",
        ]
    )
    return "\n".join(lines)


def _blocked_preflight_checks(plan: AuthorizedBugBountyPlan) -> list[str]:
    return [
        check.check
        for check in plan.validation_preflight
        if check.status == "blocked"
    ]


def _blocked_transition_guard_count(plan: IndustrialSchedulerPlan) -> int:
    return sum(
        1
        for guard in plan.lifecycle.transition_guards
        if guard.status == "blocked_until_gates_satisfied"
    )


def _unresolved_refutation_count(plan: DeepResearchPlan) -> int:
    return sum(
        1
        for item in plan.refutation_matrix
        if item.status == "unresolved_requires_human_review"
    )


def safe_display_text(value: str) -> str:
    normalized = value.strip()
    lowered = normalized.lower()
    if any(marker in lowered for marker in SECRET_MARKERS):
        return "[REDACTED]"
    return normalized[:240]


def _package_json_dependencies(path: Path) -> list[str]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError):
        return []
    packages: set[str] = set()
    if isinstance(data, dict):
        for key in ("dependencies", "devDependencies"):
            values = data.get(key)
            if isinstance(values, dict):
                packages.update(str(name) for name in values if isinstance(name, str))
    return sorted(safe_display_text(package) for package in packages)


def _requirements_dependencies(path: Path) -> list[str]:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except UnicodeDecodeError:
        return []
    packages: list[str] = []
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or stripped.startswith("-"):
            continue
        package = stripped.split("==", 1)[0].split(">=", 1)[0].split("<=", 1)[0].strip()
        if package:
            packages.append(safe_display_text(package))
    return sorted(set(packages))


def _go_mod_dependencies(path: Path) -> list[str]:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except UnicodeDecodeError:
        return []
    packages: list[str] = []
    in_require_block = False
    for raw_line in lines:
        line = raw_line.strip()
        if line == "require (":
            in_require_block = True
            continue
        if in_require_block and line == ")":
            in_require_block = False
            continue
        if line.startswith("require "):
            parts = line.split()
            if len(parts) >= 2:
                packages.append(safe_display_text(parts[1]))
        elif in_require_block and line:
            parts = line.split()
            if parts:
                packages.append(safe_display_text(parts[0]))
    return sorted(set(packages))


def _parse_minimal_scope_yaml(content: str) -> dict:
    allowed_repos: list[str] = []
    bug_bounty: dict[str, list] = {}
    section: str | None = None
    nested_section: str | None = None
    current_account: dict[str, str] | None = None
    for raw_line in content.splitlines():
        stripped = raw_line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        indent = len(raw_line) - len(raw_line.lstrip(" "))
        if indent == 0:
            current_account = None
            nested_section = None
            if stripped == "allowed_repos:":
                section = "allowed_repos"
                continue
            if stripped == "bug_bounty:":
                section = "bug_bounty"
                continue
            section = None
            continue

        if section == "allowed_repos" and stripped.startswith("- "):
            allowed_repos.append(_strip_yaml_scalar(stripped[2:]))
            continue

        if section != "bug_bounty":
            continue
        if indent == 2 and stripped.endswith(":"):
            nested_section = stripped[:-1]
            current_account = None
            if nested_section in {"allowed_assets", "allowed_domains", "test_accounts"}:
                bug_bounty.setdefault(nested_section, [])
            continue
        if nested_section in {"allowed_assets", "allowed_domains"} and stripped.startswith("- "):
            bug_bounty[nested_section].append(_strip_yaml_scalar(stripped[2:]))
            continue
        if nested_section == "test_accounts":
            if stripped.startswith("- "):
                current_account = {}
                bug_bounty[nested_section].append(current_account)
                _set_yaml_mapping_value(current_account, stripped[2:])
                continue
            if current_account is not None:
                _set_yaml_mapping_value(current_account, stripped)

    policy: dict[str, object] = {"allowed_repos": allowed_repos}
    cleaned_bug_bounty = {key: value for key, value in bug_bounty.items() if value}
    if cleaned_bug_bounty:
        policy["bug_bounty"] = cleaned_bug_bounty
    return policy


def _strip_yaml_scalar(value: str) -> str:
    return value.strip().strip('"').strip("'")


def _set_yaml_mapping_value(target: dict[str, str], value: str) -> None:
    if ":" not in value:
        return
    key, raw_scalar = value.split(":", 1)
    key = key.strip()
    if not key:
        return
    target[key] = _strip_yaml_scalar(raw_scalar)


def _is_path_within(path: Path, root: Path) -> bool:
    return path == root or root in path.parents


def _path_has_skipped_part(path: Path) -> bool:
    return any(part in SKIPPED_DIRECTORIES for part in path.parts)


def _repo_relative_path(repo_path: Path, path: Path) -> str:
    return path.relative_to(repo_path).as_posix()


def _detect_languages(repo_path: Path, authorized_files: list[dict[str, str]]) -> list[str]:
    extensions = {Path(item["path"]).suffix.lower() for item in authorized_files}
    languages: list[str] = []
    if ".py" in extensions or (repo_path / "requirements.txt").exists():
        languages.append("Python")
    if extensions & {".js", ".jsx", ".ts", ".tsx"} or (repo_path / "package.json").exists():
        languages.append("TypeScript/JavaScript")
    if ".go" in extensions or (repo_path / "go.mod").exists():
        languages.append("Go")
    return languages


def _detect_package_managers(repo_path: Path) -> list[str]:
    managers: list[str] = []
    if (repo_path / "package.json").exists():
        managers.append("npm")
    if (repo_path / "requirements.txt").exists() or (repo_path / "pyproject.toml").exists():
        managers.append("pip")
    if (repo_path / "go.mod").exists():
        managers.append("go")
    return managers


def _detect_frameworks(repo_path: Path, authorized_files: list[dict[str, str]]) -> list[str]:
    text = "\n".join(item["content"][:4_000] for item in authorized_files).lower()
    package_json = _read_text_if_exists(repo_path / "package.json").lower()
    requirements = _read_text_if_exists(repo_path / "requirements.txt").lower()
    frameworks: list[str] = []
    if "fastapi" in text or "fastapi" in requirements:
        frameworks.append("FastAPI")
    if "django" in text or "django" in requirements:
        frameworks.append("Django")
    if '"next"' in package_json or "next" in package_json:
        frameworks.append("Next.js")
    if "express" in text or '"express"' in package_json:
        frameworks.append("Express")
    return frameworks


def _read_text_if_exists(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8") if path.exists() else ""
    except UnicodeDecodeError:
        return ""


def _route_location(fact: CodebaseFactCandidate) -> str:
    method = fact.route_method or "GET"
    path = fact.route_path or fact.source_path
    return f"{method} {path}"


def _finding_vuln_type(finding: StaticFinding) -> str:
    signals = f"{finding.rule_id} {finding.category} {finding.message}".lower()
    if "injection" in signals or "sql" in signals:
        return "injection"
    if "ssrf" in signals:
        return "ssrf"
    if "auth" in signals:
        return "authorization"
    return "static-analysis"


def _finding_risk(finding: StaticFinding) -> str:
    if finding.confidence == "high":
        return "medium"
    return "low"


def _safe_int(value: object) -> int | None:
    return value if isinstance(value, int) else None


def _join_or_none(values: list[str]) -> str:
    return ", ".join(values) if values else "none"
