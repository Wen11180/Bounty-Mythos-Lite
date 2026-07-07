from __future__ import annotations

from dataclasses import dataclass, field
import json
from pathlib import Path
import subprocess
from typing import Protocol

from app.codebase_map import CodebaseFactCandidate, map_authorized_code_files


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
class VulnerabilityHypothesis:
    hypothesis_id: str
    vuln_type: str
    location: str
    reason: str
    evidence_needed: list[str]
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
    semgrep: SemgrepScan
    hypotheses: list[VulnerabilityHypothesis]
    llm_review: LLMReview
    report_markdown: str


def run_source_audit(
    repo_path: str | Path,
    scope_path: str | Path,
    *,
    semgrep_runner: SemgrepRunner | None = None,
    llm_reviewer: LLMReviewer | None = None,
) -> SourceAuditResult:
    repo = Path(repo_path).resolve()
    scope = evaluate_source_scope(repo, Path(scope_path))
    if not scope.allowed:
        raise SourceAuditBlocked(scope.reason)

    authorized_files = collect_authorized_code_files(repo)
    codebase_map = map_authorized_code_files({"authorized_code_files": authorized_files})
    intake = build_intake_profile(repo, authorized_files, codebase_map.facts)
    semgrep = build_semgrep_scan(
        semgrep_runner(repo) if semgrep_runner is not None else run_semgrep(repo)
    )
    hypotheses = build_source_hypotheses(codebase_map.facts, semgrep.findings)
    llm_review = build_llm_review(
        reviewer=llm_reviewer,
        intake=intake,
        semgrep=semgrep,
        hypotheses=hypotheses,
    )
    report = build_markdown_report(scope, intake, semgrep, hypotheses, llm_review)
    return SourceAuditResult(
        scope=scope,
        intake=intake,
        semgrep=semgrep,
        hypotheses=hypotheses,
        llm_review=llm_review,
        report_markdown=report,
    )


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
            content = path.read_text(encoding="utf-8")
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
                    safe_verification=True,
                    risk=_finding_risk(finding),
                )
            )

    return hypotheses


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
                }
                for hypothesis in hypotheses[:10]
            ],
        }
    )
    return LLMReview(
        status=safe_display_text(str(payload.get("status", "completed"))),
        summary=safe_display_text(str(payload.get("summary", ""))),
    )


def build_markdown_report(
    scope: ScopeCheck,
    intake: IntakeProfile,
    semgrep: SemgrepScan,
    hypotheses: list[VulnerabilityHypothesis],
    llm_review: LLMReview,
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
        "## Semgrep",
        f"- Status: {semgrep.status}",
        f"- Summary: {semgrep.summary}",
        f"- Findings normalized: {len(semgrep.findings)}",
    ]
    for finding in semgrep.findings[:10]:
        lines.append(
            f"- {finding.rule_id} at {finding.file}:{finding.line or 1} "
            f"({finding.confidence}) - {finding.message or 'review required'}"
        )

    lines.extend(["", "## Hypotheses"])
    if not hypotheses:
        lines.append("- No high-signal vulnerability hypotheses generated from the current inputs.")
    for hypothesis in hypotheses:
        lines.extend(
            [
                f"### {hypothesis.hypothesis_id}: {hypothesis.vuln_type}",
                f"- Location: {hypothesis.location}",
                f"- Risk: {hypothesis.risk}",
                f"- Reason: {hypothesis.reason}",
                f"- Safe verification: {'yes' if hypothesis.safe_verification else 'no'}",
                f"- Evidence needed: {_join_or_none(hypothesis.evidence_needed)}",
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


def safe_display_text(value: str) -> str:
    normalized = value.strip()
    lowered = normalized.lower()
    if any(marker in lowered for marker in SECRET_MARKERS):
        return "[REDACTED]"
    return normalized[:240]


def _parse_minimal_scope_yaml(content: str) -> dict:
    allowed_repos: list[str] = []
    in_allowed_repos = False
    for raw_line in content.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line == "allowed_repos:":
            in_allowed_repos = True
            continue
        if in_allowed_repos and line.startswith("- "):
            allowed_repos.append(_strip_yaml_scalar(line[2:]))
            continue
        in_allowed_repos = False
    return {"allowed_repos": allowed_repos}


def _strip_yaml_scalar(value: str) -> str:
    return value.strip().strip('"').strip("'")


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
