"""Fixed, offline-only adapters for registered local analysis tools."""

from __future__ import annotations

import json
import re
import tempfile
from hashlib import sha256
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.codeql_runner import run_local_codeql
from app.dependency_agent import (
    STATUS_EMPTY as DEPENDENCY_STATUS_EMPTY,
    STATUS_OK as DEPENDENCY_STATUS_OK,
    STATUS_SKIPPED as DEPENDENCY_STATUS_SKIPPED,
    DependencyProfile,
    build_dependency_profile,
    dependency_input_manifest_matches,
)
from app.semgrep_runner import run_local_semgrep

from . import (
    ExecutionAuthorizationDecision,
    ExecutionAuthorizationRequest,
    ExecutionRegistry,
    authorize_tool_execution,
)


LocalToolRunStatus = Literal["blocked", "completed", "failed", "skipped"]
_SAFE_RULE_ID = re.compile(
    r"^(?=.{1,128}$)(?!\.{1,2}(?:/|$))(?!.*(?:/)\.{1,2}(?:/|$))"
    r"[A-Za-z0-9_.:-]+(?:/[A-Za-z0-9_.:-]+)*$",
    re.ASCII,
)
_EMBEDDED_SEMGREP_CONFIG_NAME = re.compile(
    r"mythos-semgrep-[A-Za-z0-9_-]+\.yml",
    re.ASCII,
)
_CODEQL_TEMP_SARIF_RELATIVE_PATH = re.compile(
    r"mythos-codeql-[A-Za-z0-9_-]+[\\/]results\.sarif",
    re.ASCII,
)
_SAFE_DEPENDENCY_VALUE = re.compile(
    r"^[@A-Za-z0-9][A-Za-z0-9._+/@:~^<>=*|\-]{0,199}$",
    re.ASCII,
)
_SAFE_DEPENDENCY_PATH = re.compile(
    r"^(?!.*(?:^|/)\.{1,2}(?:/|$))[A-Za-z0-9][A-Za-z0-9._+/@\-]{0,499}$",
    re.ASCII,
)
_SECRET_SHAPED_DEPENDENCY_VALUE = re.compile(
    r"\bbearer\s+\S+|\b(?:api[_-]?key|access[_-]?token|authorization|"
    r"password|secret|token|cookie|credential)\s*[:=]",
    re.IGNORECASE,
)
_BARE_TOKEN_SHAPED_DEPENDENCY_VALUE = re.compile(
    r"(?:gh[pousr]_[A-Za-z0-9_]{16,}|github_pat_[A-Za-z0-9_]{16,}|"
    r"(?:AKIA|ASIA)[0-9A-Z]{16}|xox[baprs]-[A-Za-z0-9-]{10,}|"
    r"sk-[A-Za-z0-9_-]{20,}|AIza[A-Za-z0-9_-]{20,}|ya29\.[A-Za-z0-9._-]{20,}|"
    r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,})",
    re.IGNORECASE,
)
_SHA256_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$", re.ASCII)


class RegisteredDependencyProfile(BaseModel):
    """Redacted local dependency-profile summary retained for audit only."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    status: Literal[
        "dependency_profile_ready",
        "dependency_no_artifacts",
        "dependency_package_missing",
    ]
    component_count: int = Field(ge=0, le=200)
    manifest_count: int = Field(ge=0, le=40)
    reachable_count: int = Field(ge=0, le=200)
    advisory_flagged_count: int = Field(ge=0, le=200)
    high_priority_count: int = Field(ge=0, le=200)
    ecosystems: list[str] = Field(default_factory=list, max_length=20)
    network_access: Literal[False] = False
    live_advisory_lookup: Literal[False] = False
    execution_allowed: Literal[False] = False
    validation_allowed: Literal[False] = False
    candidate_promotion_allowed: Literal[False] = False
    report_submission_allowed: Literal[False] = False

    @field_validator("ecosystems")
    @classmethod
    def require_safe_ecosystems(cls, values: list[str]) -> list[str]:
        if any(
            _SAFE_DEPENDENCY_VALUE.fullmatch(value) is None
            or _is_secret_shaped_dependency_value(value)
            for value in values
        ):
            raise ValueError("safe_dependency_ecosystem_required")
        return sorted(set(values))


class RegisteredDependencyAdvisory(BaseModel):
    """A locally reachable, explicitly supplied offline advisory reference."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    package: str = Field(min_length=1, max_length=200)
    version: str = Field(min_length=1, max_length=200)
    ecosystem: str = Field(min_length=1, max_length=200)
    advisory_id: str = Field(min_length=1, max_length=200)
    priority: Literal["critical", "high", "medium", "low", "info"]
    source_paths: list[str] = Field(min_length=1, max_length=20)

    @field_validator("package", "version", "ecosystem", "advisory_id")
    @classmethod
    def require_safe_value(cls, value: str) -> str:
        if (
            _SAFE_DEPENDENCY_VALUE.fullmatch(value) is None
            or _is_secret_shaped_dependency_value(value)
        ):
            raise ValueError("safe_dependency_value_required")
        return value

    @field_validator("source_paths")
    @classmethod
    def require_safe_paths(cls, values: list[str]) -> list[str]:
        if any(
            _SAFE_DEPENDENCY_PATH.fullmatch(value) is None
            or _is_secret_shaped_dependency_value(value)
            for value in values
        ):
            raise ValueError("safe_dependency_path_required")
        return sorted(set(values))


class RegisteredDependencyInput(BaseModel):
    """One dependency-profile input pinned to the approved workspace snapshot."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    source_path: str = Field(min_length=1, max_length=500)
    content_digest: str = Field(min_length=71, max_length=71)

    @field_validator("source_path")
    @classmethod
    def require_safe_source_path(cls, value: str) -> str:
        if (
            _SAFE_DEPENDENCY_PATH.fullmatch(value) is None
            or _is_secret_shaped_dependency_value(value)
        ):
            raise ValueError("safe_dependency_path_required")
        return value

    @field_validator("content_digest")
    @classmethod
    def require_content_digest(cls, value: str) -> str:
        if _SHA256_DIGEST.fullmatch(value.lower()) is None:
            raise ValueError("dependency_content_digest_required")
        return value.lower()


class RegisteredLocalToolRunRequest(BaseModel):
    """A local package root supplied by a trusted campaign-snapshot resolver."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    authorization: ExecutionAuthorizationRequest
    package_root: str = Field(min_length=1, max_length=1000)
    package_id: str = Field(default="", max_length=255)
    timeout_s: int = Field(default=180, ge=5, le=600)
    dependency_input_manifest: list[RegisteredDependencyInput] | None = Field(
        default=None,
        max_length=1_200,
    )


class RegisteredLocalToolRun(BaseModel):
    """Sanitized local-run metadata; findings remain advisory evidence only."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    tool_id: str
    status: LocalToolRunStatus
    runner_status: str | None = None
    command_hash: str
    command_executed: bool = False
    finding_count: int = Field(default=0, ge=0)
    advisory_findings: list[dict[str, str | int]] = Field(default_factory=list, max_length=200)
    dependency_profile: RegisteredDependencyProfile | None = None
    dependency_advisories: list[RegisteredDependencyAdvisory] = Field(
        default_factory=list,
        max_length=100,
    )
    authorization: ExecutionAuthorizationDecision
    safety_gate_state: str
    execution_allowed: Literal[False] = False
    validation_allowed: Literal[False] = False
    candidate_promotion_allowed: Literal[False] = False
    report_submission_allowed: Literal[False] = False
    confirmed_vulnerability: Literal[False] = False


def run_registered_local_tool(
    request: RegisteredLocalToolRunRequest,
    *,
    registry: ExecutionRegistry | None = None,
    semgrep_subprocess_runner: Any | None = None,
    codeql_subprocess_runner: Any | None = None,
) -> RegisteredLocalToolRun:
    """Run one allowlisted local adapter after registry authorization."""
    decision = authorize_tool_execution(request.authorization, registry=registry)
    if not decision.eligible:
        return _blocked_run(request, decision)
    if decision.execution_tier != "local" or not decision.dispatch_allowed:
        return _blocked_run(request, decision, safety_gate_state="blocked")

    tool_id = request.authorization.tool_id
    if tool_id == "semgrep_local":
        runner_result = run_local_semgrep(
            package_root=request.package_root,
            package_id=request.package_id,
            human_allow_local_semgrep=True,
            timeout_s=request.timeout_s,
            subprocess_runner=semgrep_subprocess_runner,
        )
    elif tool_id == "codeql_local":
        runner_result = run_local_codeql(
            package_root=request.package_root,
            package_id=request.package_id,
            human_allow_local_codeql=True,
            timeout_s=request.timeout_s,
            subprocess_runner=codeql_subprocess_runner,
        )
    elif tool_id == "dependency_sbom_local":
        profile = _snapshot_bound_dependency_profile(request)
        if profile is None:
            return _blocked_run(
                request,
                decision,
                safety_gate_state="blocked",
                runner_status="dependency_snapshot_invalid",
            )
        profile_summary = _dependency_profile_summary(profile)
        advisories = _dependency_advisories(profile)
        profile_executed = profile.status != DEPENDENCY_STATUS_SKIPPED
        return RegisteredLocalToolRun(
            tool_id=tool_id,
            status="completed" if profile_executed else "skipped",
            runner_status=(
                "dependency_sbom_local_completed"
                if profile_executed
                else "dependency_sbom_local_skipped"
            ),
            command_hash=_command_hash(["dependency_sbom_local:offline_profile_v1"]),
            command_executed=profile_executed,
            finding_count=len(advisories),
            dependency_profile=profile_summary,
            dependency_advisories=advisories,
            authorization=decision,
            safety_gate_state="allowed",
        )
    else:
        return _blocked_run(request, decision, safety_gate_state="blocked")

    runner_status = str(runner_result.status)
    return RegisteredLocalToolRun(
        tool_id=tool_id,
        status=_run_status(runner_status),
        runner_status=runner_status,
        command_hash=_command_hash(
            runner_result.command,
            tool_id=tool_id,
            package_root=request.package_root,
            embedded_semgrep_rules=(
                tool_id == "semgrep_local"
                and getattr(runner_result, "config_source", None)
                == "embedded_offline_rules"
            ),
        ),
        command_executed=bool(runner_result.command_executed),
        finding_count=max(0, int(runner_result.finding_count)),
        advisory_findings=_advisory_findings(
            runner_result.findings,
            package_root=request.package_root,
        ),
        authorization=decision,
        safety_gate_state="allowed",
    )


def _blocked_run(
    request: RegisteredLocalToolRunRequest,
    decision: ExecutionAuthorizationDecision,
    *,
    safety_gate_state: str = "blocked",
    runner_status: str | None = None,
) -> RegisteredLocalToolRun:
    return RegisteredLocalToolRun(
        tool_id=request.authorization.tool_id,
        status="blocked",
        runner_status=runner_status,
        command_hash=_command_hash([]),
        authorization=decision,
        safety_gate_state=safety_gate_state,
    )


def _run_status(runner_status: str) -> LocalToolRunStatus:
    if runner_status.endswith("_completed"):
        return "completed"
    if runner_status.endswith("_failed"):
        return "failed"
    return "skipped"


def _snapshot_bound_dependency_profile(
    request: RegisteredLocalToolRunRequest,
) -> DependencyProfile | None:
    manifest = request.dependency_input_manifest
    if manifest is None:
        return None
    manifest_entries = [entry.model_dump(mode="json") for entry in manifest]
    if not dependency_input_manifest_matches(request.package_root, manifest_entries):
        return None
    try:
        source_root = Path(request.package_root).resolve(strict=True)
    except OSError:
        return None
    if not source_root.is_dir():
        return None

    with tempfile.TemporaryDirectory(prefix="mythos-dependency-snapshot-") as directory:
        snapshot_root = Path(directory)
        for entry in manifest:
            try:
                source = (source_root / entry.source_path).resolve(strict=True)
                source.relative_to(source_root)
                raw = source.read_bytes()
            except (OSError, ValueError):
                return None
            if "sha256:" + sha256(raw).hexdigest() != entry.content_digest:
                return None
            destination = snapshot_root.joinpath(*entry.source_path.split("/"))
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(raw)
        return build_dependency_profile(
            package_root=snapshot_root,
            package_id=request.package_id,
        )


def _dependency_profile_summary(profile: DependencyProfile) -> RegisteredDependencyProfile:
    status = profile.status
    if status not in {
        DEPENDENCY_STATUS_OK,
        DEPENDENCY_STATUS_EMPTY,
        DEPENDENCY_STATUS_SKIPPED,
    }:
        status = DEPENDENCY_STATUS_SKIPPED
    ecosystems = [
        ecosystem
        for ecosystem in profile.ecosystems
        if _safe_dependency_value(ecosystem)
    ]
    return RegisteredDependencyProfile(
        status=status,
        component_count=min(200, max(0, int(profile.component_count))),
        manifest_count=min(40, max(0, len(profile.manifests))),
        reachable_count=min(200, max(0, int(profile.reachable_count))),
        advisory_flagged_count=min(200, max(0, int(profile.advisory_flagged_count))),
        high_priority_count=min(200, max(0, int(profile.high_priority_count))),
        ecosystems=ecosystems,
    )


def _dependency_advisories(
    profile: DependencyProfile,
) -> list[RegisteredDependencyAdvisory]:
    advisories: list[RegisteredDependencyAdvisory] = []
    for component in profile.components:
        if not component.known_advisory or component.reachable != "yes":
            continue
        package = _safe_dependency_value(component.package)
        version = _safe_dependency_value(component.version)
        ecosystem = _safe_dependency_value(component.ecosystem)
        source_paths = _safe_dependency_paths(component.used_by)
        if not package or not version or not ecosystem or not source_paths:
            continue
        priority = (
            component.priority
            if component.priority in {"critical", "high", "medium", "low", "info"}
            else "info"
        )
        for advisory_id in component.advisory_ids[:10]:
            safe_advisory_id = _safe_dependency_value(advisory_id)
            if not safe_advisory_id:
                continue
            advisories.append(
                RegisteredDependencyAdvisory(
                    package=package,
                    version=version,
                    ecosystem=ecosystem,
                    advisory_id=safe_advisory_id,
                    priority=priority,
                    source_paths=source_paths,
                )
            )
    return sorted(
        {
            advisory.model_dump_json(): advisory
            for advisory in advisories
        }.values(),
        key=lambda advisory: (
            advisory.package,
            advisory.advisory_id,
            advisory.source_paths,
        ),
    )[:100]


def _safe_dependency_value(value: object) -> str:
    text = str(value).strip() if isinstance(value, str) else ""
    if (
        _SAFE_DEPENDENCY_VALUE.fullmatch(text) is None
        or _is_secret_shaped_dependency_value(text)
    ):
        return ""
    return text


def _safe_dependency_paths(values: object) -> list[str]:
    if not isinstance(values, list):
        return []
    safe_paths = []
    for value in values:
        if not isinstance(value, str):
            continue
        path = value.replace("\\", "/").strip()
        if (
            _SAFE_DEPENDENCY_PATH.fullmatch(path) is not None
            and not _is_secret_shaped_dependency_value(path)
        ):
            safe_paths.append(path)
    return sorted(set(safe_paths))[:20]


def _is_secret_shaped_dependency_value(value: str) -> bool:
    return (
        _SECRET_SHAPED_DEPENDENCY_VALUE.search(value) is not None
        or _BARE_TOKEN_SHAPED_DEPENDENCY_VALUE.search(value) is not None
    )


def local_tool_advisory_artifact_data(
    result: RegisteredLocalToolRun,
) -> tuple[str, dict[str, Any], dict[str, Any]]:
    """Return the only persistence-safe projection for a local tool result."""
    if result.tool_id == "dependency_sbom_local" and result.dependency_profile is not None:
        profile = result.dependency_profile.model_dump(mode="json")
        return (
            "dependency_sbom_advisory",
            {
                "schema_version": "registered_local_dependency_sbom_advisory_v1",
                "tool_id": result.tool_id,
                "runner_status": result.runner_status,
                "finding_count": result.finding_count,
                "dependency_profile": profile,
                "raw_payload_processed": False,
            },
            {
                "dependency_profile": profile,
                "dependency_advisories": [
                    advisory.model_dump(mode="json")
                    for advisory in result.dependency_advisories
                ],
                "execution_allowed": False,
                "validation_allowed": False,
                "candidate_promotion_allowed": False,
                "report_submission_allowed": False,
            },
        )
    return (
        "static_advisory",
        {
            "tool_id": result.tool_id,
            "runner_status": result.runner_status,
            "finding_count": result.finding_count,
            "raw_payload_processed": False,
        },
        {
            "advisory_findings": result.advisory_findings,
            "execution_allowed": False,
            "validation_allowed": False,
            "candidate_promotion_allowed": False,
            "report_submission_allowed": False,
        },
    )


def _command_hash(
    command: object,
    *,
    tool_id: str | None = None,
    package_root: str | None = None,
    embedded_semgrep_rules: bool = False,
) -> str:
    values = [str(value) for value in command] if isinstance(command, list) else []
    canonical = json.dumps(
        _stable_command_values(
            values,
            tool_id=tool_id,
            package_root=package_root,
            embedded_semgrep_rules=embedded_semgrep_rules,
        ),
        ensure_ascii=True,
        separators=(",", ":"),
    )
    return f"sha256:{sha256(canonical.encode('utf-8')).hexdigest()}"


def _stable_command_values(
    values: list[str],
    *,
    tool_id: str | None,
    package_root: str | None,
    embedded_semgrep_rules: bool,
) -> list[str]:
    if tool_id not in {"semgrep_local", "codeql_local"} or not package_root:
        return values
    try:
        root = Path(package_root).resolve()
    except OSError:
        return values

    stable_values: list[str] = []
    for value in values:
        if (
            tool_id == "semgrep_local"
            and embedded_semgrep_rules
            and _is_embedded_semgrep_config(value)
        ):
            stable_values.append("__embedded_offline_rules__")
        elif tool_id == "codeql_local" and _is_temp_codeql_sarif_output(
            value,
            package_root=root,
        ):
            stable_values.append("--output=__mythos_codeql_temp_sarif__")
        else:
            stable_values.append(value)
    return stable_values


def _is_embedded_semgrep_config(value: str) -> bool:
    try:
        path = Path(value).resolve()
    except OSError:
        return False
    return _EMBEDDED_SEMGREP_CONFIG_NAME.fullmatch(path.name) is not None


def _is_temp_codeql_sarif_output(value: str, *, package_root: Path) -> bool:
    if not value.startswith("--output="):
        return False
    try:
        relative_path = Path(value.removeprefix("--output=")).resolve().relative_to(
            package_root
        )
    except (OSError, ValueError):
        return False
    return _CODEQL_TEMP_SARIF_RELATIVE_PATH.fullmatch(
        relative_path.as_posix()
    ) is not None


def _advisory_findings(
    findings: object,
    *,
    package_root: str,
) -> list[dict[str, str | int]]:
    if not isinstance(findings, list):
        return []
    try:
        root = Path(package_root).resolve()
    except OSError:
        return []
    safe: list[dict[str, str | int]] = []
    for finding in findings[:200]:
        if not isinstance(finding, dict):
            continue
        rule_id = str(finding.get("rule_id") or "")
        raw_path = str(finding.get("path") or "")
        if _SAFE_RULE_ID.fullmatch(rule_id) is None or not raw_path:
            continue
        try:
            source_path = Path(raw_path)
            if not source_path.is_absolute():
                source_path = root / source_path
            relative_path = source_path.resolve().relative_to(root).as_posix()
        except (OSError, ValueError):
            continue
        raw_line = finding.get("line")
        if not isinstance(raw_line, int) or isinstance(raw_line, bool) or raw_line < 1:
            raw_line = 0
        safe.append(
            {
                "rule_id": rule_id,
                "path": relative_path,
                "line": raw_line,
            }
        )
    return safe


__all__ = [
    "RegisteredDependencyAdvisory",
    "RegisteredDependencyProfile",
    "RegisteredLocalToolRun",
    "RegisteredLocalToolRunRequest",
    "local_tool_advisory_artifact_data",
    "run_registered_local_tool",
]
