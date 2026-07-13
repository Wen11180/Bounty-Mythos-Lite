"""Advisory static engines (Semgrep / CodeQL) — offline, non-executing.

Lawful research only:
- Does not run live network attacks
- Does not auto-invoke scanners against remote targets
- Consumes user-supplied offline SARIF/JSON or local package advisory fixtures
- Produces multi-engine EngineSignal-compatible dicts only
- Never grants execution / validation / submission / finding promotion
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


ENGINE_SEMGREP = "semgrep_advisory"
ENGINE_CODEQL = "codeql_advisory"

ALLOWED_ENGINES = {ENGINE_SEMGREP, ENGINE_CODEQL}


class AdvisoryStaticEngineError(ValueError):
    pass


def load_advisory_findings(source: str | Path | dict[str, Any] | list[Any] | None) -> list[dict[str, Any]]:
    """Load offline advisory findings from path or already-parsed object.

    Accepts:
    - list of finding dicts
    - {"findings": [...]} / {"results": [...]} / SARIF-like {"runs":[...]}
    - path to UTF-8 JSON without secrets
    """
    if source is None:
        return []
    if isinstance(source, list):
        return [item for item in source if isinstance(item, dict)]
    if isinstance(source, dict):
        return _extract_findings_from_object(source)
    path = Path(source)
    if not path.is_file():
        raise AdvisoryStaticEngineError(f"advisory_file_not_found:{path}")
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:  # noqa: BLE001 - surface parse errors cleanly
        raise AdvisoryStaticEngineError(f"advisory_json_invalid:{path}:{exc}") from exc
    if isinstance(raw, list):
        return [item for item in raw if isinstance(item, dict)]
    if isinstance(raw, dict):
        return _extract_findings_from_object(raw)
    raise AdvisoryStaticEngineError("advisory_payload_must_be_object_or_list")


def build_semgrep_advisory_signal(
    findings: list[dict[str, Any]] | None,
    *,
    candidate: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return _build_engine_signal(
        ENGINE_SEMGREP,
        findings or [],
        candidate=candidate if isinstance(candidate, dict) else {},
    )


def build_codeql_advisory_signal(
    findings: list[dict[str, Any]] | None,
    *,
    candidate: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return _build_engine_signal(
        ENGINE_CODEQL,
        findings or [],
        candidate=candidate if isinstance(candidate, dict) else {},
    )


def build_advisory_signals_for_candidate(
    *,
    candidate: dict[str, Any] | None = None,
    semgrep_findings: list[dict[str, Any]] | None = None,
    codeql_findings: list[dict[str, Any]] | None = None,
) -> dict[str, dict[str, Any]]:
    """Return optional engine signals for multi_engine_verifier wiring."""
    out: dict[str, dict[str, Any]] = {}
    if semgrep_findings is not None:
        out[ENGINE_SEMGREP] = build_semgrep_advisory_signal(
            semgrep_findings, candidate=candidate
        )
    if codeql_findings is not None:
        out[ENGINE_CODEQL] = build_codeql_advisory_signal(
            codeql_findings, candidate=candidate
        )
    # Absolute safety floor on every signal.
    for signal in out.values():
        signal["execution_allowed"] = False
        signal["validation_allowed"] = False
        signal["report_submission_allowed"] = False
        signal["confirmed_vulnerability"] = False
        signal["finding_promotion_allowed"] = False
    return out


def _build_engine_signal(
    engine: str,
    findings: list[dict[str, Any]],
    *,
    candidate: dict[str, Any],
) -> dict[str, Any]:
    normalized = [_normalize_finding(item, default_engine=engine) for item in findings]
    root = str(candidate.get("root_cause_id") or "")
    root_base = root.split(":")[0] if root else ""
    route = candidate.get("route") if isinstance(candidate.get("route"), dict) else {}
    route_path = str(route.get("path") or candidate.get("affected_route") or "")
    code_path = str(candidate.get("affected_code_path") or "")

    matching = []
    opposing = []
    for item in normalized:
        if _finding_opposes(item, root=root, root_base=root_base):
            opposing.append(item)
            continue
        if _finding_matches(
            item,
            root=root,
            root_base=root_base,
            route_path=route_path,
            code_path=code_path,
        ):
            matching.append(item)

    notes: list[str] = [f"{engine}_offline_only", f"findings_total={len(normalized)}"]
    evidence_refs: list[str] = []
    supports: bool | None
    status = "ready"

    if not normalized:
        supports = None
        notes.append(f"{engine}_no_findings")
        status = "pending"
    elif opposing and not matching:
        supports = False
        notes.append(f"{engine}_control_or_negative_match")
        evidence_refs = _refs_from_findings(opposing)
    elif matching:
        supports = True
        notes.append(f"{engine}_rule_matches_candidate")
        evidence_refs = _refs_from_findings(matching)
    else:
        supports = None
        notes.append(f"{engine}_no_candidate_overlap")

    return {
        "engine": engine,
        "status": status,
        "supports_candidate": supports,
        "notes": notes[:20],
        "evidence_refs": evidence_refs[:20],
        "execution_allowed": False,
        "validation_allowed": False,
        "report_submission_allowed": False,
        "confirmed_vulnerability": False,
        "finding_promotion_allowed": False,
        "matched_findings": matching[:5],
        "opposing_findings": opposing[:5],
    }


def _extract_findings_from_object(raw: dict[str, Any]) -> list[dict[str, Any]]:
    for key in ("findings", "results", "items"):
        value = raw.get(key)
        if isinstance(value, list):
            return [item for item in value if isinstance(item, dict)]
    # Minimal SARIF support: runs[].results[]
    runs = raw.get("runs")
    if isinstance(runs, list):
        out: list[dict[str, Any]] = []
        for run in runs:
            if not isinstance(run, dict):
                continue
            results = run.get("results")
            if not isinstance(results, list):
                continue
            for item in results:
                if isinstance(item, dict):
                    out.append(_sarif_result_to_finding(item))
        return out
    # single finding object
    if any(k in raw for k in ("rule_id", "ruleId", "message", "check_id")):
        return [raw]
    return []


def _sarif_result_to_finding(item: dict[str, Any]) -> dict[str, Any]:
    locations = item.get("locations") if isinstance(item.get("locations"), list) else []
    uri = ""
    if locations:
        loc0 = locations[0] if isinstance(locations[0], dict) else {}
        phys = loc0.get("physicalLocation") if isinstance(loc0.get("physicalLocation"), dict) else {}
        art = phys.get("artifactLocation") if isinstance(phys.get("artifactLocation"), dict) else {}
        uri = str(art.get("uri") or "")
    msg = item.get("message")
    message = ""
    if isinstance(msg, dict):
        message = str(msg.get("text") or "")
    elif msg is not None:
        message = str(msg)
    return {
        "rule_id": str(item.get("ruleId") or item.get("rule_id") or ""),
        "message": message,
        "path": uri,
        "level": str(item.get("level") or ""),
        "properties": item.get("properties") if isinstance(item.get("properties"), dict) else {},
    }


def _normalize_finding(item: dict[str, Any], *, default_engine: str) -> dict[str, Any]:
    props = item.get("properties") if isinstance(item.get("properties"), dict) else {}
    rule = str(
        item.get("rule_id")
        or item.get("ruleId")
        or item.get("check_id")
        or item.get("query_id")
        or props.get("rule_id")
        or ""
    )
    path = str(
        item.get("path")
        or item.get("file")
        or item.get("filename")
        or item.get("uri")
        or ""
    )
    message = str(item.get("message") or item.get("title") or item.get("description") or "")
    root_cause = str(
        item.get("root_cause_id")
        or item.get("root_cause")
        or props.get("root_cause_id")
        or ""
    )
    polarity = str(item.get("polarity") or props.get("polarity") or "support").lower()
    tags = item.get("tags") if isinstance(item.get("tags"), list) else props.get("tags")
    tags_l = [str(t).lower() for t in (tags or [])]
    return {
        "engine": default_engine,
        "rule_id": rule,
        "path": path,
        "message": message,
        "root_cause_id": root_cause,
        "polarity": polarity,
        "tags": tags_l,
        "level": str(item.get("level") or item.get("severity") or ""),
    }


def _finding_opposes(item: dict[str, Any], *, root: str, root_base: str) -> bool:
    polarity = str(item.get("polarity") or "").lower()
    tags = item.get("tags") or []
    if polarity in {"oppose", "control", "negative", "refute"}:
        return True
    if any(t in {"control", "safe", "mitigated", "false-positive"} for t in tags):
        return True
    blob = " ".join(
        [
            str(item.get("rule_id") or ""),
            str(item.get("message") or ""),
            str(item.get("root_cause_id") or ""),
        ]
    ).lower()
    if "control-present" in blob or "false_positive" in blob:
        return True
    # explicit control root match still treated as oppose only if polarity/tags say so
    return False


def _finding_matches(
    item: dict[str, Any],
    *,
    root: str,
    root_base: str,
    route_path: str,
    code_path: str,
) -> bool:
    item_root = str(item.get("root_cause_id") or "")
    if root and item_root:
        if item_root == root or item_root.startswith(root_base + ":"):
            return True
        if root_base and item_root.split(":")[0] == root_base:
            return True
    blob = " ".join(
        [
            str(item.get("rule_id") or ""),
            str(item.get("message") or ""),
            str(item.get("path") or ""),
            item_root,
        ]
    ).lower()
    if root_base and root_base.lower().replace("missing_", "") in blob:
        # coarse advisory overlap, e.g. missing_ssrf_validation ~ ssrf
        family = root_base.lower().replace("missing_", "").replace("_validation", "").replace("_check", "")
        if family and family in blob:
            return True
    if code_path:
        code_leaf = code_path.split(":")[-1].lower()
        if code_leaf and code_leaf in blob:
            return True
    if route_path:
        rp = route_path.lower().strip("/")
        if rp and rp in blob:
            return True
    return False


def _refs_from_findings(findings: list[dict[str, Any]]) -> list[str]:
    refs: list[str] = []
    for item in findings:
        rule = str(item.get("rule_id") or "")
        path = str(item.get("path") or "")
        root = str(item.get("root_cause_id") or "")
        if rule:
            refs.append(f"advisory:{rule}")
        if path:
            refs.append(f"file:{path}")
        if root:
            refs.append(root)
    # stable unique preserve order
    seen: set[str] = set()
    out: list[str] = []
    for ref in refs:
        if ref and ref not in seen:
            seen.add(ref)
            out.append(ref)
    return out




def load_package_advisory_bundle(package_root: str | Path | None) -> dict[str, Any]:
    """Optional offline advisory auto-ingest from an authorized package.

    Looks for:
    - inputs/advisory/*.json
    - inputs/advisory.json

    Naming conventions (case-insensitive):
    - *semgrep* -> semgrep_advisory
    - *codeql* -> codeql_advisory
    - otherwise infer from payload engine / rule fields, default semgrep

    Safety:
    - Missing advisory dir/file is OK (present=False)
    - Paths must stay under package_root
    - Filenames containing secret/token/cookie/credential are skipped
    - Never executes scanners or network validation
    """
    empty = {
        "present": False,
        "package_root": str(package_root or ""),
        "sources": [],
        "semgrep_findings": [],
        "codeql_findings": [],
        "skipped": [],
        "execution_allowed": False,
        "validation_allowed": False,
        "report_submission_allowed": False,
        "confirmed_vulnerability": False,
    }
    if package_root is None or str(package_root).strip() == "":
        return empty
    root = Path(package_root).resolve()
    if not root.is_dir():
        return {**empty, "package_root": str(root), "skipped": ["package_root_missing"]}

    candidates: list[Path] = []
    advisory_dir = root / "inputs" / "advisory"
    single = root / "inputs" / "advisory.json"
    if advisory_dir.is_dir():
        candidates.extend(sorted(p for p in advisory_dir.rglob("*.json") if p.is_file()))
    if single.is_file():
        candidates.append(single)

    # de-dupe preserve order
    seen_paths: set[str] = set()
    files: list[Path] = []
    for path in candidates:
        key = str(path.resolve())
        if key in seen_paths:
            continue
        seen_paths.add(key)
        files.append(path)

    if not files:
        return {**empty, "package_root": str(root)}

    semgrep: list[dict[str, Any]] = []
    codeql: list[dict[str, Any]] = []
    sources: list[dict[str, Any]] = []
    skipped: list[str] = []

    blocked_name_parts = ("secret", "token", "cookie", "credential", "password", "apikey", "api_key")

    for path in files:
        try:
            resolved = path.resolve()
            resolved.relative_to(root)
        except Exception:
            skipped.append(f"outside_package:{path.name}")
            continue
        name_l = path.name.lower()
        if any(part in name_l for part in blocked_name_parts):
            skipped.append(f"blocked_filename:{path.name}")
            continue
        try:
            findings = load_advisory_findings(resolved)
        except AdvisoryStaticEngineError as exc:
            skipped.append(f"unreadable:{path.name}:{exc}")
            continue

        engine = _infer_engine_for_file(path, findings)
        if engine == ENGINE_CODEQL:
            codeql.extend(findings)
        else:
            semgrep.extend(findings)
        sources.append(
            {
                "path": str(resolved.relative_to(root)).replace("\\", "/"),
                "engine": engine,
                "finding_count": len(findings),
            }
        )

    return {
        "present": True,
        "package_root": str(root),
        "sources": sources,
        "semgrep_findings": semgrep,
        "codeql_findings": codeql,
        "skipped": skipped,
        "execution_allowed": False,
        "validation_allowed": False,
        "report_submission_allowed": False,
        "confirmed_vulnerability": False,
    }


def _infer_engine_for_file(path: Path, findings: list[dict[str, Any]]) -> str:
    name = path.name.lower()
    if "codeql" in name:
        return ENGINE_CODEQL
    if "semgrep" in name:
        return ENGINE_SEMGREP
    for item in findings[:5]:
        if not isinstance(item, dict):
            continue
        engine = str(item.get("engine") or "").lower()
        if "codeql" in engine:
            return ENGINE_CODEQL
        if "semgrep" in engine:
            return ENGINE_SEMGREP
        props = item.get("properties") if isinstance(item.get("properties"), dict) else {}
        eng2 = str(props.get("engine") or "").lower()
        if "codeql" in eng2:
            return ENGINE_CODEQL
        if "semgrep" in eng2:
            return ENGINE_SEMGREP
        rule = str(item.get("rule_id") or item.get("ruleId") or item.get("query_id") or "").lower()
        if rule.startswith("js/") or rule.startswith("py/") or "codeql" in rule:
            return ENGINE_CODEQL
    return ENGINE_SEMGREP


__all__ = [
    "ALLOWED_ENGINES",
    "AdvisoryStaticEngineError",
    "ENGINE_CODEQL",
    "ENGINE_SEMGREP",
    "build_advisory_signals_for_candidate",
    "build_codeql_advisory_signal",
    "build_semgrep_advisory_signal",
    "load_advisory_findings",
    "load_package_advisory_bundle",
]
