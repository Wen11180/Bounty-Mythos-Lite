"""Crash code-path linking: advisory static map from triaged clusters.

Final-scheme residual after crash triage + regression:
- Statically link likely code paths (file/function/symbol/lines) in authorized package
- Advisory only: never confirmed vulnerability, never promote, never execute
- Optional export under package `_export/crash_codepath/` with human flag
"""

from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


STATUS_READY = "crash_codepath_ready"
STATUS_EMPTY = "crash_codepath_empty"
STATUS_SKIPPED = "crash_codepath_package_missing"
STATUS_NO_CLUSTERS = "crash_codepath_no_clusters"
STATUS_WRITTEN = "crash_codepath_export_written"

SAFETY_INVARIANTS = [
    "local_or_authorized_package_only",
    "no_public_target_scanning",
    "no_network_access",
    "static_source_read_only",
    "no_package_code_execution",
    "no_crash_promotion",
    "no_report_submission",
    "advisory_code_path_only",
    "no_export_write_without_human_flag",
    "human_review_required_before_any_promotion",
]

_MAX_LINKS = 24
_MAX_FILE_BYTES = 256_000
_MAX_SNIPPET_CHARS = 240
_MAX_RELATED = 8
_MAX_CALLS = 12

_PY_CALL_RE = re.compile(r"\b([A-Za-z_][\w]*)\s*\(")
_RAISE_RE = re.compile(r"(?m)^\s*raise\s+([A-Za-z_][\w\.]*)")
_THROW_RE = re.compile(r"(?m)^\s*throw\s+new\s+([A-Za-z_][\w\.]*)")


class CrashCodepathError(ValueError):
    """Raised when bridge attach receives invalid input."""


@dataclass(frozen=True)
class CodePathHit:
    path: str
    file: str
    function: str
    symbol: str
    start_line: int | None = None
    end_line: int | None = None
    language: str = ""
    confidence: str = "low"
    kind: str = "primary"
    evidence_snippet: str = ""
    notes: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class CrashCodepathLink:
    link_id: str
    cluster_id: str
    crash_id: str
    target_symbol: str
    source_path: str
    exception_type: str
    crash_type: str
    primary_code_path: str
    hits: list[CodePathHit] = field(default_factory=list)
    call_sites: list[str] = field(default_factory=list)
    raise_sites: list[str] = field(default_factory=list)
    related_symbols: list[str] = field(default_factory=list)
    root_cause_summary: str = ""
    confidence: str = "low"
    resolved: bool = False
    reproducible: bool | None = None
    minimized: bool = False
    promotion_allowed: bool = False
    confirmed_vulnerability: bool = False
    notes: list[str] = field(default_factory=list)
    human_questions: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class CrashCodepathResult:
    stage: str
    inspirations: list[str]
    execution_mode: str
    status: str
    package_id: str = ""
    package_root: str = ""
    input_cluster_count: int = 0
    input_crash_count: int = 0
    links: list[CrashCodepathLink] = field(default_factory=list)
    link_count: int = 0
    resolved_count: int = 0
    primary_path_count: int = 0
    human_allow_export_write: bool = False
    export_written: bool = False
    export_count: int = 0
    export_root_relative: str = "_export/crash_codepath"
    run_stamp: str = ""
    process_spawn_allowed: bool = False
    network_access: bool = False
    live_validation: bool = False
    execution_allowed: bool = False
    validation_allowed: bool = False
    report_submission_allowed: bool = False
    confirmed_vulnerability: bool = False
    finding_promotion_allowed: bool = False
    crash_promotion_allowed: bool = False
    package_code_execution_allowed: bool = False
    safety_invariants: list[str] = field(default_factory=list)
    next_allowed_action: str = (
        "Human reviews advisory code-path links offline; "
        "Mythos never promotes crashes or confirms vulnerabilities from static links."
    )
    notes: list[str] = field(default_factory=list)
    crash_triage_status: str = ""

    def to_dict(self) -> dict[str, Any]:
        return _force_safety_dict(asdict(self))
def build_crash_codepath_plan(
    *,
    package_root: str | Path | None = None,
    package_id: str = "",
    crash_triage: dict[str, Any] | None = None,
    human_allow_export_write: bool = False,
) -> CrashCodepathResult:
    """Alias for static linker (always non-executing)."""
    return run_crash_codepath_link(
        package_root=package_root,
        package_id=package_id,
        crash_triage=crash_triage,
        human_allow_export_write=human_allow_export_write,
    )


def run_crash_codepath_link(
    *,
    package_root: str | Path | None = None,
    package_id: str = "",
    crash_triage: dict[str, Any] | None = None,
    human_allow_export_write: bool = False,
) -> CrashCodepathResult:
    """Statically link triaged crash clusters to likely authorized-package code paths."""
    root: Path | None = None
    root_s = ""
    if package_root is not None and str(package_root).strip():
        root = Path(package_root)
        root_s = str(root)
        if not root.is_dir():
            return _empty(
                status=STATUS_SKIPPED,
                package_id=package_id,
                package_root=root_s,
                notes=["package_root_missing_or_not_directory"],
                human_allow_export_write=bool(human_allow_export_write),
            )

    triage = crash_triage if isinstance(crash_triage, dict) else {}
    if not triage and root is not None:
        triage = _try_load_latest_triage_index(root)

    triaged = _extract_triaged(triage)
    triage_status = str(triage.get("status") or "")
    input_crash_count = int(triage.get("input_crash_count") or len(triaged) or 0)
    cluster_ids = {str(t.get("cluster_id") or "") for t in triaged if t.get("cluster_id")}
    input_cluster_count = int(
        triage.get("unique_cluster_count")
        or triage.get("cluster_count")
        or len(cluster_ids)
        or 0
    )

    if not triaged:
        return _empty(
            status=STATUS_NO_CLUSTERS if (triage or root) else STATUS_EMPTY,
            package_id=package_id or str(triage.get("package_id") or ""),
            package_root=root_s or str(triage.get("package_root") or ""),
            notes=[
                "no_triaged_clusters_for_codepath",
                f"crash_triage_status={triage_status or 'absent'}",
            ],
            human_allow_export_write=bool(human_allow_export_write),
            crash_triage_status=triage_status,
            input_crash_count=input_crash_count,
            input_cluster_count=input_cluster_count,
        )

    links = _build_links(triaged, root=root)
    resolved_n = sum(1 for link in links if link.resolved)
    primary_n = sum(1 for link in links if link.primary_code_path)

    export_written = False
    export_count = 0
    run_stamp = ""
    notes = [
        "advisory_static_codepath_from_crash_triage",
        "package_code_execution_blocked",
        "crash_promotion_blocked",
        "never_confirmed_vulnerability",
    ]
    status = STATUS_READY

    if human_allow_export_write and root is not None:
        written, count, stamp = _export_links(root, links, package_id=package_id)
        export_written = written
        export_count = count
        run_stamp = stamp
        if written:
            status = STATUS_WRITTEN
            notes.append("export_written_under_package_tmp")
        else:
            notes.append("export_skipped_or_failed_still_advisory")
    elif human_allow_export_write and root is None:
        notes.append("export_requested_but_no_package_root")

    return _force_safety(
        CrashCodepathResult(
            stage="v1_crash_root_cause_codepath_linking",
            inspirations=["OSS-Fuzz", "CodeQL", "final-scheme-5.11", "final-scheme-8.2"],
            execution_mode="static_advisory_only",
            status=status,
            package_id=package_id or str(triage.get("package_id") or ""),
            package_root=root_s or str(triage.get("package_root") or ""),
            input_cluster_count=input_cluster_count or len({s.cluster_id for s in links}),
            input_crash_count=input_crash_count,
            links=links,
            link_count=len(links),
            resolved_count=resolved_n,
            primary_path_count=primary_n,
            human_allow_export_write=bool(human_allow_export_write),
            export_written=export_written,
            export_count=export_count,
            run_stamp=run_stamp,
            safety_invariants=list(SAFETY_INVARIANTS),
            notes=notes,
            crash_triage_status=triage_status,
        )
    )


def attach_crash_codepath_to_bridge_result(
    bridge_result: dict[str, Any],
    *,
    package_root: str | Path | None = None,
    crash_triage: dict[str, Any] | None = None,
    crash_codepath: dict[str, Any] | CrashCodepathResult | None = None,
    human_allow_export_write: bool = False,
) -> dict[str, Any]:
    """Attach advisory crash code-path links; never unlocks promote/submit/execute."""
    if not isinstance(bridge_result, dict):
        raise CrashCodepathError("bridge_result_must_be_object")

    package_id = str(bridge_result.get("package_id") or "")
    resolved_root = package_root or bridge_result.get("package_root")
    triage = crash_triage
    if triage is None and isinstance(bridge_result.get("crash_triage"), dict):
        triage = bridge_result.get("crash_triage")

    if isinstance(crash_codepath, CrashCodepathResult):
        payload = crash_codepath.to_dict()
    elif isinstance(crash_codepath, dict):
        payload = _force_safety_dict(dict(crash_codepath))
    else:
        payload = run_crash_codepath_link(
            package_root=resolved_root,
            package_id=package_id,
            crash_triage=triage if isinstance(triage, dict) else None,
            human_allow_export_write=bool(human_allow_export_write),
        ).to_dict()

    if not payload.get("package_id") and package_id:
        payload["package_id"] = package_id
    payload = _force_safety_dict(payload)

    out = dict(bridge_result)
    out["crash_codepath"] = payload
    out["crash_codepath_present"] = True
    out["crash_codepath_status"] = str(payload.get("status") or STATUS_EMPTY)
    out["crash_codepath_link_count"] = int(payload.get("link_count") or 0)
    out["crash_codepath_resolved_count"] = int(payload.get("resolved_count") or 0)
    out["crash_codepath_primary_path_count"] = int(payload.get("primary_path_count") or 0)
    out["crash_codepath_export_written"] = bool(payload.get("export_written"))
    out["crash_codepath_export_count"] = int(payload.get("export_count") or 0)
    out["crash_codepath_crash_promotion_allowed"] = False
    out["crash_codepath_package_code_execution_allowed"] = False
    out["execution_allowed"] = False
    out["validation_allowed"] = False
    out["report_submission_allowed"] = False
    out["confirmed_vulnerability"] = False
    if out.get("submission_blocked") is not True:
        out["submission_blocked"] = True
    return out
def _extract_triaged(triage: dict[str, Any]) -> list[dict[str, Any]]:
    raw = triage.get("triaged") if isinstance(triage, dict) else None
    if not isinstance(raw, list):
        raw = triage.get("clusters") if isinstance(triage, dict) else None
    if not isinstance(raw, list):
        return []
    out: list[dict[str, Any]] = []
    seen: set[str] = set()
    for item in raw[:_MAX_LINKS]:
        if not isinstance(item, dict):
            continue
        cluster = str(item.get("cluster_id") or item.get("crash_id") or "")
        key = cluster or json.dumps(item, sort_keys=True)[:80]
        if key in seen:
            continue
        seen.add(key)
        out.append(dict(item))
    return out


def _build_links(
    triaged: list[dict[str, Any]],
    *,
    root: Path | None,
) -> list[CrashCodepathLink]:
    links: list[CrashCodepathLink] = []
    for index, item in enumerate(triaged, start=1):
        cluster_id = str(item.get("cluster_id") or f"cluster-{index}")
        crash_id = str(item.get("crash_id") or f"crash-{index}")
        target = str(item.get("target_symbol") or "unknown_target")
        source = str(item.get("source_path") or "")
        et = str(item.get("exception_type") or "Exception")
        ctype = str(item.get("crash_type") or "")
        repro = item.get("reproducible")
        if repro is not None:
            repro = bool(repro)
        minimized = bool(item.get("minimized"))
        root_cause = item.get("root_cause") if isinstance(item.get("root_cause"), dict) else {}
        rc_summary = str(
            root_cause.get("summary")
            or item.get("root_cause_summary")
            or f"Advisory: {et} around {target}"
        )[:400]

        hits, call_sites, raise_sites, related, resolved, conf, notes = _link_cluster(
            root=root,
            target_symbol=target,
            source_path=source,
            exception_type=et,
            exception_message=str(item.get("exception_message") or ""),
        )
        primary = ""
        if hits:
            primary = hits[0].path
        elif source and target:
            primary = f"{source}::{target}"
            notes = list(notes) + ["fallback_surface_only"]
        elif target:
            primary = f"::{target}"
            notes = list(notes) + ["symbol_only_no_file"]

        questions = [
            "Is this symbol reachable from an untrusted input boundary?",
            "Does the linked raise/throw site match the triaged exception family?",
            "Are there alternate control paths not visible in the static window?",
            "Does authorized scope allow deeper human local validation?",
        ]
        links.append(
            CrashCodepathLink(
                link_id=f"CPL-{index:03d}-{_slug(cluster_id)[:24]}",
                cluster_id=cluster_id,
                crash_id=crash_id,
                target_symbol=target,
                source_path=source,
                exception_type=et,
                crash_type=ctype,
                primary_code_path=primary[:240],
                hits=hits,
                call_sites=call_sites,
                raise_sites=raise_sites,
                related_symbols=related,
                root_cause_summary=rc_summary,
                confidence=conf,
                resolved=resolved,
                reproducible=repro,
                minimized=minimized,
                notes=notes,
                human_questions=questions,
            )
        )
    return links
def _link_cluster(
    *,
    root: Path | None,
    target_symbol: str,
    source_path: str,
    exception_type: str,
    exception_message: str,
) -> tuple[list[CodePathHit], list[str], list[str], list[str], bool, str, list[str]]:
    notes: list[str] = ["static_advisory_only"]
    hits: list[CodePathHit] = []
    call_sites: list[str] = []
    raise_sites: list[str] = []
    related: list[str] = []
    resolved = False
    conf = "low"

    if not target_symbol and not source_path:
        notes.append("no_symbol_or_source")
        return hits, call_sites, raise_sites, related, resolved, conf, notes

    if root is None:
        notes.append("no_package_root_for_static_resolve")
        if source_path and target_symbol:
            hits.append(
                CodePathHit(
                    path=f"{source_path}::{target_symbol}",
                    file=source_path,
                    function=target_symbol,
                    symbol=target_symbol,
                    confidence="low",
                    kind="declared_surface",
                    notes=["package_root_absent"],
                )
            )
        return hits, call_sites, raise_sites, related, False, "low", notes

    file_path = _resolve_source_file(root, source_path)
    if file_path is None and source_path:
        notes.append("source_path_not_found_under_package")
        file_path = _find_by_basename(root, source_path)
        if file_path is not None:
            notes.append("resolved_by_basename_search")

    text = ""
    rel = source_path.replace("\\", "/")
    language = _guess_language(source_path)
    if file_path is not None:
        try:
            rel = str(file_path.relative_to(root.resolve())).replace("\\", "/")
        except Exception:
            rel = source_path.replace("\\", "/")
        language = _guess_language(rel)
        text = _read_text_capped(file_path)
        if not text:
            notes.append("source_file_empty_or_unreadable")
    else:
        notes.append("no_source_file_resolved")

    if text and target_symbol:
        span = _find_function_span(text, target_symbol, language=language)
        if span is not None:
            start, end, body = span
            snippet = _snippet_at(text, start, end)
            et_leaf = exception_type.split(".")[-1] if exception_type else ""
            conf = "high" if (et_leaf and et_leaf in body) else "medium"
            hits.append(
                CodePathHit(
                    path=f"{rel}:{start}:{target_symbol}",
                    file=rel,
                    function=target_symbol,
                    symbol=target_symbol,
                    start_line=start,
                    end_line=end,
                    language=language,
                    confidence=conf,
                    kind="primary_definition",
                    evidence_snippet=snippet,
                    notes=["function_span_resolved"],
                )
            )
            resolved = True
            call_sites = _extract_calls(body, target_symbol)
            raise_sites = _extract_raises(body, language=language)
            if exception_message:
                for line_no, line in _iter_lines(body, start):
                    if exception_message[:40] and exception_message[:40] in line:
                        raise_sites.append(f"{rel}:{line_no}:message_match")
            notes.append("primary_definition_linked")
        else:
            notes.append("symbol_not_found_in_source_file")
            hits.append(
                CodePathHit(
                    path=f"{rel}::{target_symbol}",
                    file=rel,
                    function=target_symbol,
                    symbol=target_symbol,
                    language=language,
                    confidence="low",
                    kind="file_surface",
                    evidence_snippet=text[:_MAX_SNIPPET_CHARS],
                    notes=["symbol_missing_in_file"],
                )
            )
    elif source_path and target_symbol:
        hits.append(
            CodePathHit(
                path=f"{source_path}::{target_symbol}",
                file=source_path,
                function=target_symbol,
                symbol=target_symbol,
                confidence="low",
                kind="declared_surface",
                notes=["static_body_unavailable"],
            )
        )

    if root is not None and target_symbol and target_symbol != "unknown_target":
        related_hits = _scan_related_defs(root, target_symbol, skip_rel=rel)
        for h in related_hits:
            if all(existing.path != h.path for existing in hits):
                hits.append(h)
            related.append(h.path)
        related = related[:_MAX_RELATED]

    if not hits and target_symbol:
        hits.append(
            CodePathHit(
                path=f"::{target_symbol}",
                file="",
                function=target_symbol,
                symbol=target_symbol,
                confidence="low",
                kind="symbol_only",
                notes=["unresolved"],
            )
        )

    if resolved and raise_sites:
        conf = "high"
    elif resolved:
        conf = conf if conf in {"high", "medium"} else "medium"
    else:
        conf = "low"

    return (
        hits[: _MAX_RELATED + 2],
        call_sites[:_MAX_CALLS],
        list(dict.fromkeys(raise_sites))[:_MAX_CALLS],
        related[:_MAX_RELATED],
        resolved,
        conf,
        notes,
    )


def _resolve_source_file(root: Path, source_path: str) -> Path | None:
    if not source_path or not str(source_path).strip():
        return None
    root_r = root.resolve()
    cand = (root / source_path).resolve()
    try:
        cand.relative_to(root_r)
    except ValueError:
        return None
    if cand.is_file():
        return cand
    for prefix in ("", "src/", "lib/", "app/", "inputs/"):
        alt = (root / prefix / Path(source_path).name).resolve()
        try:
            alt.relative_to(root_r)
        except ValueError:
            continue
        if alt.is_file():
            return alt
    return None


def _find_by_basename(root: Path, source_path: str) -> Path | None:
    name = Path(source_path).name
    if not name or name in {".", ".."}:
        return None
    root_r = root.resolve()
    matches: list[Path] = []
    for p in root.rglob(name):
        if not p.is_file():
            continue
        try:
            p.resolve().relative_to(root_r)
        except ValueError:
            continue
        parts = {x.lower() for x in p.parts}
        if parts & {"_export", ".venv", "node_modules", "__pycache__", ".git"}:
            continue
        matches.append(p)
        if len(matches) >= 5:
            break
    if len(matches) == 1:
        return matches[0]
    return None


def _read_text_capped(path: Path) -> str:
    try:
        data = path.read_bytes()
    except Exception:
        return ""
    if len(data) > _MAX_FILE_BYTES:
        data = data[:_MAX_FILE_BYTES]
    try:
        return data.decode("utf-8")
    except Exception:
        return data.decode("utf-8", errors="replace")


def _guess_language(path: str) -> str:
    lower = (path or "").lower()
    if lower.endswith((".py", ".pyi")):
        return "python"
    if lower.endswith((".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs")):
        return "typescript"
    if lower.endswith((".go",)):
        return "go"
    if lower.endswith((".rs",)):
        return "rust"
    if lower.endswith((".java", ".kt")):
        return "jvm"
    return "unknown"
def _find_function_span(
    text: str, symbol: str, *, language: str
) -> tuple[int, int, str] | None:
    if not text or not symbol:
        return None
    if language == "python":
        patterns = [
            re.compile(
                rf"(?m)^(?P<indent>[ \t]*)(?:async\s+)?def\s+{re.escape(symbol)}\s*\("
            )
        ]
    elif language in {"typescript", "javascript"}:
        patterns = [
            re.compile(
                rf"(?m)^(?P<indent>[ \t]*)(?:export\s+)?(?:async\s+)?function\s+{re.escape(symbol)}\s*\("
            ),
            re.compile(
                rf"(?m)^(?P<indent>[ \t]*)(?:export\s+)?(?:const|let|var)\s+{re.escape(symbol)}\s*=\s*(?:async\s*)?\("
            ),
            re.compile(
                rf"(?m)^(?P<indent>[ \t]*)(?:export\s+)?(?:const|let|var)\s+{re.escape(symbol)}\s*=\s*(?:async\s*)?[A-Za-z_].*=>"
            ),
        ]
    else:
        patterns = [
            re.compile(
                rf"(?m)^(?P<indent>[ \t]*)(?:async\s+)?def\s+{re.escape(symbol)}\s*\("
            ),
            re.compile(
                rf"(?m)^(?P<indent>[ \t]*)(?:export\s+)?(?:async\s+)?function\s+{re.escape(symbol)}\s*\("
            ),
        ]

    lines = text.splitlines()
    for pat in patterns:
        for match in pat.finditer(text):
            start_line = text.count("\n", 0, match.start()) + 1
            indent = match.groupdict().get("indent") or ""
            end_line = _block_end_line(lines, start_line - 1, indent, language=language)
            body = "\n".join(lines[start_line - 1 : end_line])
            return start_line, end_line, body
    return None


def _block_end_line(
    lines: list[str], start_idx: int, indent: str, *, language: str
) -> int:
    n = len(lines)
    if start_idx >= n:
        return start_idx + 1
    if language == "python":
        leading = indent.replace("\t", "    ")
        base_indent = len(leading)
        end = start_idx + 1
        while end < n:
            line = lines[end]
            if not line.strip():
                end += 1
                continue
            lead = line[: len(line) - len(line.lstrip(" \t"))]
            cur = len(lead.replace("\t", "    "))
            if cur <= base_indent and end > start_idx:
                break
            end += 1
        return end
    depth = 0
    seen = False
    end = start_idx
    for i in range(start_idx, n):
        for ch in lines[i]:
            if ch == "{":
                depth += 1
                seen = True
            elif ch == "}":
                depth -= 1
                if seen and depth <= 0:
                    return i + 1
        end = i
        if i > start_idx + 200:
            break
    return min(n, end + 1)


def _snippet_at(text: str, start_line: int, end_line: int) -> str:
    lines = text.splitlines()
    lo = max(0, start_line - 1)
    hi = min(len(lines), max(lo + 1, min(end_line, lo + 12)))
    chunk = "\n".join(lines[lo:hi])
    return chunk[:_MAX_SNIPPET_CHARS]


def _extract_calls(body: str, self_name: str) -> list[str]:
    out: list[str] = []
    skip = {
        "if",
        "for",
        "while",
        "with",
        "return",
        "raise",
        "except",
        "assert",
        "print",
        "len",
        "str",
        "int",
        "bytes",
        "bytearray",
        "isinstance",
        "type",
        "range",
        "list",
        "dict",
        "set",
        "super",
        "self",
        self_name,
    }
    for match in _PY_CALL_RE.finditer(body or ""):
        name = match.group(1)
        if name in skip or (name[0].isupper() and name.endswith("Error")):
            continue
        if name not in out:
            out.append(name)
        if len(out) >= _MAX_CALLS:
            break
    return out


def _extract_raises(body: str, *, language: str) -> list[str]:
    out: list[str] = []
    for i, line in enumerate((body or "").splitlines(), start=1):
        m = _RAISE_RE.search(line) if language == "python" else _THROW_RE.search(line)
        if not m and language != "python":
            m = _RAISE_RE.search(line)
        if m:
            out.append(f"L{i}:{m.group(1)}")
        if len(out) >= _MAX_CALLS:
            break
    return out


def _iter_lines(body: str, start_line: int):
    for i, line in enumerate((body or "").splitlines(), start=start_line):
        yield i, line
def _scan_related_defs(root: Path, symbol: str, *, skip_rel: str) -> list[CodePathHit]:
    hits: list[CodePathHit] = []
    root_r = root.resolve()
    patterns = (
        f"def {symbol}(",
        f"async def {symbol}(",
        f"function {symbol}(",
        f"const {symbol} =",
        f"let {symbol} =",
    )
    exts = {".py", ".pyi", ".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs"}
    count_files = 0
    for p in root.rglob("*"):
        if not p.is_file() or p.suffix.lower() not in exts:
            continue
        parts = {x.lower() for x in p.parts}
        if parts & {"_export", ".venv", "node_modules", "__pycache__", ".git", "dist", "build"}:
            continue
        try:
            rel = str(p.resolve().relative_to(root_r)).replace("\\", "/")
        except Exception:
            continue
        if rel == skip_rel:
            continue
        count_files += 1
        if count_files > 400:
            break
        try:
            if p.stat().st_size > _MAX_FILE_BYTES:
                continue
            text = p.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue
        if not any(pat in text for pat in patterns):
            continue
        lang = _guess_language(rel)
        span = _find_function_span(text, symbol, language=lang)
        if span is None:
            continue
        start, end, _body = span
        hits.append(
            CodePathHit(
                path=f"{rel}:{start}:{symbol}",
                file=rel,
                function=symbol,
                symbol=symbol,
                start_line=start,
                end_line=end,
                language=lang,
                confidence="medium",
                kind="related_definition",
                evidence_snippet=_snippet_at(text, start, end),
                notes=["related_symbol_definition"],
            )
        )
        if len(hits) >= 3:
            break
    return hits


def _try_load_latest_triage_index(root: Path) -> dict[str, Any]:
    base = root / "_export" / "crash_triage"
    if not base.is_dir():
        return {}
    stamps = sorted([p for p in base.iterdir() if p.is_dir()], reverse=True)
    for stamp_dir in stamps[:5]:
        index = stamp_dir / "index.json"
        if not index.is_file():
            continue
        try:
            data = json.loads(index.read_text(encoding="utf-8"))
        except Exception:
            continue
        if not isinstance(data, dict):
            continue
        clusters = data.get("clusters")
        if isinstance(clusters, list):
            triaged = []
            for c in clusters:
                if not isinstance(c, dict):
                    continue
                cid = str(c.get("cluster_id") or "")
                tpath = stamp_dir / cid / "triage.json"
                if tpath.is_file():
                    try:
                        detail = json.loads(tpath.read_text(encoding="utf-8"))
                        if isinstance(detail, dict):
                            triaged.append(detail)
                            continue
                    except Exception:
                        pass
                triaged.append(dict(c))
            data = dict(data)
            data["triaged"] = triaged
            data.setdefault("status", "crash_triage_export_written")
        return data
    return {}


def _export_links(
    root: Path,
    links: list[CrashCodepathLink],
    *,
    package_id: str,
) -> tuple[bool, int, str]:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    export_root = (root / "_export" / "crash_codepath" / stamp).resolve()
    try:
        export_root.relative_to(root.resolve())
    except ValueError:
        return False, 0, ""
    export_root.mkdir(parents=True, exist_ok=True)

    index = {
        "package_id": package_id,
        "stamp": stamp,
        "link_count": len(links),
        "crash_promotion_allowed": False,
        "confirmed_vulnerability": False,
        "report_submission_allowed": False,
        "package_code_execution_allowed": False,
        "links": [
            {
                "link_id": link.link_id,
                "cluster_id": link.cluster_id,
                "primary_code_path": link.primary_code_path,
                "resolved": link.resolved,
                "confidence": link.confidence,
            }
            for link in links
        ],
    }
    (export_root / "index.json").write_text(
        json.dumps(index, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    (export_root / "README.md").write_text(
        "\n".join(
            [
                "# Crash code-path links (advisory)",
                "",
                "- confirmed_vulnerability: false",
                "- crash_promotion_allowed: false",
                "- package_code_execution_allowed: false",
                "- report_submission_allowed: false",
                "",
                "Human review only. Mythos never auto-promotes from these static links.",
                "",
            ]
        ),
        encoding="utf-8",
    )

    count = 0
    for link in links:
        name = f"{_slug(link.link_id)}.json"
        payload = asdict(link)
        payload["promotion_allowed"] = False
        payload["confirmed_vulnerability"] = False
        (export_root / name).write_text(
            json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        count += 1
    return True, count, stamp


def _slug(value: str) -> str:
    text = re.sub(r"[^A-Za-z0-9._-]+", "-", (value or "").strip())
    return text.strip("-") or "item"


def _empty(
    *,
    status: str,
    package_id: str = "",
    package_root: str = "",
    notes: list[str] | None = None,
    human_allow_export_write: bool = False,
    crash_triage_status: str = "",
    input_crash_count: int = 0,
    input_cluster_count: int = 0,
) -> CrashCodepathResult:
    return _force_safety(
        CrashCodepathResult(
            stage="v1_crash_root_cause_codepath_linking",
            inspirations=["OSS-Fuzz", "CodeQL", "final-scheme-5.11", "final-scheme-8.2"],
            execution_mode="static_advisory_only",
            status=status,
            package_id=package_id,
            package_root=package_root,
            input_cluster_count=input_cluster_count,
            input_crash_count=input_crash_count,
            human_allow_export_write=bool(human_allow_export_write),
            safety_invariants=list(SAFETY_INVARIANTS),
            notes=list(notes or []),
            crash_triage_status=crash_triage_status,
        )
    )


def _force_safety(result: CrashCodepathResult) -> CrashCodepathResult:
    return CrashCodepathResult(
        stage=result.stage,
        inspirations=list(result.inspirations),
        execution_mode="static_advisory_only",
        status=result.status,
        package_id=result.package_id,
        package_root=result.package_root,
        input_cluster_count=result.input_cluster_count,
        input_crash_count=result.input_crash_count,
        links=list(result.links),
        link_count=len(result.links),
        resolved_count=sum(1 for link in result.links if link.resolved),
        primary_path_count=sum(1 for link in result.links if link.primary_code_path),
        human_allow_export_write=bool(result.human_allow_export_write),
        export_written=bool(result.export_written),
        export_count=int(result.export_count or 0),
        export_root_relative=result.export_root_relative or "_export/crash_codepath",
        run_stamp=result.run_stamp,
        process_spawn_allowed=False,
        network_access=False,
        live_validation=False,
        execution_allowed=False,
        validation_allowed=False,
        report_submission_allowed=False,
        confirmed_vulnerability=False,
        finding_promotion_allowed=False,
        crash_promotion_allowed=False,
        package_code_execution_allowed=False,
        safety_invariants=list(SAFETY_INVARIANTS),
        next_allowed_action=result.next_allowed_action,
        notes=list(result.notes),
        crash_triage_status=result.crash_triage_status,
    )


def _force_safety_dict(payload: dict[str, Any]) -> dict[str, Any]:
    out = dict(payload)
    out["process_spawn_allowed"] = False
    out["network_access"] = False
    out["live_validation"] = False
    out["execution_allowed"] = False
    out["validation_allowed"] = False
    out["report_submission_allowed"] = False
    out["confirmed_vulnerability"] = False
    out["finding_promotion_allowed"] = False
    out["crash_promotion_allowed"] = False
    out["package_code_execution_allowed"] = False
    out["human_allow_export_write"] = bool(out.get("human_allow_export_write"))
    out["export_written"] = bool(out.get("export_written"))
    out["export_count"] = int(out.get("export_count") or 0)
    out["export_root_relative"] = str(
        out.get("export_root_relative") or "_export/crash_codepath"
    )
    out["safety_invariants"] = list(SAFETY_INVARIANTS)
    out["execution_mode"] = "static_advisory_only"
    links = out.get("links")
    if isinstance(links, list):
        cleaned = []
        for item in links:
            if not isinstance(item, dict):
                continue
            row = dict(item)
            row["promotion_allowed"] = False
            row["confirmed_vulnerability"] = False
            cleaned.append(row)
        out["links"] = cleaned
        out["link_count"] = len(cleaned)
        out["resolved_count"] = sum(1 for r in cleaned if r.get("resolved"))
        out["primary_path_count"] = sum(1 for r in cleaned if r.get("primary_code_path"))
    return out


__all__ = [
    "STATUS_EMPTY",
    "STATUS_NO_CLUSTERS",
    "STATUS_READY",
    "STATUS_SKIPPED",
    "STATUS_WRITTEN",
    "SAFETY_INVARIANTS",
    "CodePathHit",
    "CrashCodepathError",
    "CrashCodepathLink",
    "CrashCodepathResult",
    "attach_crash_codepath_to_bridge_result",
    "build_crash_codepath_plan",
    "run_crash_codepath_link",
]