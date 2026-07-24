"""Dependency Agent — local SBOM / supply-chain profile for authorized packages.

Final-scheme V0 Dependency Agent (5.5):
- Read dependency manifests from authorized local artifacts
- Build a lightweight SBOM component list
- Heuristic reachability from local imports (not live OSV)
- Optional offline advisory flags only (never network CVE lookup)

Lawful research only:
- No network I/O (no OSV/NVD/GitHub Advisory live queries)
- No package installs, no lockfile resolution against registries
- Never unlocks execution / validation / report submission
- Paths must stay under package_root
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable
from hashlib import sha256
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field


STATUS_OK = "dependency_profile_ready"
STATUS_EMPTY = "dependency_no_artifacts"
STATUS_SKIPPED = "dependency_package_missing"

_MAX_FILES = 400
_MAX_FILE_BYTES = 256_000
_MAX_CONTENT_SNIFF = 48_000
_MAX_COMPONENTS = 200
_MAX_DEPENDENCY_INPUT_FILES = 1_200

_SKIP_DIR_NAMES = {
    ".git", ".hg", ".svn", ".venv", "venv", "node_modules", "__pycache__",
    ".pytest_cache", ".mypy_cache", ".tox", "dist", "build", "coverage",
    ".idea", ".vscode", "target", "vendor",
}

_BLOCKED_NAME_PARTS = (
    "secret", "token", "cookie", "credential", "password", "apikey", "api_key",
)

_RISKY_NAME_HINTS = {
    "serialize-javascript": "high",
    "node-serialize": "high",
    "serialize": "medium",
    "lodash": "low",
    "minimist": "medium",
    "request": "medium",
    "axios": "low",
    "got": "low",
    "node-fetch": "low",
    "pickle": "high",
    "pyyaml": "medium",
    "django": "low",
    "flask": "low",
    "jinja2": "medium",
    "pillow": "medium",
    "urllib3": "low",
    "requests": "low",
    "express": "low",
    "body-parser": "low",
    "multer": "medium",
    "xml2js": "medium",
    "libxmljs": "high",
}

_MANIFEST_NAMES = {
    "package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml",
    "requirements.txt", "pyproject.toml", "pipfile", "poetry.lock", "setup.py",
    "go.mod", "go.sum", "cargo.toml", "cargo.lock", "composer.json",
    "composer.lock", "gemfile", "gemfile.lock", "pom.xml",
    "build.gradle", "build.gradle.kts",
}

_DEPENDENCY_SOURCE_SUFFIXES = {
    ".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".py", ".go",
    ".rb", ".php", ".rs", ".java", ".kt",
}

_IMPORT_JS = re.compile(
    r"""(?:from\s+['"]([^'"]+)['"]|require\(\s*['"]([^'"]+)['"]\s*\)|import\(\s*['"]([^'"]+)['"]\s*\))""",
    re.I,
)
_IMPORT_PY = re.compile(
    r"""^(?:from\s+([A-Za-z_][\w.]*)\s+import|import\s+([A-Za-z_][\w.]*))""",
    re.M,
)
_REQUIREMENTS_LINE = re.compile(r"""^\s*([A-Za-z0-9_.\-]+)\s*([=~<>!]=?[^\s;]+)?""")
_CARGO_DEP = re.compile(
    r"""^\s*([A-Za-z0-9_\-]+)\s*=\s*(?:"([^"]+)"|\{[^}]*version\s*=\s*"([^"]+)")""",
    re.M,
)
_GEMFILE = re.compile(r"""^\s*gem\s+['"]([^'"]+)['"](?:,\s*['"]([^'"]+)['"])?""", re.M)


class DependencyAgentError(ValueError):
    pass


class DependencyComponent(BaseModel):
    """One SBOM-ish dependency component (advisory only)."""

    package: str
    version: str = "unknown"
    ecosystem: str = "unknown"
    known_advisory: bool = False
    advisory_ids: list[str] = Field(default_factory=list)
    reachable: str = "unknown"
    used_by: list[str] = Field(default_factory=list)
    priority: str = "info"
    source_manifest: str = ""
    direct: bool = True
    notes: list[str] = Field(default_factory=list)


class DependencyProfile(BaseModel):
    """Local dependency / SBOM profile (never live CVE confirmed)."""

    status: str = STATUS_EMPTY
    package_id: str = ""
    package_root: str = ""
    ecosystems: list[str] = Field(default_factory=list)
    manifests: list[str] = Field(default_factory=list)
    components: list[DependencyComponent] = Field(default_factory=list)
    component_count: int = 0
    reachable_count: int = 0
    advisory_flagged_count: int = 0
    high_priority_count: int = 0
    import_refs_scanned: int = 0
    source_files_scanned: int = 0
    signals: list[str] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)
    sbom_summary: dict[str, Any] = Field(default_factory=dict)
    execution_allowed: bool = False
    validation_allowed: bool = False
    report_submission_allowed: bool = False
    confirmed_vulnerability: bool = False
    finding_promotion_allowed: bool = False
    network_access: bool = False
    live_advisory_lookup: bool = False
    next_allowed_action: str = (
        "Review local SBOM / reachability heuristically; no live CVE lookup or auto-submit."
    )


def build_dependency_input_manifest(
    package_root: str | Path,
) -> list[dict[str, str]]:
    """Hash every local file the dependency profile may read for a snapshot."""
    try:
        root = Path(package_root).resolve(strict=True)
    except OSError as exc:
        raise DependencyAgentError("dependency_input_root_missing") from exc
    if not root.is_dir():
        raise DependencyAgentError("dependency_input_root_missing")

    entries: list[dict[str, str]] = []
    for path in _dependency_input_paths(root):
        try:
            raw = path.read_bytes()
        except OSError as exc:
            raise DependencyAgentError("dependency_input_unreadable") from exc
        if len(raw) > _MAX_FILE_BYTES:
            continue
        relative_path = _rel_posix(root, path)
        if not _safe_dependency_input_relative_path(relative_path):
            continue
        entries.append(
            {
                "source_path": relative_path,
                "content_digest": "sha256:" + sha256(raw).hexdigest(),
            }
        )
    return sorted(entries, key=lambda item: item["source_path"])


def dependency_input_manifest_matches(
    package_root: str | Path,
    manifest: object,
) -> bool:
    """Check an untrusted manifest against the files the profile would inspect."""
    normalized = _normalized_dependency_input_manifest(manifest)
    if normalized is None:
        return False
    try:
        return build_dependency_input_manifest(package_root) == normalized
    except DependencyAgentError:
        return False
def build_dependency_profile(
    *,
    package_root: str | Path | None = None,
    package_id: str = "",
    authorized_code_files: list[dict[str, Any]] | None = None,
    offline_advisories: list[dict[str, Any]] | None = None,
    max_files: int = _MAX_FILES,
) -> DependencyProfile:
    """Build local SBOM-style dependency profile from authorized artifacts only."""
    root: Path | None = None
    if package_root is not None and str(package_root).strip():
        root = Path(package_root).resolve()

    if root is not None and not root.is_dir():
        return _force_safety(
            DependencyProfile(
                status=STATUS_SKIPPED,
                package_id=package_id or root.name,
                package_root=str(root),
                notes=["package_root_missing"],
            )
        )

    resolved_package_id = package_id
    if not resolved_package_id and root is not None:
        resolved_package_id = root.name

    components: dict[str, DependencyComponent] = {}
    manifests: list[str] = []
    ecosystems: set[str] = set()
    signals: list[str] = []
    notes: list[str] = []
    import_index: dict[str, list[str]] = {}
    import_refs = 0
    scanned = 0
    advisory_map = _index_offline_advisories(offline_advisories)
    input_paths: list[Path] = []

    if root is not None:
        try:
            input_paths = _dependency_input_paths(root)
        except DependencyAgentError as exc:
            return _force_safety(
                DependencyProfile(
                    status=STATUS_SKIPPED,
                    package_id=resolved_package_id,
                    package_root=str(root),
                    notes=[str(exc)],
                )
            )
        if len(input_paths) > max_files:
            return _force_safety(
                DependencyProfile(
                    status=STATUS_SKIPPED,
                    package_id=resolved_package_id,
                    package_root=str(root),
                    notes=["dependency_profile_file_limit_exceeded"],
                )
            )
        if not package_id:
            resolved_package_id = _read_package_id(root, input_paths) or root.name
        offline_components, offline_manifests, offline_notes = (
            _load_offline_dependency_fixtures(root, input_paths)
        )
        notes.extend(offline_notes)
        for rel in offline_manifests:
            if rel not in manifests:
                manifests.append(rel)
        for comp in offline_components:
            _merge_component(components, comp)
            ecosystems.add(comp.ecosystem)
        if offline_components:
            signals.append("offline_dependency_fixtures")

    if isinstance(authorized_code_files, list):
        for item in authorized_code_files:
            if not isinstance(item, dict):
                continue
            path = item.get("path")
            content = item.get("content")
            if not isinstance(path, str) or not isinstance(content, str):
                continue
            if _name_blocked(path):
                notes.append(f"skipped_blocked_name:{Path(path).name}")
                continue
            scanned += 1
            rel = path.replace("\\", "/")
            name = Path(rel).name.lower()
            if name in _MANIFEST_NAMES or name.endswith(".csproj"):
                parsed = _parse_manifest(rel, content)
                for comp in parsed:
                    _merge_component(components, comp)
                    ecosystems.add(comp.ecosystem)
                if parsed and rel not in manifests:
                    manifests.append(rel)
            refs = _extract_imports(rel, content)
            import_refs += len(refs)
            for pkg, eco in refs:
                pkg = _canonical_package_name(pkg, eco)
                import_index.setdefault(pkg, [])
                if rel not in import_index[pkg]:
                    import_index[pkg].append(rel)
                key = _component_key(pkg, eco)
                if key not in components:
                    components[key] = DependencyComponent(
                        package=pkg,
                        version="unknown",
                        ecosystem=eco,
                        source_manifest="import_usage",
                        direct=True,
                        notes=["observed_from_import_only"],
                    )
                    ecosystems.add(eco)
        if authorized_code_files:
            signals.append("authorized_code_files")

    if root is not None:
        for path in input_paths:
            try:
                path.resolve().relative_to(root)
            except Exception:
                notes.append(f"outside_package:{path.name}")
                continue
            if _name_blocked(path.name):
                notes.append(f"skipped_blocked_name:{path.name}")
                continue
            rel = _rel_posix(root, path)
            scanned += 1
            name = path.name.lower()
            if name in _MANIFEST_NAMES or name.endswith(".csproj"):
                text = _safe_read_text(path)
                if text is None:
                    continue
                parsed = _parse_manifest(rel, text)
                for comp in parsed:
                    _merge_component(components, comp)
                    ecosystems.add(comp.ecosystem)
                if parsed and rel not in manifests:
                    manifests.append(rel)
            elif name in {"dependencies.json", "sbom.json", "dependency.json"}:
                if rel not in manifests:
                    manifests.append(rel)
            elif path.suffix.lower() in {
                ".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".py", ".go",
                ".rb", ".php", ".rs", ".java", ".kt",
            }:
                text = _safe_read_text(path)
                if text is None:
                    continue
                refs = _extract_imports(rel, text)
                import_refs += len(refs)
                for pkg, eco in refs:
                    import_index.setdefault(pkg, [])
                    if rel not in import_index[pkg]:
                        import_index[pkg].append(rel)
                    key = _component_key(pkg, eco)
                    if key not in components:
                        components[key] = DependencyComponent(
                            package=pkg,
                            version="unknown",
                            ecosystem=eco,
                            source_manifest="import_usage",
                            direct=True,
                            notes=["observed_from_import_only"],
                        )
                        ecosystems.add(eco)
        signals.append("package_filesystem")

    # lower-key index for case-insensitive match (e.g. PyYAML vs pyyaml import alias)
    import_index_l = {k.lower(): v for k, v in import_index.items()}

    for key, comp in list(components.items()):
        used = list(import_index.get(comp.package, []) or import_index_l.get(comp.package.lower(), []))
        if not used:
            base = comp.package.split("/")[-1]
            base_l = base.lower()
            for ipkg, paths in import_index.items():
                ipkg_l = ipkg.lower()
                if (
                    ipkg_l == comp.package.lower()
                    or ipkg_l.endswith("/" + base_l)
                    or ipkg_l == base_l
                ):
                    used = list(paths)
                    break
        if used:
            comp.used_by = used[:20]
            comp.reachable = "yes"
        elif comp.source_manifest == "import_usage":
            comp.reachable = "yes"
        else:
            comp.reachable = "unknown"

        adv_ids = advisory_map.get(comp.package.lower(), [])
        if not adv_ids:
            adv_ids = advisory_map.get(comp.package.split("/")[-1].lower(), [])
        if adv_ids:
            comp.known_advisory = True
            comp.advisory_ids = adv_ids[:10]
            if "offline_advisory_fixture" not in comp.notes:
                comp.notes.append("offline_advisory_fixture")

        comp.priority = _priority_for(comp)
        components[key] = comp

    component_list = sorted(
        components.values(),
        key=lambda c: (
            _priority_rank(c.priority),
            0 if c.reachable == "yes" else 1,
            c.package.lower(),
        ),
    )[:_MAX_COMPONENTS]

    reachable_count = sum(1 for c in component_list if c.reachable == "yes")
    advisory_count = sum(1 for c in component_list if c.known_advisory)
    high_count = sum(1 for c in component_list if c.priority in {"critical", "high"})
    status = STATUS_OK if component_list or manifests else STATUS_EMPTY
    if status == STATUS_EMPTY:
        notes.append("no_dependency_manifests_or_imports")

    summary = {
        "component_count": len(component_list),
        "manifest_count": len(manifests),
        "ecosystem_count": len(ecosystems),
        "reachable_count": reachable_count,
        "advisory_flagged_count": advisory_count,
        "high_priority_count": high_count,
        "primary_ecosystem": sorted(ecosystems)[0] if ecosystems else "",
        "has_manifests": bool(manifests),
        "live_advisory_lookup": False,
    }

    profile = DependencyProfile(
        status=status,
        package_id=resolved_package_id,
        package_root=str(root) if root is not None else "",
        ecosystems=sorted(ecosystems),
        manifests=_sorted_unique(manifests)[:40],
        components=component_list,
        component_count=len(component_list),
        reachable_count=reachable_count,
        advisory_flagged_count=advisory_count,
        high_priority_count=high_count,
        import_refs_scanned=import_refs,
        source_files_scanned=scanned,
        signals=_sorted_unique(signals),
        notes=notes[:40],
        sbom_summary=summary,
    )
    return _force_safety(profile)


def load_package_dependency_profile(package_root: str | Path | None) -> dict[str, Any]:
    """Load dependency profile for an authorized package directory."""
    return build_dependency_profile(package_root=package_root).model_dump()


def attach_dependency_profile_to_bridge_result(
    bridge_result: dict[str, Any],
    *,
    package_root: str | Path | None = None,
    authorized_code_files: list[dict[str, Any]] | None = None,
    dependency_profile: dict[str, Any] | DependencyProfile | None = None,
) -> dict[str, Any]:
    """Attach advisory dependency/SBOM profile to report-bridge result."""
    if not isinstance(bridge_result, dict):
        raise DependencyAgentError("bridge_result_must_be_object")

    package_id = str(bridge_result.get("package_id") or "")
    resolved_root = package_root or bridge_result.get("package_root")

    if isinstance(dependency_profile, DependencyProfile):
        payload = dependency_profile.model_dump()
    elif isinstance(dependency_profile, dict):
        payload = dict(dependency_profile)
    else:
        payload = build_dependency_profile(
            package_root=resolved_root,
            package_id=package_id,
            authorized_code_files=authorized_code_files,
        ).model_dump()

    if not payload.get("package_id") and package_id:
        payload["package_id"] = package_id
    payload = _force_safety_dict(payload)

    out = dict(bridge_result)
    out["dependency_profile"] = payload
    out["dependency_profile_present"] = payload.get("status") in {STATUS_OK, STATUS_EMPTY}
    out["sbom_component_count"] = int(payload.get("component_count") or 0)
    out["sbom_ecosystems"] = list(payload.get("ecosystems") or [])
    out["execution_allowed"] = False
    out["validation_allowed"] = False
    out["report_submission_allowed"] = False
    out["confirmed_vulnerability"] = False
    if out.get("submission_blocked") is not True:
        out["submission_blocked"] = True
    return out
def _load_offline_dependency_fixtures(
    root: Path,
    input_paths: list[Path],
) -> tuple[list[DependencyComponent], list[str], list[str]]:
    components: list[DependencyComponent] = []
    manifests: list[str] = []
    notes: list[str] = []
    for path in input_paths:
        if not _is_offline_dependency_fixture_path(root, path):
            continue
        if _name_blocked(path.name):
            notes.append(f"skipped_blocked_name:{path.name}")
            continue
        try:
            path.resolve().relative_to(root)
        except Exception:
            notes.append(f"outside_package:{path.name}")
            continue
        text = _safe_read_text(path)
        if not text:
            continue
        rel = _rel_posix(root, path)
        manifests.append(rel)
        try:
            raw = json.loads(text)
        except json.JSONDecodeError:
            notes.append(f"invalid_json:{path.name}")
            continue
        for item in _extract_component_dicts(raw):
            comp = _component_from_dict(item, source_manifest=rel)
            if comp is not None:
                components.append(comp)
    return components, manifests, notes


def _extract_component_dicts(raw: Any) -> list[dict[str, Any]]:
    if isinstance(raw, list):
        return [x for x in raw if isinstance(x, dict)]
    if not isinstance(raw, dict):
        return []
    for key in ("components", "dependencies", "packages", "artifacts"):
        value = raw.get(key)
        if isinstance(value, list):
            return [x for x in value if isinstance(x, dict)]
    if any(k in raw for k in ("package", "name", "purl")):
        return [raw]
    return []


def _component_from_dict(item: dict[str, Any], *, source_manifest: str) -> DependencyComponent | None:
    name = item.get("package") or item.get("name") or item.get("library")
    if not isinstance(name, str) or not name.strip():
        purl = item.get("purl")
        if isinstance(purl, str) and purl.startswith("pkg:"):
            try:
                body = purl[4:]
                eco, rest = body.split("/", 1)
                if "@" in rest:
                    name, ver = rest.rsplit("@", 1)
                else:
                    name, ver = rest, "unknown"
                return DependencyComponent(
                    package=name,
                    version=ver,
                    ecosystem=_normalize_ecosystem(eco),
                    known_advisory=bool(item.get("known_advisory")),
                    advisory_ids=_as_str_list(item.get("advisory_ids") or item.get("advisories")),
                    reachable=str(item.get("reachable") or "unknown"),
                    used_by=_as_str_list(item.get("used_by")),
                    priority=str(item.get("priority") or "info"),
                    source_manifest=source_manifest,
                    direct=bool(item.get("direct", True)),
                )
            except ValueError:
                return None
        return None
    version = item.get("version") or item.get("versionRange") or "unknown"
    ecosystem = item.get("ecosystem") or item.get("type") or "unknown"
    return DependencyComponent(
        package=str(name).strip(),
        version=str(version).strip() if version is not None else "unknown",
        ecosystem=_normalize_ecosystem(str(ecosystem)),
        known_advisory=bool(item.get("known_advisory")),
        advisory_ids=_as_str_list(item.get("advisory_ids") or item.get("advisories")),
        reachable=str(item.get("reachable") or "unknown"),
        used_by=_as_str_list(item.get("used_by")),
        priority=str(item.get("priority") or "info"),
        source_manifest=source_manifest,
        direct=bool(item.get("direct", True)),
        notes=_as_str_list(item.get("notes")),
    )


def _index_offline_advisories(
    offline_advisories: list[dict[str, Any]] | None,
) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    if not isinstance(offline_advisories, list):
        return out
    for item in offline_advisories:
        if not isinstance(item, dict):
            continue
        name = item.get("package") or item.get("name") or item.get("library")
        if not isinstance(name, str) or not name.strip():
            continue
        adv = item.get("advisory_ids") or item.get("advisories") or item.get("id")
        ids = _as_str_list(adv if not isinstance(adv, str) else [adv])
        if not ids and item.get("known_advisory"):
            ids = ["offline-advisory"]
        key = name.strip().lower()
        out.setdefault(key, [])
        for adv_id in ids:
            if adv_id not in out[key]:
                out[key].append(adv_id)
    return out


def _parse_manifest(rel: str, text: str) -> list[DependencyComponent]:
    name = Path(rel).name.lower()
    if name == "package.json":
        return _parse_package_json(rel, text)
    if name == "requirements.txt":
        return _parse_requirements_txt(rel, text)
    if name == "pyproject.toml":
        return _parse_pyproject_toml(rel, text)
    if name == "go.mod":
        return _parse_go_mod(rel, text)
    if name == "cargo.toml":
        return _parse_cargo_toml(rel, text)
    if name == "composer.json":
        return _parse_composer_json(rel, text)
    if name == "gemfile":
        return _parse_gemfile(rel, text)
    if name == "package-lock.json":
        return _parse_package_lock_top(rel, text)
    return []


def _parse_package_json(rel: str, text: str) -> list[DependencyComponent]:
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return []
    if not isinstance(data, dict):
        return []
    out: list[DependencyComponent] = []
    for section, direct in (
        ("dependencies", True),
        ("devDependencies", True),
        ("peerDependencies", True),
        ("optionalDependencies", True),
    ):
        block = data.get(section)
        if not isinstance(block, dict):
            continue
        for pkg, ver in block.items():
            if not isinstance(pkg, str):
                continue
            out.append(
                DependencyComponent(
                    package=pkg,
                    version=str(ver) if ver is not None else "unknown",
                    ecosystem="npm",
                    source_manifest=rel,
                    direct=direct,
                    notes=[f"section:{section}"],
                )
            )
    return out


def _parse_package_lock_top(rel: str, text: str) -> list[DependencyComponent]:
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return []
    if not isinstance(data, dict):
        return []
    out: list[DependencyComponent] = []
    packages = data.get("packages")
    if isinstance(packages, dict):
        for key, meta in packages.items():
            if not isinstance(meta, dict) or key in {"", "."}:
                continue
            name = key
            if name.startswith("node_modules/"):
                name = name[len("node_modules/") :]
            out.append(
                DependencyComponent(
                    package=str(name),
                    version=str(meta.get("version") or "unknown"),
                    ecosystem="npm",
                    source_manifest=rel,
                    direct=False,
                )
            )
            if len(out) >= _MAX_COMPONENTS:
                break
        return out
    deps = data.get("dependencies")
    if isinstance(deps, dict):
        for pkg, meta in deps.items():
            version = "unknown"
            if isinstance(meta, dict):
                version = str(meta.get("version") or "unknown")
            out.append(
                DependencyComponent(
                    package=str(pkg),
                    version=version,
                    ecosystem="npm",
                    source_manifest=rel,
                    direct=True,
                )
            )
    return out


def _parse_requirements_txt(rel: str, text: str) -> list[DependencyComponent]:
    out: list[DependencyComponent] = []
    for line in text.splitlines():
        raw = line.strip()
        if not raw or raw.startswith("#") or raw.startswith("-"):
            continue
        match = _REQUIREMENTS_LINE.match(raw)
        if not match:
            continue
        pkg = _canonical_package_name(match.group(1), "pypi")
        ver = (match.group(2) or "unknown").lstrip("=~<>!")
        out.append(
            DependencyComponent(
                package=pkg,
                version=ver or "unknown",
                ecosystem="pypi",
                source_manifest=rel,
                direct=True,
            )
        )
    return out


def _parse_pyproject_toml(rel: str, text: str) -> list[DependencyComponent]:
    out: list[DependencyComponent] = []
    in_poetry_deps = False
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("["):
            in_poetry_deps = stripped in {
                "[tool.poetry.dependencies]",
                "[tool.poetry.dev-dependencies]",
            }
            continue
        if stripped.startswith("dependencies") and "=" in stripped and "[" in stripped:
            inside = stripped.split("=", 1)[1].strip()
            for m in re.finditer(r"""['"]([A-Za-z0-9_.\-]+[^'"]*)['"]""", inside):
                pkg, ver = _split_pep_req(m.group(1))
                out.append(
                    DependencyComponent(
                        package=pkg,
                        version=ver,
                        ecosystem="pypi",
                        source_manifest=rel,
                        direct=True,
                    )
                )
            continue
        if in_poetry_deps and "=" in stripped and not stripped.startswith("#"):
            key, val = stripped.split("=", 1)
            pkg = key.strip().strip("\"'")
            if pkg.lower() == "python":
                continue
            ver = val.strip().strip("\"'")
            if ver.startswith("{"):
                vm = re.search(r"""version\s*=\s*['"]([^'"]+)['"]""", ver)
                ver = vm.group(1) if vm else "unknown"
            out.append(
                DependencyComponent(
                    package=pkg,
                    version=ver or "unknown",
                    ecosystem="pypi",
                    source_manifest=rel,
                    direct=True,
                )
            )
        if stripped.startswith("\"") or stripped.startswith("'"):
            token = stripped.strip(",").strip().strip("\"'")
            if token and not token.startswith("["):
                pkg, ver = _split_pep_req(token)
                if pkg:
                    out.append(
                        DependencyComponent(
                            package=pkg,
                            version=ver,
                            ecosystem="pypi",
                            source_manifest=rel,
                            direct=True,
                        )
                    )
    return out


def _parse_go_mod(rel: str, text: str) -> list[DependencyComponent]:
    out: list[DependencyComponent] = []
    in_require = False
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("require ("):
            in_require = True
            continue
        if in_require and stripped == ")":
            in_require = False
            continue
        if stripped.startswith("require ") and not stripped.startswith("require ("):
            parts = stripped[len("require ") :].split()
            if len(parts) >= 2:
                out.append(
                    DependencyComponent(
                        package=parts[0],
                        version=parts[1],
                        ecosystem="go",
                        source_manifest=rel,
                        direct=True,
                    )
                )
            continue
        if in_require:
            parts = stripped.split()
            if len(parts) >= 2 and not parts[0].startswith("//"):
                out.append(
                    DependencyComponent(
                        package=parts[0],
                        version=parts[1],
                        ecosystem="go",
                        source_manifest=rel,
                        direct=True,
                    )
                )
    return out


def _parse_cargo_toml(rel: str, text: str) -> list[DependencyComponent]:
    out: list[DependencyComponent] = []
    in_deps = False
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("["):
            in_deps = stripped in {"[dependencies]", "[dev-dependencies]"}
            continue
        if not in_deps or "=" not in stripped or stripped.startswith("#"):
            continue
        match = _CARGO_DEP.match(stripped)
        if not match:
            continue
        out.append(
            DependencyComponent(
                package=match.group(1),
                version=match.group(2) or match.group(3) or "unknown",
                ecosystem="cargo",
                source_manifest=rel,
                direct=True,
            )
        )
    return out


def _parse_composer_json(rel: str, text: str) -> list[DependencyComponent]:
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return []
    if not isinstance(data, dict):
        return []
    out: list[DependencyComponent] = []
    for section in ("require", "require-dev"):
        block = data.get(section)
        if not isinstance(block, dict):
            continue
        for pkg, ver in block.items():
            if pkg == "php":
                continue
            out.append(
                DependencyComponent(
                    package=str(pkg),
                    version=str(ver),
                    ecosystem="composer",
                    source_manifest=rel,
                    direct=True,
                    notes=[f"section:{section}"],
                )
            )
    return out


def _parse_gemfile(rel: str, text: str) -> list[DependencyComponent]:
    out: list[DependencyComponent] = []
    for match in _GEMFILE.finditer(text):
        out.append(
            DependencyComponent(
                package=match.group(1),
                version=match.group(2) or "unknown",
                ecosystem="rubygems",
                source_manifest=rel,
                direct=True,
            )
        )
    return out
def _extract_imports(path: str, text: str) -> list[tuple[str, str]]:
    """Return list of (package, ecosystem) observed in source."""
    sample = text[:_MAX_CONTENT_SNIFF]
    lower_path = path.lower()
    out: list[tuple[str, str]] = []
    if lower_path.endswith((".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs")):
        for match in _IMPORT_JS.finditer(sample):
            spec = match.group(1) or match.group(2) or match.group(3)
            pkg = _npm_package_from_specifier(spec)
            if pkg:
                out.append((pkg, "npm"))
    elif lower_path.endswith(".py"):
        for match in _IMPORT_PY.finditer(sample):
            mod = match.group(1) or match.group(2)
            if not mod:
                continue
            top = mod.split(".")[0]
            if top and top not in {
                "__future__", "typing", "pathlib", "os", "sys", "re", "json",
            }:
                out.append((top, "pypi"))
    elif lower_path.endswith(".go"):
        for match in re.finditer(r'"([A-Za-z0-9.\-_/]+)"', sample):
            imp = match.group(1)
            if "/" in imp and not imp.startswith("."):
                parts = imp.split("/")
                if imp.startswith("github.com/") or imp.startswith("golang.org/"):
                    pkg = "/".join(parts[:3]) if len(parts) >= 3 else imp
                else:
                    pkg = "/".join(parts[:2]) if len(parts) >= 2 else imp
                out.append((pkg, "go"))
    elif lower_path.endswith(".rb"):
        for match in re.finditer(
            r"""^\s*(?:require|require_relative)\s+['"]([^'"]+)['"]""",
            sample,
            re.M,
        ):
            out.append((match.group(1), "rubygems"))
    elif lower_path.endswith(".php"):
        for match in re.finditer(
            r"""^\s*(?:use|require|include)(?:_once)?\s+['"]?([A-Za-z_\\][^;'"]*)""",
            sample,
            re.M,
        ):
            name = match.group(1).strip("\\")
            if name:
                out.append((name.split("\\")[0], "composer"))

    seen: set[tuple[str, str]] = set()
    unique: list[tuple[str, str]] = []
    for item in out:
        if item in seen:
            continue
        seen.add(item)
        unique.append(item)
    return unique


def _npm_package_from_specifier(spec: str | None) -> str | None:
    if not isinstance(spec, str) or not spec.strip():
        return None
    s = spec.strip()
    if s.startswith(".") or s.startswith("/") or s.startswith("node:"):
        return None
    if s.startswith("@"):
        parts = s.split("/")
        if len(parts) >= 2:
            return parts[0] + "/" + parts[1]
        return s
    return s.split("/")[0]


def _split_pep_req(token: str) -> tuple[str, str]:
    token = token.strip()
    for sep in ("===", "==", ">=", "<=", "~=", "!=", ">", "<"):
        if sep in token:
            pkg, ver = token.split(sep, 1)
            return pkg.strip(), ver.strip() or "unknown"
    return token, "unknown"


_IMPORT_ALIASES = {
    # observed import top-level -> declared package name
    "yaml": "pyyaml",
    "cv2": "opencv-python",
    "PIL": "pillow",
    "bs4": "beautifulsoup4",
    "sklearn": "scikit-learn",
    "jwt": "pyjwt",
}


def _canonical_package_name(package: str, ecosystem: str) -> str:
    pkg = (package or "").strip()
    if ecosystem == "pypi":
        # aliases keyed by import top-level / lower name
        return _IMPORT_ALIASES.get(pkg, _IMPORT_ALIASES.get(pkg.lower(), pkg))
    return pkg


def _priority_for(comp: DependencyComponent) -> str:
    base = comp.priority if comp.priority in {"critical", "high", "medium", "low", "info"} else "info"
    name = comp.package.lower()
    hint = _RISKY_NAME_HINTS.get(name) or _RISKY_NAME_HINTS.get(name.split("/")[-1])
    if comp.known_advisory:
        rank = min(_priority_rank(base), _priority_rank(hint or "medium"), _priority_rank("medium"))
        return _rank_to_priority(rank)
    if hint:
        rank = min(_priority_rank(base), _priority_rank(hint))
        if comp.reachable == "yes":
            return _rank_to_priority(rank)
        return _rank_to_priority(max(rank, _priority_rank("low")))
    return base


def _priority_rank(value: str) -> int:
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    return order.get((value or "info").lower(), 4)


def _rank_to_priority(rank: int) -> str:
    return {0: "critical", 1: "high", 2: "medium", 3: "low", 4: "info"}.get(rank, "info")


def _merge_component(store: dict[str, DependencyComponent], comp: DependencyComponent) -> None:
    key = _component_key(comp.package, comp.ecosystem)
    existing = store.get(key)
    if existing is None:
        store[key] = comp
        return
    if existing.version in {"", "unknown"} and comp.version not in {"", "unknown"}:
        existing.version = comp.version
    if not existing.known_advisory and comp.known_advisory:
        existing.known_advisory = True
    for adv in comp.advisory_ids:
        if adv not in existing.advisory_ids:
            existing.advisory_ids.append(adv)
    for path in comp.used_by:
        if path not in existing.used_by:
            existing.used_by.append(path)
    if existing.source_manifest in {"", "import_usage"} and comp.source_manifest not in {
        "",
        "import_usage",
    }:
        existing.source_manifest = comp.source_manifest
    for note in comp.notes:
        if note not in existing.notes:
            existing.notes.append(note)
    store[key] = existing


def _component_key(package: str, ecosystem: str) -> str:
    return f"{_normalize_ecosystem(ecosystem)}::{package.lower()}"


def _normalize_ecosystem(value: str) -> str:
    v = (value or "unknown").strip().lower()
    aliases = {
        "npm": "npm", "node": "npm", "javascript": "npm", "typescript": "npm",
        "pypi": "pypi", "pip": "pypi", "python": "pypi",
        "go": "go", "golang": "go",
        "cargo": "cargo", "rust": "cargo", "crates": "cargo",
        "composer": "composer", "php": "composer",
        "rubygems": "rubygems", "ruby": "rubygems", "gem": "rubygems",
        "maven": "maven", "gradle": "maven", "java": "maven",
        "nuget": "nuget", "dotnet": "nuget",
    }
    return aliases.get(v, v or "unknown")


def _dependency_input_paths(root: Path) -> list[Path]:
    paths: dict[str, Path] = {}
    for path in _offline_dependency_fixture_paths(root):
        _add_dependency_input_path(paths, root=root, path=path)
    for scan_root, _label in _package_scan_roots(root):
        for path in _iter_files(
            scan_root,
            package_root=root,
            max_files=_MAX_DEPENDENCY_INPUT_FILES,
            include=lambda candidate: _is_dependency_profile_input(
                candidate,
                root=root,
            ),
            fail_on_limit=True,
        ):
            if _is_dependency_profile_input(path, root=root):
                _add_dependency_input_path(paths, root=root, path=path)
    if len(paths) > _MAX_DEPENDENCY_INPUT_FILES:
        raise DependencyAgentError("dependency_input_limit_exceeded")
    return [paths[key] for key in sorted(paths)]


def _offline_dependency_fixture_paths(root: Path) -> list[Path]:
    candidates = [
        root / "inputs" / "dependencies.json",
        root / "inputs" / "dependency.json",
        root / "inputs" / "sbom.json",
        root / "inputs" / "advisory" / "dependencies.json",
        root / "_extract" / "SBOM.json",
        root / "_extract" / "DEPENDENCIES.json",
    ]
    dependency_directory = root / "inputs" / "dependencies"
    if dependency_directory.is_symlink():
        _resolve_dependency_input_path(dependency_directory, package_root=root)
    if dependency_directory.is_dir():
        candidates.extend(
            _iter_files(
                dependency_directory,
                package_root=root,
                max_files=_MAX_DEPENDENCY_INPUT_FILES,
                include=lambda path: path.suffix.lower() == ".json",
                fail_on_limit=True,
            )
        )
    return candidates


def _is_offline_dependency_fixture_path(root: Path, path: Path) -> bool:
    relative_path = _rel_posix(root, path)
    if relative_path.lower() in {
        "inputs/dependencies.json",
        "inputs/dependency.json",
        "inputs/sbom.json",
        "inputs/advisory/dependencies.json",
        "_extract/sbom.json",
        "_extract/dependencies.json",
    }:
        return True
    return (
        relative_path.startswith("inputs/dependencies/")
        and path.suffix.lower() == ".json"
    )


def _add_dependency_input_path(
    paths: dict[str, Path],
    *,
    root: Path,
    path: Path,
) -> None:
    if not path.exists():
        if path.is_symlink():
            _resolve_dependency_input_path(path, package_root=root)
        return
    try:
        resolved = _resolve_dependency_input_path(path, package_root=root)
        relative_path = resolved.relative_to(root.resolve(strict=True)).as_posix()
    except DependencyAgentError:
        raise
    if (
        not resolved.is_file()
        or not _safe_dependency_input_relative_path(relative_path)
    ):
        return
    try:
        if resolved.stat().st_size > _MAX_FILE_BYTES:
            return
    except OSError:
        return
    paths[relative_path] = resolved


def _is_dependency_profile_input(path: Path, *, root: Path) -> bool:
    try:
        resolved = path.resolve(strict=True)
        resolved.relative_to(root)
    except (OSError, ValueError):
        return False
    if not resolved.is_file() or _name_blocked(resolved.name):
        return False
    try:
        if resolved.stat().st_size > _MAX_FILE_BYTES:
            return False
    except OSError:
        return False
    name = resolved.name.lower()
    return (
        name in _MANIFEST_NAMES
        or name == "case.json"
        or name.endswith(".csproj")
        or resolved.suffix.lower() in _DEPENDENCY_SOURCE_SUFFIXES
    )


def _normalized_dependency_input_manifest(
    manifest: object,
) -> list[dict[str, str]] | None:
    if not isinstance(manifest, list) or len(manifest) > _MAX_DEPENDENCY_INPUT_FILES:
        return None
    entries: list[dict[str, str]] = []
    seen_paths: set[str] = set()
    for item in manifest:
        if not isinstance(item, dict):
            return None
        source_path = _safe_dependency_input_relative_path(item.get("source_path"))
        content_digest = item.get("content_digest")
        if (
            not source_path
            or source_path in seen_paths
            or not isinstance(content_digest, str)
            or not re.fullmatch(r"sha256:[0-9a-f]{64}", content_digest.lower())
        ):
            return None
        seen_paths.add(source_path)
        entries.append(
            {
                "source_path": source_path,
                "content_digest": content_digest.lower(),
            }
        )
    return sorted(entries, key=lambda item: item["source_path"])


def _safe_dependency_input_relative_path(value: object) -> str:
    if not isinstance(value, str):
        return ""
    path = value.replace("\\", "/").strip()
    parts = [part for part in path.split("/") if part]
    if (
        not parts
        or path.startswith("/")
        or ":" in path
        or ".." in parts
        or any(_name_blocked(part) for part in parts)
    ):
        return ""
    return "/".join(parts)


def _resolve_dependency_input_path(path: Path, *, package_root: Path) -> Path:
    try:
        resolved_root = package_root.resolve(strict=True)
        resolved_path = path.resolve(strict=True)
    except RuntimeError as exc:
        raise DependencyAgentError("dependency_input_path_cycle") from exc
    except OSError as exc:
        raise DependencyAgentError("dependency_input_path_unavailable") from exc
    try:
        resolved_path.relative_to(resolved_root)
    except ValueError as exc:
        raise DependencyAgentError("dependency_input_path_escape") from exc
    return resolved_path


def _package_scan_roots(root: Path) -> list[tuple[Path, str]]:
    roots: list[tuple[Path, str]] = []
    for name, label in (
        ("inputs", "inputs"),
        ("_upstream", "_upstream"),
        ("_extract", "_extract"),
    ):
        path = root / name
        if path.is_symlink():
            resolved_path = _resolve_dependency_input_path(path, package_root=root)
            if resolved_path == root.resolve(strict=True):
                raise DependencyAgentError("dependency_input_path_cycle")
        if path.is_dir():
            _resolve_dependency_input_path(path, package_root=root)
            roots.append((path, label))
    roots.append((root, "package_root_manifests"))
    return roots


def _iter_files(
    scan_root: Path,
    *,
    package_root: Path,
    max_files: int,
    include: Callable[[Path], bool] | None = None,
    fail_on_limit: bool = False,
) -> list[Path]:
    resolved_package_root = _resolve_dependency_input_path(
        package_root,
        package_root=package_root,
    )
    resolved_scan_root = _resolve_dependency_input_path(
        scan_root,
        package_root=resolved_package_root,
    )
    files: list[Path] = []
    traversed_entries = 0
    traversal_limit_reached = False

    def bounded_sorted_entries(directory: Path) -> list[Path]:
        nonlocal traversed_entries, traversal_limit_reached
        entries: list[Path] = []
        try:
            for entry in directory.iterdir():
                traversed_entries += 1
                if traversed_entries > max_files:
                    if fail_on_limit:
                        raise DependencyAgentError("dependency_input_limit_exceeded")
                    traversal_limit_reached = True
                    break
                entries.append(entry)
        except OSError as exc:
            raise DependencyAgentError("dependency_input_path_unavailable") from exc
        return sorted(entries, key=lambda path: path.name.lower())

    def append_file(path: Path) -> None:
        if include is not None and not include(path):
            return
        if len(files) >= max_files:
            if fail_on_limit:
                raise DependencyAgentError("dependency_input_limit_exceeded")
            return
        files.append(path)

    if resolved_scan_root.is_file():
        append_file(resolved_scan_root)
        return files
    if resolved_scan_root == resolved_package_root:
        for child in bounded_sorted_entries(resolved_scan_root):
            if child.is_symlink():
                resolved_child = _resolve_dependency_input_path(
                    child,
                    package_root=resolved_package_root,
                )
                if resolved_child.is_file():
                    append_file(resolved_child)
                continue
            if child.is_file():
                append_file(child)
            if not fail_on_limit and len(files) >= max_files:
                break
        return files
    stack = [resolved_scan_root]
    visited: set[Path] = set()
    while (
        stack
        and not traversal_limit_reached
        and (fail_on_limit or len(files) < max_files)
    ):
        current = _resolve_dependency_input_path(
            stack.pop(),
            package_root=resolved_package_root,
        )
        if current in visited:
            raise DependencyAgentError("dependency_input_path_cycle")
        if not current.is_dir():
            raise DependencyAgentError("dependency_input_path_unavailable")
        visited.add(current)
        for entry in bounded_sorted_entries(current):
            if entry.is_symlink():
                resolved_entry = _resolve_dependency_input_path(
                    entry,
                    package_root=resolved_package_root,
                )
                if resolved_entry.is_dir():
                    if entry.name in _SKIP_DIR_NAMES or entry.name.startswith("."):
                        continue
                    stack.append(resolved_entry)
                elif resolved_entry.is_file():
                    append_file(resolved_entry)
                else:
                    raise DependencyAgentError("dependency_input_path_unavailable")
                continue
            if entry.is_dir():
                if entry.name in _SKIP_DIR_NAMES or entry.name.startswith("."):
                    continue
                stack.append(
                    _resolve_dependency_input_path(
                        entry,
                        package_root=resolved_package_root,
                    )
                )
            elif entry.is_file():
                try:
                    if entry.stat().st_size > _MAX_FILE_BYTES:
                        continue
                except OSError:
                    continue
                append_file(entry)
                if not fail_on_limit and len(files) >= max_files:
                    break
    return files


def _safe_read_text(path: Path) -> str | None:
    try:
        if path.stat().st_size > _MAX_FILE_BYTES:
            return None
        raw = path.read_bytes()
    except OSError:
        return None
    if b"\x00" in raw[:4096]:
        return None
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        try:
            return raw.decode("utf-8", errors="replace")
        except Exception:
            return None


def _read_package_id(root: Path, input_paths: list[Path]) -> str:
    bound_paths = set(input_paths)
    for name in ("package.json", "case.json"):
        path = root / name
        try:
            resolved_path = path.resolve(strict=True)
        except (OSError, RuntimeError):
            continue
        if resolved_path not in bound_paths:
            continue
        text = _safe_read_text(resolved_path)
        if not text:
            continue
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            continue
        if isinstance(data, dict):
            for key in ("package_id", "case_id"):
                value = data.get(key)
                if isinstance(value, str) and value.strip():
                    return value.strip()
    return ""


def _name_blocked(name: str) -> bool:
    lower = name.lower()
    return any(part in lower for part in _BLOCKED_NAME_PARTS)


def _rel_posix(root: Path, path: Path) -> str:
    try:
        return path.resolve().relative_to(root).as_posix()
    except Exception:
        return path.name


def _sorted_unique(values: Any) -> list[str]:
    items: set[str] = set()
    for value in values or []:
        text = str(value).strip()
        if text:
            items.add(text)
    return sorted(items, key=lambda s: s.lower())


def _as_str_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value] if value.strip() else []
    if isinstance(value, list):
        out: list[str] = []
        for item in value:
            if isinstance(item, str) and item.strip():
                out.append(item.strip())
            elif isinstance(item, dict):
                for key in ("id", "advisory_id", "ghsa", "cve"):
                    v = item.get(key)
                    if isinstance(v, str) and v.strip():
                        out.append(v.strip())
                        break
        return out
    return []


def _force_safety(profile: DependencyProfile) -> DependencyProfile:
    return DependencyProfile.model_validate(_force_safety_dict(profile.model_dump()))


def _force_safety_dict(payload: dict[str, Any]) -> dict[str, Any]:
    out = dict(payload)
    out["execution_allowed"] = False
    out["validation_allowed"] = False
    out["report_submission_allowed"] = False
    out["confirmed_vulnerability"] = False
    out["finding_promotion_allowed"] = False
    out["network_access"] = False
    out["live_advisory_lookup"] = False
    if not out.get("next_allowed_action"):
        out["next_allowed_action"] = (
            "Review local SBOM / reachability heuristically; no live CVE lookup or auto-submit."
        )
    return out


__all__ = [
    "STATUS_OK",
    "STATUS_EMPTY",
    "STATUS_SKIPPED",
    "DependencyAgentError",
    "DependencyComponent",
    "DependencyProfile",
    "build_dependency_input_manifest",
    "build_dependency_profile",
    "dependency_input_manifest_matches",
    "load_package_dependency_profile",
    "attach_dependency_profile_to_bridge_result",
]
