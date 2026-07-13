"""Intake Agent — stack / framework / entrypoint detection for authorized packages.

Final-scheme V0 Intake Agent (5.2):
- Identify languages, frameworks, package managers
- Identify entrypoints and auth-related components
- Generate a project profile from local authorized artifacts only

Lawful research only:
- No network I/O
- No live scanning or remote clone
- Never unlocks execution / validation / report submission
- Paths must stay under package_root when loading packages
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field


STATUS_OK = "intake_profile_ready"
STATUS_EMPTY = "intake_no_artifacts"
STATUS_SKIPPED = "intake_package_missing"

_MAX_FILES = 400
_MAX_FILE_BYTES = 256_000
_MAX_CONTENT_SNIFF = 24_000

_SKIP_DIR_NAMES = {
    ".git",
    ".hg",
    ".svn",
    ".venv",
    "venv",
    "node_modules",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".tox",
    "dist",
    "build",
    "coverage",
    ".idea",
    ".vscode",
    "target",
    "vendor",
}

_BLOCKED_NAME_PARTS = (
    "secret",
    "token",
    "cookie",
    "credential",
    "password",
    "apikey",
    "api_key",
)

_LANG_BY_SUFFIX: dict[str, str] = {
    ".py": "Python",
    ".pyi": "Python",
    ".ts": "TypeScript",
    ".tsx": "TypeScript",
    ".js": "JavaScript",
    ".jsx": "JavaScript",
    ".mjs": "JavaScript",
    ".cjs": "JavaScript",
    ".go": "Go",
    ".rs": "Rust",
    ".java": "Java",
    ".kt": "Kotlin",
    ".kts": "Kotlin",
    ".rb": "Ruby",
    ".php": "PHP",
    ".cs": "C#",
    ".swift": "Swift",
    ".scala": "Scala",
    ".c": "C",
    ".h": "C",
    ".cpp": "C++",
    ".cc": "C++",
    ".hpp": "C++",
}

# filename, languages, package_managers
_MANIFEST_NAMES: dict[str, tuple[list[str], list[str]]] = {
    "package.json": (["JavaScript", "TypeScript"], ["npm"]),
    "package-lock.json": (["JavaScript", "TypeScript"], ["npm"]),
    "yarn.lock": (["JavaScript", "TypeScript"], ["yarn"]),
    "pnpm-lock.yaml": (["JavaScript", "TypeScript"], ["pnpm"]),
    "requirements.txt": (["Python"], ["pip"]),
    "pyproject.toml": (["Python"], ["pip", "poetry"]),
    "pipfile": (["Python"], ["pipenv"]),
    "poetry.lock": (["Python"], ["poetry"]),
    "setup.py": (["Python"], ["pip"]),
    "go.mod": (["Go"], ["go_modules"]),
    "go.sum": (["Go"], ["go_modules"]),
    "cargo.toml": (["Rust"], ["cargo"]),
    "cargo.lock": (["Rust"], ["cargo"]),
    "pom.xml": (["Java"], ["maven"]),
    "build.gradle": (["Java"], ["gradle"]),
    "build.gradle.kts": (["Kotlin", "Java"], ["gradle"]),
    "composer.json": (["PHP"], ["composer"]),
    "gemfile": (["Ruby"], ["bundler"]),
    "gemfile.lock": (["Ruby"], ["bundler"]),
}

_FRAMEWORK_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("FastAPI", re.compile(r"\bfrom\s+fastapi\b|\bimport\s+fastapi\b|FastAPI\s*\(", re.I)),
    ("Flask", re.compile(r"\bfrom\s+flask\b|\bimport\s+flask\b|Flask\s*\(", re.I)),
    ("Django", re.compile(r"\bdjango\b|from\s+django\.|urlpatterns\s*=", re.I)),
    ("Express", re.compile(r"""from\s+['"]express['"]|require\(\s*['"]express['"]\)|\bexpress\s*\(""", re.I)),
    ("Next.js", re.compile(r"""from\s+['"]next(?:/[^'"]*)?['"]|require\(\s*['"]next(?:/[^'"]*)?['"]\)|['"]next['"]\s*:""", re.I)),
    ("NestJS", re.compile(r"@nestjs/|@Controller\(|@Injectable\(", re.I)),
    ("React", re.compile(r"""from\s+['"]react['"]|require\(\s*['"]react['"]\)""", re.I)),
    ("Gin", re.compile(r"\bgin\.Default\(|\bgin\.New\(|github\.com/gin-gonic/gin", re.I)),
    ("Echo", re.compile(r"\becho\.New\(|github\.com/labstack/echo", re.I)),
    ("Chi", re.compile(r"\bchi\.NewRouter\(|go-chi/chi", re.I)),
    ("Gitea", re.compile(r"code\.gitea\.io/gitea|\bcontext\.APIContext\b", re.I)),
    ("Rails", re.compile(r"\bRails\.application\b|ActionController::Base", re.I)),
    ("Laravel", re.compile(r"Illuminate\\|Route::(get|post|put|patch|delete)\b", re.I)),
    ("Spring", re.compile(r"@RestController|@RequestMapping|springframework", re.I)),
    ("ASP.NET", re.compile(r"Microsoft\.AspNetCore|\[Http(Get|Post|Put|Delete)\]", re.I)),
]

_ENTRYPOINT_DIR_HINTS = (
    "src/app/api",
    "app/api",
    "pages/api",
    "backend/routes",
    "backend/controllers",
    "routes",
    "routers",
    "controllers",
    "handlers",
    "cmd",
    "api",
    "server",
    "apps/api",
    "src/routes",
    "src/controllers",
    "internal/api",
    "internal/router",
    "pkg/api",
)

_AUTH_NAME_HINTS = (
    "auth",
    "authorization",
    "authorize",
    "permission",
    "middleware",
    "jwt",
    "session",
    "policy",
    "rbac",
    "acl",
    "guard",
    "ssrf",
)

_ROUTE_METHOD_PATH = re.compile(
    r"""(?:@\w+\.(get|post|put|patch|delete)\(\s*['"]([^'"]+)['"]"""
    r"""|\.(get|post|put|patch|delete)\(\s*['"]([^'"]+)['"])""",
    re.I,
)
_ROUTE_FLASK = re.compile(r"""@(?:app|bp)\.route\(\s*['"]([^'"]+)['"]""", re.I)
_ROUTE_GO = re.compile(
    r"""\.(?:HandleFunc|Handle|GET|POST|PUT|PATCH|DELETE)\(\s*['"]([^'"]+)['"]""",
    re.I,
)
_ROUTE_LARAVEL = re.compile(
    r"""Route::(?:get|post|put|patch|delete)\(\s*['"]([^'"]+)['"]""",
    re.I,
)
_ROUTE_API_STRING = re.compile(r"""['"](/(?:api|v\d+|local)[^'"]*)['"]""", re.I)

_BUILD_HINTS: dict[str, str] = {
    "dockerfile": "docker",
    "docker-compose.yml": "docker_compose",
    "docker-compose.yaml": "docker_compose",
    "makefile": "make",
    "cmakelists.txt": "cmake",
    "tsconfig.json": "typescript",
    "webpack.config.js": "webpack",
    "vite.config.ts": "vite",
    "vite.config.js": "vite",
    "next.config.js": "next",
    "next.config.mjs": "next",
    "manage.py": "django",
}


class IntakeAgentError(ValueError):
    pass


class IntakeProfile(BaseModel):
    """Project profile from local authorized artifacts (advisory only)."""

    status: str = STATUS_EMPTY
    package_id: str = ""
    package_root: str = ""
    language: list[str] = Field(default_factory=list)
    framework: list[str] = Field(default_factory=list)
    package_managers: list[str] = Field(default_factory=list)
    entrypoints: list[str] = Field(default_factory=list)
    auth_components: list[str] = Field(default_factory=list)
    dependency_manifests: list[str] = Field(default_factory=list)
    build_systems: list[str] = Field(default_factory=list)
    source_files_scanned: int = 0
    artifact_roots: list[str] = Field(default_factory=list)
    signals: list[str] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)
    attack_surface_summary: dict[str, Any] = Field(default_factory=dict)
    execution_allowed: bool = False
    validation_allowed: bool = False
    report_submission_allowed: bool = False
    confirmed_vulnerability: bool = False
    finding_promotion_allowed: bool = False
    network_access: bool = False
    next_allowed_action: str = (
        "Use intake profile as advisory surface context only; no live scan or auto-submit."
    )


def build_intake_profile(
    *,
    package_root: str | Path | None = None,
    package_id: str = "",
    authorized_code_files: list[dict[str, Any]] | None = None,
    max_files: int = _MAX_FILES,
) -> IntakeProfile:
    """Build stack/entrypoint profile from authorized local package and/or code files."""
    root: Path | None = None
    if package_root is not None and str(package_root).strip():
        root = Path(package_root).resolve()

    if root is not None and not root.is_dir():
        return _force_safety(
            IntakeProfile(
                status=STATUS_SKIPPED,
                package_id=package_id or root.name,
                package_root=str(root),
                notes=["package_root_missing"],
            )
        )

    languages: set[str] = set()
    frameworks: set[str] = set()
    managers: set[str] = set()
    entrypoints: list[str] = []
    auth_components: list[str] = []
    dep_manifests: list[str] = []
    build_systems: set[str] = set()
    signals: list[str] = []
    notes: list[str] = []
    artifact_roots: list[str] = []
    scanned = 0

    resolved_package_id = package_id
    if not resolved_package_id and root is not None:
        resolved_package_id = _read_package_id(root) or root.name

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
            languages.update(_languages_from_path(rel))
            frameworks.update(_frameworks_from_text(content))
            for ep in _entrypoints_from_text(rel, content):
                entrypoints.append(ep)
            if _looks_auth_path(rel) and rel not in auth_components:
                auth_components.append(rel)
        if authorized_code_files:
            signals.append("authorized_code_files")

    if root is not None:
        for scan_root, label in _package_scan_roots(root):
            artifact_roots.append(label)
            for path in _iter_files(scan_root, package_root=root, max_files=max_files):
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

                _apply_manifest_filename(
                    path.name,
                    languages=languages,
                    managers=managers,
                    dep_manifests=dep_manifests,
                    rel=rel,
                )
                build = _BUILD_HINTS.get(path.name.lower())
                if build:
                    build_systems.add(build)

                languages.update(_languages_from_path(rel))

                for hint in _ENTRYPOINT_DIR_HINTS:
                    needle = f"/{hint}/"
                    norm = f"/{rel}/"
                    if needle in norm or rel.startswith(hint + "/") or rel == hint:
                        if rel not in entrypoints:
                            entrypoints.append(rel)

                if _looks_auth_path(rel) and rel not in auth_components:
                    auth_components.append(rel)

                if path.suffix.lower() in _LANG_BY_SUFFIX or path.name.lower() in {
                    "package.json",
                    "go.mod",
                    "pyproject.toml",
                    "cargo.toml",
                    "composer.json",
                    "gemfile",
                    "pom.xml",
                    "requirements.txt",
                    "pipfile",
                }:
                    text = _safe_read_text(path)
                    if text is None:
                        continue
                    frameworks.update(_frameworks_from_text(text))
                    for ep in _entrypoints_from_text(rel, text):
                        entrypoints.append(ep)
                    lname = path.name.lower()
                    if lname == "package.json":
                        _apply_package_json(text, frameworks=frameworks, managers=managers)
                    elif lname == "go.mod":
                        _apply_go_mod(text, frameworks=frameworks)
                    elif lname in {"requirements.txt", "pyproject.toml", "pipfile"}:
                        _apply_python_deps(text, frameworks=frameworks)

        signals.append("package_filesystem")

    map_entrypoints = _entrypoints_from_codebase_map(authorized_code_files)
    for ep in map_entrypoints:
        entrypoints.append(ep)
    if map_entrypoints:
        signals.append("codebase_map_routes")

    languages_list = _sorted_unique(languages)
    frameworks_list = _sorted_unique(frameworks)
    managers_list = _sorted_unique(managers)
    entrypoints_list = _sorted_unique(entrypoints)[:80]
    auth_list = _sorted_unique(auth_components)[:60]
    dep_list = _sorted_unique(dep_manifests)[:40]
    build_list = _sorted_unique(build_systems)

    status = STATUS_OK if (scanned > 0 or languages_list or entrypoints_list) else STATUS_EMPTY
    if status == STATUS_EMPTY:
        notes.append("no_source_or_manifest_artifacts")

    surface = {
        "language_count": len(languages_list),
        "framework_count": len(frameworks_list),
        "entrypoint_count": len(entrypoints_list),
        "auth_component_count": len(auth_list),
        "dependency_manifest_count": len(dep_list),
        "primary_language": languages_list[0] if languages_list else "",
        "primary_framework": frameworks_list[0] if frameworks_list else "",
        "has_web_framework": bool(frameworks_list),
        "has_auth_surface": bool(auth_list),
        "has_dependency_manifests": bool(dep_list),
    }

    profile = IntakeProfile(
        status=status,
        package_id=resolved_package_id,
        package_root=str(root) if root is not None else "",
        language=languages_list,
        framework=frameworks_list,
        package_managers=managers_list,
        entrypoints=entrypoints_list,
        auth_components=auth_list,
        dependency_manifests=dep_list,
        build_systems=build_list,
        source_files_scanned=scanned,
        artifact_roots=_sorted_unique(artifact_roots),
        signals=_sorted_unique(signals),
        notes=notes[:40],
        attack_surface_summary=surface,
    )
    return _force_safety(profile)


def load_package_intake_profile(package_root: str | Path | None) -> dict[str, Any]:
    """Load intake profile for an authorized package directory."""
    return build_intake_profile(package_root=package_root).model_dump()


def attach_intake_profile_to_bridge_result(
    bridge_result: dict[str, Any],
    *,
    package_root: str | Path | None = None,
    authorized_code_files: list[dict[str, Any]] | None = None,
    intake_profile: dict[str, Any] | IntakeProfile | None = None,
) -> dict[str, Any]:
    """Attach advisory intake profile to report-bridge result. Never unlocks gates."""
    if not isinstance(bridge_result, dict):
        raise IntakeAgentError("bridge_result_must_be_object")

    package_id = str(bridge_result.get("package_id") or "")
    resolved_root = package_root or bridge_result.get("package_root")

    if isinstance(intake_profile, IntakeProfile):
        payload = intake_profile.model_dump()
    elif isinstance(intake_profile, dict):
        payload = dict(intake_profile)
    else:
        payload = build_intake_profile(
            package_root=resolved_root,
            package_id=package_id,
            authorized_code_files=authorized_code_files,
        ).model_dump()

    if not payload.get("package_id") and package_id:
        payload["package_id"] = package_id
    payload = _force_safety_dict(payload)

    out = dict(bridge_result)
    out["intake_profile"] = payload
    out["intake_profile_present"] = payload.get("status") in {STATUS_OK, STATUS_EMPTY}
    out["stack_languages"] = list(payload.get("language") or [])
    out["stack_frameworks"] = list(payload.get("framework") or [])
    out["stack_entrypoints"] = list(payload.get("entrypoints") or [])
    out["execution_allowed"] = False
    out["validation_allowed"] = False
    out["report_submission_allowed"] = False
    out["confirmed_vulnerability"] = False
    if out.get("submission_blocked") is not True:
        out["submission_blocked"] = True
    return out


def _package_scan_roots(root: Path) -> list[tuple[Path, str]]:
    roots: list[tuple[Path, str]] = []
    for name, label in (
        ("inputs", "inputs"),
        ("_upstream", "_upstream"),
        ("_extract", "_extract"),
    ):
        path = root / name
        if path.is_dir():
            roots.append((path, label))
    roots.append((root, "package_root_manifests"))
    return roots


def _iter_files(
    scan_root: Path,
    *,
    package_root: Path,
    max_files: int,
) -> list[Path]:
    files: list[Path] = []
    if scan_root.is_file():
        return [scan_root]

    # Shallow-only when scanning the package root itself (manifests only).
    if scan_root.resolve() == package_root.resolve():
        try:
            for child in sorted(scan_root.iterdir(), key=lambda p: p.name.lower()):
                if child.is_file():
                    files.append(child)
                if len(files) >= max_files:
                    break
        except OSError:
            return []
        return files

    stack = [scan_root]
    while stack and len(files) < max_files:
        current = stack.pop()
        try:
            entries = sorted(current.iterdir(), key=lambda p: p.name.lower())
        except OSError:
            continue
        for entry in entries:
            if len(files) >= max_files:
                break
            if entry.is_dir():
                if entry.name in _SKIP_DIR_NAMES or entry.name.startswith("."):
                    continue
                stack.append(entry)
            elif entry.is_file():
                try:
                    if entry.stat().st_size > _MAX_FILE_BYTES:
                        continue
                except OSError:
                    continue
                files.append(entry)
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


def _read_package_id(root: Path) -> str:
    for name in ("package.json", "case.json"):
        path = root / name
        if not path.is_file():
            continue
        text = _safe_read_text(path)
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


def _languages_from_path(path: str) -> set[str]:
    suffix = Path(path).suffix.lower()
    lang = _LANG_BY_SUFFIX.get(suffix)
    return {lang} if lang else set()


def _apply_manifest_filename(
    name: str,
    *,
    languages: set[str],
    managers: set[str],
    dep_manifests: list[str],
    rel: str,
) -> None:
    key = name.lower()
    if key.endswith(".csproj"):
        languages.add("C#")
        managers.add("dotnet")
        if rel not in dep_manifests:
            dep_manifests.append(rel)
        return
    hit = _MANIFEST_NAMES.get(key)
    if not hit:
        return
    langs, pms = hit
    languages.update(langs)
    managers.update(pms)
    if rel not in dep_manifests:
        dep_manifests.append(rel)


def _frameworks_from_text(text: str) -> set[str]:
    found: set[str] = set()
    sample = text[:_MAX_CONTENT_SNIFF]
    for name, pattern in _FRAMEWORK_PATTERNS:
        if pattern.search(sample):
            found.add(name)
    return found


def _entrypoints_from_text(path: str, text: str) -> list[str]:
    found: list[str] = []
    sample = text[:_MAX_CONTENT_SNIFF]
    for match in _ROUTE_METHOD_PATH.finditer(sample):
        method = match.group(1) or match.group(3)
        route = match.group(2) or match.group(4)
        if method and route and str(route).startswith("/"):
            found.append(f"{method.upper()} {route}")
    for match in _ROUTE_FLASK.finditer(sample):
        route = match.group(1)
        if route.startswith("/"):
            found.append(route)
    for match in _ROUTE_GO.finditer(sample):
        route = match.group(1)
        if route.startswith("/"):
            found.append(route)
    for match in _ROUTE_LARAVEL.finditer(sample):
        route = match.group(1)
        if route.startswith("/"):
            found.append(route)
    for match in _ROUTE_API_STRING.finditer(sample):
        route = match.group(1)
        if route.startswith("/"):
            found.append(route)

    lower = path.lower().replace("\\", "/")
    if any(
        part in lower
        for part in (
            "/routes/",
            "/routers/",
            "/controllers/",
            "/handlers/",
            "/api/",
            "router.",
            "routes.",
            "main.py",
            "app.py",
            "server.ts",
            "server.js",
        )
    ):
        found.append(path.replace("\\", "/"))
    return found


def _entrypoints_from_codebase_map(
    authorized_code_files: list[dict[str, Any]] | None,
) -> list[str]:
    if not isinstance(authorized_code_files, list) or not authorized_code_files:
        return []
    try:
        from app.codebase_map import map_authorized_code_files
    except Exception:
        return []
    try:
        mapped = map_authorized_code_files({"authorized_code_files": authorized_code_files})
    except Exception:
        return []
    out: list[str] = []
    for fact in getattr(mapped, "facts", []) or []:
        if getattr(fact, "fact_type", None) != "route_handler":
            continue
        method = getattr(fact, "route_method", None) or ""
        route = getattr(fact, "route_path", None) or ""
        path = getattr(fact, "source_path", None) or ""
        if method and route:
            out.append(f"{str(method).upper()} {route}")
        elif path:
            out.append(str(path))
    return out


def _apply_package_json(text: str, *, frameworks: set[str], managers: set[str]) -> None:
    managers.add("npm")
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return
    if not isinstance(data, dict):
        return
    deps: dict[str, Any] = {}
    for key in ("dependencies", "devDependencies", "peerDependencies"):
        block = data.get(key)
        if isinstance(block, dict):
            deps.update(block)
    names = {str(k).lower() for k in deps}
    if "express" in names:
        frameworks.add("Express")
    if "next" in names:
        frameworks.add("Next.js")
    if "@nestjs/core" in names or any(n.startswith("@nestjs/") for n in names):
        frameworks.add("NestJS")
    if "react" in names:
        frameworks.add("React")
    if "fastapi" in names:
        frameworks.add("FastAPI")


def _apply_go_mod(text: str, *, frameworks: set[str]) -> None:
    lower = text.lower()
    if "github.com/gin-gonic/gin" in lower:
        frameworks.add("Gin")
    if "github.com/labstack/echo" in lower:
        frameworks.add("Echo")
    if "github.com/go-chi/chi" in lower:
        frameworks.add("Chi")
    if "code.gitea.io/gitea" in lower or "gitea" in lower:
        frameworks.add("Gitea")


def _apply_python_deps(text: str, *, frameworks: set[str]) -> None:
    lower = text.lower()
    if "fastapi" in lower:
        frameworks.add("FastAPI")
    if "flask" in lower:
        frameworks.add("Flask")
    if "django" in lower:
        frameworks.add("Django")


def _looks_auth_path(path: str) -> bool:
    lower = path.lower().replace("\\", "/")
    name = Path(lower).name
    parts = lower.split("/")
    for hint in _AUTH_NAME_HINTS:
        if hint in name or any(hint in part for part in parts):
            return True
    return False


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
    if isinstance(values, set):
        iterable = values
    else:
        iterable = values or []
    for value in iterable:
        text = str(value).strip()
        if text:
            items.add(text)
    return sorted(items, key=lambda s: s.lower())


def _force_safety(profile: IntakeProfile) -> IntakeProfile:
    return IntakeProfile.model_validate(_force_safety_dict(profile.model_dump()))


def _force_safety_dict(payload: dict[str, Any]) -> dict[str, Any]:
    out = dict(payload)
    out["execution_allowed"] = False
    out["validation_allowed"] = False
    out["report_submission_allowed"] = False
    out["confirmed_vulnerability"] = False
    out["finding_promotion_allowed"] = False
    out["network_access"] = False
    if not out.get("next_allowed_action"):
        out["next_allowed_action"] = (
            "Use intake profile as advisory surface context only; no live scan or auto-submit."
        )
    return out


__all__ = [
    "STATUS_OK",
    "STATUS_EMPTY",
    "STATUS_SKIPPED",
    "IntakeAgentError",
    "IntakeProfile",
    "build_intake_profile",
    "load_package_intake_profile",
    "attach_intake_profile_to_bridge_result",
]
