"""Regression checks for deterministic FastAPI route registration."""

import ast
from collections import defaultdict
from pathlib import Path

from fastapi.routing import APIRoute

from app.main import app


ACTIVE_ROUTER_MODULES = (
    "health.py",
    "programs.py",
    "control_center.py",
    "internal.py",
    "program_rules.py",
    "artifacts.py",
    "approvals.py",
)


def _top_level_function_names(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    return {
        node.name
        for node in tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    }


def test_registered_http_methods_have_one_handler_per_path():
    routes: dict[tuple[str, str], list[str]] = defaultdict(list)
    for route in app.routes:
        if isinstance(route, APIRoute):
            for method in route.methods:
                routes[(method, route.path)].append(route.name)

    duplicates = {
        f"{method} {path}": names
        for (method, path), names in routes.items()
        if len(names) > 1
    }

    assert duplicates == {}


def test_active_router_implementations_are_not_left_in_main():
    app_root = Path(__file__).resolve().parents[1] / "app"
    main_names = _top_level_function_names(app_root / "main.py")
    duplicates = {
        router_module: sorted(
            main_names
            & _top_level_function_names(app_root / "routers" / router_module)
        )
        for router_module in ACTIVE_ROUTER_MODULES
    }

    assert duplicates == {router_module: [] for router_module in ACTIVE_ROUTER_MODULES}
