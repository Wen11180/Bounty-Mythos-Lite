from app.codebase_map import map_authorized_code_files


def test_map_authorized_code_files_marks_sensitive_route_without_authz_as_gap_candidate():
    result = map_authorized_code_files(
        {
            "authorized_code_files": [
                {
                    "path": "apps/api/routes/files.py",
                    "content": """
from fastapi import APIRouter

router = APIRouter()

@router.get("/files/{file_id}/export")
def export_file(file_id: str):
    return send_file(file_id)
""",
                }
            ]
        }
    )

    fact_types = [fact.fact_type for fact in result.facts]
    gap = next(
        fact for fact in result.facts if fact.fact_type == "authorization_gap_candidate"
    )

    assert fact_types.count("route_handler") == 1
    assert fact_types.count("sensitive_sink") == 1
    assert fact_types.count("authorization_gap_candidate") == 1
    assert gap.symbol_name == "export_file"
    assert gap.route_method == "GET"
    assert gap.route_path == "/files/{file_id}/export"
    assert gap.authz_hint == "missing_handler_authz_check"
    assert gap.sensitivity_label == "high"
    assert gap.payload == {
        "handler": "export_file",
        "mapping_mode": "static_code_snippet_analysis",
        "review_state": "needs_human_review",
        "sink_count": 1,
    }
    assert "send_file(file_id)" not in str(gap.payload)
    assert "Authorization" not in str(gap.payload)
    assert "Bearer" not in str(gap.payload)


def test_map_authorized_code_files_does_not_mark_gap_when_handler_has_authz():
    result = map_authorized_code_files(
        {
            "authorized_code_files": [
                {
                    "path": "apps/api/routes/files.py",
                    "content": """
from fastapi import APIRouter

router = APIRouter()

@router.get("/files/{file_id}/export")
def export_file(file_id: str):
    authorize_owner_or_admin(file_id)
    return send_file(file_id)
""",
                }
            ]
        }
    )

    assert {fact.fact_type for fact in result.facts} == {
        "route_handler",
        "authz_check",
        "sensitive_sink",
    }


def test_map_authorized_code_files_treats_dependency_injected_authz_as_route_authz():
    result = map_authorized_code_files(
        {
            "authorized_code_files": [
                {
                    "path": "apps/api/routes/files.py",
                    "content": """
from fastapi import APIRouter, Depends

router = APIRouter()

@router.get("/files/{file_id}/export")
def export_file(file_id: str, user=Depends(require_user)):
    return send_file(file_id)
""",
                }
            ]
        }
    )

    fact_types = [fact.fact_type for fact in result.facts]
    authz = next(fact for fact in result.facts if fact.fact_type == "authz_check")

    assert fact_types.count("route_handler") == 1
    assert fact_types.count("authz_check") == 1
    assert fact_types.count("sensitive_sink") == 1
    assert "authorization_gap_candidate" not in fact_types
    assert authz.symbol_name == "require_user"
    assert authz.payload == {
        "handler": "export_file",
        "line": 7,
        "mapping_mode": "static_code_snippet_analysis",
    }


def test_map_authorized_code_files_treats_decorator_dependency_authz_as_route_authz():
    result = map_authorized_code_files(
        {
            "authorized_code_files": [
                {
                    "path": "apps/api/routes/files.py",
                    "content": """
from fastapi import APIRouter, Depends

router = APIRouter()

@router.get("/files/{file_id}/export", dependencies=[Depends(require_user)])
def export_file(file_id: str):
    return send_file(file_id)
""",
                }
            ]
        }
    )

    fact_types = [fact.fact_type for fact in result.facts]
    authz = next(fact for fact in result.facts if fact.fact_type == "authz_check")

    assert fact_types.count("route_handler") == 1
    assert fact_types.count("authz_check") == 1
    assert fact_types.count("sensitive_sink") == 1
    assert "authorization_gap_candidate" not in fact_types
    assert authz.symbol_name == "require_user"
    assert authz.payload == {
        "handler": "export_file",
        "line": 6,
        "mapping_mode": "static_code_snippet_analysis",
    }


def test_map_authorized_code_files_treats_multiline_decorator_dependency_authz_as_route_authz():
    result = map_authorized_code_files(
        {
            "authorized_code_files": [
                {
                    "path": "apps/api/routes/files.py",
                    "content": """
from fastapi import APIRouter, Depends

router = APIRouter()

@router.get(
    "/files/{file_id}/export",
    dependencies=[Depends(require_user)],
)
def export_file(file_id: str):
    return send_file(file_id)
""",
                }
            ]
        }
    )

    route = next(fact for fact in result.facts if fact.fact_type == "route_handler")
    fact_types = [fact.fact_type for fact in result.facts]
    authz = next(fact for fact in result.facts if fact.fact_type == "authz_check")

    assert fact_types.count("route_handler") == 1
    assert fact_types.count("authz_check") == 1
    assert fact_types.count("sensitive_sink") == 1
    assert "authorization_gap_candidate" not in fact_types
    assert route.route_path == "/files/{file_id}/export"
    assert authz.symbol_name == "require_user"
    assert authz.payload == {
        "handler": "export_file",
        "line": 8,
        "mapping_mode": "static_code_snippet_analysis",
    }


def test_map_authorized_code_files_treats_security_dependency_authz_as_route_authz():
    result = map_authorized_code_files(
        {
            "authorized_code_files": [
                {
                    "path": "apps/api/routes/files.py",
                    "content": """
from fastapi import APIRouter, Security

router = APIRouter()

@router.get("/files/{file_id}/export")
def export_file(file_id: str, user=Security(require_user)):
    return send_file(file_id)
""",
                }
            ]
        }
    )

    fact_types = [fact.fact_type for fact in result.facts]
    authz = next(fact for fact in result.facts if fact.fact_type == "authz_check")

    assert fact_types.count("route_handler") == 1
    assert fact_types.count("authz_check") == 1
    assert fact_types.count("sensitive_sink") == 1
    assert "authorization_gap_candidate" not in fact_types
    assert authz.symbol_name == "require_user"
    assert authz.payload == {
        "handler": "export_file",
        "line": 7,
        "mapping_mode": "static_code_snippet_analysis",
    }


def test_map_authorized_code_files_treats_multiline_signature_dependency_authz_as_route_authz():
    result = map_authorized_code_files(
        {
            "authorized_code_files": [
                {
                    "path": "apps/api/routes/files.py",
                    "content": """
from fastapi import APIRouter, Depends

router = APIRouter()

@router.get("/files/{file_id}/export")
def export_file(
    file_id: str,
    user=Depends(require_user),
):
    return send_file(file_id)
""",
                }
            ]
        }
    )

    fact_types = [fact.fact_type for fact in result.facts]
    authz = next(fact for fact in result.facts if fact.fact_type == "authz_check")

    assert fact_types.count("route_handler") == 1
    assert fact_types.count("authz_check") == 1
    assert fact_types.count("sensitive_sink") == 1
    assert "authorization_gap_candidate" not in fact_types
    assert authz.symbol_name == "require_user"
    assert authz.payload == {
        "handler": "export_file",
        "line": 9,
        "mapping_mode": "static_code_snippet_analysis",
    }


def test_map_authorized_code_files_treats_decorator_security_authz_as_route_authz():
    result = map_authorized_code_files(
        {
            "authorized_code_files": [
                {
                    "path": "apps/api/routes/files.py",
                    "content": """
from fastapi import APIRouter, Security

router = APIRouter()

@router.get("/files/{file_id}/export", dependencies=[Security(require_user)])
def export_file(file_id: str):
    return send_file(file_id)
""",
                }
            ]
        }
    )

    fact_types = [fact.fact_type for fact in result.facts]
    authz = next(fact for fact in result.facts if fact.fact_type == "authz_check")

    assert fact_types.count("route_handler") == 1
    assert fact_types.count("authz_check") == 1
    assert fact_types.count("sensitive_sink") == 1
    assert "authorization_gap_candidate" not in fact_types
    assert authz.symbol_name == "require_user"
    assert authz.payload == {
        "handler": "export_file",
        "line": 6,
        "mapping_mode": "static_code_snippet_analysis",
    }


def test_map_authorized_code_files_does_not_mark_gap_when_service_layer_has_authz():
    result = map_authorized_code_files(
        {
            "authorized_code_files": [
                {
                    "path": "apps/api/routes/files.py",
                    "content": """
from fastapi import APIRouter
from app.services.files import export_file_for_user

router = APIRouter()

@router.get("/files/{file_id}/export")
def export_file(file_id: str, user_id: str):
    return export_file_for_user(file_id, user_id)
""",
                },
                {
                    "path": "apps/api/services/files.py",
                    "content": """
def export_file_for_user(file_id: str, user_id: str):
    authorize_owner_or_admin(file_id, user_id)
    return send_file(file_id)
""",
                },
            ]
        }
    )

    fact_types = [fact.fact_type for fact in result.facts]
    service_call = next(
        fact for fact in result.facts if fact.fact_type == "service_call"
    )

    assert fact_types.count("route_handler") == 1
    assert fact_types.count("service_call") == 1
    assert fact_types.count("authz_check") == 1
    assert fact_types.count("sensitive_sink") == 1
    assert "authorization_gap_candidate" not in fact_types
    assert service_call.symbol_name == "export_file_for_user"
    assert service_call.payload == {
        "caller": "export_file",
        "line": 9,
        "mapping_mode": "static_code_snippet_analysis",
    }


def test_map_authorized_code_files_preserves_tab_indented_handler_scope():
    result = map_authorized_code_files(
        {
            "authorized_code_files": [
                {
                    "path": "apps/api/routes/files.py",
                    "content": (
                        'from fastapi import APIRouter\n\n'
                        'router = APIRouter()\n\n'
                        '@router.get("/files/{file_id}/export")\n'
                        'def export_file(file_id: str):\n'
                        '\tauthorize_owner_or_admin(file_id)\n'
                        '\treturn send_file(file_id)\n'
                    ),
                }
            ]
        }
    )

    scoped_facts = {
        (fact.fact_type, fact.symbol_name): fact.payload.get("handler")
        for fact in result.facts
    }

    assert scoped_facts == {
        ("route_handler", "export_file"): "export_file",
        ("authz_check", "authorize_owner_or_admin"): "export_file",
        ("sensitive_sink", "send_file"): "export_file",
    }


def test_map_authorized_code_files_restores_handler_scope_after_nested_function():
    result = map_authorized_code_files(
        {
            "authorized_code_files": [
                {
                    "path": "apps/api/routes/files.py",
                    "content": """
from fastapi import APIRouter

router = APIRouter()

@router.get("/files/{file_id}/export")
def export_file(file_id: str):
    def format_label() -> str:
        return "file"

    authorize_owner_or_admin(file_id)
    return send_file(file_id)
""",
                }
            ]
        }
    )

    scoped_facts = {
        (fact.fact_type, fact.symbol_name): fact.payload.get("handler")
        for fact in result.facts
    }

    assert scoped_facts == {
        ("route_handler", "export_file"): "export_file",
        ("authz_check", "authorize_owner_or_admin"): "export_file",
        ("sensitive_sink", "send_file"): "export_file",
    }
