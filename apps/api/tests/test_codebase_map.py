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
        "sink_symbols": ["send_file"],
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


def test_map_authorized_code_files_treats_owner_filter_as_authz_check():
    result = map_authorized_code_files(
        {
            "authorized_code_files": [
                {
                    "path": "apps/api/routes/files.py",
                    "content": """
from fastapi import APIRouter

router = APIRouter()

@router.get("/files/{file_id}/export")
def export_file(file_id: str, user_id: str):
    file = db.query(File).filter(File.id == file_id, File.owner_id == user_id).one()
    return send_file(file.path)
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
    assert authz.symbol_name == "owner_id_filter"
    assert authz.authz_hint == "owner_or_admin_check"
    assert authz.payload == {
        "handler": "export_file",
        "line": 8,
        "mapping_mode": "static_code_snippet_analysis",
    }


def test_map_authorized_code_files_treats_tenant_filter_as_authz_check():
    result = map_authorized_code_files(
        {
            "authorized_code_files": [
                {
                    "path": "apps/api/routes/invoices.py",
                    "content": """
from fastapi import APIRouter

router = APIRouter()

@router.get("/invoices/{invoice_id}/export")
def export_invoice(invoice_id: str, current_user):
    invoice = db.query(Invoice).filter(
        Invoice.id == invoice_id,
        Invoice.tenant_id == current_user.tenant_id,
    ).one()
    return send_file(invoice.path)
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
    assert authz.symbol_name == "tenant_id_filter"
    assert authz.authz_hint == "ownership_boundary_check"
    assert authz.payload == {
        "handler": "export_invoice",
        "line": 10,
        "mapping_mode": "static_code_snippet_analysis",
    }


def test_map_authorized_code_files_treats_account_relation_comparison_as_authz_check():
    result = map_authorized_code_files(
        {
            "authorized_code_files": [
                {
                    "path": "apps/api/routes/files.py",
                    "content": """
from fastapi import APIRouter

router = APIRouter()

@router.get("/files/{file_id}/export")
def export_file(file_id: str, current_user):
    file = db.query(File).filter(File.id == file_id, File.account == current_user.account).one()
    return send_file(file.path)
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
    assert authz.symbol_name == "account_id_filter"
    assert authz.authz_hint == "ownership_boundary_check"
    assert authz.payload == {
        "handler": "export_file",
        "line": 8,
        "mapping_mode": "static_code_snippet_analysis",
    }


def test_map_authorized_code_files_treats_filter_by_account_boundary_as_authz_check():
    result = map_authorized_code_files(
        {
            "authorized_code_files": [
                {
                    "path": "apps/api/routes/files.py",
                    "content": """
from fastapi import APIRouter

router = APIRouter()

@router.get("/files/{file_id}/export")
def export_file(file_id: str, current_user):
    file = db.query(File).filter_by(id=file_id, account_id=current_user.account_id).one()
    return send_file(file.path)
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
    assert authz.symbol_name == "account_id_filter"
    assert authz.authz_hint == "ownership_boundary_check"
    assert authz.payload == {
        "handler": "export_file",
        "line": 8,
        "mapping_mode": "static_code_snippet_analysis",
    }


def test_map_authorized_code_files_treats_account_relation_boundary_as_authz_check():
    result = map_authorized_code_files(
        {
            "authorized_code_files": [
                {
                    "path": "apps/api/routes/files.py",
                    "content": """
from fastapi import APIRouter

router = APIRouter()

@router.get("/files/{file_id}/export")
def export_file(file_id: str, current_user):
    file = File.objects.filter(id=file_id, account=current_user.account).get()
    return send_file(file.path)
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
    assert authz.symbol_name == "account_id_filter"
    assert authz.authz_hint == "ownership_boundary_check"
    assert authz.payload == {
        "handler": "export_file",
        "line": 8,
        "mapping_mode": "static_code_snippet_analysis",
    }


def test_map_authorized_code_files_treats_org_relation_alias_boundary_as_authz_check():
    result = map_authorized_code_files(
        {
            "authorized_code_files": [
                {
                    "path": "apps/api/routes/files.py",
                    "content": """
from fastapi import APIRouter

router = APIRouter()

@router.get("/files/{file_id}/export")
def export_file(file_id: str, current_user):
    file = File.objects.filter(id=file_id, org=current_user.organization).get()
    return send_file(file.path)
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
    assert authz.symbol_name == "org_id_filter"
    assert authz.authz_hint == "ownership_boundary_check"
    assert authz.payload == {
        "handler": "export_file",
        "line": 8,
        "mapping_mode": "static_code_snippet_analysis",
    }


def test_map_authorized_code_files_treats_account_relation_membership_boundary_as_authz_check():
    result = map_authorized_code_files(
        {
            "authorized_code_files": [
                {
                    "path": "apps/api/routes/files.py",
                    "content": """
from fastapi import APIRouter

router = APIRouter()

@router.get("/files/{file_id}/export")
def export_file(file_id: str, current_user):
    file = File.objects.filter(id=file_id, account__in=current_user.accounts).get()
    return send_file(file.path)
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
    assert authz.symbol_name == "account_id_filter"
    assert authz.authz_hint == "ownership_boundary_check"
    assert authz.payload == {
        "handler": "export_file",
        "line": 8,
        "mapping_mode": "static_code_snippet_analysis",
    }


def test_map_authorized_code_files_treats_double_underscore_account_boundary_as_authz_check():
    result = map_authorized_code_files(
        {
            "authorized_code_files": [
                {
                    "path": "apps/api/routes/files.py",
                    "content": """
from fastapi import APIRouter

router = APIRouter()

@router.get("/files/{file_id}/export")
def export_file(file_id: str, current_user):
    file = File.objects.filter(id=file_id, account__id=current_user.account_id).get()
    return send_file(file.path)
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
    assert authz.symbol_name == "account_id_filter"
    assert authz.authz_hint == "ownership_boundary_check"
    assert authz.payload == {
        "handler": "export_file",
        "line": 8,
        "mapping_mode": "static_code_snippet_analysis",
    }


def test_map_authorized_code_files_treats_double_underscore_in_account_boundary_as_authz_check():
    result = map_authorized_code_files(
        {
            "authorized_code_files": [
                {
                    "path": "apps/api/routes/files.py",
                    "content": """
from fastapi import APIRouter

router = APIRouter()

@router.get("/files/{file_id}/export")
def export_file(file_id: str, current_user):
    file = File.objects.filter(id=file_id, account_id__in=current_user.account_ids).get()
    return send_file(file.path)
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
    assert authz.symbol_name == "account_id_filter"
    assert authz.authz_hint == "ownership_boundary_check"
    assert authz.payload == {
        "handler": "export_file",
        "line": 8,
        "mapping_mode": "static_code_snippet_analysis",
    }


def test_map_authorized_code_files_treats_membership_boundary_as_authz_check():
    result = map_authorized_code_files(
        {
            "authorized_code_files": [
                {
                    "path": "apps/api/routes/invoices.py",
                    "content": """
from fastapi import APIRouter

router = APIRouter()

@router.get("/invoices/{invoice_id}/export")
def export_invoice(invoice_id: str, current_user):
    invoice = db.query(Invoice).filter(
        Invoice.id == invoice_id,
        Invoice.tenant_id.in_(current_user.tenant_ids),
    ).one()
    return send_file(invoice.path)
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
    assert authz.symbol_name == "tenant_id_filter"
    assert authz.authz_hint == "ownership_boundary_check"
    assert authz.payload == {
        "handler": "export_invoice",
        "line": 10,
        "mapping_mode": "static_code_snippet_analysis",
    }


def test_map_authorized_code_files_treats_relation_membership_method_as_authz_check():
    result = map_authorized_code_files(
        {
            "authorized_code_files": [
                {
                    "path": "apps/api/routes/files.py",
                    "content": """
from fastapi import APIRouter

router = APIRouter()

@router.get("/files/{file_id}/export")
def export_file(file_id: str, current_user):
    file = db.query(File).filter(
        File.id == file_id,
        File.account.in_(current_user.accounts),
    ).one()
    return send_file(file.path)
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
    assert authz.symbol_name == "account_id_filter"
    assert authz.authz_hint == "ownership_boundary_check"
    assert authz.payload == {
        "handler": "export_file",
        "line": 10,
        "mapping_mode": "static_code_snippet_analysis",
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


def test_map_authorized_code_files_treats_multiline_scoped_security_as_route_authz():
    result = map_authorized_code_files(
        {
            "authorized_code_files": [
                {
                    "path": "apps/api/routes/files.py",
                    "content": """
from fastapi import APIRouter, Security

router = APIRouter()

@router.get(
    "/files/{file_id}/export",
    dependencies=[
        Security(
            require_user,
            scopes=["files:export"],
        )
    ],
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
        "line": 10,
        "mapping_mode": "static_code_snippet_analysis",
    }


def test_map_authorized_code_files_treats_imported_authz_alias_as_route_authz():
    result = map_authorized_code_files(
        {
            "authorized_code_files": [
                {
                    "path": "apps/api/routes/files.py",
                    "content": """
from fastapi import APIRouter, Depends
from app.auth import require_user as RequireUser

router = APIRouter()

@router.get("/files/{file_id}/export")
def export_file(file_id: str, user=Depends(RequireUser)):
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


def test_map_authorized_code_files_treats_dependency_alias_in_signature_as_route_authz():
    result = map_authorized_code_files(
        {
            "authorized_code_files": [
                {
                    "path": "apps/api/routes/files.py",
                    "content": """
from fastapi import APIRouter, Depends

router = APIRouter()
CurrentUser = Depends(require_user)

@router.get("/files/{file_id}/export")
def export_file(file_id: str, user=CurrentUser):
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
        "line": 8,
        "mapping_mode": "static_code_snippet_analysis",
    }


def test_map_authorized_code_files_treats_dependency_alias_in_decorator_as_route_authz():
    result = map_authorized_code_files(
        {
            "authorized_code_files": [
                {
                    "path": "apps/api/routes/files.py",
                    "content": """
from fastapi import APIRouter, Depends

router = APIRouter()
CurrentUser = Depends(require_user)

@router.get("/files/{file_id}/export", dependencies=[CurrentUser])
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
        "line": 7,
        "mapping_mode": "static_code_snippet_analysis",
    }


def test_map_authorized_code_files_treats_dependency_wrapper_as_route_authz():
    result = map_authorized_code_files(
        {
            "authorized_code_files": [
                {
                    "path": "apps/api/routes/files.py",
                    "content": """
from fastapi import APIRouter, Depends
from app.dependencies import current_user

router = APIRouter()

@router.get("/files/{file_id}/export")
def export_file(file_id: str, user=Depends(current_user)):
    return send_file(file_id)
""",
                },
                {
                    "path": "apps/api/dependencies.py",
                    "content": """
from fastapi import Depends
from app.auth import require_user

def current_user(user=Depends(require_user)):
    return user
""",
                },
            ]
        }
    )

    fact_types = [fact.fact_type for fact in result.facts]
    route_authz = [
        fact
        for fact in result.facts
        if fact.fact_type == "authz_check"
        and fact.payload.get("handler") == "export_file"
    ]

    assert fact_types.count("route_handler") == 1
    assert fact_types.count("sensitive_sink") == 1
    assert "authorization_gap_candidate" not in fact_types
    assert route_authz[0].symbol_name == "require_user"
    assert route_authz[0].payload == {
        "handler": "export_file",
        "line": 8,
        "mapping_mode": "static_code_snippet_analysis",
    }


def test_map_authorized_code_files_treats_dependency_wrapper_chain_as_route_authz():
    result = map_authorized_code_files(
        {
            "authorized_code_files": [
                {
                    "path": "apps/api/routes/files.py",
                    "content": """
from fastapi import APIRouter, Depends
from app.dependencies import current_active_user

router = APIRouter()

@router.get("/files/{file_id}/export")
def export_file(file_id: str, user=Depends(current_active_user)):
    return send_file(file_id)
""",
                },
                {
                    "path": "apps/api/dependencies.py",
                    "content": """
from fastapi import Depends
from app.auth import require_user

def current_active_user(user=Depends(current_user)):
    return user

def current_user(user=Depends(require_user)):
    return user
""",
                },
            ]
        }
    )

    fact_types = [fact.fact_type for fact in result.facts]
    route_authz = [
        fact
        for fact in result.facts
        if fact.fact_type == "authz_check"
        and fact.payload.get("handler") == "export_file"
    ]

    assert fact_types.count("route_handler") == 1
    assert fact_types.count("sensitive_sink") == 1
    assert "authorization_gap_candidate" not in fact_types
    assert route_authz[0].symbol_name == "require_user"


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


def test_map_authorized_code_files_does_not_mark_gap_when_repository_layer_has_owner_filter():
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
def export_file(file_id: str, current_user):
    return export_file_for_user(file_id, current_user)
""",
                },
                {
                    "path": "apps/api/services/files.py",
                    "content": """
from app.repositories.files import load_file_for_user

def export_file_for_user(file_id: str, current_user):
    file = load_file_for_user(file_id, current_user)
    return send_file(file.path)
""",
                },
                {
                    "path": "apps/api/repositories/files.py",
                    "content": """
def load_file_for_user(file_id: str, current_user):
    return db.query(File).filter_by(id=file_id, account_id=current_user.account_id).one()
""",
                },
            ]
        }
    )

    fact_types = [fact.fact_type for fact in result.facts]
    service_calls = [
        fact.symbol_name for fact in result.facts if fact.fact_type == "service_call"
    ]

    assert fact_types.count("route_handler") == 1
    assert "export_file_for_user" in service_calls
    assert "load_file_for_user" in service_calls
    assert fact_types.count("authz_check") == 1
    assert fact_types.count("sensitive_sink") == 1
    assert "authorization_gap_candidate" not in fact_types


def test_map_authorized_code_files_follows_imported_service_alias_to_repository_owner_filter():
    result = map_authorized_code_files(
        {
            "authorized_code_files": [
                {
                    "path": "apps/api/routes/files.py",
                    "content": """
from fastapi import APIRouter
from app.services.files import export_file_for_user as export_for_user

router = APIRouter()

@router.get("/files/{file_id}/export")
def export_file(file_id: str, current_user):
    return export_for_user(file_id, current_user)
""",
                },
                {
                    "path": "apps/api/services/files.py",
                    "content": """
from app.repositories.files import load_file_for_user

def export_file_for_user(file_id: str, current_user):
    file = load_file_for_user(file_id, current_user)
    return send_file(file.path)
""",
                },
                {
                    "path": "apps/api/repositories/files.py",
                    "content": """
def load_file_for_user(file_id: str, current_user):
    return db.query(File).filter_by(id=file_id, account_id=current_user.account_id).one()
""",
                },
            ]
        }
    )

    fact_types = [fact.fact_type for fact in result.facts]
    service_calls = [
        fact.symbol_name for fact in result.facts if fact.fact_type == "service_call"
    ]

    assert "export_file_for_user" in service_calls
    assert "export_for_user" not in service_calls
    assert "load_file_for_user" in service_calls
    assert fact_types.count("authz_check") == 1
    assert fact_types.count("sensitive_sink") == 1
    assert "authorization_gap_candidate" not in fact_types


def test_map_authorized_code_files_follows_local_method_alias_to_repository_owner_filter():
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
def export_file(file_id: str, current_user):
    return export_file_for_user(file_id, current_user)
""",
                },
                {
                    "path": "apps/api/services/files.py",
                    "content": """
from app.repositories.files import FileRepository

def export_file_for_user(file_id: str, current_user):
    repository = FileRepository()
    loader = repository.load_for_user
    file = loader(file_id, current_user)
    return send_file(file.path)
""",
                },
                {
                    "path": "apps/api/repositories/files.py",
                    "content": """
class FileRepository:
    def load_for_user(self, file_id: str, current_user):
        return db.query(File).filter_by(id=file_id, account_id=current_user.account_id).one()
""",
                },
            ]
        }
    )

    fact_types = [fact.fact_type for fact in result.facts]
    service_calls = [
        fact.symbol_name for fact in result.facts if fact.fact_type == "service_call"
    ]

    assert "export_file_for_user" in service_calls
    assert "load_for_user" in service_calls
    assert "loader" not in service_calls
    assert fact_types.count("authz_check") == 1
    assert fact_types.count("sensitive_sink") == 1
    assert "authorization_gap_candidate" not in fact_types


def test_map_authorized_code_files_follows_chained_local_alias_to_repository_owner_filter():
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
def export_file(file_id: str, current_user):
    return export_file_for_user(file_id, current_user)
""",
                },
                {
                    "path": "apps/api/services/files.py",
                    "content": """
from app.repositories.files import FileRepository

def export_file_for_user(file_id: str, current_user):
    repository = FileRepository()
    loader = repository.load_for_user
    safe_loader = loader
    file = safe_loader(file_id, current_user)
    return send_file(file.path)
""",
                },
                {
                    "path": "apps/api/repositories/files.py",
                    "content": """
class FileRepository:
    def load_for_user(self, file_id: str, current_user):
        return db.query(File).filter_by(id=file_id, account_id=current_user.account_id).one()
""",
                },
            ]
        }
    )

    fact_types = [fact.fact_type for fact in result.facts]
    service_calls = [
        fact.symbol_name for fact in result.facts if fact.fact_type == "service_call"
    ]

    assert "export_file_for_user" in service_calls
    assert "load_for_user" in service_calls
    assert "safe_loader" not in service_calls
    assert fact_types.count("authz_check") == 1
    assert fact_types.count("sensitive_sink") == 1
    assert "authorization_gap_candidate" not in fact_types


def test_map_authorized_code_files_follows_same_class_field_alias_to_repository_owner_filter():
    result = map_authorized_code_files(
        {
            "authorized_code_files": [
                {
                    "path": "apps/api/routes/files.py",
                    "content": """
from fastapi import APIRouter
from app.services.files import FileExportService

router = APIRouter()

@router.get("/files/{file_id}/export")
def export_file(file_id: str, current_user):
    service = FileExportService()
    return service.export_file_for_user(file_id, current_user)
""",
                },
                {
                    "path": "apps/api/services/files.py",
                    "content": """
from app.repositories.files import FileRepository

class FileExportService:
    def __init__(self):
        repository = FileRepository()
        self.loader = repository.load_for_user

    def export_file_for_user(self, file_id: str, current_user):
        file = self.loader(file_id, current_user)
        return send_file(file.path)
""",
                },
                {
                    "path": "apps/api/repositories/files.py",
                    "content": """
class FileRepository:
    def load_for_user(self, file_id: str, current_user):
        return db.query(File).filter_by(id=file_id, account_id=current_user.account_id).one()
""",
                },
            ]
        }
    )

    fact_types = [fact.fact_type for fact in result.facts]
    service_calls = [
        fact.symbol_name for fact in result.facts if fact.fact_type == "service_call"
    ]

    assert "export_file_for_user" in service_calls
    assert "load_for_user" in service_calls
    assert "loader" not in service_calls
    assert fact_types.count("authz_check") == 1
    assert fact_types.count("sensitive_sink") == 1
    assert "authorization_gap_candidate" not in fact_types


def test_map_authorized_code_files_follows_chained_same_class_field_alias_to_repository_owner_filter():
    result = map_authorized_code_files(
        {
            "authorized_code_files": [
                {
                    "path": "apps/api/routes/files.py",
                    "content": """
from fastapi import APIRouter
from app.services.files import FileExportService

router = APIRouter()

@router.get("/files/{file_id}/export")
def export_file(file_id: str, current_user):
    service = FileExportService()
    return service.export_file_for_user(file_id, current_user)
""",
                },
                {
                    "path": "apps/api/services/files.py",
                    "content": """
from app.repositories.files import FileRepository

class FileExportService:
    def __init__(self):
        repository = FileRepository()
        self.loader = repository.load_for_user
        self.safe_loader = self.loader

    def export_file_for_user(self, file_id: str, current_user):
        file = self.safe_loader(file_id, current_user)
        return send_file(file.path)
""",
                },
                {
                    "path": "apps/api/repositories/files.py",
                    "content": """
class FileRepository:
    def load_for_user(self, file_id: str, current_user):
        return db.query(File).filter_by(id=file_id, account_id=current_user.account_id).one()
""",
                },
            ]
        }
    )

    fact_types = [fact.fact_type for fact in result.facts]
    service_calls = [
        fact.symbol_name for fact in result.facts if fact.fact_type == "service_call"
    ]

    assert "export_file_for_user" in service_calls
    assert "load_for_user" in service_calls
    assert "safe_loader" not in service_calls
    assert fact_types.count("authz_check") == 1
    assert fact_types.count("sensitive_sink") == 1
    assert "authorization_gap_candidate" not in fact_types


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
