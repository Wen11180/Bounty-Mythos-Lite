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
        "root_cause": "missing_object_ownership_check",
        "security_invariant": (
            "Object-level actions must verify requester ownership or role before sensitive sinks run."
        ),
        "sink_count": 1,
        "sink_symbols": ["send_file"],
    }
    assert "send_file(file_id)" not in str(gap.payload)
    assert "Authorization" not in str(gap.payload)
    assert "Bearer" not in str(gap.payload)


def test_map_authorized_code_files_marks_flask_sensitive_route_without_authz_as_gap_candidate():
    result = map_authorized_code_files(
        {
            "authorized_code_files": [
                {
                    "path": "apps/api/routes/files.py",
                    "content": """
from flask import Flask, send_file

app = Flask(__name__)

@app.route("/files/<file_id>/export", methods=["GET"])
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
    assert gap.route_path == "/files/<file_id>/export"
    assert gap.authz_hint == "missing_handler_authz_check"
    assert gap.sensitivity_label == "high"


def test_map_authorized_code_files_treats_flask_login_required_as_route_authz():
    result = map_authorized_code_files(
        {
            "authorized_code_files": [
                {
                    "path": "apps/api/routes/files.py",
                    "content": """
from flask import Flask, send_file
from flask_login import login_required

app = Flask(__name__)

@app.route("/files/<file_id>/export", methods=["GET"])
@login_required
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
    assert authz.symbol_name == "login_required"
    assert authz.payload == {
        "handler": "export_file",
        "line": 8,
        "mapping_mode": "static_code_snippet_analysis",
    }


def test_map_authorized_code_files_marks_flask_add_url_rule_function_without_authz_as_gap_candidate():
    result = map_authorized_code_files(
        {
            "authorized_code_files": [
                {
                    "path": "apps/api/routes/files.py",
                    "content": """
from flask import Flask, send_file

app = Flask(__name__)

def export_file(file_id: str):
    return send_file(file_id)

app.add_url_rule(
    "/files/<file_id>/export",
    view_func=export_file,
    methods=["GET"],
)
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
    assert gap.route_path == "/files/<file_id>/export"
    assert gap.authz_hint == "missing_handler_authz_check"
    assert gap.sensitivity_label == "high"


def test_map_authorized_code_files_treats_flask_add_url_rule_function_decorator_as_route_authz():
    result = map_authorized_code_files(
        {
            "authorized_code_files": [
                {
                    "path": "apps/api/routes/files.py",
                    "content": """
from flask import Flask, send_file
from flask_login import login_required

app = Flask(__name__)

@login_required
def export_file(file_id: str):
    return send_file(file_id)

app.add_url_rule(
    "/files/<file_id>/export",
    view_func=export_file,
    methods=["GET"],
)
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
    assert authz.symbol_name == "login_required"
    assert authz.payload == {
        "handler": "export_file",
        "line": 7,
        "mapping_mode": "static_code_snippet_analysis",
    }


def test_map_authorized_code_files_marks_flask_method_view_without_authz_as_gap_candidate():
    result = map_authorized_code_files(
        {
            "authorized_code_files": [
                {
                    "path": "apps/api/routes/files.py",
                    "content": """
from flask import Flask, send_file
from flask.views import MethodView

app = Flask(__name__)

class FileExport(MethodView):
    def get(self, file_id: str):
        return send_file(file_id)

app.add_url_rule(
    "/files/<file_id>/export",
    view_func=FileExport.as_view("export_file"),
)
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
    assert gap.symbol_name == "FileExport.get"
    assert gap.route_method == "GET"
    assert gap.route_path == "/files/<file_id>/export"
    assert gap.authz_hint == "missing_handler_authz_check"
    assert gap.sensitivity_label == "high"


def test_map_authorized_code_files_treats_flask_method_view_decorator_as_route_authz():
    result = map_authorized_code_files(
        {
            "authorized_code_files": [
                {
                    "path": "apps/api/routes/files.py",
                    "content": """
from flask import Flask, send_file
from flask.views import MethodView
from flask_login import login_required

app = Flask(__name__)

class FileExport(MethodView):
    decorators = [login_required]

    def get(self, file_id: str):
        return send_file(file_id)

app.add_url_rule(
    "/files/<file_id>/export",
    view_func=FileExport.as_view("export_file"),
)
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
    assert authz.symbol_name == "login_required"
    assert authz.payload == {
        "handler": "FileExport.get",
        "line": 9,
        "mapping_mode": "static_code_snippet_analysis",
    }


def test_map_authorized_code_files_treats_flask_method_view_tuple_decorator_as_route_authz():
    result = map_authorized_code_files(
        {
            "authorized_code_files": [
                {
                    "path": "apps/api/routes/files.py",
                    "content": """
from flask import Flask, send_file
from flask.views import MethodView
from flask_login import login_required

app = Flask(__name__)

class FileExport(MethodView):
    decorators = (login_required,)

    def get(self, file_id: str):
        return send_file(file_id)

app.add_url_rule(
    "/files/<file_id>/export",
    view_func=FileExport.as_view("export_file"),
)
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
    assert authz.symbol_name == "login_required"
    assert authz.payload == {
        "handler": "FileExport.get",
        "line": 9,
        "mapping_mode": "static_code_snippet_analysis",
    }


def test_map_authorized_code_files_treats_flask_method_view_method_decorator_as_route_authz():
    result = map_authorized_code_files(
        {
            "authorized_code_files": [
                {
                    "path": "apps/api/routes/files.py",
                    "content": """
from flask import Flask, send_file
from flask.views import MethodView
from flask_login import login_required

app = Flask(__name__)

class FileExport(MethodView):
    @login_required
    def get(self, file_id: str):
        return send_file(file_id)

app.add_url_rule(
    "/files/<file_id>/export",
    view_func=FileExport.as_view("export_file"),
)
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
    assert authz.symbol_name == "login_required"
    assert authz.payload == {
        "handler": "FileExport.get",
        "line": 9,
        "mapping_mode": "static_code_snippet_analysis",
    }


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


def test_map_authorized_code_files_treats_org_id_organization_id_comparison_as_authz_check():
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
    file = db.query(File).filter(File.id == file_id, File.org_id == current_user.organization_id).one()
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


def test_map_authorized_code_files_treats_org_id_relation_id_boundary_as_authz_check():
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
    file = File.objects.filter(id=file_id, org_id=current_user.organization.id).get()
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


def test_map_authorized_code_files_treats_org_id_relation_id_comparison_as_authz_check():
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
    file = db.query(File).filter(File.id == file_id, File.org_id == current_user.organization.id).one()
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


def test_map_authorized_code_files_treats_owner_current_user_comparison_as_authz_check():
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
    file = db.query(File).filter(File.id == file_id, File.owner == current_user).one()
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


def test_map_authorized_code_files_treats_created_by_id_current_user_id_comparison_as_authz_check():
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
    file = db.query(File).filter(File.id == file_id, File.created_by_id == current_user.id).one()
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
    assert authz.symbol_name == "created_by_id_filter"
    assert authz.authz_hint == "ownership_boundary_check"
    assert authz.payload == {
        "handler": "export_file",
        "line": 8,
        "mapping_mode": "static_code_snippet_analysis",
    }


def test_map_authorized_code_files_treats_created_by_current_user_comparison_as_authz_check():
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
    file = db.query(File).filter(File.id == file_id, File.created_by == current_user).one()
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
    assert authz.symbol_name == "created_by_id_filter"
    assert authz.authz_hint == "ownership_boundary_check"
    assert authz.payload == {
        "handler": "export_file",
        "line": 8,
        "mapping_mode": "static_code_snippet_analysis",
    }


def test_map_authorized_code_files_treats_created_by_id_current_user_id_kwarg_as_authz_check():
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
    file = File.objects.filter(id=file_id, created_by_id=current_user.id).get()
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
    assert authz.symbol_name == "created_by_id_filter"
    assert authz.authz_hint == "ownership_boundary_check"
    assert authz.payload == {
        "handler": "export_file",
        "line": 8,
        "mapping_mode": "static_code_snippet_analysis",
    }


def test_map_authorized_code_files_treats_created_by_current_user_kwarg_as_authz_check():
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
    file = File.objects.filter(id=file_id, created_by=current_user).get()
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
    assert authz.symbol_name == "created_by_id_filter"
    assert authz.authz_hint == "ownership_boundary_check"
    assert authz.payload == {
        "handler": "export_file",
        "line": 8,
        "mapping_mode": "static_code_snippet_analysis",
    }


def test_map_authorized_code_files_treats_created_by_relation_id_kwarg_as_authz_check():
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
    file = File.objects.filter(id=file_id, created_by__id=current_user.id).get()
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
    assert authz.symbol_name == "created_by_id_filter"
    assert authz.authz_hint == "ownership_boundary_check"
    assert authz.payload == {
        "handler": "export_file",
        "line": 8,
        "mapping_mode": "static_code_snippet_analysis",
    }


def test_map_authorized_code_files_treats_single_item_created_by_id_current_user_id_membership_list_as_authz_check():
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
    file = db.query(File).filter(File.id == file_id, File.created_by_id.in_([current_user.id])).one()
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
    assert authz.symbol_name == "created_by_id_filter"
    assert authz.authz_hint == "ownership_boundary_check"
    assert authz.payload == {
        "handler": "export_file",
        "line": 8,
        "mapping_mode": "static_code_snippet_analysis",
    }


def test_map_authorized_code_files_treats_single_item_created_by_id_current_user_id_kwarg_membership_list_as_authz_check():
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
    file = File.objects.filter(id=file_id, created_by_id__in=[current_user.id]).get()
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
    assert authz.symbol_name == "created_by_id_filter"
    assert authz.authz_hint == "ownership_boundary_check"
    assert authz.payload == {
        "handler": "export_file",
        "line": 8,
        "mapping_mode": "static_code_snippet_analysis",
    }


def test_map_authorized_code_files_treats_created_by_id_current_user_pk_kwarg_as_authz_check():
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
    file = File.objects.filter(id=file_id, created_by_id=current_user.pk).get()
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
    assert authz.symbol_name == "created_by_id_filter"
    assert authz.authz_hint == "ownership_boundary_check"
    assert authz.payload == {
        "handler": "export_file",
        "line": 8,
        "mapping_mode": "static_code_snippet_analysis",
    }


def test_map_authorized_code_files_treats_created_by_id_user_pk_kwarg_as_authz_check():
    result = map_authorized_code_files(
        {
            "authorized_code_files": [
                {
                    "path": "apps/api/routes/files.py",
                    "content": """
from fastapi import APIRouter

router = APIRouter()

@router.get("/files/{file_id}/export")
def export_file(file_id: str, user):
    file = File.objects.filter(id=file_id, created_by_id=user.pk).get()
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
    assert authz.symbol_name == "created_by_id_filter"
    assert authz.authz_hint == "ownership_boundary_check"
    assert authz.payload == {
        "handler": "export_file",
        "line": 8,
        "mapping_mode": "static_code_snippet_analysis",
    }


def test_map_authorized_code_files_treats_created_by_id_request_user_id_kwarg_as_authz_check():
    result = map_authorized_code_files(
        {
            "authorized_code_files": [
                {
                    "path": "apps/api/routes/files.py",
                    "content": """
from fastapi import APIRouter

router = APIRouter()

@router.get("/files/{file_id}/export")
def export_file(file_id: str, request):
    file = File.objects.filter(id=file_id, created_by_id=request.user.id).get()
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
    assert authz.symbol_name == "created_by_id_filter"
    assert authz.authz_hint == "ownership_boundary_check"
    assert authz.payload == {
        "handler": "export_file",
        "line": 8,
        "mapping_mode": "static_code_snippet_analysis",
    }


def test_map_authorized_code_files_treats_created_by_id_request_user_pk_kwarg_as_authz_check():
    result = map_authorized_code_files(
        {
            "authorized_code_files": [
                {
                    "path": "apps/api/routes/files.py",
                    "content": """
from fastapi import APIRouter

router = APIRouter()

@router.get("/files/{file_id}/export")
def export_file(file_id: str, request):
    file = File.objects.filter(id=file_id, created_by_id=request.user.pk).get()
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
    assert authz.symbol_name == "created_by_id_filter"
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


def test_map_authorized_code_files_treats_local_principal_account_id_alias_as_authz_check():
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
    authorized_account_id = current_user.account_id
    file = db.query(File).filter_by(id=file_id, account_id=authorized_account_id).one()
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
        "line": 9,
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


def test_map_authorized_code_files_treats_owner_current_user_relation_boundary_as_authz_check():
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
    file = File.objects.filter(id=file_id, owner=current_user).get()
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


def test_map_authorized_code_files_treats_organization_id_membership_alias_as_authz_check():
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
    file = File.objects.filter(id=file_id, organization_id__in=current_user.org_ids).get()
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
    assert authz.symbol_name == "organization_id_filter"
    assert authz.authz_hint == "ownership_boundary_check"
    assert authz.payload == {
        "handler": "export_file",
        "line": 8,
        "mapping_mode": "static_code_snippet_analysis",
    }


def test_map_authorized_code_files_treats_single_item_org_id_membership_list_as_authz_check():
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
    file = db.query(File).filter(File.id == file_id, File.org_id.in_([current_user.organization_id])).one()
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


def test_map_authorized_code_files_treats_single_item_org_relation_id_membership_list_as_authz_check():
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
    file = db.query(File).filter(File.id == file_id, File.org_id.in_([current_user.organization.id])).one()
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


def test_map_authorized_code_files_treats_single_item_org_id_membership_tuple_as_authz_check():
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
    file = db.query(File).filter(File.id == file_id, File.org_id.in_((current_user.organization_id,))).one()
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


def test_map_authorized_code_files_treats_single_item_org_id_membership_set_as_authz_check():
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
    file = db.query(File).filter(File.id == file_id, File.org_id.in_({current_user.organization_id})).one()
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


def test_map_authorized_code_files_treats_keyword_dependency_authz_as_route_authz():
    result = map_authorized_code_files(
        {
            "authorized_code_files": [
                {
                    "path": "apps/api/routes/files.py",
                    "content": """
from fastapi import APIRouter, Depends

router = APIRouter()

@router.get("/files/{file_id}/export")
def export_file(file_id: str, user=Depends(dependency=require_user)):
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


def test_map_authorized_code_files_treats_router_level_dependency_authz_as_route_authz():
    result = map_authorized_code_files(
        {
            "authorized_code_files": [
                {
                    "path": "apps/api/routes/files.py",
                    "content": """
from fastapi import APIRouter, Depends

router = APIRouter(dependencies=[Depends(require_user)])

@router.get("/files/{file_id}/export")
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
        "line": 4,
        "mapping_mode": "static_code_snippet_analysis",
    }


def test_map_authorized_code_files_treats_qualified_router_level_dependency_authz_as_route_authz():
    result = map_authorized_code_files(
        {
            "authorized_code_files": [
                {
                    "path": "apps/api/routes/files.py",
                    "content": """
from fastapi import Depends
import fastapi

router = fastapi.APIRouter(dependencies=[Depends(require_user)])

@router.get("/files/{file_id}/export")
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
        "line": 5,
        "mapping_mode": "static_code_snippet_analysis",
    }


def test_map_authorized_code_files_treats_aliased_router_level_dependency_authz_as_route_authz():
    result = map_authorized_code_files(
        {
            "authorized_code_files": [
                {
                    "path": "apps/api/routes/files.py",
                    "content": """
from fastapi import APIRouter as Router, Depends

router = Router(dependencies=[Depends(require_user)])

@router.get("/files/{file_id}/export")
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
        "line": 4,
        "mapping_mode": "static_code_snippet_analysis",
    }


def test_map_authorized_code_files_treats_multiline_router_level_dependency_with_prefix_as_route_authz():
    result = map_authorized_code_files(
        {
            "authorized_code_files": [
                {
                    "path": "apps/api/routes/files.py",
                    "content": """
from fastapi import APIRouter, Depends

router = APIRouter(
    prefix="/v1",
    dependencies=[Depends(require_user)],
)

@router.get("/files/{file_id}/export")
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


def test_map_authorized_code_files_treats_multiline_router_level_split_dependency_authz_as_route_authz():
    result = map_authorized_code_files(
        {
            "authorized_code_files": [
                {
                    "path": "apps/api/routes/files.py",
                    "content": """
from fastapi import APIRouter, Depends

router = APIRouter(
    dependencies=[
        Depends(
            require_user,
        )
    ]
)

@router.get("/files/{file_id}/export")
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


def test_map_authorized_code_files_treats_decorator_dependency_wrapper_as_route_authz():
    result = map_authorized_code_files(
        {
            "authorized_code_files": [
                {
                    "path": "apps/api/routes/files.py",
                    "content": """
from fastapi import APIRouter, Depends
from app.dependencies import current_staff_user

router = APIRouter()

@router.get("/files/{file_id}/export", dependencies=[Depends(current_staff_user)])
def export_file(file_id: str):
    return send_file(file_id)
""",
                },
                {
                    "path": "apps/api/dependencies.py",
                    "content": """
from fastapi import Depends
from app.auth import require_user

def current_staff_user(user=Depends(current_user)):
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


def test_map_authorized_code_files_treats_multiline_decorator_dependency_wrapper_as_route_authz():
    result = map_authorized_code_files(
        {
            "authorized_code_files": [
                {
                    "path": "apps/api/routes/files.py",
                    "content": """
from fastapi import APIRouter, Depends
from app.dependencies import current_staff_user

router = APIRouter()

@router.get(
    "/files/{file_id}/export",
    dependencies=[
        Depends(
            current_staff_user,
        )
    ],
)
def export_file(file_id: str):
    return send_file(file_id)
""",
                },
                {
                    "path": "apps/api/dependencies.py",
                    "content": """
from fastapi import Depends
from app.auth import require_user

def current_staff_user(user=Depends(current_user)):
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


def test_map_authorized_code_files_treats_keyword_dependency_alias_in_signature_as_route_authz():
    result = map_authorized_code_files(
        {
            "authorized_code_files": [
                {
                    "path": "apps/api/routes/files.py",
                    "content": """
from fastapi import APIRouter, Depends

router = APIRouter()
CurrentUser = Depends(dependency=require_user)

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


def test_map_authorized_code_files_treats_deeper_dependency_wrapper_chain_as_route_authz():
    result = map_authorized_code_files(
        {
            "authorized_code_files": [
                {
                    "path": "apps/api/routes/files.py",
                    "content": """
from fastapi import APIRouter, Depends
from app.dependencies import current_staff_user

router = APIRouter()

@router.get("/files/{file_id}/export")
def export_file(file_id: str, user=Depends(current_staff_user)):
    return send_file(file_id)
""",
                },
                {
                    "path": "apps/api/dependencies.py",
                    "content": """
from fastapi import Depends
from app.auth import require_user

def current_staff_user(user=Depends(current_active_user)):
    return user

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


def test_map_authorized_code_files_treats_dependency_alias_to_wrapper_chain_as_route_authz():
    result = map_authorized_code_files(
        {
            "authorized_code_files": [
                {
                    "path": "apps/api/routes/files.py",
                    "content": """
from fastapi import APIRouter, Depends
from app.dependencies import CurrentStaffUser

router = APIRouter()

@router.get("/files/{file_id}/export")
def export_file(file_id: str, user=CurrentStaffUser):
    return send_file(file_id)
""",
                },
                {
                    "path": "apps/api/dependencies.py",
                    "content": """
from fastapi import Depends
from app.auth import require_user

CurrentStaffUser = Depends(current_staff_user)

def current_staff_user(user=Depends(current_active_user)):
    return user

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


def test_map_authorized_code_files_treats_decorator_dependency_alias_to_wrapper_chain_as_route_authz():
    result = map_authorized_code_files(
        {
            "authorized_code_files": [
                {
                    "path": "apps/api/routes/files.py",
                    "content": """
from fastapi import APIRouter
from app.dependencies import CurrentStaffUser

router = APIRouter()

@router.get("/files/{file_id}/export", dependencies=[CurrentStaffUser])
def export_file(file_id: str):
    return send_file(file_id)
""",
                },
                {
                    "path": "apps/api/dependencies.py",
                    "content": """
from fastapi import Depends
from app.auth import require_user

CurrentStaffUser = Depends(current_staff_user)

def current_staff_user(user=Depends(current_active_user)):
    return user

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


def test_map_authorized_code_files_follows_multiline_repository_owner_filter():
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
    return export_file_for_user(
        file_id,
        current_user,
    )
""",
                },
                {
                    "path": "apps/api/services/files.py",
                    "content": """
from app.repositories.files import load_file_for_user

def export_file_for_user(file_id: str, current_user):
    file = load_file_for_user(
        file_id,
        current_user,
    )
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
    assert "load_file_for_user" in service_calls
    assert fact_types.count("authz_check") == 1
    assert fact_types.count("sensitive_sink") == 1
    assert "authorization_gap_candidate" not in fact_types


def test_map_authorized_code_files_treats_multiline_membership_filter_as_authz_check():
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
        File.account_id.in_(
            current_user.account_ids
        ),
    ).one()
    return send_file(file.path)
""",
                }
            ]
        }
    )

    fact_types = [fact.fact_type for fact in result.facts]
    authz_symbols = [
        fact.symbol_name for fact in result.facts if fact.fact_type == "authz_check"
    ]

    assert "account_id_filter" in authz_symbols
    assert fact_types.count("sensitive_sink") == 1
    assert "authorization_gap_candidate" not in fact_types


def test_map_authorized_code_files_treats_bracketed_multiline_membership_filter_as_authz_check():
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
        File.account_id.in_([
            current_user.account_id,
        ]),
    ).one()
    return send_file(file.path)
""",
                }
            ]
        }
    )

    fact_types = [fact.fact_type for fact in result.facts]
    authz_symbols = [
        fact.symbol_name for fact in result.facts if fact.fact_type == "authz_check"
    ]

    assert "account_id_filter" in authz_symbols
    assert fact_types.count("sensitive_sink") == 1
    assert "authorization_gap_candidate" not in fact_types


def test_map_authorized_code_files_treats_multiline_kwarg_membership_filter_as_authz_check():
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
    file = File.objects.filter(
        id=file_id,
        account_id__in=[
            current_user.account_id,
        ],
    ).get()
    return send_file(file.path)
""",
                }
            ]
        }
    )

    fact_types = [fact.fact_type for fact in result.facts]
    authz_symbols = [
        fact.symbol_name for fact in result.facts if fact.fact_type == "authz_check"
    ]

    assert "account_id_filter" in authz_symbols
    assert fact_types.count("sensitive_sink") == 1
    assert "authorization_gap_candidate" not in fact_types


def test_map_authorized_code_files_treats_workspace_id_filter_as_authz_check():
    result = map_authorized_code_files(
        {
            "authorized_code_files": [
                {
                    "path": "apps/api/routes/assistant.py",
                    "content": """
from fastapi import APIRouter

router = APIRouter()

@router.post("/workspaces/{workspace_id}/assistant/query")
def query_workspace(workspace_id: str, current_user):
    docs = db.query(Document).filter(
        Document.workspace_id == current_user.workspace_id,
    ).all()
    return answer_from_documents(docs)
""",
                }
            ]
        }
    )

    fact_types = [fact.fact_type for fact in result.facts]
    authz_symbols = [
        fact.symbol_name for fact in result.facts if fact.fact_type == "authz_check"
    ]

    assert "workspace_id_filter" in authz_symbols
    assert "authorization_gap_candidate" not in fact_types


def test_map_authorized_code_files_treats_team_id_filter_as_authz_check():
    result = map_authorized_code_files(
        {
            "authorized_code_files": [
                {
                    "path": "apps/api/routes/teams.py",
                    "content": """
from fastapi import APIRouter

router = APIRouter()

@router.patch("/teams/{team_id}/invite-policy")
def update_invite_policy(team_id: str, current_user):
    policy = db.query(InvitePolicy).filter(
        InvitePolicy.team_id == current_user.team_id,
    ).one()
    return update_role(policy)
""",
                }
            ]
        }
    )

    fact_types = [fact.fact_type for fact in result.facts]
    authz_symbols = [
        fact.symbol_name for fact in result.facts if fact.fact_type == "authz_check"
    ]

    assert "team_id_filter" in authz_symbols
    assert "authorization_gap_candidate" not in fact_types


def test_map_authorized_code_files_treats_project_id_filter_as_authz_check():
    result = map_authorized_code_files(
        {
            "authorized_code_files": [
                {
                    "path": "apps/api/routes/projects.py",
                    "content": """
from fastapi import APIRouter

router = APIRouter()

@router.get("/projects/{project_id}/exports/{export_id}")
def download_project_export(project_id: str, export_id: str, current_user):
    export = db.query(ProjectExport).filter(
        ProjectExport.id == export_id,
        ProjectExport.project_id == current_user.project_id,
    ).one()
    return send_file(export.path)
""",
                }
            ]
        }
    )

    fact_types = [fact.fact_type for fact in result.facts]
    authz_symbols = [
        fact.symbol_name for fact in result.facts if fact.fact_type == "authz_check"
    ]

    assert "project_id_filter" in authz_symbols
    assert fact_types.count("sensitive_sink") == 1
    assert "authorization_gap_candidate" not in fact_types


def test_map_authorized_code_files_treats_group_id_filter_as_authz_check():
    result = map_authorized_code_files(
        {
            "authorized_code_files": [
                {
                    "path": "apps/api/routes/groups.py",
                    "content": """
from fastapi import APIRouter

router = APIRouter()

@router.get("/groups/{group_id}/exports/{export_id}")
def download_group_export(group_id: str, export_id: str, current_user):
    export = db.query(GroupExport).filter(
        GroupExport.id == export_id,
        GroupExport.group_id == current_user.group_id,
    ).one()
    return send_file(export.path)
""",
                }
            ]
        }
    )

    fact_types = [fact.fact_type for fact in result.facts]
    authz_symbols = [
        fact.symbol_name for fact in result.facts if fact.fact_type == "authz_check"
    ]

    assert "group_id_filter" in authz_symbols
    assert fact_types.count("sensitive_sink") == 1
    assert "authorization_gap_candidate" not in fact_types


def test_map_authorized_code_files_marks_agent_tool_execution_without_authz_as_gap_candidate():
    result = map_authorized_code_files(
        {
            "authorized_code_files": [
                {
                    "path": "apps/api/routes/agents.py",
                    "content": """
from fastapi import APIRouter

router = APIRouter()

@router.post("/agents/{agent_id}/tools/execute")
def run_agent_tool(agent_id: str, tool_name: str, current_user):
    return execute_agent_tool(agent_id, tool_name)
""",
                }
            ]
        }
    )

    fact_types = [fact.fact_type for fact in result.facts]
    gap = next(
        fact for fact in result.facts if fact.fact_type == "authorization_gap_candidate"
    )

    assert "sensitive_sink" in fact_types
    assert gap.route_method == "POST"
    assert gap.route_path == "/agents/{agent_id}/tools/execute"


def test_map_authorized_code_files_marks_agent_tool_dispatch_without_authz_as_gap_candidate():
    result = map_authorized_code_files(
        {
            "authorized_code_files": [
                {
                    "path": "apps/api/routes/agents.py",
                    "content": """
from fastapi import APIRouter

router = APIRouter()

@router.post("/agents/{agent_id}/tools/dispatch")
def dispatch_tool(agent_id: str, tool_name: str, current_user):
    return dispatch_agent_tool(agent_id, tool_name)
""",
                }
            ]
        }
    )

    fact_types = [fact.fact_type for fact in result.facts]
    sink = next(fact for fact in result.facts if fact.fact_type == "sensitive_sink")
    gap = next(
        fact for fact in result.facts if fact.fact_type == "authorization_gap_candidate"
    )

    assert fact_types.count("route_handler") == 1
    assert sink.symbol_name == "dispatch_agent_tool"
    assert gap.route_method == "POST"
    assert gap.route_path == "/agents/{agent_id}/tools/dispatch"


def test_map_authorized_code_files_treats_agent_id_filter_as_authz_check():
    result = map_authorized_code_files(
        {
            "authorized_code_files": [
                {
                    "path": "apps/api/routes/agents.py",
                    "content": """
from fastapi import APIRouter

router = APIRouter()

@router.post("/agents/{agent_id}/tools/execute")
def run_agent_tool(agent_id: str, tool_name: str, current_user):
    agent = db.query(Agent).filter(
        Agent.agent_id == current_user.agent_id,
    ).one()
    return execute_agent_tool(agent, tool_name)
""",
                }
            ]
        }
    )

    fact_types = [fact.fact_type for fact in result.facts]
    authz_symbols = [
        fact.symbol_name for fact in result.facts if fact.fact_type == "authz_check"
    ]

    assert "agent_id_filter" in authz_symbols
    assert "sensitive_sink" in fact_types
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
