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


def test_map_authorized_code_files_preserves_shared_service_edges_for_each_route():
    result = map_authorized_code_files(
        {
            "authorized_code_files": [
                {
                    "path": "apps/api/routes/records.py",
                    "content": '''
from fastapi import APIRouter

router = APIRouter()

@router.get("/records/{record_id}")
def read_record(record_id: str):
    return load_record(record_id)

@router.get("/records/{record_id}/summary")
def read_record_summary(record_id: str):
    return load_record(record_id)

def load_record(record_id: str):
    return send_file(record_id)
''',
                }
            ]
        }
    )

    shared_edges = [
        fact
        for fact in result.facts
        if fact.fact_type == "service_call" and fact.symbol_name == "load_record"
    ]
    gap_handlers = {
        fact.payload["handler"]
        for fact in result.facts
        if fact.fact_type == "authorization_gap_candidate"
    }

    assert {fact.payload["caller"] for fact in shared_edges} == {
        "read_record",
        "read_record_summary",
    }
    assert gap_handlers == {"read_record", "read_record_summary"}


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


def test_map_authorized_code_files_maps_express_route_middleware_and_one_hop_service():
    result = map_authorized_code_files(
        {
            "authorized_code_files": [
                {
                    "path": "src/routes/files.ts",
                    "content": '''
import { Router } from "express";

const router = Router();

router.get("/files/:fileId/export", requireUser, exportFile);

async function exportFile(req: Request, res: Response) {
  return exportFileForUser(req.params.fileId);
}

async function exportFileForUser(fileId: string) {
  return sendFile(fileId);
}
''',
                }
            ]
        }
    )

    route = next(fact for fact in result.facts if fact.fact_type == "route_handler")
    authz = next(fact for fact in result.facts if fact.fact_type == "authz_check")
    service = next(
        fact
        for fact in result.facts
        if fact.fact_type == "service_call"
        and fact.symbol_name == "exportFileForUser"
    )
    sink = next(fact for fact in result.facts if fact.fact_type == "sensitive_sink")

    assert route.symbol_name == "exportFile"
    assert route.route_method == "GET"
    assert route.route_path == "/files/:fileId/export"
    assert route.payload["handler"] == "exportFile"
    assert authz.symbol_name == "requireUser"
    assert authz.authz_hint == "authorization_boundary_candidate"
    assert authz.payload["handler"] == "exportFile"
    assert service.payload["caller"] == "exportFile"
    assert sink.symbol_name == "sendFile"
    assert sink.payload["handler"] == "exportFileForUser"
    assert not any(
        fact.fact_type == "authorization_gap_candidate" for fact in result.facts
    )


def test_map_authorized_code_files_maps_express_missing_authz_through_one_hop_service():
    result = map_authorized_code_files(
        {
            "authorized_code_files": [
                {
                    "path": "src/routes/files.ts",
                    "content": '''
import express from "express";

const app = express();

app.get("/files/:fileId/export", exportFile);

const exportFile = async (req: Request, res: Response) => {
  return exportFileForUser(req.params.fileId);
};

const exportFileForUser = async (fileId: string) => {
  return sendFile(fileId);
};
''',
                }
            ]
        }
    )

    gap = next(
        fact for fact in result.facts if fact.fact_type == "authorization_gap_candidate"
    )

    assert gap.symbol_name == "exportFile"
    assert gap.route_method == "GET"
    assert gap.route_path == "/files/:fileId/export"
    assert gap.payload["sink_symbols"] == ["sendFile"]
    assert gap.payload["review_state"] == "needs_human_review"


def test_map_authorized_code_files_maps_express_ownership_comparison_as_authz():
    result = map_authorized_code_files(
        {
            "authorized_code_files": [
                {
                    "path": "src/routes/files.ts",
                    "content": '''
import { Router } from "express";

const router = Router();

router.delete("/files/:fileId", deleteFile);

async function deleteFile(req: Request, res: Response) {
  const file = await loadFile(req.params.fileId);
  if (file.ownerId !== req.user.id) {
    return res.sendStatus(403);
  }
  return fileStore.deleteFile(file.id);
}
''',
                }
            ]
        }
    )

    authz = next(fact for fact in result.facts if fact.fact_type == "authz_check")

    assert authz.symbol_name == "owner_id_filter"
    assert authz.authz_hint == "owner_or_admin_check"
    assert authz.payload["handler"] == "deleteFile"
    assert any(
        fact.fact_type == "sensitive_sink" and fact.symbol_name == "deleteFile"
        for fact in result.facts
    )
    assert not any(
        fact.fact_type == "authorization_gap_candidate" for fact in result.facts
    )


def test_map_authorized_code_files_keeps_express_one_hop_authz_for_targeted_review():
    result = map_authorized_code_files(
        {
            "authorized_code_files": [
                {
                    "path": "src/routes/records.ts",
                    "content": '''
import { Router } from "express";

const router = Router();

router.get("/records/:recordId", readRecord);

async function readRecord(req: Request, res: Response) {
  await verifyRecordAccess(req.params.recordId, req.user);
  return sendFile(req.params.recordId);
}

async function verifyRecordAccess(recordId: string, user: User) {
  const record = await loadRecord(recordId);
  if (record.ownerId !== user.id) {
    return res.sendStatus(403);
  }
  return record;
}
''',
                }
            ]
        }
    )

    assert any(
        fact.fact_type == "authz_check"
        and fact.symbol_name == "owner_id_filter"
        and fact.payload["handler"] == "verifyRecordAccess"
        for fact in result.facts
    )
    gap = next(
        fact
        for fact in result.facts
        if fact.fact_type == "authorization_gap_candidate"
    )
    assert gap.symbol_name == "readRecord"
    assert gap.payload["review_state"] == "needs_human_review"


def test_map_authorized_code_files_does_not_invent_express_dynamic_routes():
    result = map_authorized_code_files(
        {
            "authorized_code_files": [
                {
                    "path": "src/routes/files.ts",
                    "content": '''
import { Router } from "express";

const router = Router();
const method = "get";
const path = "/files/:fileId/export";

router[method](path, exportFile);

function exportFile(req: Request, res: Response) {
  return sendFile(req.params.fileId);
}
''',
                }
            ]
        }
    )

    assert not any(fact.fact_type == "route_handler" for fact in result.facts)
    assert not any(
        fact.fact_type == "authorization_gap_candidate" for fact in result.facts
    )


def test_map_authorized_code_files_does_not_map_express_route_text_inside_string():
    result = map_authorized_code_files(
        {
            "authorized_code_files": [
                {
                    "path": "src/routes/files.ts",
                    "content": '''
import { Router } from "express";

const router = Router();
const example = 'router.get("/files/:fileId/export", exportFile)';

function exportFile(req: Request, res: Response) {
  return sendFile(req.params.fileId);
}
''',
                }
            ]
        }
    )

    assert not any(fact.fact_type == "route_handler" for fact in result.facts)
    assert not any(
        fact.fact_type == "authorization_gap_candidate" for fact in result.facts
    )


def test_map_authorized_code_files_does_not_treat_express_import_text_as_code():
    result = map_authorized_code_files(
        {
            "authorized_code_files": [
                {
                    "path": "src/routes/files.ts",
                    "content": '''
const example = 'import { Router } from "express"';
const router = Router();
router.get("/files/:fileId/export", exportFile);

function exportFile(req: Request, res: Response) {
  return sendFile(req.params.fileId);
}
''',
                }
            ]
        }
    )

    assert not any(fact.fact_type == "route_handler" for fact in result.facts)
    assert not any(
        fact.fact_type == "authorization_gap_candidate" for fact in result.facts
    )


def test_map_authorized_code_files_maps_express_router_middleware_as_authz():
    result = map_authorized_code_files(
        {
            "authorized_code_files": [
                {
                    "path": "src/routes/files.ts",
                    "content": '''
import { Router } from "express";

const router = Router();
router.use(requireRole("reviewer"));
router.get("/files/:fileId/export", exportFile);

function exportFile(req: Request, res: Response) {
  return sendFile(req.params.fileId);
}
''',
                }
            ]
        }
    )

    authz = next(fact for fact in result.facts if fact.fact_type == "authz_check")

    assert authz.symbol_name == "requireRole"
    assert authz.authz_hint == "role_check"
    assert authz.payload["handler"] == "exportFile"
    assert not any(
        fact.fact_type == "authorization_gap_candidate" for fact in result.facts
    )


def test_map_authorized_code_files_does_not_apply_scoped_express_middleware_to_other_routes():
    result = map_authorized_code_files(
        {
            "authorized_code_files": [
                {
                    "path": "src/routes/files.ts",
                    "content": '''
import { Router } from "express";

const router = Router();
router.use("/admin", requireUser);
router.get("/files/:fileId/export", exportFile);

function exportFile(req: Request, res: Response) {
  return sendFile(req.params.fileId);
}
''',
                }
            ]
        }
    )

    gap = next(
        fact for fact in result.facts if fact.fact_type == "authorization_gap_candidate"
    )

    assert gap.symbol_name == "exportFile"
    assert not any(fact.fact_type == "authz_check" for fact in result.facts)


def test_map_authorized_code_files_does_not_treat_role_text_as_an_authz_check():
    result = map_authorized_code_files(
        {
            "authorized_code_files": [
                {
                    "path": "src/routes/files.ts",
                    "content": '''
import { Router } from "express";

const router = Router();
router.get("/files/:fileId/export", exportFile);

function exportFile(req: Request, res: Response) {
  const example = 'req.user.role !== "admin"';
  return sendFile(req.params.fileId);
}
''',
                }
            ]
        }
    )

    assert not any(fact.fact_type == "authz_check" for fact in result.facts)
    assert any(
        fact.fact_type == "authorization_gap_candidate" for fact in result.facts
    )


def test_map_authorized_code_files_does_not_apply_nested_express_helper_authz_to_handler():
    result = map_authorized_code_files(
        {
            "authorized_code_files": [
                {
                    "path": "src/routes/files.ts",
                    "content": '''
import { Router } from "express";

const router = Router();
router.get("/files/:fileId/export", exportFile);

function exportFile(req: Request, res: Response) {
  function unusedAuthorizationHelper() {
    requireUser();
  }
  return sendFile(req.params.fileId);
}
''',
                }
            ]
        }
    )

    gap = next(
        fact for fact in result.facts if fact.fact_type == "authorization_gap_candidate"
    )
    authz = next(fact for fact in result.facts if fact.fact_type == "authz_check")

    assert gap.symbol_name == "exportFile"
    assert authz.payload["handler"] == "unusedAuthorizationHelper"


def test_map_authorized_code_files_maps_express_role_and_tenant_comparisons():
    result = map_authorized_code_files(
        {
            "authorized_code_files": [
                {
                    "path": "src/routes/files.ts",
                    "content": '''
import { Router } from "express";

const router = Router();
router.delete("/files/:fileId", deleteFile);
router.post("/files/:fileId/publish", publishFile);

function deleteFile(req: Request, res: Response) {
  if (req.user.role !== "admin") {
    return res.sendStatus(403);
  }
  return fileStore.deleteFile(req.params.fileId);
}

function publishFile(req: Request, res: Response) {
  const file = loadFile(req.params.fileId);
  if (file.tenantId !== req.user.tenantId) {
    return res.sendStatus(403);
  }
  return update(file);
}
''',
                }
            ]
        }
    )

    authz_by_handler = {
        fact.payload["handler"]: (fact.symbol_name, fact.authz_hint)
        for fact in result.facts
        if fact.fact_type == "authz_check"
    }

    assert authz_by_handler == {
        "deleteFile": ("role_check", "role_check"),
        "publishFile": ("tenant_id_filter", "ownership_boundary_check"),
    }
    assert not any(
        fact.fact_type == "authorization_gap_candidate" for fact in result.facts
    )


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



def test_map_authorized_code_files_marks_outbound_fetch_without_ssrf_guard_as_gap_candidate():
    result = map_authorized_code_files(
        {
            "authorized_code_files": [
                {
                    "path": "apps/api/routes/webhooks.ts",
                    "content": """
import { Router } from "express";

const router = Router();

router.post("/webhooks/deliver", deliver_webhook);

async function deliver_webhook(req: Request, res: Response) {
  const target = req.body.subscriberUrl;
  return fetch(target);
}
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
    assert fact_types.count("sensitive_sink") >= 1
    assert fact_types.count("authorization_gap_candidate") == 1
    assert gap.symbol_name == "deliver_webhook"
    assert gap.route_method == "POST"
    assert gap.route_path == "/webhooks/deliver"
    assert gap.authz_hint == "missing_handler_ssrf_check"
    assert gap.payload["root_cause"] == "missing_ssrf_validation"
    assert "fetch" in gap.payload["sink_symbols"]


def test_map_authorized_code_files_treats_ssrf_guard_as_control_for_outbound_fetch():
    result = map_authorized_code_files(
        {
            "authorized_code_files": [
                {
                    "path": "apps/api/routes/webhooks.ts",
                    "content": """
import { Router } from "express";

const router = Router();

router.post("/webhooks/deliver", deliver_webhook);

async function verify_subscriber_url(url: string) {
  return validateUrlForSSRF(url);
}

async function deliver_webhook(req: Request, res: Response) {
  const target = req.body.subscriberUrl;
  await verify_subscriber_url(target);
  return fetch(target);
}
""",
                }
            ]
        }
    )

    fact_types = [fact.fact_type for fact in result.facts]
    authz = next(
        fact
        for fact in result.facts
        if fact.fact_type == "authz_check"
        and fact.authz_hint == "ssrf_validation_check"
    )
    # TypeScript keeps gap candidates for targeted review even when service helper has controls.
    gaps = [fact for fact in result.facts if fact.fact_type == "authorization_gap_candidate"]

    assert fact_types.count("sensitive_sink") >= 1
    assert authz.symbol_name == "validateUrlForSSRF"
    assert authz.payload["handler"] == "verify_subscriber_url"
    assert gaps  # emitted for route-level review; hunter refutes via control evidence


def test_map_authorized_code_files_python_fetch_without_ssrf_guard_is_ssrf_gap():
    result = map_authorized_code_files(
        {
            "authorized_code_files": [
                {
                    "path": "apps/api/routes/webhooks.py",
                    "content": """
from fastapi import APIRouter

router = APIRouter()

@router.post("/webhooks/deliver")
def deliver_webhook(subscriber_url: str):
    return fetch(subscriber_url)
""",
                }
            ]
        }
    )

    gap = next(
        fact for fact in result.facts if fact.fact_type == "authorization_gap_candidate"
    )
    assert gap.authz_hint == "missing_handler_ssrf_check"
    assert gap.payload["root_cause"] == "missing_ssrf_validation"


def test_map_authorized_code_files_marks_get_blob_without_path_guard_as_gap_candidate():
    result = map_authorized_code_files(
        {
            "authorized_code_files": [
                {
                    "path": "apps/api/routes/media.ts",
                    "content": """
import { Router } from "express";

const router = Router();

router.get("/media/:filepath", serve_media);

async function serve_media(req: Request, res: Response) {
  const key = req.params.filepath;
  return get_blob(key);
}
""",
                }
            ]
        }
    )

    gap = next(
        fact for fact in result.facts if fact.fact_type == "authorization_gap_candidate"
    )

    assert gap.symbol_name == "serve_media"
    assert gap.route_method == "GET"
    assert gap.route_path == "/media/:filepath"
    assert gap.authz_hint == "missing_handler_path_check"
    assert gap.payload["root_cause"] == "missing_path_validation"
    assert "get_blob" in gap.payload["sink_symbols"]


def test_map_authorized_code_files_treats_path_guard_as_control_for_get_blob():
    result = map_authorized_code_files(
        {
            "authorized_code_files": [
                {
                    "path": "apps/api/routes/media.ts",
                    "content": """
import { Router } from "express";

const router = Router();

router.get("/media/:filepath", serve_media);

function makeFilename(name: string) {
  return filepath_base(name);
}

async function serve_media(req: Request, res: Response) {
  const key = makeFilename(req.params.filepath);
  return get_blob(key);
}
""",
                }
            ]
        }
    )

    authz = next(
        fact
        for fact in result.facts
        if fact.fact_type == "authz_check"
        and fact.authz_hint == "path_validation_check"
    )
    assert any(f.fact_type == "sensitive_sink" for f in result.facts)
    assert authz.symbol_name in {"filepath_base", "makeFilename"}


def test_map_authorized_code_files_python_read_file_without_path_guard_is_path_gap():
    result = map_authorized_code_files(
        {
            "authorized_code_files": [
                {
                    "path": "apps/api/routes/media.py",
                    "content": """
from fastapi import APIRouter

router = APIRouter()

@router.get("/media/{filepath}")
def serve_media(filepath: str):
    return read_file(filepath)
""",
                }
            ]
        }
    )

    gap = next(
        fact for fact in result.facts if fact.fact_type == "authorization_gap_candidate"
    )
    assert gap.authz_hint == "missing_handler_path_check"
    assert gap.payload["root_cause"] == "missing_path_validation"


def test_map_authorized_code_files_marks_update_user_without_mass_assign_guard_as_gap():
    result = map_authorized_code_files(
        {
            "authorized_code_files": [
                {
                    "path": "apps/api/routes/users.ts",
                    "content": """
import { Router } from "express";

const router = Router();

router.put("/users/:id", update_self_user);

async function update_self_user(req: Request, res: Response) {
  const body = req.body;
  return update_user(req.params.id, body);
}
""",
                }
            ]
        }
    )

    gap = next(
        fact for fact in result.facts if fact.fact_type == "authorization_gap_candidate"
    )
    assert gap.symbol_name == "update_self_user"
    assert gap.authz_hint == "missing_handler_mass_assignment_check"
    assert gap.payload["root_cause"] == "missing_mass_assignment_guard"
    assert "update_user" in gap.payload["sink_symbols"]


def test_map_authorized_code_files_treats_mass_assign_guard_as_control_for_update_user():
    result = map_authorized_code_files(
        {
            "authorized_code_files": [
                {
                    "path": "apps/api/routes/users.ts",
                    "content": """
import { Router } from "express";

const router = Router();

router.put("/users/:id", update_self_user);

function assert_user_change_allowed(user_id: string, body: any) {
  return forbid_privilege_fields(body);
}

async function update_self_user(req: Request, res: Response) {
  const body = req.body;
  await prepare_user_update(req.params.id, body);
  return update_user(req.params.id, body);
}

async function prepare_user_update(user_id: string, body: any) {
  return assert_user_change_allowed(user_id, body);
}
""",
                }
            ]
        }
    )

    authz = next(
        fact
        for fact in result.facts
        if fact.fact_type == "authz_check"
        and fact.authz_hint == "mass_assignment_check"
    )
    assert any(f.fact_type == "sensitive_sink" for f in result.facts)
    assert authz.symbol_name in {
        "assert_user_change_allowed",
        "forbid_privilege_fields",
    }
    gaps = [f for f in result.facts if f.fact_type == "authorization_gap_candidate"]
    assert gaps  # TS emits gaps for review; hunter refutes via control


def test_map_authorized_code_files_python_update_user_without_guard_is_mass_gap():
    result = map_authorized_code_files(
        {
            "authorized_code_files": [
                {
                    "path": "apps/api/routes/users.py",
                    "content": """
from fastapi import APIRouter

router = APIRouter()

@router.put("/users/{item_id}")
def update_self_user(item_id: str, new_data: dict):
    return update_user(item_id, new_data)
""",
                }
            ]
        }
    )

    gap = next(
        fact for fact in result.facts if fact.fact_type == "authorization_gap_candidate"
    )
    assert gap.authz_hint == "missing_handler_mass_assignment_check"
    assert gap.payload["root_cause"] == "missing_mass_assignment_guard"

def test_map_authorized_code_files_marks_run_sql_without_injection_guard_as_gap_candidate():
    result = map_authorized_code_files(
        {
            "authorized_code_files": [
                {
                    "path": "apps/api/routes/search.ts",
                    "content": """
import { Router } from "express";

const router = Router();

router.get("/campaigns/search", search_campaigns);

async function search_campaigns(req: Request, res: Response) {
  const q = req.query.q;
  return run_sql(q);
}
""",
                }
            ]
        }
    )

    gap = next(
        fact for fact in result.facts if fact.fact_type == "authorization_gap_candidate"
    )
    assert gap.symbol_name == "search_campaigns"
    assert gap.authz_hint == "missing_handler_injection_check"
    assert gap.payload["root_cause"] == "missing_injection_validation"
    assert "run_sql" in gap.payload["sink_symbols"]


def test_map_authorized_code_files_treats_injection_guard_as_control_for_run_sql():
    result = map_authorized_code_files(
        {
            "authorized_code_files": [
                {
                    "path": "apps/api/routes/search.ts",
                    "content": """
import { Router } from "express";

const router = Router();

router.get("/campaigns/search", search_campaigns);

function makeSearchString(q: string) {
  return q;
}

function prepare_search(q: string) {
  return makeSearchString(q);
}

async function search_campaigns(req: Request, res: Response) {
  const q = req.query.q;
  const safe = prepare_search(q);
  return run_sql(safe);
}
""",
                }
            ]
        }
    )

    authz = next(
        fact
        for fact in result.facts
        if fact.fact_type == "authz_check"
        and fact.authz_hint == "injection_validation_check"
    )
    assert authz.symbol_name in {"makeSearchString", "prepare_search"}
    assert any(f.fact_type == "sensitive_sink" for f in result.facts)


def test_map_authorized_code_files_python_execute_query_without_guard_is_injection_gap():
    result = map_authorized_code_files(
        {
            "authorized_code_files": [
                {
                    "path": "apps/api/routes/search.py",
                    "content": """
from fastapi import APIRouter

router = APIRouter()

@router.get("/campaigns/search")
def search_campaigns(q: str):
    return execute_query(q)
""",
                }
            ]
        }
    )

    gap = next(
        fact for fact in result.facts if fact.fact_type == "authorization_gap_candidate"
    )
    assert gap.authz_hint == "missing_handler_injection_check"
    assert gap.payload["root_cause"] == "missing_injection_validation"


def test_map_static_multilang_java_go_rails_ownership_and_role_facts():
    java = """
@RestController
public class RecordsController {
  @GetMapping("/records/{recordId}")
  public Object readRecord(String recordId, User user) {
    Record record = loadRecord(recordId);
    if (!record.getOwnerId().equals(user.getId())) {
      return deny();
    }
    return sendFile(record.getPath());
  }
}
"""
    go = """
package handlers
func mount(r Router) { r.GET("/records/{recordId}", readRecord) }
func readRecord(w http.ResponseWriter, r *http.Request) {
  record := loadRecord(recordId)
  if record.OwnerID != user.ID { return }
  sendFile(w, record.Path)
}
"""
    rails = """
get "/records/:record_id", to: "records#read_record"
def read_record
  record = load_record(params[:record_id])
  if record.owner_id != current_user.id
    deny
  end
  send_file record.path
end
"""
    for path, content, handler in [
        ("RecordsController.java", java, "readRecord"),
        ("handlers.go", go, "readRecord"),
        ("records.rb", rails, "read_record"),
    ]:
        result = map_authorized_code_files(
            {"authorized_code_files": [{"path": path, "content": content}]}
        )
        types = {f.fact_type for f in result.facts}
        assert "route_handler" in types
        assert "authz_check" in types
        assert "sensitive_sink" in types
        authz = [f for f in result.facts if f.fact_type == "authz_check"]
        assert any(
            f.authz_hint in {"owner_or_admin_check", "ownership_boundary_check"}
            and isinstance(f.payload, dict)
            and f.payload.get("handler") == handler
            for f in authz
        )


def test_map_static_multilang_csharp_php_ownership_and_role_facts():
    csharp = """
public class RecordsController {
  [HttpGet("/records/{id}")]
  public IActionResult GetRecord(int id) {
    if (record.OwnerId != user.Id) { return Forbid(); }
    return File(record.Path);
  }
}
"""
    php = """
<?php
Route::get('/records/{id}', function ($id) {
  if ($record->owner_id != $user->id) { abort(403); }
  return response()->download($record->path);
});
"""
    csharp_role = """
public class RecordsController {
  [HttpGet("/records/{id}")]
  public IActionResult GetRecord(int id) {
    if (user.Role != "admin") { return Forbid(); }
    return File(record.Path);
  }
}
"""
    for path, content, expect_hint in [
        ("RecordsController.cs", csharp, {"owner_or_admin_check", "ownership_boundary_check"}),
        ("routes.php", php, {"owner_or_admin_check", "ownership_boundary_check"}),
        ("RecordsController.cs", csharp_role, {"role_check", "permission_check"}),
    ]:
        result = map_authorized_code_files(
            {"authorized_code_files": [{"path": path, "content": content}]}
        )
        types = {f.fact_type for f in result.facts}
        assert "route_handler" in types
        assert "authz_check" in types
        authz = [f for f in result.facts if f.fact_type == "authz_check"]
        assert any(f.authz_hint in expect_hint for f in authz)

def test_map_static_multilang_kotlin_ownership_and_role_facts():
    kotlin = """
@RestController
class RecordsController {
  @GetMapping("/records/{recordId}")
  fun readRecord(recordId: String, user: User): Any {
    val record = loadRecord(recordId)
    if (record.ownerId != user.id) {
      return deny()
    }
    return sendFile(record.path)
  }
}
"""
    kotlin_role = """
@RestController
class RecordsController {
  @GetMapping("/records/{recordId}")
  fun readRecord(recordId: String, user: User): Any {
    if (user.role != "admin") {
      return deny()
    }
    return sendFile(record.path)
  }
}
"""
    for path, content, expect_hint in [
        ("RecordsController.kt", kotlin, {"owner_or_admin_check", "ownership_boundary_check"}),
        ("RecordsController.kt", kotlin_role, {"role_check", "permission_check"}),
    ]:
        result = map_authorized_code_files(
            {"authorized_code_files": [{"path": path, "content": content}]}
        )
        types = {f.fact_type for f in result.facts}
        assert "route_handler" in types
        assert "authz_check" in types
        authz = [f for f in result.facts if f.fact_type == "authz_check"]
        assert any(f.authz_hint in expect_hint for f in authz)


def test_map_static_multilang_rust_scala_ownership_and_role_facts():
    rust = """
#[get("/records/{record_id}")]
async fn read_record(record_id: String, user: User) -> impl IntoResponse {
    let record = load_record(&record_id);
    if record.owner_id != user.id {
        return deny();
    }
    send_file(record.path)
}
"""
    rust_role = """
#[get("/records/{record_id}")]
async fn read_record(record_id: String, user: User) -> impl IntoResponse {
    if user.role != "admin" {
        return deny();
    }
    send_file(record.path)
}
"""
    scala = """
@RestController
class RecordsController {
  @GetMapping("/records/{recordId}")
  def readRecord(recordId: String, user: User) = {
    val record = loadRecord(recordId)
    if (record.ownerId != user.id) {
      return deny()
    }
    sendFile(record.path)
  }
}
"""
    scala_role = """
@RestController
class RecordsController {
  @GetMapping("/records/{recordId}")
  def readRecord(recordId: String, user: User) = {
    if (user.role != "admin") {
      return deny()
    }
    sendFile(record.path)
  }
}
"""
    for path, content, expect_hint in [
        ("handlers.rs", rust, {"owner_or_admin_check", "ownership_boundary_check"}),
        ("handlers.rs", rust_role, {"role_check", "permission_check"}),
        ("RecordsController.scala", scala, {"owner_or_admin_check", "ownership_boundary_check"}),
        ("RecordsController.scala", scala_role, {"role_check", "permission_check"}),
    ]:
        result = map_authorized_code_files(
            {"authorized_code_files": [{"path": path, "content": content}]}
        )
        types = {f.fact_type for f in result.facts}
        assert "route_handler" in types
        assert "authz_check" in types
        authz = [f for f in result.facts if f.fact_type == "authz_check"]
        assert any(f.authz_hint in expect_hint for f in authz)
