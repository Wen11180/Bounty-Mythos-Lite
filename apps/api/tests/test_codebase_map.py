import ast

import pytest

from app.codebase_map import (
    _django_drf_class_body_outer_rebindings,
    _django_drf_method_depends_on_action,
    map_authorized_code_files,
)


def test_map_authorized_code_files_scopes_nestjs_class_guards_to_their_controller():
    result = map_authorized_code_files(
        {
            "authorized_code_files": [
                {
                    "path": "records.controller.ts",
                    "content": '''
import { Controller, Get, UseGuards } from "@nestjs/common";

@UseGuards(OwnerGuard)
@Controller("admin-records")
export class AdminRecordsController {
  @Get(":recordId")
  async readAdminRecord(recordId: string) {
    return sendFile(recordId);
  }
}

@Controller("public-records")
export class PublicRecordsController {
  @Get(":recordId")
  async readPublicRecord(recordId: string) {
    return sendFile(recordId);
  }
}
''',
                }
            ]
        }
    )

    routes = {
        (fact.symbol_name, fact.route_method, fact.route_path)
        for fact in result.facts
        if fact.fact_type == "route_handler"
    }
    guards_by_handler = {
        fact.payload["handler"]: fact.symbol_name
        for fact in result.facts
        if fact.fact_type == "authz_check"
    }
    sink_handlers = {
        fact.payload["handler"]
        for fact in result.facts
        if fact.fact_type == "sensitive_sink"
    }
    gap_handlers = {
        fact.symbol_name
        for fact in result.facts
        if fact.fact_type == "authorization_gap_candidate"
    }

    assert routes == {
        ("readAdminRecord", "GET", "/admin-records/:recordId"),
        ("readPublicRecord", "GET", "/public-records/:recordId"),
    }
    assert guards_by_handler == {"readAdminRecord": "OwnerGuard"}
    assert sink_handlers == {"readAdminRecord", "readPublicRecord"}
    assert gap_handlers == {"readPublicRecord"}


def test_map_authorized_code_files_maps_nestjs_injectable_ownership_checks():
    result = map_authorized_code_files(
        {
            "authorized_code_files": [
                {
                    "path": "records.controller.ts",
                    "content": '''
import { Controller, Get, Injectable } from "@nestjs/common";

@Injectable()
@Controller("records")
export class RecordsController {
  @Get(":recordId")
  async readRecord(recordId: string, user: User) {
    const record = await this.recordsService.getForUser(recordId, user);
    return sendFile(record.path);
  }
}

@Injectable()
export class RecordsService {
  async getForUser(recordId: string, user: User) {
    const record = await loadRecord(recordId);
    if (record.ownerId !== user.id) {
      return deny();
    }
    return record;
  }
}
''',
                }
            ]
        }
    )

    assert any(
        fact.fact_type == "service_call"
        and fact.symbol_name == "getForUser"
        and fact.payload.get("caller") == "readRecord"
        for fact in result.facts
    )
    assert any(
        fact.fact_type == "authz_check"
        and fact.symbol_name == "owner_id_filter"
        and fact.authz_hint == "owner_or_admin_check"
        and fact.payload.get("handler") == "getForUser"
        for fact in result.facts
    )
    assert len(
        [
            fact
            for fact in result.facts
            if (
                fact.fact_type == "sensitive_sink"
                and fact.payload.get("handler") == "readRecord"
            )
        ]
    ) == 1


def test_map_authorized_code_files_ignores_injectable_marker_in_decorator_string():
    result = map_authorized_code_files(
        {
            "authorized_code_files": [
                {
                    "path": "documentation.ts",
                    "content": '''
@Tag("@Injectable")
export class DocumentationService {
  async getForUser(recordId: string, user: User) {
    const record = await loadRecord(recordId);
    if (record.ownerId !== user.id) {
      return deny();
    }
    return record;
  }
}
''',
                }
            ]
        }
    )

    assert not any(
        fact.payload.get("handler") == "getForUser" for fact in result.facts
    )


def test_map_authorized_code_files_ignores_non_nestjs_injectable_service():
    result = map_authorized_code_files(
        {
            "authorized_code_files": [
                {
                    "path": "documentation.ts",
                    "content": '''
import { Injectable } from "@angular/core";

@Injectable()
export class DocumentationService {
  async getForUser(recordId: string, user: User) {
    const record = await loadRecord(recordId);
    if (record.ownerId !== user.id) {
      return deny();
    }
    return record;
  }
}
''',
                }
            ]
        }
    )

    assert not any(
        fact.payload.get("handler") == "getForUser" for fact in result.facts
    )


def test_map_authorized_code_files_maps_nestjs_injectable_import_alias():
    result = map_authorized_code_files(
        {
            "authorized_code_files": [
                {
                    "path": "records.service.ts",
                    "content": '''
import { Injectable as NestInjectable } from "@nestjs/common";

@NestInjectable()
export class RecordsService {
  async getForUser(recordId: string, user: User) {
    const record = await loadRecord(recordId);
    if (record.ownerId !== user.id) {
      return deny();
    }
    return record;
  }
}
''',
                }
            ]
        }
    )

    assert any(
        fact.fact_type == "authz_check"
        and fact.authz_hint == "owner_or_admin_check"
        and fact.payload.get("handler") == "getForUser"
        and fact.payload.get("service_class") == "RecordsService"
        for fact in result.facts
    )


@pytest.mark.parametrize(
    ("import_suffix", "source_suffix"),
    ((".js", ".ts"), (".mjs", ".mts"), (".cjs", ".cts")),
)
def test_map_authorized_code_files_resolves_nestjs_service_import_source(
    import_suffix: str,
    source_suffix: str,
):
    result = map_authorized_code_files(
        {
            "authorized_code_files": [
                {
                    "path": "records.controller.ts",
                    "content": '''
import { Controller, Get } from "@nestjs/common";
import { RecordsService as ProjectRecordsService } from "./services/records.service.js";

@Controller("records")
export class RecordsController {
  constructor(private readonly recordsService: ProjectRecordsService) {}

  @Get(":recordId")
  async readRecord(recordId: string, user: User) {
    return this.recordsService.getForUser(recordId, user);
  }
}
'''.replace(
                        "./services/records.service.js",
                        f"./services/records.service{import_suffix}",
                    ),
                },
                {
                    "path": f"services/records.service{source_suffix}",
                    "content": '''
import { Injectable } from "@nestjs/common";

@Injectable()
export class RecordsService {
  async getForUser(recordId: string, user: User) {
    return recordId;
  }
}
''',
                },
            ]
        }
    )

    service_call = next(
        fact
        for fact in result.facts
        if fact.fact_type == "service_call"
        and fact.source_path == "records.controller.ts"
        and fact.symbol_name == "getForUser"
    )

    assert service_call.payload["target_service_class"] == "RecordsService"
    assert (
        service_call.payload["target_service_source_path"]
        == f"services/records.service{source_suffix}"
    )


@pytest.mark.parametrize(
    ("content", "expects_external_rebinding"),
    (
        (
            """
class Configure:
    for item in values:
        import rest_framework as rf
        if stop:
            break
        rf = local_holder
    else:
        rf = local_holder
    rf.viewsets.ModelViewSet = build_non_drf_base()
""",
            True,
        ),
        (
            """
class Configure:
    try:
        rest_framework = local_holder
        raise RuntimeError()
    except RuntimeError:
        rest_framework.viewsets.ModelViewSet = build_non_drf_base()
""",
            False,
        ),
        (
            """
class Configure:
    for item in items:
        break
        rest_framework.viewsets.ModelViewSet = build_non_drf_base()
""",
            False,
        ),
        (
            """
class Configure:
    for item in items:
        continue
        rest_framework.viewsets.ModelViewSet = build_non_drf_base()
""",
            False,
        ),
        (
            """
class Configure:
    try:
        always_raises()
        rest_framework = local_holder
    except RuntimeError:
        rest_framework.viewsets.ModelViewSet = build_non_drf_base()
""",
            True,
        ),
        (
            """
class Configure:
    try:
        raise RuntimeError()
        rest_framework = local_holder
    except RuntimeError:
        rest_framework.viewsets.ModelViewSet = build_non_drf_base()
""",
            True,
        ),
        (
            """
class Configure:
    try:
        raise RuntimeError()
    except RuntimeError as rest_framework:
        rest_framework.viewsets.ModelViewSet = build_non_drf_base()
""",
            False,
        ),
    ),
)
def test_django_drf_class_body_rebindings_follow_break_and_except_states(
    content,
    expects_external_rebinding,
):
    statement = ast.parse(content).body[0]
    assert isinstance(statement, ast.ClassDef)

    rebindings = _django_drf_class_body_outer_rebindings(statement)

    assert rebindings is not None
    assert (
        ("rest_framework", "viewsets", "ModelViewSet")
        in rebindings.attribute_paths
    ) is expects_external_rebinding


@pytest.mark.parametrize(
    ("content", "expected"),
    (
        (
            """
def get_queryset(self):
    queryset = File.objects.filter(owner_id=current_user.id)
    if self.action == "destroy":
        queryset = File.objects.all()
        queryset = File.objects.filter(owner_id=current_user.id)
    return queryset
""",
            False,
        ),
        (
            """
def get_queryset(self):
    queryset = File.objects.filter(owner_id=current_user.id)
    for item in items:
        break
        queryset = self.action
    return queryset
""",
            False,
        ),
        (
            """
def get_queryset(self):
    queryset = File.objects.filter(owner_id=current_user.id)
    for item in items:
        continue
        queryset = self.action
    return queryset
""",
            False,
        ),
        (
            """
def get_queryset(self):
    self.queryset = File.objects.filter(owner_id=current_user.id)
    if self.action == "destroy":
        self.queryset = File.objects.all()
        self.queryset = File.objects.filter(owner_id=current_user.id)
    return self.queryset
""",
            False,
        ),
        (
            """
def get_queryset(self):
    queryset = File.objects.filter(owner_id=current_user.id)
    if self.action == "destroy":
        queryset = File.objects.filter(owner_id=current_user.id)
        queryset = File.objects.all()
    return queryset
""",
            True,
        ),
        (
            """
def get_queryset(self):
    try:
        queryset = self.action
        raise RuntimeError()
    except RuntimeError:
        return queryset
""",
            True,
        ),
        (
            """
def get_queryset(self):
    try:
        queryset = self.action
        raise RuntimeError()
    except RuntimeError:
        pass
    finally:
        queryset = File.objects.filter(owner_id=current_user.id)
    return queryset
""",
            False,
        ),
        (
            """
def get_queryset(self):
    match feature:
        case _:
            queryset = File.objects.filter(owner_id=current_user.id)
    return queryset
""",
            False,
        ),
    ),
)
def test_django_drf_action_dependency_follows_branch_exit_values(content, expected):
    member = ast.parse(content).body[0]
    assert isinstance(member, ast.FunctionDef)

    assert _django_drf_method_depends_on_action(member) is expected


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


def test_map_authorized_code_files_composes_static_fastapi_router_prefixes():
    result = map_authorized_code_files(
        {
            "authorized_code_files": [
                {
                    "path": "app.py",
                    "content": """
from fastapi import FastAPI
from api.router import router as api_router

app = FastAPI()
app.include_router(api_router, prefix="/v1")
""",
                },
                {
                    "path": "api/router.py",
                    "content": """
from fastapi import APIRouter
from routes.files import router as files_router

router = APIRouter(prefix="/api")
router.include_router(files_router, prefix="/files")
""",
                },
                {
                    "path": "routes/files.py",
                    "content": """
from fastapi import APIRouter

router = APIRouter(prefix="/exports")

@router.get("/{file_id}")
def export_file(file_id: str):
    return send_file(file_id)
""",
                },
            ]
        }
    )

    routes = [
        (fact.route_method, fact.route_path)
        for fact in result.facts
        if fact.fact_type == "route_handler"
    ]
    gap = next(
        fact for fact in result.facts if fact.fact_type == "authorization_gap_candidate"
    )

    assert routes == [("GET", "/v1/api/files/exports/{file_id}")]
    assert gap.route_path == "/v1/api/files/exports/{file_id}"


def test_map_authorized_code_files_resolves_package_relative_fastapi_router_imports():
    result = map_authorized_code_files(
        {
            "authorized_code_files": [
                {
                    "path": "project/__init__.py",
                    "content": """
from fastapi import FastAPI
from .routes import router

app = FastAPI()
app.include_router(router, prefix="/v1")
""",
                },
                {
                    "path": "project/routes.py",
                    "content": """
from fastapi import APIRouter

router = APIRouter(prefix="/api")

@router.get("/exports/{file_id}")
def export_file(file_id: str):
    return send_file(file_id)
""",
                },
                {
                    "path": "other/routes.py",
                    "content": """
from fastapi import APIRouter

router = APIRouter(prefix="/other")
""",
                },
            ]
        }
    )

    route = next(fact for fact in result.facts if fact.fact_type == "route_handler")
    gap = next(
        fact for fact in result.facts if fact.fact_type == "authorization_gap_candidate"
    )

    assert route.route_path == "/v1/api/exports/{file_id}"
    assert gap.route_path == "/v1/api/exports/{file_id}"


def test_map_authorized_code_files_keeps_dynamic_fastapi_include_prefix_unresolved():
    result = map_authorized_code_files(
        {
            "authorized_code_files": [
                {
                    "path": "app.py",
                    "content": """
from fastapi import FastAPI
from routes.files import router as files_router

app = FastAPI()
api_prefix = load_local_prefix()
app.include_router(files_router, prefix=api_prefix)
""",
                },
                {
                    "path": "routes/files.py",
                    "content": """
from fastapi import APIRouter

router = APIRouter(prefix="/files")

@router.get("/{file_id}")
def export_file(file_id: str):
    return send_file(file_id)
""",
                },
            ]
        }
    )

    route = next(fact for fact in result.facts if fact.fact_type == "route_handler")
    gap = next(
        fact for fact in result.facts if fact.fact_type == "authorization_gap_candidate"
    )

    assert route.route_path == "/files/{file_id}"
    assert gap.route_path == "/files/{file_id}"


def test_map_authorized_code_files_does_not_assume_unknown_include_router_owner():
    result = map_authorized_code_files(
        {
            "authorized_code_files": [
                {
                    "path": "registry.py",
                    "content": """
from routes.files import router as files_router

registry = RouterRegistry()
registry.include_router(files_router, prefix="/invented")
""",
                },
                {
                    "path": "routes/files.py",
                    "content": """
from fastapi import APIRouter

router = APIRouter(prefix="/files")

@router.get("/{file_id}")
def export_file(file_id: str):
    return send_file(file_id)
""",
                },
            ]
        }
    )

    route = next(fact for fact in result.facts if fact.fact_type == "route_handler")
    gap = next(
        fact for fact in result.facts if fact.fact_type == "authorization_gap_candidate"
    )

    assert route.route_path == "/files/{file_id}"
    assert gap.route_path == "/files/{file_id}"


def test_map_authorized_code_files_composes_static_flask_blueprint_prefixes():
    result = map_authorized_code_files(
        {
            "authorized_code_files": [
                {
                    "path": "app.py",
                    "content": """
from flask import Flask
from api.blueprint import bp as api_bp

app = Flask(__name__)
app.register_blueprint(api_bp, url_prefix="/v1")
""",
                },
                {
                    "path": "api/blueprint.py",
                    "content": """
from flask import Blueprint
from routes.files import bp as files_bp

bp = Blueprint("api", __name__, url_prefix="/api")
bp.register_blueprint(files_bp, url_prefix="/files")
""",
                },
                {
                    "path": "routes/files.py",
                    "content": """
from flask import Blueprint, send_file

bp = Blueprint("files", __name__, url_prefix="/exports")

@bp.route("/<file_id>", methods=["GET"])
def export_file(file_id: str):
    return send_file(file_id)
""",
                },
            ]
        }
    )

    routes = [
        (fact.route_method, fact.route_path)
        for fact in result.facts
        if fact.fact_type == "route_handler"
    ]
    gap = next(
        fact for fact in result.facts if fact.fact_type == "authorization_gap_candidate"
    )

    assert routes == [("GET", "/v1/api/files/exports/<file_id>")]
    assert gap.route_path == "/v1/api/files/exports/<file_id>"


def test_map_authorized_code_files_does_not_assume_unknown_blueprint_owner():
    result = map_authorized_code_files(
        {
            "authorized_code_files": [
                {
                    "path": "registry.py",
                    "content": """
from routes.files import bp

registry = BlueprintRegistry()
registry.register_blueprint(bp, url_prefix="/invented")
""",
                },
                {
                    "path": "routes/files.py",
                    "content": """
from flask import Blueprint, send_file

bp = Blueprint("files", __name__, url_prefix="/files")

@bp.route("/<file_id>", methods=["GET"])
def export_file(file_id: str):
    return send_file(file_id)
""",
                },
            ]
        }
    )

    route = next(fact for fact in result.facts if fact.fact_type == "route_handler")
    gap = next(
        fact for fact in result.facts if fact.fact_type == "authorization_gap_candidate"
    )

    assert route.route_path == "/files/<file_id>"
    assert gap.route_path == "/files/<file_id>"


def test_map_authorized_code_files_composes_static_django_urlconf_prefixes():
    result = map_authorized_code_files(
        {
            "authorized_code_files": [
                {
                    "path": "project/settings.py",
                    "content": """
ROOT_URLCONF = "project.urls"
""",
                },
                {
                    "path": "project/urls.py",
                    "content": """
from django.urls import include, path

urlpatterns = [
    path("v1/", include("api.urls")),
]
""",
                },
                {
                    "path": "api/urls.py",
                    "content": """
from django.urls import include, path

urlpatterns = [
    path("files/", include("routes.urls")),
]
""",
                },
                {
                    "path": "routes/urls.py",
                    "content": """
from django.urls import path
from . import views as file_views

urlpatterns = [
    path("exports/<uuid:file_id>/", file_views.export_file),
]
""",
                },
                {
                    "path": "routes/views.py",
                    "content": """
def export_file(file_id: str):
    return send_file(file_id)
""",
                },
            ]
        }
    )

    routes = [
        fact
        for fact in result.facts
        if fact.fact_type == "route_handler"
    ]
    gap = next(
        fact for fact in result.facts if fact.fact_type == "authorization_gap_candidate"
    )

    assert [(fact.route_method, fact.route_path) for fact in routes] == [
        ("ANY", "/v1/files/exports/<uuid:file_id>/"),
    ]
    assert routes[0].source_path == "routes/views.py"
    assert routes[0].symbol_name == "export_file"
    assert gap.route_path == "/v1/files/exports/<uuid:file_id>/"
    assert gap.source_path == "routes/views.py"


def test_map_authorized_code_files_maps_incremental_django_urlconf_with_namespaced_include():
    result = map_authorized_code_files(
        {
            "authorized_code_files": [
                {
                    "path": "project/settings.py",
                    "content": """
ROOT_URLCONF = "project.urls"
""",
                },
                {
                    "path": "project/urls.py",
                    "content": """
from django.urls import include, path

urlpatterns = []
urlpatterns += [
    path("v1/", include(("api.urls", "api"), namespace="api")),
]
""",
                },
                {
                    "path": "api/urls.py",
                    "content": """
from django.urls import path
from .views import export_file

urlpatterns = [
    path("exports/<uuid:file_id>/", export_file),
]
""",
                },
                {
                    "path": "api/views.py",
                    "content": """
def export_file(file_id: str):
    return send_file(file_id)
""",
                },
            ]
        }
    )

    route = next(fact for fact in result.facts if fact.fact_type == "route_handler")
    gap = next(
        fact for fact in result.facts if fact.fact_type == "authorization_gap_candidate"
    )

    assert (route.route_method, route.route_path) == (
        "ANY",
        "/v1/exports/<uuid:file_id>/",
    )
    assert route.source_path == "api/views.py"
    assert route.symbol_name == "export_file"
    assert gap.route_path == "/v1/exports/<uuid:file_id>/"


def test_map_authorized_code_files_does_not_keep_overridden_django_urlpatterns():
    result = map_authorized_code_files(
        {
            "authorized_code_files": [
                {
                    "path": "project/settings.py",
                    "content": """
ROOT_URLCONF = "project.urls"
""",
                },
                {
                    "path": "project/urls.py",
                    "content": """
from django.urls import path

urlpatterns = [
    path("stale/<uuid:file_id>/", export_file),
]
urlpatterns = []

def export_file(file_id: str):
    return send_file(file_id)
""",
                },
            ]
        }
    )

    assert not any(fact.fact_type == "route_handler" for fact in result.facts)
    assert not any(
        fact.fact_type == "authorization_gap_candidate" for fact in result.facts
    )


def test_map_authorized_code_files_keeps_only_latest_static_django_root_urlconf():
    result = map_authorized_code_files(
        {
            "authorized_code_files": [
                {
                    "path": "project/settings.py",
                    "content": """
ROOT_URLCONF = "stale.urls"
ROOT_URLCONF = "project.urls"
""",
                },
                {
                    "path": "project/urls.py",
                    "content": """
from django.urls import path
from .views import export_file

urlpatterns = [
    path("exports/<uuid:file_id>/", export_file),
]
""",
                },
                {
                    "path": "project/views.py",
                    "content": """
def export_file(file_id: str):
    return send_file(file_id)
""",
                },
                {
                    "path": "stale/urls.py",
                    "content": """
from django.urls import path
from .views import stale_export

urlpatterns = [
    path("stale/<uuid:file_id>/", stale_export),
]
""",
                },
                {
                    "path": "stale/views.py",
                    "content": """
def stale_export(file_id: str):
    return send_file(file_id)
""",
                },
            ]
        }
    )

    routes = [fact for fact in result.facts if fact.fact_type == "route_handler"]
    gaps = [
        fact
        for fact in result.facts
        if fact.fact_type == "authorization_gap_candidate"
    ]

    assert [(fact.source_path, fact.route_path) for fact in routes] == [
        ("project/views.py", "/exports/<uuid:file_id>/"),
    ]
    assert [(fact.source_path, fact.route_path) for fact in gaps] == [
        ("project/views.py", "/exports/<uuid:file_id>/"),
    ]


def test_map_authorized_code_files_keeps_ambiguous_django_roots_unresolved():
    result = map_authorized_code_files(
        {
            "authorized_code_files": [
                {
                    "path": "project/settings.py",
                    "content": 'ROOT_URLCONF = "project.urls"',
                },
                {
                    "path": "alternate/settings.py",
                    "content": 'ROOT_URLCONF = "alternate.urls"',
                },
                {
                    "path": "project/urls.py",
                    "content": """
from django.urls import path

urlpatterns = [path("project/", project_export)]

def project_export():
    return send_file("project")
""",
                },
                {
                    "path": "alternate/urls.py",
                    "content": """
from django.urls import path

urlpatterns = [path("alternate/", alternate_export)]

def alternate_export():
    return send_file("alternate")
""",
                },
            ]
        }
    )

    assert not any(fact.fact_type == "route_handler" for fact in result.facts)
    assert not any(
        fact.fact_type == "authorization_gap_candidate" for fact in result.facts
    )


def test_map_authorized_code_files_keeps_dynamic_django_root_unresolved():
    result = map_authorized_code_files(
        {
            "authorized_code_files": [
                {
                    "path": "project/settings.py",
                    "content": 'ROOT_URLCONF = "project.urls"',
                },
                {
                    "path": "alternate/settings.py",
                    "content": """
ROOT_URLCONF = load_root_urlconf()
""",
                },
                {
                    "path": "project/urls.py",
                    "content": """
from django.urls import path

urlpatterns = [path("project/", project_export)]

def project_export():
    return send_file("project")
""",
                },
            ]
        }
    )

    assert not any(fact.fact_type == "route_handler" for fact in result.facts)
    assert not any(
        fact.fact_type == "authorization_gap_candidate" for fact in result.facts
    )


def test_map_authorized_code_files_keeps_dynamic_django_include_prefix_unresolved():
    result = map_authorized_code_files(
        {
            "authorized_code_files": [
                {
                    "path": "project/settings.py",
                    "content": """
ROOT_URLCONF = "project.urls"
""",
                },
                {
                    "path": "project/urls.py",
                    "content": """
from django.urls import include, path

api_prefix = load_local_prefix()
urlpatterns = [
    path(api_prefix, include("routes.urls")),
]
""",
                },
                {
                    "path": "routes/urls.py",
                    "content": """
from django.urls import path
from .views import export_file

urlpatterns = [
    path("exports/<uuid:file_id>/", export_file),
]
""",
                },
                {
                    "path": "routes/views.py",
                    "content": """
def export_file(file_id: str):
    return send_file(file_id)
""",
                },
            ]
        }
    )

    assert not any(fact.fact_type == "route_handler" for fact in result.facts)
    assert not any(
        fact.fact_type == "authorization_gap_candidate" for fact in result.facts
    )


@pytest.mark.parametrize("router_type", ("DefaultRouter", "SimpleRouter"))
def test_map_authorized_code_files_maps_static_drf_router_crud_actions(router_type):
    result = map_authorized_code_files(
        {
            "authorized_code_files": [
                {
                    "path": "project/settings.py",
                    "content": 'ROOT_URLCONF = "project.urls"',
                },
                {
                    "path": "project/urls.py",
                    "content": f"""
from django.urls import include, path
from rest_framework.routers import {router_type}
from .views import ProjectViewSet

router = {router_type}()
router.register("projects", ProjectViewSet, basename="project")
urlpatterns = [
    path("api/", include(router.urls)),
]
""",
                },
                {
                    "path": "project/views.py",
                    "content": """
from rest_framework.viewsets import ViewSet

class ProjectViewSet(ViewSet):
    def list(self, request):
        return []

    def create(self, request):
        return None

    def retrieve(self, request, pk):
        project = Project.objects.get(pk=pk)
        return send_file(project.path)

    def update(self, request, pk):
        return None

    def partial_update(self, request, pk):
        return None

    def destroy(self, request, pk):
        return None
""",
                },
            ]
        }
    )

    routes = {
        (fact.symbol_name, fact.route_method, fact.route_path)
        for fact in result.facts
        if fact.fact_type == "route_handler"
    }
    sink = next(fact for fact in result.facts if fact.fact_type == "sensitive_sink")
    gap = next(
        fact
        for fact in result.facts
        if fact.fact_type == "authorization_gap_candidate"
    )

    assert routes == {
        ("ProjectViewSet.list", "GET", "/api/projects/"),
        ("ProjectViewSet.create", "POST", "/api/projects/"),
        ("ProjectViewSet.retrieve", "GET", "/api/projects/{pk}/"),
        ("ProjectViewSet.update", "PUT", "/api/projects/{pk}/"),
        ("ProjectViewSet.partial_update", "PATCH", "/api/projects/{pk}/"),
        ("ProjectViewSet.destroy", "DELETE", "/api/projects/{pk}/"),
    }
    assert sink.payload["handler"] == "ProjectViewSet.retrieve"
    assert (gap.symbol_name, gap.route_method, gap.route_path) == (
        "ProjectViewSet.retrieve",
        "GET",
        "/api/projects/{pk}/",
    )


def test_map_authorized_code_files_maps_model_viewset_destroy_hook_to_delete_route():
    result = map_authorized_code_files(
        {
            "authorized_code_files": [
                {
                    "path": "project/settings.py",
                    "content": 'ROOT_URLCONF = "project.urls"',
                },
                {
                    "path": "project/urls.py",
                    "content": """
from django.urls import include, path
from rest_framework.routers import DefaultRouter
from .views import FileViewSet

router = DefaultRouter()
router.register("files", FileViewSet, basename="file")
urlpatterns = [path("api/", include(router.urls))]
""",
                },
                {
                    "path": "project/views.py",
                    "content": """
from rest_framework.viewsets import ModelViewSet

class FileViewSet(ModelViewSet):
    def perform_destroy(self, instance):
        return delete_file(instance.path)
""",
                },
            ]
        }
    )

    route = next(fact for fact in result.facts if fact.fact_type == "route_handler")
    sink = next(fact for fact in result.facts if fact.fact_type == "sensitive_sink")
    gap = next(
        fact
        for fact in result.facts
        if fact.fact_type == "authorization_gap_candidate"
    )

    assert (route.symbol_name, route.route_method, route.route_path) == (
        "FileViewSet.destroy",
        "DELETE",
        "/api/files/{pk}/",
    )
    assert sink.payload["handler"] == "FileViewSet.perform_destroy"
    assert (gap.symbol_name, gap.route_method, gap.route_path) == (
        "FileViewSet.destroy",
        "DELETE",
        "/api/files/{pk}/",
    )


def test_map_authorized_code_files_uses_model_viewset_queryset_guard_before_destroy_hook():
    result = map_authorized_code_files(
        {
            "authorized_code_files": [
                {
                    "path": "project/settings.py",
                    "content": 'ROOT_URLCONF = "project.urls"',
                },
                {
                    "path": "project/urls.py",
                    "content": """
from django.urls import include, path
from rest_framework.routers import DefaultRouter
from .views import FileViewSet

router = DefaultRouter()
router.register("files", FileViewSet, basename="file")
urlpatterns = [path("api/", include(router.urls))]
""",
                },
                {
                    "path": "project/views.py",
                    "content": """
from rest_framework.viewsets import ModelViewSet

class FileViewSet(ModelViewSet):
    def get_queryset(self):
        return File.objects.filter(owner_id=current_user.id)

    def perform_destroy(self, instance):
        return delete_file(instance.path)
""",
                },
            ]
        }
    )

    routes = {
        (fact.symbol_name, fact.route_method, fact.route_path)
        for fact in result.facts
        if fact.fact_type == "route_handler"
    }
    calls = [fact for fact in result.facts if fact.fact_type == "service_call"]

    assert routes == {
        ("FileViewSet.list", "GET", "/api/files/"),
        ("FileViewSet.retrieve", "GET", "/api/files/{pk}/"),
        ("FileViewSet.update", "PUT", "/api/files/{pk}/"),
        ("FileViewSet.partial_update", "PATCH", "/api/files/{pk}/"),
        ("FileViewSet.destroy", "DELETE", "/api/files/{pk}/"),
    }
    assert any(
        fact.symbol_name == "FileViewSet.get_queryset"
        and fact.payload.get("caller") == "FileViewSet.destroy"
        for fact in calls
    )
    assert not any(
        fact.fact_type == "authorization_gap_candidate" for fact in result.facts
    )


def test_map_authorized_code_files_maps_read_only_model_viewset_queryset_hook_from_module_alias():
    result = map_authorized_code_files(
        {
            "authorized_code_files": [
                {
                    "path": "project/settings.py",
                    "content": 'ROOT_URLCONF = "project.urls"',
                },
                {
                    "path": "project/urls.py",
                    "content": """
from django.urls import include, path
from rest_framework.routers import DefaultRouter
from .views import FileViewSet

router = DefaultRouter()
router.register("files", FileViewSet, basename="file")
urlpatterns = [path("api/", include(router.urls))]
""",
                },
                {
                    "path": "project/views.py",
                    "content": """
from rest_framework import viewsets

class FileViewSet(viewsets.ReadOnlyModelViewSet):
    def get_queryset(self):
        return get_blob(current_user.id)
""",
                },
            ]
        }
    )

    routes = {
        (fact.symbol_name, fact.route_method, fact.route_path)
        for fact in result.facts
        if fact.fact_type == "route_handler"
    }

    assert routes == {
        ("FileViewSet.list", "GET", "/api/files/"),
        ("FileViewSet.retrieve", "GET", "/api/files/{pk}/"),
    }
    assert {
        (fact.symbol_name, fact.route_path)
        for fact in result.facts
        if fact.fact_type == "authorization_gap_candidate"
    } == {
        ("FileViewSet.list", "/api/files/"),
        ("FileViewSet.retrieve", "/api/files/{pk}/"),
    }


def test_map_authorized_code_files_requires_drf_import_for_inherited_viewset_hooks():
    result = map_authorized_code_files(
        {
            "authorized_code_files": [
                {
                    "path": "project/settings.py",
                    "content": 'ROOT_URLCONF = "project.urls"',
                },
                {
                    "path": "project/urls.py",
                    "content": """
from django.urls import include, path
from rest_framework.routers import DefaultRouter
from .views import FileViewSet

router = DefaultRouter()
router.register("files", FileViewSet, basename="file")
urlpatterns = [path("api/", include(router.urls))]
""",
                },
                {
                    "path": "project/views.py",
                    "content": """
class ModelViewSet:
    pass

class FileViewSet(ModelViewSet):
    def perform_destroy(self, instance):
        return delete_file(instance.path)
""",
                },
            ]
        }
    )

    assert not any(fact.fact_type == "route_handler" for fact in result.facts)
    assert not any(
        fact.fact_type == "authorization_gap_candidate" for fact in result.facts
    )


@pytest.mark.parametrize(
    "view_content",
    (
        """
from rest_framework.viewsets import ModelViewSet

ModelViewSet = build_non_drf_base()

class FileViewSet(ModelViewSet):
    def perform_destroy(self, instance):
        return delete_file(instance.path)
""",
        """
from rest_framework import viewsets

viewsets = build_non_drf_module()

class FileViewSet(viewsets.ModelViewSet):
    def perform_destroy(self, instance):
        return delete_file(instance.path)
""",
    ),
)
def test_map_authorized_code_files_ignores_rebound_drf_viewset_aliases(view_content):
    result = map_authorized_code_files(
        {
            "authorized_code_files": [
                {
                    "path": "project/settings.py",
                    "content": 'ROOT_URLCONF = "project.urls"',
                },
                {
                    "path": "project/urls.py",
                    "content": """
from django.urls import include, path
from rest_framework.routers import DefaultRouter
from .views import FileViewSet

router = DefaultRouter()
router.register("files", FileViewSet, basename="file")
urlpatterns = [path("api/", include(router.urls))]
""",
                },
                {"path": "project/views.py", "content": view_content},
            ]
        }
    )

    assert not any(fact.fact_type == "route_handler" for fact in result.facts)
    assert not any(
        fact.fact_type == "authorization_gap_candidate" for fact in result.facts
    )


@pytest.mark.parametrize(
    "view_content",
    (
        """
from rest_framework.viewsets import ModelViewSet

ModelViewSet: object

class FileViewSet(ModelViewSet):
    def perform_destroy(self, instance):
        return delete_file(instance.path)
""",
        """
from rest_framework import viewsets

viewsets: object

class FileViewSet(viewsets.ModelViewSet):
    def perform_destroy(self, instance):
        return delete_file(instance.path)
""",
    ),
)
def test_map_authorized_code_files_keeps_drf_viewset_aliases_after_bare_annotations(
    view_content,
):
    result = map_authorized_code_files(
        {
            "authorized_code_files": [
                {
                    "path": "project/settings.py",
                    "content": 'ROOT_URLCONF = "project.urls"',
                },
                {
                    "path": "project/urls.py",
                    "content": """
from django.urls import include, path
from rest_framework.routers import DefaultRouter
from .views import FileViewSet

router = DefaultRouter()
router.register("files", FileViewSet, basename="file")
urlpatterns = [path("api/", include(router.urls))]
""",
                },
                {"path": "project/views.py", "content": view_content},
            ]
        }
    )

    assert {
        (fact.symbol_name, fact.route_method, fact.route_path)
        for fact in result.facts
        if fact.fact_type == "route_handler"
    } == {("FileViewSet.destroy", "DELETE", "/api/files/{pk}/")}


@pytest.mark.parametrize(
    "rebinding",
    (
        """
for ModelViewSet in (build_non_drf_base(),):
    pass
""",
        """
with build_non_drf_context() as ModelViewSet:
    pass
""",
        """
if (ModelViewSet := build_non_drf_base()):
    pass
""",
        """
def marker(value=(ModelViewSet := build_non_drf_base())):
    pass
""",
    ),
)
def test_map_authorized_code_files_ignores_drf_aliases_rebound_by_top_level_statements(
    rebinding,
):
    result = map_authorized_code_files(
        {
            "authorized_code_files": [
                {
                    "path": "project/settings.py",
                    "content": 'ROOT_URLCONF = "project.urls"',
                },
                {
                    "path": "project/urls.py",
                    "content": """
from django.urls import include, path
from rest_framework.routers import DefaultRouter
from .views import FileViewSet

router = DefaultRouter()
router.register("files", FileViewSet, basename="file")
urlpatterns = [path("api/", include(router.urls))]
""",
                },
                {
                    "path": "project/views.py",
                    "content": f"""
from rest_framework.viewsets import ModelViewSet
{rebinding}
class FileViewSet(ModelViewSet):
    def perform_destroy(self, instance):
        return delete_file(instance.path)
""",
                },
            ]
        }
    )

    assert not any(fact.fact_type == "route_handler" for fact in result.facts)
    assert not any(
        fact.fact_type == "authorization_gap_candidate" for fact in result.facts
    )


@pytest.mark.parametrize(
    "view_content",
    (
        """
from rest_framework.viewsets import ModelViewSet

sentinel = (ModelViewSet := build_non_drf_base())

class FileViewSet(ModelViewSet):
    def perform_destroy(self, instance):
        return delete_file(instance.path)
""",
        """
from rest_framework import viewsets

sentinel = (viewsets := build_non_drf_module())

class FileViewSet(viewsets.ModelViewSet):
    def perform_destroy(self, instance):
        return delete_file(instance.path)
""",
    ),
)
def test_map_authorized_code_files_ignores_drf_aliases_rebound_in_assignment_values(
    view_content,
):
    result = map_authorized_code_files(
        {
            "authorized_code_files": [
                {
                    "path": "project/settings.py",
                    "content": 'ROOT_URLCONF = "project.urls"',
                },
                {
                    "path": "project/urls.py",
                    "content": """
from django.urls import include, path
from rest_framework.routers import DefaultRouter
from .views import FileViewSet

router = DefaultRouter()
router.register("files", FileViewSet, basename="file")
urlpatterns = [path("api/", include(router.urls))]
""",
                },
                {"path": "project/views.py", "content": view_content},
            ]
        }
    )

    assert not any(fact.fact_type == "route_handler" for fact in result.facts)
    assert not any(
        fact.fact_type == "authorization_gap_candidate" for fact in result.facts
    )


def test_map_authorized_code_files_keeps_viewset_declared_before_drf_alias_rebinding():
    result = map_authorized_code_files(
        {
            "authorized_code_files": [
                {
                    "path": "project/settings.py",
                    "content": 'ROOT_URLCONF = "project.urls"',
                },
                {
                    "path": "project/urls.py",
                    "content": """
from django.urls import include, path
from rest_framework.routers import DefaultRouter
from .views import EarlierViewSet, LaterViewSet

router = DefaultRouter()
router.register("earlier", EarlierViewSet, basename="earlier")
router.register("later", LaterViewSet, basename="later")
urlpatterns = [path("api/", include(router.urls))]
""",
                },
                {
                    "path": "project/views.py",
                    "content": """
from rest_framework.viewsets import ModelViewSet

class EarlierViewSet(ModelViewSet):
    def perform_destroy(self, instance):
        return delete_file(instance.path)

ModelViewSet = build_non_drf_base()

class LaterViewSet(ModelViewSet):
    def perform_destroy(self, instance):
        return delete_file(instance.path)
""",
                },
            ]
        }
    )

    assert {
        (fact.symbol_name, fact.route_method, fact.route_path)
        for fact in result.facts
        if fact.fact_type == "route_handler"
    } == {("EarlierViewSet.destroy", "DELETE", "/api/earlier/{pk}/")}


@pytest.mark.parametrize(
    "action_lookup",
    (
        "self.action",
        'getattr(self, "action", None)',
    ),
)
def test_map_authorized_code_files_keeps_destroy_candidate_for_action_dependent_queryset(
    action_lookup,
):
    result = map_authorized_code_files(
        {
            "authorized_code_files": [
                {
                    "path": "project/settings.py",
                    "content": 'ROOT_URLCONF = "project.urls"',
                },
                {
                    "path": "project/urls.py",
                    "content": """
from django.urls import include, path
from rest_framework.routers import DefaultRouter
from .views import FileViewSet

router = DefaultRouter()
router.register("files", FileViewSet, basename="file")
urlpatterns = [path("api/", include(router.urls))]
""",
                },
                {
                    "path": "project/views.py",
                    "content": f"""
from rest_framework.viewsets import ModelViewSet

class FileViewSet(ModelViewSet):
    def get_queryset(self):
        action = {action_lookup}
        if action == "list":
            return File.objects.filter(owner_id=current_user.id)
        return File.objects.all()

    def perform_destroy(self, instance):
        return delete_file(instance.path)
""",
                },
            ]
        }
    )

    assert {
        (fact.symbol_name, fact.route_method, fact.route_path)
        for fact in result.facts
        if fact.fact_type == "authorization_gap_candidate"
    } == {("FileViewSet.destroy", "DELETE", "/api/files/{pk}/")}
    assert any(
        fact.fact_type == "service_call"
        and fact.symbol_name == "FileViewSet.get_queryset"
        and fact.payload.get("caller") == "FileViewSet.destroy"
        and fact.payload.get("lifecycle_action_dependent") is True
        for fact in result.facts
    )


def test_map_authorized_code_files_keeps_unconditional_queryset_guard_with_non_control_action_reads():
    result = map_authorized_code_files(
        {
            "authorized_code_files": [
                {
                    "path": "project/settings.py",
                    "content": 'ROOT_URLCONF = "project.urls"',
                },
                {
                    "path": "project/urls.py",
                    "content": """
from django.urls import include, path
from rest_framework.routers import DefaultRouter
from .views import FileViewSet

router = DefaultRouter()
router.register("files", FileViewSet, basename="file")
urlpatterns = [path("api/", include(router.urls))]
""",
                },
                {
                    "path": "project/views.py",
                    "content": """
from rest_framework.viewsets import ModelViewSet

class FileViewSet(ModelViewSet):
    def get_queryset(self):
        def action_name():
            return self.action

        if self.action:
            audit_log("action")
        audit_log(getattr(self, "action", None))
        return File.objects.filter(owner_id=current_user.id)

    def perform_destroy(self, instance):
        return delete_file(instance.path)
""",
                },
            ]
        }
    )

    assert not any(
        fact.fact_type == "authorization_gap_candidate" for fact in result.facts
    )
    assert any(
        fact.fact_type == "service_call"
        and fact.symbol_name == "FileViewSet.get_queryset"
        and fact.payload.get("caller") == "FileViewSet.destroy"
        and fact.payload.get("lifecycle_action_dependent") is not True
        for fact in result.facts
    )


def test_map_authorized_code_files_keeps_queryset_guard_after_action_alias_rebinding():
    result = map_authorized_code_files(
        {
            "authorized_code_files": [
                {
                    "path": "project/settings.py",
                    "content": 'ROOT_URLCONF = "project.urls"',
                },
                {
                    "path": "project/urls.py",
                    "content": """
from django.urls import include, path
from rest_framework.routers import DefaultRouter
from .views import FileViewSet

router = DefaultRouter()
router.register("files", FileViewSet, basename="file")
urlpatterns = [path("api/", include(router.urls))]
""",
                },
                {
                    "path": "project/views.py",
                    "content": """
from rest_framework.viewsets import ModelViewSet

class FileViewSet(ModelViewSet):
    def get_queryset(self):
        action = self.action
        action = "list"
        if action == "list":
            return File.objects.filter(owner_id=current_user.id)
        return File.objects.filter(owner_id=current_user.id)

    def perform_destroy(self, instance):
        return delete_file(instance.path)
""",
                },
            ]
        }
    )

    assert not any(
        fact.fact_type == "authorization_gap_candidate" for fact in result.facts
    )
    assert any(
        fact.fact_type == "service_call"
        and fact.symbol_name == "FileViewSet.get_queryset"
        and fact.payload.get("caller") == "FileViewSet.destroy"
        and fact.payload.get("lifecycle_action_dependent") is not True
        for fact in result.facts
    )


def test_map_authorized_code_files_keeps_destroy_candidate_for_augmented_action_alias():
    result = map_authorized_code_files(
        {
            "authorized_code_files": [
                {
                    "path": "project/settings.py",
                    "content": 'ROOT_URLCONF = "project.urls"',
                },
                {
                    "path": "project/urls.py",
                    "content": """
from django.urls import include, path
from rest_framework.routers import DefaultRouter
from .views import FileViewSet

router = DefaultRouter()
router.register("files", FileViewSet, basename="file")
urlpatterns = [path("api/", include(router.urls))]
""",
                },
                {
                    "path": "project/views.py",
                    "content": """
from rest_framework.viewsets import ModelViewSet

class FileViewSet(ModelViewSet):
    def get_queryset(self):
        action = self.action
        action += "-scoped"
        if action == "list-scoped":
            return File.objects.filter(owner_id=current_user.id)
        return File.objects.all()

    def perform_destroy(self, instance):
        return delete_file(instance.path)
""",
                },
            ]
        }
    )

    assert {
        (fact.symbol_name, fact.route_method, fact.route_path)
        for fact in result.facts
        if fact.fact_type == "authorization_gap_candidate"
    } == {("FileViewSet.destroy", "DELETE", "/api/files/{pk}/")}
    assert any(
        fact.fact_type == "service_call"
        and fact.symbol_name == "FileViewSet.get_queryset"
        and fact.payload.get("caller") == "FileViewSet.destroy"
        and fact.payload.get("lifecycle_action_dependent") is True
        for fact in result.facts
    )


@pytest.mark.parametrize(
    ("assignment_target", "return_value"),
    (
        ("queryset", "queryset"),
        ("self.queryset", "self.queryset"),
        (
            "self.queryset",
            'getattr(self, "queryset", File.objects.none())',
        ),
    ),
)
def test_map_authorized_code_files_keeps_destroy_candidate_for_action_controlled_queryset_assignment(
    assignment_target,
    return_value,
):
    result = map_authorized_code_files(
        {
            "authorized_code_files": [
                {
                    "path": "project/settings.py",
                    "content": 'ROOT_URLCONF = "project.urls"',
                },
                {
                    "path": "project/urls.py",
                    "content": """
from django.urls import include, path
from rest_framework.routers import DefaultRouter
from .views import FileViewSet

router = DefaultRouter()
router.register("files", FileViewSet, basename="file")
urlpatterns = [path("api/", include(router.urls))]
""",
                },
                {
                    "path": "project/views.py",
                    "content": f"""
from rest_framework.viewsets import ModelViewSet

class FileViewSet(ModelViewSet):
    def get_queryset(self):
        {assignment_target} = File.objects.filter(owner_id=current_user.id)
        if self.action == "destroy":
            {assignment_target} = File.objects.all()
        return {return_value}

    def perform_destroy(self, instance):
        return delete_file(instance.path)
""",
                },
            ]
        }
    )

    assert {
        (fact.symbol_name, fact.route_method, fact.route_path)
        for fact in result.facts
        if fact.fact_type == "authorization_gap_candidate"
    } == {("FileViewSet.destroy", "DELETE", "/api/files/{pk}/")}
    assert any(
        fact.fact_type == "service_call"
        and fact.symbol_name == "FileViewSet.get_queryset"
        and fact.payload.get("caller") == "FileViewSet.destroy"
        and fact.payload.get("lifecycle_action_dependent") is True
        for fact in result.facts
    )


def test_map_authorized_code_files_keeps_destroy_candidate_for_action_value_in_feature_branch():
    result = map_authorized_code_files(
        {
            "authorized_code_files": [
                {
                    "path": "project/settings.py",
                    "content": 'ROOT_URLCONF = "project.urls"',
                },
                {
                    "path": "project/urls.py",
                    "content": """
from django.urls import include, path
from rest_framework.routers import DefaultRouter
from .views import FileViewSet

router = DefaultRouter()
router.register("files", FileViewSet, basename="file")
urlpatterns = [path("api/", include(router.urls))]
""",
                },
                {
                    "path": "project/views.py",
                    "content": """
from rest_framework.viewsets import ModelViewSet

class FileViewSet(ModelViewSet):
    def get_queryset(self):
        if feature_enabled:
            queryset = (
                File.objects.all()
                if self.action == "destroy"
                else File.objects.filter(owner_id=current_user.id)
            )
        else:
            queryset = File.objects.filter(owner_id=current_user.id)
        return queryset

    def perform_destroy(self, instance):
        return delete_file(instance.path)
""",
                },
            ]
        }
    )

    assert {
        (fact.symbol_name, fact.route_method, fact.route_path)
        for fact in result.facts
        if fact.fact_type == "authorization_gap_candidate"
    } == {("FileViewSet.destroy", "DELETE", "/api/files/{pk}/")}
    assert any(
        fact.fact_type == "service_call"
        and fact.symbol_name == "FileViewSet.get_queryset"
        and fact.payload.get("caller") == "FileViewSet.destroy"
        and fact.payload.get("lifecycle_action_dependent") is True
        for fact in result.facts
    )


def test_map_authorized_code_files_maps_unaliased_drf_viewsets_module_import():
    result = map_authorized_code_files(
        {
            "authorized_code_files": [
                {
                    "path": "project/settings.py",
                    "content": 'ROOT_URLCONF = "project.urls"',
                },
                {
                    "path": "project/urls.py",
                    "content": """
from django.urls import include, path
from rest_framework.routers import DefaultRouter
from .views import FileViewSet

router = DefaultRouter()
router.register("files", FileViewSet, basename="file")
urlpatterns = [path("api/", include(router.urls))]
""",
                },
                {
                    "path": "project/views.py",
                    "content": """
import rest_framework.viewsets

class FileViewSet(rest_framework.viewsets.ModelViewSet):
    def perform_destroy(self, instance):
        return delete_file(instance.path)
""",
                },
            ]
        }
    )

    assert {
        (fact.symbol_name, fact.route_method, fact.route_path)
        for fact in result.facts
        if fact.fact_type == "route_handler"
    } == {("FileViewSet.destroy", "DELETE", "/api/files/{pk}/")}


@pytest.mark.parametrize(
    "following_import",
    (
        "import rest_framework",
        "import rest_framework.authentication",
    ),
)
def test_map_authorized_code_files_keeps_unaliased_drf_viewsets_after_compatible_import(
    following_import,
):
    result = map_authorized_code_files(
        {
            "authorized_code_files": [
                {
                    "path": "project/settings.py",
                    "content": 'ROOT_URLCONF = "project.urls"',
                },
                {
                    "path": "project/urls.py",
                    "content": """
from django.urls import include, path
from rest_framework.routers import DefaultRouter
from .views import FileViewSet

router = DefaultRouter()
router.register("files", FileViewSet, basename="file")
urlpatterns = [path("api/", include(router.urls))]
""",
                },
                {
                    "path": "project/views.py",
                    "content": f"""
import rest_framework.viewsets
{following_import}

class FileViewSet(rest_framework.viewsets.ModelViewSet):
    def perform_destroy(self, instance):
        return delete_file(instance.path)
""",
                },
            ]
        }
    )

    assert {
        (fact.symbol_name, fact.route_method, fact.route_path)
        for fact in result.facts
        if fact.fact_type == "route_handler"
    } == {("FileViewSet.destroy", "DELETE", "/api/files/{pk}/")}


def test_map_authorized_code_files_ignores_viewsets_module_alias_overwritten_by_parent_import():
    result = map_authorized_code_files(
        {
            "authorized_code_files": [
                {
                    "path": "project/settings.py",
                    "content": 'ROOT_URLCONF = "project.urls"',
                },
                {
                    "path": "project/urls.py",
                    "content": """
from django.urls import include, path
from rest_framework.routers import DefaultRouter
from .views import FileViewSet

router = DefaultRouter()
router.register("files", FileViewSet, basename="file")
urlpatterns = [path("api/", include(router.urls))]
""",
                },
                {
                    "path": "project/views.py",
                    "content": """
from rest_framework import viewsets as rest_framework
import rest_framework.authentication

class FileViewSet(rest_framework.ModelViewSet):
    def perform_destroy(self, instance):
        return delete_file(instance.path)
""",
                },
            ]
        }
    )

    assert not any(fact.fact_type == "route_handler" for fact in result.facts)
    assert not any(
        fact.fact_type == "authorization_gap_candidate" for fact in result.facts
    )


@pytest.mark.parametrize(
    "rebinding",
    (
        "rest_framework.viewsets = build_non_drf_module()",
        "rest_framework.viewsets.ModelViewSet = build_non_drf_base()",
        """
if feature_enabled:
    rest_framework.viewsets = build_non_drf_module()
""",
    ),
)
def test_map_authorized_code_files_ignores_unaliased_drf_viewsets_after_attribute_rebinding(
    rebinding,
):
    result = map_authorized_code_files(
        {
            "authorized_code_files": [
                {
                    "path": "project/settings.py",
                    "content": 'ROOT_URLCONF = "project.urls"',
                },
                {
                    "path": "project/urls.py",
                    "content": """
from django.urls import include, path
from rest_framework.routers import DefaultRouter
from .views import FileViewSet

router = DefaultRouter()
router.register("files", FileViewSet, basename="file")
urlpatterns = [path("api/", include(router.urls))]
""",
                },
                {
                    "path": "project/views.py",
                    "content": f"""
import rest_framework.viewsets

{rebinding}

class FileViewSet(rest_framework.viewsets.ModelViewSet):
    def perform_destroy(self, instance):
        return delete_file(instance.path)
""",
                },
            ]
        }
    )

    assert not any(fact.fact_type == "route_handler" for fact in result.facts)
    assert not any(
        fact.fact_type == "authorization_gap_candidate" for fact in result.facts
    )


@pytest.mark.parametrize(
    "view_content",
    (
        """
from rest_framework.viewsets import ModelViewSet

ModelViewSet.serializer_class = FileSerializer

class FileViewSet(ModelViewSet):
    def perform_destroy(self, instance):
        return delete_file(instance.path)
""",
        """
import rest_framework.viewsets

rest_framework.settings.DEFAULT_RENDERER_CLASSES = []

class FileViewSet(rest_framework.viewsets.ModelViewSet):
    def perform_destroy(self, instance):
        return delete_file(instance.path)
""",
    ),
)
def test_map_authorized_code_files_keeps_drf_viewset_aliases_after_unrelated_attribute_writes(
    view_content,
):
    result = map_authorized_code_files(
        {
            "authorized_code_files": [
                {
                    "path": "project/settings.py",
                    "content": 'ROOT_URLCONF = "project.urls"',
                },
                {
                    "path": "project/urls.py",
                    "content": """
from django.urls import include, path
from rest_framework.routers import DefaultRouter
from .views import FileViewSet

router = DefaultRouter()
router.register("files", FileViewSet, basename="file")
urlpatterns = [path("api/", include(router.urls))]
""",
                },
                {"path": "project/views.py", "content": view_content},
            ]
        }
    )

    assert {
        (fact.symbol_name, fact.route_method, fact.route_path)
        for fact in result.facts
        if fact.fact_type == "route_handler"
    } == {("FileViewSet.destroy", "DELETE", "/api/files/{pk}/")}


def test_map_authorized_code_files_maps_static_drf_router_custom_actions():
    result = map_authorized_code_files(
        {
            "authorized_code_files": [
                {
                    "path": "project/settings.py",
                    "content": 'ROOT_URLCONF = "project.urls"',
                },
                {
                    "path": "project/urls.py",
                    "content": """
from django.urls import include, path
from rest_framework.routers import DefaultRouter
from .views import FileViewSet

router = DefaultRouter()
router.register("files", FileViewSet, basename="file")
urlpatterns = [path("api/", include(router.urls))]
""",
                },
                {
                    "path": "project/views.py",
                    "content": """
from rest_framework.decorators import action as api_action
from rest_framework.viewsets import ViewSet

class FileViewSet(ViewSet):
    @api_action(detail=True, methods=("post",), url_path="regenerate-export")
    def regenerate_export(self, request, pk):
        return send_file(pk)

    @api_action(detail=False)
    def health_check(self, request):
        return []
""",
                },
            ]
        }
    )

    routes = {
        (fact.symbol_name, fact.route_method, fact.route_path)
        for fact in result.facts
        if fact.fact_type == "route_handler"
    }
    assert routes == {
        (
            "FileViewSet.regenerate_export",
            "POST",
            "/api/files/{pk}/regenerate-export/",
        ),
        ("FileViewSet.health_check", "GET", "/api/files/health-check/"),
    }
    sink = next(
        fact
        for fact in result.facts
        if fact.fact_type == "sensitive_sink"
        and fact.payload.get("handler") == "FileViewSet.regenerate_export"
    )
    gap = next(
        fact
        for fact in result.facts
        if fact.fact_type == "authorization_gap_candidate"
        and fact.symbol_name == "FileViewSet.regenerate_export"
    )

    assert sink.payload["handler"] == "FileViewSet.regenerate_export"
    assert (gap.route_method, gap.route_path) == (
        "POST",
        "/api/files/{pk}/regenerate-export/",
    )


@pytest.mark.parametrize(
    "view_content",
    (
        """
from rest_framework.decorators import action
from rest_framework.viewsets import ViewSet

action = local_decorator

class FileViewSet(ViewSet):
    @action(detail=True, methods=["post"])
    def export(self, request, pk):
        return send_file(pk)
""",
        """
from rest_framework import decorators
from rest_framework.viewsets import ViewSet

decorators = local_decorator_module()

class FileViewSet(ViewSet):
    @decorators.action(detail=True, methods=["post"])
    def export(self, request, pk):
        return send_file(pk)
""",
        """
import rest_framework.decorators
from rest_framework.viewsets import ViewSet

rest_framework.decorators.action = local_decorator

class FileViewSet(ViewSet):
    @rest_framework.decorators.action(detail=True, methods=["post"])
    def export(self, request, pk):
        return send_file(pk)
""",
    ),
)
def test_map_authorized_code_files_ignores_rebound_drf_action_aliases(view_content):
    result = map_authorized_code_files(
        {
            "authorized_code_files": [
                {
                    "path": "project/settings.py",
                    "content": 'ROOT_URLCONF = "project.urls"',
                },
                {
                    "path": "project/urls.py",
                    "content": """
from django.urls import include, path
from rest_framework.routers import DefaultRouter
from .views import FileViewSet

router = DefaultRouter()
router.register("files", FileViewSet, basename="file")
urlpatterns = [path("api/", include(router.urls))]
""",
                },
                {"path": "project/views.py", "content": view_content},
            ]
        }
    )

    assert not any(fact.fact_type == "route_handler" for fact in result.facts)
    assert not any(
        fact.fact_type == "authorization_gap_candidate" for fact in result.facts
    )


def test_map_authorized_code_files_ignores_decorator_module_alias_overwritten_by_parent_import():
    result = map_authorized_code_files(
        {
            "authorized_code_files": [
                {
                    "path": "project/settings.py",
                    "content": 'ROOT_URLCONF = "project.urls"',
                },
                {
                    "path": "project/urls.py",
                    "content": """
from django.urls import include, path
from rest_framework.routers import DefaultRouter
from .views import FileViewSet

router = DefaultRouter()
router.register("files", FileViewSet, basename="file")
urlpatterns = [path("api/", include(router.urls))]
""",
                },
                {
                    "path": "project/views.py",
                    "content": """
from rest_framework import decorators as rest_framework
from rest_framework.viewsets import ViewSet
import rest_framework.authentication

class FileViewSet(ViewSet):
    @rest_framework.action(detail=True, methods=["post"])
    def export(self, request, pk):
        return send_file(pk)
""",
                },
            ]
        }
    )

    assert not any(fact.fact_type == "route_handler" for fact in result.facts)
    assert not any(
        fact.fact_type == "authorization_gap_candidate" for fact in result.facts
    )


def test_map_authorized_code_files_requires_drf_viewset_base_for_custom_actions():
    result = map_authorized_code_files(
        {
            "authorized_code_files": [
                {
                    "path": "project/settings.py",
                    "content": 'ROOT_URLCONF = "project.urls"',
                },
                {
                    "path": "project/urls.py",
                    "content": """
from django.urls import include, path
from rest_framework.routers import DefaultRouter
from .views import FileViewSet

router = DefaultRouter()
router.register("files", FileViewSet, basename="file")
urlpatterns = [path("api/", include(router.urls))]
""",
                },
                {
                    "path": "project/views.py",
                    "content": """
from rest_framework.decorators import action

class FileViewSet:
    @action(detail=True, methods=["post"])
    def export(self, request, pk):
        return send_file(pk)
""",
                },
            ]
        }
    )

    assert not any(fact.fact_type == "route_handler" for fact in result.facts)
    assert not any(
        fact.fact_type == "authorization_gap_candidate" for fact in result.facts
    )


def test_map_authorized_code_files_ignores_class_local_drf_action_rebinding():
    result = map_authorized_code_files(
        {
            "authorized_code_files": [
                {
                    "path": "project/settings.py",
                    "content": 'ROOT_URLCONF = "project.urls"',
                },
                {
                    "path": "project/urls.py",
                    "content": """
from django.urls import include, path
from rest_framework.routers import DefaultRouter
from .views import FileViewSet

router = DefaultRouter()
router.register("files", FileViewSet, basename="file")
urlpatterns = [path("api/", include(router.urls))]
""",
                },
                {
                    "path": "project/views.py",
                    "content": """
from rest_framework.decorators import action
from rest_framework.viewsets import ViewSet

class FileViewSet(ViewSet):
    action = local_decorator

    @action(detail=True, methods=["post"])
    def export(self, request, pk):
        return send_file(pk)
""",
                },
            ]
        }
    )

    assert not any(fact.fact_type == "route_handler" for fact in result.facts)
    assert not any(
        fact.fact_type == "authorization_gap_candidate" for fact in result.facts
    )


def test_map_authorized_code_files_applies_method_decorator_rebindings_in_order():
    result = map_authorized_code_files(
        {
            "authorized_code_files": [
                {
                    "path": "project/settings.py",
                    "content": 'ROOT_URLCONF = "project.urls"',
                },
                {
                    "path": "project/urls.py",
                    "content": """
from django.urls import include, path
from rest_framework.routers import DefaultRouter
from .views import FileViewSet

router = DefaultRouter()
router.register("files", FileViewSet, basename="file")
urlpatterns = [path("api/", include(router.urls))]
""",
                },
                {
                    "path": "project/views.py",
                    "content": """
from rest_framework.decorators import action
from rest_framework.viewsets import ViewSet

class FileViewSet(ViewSet):
    @decorate(action := local_decorator)
    @action(detail=True, methods=["post"])
    def export(self, request, pk):
        return send_file(pk)
""",
                },
            ]
        }
    )

    assert not any(fact.fact_type == "route_handler" for fact in result.facts)
    assert not any(
        fact.fact_type == "authorization_gap_candidate" for fact in result.facts
    )


@pytest.mark.parametrize(
    "view_content",
    (
        """
from rest_framework.viewsets import ModelViewSet

@decorate(ModelViewSet := build_non_drf_base())
class FileViewSet(ModelViewSet):
    def perform_destroy(self, instance):
        return delete_file(instance.path)
""",
        """
from rest_framework.decorators import action
from rest_framework.viewsets import ViewSet

@decorate(action := local_decorator)
class FileViewSet(ViewSet):
    @action(detail=True, methods=["post"])
    def export(self, request, pk):
        return send_file(pk)
""",
    ),
)
def test_map_authorized_code_files_applies_class_header_rebindings_before_mapping(
    view_content,
):
    result = map_authorized_code_files(
        {
            "authorized_code_files": [
                {
                    "path": "project/settings.py",
                    "content": 'ROOT_URLCONF = "project.urls"',
                },
                {
                    "path": "project/urls.py",
                    "content": """
from django.urls import include, path
from rest_framework.routers import DefaultRouter
from .views import FileViewSet

router = DefaultRouter()
router.register("files", FileViewSet, basename="file")
urlpatterns = [path("api/", include(router.urls))]
""",
                },
                {"path": "project/views.py", "content": view_content},
            ]
        }
    )

    assert not any(fact.fact_type == "route_handler" for fact in result.facts)
    assert not any(
        fact.fact_type == "authorization_gap_candidate" for fact in result.facts
    )


@pytest.mark.parametrize(
    "configuration",
    (
        "rest_framework.viewsets = build_non_drf_module()",
        "rest_framework.viewsets.ModelViewSet = build_non_drf_base()",
        "import rest_framework\n    rest_framework.viewsets.ModelViewSet = build_non_drf_base()",
        "from rest_framework import viewsets\n    viewsets.ModelViewSet = build_non_drf_base()",
        "if feature_enabled:\n        import rest_framework as api\n    else:\n        api = local_holder\n    api.viewsets.ModelViewSet = build_non_drf_base()",
    ),
)
def test_map_authorized_code_files_applies_class_body_viewset_attribute_rebindings(
    configuration,
):
    result = map_authorized_code_files(
        {
            "authorized_code_files": [
                {
                    "path": "project/settings.py",
                    "content": 'ROOT_URLCONF = "project.urls"',
                },
                {
                    "path": "project/urls.py",
                    "content": """
from django.urls import include, path
from rest_framework.routers import DefaultRouter
from .views import FileViewSet

router = DefaultRouter()
router.register("files", FileViewSet, basename="file")
urlpatterns = [path("api/", include(router.urls))]
""",
                },
                {
                    "path": "project/views.py",
                    "content": f"""
import rest_framework.viewsets

class Configure:
    {configuration}

class FileViewSet(rest_framework.viewsets.ModelViewSet):
    def perform_destroy(self, instance):
        return delete_file(instance.path)
""",
                },
            ]
        }
    )

    assert not any(fact.fact_type == "route_handler" for fact in result.facts)
    assert not any(
        fact.fact_type == "authorization_gap_candidate" for fact in result.facts
    )


@pytest.mark.parametrize(
    "configuration",
    (
        "rest_framework.decorators.action = local_decorator",
        "from rest_framework import decorators\n    decorators.action = local_decorator",
    ),
)
def test_map_authorized_code_files_applies_class_body_action_attribute_rebinding(
    configuration,
):
    result = map_authorized_code_files(
        {
            "authorized_code_files": [
                {
                    "path": "project/settings.py",
                    "content": 'ROOT_URLCONF = "project.urls"',
                },
                {
                    "path": "project/urls.py",
                    "content": """
from django.urls import include, path
from rest_framework.routers import DefaultRouter
from .views import FileViewSet

router = DefaultRouter()
router.register("files", FileViewSet, basename="file")
urlpatterns = [path("api/", include(router.urls))]
""",
                },
                {
                    "path": "project/views.py",
                    "content": f"""
import rest_framework.decorators
from rest_framework.viewsets import ViewSet

class Configure:
    {configuration}

class FileViewSet(ViewSet):
    @rest_framework.decorators.action(detail=True, methods=["post"])
    def export(self, request, pk):
        return send_file(pk)
""",
                },
            ]
        }
    )

    assert not any(fact.fact_type == "route_handler" for fact in result.facts)
    assert not any(
        fact.fact_type == "authorization_gap_candidate" for fact in result.facts
    )


@pytest.mark.parametrize(
    "configuration",
    (
        "rest_framework = local_holder\n    rest_framework.viewsets = build_non_drf_module()",
        "for feature in features:\n        import rest_framework as api\n    else:\n        api = local_holder\n    api.viewsets.ModelViewSet = build_non_drf_base()",
    ),
)
def test_map_authorized_code_files_keeps_outer_viewset_alias_after_class_local_shadowing(
    configuration,
):
    result = map_authorized_code_files(
        {
            "authorized_code_files": [
                {
                    "path": "project/settings.py",
                    "content": 'ROOT_URLCONF = "project.urls"',
                },
                {
                    "path": "project/urls.py",
                    "content": """
from django.urls import include, path
from rest_framework.routers import DefaultRouter
from .views import FileViewSet

router = DefaultRouter()
router.register("files", FileViewSet, basename="file")
urlpatterns = [path("api/", include(router.urls))]
""",
                },
                {
                    "path": "project/views.py",
                    "content": f"""
import rest_framework.viewsets

class Configure:
    {configuration}

class FileViewSet(rest_framework.viewsets.ModelViewSet):
    def perform_destroy(self, instance):
        return delete_file(instance.path)
""",
                },
            ]
        }
    )

    assert {
        (fact.symbol_name, fact.route_method, fact.route_path)
        for fact in result.facts
        if fact.fact_type == "route_handler"
    } == {("FileViewSet.destroy", "DELETE", "/api/files/{pk}/")}


def test_map_authorized_code_files_keeps_dynamic_drf_router_custom_action_unresolved():
    result = map_authorized_code_files(
        {
            "authorized_code_files": [
                {
                    "path": "project/settings.py",
                    "content": 'ROOT_URLCONF = "project.urls"',
                },
                {
                    "path": "project/urls.py",
                    "content": """
from django.urls import include, path
from rest_framework.routers import DefaultRouter
from .views import FileViewSet

router = DefaultRouter()
router.register("files", FileViewSet, basename="file")
urlpatterns = [path("api/", include(router.urls))]
""",
                },
                {
                    "path": "project/views.py",
                    "content": """
from rest_framework.decorators import action
from rest_framework.viewsets import ViewSet

class FileViewSet(ViewSet):
    @action(detail=True, methods=["post"], url_path=build_action_path())
    def regenerate_export(self, request, pk):
        return send_file(pk)
""",
                },
            ]
        }
    )

    assert not any(fact.fact_type == "route_handler" for fact in result.facts)
    assert not any(
        fact.fact_type == "authorization_gap_candidate" for fact in result.facts
    )


def test_map_authorized_code_files_maps_unaliased_drf_action_module_and_standard_methods():
    result = map_authorized_code_files(
        {
            "authorized_code_files": [
                {
                    "path": "project/settings.py",
                    "content": 'ROOT_URLCONF = "project.urls"',
                },
                {
                    "path": "project/urls.py",
                    "content": """
from django.urls import include, path
from rest_framework.routers import DefaultRouter
from .views import FileViewSet

router = DefaultRouter()
router.register("files", FileViewSet, basename="file")
urlpatterns = [path("api/", include(router.urls))]
""",
                },
                {
                    "path": "project/views.py",
                    "content": """
import rest_framework.decorators
from rest_framework.viewsets import ViewSet

class FileViewSet(ViewSet):
    @rest_framework.decorators.action(
        detail=True,
        methods=["head", "options", "trace"],
    )
    def metadata(self, request, pk):
        return []
""",
                },
            ]
        }
    )

    routes = {
        (fact.symbol_name, fact.route_method, fact.route_path)
        for fact in result.facts
        if fact.fact_type == "route_handler"
    }
    assert routes == {
        ("FileViewSet.metadata", "HEAD", "/api/files/{pk}/metadata/"),
        ("FileViewSet.metadata", "OPTIONS", "/api/files/{pk}/metadata/"),
        ("FileViewSet.metadata", "TRACE", "/api/files/{pk}/metadata/"),
    }


def test_map_authorized_code_files_maps_direct_static_drf_router_urls():
    result = map_authorized_code_files(
        {
            "authorized_code_files": [
                {
                    "path": "project/settings.py",
                    "content": 'ROOT_URLCONF = "project.urls"',
                },
                {
                    "path": "project/urls.py",
                    "content": """
from rest_framework.routers import DefaultRouter
from .views import ProjectViewSet

router = DefaultRouter()
router.register("projects", ProjectViewSet, basename="project")
urlpatterns = router.urls
""",
                },
                {
                    "path": "project/views.py",
                    "content": """
from rest_framework.viewsets import ViewSet

class ProjectViewSet(ViewSet):
    def list(self, request):
        return send_file("manifest")
""",
                },
            ]
        }
    )

    route = next(fact for fact in result.facts if fact.fact_type == "route_handler")
    sink = next(fact for fact in result.facts if fact.fact_type == "sensitive_sink")

    assert (route.symbol_name, route.route_method, route.route_path) == (
        "ProjectViewSet.list",
        "GET",
        "/projects/",
    )
    assert sink.payload["handler"] == "ProjectViewSet.list"


def test_map_authorized_code_files_maps_static_drf_router_lookup_field():
    result = map_authorized_code_files(
        {
            "authorized_code_files": [
                {
                    "path": "project/settings.py",
                    "content": 'ROOT_URLCONF = "project.urls"',
                },
                {
                    "path": "project/urls.py",
                    "content": """
from django.urls import include, path
from rest_framework.routers import DefaultRouter
from .views import ProjectViewSet

router = DefaultRouter()
router.register("projects", ProjectViewSet, basename="project")
urlpatterns = [path("api/", include(router.urls))]
""",
                },
                {
                    "path": "project/views.py",
                    "content": """
from rest_framework.viewsets import ViewSet

class ProjectViewSet(ViewSet):
    lookup_field = "slug"

    def retrieve(self, request, slug):
        project = Project.objects.get(slug=slug)
        return send_file(project.path)
""",
                },
            ]
        }
    )

    route = next(fact for fact in result.facts if fact.fact_type == "route_handler")
    assert (route.symbol_name, route.route_method, route.route_path) == (
        "ProjectViewSet.retrieve",
        "GET",
        "/api/projects/{slug}/",
    )


def test_map_authorized_code_files_keeps_dynamic_drf_lookup_detail_unresolved():
    result = map_authorized_code_files(
        {
            "authorized_code_files": [
                {
                    "path": "project/settings.py",
                    "content": 'ROOT_URLCONF = "project.urls"',
                },
                {
                    "path": "project/urls.py",
                    "content": """
from django.urls import include, path
from rest_framework.routers import DefaultRouter
from .views import ProjectViewSet

router = DefaultRouter()
router.register("projects", ProjectViewSet, basename="project")
urlpatterns = [path("api/", include(router.urls))]
""",
                },
                {
                    "path": "project/views.py",
                    "content": """
from rest_framework.viewsets import ViewSet

class ProjectViewSet(ViewSet):
    lookup_field = build_lookup_field()

    def list(self, request):
        return []

    def retrieve(self, request, value):
        return send_file(value)
""",
                },
            ]
        }
    )

    routes = {
        (fact.symbol_name, fact.route_method, fact.route_path)
        for fact in result.facts
        if fact.fact_type == "route_handler"
    }
    assert routes == {("ProjectViewSet.list", "GET", "/api/projects/")}
    assert not any(
        fact.fact_type == "authorization_gap_candidate" for fact in result.facts
    )


def test_map_authorized_code_files_keeps_dynamic_drf_router_registration_unresolved():
    result = map_authorized_code_files(
        {
            "authorized_code_files": [
                {
                    "path": "project/settings.py",
                    "content": 'ROOT_URLCONF = "project.urls"',
                },
                {
                    "path": "project/urls.py",
                    "content": """
from django.urls import include, path
from rest_framework.routers import DefaultRouter
from .views import ProjectViewSet

router = DefaultRouter()
router.register(load_prefix(), ProjectViewSet, basename="project")
urlpatterns = [
    path("api/", include(router.urls)),
]
""",
                },
                {
                    "path": "project/views.py",
                    "content": """
from rest_framework.viewsets import ViewSet

class ProjectViewSet(ViewSet):
    def list(self, request):
        return send_file("manifest")
""",
                },
            ]
        }
    )

    assert not any(fact.fact_type == "route_handler" for fact in result.facts)
    assert not any(
        fact.fact_type == "authorization_gap_candidate" for fact in result.facts
    )


def test_map_authorized_code_files_keeps_custom_drf_router_trailing_slash_unresolved():
    result = map_authorized_code_files(
        {
            "authorized_code_files": [
                {
                    "path": "project/settings.py",
                    "content": 'ROOT_URLCONF = "project.urls"',
                },
                {
                    "path": "project/urls.py",
                    "content": """
from django.urls import include, path
from rest_framework.routers import DefaultRouter
from .views import ProjectViewSet

router = DefaultRouter()
router.trailing_slash = ""
router.register("projects", ProjectViewSet, basename="project")
urlpatterns = [path("api/", include(router.urls))]
""",
                },
                {
                    "path": "project/views.py",
                    "content": """
from rest_framework.viewsets import ViewSet

class ProjectViewSet(ViewSet):
    def list(self, request):
        return send_file("manifest")
""",
                },
            ]
        }
    )

    assert not any(fact.fact_type == "route_handler" for fact in result.facts)
    assert not any(
        fact.fact_type == "authorization_gap_candidate" for fact in result.facts
    )


def test_map_authorized_code_files_maps_imported_static_drf_router_instance():
    result = map_authorized_code_files(
        {
            "authorized_code_files": [
                {
                    "path": "project/settings.py",
                    "content": 'ROOT_URLCONF = "project.urls"',
                },
                {
                    "path": "project/urls.py",
                    "content": """
from django.urls import include, path

urlpatterns = [path("api/", include("api.urls"))]
""",
                },
                {
                    "path": "api/urls.py",
                    "content": """
from django.urls import include, path
from .router import router as api_router

urlpatterns = [path("", include(api_router.urls))]
""",
                },
                {
                    "path": "api/router.py",
                    "content": """
from rest_framework.routers import DefaultRouter
from .views import FileViewSet

router = DefaultRouter()
router.register("files", FileViewSet, basename="file")
""",
                },
                {
                    "path": "api/views.py",
                    "content": """
from rest_framework.viewsets import ViewSet

class FileViewSet(ViewSet):
    def retrieve(self, request, pk):
        return send_file(pk)
""",
                },
            ]
        }
    )

    route = next(fact for fact in result.facts if fact.fact_type == "route_handler")
    gap = next(
        fact
        for fact in result.facts
        if fact.fact_type == "authorization_gap_candidate"
    )

    assert (route.symbol_name, route.route_method, route.route_path) == (
        "FileViewSet.retrieve",
        "GET",
        "/api/files/{pk}/",
    )
    assert gap.symbol_name == "FileViewSet.retrieve"


def test_map_authorized_code_files_maps_drf_router_through_imported_module_attribute():
    result = map_authorized_code_files(
        {
            "authorized_code_files": [
                {
                    "path": "project/settings.py",
                    "content": 'ROOT_URLCONF = "project.urls"',
                },
                {
                    "path": "project/urls.py",
                    "content": """
from django.urls import include, path
from . import router

urlpatterns = [path("api/", include(router.router.urls))]
""",
                },
                {
                    "path": "project/router.py",
                    "content": """
from rest_framework.routers import DefaultRouter
from .views import FileViewSet

router = DefaultRouter()
router.register("files", FileViewSet, basename="file")
""",
                },
                {
                    "path": "project/views.py",
                    "content": """
from rest_framework.viewsets import ViewSet

class FileViewSet(ViewSet):
    def retrieve(self, request, pk):
        return send_file(pk)
""",
                },
            ]
        }
    )

    route = next(fact for fact in result.facts if fact.fact_type == "route_handler")
    gap = next(
        fact
        for fact in result.facts
        if fact.fact_type == "authorization_gap_candidate"
    )

    assert (route.symbol_name, route.route_method, route.route_path) == (
        "FileViewSet.retrieve",
        "GET",
        "/api/files/{pk}/",
    )
    assert gap.symbol_name == "FileViewSet.retrieve"


def test_map_authorized_code_files_keeps_shadowed_drf_router_module_unresolved():
    result = map_authorized_code_files(
        {
            "authorized_code_files": [
                {
                    "path": "project/settings.py",
                    "content": 'ROOT_URLCONF = "project.urls"',
                },
                {
                    "path": "project/urls.py",
                    "content": """
from django.urls import include, path
from . import router

router = build_router()
urlpatterns = [path("api/", include(router.router.urls))]
""",
                },
                {
                    "path": "project/router.py",
                    "content": """
from rest_framework.routers import DefaultRouter
from .views import FileViewSet

router = DefaultRouter()
router.register("files", FileViewSet, basename="file")
""",
                },
                {
                    "path": "project/views.py",
                    "content": """
from rest_framework.viewsets import ViewSet

class FileViewSet(ViewSet):
    def retrieve(self, request, pk):
        return send_file(pk)
""",
                },
            ]
        }
    )

    assert not any(fact.fact_type == "route_handler" for fact in result.facts)
    assert not any(
        fact.fact_type == "authorization_gap_candidate" for fact in result.facts
    )


@pytest.mark.parametrize(
    ("mutation", "expected_handlers"),
    (
        ("router.router = build_router()", set()),
        ('router.router.trailing_slash = ""', set()),
        (
            'router.router.register("exports", ExportViewSet, basename="export")',
            {
                ("FileViewSet.list", "GET", "/api/files/"),
                ("ExportViewSet.list", "GET", "/api/exports/"),
            },
        ),
    ),
)
def test_map_authorized_code_files_tracks_drf_router_module_attribute_lifecycle(
    mutation,
    expected_handlers,
):
    result = map_authorized_code_files(
        {
            "authorized_code_files": [
                {
                    "path": "project/settings.py",
                    "content": 'ROOT_URLCONF = "project.urls"',
                },
                {
                    "path": "project/urls.py",
                    "content": f"""
from django.urls import include, path
from . import router
from .views import ExportViewSet

{mutation}
urlpatterns = [path("api/", include(router.router.urls))]
""",
                },
                {
                    "path": "project/router.py",
                    "content": """
from rest_framework.routers import DefaultRouter
from .views import FileViewSet

router = DefaultRouter()
router.register("files", FileViewSet, basename="file")
""",
                },
                {
                    "path": "project/views.py",
                    "content": """
from rest_framework.viewsets import ViewSet

class FileViewSet(ViewSet):
    def list(self, request):
        return send_file("manifest")

class ExportViewSet(ViewSet):
    def list(self, request):
        return send_file("export")
""",
                },
            ]
        }
    )

    handlers = {
        (fact.symbol_name, fact.route_method, fact.route_path)
        for fact in result.facts
        if fact.fact_type == "route_handler"
    }
    assert handlers == expected_handlers


@pytest.mark.parametrize(
    ("replacement_import", "expected_handlers"),
    (
        ("from . import second as router", set()),
        ("import project.second as router", set()),
        (
            "import project.first as router",
            {("FileViewSet.list", "GET", "/api/files/")},
        ),
    ),
)
def test_map_authorized_code_files_clears_rebound_drf_router_module_state(
    replacement_import,
    expected_handlers,
):
    result = map_authorized_code_files(
        {
            "authorized_code_files": [
                {
                    "path": "project/settings.py",
                    "content": 'ROOT_URLCONF = "project.urls"',
                },
                {
                    "path": "project/urls.py",
                    "content": f"""
from django.urls import include, path
from . import first as router
{replacement_import}

urlpatterns = [path("api/", include(router.router.urls))]
""",
                },
                {
                    "path": "project/first.py",
                    "content": """
from rest_framework.routers import DefaultRouter
from .views import FileViewSet

router = DefaultRouter()
router.register("files", FileViewSet, basename="file")
""",
                },
                {"path": "project/second.py", "content": "router = build_router()\n"},
                {
                    "path": "project/views.py",
                    "content": """
from rest_framework.viewsets import ViewSet

class FileViewSet(ViewSet):
    def list(self, request):
        return send_file("manifest")
""",
                },
            ]
        }
    )

    handlers = {
        (fact.symbol_name, fact.route_method, fact.route_path)
        for fact in result.facts
        if fact.fact_type == "route_handler"
    }
    assert handlers == expected_handlers
    if not expected_handlers:
        assert not any(
            fact.fact_type == "authorization_gap_candidate" for fact in result.facts
        )


def test_map_authorized_code_files_invalidates_shared_drf_router_module_aliases():
    result = map_authorized_code_files(
        {
            "authorized_code_files": [
                {
                    "path": "project/settings.py",
                    "content": 'ROOT_URLCONF = "project.urls"',
                },
                {
                    "path": "project/urls.py",
                    "content": """
from django.urls import include, path
from . import router as primary
from . import router as mirror

primary.router = build_router()
urlpatterns = [path("api/", include(mirror.router.urls))]
""",
                },
                {
                    "path": "project/router.py",
                    "content": """
from rest_framework.routers import DefaultRouter
from .views import FileViewSet

router = DefaultRouter()
router.register("files", FileViewSet, basename="file")
""",
                },
                {
                    "path": "project/views.py",
                    "content": """
from rest_framework.viewsets import ViewSet

class FileViewSet(ViewSet):
    def list(self, request):
        return send_file("manifest")
""",
                },
            ]
        }
    )

    assert not any(fact.fact_type == "route_handler" for fact in result.facts)
    assert not any(
        fact.fact_type == "authorization_gap_candidate" for fact in result.facts
    )


def test_map_authorized_code_files_tracks_static_drf_router_module_rebuild_across_aliases():
    result = map_authorized_code_files(
        {
            "authorized_code_files": [
                {
                    "path": "project/settings.py",
                    "content": 'ROOT_URLCONF = "project.urls"',
                },
                {
                    "path": "project/urls.py",
                    "content": """
from django.urls import include, path
from rest_framework.routers import DefaultRouter
from . import router as primary
from . import router as mirror
from .views import ExportViewSet

primary.router = DefaultRouter()
mirror.router.register("exports", ExportViewSet, basename="export")
urlpatterns = [path("api/", include(primary.router.urls))]
""",
                },
                {
                    "path": "project/router.py",
                    "content": """
from rest_framework.routers import DefaultRouter
from .views import FileViewSet

router = DefaultRouter()
router.register("files", FileViewSet, basename="file")
""",
                },
                {
                    "path": "project/views.py",
                    "content": """
from rest_framework.viewsets import ViewSet

class FileViewSet(ViewSet):
    def list(self, request):
        return send_file("manifest")

class ExportViewSet(ViewSet):
    def list(self, request):
        return send_file("export")
""",
                },
            ]
        }
    )

    handlers = {
        (fact.symbol_name, fact.route_method, fact.route_path)
        for fact in result.facts
        if fact.fact_type == "route_handler"
    }
    assert handlers == {("ExportViewSet.list", "GET", "/api/exports/")}


def test_map_authorized_code_files_reimports_static_drf_router_module_after_rebuild():
    result = map_authorized_code_files(
        {
            "authorized_code_files": [
                {
                    "path": "project/settings.py",
                    "content": 'ROOT_URLCONF = "project.urls"',
                },
                {
                    "path": "project/urls.py",
                    "content": """
from django.urls import include, path
from rest_framework.routers import DefaultRouter
from . import router as primary

primary.router = DefaultRouter()
from . import router as mirror

urlpatterns = [path("api/", include(mirror.router.urls))]
""",
                },
                {
                    "path": "project/router.py",
                    "content": """
from rest_framework.routers import DefaultRouter
from .views import FileViewSet

router = DefaultRouter()
router.register("files", FileViewSet, basename="file")
""",
                },
                {
                    "path": "project/views.py",
                    "content": """
from rest_framework.viewsets import ViewSet

class FileViewSet(ViewSet):
    def list(self, request):
        return send_file("manifest")
""",
                },
            ]
        }
    )

    assert not any(fact.fact_type == "route_handler" for fact in result.facts)
    assert not any(
        fact.fact_type == "authorization_gap_candidate" for fact in result.facts
    )


def test_map_authorized_code_files_keeps_direct_drf_router_reference_after_module_rebuild():
    result = map_authorized_code_files(
        {
            "authorized_code_files": [
                {
                    "path": "project/settings.py",
                    "content": 'ROOT_URLCONF = "project.urls"',
                },
                {
                    "path": "project/urls.py",
                    "content": """
from django.urls import include, path
from rest_framework.routers import DefaultRouter
from . import router as primary
from .router import router as direct_router

primary.router = DefaultRouter()
urlpatterns = [path("api/", include(direct_router.urls))]
""",
                },
                {
                    "path": "project/router.py",
                    "content": """
from rest_framework.routers import DefaultRouter
from .views import FileViewSet

router = DefaultRouter()
router.register("files", FileViewSet, basename="file")
""",
                },
                {
                    "path": "project/views.py",
                    "content": """
from rest_framework.viewsets import ViewSet

class FileViewSet(ViewSet):
    def list(self, request):
        return send_file("manifest")
""",
                },
            ]
        }
    )

    route = next(fact for fact in result.facts if fact.fact_type == "route_handler")
    assert (route.symbol_name, route.route_method, route.route_path) == (
        "FileViewSet.list",
        "GET",
        "/api/files/",
    )


def test_map_authorized_code_files_reloads_static_drf_router_module_in_child_urlconf():
    result = map_authorized_code_files(
        {
            "authorized_code_files": [
                {
                    "path": "project/settings.py",
                    "content": 'ROOT_URLCONF = "project.urls"',
                },
                {
                    "path": "project/urls.py",
                    "content": """
from django.urls import include, path
from rest_framework.routers import DefaultRouter
from . import router

router.router = DefaultRouter()
urlpatterns = [path("api/", include("project.child_urls"))]
""",
                },
                {
                    "path": "project/child_urls.py",
                    "content": """
from django.urls import include, path
from . import router

urlpatterns = [path("", include(router.router.urls))]
""",
                },
                {
                    "path": "project/router.py",
                    "content": """
from rest_framework.routers import DefaultRouter
from .views import FileViewSet

router = DefaultRouter()
router.register("files", FileViewSet, basename="file")
""",
                },
                {
                    "path": "project/views.py",
                    "content": """
from rest_framework.viewsets import ViewSet

class FileViewSet(ViewSet):
    def list(self, request):
        return send_file("manifest")
""",
                },
            ]
        }
    )

    assert not any(fact.fact_type == "route_handler" for fact in result.facts)
    assert not any(
        fact.fact_type == "authorization_gap_candidate" for fact in result.facts
    )


def test_map_authorized_code_files_invalidates_drf_router_module_across_urlconfs():
    result = map_authorized_code_files(
        {
            "authorized_code_files": [
                {
                    "path": "project/settings.py",
                    "content": 'ROOT_URLCONF = "project.urls"',
                },
                {
                    "path": "project/urls.py",
                    "content": """
from django.urls import include, path
from . import router

router.router = build_router()
urlpatterns = [path("api/", include("project.child_urls"))]
""",
                },
                {
                    "path": "project/child_urls.py",
                    "content": """
from django.urls import include, path
from . import router

urlpatterns = [path("", include(router.router.urls))]
""",
                },
                {
                    "path": "project/router.py",
                    "content": """
from rest_framework.routers import DefaultRouter
from .views import FileViewSet

router = DefaultRouter()
router.register("files", FileViewSet, basename="file")
""",
                },
                {
                    "path": "project/views.py",
                    "content": """
from rest_framework.viewsets import ViewSet

class FileViewSet(ViewSet):
    def list(self, request):
        return send_file("manifest")
""",
                },
            ]
        }
    )

    assert not any(fact.fact_type == "route_handler" for fact in result.facts)
    assert not any(
        fact.fact_type == "authorization_gap_candidate" for fact in result.facts
    )


def test_map_authorized_code_files_invalidates_nested_drf_router_module_aliases():
    result = map_authorized_code_files(
        {
            "authorized_code_files": [
                {
                    "path": "project/settings.py",
                    "content": 'ROOT_URLCONF = "project.urls"',
                },
                {
                    "path": "project/urls.py",
                    "content": """
from django.urls import include, path
from . import outer as primary
from . import outer as mirror

primary.inner = build_router_module()
urlpatterns = [path("api/", include(mirror.inner.router.urls))]
""",
                },
                {
                    "path": "project/outer.py",
                    "content": "from . import inner\n",
                },
                {
                    "path": "project/inner.py",
                    "content": """
from rest_framework.routers import DefaultRouter
from .views import FileViewSet

router = DefaultRouter()
router.register("files", FileViewSet, basename="file")
""",
                },
                {
                    "path": "project/views.py",
                    "content": """
from rest_framework.viewsets import ViewSet

class FileViewSet(ViewSet):
    def list(self, request):
        return send_file("manifest")
""",
                },
            ]
        }
    )

    assert not any(fact.fact_type == "route_handler" for fact in result.facts)
    assert not any(
        fact.fact_type == "authorization_gap_candidate" for fact in result.facts
    )


def test_map_authorized_code_files_keeps_nested_drf_router_rebuild_conservative():
    result = map_authorized_code_files(
        {
            "authorized_code_files": [
                {
                    "path": "project/settings.py",
                    "content": 'ROOT_URLCONF = "project.urls"',
                },
                {
                    "path": "project/urls.py",
                    "content": """
from django.urls import include, path
from rest_framework.routers import DefaultRouter
from . import outer as primary
from . import inner as mirror

primary.inner.router = DefaultRouter()
urlpatterns = [path("api/", include(mirror.router.urls))]
""",
                },
                {
                    "path": "project/outer.py",
                    "content": "from . import inner\n",
                },
                {
                    "path": "project/inner.py",
                    "content": """
from rest_framework.routers import DefaultRouter
from .views import FileViewSet

router = DefaultRouter()
router.register("files", FileViewSet, basename="file")
""",
                },
                {
                    "path": "project/views.py",
                    "content": """
from rest_framework.viewsets import ViewSet

class FileViewSet(ViewSet):
    def list(self, request):
        return send_file("manifest")
""",
                },
            ]
        }
    )

    assert not any(fact.fact_type == "route_handler" for fact in result.facts)
    assert not any(
        fact.fact_type == "authorization_gap_candidate" for fact in result.facts
    )


def test_map_authorized_code_files_keeps_nested_drf_router_rebuild_conservative_in_child_urlconf():
    result = map_authorized_code_files(
        {
            "authorized_code_files": [
                {
                    "path": "project/settings.py",
                    "content": 'ROOT_URLCONF = "project.urls"',
                },
                {
                    "path": "project/urls.py",
                    "content": """
from django.urls import include, path
from rest_framework.routers import DefaultRouter
from . import outer as primary

primary.inner.router = DefaultRouter()
urlpatterns = [path("api/", include("project.child_urls"))]
""",
                },
                {
                    "path": "project/child_urls.py",
                    "content": """
from django.urls import include, path
from .inner import router

urlpatterns = [path("", include(router.urls))]
""",
                },
                {
                    "path": "project/outer.py",
                    "content": "from . import inner\n",
                },
                {
                    "path": "project/inner.py",
                    "content": """
from rest_framework.routers import DefaultRouter
from .views import FileViewSet

router = DefaultRouter()
router.register("files", FileViewSet, basename="file")
""",
                },
                {
                    "path": "project/views.py",
                    "content": """
from rest_framework.viewsets import ViewSet

class FileViewSet(ViewSet):
    def list(self, request):
        return send_file("manifest")
""",
                },
            ]
        }
    )

    assert not any(fact.fact_type == "route_handler" for fact in result.facts)
    assert not any(
        fact.fact_type == "authorization_gap_candidate" for fact in result.facts
    )


@pytest.mark.parametrize(
    ("mutation", "expected_handlers"),
    (
        ("api_router = build_router()", set()),
        ("api_router.trailing_slash = \"\"", set()),
        (
            'api_router.register("exports", ExportViewSet, basename="export")',
            {
                ("FileViewSet.list", "GET", "/api/files/"),
                ("ExportViewSet.list", "GET", "/api/exports/"),
            },
        ),
    ),
)
def test_map_authorized_code_files_tracks_imported_drf_router_alias_lifecycle(
    mutation,
    expected_handlers,
):
    result = map_authorized_code_files(
        {
            "authorized_code_files": [
                {
                    "path": "project/settings.py",
                    "content": 'ROOT_URLCONF = "project.urls"',
                },
                {
                    "path": "project/urls.py",
                    "content": """
from django.urls import include, path

urlpatterns = [path("api/", include("api.urls"))]
""",
                },
                {
                    "path": "api/urls.py",
                    "content": f"""
from django.urls import include, path
from .router import router as api_router
from .views import ExportViewSet

{mutation}
urlpatterns = [path("", include(api_router.urls))]
""",
                },
                {
                    "path": "api/router.py",
                    "content": """
from rest_framework.routers import DefaultRouter
from .views import FileViewSet

router = DefaultRouter()
router.register("files", FileViewSet, basename="file")
""",
                },
                {
                    "path": "api/views.py",
                    "content": """
from rest_framework.viewsets import ViewSet

class FileViewSet(ViewSet):
    def list(self, request):
        return send_file("manifest")

class ExportViewSet(ViewSet):
    def list(self, request):
        return send_file("export")
""",
                },
            ]
        }
    )

    handlers = {
        (fact.symbol_name, fact.route_method, fact.route_path)
        for fact in result.facts
        if fact.fact_type == "route_handler"
    }
    assert handlers == expected_handlers


@pytest.mark.parametrize(
    ("router_module", "expected_handlers"),
    (
        (
            """
from .base import router
""",
            {("BaseViewSet.list", "GET", "/api/base/")},
        ),
        (
            """
from .base import router
from .views import ExportViewSet

router.register("exports", ExportViewSet, basename="export")
""",
            {
                ("BaseViewSet.list", "GET", "/api/base/"),
                ("ExportViewSet.list", "GET", "/api/exports/"),
            },
        ),
    ),
)
def test_map_authorized_code_files_maps_reexported_drf_router_instance(
    router_module,
    expected_handlers,
):
    result = map_authorized_code_files(
        {
            "authorized_code_files": [
                {
                    "path": "project/settings.py",
                    "content": 'ROOT_URLCONF = "project.urls"',
                },
                {
                    "path": "project/urls.py",
                    "content": """
from django.urls import include, path

urlpatterns = [path("api/", include("api.urls"))]
""",
                },
                {
                    "path": "api/urls.py",
                    "content": """
from django.urls import include, path
from .router import router

urlpatterns = [path("", include(router.urls))]
""",
                },
                {"path": "api/router.py", "content": router_module},
                {
                    "path": "api/base.py",
                    "content": """
from rest_framework.routers import DefaultRouter
from .views import BaseViewSet

router = DefaultRouter()
router.register("base", BaseViewSet, basename="base")
""",
                },
                {
                    "path": "api/views.py",
                    "content": """
from rest_framework.viewsets import ViewSet

class BaseViewSet(ViewSet):
    def list(self, request):
        return send_file("base")

class ExportViewSet(ViewSet):
    def list(self, request):
        return send_file("export")
""",
                },
            ]
        }
    )

    handlers = {
        (fact.symbol_name, fact.route_method, fact.route_path)
        for fact in result.facts
        if fact.fact_type == "route_handler"
    }
    assert handlers == expected_handlers


def test_map_authorized_code_files_keeps_cyclic_drf_router_reexports_unresolved():
    result = map_authorized_code_files(
        {
            "authorized_code_files": [
                {
                    "path": "project/settings.py",
                    "content": 'ROOT_URLCONF = "project.urls"',
                },
                {
                    "path": "project/urls.py",
                    "content": """
from django.urls import include, path

urlpatterns = [path("api/", include("api.urls"))]
""",
                },
                {
                    "path": "api/urls.py",
                    "content": """
from django.urls import include, path
from .router import router

urlpatterns = [path("", include(router.urls))]
""",
                },
                {
                    "path": "api/router.py",
                    "content": "from .base import router\n",
                },
                {
                    "path": "api/base.py",
                    "content": "from .router import router\n",
                },
            ]
        }
    )

    assert not any(fact.fact_type == "route_handler" for fact in result.facts)


@pytest.mark.parametrize(
    ("mutation", "expected_handlers"),
    (
        (
            'primary_router.register("exports", ExportViewSet, basename="export")',
            {
                ("BaseViewSet.list", "GET", "/api/mirror/base/"),
                ("ExportViewSet.list", "GET", "/api/mirror/exports/"),
            },
        ),
        ('primary_router.trailing_slash = ""', set()),
    ),
)
def test_map_authorized_code_files_shares_imported_drf_router_alias_state(
    mutation,
    expected_handlers,
):
    result = map_authorized_code_files(
        {
            "authorized_code_files": [
                {
                    "path": "project/settings.py",
                    "content": 'ROOT_URLCONF = "project.urls"',
                },
                {
                    "path": "project/urls.py",
                    "content": """
from django.urls import include, path

urlpatterns = [path("api/", include("api.urls"))]
""",
                },
                {
                    "path": "api/urls.py",
                    "content": f"""
from django.urls import include, path
from .base import router as primary_router
from .base import router as mirror_router
from .views import ExportViewSet

{mutation}
urlpatterns = [path("mirror/", include(mirror_router.urls))]
""",
                },
                {
                    "path": "api/base.py",
                    "content": """
from rest_framework.routers import DefaultRouter
from .views import BaseViewSet

router = DefaultRouter()
router.register("base", BaseViewSet, basename="base")
""",
                },
                {
                    "path": "api/views.py",
                    "content": """
from rest_framework.viewsets import ViewSet

class BaseViewSet(ViewSet):
    def list(self, request):
        return send_file("base")

class ExportViewSet(ViewSet):
    def list(self, request):
        return send_file("export")
""",
                },
            ]
        }
    )

    handlers = {
        (fact.symbol_name, fact.route_method, fact.route_path)
        for fact in result.facts
        if fact.fact_type == "route_handler"
    }
    assert handlers == expected_handlers


@pytest.mark.parametrize(
    "mutation",
    (
        'router.register("phantom", PhantomViewSet, basename="phantom")',
        'router.trailing_slash = ""',
    ),
)
def test_map_authorized_code_files_ignores_unreachable_drf_router_mutation(mutation):
    result = map_authorized_code_files(
        {
            "authorized_code_files": [
                {
                    "path": "project/settings.py",
                    "content": 'ROOT_URLCONF = "project.urls"',
                },
                {
                    "path": "project/urls.py",
                    "content": """
from django.urls import include, path

urlpatterns = [path("api/", include("api.urls"))]
""",
                },
                {
                    "path": "api/urls.py",
                    "content": """
from django.urls import include, path
from .router import router

urlpatterns = [path("", include(router.urls))]
""",
                },
                {
                    "path": "api/router.py",
                    "content": """
from rest_framework.routers import DefaultRouter
from .views import BaseViewSet

router = DefaultRouter()
router.register("base", BaseViewSet, basename="base")
""",
                },
                {
                    "path": "api/unused.py",
                    "content": f"""
from .router import router
from .views import PhantomViewSet

{mutation}
""",
                },
                {
                    "path": "api/views.py",
                    "content": """
from rest_framework.viewsets import ViewSet

class BaseViewSet(ViewSet):
    def list(self, request):
        return send_file("base")

class PhantomViewSet(ViewSet):
    def list(self, request):
        return send_file("phantom")
""",
                },
            ]
        }
    )

    handlers = {
        (fact.symbol_name, fact.route_method, fact.route_path)
        for fact in result.facts
        if fact.fact_type == "route_handler"
    }
    assert handlers == {("BaseViewSet.list", "GET", "/api/base/")}


@pytest.mark.parametrize(
    "root_urlconf",
    (
        """
urlpatterns = [path("stale/", include("api.unused_urls"))]
urlpatterns = [path("api/", include("api.urls"))]
""",
        """
def build_unused_patterns():
    return [path("stale/", include("api.unused_urls"))]

urlpatterns = [path("api/", include("api.urls"))]
""",
    ),
)
def test_map_authorized_code_files_ignores_inactive_drf_router_include(
    root_urlconf,
):
    result = map_authorized_code_files(
        {
            "authorized_code_files": [
                {
                    "path": "project/settings.py",
                    "content": 'ROOT_URLCONF = "project.urls"',
                },
                {
                    "path": "project/urls.py",
                    "content": f"""
from django.urls import include, path

{root_urlconf}
""",
                },
                {
                    "path": "api/urls.py",
                    "content": """
from django.urls import include, path
from .router import router

urlpatterns = [path("", include(router.urls))]
""",
                },
                {
                    "path": "api/router.py",
                    "content": """
from rest_framework.routers import DefaultRouter
from .views import BaseViewSet

router = DefaultRouter()
router.register("base", BaseViewSet, basename="base")
""",
                },
                {
                    "path": "api/unused_urls.py",
                    "content": """
from .router import router
from .views import PhantomViewSet

router.register("phantom", PhantomViewSet, basename="phantom")
urlpatterns = []
""",
                },
                {
                    "path": "api/views.py",
                    "content": """
from rest_framework.viewsets import ViewSet

class BaseViewSet(ViewSet):
    def list(self, request):
        return send_file("base")

class PhantomViewSet(ViewSet):
    def list(self, request):
        return send_file("phantom")
""",
                },
            ]
        }
    )

    handlers = {
        (fact.symbol_name, fact.route_method, fact.route_path)
        for fact in result.facts
        if fact.fact_type == "route_handler"
    }
    assert handlers == {("BaseViewSet.list", "GET", "/api/base/")}


def test_map_authorized_code_files_snapshots_drf_router_urls_before_later_include_mutation():
    result = map_authorized_code_files(
        {
            "authorized_code_files": [
                {
                    "path": "project/settings.py",
                    "content": 'ROOT_URLCONF = "project.urls"',
                },
                {
                    "path": "project/urls.py",
                    "content": """
from django.urls import include, path

urlpatterns = [
    path("a/", include("api.a_urls")),
    path("b/", include("api.b_urls")),
]
""",
                },
                {
                    "path": "api/a_urls.py",
                    "content": """
from django.urls import include, path
from .router import router

urlpatterns = [path("", include(router.urls))]
""",
                },
                {
                    "path": "api/b_urls.py",
                    "content": """
from .router import router
from .views import PhantomViewSet

router.register("phantom", PhantomViewSet, basename="phantom")
urlpatterns = []
""",
                },
                {
                    "path": "api/router.py",
                    "content": """
from rest_framework.routers import DefaultRouter
from .views import BaseViewSet

router = DefaultRouter()
router.register("base", BaseViewSet, basename="base")
""",
                },
                {
                    "path": "api/views.py",
                    "content": """
from rest_framework.viewsets import ViewSet

class BaseViewSet(ViewSet):
    def list(self, request):
        return send_file("base")

class PhantomViewSet(ViewSet):
    def list(self, request):
        return send_file("phantom")
""",
                },
            ]
        }
    )

    handlers = {
        (fact.symbol_name, fact.route_method, fact.route_path)
        for fact in result.facts
        if fact.fact_type == "route_handler"
    }
    assert handlers == {("BaseViewSet.list", "GET", "/a/base/")}


def test_map_authorized_code_files_does_not_load_shadowed_drf_router_submodule():
    result = map_authorized_code_files(
        {
            "authorized_code_files": [
                {
                    "path": "project/settings.py",
                    "content": 'ROOT_URLCONF = "project.urls"',
                },
                {
                    "path": "project/urls.py",
                    "content": """
from django.urls import include, path
from api import router

urlpatterns = [path("api/", include(router.urls))]
""",
                },
                {
                    "path": "api/__init__.py",
                    "content": "from .base import router\n",
                },
                {
                    "path": "api/base.py",
                    "content": """
from rest_framework.routers import DefaultRouter
from .views import BaseViewSet

router = DefaultRouter()
router.register("base", BaseViewSet, basename="base")
""",
                },
                {
                    "path": "api/router.py",
                    "content": """
from .base import router
from .views import PhantomViewSet

router.register("phantom", PhantomViewSet, basename="phantom")
""",
                },
                {
                    "path": "api/views.py",
                    "content": """
from rest_framework.viewsets import ViewSet

class BaseViewSet(ViewSet):
    def list(self, request):
        return send_file("base")

class PhantomViewSet(ViewSet):
    def list(self, request):
        return send_file("phantom")
""",
                },
            ]
        }
    )

    handlers = {
        (fact.symbol_name, fact.route_method, fact.route_path)
        for fact in result.facts
        if fact.fact_type == "route_handler"
    }
    assert handlers == {("BaseViewSet.list", "GET", "/api/base/")}


def test_map_authorized_code_files_maps_namespaced_static_drf_router_include():
    result = map_authorized_code_files(
        {
            "authorized_code_files": [
                {
                    "path": "project/settings.py",
                    "content": 'ROOT_URLCONF = "project.urls"',
                },
                {
                    "path": "project/urls.py",
                    "content": """
from django.urls import include, path
from rest_framework.routers import DefaultRouter
from .views import FileViewSet

router = DefaultRouter()
router.register("files", FileViewSet, basename="file")
urlpatterns = [
    path("api/", include((router.urls, "api"), namespace="api")),
]
""",
                },
                {
                    "path": "project/views.py",
                    "content": """
from rest_framework.viewsets import ViewSet

class FileViewSet(ViewSet):
    def list(self, request):
        return send_file("manifest")
""",
                },
            ]
        }
    )

    route = next(fact for fact in result.facts if fact.fact_type == "route_handler")
    assert (route.symbol_name, route.route_method, route.route_path) == (
        "FileViewSet.list",
        "GET",
        "/api/files/",
    )


def test_map_authorized_code_files_does_not_assume_django_urlconf_root():
    result = map_authorized_code_files(
        {
            "authorized_code_files": [
                {
                    "path": "routes/urls.py",
                    "content": """
from django.urls import path
from .views import export_file

urlpatterns = [
    path("exports/<uuid:file_id>/", export_file),
]
""",
                },
                {
                    "path": "routes/views.py",
                    "content": """
def export_file(file_id: str):
    return send_file(file_id)
""",
                },
            ]
        }
    )

    assert not any(fact.fact_type == "route_handler" for fact in result.facts)
    assert not any(
        fact.fact_type == "authorization_gap_candidate" for fact in result.facts
    )


def test_map_authorized_code_files_does_not_assume_unknown_django_view_receiver():
    result = map_authorized_code_files(
        {
            "authorized_code_files": [
                {
                    "path": "project/settings.py",
                    "content": """
ROOT_URLCONF = "project.urls"
""",
                },
                {
                    "path": "project/urls.py",
                    "content": """
from django.urls import path

urlpatterns = [
    path("exports/<uuid:file_id>/", unknown_views.export_file),
]

def export_file(file_id: str):
    return send_file(file_id)
""",
                },
            ]
        }
    )

    assert not any(fact.fact_type == "route_handler" for fact in result.facts)
    assert not any(
        fact.fact_type == "authorization_gap_candidate" for fact in result.facts
    )


def test_map_authorized_code_files_maps_django_api_view_to_its_method_identity():
    result = map_authorized_code_files(
        {
            "authorized_code_files": [
                {
                    "path": "project/settings.py",
                    "content": 'ROOT_URLCONF = "project.urls"',
                },
                {
                    "path": "project/urls.py",
                    "content": """
from django.urls import path
from .views import ProjectDownload

urlpatterns = [
    path("projects/<int:pk>/download/", ProjectDownload.as_view()),
]
""",
                },
                {
                    "path": "project/views.py",
                    "content": """
from rest_framework.views import APIView

class ProjectDownload(APIView):
    def get(self, request, pk):
        project = Project.objects.get(pk=pk)
        return send_file(project.path)
""",
                },
            ]
        }
    )

    route = next(fact for fact in result.facts if fact.fact_type == "route_handler")
    sink = next(fact for fact in result.facts if fact.fact_type == "sensitive_sink")
    gap = next(
        fact
        for fact in result.facts
        if fact.fact_type == "authorization_gap_candidate"
    )

    assert (route.symbol_name, route.route_method, route.route_path) == (
        "ProjectDownload.get",
        "GET",
        "/projects/<int:pk>/download/",
    )
    assert route.payload["handler"] == "ProjectDownload.get"
    assert sink.payload["handler"] == "ProjectDownload.get"
    assert gap.symbol_name == "ProjectDownload.get"


def test_map_authorized_code_files_keeps_django_class_view_methods_isolated():
    result = map_authorized_code_files(
        {
            "authorized_code_files": [
                {
                    "path": "project/settings.py",
                    "content": 'ROOT_URLCONF = "project.urls"',
                },
                {
                    "path": "project/urls.py",
                    "content": """
from django.urls import path
from . import views

urlpatterns = [
    path("projects/<int:pk>/download/", views.PublicProjectDownload.as_view()),
    path("my-projects/<int:pk>/download/", views.OwnedProjectDownload.as_view()),
]
""",
                },
                {
                    "path": "project/views.py",
                    "content": """
from rest_framework.views import APIView

class PublicProjectDownload(APIView):
    def get(self, request, pk):
        project = Project.objects.get(pk=pk)
        return send_file(project.path)

class OwnedProjectDownload(APIView):
    def get(self, request, pk):
        project = Project.objects.get(pk=pk, owner_id=request.user.id)
        return send_file(project.path)
""",
                },
            ]
        }
    )

    routes = {
        (fact.symbol_name, fact.route_method, fact.route_path)
        for fact in result.facts
        if fact.fact_type == "route_handler"
    }
    sink_handlers = {
        fact.payload["handler"]
        for fact in result.facts
        if fact.fact_type == "sensitive_sink"
    }
    gap_handlers = {
        fact.symbol_name
        for fact in result.facts
        if fact.fact_type == "authorization_gap_candidate"
    }

    assert routes == {
        (
            "PublicProjectDownload.get",
            "GET",
            "/projects/<int:pk>/download/",
        ),
        (
            "OwnedProjectDownload.get",
            "GET",
            "/my-projects/<int:pk>/download/",
        ),
    }
    assert sink_handlers == {
        "PublicProjectDownload.get",
        "OwnedProjectDownload.get",
    }
    assert gap_handlers == {"PublicProjectDownload.get"}


def test_map_authorized_code_files_keeps_django_class_view_decorator_authz():
    result = map_authorized_code_files(
        {
            "authorized_code_files": [
                {
                    "path": "project/settings.py",
                    "content": 'ROOT_URLCONF = "project.urls"',
                },
                {
                    "path": "project/urls.py",
                    "content": """
from django.urls import path
from .views import OwnedProjectDownload

urlpatterns = [
    path("my-projects/<int:pk>/download/", OwnedProjectDownload.as_view()),
]
""",
                },
                {
                    "path": "project/views.py",
                    "content": """
from rest_framework.views import APIView

class OwnedProjectDownload(APIView):
    @require_owner
    def get(self, request, pk):
        project = Project.objects.get(pk=pk)
        return send_file(project.path)
""",
                },
            ]
        }
    )

    assert any(
        fact.fact_type == "authz_check"
        and fact.authz_hint == "ownership_boundary_check"
        and fact.payload["handler"] == "OwnedProjectDownload.get"
        for fact in result.facts
    )
    assert not any(
        fact.fact_type == "authorization_gap_candidate" for fact in result.facts
    )


def test_map_authorized_code_files_keeps_django_dispatch_decorator_authz():
    result = map_authorized_code_files(
        {
            "authorized_code_files": [
                {
                    "path": "project/settings.py",
                    "content": 'ROOT_URLCONF = "project.urls"',
                },
                {
                    "path": "project/urls.py",
                    "content": """
from django.urls import path
from .views import OwnedProjectDownload

urlpatterns = [
    path("my-projects/<int:pk>/download/", OwnedProjectDownload.as_view()),
]
""",
                },
                {
                    "path": "project/views.py",
                    "content": """
from django.utils.decorators import method_decorator
from rest_framework.views import APIView

@method_decorator(require_owner, name="dispatch")
class OwnedProjectDownload(APIView):
    def get(self, request, pk):
        project = Project.objects.get(pk=pk)
        return send_file(project.path)
""",
                },
            ]
        }
    )

    assert any(
        fact.fact_type == "authz_check"
        and fact.authz_hint == "ownership_boundary_check"
        and fact.payload["handler"] == "OwnedProjectDownload.get"
        for fact in result.facts
    )
    assert not any(
        fact.fact_type == "authorization_gap_candidate" for fact in result.facts
    )


def test_map_authorized_code_files_keeps_multiline_django_dispatch_decorator_authz():
    result = map_authorized_code_files(
        {
            "authorized_code_files": [
                {
                    "path": "project/settings.py",
                    "content": 'ROOT_URLCONF = "project.urls"',
                },
                {
                    "path": "project/urls.py",
                    "content": """
from django.urls import path
from .views import OwnedProjectDownload

urlpatterns = [
    path("my-projects/<int:pk>/download/", OwnedProjectDownload.as_view()),
]
""",
                },
                {
                    "path": "project/views.py",
                    "content": """
from django.utils.decorators import method_decorator
from rest_framework.views import APIView

@method_decorator(
    [require_owner],
    name="dispatch",
)
class OwnedProjectDownload(APIView):
    def get(self, request, pk):
        project = Project.objects.get(pk=pk)
        return send_file(project.path)
""",
                },
            ]
        }
    )

    assert any(
        fact.fact_type == "authz_check"
        and fact.authz_hint == "ownership_boundary_check"
        and fact.payload["handler"] == "OwnedProjectDownload.get"
        for fact in result.facts
    )
    assert not any(
        fact.fact_type == "authorization_gap_candidate" for fact in result.facts
    )


def test_map_authorized_code_files_keeps_aliased_django_method_decorator_authz():
    result = map_authorized_code_files(
        {
            "authorized_code_files": [
                {
                    "path": "project/settings.py",
                    "content": 'ROOT_URLCONF = "project.urls"',
                },
                {
                    "path": "project/urls.py",
                    "content": """
from django.urls import path
from .views import FileViewSet

urlpatterns = [
    path("files/", FileViewSet.as_view({"get": "list"})),
]
""",
                },
                {
                    "path": "project/views.py",
                    "content": """
from django.utils.decorators import method_decorator as decorate
from rest_framework.viewsets import ViewSet

@decorate(
    [require_owner],
    name="dispatch",
)
class FileViewSet(ViewSet):
    def list(self, request):
        return send_file("manifest")
""",
                },
            ]
        }
    )

    assert any(
        fact.fact_type == "authz_check"
        and fact.authz_hint == "ownership_boundary_check"
        and fact.payload["handler"] == "FileViewSet.list"
        for fact in result.facts
    )
    assert not any(
        fact.fact_type == "authorization_gap_candidate" for fact in result.facts
    )


def test_map_authorized_code_files_keeps_keyword_django_method_decorator_authz():
    result = map_authorized_code_files(
        {
            "authorized_code_files": [
                {
                    "path": "project/settings.py",
                    "content": 'ROOT_URLCONF = "project.urls"',
                },
                {
                    "path": "project/urls.py",
                    "content": """
from django.urls import path
from .views import FileViewSet

urlpatterns = [
    path("files/", FileViewSet.as_view({"get": "list"})),
]
""",
                },
                {
                    "path": "project/views.py",
                    "content": """
from django.utils.decorators import method_decorator as decorate
from rest_framework.viewsets import ViewSet

@decorate(
    decorator=(require_owner,),
    name="dispatch",
)
class FileViewSet(ViewSet):
    def list(self, request):
        return send_file("manifest")
""",
                },
            ]
        }
    )

    assert any(
        fact.fact_type == "authz_check"
        and fact.authz_hint == "ownership_boundary_check"
        and fact.payload["handler"] == "FileViewSet.list"
        for fact in result.facts
    )
    assert not any(
        fact.fact_type == "authorization_gap_candidate" for fact in result.facts
    )


def test_map_authorized_code_files_keeps_positional_django_method_decorator_name():
    result = map_authorized_code_files(
        {
            "authorized_code_files": [
                {
                    "path": "project/settings.py",
                    "content": 'ROOT_URLCONF = "project.urls"',
                },
                {
                    "path": "project/urls.py",
                    "content": """
from django.urls import path
from .views import OwnedProjectDownload

urlpatterns = [
    path("my-projects/<int:pk>/download/", OwnedProjectDownload.as_view()),
]
""",
                },
                {
                    "path": "project/views.py",
                    "content": """
from django.utils.decorators import method_decorator
from rest_framework.views import APIView

@method_decorator(require_owner, "dispatch")
class OwnedProjectDownload(APIView):
    def get(self, request, pk):
        project = Project.objects.get(pk=pk)
        return send_file(project.path)

    def post(self, request, pk):
        project = Project.objects.get(pk=pk)
        return send_file(project.path)
""",
                },
            ]
        }
    )

    assert {
        fact.payload["handler"]
        for fact in result.facts
        if (
            fact.fact_type == "authz_check"
            and fact.authz_hint == "ownership_boundary_check"
        )
    } == {"OwnedProjectDownload.get", "OwnedProjectDownload.post"}
    assert not any(
        fact.fact_type == "authorization_gap_candidate" for fact in result.facts
    )


@pytest.mark.parametrize(
    "wrapped_decorator",
    ("require_owner", "[require_owner]", "(require_owner,)"),
)
def test_map_authorized_code_files_keeps_django_method_decorator_authz(
    wrapped_decorator,
):
    result = map_authorized_code_files(
        {
            "authorized_code_files": [
                {
                    "path": "project/settings.py",
                    "content": 'ROOT_URLCONF = "project.urls"',
                },
                {
                    "path": "project/urls.py",
                    "content": """
from django.urls import path
from .views import OwnedProjectDownload

urlpatterns = [
    path("my-projects/<int:pk>/download/", OwnedProjectDownload.as_view()),
]
""",
                },
                {
                    "path": "project/views.py",
                    "content": f"""
from django.utils.decorators import method_decorator
from rest_framework.views import APIView

class OwnedProjectDownload(APIView):
    @method_decorator({wrapped_decorator})
    def get(self, request, pk):
        project = Project.objects.get(pk=pk)
        return send_file(project.path)
""",
                },
            ]
        }
    )

    assert any(
        fact.fact_type == "authz_check"
        and fact.authz_hint == "ownership_boundary_check"
        and fact.payload["handler"] == "OwnedProjectDownload.get"
        for fact in result.facts
    )
    assert not any(
        fact.fact_type == "authorization_gap_candidate" for fact in result.facts
    )


def test_map_authorized_code_files_maps_drf_viewset_action_map():
    result = map_authorized_code_files(
        {
            "authorized_code_files": [
                {
                    "path": "project/settings.py",
                    "content": 'ROOT_URLCONF = "project.urls"',
                },
                {
                    "path": "project/urls.py",
                    "content": """
from django.urls import path
from .views import FileViewSet

urlpatterns = [
    path("files/", FileViewSet.as_view({"get": "list"})),
]
""",
                },
                {
                    "path": "project/views.py",
                    "content": """
from rest_framework.viewsets import ViewSet

class FileViewSet(ViewSet):
    def list(self, request):
        return send_file("manifest")
""",
                },
            ]
        }
    )

    route = next(fact for fact in result.facts if fact.fact_type == "route_handler")
    sink = next(fact for fact in result.facts if fact.fact_type == "sensitive_sink")
    gap = next(
        fact
        for fact in result.facts
        if fact.fact_type == "authorization_gap_candidate"
    )

    assert (route.symbol_name, route.route_method, route.route_path) == (
        "FileViewSet.list",
        "GET",
        "/files/",
    )
    assert sink.payload["handler"] == "FileViewSet.list"
    assert gap.symbol_name == "FileViewSet.list"


def test_map_authorized_code_files_keeps_dynamic_drf_viewset_actions_unresolved():
    result = map_authorized_code_files(
        {
            "authorized_code_files": [
                {
                    "path": "project/settings.py",
                    "content": 'ROOT_URLCONF = "project.urls"',
                },
                {
                    "path": "project/urls.py",
                    "content": """
from django.urls import path
from .views import FileViewSet

actions = build_actions()
urlpatterns = [
    path("files/", FileViewSet.as_view(actions)),
]
""",
                },
                {
                    "path": "project/views.py",
                    "content": """
from rest_framework.viewsets import ViewSet

class FileViewSet(ViewSet):
    def list(self, request):
        return send_file("manifest")
""",
                },
            ]
        }
    )

    assert not any(fact.fact_type == "route_handler" for fact in result.facts)
    assert not any(
        fact.fact_type == "authorization_gap_candidate" for fact in result.facts
    )


def test_map_authorized_code_files_keeps_django_class_view_helpers_isolated():
    result = map_authorized_code_files(
        {
            "authorized_code_files": [
                {
                    "path": "project/settings.py",
                    "content": 'ROOT_URLCONF = "project.urls"',
                },
                {
                    "path": "project/urls.py",
                    "content": """
from django.urls import path
from . import views

urlpatterns = [
    path("projects/<int:pk>/download/", views.PublicProjectDownload.as_view()),
    path("my-projects/<int:pk>/download/", views.OwnedProjectDownload.as_view()),
]
""",
                },
                {
                    "path": "project/views.py",
                    "content": """
from rest_framework.views import APIView

class PublicProjectDownload(APIView):
    def get(self, request, pk):
        return self._export(pk)

    def _export(self, pk):
        project = Project.objects.get(pk=pk)
        return send_file(project.path)

class OwnedProjectDownload(APIView):
    def get(self, request, pk):
        return self._export(pk)

    def _export(self, pk):
        project = Project.objects.get(pk=pk, owner_id=request.user.id)
        return send_file(project.path)
""",
                },
            ]
        }
    )

    service_calls = {
        (fact.payload["caller"], fact.symbol_name)
        for fact in result.facts
        if fact.fact_type == "service_call" and fact.symbol_name.endswith("._export")
    }
    gap_handlers = {
        fact.symbol_name
        for fact in result.facts
        if fact.fact_type == "authorization_gap_candidate"
    }

    assert service_calls == {
        ("PublicProjectDownload.get", "PublicProjectDownload._export"),
        ("OwnedProjectDownload.get", "OwnedProjectDownload._export"),
    }
    assert gap_handlers == {"PublicProjectDownload.get"}


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


def test_map_authorized_code_files_keeps_same_named_handler_authz_in_its_source_path():
    result = map_authorized_code_files(
        {
            "authorized_code_files": [
                {
                    "path": "apps/api/routes.py",
                    "content": """
from fastapi import APIRouter

router = APIRouter()

@router.get("/records/{record_id}")
def read_record(record_id: str):
    return send_file(record_id)
""",
                },
                {
                    "path": "apps/admin/routes.py",
                    "content": """
from fastapi import APIRouter

router = APIRouter()

@router.get("/admin/records/{record_id}")
def read_record(record_id: str, current_user):
    authorize_owner_or_admin(record_id, current_user)
    return send_file(record_id)
""",
                },
            ]
        }
    )

    gaps = [
        fact
        for fact in result.facts
        if fact.fact_type == "authorization_gap_candidate"
    ]

    assert [(gap.source_path, gap.symbol_name) for gap in gaps] == [
        ("apps/api/routes.py", "read_record"),
    ]


def test_map_authorized_code_files_keeps_same_source_service_handler_when_names_collide():
    result = map_authorized_code_files(
        {
            "authorized_code_files": [
                {
                    "path": "apps/api/routes.py",
                    "content": """
from fastapi import APIRouter

router = APIRouter()

@router.get("/records/{record_id}")
def read_record(record_id: str):
    return load_record(record_id)

def load_record(record_id: str):
    return send_file(record_id)
""",
                },
                {
                    "path": "apps/admin/routes.py",
                    "content": """
def load_record(record_id: str, current_user):
    authorize_owner_or_admin(record_id, current_user)
    return send_file(record_id)
""",
                },
            ]
        }
    )

    gaps = [
        fact
        for fact in result.facts
        if fact.fact_type == "authorization_gap_candidate"
    ]

    assert [(gap.source_path, gap.symbol_name) for gap in gaps] == [
        ("apps/api/routes.py", "read_record"),
    ]


def test_map_authorized_code_files_keeps_ambiguous_dependency_wrappers_unresolved():
    result = map_authorized_code_files(
        {
            "authorized_code_files": [
                {
                    "path": "apps/api/routes.py",
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
                {
                    "path": "apps/admin/dependencies.py",
                    "content": """
def current_user(user):
    return load_user(user)
""",
                },
            ]
        }
    )

    route_authz = [
        fact
        for fact in result.facts
        if fact.fact_type == "authz_check"
        and fact.source_path == "apps/api/routes.py"
        and fact.payload.get("handler") == "export_file"
    ]
    gaps = [
        fact
        for fact in result.facts
        if fact.fact_type == "authorization_gap_candidate"
    ]

    assert route_authz == []
    assert [(gap.source_path, gap.symbol_name) for gap in gaps] == [
        ("apps/api/routes.py", "export_file"),
    ]


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
    assert gap.authz_hint == "missing_handler_agent_tool_authorization_check"
    assert gap.payload["root_cause"] == "missing_agent_tool_authorization_check"


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
    assert gap.authz_hint == "missing_handler_agent_tool_authorization_check"
    assert gap.payload["root_cause"] == "missing_agent_tool_authorization_check"


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
    gap = next(
        fact for fact in result.facts if fact.fact_type == "authorization_gap_candidate"
    )
    assert gap.payload["root_cause"] == "missing_agent_tool_authorization_check"


def test_map_authorized_code_files_marks_typescript_agent_tool_execution_without_policy():
    result = map_authorized_code_files(
        {
            "authorized_code_files": [
                {
                    "path": "apps/api/routes/agents.ts",
                    "content": """
import { Router } from "express";

const router = Router();

router.post("/agents/:agentId/tools/execute", runAgentTool);

async function runAgentTool(req: Request, res: Response) {
  return executeAgentTool(req.params.agentId, req.body.toolName);
}
""",
                }
            ]
        }
    )

    gap = next(
        fact for fact in result.facts if fact.fact_type == "authorization_gap_candidate"
    )

    assert gap.authz_hint == "missing_handler_agent_tool_authorization_check"
    assert gap.payload["root_cause"] == "missing_agent_tool_authorization_check"
    assert "executeAgentTool" in gap.payload["sink_symbols"]


def test_map_authorized_code_files_preserves_job_dispatch_as_object_boundary():
    result = map_authorized_code_files(
        {
            "authorized_code_files": [
                {
                    "path": "apps/api/routes/jobs.ts",
                    "content": """
import { Router } from "express";

const router = Router();

router.post("/jobs/:jobId/run", runJob);

async function runJob(req: Request, res: Response) {
  return dispatchAgentTool(req.params.jobId);
}
""",
                }
            ]
        }
    )

    gap = next(
        fact for fact in result.facts if fact.fact_type == "authorization_gap_candidate"
    )

    assert gap.authz_hint == "missing_handler_authz_check"
    assert gap.payload["root_cause"] == "missing_object_ownership_check"


@pytest.mark.parametrize(
    ("source_path", "source_code", "expected_guard", "expected_sink"),
    (
        (
            "apps/api/routes/agents.py",
            """
from fastapi import APIRouter

router = APIRouter()

@router.post("/agents/{agent_id}/tools/execute")
def run_agent_tool(agent_id: str, tool_name: str):
    assert_tool_allowed(agent_id, tool_name)
    return execute_agent_tool(agent_id, tool_name)
""",
            "assert_tool_allowed",
            "execute_agent_tool",
        ),
        (
            "apps/api/routes/agents.ts",
            """
import { Router } from "express";

const router = Router();

router.post("/agents/:agentId/tools/execute", runAgentTool);

function assertToolAllowed(agentId: string, toolName: string) {
  return true;
}

async function runAgentTool(req: Request, res: Response) {
  assertToolAllowed(req.params.agentId, req.body.toolName);
  return executeAgentTool(req.params.agentId, req.body.toolName);
}
""",
            "assertToolAllowed",
            "executeAgentTool",
        ),
    ),
)
def test_map_authorized_code_files_treats_agent_tool_policy_as_control(
    source_path,
    source_code,
    expected_guard,
    expected_sink,
):
    result = map_authorized_code_files(
        {"authorized_code_files": [{"path": source_path, "content": source_code}]}
    )

    authz = next(
        fact
        for fact in result.facts
        if fact.fact_type == "authz_check"
        and fact.authz_hint == "agent_tool_authorization_check"
    )

    assert authz.symbol_name == expected_guard
    assert any(
        fact.fact_type == "sensitive_sink" and fact.symbol_name == expected_sink
        for fact in result.facts
    )
    assert not any(
        fact.fact_type == "authorization_gap_candidate" for fact in result.facts
    )


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


def test_map_authorized_code_files_composes_static_express_router_mount_prefixes():
    result = map_authorized_code_files(
        {
            "authorized_code_files": [
                {
                    "path": "src/routes/records.ts",
                    "content": '''
import express, { Router } from "express";

const app = express();
const apiRouter = Router();
const recordsRouter = Router();

app.use("/api/v1", apiRouter);
apiRouter.use("/records", recordsRouter);
recordsRouter.get("/:recordId/export", requireUser, exportRecord);

function exportRecord(req: Request, res: Response) {
  return sendFile(req.params.recordId);
}
''',
                }
            ]
        }
    )

    route = next(fact for fact in result.facts if fact.fact_type == "route_handler")

    assert route.symbol_name == "exportRecord"
    assert route.route_method == "GET"
    assert route.route_path == "/api/v1/records/:recordId/export"
    assert any(
        fact.fact_type == "authz_check"
        and fact.symbol_name == "requireUser"
        and fact.payload["handler"] == "exportRecord"
        for fact in result.facts
    )
    assert not any(
        fact.fact_type == "authorization_gap_candidate" for fact in result.facts
    )


def test_map_authorized_code_files_does_not_invent_dynamic_express_router_mount_prefixes():
    result = map_authorized_code_files(
        {
            "authorized_code_files": [
                {
                    "path": "src/routes/records.ts",
                    "content": '''
import express, { Router } from "express";

const app = express();
const recordsRouter = Router();
const prefix = loadAuthorizedPrefix();

app.use(prefix, recordsRouter);
recordsRouter.get("/:recordId/export", requireUser, exportRecord);

function exportRecord(req: Request, res: Response) {
  return sendFile(req.params.recordId);
}
''',
                }
            ]
        }
    )

    route = next(fact for fact in result.facts if fact.fact_type == "route_handler")

    assert route.route_path == "/:recordId/export"


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



@pytest.mark.parametrize(
    ("source_path", "content", "handler", "decoder", "sink_symbol"),
    [
        pytest.param(
            "apps/api/routes/reports.py",
            """
from fastapi import APIRouter
import jwt

router = APIRouter()

@router.get("/reports/{report_id}/export")
def export_report(report_id: str, token: str):
    claims = jwt.decode(token, options={"verify_signature": False})
    return send_file(claims["path"])
""",
            "export_report",
            "jwt.decode",
            "send_file",
            id="python-explicit-signature-disabled",
        ),
        pytest.param(
            "apps/api/routes/reports.ts",
            """
import { Router } from "express";
import jwt from "jsonwebtoken";

const router = Router();

router.get("/reports/:reportId/export", exportReport);

async function exportReport(req: Request, res: Response) {
  const claims = jwt.decode(req.headers.authorization || "");
  return sendFile(claims?.path);
}
""",
            "exportReport",
            "jwt.decode",
            "sendFile",
            id="typescript-jsonwebtoken-decode",
        ),
        pytest.param(
            "ReportsController.java",
            """
@RestController
public class ReportsController {
  @GetMapping("/reports/{reportId}/export")
  public Object exportReport(String token) {
    DecodedJWT claims = JWT.decode(token);
    return sendFile(claims.getClaim("path").asString());
  }
}
""",
            "exportReport",
            "JWT.decode",
            "sendFile",
            id="java-jwt-decode",
        ),
    ],
)
def test_map_authorized_code_files_marks_unverified_jwt_decode_before_sensitive_sink_as_gap(
    source_path,
    content,
    handler,
    decoder,
    sink_symbol,
):
    result = map_authorized_code_files(
        {"authorized_code_files": [{"path": source_path, "content": content}]}
    )

    decoder_fact = next(
        fact
        for fact in result.facts
        if fact.fact_type == "unverified_token_decode"
    )
    gaps = [
        fact
        for fact in result.facts
        if fact.fact_type == "authorization_gap_candidate"
    ]

    assert decoder_fact.symbol_name == decoder
    assert decoder_fact.payload["handler"] == handler
    assert len(gaps) == 1
    assert gaps[0].symbol_name == handler
    assert gaps[0].authz_hint == "missing_handler_jwt_verification_check"
    assert gaps[0].payload["root_cause"] == "missing_jwt_verification"
    assert gaps[0].payload["decoder_symbols"] == [decoder]
    assert gaps[0].payload["sink_symbols"] == [sink_symbol]
    assert gaps[0].payload["review_state"] == "needs_human_review"


def test_map_authorized_code_files_refutes_jwt_gap_for_prior_explicit_verification():
    result = map_authorized_code_files(
        {
            "authorized_code_files": [
                {
                    "path": "apps/api/routes/reports.py",
                    "content": """
from fastapi import APIRouter
import jwt

router = APIRouter()

@router.get("/reports/{report_id}/export")
def export_report(report_id: str, token: str):
    claims = jwt.decode(token, options={"verify_signature": False})
    verified_claims = jwt.verify(token, verification_key)
    return send_file(verified_claims["path"])
""",
                }
            ]
        }
    )

    assert any(
        fact.fact_type == "authz_check"
        and fact.authz_hint == "jwt_verification_check"
        for fact in result.facts
    )
    assert not any(
        fact.fact_type == "authorization_gap_candidate"
        and fact.payload.get("root_cause") == "missing_jwt_verification"
        for fact in result.facts
    )


@pytest.mark.parametrize(
    ("source_path", "content"),
    (
        (
            "apps/api/routes/reports.py",
            """
from fastapi import APIRouter
import jwt

router = APIRouter()

@router.get("/reports/{report_id}/export")
def export_report(report_id: str, token: str):
    unsafe_claims = jwt.decode(token, options={"verify_signature": False})
    verified_claims = jwt.verify(token, verification_key)
    return send_file(unsafe_claims["path"])
""",
        ),
        (
            "apps/api/routes/reports.ts",
            """
import { Router } from "express";
import jwt from "jsonwebtoken";

const router = Router();

router.get("/reports/:reportId/export", exportReport);

async function exportReport(req: Request, res: Response) {
  const unsafeClaims = jwt.decode(req.headers.authorization || "");
  const verifiedClaims = jwt.verify(req.headers.authorization || "", verificationKey);
  return sendFile(unsafeClaims?.path);
}
""",
        ),
        (
            "ReportsController.java",
            """
@RestController
public class ReportsController {
  @GetMapping("/reports/{reportId}/export")
  public Object exportReport(String token) {
    DecodedJWT unsafeClaims = JWT.decode(token);
    DecodedJWT verifiedClaims = JWT.verify(token, verificationKey);
    return sendFile(unsafeClaims.getClaim("path").asString());
  }
}
""",
        ),
    ),
)
def test_map_authorized_code_files_keeps_jwt_gap_when_sink_uses_unverified_claims(
    source_path,
    content,
):
    result = map_authorized_code_files(
        {"authorized_code_files": [{"path": source_path, "content": content}]}
    )

    assert any(
        fact.fact_type == "authorization_gap_candidate"
        and fact.payload.get("root_cause") == "missing_jwt_verification"
        for fact in result.facts
    )


@pytest.mark.parametrize(
    ("source_path", "content"),
    (
        (
            "apps/api/routes/reports.py",
            """
from fastapi import APIRouter
import jwt

router = APIRouter()

@router.get("/reports/{report_id}/export")
def export_report(
    report_id: str,
    attacker_token: str,
    service_token: str,
    use_service_token: bool,
):
    selected_token = attacker_token
    if use_service_token:
        selected_token = service_token
    claims = jwt.decode(selected_token, options={"verify_signature": False})
    verified_claims = jwt.verify(service_token, verification_key)
    return send_file(claims["path"])
""",
        ),
        (
            "ReportsController.java",
            """
@RestController
public class ReportsController {
  @GetMapping("/reports/{reportId}/export")
  public Object exportReport(
      String attackerToken,
      String serviceToken,
      boolean useServiceToken) {
    String selectedToken = attackerToken;
    if (useServiceToken) {
      selectedToken = serviceToken;
    }
    DecodedJWT claims = JWT.decode(selectedToken);
    DecodedJWT verifiedClaims = JWT.verify(serviceToken, verificationKey);
    return sendFile(claims.getClaim("path").asString());
  }
}
""",
        ),
    ),
)
def test_map_authorized_code_files_keeps_jwt_gap_for_conditional_token_rebinding(
    source_path,
    content,
):
    result = map_authorized_code_files(
        {"authorized_code_files": [{"path": source_path, "content": content}]}
    )

    assert any(
        fact.fact_type == "authorization_gap_candidate"
        and fact.payload.get("root_cause") == "missing_jwt_verification"
        for fact in result.facts
    )


def test_map_authorized_code_files_keeps_jwt_gap_when_verification_follows_sink():
    result = map_authorized_code_files(
        {
            "authorized_code_files": [
                {
                    "path": "apps/api/routes/reports.py",
                    "content": """
from fastapi import APIRouter
import jwt

router = APIRouter()

@router.get("/reports/{report_id}/export")
def export_report(report_id: str, token: str):
    claims = jwt.decode(token, options={"verify_signature": False})
    exported = send_file(claims["path"])
    jwt.verify(token, verification_key)
    return exported
""",
                }
            ]
        }
    )

    assert any(
        fact.fact_type == "authorization_gap_candidate"
        and fact.payload.get("root_cause") == "missing_jwt_verification"
        for fact in result.facts
    )


def test_map_authorized_code_files_does_not_treat_verified_python_jwt_decode_as_gap():
    result = map_authorized_code_files(
        {
            "authorized_code_files": [
                {
                    "path": "apps/api/routes/reports.py",
                    "content": """
from fastapi import APIRouter
import jwt

router = APIRouter()

@router.get("/reports/{report_id}/export")
def export_report(report_id: str, token: str):
    claims = jwt.decode(token, verification_key, algorithms=["HS256"])
    return send_file(claims["path"])
""",
                }
            ]
        }
    )

    assert not any(
        fact.fact_type == "unverified_token_decode" for fact in result.facts
    )
    assert not any(
        fact.fact_type == "authorization_gap_candidate"
        and fact.payload.get("root_cause") == "missing_jwt_verification"
        for fact in result.facts
    )


def test_map_authorized_code_files_ignores_jwt_decode_text_in_python_strings():
    result = map_authorized_code_files(
        {
            "authorized_code_files": [
                {
                    "path": "apps/api/routes/reports.py",
                    "content": """
from fastapi import APIRouter

router = APIRouter()

@router.get("/reports/{report_id}/export")
def export_report(report_id: str):
    review_note = 'jwt.decode(value, options={"verify_signature": False})'
    return send_file(report_id)
""",
                }
            ]
        }
    )

    assert not any(
        fact.fact_type == "unverified_token_decode" for fact in result.facts
    )
    assert not any(
        fact.fact_type == "authorization_gap_candidate"
        and fact.payload.get("root_cause") == "missing_jwt_verification"
        for fact in result.facts
    )


def test_map_authorized_code_files_keeps_jwt_gap_when_verification_uses_other_token():
    result = map_authorized_code_files(
        {
            "authorized_code_files": [
                {
                    "path": "apps/api/routes/reports.py",
                    "content": """
from fastapi import APIRouter
import jwt

router = APIRouter()

@router.get("/reports/{report_id}/export")
def export_report(report_id: str, attacker_token: str, service_token: str):
    claims = jwt.decode(attacker_token, options={"verify_signature": False})
    verified_claims = jwt.verify(service_token, verification_key)
    return send_file(claims["path"])
""",
                }
            ]
        }
    )

    assert any(
        fact.fact_type == "authorization_gap_candidate"
        and fact.payload.get("root_cause") == "missing_jwt_verification"
        for fact in result.facts
    )


def test_map_authorized_code_files_keeps_jwt_gap_for_different_request_headers():
    result = map_authorized_code_files(
        {
            "authorized_code_files": [
                {
                    "path": "apps/api/routes/reports.py",
                    "content": """
from fastapi import APIRouter, Request
import jwt

router = APIRouter()

@router.get("/reports/{report_id}/export")
def export_report(report_id: str, request: Request):
    claims = jwt.decode(request.headers["Authorization"], options={"verify_signature": False})
    verified_claims = jwt.verify(request.headers["X-Service-Token"], verification_key)
    return send_file(claims["path"])
""",
                }
            ]
        }
    )

    assert any(
        fact.fact_type == "authorization_gap_candidate"
        and fact.payload.get("root_cause") == "missing_jwt_verification"
        for fact in result.facts
    )


def test_map_authorized_code_files_keeps_jwt_gap_for_conditional_typescript_token():
    result = map_authorized_code_files(
        {
            "authorized_code_files": [
                {
                    "path": "apps/api/routes/reports.ts",
                    "content": """
import { Router } from "express";
import jwt from "jsonwebtoken";

const router = Router();

router.get("/reports/:reportId/export", exportReport);

async function exportReport(req: Request, res: Response) {
  const claims = jwt.decode(req.headers.authorization || req.query.fallbackToken);
  const verifiedClaims = jwt.verify(req.headers.authorization, verificationKey);
  return sendFile(claims?.path);
}
""",
                }
            ]
        }
    )

    assert any(
        fact.fact_type == "authorization_gap_candidate"
        and fact.payload.get("root_cause") == "missing_jwt_verification"
        for fact in result.facts
    )


def test_map_authorized_code_files_preserves_distinct_jwt_token_facts_per_handler():
    result = map_authorized_code_files(
        {
            "authorized_code_files": [
                {
                    "path": "apps/api/routes/reports.ts",
                    "content": """
import { Router } from "express";
import jwt from "jsonwebtoken";

const router = Router();

router.get("/reports/:reportId/export", exportReport);

async function exportReport(req: Request, res: Response) {
  const serviceClaims = jwt.decode(req.headers.serviceToken || "");
  const verifiedClaims = jwt.verify(req.headers.serviceToken || "", verificationKey);
  const attackerClaims = jwt.decode(req.headers.attackerToken || "");
  return sendFile(attackerClaims?.path);
}
""",
                }
            ]
        }
    )

    decoder_facts = [
        fact
        for fact in result.facts
        if fact.fact_type == "unverified_token_decode"
    ]

    assert {fact.payload["token_ref"] for fact in decoder_facts} == {
        "token:req.headers.serviceToken",
        "token:req.headers.attackerToken",
    }
    assert any(
        fact.fact_type == "authorization_gap_candidate"
        and fact.payload.get("root_cause") == "missing_jwt_verification"
        for fact in result.facts
    )


def test_map_authorized_code_files_preserves_multiple_python_jwt_calls_on_one_line():
    result = map_authorized_code_files(
        {
            "authorized_code_files": [
                {
                    "path": "apps/api/routes/reports.py",
                    "content": """
from fastapi import APIRouter
import jwt

router = APIRouter()

@router.get("/reports/{report_id}/export")
def export_report(report_id: str, service_token: str, attacker_token: str):
    service_claims = jwt.decode(service_token, options={"verify_signature": False}); attacker_claims = jwt.decode(attacker_token, options={"verify_signature": False}); verified_claims = jwt.verify(service_token, verification_key); return send_file(attacker_claims["path"])
""",
                }
            ]
        }
    )

    decoder_facts = [
        fact
        for fact in result.facts
        if fact.fact_type == "unverified_token_decode"
    ]

    assert {fact.payload["token_ref"] for fact in decoder_facts} == {
        "token:service_token",
        "token:attacker_token",
    }
    assert any(
        fact.fact_type == "authorization_gap_candidate"
        and fact.payload.get("root_cause") == "missing_jwt_verification"
        for fact in result.facts
    )


def test_map_authorized_code_files_keeps_multilang_jwt_gap_for_conditional_token():
    result = map_authorized_code_files(
        {
            "authorized_code_files": [
                {
                    "path": "ReportsController.cs",
                    "content": """
public class ReportsController {
  [HttpGet("/reports/{reportId}/export")]
  public IActionResult ExportReport(string attackerToken, string serviceToken) {
    var claims = JWT.decode(attackerToken ?? serviceToken);
    var verifiedClaims = JWT.verify(attackerToken, verificationKey);
    return File(claims.Path);
  }
}
""",
                }
            ]
        }
    )

    assert any(
        fact.fact_type == "authorization_gap_candidate"
        and fact.payload.get("root_cause") == "missing_jwt_verification"
        for fact in result.facts
    )


def test_map_authorized_code_files_keeps_jwt_gap_after_later_multilang_token_alias_reassignment():
    result = map_authorized_code_files(
        {
            "authorized_code_files": [
                {
                    "path": "ReportsController.java",
                    "content": """
@RestController
public class ReportsController {
  @GetMapping("/reports/{reportId}/export")
  public Object exportReport(String attackerToken, String serviceToken) {
    String selectedToken = attackerToken; DecodedJWT claims = JWT.decode(selectedToken); selectedToken = serviceToken; DecodedJWT verifiedClaims = JWT.verify(selectedToken, verificationKey); return sendFile(claims.getClaim("path").asString());
  }
}
""",
                }
            ]
        }
    )

    assert any(
        fact.fact_type == "authorization_gap_candidate"
        and fact.payload.get("root_cause") == "missing_jwt_verification"
        for fact in result.facts
    )


def test_map_authorized_code_files_does_not_treat_generic_verify_token_as_jwt_validation():
    result = map_authorized_code_files(
        {
            "authorized_code_files": [
                {
                    "path": "apps/api/routes/reports.ts",
                    "content": """
import { Router } from "express";
import jwt from "jsonwebtoken";

const router = Router();

router.get("/reports/:reportId/export", exportReport);

function verifyToken(token: string): boolean {
  return token.length > 3;
}

function verifyJwt(token: string): boolean {
  return token.length > 3;
}

async function exportReport(req: Request, res: Response) {
  const claims = jwt.decode(req.headers.authorization || "");
  verifyToken(req.headers.authorization || "");
  verifyJwt(req.headers.authorization || "");
  return sendFile(claims?.path);
}
""",
                }
            ]
        }
    )

    assert any(
        fact.fact_type == "authorization_gap_candidate"
        and fact.payload.get("root_cause") == "missing_jwt_verification"
        for fact in result.facts
    )


def test_map_authorized_code_files_matches_jwt_token_aliases_before_refuting_gap():
    result = map_authorized_code_files(
        {
            "authorized_code_files": [
                {
                    "path": "apps/api/routes/reports.py",
                    "content": """
from fastapi import APIRouter
import jwt

router = APIRouter()

@router.get("/reports/{report_id}/export")
def export_report(report_id: str, token: str):
    raw_token = token
    claims = jwt.decode(raw_token, options={"verify_signature": False})
    verified_claims = jwt.verify(token, verification_key)
    return send_file(verified_claims["path"])
""",
                }
            ]
        }
    )

    assert not any(
        fact.fact_type == "authorization_gap_candidate"
        and fact.payload.get("root_cause") == "missing_jwt_verification"
        for fact in result.facts
    )


def test_map_authorized_code_files_follows_jwt_decode_to_reachable_local_helper_sink():
    result = map_authorized_code_files(
        {
            "authorized_code_files": [
                {
                    "path": "apps/api/routes/reports.py",
                    "content": """
from fastapi import APIRouter
import jwt

router = APIRouter()

@router.get("/reports/{report_id}/export")
def export_report(report_id: str, token: str):
    claims = jwt.decode(token, options={"verify_signature": False})
    return export_claim_path(claims)

def export_claim_path(claims: dict):
    return send_file(claims["path"])
""",
                }
            ]
        }
    )

    gap = next(
        fact
        for fact in result.facts
        if fact.fact_type == "authorization_gap_candidate"
        and fact.payload.get("root_cause") == "missing_jwt_verification"
    )

    assert gap.symbol_name == "export_report"
    assert gap.payload["decoder_symbols"] == ["jwt.decode"]
    assert gap.payload["sink_symbols"] == ["send_file"]


def test_map_authorized_code_files_uses_python_column_order_for_jwt_and_sink():
    result = map_authorized_code_files(
        {
            "authorized_code_files": [
                {
                    "path": "apps/api/routes/reports.py",
                    "content": """
from fastapi import APIRouter
import jwt

router = APIRouter()

@router.get("/reports/{report_id}/export")
def export_report(report_id: str, token: str):
    claims = jwt.decode(token, options={"verify_signature": False}); return send_file(claims["path"])
""",
                }
            ]
        }
    )

    assert any(
        fact.fact_type == "authorization_gap_candidate"
        and fact.payload.get("root_cause") == "missing_jwt_verification"
        for fact in result.facts
    )


def test_map_authorized_code_files_uses_python_column_order_for_jwt_verification():
    result = map_authorized_code_files(
        {
            "authorized_code_files": [
                {
                    "path": "apps/api/routes/reports.py",
                    "content": """
from fastapi import APIRouter
import jwt

router = APIRouter()

@router.get("/reports/{report_id}/export")
def export_report(report_id: str, token: str):
    claims = jwt.decode(token, options={"verify_signature": False})
    verified_claims = jwt.verify(token, verification_key); return send_file(verified_claims["path"])
""",
                }
            ]
        }
    )

    assert not any(
        fact.fact_type == "authorization_gap_candidate"
        and fact.payload.get("root_cause") == "missing_jwt_verification"
        for fact in result.facts
    )


def test_map_authorized_code_files_uses_typescript_column_order_for_jwt_and_sink():
    result = map_authorized_code_files(
        {
            "authorized_code_files": [
                {
                    "path": "apps/api/routes/reports.ts",
                    "content": """
import { Router } from "express";
import jwt from "jsonwebtoken";

const router = Router();

router.get("/reports/:reportId/export", exportReport);

async function exportReport(req: Request, res: Response) {
  const claims = jwt.decode(req.headers.authorization || ""); return sendFile(claims?.path);
}
""",
                }
            ]
        }
    )

    assert any(
        fact.fact_type == "authorization_gap_candidate"
        and fact.payload.get("root_cause") == "missing_jwt_verification"
        for fact in result.facts
    )


def test_map_authorized_code_files_uses_typescript_column_order_for_jwt_verification():
    result = map_authorized_code_files(
        {
            "authorized_code_files": [
                {
                    "path": "apps/api/routes/reports.ts",
                    "content": """
import { Router } from "express";
import jwt from "jsonwebtoken";

const router = Router();

router.get("/reports/:reportId/export", exportReport);

async function exportReport(req: Request, res: Response) {
  const claims = jwt.decode(req.headers.authorization || "");
  const verifiedClaims = jwt.verify(req.headers.authorization || "", verificationKey); return sendFile(verifiedClaims.path);
}
""",
                }
            ]
        }
    )

    assert not any(
        fact.fact_type == "authorization_gap_candidate"
        and fact.payload.get("root_cause") == "missing_jwt_verification"
        for fact in result.facts
    )



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


def test_map_authorized_code_files_marks_explicit_axios_request_as_ssrf_gap():
    result = map_authorized_code_files(
        {
            "authorized_code_files": [
                {
                    "path": "apps/api/routes/webhooks.ts",
                    "content": """
import axios from "axios";
import { Router } from "express";

const router = Router();

router.post("/webhooks/deliver", deliver_webhook);

async function deliver_webhook(req: Request, res: Response) {
  const target = req.body.subscriberUrl;
  return axios.get(target);
}
""",
                }
            ]
        }
    )

    sink = next(
        fact
        for fact in result.facts
        if fact.fact_type == "sensitive_sink" and fact.symbol_name == "axios_get"
    )
    gap = next(
        fact
        for fact in result.facts
        if fact.fact_type == "authorization_gap_candidate"
    )

    assert sink.payload["input_ref"] == "input:target"
    assert gap.authz_hint == "missing_handler_ssrf_check"
    assert gap.payload["root_cause"] == "missing_ssrf_validation"
    assert "axios_get" in gap.payload["sink_symbols"]


def test_map_authorized_code_files_accepts_matching_ssrf_guard_for_axios():
    result = map_authorized_code_files(
        {
            "authorized_code_files": [
                {
                    "path": "apps/api/routes/webhooks.ts",
                    "content": """
import axios from "axios";
import { Router } from "express";

const router = Router();

router.post("/webhooks/deliver", deliver_webhook);

async function deliver_webhook(req: Request, res: Response) {
  const target = req.body.subscriberUrl;
  validateUrlForSSRF(target);
  return axios.post(target, {});
}
""",
                }
            ]
        }
    )

    ssrf_facts = [
        fact
        for fact in result.facts
        if fact.authz_hint == "ssrf_validation_check"
        or fact.symbol_name == "axios_post"
    ]

    assert {fact.payload.get("input_ref") for fact in ssrf_facts} == {"input:target"}
    assert not any(
        fact.fact_type == "authorization_gap_candidate"
        and fact.payload.get("root_cause") == "missing_ssrf_validation"
        for fact in result.facts
    )


def test_map_authorized_code_files_marks_default_axios_alias_as_ssrf_gap():
    result = map_authorized_code_files(
        {
            "authorized_code_files": [
                {
                    "path": "apps/api/routes/webhooks.ts",
                    "content": """
import outbound from "axios";
import { Router } from "express";

const router = Router();

router.post("/webhooks/deliver", deliver_webhook);

async function deliver_webhook(req: Request, res: Response) {
  return outbound.get(req.body.subscriberUrl);
}
""",
                }
            ]
        }
    )

    sink = next(
        fact
        for fact in result.facts
        if fact.fact_type == "sensitive_sink" and fact.symbol_name == "axios_get"
    )
    gap = next(
        fact
        for fact in result.facts
        if fact.fact_type == "authorization_gap_candidate"
    )

    assert sink.payload["input_ref"] == "input:req.body.subscriberUrl"
    assert gap.authz_hint == "missing_handler_ssrf_check"


def test_map_authorized_code_files_accepts_ssrf_guard_for_require_axios_alias():
    result = map_authorized_code_files(
        {
            "authorized_code_files": [
                {
                    "path": "apps/api/routes/webhooks.ts",
                    "content": """
const outbound: AxiosStatic = require("axios");
import { Router } from "express";

const router = Router();

router.post("/webhooks/deliver", deliver_webhook);

async function deliver_webhook(req: Request, res: Response) {
  const target = req.body.subscriberUrl;
  validateUrlForSSRF(target);
  return outbound.post(target, {});
}
""",
                }
            ]
        }
    )

    ssrf_facts = [
        fact
        for fact in result.facts
        if fact.authz_hint == "ssrf_validation_check"
        or fact.symbol_name == "axios_post"
    ]

    assert {fact.payload.get("input_ref") for fact in ssrf_facts} == {"input:target"}
    assert not any(
        fact.fact_type == "authorization_gap_candidate"
        and fact.payload.get("root_cause") == "missing_ssrf_validation"
        for fact in result.facts
    )


def test_map_authorized_code_files_marks_namespace_axios_alias_as_ssrf_gap():
    result = map_authorized_code_files(
        {
            "authorized_code_files": [
                {
                    "path": "apps/api/routes/webhooks.ts",
                    "content": """
import * as outbound from "axios";
import { Router } from "express";

const router = Router();

router.post("/webhooks/deliver", deliver_webhook);

async function deliver_webhook(req: Request, res: Response) {
  return outbound.put(req.body.subscriberUrl, {});
}
""",
                }
            ]
        }
    )

    assert any(
        fact.fact_type == "sensitive_sink" and fact.symbol_name == "axios_put"
        for fact in result.facts
    )
    assert any(
        fact.fact_type == "authorization_gap_candidate"
        and fact.payload.get("root_cause") == "missing_ssrf_validation"
        for fact in result.facts
    )


@pytest.mark.parametrize(
    ("import_statement", "outbound_call"),
    (
        ('import outboundFetch from "node-fetch";', "outboundFetch(target)"),
        ('import * as outbound from "node-fetch";', "outbound.default(target)"),
        ('import outbound from "got";', "outbound.get(target)"),
        ('import * as outbound from "node:https";', "outbound.request(target)"),
        ('import * as outbound from "undici";', "outbound.fetch(target)"),
        (
            'import { request as outboundRequest } from "undici";',
            "outboundRequest(target)",
        ),
    ),
)
def test_map_authorized_code_files_marks_explicit_http_sdk_alias_as_ssrf_gap(
    import_statement,
    outbound_call,
):
    result = map_authorized_code_files(
        {
            "authorized_code_files": [
                {
                    "path": "apps/api/routes/webhooks.ts",
                    "content": f"""
{import_statement}
import {{ Router }} from "express";

const router = Router();

router.post("/webhooks/deliver", deliver_webhook);

async function deliver_webhook(req: Request, res: Response) {{
  const target = req.body.subscriberUrl;
  return {outbound_call};
}}
""",
                }
            ]
        }
    )

    assert any(
        fact.fact_type == "sensitive_sink" and fact.symbol_name == "fetch"
        for fact in result.facts
    )
    assert any(
        fact.fact_type == "authorization_gap_candidate"
        and fact.payload.get("root_cause") == "missing_ssrf_validation"
        for fact in result.facts
    )


def test_map_authorized_code_files_accepts_ssrf_guard_for_require_got_alias():
    result = map_authorized_code_files(
        {
            "authorized_code_files": [
                {
                    "path": "apps/api/routes/webhooks.ts",
                    "content": """
const outbound = require("got");
import { Router } from "express";

const router = Router();

router.post("/webhooks/deliver", deliver_webhook);

async function deliver_webhook(req: Request, res: Response) {
  const target = req.body.subscriberUrl;
  validateUrlForSSRF(target);
  return outbound.post(target, {});
}
""",
                }
            ]
        }
    )

    assert any(
        fact.fact_type == "sensitive_sink" and fact.symbol_name == "fetch"
        for fact in result.facts
    )
    assert not any(
        fact.fact_type == "authorization_gap_candidate"
        and fact.payload.get("root_cause") == "missing_ssrf_validation"
        for fact in result.facts
    )


def test_map_authorized_code_files_does_not_guess_local_http_client_alias_as_sink():
    result = map_authorized_code_files(
        {
            "authorized_code_files": [
                {
                    "path": "apps/api/routes/webhooks.ts",
                    "content": """
import outbound from "./outbound-client";
import { Router } from "express";

const router = Router();

router.post("/webhooks/deliver", deliver_webhook);

async function deliver_webhook(req: Request, res: Response) {
  return outbound(req.body.subscriberUrl);
}
""",
                }
            ]
        }
    )

    assert not any(
        fact.fact_type == "sensitive_sink" and fact.symbol_name == "fetch"
        for fact in result.facts
    )
    assert not any(
        fact.fact_type == "authorization_gap_candidate"
        and fact.payload.get("root_cause") == "missing_ssrf_validation"
        for fact in result.facts
    )


def test_map_authorized_code_files_does_not_treat_node_fetch_namespace_as_direct_sink():
    result = map_authorized_code_files(
        {
            "authorized_code_files": [
                {
                    "path": "apps/api/routes/webhooks.ts",
                    "content": """
import * as outbound from "node-fetch";
import { Router } from "express";

const router = Router();

router.post("/webhooks/deliver", deliver_webhook);

async function deliver_webhook(req: Request, res: Response) {
  return outbound(req.body.subscriberUrl);
}
""",
                }
            ]
        }
    )

    assert not any(
        fact.fact_type == "sensitive_sink" and fact.symbol_name == "fetch"
        for fact in result.facts
    )
    assert not any(
        fact.fact_type == "authorization_gap_candidate"
        and fact.payload.get("root_cause") == "missing_ssrf_validation"
        for fact in result.facts
    )


@pytest.mark.parametrize(
    ("import_statement", "outbound_call"),
    (
        ("import requests", "requests.get(target)"),
        ("import httpx as outbound", "outbound.post(target, json={})"),
        ("import requests", 'requests.request("GET", target)'),
    ),
)
def test_map_authorized_code_files_marks_explicit_python_http_sdk_as_ssrf_gap(
    import_statement,
    outbound_call,
):
    result = map_authorized_code_files(
        {
            "authorized_code_files": [
                {
                    "path": "apps/api/routes/webhooks.py",
                    "content": f"""
{import_statement}
from fastapi import APIRouter

router = APIRouter()

@router.post("/webhooks/deliver")
def deliver_webhook(target: str):
    return {outbound_call}
""",
                }
            ]
        }
    )

    sink = next(
        fact
        for fact in result.facts
        if fact.fact_type == "sensitive_sink" and fact.symbol_name == "fetch"
    )
    assert sink.payload["input_ref"] == "input:target"
    assert any(
        fact.fact_type == "authorization_gap_candidate"
        and fact.payload.get("root_cause") == "missing_ssrf_validation"
        for fact in result.facts
    )


def test_map_authorized_code_files_accepts_ssrf_guard_for_python_http_sdk_alias():
    result = map_authorized_code_files(
        {
            "authorized_code_files": [
                {
                    "path": "apps/api/routes/webhooks.py",
                    "content": """
import requests as outbound
from fastapi import APIRouter

router = APIRouter()

@router.post("/webhooks/deliver")
def deliver_webhook(target: str):
    validate_url_for_ssrf(target)
    return outbound.post(target, json={})
""",
                }
            ]
        }
    )

    assert any(
        fact.fact_type == "sensitive_sink" and fact.symbol_name == "fetch"
        for fact in result.facts
    )
    assert not any(
        fact.fact_type == "authorization_gap_candidate"
        and fact.payload.get("root_cause") == "missing_ssrf_validation"
        for fact in result.facts
    )


def test_map_authorized_code_files_does_not_guess_python_http_client_alias_as_sink():
    result = map_authorized_code_files(
        {
            "authorized_code_files": [
                {
                    "path": "apps/api/routes/webhooks.py",
                    "content": """
import local_client as outbound
from fastapi import APIRouter

router = APIRouter()

@router.post("/webhooks/deliver")
def deliver_webhook(target: str):
    return outbound.request("GET", target)
""",
                }
            ]
        }
    )

    assert not any(
        fact.fact_type == "sensitive_sink" and fact.symbol_name == "fetch"
        for fact in result.facts
    )
    assert not any(
        fact.fact_type == "authorization_gap_candidate"
        and fact.payload.get("root_cause") == "missing_ssrf_validation"
        for fact in result.facts
    )


def test_map_authorized_code_files_does_not_guess_generic_get_as_http_sink():
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
  return client.get(target);
}
""",
                }
            ]
        }
    )

    assert not any(
        fact.fact_type == "sensitive_sink" and fact.symbol_name == "axios_get"
        for fact in result.facts
    )
    assert not any(
        fact.fact_type == "authorization_gap_candidate"
        and fact.payload.get("root_cause") == "missing_ssrf_validation"
        for fact in result.facts
    )


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
    assert any(
        gap.payload["root_cause"] == "missing_ssrf_validation" for gap in gaps
    )


def test_map_authorized_code_files_keeps_ssrf_gap_when_guard_validates_different_typescript_input():
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
  const serviceTarget = req.body.serviceUrl;
  const attackerTarget = req.body.callbackUrl;
  validateUrlForSSRF(serviceTarget);
  return fetch(attackerTarget);
}
""",
                }
            ]
        }
    )

    guard = next(
        fact
        for fact in result.facts
        if fact.fact_type == "authz_check"
        and fact.authz_hint == "ssrf_validation_check"
    )
    sink = next(
        fact
        for fact in result.facts
        if fact.fact_type == "sensitive_sink" and fact.symbol_name == "fetch"
    )

    assert guard.payload["input_ref"] == "input:serviceTarget"
    assert sink.payload["input_ref"] == "input:attackerTarget"
    assert any(
        fact.fact_type == "authorization_gap_candidate"
        and fact.payload.get("root_cause") == "missing_ssrf_validation"
        for fact in result.facts
    )


def test_map_authorized_code_files_keeps_ssrf_gap_when_guard_validates_different_python_input():
    result = map_authorized_code_files(
        {
            "authorized_code_files": [
                {
                    "path": "apps/api/routes/webhooks.py",
                    "content": """
from fastapi import APIRouter

router = APIRouter()

@router.post("/webhooks/deliver")
def deliver_webhook(service_url: str, attacker_url: str):
    validate_outbound_url(service_url)
    return fetch(attacker_url)
""",
                }
            ]
        }
    )

    guard = next(
        fact
        for fact in result.facts
        if fact.fact_type == "authz_check"
        and fact.authz_hint == "ssrf_validation_check"
    )
    sink = next(
        fact
        for fact in result.facts
        if fact.fact_type == "sensitive_sink" and fact.symbol_name == "fetch"
    )

    assert guard.payload["input_ref"] == "input:service_url"
    assert sink.payload["input_ref"] == "input:attacker_url"
    assert any(
        fact.fact_type == "authorization_gap_candidate"
        and fact.payload.get("root_cause") == "missing_ssrf_validation"
        for fact in result.facts
    )


def test_map_authorized_code_files_requires_ssrf_guard_for_every_outbound_input():
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
  const serviceTarget = req.body.serviceUrl;
  const attackerTarget = req.body.callbackUrl;
  validateUrlForSSRF(serviceTarget);
  await fetch(serviceTarget);
  return fetch(attackerTarget);
}
""",
                }
            ]
        }
    )

    assert any(
        fact.fact_type == "authorization_gap_candidate"
        and fact.payload.get("root_cause") == "missing_ssrf_validation"
        for fact in result.facts
    )


def test_map_authorized_code_files_keeps_ssrf_gap_for_unmapped_service_call_input():
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
  const url = req.body.serviceUrl;
  validateUrlForSSRF(url);
  return fetch_remote(req.body.callbackUrl);
}

async function fetch_remote(url: string) {
  return fetch(url);
}
""",
                }
            ]
        }
    )

    assert any(
        fact.fact_type == "authorization_gap_candidate"
        and fact.payload.get("root_cause") == "missing_ssrf_validation"
        for fact in result.facts
    )


def test_map_authorized_code_files_multilang_keeps_every_outbound_ssrf_input():
    result = map_authorized_code_files(
        {
            "authorized_code_files": [
                {
                    "path": "WebhookController.java",
                    "content": """
@PostMapping("/webhooks/deliver")
public Object deliver(String serviceUrl, String callbackUrl) {
  validateUrlForSSRF(serviceUrl);
  fetch(serviceUrl); return fetch(callbackUrl);
}
""",
                }
            ]
        }
    )

    sink_input_refs = {
        fact.payload.get("input_ref")
        for fact in result.facts
        if fact.fact_type == "sensitive_sink" and fact.symbol_name == "fetch"
    }

    assert sink_input_refs == {"input:serviceUrl", "input:callbackUrl"}
    assert any(
        fact.fact_type == "authorization_gap_candidate"
        and fact.payload.get("root_cause") == "missing_ssrf_validation"
        for fact in result.facts
    )


def test_map_authorized_code_files_keeps_ssrf_gap_after_python_input_reassignment():
    result = map_authorized_code_files(
        {
            "authorized_code_files": [
                {
                    "path": "apps/api/routes/webhooks.py",
                    "content": """
from fastapi import APIRouter

router = APIRouter()

@router.post("/webhooks/deliver")
def deliver_webhook(service_url: str, callback_url: str):
    url = service_url
    validate_outbound_url(url)
    url = callback_url
    return fetch(url)
""",
                }
            ]
        }
    )

    assert any(
        fact.fact_type == "authorization_gap_candidate"
        and fact.payload.get("root_cause") == "missing_ssrf_validation"
        for fact in result.facts
    )


def test_map_authorized_code_files_keeps_ssrf_gap_after_typescript_input_reassignment():
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
  let url: string = req.body.serviceUrl;
  validateUrlForSSRF(url);
  url = req.body.callbackUrl;
  return fetch(url);
}
""",
                }
            ]
        }
    )

    assert any(
        fact.fact_type == "authorization_gap_candidate"
        and fact.payload.get("root_cause") == "missing_ssrf_validation"
        for fact in result.facts
    )


def test_map_authorized_code_files_keeps_ssrf_gap_after_multilang_input_reassignment():
    result = map_authorized_code_files(
        {
            "authorized_code_files": [
                {
                    "path": "WebhookController.java",
                    "content": """
@PostMapping("/webhooks/deliver")
public Object deliver(String serviceUrl, String callbackUrl) {
  String url = serviceUrl;
  validateUrlForSSRF(url);
  url = callbackUrl;
  return fetch(url);
}
""",
                }
            ]
        }
    )

    assert any(
        fact.fact_type == "authorization_gap_candidate"
        and fact.payload.get("root_cause") == "missing_ssrf_validation"
        for fact in result.facts
    )


def test_map_authorized_code_files_keeps_ssrf_gap_after_input_attribute_mutation():
    result = map_authorized_code_files(
        {
            "authorized_code_files": [
                {
                    "path": "apps/api/routes/webhooks.py",
                    "content": """
from fastapi import APIRouter

router = APIRouter()

@router.post("/webhooks/deliver")
def deliver_python(target):
    validate_outbound_url(target.service_url)
    target.service_url = target.callback_url
    return fetch(target.service_url)
""",
                },
                {
                    "path": "apps/api/routes/webhooks.ts",
                    "content": """
import { Router } from "express";

const router = Router();

router.post("/webhooks/deliver", deliver_typescript);

async function deliver_typescript(req: Request, res: Response) {
  const target = req.body;
  validateUrlForSSRF(target.serviceUrl);
  target.serviceUrl = target.callbackUrl;
  return fetch(target.serviceUrl);
}
""",
                },
                {
                    "path": "WebhookController.java",
                    "content": """
@PostMapping("/webhooks/deliver")
public Object deliverJava(Target target) {
  validateUrlForSSRF(target.serviceUrl);
  target.serviceUrl = target.callbackUrl;
  return fetch(target.serviceUrl);
}
""",
                },
            ]
        }
    )

    gap_paths = {
        fact.source_path
        for fact in result.facts
        if fact.fact_type == "authorization_gap_candidate"
        and fact.payload.get("root_cause") == "missing_ssrf_validation"
    }

    assert gap_paths == {
        "apps/api/routes/webhooks.py",
        "apps/api/routes/webhooks.ts",
        "WebhookController.java",
    }


def test_map_authorized_code_files_keeps_ssrf_gap_after_loop_input_binding():
    result = map_authorized_code_files(
        {
            "authorized_code_files": [
                {
                    "path": "apps/api/routes/webhooks.py",
                    "content": """
from fastapi import APIRouter

router = APIRouter()

@router.post("/webhooks/deliver")
def deliver_python(url: str, callback_urls: list[str]):
    validate_outbound_url(url)
    for url in callback_urls:
        return fetch(url)
""",
                },
                {
                    "path": "apps/api/routes/webhooks.ts",
                    "content": """
import { Router } from "express";

const router = Router();

router.post("/webhooks/deliver", deliver_typescript);

async function deliver_typescript(req: Request, res: Response) {
  let url = req.body.serviceUrl;
  validateUrlForSSRF(url);
  for (url of req.body.callbackUrls) {
    return fetch(url);
  }
}
""",
                },
                {
                    "path": "proxy.go",
                    "content": """
func mount(r Router) { r.POST("/webhooks/deliver", proxy) }
func proxy() {
  validateUrlForSSRF(url)
  for _, url := range callbackUrls {
    fetch(url)
  }
}
""",
                },
            ]
        }
    )

    gap_paths = {
        fact.source_path
        for fact in result.facts
        if fact.fact_type == "authorization_gap_candidate"
        and fact.payload.get("root_cause") == "missing_ssrf_validation"
    }

    assert gap_paths == {
        "apps/api/routes/webhooks.py",
        "apps/api/routes/webhooks.ts",
        "proxy.go",
    }


def test_map_authorized_code_files_accepts_initial_typescript_destructuring_ssrf_control():
    result = map_authorized_code_files(
        {
            "authorized_code_files": [
                {
                    "path": "apps/api/routes/webhooks.ts",
                    "content": """
import { Router } from "express";

const router = Router();

router.post("/webhooks/object", deliver_object);
router.post("/webhooks/array", deliver_array);

async function deliver_object(req: Request, res: Response) {
  const { url } = req.body;
  validateUrlForSSRF(url);
  return fetch(url);
}

async function deliver_array(req: Request, res: Response) {
  const [url] = req.body.urls;
  validateUrlForSSRF(url);
  return fetch(url);
}
""",
                }
            ]
        }
    )

    ssrf_facts = [
        fact
        for fact in result.facts
        if fact.authz_hint == "ssrf_validation_check" or fact.symbol_name == "fetch"
    ]

    assert {fact.payload.get("input_ref") for fact in ssrf_facts} == {"input:url"}
    assert not any(
        fact.fact_type == "authorization_gap_candidate"
        and fact.payload.get("root_cause") == "missing_ssrf_validation"
        for fact in result.facts
    )


def test_map_authorized_code_files_keeps_ssrf_gap_after_typescript_destructuring_rebinding():
    result = map_authorized_code_files(
        {
            "authorized_code_files": [
                {
                    "path": "apps/api/routes/webhooks.ts",
                    "content": """
import { Router } from "express";

const router = Router();

router.post("/webhooks/object", deliver_object);
router.post("/webhooks/array", deliver_array);

async function deliver_object(req: Request, res: Response) {
  let url = req.body.serviceUrl;
  validateUrlForSSRF(url);
  ({ callback: { url } } = req.body);
  return fetch(url);
}

async function deliver_array(req: Request, res: Response) {
  let url = req.body.serviceUrl;
  validateUrlForSSRF(url);
  [url] = req.body.callbackUrls;
  return fetch(url);
}
""",
                }
            ]
        }
    )

    gap_routes = {
        fact.route_path
        for fact in result.facts
        if fact.fact_type == "authorization_gap_candidate"
        and fact.payload.get("root_cause") == "missing_ssrf_validation"
    }

    assert gap_routes == {"/webhooks/object", "/webhooks/array"}


def test_map_authorized_code_files_keeps_inline_typescript_control_scoped_to_its_statement():
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
  if (req.body.audit) recordAudit();
  validateUrlForSSRF(req.body.url);
  return fetch(req.body.url);
}
""",
                }
            ]
        }
    )

    ssrf_facts = [
        fact
        for fact in result.facts
        if fact.authz_hint == "ssrf_validation_check" or fact.symbol_name == "fetch"
    ]

    assert {fact.payload.get("input_ref") for fact in ssrf_facts} == {"input:req.body.url"}
    assert not any(
        fact.fact_type == "authorization_gap_candidate"
        and fact.payload.get("root_cause") == "missing_ssrf_validation"
        for fact in result.facts
    )


def test_map_authorized_code_files_keeps_ssrf_gap_after_go_tuple_rebinding():
    result = map_authorized_code_files(
        {
            "authorized_code_files": [
                {
                    "path": "proxy.go",
                    "content": """
func mount(r Router) { r.POST("/webhooks/deliver", proxy) }
func proxy(url string, callbackUrl string) {
  validateUrlForSSRF(url)
  url, err := callbackUrl, error(nil)
  fetch(url)
}
""",
                }
            ]
        }
    )

    assert any(
        fact.fact_type == "authorization_gap_candidate"
        and fact.payload.get("root_cause") == "missing_ssrf_validation"
        for fact in result.facts
    )


def test_map_authorized_code_files_accepts_go_initial_short_tuple_declaration_ssrf_control():
    result = map_authorized_code_files(
        {
            "authorized_code_files": [
                {
                    "path": "proxy.go",
                    "content": """
func mount(r Router) { r.POST("/webhooks/deliver", proxy) }
func proxy(requestUrl string) {
  url, err := requestUrl, error(nil)
  validateUrlForSSRF(url)
  fetch(url)
}
""",
                }
            ]
        }
    )

    assert not any(
        fact.fact_type == "authorization_gap_candidate"
        and fact.payload.get("root_cause") == "missing_ssrf_validation"
        for fact in result.facts
    )


def test_map_authorized_code_files_keeps_ssrf_gap_after_python_match_capture_rebinding():
    result = map_authorized_code_files(
        {
            "authorized_code_files": [
                {
                    "path": "apps/api/routes/webhooks.py",
                    "content": """
from fastapi import APIRouter

router = APIRouter()

@router.post("/webhooks/deliver")
def deliver_webhook(url: str, payload: dict):
    validate_outbound_url(url)
    match payload:
        case {"callback_url": url}:
            pass
    return fetch(url)
""",
                }
            ]
        }
    )

    assert any(
        fact.fact_type == "authorization_gap_candidate"
        and fact.payload.get("root_cause") == "missing_ssrf_validation"
        for fact in result.facts
    )


def test_map_authorized_code_files_treats_typescript_sink_helper_control_as_covered():
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
  return deliver_safe(req.body.subscriberUrl);
}

async function deliver_safe(url: string) {
  validateUrlForSSRF(url);
  return fetch(url);
}
""",
                }
            ]
        }
    )

    assert any(
        fact.fact_type == "authz_check"
        and fact.authz_hint == "ssrf_validation_check"
        and fact.payload["handler"] == "deliver_safe"
        for fact in result.facts
    )
    assert not any(
        fact.fact_type == "authorization_gap_candidate"
        and fact.payload.get("root_cause") == "missing_ssrf_validation"
        for fact in result.facts
    )


def test_map_authorized_code_files_keeps_ssrf_gap_when_guard_follows_service_sink():
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
  await dispatch_webhook(req.body.subscriberUrl);
  validateUrlForSSRF(req.body.subscriberUrl);
  return res.sendStatus(204);
}

async function dispatch_webhook(target: string) {
  return fetch(target);
}
""",
                }
            ]
        }
    )

    gaps = [
        fact
        for fact in result.facts
        if fact.fact_type == "authorization_gap_candidate"
    ]

    assert len(gaps) == 1
    assert gaps[0].payload["root_cause"] == "missing_ssrf_validation"


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


@pytest.mark.parametrize(
    ("path", "content", "sink_symbol"),
    [
        (
            "ProxyController.java",
            """
@PostMapping("/webhooks")
public Object proxy(String url) {
  return restTemplate.getForObject(url, String.class);
}
""",
            "rest_template_get_for_object",
        ),
        (
            "proxy.go",
            """
func mount(r Router) { r.POST("/webhooks", proxy) }
func proxy(url string) { http.Get(url) }
""",
            "http_get",
        ),
        (
            "ProxyController.cs",
            """
[HttpPost("/webhooks")]
public IActionResult Proxy(string url) {
  return _httpClient.GetAsync(url);
}
""",
            "http_client_get_async",
        ),
    ],
)
def test_map_authorized_code_files_maps_explicit_http_sdk_calls_as_ssrf_sinks(
    path,
    content,
    sink_symbol,
):
    result = map_authorized_code_files(
        {"authorized_code_files": [{"path": path, "content": content}]}
    )

    sink = next(
        fact
        for fact in result.facts
        if fact.fact_type == "sensitive_sink" and fact.symbol_name == sink_symbol
    )

    assert sink.payload["input_ref"] == "input:url"
    assert any(
        fact.fact_type == "authorization_gap_candidate"
        and fact.payload.get("root_cause") == "missing_ssrf_validation"
        for fact in result.facts
    )


@pytest.mark.parametrize(
    ("path", "content"),
    [
        (
            "ProxyController.java",
            """
@PostMapping("/webhooks")
public Object proxy(String url) {
  validateUrl(url);
  return restTemplate.getForEntity(url, String.class);
}
""",
        ),
        (
            "proxy.go",
            """
func mount(r Router) { r.POST("/webhooks", proxy) }
func proxy(url string) {
  validateUrl(url)
  http.Post(url, "application/json", body)
}
""",
        ),
        (
            "ProxyController.cs",
            """
[HttpPost("/webhooks")]
public IActionResult Proxy(string url) {
  ValidateUrl(url);
  return _httpClient.PostAsync(url, body);
}
""",
        ),
    ],
)
def test_map_authorized_code_files_refutes_explicit_http_sdk_sink_with_matching_guard(
    path,
    content,
):
    result = map_authorized_code_files(
        {"authorized_code_files": [{"path": path, "content": content}]}
    )

    assert not any(
        fact.fact_type == "authorization_gap_candidate"
        and fact.payload.get("root_cause") == "missing_ssrf_validation"
        for fact in result.facts
    )


def test_map_authorized_code_files_does_not_guess_generic_client_method_as_http_sdk():
    result = map_authorized_code_files(
        {
            "authorized_code_files": [
                {
                    "path": "ProxyController.cs",
                    "content": """
[HttpPost("/webhooks")]
public IActionResult Proxy(string url) {
  return client.GetAsync(url);
}
""",
                }
            ]
        }
    )

    assert not any(
        fact.fact_type == "sensitive_sink"
        and fact.symbol_name == "http_client_get_async"
        for fact in result.facts
    )
    assert not any(
        fact.fact_type == "authorization_gap_candidate"
        and fact.payload.get("root_cause") == "missing_ssrf_validation"
        for fact in result.facts
    )


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


def test_map_authorized_code_files_marks_exec_without_command_guard_as_gap_candidate():
    result = map_authorized_code_files(
        {
            "authorized_code_files": [
                {
                    "path": "apps/api/routes/maintenance.ts",
                    "content": """
import { Router } from "express";

const router = Router();

router.post("/maintenance/run", run_maintenance);

async function run_maintenance(req: Request, res: Response) {
  return exec(req.body.command);
}
""",
                }
            ]
        }
    )

    gap = next(
        fact for fact in result.facts if fact.fact_type == "authorization_gap_candidate"
    )

    assert gap.symbol_name == "run_maintenance"
    assert gap.authz_hint == "missing_handler_command_injection_check"
    assert gap.payload["root_cause"] == "missing_command_injection_validation"
    assert "exec" in gap.payload["sink_symbols"]


@pytest.mark.parametrize(
    ("source_path", "source_code", "expected_guard"),
    (
        (
            "apps/api/routes/maintenance.ts",
            """
import { Router } from "express";

const router = Router();

router.post("/maintenance/run", run_maintenance);

function commandAllowlist(command: string) {
  return command;
}

async function run_maintenance(req: Request, res: Response) {
  const command = commandAllowlist(req.body.command);
  return exec(command);
}
""",
            "commandAllowlist",
        ),
        (
            "apps/api/routes/maintenance.py",
            """
from fastapi import APIRouter

router = APIRouter()

@router.post("/maintenance/run")
def run_maintenance(command: str):
    safe_command = validate_command(command)
    return system(safe_command)
""",
            "validate_command",
        ),
    ),
)
def test_map_authorized_code_files_treats_command_validation_as_control(
    source_path,
    source_code,
    expected_guard,
):
    result = map_authorized_code_files(
        {"authorized_code_files": [{"path": source_path, "content": source_code}]}
    )

    authz = next(
        fact
        for fact in result.facts
        if fact.fact_type == "authz_check"
        and fact.authz_hint == "command_injection_validation_check"
    )

    assert authz.symbol_name == expected_guard
    assert any(fact.fact_type == "sensitive_sink" for fact in result.facts)


@pytest.mark.parametrize(
    ("route_path", "parameters", "guard_call", "sink_call", "root_cause"),
    (
        (
            "/media/read",
            "safe_path: str, attacker_path: str",
            "safe_join(safe_path)",
            "read_file(attacker_path)",
            "missing_path_validation",
        ),
        (
            "/users/update",
            "safe_body: dict, attacker_body: dict",
            "forbid_privilege_fields(safe_body)",
            'update_user("record", attacker_body)',
            "missing_mass_assignment_guard",
        ),
        (
            "/users/persist",
            "safe_body: dict, attacker_body: dict",
            "forbid_privilege_fields(safe_body)",
            'persist_user("record", attacker_body)',
            "missing_mass_assignment_guard",
        ),
        (
            "/search",
            "safe_query: str, attacker_query: str",
            "parameterize(safe_query)",
            "run_sql(attacker_query)",
            "missing_injection_validation",
        ),
        (
            "/maintenance/run",
            "safe_command: str, attacker_command: str",
            "validate_command(safe_command)",
            "system(attacker_command)",
            "missing_command_injection_validation",
        ),
        (
            "/imports/profile",
            "safe_payload: bytes, attacker_payload: bytes",
            "validate_serialized_payload(safe_payload)",
            "pickle.loads(attacker_payload)",
            "missing_unsafe_deserialization_guard",
        ),
        (
            "/uploads",
            "safe_document: bytes, attacker_document: bytes",
            "validate_upload(safe_document)",
            "save_upload(attacker_document)",
            "missing_file_upload_validation",
        ),
    ),
)
def test_map_authorized_code_files_keeps_input_bound_gap_for_different_guard_input(
    route_path,
    parameters,
    guard_call,
    sink_call,
    root_cause,
):
    result = map_authorized_code_files(
        {
            "authorized_code_files": [
                {
                    "path": "apps/api/routes/input_binding.py",
                    "content": f'''
import pickle

from fastapi import APIRouter

router = APIRouter()

@router.post("{route_path}")
def handle({parameters}):
    {guard_call}
    return {sink_call}
''',
                }
            ]
        }
    )

    assert any(
        fact.fact_type == "authorization_gap_candidate"
        and fact.payload.get("root_cause") == root_cause
        for fact in result.facts
    )


def test_map_authorized_code_files_closes_command_gap_for_same_validated_input():
    result = map_authorized_code_files(
        {
            "authorized_code_files": [
                {
                    "path": "apps/api/routes/maintenance.py",
                    "content": '''
from fastapi import APIRouter

router = APIRouter()

@router.post("/maintenance/run")
def run_maintenance(command: str):
    validate_command(command)
    return system(command)
''',
                }
            ]
        }
    )

    assert not any(
        fact.fact_type == "authorization_gap_candidate"
        and fact.payload.get("root_cause") == "missing_command_injection_validation"
        for fact in result.facts
    )


def test_map_authorized_code_files_accepts_validated_command_result_binding():
    result = map_authorized_code_files(
        {
            "authorized_code_files": [
                {
                    "path": "apps/api/routes/maintenance.py",
                    "content": '''
from fastapi import APIRouter

router = APIRouter()

@router.post("/maintenance/run")
def run_maintenance(command: str):
    safe_command = validate_command(command)
    return system(safe_command)
''',
                }
            ]
        }
    )

    assert not any(
        fact.fact_type == "authorization_gap_candidate"
        and fact.payload.get("root_cause") == "missing_command_injection_validation"
        for fact in result.facts
    )


def test_map_authorized_code_files_keeps_command_gap_when_validation_follows_sink():
    result = map_authorized_code_files(
        {
            "authorized_code_files": [
                {
                    "path": "apps/api/routes/maintenance.py",
                    "content": '''
from fastapi import APIRouter

router = APIRouter()

@router.post("/maintenance/run")
def run_maintenance(command: str):
    result = system(command)
    validate_command(command)
    return result
''',
                }
            ]
        }
    )

    assert any(
        fact.fact_type == "authorization_gap_candidate"
        and fact.payload.get("root_cause") == "missing_command_injection_validation"
        for fact in result.facts
    )


def test_map_authorized_code_files_keeps_typescript_command_gap_for_different_input():
    result = map_authorized_code_files(
        {
            "authorized_code_files": [
                {
                    "path": "apps/api/routes/maintenance.ts",
                    "content": '''
import { Router } from "express";

const router = Router();

router.post("/maintenance/run", runMaintenance);

async function runMaintenance(req: Request, res: Response) {
  const safeCommand = req.body.safeCommand;
  const attackerCommand = req.body.attackerCommand;
  validateCommand(safeCommand);
  return exec(attackerCommand);
}
''',
                }
            ]
        }
    )

    assert any(
        fact.fact_type == "authorization_gap_candidate"
        and fact.payload.get("root_cause") == "missing_command_injection_validation"
        for fact in result.facts
    )


@pytest.mark.parametrize(
    ("route_path", "sink", "wrong_guard", "root_cause"),
    (
        ("/webhooks/deliver", "fetch", "validate_command", "missing_ssrf_validation"),
        ("/media/{filepath}", "read_file", "validate_command", "missing_path_validation"),
        ("/users/{user_id}", "update_user", "validate_command", "missing_mass_assignment_guard"),
        ("/search", "run_sql", "validate_command", "missing_injection_validation"),
        ("/maintenance/run", "system", "parameterize", "missing_command_injection_validation"),
        ("/imports", "pickle_loads", "validate_command", "missing_unsafe_deserialization_guard"),
        ("/uploads", "save_upload", "validate_command", "missing_file_upload_validation"),
        ("/payments", "charge_card", "validate_command", "missing_server_authoritative_amount_check"),
        ("/redemptions", "consume_one_time_token", "validate_command", "missing_transactional_state_guard"),
        ("/agents/{agent_id}/tools/execute", "execute_agent_tool", "validate_command", "missing_agent_tool_authorization_check"),
    ),
)
def test_map_authorized_code_files_requires_a_matching_static_gap_control(
    route_path,
    sink,
    wrong_guard,
    root_cause,
):
    result = map_authorized_code_files(
        {
            "authorized_code_files": [
                {
                    "path": "apps/api/routes/semantic_gaps.py",
                    "content": f'''
from fastapi import APIRouter

router = APIRouter()

@router.post("{route_path}")
def handle(value: str):
    {wrong_guard}(value)
    return {sink}(value)
''',
                }
            ]
        }
    )

    assert any(
        fact.fact_type == "authz_check" and fact.symbol_name == wrong_guard
        for fact in result.facts
    )
    assert any(
        fact.fact_type == "authorization_gap_candidate"
        and fact.payload.get("root_cause") == root_cause
        for fact in result.facts
    )


def test_map_authorized_code_files_marks_pickle_loads_without_guard_as_gap_candidate():
    result = map_authorized_code_files(
        {
            "authorized_code_files": [
                {
                    "path": "apps/api/routes/imports.py",
                    "content": """
import pickle

from fastapi import APIRouter

router = APIRouter()

@router.post("/imports/profile")
def import_profile(serialized_payload: bytes):
    return pickle.loads(serialized_payload)
""",
                }
            ]
        }
    )

    gap = next(
        fact for fact in result.facts if fact.fact_type == "authorization_gap_candidate"
    )

    assert gap.symbol_name == "import_profile"
    assert gap.authz_hint == "missing_handler_deserialization_check"
    assert gap.payload["root_cause"] == "missing_unsafe_deserialization_guard"
    assert "pickle_loads" in gap.payload["sink_symbols"]


def test_map_authorized_code_files_marks_yaml_load_without_safe_loader_as_gap_candidate():
    result = map_authorized_code_files(
        {
            "authorized_code_files": [
                {
                    "path": "apps/api/routes/imports.py",
                    "content": """
import yaml

from fastapi import APIRouter

router = APIRouter()

@router.post("/imports/profile")
def import_profile(serialized_payload: bytes):
    return yaml.load(serialized_payload)
""",
                }
            ]
        }
    )

    gap = next(
        fact for fact in result.facts if fact.fact_type == "authorization_gap_candidate"
    )

    assert gap.symbol_name == "import_profile"
    assert gap.authz_hint == "missing_handler_deserialization_check"
    assert gap.payload["root_cause"] == "missing_unsafe_deserialization_guard"
    assert "yaml_load" in gap.payload["sink_symbols"]


def test_map_authorized_code_files_marks_imported_yaml_load_alias_as_gap_candidate():
    result = map_authorized_code_files(
        {
            "authorized_code_files": [
                {
                    "path": "apps/api/routes/imports.py",
                    "content": """
from fastapi import APIRouter
from yaml import load as yaml_load

router = APIRouter()

@router.post("/imports/profile")
def import_profile(serialized_payload: bytes):
    return yaml_load(serialized_payload)
""",
                }
            ]
        }
    )

    gap = next(
        fact for fact in result.facts if fact.fact_type == "authorization_gap_candidate"
    )

    assert gap.symbol_name == "import_profile"
    assert gap.authz_hint == "missing_handler_deserialization_check"
    assert gap.payload["root_cause"] == "missing_unsafe_deserialization_guard"
    assert "yaml_load" in gap.payload["sink_symbols"]


def test_map_authorized_code_files_marks_yaml_module_alias_as_gap_candidate():
    result = map_authorized_code_files(
        {
            "authorized_code_files": [
                {
                    "path": "apps/api/routes/imports.py",
                    "content": """
import yaml as config_yaml

from fastapi import APIRouter

router = APIRouter()

@router.post("/imports/profile")
def import_profile(serialized_payload: bytes):
    return config_yaml.load(serialized_payload)
""",
                }
            ]
        }
    )

    gap = next(
        fact for fact in result.facts if fact.fact_type == "authorization_gap_candidate"
    )

    assert gap.symbol_name == "import_profile"
    assert gap.authz_hint == "missing_handler_deserialization_check"
    assert gap.payload["root_cause"] == "missing_unsafe_deserialization_guard"
    assert "yaml_load" in gap.payload["sink_symbols"]


def test_map_authorized_code_files_treats_yaml_safe_loader_as_deserialization_control():
    result = map_authorized_code_files(
        {
            "authorized_code_files": [
                {
                    "path": "apps/api/routes/imports.py",
                    "content": """
import yaml

from fastapi import APIRouter

router = APIRouter()

@router.post("/imports/profile")
def import_profile(serialized_payload: bytes):
    return yaml.load(serialized_payload, Loader=yaml.SafeLoader)
""",
                }
            ]
        }
    )

    authz = next(
        fact
        for fact in result.facts
        if fact.fact_type == "authz_check"
        and fact.authz_hint == "deserialization_validation_check"
    )

    assert authz.symbol_name == "yaml_safe_loader"
    assert not any(fact.fact_type == "sensitive_sink" for fact in result.facts)
    assert not any(
        fact.fact_type == "authorization_gap_candidate" for fact in result.facts
    )


def test_map_authorized_code_files_treats_imported_yaml_safe_loader_as_control():
    result = map_authorized_code_files(
        {
            "authorized_code_files": [
                {
                    "path": "apps/api/routes/imports.py",
                    "content": """
from fastapi import APIRouter
from yaml import SafeLoader, load as yaml_load

router = APIRouter()

@router.post("/imports/profile")
def import_profile(serialized_payload: bytes):
    return yaml_load(serialized_payload, Loader=SafeLoader)
""",
                }
            ]
        }
    )

    authz = next(
        fact
        for fact in result.facts
        if fact.fact_type == "authz_check"
        and fact.authz_hint == "deserialization_validation_check"
    )

    assert authz.symbol_name == "yaml_safe_loader"
    assert not any(fact.fact_type == "sensitive_sink" for fact in result.facts)
    assert not any(
        fact.fact_type == "authorization_gap_candidate" for fact in result.facts
    )


def test_map_authorized_code_files_does_not_accept_yaml_safe_loader_comment_as_control():
    result = map_authorized_code_files(
        {
            "authorized_code_files": [
                {
                    "path": "apps/api/routes/imports.py",
                    "content": """
import yaml

from fastapi import APIRouter

router = APIRouter()

@router.post("/imports/profile")
def import_profile(serialized_payload: bytes):
    return yaml.load(serialized_payload)  # Loader=yaml.SafeLoader
""",
                }
            ]
        }
    )

    gap = next(
        fact for fact in result.facts if fact.fact_type == "authorization_gap_candidate"
    )

    assert gap.payload["root_cause"] == "missing_unsafe_deserialization_guard"


def test_map_authorized_code_files_does_not_accept_unrelated_yaml_safe_loader_as_control():
    result = map_authorized_code_files(
        {
            "authorized_code_files": [
                {
                    "path": "apps/api/routes/imports.py",
                    "content": """
import yaml

from fastapi import APIRouter

router = APIRouter()

@router.post("/imports/profile")
def import_profile(serialized_payload: bytes):
    return yaml.load(serialized_payload); audit(Loader=yaml.SafeLoader)
""",
                }
            ]
        }
    )

    gap = next(
        fact for fact in result.facts if fact.fact_type == "authorization_gap_candidate"
    )

    assert gap.payload["root_cause"] == "missing_unsafe_deserialization_guard"


def test_map_authorized_code_files_requires_qualified_yaml_safe_loader_control():
    result = map_authorized_code_files(
        {
            "authorized_code_files": [
                {
                    "path": "apps/api/routes/imports.py",
                    "content": """
import yaml
from custom_loader import SafeLoader

from fastapi import APIRouter

router = APIRouter()

@router.post("/imports/profile")
def import_profile(serialized_payload: bytes):
    return yaml.load(serialized_payload, Loader=SafeLoader)
""",
                }
            ]
        }
    )

    gap = next(
        fact for fact in result.facts if fact.fact_type == "authorization_gap_candidate"
    )

    assert gap.payload["root_cause"] == "missing_unsafe_deserialization_guard"


@pytest.mark.parametrize("parser_call", ("json.loads", "yaml.safe_load"))
def test_map_authorized_code_files_does_not_treat_standard_parsers_as_unsafe_sinks(
    parser_call,
):
    result = map_authorized_code_files(
        {
            "authorized_code_files": [
                {
                    "path": "apps/api/routes/imports.py",
                    "content": f"""
from fastapi import APIRouter

router = APIRouter()

@router.post(\"/imports/profile\")
def import_profile(serialized_payload: bytes):
    return {parser_call}(serialized_payload)
""",
                }
            ]
        }
    )

    assert not any(fact.fact_type == "sensitive_sink" for fact in result.facts)
    assert not any(
        fact.fact_type == "authorization_gap_candidate" for fact in result.facts
    )


@pytest.mark.parametrize(
    ("source_path", "source_code", "expected_guard"),
    (
        (
            "apps/api/routes/imports.py",
            """
import pickle

from fastapi import APIRouter

router = APIRouter()

@router.post("/imports/profile")
def import_profile(serialized_payload: bytes):
    safe_payload = validate_serialized_payload(serialized_payload)
    return pickle.loads(safe_payload)
""",
            "validate_serialized_payload",
        ),
        (
            "apps/api/routes/imports.ts",
            """
import { Router } from "express";

const router = Router();

router.post("/imports/profile", importProfile);

function validateSerializedPayload(payload: string) {
  return payload;
}

async function importProfile(req: Request, res: Response) {
  const payload = validateSerializedPayload(req.body.payload);
  return unsafeDeserialize(payload);
}
""",
            "validateSerializedPayload",
        ),
    ),
)
def test_map_authorized_code_files_treats_deserialization_validation_as_control(
    source_path,
    source_code,
    expected_guard,
):
    result = map_authorized_code_files(
        {"authorized_code_files": [{"path": source_path, "content": source_code}]}
    )

    authz = next(
        fact
        for fact in result.facts
        if fact.fact_type == "authz_check"
        and fact.authz_hint == "deserialization_validation_check"
    )

    assert authz.symbol_name == expected_guard
    assert any(fact.fact_type == "sensitive_sink" for fact in result.facts)


def test_map_authorized_code_files_marks_upload_storage_without_guard_as_gap_candidate():
    result = map_authorized_code_files(
        {
            "authorized_code_files": [
                {
                    "path": "apps/api/routes/uploads.py",
                    "content": """
from fastapi import APIRouter, UploadFile

router = APIRouter()

@router.post("/uploads")
def upload_document(document: UploadFile):
    return save_upload(document)
""",
                }
            ]
        }
    )

    gap = next(
        fact for fact in result.facts if fact.fact_type == "authorization_gap_candidate"
    )

    assert gap.symbol_name == "upload_document"
    assert gap.authz_hint == "missing_handler_file_upload_check"
    assert gap.payload["root_cause"] == "missing_file_upload_validation"
    assert "save_upload" in gap.payload["sink_symbols"]


def test_map_authorized_code_files_does_not_treat_generic_file_save_as_upload_sink():
    result = map_authorized_code_files(
        {
            "authorized_code_files": [
                {
                    "path": "apps/api/routes/files.py",
                    "content": """
from fastapi import APIRouter

router = APIRouter()

@router.post("/files")
def save_document(document: bytes):
    return save_file(document)
""",
                }
            ]
        }
    )

    assert not any(
        fact.fact_type == "sensitive_sink" and fact.symbol_name == "save_file"
        for fact in result.facts
    )
    assert not any(
        fact.fact_type == "authorization_gap_candidate"
        and fact.payload.get("root_cause") == "missing_file_upload_validation"
        for fact in result.facts
    )


@pytest.mark.parametrize(
    ("source_path", "source_code", "expected_guard", "expected_sink"),
    (
        (
            "apps/api/routes/uploads.py",
            """
from fastapi import APIRouter, UploadFile

router = APIRouter()

@router.post("/uploads")
def upload_document(document: UploadFile):
    validated_document = validate_upload(document)
    return save_upload(validated_document)
""",
            "validate_upload",
            "save_upload",
        ),
        (
            "apps/api/routes/uploads.ts",
            """
import { Router } from "express";

const router = Router();

router.post("/uploads", uploadDocument);

function validateUpload(upload: unknown) {
  return upload;
}

async function uploadDocument(req: Request, res: Response) {
  const upload = validateUpload(req.file);
  return storeUpload(upload);
}
""",
            "validateUpload",
            "storeUpload",
        ),
    ),
)
def test_map_authorized_code_files_treats_upload_validation_as_control(
    source_path,
    source_code,
    expected_guard,
    expected_sink,
):
    result = map_authorized_code_files(
        {"authorized_code_files": [{"path": source_path, "content": source_code}]}
    )

    authz = next(
        fact
        for fact in result.facts
        if fact.fact_type == "authz_check"
        and fact.authz_hint == "file_upload_validation_check"
    )

    assert authz.symbol_name == expected_guard
    assert any(
        fact.fact_type == "sensitive_sink" and fact.symbol_name == expected_sink
        for fact in result.facts
    )
    assert not any(
        fact.fact_type == "authorization_gap_candidate" for fact in result.facts
    )


def test_map_authorized_code_files_marks_transfer_funds_without_server_amount_guard():
    result = map_authorized_code_files(
        {
            "authorized_code_files": [
                {
                    "path": "apps/api/routes/payments.py",
                    "content": """
from fastapi import APIRouter

router = APIRouter()

@router.post("/payments/transfers")
def create_transfer(order_id: str, recipient_id: str, amount: int):
    return transfer_funds(recipient_id, amount)
""",
                }
            ]
        }
    )

    gap = next(
        fact for fact in result.facts if fact.fact_type == "authorization_gap_candidate"
    )

    assert gap.symbol_name == "create_transfer"
    assert gap.authz_hint == "missing_handler_server_amount_check"
    assert gap.payload["root_cause"] == "missing_server_authoritative_amount_check"
    assert "transfer_funds" in gap.payload["sink_symbols"]


def test_map_authorized_code_files_marks_typescript_transfer_funds_without_server_amount_guard():
    result = map_authorized_code_files(
        {
            "authorized_code_files": [
                {
                    "path": "apps/api/routes/payments.ts",
                    "content": """
import { Router } from "express";

const router = Router();

router.post("/payments/transfers", createTransfer);

async function createTransfer(req: Request, res: Response) {
  return transferFunds(req.body.recipientId, req.body.amount);
}
""",
                }
            ]
        }
    )

    gap = next(
        fact for fact in result.facts if fact.fact_type == "authorization_gap_candidate"
    )

    assert gap.symbol_name == "createTransfer"
    assert gap.authz_hint == "missing_handler_server_amount_check"
    assert gap.payload["root_cause"] == "missing_server_authoritative_amount_check"
    assert "transferFunds" in gap.payload["sink_symbols"]


def test_map_authorized_code_files_preserves_camel_blob_access_as_object_boundary():
    result = map_authorized_code_files(
        {
            "authorized_code_files": [
                {
                    "path": "apps/api/routes/capsules.ts",
                    "content": """
import { Router } from "express";

const router = Router();

router.post("/capsules/:capsuleId/download", downloadCapsule);

async function downloadCapsule(req: Request, res: Response) {
  return getBlob(req.params.capsuleId);
}
""",
                }
            ]
        }
    )

    gap = next(
        fact for fact in result.facts if fact.fact_type == "authorization_gap_candidate"
    )

    assert gap.authz_hint == "missing_handler_authz_check"
    assert gap.payload["root_cause"] == "missing_object_ownership_check"


def test_map_authorized_code_files_does_not_treat_generic_transfer_as_money_flow_sink():
    result = map_authorized_code_files(
        {
            "authorized_code_files": [
                {
                    "path": "apps/api/routes/operations.py",
                    "content": """
from fastapi import APIRouter

router = APIRouter()

@router.post("/operations/transfer")
def transfer_document(document: bytes):
    return transfer(document)
""",
                }
            ]
        }
    )

    assert not any(
        fact.fact_type == "authorization_gap_candidate"
        and fact.payload.get("root_cause")
        == "missing_server_authoritative_amount_check"
        for fact in result.facts
    )


@pytest.mark.parametrize(
    ("source_path", "source_code", "expected_guard", "expected_sink"),
    (
        (
            "apps/api/routes/payments.py",
            """
from fastapi import APIRouter

router = APIRouter()

@router.post("/payments/transfers")
def create_transfer(order_id: str, recipient_id: str, amount: int):
    server_amount = derive_server_amount(order_id)
    return transfer_funds(recipient_id, server_amount)
""",
            "derive_server_amount",
            "transfer_funds",
        ),
        (
            "apps/api/routes/payments.ts",
            """
import { Router } from "express";

const router = Router();

router.post("/payments/transfers", createTransfer);

function deriveServerAmount(orderId: string) {
  return 1;
}

async function createTransfer(req: Request, res: Response) {
  const serverAmount = deriveServerAmount(req.body.orderId);
  return transferFunds(req.body.recipientId, serverAmount);
}
""",
            "deriveServerAmount",
            "transferFunds",
        ),
    ),
)
def test_map_authorized_code_files_treats_server_amount_derivation_as_control(
    source_path,
    source_code,
    expected_guard,
    expected_sink,
):
    result = map_authorized_code_files(
        {"authorized_code_files": [{"path": source_path, "content": source_code}]}
    )

    authz = next(
        fact
        for fact in result.facts
        if fact.fact_type == "authz_check"
        and fact.authz_hint == "server_authoritative_amount_check"
    )

    assert authz.symbol_name == expected_guard
    assert any(
        fact.fact_type == "sensitive_sink" and fact.symbol_name == expected_sink
        for fact in result.facts
    )
    assert not any(
        fact.fact_type == "authorization_gap_candidate" for fact in result.facts
    )


@pytest.mark.parametrize(
    "source_code",
    (
        """
from fastapi import APIRouter

router = APIRouter()

@router.post("/payments/transfers")
def create_transfer(order_id: str, recipient_id: str, amount: int):
    require_user()
    return transfer_funds(recipient_id, amount)
""",
        """
from fastapi import APIRouter

router = APIRouter()

@router.post("/payments/transfers")
def create_transfer(order_id: str, recipient_id: str, amount: int):
    result = transfer_funds(recipient_id, amount)
    derive_server_amount(order_id)
    return result
""",
    ),
)
def test_map_authorized_code_files_keeps_money_flow_gap_without_prior_matching_control(
    source_code,
):
    result = map_authorized_code_files(
        {
            "authorized_code_files": [
                {"path": "apps/api/routes/payments.py", "content": source_code}
            ]
        }
    )

    gap = next(
        fact
        for fact in result.facts
        if fact.fact_type == "authorization_gap_candidate"
        and fact.payload.get("root_cause")
        == "missing_server_authoritative_amount_check"
    )

    assert gap.symbol_name == "create_transfer"


@pytest.mark.parametrize(
    ("source_path", "source_code", "expected_sink"),
    (
        (
            "apps/api/routes/redemptions.py",
            """
from fastapi import APIRouter

router = APIRouter()

@router.post("/redemptions/{token_id}")
def redeem_token(token_id: str):
    return consume_one_time_token(token_id)
""",
            "consume_one_time_token",
        ),
        (
            "apps/api/routes/redemptions.ts",
            """
import { Router } from "express";

const router = Router();

router.post("/redemptions/:tokenId", redeemToken);

async function redeemToken(req: Request, res: Response) {
  return consumeOneTimeToken(req.params.tokenId);
}
""",
            "consumeOneTimeToken",
        ),
    ),
)
def test_map_authorized_code_files_marks_explicit_state_transition_without_guard(
    source_path,
    source_code,
    expected_sink,
):
    result = map_authorized_code_files(
        {"authorized_code_files": [{"path": source_path, "content": source_code}]}
    )

    gap = next(
        fact
        for fact in result.facts
        if fact.fact_type == "authorization_gap_candidate"
        and fact.payload.get("root_cause") == "missing_transactional_state_guard"
    )

    assert gap.authz_hint == "missing_handler_transactional_state_check"
    assert expected_sink in gap.payload["sink_symbols"]


@pytest.mark.parametrize(
    ("source_path", "source_code", "expected_guard", "expected_sink"),
    (
        (
            "apps/api/routes/redemptions.py",
            """
from fastapi import APIRouter

router = APIRouter()

@router.post("/redemptions/{token_id}")
def redeem_token(token_id: str):
    with_transactional_state_guard()
    return consume_one_time_token(token_id)
""",
            "with_transactional_state_guard",
            "consume_one_time_token",
        ),
        (
            "apps/api/routes/redemptions.py",
            """
from fastapi import APIRouter

router = APIRouter()

@router.post("/redemptions/{token_id}")
@transactional
def redeem_token(token_id: str):
    return consume_one_time_token(token_id)
""",
            "transactional",
            "consume_one_time_token",
        ),
        (
            "apps/api/routes/redemptions.ts",
            """
import { Router } from "express";

const router = Router();

router.post("/redemptions/:tokenId", redeemToken);

function withTransactionalStateGuard() {
  return true;
}

async function redeemToken(req: Request, res: Response) {
  withTransactionalStateGuard();
  return consumeOneTimeToken(req.params.tokenId);
}
""",
            "withTransactionalStateGuard",
            "consumeOneTimeToken",
        ),
    ),
)
def test_map_authorized_code_files_treats_transactional_state_guard_as_control(
    source_path,
    source_code,
    expected_guard,
    expected_sink,
):
    result = map_authorized_code_files(
        {"authorized_code_files": [{"path": source_path, "content": source_code}]}
    )

    assert any(
        fact.fact_type == "authz_check"
        and fact.symbol_name == expected_guard
        and fact.authz_hint == "transactional_state_guard"
        for fact in result.facts
    )
    assert any(
        fact.fact_type == "sensitive_sink" and fact.symbol_name == expected_sink
        for fact in result.facts
    )
    assert not any(
        fact.fact_type == "authorization_gap_candidate"
        and fact.payload.get("root_cause") == "missing_transactional_state_guard"
        for fact in result.facts
    )


def test_map_authorized_code_files_does_not_infer_generic_update_as_state_transition():
    result = map_authorized_code_files(
        {
            "authorized_code_files": [
                {
                    "path": "apps/api/routes/records.py",
                    "content": """
from fastapi import APIRouter

router = APIRouter()

@router.post("/records/{record_id}")
def update_record(record_id: str, body: dict):
    return update(record_id, body)
""",
                }
            ]
        }
    )

    assert not any(
        fact.fact_type == "authorization_gap_candidate"
        and fact.payload.get("root_cause") == "missing_transactional_state_guard"
        for fact in result.facts
    )


def test_map_authorized_code_files_keeps_state_transition_gap_for_unrelated_name():
    result = map_authorized_code_files(
        {
            "authorized_code_files": [
                {
                    "path": "apps/api/routes/redemptions.py",
                    "content": """
from fastapi import APIRouter

router = APIRouter()

@router.post("/redemptions/{token_id}")
def redeem_token(token_id: str):
    transactional_email_receipt(token_id)
    return consume_one_time_token(token_id)
""",
                }
            ]
        }
    )

    assert any(
        fact.fact_type == "authorization_gap_candidate"
        and fact.payload.get("root_cause") == "missing_transactional_state_guard"
        for fact in result.facts
    )


@pytest.mark.parametrize(
    ("source_path", "source_code", "expected_sink"),
    (
        (
            "MaintenanceController.java",
            """
@RestController
public class MaintenanceController {
  @PostMapping("/maintenance/run")
  public Object runMaintenance(String command) {
    return Runtime.getRuntime().exec(command);
  }
}
""",
            "exec",
        ),
        (
            "maintenance.rb",
            """
post "/maintenance/run", to: "maintenance#run_maintenance"

def run_maintenance
  system(params[:command])
end
""",
            "system",
        ),
    ),
)
def test_map_static_multilang_marks_command_execution_without_matching_guard(
    source_path,
    source_code,
    expected_sink,
):
    result = map_authorized_code_files(
        {"authorized_code_files": [{"path": source_path, "content": source_code}]}
    )

    assert any(
        fact.fact_type == "sensitive_sink" and fact.symbol_name == expected_sink
        for fact in result.facts
    )
    assert any(
        fact.fact_type == "authorization_gap_candidate"
        and fact.payload.get("root_cause") == "missing_command_injection_validation"
        for fact in result.facts
    )


def test_map_static_multilang_treats_command_validation_as_control():
    result = map_authorized_code_files(
        {
            "authorized_code_files": [
                {
                    "path": "MaintenanceController.java",
                    "content": """
@RestController
public class MaintenanceController {
  @PostMapping("/maintenance/run")
  public Object runMaintenance(String command) {
    String allowed = validateCommand(command);
    return Runtime.getRuntime().exec(allowed);
  }
}
""",
                }
            ]
        }
    )

    assert any(
        fact.fact_type == "authz_check"
        and fact.authz_hint == "command_injection_validation_check"
        for fact in result.facts
    )
    assert not any(
        fact.fact_type == "authorization_gap_candidate"
        and fact.payload.get("root_cause") == "missing_command_injection_validation"
        for fact in result.facts
    )


def test_map_static_multilang_keeps_command_gap_for_different_guard_input():
    result = map_authorized_code_files(
        {
            "authorized_code_files": [
                {
                    "path": "MaintenanceController.java",
                    "content": """
@RestController
public class MaintenanceController {
  @PostMapping("/maintenance/run")
  public Object runMaintenance(String safeCommand, String attackerCommand) {
    validateCommand(safeCommand);
    return Runtime.getRuntime().exec(attackerCommand);
  }
}
""",
                }
            ]
        }
    )

    assert any(
        fact.fact_type == "authorization_gap_candidate"
        and fact.payload.get("root_cause") == "missing_command_injection_validation"
        for fact in result.facts
    )


def test_map_static_multilang_does_not_treat_system_receiver_as_command_sink():
    result = map_authorized_code_files(
        {
            "authorized_code_files": [
                {
                    "path": "StatusController.java",
                    "content": """
@RestController
public class StatusController {
  @GetMapping("/status")
  public Object status() {
    System.out.println("healthy");
    return "ok";
  }
}
""",
                }
            ]
        }
    )

    assert not any(
        fact.fact_type == "sensitive_sink" and fact.symbol_name == "System"
        for fact in result.facts
    )
    assert not any(
        fact.fact_type == "authorization_gap_candidate"
        and fact.payload.get("root_cause") == "missing_command_injection_validation"
        for fact in result.facts
    )


def test_map_static_multilang_does_not_treat_command_variable_as_control():
    result = map_authorized_code_files(
        {
            "authorized_code_files": [
                {
                    "path": "MaintenanceController.java",
                    "content": """
@RestController
public class MaintenanceController {
  @PostMapping("/maintenance/run")
  public Object runMaintenance(String command) {
    String safeCommand = command;
    return Runtime.getRuntime().exec(safeCommand);
  }
}
""",
                }
            ]
        }
    )

    assert not any(
        fact.fact_type == "authz_check"
        and fact.authz_hint == "command_injection_validation_check"
        for fact in result.facts
    )
    assert any(
        fact.fact_type == "authorization_gap_candidate"
        and fact.payload.get("root_cause") == "missing_command_injection_validation"
        for fact in result.facts
    )


def test_map_static_multilang_treats_transactional_state_guard_as_control():
    result = map_authorized_code_files(
        {
            "authorized_code_files": [
                {
                    "path": "RedemptionController.java",
                    "content": """
@RestController
public class RedemptionController {
  @PostMapping("/redemptions/{tokenId}")
  public Object redeemToken(String tokenId) {
    withTransactionalStateGuard();
    return consumeOneTimeToken(tokenId);
  }
}
""",
                }
            ]
        }
    )

    assert any(
        fact.fact_type == "authz_check"
        and fact.authz_hint == "transactional_state_guard"
        for fact in result.facts
    )
    assert any(
        fact.fact_type == "sensitive_sink"
        and fact.symbol_name == "consumeOneTimeToken"
        for fact in result.facts
    )
    assert not any(
        fact.fact_type == "authorization_gap_candidate"
        and fact.payload.get("root_cause") == "missing_transactional_state_guard"
        for fact in result.facts
    )


@pytest.mark.parametrize(
    ("source_path", "source_code"),
    (
        (
            "RedemptionController.java",
            """
import org.springframework.transaction.annotation.Transactional;

@RestController
public class RedemptionController {
  @Transactional
  @PostMapping("/redemptions/{tokenId}")
  public Object redeemToken(String tokenId) {
    return consumeOneTimeToken(tokenId);
  }
}
""",
        ),
        (
            "handlers.go",
            """
package handlers

func mount(r Router) { r.POST("/redemptions/{tokenId}", redeemToken) }

func redeemToken() {
  db.Transaction(func(tx *DB) error {
    consumeOneTimeToken(tokenId)
    return nil
  })
}
""",
        ),
        (
            "redemptions.rb",
            """
post "/redemptions/:token_id", to: "redemptions#redeem_token"

def redeem_token
  ApplicationRecord.transaction do
    consume_one_time_token(params[:token_id])
  end
end
""",
        ),
    ),
)
def test_map_static_multilang_recognizes_framework_transaction_controls(
    source_path,
    source_code,
):
    result = map_authorized_code_files(
        {"authorized_code_files": [{"path": source_path, "content": source_code}]}
    )

    assert any(
        fact.fact_type == "authz_check"
        and fact.authz_hint == "transactional_state_guard"
        for fact in result.facts
    )
    assert not any(
        fact.fact_type == "authorization_gap_candidate"
        and fact.payload.get("root_cause") == "missing_transactional_state_guard"
        for fact in result.facts
    )


@pytest.mark.parametrize(
    ("source_path", "source_code"),
    (
        (
            "RedemptionController.java",
            """
@RestController
public class RedemptionController {
  @PostMapping("/redemptions/{tokenId}")
  public Object redeemToken(String tokenId) {
    // withTransactionalStateGuard();
    String note = "withTransactionalStateGuard()";
    /* withTransactionalStateGuard(); */
    return consumeOneTimeToken(tokenId);
  }
}
""",
        ),
        (
            "handlers.go",
            """
package handlers

func mount(r Router) { r.POST("/redemptions/{tokenId}", redeemToken) }

func redeemToken() {
  // withTransactionalStateGuard()
  note := "withTransactionalStateGuard()"
  return consumeOneTimeToken(tokenId)
}
""",
        ),
        (
            "redemptions.rb",
            """
post "/redemptions/:token_id", to: "redemptions#redeem_token"

def redeem_token
  # with_transactional_state_guard
  note = "with_transactional_state_guard()"
  consume_one_time_token(params[:token_id])
end
""",
        ),
    ),
)
def test_map_static_multilang_ignores_transactional_markers_in_non_code_text(
    source_path,
    source_code,
):
    result = map_authorized_code_files(
        {"authorized_code_files": [{"path": source_path, "content": source_code}]}
    )

    assert not any(
        fact.fact_type == "authz_check"
        and fact.authz_hint == "transactional_state_guard"
        for fact in result.facts
    )
    assert any(
        fact.fact_type == "authorization_gap_candidate"
        and fact.payload.get("root_cause") == "missing_transactional_state_guard"
        for fact in result.facts
    )


def test_map_static_multilang_requires_transaction_call_context():
    result = map_authorized_code_files(
        {
            "authorized_code_files": [
                {
                    "path": "redemptions.rb",
                    "content": """
post "/redemptions/:token_id", to: "redemptions#redeem_token"

def redeem_token
  transaction_runner = ApplicationRecord.transaction
  consume_one_time_token(params[:token_id])
end
""",
                }
            ]
        }
    )

    assert not any(
        fact.fact_type == "authz_check"
        and fact.authz_hint == "transactional_state_guard"
        for fact in result.facts
    )
    assert any(
        fact.fact_type == "authorization_gap_candidate"
        and fact.payload.get("root_cause") == "missing_transactional_state_guard"
        for fact in result.facts
    )


@pytest.mark.parametrize(
    ("source_path", "source_code"),
    (
        (
            "handlers.go",
            """
package handlers

func mount(r Router) { r.POST("/redemptions/{tokenId}", redeemToken) }

func redeemToken() {
  db.Transaction(func(tx *DB) error {
    recordAudit()
    return nil
  })
  return consumeOneTimeToken(tokenId)
}
""",
        ),
        (
            "redemptions.rb",
            """
post "/redemptions/:token_id", to: "redemptions#redeem_token"

def redeem_token
  ApplicationRecord.transaction do
    record_audit
  end
  consume_one_time_token(params[:token_id])
end
""",
        ),
    ),
)
def test_map_static_multilang_keeps_gap_when_transaction_scope_ends_before_sink(
    source_path,
    source_code,
):
    result = map_authorized_code_files(
        {"authorized_code_files": [{"path": source_path, "content": source_code}]}
    )

    assert not any(
        fact.fact_type == "authz_check"
        and fact.authz_hint == "transactional_state_guard"
        for fact in result.facts
    )
    assert any(
        fact.fact_type == "authorization_gap_candidate"
        and fact.payload.get("root_cause") == "missing_transactional_state_guard"
        for fact in result.facts
    )


@pytest.mark.parametrize(
    ("source_path", "source_code"),
    (
        (
            "handlers.go",
            """
package handlers

func mount(r Router) { r.POST("/redemptions/{tokenId}", redeemToken) }

func redeemToken() {
  db.Transaction(func(tx *DB) error {
    consumeOneTimeToken(firstTokenId)
    return nil
  })
  return consumeOneTimeToken(secondTokenId)
}
""",
        ),
        (
            "redemptions.rb",
            """
post "/redemptions/:token_id", to: "redemptions#redeem_token"

def redeem_token
  ApplicationRecord.transaction do
    consume_one_time_token(first_token_id)
  end
  consume_one_time_token(second_token_id)
end
""",
        ),
    ),
)
def test_map_static_multilang_keeps_gap_when_transaction_scope_misses_a_sink(
    source_path,
    source_code,
):
    result = map_authorized_code_files(
        {"authorized_code_files": [{"path": source_path, "content": source_code}]}
    )

    assert not any(
        fact.fact_type == "authz_check"
        and fact.authz_hint == "transactional_state_guard"
        for fact in result.facts
    )
    assert any(
        fact.fact_type == "authorization_gap_candidate"
        and fact.payload.get("root_cause") == "missing_transactional_state_guard"
        for fact in result.facts
    )


@pytest.mark.parametrize(
    ("source_path", "source_code"),
    (
        (
            "handlers.go",
            """
package handlers

func mount(r Router) { r.POST("/redemptions/{tokenId}", redeemToken) }

func redeemToken() { return db.Transaction(func(tx *DB) error { return consumeOneTimeToken(tokenId) }) }
""",
        ),
        (
            "redemptions.rb",
            """
post "/redemptions/:token_id", to: "redemptions#redeem_token"

def redeem_token
  ApplicationRecord.transaction { consume_one_time_token(params[:token_id]) }
end
""",
        ),
    ),
)
def test_map_static_multilang_treats_same_line_transaction_scope_as_control(
    source_path,
    source_code,
):
    result = map_authorized_code_files(
        {"authorized_code_files": [{"path": source_path, "content": source_code}]}
    )

    assert any(
        fact.fact_type == "authz_check"
        and fact.authz_hint == "transactional_state_guard"
        for fact in result.facts
    )
    assert not any(
        fact.fact_type == "authorization_gap_candidate"
        and fact.payload.get("root_cause") == "missing_transactional_state_guard"
        for fact in result.facts
    )


def test_map_static_multilang_propagates_java_class_transactional_annotation():
    result = map_authorized_code_files(
        {
            "authorized_code_files": [
                {
                    "path": "RedemptionController.java",
                    "content": """
import org.springframework.transaction.annotation.Transactional;

@Transactional
@RestController
public class RedemptionController {
  @PostMapping("/redemptions/{tokenId}")
  public Object redeemToken(String tokenId) {
    return consumeOneTimeToken(tokenId);
  }

  @PostMapping("/redemptions/{tokenId}/retry")
  public Object retryRedemption(String tokenId) {
    return consumeOneTimeToken(tokenId);
  }
}
""",
                }
            ]
        }
    )

    guarded_handlers = {
        fact.payload.get("handler")
        for fact in result.facts
        if fact.fact_type == "authz_check"
        and fact.authz_hint == "transactional_state_guard"
    }

    assert guarded_handlers == {"redeemToken", "retryRedemption"}
    assert not any(
        fact.fact_type == "authorization_gap_candidate"
        and fact.payload.get("root_cause") == "missing_transactional_state_guard"
        for fact in result.facts
    )


@pytest.mark.parametrize(
    "source_code",
    (
        """
import org.springframework.transaction.annotation.Transactional;

@RestController
public class RedemptionController {
  @Transactional(propagation = Propagation.NOT_SUPPORTED)
  @PostMapping("/redemptions/{tokenId}")
  public Object redeemToken(String tokenId) {
    return consumeOneTimeToken(tokenId);
  }
}
""",
        """
import org.springframework.transaction.annotation.Transactional;

@Transactional(propagation = Propagation.NEVER)
@RestController
public class RedemptionController {
  @PostMapping("/redemptions/{tokenId}")
  public Object redeemToken(String tokenId) {
    return consumeOneTimeToken(tokenId);
  }
}
""",
    ),
)
def test_map_static_multilang_keeps_gap_for_nontransactional_propagation(
    source_code,
):
    result = map_authorized_code_files(
        {
            "authorized_code_files": [
                {"path": "RedemptionController.java", "content": source_code}
            ]
        }
    )

    assert not any(
        fact.fact_type == "authz_check"
        and fact.authz_hint == "transactional_state_guard"
        for fact in result.facts
    )
    assert any(
        fact.fact_type == "authorization_gap_candidate"
        and fact.payload.get("root_cause") == "missing_transactional_state_guard"
        for fact in result.facts
    )


def test_map_static_multilang_does_not_inherit_outer_class_transactional_annotation():
    result = map_authorized_code_files(
        {
            "authorized_code_files": [
                {
                    "path": "OuterController.java",
                    "content": """
import org.springframework.transaction.annotation.Transactional;

@Transactional
public class OuterController {
  @RestController
  public static class RedemptionController {
    @PostMapping("/redemptions/{tokenId}")
    public Object redeemToken(String tokenId) {
      return consumeOneTimeToken(tokenId);
    }
  }
}
""",
                }
            ]
        }
    )

    assert not any(
        fact.fact_type == "authz_check"
        and fact.authz_hint == "transactional_state_guard"
        and fact.payload.get("handler") == "redeemToken"
        for fact in result.facts
    )
    assert any(
        fact.fact_type == "authorization_gap_candidate"
        and fact.symbol_name == "redeemToken"
        and fact.payload.get("root_cause") == "missing_transactional_state_guard"
        for fact in result.facts
    )


def test_map_static_multilang_combines_spring_controller_prefix_and_method_route():
    content = """
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping(path = "/api/v1/records/")
public class RecordsController {
  @GetMapping("/{recordId}")
  public Object readRecord(String recordId) {
    Record record = loadRecord(recordId);
    return sendFile(record.getPath());
  }
}
"""

    result = map_authorized_code_files(
        {"authorized_code_files": [{"path": "RecordsController.java", "content": content}]}
    )

    assert any(
        fact.fact_type == "route_handler"
        and fact.symbol_name == "readRecord"
        and fact.route_method == "GET"
        and fact.route_path == "/api/v1/records/{recordId}"
        for fact in result.facts
    )


def test_map_static_multilang_propagates_spring_class_route_and_authz():
    content = """
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1")
@PreAuthorize("hasRole('RECORD_READER')")
public class RecordsController {
  @GetMapping("/records/{recordId}")
  public Object readRecord(String recordId) {
    return sendFile(loadRecord(recordId).getPath());
  }
}
"""

    result = map_authorized_code_files(
        {"authorized_code_files": [{"path": "RecordsController.java", "content": content}]}
    )

    assert any(
        fact.fact_type == "route_handler"
        and fact.symbol_name == "readRecord"
        and fact.route_method == "GET"
        and fact.route_path == "/api/v1/records/{recordId}"
        for fact in result.facts
    )
    assert any(
        fact.fact_type == "authz_check"
        and fact.symbol_name == "PreAuthorize"
        and fact.authz_hint == "role_check"
        and fact.payload.get("handler") == "readRecord"
        for fact in result.facts
    )
    assert not any(
        fact.fact_type == "authorization_gap_candidate"
        and fact.symbol_name == "readRecord"
        for fact in result.facts
    )


def test_map_static_multilang_keeps_gap_for_spring_class_permit_all():
    content = """
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1")
@PreAuthorize("permitAll()")
public class RecordsController {
  @GetMapping("/records/{recordId}")
  public Object readRecord(String recordId) {
    return sendFile(loadRecord(recordId).getPath());
  }
}
"""

    result = map_authorized_code_files(
        {"authorized_code_files": [{"path": "RecordsController.java", "content": content}]}
    )

    assert any(
        fact.fact_type == "route_handler"
        and fact.symbol_name == "readRecord"
        and fact.route_path == "/api/v1/records/{recordId}"
        for fact in result.facts
    )
    assert any(
        fact.fact_type == "authz_check"
        and fact.authz_hint == "public_access"
        and fact.payload.get("handler") == "readRecord"
        for fact in result.facts
    )
    assert any(
        fact.fact_type == "authorization_gap_candidate"
        and fact.symbol_name == "readRecord"
        for fact in result.facts
    )


def test_map_static_multilang_keeps_gap_for_java_security_permit_all():
    content = """
import jakarta.annotation.security.PermitAll;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class RecordsController {
  @PermitAll
  @GetMapping("/records/{recordId}")
  public Object readRecord(String recordId) {
    return sendFile(loadRecord(recordId).getPath());
  }
}
"""

    result = map_authorized_code_files(
        {"authorized_code_files": [{"path": "RecordsController.java", "content": content}]}
    )

    assert any(
        fact.fact_type == "authz_check"
        and fact.symbol_name == "PermitAll"
        and fact.authz_hint == "public_access"
        and fact.payload.get("handler") == "readRecord"
        for fact in result.facts
    )
    assert any(
        fact.fact_type == "authorization_gap_candidate"
        and fact.symbol_name == "readRecord"
        for fact in result.facts
    )


def test_map_static_multilang_suppresses_gap_for_java_security_class_deny_all():
    content = """
import jakarta.annotation.security.DenyAll;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@DenyAll
public class RecordsController {
  @GetMapping("/records/{recordId}")
  public Object readRecord(String recordId) {
    return sendFile(loadRecord(recordId).getPath());
  }
}
"""

    result = map_authorized_code_files(
        {"authorized_code_files": [{"path": "RecordsController.java", "content": content}]}
    )

    assert any(
        fact.fact_type == "authz_check"
        and fact.symbol_name == "DenyAll"
        and fact.authz_hint == "access_denied_check"
        and fact.payload.get("handler") == "readRecord"
        for fact in result.facts
    )
    assert not any(
        fact.fact_type == "authorization_gap_candidate"
        and fact.symbol_name == "readRecord"
        for fact in result.facts
    )


def test_map_static_multilang_suppresses_static_gap_for_java_security_deny_all():
    content = """
import jakarta.annotation.security.DenyAll;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@DenyAll
public class MaintenanceController {
  @PostMapping("/maintenance/run")
  public Object runMaintenance(String command) {
    return Runtime.getRuntime().exec(command);
  }
}
"""

    result = map_authorized_code_files(
        {
            "authorized_code_files": [
                {"path": "MaintenanceController.java", "content": content}
            ]
        }
    )

    assert any(
        fact.fact_type == "authz_check"
        and fact.authz_hint == "access_denied_check"
        and fact.payload.get("handler") == "runMaintenance"
        for fact in result.facts
    )
    assert not any(
        fact.fact_type == "authorization_gap_candidate"
        and fact.payload.get("root_cause") == "missing_command_injection_validation"
        for fact in result.facts
    )


def test_map_static_multilang_keeps_gap_for_spring_constant_true_access():
    content = """
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class RecordsController {
  @PreAuthorize(value = "true")
  @GetMapping("/records/{recordId}")
  public Object readRecord(String recordId) {
    return sendFile(loadRecord(recordId).getPath());
  }
}
"""

    result = map_authorized_code_files(
        {"authorized_code_files": [{"path": "RecordsController.java", "content": content}]}
    )

    assert any(
        fact.fact_type == "authz_check"
        and fact.authz_hint == "public_access"
        and fact.payload.get("handler") == "readRecord"
        for fact in result.facts
    )
    assert any(
        fact.fact_type == "authorization_gap_candidate"
        and fact.symbol_name == "readRecord"
        for fact in result.facts
    )


@pytest.mark.parametrize(
    "expression",
    (
        "permitAll() || hasRole('RECORD_READER')",
        "true || hasRole('RECORD_READER')",
        "true or hasRole('RECORD_READER')",
        "(permitAll() || hasRole('RECORD_READER'))",
        "((permitAll() || hasRole('RECORD_READER')))",
    ),
)
def test_map_static_multilang_keeps_gap_for_spring_public_or_expression(expression):
    content = f"""
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class RecordsController {{
  @PreAuthorize("{expression}")
  @GetMapping("/records/{{recordId}}")
  public Object readRecord(String recordId) {{
    return sendFile(loadRecord(recordId).getPath());
  }}
}}
"""

    result = map_authorized_code_files(
        {"authorized_code_files": [{"path": "RecordsController.java", "content": content}]}
    )

    assert any(
        fact.fact_type == "route_handler"
        and fact.symbol_name == "readRecord"
        and fact.route_path == "/records/{recordId}"
        for fact in result.facts
    )
    assert any(
        fact.fact_type == "authz_check"
        and fact.authz_hint == "public_access"
        and fact.payload.get("handler") == "readRecord"
        for fact in result.facts
    )
    assert any(
        fact.fact_type == "authorization_gap_candidate"
        and fact.symbol_name == "readRecord"
        for fact in result.facts
    )


def test_map_static_multilang_method_permit_all_overrides_spring_class_role_guard():
    content = """
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@PreAuthorize("hasRole('RECORD_READER')")
public class RecordsController {
  @PreAuthorize("permitAll()")
  @GetMapping("/records/{recordId}")
  public Object readRecord(String recordId) {
    return sendFile(loadRecord(recordId).getPath());
  }
}
"""

    result = map_authorized_code_files(
        {"authorized_code_files": [{"path": "RecordsController.java", "content": content}]}
    )

    authz = [
        fact
        for fact in result.facts
        if fact.fact_type == "authz_check"
        and fact.payload.get("handler") == "readRecord"
    ]
    assert [fact.authz_hint for fact in authz] == ["public_access"]
    assert any(
        fact.fact_type == "authorization_gap_candidate"
        and fact.symbol_name == "readRecord"
        for fact in result.facts
    )


def test_map_static_multilang_keeps_gap_for_spring_authentication_only_check():
    content = """
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class RecordsController {
  @PreAuthorize("isAuthenticated()")
  @GetMapping("/records/{recordId}")
  public Object readRecord(String recordId) {
    return sendFile(loadRecord(recordId).getPath());
  }
}
"""

    result = map_authorized_code_files(
        {"authorized_code_files": [{"path": "RecordsController.java", "content": content}]}
    )

    assert any(
        fact.fact_type == "authz_check"
        and fact.authz_hint == "authentication_check"
        and fact.payload.get("handler") == "readRecord"
        for fact in result.facts
    )
    assert any(
        fact.fact_type == "authorization_gap_candidate"
        and fact.symbol_name == "readRecord"
        for fact in result.facts
    )


def test_map_static_multilang_does_not_leak_spring_class_annotations_to_nested_controller():
    content = """
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RequestMapping("/outer")
@PreAuthorize("hasRole('OUTER_READER')")
public class OuterController {
  @RestController
  public static class PublicController {
    @GetMapping("/records/{recordId}")
    public Object readRecord(String recordId) {
      return sendFile(loadRecord(recordId).getPath());
    }
  }
}
"""

    result = map_authorized_code_files(
        {"authorized_code_files": [{"path": "OuterController.java", "content": content}]}
    )

    assert any(
        fact.fact_type == "route_handler"
        and fact.symbol_name == "readRecord"
        and fact.route_path == "/records/{recordId}"
        for fact in result.facts
    )
    assert not any(
        fact.fact_type == "authz_check"
        and fact.symbol_name == "PreAuthorize"
        and fact.payload.get("handler") == "readRecord"
        for fact in result.facts
    )
    assert any(
        fact.fact_type == "authorization_gap_candidate"
        and fact.symbol_name == "readRecord"
        for fact in result.facts
    )


def test_map_static_multilang_maps_explicit_spring_request_mapping_methods():
    content = """
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1")
public class RecordsController {
  // @RequestMapping(path = "/comment-only", method = RequestMethod.DELETE)
  @RequestMapping(
      method = {RequestMethod.GET, RequestMethod.POST},
      path = "/records/{recordId}"
  )
  public Object readRecord(String recordId) {
    return sendFile(loadRecord(recordId).getPath());
  }
}
"""

    result = map_authorized_code_files(
        {"authorized_code_files": [{"path": "RecordsController.java", "content": content}]}
    )
    route_methods = {
        fact.route_method
        for fact in result.facts
        if fact.fact_type == "route_handler"
        and fact.symbol_name == "readRecord"
        and fact.route_path == "/api/v1/records/{recordId}"
    }

    assert route_methods == {"GET", "POST"}
    assert not any(
        fact.fact_type == "route_handler" and fact.route_method == "DELETE"
        for fact in result.facts
    )


@pytest.mark.parametrize(
    ("annotation", "symbol_name"),
    (
        ('@PreAuthorize("hasRole(\'RECORD_READER\')")', "PreAuthorize"),
        ('@PreAuthorize("hasRole(\'RECORD_READER\') && permitAll()")', "PreAuthorize"),
        ('@Secured("ROLE_RECORD_READER")', "Secured"),
        ('@RolesAllowed("RECORD_READER")', "RolesAllowed"),
    ),
)
def test_map_static_multilang_maps_spring_declarative_method_authz(
    annotation,
    symbol_name,
):
    content = f"""
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class RecordsController {{
  {annotation}
  @GetMapping("/records/{{recordId}}")
  public Object readRecord(String recordId) {{
    return sendFile(loadRecord(recordId).getPath());
  }}
}}
"""

    result = map_authorized_code_files(
        {"authorized_code_files": [{"path": "RecordsController.java", "content": content}]}
    )

    assert any(
        fact.fact_type == "authz_check"
        and fact.symbol_name == symbol_name
        and fact.authz_hint == "role_check"
        and fact.payload.get("handler") == "readRecord"
        for fact in result.facts
    )
    assert not any(
        fact.fact_type == "authorization_gap_candidate"
        and fact.symbol_name == "readRecord"
        for fact in result.facts
    )


def test_map_static_multilang_ignores_commented_spring_declarative_authz():
    content = """
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class RecordsController {
  // @PreAuthorize("hasRole('RECORD_READER')")
  @GetMapping("/records/{recordId}")
  public Object readRecord(String recordId) {
    return sendFile(loadRecord(recordId).getPath());
  }
}
"""

    result = map_authorized_code_files(
        {"authorized_code_files": [{"path": "RecordsController.java", "content": content}]}
    )

    assert not any(
        fact.fact_type == "authz_check" and fact.symbol_name == "PreAuthorize"
        for fact in result.facts
    )
    assert any(
        fact.fact_type == "authorization_gap_candidate"
        and fact.symbol_name == "readRecord"
        for fact in result.facts
    )


def test_map_static_multilang_ignores_commented_spring_controller_prefix():
    content = """
// @RequestMapping("/comment-only")
@RestController
public class RecordsController {
  @GetMapping("/records/{recordId}")
  public Object readRecord(String recordId) {
    return sendFile(loadRecord(recordId).getPath());
  }
}
"""

    result = map_authorized_code_files(
        {"authorized_code_files": [{"path": "RecordsController.java", "content": content}]}
    )

    assert any(
        fact.fact_type == "route_handler"
        and fact.symbol_name == "readRecord"
        and fact.route_path == "/records/{recordId}"
        for fact in result.facts
    )
    assert not any(
        fact.fact_type == "route_handler"
        and fact.route_path == "/comment-only/records/{recordId}"
        for fact in result.facts
    )


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


def test_go_reachable_nested_ownership_check_suppresses_gap_candidate():
    content = """
package handlers

func mount(r Router) { r.GET("/records/{recordId}", readRecord) }

func readRecord() {
  record := loadRecord(recordId)
  loadRecordForUser(record, user)
  sendFile(record.Path)
}

func loadRecordForUser(record Record, user User) {
  validateAccess(record, user)
}

func validateAccess(record Record, user User) {
  if record.OwnerID != user.ID { return }
}
"""

    result = map_authorized_code_files(
        {"authorized_code_files": [{"path": "handlers.go", "content": content}]}
    )

    assert any(
        fact.fact_type == "authz_check"
        and fact.authz_hint == "owner_or_admin_check"
        and isinstance(fact.payload, dict)
        and fact.payload.get("handler") == "validateAccess"
        for fact in result.facts
    )
    assert not any(
        fact.fact_type == "authorization_gap_candidate"
        and fact.symbol_name == "readRecord"
        for fact in result.facts
    )


def test_go_unreachable_ownership_check_does_not_suppress_gap_candidate():
    content = """
package handlers

func mount(r Router) { r.GET("/records/{recordId}", readRecord) }

func readRecord() {
  record := loadRecord(recordId)
  sendFile(record.Path)
}

func validateAccess(record Record, user User) {
  if record.OwnerID != user.ID { return }
}
"""

    result = map_authorized_code_files(
        {"authorized_code_files": [{"path": "handlers.go", "content": content}]}
    )

    assert any(
        fact.fact_type == "authorization_gap_candidate"
        and fact.symbol_name == "readRecord"
        for fact in result.facts
    )


def test_go_nested_ownership_check_after_sink_keeps_gap_candidate():
    content = """
package handlers

func mount(r Router) { r.GET("/records/{recordId}", readRecord) }

func readRecord() {
  record := loadRecord(recordId)
  loadRecordForUser(record, user)
}

func loadRecordForUser(record Record, user User) {
  sendFile(record.Path)
  validateAccess(record, user)
}

func validateAccess(record Record, user User) {
  if record.OwnerID != user.ID { return }
}
"""

    result = map_authorized_code_files(
        {"authorized_code_files": [{"path": "handlers.go", "content": content}]}
    )

    assert any(
        fact.fact_type == "authorization_gap_candidate"
        and fact.symbol_name == "readRecord"
        for fact in result.facts
    )


def test_ruby_reachable_nested_ownership_check_suppresses_gap_candidate():
    content = """
get "/records/:record_id", to: "records#read_record"

def read_record
  record = load_record(params[:record_id])
  load_record_for_user(record, current_user)
  send_file record.path
end

def load_record_for_user(record, user)
  validate_access(record, user)
end

def validate_access(record, user)
  if record.owner_id != user.id
    deny
  end
end
"""

    result = map_authorized_code_files(
        {"authorized_code_files": [{"path": "records.rb", "content": content}]}
    )

    assert any(
        fact.fact_type == "authz_check"
        and fact.authz_hint == "owner_or_admin_check"
        and isinstance(fact.payload, dict)
        and fact.payload.get("handler") == "validate_access"
        for fact in result.facts
    )
    assert not any(
        fact.fact_type == "authorization_gap_candidate"
        and fact.symbol_name == "read_record"
        for fact in result.facts
    )


def test_ruby_nested_ownership_check_after_sink_keeps_gap_candidate():
    content = """
get "/records/:record_id", to: "records#read_record"

def read_record
  record = load_record(params[:record_id])
  load_record_for_user(record, current_user)
end

def load_record_for_user(record, user)
  send_file record.path
  validate_access(record, user)
end

def validate_access(record, user)
  if record.owner_id != user.id
    deny
  end
end
"""

    result = map_authorized_code_files(
        {"authorized_code_files": [{"path": "records.rb", "content": content}]}
    )

    assert any(
        fact.fact_type == "authorization_gap_candidate"
        and fact.symbol_name == "read_record"
        for fact in result.facts
    )


@pytest.mark.parametrize(
    ("callback_scope", "protected_handler", "unprotected_handler"),
    (
        ("only: :show_record", "show_record", "export_record"),
        ("except: :export_record", "show_record", "export_record"),
    ),
)
def test_ruby_scoped_before_action_does_not_suppress_other_sensitive_action(
    callback_scope,
    protected_handler,
    unprotected_handler,
):
    content = f"""
get "/records/:record_id", to: "records#show_record"
get "/records/:record_id/export", to: "records#export_record"
before_action :verify_record_access, {callback_scope}

def show_record
  record = load_record(params[:record_id])
  send_file record.path
end

def export_record
  record = load_record(params[:record_id])
  send_file record.path
end

def verify_record_access
  record = load_record(params[:record_id])
  if record.owner_id != current_user.id
    deny
  end
end
"""

    result = map_authorized_code_files(
        {"authorized_code_files": [{"path": "records.rb", "content": content}]}
    )

    assert not any(
        fact.fact_type == "authorization_gap_candidate"
        and fact.symbol_name == protected_handler
        for fact in result.facts
    )
    assert any(
        fact.fact_type == "authorization_gap_candidate"
        and fact.symbol_name == unprotected_handler
        for fact in result.facts
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


@pytest.mark.parametrize(
    ("attribute", "expected_hint", "expects_gap"),
    (
        ("[AllowAnonymous]", "public_access", True),
        ("[Authorize]", "authentication_check", True),
        ('[Authorize(Roles = "RECORD_READER")]', "role_check", False),
        (
            '[Authorize(Roles = "RECORD_READER")]\n  [Authorize]',
            "role_check",
            False,
        ),
    ),
)
def test_map_static_multilang_maps_csharp_method_declarative_authz(
    attribute,
    expected_hint,
    expects_gap,
):
    content = f"""
public class RecordsController {{
  {attribute}
  [HttpGet("/records/{{recordId}}")]
  public IActionResult ReadRecord(string recordId) {{
    return File(loadRecord(recordId).Path);
  }}
}}
"""

    result = map_authorized_code_files(
        {
            "authorized_code_files": [
                {"path": "RecordsController.cs", "content": content}
            ]
        }
    )

    assert any(
        fact.fact_type == "authz_check"
        and fact.authz_hint == expected_hint
        and fact.payload.get("handler") == "ReadRecord"
        for fact in result.facts
    )
    assert any(
        fact.fact_type == "authorization_gap_candidate"
        and fact.symbol_name == "ReadRecord"
        for fact in result.facts
    ) is expects_gap


def test_map_static_multilang_maps_csharp_controller_authz_and_method_override():
    class_role_content = """
[Authorize(Roles = "RECORD_READER")]
public class RecordsController {
  [Authorize]
  [HttpGet("/records/{recordId}")]
  public IActionResult ReadRecord(string recordId) {
    return File(loadRecord(recordId).Path);
  }
}
"""
    method_override_content = """
[Authorize]
public class RecordsController {
  [AllowAnonymous]
  [HttpGet("/records/{recordId}")]
  public IActionResult ReadRecord(string recordId) {
    return File(loadRecord(recordId).Path);
  }
}
"""

    class_role_result = map_authorized_code_files(
        {
            "authorized_code_files": [
                {"path": "RecordsController.cs", "content": class_role_content}
            ]
        }
    )
    method_override_result = map_authorized_code_files(
        {
            "authorized_code_files": [
                {"path": "RecordsController.cs", "content": method_override_content}
            ]
        }
    )

    assert any(
        fact.fact_type == "authz_check"
        and fact.authz_hint == "role_check"
        and fact.payload.get("handler") == "ReadRecord"
        for fact in class_role_result.facts
    )
    assert not any(
        fact.fact_type == "authorization_gap_candidate"
        and fact.symbol_name == "ReadRecord"
        for fact in class_role_result.facts
    )
    override_authz = [
        fact.authz_hint
        for fact in method_override_result.facts
        if fact.fact_type == "authz_check"
        and fact.payload.get("handler") == "ReadRecord"
    ]
    assert override_authz == ["public_access"]
    assert any(
        fact.fact_type == "authorization_gap_candidate"
        and fact.symbol_name == "ReadRecord"
        for fact in method_override_result.facts
    )


def test_map_static_multilang_keeps_nested_csharp_controller_public():
    content = """
[Authorize(Roles = "OUTER_READER")]
[Route("/outer")]
public class OuterController {
  public class PublicController {
    [HttpGet("/records/{recordId}")]
    public IActionResult ReadRecord(string recordId) {
      return File(loadRecord(recordId).Path);
    }
  }
}
"""

    result = map_authorized_code_files(
        {"authorized_code_files": [{"path": "OuterController.cs", "content": content}]}
    )

    assert not any(
        fact.fact_type == "authz_check"
        and fact.authz_hint == "role_check"
        and fact.payload.get("handler") == "ReadRecord"
        for fact in result.facts
    )
    assert any(
        fact.fact_type == "authorization_gap_candidate"
        and fact.symbol_name == "ReadRecord"
        for fact in result.facts
    )
    assert any(
        fact.fact_type == "route_handler"
        and fact.symbol_name == "ReadRecord"
        and fact.route_path == "/records/{recordId}"
        for fact in result.facts
    )


def test_map_static_multilang_combines_csharp_controller_route_prefix():
    content = """
[Route("/api/v1/records")]
public class RecordsController {
  [HttpGet("{recordId}")]
  public IActionResult ReadRecord(string recordId) {
    return File(loadRecord(recordId).Path);
  }

  [HttpGet]
  public IActionResult ListRecords() {
    return Ok();
  }

  [HttpGet("/health")]
  public IActionResult Health() {
    return Ok();
  }
}
"""

    result = map_authorized_code_files(
        {
            "authorized_code_files": [
                {"path": "RecordsController.cs", "content": content}
            ]
        }
    )
    route_paths = {
        fact.symbol_name: fact.route_path
        for fact in result.facts
        if fact.fact_type == "route_handler"
    }

    assert route_paths == {
        "ReadRecord": "/api/v1/records/{recordId}",
        "ListRecords": "/api/v1/records",
        "Health": "/health",
    }


def test_map_static_multilang_uses_csharp_method_route_template():
    content = """
[Route("/api/v1")]
public class RecordsController {
  [Route("records/{recordId}")]
  [HttpGet]
  public IActionResult ReadRecord(string recordId) {
    return File(loadRecord(recordId).Path);
  }

  [Route("/health")]
  [HttpGet]
  public IActionResult Health() {
    return Ok();
  }

  [Route("legacy/{recordId}")]
  [HttpGet("records/{recordId}")]
  public IActionResult ReadCurrentRecord(string recordId) {
    return File(loadRecord(recordId).Path);
  }

  [Route("named/{recordId}")]
  [HttpGet(Name = "ReadNamedRecordRoute")]
  public IActionResult ReadNamedRecord(string recordId) {
    return File(loadRecord(recordId).Path);
  }
}
"""

    result = map_authorized_code_files(
        {
            "authorized_code_files": [
                {"path": "RecordsController.cs", "content": content}
            ]
        }
    )
    route_paths = {
        fact.symbol_name: fact.route_path
        for fact in result.facts
        if fact.fact_type == "route_handler"
    }

    assert route_paths == {
        "ReadRecord": "/api/v1/records/{recordId}",
        "Health": "/health",
        "ReadCurrentRecord": "/api/v1/records/{recordId}",
        "ReadNamedRecord": "/api/v1/named/{recordId}",
    }


def test_map_static_multilang_ignores_commented_csharp_http_route():
    content = """
public class RecordsController {
  // [HttpGet("/comment-only")]
  [HttpGet("/records/{recordId}")]
  public IActionResult ReadRecord(string recordId) {
    return File(loadRecord(recordId).Path);
  }
}
"""

    result = map_authorized_code_files(
        {
            "authorized_code_files": [
                {"path": "RecordsController.cs", "content": content}
            ]
        }
    )
    routes = [
        (fact.symbol_name, fact.route_path)
        for fact in result.facts
        if fact.fact_type == "route_handler"
    ]

    assert routes == [("ReadRecord", "/records/{recordId}")]


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


def test_map_static_multilang_maps_kotlin_controller_prefix_and_declarative_authz():
    content = """
import org.springframework.security.access.prepost.PreAuthorize
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RestController
import jakarta.annotation.security.PermitAll

@RestController
@RequestMapping("/api/v1")
@PreAuthorize("hasRole('RECORD_READER')")
class RecordsController {
  @GetMapping("/records/{recordId}")
  fun readRecord(recordId: String): Any {
    return sendFile(loadRecord(recordId).path)
  }

  @PermitAll
  @GetMapping("/public/{recordId}")
  fun downloadRecord(recordId: String): Any {
    return sendFile(loadRecord(recordId).path)
  }
}
"""

    result = map_authorized_code_files(
        {"authorized_code_files": [{"path": "RecordsController.kt", "content": content}]}
    )
    routes = {
        fact.symbol_name: fact.route_path
        for fact in result.facts
        if fact.fact_type == "route_handler"
    }
    authz_by_handler = {
        fact.payload.get("handler"): fact.authz_hint
        for fact in result.facts
        if fact.fact_type == "authz_check"
    }
    gap_handlers = {
        fact.symbol_name
        for fact in result.facts
        if fact.fact_type == "authorization_gap_candidate"
    }

    assert routes == {
        "readRecord": "/api/v1/records/{recordId}",
        "downloadRecord": "/api/v1/public/{recordId}",
    }
    assert authz_by_handler == {
        "readRecord": "role_check",
        "downloadRecord": "public_access",
    }
    assert gap_handlers == {"downloadRecord"}


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


def test_map_authorized_code_files_maps_strawberry_graphql_query_without_http_route():
    result = map_authorized_code_files(
        {
            "authorized_code_files": [
                {
                    "path": "gql/records.py",
                    "content": """
import strawberry


@strawberry.type
class Query:
    @strawberry.field
    def record(self, info, record_id: str):
        return send_file(record_id)
""",
                }
            ]
        }
    )

    operations = [
        fact for fact in result.facts if fact.fact_type == "graphql_operation"
    ]
    gaps = [
        fact for fact in result.facts if fact.fact_type == "authorization_gap_candidate"
    ]

    assert len(operations) == 1
    operation = operations[0]
    assert operation.source_path == "gql/records.py"
    assert operation.symbol_name == "record"
    assert operation.route_method is None
    assert operation.route_path is None
    assert operation.payload["handler"] == "record"
    assert operation.payload["operation_type"] == "query"
    assert operation.payload["operation_name"] == "record"
    assert operation.payload["framework"] == "strawberry"

    assert len(gaps) == 1
    gap = gaps[0]
    assert gap.symbol_name == "record"
    assert gap.route_method is None
    assert gap.route_path is None
    assert gap.payload["entrypoint_kind"] == "graphql_operation"
    assert gap.payload["graphql_operation_type"] == "query"
    assert gap.payload["graphql_operation_name"] == "record"


def test_map_authorized_code_files_skips_ambiguous_strawberry_graphql_bindings():
    result = map_authorized_code_files(
        {
            "authorized_code_files": [
                {
                    "path": "gql/records.py",
                    "content": """
import strawberry


@strawberry.type
class Query:
    @strawberry.field(name="record")
    def read_record(self, info, record_id: str):
        return send_file(record_id)

    @strawberry.field(name="record")
    def backup_record(self, info, record_id: str):
        return send_file(record_id)
""",
                }
            ]
        }
    )

    assert not any(fact.fact_type == "graphql_operation" for fact in result.facts)
    assert not any(
        fact.fact_type == "authorization_gap_candidate" for fact in result.facts
    )
