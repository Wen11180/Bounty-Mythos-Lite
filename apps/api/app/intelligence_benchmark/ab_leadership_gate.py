"""A+B Candidate Hunter leadership gate (lab / synthetic hard corpus).

Claim scope: authorized policy/API/HAR/local-code falsification quality only.
Does not claim live-program or XBOW superiority.
"""

from __future__ import annotations

import json
from typing import Any

from app.candidate_hunter_loop import (
    advance_candidate_hunter_round,
    build_candidate_hunter_observations,
)
from app.falsification_engine import validate_falsification_card
from app.multi_engine_verifier import (
    VERDICT_FALSE_POSITIVE_LIKELY,
    VERDICT_LOCAL_STATIC_CONSISTENT,
    verdict_from_hunter_and_map,
)


REQUIRED_METRICS = (
    "scenario_pass_rate",
    "safety_rate",
    "falsify_coverage",
    "card_valid_rate",
    "retain_hit",
    "refute_kill",
    "suppress_kill",
    "needs_evidence_card_rate",
    "dedupe_kill",
    "rank_order_hit",
    "nested_refute_kill",
    "multi_engine_agree",
    "python_refute_kill",
    "tenant_refute_kill",
    "inline_refute_kill",
    "async_refute_kill",
    "multihop_refute_kill",
    "role_owner_and_refute_kill",
    "membership_refute_kill",
    "bool_helper_refute_kill",
    "workspace_refute_kill",
    "assert_refute_kill",
    "or_refute_kill",
    "gated_eq_refute_kill",
    "decorator_refute_kill",
    "query_filter_refute_kill",
    "depends_refute_kill",
    "ts_membership_refute_kill",
    "cross_file_py_refute_kill",
    "cross_file_bool_refute_kill",
    "class_method_refute_kill",
    "ts_cross_file_refute_kill",
    "assign_helper_refute_kill",
    "service_layer_refute_kill",
    "g_current_user_refute_kill",
    "or_admin_owner_refute_kill",
    "ts_middleware_refute_kill",
    "team_refute_kill",
    "ts_service_layer_refute_kill",
    "created_by_refute_kill",
    "with_context_refute_kill",
    "ts_use_middleware_refute_kill",
    "django_view_refute_kill",
    "ts_nestjs_guard_refute_kill",
    "author_id_refute_kill",
    "try_ensure_refute_kill",
    "ternary_refute_kill",
    "response_403_refute_kill",
    "getattr_owner_refute_kill",
    "request_state_refute_kill",
    "graphql_context_refute_kill",
    "ts_prisma_owner_refute_kill",
    "guard_after_sink_retain_hit",
    "login_only_retain_hit",
    "ts_guard_after_sink_retain_hit",
    "walrus_refute_kill",
    "match_refute_kill",
    "status_only_retain_hit",
    "wrong_field_retain_hit",
    "role_only_retain_hit",
    "ts_login_only_retain_hit",
    "ts_role_only_retain_hit",
    "hardcoded_owner_retain_hit",
    "spoofable_principal_retain_hit",
    "wrong_object_retain_hit",
    "ts_hardcoded_owner_retain_hit",
    "ts_status_only_retain_hit",
    "query_param_principal_retain_hit",
    "java_refute_kill",
    "go_refute_kill",
    "rails_refute_kill",
    "java_role_only_retain_hit",
    "go_role_only_retain_hit",
    "rails_role_only_retain_hit",
    "java_status_only_retain_hit",
    "java_service_refute_kill",
    "go_middleware_refute_kill",
    "rails_before_action_refute_kill",
    "java_guard_after_sink_retain_hit",
    "go_status_only_retain_hit",
    "rails_status_only_retain_hit",
    "csharp_refute_kill",
    "php_refute_kill",
    "csharp_role_only_retain_hit",
    "php_role_only_retain_hit",
    "kotlin_refute_kill",
    "kotlin_role_only_retain_hit",
    "csharp_service_refute_kill",
    "php_controller_refute_kill",
    "rust_refute_kill",
    "rust_role_only_retain_hit",
    "scala_refute_kill",
    "scala_role_only_retain_hit",
)


class AbLeadershipGateError(ValueError):
    """Raised when A+B leadership gate inputs or scenarios are invalid."""


def _safe_flags(observations: dict[str, Any]) -> dict[str, Any]:
    return {
        **observations,
        "execution_allowed": False,
        "dispatch_allowed": False,
        "validation_allowed": False,
        "candidate_promotion_allowed": False,
        "report_submission_allowed": False,
        "raw_payload_processed": False,
    }


def _surface_and_context(route: str) -> tuple[list[dict], list[dict]]:
    return (
        [
            {
                "fact_type": "api_surface",
                "artifact_kind": "api",
                "route_method": "GET",
                "route_path": route,
            },
            {"fact_type": "har_context", "artifact_kind": "har"},
        ],
        [
            {"fact_type": "scope_context", "artifact_kind": "scope"},
            {"fact_type": "policy_context", "artifact_kind": "policy"},
        ],
    )


def _auth_candidate(
    *,
    route: str,
    source_path: str,
    symbol_name: str,
    root_cause: str = "missing_object_ownership_check",
    vuln_type: str = "authorization",
    hypothesis_id: str = "H-001",
    priority_score: int = 80,
) -> dict[str, Any]:
    return {
        "hypothesis_id": hypothesis_id,
        "vuln_type": vuln_type,
        "location": f"GET {route}",
        "priority_score": priority_score,
        "source_facts": [
            {
                "fact_type": "authorization_gap_candidate",
                "artifact_kind": "code",
                "source_path": source_path,
                "symbol_name": symbol_name,
                "route_method": "GET",
                "route_path": route,
                "root_cause": root_cause,
            }
        ],
    }


OWNERSHIP_TS = """
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
"""

PUBLIC_TS = """
import { Router } from "express";
const router = Router();
router.get("/records/:recordId", readRecord);
async function readRecord(req: Request, res: Response) {
  const record = await loadPublicRecord(req.params.recordId);
  return sendFile(record.path);
}
async function loadPublicRecord(recordId: string) {
  return recordStore.get(recordId, { visibility: "public" });
}
"""

UNGUARDED_SESSION_TS = """
import { Router } from "express";
const router = Router();
router.get("/sessions/:sessionId", getSession);
async function getSession(req: Request, res: Response) {
  return sendFile(req.params.sessionId);
}
"""

UNGUARDED_RECORD_TS = """
import { Router } from "express";
const router = Router();
router.get("/records/:recordId", readRecord);
async function readRecord(req: Request, res: Response) {
  return sendFile(req.params.recordId);
}
"""

MULTI_ROOT_SHARED_SERVICE_TS = """
import { Router } from "express";
const router = Router();
router.get("/records/:recordId", readRecord);
router.get("/records/:recordId/summary", readRecordSummary);
router.get("/records/:recordId/meta", readRecordMeta);
async function readRecord(req: Request, res: Response) {
  return loadRecord(req.params.recordId);
}
async function readRecordSummary(req: Request, res: Response) {
  return loadRecord(req.params.recordId);
}
async function readRecordMeta(req: Request, res: Response) {
  return loadRecord(req.params.recordId);
}
async function loadRecord(recordId: string) {
  return sendFile(recordId);
}
"""

HELD_OUT_TRANSFER_OWNERSHIP_TS = """
import { Router } from "express";
const router = Router();
router.get("/local/transfers/h9d2/:record_id", transfer_funds);
async function transfer_funds(req: Request, res: Response) {
  await verify_transfer_access(req.params.record_id, req.user);
  return transfer(req.params.record_id);
}
async function verify_transfer_access(record_id: string, user: User) {
  const record = await load_record(record_id);
  if (record.owner_id !== user.id) {
    return deny();
  }
  return record;
}
"""

NESTED_PARENT_OWNERSHIP_TS = """
import { Router } from "express";
const router = Router();
router.get("/records/:recordId", readRecord);
async function readRecord(req: Request, res: Response) {
  await verifyNestedAccess(req.params.recordId, req.user);
  return sendFile(req.params.recordId);
}
async function verifyNestedAccess(recordId: string, user: User) {
  const child = await loadChild(recordId);
  if (child.parent.ownerId !== user.id) {
    return res.sendStatus(403);
  }
  return child;
}
"""

PYTHON_OWNERSHIP_DENY_PY = """
from flask import Blueprint
bp = Blueprint("records", __name__)

@bp.get("/records/<record_id>")
def read_record(record_id):
    verify_record_access(record_id, current_user)
    return send_file(record_id)

def verify_record_access(record_id, user):
    record = load_record(record_id)
    if record.owner_id != user.id:
        return deny()
    return record
"""

PYTHON_TENANT_BOUNDARY_PY = """
from flask import Blueprint
bp = Blueprint("docs", __name__)

@bp.get("/orgs/<org_id>/docs/<doc_id>")
def read_doc(org_id, doc_id):
    verify_tenant_doc(org_id, doc_id, current_user)
    return send_file(doc_id)

def verify_tenant_doc(org_id, doc_id, user):
    doc = load_doc(doc_id)
    if doc.tenant_id != user.tenant_id:
        return deny()
    return doc
"""

PYTHON_INLINE_OWNERSHIP_PY = """
from flask import Blueprint
bp = Blueprint("records", __name__)

@bp.get("/records/<record_id>")
def read_record(record_id):
    record = load_record(record_id)
    if record.owner_id != current_user.id:
        raise PermissionError()
    return send_file(record_id)
"""

PYTHON_ASYNC_OWNERSHIP_PY = """
from fastapi import APIRouter
router = APIRouter()

@router.get("/records/{record_id}")
async def read_record(record_id: str, current_user):
    await verify_record_access(record_id, current_user)
    return send_file(record_id)

async def verify_record_access(record_id, user):
    record = await load_record(record_id)
    if record.owner_id != user.id:
        raise PermissionError()
    return record
"""

PYTHON_MULTIHOP_OWNERSHIP_PY = """
from flask import Blueprint
bp = Blueprint("items", __name__)

@bp.get("/items/<item_id>")
def read_item(item_id):
    verify_item_access(item_id, current_user)
    return send_file(item_id)

def verify_item_access(item_id, user):
    item = load_item(item_id)
    if item.folder.project.owner_id != user.id:
        raise PermissionError()
    return item
"""

PYTHON_ROLE_OWNER_AND_PY = """
from flask import Blueprint
bp = Blueprint("records", __name__)

@bp.get("/records/<record_id>")
def read_record(record_id):
    record = load_record(record_id)
    if user.role != "admin" and record.owner_id != user.id:
        return deny()
    return send_file(record_id)
"""

PYTHON_MEMBERSHIP_PY = """
from flask import Blueprint
bp = Blueprint("records", __name__)

@bp.get("/records/<record_id>")
def read_record(record_id):
    record = load_record(record_id)
    if user.id not in record.member_ids:
        return deny()
    return send_file(record_id)
"""

PYTHON_BOOL_HELPER_PY = """
from flask import Blueprint
bp = Blueprint("records", __name__)

@bp.get("/records/<record_id>")
def read_record(record_id):
    record = load_record(record_id)
    if not can_access(record, current_user):
        return deny()
    return send_file(record_id)

def can_access(record, user):
    return record.owner_id == user.id
"""

PYTHON_WORKSPACE_BOUNDARY_PY = """
from flask import Blueprint
bp = Blueprint("records", __name__)

@bp.get("/records/<record_id>")
def read_record(record_id):
    record = load_record(record_id)
    if record.workspace_id != current_user.workspace_id:
        return deny()
    return send_file(record_id)
"""

PYTHON_ASSERT_OWNERSHIP_PY = """
from flask import Blueprint
bp = Blueprint("records", __name__)

@bp.get("/records/<record_id>")
def read_record(record_id):
    record = load_record(record_id)
    assert record.owner_id == current_user.id
    return send_file(record_id)
"""

PYTHON_OR_BOUNDARY_PY = """
from flask import Blueprint
bp = Blueprint("records", __name__)

@bp.get("/records/<record_id>")
def read_record(record_id):
    record = load_record(record_id)
    if record.owner_id != current_user.id or record.team_id != current_user.team_id:
        return deny()
    return send_file(record_id)
"""

PYTHON_GATED_EQ_PY = """
from flask import Blueprint
bp = Blueprint("records", __name__)

@bp.get("/records/<record_id>")
def read_record(record_id):
    record = load_record(record_id)
    if record.owner_id == current_user.id:
        return send_file(record_id)
    return deny()
"""

PYTHON_DECORATOR_OWNERSHIP_PY = """
from flask import Blueprint
bp = Blueprint("records", __name__)

@bp.get("/records/<record_id>")
@require_ownership
def read_record(record_id):
    return send_file(record_id)
"""

PYTHON_QUERY_FILTER_PY = """
from flask import Blueprint
bp = Blueprint("records", __name__)

@bp.get("/records/<record_id>")
def read_record(record_id):
    record = Record.query.filter_by(id=record_id, owner_id=current_user.id).first_or_404()
    return send_file(record.path)
"""

PYTHON_DEPENDS_OWNERSHIP_PY = """
from fastapi import APIRouter, Depends
router = APIRouter()

@router.get("/records/{record_id}")
async def read_record(record_id: str, record=Depends(get_owned_record)):
    return send_file(record_id)

async def get_owned_record(record_id, user):
    record = await load_record(record_id)
    if record.owner_id != user.id:
        raise PermissionError()
    return record
"""

TS_MEMBERSHIP_PY = """
import { Router } from "express";
const router = Router();
router.get("/records/:recordId", readRecord);
async function readRecord(req: Request, res: Response) {
  const record = await loadRecord(req.params.recordId);
  if (!record.memberIds.includes(req.user.id)) {
    return res.sendStatus(403);
  }
  return sendFile(req.params.recordId);
}
"""





PYTHON_CROSS_FILE_AUTHZ_PY = """
def verify_record_access(record_id, user):
    record = load_record(record_id)
    if record.owner_id != user.id:
        return deny()
    return record
"""

PYTHON_CROSS_FILE_ROUTES_PY = """
from flask import Blueprint
from authz import verify_record_access
bp = Blueprint("records", __name__)

@bp.get("/records/<record_id>")
def read_record(record_id):
    verify_record_access(record_id, current_user)
    return send_file(record_id)
"""

PYTHON_CROSS_FILE_BOOL_AUTHZ_PY = """
def can_access(record, user):
    return record.owner_id == user.id
"""

PYTHON_CROSS_FILE_BOOL_ROUTES_PY = """
from flask import Blueprint
from authz import can_access
bp = Blueprint("records", __name__)

@bp.get("/records/<record_id>")
def read_record(record_id):
    record = load_record(record_id)
    if not can_access(record, current_user):
        return deny()
    return send_file(record_id)
"""

PYTHON_CLASS_METHOD_OWNERSHIP_PY = """
from flask import Blueprint
bp = Blueprint("records", __name__)

class AccessService:
    def verify(self, record_id, user):
        record = load_record(record_id)
        if record.owner_id != user.id:
            return deny()
        return record

svc = AccessService()

@bp.get("/records/<record_id>")
def read_record(record_id):
    svc.verify(record_id, current_user)
    return send_file(record_id)
"""

TS_CROSS_FILE_AUTHZ_TS = """
export async function verifyRecordAccess(recordId: string, user: User) {
  const record = await loadRecord(recordId);
  if (record.ownerId !== user.id) {
    return res.sendStatus(403);
  }
  return record;
}
"""

TS_CROSS_FILE_ROUTES_TS = """
import { Router } from "express";
import { verifyRecordAccess } from "./authz";
const router = Router();
router.get("/records/:recordId", readRecord);
async function readRecord(req: Request, res: Response) {
  await verifyRecordAccess(req.params.recordId, req.user);
  return sendFile(req.params.recordId);
}
"""



PYTHON_ASSIGN_HELPER_AUTHZ_PY = """
def verify_record_access(record_id, user):
    record = load_record(record_id)
    if record.owner_id != user.id:
        return deny()
    return record
"""

PYTHON_ASSIGN_HELPER_ROUTES_PY = """
from flask import Blueprint
from authz import verify_record_access
bp = Blueprint("records", __name__)

@bp.get("/records/<record_id>")
def read_record(record_id):
    record = verify_record_access(record_id, current_user)
    return send_file(record.path)
"""

PYTHON_SERVICE_LAYER_AUTHZ_PY = """
def ensure_owner(record, user):
    if record.owner_id != user.id:
        raise PermissionError()
"""

PYTHON_SERVICE_LAYER_SERVICE_PY = """
from authz import ensure_owner

def get_record_for_user(record_id, user):
    record = load_record(record_id)
    ensure_owner(record, user)
    return record
"""

PYTHON_SERVICE_LAYER_ROUTES_PY = """
from flask import Blueprint
from service import get_record_for_user
bp = Blueprint("records", __name__)

@bp.get("/records/<record_id>")
def read_record(record_id):
    record = get_record_for_user(record_id, current_user)
    return send_file(record.path)
"""

PYTHON_G_CURRENT_USER_PY = """
from flask import Blueprint, g
bp = Blueprint("records", __name__)

@bp.get("/records/<record_id>")
def read_record(record_id):
    record = load_record(record_id)
    if record.owner_id != g.current_user.id:
        return deny()
    return send_file(record_id)
"""

PYTHON_OR_ADMIN_OWNER_PY = """
from flask import Blueprint
bp = Blueprint("records", __name__)

@bp.get("/records/<record_id>")
def read_record(record_id):
    record = load_record(record_id)
    if user.role == "admin" or record.owner_id == user.id:
        return send_file(record_id)
    return deny()
"""

PYTHON_TEAM_BOUNDARY_PY = """
from flask import Blueprint
bp = Blueprint("records", __name__)

@bp.get("/records/<record_id>")
def read_record(record_id):
    record = load_record(record_id)
    if record.team_id != current_user.team_id:
        return deny()
    return send_file(record_id)
"""

TS_MIDDLEWARE_OWNERSHIP_TS = """
import { Router } from "express";
const router = Router();
async function requireOwner(req: Request, res: Response, next: NextFunction) {
  const record = await loadRecord(req.params.recordId);
  if (record.ownerId !== req.user.id) {
    return res.sendStatus(403);
  }
  next();
}
router.get("/records/:recordId", requireOwner, readRecord);
async function readRecord(req: Request, res: Response) {
  return sendFile(req.params.recordId);
}
"""

TS_SERVICE_LAYER_AUTHZ_TS = """
export async function ensureOwner(record: any, user: User) {
  if (record.ownerId !== user.id) {
    throw new Error("forbidden");
  }
}
"""

TS_SERVICE_LAYER_SERVICE_TS = """
import { ensureOwner } from "./authz";
export async function getRecordForUser(recordId: string, user: User) {
  const record = await loadRecord(recordId);
  await ensureOwner(record, user);
  return record;
}
"""

TS_SERVICE_LAYER_ROUTES_TS = """
import { Router } from "express";
import { getRecordForUser } from "./service";
const router = Router();
router.get("/records/:recordId", readRecord);
async function readRecord(req: Request, res: Response) {
  const record = await getRecordForUser(req.params.recordId, req.user);
  return sendFile(record.path);
}
"""

PYTHON_CREATED_BY_BOUNDARY_PY = """
from flask import Blueprint
bp = Blueprint("records", __name__)

@bp.get("/records/<record_id>")
def read_record(record_id):
    record = load_record(record_id)
    if record.created_by_id != current_user.id:
        return deny()
    return send_file(record_id)
"""

PYTHON_WITH_CONTEXT_OWNERSHIP_PY = """
from flask import Blueprint
bp = Blueprint("records", __name__)

@bp.get("/records/<record_id>")
def read_record(record_id):
    with ownership_context(record_id, current_user) as record:
        return send_file(record.path)

def ownership_context(record_id, user):
    record = load_record(record_id)
    if record.owner_id != user.id:
        raise PermissionError()
    return record
"""

TS_USE_MIDDLEWARE_OWNERSHIP_TS = """
import { Router } from "express";
const router = Router();
async function ensureOwner(req: Request, res: Response, next: NextFunction) {
  const record = await loadRecord(req.params.recordId);
  if (record.ownerId !== req.user.id) {
    return res.sendStatus(403);
  }
  next();
}
router.use("/records/:recordId", ensureOwner);
router.get("/records/:recordId", readRecord);
async function readRecord(req: Request, res: Response) {
  return sendFile(req.params.recordId);
}
"""

PYTHON_DJANGO_VIEW_OWNERSHIP_PY = """
from django.contrib.auth.decorators import login_required

@login_required
def read_record(request, record_id):
    record = Record.objects.get(pk=record_id)
    if record.owner_id != request.user.id:
        raise PermissionDenied()
    return send_file(record.path)
"""

TS_NESTJS_GUARD_OWNERSHIP_TS = """
import { Controller, Get, UseGuards, Param } from "@nestjs/common";
@Controller("records")
export class RecordsController {
  @Get(":recordId")
  @UseGuards(OwnerGuard)
  async readRecord(@Param("recordId") recordId: string) {
    return sendFile(recordId);
  }
}
class OwnerGuard {
  canActivate(context: any) {
    const record = loadRecord(context.params.recordId);
    if (record.ownerId !== context.user.id) {
      return false;
    }
    return true;
  }
}
"""

PYTHON_AUTHOR_ID_BOUNDARY_PY = """
from flask import Blueprint
bp = Blueprint("records", __name__)

@bp.get("/records/<record_id>")
def read_record(record_id):
    record = load_record(record_id)
    if record.author_id != current_user.id:
        return deny()
    return send_file(record_id)
"""

PYTHON_TRY_ENSURE_OWNER_PY = """
from flask import Blueprint
bp = Blueprint("records", __name__)

@bp.get("/records/<record_id>")
def read_record(record_id):
    record = load_record(record_id)
    try:
        ensure_owner(record, current_user)
    except PermissionError:
        raise
    return send_file(record_id)

def ensure_owner(record, user):
    if record.owner_id != user.id:
        raise PermissionError()
"""

PYTHON_TERNARY_OWNERSHIP_PY = """
from flask import Blueprint
bp = Blueprint("records", __name__)

@bp.get("/records/<record_id>")
def read_record(record_id):
    record = load_record(record_id)
    return send_file(record_id) if record.owner_id == current_user.id else deny()
"""

PYTHON_RESPONSE_403_PY = """
from flask import Blueprint, Response
bp = Blueprint("records", __name__)

@bp.get("/records/<record_id>")
def read_record(record_id):
    record = load_record(record_id)
    if record.owner_id != current_user.id:
        return Response(status=403)
    return send_file(record_id)
"""

PYTHON_GETATTR_OWNER_PY = """
from flask import Blueprint
bp = Blueprint("records", __name__)

@bp.get("/records/<record_id>")
def read_record(record_id):
    record = load_record(record_id)
    if getattr(record, "owner_id") != current_user.id:
        return deny()
    return send_file(record_id)
"""

PYTHON_REQUEST_STATE_USER_PY = """
from fastapi import FastAPI, HTTPException
app = FastAPI()

@app.get("/records/{record_id}")
def read_record(record_id: str, request):
    record = load_record(record_id)
    if record.owner_id != request.state.user.id:
        raise HTTPException(status_code=403)
    return send_file(record_id)
"""

PYTHON_GRAPHQL_CONTEXT_PY = """
def resolve_record(root, info, record_id):
    record = load_record(record_id)
    if record.owner_id != info.context.user.id:
        raise PermissionError("forbidden")
    return send_file(record_id)
"""

TS_PRISMA_OWNER_FILTER_TS = """
import { Router } from "express";
const router = Router();
router.get("/records/:recordId", readRecord);
async function readRecord(req, res) {
  const record = await prisma.record.findFirst({
    where: { id: req.params.recordId, ownerId: req.user.id },
  });
  if (!record) return res.sendStatus(404);
  return sendFile(record.path);
}
"""

PYTHON_GUARD_AFTER_SINK_PY = """
from flask import Blueprint
bp = Blueprint("records", __name__)

@bp.get("/records/<record_id>")
def read_record(record_id):
    record = load_record(record_id)
    data = send_file(record_id)
    if record.owner_id != current_user.id:
        return deny()
    return data
"""

PYTHON_LOGIN_ONLY_PY = """
from flask import Blueprint
bp = Blueprint("records", __name__)

@bp.get("/records/<record_id>")
def read_record(record_id):
    if not current_user.is_authenticated:
        return deny()
    record = load_record(record_id)
    return send_file(record_id)
"""

TS_GUARD_AFTER_SINK_TS = """
import { Router } from "express";
const router = Router();
router.get("/records/:recordId", readRecord);
async function readRecord(req, res) {
  const record = await loadRecord(req.params.recordId);
  const data = await sendFile(record.path);
  if (record.ownerId !== req.user.id) {
    return res.sendStatus(403);
  }
  return data;
}
"""

PYTHON_WALRUS_OWNERSHIP_PY = """
from flask import Blueprint
bp = Blueprint("records", __name__)

@bp.get("/records/<record_id>")
def read_record(record_id):
    record = load_record(record_id)
    if (owner := record.owner_id) != current_user.id:
        return deny()
    return send_file(record_id)
"""

PYTHON_MATCH_OWNERSHIP_PY = """
from flask import Blueprint
bp = Blueprint("records", __name__)

@bp.get("/records/<record_id>")
def read_record(record_id):
    record = load_record(record_id)
    match record.owner_id == current_user.id:
        case True:
            return send_file(record_id)
        case False:
            return deny()
"""

# Ineffective-but-present guards: must RETAIN (do not false-refute).
PYTHON_STATUS_ONLY_PY = """
from flask import Blueprint
bp = Blueprint("records", __name__)

@bp.get("/records/<record_id>")
def read_record(record_id):
    record = load_record(record_id)
    if record.status != "active":
        return deny()
    return send_file(record_id)
"""

PYTHON_WRONG_FIELD_COMPARE_PY = """
from flask import Blueprint
bp = Blueprint("records", __name__)

@bp.get("/records/<record_id>")
def read_record(record_id):
    record = load_record(record_id)
    if record.status_id != current_user.id:
        return deny()
    return send_file(record_id)
"""

PYTHON_ROLE_ONLY_PY = """
from flask import Blueprint
bp = Blueprint("records", __name__)

@bp.get("/records/<record_id>")
def read_record(record_id):
    if not current_user.is_admin:
        return deny()
    record = load_record(record_id)
    return send_file(record_id)
"""

TS_LOGIN_ONLY_TS = """
import { Router } from "express";
const router = Router();
router.get("/records/:recordId", readRecord);
async function readRecord(req, res) {
  if (!req.user) {
    return res.sendStatus(401);
  }
  const record = await loadRecord(req.params.recordId);
  return sendFile(record.path);
}
"""

TS_ROLE_ONLY_TS = """
import { Router } from "express";
const router = Router();
router.get("/records/:recordId", readRecord);
async function readRecord(req, res) {
  if (req.user.role !== "admin") {
    return res.sendStatus(403);
  }
  const record = await loadRecord(req.params.recordId);
  return sendFile(record.path);
}
"""

PYTHON_HARDCODED_OWNER_PY = """
from flask import Blueprint
bp = Blueprint("records", __name__)

@bp.get("/records/<record_id>")
def read_record(record_id):
    record = load_record(record_id)
    if record.owner_id != 1:
        return deny()
    return send_file(record_id)
"""

PYTHON_SPOOFABLE_HEADER_PY = """
from flask import Blueprint
bp = Blueprint("records", __name__)

@bp.get("/records/<record_id>")
def read_record(record_id):
    record = load_record(record_id)
    if record.owner_id != request.headers.get("X-User-Id"):
        return deny()
    return send_file(record_id)
"""

PYTHON_WRONG_OBJECT_UNRELATED_PY = """
from flask import Blueprint
bp = Blueprint("records", __name__)

@bp.get("/records/<record_id>")
def read_record(record_id):
    record = load_record(record_id)
    template = load_template("default")
    if template.owner_id != current_user.id:
        return deny()
    return send_file(record_id)
"""

TS_HARDCODED_OWNER_TS = """
import { Router } from "express";
const router = Router();
router.get("/records/:recordId", readRecord);
async function readRecord(req, res) {
  const record = await loadRecord(req.params.recordId);
  if (record.ownerId !== 1) {
    return res.sendStatus(403);
  }
  return sendFile(record.path);
}
"""

TS_STATUS_ONLY_TS = """
import { Router } from "express";
const router = Router();
router.get("/records/:recordId", readRecord);
async function readRecord(req, res) {
  const record = await loadRecord(req.params.recordId);
  if (record.status !== "active") {
    return res.sendStatus(403);
  }
  return sendFile(record.path);
}
"""

PYTHON_QUERY_PARAM_PRINCIPAL_PY = """
from flask import Blueprint
bp = Blueprint("records", __name__)

@bp.get("/records/<record_id>")
def read_record(record_id):
    record = load_record(record_id)
    if record.owner_id != request.args.get("user_id"):
        return deny()
    return send_file(record_id)
"""

# Multi-language held-out: Spring/Java, Go, Rails ownership refute + invalid-guard retain.
JAVA_OWNERSHIP_JAVA = """
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

JAVA_ROLE_ONLY_JAVA = """
@RestController
public class RecordsController {
  @GetMapping("/records/{recordId}")
  public Object readRecord(String recordId, User user) {
    if (!user.getRole().equals("admin")) {
      return deny();
    }
    Record record = loadRecord(recordId);
    return sendFile(record.getPath());
  }
}
"""

JAVA_STATUS_ONLY_JAVA = """
@RestController
public class RecordsController {
  @GetMapping("/records/{recordId}")
  public Object readRecord(String recordId, User user) {
    Record record = loadRecord(recordId);
    if (!record.getStatus().equals("active")) {
      return deny();
    }
    return sendFile(record.getPath());
  }
}
"""

GO_OWNERSHIP_GO = """
package handlers

func mount(r Router) {
  r.GET("/records/{recordId}", readRecord)
}

func readRecord(w http.ResponseWriter, r *http.Request) {
  record := loadRecord(recordId)
  if record.OwnerID != user.ID {
    return
  }
  sendFile(w, record.Path)
}
"""

GO_ROLE_ONLY_GO = """
package handlers

func mount(r Router) {
  r.GET("/records/{recordId}", readRecord)
}

func readRecord(w http.ResponseWriter, r *http.Request) {
  if user.Role != "admin" {
    return
  }
  record := loadRecord(recordId)
  sendFile(w, record.Path)
}
"""

RAILS_OWNERSHIP_RB = """
get "/records/:record_id", to: "records#read_record"

def read_record
  record = load_record(params[:record_id])
  if record.owner_id != current_user.id
    deny
  end
  send_file record.path
end
"""

RAILS_ROLE_ONLY_RB = """
get "/records/:record_id", to: "records#read_record"

def read_record
  if current_user.role != "admin"
    deny
  end
  record = load_record(params[:record_id])
  send_file record.path
end
"""

JAVA_SERVICE_LAYER_JAVA = """
@RestController
public class RecordsController {
  private final RecordService recordService = new RecordService();

  @GetMapping("/records/{recordId}")
  public Object readRecord(String recordId, User user) {
    Record record = recordService.getForUser(recordId, user);
    return sendFile(record.getPath());
  }
}

class RecordService {
  public Record getForUser(String recordId, User user) {
    Record record = loadRecord(recordId);
    if (!record.getOwnerId().equals(user.getId())) {
      throw new AccessDeniedException("forbidden");
    }
    return record;
  }
}
"""

JAVA_GUARD_AFTER_SINK_JAVA = """
@RestController
public class RecordsController {
  @GetMapping("/records/{recordId}")
  public Object readRecord(String recordId, User user) {
    Record record = loadRecord(recordId);
    Object out = sendFile(record.getPath());
    if (!record.getOwnerId().equals(user.getId())) {
      return deny();
    }
    return out;
  }
}
"""

GO_MIDDLEWARE_OWNERSHIP_GO = """
package handlers

func mount(r Router) {
  r.GET("/records/{recordId}", requireOwner, readRecord)
}

func requireOwner(next Handler) Handler {
  record := loadRecord(recordId)
  if record.OwnerID != user.ID {
    return
  }
  return next
}

func readRecord(w http.ResponseWriter, r *http.Request) {
  sendFile(w, record.Path)
}
"""

GO_STATUS_ONLY_GO = """
package handlers

func mount(r Router) {
  r.GET("/records/{recordId}", readRecord)
}

func readRecord(w http.ResponseWriter, r *http.Request) {
  record := loadRecord(recordId)
  if record.Status != "active" {
    return
  }
  sendFile(w, record.Path)
}
"""

RAILS_BEFORE_ACTION_OWNERSHIP_RB = """
before_action :ensure_owner
get "/records/:record_id", to: "records#read_record"

def ensure_owner
  record = load_record(params[:record_id])
  if record.owner_id != current_user.id
    deny
  end
end

def read_record
  send_file record.path
end
"""

RAILS_STATUS_ONLY_RB = """
get "/records/:record_id", to: "records#read_record"

def read_record
  record = load_record(params[:record_id])
  if record.status != "active"
    deny
  end
  send_file record.path
end
"""

CSHARP_OWNERSHIP_CS = """
public class RecordsController {
  [HttpGet("/records/{id}")]
  public IActionResult GetRecord(int id) {
    var record = LoadRecord(id);
    if (record.OwnerId != user.Id) {
      return Forbid();
    }
    return File(record.Path);
  }
}
"""

CSHARP_ROLE_ONLY_CS = """
public class RecordsController {
  [HttpGet("/records/{id}")]
  public IActionResult GetRecord(int id) {
    if (user.Role != "admin") {
      return Forbid();
    }
    return File(record.Path);
  }
}
"""

PHP_OWNERSHIP_PHP = """
<?php
Route::get('/records/{id}', function ($id) {
  $record = load_record($id);
  if ($record->owner_id != $user->id) {
    abort(403);
  }
  return response()->download($record->path);
});
"""

PHP_ROLE_ONLY_PHP = """
<?php
Route::get('/records/{id}', function ($id) {
  if ($user->role != 'admin') {
    abort(403);
  }
  return response()->download($record->path);
});
"""

KOTLIN_OWNERSHIP_KT = """
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

KOTLIN_ROLE_ONLY_KT = """
@RestController
class RecordsController {
  @GetMapping("/records/{recordId}")
  fun readRecord(recordId: String, user: User): Any {
    if (user.role != "admin") {
      return deny()
    }
    val record = loadRecord(recordId)
    return sendFile(record.path)
  }
}
"""

CSHARP_SERVICE_LAYER_CS = """
public class RecordsController {
  private RecordService recordService = new RecordService();
  [HttpGet("/records/{id}")]
  public IActionResult GetRecord(int id) {
    var record = recordService.GetForUser(id, user);
    return File(record.Path);
  }
}
public class RecordService {
  public Record GetForUser(int id, User user) {
    var record = LoadRecord(id);
    if (record.OwnerId != user.Id) {
      throw new UnauthorizedAccessException();
    }
    return record;
  }
}
"""

PHP_CONTROLLER_OWNERSHIP_PHP = """
<?php
function show($id) {
  $record = load_record($id);
  if ($record->owner_id != $user->id) {
    abort(403);
  }
  return response()->download($record->path);
}
Route::get('/records/{id}', [RecordsController::class, 'show']);
"""

RUST_OWNERSHIP_RS = """
#[get("/records/{id}")]
async fn read_record() {
    let record = load_record(id);
    if record.owner_id != user.id {
        return deny();
    }
    send_file(&record.path)
}
"""

RUST_ROLE_ONLY_RS = """
#[get("/records/{id}")]
async fn read_record() {
    if user.role != "admin" {
        return deny();
    }
    let record = load_record(id);
    send_file(&record.path)
}
"""

SCALA_OWNERSHIP_SCALA = """
@GetMapping("/records/{recordId}")
def readRecord(recordId: String, user: User) = {
  val record = loadRecord(recordId)
  if (record.ownerId != user.id) {
    return deny()
  }
  sendFile(record.path)
}
"""

SCALA_ROLE_ONLY_SCALA = """
@GetMapping("/records/{recordId}")
def readRecord(recordId: String, user: User) = {
  if (user.role != "admin") {
    return deny()
  }
  val record = loadRecord(recordId)
  sendFile(record.path)
}
"""



def _run_round(observations: dict[str, Any]) -> dict[str, Any]:
    return advance_candidate_hunter_round(
        pipeline_run_id="ab-leadership",
        round_number=1,
        candidate_states=list(observations.get("candidate_states") or []),
        observations=_safe_flags(observations),
        prior_decisions=[],
    )


def _scenario_catalog() -> list[dict[str, Any]]:
    route_records = "/records/{record_id}"
    route_sessions = "/sessions/{session_id}"
    route_transfer = "/local/transfers/h9d2/{record_id}"
    surface_r, context_r = _surface_and_context(route_records)
    surface_s, context_s = _surface_and_context(route_sessions)
    surface_t, context_t = _surface_and_context(route_transfer)

    retain_obs = build_candidate_hunter_observations(
        pipeline_run_id="ab-leadership",
        candidates=[
            _auth_candidate(
                route=route_sessions,
                source_path="sessions.ts",
                symbol_name="getSession",
                root_cause="missing_session_binding_check",
                vuln_type="authentication",
            )
        ],
        code_files=[{"path": "sessions.ts", "content": UNGUARDED_SESSION_TS}],
        surface_facts=surface_s,
        context_facts=context_s,
    )
    refute_obs = build_candidate_hunter_observations(
        pipeline_run_id="ab-leadership",
        candidates=[
            _auth_candidate(
                route=route_records,
                source_path="routes.ts",
                symbol_name="readRecord",
            )
        ],
        code_files=[{"path": "routes.ts", "content": OWNERSHIP_TS}],
        surface_facts=surface_r,
        context_facts=context_r,
    )
    suppress_obs = build_candidate_hunter_observations(
        pipeline_run_id="ab-leadership",
        candidates=[
            _auth_candidate(
                route=route_records,
                source_path="routes.ts",
                symbol_name="readRecord",
            )
        ],
        code_files=[{"path": "routes.ts", "content": PUBLIC_TS}],
        surface_facts=surface_r,
        context_facts=context_r,
    )
    needs_obs = build_candidate_hunter_observations(
        pipeline_run_id="ab-leadership",
        candidates=[
            {
                "hypothesis_id": "H-001",
                "vuln_type": "authorization",
                "location": f"GET {route_records}",
                "priority_score": 80,
                "source_facts": [
                    {
                        "fact_type": "authorization_gap_candidate",
                        "artifact_kind": "api",
                        "route_method": "GET",
                        "route_path": route_records,
                        "root_cause": "missing_object_ownership_check",
                    }
                ],
            }
        ],
        code_files=[],
        surface_facts=surface_r,
        context_facts=context_r,
    )

    multi_routes = [
        "/records/{record_id}",
        "/records/{record_id}/summary",
        "/records/{record_id}/meta",
    ]
    multi_symbols = ["readRecord", "readRecordSummary", "readRecordMeta"]
    multi_surface = [
        {
            "fact_type": "api_surface",
            "artifact_kind": "api",
            "route_method": "GET",
            "route_path": route,
        }
        for route in multi_routes
    ] + [{"fact_type": "har_context", "artifact_kind": "har"}]
    multi_candidates = [
        _auth_candidate(
            route=route,
            source_path="routes.ts",
            symbol_name=symbol,
            hypothesis_id=f"H-00{index}",
            priority_score=90 - (index - 1) * 5,
        )
        for index, (route, symbol) in enumerate(
            zip(multi_routes, multi_symbols, strict=True),
            start=1,
        )
    ]
    multi_obs = build_candidate_hunter_observations(
        pipeline_run_id="ab-leadership",
        candidates=multi_candidates,
        code_files=[{"path": "routes.ts", "content": MULTI_ROOT_SHARED_SERVICE_TS}],
        surface_facts=multi_surface,
        context_facts=context_r,
    )

    held_out_obs = build_candidate_hunter_observations(
        pipeline_run_id="ab-leadership",
        candidates=[
            _auth_candidate(
                route=route_transfer,
                source_path="code.ts",
                symbol_name="transfer_funds",
            )
        ],
        code_files=[{"path": "code.ts", "content": HELD_OUT_TRANSFER_OWNERSHIP_TS}],
        surface_facts=surface_t,
        context_facts=context_t,
    )

    rank_obs = build_candidate_hunter_observations(
        pipeline_run_id="ab-leadership",
        candidates=[
            _auth_candidate(
                route=route_sessions,
                source_path="sessions.ts",
                symbol_name="getSession",
                root_cause="missing_session_binding_check",
                vuln_type="authentication",
                hypothesis_id="H-001",
                priority_score=90,
            ),
            _auth_candidate(
                route=route_records,
                source_path="records.ts",
                symbol_name="readRecord",
                hypothesis_id="H-002",
                priority_score=50,
            ),
        ],
        code_files=[
            {"path": "sessions.ts", "content": UNGUARDED_SESSION_TS},
            {"path": "records.ts", "content": UNGUARDED_RECORD_TS},
        ],
        surface_facts=[
            {
                "fact_type": "api_surface",
                "artifact_kind": "api",
                "route_method": "GET",
                "route_path": route_sessions,
            },
            {
                "fact_type": "api_surface",
                "artifact_kind": "api",
                "route_method": "GET",
                "route_path": route_records,
            },
            {"fact_type": "har_context", "artifact_kind": "har"},
        ],
        context_facts=context_r,
    )

    nested_obs = build_candidate_hunter_observations(
        pipeline_run_id="ab-leadership",
        candidates=[
            _auth_candidate(
                route=route_records,
                source_path="routes.ts",
                symbol_name="readRecord",
            )
        ],
        code_files=[{"path": "routes.ts", "content": NESTED_PARENT_OWNERSHIP_TS}],
        surface_facts=surface_r,
        context_facts=context_r,
    )

    route_org_doc = "/orgs/{org_id}/docs/{doc_id}"
    surface_o, context_o = _surface_and_context(route_org_doc)
    python_owner_obs = build_candidate_hunter_observations(
        pipeline_run_id="ab-leadership",
        candidates=[
            _auth_candidate(
                route=route_records,
                source_path="routes.py",
                symbol_name="read_record",
            )
        ],
        code_files=[{"path": "routes.py", "content": PYTHON_OWNERSHIP_DENY_PY}],
        surface_facts=surface_r,
        context_facts=context_r,
    )
    python_tenant_obs = build_candidate_hunter_observations(
        pipeline_run_id="ab-leadership",
        candidates=[
            _auth_candidate(
                route=route_org_doc,
                source_path="routes.py",
                symbol_name="read_doc",
            )
        ],
        code_files=[{"path": "routes.py", "content": PYTHON_TENANT_BOUNDARY_PY}],
        surface_facts=surface_o,
        context_facts=context_o,
    )

    python_inline_obs = build_candidate_hunter_observations(
        pipeline_run_id="ab-leadership",
        candidates=[
            _auth_candidate(
                route=route_records,
                source_path="routes.py",
                symbol_name="read_record",
            )
        ],
        code_files=[{"path": "routes.py", "content": PYTHON_INLINE_OWNERSHIP_PY}],
        surface_facts=surface_r,
        context_facts=context_r,
    )
    python_async_obs = build_candidate_hunter_observations(
        pipeline_run_id="ab-leadership",
        candidates=[
            _auth_candidate(
                route=route_records,
                source_path="routes.py",
                symbol_name="read_record",
            )
        ],
        code_files=[{"path": "routes.py", "content": PYTHON_ASYNC_OWNERSHIP_PY}],
        surface_facts=surface_r,
        context_facts=context_r,
    )
    route_items = "/items/{item_id}"
    surface_i, context_i = _surface_and_context(route_items)
    python_multihop_obs = build_candidate_hunter_observations(
        pipeline_run_id="ab-leadership",
        candidates=[
            _auth_candidate(
                route=route_items,
                source_path="routes.py",
                symbol_name="read_item",
            )
        ],
        code_files=[{"path": "routes.py", "content": PYTHON_MULTIHOP_OWNERSHIP_PY}],
        surface_facts=surface_i,
        context_facts=context_i,
    )
    python_role_owner_obs = build_candidate_hunter_observations(
        pipeline_run_id="ab-leadership",
        candidates=[
            _auth_candidate(
                route=route_records,
                source_path="routes.py",
                symbol_name="read_record",
            )
        ],
        code_files=[{"path": "routes.py", "content": PYTHON_ROLE_OWNER_AND_PY}],
        surface_facts=surface_r,
        context_facts=context_r,
    )
    python_membership_obs = build_candidate_hunter_observations(
        pipeline_run_id="ab-leadership",
        candidates=[
            _auth_candidate(
                route=route_records,
                source_path="routes.py",
                symbol_name="read_record",
            )
        ],
        code_files=[{"path": "routes.py", "content": PYTHON_MEMBERSHIP_PY}],
        surface_facts=surface_r,
        context_facts=context_r,
    )
    python_bool_helper_obs = build_candidate_hunter_observations(
        pipeline_run_id="ab-leadership",
        candidates=[
            _auth_candidate(
                route=route_records,
                source_path="routes.py",
                symbol_name="read_record",
            )
        ],
        code_files=[{"path": "routes.py", "content": PYTHON_BOOL_HELPER_PY}],
        surface_facts=surface_r,
        context_facts=context_r,
    )
    python_workspace_obs = build_candidate_hunter_observations(
        pipeline_run_id="ab-leadership",
        candidates=[
            _auth_candidate(
                route=route_records,
                source_path="routes.py",
                symbol_name="read_record",
            )
        ],
        code_files=[{"path": "routes.py", "content": PYTHON_WORKSPACE_BOUNDARY_PY}],
        surface_facts=surface_r,
        context_facts=context_r,
    )
    python_assert_obs = build_candidate_hunter_observations(
        pipeline_run_id="ab-leadership",
        candidates=[
            _auth_candidate(
                route=route_records,
                source_path="routes.py",
                symbol_name="read_record",
            )
        ],
        code_files=[{"path": "routes.py", "content": PYTHON_ASSERT_OWNERSHIP_PY}],
        surface_facts=surface_r,
        context_facts=context_r,
    )
    python_or_obs = build_candidate_hunter_observations(
        pipeline_run_id="ab-leadership",
        candidates=[
            _auth_candidate(
                route=route_records,
                source_path="routes.py",
                symbol_name="read_record",
            )
        ],
        code_files=[{"path": "routes.py", "content": PYTHON_OR_BOUNDARY_PY}],
        surface_facts=surface_r,
        context_facts=context_r,
    )
    python_gated_obs = build_candidate_hunter_observations(
        pipeline_run_id="ab-leadership",
        candidates=[
            _auth_candidate(
                route=route_records,
                source_path="routes.py",
                symbol_name="read_record",
            )
        ],
        code_files=[{"path": "routes.py", "content": PYTHON_GATED_EQ_PY}],
        surface_facts=surface_r,
        context_facts=context_r,
    )
    python_decorator_obs = build_candidate_hunter_observations(
        pipeline_run_id="ab-leadership",
        candidates=[
            _auth_candidate(
                route=route_records,
                source_path="routes.py",
                symbol_name="read_record",
            )
        ],
        code_files=[{"path": "routes.py", "content": PYTHON_DECORATOR_OWNERSHIP_PY}],
        surface_facts=surface_r,
        context_facts=context_r,
    )
    python_query_filter_obs = build_candidate_hunter_observations(
        pipeline_run_id="ab-leadership",
        candidates=[
            _auth_candidate(
                route=route_records,
                source_path="routes.py",
                symbol_name="read_record",
            )
        ],
        code_files=[{"path": "routes.py", "content": PYTHON_QUERY_FILTER_PY}],
        surface_facts=surface_r,
        context_facts=context_r,
    )
    python_depends_obs = build_candidate_hunter_observations(
        pipeline_run_id="ab-leadership",
        candidates=[
            _auth_candidate(
                route=route_records,
                source_path="routes.py",
                symbol_name="read_record",
            )
        ],
        code_files=[{"path": "routes.py", "content": PYTHON_DEPENDS_OWNERSHIP_PY}],
        surface_facts=surface_r,
        context_facts=context_r,
    )
    ts_membership_obs = build_candidate_hunter_observations(
        pipeline_run_id="ab-leadership",
        candidates=[
            _auth_candidate(
                route=route_records,
                source_path="routes.ts",
                symbol_name="readRecord",
            )
        ],
        code_files=[{"path": "routes.ts", "content": TS_MEMBERSHIP_PY}],
        surface_facts=surface_r,
        context_facts=context_r,
    )
    python_cross_file_obs = build_candidate_hunter_observations(
        pipeline_run_id="ab-leadership",
        candidates=[
            _auth_candidate(
                route=route_records,
                source_path="routes.py",
                symbol_name="read_record",
            )
        ],
        code_files=[
            {"path": "authz.py", "content": PYTHON_CROSS_FILE_AUTHZ_PY},
            {"path": "routes.py", "content": PYTHON_CROSS_FILE_ROUTES_PY},
        ],
        surface_facts=surface_r,
        context_facts=context_r,
    )
    python_cross_file_bool_obs = build_candidate_hunter_observations(
        pipeline_run_id="ab-leadership",
        candidates=[
            _auth_candidate(
                route=route_records,
                source_path="routes.py",
                symbol_name="read_record",
            )
        ],
        code_files=[
            {"path": "authz.py", "content": PYTHON_CROSS_FILE_BOOL_AUTHZ_PY},
            {"path": "routes.py", "content": PYTHON_CROSS_FILE_BOOL_ROUTES_PY},
        ],
        surface_facts=surface_r,
        context_facts=context_r,
    )
    python_class_method_obs = build_candidate_hunter_observations(
        pipeline_run_id="ab-leadership",
        candidates=[
            _auth_candidate(
                route=route_records,
                source_path="routes.py",
                symbol_name="read_record",
            )
        ],
        code_files=[{"path": "routes.py", "content": PYTHON_CLASS_METHOD_OWNERSHIP_PY}],
        surface_facts=surface_r,
        context_facts=context_r,
    )
    ts_cross_file_obs = build_candidate_hunter_observations(
        pipeline_run_id="ab-leadership",
        candidates=[
            _auth_candidate(
                route=route_records,
                source_path="routes.ts",
                symbol_name="readRecord",
            )
        ],
        code_files=[
            {"path": "authz.ts", "content": TS_CROSS_FILE_AUTHZ_TS},
            {"path": "routes.ts", "content": TS_CROSS_FILE_ROUTES_TS},
        ],
        surface_facts=surface_r,
        context_facts=context_r,
    )
    python_assign_helper_obs = build_candidate_hunter_observations(
        pipeline_run_id="ab-leadership",
        candidates=[
            _auth_candidate(
                route=route_records,
                source_path="routes.py",
                symbol_name="read_record",
            )
        ],
        code_files=[
            {"path": "authz.py", "content": PYTHON_ASSIGN_HELPER_AUTHZ_PY},
            {"path": "routes.py", "content": PYTHON_ASSIGN_HELPER_ROUTES_PY},
        ],
        surface_facts=surface_r,
        context_facts=context_r,
    )
    python_service_layer_obs = build_candidate_hunter_observations(
        pipeline_run_id="ab-leadership",
        candidates=[
            _auth_candidate(
                route=route_records,
                source_path="routes.py",
                symbol_name="read_record",
            )
        ],
        code_files=[
            {"path": "authz.py", "content": PYTHON_SERVICE_LAYER_AUTHZ_PY},
            {"path": "service.py", "content": PYTHON_SERVICE_LAYER_SERVICE_PY},
            {"path": "routes.py", "content": PYTHON_SERVICE_LAYER_ROUTES_PY},
        ],
        surface_facts=surface_r,
        context_facts=context_r,
    )
    python_g_current_user_obs = build_candidate_hunter_observations(
        pipeline_run_id="ab-leadership",
        candidates=[
            _auth_candidate(
                route=route_records,
                source_path="routes.py",
                symbol_name="read_record",
            )
        ],
        code_files=[{"path": "routes.py", "content": PYTHON_G_CURRENT_USER_PY}],
        surface_facts=surface_r,
        context_facts=context_r,
    )
    python_or_admin_owner_obs = build_candidate_hunter_observations(
        pipeline_run_id="ab-leadership",
        candidates=[
            _auth_candidate(
                route=route_records,
                source_path="routes.py",
                symbol_name="read_record",
            )
        ],
        code_files=[{"path": "routes.py", "content": PYTHON_OR_ADMIN_OWNER_PY}],
        surface_facts=surface_r,
        context_facts=context_r,
    )
    python_team_obs = build_candidate_hunter_observations(
        pipeline_run_id="ab-leadership",
        candidates=[
            _auth_candidate(
                route=route_records,
                source_path="routes.py",
                symbol_name="read_record",
            )
        ],
        code_files=[{"path": "routes.py", "content": PYTHON_TEAM_BOUNDARY_PY}],
        surface_facts=surface_r,
        context_facts=context_r,
    )
    ts_middleware_obs = build_candidate_hunter_observations(
        pipeline_run_id="ab-leadership",
        candidates=[
            _auth_candidate(
                route=route_records,
                source_path="routes.ts",
                symbol_name="readRecord",
            )
        ],
        code_files=[{"path": "routes.ts", "content": TS_MIDDLEWARE_OWNERSHIP_TS}],
        surface_facts=surface_r,
        context_facts=context_r,
    )
    ts_service_layer_obs = build_candidate_hunter_observations(
        pipeline_run_id="ab-leadership",
        candidates=[
            _auth_candidate(
                route=route_records,
                source_path="routes.ts",
                symbol_name="readRecord",
            )
        ],
        code_files=[
            {"path": "authz.ts", "content": TS_SERVICE_LAYER_AUTHZ_TS},
            {"path": "service.ts", "content": TS_SERVICE_LAYER_SERVICE_TS},
            {"path": "routes.ts", "content": TS_SERVICE_LAYER_ROUTES_TS},
        ],
        surface_facts=surface_r,
        context_facts=context_r,
    )
    python_created_by_obs = build_candidate_hunter_observations(
        pipeline_run_id="ab-leadership",
        candidates=[
            _auth_candidate(
                route=route_records,
                source_path="routes.py",
                symbol_name="read_record",
            )
        ],
        code_files=[{"path": "routes.py", "content": PYTHON_CREATED_BY_BOUNDARY_PY}],
        surface_facts=surface_r,
        context_facts=context_r,
    )
    python_with_context_obs = build_candidate_hunter_observations(
        pipeline_run_id="ab-leadership",
        candidates=[
            _auth_candidate(
                route=route_records,
                source_path="routes.py",
                symbol_name="read_record",
            )
        ],
        code_files=[{"path": "routes.py", "content": PYTHON_WITH_CONTEXT_OWNERSHIP_PY}],
        surface_facts=surface_r,
        context_facts=context_r,
    )
    ts_use_middleware_obs = build_candidate_hunter_observations(
        pipeline_run_id="ab-leadership",
        candidates=[
            _auth_candidate(
                route=route_records,
                source_path="routes.ts",
                symbol_name="readRecord",
            )
        ],
        code_files=[{"path": "routes.ts", "content": TS_USE_MIDDLEWARE_OWNERSHIP_TS}],
        surface_facts=surface_r,
        context_facts=context_r,
    )
    python_django_view_obs = build_candidate_hunter_observations(
        pipeline_run_id="ab-leadership",
        candidates=[
            _auth_candidate(
                route=route_records,
                source_path="views.py",
                symbol_name="read_record",
            )
        ],
        code_files=[{"path": "views.py", "content": PYTHON_DJANGO_VIEW_OWNERSHIP_PY}],
        surface_facts=surface_r,
        context_facts=context_r,
    )
    ts_nestjs_guard_obs = build_candidate_hunter_observations(
        pipeline_run_id="ab-leadership",
        candidates=[
            _auth_candidate(
                route=route_records,
                source_path="routes.ts",
                symbol_name="readRecord",
            )
        ],
        code_files=[{"path": "routes.ts", "content": TS_NESTJS_GUARD_OWNERSHIP_TS}],
        surface_facts=surface_r,
        context_facts=context_r,
    )
    python_author_id_obs = build_candidate_hunter_observations(
        pipeline_run_id="ab-leadership",
        candidates=[
            _auth_candidate(
                route=route_records,
                source_path="routes.py",
                symbol_name="read_record",
            )
        ],
        code_files=[{"path": "routes.py", "content": PYTHON_AUTHOR_ID_BOUNDARY_PY}],
        surface_facts=surface_r,
        context_facts=context_r,
    )
    python_try_ensure_obs = build_candidate_hunter_observations(
        pipeline_run_id="ab-leadership",
        candidates=[
            _auth_candidate(
                route=route_records,
                source_path="routes.py",
                symbol_name="read_record",
            )
        ],
        code_files=[{"path": "routes.py", "content": PYTHON_TRY_ENSURE_OWNER_PY}],
        surface_facts=surface_r,
        context_facts=context_r,
    )
    python_ternary_obs = build_candidate_hunter_observations(
        pipeline_run_id="ab-leadership",
        candidates=[
            _auth_candidate(
                route=route_records,
                source_path="routes.py",
                symbol_name="read_record",
            )
        ],
        code_files=[{"path": "routes.py", "content": PYTHON_TERNARY_OWNERSHIP_PY}],
        surface_facts=surface_r,
        context_facts=context_r,
    )
    python_response_403_obs = build_candidate_hunter_observations(
        pipeline_run_id="ab-leadership",
        candidates=[
            _auth_candidate(
                route=route_records,
                source_path="routes.py",
                symbol_name="read_record",
            )
        ],
        code_files=[{"path": "routes.py", "content": PYTHON_RESPONSE_403_PY}],
        surface_facts=surface_r,
        context_facts=context_r,
    )
    python_getattr_owner_obs = build_candidate_hunter_observations(
        pipeline_run_id="ab-leadership",
        candidates=[
            _auth_candidate(
                route=route_records,
                source_path="routes.py",
                symbol_name="read_record",
            )
        ],
        code_files=[{"path": "routes.py", "content": PYTHON_GETATTR_OWNER_PY}],
        surface_facts=surface_r,
        context_facts=context_r,
    )
    python_request_state_obs = build_candidate_hunter_observations(
        pipeline_run_id="ab-leadership",
        candidates=[
            _auth_candidate(
                route=route_records,
                source_path="routes.py",
                symbol_name="read_record",
            )
        ],
        code_files=[{"path": "routes.py", "content": PYTHON_REQUEST_STATE_USER_PY}],
        surface_facts=surface_r,
        context_facts=context_r,
    )
    python_graphql_context_obs = build_candidate_hunter_observations(
        pipeline_run_id="ab-leadership",
        candidates=[
            _auth_candidate(
                route=route_records,
                source_path="routes.py",
                symbol_name="resolve_record",
            )
        ],
        code_files=[{"path": "routes.py", "content": PYTHON_GRAPHQL_CONTEXT_PY}],
        surface_facts=surface_r,
        context_facts=context_r,
    )
    ts_prisma_owner_obs = build_candidate_hunter_observations(
        pipeline_run_id="ab-leadership",
        candidates=[
            _auth_candidate(
                route=route_records,
                source_path="routes.ts",
                symbol_name="readRecord",
            )
        ],
        code_files=[{"path": "routes.ts", "content": TS_PRISMA_OWNER_FILTER_TS}],
        surface_facts=surface_r,
        context_facts=context_r,
    )
    python_guard_after_sink_obs = build_candidate_hunter_observations(
        pipeline_run_id="ab-leadership",
        candidates=[
            _auth_candidate(
                route=route_records,
                source_path="routes.py",
                symbol_name="read_record",
            )
        ],
        code_files=[{"path": "routes.py", "content": PYTHON_GUARD_AFTER_SINK_PY}],
        surface_facts=surface_r,
        context_facts=context_r,
    )
    python_login_only_obs = build_candidate_hunter_observations(
        pipeline_run_id="ab-leadership",
        candidates=[
            _auth_candidate(
                route=route_records,
                source_path="routes.py",
                symbol_name="read_record",
            )
        ],
        code_files=[{"path": "routes.py", "content": PYTHON_LOGIN_ONLY_PY}],
        surface_facts=surface_r,
        context_facts=context_r,
    )
    ts_guard_after_sink_obs = build_candidate_hunter_observations(
        pipeline_run_id="ab-leadership",
        candidates=[
            _auth_candidate(
                route=route_records,
                source_path="routes.ts",
                symbol_name="readRecord",
            )
        ],
        code_files=[{"path": "routes.ts", "content": TS_GUARD_AFTER_SINK_TS}],
        surface_facts=surface_r,
        context_facts=context_r,
    )
    python_walrus_obs = build_candidate_hunter_observations(
        pipeline_run_id="ab-leadership",
        candidates=[
            _auth_candidate(
                route=route_records,
                source_path="routes.py",
                symbol_name="read_record",
            )
        ],
        code_files=[{"path": "routes.py", "content": PYTHON_WALRUS_OWNERSHIP_PY}],
        surface_facts=surface_r,
        context_facts=context_r,
    )
    python_match_obs = build_candidate_hunter_observations(
        pipeline_run_id="ab-leadership",
        candidates=[
            _auth_candidate(
                route=route_records,
                source_path="routes.py",
                symbol_name="read_record",
            )
        ],
        code_files=[{"path": "routes.py", "content": PYTHON_MATCH_OWNERSHIP_PY}],
        surface_facts=surface_r,
        context_facts=context_r,
    )
    python_status_only_obs = build_candidate_hunter_observations(
        pipeline_run_id="ab-leadership",
        candidates=[
            _auth_candidate(
                route=route_records,
                source_path="routes.py",
                symbol_name="read_record",
            )
        ],
        code_files=[{"path": "routes.py", "content": PYTHON_STATUS_ONLY_PY}],
        surface_facts=surface_r,
        context_facts=context_r,
    )
    python_wrong_field_obs = build_candidate_hunter_observations(
        pipeline_run_id="ab-leadership",
        candidates=[
            _auth_candidate(
                route=route_records,
                source_path="routes.py",
                symbol_name="read_record",
            )
        ],
        code_files=[{"path": "routes.py", "content": PYTHON_WRONG_FIELD_COMPARE_PY}],
        surface_facts=surface_r,
        context_facts=context_r,
    )
    python_role_only_obs = build_candidate_hunter_observations(
        pipeline_run_id="ab-leadership",
        candidates=[
            _auth_candidate(
                route=route_records,
                source_path="routes.py",
                symbol_name="read_record",
            )
        ],
        code_files=[{"path": "routes.py", "content": PYTHON_ROLE_ONLY_PY}],
        surface_facts=surface_r,
        context_facts=context_r,
    )
    ts_login_only_obs = build_candidate_hunter_observations(
        pipeline_run_id="ab-leadership",
        candidates=[
            _auth_candidate(
                route=route_records,
                source_path="routes.ts",
                symbol_name="readRecord",
            )
        ],
        code_files=[{"path": "routes.ts", "content": TS_LOGIN_ONLY_TS}],
        surface_facts=surface_r,
        context_facts=context_r,
    )
    ts_role_only_obs = build_candidate_hunter_observations(
        pipeline_run_id="ab-leadership",
        candidates=[
            _auth_candidate(
                route=route_records,
                source_path="routes.ts",
                symbol_name="readRecord",
            )
        ],
        code_files=[{"path": "routes.ts", "content": TS_ROLE_ONLY_TS}],
        surface_facts=surface_r,
        context_facts=context_r,
    )
    python_hardcoded_owner_obs = build_candidate_hunter_observations(
        pipeline_run_id="ab-leadership",
        candidates=[
            _auth_candidate(
                route=route_records,
                source_path="routes.py",
                symbol_name="read_record",
            )
        ],
        code_files=[{"path": "routes.py", "content": PYTHON_HARDCODED_OWNER_PY}],
        surface_facts=surface_r,
        context_facts=context_r,
    )
    python_spoofable_header_obs = build_candidate_hunter_observations(
        pipeline_run_id="ab-leadership",
        candidates=[
            _auth_candidate(
                route=route_records,
                source_path="routes.py",
                symbol_name="read_record",
            )
        ],
        code_files=[{"path": "routes.py", "content": PYTHON_SPOOFABLE_HEADER_PY}],
        surface_facts=surface_r,
        context_facts=context_r,
    )
    python_wrong_object_obs = build_candidate_hunter_observations(
        pipeline_run_id="ab-leadership",
        candidates=[
            _auth_candidate(
                route=route_records,
                source_path="routes.py",
                symbol_name="read_record",
            )
        ],
        code_files=[{"path": "routes.py", "content": PYTHON_WRONG_OBJECT_UNRELATED_PY}],
        surface_facts=surface_r,
        context_facts=context_r,
    )
    ts_hardcoded_owner_obs = build_candidate_hunter_observations(
        pipeline_run_id="ab-leadership",
        candidates=[
            _auth_candidate(
                route=route_records,
                source_path="routes.ts",
                symbol_name="readRecord",
            )
        ],
        code_files=[{"path": "routes.ts", "content": TS_HARDCODED_OWNER_TS}],
        surface_facts=surface_r,
        context_facts=context_r,
    )
    ts_status_only_obs = build_candidate_hunter_observations(
        pipeline_run_id="ab-leadership",
        candidates=[
            _auth_candidate(
                route=route_records,
                source_path="routes.ts",
                symbol_name="readRecord",
            )
        ],
        code_files=[{"path": "routes.ts", "content": TS_STATUS_ONLY_TS}],
        surface_facts=surface_r,
        context_facts=context_r,
    )
    python_query_param_principal_obs = build_candidate_hunter_observations(
        pipeline_run_id="ab-leadership",
        candidates=[
            _auth_candidate(
                route=route_records,
                source_path="routes.py",
                symbol_name="read_record",
            )
        ],
        code_files=[{"path": "routes.py", "content": PYTHON_QUERY_PARAM_PRINCIPAL_PY}],
        surface_facts=surface_r,
        context_facts=context_r,
    )
    java_ownership_obs = build_candidate_hunter_observations(
        pipeline_run_id="ab-leadership",
        candidates=[
            _auth_candidate(
                route=route_records,
                source_path="RecordsController.java",
                symbol_name="readRecord",
            )
        ],
        code_files=[{"path": "RecordsController.java", "content": JAVA_OWNERSHIP_JAVA}],
        surface_facts=surface_r,
        context_facts=context_r,
    )
    java_role_only_obs = build_candidate_hunter_observations(
        pipeline_run_id="ab-leadership",
        candidates=[
            _auth_candidate(
                route=route_records,
                source_path="RecordsController.java",
                symbol_name="readRecord",
            )
        ],
        code_files=[{"path": "RecordsController.java", "content": JAVA_ROLE_ONLY_JAVA}],
        surface_facts=surface_r,
        context_facts=context_r,
    )
    java_status_only_obs = build_candidate_hunter_observations(
        pipeline_run_id="ab-leadership",
        candidates=[
            _auth_candidate(
                route=route_records,
                source_path="RecordsController.java",
                symbol_name="readRecord",
            )
        ],
        code_files=[{"path": "RecordsController.java", "content": JAVA_STATUS_ONLY_JAVA}],
        surface_facts=surface_r,
        context_facts=context_r,
    )
    go_ownership_obs = build_candidate_hunter_observations(
        pipeline_run_id="ab-leadership",
        candidates=[
            _auth_candidate(
                route=route_records,
                source_path="handlers.go",
                symbol_name="readRecord",
            )
        ],
        code_files=[{"path": "handlers.go", "content": GO_OWNERSHIP_GO}],
        surface_facts=surface_r,
        context_facts=context_r,
    )
    go_role_only_obs = build_candidate_hunter_observations(
        pipeline_run_id="ab-leadership",
        candidates=[
            _auth_candidate(
                route=route_records,
                source_path="handlers.go",
                symbol_name="readRecord",
            )
        ],
        code_files=[{"path": "handlers.go", "content": GO_ROLE_ONLY_GO}],
        surface_facts=surface_r,
        context_facts=context_r,
    )
    rails_ownership_obs = build_candidate_hunter_observations(
        pipeline_run_id="ab-leadership",
        candidates=[
            _auth_candidate(
                route=route_records,
                source_path="records.rb",
                symbol_name="read_record",
            )
        ],
        code_files=[{"path": "records.rb", "content": RAILS_OWNERSHIP_RB}],
        surface_facts=surface_r,
        context_facts=context_r,
    )
    rails_role_only_obs = build_candidate_hunter_observations(
        pipeline_run_id="ab-leadership",
        candidates=[
            _auth_candidate(
                route=route_records,
                source_path="records.rb",
                symbol_name="read_record",
            )
        ],
        code_files=[{"path": "records.rb", "content": RAILS_ROLE_ONLY_RB}],
        surface_facts=surface_r,
        context_facts=context_r,
    )
    java_service_layer_obs = build_candidate_hunter_observations(
        pipeline_run_id="ab-leadership",
        candidates=[
            _auth_candidate(
                route=route_records,
                source_path="RecordsController.java",
                symbol_name="readRecord",
            )
        ],
        code_files=[{"path": "RecordsController.java", "content": JAVA_SERVICE_LAYER_JAVA}],
        surface_facts=surface_r,
        context_facts=context_r,
    )
    java_guard_after_sink_obs = build_candidate_hunter_observations(
        pipeline_run_id="ab-leadership",
        candidates=[
            _auth_candidate(
                route=route_records,
                source_path="RecordsController.java",
                symbol_name="readRecord",
            )
        ],
        code_files=[{"path": "RecordsController.java", "content": JAVA_GUARD_AFTER_SINK_JAVA}],
        surface_facts=surface_r,
        context_facts=context_r,
    )
    go_middleware_obs = build_candidate_hunter_observations(
        pipeline_run_id="ab-leadership",
        candidates=[
            _auth_candidate(
                route=route_records,
                source_path="handlers.go",
                symbol_name="readRecord",
            )
        ],
        code_files=[{"path": "handlers.go", "content": GO_MIDDLEWARE_OWNERSHIP_GO}],
        surface_facts=surface_r,
        context_facts=context_r,
    )
    go_status_only_obs = build_candidate_hunter_observations(
        pipeline_run_id="ab-leadership",
        candidates=[
            _auth_candidate(
                route=route_records,
                source_path="handlers.go",
                symbol_name="readRecord",
            )
        ],
        code_files=[{"path": "handlers.go", "content": GO_STATUS_ONLY_GO}],
        surface_facts=surface_r,
        context_facts=context_r,
    )
    rails_before_action_obs = build_candidate_hunter_observations(
        pipeline_run_id="ab-leadership",
        candidates=[
            _auth_candidate(
                route=route_records,
                source_path="records.rb",
                symbol_name="read_record",
            )
        ],
        code_files=[{"path": "records.rb", "content": RAILS_BEFORE_ACTION_OWNERSHIP_RB}],
        surface_facts=surface_r,
        context_facts=context_r,
    )
    rails_status_only_obs = build_candidate_hunter_observations(
        pipeline_run_id="ab-leadership",
        candidates=[
            _auth_candidate(
                route=route_records,
                source_path="records.rb",
                symbol_name="read_record",
            )
        ],
        code_files=[{"path": "records.rb", "content": RAILS_STATUS_ONLY_RB}],
        surface_facts=surface_r,
        context_facts=context_r,
    )
    csharp_ownership_obs = build_candidate_hunter_observations(
        pipeline_run_id="ab-leadership",
        candidates=[
            _auth_candidate(
                route=route_records,
                source_path="RecordsController.cs",
                symbol_name="GetRecord",
            )
        ],
        code_files=[{"path": "RecordsController.cs", "content": CSHARP_OWNERSHIP_CS}],
        surface_facts=surface_r,
        context_facts=context_r,
    )
    csharp_role_only_obs = build_candidate_hunter_observations(
        pipeline_run_id="ab-leadership",
        candidates=[
            _auth_candidate(
                route=route_records,
                source_path="RecordsController.cs",
                symbol_name="GetRecord",
            )
        ],
        code_files=[{"path": "RecordsController.cs", "content": CSHARP_ROLE_ONLY_CS}],
        surface_facts=surface_r,
        context_facts=context_r,
    )
    php_ownership_obs = build_candidate_hunter_observations(
        pipeline_run_id="ab-leadership",
        candidates=[
            _auth_candidate(
                route=route_records,
                source_path="routes.php",
                symbol_name="route_get_3",
            )
        ],
        code_files=[{"path": "routes.php", "content": PHP_OWNERSHIP_PHP}],
        surface_facts=surface_r,
        context_facts=context_r,
    )
    php_role_only_obs = build_candidate_hunter_observations(
        pipeline_run_id="ab-leadership",
        candidates=[
            _auth_candidate(
                route=route_records,
                source_path="routes.php",
                symbol_name="route_get_3",
            )
        ],
        code_files=[{"path": "routes.php", "content": PHP_ROLE_ONLY_PHP}],
        surface_facts=surface_r,
        context_facts=context_r,
    )

    kotlin_ownership_obs = build_candidate_hunter_observations(
        pipeline_run_id="ab-leadership",
        candidates=[
            _auth_candidate(
                route=route_records,
                source_path="RecordsController.kt",
                symbol_name="readRecord",
            )
        ],
        code_files=[{"path": "RecordsController.kt", "content": KOTLIN_OWNERSHIP_KT}],
        surface_facts=surface_r,
        context_facts=context_r,
    )
    kotlin_role_only_obs = build_candidate_hunter_observations(
        pipeline_run_id="ab-leadership",
        candidates=[
            _auth_candidate(
                route=route_records,
                source_path="RecordsController.kt",
                symbol_name="readRecord",
            )
        ],
        code_files=[{"path": "RecordsController.kt", "content": KOTLIN_ROLE_ONLY_KT}],
        surface_facts=surface_r,
        context_facts=context_r,
    )
    csharp_service_layer_obs = build_candidate_hunter_observations(
        pipeline_run_id="ab-leadership",
        candidates=[
            _auth_candidate(
                route=route_records,
                source_path="RecordsController.cs",
                symbol_name="GetRecord",
            )
        ],
        code_files=[{"path": "RecordsController.cs", "content": CSHARP_SERVICE_LAYER_CS}],
        surface_facts=surface_r,
        context_facts=context_r,
    )
    php_controller_ownership_obs = build_candidate_hunter_observations(
        pipeline_run_id="ab-leadership",
        candidates=[
            _auth_candidate(
                route=route_records,
                source_path="routes.php",
                symbol_name="show",
            )
        ],
        code_files=[{"path": "routes.php", "content": PHP_CONTROLLER_OWNERSHIP_PHP}],
        surface_facts=surface_r,
        context_facts=context_r,
    )

    rust_ownership_obs = build_candidate_hunter_observations(
        pipeline_run_id="ab-leadership",
        candidates=[
            _auth_candidate(
                route=route_records,
                source_path="records.rs",
                symbol_name="read_record",
            )
        ],
        code_files=[{"path": "records.rs", "content": RUST_OWNERSHIP_RS}],
        surface_facts=surface_r,
        context_facts=context_r,
    )
    rust_role_only_obs = build_candidate_hunter_observations(
        pipeline_run_id="ab-leadership",
        candidates=[
            _auth_candidate(
                route=route_records,
                source_path="records.rs",
                symbol_name="read_record",
            )
        ],
        code_files=[{"path": "records.rs", "content": RUST_ROLE_ONLY_RS}],
        surface_facts=surface_r,
        context_facts=context_r,
    )
    scala_ownership_obs = build_candidate_hunter_observations(
        pipeline_run_id="ab-leadership",
        candidates=[
            _auth_candidate(
                route=route_records,
                source_path="RecordsController.scala",
                symbol_name="readRecord",
            )
        ],
        code_files=[{"path": "RecordsController.scala", "content": SCALA_OWNERSHIP_SCALA}],
        surface_facts=surface_r,
        context_facts=context_r,
    )
    scala_role_only_obs = build_candidate_hunter_observations(
        pipeline_run_id="ab-leadership",
        candidates=[
            _auth_candidate(
                route=route_records,
                source_path="RecordsController.scala",
                symbol_name="readRecord",
            )
        ],
        code_files=[{"path": "RecordsController.scala", "content": SCALA_ROLE_ONLY_SCALA}],
        surface_facts=surface_r,
        context_facts=context_r,
    )


    return [
        {
            "scenario_id": "retain_unguarded_session",
            "expected": "retained",
            "observations": retain_obs,
        },
        {
            "scenario_id": "refute_ownership_guard",
            "expected": "refuted",
            "observations": refute_obs,
        },
        {
            "scenario_id": "suppress_public_filter",
            "expected": "suppressed",
            "observations": suppress_obs,
        },
        {
            "scenario_id": "needs_evidence_api_only",
            "expected": "needs_evidence",
            "observations": needs_obs,
        },
        {
            "scenario_id": "dedupe_multi_root_shared_service",
            "expected": "multi",
            "metric_bucket": "dedupe",
            "expect_counts": {"retained": 1, "deduplicated": 2},
            "require_final_count": 1,
            "require_cards_for": ["retained", "deduplicated"],
            "observations": multi_obs,
        },
        {
            "scenario_id": "held_out_transfer_ownership",
            "expected": "refuted",
            "observations": held_out_obs,
        },
        {
            "scenario_id": "rank_two_retained_by_priority",
            "expected": "rank_order",
            "metric_bucket": "rank",
            "expect_final_ids": ["H-001", "H-002"],
            "observations": rank_obs,
        },
        {
            "scenario_id": "refute_nested_parent_ownership",
            "expected": "refuted",
            "metric_bucket": "nested_refute",
            "observations": nested_obs,
        },
        {
            "scenario_id": "refute_python_ownership_deny",
            "expected": "refuted",
            "metric_bucket": "python_refute",
            "observations": python_owner_obs,
        },
        {
            "scenario_id": "refute_python_tenant_boundary",
            "expected": "refuted",
            "metric_bucket": "tenant_refute",
            "observations": python_tenant_obs,
        },
        {
            "scenario_id": "refute_python_inline_ownership",
            "expected": "refuted",
            "metric_bucket": "inline_refute",
            "observations": python_inline_obs,
        },
        {
            "scenario_id": "refute_python_async_ownership",
            "expected": "refuted",
            "metric_bucket": "async_refute",
            "observations": python_async_obs,
        },
        {
            "scenario_id": "refute_python_multihop_ownership",
            "expected": "refuted",
            "metric_bucket": "multihop_refute",
            "observations": python_multihop_obs,
        },
        {
            "scenario_id": "refute_python_role_owner_and",
            "expected": "refuted",
            "metric_bucket": "role_owner_and_refute",
            "observations": python_role_owner_obs,
        },
        {
            "scenario_id": "refute_python_membership",
            "expected": "refuted",
            "metric_bucket": "membership_refute",
            "observations": python_membership_obs,
        },
        {
            "scenario_id": "refute_python_bool_helper_guard",
            "expected": "refuted",
            "metric_bucket": "bool_helper_refute",
            "observations": python_bool_helper_obs,
        },
        {
            "scenario_id": "refute_python_workspace_boundary",
            "expected": "refuted",
            "metric_bucket": "workspace_refute",
            "observations": python_workspace_obs,
        },
        {
            "scenario_id": "refute_python_assert_ownership",
            "expected": "refuted",
            "metric_bucket": "assert_refute",
            "observations": python_assert_obs,
        },
        {
            "scenario_id": "refute_python_or_boundary",
            "expected": "refuted",
            "metric_bucket": "or_refute",
            "observations": python_or_obs,
        },
        {
            "scenario_id": "refute_python_gated_eq",
            "expected": "refuted",
            "metric_bucket": "gated_eq_refute",
            "observations": python_gated_obs,
        },
        {
            "scenario_id": "refute_python_ownership_decorator",
            "expected": "refuted",
            "metric_bucket": "decorator_refute",
            "observations": python_decorator_obs,
        },
        {
            "scenario_id": "refute_python_query_filter",
            "expected": "refuted",
            "metric_bucket": "query_filter_refute",
            "observations": python_query_filter_obs,
        },
        {
            "scenario_id": "refute_python_depends_ownership",
            "expected": "refuted",
            "metric_bucket": "depends_refute",
            "observations": python_depends_obs,
        },
        {
            "scenario_id": "refute_ts_membership_includes",
            "expected": "refuted",
            "metric_bucket": "ts_membership_refute",
            "observations": ts_membership_obs,
        },
        {
            "scenario_id": "refute_python_cross_file_ownership",
            "expected": "refuted",
            "metric_bucket": "cross_file_py_refute",
            "observations": python_cross_file_obs,
        },
        {
            "scenario_id": "refute_python_cross_file_bool_helper",
            "expected": "refuted",
            "metric_bucket": "cross_file_bool_refute",
            "observations": python_cross_file_bool_obs,
        },
        {
            "scenario_id": "refute_python_class_method_ownership",
            "expected": "refuted",
            "metric_bucket": "class_method_refute",
            "observations": python_class_method_obs,
        },
        {
            "scenario_id": "refute_ts_cross_file_ownership",
            "expected": "refuted",
            "metric_bucket": "ts_cross_file_refute",
            "observations": ts_cross_file_obs,
        },
        {
            "scenario_id": "refute_python_assign_ownership_helper",
            "expected": "refuted",
            "metric_bucket": "assign_helper_refute",
            "observations": python_assign_helper_obs,
        },
        {
            "scenario_id": "refute_python_service_layer_ownership",
            "expected": "refuted",
            "metric_bucket": "service_layer_refute",
            "observations": python_service_layer_obs,
        },
        {
            "scenario_id": "refute_python_g_current_user",
            "expected": "refuted",
            "metric_bucket": "g_current_user_refute",
            "observations": python_g_current_user_obs,
        },
        {
            "scenario_id": "refute_python_or_admin_owner_allow",
            "expected": "refuted",
            "metric_bucket": "or_admin_owner_refute",
            "observations": python_or_admin_owner_obs,
        },
        {
            "scenario_id": "refute_python_team_boundary",
            "expected": "refuted",
            "metric_bucket": "team_refute",
            "observations": python_team_obs,
        },
        {
            "scenario_id": "refute_ts_middleware_ownership",
            "expected": "refuted",
            "metric_bucket": "ts_middleware_refute",
            "observations": ts_middleware_obs,
        },
        {
            "scenario_id": "refute_ts_service_layer_ownership",
            "expected": "refuted",
            "metric_bucket": "ts_service_layer_refute",
            "observations": ts_service_layer_obs,
        },
        {
            "scenario_id": "refute_python_created_by_boundary",
            "expected": "refuted",
            "metric_bucket": "created_by_refute",
            "observations": python_created_by_obs,
        },
        {
            "scenario_id": "refute_python_with_context_ownership",
            "expected": "refuted",
            "metric_bucket": "with_context_refute",
            "observations": python_with_context_obs,
        },
        {
            "scenario_id": "refute_ts_use_middleware_ownership",
            "expected": "refuted",
            "metric_bucket": "ts_use_middleware_refute",
            "observations": ts_use_middleware_obs,
        },
        {
            "scenario_id": "refute_python_django_view_ownership",
            "expected": "refuted",
            "metric_bucket": "django_view_refute",
            "observations": python_django_view_obs,
        },
        {
            "scenario_id": "refute_ts_nestjs_guard_ownership",
            "expected": "refuted",
            "metric_bucket": "ts_nestjs_guard_refute",
            "observations": ts_nestjs_guard_obs,
        },
        {
            "scenario_id": "refute_python_author_id_boundary",
            "expected": "refuted",
            "metric_bucket": "author_id_refute",
            "observations": python_author_id_obs,
        },
        {
            "scenario_id": "refute_python_try_ensure_owner",
            "expected": "refuted",
            "metric_bucket": "try_ensure_refute",
            "observations": python_try_ensure_obs,
        },
        {
            "scenario_id": "refute_python_ternary_ownership",
            "expected": "refuted",
            "metric_bucket": "ternary_refute",
            "observations": python_ternary_obs,
        },
        {
            "scenario_id": "refute_python_response_403",
            "expected": "refuted",
            "metric_bucket": "response_403_refute",
            "observations": python_response_403_obs,
        },
        {
            "scenario_id": "refute_python_getattr_owner",
            "expected": "refuted",
            "metric_bucket": "getattr_owner_refute",
            "observations": python_getattr_owner_obs,
        },
        {
            "scenario_id": "refute_python_request_state_user",
            "expected": "refuted",
            "metric_bucket": "request_state_refute",
            "observations": python_request_state_obs,
        },
        {
            "scenario_id": "refute_python_graphql_context",
            "expected": "refuted",
            "metric_bucket": "graphql_context_refute",
            "observations": python_graphql_context_obs,
        },
        {
            "scenario_id": "refute_ts_prisma_owner_filter",
            "expected": "refuted",
            "metric_bucket": "ts_prisma_owner_refute",
            "observations": ts_prisma_owner_obs,
        },
        {
            "scenario_id": "retain_python_guard_after_sink",
            "expected": "retained",
            "metric_bucket": "guard_after_sink_retain",
            "observations": python_guard_after_sink_obs,
        },
        {
            "scenario_id": "retain_python_login_only",
            "expected": "retained",
            "metric_bucket": "login_only_retain",
            "observations": python_login_only_obs,
        },
        {
            "scenario_id": "retain_ts_guard_after_sink",
            "expected": "retained",
            "metric_bucket": "ts_guard_after_sink_retain",
            "observations": ts_guard_after_sink_obs,
        },
        {
            "scenario_id": "refute_python_walrus_ownership",
            "expected": "refuted",
            "metric_bucket": "walrus_refute",
            "observations": python_walrus_obs,
        },
        {
            "scenario_id": "refute_python_match_ownership",
            "expected": "refuted",
            "metric_bucket": "match_refute",
            "observations": python_match_obs,
        },
        {
            "scenario_id": "retain_python_status_only",
            "expected": "retained",
            "metric_bucket": "status_only_retain",
            "observations": python_status_only_obs,
        },
        {
            "scenario_id": "retain_python_wrong_field_compare",
            "expected": "retained",
            "metric_bucket": "wrong_field_retain",
            "observations": python_wrong_field_obs,
        },
        {
            "scenario_id": "retain_python_role_only",
            "expected": "retained",
            "metric_bucket": "role_only_retain",
            "observations": python_role_only_obs,
        },
        {
            "scenario_id": "retain_ts_login_only",
            "expected": "retained",
            "metric_bucket": "ts_login_only_retain",
            "observations": ts_login_only_obs,
        },
        {
            "scenario_id": "retain_ts_role_only",
            "expected": "retained",
            "metric_bucket": "ts_role_only_retain",
            "observations": ts_role_only_obs,
        },
        {
            "scenario_id": "retain_python_hardcoded_owner",
            "expected": "retained",
            "metric_bucket": "hardcoded_owner_retain",
            "observations": python_hardcoded_owner_obs,
        },
        {
            "scenario_id": "retain_python_spoofable_header_principal",
            "expected": "retained",
            "metric_bucket": "spoofable_principal_retain",
            "observations": python_spoofable_header_obs,
        },
        {
            "scenario_id": "retain_python_wrong_object_unrelated",
            "expected": "retained",
            "metric_bucket": "wrong_object_retain",
            "observations": python_wrong_object_obs,
        },
        {
            "scenario_id": "retain_ts_hardcoded_owner",
            "expected": "retained",
            "metric_bucket": "ts_hardcoded_owner_retain",
            "observations": ts_hardcoded_owner_obs,
        },
        {
            "scenario_id": "retain_ts_status_only",
            "expected": "retained",
            "metric_bucket": "ts_status_only_retain",
            "observations": ts_status_only_obs,
        },
        {
            "scenario_id": "retain_python_query_param_principal",
            "expected": "retained",
            "metric_bucket": "query_param_principal_retain",
            "observations": python_query_param_principal_obs,
        },
        {
            "scenario_id": "refute_java_spring_ownership",
            "expected": "refuted",
            "metric_bucket": "java_refute",
            "observations": java_ownership_obs,
        },
        {
            "scenario_id": "refute_go_ownership",
            "expected": "refuted",
            "metric_bucket": "go_refute",
            "observations": go_ownership_obs,
        },
        {
            "scenario_id": "refute_rails_ownership",
            "expected": "refuted",
            "metric_bucket": "rails_refute",
            "observations": rails_ownership_obs,
        },
        {
            "scenario_id": "retain_java_role_only",
            "expected": "retained",
            "metric_bucket": "java_role_only_retain",
            "observations": java_role_only_obs,
        },
        {
            "scenario_id": "retain_go_role_only",
            "expected": "retained",
            "metric_bucket": "go_role_only_retain",
            "observations": go_role_only_obs,
        },
        {
            "scenario_id": "retain_rails_role_only",
            "expected": "retained",
            "metric_bucket": "rails_role_only_retain",
            "observations": rails_role_only_obs,
        },
        {
            "scenario_id": "retain_java_status_only",
            "expected": "retained",
            "metric_bucket": "java_status_only_retain",
            "observations": java_status_only_obs,
        },
        {
            "scenario_id": "refute_java_service_layer_ownership",
            "expected": "refuted",
            "metric_bucket": "java_service_refute",
            "observations": java_service_layer_obs,
        },
        {
            "scenario_id": "refute_go_middleware_ownership",
            "expected": "refuted",
            "metric_bucket": "go_middleware_refute",
            "observations": go_middleware_obs,
        },
        {
            "scenario_id": "refute_rails_before_action_ownership",
            "expected": "refuted",
            "metric_bucket": "rails_before_action_refute",
            "observations": rails_before_action_obs,
        },
        {
            "scenario_id": "retain_java_guard_after_sink",
            "expected": "retained",
            "metric_bucket": "java_guard_after_sink_retain",
            "observations": java_guard_after_sink_obs,
        },
        {
            "scenario_id": "retain_go_status_only",
            "expected": "retained",
            "metric_bucket": "go_status_only_retain",
            "observations": go_status_only_obs,
        },
        {
            "scenario_id": "retain_rails_status_only",
            "expected": "retained",
            "metric_bucket": "rails_status_only_retain",
            "observations": rails_status_only_obs,
        },
        {
            "scenario_id": "refute_csharp_ownership",
            "expected": "refuted",
            "metric_bucket": "csharp_refute",
            "observations": csharp_ownership_obs,
        },
        {
            "scenario_id": "refute_php_ownership",
            "expected": "refuted",
            "metric_bucket": "php_refute",
            "observations": php_ownership_obs,
        },
        {
            "scenario_id": "retain_csharp_role_only",
            "expected": "retained",
            "metric_bucket": "csharp_role_only_retain",
            "observations": csharp_role_only_obs,
        },
        {
            "scenario_id": "retain_php_role_only",
            "expected": "retained",
            "metric_bucket": "php_role_only_retain",
            "observations": php_role_only_obs,
        },
        {
            "scenario_id": "refute_kotlin_ownership",
            "expected": "refuted",
            "metric_bucket": "kotlin_refute",
            "observations": kotlin_ownership_obs,
        },
        {
            "scenario_id": "retain_kotlin_role_only",
            "expected": "retained",
            "metric_bucket": "kotlin_role_only_retain",
            "observations": kotlin_role_only_obs,
        },
        {
            "scenario_id": "refute_csharp_service_layer_ownership",
            "expected": "refuted",
            "metric_bucket": "csharp_service_refute",
            "observations": csharp_service_layer_obs,
        },
        {
            "scenario_id": "refute_php_controller_ownership",
            "expected": "refuted",
            "metric_bucket": "php_controller_refute",
            "observations": php_controller_ownership_obs,
        },
        {
            "scenario_id": "refute_rust_ownership",
            "expected": "refuted",
            "metric_bucket": "rust_refute",
            "observations": rust_ownership_obs,
        },
        {
            "scenario_id": "retain_rust_role_only",
            "expected": "retained",
            "metric_bucket": "rust_role_only_retain",
            "observations": rust_role_only_obs,
        },
        {
            "scenario_id": "refute_scala_ownership",
            "expected": "refuted",
            "metric_bucket": "scala_refute",
            "observations": scala_ownership_obs,
        },
        {
            "scenario_id": "retain_scala_role_only",
            "expected": "retained",
            "metric_bucket": "scala_role_only_retain",
            "observations": scala_role_only_obs,
        },

        {
            "scenario_id": "multi_engine_advisory_consistent",
            "expected": "multi_engine_advisory",
            "metric_bucket": "multi_engine",
            "cases": [
                {
                    "label": "retain_local_static_consistent",
                    "expected_disposition": "retained",
                    "expect_verdict": VERDICT_LOCAL_STATIC_CONSISTENT,
                    "use_gap_root": True,
                    "use_control_refs": False,
                    "observations": retain_obs,
                },
                {
                    "label": "refute_false_positive_likely",
                    "expected_disposition": "refuted",
                    "expect_verdict": VERDICT_FALSE_POSITIVE_LIKELY,
                    "use_gap_root": False,
                    "use_control_refs": True,
                    "observations": refute_obs,
                },
            ],
        },
    ]



def _multi_engine_case_ok(case: dict[str, Any]) -> tuple[bool, bool, bool, dict[str, Any] | None, dict[str, Any]]:
    """Run one multi-engine advisory subcase. Returns (disp_ok, has_card, quality_ok, card, detail)."""
    observations = case.get("observations") if isinstance(case.get("observations"), dict) else {}
    result = _run_round(observations)
    expected_disp = str(case.get("expected_disposition") or "")
    decisions = [
        decision
        for decision in (result.get("candidate_decisions") or [])
        if isinstance(decision, dict)
    ]
    decision = decisions[0] if decisions else {}
    disposition = str(decision.get("disposition") or "")
    disposition_ok = disposition == expected_disp
    card = decision.get("falsification_card") if isinstance(decision.get("falsification_card"), dict) else None
    has_card, quality_ok = _card_quality_ok(card, expected_disp)

    gap_root_causes: list[str] = []
    control_refs: list[str] = []
    root = str(decision.get("root_cause_id") or "")
    if case.get("use_gap_root") and root:
        gap_root_causes = [root]
    if case.get("use_control_refs"):
        control_refs = [str(ref) for ref in (decision.get("evidence_refs") or []) if str(ref)]

    verdict = verdict_from_hunter_and_map(
        candidate=decision if decision else {"disposition": disposition},
        gap_root_causes=gap_root_causes,
        control_refs=control_refs,
        report_submission_blocked=True,
        scope_allowed=True,
    )
    expect_verdict = str(case.get("expect_verdict") or "")
    verdict_ok = verdict.status == expect_verdict
    safety_ok = (
        verdict.execution_allowed is False
        and verdict.validation_allowed is False
        and verdict.report_submission_allowed is False
        and verdict.finding_promotion_allowed is False
        and verdict.confirmed_vulnerability is False
    )
    agree_ok = disposition_ok and quality_ok and verdict_ok and safety_ok and float(verdict.agreement_score) >= 1.0
    detail = {
        "label": str(case.get("label") or ""),
        "disposition": disposition,
        "disposition_ok": disposition_ok,
        "verdict_status": verdict.status,
        "verdict_ok": verdict_ok,
        "agreement_score": verdict.agreement_score,
        "safety_ok": safety_ok,
        "agree_ok": agree_ok,
    }
    return disposition_ok, has_card, quality_ok and agree_ok, card, detail


def _multi_engine_advisory_ok(item: dict[str, Any]) -> tuple[bool, bool, bool, dict[str, Any] | None, list[dict[str, Any]]]:
    cases = item.get("cases") if isinstance(item.get("cases"), list) else []
    if not cases:
        return False, False, False, None, []
    all_disp = True
    all_has = True
    all_quality = True
    first_card: dict[str, Any] | None = None
    details: list[dict[str, Any]] = []
    for case in cases:
        if not isinstance(case, dict):
            all_disp = False
            all_has = False
            all_quality = False
            continue
        disp_ok, has_card, quality_ok, card, detail = _multi_engine_case_ok(case)
        details.append(detail)
        all_disp = all_disp and disp_ok
        all_has = all_has and has_card
        all_quality = all_quality and quality_ok
        if first_card is None and isinstance(card, dict):
            first_card = card
    return all_disp, all_has, all_quality, first_card, details


def _decision_cards(result: dict[str, Any]) -> list[dict[str, Any]]:
    cards: list[dict[str, Any]] = []
    for decision in result.get("candidate_decisions") or []:
        if not isinstance(decision, dict):
            continue
        card = decision.get("falsification_card")
        if isinstance(card, dict):
            cards.append(card)
    return cards


def _first_card(result: dict[str, Any], expected: str) -> dict[str, Any] | None:
    if expected == "needs_evidence":
        requests = result.get("evidence_requests") or []
        if requests and isinstance(requests[0], dict):
            card = requests[0].get("falsification_card")
            return card if isinstance(card, dict) else None
        return None
    if expected in {"multi", "rank_order", "multi_engine_advisory"}:
        cards = _decision_cards(result)
        return cards[0] if cards else None
    decisions = result.get("candidate_decisions") or []
    if decisions and isinstance(decisions[0], dict):
        card = decisions[0].get("falsification_card")
        return card if isinstance(card, dict) else None
    return None


def _disposition_counts(result: dict[str, Any]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for decision in result.get("candidate_decisions") or []:
        if not isinstance(decision, dict):
            continue
        disposition = str(decision.get("disposition") or "")
        if not disposition:
            continue
        counts[disposition] = counts.get(disposition, 0) + 1
    return counts


def _disposition_ok(result: dict[str, Any], item: dict[str, Any]) -> bool:
    expected = str(item.get("expected") or "")
    if expected == "needs_evidence":
        return bool(result.get("evidence_requests")) and not any(
            (entry or {}).get("disposition") == "retained"
            for entry in (result.get("candidate_decisions") or [])
            if isinstance(entry, dict)
        )
    if expected == "multi":
        counts = _disposition_counts(result)
        expect_counts = item.get("expect_counts") if isinstance(item.get("expect_counts"), dict) else {}
        if any(counts.get(str(key), 0) != int(value) for key, value in expect_counts.items()):
            return False
        require_final = item.get("require_final_count")
        if require_final is not None and len(result.get("final_candidates") or []) != int(
            require_final
        ):
            return False
        return True
    if expected == "rank_order":
        finals = result.get("final_candidates") or []
        expect_ids = item.get("expect_final_ids") if isinstance(item.get("expect_final_ids"), list) else []
        actual_ids = [
            str(entry.get("candidate_id") or "")
            for entry in finals
            if isinstance(entry, dict)
        ]
        if actual_ids != [str(value) for value in expect_ids]:
            return False
        ranks = [
            entry.get("rank")
            for entry in finals
            if isinstance(entry, dict)
        ]
        return ranks == list(range(1, len(actual_ids) + 1))
    decisions = result.get("candidate_decisions") or []
    if not decisions or not isinstance(decisions[0], dict):
        return False
    return decisions[0].get("disposition") == expected


def _card_quality_ok(card: dict[str, Any] | None, expected: str) -> tuple[bool, bool]:
    """Return (has_card, valid_and_semantic)."""
    if not isinstance(card, dict):
        return False, False
    if validate_falsification_card(card):
        return True, False
    decision = card.get("decision") if isinstance(card.get("decision"), dict) else {}
    status = str(decision.get("status") or "")
    if expected == "retained":
        semantic = bool(card.get("broken_invariant")) and bool(
            decision.get("why_still_alive")
        )
    elif expected in {"refuted", "suppressed", "deduplicated"}:
        killed = [
            item
            for item in (card.get("kill_attempts") or [])
            if isinstance(item, dict) and item.get("status") == "killed"
        ]
        semantic = bool(decision.get("why_dead")) and bool(killed) and all(
            item.get("evidence_refs") for item in killed
        )
        if expected == "deduplicated":
            semantic = semantic and bool(decision.get("duplicate_of"))
    elif expected == "needs_evidence":
        semantic = status == "needs_evidence" and bool(card.get("evidence_gaps"))
    elif expected in {"multi", "rank_order", "multi_engine_advisory"}:
        # Multi/rank/multi-engine scenarios validate per-decision cards separately.
        semantic = True
    else:
        semantic = status == expected
    # Safety flags must stay false.
    safety = card.get("safety") if isinstance(card.get("safety"), dict) else {}
    semantic = semantic and all(safety.get(key) is False for key in (
        "execution_allowed",
        "dispatch_allowed",
        "validation_allowed",
        "candidate_promotion_allowed",
        "report_submission_allowed",
    ))
    return True, semantic


def _multi_cards_quality_ok(result: dict[str, Any], item: dict[str, Any]) -> tuple[bool, bool]:
    require_for = {
        str(value)
        for value in (item.get("require_cards_for") or [])
        if str(value)
    } or {"retained", "deduplicated", "refuted", "suppressed"}
    decisions = [
        decision
        for decision in (result.get("candidate_decisions") or [])
        if isinstance(decision, dict)
        and str(decision.get("disposition") or "") in require_for
    ]
    if not decisions:
        return False, False
    all_have = True
    all_quality = True
    for decision in decisions:
        disposition = str(decision.get("disposition") or "")
        card = decision.get("falsification_card")
        has_card, quality_ok = _card_quality_ok(
            card if isinstance(card, dict) else None,
            disposition,
        )
        all_have = all_have and has_card
        all_quality = all_quality and quality_ok
    return all_have, all_quality


def _rank_cards_quality_ok(result: dict[str, Any]) -> tuple[bool, bool]:
    finals = [
        entry
        for entry in (result.get("final_candidates") or [])
        if isinstance(entry, dict)
    ]
    if not finals:
        return False, False
    all_have = True
    all_quality = True
    for entry in finals:
        card = entry.get("falsification_card")
        has_card, quality_ok = _card_quality_ok(
            card if isinstance(card, dict) else None,
            "retained",
        )
        all_have = all_have and has_card
        all_quality = all_quality and quality_ok
        if not list(entry.get("why_still_alive") or []) and isinstance(card, dict):
            decision = card.get("decision") if isinstance(card.get("decision"), dict) else {}
            if not decision.get("why_still_alive"):
                all_quality = False
    return all_have, all_quality


def _blob_safe(payload: object) -> bool:
    text = json.dumps(payload, default=str)
    markers = ("SECRET", "Bearer ", "cookie=", "Authorization:")
    lowered = text.lower()
    if "secret" in lowered and "SECRET" in text:
        return False
    for marker in markers:
        if marker.lower() in lowered and marker in text:
            return False
    # Also block obvious credential shapes even if case differs.
    for marker in ("bearer ", "cookie=", "authorization:"):
        if marker in lowered:
            return False
    return True


def run_ab_leadership_gate(*, require_perfect: bool = True) -> dict[str, Any]:
    """Run synthetic A+B hard scenarios and compute falsify leadership metrics."""
    scenarios = _scenario_catalog()
    rows: list[dict[str, Any]] = []

    scenario_pass = 0
    safety_pass = 0
    falsify_pass = 0
    card_valid = 0
    retain_hit = 0
    retain_expected = 0
    refute_kill = 0
    refute_expected = 0
    suppress_kill = 0
    suppress_expected = 0
    needs_card = 0
    needs_expected = 0
    dedupe_kill = 0
    dedupe_expected = 0
    rank_hit = 0
    rank_expected = 0
    nested_kill = 0
    nested_expected = 0
    multi_engine_hit = 0
    multi_engine_expected = 0
    python_kill = 0
    python_expected = 0
    tenant_kill = 0
    tenant_expected = 0
    inline_kill = 0
    inline_expected = 0
    async_kill = 0
    async_expected = 0
    multihop_kill = 0
    multihop_expected = 0
    role_owner_and_kill = 0
    role_owner_and_expected = 0
    membership_kill = 0
    membership_expected = 0
    bool_helper_kill = 0
    bool_helper_expected = 0
    workspace_kill = 0
    workspace_expected = 0
    assert_kill = 0
    assert_expected = 0
    or_kill = 0
    or_expected = 0
    gated_eq_kill = 0
    gated_eq_expected = 0
    decorator_kill = 0
    decorator_expected = 0
    query_filter_kill = 0
    query_filter_expected = 0
    depends_kill = 0
    depends_expected = 0
    ts_membership_kill = 0
    ts_membership_expected = 0
    cross_file_py_kill = 0
    cross_file_py_expected = 0
    cross_file_bool_kill = 0
    cross_file_bool_expected = 0
    class_method_kill = 0
    class_method_expected = 0
    ts_cross_file_kill = 0
    ts_cross_file_expected = 0
    assign_helper_kill = 0
    assign_helper_expected = 0
    service_layer_kill = 0
    service_layer_expected = 0
    g_current_user_kill = 0
    g_current_user_expected = 0
    or_admin_owner_kill = 0
    or_admin_owner_expected = 0
    ts_middleware_kill = 0
    ts_middleware_expected = 0
    team_kill = 0
    team_expected = 0
    ts_service_layer_kill = 0
    ts_service_layer_expected = 0
    created_by_kill = 0
    created_by_expected = 0
    with_context_kill = 0
    with_context_expected = 0
    ts_use_middleware_kill = 0
    ts_use_middleware_expected = 0
    django_view_kill = 0
    django_view_expected = 0
    ts_nestjs_guard_kill = 0
    ts_nestjs_guard_expected = 0
    author_id_kill = 0
    author_id_expected = 0
    try_ensure_kill = 0
    try_ensure_expected = 0
    ternary_kill = 0
    ternary_expected = 0
    response_403_kill = 0
    response_403_expected = 0
    getattr_owner_kill = 0
    getattr_owner_expected = 0
    request_state_kill = 0
    request_state_expected = 0
    graphql_context_kill = 0
    graphql_context_expected = 0
    ts_prisma_owner_kill = 0
    ts_prisma_owner_expected = 0
    guard_after_sink_hit = 0
    guard_after_sink_expected = 0
    login_only_hit = 0
    login_only_expected = 0
    ts_guard_after_sink_hit = 0
    ts_guard_after_sink_expected = 0
    status_only_hit = 0
    status_only_expected = 0
    wrong_field_hit = 0
    wrong_field_expected = 0
    role_only_hit = 0
    role_only_expected = 0
    ts_login_only_hit = 0
    ts_login_only_expected = 0
    ts_role_only_hit = 0
    ts_role_only_expected = 0
    hardcoded_owner_hit = 0
    hardcoded_owner_expected = 0
    spoofable_principal_hit = 0
    spoofable_principal_expected = 0
    wrong_object_hit = 0
    wrong_object_expected = 0
    ts_hardcoded_owner_hit = 0
    ts_hardcoded_owner_expected = 0
    ts_status_only_hit = 0
    ts_status_only_expected = 0
    query_param_principal_hit = 0
    query_param_principal_expected = 0
    java_kill = 0
    java_expected = 0
    go_kill = 0
    go_expected = 0
    rails_kill = 0
    rails_expected = 0
    java_role_only_hit = 0
    java_role_only_expected = 0
    go_role_only_hit = 0
    go_role_only_expected = 0
    rails_role_only_hit = 0
    rails_role_only_expected = 0
    java_status_only_hit = 0
    java_status_only_expected = 0
    java_service_kill = 0
    java_service_expected = 0
    go_middleware_kill = 0
    go_middleware_expected = 0
    rails_before_action_kill = 0
    rails_before_action_expected = 0
    java_guard_after_sink_hit = 0
    java_guard_after_sink_expected = 0
    go_status_only_hit = 0
    go_status_only_expected = 0
    rails_status_only_hit = 0
    rails_status_only_expected = 0
    csharp_kill = 0
    csharp_expected = 0
    php_kill = 0
    php_expected = 0
    csharp_role_only_hit = 0
    csharp_role_only_expected = 0
    php_role_only_hit = 0
    php_role_only_expected = 0
    kotlin_kill = 0
    kotlin_expected = 0
    kotlin_role_only_hit = 0
    kotlin_role_only_expected = 0
    csharp_service_kill = 0
    csharp_service_expected = 0
    php_controller_kill = 0
    php_controller_expected = 0
    rust_kill = 0
    rust_expected = 0
    rust_role_only_hit = 0
    rust_role_only_expected = 0
    scala_kill = 0
    scala_expected = 0
    scala_role_only_hit = 0
    scala_role_only_expected = 0
    walrus_kill = 0
    walrus_expected = 0
    match_kill = 0
    match_expected = 0

    for item in scenarios:
        scenario_id = str(item["scenario_id"])
        expected = str(item["expected"])
        multi_engine_details: list[dict[str, Any]] = []

        if expected == "multi_engine_advisory":
            disposition_ok, has_card, quality_ok, card, multi_engine_details = (
                _multi_engine_advisory_ok(item)
            )
            # Synthetic aggregate result for safety scan only.
            result = {
                "candidate_decisions": [],
                "final_candidates": [],
                "evidence_requests": [],
                "multi_engine_details": multi_engine_details,
            }
        else:
            result = _run_round(item["observations"])
            disposition_ok = _disposition_ok(result, item)
            if expected == "multi":
                has_card, quality_ok = _multi_cards_quality_ok(result, item)
                card = _first_card(result, expected)
            elif expected == "rank_order":
                has_card, quality_ok = _rank_cards_quality_ok(result)
                card = _first_card(result, expected)
            else:
                card = _first_card(result, expected)
                has_card, quality_ok = _card_quality_ok(card, expected)

        safe = _blob_safe(result) and all(
            _blob_safe(detail) for detail in multi_engine_details
        )

        if expected == "retained":
            retain_expected += 1
            if disposition_ok:
                retain_hit += 1
            if item.get("metric_bucket") == "guard_after_sink_retain":
                guard_after_sink_expected += 1
                if disposition_ok and quality_ok:
                    guard_after_sink_hit += 1
            if item.get("metric_bucket") == "login_only_retain":
                login_only_expected += 1
                if disposition_ok and quality_ok:
                    login_only_hit += 1
            if item.get("metric_bucket") == "ts_guard_after_sink_retain":
                ts_guard_after_sink_expected += 1
                if disposition_ok and quality_ok:
                    ts_guard_after_sink_hit += 1
            if item.get("metric_bucket") == "status_only_retain":
                status_only_expected += 1
                if disposition_ok and quality_ok:
                    status_only_hit += 1
            if item.get("metric_bucket") == "wrong_field_retain":
                wrong_field_expected += 1
                if disposition_ok and quality_ok:
                    wrong_field_hit += 1
            if item.get("metric_bucket") == "role_only_retain":
                role_only_expected += 1
                if disposition_ok and quality_ok:
                    role_only_hit += 1
            if item.get("metric_bucket") == "ts_login_only_retain":
                ts_login_only_expected += 1
                if disposition_ok and quality_ok:
                    ts_login_only_hit += 1
            if item.get("metric_bucket") == "ts_role_only_retain":
                ts_role_only_expected += 1
                if disposition_ok and quality_ok:
                    ts_role_only_hit += 1
            if item.get("metric_bucket") == "hardcoded_owner_retain":
                hardcoded_owner_expected += 1
                if disposition_ok and quality_ok:
                    hardcoded_owner_hit += 1
            if item.get("metric_bucket") == "spoofable_principal_retain":
                spoofable_principal_expected += 1
                if disposition_ok and quality_ok:
                    spoofable_principal_hit += 1
            if item.get("metric_bucket") == "wrong_object_retain":
                wrong_object_expected += 1
                if disposition_ok and quality_ok:
                    wrong_object_hit += 1
            if item.get("metric_bucket") == "ts_hardcoded_owner_retain":
                ts_hardcoded_owner_expected += 1
                if disposition_ok and quality_ok:
                    ts_hardcoded_owner_hit += 1
            if item.get("metric_bucket") == "ts_status_only_retain":
                ts_status_only_expected += 1
                if disposition_ok and quality_ok:
                    ts_status_only_hit += 1
            if item.get("metric_bucket") == "query_param_principal_retain":
                query_param_principal_expected += 1
                if disposition_ok and quality_ok:
                    query_param_principal_hit += 1
            if item.get("metric_bucket") == "java_role_only_retain":
                java_role_only_expected += 1
                if disposition_ok and quality_ok:
                    java_role_only_hit += 1
            if item.get("metric_bucket") == "go_role_only_retain":
                go_role_only_expected += 1
                if disposition_ok and quality_ok:
                    go_role_only_hit += 1
            if item.get("metric_bucket") == "rails_role_only_retain":
                rails_role_only_expected += 1
                if disposition_ok and quality_ok:
                    rails_role_only_hit += 1
            if item.get("metric_bucket") == "java_status_only_retain":
                java_status_only_expected += 1
                if disposition_ok and quality_ok:
                    java_status_only_hit += 1
            if item.get("metric_bucket") == "java_guard_after_sink_retain":
                java_guard_after_sink_expected += 1
                if disposition_ok and quality_ok:
                    java_guard_after_sink_hit += 1
            if item.get("metric_bucket") == "go_status_only_retain":
                go_status_only_expected += 1
                if disposition_ok and quality_ok:
                    go_status_only_hit += 1
            if item.get("metric_bucket") == "rails_status_only_retain":
                rails_status_only_expected += 1
                if disposition_ok and quality_ok:
                    rails_status_only_hit += 1
        elif expected == "refuted":
            refute_expected += 1
            if disposition_ok and quality_ok:
                refute_kill += 1
            if item.get("metric_bucket") == "nested_refute":
                nested_expected += 1
                if disposition_ok and quality_ok:
                    nested_kill += 1
            if item.get("metric_bucket") == "python_refute":
                python_expected += 1
                if disposition_ok and quality_ok:
                    python_kill += 1
            if item.get("metric_bucket") == "java_refute":
                java_expected += 1
                if disposition_ok and quality_ok:
                    java_kill += 1
            if item.get("metric_bucket") == "go_refute":
                go_expected += 1
                if disposition_ok and quality_ok:
                    go_kill += 1
            if item.get("metric_bucket") == "rails_refute":
                rails_expected += 1
                if disposition_ok and quality_ok:
                    rails_kill += 1
            if item.get("metric_bucket") == "java_service_refute":
                java_service_expected += 1
                if disposition_ok and quality_ok:
                    java_service_kill += 1
            if item.get("metric_bucket") == "go_middleware_refute":
                go_middleware_expected += 1
                if disposition_ok and quality_ok:
                    go_middleware_kill += 1
            if item.get("metric_bucket") == "rails_before_action_refute":
                rails_before_action_expected += 1
                if disposition_ok and quality_ok:
                    rails_before_action_kill += 1
            if item.get("metric_bucket") == "csharp_refute":
                csharp_expected += 1
                if disposition_ok and quality_ok:
                    csharp_kill += 1
            if item.get("metric_bucket") == "php_refute":
                php_expected += 1
                if disposition_ok and quality_ok:
                    php_kill += 1
            if item.get("metric_bucket") == "csharp_role_only_retain":
                csharp_role_only_expected += 1
                if disposition_ok and quality_ok:
                    csharp_role_only_hit += 1
            if item.get("metric_bucket") == "php_role_only_retain":
                php_role_only_expected += 1
                if disposition_ok and quality_ok:
                    php_role_only_hit += 1
            if item.get("metric_bucket") == "kotlin_refute":
                kotlin_expected += 1
                if disposition_ok and quality_ok:
                    kotlin_kill += 1
            if item.get("metric_bucket") == "kotlin_role_only_retain":
                kotlin_role_only_expected += 1
                if disposition_ok and quality_ok:
                    kotlin_role_only_hit += 1
            if item.get("metric_bucket") == "csharp_service_refute":
                csharp_service_expected += 1
                if disposition_ok and quality_ok:
                    csharp_service_kill += 1
            if item.get("metric_bucket") == "php_controller_refute":
                php_controller_expected += 1
                if disposition_ok and quality_ok:
                    php_controller_kill += 1
            if item.get("metric_bucket") == "rust_refute":
                rust_expected += 1
                if disposition_ok and quality_ok:
                    rust_kill += 1
            if item.get("metric_bucket") == "rust_role_only_retain":
                rust_role_only_expected += 1
                if disposition_ok and quality_ok:
                    rust_role_only_hit += 1
            if item.get("metric_bucket") == "scala_refute":
                scala_expected += 1
                if disposition_ok and quality_ok:
                    scala_kill += 1
            if item.get("metric_bucket") == "scala_role_only_retain":
                scala_role_only_expected += 1
                if disposition_ok and quality_ok:
                    scala_role_only_hit += 1
            if item.get("metric_bucket") == "tenant_refute":
                tenant_expected += 1
                if disposition_ok and quality_ok:
                    tenant_kill += 1
            if item.get("metric_bucket") == "inline_refute":
                inline_expected += 1
                if disposition_ok and quality_ok:
                    inline_kill += 1
            if item.get("metric_bucket") == "async_refute":
                async_expected += 1
                if disposition_ok and quality_ok:
                    async_kill += 1
            if item.get("metric_bucket") == "multihop_refute":
                multihop_expected += 1
                if disposition_ok and quality_ok:
                    multihop_kill += 1
            if item.get("metric_bucket") == "role_owner_and_refute":
                role_owner_and_expected += 1
                if disposition_ok and quality_ok:
                    role_owner_and_kill += 1
            if item.get("metric_bucket") == "membership_refute":
                membership_expected += 1
                if disposition_ok and quality_ok:
                    membership_kill += 1
            if item.get("metric_bucket") == "bool_helper_refute":
                bool_helper_expected += 1
                if disposition_ok and quality_ok:
                    bool_helper_kill += 1
            if item.get("metric_bucket") == "workspace_refute":
                workspace_expected += 1
                if disposition_ok and quality_ok:
                    workspace_kill += 1
            if item.get("metric_bucket") == "assert_refute":
                assert_expected += 1
                if disposition_ok and quality_ok:
                    assert_kill += 1
            if item.get("metric_bucket") == "or_refute":
                or_expected += 1
                if disposition_ok and quality_ok:
                    or_kill += 1
            if item.get("metric_bucket") == "gated_eq_refute":
                gated_eq_expected += 1
                if disposition_ok and quality_ok:
                    gated_eq_kill += 1
            if item.get("metric_bucket") == "decorator_refute":
                decorator_expected += 1
                if disposition_ok and quality_ok:
                    decorator_kill += 1
            if item.get("metric_bucket") == "query_filter_refute":
                query_filter_expected += 1
                if disposition_ok and quality_ok:
                    query_filter_kill += 1
            if item.get("metric_bucket") == "depends_refute":
                depends_expected += 1
                if disposition_ok and quality_ok:
                    depends_kill += 1
            if item.get("metric_bucket") == "ts_membership_refute":
                ts_membership_expected += 1
                if disposition_ok and quality_ok:
                    ts_membership_kill += 1
            if item.get("metric_bucket") == "cross_file_py_refute":
                cross_file_py_expected += 1
                if disposition_ok and quality_ok:
                    cross_file_py_kill += 1
            if item.get("metric_bucket") == "cross_file_bool_refute":
                cross_file_bool_expected += 1
                if disposition_ok and quality_ok:
                    cross_file_bool_kill += 1
            if item.get("metric_bucket") == "class_method_refute":
                class_method_expected += 1
                if disposition_ok and quality_ok:
                    class_method_kill += 1
            if item.get("metric_bucket") == "ts_cross_file_refute":
                ts_cross_file_expected += 1
                if disposition_ok and quality_ok:
                    ts_cross_file_kill += 1
            if item.get("metric_bucket") == "assign_helper_refute":
                assign_helper_expected += 1
                if disposition_ok and quality_ok:
                    assign_helper_kill += 1
            if item.get("metric_bucket") == "service_layer_refute":
                service_layer_expected += 1
                if disposition_ok and quality_ok:
                    service_layer_kill += 1
            if item.get("metric_bucket") == "g_current_user_refute":
                g_current_user_expected += 1
                if disposition_ok and quality_ok:
                    g_current_user_kill += 1
            if item.get("metric_bucket") == "or_admin_owner_refute":
                or_admin_owner_expected += 1
                if disposition_ok and quality_ok:
                    or_admin_owner_kill += 1
            if item.get("metric_bucket") == "ts_middleware_refute":
                ts_middleware_expected += 1
                if disposition_ok and quality_ok:
                    ts_middleware_kill += 1
            if item.get("metric_bucket") == "team_refute":
                team_expected += 1
                if disposition_ok and quality_ok:
                    team_kill += 1
            if item.get("metric_bucket") == "ts_service_layer_refute":
                ts_service_layer_expected += 1
                if disposition_ok and quality_ok:
                    ts_service_layer_kill += 1
            if item.get("metric_bucket") == "created_by_refute":
                created_by_expected += 1
                if disposition_ok and quality_ok:
                    created_by_kill += 1
            if item.get("metric_bucket") == "with_context_refute":
                with_context_expected += 1
                if disposition_ok and quality_ok:
                    with_context_kill += 1
            if item.get("metric_bucket") == "ts_use_middleware_refute":
                ts_use_middleware_expected += 1
                if disposition_ok and quality_ok:
                    ts_use_middleware_kill += 1
            if item.get("metric_bucket") == "django_view_refute":
                django_view_expected += 1
                if disposition_ok and quality_ok:
                    django_view_kill += 1
            if item.get("metric_bucket") == "ts_nestjs_guard_refute":
                ts_nestjs_guard_expected += 1
                if disposition_ok and quality_ok:
                    ts_nestjs_guard_kill += 1
            if item.get("metric_bucket") == "author_id_refute":
                author_id_expected += 1
                if disposition_ok and quality_ok:
                    author_id_kill += 1
            if item.get("metric_bucket") == "try_ensure_refute":
                try_ensure_expected += 1
                if disposition_ok and quality_ok:
                    try_ensure_kill += 1
            if item.get("metric_bucket") == "ternary_refute":
                ternary_expected += 1
                if disposition_ok and quality_ok:
                    ternary_kill += 1
            if item.get("metric_bucket") == "response_403_refute":
                response_403_expected += 1
                if disposition_ok and quality_ok:
                    response_403_kill += 1
            if item.get("metric_bucket") == "getattr_owner_refute":
                getattr_owner_expected += 1
                if disposition_ok and quality_ok:
                    getattr_owner_kill += 1
            if item.get("metric_bucket") == "request_state_refute":
                request_state_expected += 1
                if disposition_ok and quality_ok:
                    request_state_kill += 1
            if item.get("metric_bucket") == "graphql_context_refute":
                graphql_context_expected += 1
                if disposition_ok and quality_ok:
                    graphql_context_kill += 1
            if item.get("metric_bucket") == "ts_prisma_owner_refute":
                ts_prisma_owner_expected += 1
                if disposition_ok and quality_ok:
                    ts_prisma_owner_kill += 1
            if item.get("metric_bucket") == "walrus_refute":
                walrus_expected += 1
                if disposition_ok and quality_ok:
                    walrus_kill += 1
            if item.get("metric_bucket") == "match_refute":
                match_expected += 1
                if disposition_ok and quality_ok:
                    match_kill += 1
        elif expected == "suppressed":
            suppress_expected += 1
            if disposition_ok and quality_ok:
                suppress_kill += 1
        elif expected == "needs_evidence":
            needs_expected += 1
            if disposition_ok and quality_ok:
                needs_card += 1
        elif expected == "multi" and item.get("metric_bucket") == "dedupe":
            dedupe_expected += 1
            if disposition_ok and quality_ok:
                dedupe_kill += 1
        elif expected == "rank_order":
            rank_expected += 1
            if disposition_ok and quality_ok:
                rank_hit += 1
        elif expected == "multi_engine_advisory":
            multi_engine_expected += 1
            if disposition_ok and quality_ok:
                multi_engine_hit += 1

        if disposition_ok and quality_ok:
            scenario_pass += 1
        if safe:
            safety_pass += 1
        if has_card:
            falsify_pass += 1
        if has_card:
            if expected == "multi":
                multi_valid = True
                for decision in result.get("candidate_decisions") or []:
                    if not isinstance(decision, dict):
                        continue
                    card_item = decision.get("falsification_card")
                    if isinstance(card_item, dict) and validate_falsification_card(card_item):
                        multi_valid = False
                        break
                if multi_valid:
                    card_valid += 1
            elif expected == "rank_order":
                rank_valid = True
                for entry in result.get("final_candidates") or []:
                    if not isinstance(entry, dict):
                        continue
                    card_item = entry.get("falsification_card")
                    if isinstance(card_item, dict) and validate_falsification_card(card_item):
                        rank_valid = False
                        break
                if rank_valid:
                    card_valid += 1
            elif expected == "multi_engine_advisory":
                if card is None or not validate_falsification_card(card or {}):
                    card_valid += 1
            elif not validate_falsification_card(card or {}):
                card_valid += 1

        row: dict[str, Any] = {
            "scenario_id": scenario_id,
            "expected": expected,
            "disposition_ok": disposition_ok,
            "has_falsification_card": has_card,
            "card_quality_ok": quality_ok,
            "safe": safe,
            "decision_status": (
                (card or {}).get("decision", {}).get("status")
                if isinstance(card, dict)
                else None
            ),
        }
        if multi_engine_details:
            row["multi_engine_details"] = multi_engine_details
        rows.append(row)

    total = len(scenarios) or 1

    def _rate(num: int, den: int) -> float:
        if den <= 0:
            return 1.0
        return round(num / den, 4)

    metrics = {
        "scenario_pass_rate": _rate(scenario_pass, total),
        "safety_rate": _rate(safety_pass, total),
        "falsify_coverage": _rate(falsify_pass, total),
        "card_valid_rate": _rate(card_valid, total),
        "retain_hit": _rate(retain_hit, retain_expected),
        "refute_kill": _rate(refute_kill, refute_expected),
        "suppress_kill": _rate(suppress_kill, suppress_expected),
        "needs_evidence_card_rate": _rate(needs_card, needs_expected),
        "dedupe_kill": _rate(dedupe_kill, dedupe_expected),
        "rank_order_hit": _rate(rank_hit, rank_expected),
        "nested_refute_kill": _rate(nested_kill, nested_expected),
        "multi_engine_agree": _rate(multi_engine_hit, multi_engine_expected),
        "python_refute_kill": _rate(python_kill, python_expected),
        "tenant_refute_kill": _rate(tenant_kill, tenant_expected),
        "inline_refute_kill": _rate(inline_kill, inline_expected),
        "async_refute_kill": _rate(async_kill, async_expected),
        "multihop_refute_kill": _rate(multihop_kill, multihop_expected),
        "role_owner_and_refute_kill": _rate(role_owner_and_kill, role_owner_and_expected),
        "membership_refute_kill": _rate(membership_kill, membership_expected),
        "bool_helper_refute_kill": _rate(bool_helper_kill, bool_helper_expected),
        "workspace_refute_kill": _rate(workspace_kill, workspace_expected),
        "assert_refute_kill": _rate(assert_kill, assert_expected),
        "or_refute_kill": _rate(or_kill, or_expected),
        "gated_eq_refute_kill": _rate(gated_eq_kill, gated_eq_expected),
        "decorator_refute_kill": _rate(decorator_kill, decorator_expected),
        "query_filter_refute_kill": _rate(query_filter_kill, query_filter_expected),
        "depends_refute_kill": _rate(depends_kill, depends_expected),
        "ts_membership_refute_kill": _rate(ts_membership_kill, ts_membership_expected),
        "cross_file_py_refute_kill": _rate(cross_file_py_kill, cross_file_py_expected),
        "cross_file_bool_refute_kill": _rate(cross_file_bool_kill, cross_file_bool_expected),
        "class_method_refute_kill": _rate(class_method_kill, class_method_expected),
        "ts_cross_file_refute_kill": _rate(ts_cross_file_kill, ts_cross_file_expected),
        "assign_helper_refute_kill": _rate(assign_helper_kill, assign_helper_expected),
        "service_layer_refute_kill": _rate(service_layer_kill, service_layer_expected),
        "g_current_user_refute_kill": _rate(g_current_user_kill, g_current_user_expected),
        "or_admin_owner_refute_kill": _rate(or_admin_owner_kill, or_admin_owner_expected),
        "ts_middleware_refute_kill": _rate(ts_middleware_kill, ts_middleware_expected),
        "team_refute_kill": _rate(team_kill, team_expected),
        "ts_service_layer_refute_kill": _rate(ts_service_layer_kill, ts_service_layer_expected),
        "created_by_refute_kill": _rate(created_by_kill, created_by_expected),
        "with_context_refute_kill": _rate(with_context_kill, with_context_expected),
        "ts_use_middleware_refute_kill": _rate(ts_use_middleware_kill, ts_use_middleware_expected),
        "django_view_refute_kill": _rate(django_view_kill, django_view_expected),
        "ts_nestjs_guard_refute_kill": _rate(ts_nestjs_guard_kill, ts_nestjs_guard_expected),
        "author_id_refute_kill": _rate(author_id_kill, author_id_expected),
        "try_ensure_refute_kill": _rate(try_ensure_kill, try_ensure_expected),
        "ternary_refute_kill": _rate(ternary_kill, ternary_expected),
        "response_403_refute_kill": _rate(response_403_kill, response_403_expected),
        "getattr_owner_refute_kill": _rate(getattr_owner_kill, getattr_owner_expected),
        "request_state_refute_kill": _rate(request_state_kill, request_state_expected),
        "graphql_context_refute_kill": _rate(graphql_context_kill, graphql_context_expected),
        "ts_prisma_owner_refute_kill": _rate(ts_prisma_owner_kill, ts_prisma_owner_expected),
        "guard_after_sink_retain_hit": _rate(guard_after_sink_hit, guard_after_sink_expected),
        "login_only_retain_hit": _rate(login_only_hit, login_only_expected),
        "ts_guard_after_sink_retain_hit": _rate(ts_guard_after_sink_hit, ts_guard_after_sink_expected),
        "walrus_refute_kill": _rate(walrus_kill, walrus_expected),
        "match_refute_kill": _rate(match_kill, match_expected),
        "status_only_retain_hit": _rate(status_only_hit, status_only_expected),
        "wrong_field_retain_hit": _rate(wrong_field_hit, wrong_field_expected),
        "role_only_retain_hit": _rate(role_only_hit, role_only_expected),
        "ts_login_only_retain_hit": _rate(ts_login_only_hit, ts_login_only_expected),
        "ts_role_only_retain_hit": _rate(ts_role_only_hit, ts_role_only_expected),
        "hardcoded_owner_retain_hit": _rate(hardcoded_owner_hit, hardcoded_owner_expected),
        "spoofable_principal_retain_hit": _rate(spoofable_principal_hit, spoofable_principal_expected),
        "wrong_object_retain_hit": _rate(wrong_object_hit, wrong_object_expected),
        "ts_hardcoded_owner_retain_hit": _rate(ts_hardcoded_owner_hit, ts_hardcoded_owner_expected),
        "ts_status_only_retain_hit": _rate(ts_status_only_hit, ts_status_only_expected),
        "query_param_principal_retain_hit": _rate(query_param_principal_hit, query_param_principal_expected),
        "java_refute_kill": _rate(java_kill, java_expected),
        "go_refute_kill": _rate(go_kill, go_expected),
        "rails_refute_kill": _rate(rails_kill, rails_expected),
        "java_role_only_retain_hit": _rate(java_role_only_hit, java_role_only_expected),
        "go_role_only_retain_hit": _rate(go_role_only_hit, go_role_only_expected),
        "rails_role_only_retain_hit": _rate(rails_role_only_hit, rails_role_only_expected),
        "java_status_only_retain_hit": _rate(java_status_only_hit, java_status_only_expected),
        "java_service_refute_kill": _rate(java_service_kill, java_service_expected),
        "go_middleware_refute_kill": _rate(go_middleware_kill, go_middleware_expected),
        "rails_before_action_refute_kill": _rate(rails_before_action_kill, rails_before_action_expected),
        "java_guard_after_sink_retain_hit": _rate(java_guard_after_sink_hit, java_guard_after_sink_expected),
        "go_status_only_retain_hit": _rate(go_status_only_hit, go_status_only_expected),
        "rails_status_only_retain_hit": _rate(rails_status_only_hit, rails_status_only_expected),
        "csharp_refute_kill": _rate(csharp_kill, csharp_expected),
        "php_refute_kill": _rate(php_kill, php_expected),
        "csharp_role_only_retain_hit": _rate(csharp_role_only_hit, csharp_role_only_expected),
        "php_role_only_retain_hit": _rate(php_role_only_hit, php_role_only_expected),
        "kotlin_refute_kill": _rate(kotlin_kill, kotlin_expected),
        "kotlin_role_only_retain_hit": _rate(kotlin_role_only_hit, kotlin_role_only_expected),
        "csharp_service_refute_kill": _rate(csharp_service_kill, csharp_service_expected),
        "php_controller_refute_kill": _rate(php_controller_kill, php_controller_expected),
        "rust_refute_kill": _rate(rust_kill, rust_expected),
        "rust_role_only_retain_hit": _rate(rust_role_only_hit, rust_role_only_expected),
        "scala_refute_kill": _rate(scala_kill, scala_expected),
        "scala_role_only_retain_hit": _rate(scala_role_only_hit, scala_role_only_expected),
    }
    failures = [
        row["scenario_id"]
        for row in rows
        if not (
            row["disposition_ok"]
            and row["has_falsification_card"]
            and row["card_quality_ok"]
            and row["safe"]
        )
    ]
    passed = all(metrics[key] == 1.0 for key in REQUIRED_METRICS) and not failures
    if require_perfect and not passed:
        # Still return payload; caller decides exit code.
        pass

    return {
        "schema_version": "ab_leadership_gate_v1",
        "claim_scope": "lab_ab_falsify_quality",
        "passed": passed,
        "failures": failures,
        "scenario_count": len(scenarios),
        "scenarios": rows,
        "metrics": metrics,
        "required_metrics": list(REQUIRED_METRICS),
        "execution_allowed": False,
        "report_submission_allowed": False,
        "notes": [
            "Synthetic authorized local A+B hard scenarios only.",
            "Does not claim live bounty program or XBOW superiority.",
        ],
    }
