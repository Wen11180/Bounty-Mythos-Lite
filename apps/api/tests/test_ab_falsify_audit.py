"""A+B Candidate Hunter falsify-card audit on hard local scenarios."""

from __future__ import annotations

import json

from app.candidate_hunter_loop import (
    advance_candidate_hunter_round,
    build_candidate_hunter_observations,
)
from app.falsification_engine import validate_falsification_card


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


def _safe_flags(observations: dict) -> dict:
    return {
        **observations,
        "execution_allowed": False,
        "dispatch_allowed": False,
        "validation_allowed": False,
        "candidate_promotion_allowed": False,
        "report_submission_allowed": False,
        "raw_payload_processed": False,
    }


def _advance(observations: dict):
    result = advance_candidate_hunter_round(
        pipeline_run_id="run-001",
        round_number=1,
        candidate_states=observations["candidate_states"],
        observations=_safe_flags(observations),
        prior_decisions=[],
    )
    return result


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


def _auth_candidate(route: str, source_path: str, symbol: str, root: str) -> dict:
    return {
        "hypothesis_id": "H-001",
        "vuln_type": "authorization",
        "location": f"GET {route}",
        "priority_score": 80,
        "source_facts": [
            {
                "fact_type": "authorization_gap_candidate",
                "artifact_kind": "code",
                "source_path": source_path,
                "symbol_name": symbol,
                "route_method": "GET",
                "route_path": route,
                "root_cause": root,
            }
        ],
    }


def test_retain_hard_case_has_valid_survived_falsify_card():
    route = "/sessions/{session_id}"
    surface, context = _surface_and_context(route)
    observations = build_candidate_hunter_observations(
        pipeline_run_id="run-001",
        candidates=[
            {
                "hypothesis_id": "H-001",
                "vuln_type": "authentication",
                "location": f"GET {route}",
                "priority_score": 80,
                "source_facts": [
                    {
                        "fact_type": "authorization_gap_candidate",
                        "artifact_kind": "code",
                        "source_path": "sessions.ts",
                        "symbol_name": "getSession",
                        "route_method": "GET",
                        "route_path": route,
                        "root_cause": "missing_session_binding_check",
                    }
                ],
            }
        ],
        code_files=[
            {
                "path": "sessions.ts",
                "content": """
import { Router } from "express";
const router = Router();
router.get("/sessions/:sessionId", getSession);
async function getSession(req: Request, res: Response) {
  return sendFile(req.params.sessionId);
}
""",
            }
        ],
        surface_facts=surface,
        context_facts=context,
    )
    result = _advance(observations)
    decision = result["candidate_decisions"][0]
    assert decision["disposition"] == "retained"
    card = decision["falsification_card"]
    assert validate_falsification_card(card) == []
    assert card["broken_invariant"]
    assert card["decision"]["why_still_alive"]
    assert all(item["status"] != "killed" for item in card["kill_attempts"])
    projection = result["final_candidates"][0]
    assert projection["falsification_card"]
    assert projection["why_still_alive"]
    blob = json.dumps(result)
    assert "SECRET" not in blob
    assert "Bearer" not in blob


def test_ownership_guard_refute_has_kill_evidence_on_card():
    route = "/records/{record_id}"
    surface, context = _surface_and_context(route)
    observations = build_candidate_hunter_observations(
        pipeline_run_id="run-001",
        candidates=[
            _auth_candidate(
                route,
                "routes.ts",
                "readRecord",
                "missing_object_ownership_check",
            )
        ],
        code_files=[{"path": "routes.ts", "content": OWNERSHIP_TS}],
        surface_facts=surface,
        context_facts=context,
    )
    result = _advance(observations)
    decision = result["candidate_decisions"][0]
    assert decision["disposition"] == "refuted"
    card = decision["falsification_card"]
    assert validate_falsification_card(card) == []
    assert card["decision"]["why_dead"]
    killed = [item for item in card["kill_attempts"] if item["status"] == "killed"]
    assert killed
    assert all(item["evidence_refs"] for item in killed)
    assert result["final_candidates"] == []


def test_public_filter_suppress_card_why_dead():
    route = "/records/{record_id}"
    surface, context = _surface_and_context(route)
    observations = build_candidate_hunter_observations(
        pipeline_run_id="run-001",
        candidates=[
            _auth_candidate(
                route,
                "routes.ts",
                "readRecord",
                "missing_object_ownership_check",
            )
        ],
        code_files=[{"path": "routes.ts", "content": PUBLIC_TS}],
        surface_facts=surface,
        context_facts=context,
    )
    result = _advance(observations)
    decision = result["candidate_decisions"][0]
    assert decision["disposition"] == "suppressed"
    card = decision["falsification_card"]
    assert validate_falsification_card(card) == []
    assert card["decision"]["why_dead"]
    killed = [item for item in card["kill_attempts"] if item["status"] == "killed"]
    assert killed
    assert all(item["evidence_refs"] for item in killed)


def test_needs_evidence_request_carries_falsification_card():
    route = "/records/{record_id}"
    surface, context = _surface_and_context(route)
    observations = build_candidate_hunter_observations(
        pipeline_run_id="run-001",
        candidates=[
            {
                "hypothesis_id": "H-001",
                "vuln_type": "authorization",
                "location": f"GET {route}",
                "priority_score": 80,
                "source_facts": [
                    {
                        "fact_type": "authorization_gap_candidate",
                        "artifact_kind": "api",
                        "route_method": "GET",
                        "route_path": route,
                        "root_cause": "missing_object_ownership_check",
                    }
                ],
            }
        ],
        code_files=[],
        surface_facts=surface,
        context_facts=context,
    )
    result = _advance(observations)
    assert result["evidence_requests"]
    card = result["evidence_requests"][0]["falsification_card"]
    assert card["decision"]["status"] == "needs_evidence"
    assert validate_falsification_card(card) == []
    assert card["evidence_gaps"]
