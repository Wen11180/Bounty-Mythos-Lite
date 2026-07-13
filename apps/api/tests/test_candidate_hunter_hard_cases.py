from __future__ import annotations

from app.candidate_hunter_loop import (
    advance_candidate_hunter_round,
    build_candidate_hunter_observations,
)


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
    state = observations["candidate_states"][0]
    result = advance_candidate_hunter_round(
        pipeline_run_id="run-001",
        round_number=1,
        candidate_states=[state],
        observations=_safe_flags(observations),
        prior_decisions=[],
    )
    return state, result


def _authorization_candidate(
    *,
    route: str,
    source_path: str | None = None,
    symbol_name: str = "readRecord",
    artifact_kind: str = "code",
) -> dict:
    source_facts = [
        {
            "fact_type": "authorization_gap_candidate",
            "artifact_kind": artifact_kind,
            "route_method": "GET",
            "route_path": route,
            "root_cause": "missing_object_ownership_check",
        }
    ]
    if source_path is not None:
        source_facts[0]["source_path"] = source_path
        source_facts[0]["symbol_name"] = symbol_name
    return {
        "hypothesis_id": "H-001",
        "vuln_type": "authorization",
        "location": f"GET {route}",
        "priority_score": 80,
        "source_facts": source_facts,
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


def test_openapi_route_style_ownership_guard_refutes_candidate():
    """Hallucination-bait Weak #1: OpenAPI {param} must still see Express :param ownership."""
    route = "/records/{record_id}"
    surface, context = _surface_and_context(route)
    observations = build_candidate_hunter_observations(
        pipeline_run_id="run-001",
        candidates=[
            _authorization_candidate(
                route=route,
                source_path="routes.ts",
                symbol_name="readRecord",
            )
        ],
        code_files=[{"path": "routes.ts", "content": OWNERSHIP_TS}],
        surface_facts=surface,
        context_facts=context,
    )

    state, result = _advance(observations)

    assert state["control_evidence_ref"].startswith("code:routes.ts:")
    assert result["candidate_decisions"][0]["disposition"] == "refuted"
    assert result["final_candidates"] == []


def test_openapi_route_style_public_filter_suppresses_candidate():
    """Weak #2 pressure: public filter must suppress under OpenAPI route style."""
    route = "/records/{record_id}"
    surface, context = _surface_and_context(route)
    observations = build_candidate_hunter_observations(
        pipeline_run_id="run-001",
        candidates=[
            _authorization_candidate(
                route=route,
                source_path="routes.ts",
                symbol_name="readRecord",
            )
        ],
        code_files=[{"path": "routes.ts", "content": PUBLIC_TS}],
        surface_facts=surface,
        context_facts=context,
    )

    state, result = _advance(observations)

    assert state["public_evidence_ref"].startswith("code:routes.ts:")
    assert result["candidate_decisions"][0]["disposition"] == "suppressed"
    assert result["final_candidates"] == []


def test_missing_route_handler_never_retains_candidate():
    """Weak #5: API/HAR route without a matching local handler must request code, not retain."""
    route = "/records/{record_id}"
    surface, context = _surface_and_context(route)
    observations = build_candidate_hunter_observations(
        pipeline_run_id="run-001",
        candidates=[
            _authorization_candidate(
                route=route,
                source_path="ghost.ts",
                symbol_name="ghostHandler",
            )
        ],
        code_files=[
            {
                "path": "other.ts",
                "content": """
import { Router } from "express";
const router = Router();
router.get("/other/:id", other);
async function other(req: Request, res: Response) {
  return res.json({});
}
""",
            }
        ],
        surface_facts=surface,
        context_facts=context,
    )

    state, result = _advance(observations)

    assert "code:ghost.ts:ghostHandler" not in state["source_fact_refs"]
    assert all(item.get("disposition") != "retained" for item in result["candidate_decisions"])
    assert result["final_candidates"] == []
    assert result["evidence_requests"]
    missing = result["evidence_requests"][0]["missing_evidence"]
    assert "artifact:code" in missing or "gap_provenance" in missing or "evidence_trace" in missing


def test_invented_code_path_without_observed_handler_never_retains():
    """Hallucination bait: candidate-cited invented.ts must not invent observed code evidence."""
    route = "/records/:recordId"
    surface, context = _surface_and_context(route)
    observations = build_candidate_hunter_observations(
        pipeline_run_id="run-001",
        candidates=[
            _authorization_candidate(
                route=route,
                source_path="invented.ts",
                symbol_name="readRecord",
            )
        ],
        code_files=[],
        surface_facts=surface,
        context_facts=context,
    )

    state, result = _advance(observations)

    assert "code:invented.ts:readRecord" not in state["source_fact_refs"]
    assert "code" not in state["observed_artifact_kinds"]
    assert result["final_candidates"] == []
    assert all(item.get("disposition") != "retained" for item in result["candidate_decisions"])
    assert result["evidence_requests"]
    assert "artifact:code" in result["evidence_requests"][0]["missing_evidence"]


def test_api_only_gap_without_code_handler_requests_evidence():
    """Missing code link: API-sourced gap with no matching handler stays non-terminal."""
    route = "/records/{record_id}"
    surface, context = _surface_and_context(route)
    observations = build_candidate_hunter_observations(
        pipeline_run_id="run-001",
        candidates=[
            _authorization_candidate(
                route=route,
                artifact_kind="api",
            )
        ],
        code_files=[
            {
                "path": "unrelated.ts",
                "content": """
import { Router } from "express";
const router = Router();
router.get("/health", health);
async function health(req: Request, res: Response) {
  return res.sendStatus(200);
}
""",
            }
        ],
        surface_facts=surface,
        context_facts=context,
    )

    state, result = _advance(observations)

    assert result["final_candidates"] == []
    assert all(item.get("disposition") != "retained" for item in result["candidate_decisions"])
    assert result["evidence_requests"]
    assert "artifact:code" in result["evidence_requests"][0]["missing_evidence"]


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


MULTI_ROOT_DIRECT_SINK_TS = """
import { Router } from "express";

const router = Router();

router.get("/records/:recordId", readRecord);
router.get("/records/:recordId/summary", readRecordSummary);

async function readRecord(req: Request, res: Response) {
  return sendFile(req.params.recordId);
}

async function readRecordSummary(req: Request, res: Response) {
  return sendFile(req.params.recordId);
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


SESSION_OWNERSHIP_TS = """
import { Router } from "express";

const router = Router();

router.get("/sessions/:sessionId", getSession);

async function getSession(req: Request, res: Response) {
  await assertSessionOwner(req.params.sessionId, req.user);
  return sendFile(req.params.sessionId);
}

async function assertSessionOwner(sessionId: string, user: User) {
  const session = await loadSession(sessionId);
  if (session.ownerId !== user.id) {
    return res.sendStatus(403);
  }
  return session;
}
"""


def _multi_root_candidates(
    routes: list[str],
    symbols: list[str],
    *,
    priority_scores: list[int] | None = None,
) -> list[dict]:
    scores = priority_scores or [90 - index * 5 for index in range(len(routes))]
    return [
        {
            "hypothesis_id": f"H-00{index}",
            "vuln_type": "authorization",
            "location": f"GET {route}",
            "priority_score": scores[index - 1],
            "source_facts": [
                {
                    "fact_type": "authorization_gap_candidate",
                    "artifact_kind": "code",
                    "source_path": "routes.ts",
                    "symbol_name": symbol,
                    "route_method": "GET",
                    "route_path": route,
                    "root_cause": "missing_object_ownership_check",
                }
            ],
        }
        for index, (route, symbol) in enumerate(zip(routes, symbols, strict=True), start=1)
    ]


def test_typescript_multi_root_shared_service_deduplicates():
    """Weak #3: multi-route shared service root keeps one retain and dedupes the rest."""
    routes = [
        "/records/{record_id}",
        "/records/{record_id}/summary",
        "/records/{record_id}/meta",
    ]
    symbols = ["readRecord", "readRecordSummary", "readRecordMeta"]
    surface = [
        {
            "fact_type": "api_surface",
            "artifact_kind": "api",
            "route_method": "GET",
            "route_path": route,
        }
        for route in routes
    ] + [{"fact_type": "har_context", "artifact_kind": "har"}]
    context = [
        {"fact_type": "scope_context", "artifact_kind": "scope"},
        {"fact_type": "policy_context", "artifact_kind": "policy"},
    ]
    observations = build_candidate_hunter_observations(
        pipeline_run_id="run-001",
        candidates=_multi_root_candidates(routes, symbols),
        code_files=[{"path": "routes.ts", "content": MULTI_ROOT_SHARED_SERVICE_TS}],
        surface_facts=surface,
        context_facts=context,
    )

    shared = {
        state["candidate_id"]: state["shared_root"]
        for state in observations["candidate_states"]
    }
    assert shared == {
        "H-001": "loadRecord",
        "H-002": "loadRecord",
        "H-003": "loadRecord",
    }

    result = advance_candidate_hunter_round(
        pipeline_run_id="run-001",
        round_number=1,
        candidate_states=observations["candidate_states"],
        observations=_safe_flags(observations),
        prior_decisions=[],
    )
    decisions = {
        item["candidate_id"]: item for item in result["candidate_decisions"]
    }
    assert [item["candidate_id"] for item in result["final_candidates"]] == ["H-001"]
    assert decisions["H-001"]["disposition"] == "retained"
    assert decisions["H-002"]["disposition"] == "deduplicated"
    assert decisions["H-003"]["disposition"] == "deduplicated"
    assert decisions["H-002"]["duplicate_of"] == decisions["H-001"]["root_cause_id"]
    assert decisions["H-003"]["duplicate_of"] == decisions["H-001"]["root_cause_id"]


def test_typescript_multi_root_equal_priority_is_deterministic():
    """Weak #3: equal priority chooses stable canonical candidate id."""
    routes = ["/records/{record_id}", "/records/{record_id}/summary"]
    symbols = ["readRecord", "readRecordSummary"]
    surface = [
        {
            "fact_type": "api_surface",
            "artifact_kind": "api",
            "route_method": "GET",
            "route_path": route,
        }
        for route in routes
    ] + [{"fact_type": "har_context", "artifact_kind": "har"}]
    context = [
        {"fact_type": "scope_context", "artifact_kind": "scope"},
        {"fact_type": "policy_context", "artifact_kind": "policy"},
    ]
    # Intentionally higher id first with equal priority.
    candidates = [
        {
            "hypothesis_id": "H-002",
            "vuln_type": "authorization",
            "location": f"GET {routes[1]}",
            "priority_score": 80,
            "source_facts": [
                {
                    "fact_type": "authorization_gap_candidate",
                    "artifact_kind": "code",
                    "source_path": "routes.ts",
                    "symbol_name": symbols[1],
                    "route_method": "GET",
                    "route_path": routes[1],
                    "root_cause": "missing_object_ownership_check",
                }
            ],
        },
        {
            "hypothesis_id": "H-001",
            "vuln_type": "authorization",
            "location": f"GET {routes[0]}",
            "priority_score": 80,
            "source_facts": [
                {
                    "fact_type": "authorization_gap_candidate",
                    "artifact_kind": "code",
                    "source_path": "routes.ts",
                    "symbol_name": symbols[0],
                    "route_method": "GET",
                    "route_path": routes[0],
                    "root_cause": "missing_object_ownership_check",
                }
            ],
        },
    ]
    observations = build_candidate_hunter_observations(
        pipeline_run_id="run-001",
        candidates=candidates,
        code_files=[{"path": "routes.ts", "content": MULTI_ROOT_SHARED_SERVICE_TS}],
        surface_facts=surface,
        context_facts=context,
    )
    result = advance_candidate_hunter_round(
        pipeline_run_id="run-001",
        round_number=1,
        candidate_states=observations["candidate_states"],
        observations=_safe_flags(observations),
        prior_decisions=[],
    )
    decisions = {
        item["candidate_id"]: item for item in result["candidate_decisions"]
    }
    assert [item["candidate_id"] for item in result["final_candidates"]] == ["H-001"]
    assert decisions["H-001"]["disposition"] == "retained"
    assert decisions["H-002"]["disposition"] == "deduplicated"


def test_typescript_multi_root_direct_same_sink_deduplicates():
    """Weak #3 hard case: two handlers that call the same sink must not both retain."""
    routes = ["/records/{record_id}", "/records/{record_id}/summary"]
    symbols = ["readRecord", "readRecordSummary"]
    surface = [
        {
            "fact_type": "api_surface",
            "artifact_kind": "api",
            "route_method": "GET",
            "route_path": route,
        }
        for route in routes
    ] + [{"fact_type": "har_context", "artifact_kind": "har"}]
    context = [
        {"fact_type": "scope_context", "artifact_kind": "scope"},
        {"fact_type": "policy_context", "artifact_kind": "policy"},
    ]
    observations = build_candidate_hunter_observations(
        pipeline_run_id="run-001",
        candidates=_multi_root_candidates(routes, symbols, priority_scores=[80, 70]),
        code_files=[{"path": "routes.ts", "content": MULTI_ROOT_DIRECT_SINK_TS}],
        surface_facts=surface,
        context_facts=context,
    )

    shared = {
        state["candidate_id"]: state["shared_root"]
        for state in observations["candidate_states"]
    }
    assert shared["H-001"] == shared["H-002"]
    assert shared["H-001"]

    result = advance_candidate_hunter_round(
        pipeline_run_id="run-001",
        round_number=1,
        candidate_states=observations["candidate_states"],
        observations=_safe_flags(observations),
        prior_decisions=[],
    )
    decisions = {
        item["candidate_id"]: item for item in result["candidate_decisions"]
    }
    assert [item["candidate_id"] for item in result["final_candidates"]] == ["H-001"]
    assert decisions["H-001"]["disposition"] == "retained"
    assert decisions["H-002"]["disposition"] == "deduplicated"
    assert decisions["H-002"]["duplicate_of"] == decisions["H-001"]["root_cause_id"]


def test_held_out_transfer_ownership_guard_refutes_under_openapi_route():
    """Weak #4: held-out transfer/auth family still refutes on ownership guard."""
    route = "/local/transfers/h9d2/{record_id}"
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
                        "artifact_kind": "code",
                        "source_path": "code.ts",
                        "symbol_name": "transfer_funds",
                        "route_method": "GET",
                        "route_path": route,
                        "root_cause": "missing_object_ownership_check",
                    }
                ],
            }
        ],
        code_files=[{"path": "code.ts", "content": HELD_OUT_TRANSFER_OWNERSHIP_TS}],
        surface_facts=surface,
        context_facts=context,
    )
    state, result = _advance(observations)
    assert state["control_evidence_ref"].startswith("code:code.ts:")
    assert result["candidate_decisions"][0]["disposition"] == "refuted"
    assert result["final_candidates"] == []


def test_authentication_family_session_ownership_guard_refutes():
    """Weak #4 pressure: authentication-labeled candidate still refutes on ownership."""
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
                        "root_cause": "missing_session_ownership_check",
                    }
                ],
            }
        ],
        code_files=[{"path": "sessions.ts", "content": SESSION_OWNERSHIP_TS}],
        surface_facts=surface,
        context_facts=context,
    )
    state, result = _advance(observations)
    assert state["control_evidence_ref"].startswith("code:sessions.ts:")
    assert result["candidate_decisions"][0]["disposition"] == "refuted"
    assert result["final_candidates"] == []


def test_authentication_family_unguarded_session_can_retain():
    """Weak #4 complement: authentication unguarded flow remains retainable."""
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
    state, result = _advance(observations)
    assert not state.get("control_evidence_ref")
    assert result["candidate_decisions"][0]["disposition"] == "retained"
    assert result["final_candidates"][0]["candidate_id"] == "H-001"
