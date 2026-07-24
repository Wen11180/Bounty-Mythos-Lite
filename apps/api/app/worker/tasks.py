from hashlib import sha256
import asyncio
import logging
import json
import re
from threading import Lock, Thread, current_thread
from typing import Any

from app.artifact_ingestion import extract_sbom_dependency_signals, normalize_artifact
from app.codebase_map import (
    CodebaseFactCandidate,
    CodebaseMapResult,
    INPUT_REFERENCE_KIND_STRAIGHT_LINE,
    map_authorized_code_files,
    reachable_service_source_paths,
    safe_claim_reference,
    safe_input_reference,
)
from app.campaign_orchestrator import campaign_elapsed_minutes, campaign_token_used_from_runs
from app.config import get_settings
from app.cross_source_candidate_generator import (
    CandidateModelConfig,
    RegistryCandidateReasoner,
    build_fact_pack,
    candidate_model_config_digest,
    candidate_model_config_from_value,
    generate_cross_source_candidates,
)
from app.db import get_session_factory, initialize_database
from app.db_models import (
    AgentRunRecord,
    CampaignRecord,
    CampaignTaskRecord,
    CodebaseFactRecord,
    LearningSignalRecord,
    LLMRunRecord,
    PipelineStageRecord,
)
from app.mythos_brain import LearningSignal, MythosLesson, build_mythos_lessons
from app.repository import DatabaseRepository
from app.studio_workspace import load_authorized_campaign_inputs
from app.llm.registry import build_default_registry
from app.worker.celery_app import celery_app


_DISPATCHABLE_TASK_STATUSES = {"queued", "ready", "dispatched"}
_NON_DISPATCHABLE_TASK_STATUSES = {
    "awaiting_approval",
    "awaiting_evidence",
    "blocked",
    "canceled",
    "completed",
    "failed",
    "needs_evidence",
    "running",
}
_AUTONOMOUS_RESEARCH_RUNTIME_SCHEMA = "autonomous_research_v1"
_SOURCE_SNAPSHOT_DIGEST_PATTERN = re.compile(r"sha256:[0-9a-f]{64}")
_CAMPAIGN_OBSERVATION_PROJECTION_SCHEMA = "campaign_observation_projection_v1"
_RUNTIME_TARGET_INTAKE_PROJECTION_SCHEMA = "runtime_target_intake_projection_v1"
_RUNTIME_TARGET_INTAKE_STATUSES = {
    "intake_profile_ready",
    "intake_no_artifacts",
    "intake_package_missing",
}
_RUNTIME_TARGET_INTAKE_LANGUAGES = {
    "C",
    "C#",
    "C++",
    "Go",
    "Java",
    "JavaScript",
    "Kotlin",
    "PHP",
    "Python",
    "Ruby",
    "Rust",
    "Scala",
    "Swift",
    "TypeScript",
}
_RUNTIME_TARGET_INTAKE_FRAMEWORKS = {
    "ASP.NET",
    "Chi",
    "Django",
    "Echo",
    "Express",
    "FastAPI",
    "Flask",
    "Gin",
    "Gitea",
    "Laravel",
    "NestJS",
    "Next.js",
    "Rails",
    "React",
    "Spring",
}
_RUNTIME_TARGET_INTAKE_SAFETY_FIELDS = (
    "raw_payload_processed",
    "execution_allowed",
    "dispatch_allowed",
    "validation_allowed",
    "candidate_promotion_allowed",
    "report_submission_allowed",
)
_SECURITY_INVARIANT_PROJECTION_SCHEMA = "security_invariant_projection_v1"
_AUTONOMOUS_CROSS_SOURCE_LLM_ADVISORY_SCHEMA = (
    "autonomous_cross_source_llm_advisory_v1"
)
_SECURITY_INVARIANT_REF_PATTERN = re.compile(r"security_invariant:[0-9a-f]{64}")
_CODEBASE_FACT_REF_PATTERN = re.compile(r"codebase_fact:[A-Za-z0-9_-]{1,100}")
_MODEL_ADVISORY_CANDIDATE_ID_PATTERN = re.compile(r"[A-Za-z0-9_-]{1,100}")
_MODEL_ADVISORY_LLM_RUN_ID_PATTERN = re.compile(r"llm_run_[A-Za-z0-9_-]{1,90}")
_MODEL_ADVISORY_TEXT_PATTERNS = (
    re.compile(r"\bbearer\s+\S+", re.IGNORECASE),
    re.compile(r"\b(?:api[_-]?key|password|secret|token)\s*[:=]", re.IGNORECASE),
    re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE),
    re.compile(r"\bconfirmed?\b", re.IGNORECASE),
    re.compile(r"\bexploit(?:ed|able|ation)?\b", re.IGNORECASE),
    re.compile(r"\blive\s+(?:test|validation|request)\b", re.IGNORECASE),
    re.compile(r"\breport\s+(?:ready|submission|submitted)\b", re.IGNORECASE),
    re.compile(r"\bsubmit(?:ted)?\b", re.IGNORECASE),
)
_ADVISORY_ARTIFACT_INPUT_REF_PATTERN = re.compile(
    r"artifact:(artifact_[A-Za-z0-9_-]{1,90})",
    re.ASCII,
)
_LEARNING_SIGNAL_INPUT_REF_PATTERN = re.compile(
    r"learning_signal:(learning_signal_[A-Za-z0-9_-]{1,90})",
    re.ASCII,
)
_HISTORICAL_REPORT_STAGE_INPUT_REF_PATTERN = re.compile(
    r"historical_report_stage:(pipeline_stage_[A-Za-z0-9_-]{1,90})",
    re.ASCII,
)
_TOKEN_REFERENCE_PATTERN = re.compile(
    r"token:[A-Za-z_$][A-Za-z0-9_$]*(?:\.[A-Za-z_$][A-Za-z0-9_$]*)*"
)
_RUNTIME_TARGET_MODEL_PROJECTION_SCHEMA = "runtime_target_model_projection_v1"
_RUNTIME_ATTACK_SURFACE_QUEUE_SCHEMA = "runtime_attack_surface_queue_v1"
_RUNTIME_CANDIDATE_HUNTER_PROJECTION_SCHEMA = (
    "runtime_candidate_hunter_projection_v1"
)
_SECURITY_INVARIANT_FAMILIES = {
    "object_authorization_boundary": (
        "Object-scoped routes must enforce ownership or role checks before mapped sensitive work."
    ),
    "route_authorization_boundary": (
        "Mapped routes must enforce an authorization boundary before sensitive work."
    ),
    "sensitive_sink_boundary": (
        "Mapped sensitive work must remain behind the route authorization boundary."
    ),
    "ssrf_egress_boundary": (
        "Outbound requests to user-controlled URLs must validate the target "
        "against private networks, metadata endpoints, and unsafe schemes."
    ),
    "path_traversal_boundary": (
        "User-controlled file paths must be sanitized before reaching filesystem read sinks."
    ),
    "mass_assignment_boundary": (
        "User-controlled update payloads must not set privilege or tenancy fields without an allowlist."
    ),
    "injection_query_boundary": (
        "Untrusted input must be parameterized or structurally constrained before reaching query execution sinks."
    ),
    "command_execution_boundary": (
        "Command selection and arguments must be constrained by an explicit local allowlist "
        "or structured validation before command-execution sinks."
    ),
    "unsafe_deserialization_boundary": (
        "Serialized input must pass an explicit type and loader policy before unsafe "
        "deserialization sinks."
    ),
    "file_upload_boundary": (
        "Uploaded files must pass explicit type, filename, and storage policy checks "
        "before upload-storage sinks."
    ),
    "server_authoritative_money_flow": (
        "Financial amounts, credits, and refunds must be derived from trusted server-side "
        "order or account state before financial action sinks."
    ),
    "state_transition_consistency": (
        "One-time, quota, and limited-resource state transitions must use an explicit "
        "transactional or conditional-write guard before the transition sink."
    ),
    "agent_tool_authorization_boundary": (
        "Agent tool dispatch must verify the current user, agent policy, and task context "
        "permit the selected tool before invocation."
    ),
    "jwt_authentication_boundary": (
        "JWT claims must be signature-verified and validated before they influence "
        "sensitive operations."
    ),
}
_SECURITY_INVARIANT_STATUSES = {
    "guard_observed",
    "needs_evidence",
    "needs_refutation",
}
_STATIC_GAP_PROFILES = {
    "missing_ssrf_validation": {
        "vuln_type": "ssrf",
        "security_invariant_family": "ssrf_egress_boundary",
        "hypothesis": "Review {route_label} for outbound target validation gaps.",
        "broken_invariant": _SECURITY_INVARIANT_FAMILIES["ssrf_egress_boundary"],
        "validation_mode": "offline_ssrf_target_policy_review",
        "evidence_needed": (
            "local_egress_validation_trace",
            "allowed_target_policy_review",
            "sanitized_target_classification",
        ),
        "validation_steps": (
            "Review the local URL parsing and egress policy call path.",
            "Confirm URL allowlist and denylist controls before any validation planning.",
            "Use only fixture target classes in a human-approved review; do not send requests from this plan.",
        ),
        "refutation_questions": (
            "Does a same-handler URL validation control run before the outbound sink?",
            "Does normalized URL handling reject private, metadata, and unsafe scheme targets?",
            "Can local control evidence refute the egress boundary gap before validation?",
        ),
        "impact": (
            "Potential server-side outbound request risk if an untrusted target reaches the mapped egress sink."
        ),
        "playbook_id": "ssrf_egress_boundary",
        "playbook_label": "SSRF egress boundary",
        "priority_score": 70,
        "impact_score": 80,
        "guard_hints": ("ssrf_validation_check",),
    },
    "missing_path_validation": {
        "vuln_type": "path_traversal",
        "security_invariant_family": "path_traversal_boundary",
        "hypothesis": "Review {route_label} for file path canonicalization gaps.",
        "broken_invariant": _SECURITY_INVARIANT_FAMILIES["path_traversal_boundary"],
        "validation_mode": "offline_path_canonicalization_review",
        "evidence_needed": (
            "local_path_validation_trace",
            "path_boundary_policy_review",
            "sanitized_fixture_path_classification",
        ),
        "validation_steps": (
            "Review local basename, safe-join, and canonicalization controls before the file sink.",
            "Confirm the mapped handler rejects traversal-shaped fixture paths before validation planning.",
            "Use only local fixtures in a human-approved review; do not read external files from this plan.",
        ),
        "refutation_questions": (
            "Does a same-handler canonicalization or safe-join control run before the file sink?",
            "Does the control reject traversal-shaped fixture paths after normalization?",
            "Can local control evidence refute the filesystem boundary gap before validation?",
        ),
        "impact": (
            "Potential unauthorized file access risk if an untrusted path reaches the mapped filesystem sink."
        ),
        "playbook_id": "path_traversal_boundary",
        "playbook_label": "Path traversal boundary",
        "priority_score": 70,
        "impact_score": 78,
        "guard_hints": ("path_validation_check",),
    },
    "missing_mass_assignment_guard": {
        "vuln_type": "mass_assignment",
        "security_invariant_family": "mass_assignment_boundary",
        "hypothesis": "Review {route_label} for writable sensitive field boundary gaps.",
        "broken_invariant": _SECURITY_INVARIANT_FAMILIES["mass_assignment_boundary"],
        "validation_mode": "offline_field_allowlist_review",
        "evidence_needed": (
            "local_field_allowlist_trace",
            "sensitive_field_policy_review",
            "sanitized_fixture_field_matrix",
        ),
        "validation_steps": (
            "Review local DTO, schema, and field allowlist controls before the update sink.",
            "Confirm privilege and tenancy fields are rejected by mapped validation controls.",
            "Use only synthetic field names in a human-approved review; do not update data from this plan.",
        ),
        "refutation_questions": (
            "Does a same-handler field allowlist run before the update sink?",
            "Are privilege and tenancy fields rejected by local schema or policy controls?",
            "Can local control evidence refute the writable-field boundary gap before validation?",
        ),
        "impact": (
            "Potential privilege or tenancy boundary risk if untrusted fields reach the mapped update sink."
        ),
        "playbook_id": "mass_assignment_boundary",
        "playbook_label": "Mass assignment boundary",
        "priority_score": 68,
        "impact_score": 78,
        "guard_hints": ("mass_assignment_check",),
    },
    "missing_injection_validation": {
        "vuln_type": "injection",
        "security_invariant_family": "injection_query_boundary",
        "hypothesis": "Review {route_label} for query parameterization boundary gaps.",
        "broken_invariant": _SECURITY_INVARIANT_FAMILIES["injection_query_boundary"],
        "validation_mode": "offline_query_parameterization_review",
        "evidence_needed": (
            "local_query_parameterization_trace",
            "query_boundary_policy_review",
            "sanitized_fixture_input_classification",
        ),
        "validation_steps": (
            "Review local query construction and parameterization controls before the execution sink.",
            "Confirm untrusted input is structurally constrained without constructing payloads.",
            "Use only local fixture reasoning in a human-approved review; do not execute queries from this plan.",
        ),
        "refutation_questions": (
            "Does a same-handler parameterization or structural validation control run before query execution?",
            "Does the mapped query API keep untrusted input out of executable query structure?",
            "Can local control evidence refute the query boundary gap before validation?",
        ),
        "impact": (
            "Potential query manipulation risk if untrusted input reaches the mapped execution sink."
        ),
        "playbook_id": "injection_query_boundary",
        "playbook_label": "Injection query boundary",
        "priority_score": 72,
        "impact_score": 82,
        "guard_hints": ("injection_validation_check",),
    },
    "missing_command_injection_validation": {
        "vuln_type": "command_injection",
        "security_invariant_family": "command_execution_boundary",
        "hypothesis": "Review {route_label} for command execution validation gaps.",
        "broken_invariant": _SECURITY_INVARIANT_FAMILIES["command_execution_boundary"],
        "validation_mode": "offline_command_execution_boundary_review",
        "evidence_needed": (
            "local_command_validation_trace",
            "command_allowlist_policy_review",
            "sanitized_command_fixture_classification",
        ),
        "validation_steps": (
            "Review the local command selection and argument validation path before the command-execution sink.",
            "Confirm only explicitly allowed command identifiers and structured argument rules reach the mapped sink.",
            "Use only synthetic command labels in a human-approved offline review; do not invoke processes from this plan.",
        ),
        "refutation_questions": (
            "Does a same-handler command allowlist or argument validation control run before execution?",
            "Does the mapped control constrain command identifiers and arguments without constructing commands?",
            "Can local control evidence refute the command execution boundary gap before validation?",
        ),
        "impact": (
            "Potential command execution risk if untrusted command selection or arguments reach the mapped sink."
        ),
        "playbook_id": "command_execution_boundary",
        "playbook_label": "Command execution boundary",
        "priority_score": 74,
        "impact_score": 85,
        "guard_hints": ("command_injection_validation_check",),
    },
    "missing_unsafe_deserialization_guard": {
        "vuln_type": "unsafe_deserialization",
        "security_invariant_family": "unsafe_deserialization_boundary",
        "hypothesis": "Review {route_label} for unsafe deserialization boundary gaps.",
        "broken_invariant": _SECURITY_INVARIANT_FAMILIES[
            "unsafe_deserialization_boundary"
        ],
        "validation_mode": "offline_deserialization_policy_review",
        "evidence_needed": (
            "local_deserialization_trace",
            "safe_loader_policy_review",
            "sanitized_serialized_fixture_classification",
        ),
        "validation_steps": (
            "Review the local deserialization call path and loader policy before the mapped sink.",
            "Confirm type restrictions and safe loader selection reject unsupported serialized inputs.",
            "Use only sanitized local fixtures in a human-approved offline review; do not deserialize supplied data from this plan.",
        ),
        "refutation_questions": (
            "Does a same-handler serialized-payload validation control run before deserialization?",
            "Does the mapped loader restrict allowed types and formats before object construction?",
            "Can local control evidence refute the deserialization boundary gap before validation?",
        ),
        "impact": (
            "Potential unsafe object construction risk if untrusted serialized input reaches the mapped sink."
        ),
        "playbook_id": "unsafe_deserialization_boundary",
        "playbook_label": "Unsafe deserialization boundary",
        "priority_score": 74,
        "impact_score": 85,
        "guard_hints": ("deserialization_validation_check",),
    },
    "missing_file_upload_validation": {
        "vuln_type": "file_upload",
        "security_invariant_family": "file_upload_boundary",
        "hypothesis": "Review {route_label} for file-upload validation and storage boundary gaps.",
        "broken_invariant": _SECURITY_INVARIANT_FAMILIES["file_upload_boundary"],
        "validation_mode": "offline_file_upload_policy_review",
        "evidence_needed": (
            "local_upload_validation_trace",
            "upload_storage_policy_review",
            "sanitized_upload_fixture_classification",
        ),
        "validation_steps": (
            "Review the local upload validation and storage call path before the mapped sink.",
            "Confirm type, filename, and storage policy checks reject unsupported fixture uploads.",
            "Use only sanitized local fixture metadata in a human-approved offline review; do not upload files from this plan.",
        ),
        "refutation_questions": (
            "Does a same-handler upload validation control run before storage?",
            "Does the mapped policy constrain file type, filename, and storage exposure?",
            "Can local control evidence refute the upload boundary gap before validation?",
        ),
        "impact": (
            "Potential unsafe file handling risk if untrusted uploads reach the mapped storage sink."
        ),
        "playbook_id": "file_upload_boundary",
        "playbook_label": "File upload boundary",
        "priority_score": 72,
        "impact_score": 82,
        "guard_hints": ("file_upload_validation_check",),
    },
    "missing_server_authoritative_amount_check": {
        "vuln_type": "business_logic",
        "security_invariant_family": "server_authoritative_money_flow",
        "hypothesis": "Review {route_label} for client-controlled financial amount or credit gaps.",
        "broken_invariant": _SECURITY_INVARIANT_FAMILIES[
            "server_authoritative_money_flow"
        ],
        "validation_mode": "offline_server_amount_policy_review",
        "evidence_needed": (
            "local_money_flow_trace",
            "server_amount_derivation_policy_review",
            "sanitized_transaction_fixture_classification",
        ),
        "validation_steps": (
            "Review the local amount derivation and financial action call path before the mapped sink.",
            "Confirm trusted order or account state supplies the amount, credit, or refund decision.",
            "Use only sanitized transaction fixture metadata in a human-approved offline review; do not create payments, refunds, or transfers from this plan.",
        ),
        "refutation_questions": (
            "Does a same-handler server-side amount derivation control run before the financial sink?",
            "Does the mapped action ignore client-supplied amount or credit values in favor of trusted state?",
            "Can local control evidence refute the money-flow boundary gap before validation?",
        ),
        "impact": (
            "Potential financial integrity risk if client-controlled values reach a mapped payment, refund, credit, or transfer action."
        ),
        "playbook_id": "money_flow_tampering",
        "playbook_label": "Server-authoritative money flow",
        "priority_score": 78,
        "impact_score": 88,
        "guard_hints": ("server_authoritative_amount_check",),
    },
    "missing_transactional_state_guard": {
        "vuln_type": "race_condition",
        "security_invariant_family": "state_transition_consistency",
        "hypothesis": "Review {route_label} for transactional state-transition consistency gaps.",
        "broken_invariant": _SECURITY_INVARIANT_FAMILIES[
            "state_transition_consistency"
        ],
        "validation_mode": "offline_transactional_state_review",
        "evidence_needed": (
            "local_state_transition_trace",
            "transactional_guard_policy_review",
            "sanitized_state_transition_fixture_review",
        ),
        "validation_steps": (
            "Review the local state-transition and transactional-control call path before the mapped sink.",
            "Confirm local persistence constraints, conditional writes, and retry semantics preserve the one-time or quota invariant.",
            "Use only local synthetic sequence fixtures in a human-approved offline review; do not run concurrent requests or mutate target state.",
        ),
        "refutation_questions": (
            "Does an explicit transaction, conditional write, or lock run before the mapped state-transition sink?",
            "Do local persistence constraints preserve the one-time or quota invariant under retry or concurrent access?",
            "Can local control evidence refute the state-transition consistency gap before validation?",
        ),
        "impact": (
            "Potential duplicate redemption, quota over-consumption, or inconsistent state if a mapped one-time or quota transition lacks an atomic guard."
        ),
        "playbook_id": "state_transition_consistency",
        "playbook_label": "Transactional state transition",
        "priority_score": 74,
        "impact_score": 84,
        "guard_hints": ("transactional_state_guard",),
    },
    "missing_agent_tool_authorization_check": {
        "vuln_type": "agent_tool_authz_gap",
        "security_invariant_family": "agent_tool_authorization_boundary",
        "hypothesis": "Review {route_label} for agent tool authorization policy gaps.",
        "broken_invariant": _SECURITY_INVARIANT_FAMILIES[
            "agent_tool_authorization_boundary"
        ],
        "validation_mode": "offline_agent_tool_policy_review",
        "evidence_needed": (
            "local_agent_tool_policy_trace",
            "tool_allowlist_policy_review",
            "sanitized_tool_fixture_classification",
        ),
        "validation_steps": (
            "Review the local agent, user, task-context, and tool-policy checks before the mapped dispatch sink.",
            "Confirm disallowed tool labels and resource scopes are rejected by local policy without invoking a tool.",
            "Use only sanitized local mock-tool metadata in a human-approved offline review; do not dispatch tools from this plan.",
        ),
        "refutation_questions": (
            "Does a same-handler per-agent and per-user tool policy check run before dispatch?",
            "Does the mapped dispatcher recheck task and resource scope for the selected tool?",
            "Can local control evidence refute the agent tool authorization gap before validation?",
        ),
        "impact": (
            "Potential privileged action or resource-scope risk if an agent dispatches a tool beyond the current policy boundary."
        ),
        "playbook_id": "agent_tool_authorization",
        "playbook_label": "Agent tool authorization",
        "priority_score": 78,
        "impact_score": 88,
        "guard_hints": ("agent_tool_authorization_check",),
    },
    "missing_jwt_verification": {
        "vuln_type": "jwt_authentication_bypass",
        "security_invariant_family": "jwt_authentication_boundary",
        "hypothesis": "Review {route_label} for JWT signature verification and claims-validation gaps.",
        "broken_invariant": _SECURITY_INVARIANT_FAMILIES[
            "jwt_authentication_boundary"
        ],
        "validation_mode": "offline_jwt_verification_review",
        "evidence_needed": (
            "local_jwt_verification_trace",
            "jwt_claims_validation_policy_review",
            "sanitized_token_shape_classification",
        ),
        "validation_steps": (
            "Review the local JWT decoding, signature verification, and claims-validation call path before the mapped sensitive operation.",
            "Confirm issuer, audience, expiry, and algorithm policy are bound to trusted local configuration.",
            "Use only sanitized local token-shape fixtures in a human-approved review; do not access accounts or submit requests from this plan.",
        ),
        "refutation_questions": (
            "Does an explicit JWT verification or validation control run before the sensitive operation?",
            "Does the mapped verifier bind signature, issuer, audience, expiry, and algorithm checks to trusted local policy?",
            "Can local control evidence show decoded claims do not influence the sensitive operation before any validation planning?",
        ),
        "impact": (
            "Potential authentication or authorization bypass risk if unverified JWT claims influence a mapped sensitive operation."
        ),
        "playbook_id": "jwt_authentication_boundary",
        "playbook_label": "JWT authentication boundary",
        "priority_score": 78,
        "impact_score": 88,
        "guard_hints": ("jwt_verification_check",),
    },
}
_AUTONOMOUS_EXPLOIT_CHAIN_PROJECTION_SCHEMA = "autonomous_exploit_chain_projection_v1"
_AUTONOMOUS_VARIANT_ANALYSIS_PROJECTION_SCHEMA = (
    "autonomous_variant_analysis_projection_v1"
)
_AUTONOMOUS_FINDING_DEDUP_RISK_PROJECTION_SCHEMA = (
    "autonomous_finding_dedup_risk_projection_v1"
)
_AUTONOMOUS_DEEP_CODE_REASONING_PROJECTION_SCHEMA = (
    "autonomous_deep_code_reasoning_projection_v1"
)
_EXPLOIT_CHAIN_REF_PATTERN = re.compile(r"exploit_chain:CH-[0-9]{3}")
_VARIANT_ANALYSIS_ID_PATTERN = re.compile(r"VA-[0-9]{3}")
_FINDING_DEDUP_RISK_CLUSTER_ID_PATTERN = re.compile(r"FDC-[0-9]{3}")
_DEEP_CODE_REASONING_PATH_ID_PATTERN = re.compile(r"DCR-[0-9]{3}")
_DEEP_CODE_REASONING_MODEL_ID_PATTERN = re.compile(r"PM-[0-9]{3}")
_CHAIN_TOKEN_PATTERN = re.compile(r"[a-z][a-z0-9_-]{0,79}")
_CHAIN_REFUTATION_QUESTIONS = [
    "Does persisted local evidence refute a required chain precondition?",
    "Does a mapped control break the chain before the next primitive?",
    "Is a human-approved non-destructive validation plan still needed?",
]
_AUTONOMOUS_REPORT_PROVENANCE_SCHEMA = "autonomous_report_provenance_v1"
_AUTONOMOUS_REPORT_REVIEW_SCHEMA = "autonomous_report_review_v1"
_RUNTIME_REPORT_MULTI_ENGINE_STATUSES = {
    "local_static_consistent",
    "needs_human_review",
}
_RUNTIME_REPORT_MULTI_ENGINE_SAFETY_FIELDS = (
    "execution_allowed",
    "validation_allowed",
    "report_submission_allowed",
    "finding_promotion_allowed",
    "confirmed_vulnerability",
)
_RUNTIME_REPORT_FALSIFICATION_SCHEMA = "falsification_card_v1"
_RUNTIME_REPORT_FALSIFICATION_SAFETY_FIELDS = (
    "execution_allowed",
    "dispatch_allowed",
    "validation_allowed",
    "candidate_promotion_allowed",
    "report_submission_allowed",
)
_SHA256_PATTERN = re.compile(r"[0-9a-f]{64}")
_SAFE_PROVENANCE_REF_PATTERN = re.compile(
    r"[a-z][a-z0-9_]{0,50}:[A-Za-z0-9._:/{}@+\-]{1,500}"
)
_autonomous_research_wakeup_thread_lock = Lock()
_autonomous_research_wakeup_thread: Thread | None = None
_logger = logging.getLogger(__name__)


class _WorkerExecutionFailure(RuntimeError):
    pass


@celery_app.task(name="worker.ping")
def ping() -> str:
    return "pong"


@celery_app.task(name="agent.run")
def run_agent_task_from_queue(campaign_task_id: str) -> dict:
    initialize_database()
    with get_session_factory()() as session:
        return run_agent_task(campaign_task_id, repository=DatabaseRepository(session))


@celery_app.task(name="autonomous_research.wakeup")
def run_autonomous_research_wakeup_from_queue() -> dict:
    return _run_autonomous_research_wakeup_with_worker_session()


def start_autonomous_research_wakeup_in_background() -> bool:
    global _autonomous_research_wakeup_thread

    with _autonomous_research_wakeup_thread_lock:
        if (
            _autonomous_research_wakeup_thread is not None
            and _autonomous_research_wakeup_thread.is_alive()
        ):
            return False
        thread = Thread(
            target=_run_autonomous_research_wakeup_in_background,
            daemon=True,
            name="autonomous-research-wakeup",
        )
        _autonomous_research_wakeup_thread = thread
        try:
            thread.start()
        except Exception:
            _autonomous_research_wakeup_thread = None
            raise
    return True


def _run_autonomous_research_wakeup_in_background() -> None:
    global _autonomous_research_wakeup_thread

    try:
        _run_autonomous_research_wakeup_with_worker_session()
    except Exception:
        _logger.warning("autonomous_research_wakeup_background_failed")
    finally:
        with _autonomous_research_wakeup_thread_lock:
            if _autonomous_research_wakeup_thread is current_thread():
                _autonomous_research_wakeup_thread = None


def _run_autonomous_research_wakeup_with_worker_session() -> dict:
    from app.autonomous_research_wakeup import run_autonomous_research_wakeup

    initialize_database()
    with get_session_factory()() as session:
        return run_autonomous_research_wakeup(
            repository=DatabaseRepository(session),
            dispatcher=dispatch_agent_task,
        )


def dispatch_agent_task(*, campaign_task_id: str) -> dict:
    if get_settings().worker_dispatch_mode == "inline":
        result = run_agent_task_from_queue.run(campaign_task_id)
        return {
            "campaign_task_id": campaign_task_id,
            "dispatch_mode": "inline",
            "result": result,
        }

    queued_task = run_agent_task_from_queue.delay(campaign_task_id)
    return {
        "campaign_task_id": campaign_task_id,
        "dispatch_mode": "celery",
        "celery_task_id": queued_task.id,
    }


def run_agent_task(
    campaign_task_id: str,
    *,
    repository: DatabaseRepository,
) -> dict:
    try:
        return _run_agent_task(campaign_task_id, repository=repository)
    except _WorkerExecutionFailure:
        repository.session.rollback()
        task = repository.session.get(CampaignTaskRecord, campaign_task_id)
        if task is None or task.status != "running":
            raise
        return _record_unexpected_worker_failure(task=task, repository=repository)


def _run_agent_task(
    campaign_task_id: str,
    *,
    repository: DatabaseRepository,
) -> dict:
    task = repository.session.get(CampaignTaskRecord, campaign_task_id)
    if task is None:
        return {
            "status": "not_found",
            "task_id": campaign_task_id,
            "stop_reason": "campaign_task_not_found",
        }

    if (
        task.status == "blocked"
        and task.task_type == "candidate_hunter_evidence_inspection"
    ):
        from app.autonomous_research_runtime import (
            reconcile_autonomous_research_evidence_block,
        )

        task_payload = task.payload if isinstance(task.payload, dict) else {}
        owner_task_id = task_payload.get("owner_task_id")
        owner_task = (
            repository.session.get(CampaignTaskRecord, owner_task_id)
            if isinstance(owner_task_id, str)
            else None
        )
        if owner_task is not None:
            reconcile_autonomous_research_evidence_block(
                owner_task=owner_task,
                repository=repository,
            )
        return _persisted_task_result(task)
    if task.status in _NON_DISPATCHABLE_TASK_STATUSES:
        return _persisted_task_result(task)
    if task.task_type == "validation_handoff":
        return _await_human_approval(task=task, repository=repository)
    if task.status not in _DISPATCHABLE_TASK_STATUSES:
        return {
            "status": "blocked",
            "task_id": task.id,
            "stop_reason": "task_not_dispatchable",
        }
    claimed_task = repository.claim_campaign_task_execution(task.id)
    if claimed_task is None:
        persisted_task = repository.session.get(CampaignTaskRecord, task.id)
        if persisted_task is None:
            return {
                "status": "not_found",
                "task_id": task.id,
                "stop_reason": "campaign_task_not_found",
            }
        return _persisted_task_result(persisted_task)
    task = claimed_task
    if task.execution_claim_id is not None:
        renewed_task = repository.renew_campaign_task_execution_lease(
            task.id,
            execution_claim_id=task.execution_claim_id,
        )
        if renewed_task is None:
            return _persisted_task_result(
                repository.session.get(CampaignTaskRecord, task.id) or task
            )
        task = renewed_task

    if task.task_type == "candidate_hunter_evidence_inspection":
        from app.candidate_hunter_evidence import (
            resume_candidate_hunter_after_evidence,
            run_evidence_inspection_task,
        )

        result = run_evidence_inspection_task(repository=repository, task_id=task.id)
        if result.get("status") != "completed":
            _record_runtime_evidence_resume(
                evidence_task=task,
                resumed=result,
                repository=repository,
            )
            return result
        resumed = resume_candidate_hunter_after_evidence(
            repository=repository,
            evidence_task_id=task.id,
        )
        _record_runtime_evidence_resume(
            evidence_task=task,
            resumed=resumed,
            repository=repository,
        )
        return resumed

    campaign = repository.get_campaign(task.campaign_id)
    if task.task_type == "research_director_local_tool_run":
        from app.research_director.runtime import run_campaign_local_tool_task

        return run_campaign_local_tool_task(
            task=task,
            repository=repository,
        )
    stop_reason = _agent_task_stop_reason(
        campaign=campaign,
        repository=repository,
    )
    from app.autonomous_research_runtime import (
        autonomous_research_task_stop_reason,
    )

    if stop_reason is None:
        stop_reason = autonomous_research_task_stop_reason(
            task=task,
            campaign=campaign,
            repository=repository,
        )
    if stop_reason is not None:
        return _block_agent_task(
            task=task,
            repository=repository,
            stop_reason=stop_reason,
        )
    workspace_inputs, workspace_stop_reason = _runtime_workspace_inputs(
        task=task,
        campaign=campaign,
    )
    if workspace_stop_reason is not None:
        return _block_agent_task(
            task=task,
            repository=repository,
            stop_reason=workspace_stop_reason,
        )

    observed_target_intake: dict | None = None
    observed_target_intake_ref: str | None = None
    task_payload = task.payload if isinstance(task.payload, dict) else {}
    if (
        task.task_type == "attack_surface_mapping"
        and task_payload.get("runtime_schema")
        == _AUTONOMOUS_RESEARCH_RUNTIME_SCHEMA
    ):
        expected_target_intake = _runtime_target_intake_projection(
            authorized_code_files=(
                workspace_inputs.get("code_files")
                if isinstance(workspace_inputs, dict)
                else None
            ),
        )
        (
            observed_target_intake,
            observed_target_intake_ref,
            target_intake_stop_reason,
        ) = _runtime_observed_target_intake_projection(
            task=task,
            campaign=campaign,
            repository=repository,
            expected_target_intake=expected_target_intake,
        )
        if target_intake_stop_reason is not None:
            return _block_agent_task(
                task=task,
                repository=repository,
                stop_reason=target_intake_stop_reason,
            )

    target_model_projection: dict | None = None
    if task.task_type in {
        "security_invariant_generation",
        "hypothesis_generation",
    }:
        target_model_projection, target_model_stop_reason = (
            _runtime_target_model_projection(
                task=task,
                campaign=campaign,
                repository=repository,
            )
        )
        if target_model_stop_reason is not None:
            return _block_agent_task(
                task=task,
                repository=repository,
                stop_reason=target_model_stop_reason,
            )

    security_invariants: list[dict] | None = None
    if task.task_type == "hypothesis_generation":
        security_invariants, invariant_stop_reason = (
            _runtime_security_invariant_projection(
                task=task,
                campaign=campaign,
                repository=repository,
            )
        )
        if invariant_stop_reason is not None:
            return _block_agent_task(
                task=task,
                repository=repository,
                stop_reason=invariant_stop_reason,
            )

    if task.task_type == "cross_source_llm_advisory":
        return _run_cross_source_llm_advisory_task(
            task=task,
            campaign=campaign,
            repository=repository,
            workspace_inputs=workspace_inputs,
        )

    if task.task_type == "exploit_chain_reasoning":
        return _run_exploit_chain_reasoning_task(
            task=task,
            campaign=campaign,
            repository=repository,
        )

    if task.task_type == "variant_analysis":
        return _run_variant_analysis_task(
            task=task,
            campaign=campaign,
            repository=repository,
        )

    if task.task_type == "deep_code_reasoning":
        return _run_deep_code_reasoning_task(
            task=task,
            campaign=campaign,
            repository=repository,
        )

    if task.task_type == "candidate_refutation":
        return _run_candidate_refutation_task(
            task=task,
            campaign=campaign,
            repository=repository,
            workspace_inputs=workspace_inputs,
        )

    if task.task_type == "finding_dedup_and_rank":
        return _run_finding_dedup_and_rank_task(
            task=task,
            campaign=campaign,
            repository=repository,
        )

    if task.task_type == "report_review":
        return _run_report_review_task(
            task=task,
            campaign=campaign,
            repository=repository,
        )

    materialized_output_refs, artifact_payload = _materialize_read_only_artifacts(
        task=task,
        campaign=campaign,
        repository=repository,
        workspace_inputs=workspace_inputs,
        security_invariants=security_invariants,
        target_model_projection=target_model_projection,
        observed_target_intake=observed_target_intake,
        observed_target_intake_ref=observed_target_intake_ref,
    )
    agent_run_output_refs = materialized_output_refs or [f"campaign_task:{task.id}:completed"]
    agent_run_payload = {
        **artifact_payload,
        "raw_payload_processed": False,
        "worker_mode": "safe_read_only_artifact_materializer",
    }
    completed_execution = _finish_task_execution(
        task=task,
        repository=repository,
        task_status="completed",
        output_refs=materialized_output_refs,
        agent_status="completed",
        agent_output_refs=agent_run_output_refs,
        safety_gate_state="allowed",
        stop_reason=None,
        payload=agent_run_payload,
    )
    if completed_execution is None:
        return _execution_lease_lost_result(task=task, repository=repository)
    completed_task, agent_run = completed_execution
    from app.autonomous_research_runtime import record_autonomous_research_task_completion

    record_autonomous_research_task_completion(
        task=completed_task,
        repository=repository,
    )
    return {
        "status": "completed",
        "task_id": task.id,
        "agent_run_id": agent_run.id,
        "stop_reason": None,
    }


def _runtime_workspace_inputs(
    *,
    task: CampaignTaskRecord,
    campaign: CampaignRecord | None,
) -> tuple[dict | None, str | None]:
    task_payload = task.payload if isinstance(task.payload, dict) else {}
    if task_payload.get("runtime_schema") != "autonomous_research_v1":
        return None, None
    campaign_payload = campaign.payload if campaign is not None and isinstance(campaign.payload, dict) else {}
    snapshot = campaign_payload.get("workspace_snapshot")
    if snapshot is None:
        return None, None
    try:
        inputs = load_authorized_campaign_inputs(snapshot)
    except ValueError as exc:
        reason = str(exc)
        return None, (
            "workspace_snapshot_changed"
            if reason == "workspace_snapshot_changed"
            else "workspace_snapshot_invalid"
        )
    if task_payload.get("source_snapshot_digest") != inputs.get(
        "source_snapshot_digest"
    ):
        return None, "source_snapshot_changed"
    return inputs, None


def _await_human_approval(
    *,
    task: CampaignTaskRecord,
    repository: DatabaseRepository,
) -> dict:
    repository.update_campaign_task_status(task.id, "awaiting_approval")
    return {
        "status": "awaiting_approval",
        "task_id": task.id,
        "stop_reason": "human_approval_required",
    }


def _persisted_task_result(task: CampaignTaskRecord) -> dict:
    stop_reason = {
        "awaiting_approval": "human_approval_required",
        "awaiting_evidence": "awaiting_evidence",
        "needs_evidence": "awaiting_evidence",
        "running": "task_already_running",
    }.get(task.status)
    return {
        "status": task.status,
        "task_id": task.id,
        "stop_reason": stop_reason,
    }


def _finish_task_execution(
    *,
    task: CampaignTaskRecord,
    repository: DatabaseRepository,
    task_status: str,
    output_refs: list[str],
    agent_status: str,
    agent_output_refs: list[str],
    safety_gate_state: str,
    stop_reason: str | None,
    payload: dict,
) -> tuple[CampaignTaskRecord, AgentRunRecord] | None:
    if task.execution_claim_id is not None:
        renewed_task = repository.renew_campaign_task_execution_lease(
            task.id,
            execution_claim_id=task.execution_claim_id,
        )
        if renewed_task is None:
            return None
        renewed_claim_id = renewed_task.execution_claim_id
        if renewed_claim_id is None:
            return None
        return repository.finish_campaign_task_execution(
            task_id=renewed_task.id,
            execution_claim_id=renewed_claim_id,
            task_status=task_status,
            task_output_refs=[
                f"agent_run:{renewed_claim_id}",
                *output_refs,
            ],
            agent_status=agent_status,
            agent_output_refs=agent_output_refs,
            safety_gate_state=safety_gate_state,
            stop_reason=stop_reason,
            payload=payload,
        )

    active_run = repository.find_active_agent_run_for_task(task.id)
    if active_run is not None:
        agent_run = repository.finish_agent_run(
            active_run.id,
            status=agent_status,
            output_refs=agent_output_refs,
            safety_gate_state=safety_gate_state,
            stop_reason=stop_reason,
            payload=payload,
        )
    else:
        agent_run = repository.save_agent_run(
            campaign_id=task.campaign_id,
            task_id=task.id,
            agent_type=task.agent_type,
            status=agent_status,
            input_refs=[f"campaign_task:{task.id}"],
            output_refs=agent_output_refs,
            tool_calls=[],
            safety_gate_state=safety_gate_state,
            stop_reason=stop_reason,
            payload=payload,
        )
    if agent_run is None:
        return None
    completed_task = repository.update_campaign_task_status(
        task.id,
        task_status,
        output_refs=[f"agent_run:{agent_run.id}", *output_refs],
    )
    if completed_task is None:
        return None
    return completed_task, agent_run


def _active_agent_run_for_task(
    *,
    task: CampaignTaskRecord,
    repository: DatabaseRepository,
) -> AgentRunRecord | None:
    if task.execution_claim_id is not None:
        agent_run = repository.session.get(AgentRunRecord, task.execution_claim_id)
        if (
            agent_run is not None
            and agent_run.task_id == task.id
            and agent_run.status in {"dispatched", "running", "awaiting_approval"}
        ):
            return agent_run
        return None
    return repository.find_active_agent_run_for_task(task.id)


def _execution_lease_lost_result(
    *,
    task: CampaignTaskRecord,
    repository: DatabaseRepository,
) -> dict:
    persisted_task = repository.session.get(CampaignTaskRecord, task.id)
    if persisted_task is None:
        return {
            "status": "not_found",
            "task_id": task.id,
            "stop_reason": "campaign_task_not_found",
        }
    return {
        "status": persisted_task.status,
        "task_id": persisted_task.id,
        "stop_reason": "execution_lease_lost",
    }


def _record_runtime_evidence_resume(
    *,
    evidence_task: CampaignTaskRecord,
    resumed: dict,
    repository: DatabaseRepository,
) -> None:
    payload = evidence_task.payload if isinstance(evidence_task.payload, dict) else {}
    owner_task_id = payload.get("owner_task_id")
    if not isinstance(owner_task_id, str):
        return
    owner_task = repository.session.get(CampaignTaskRecord, owner_task_id)
    owner_payload = owner_task.payload if owner_task is not None else {}
    if (
        owner_task is None
        or not isinstance(owner_payload, dict)
        or owner_payload.get("runtime_schema") != "autonomous_research_v1"
    ):
        return

    from app.autonomous_research_runtime import (
        record_autonomous_research_task_awaiting_evidence,
        record_autonomous_research_task_blocked,
        record_autonomous_research_task_completion,
    )

    if owner_task.status == "completed" and resumed.get("status") == "completed":
        pipeline_run_id = _worker_safe_string(payload.get("pipeline_run_id"))
        pipeline_run = repository.get_pipeline_run(pipeline_run_id)
        campaign = repository.get_campaign(owner_task.campaign_id)
        (
            runtime_candidate_hunter_projection,
            _candidate_hunter_projection,
            candidate_hunter_stop_reason,
        ) = (
            _load_runtime_candidate_hunter_output_projection(
                task=owner_task,
                campaign=campaign,
                pipeline_run=pipeline_run,
                repository=repository,
            )
            if campaign is not None and pipeline_run is not None
            else (None, None, "candidate_hunter_projection_missing")
        )
        if (
            candidate_hunter_stop_reason is not None
            or runtime_candidate_hunter_projection is None
        ):
            blocked_task = repository.update_campaign_task_status(
                owner_task.id,
                "blocked",
                output_refs=[],
            )
            if blocked_task is not None:
                record_autonomous_research_task_blocked(
                    task=blocked_task,
                    repository=repository,
                    stop_reason=candidate_hunter_stop_reason
                    or "candidate_hunter_projection_invalid",
                )
            return

        owner_agent_runs = [
            run
            for run in repository.list_campaign_agent_runs(owner_task.campaign_id)
            if run.task_id == owner_task.id
            and run.status == "completed"
            and run.safety_gate_state == "allowed"
        ]
        if len(owner_agent_runs) != 1:
            blocked_task = repository.update_campaign_task_status(
                owner_task.id,
                "blocked",
                output_refs=[],
            )
            if blocked_task is not None:
                record_autonomous_research_task_blocked(
                    task=blocked_task,
                    repository=repository,
                    stop_reason="candidate_hunter_projection_invalid",
                )
            return

        pipeline_run_ref = f"pipeline_run:{pipeline_run_id}"
        projection_ref = f"candidate_hunter_projection:{owner_task.id}"
        agent_output_refs = [
            pipeline_run_ref,
            *runtime_candidate_hunter_projection["candidate_hunter_stage_refs"],
            projection_ref,
        ]
        agent_run = repository.finish_agent_run(
            owner_agent_runs[0].id,
            status="completed",
            output_refs=agent_output_refs,
            safety_gate_state="allowed",
            stop_reason=None,
            payload={
                "artifact_kind": "candidate_hunter_projection",
                "pipeline_run_id": pipeline_run_id,
                "candidate_hunter_status": "completed",
                "candidate_hunter_projection": runtime_candidate_hunter_projection,
                "raw_payload_processed": False,
                "execution_allowed": False,
                "dispatch_allowed": False,
                "validation_allowed": False,
                "candidate_promotion_allowed": False,
                "report_submission_allowed": False,
            },
        )
        if agent_run is None:
            blocked_task = repository.update_campaign_task_status(
                owner_task.id,
                "blocked",
                output_refs=[],
            )
            if blocked_task is not None:
                record_autonomous_research_task_blocked(
                    task=blocked_task,
                    repository=repository,
                    stop_reason="candidate_hunter_projection_invalid",
                )
            return

        owner_output_refs = [
            ref for ref in owner_task.output_refs if isinstance(ref, str)
        ]
        for output_ref in (pipeline_run_ref, projection_ref):
            if output_ref not in owner_output_refs:
                owner_output_refs.append(output_ref)
        if owner_output_refs != owner_task.output_refs:
            owner_task = (
                repository.update_campaign_task_status(
                    owner_task.id,
                    "completed",
                    output_refs=owner_output_refs,
                )
                or owner_task
            )
        record_autonomous_research_task_completion(
            task=owner_task,
            repository=repository,
        )
    elif owner_task.status in {"awaiting_evidence", "needs_evidence"}:
        record_autonomous_research_task_awaiting_evidence(
            task=owner_task,
            repository=repository,
        )
    elif owner_task.status == "blocked":
        record_autonomous_research_task_blocked(
            task=owner_task,
            repository=repository,
            stop_reason=_worker_safe_string(resumed.get("stop_reason"))
            or "candidate_hunter_blocked",
        )


def recover_completed_evidence_task(
    *,
    task: CampaignTaskRecord,
    repository: DatabaseRepository,
) -> dict:
    persisted_task = repository.session.get(CampaignTaskRecord, task.id)
    if (
        persisted_task is None
        or persisted_task.task_type != "candidate_hunter_evidence_inspection"
        or persisted_task.status != "completed"
    ):
        return {
            "status": "blocked",
            "task_id": task.id,
            "stop_reason": "evidence_task_not_recoverable",
        }
    from app.candidate_hunter_evidence import resume_candidate_hunter_after_evidence

    resumed = resume_candidate_hunter_after_evidence(
        repository=repository,
        evidence_task_id=persisted_task.id,
    )
    _record_runtime_evidence_resume(
        evidence_task=persisted_task,
        resumed=resumed,
        repository=repository,
    )
    return resumed


def _block_agent_task(
    *,
    task: CampaignTaskRecord,
    repository: DatabaseRepository,
    stop_reason: str,
) -> dict:
    from app.autonomous_research_runtime import record_autonomous_research_task_blocked

    blocked_execution = _finish_task_execution(
        task=task,
        repository=repository,
        task_status="blocked",
        output_refs=[],
        agent_status="blocked",
        agent_output_refs=[],
        safety_gate_state="blocked",
        stop_reason=stop_reason,
        payload={"raw_payload_processed": False},
    )
    if blocked_execution is None:
        return _execution_lease_lost_result(task=task, repository=repository)
    blocked_task, agent_run = blocked_execution
    record_autonomous_research_task_blocked(
        task=blocked_task,
        repository=repository,
        stop_reason=stop_reason,
    )
    return {
        "status": "blocked",
        "task_id": task.id,
        "agent_run_id": agent_run.id,
        "stop_reason": stop_reason,
    }


def _record_unexpected_worker_failure(
    *,
    task: CampaignTaskRecord,
    repository: DatabaseRepository,
) -> dict:
    if task.task_type == "candidate_hunter_evidence_inspection":
        from app.candidate_hunter_evidence import _block_evidence_task

        result = _block_evidence_task(
            repository=repository,
            task=task,
            stop_reason="worker_failed",
        )
        _record_runtime_evidence_resume(
            evidence_task=task,
            resumed=result,
            repository=repository,
        )
        return result

    from app.autonomous_research_runtime import (
        build_autonomous_research_agent_payload,
        record_autonomous_research_task_failure,
    )

    task_payload = task.payload if isinstance(task.payload, dict) else {}
    source_snapshot_digest = task_payload.get("source_snapshot_digest")
    failure_payload = {"raw_payload_processed": False}
    if (
        task_payload.get("runtime_schema") == _AUTONOMOUS_RESEARCH_RUNTIME_SCHEMA
        and isinstance(source_snapshot_digest, str)
        and _SOURCE_SNAPSHOT_DIGEST_PATTERN.fullmatch(source_snapshot_digest)
    ):
        failure_payload = build_autonomous_research_agent_payload(
            source_snapshot_digest=source_snapshot_digest,
        )

    failed_execution = _finish_task_execution(
        task=task,
        repository=repository,
        task_status="failed",
        output_refs=[],
        agent_status="failed",
        agent_output_refs=[],
        safety_gate_state="blocked",
        stop_reason="worker_failed",
        payload=failure_payload,
    )
    if failed_execution is None:
        return _execution_lease_lost_result(task=task, repository=repository)
    failed_task, agent_run = failed_execution
    record_autonomous_research_task_failure(
        task=failed_task,
        repository=repository,
        stop_reason="worker_failed",
    )
    return {
        "status": "failed",
        "task_id": task.id,
        "agent_run_id": agent_run.id,
        "stop_reason": "worker_failed",
    }


def _runtime_chain_specialist_inputs(
    *,
    task: CampaignTaskRecord,
    campaign: CampaignRecord,
    repository: DatabaseRepository,
) -> tuple[Any, list, str, list[dict[str, str]]] | None:
    task_payload = task.payload if isinstance(task.payload, dict) else {}
    pipeline_run_id = task_payload.get("pipeline_run_id")
    pipeline_run = (
        repository.get_pipeline_run(pipeline_run_id)
        if isinstance(pipeline_run_id, str)
        else None
    )
    pipeline_payload = pipeline_run.payload if pipeline_run is not None else {}
    hypotheses = (
        pipeline_payload.get("hypotheses")
        if isinstance(pipeline_payload, dict)
        else None
    )
    source_snapshot_digest = _worker_safe_string(
        task_payload.get("source_snapshot_digest")
    )
    if (
        pipeline_run is None
        or pipeline_run.asset != campaign.default_asset
        or pipeline_run.scope_status != "in_scope"
        or not isinstance(pipeline_payload, dict)
        or pipeline_payload.get("campaign_id") != campaign.id
        or not isinstance(hypotheses, list)
        or _SOURCE_SNAPSHOT_DIGEST_PATTERN.fullmatch(source_snapshot_digest) is None
    ):
        return None
    return (
        pipeline_run,
        hypotheses,
        source_snapshot_digest,
        _chain_reasoning_hypothesis_seeds(hypotheses),
    )


def _runtime_cross_source_candidate_model_config(
    *,
    task: CampaignTaskRecord,
    campaign: CampaignRecord,
) -> tuple[CandidateModelConfig | None, str | None]:
    task_payload = task.payload if isinstance(task.payload, dict) else {}
    campaign_payload = campaign.payload if isinstance(campaign.payload, dict) else {}
    if "candidate_model" not in campaign_payload:
        return None, "candidate_model_config_missing"
    campaign_config = candidate_model_config_from_value(
        campaign_payload.get("candidate_model")
    )
    if campaign_config is None:
        return None, "candidate_model_config_invalid"
    task_config = candidate_model_config_from_value(task_payload.get("candidate_model"))
    config_digest = candidate_model_config_digest(campaign_config)
    input_refs = task.input_refs if isinstance(task.input_refs, list) else []
    if (
        task_config is None
        or task_config != campaign_config
        or task_payload.get("candidate_model_config_digest") != config_digest
        or input_refs.count(f"candidate_model_config:{config_digest}") != 1
    ):
        return None, "candidate_model_config_changed"
    return campaign_config, None


def _runtime_cross_source_advisory_baseline_candidate(
    hypothesis: object,
) -> tuple[dict, list[dict]] | None:
    if not isinstance(hypothesis, dict):
        return None
    candidate_id = _worker_safe_string(hypothesis.get("hypothesis_id"))
    if _MODEL_ADVISORY_CANDIDATE_ID_PATTERN.fullmatch(candidate_id) is None:
        return None
    source_facts = hypothesis.get("source_facts")
    if not isinstance(source_facts, list):
        return None
    safe_source_facts = [
        item
        for item in source_facts
        if isinstance(item, dict)
        and _model_advisory_text_is_safe(item.get("fact_ref"))
    ]
    route = next(
        (
            {
                "method": _worker_safe_string(item.get("route_method")).upper(),
                "path": _worker_safe_string(item.get("route_path")),
            }
            for item in safe_source_facts
            if _worker_safe_string(item.get("route_method")).upper()
            in {"GET", "POST", "PUT", "PATCH", "DELETE"}
            and _worker_safe_string(item.get("route_path")).startswith("/")
        ),
        None,
    )
    if route is None:
        return None
    source_fact_refs = _model_advisory_fact_refs(
        [item.get("fact_ref") for item in safe_source_facts],
        maximum=20,
    )
    if not source_fact_refs:
        return None
    return (
        {
            "hypothesis_id": candidate_id,
            "vuln_type": _worker_safe_string(hypothesis.get("vuln_type"))
            or "candidate",
            "route": route,
            "priority_score": _candidate_model_priority(
                hypothesis.get("priority_score")
            ),
            "root_cause": _worker_safe_string(hypothesis.get("root_cause")),
            "source_fact_refs": source_fact_refs,
            "evidence_needed": _worker_safe_string_list(
                hypothesis.get("evidence_needed")
            ),
            "false_positive_checks": _worker_safe_string_list(
                hypothesis.get("refutation_questions")
            ),
        },
        safe_source_facts,
    )


def _runtime_cross_source_fact_pack(
    *,
    campaign: CampaignRecord,
    pipeline_run_id: str,
    source_snapshot_digest: str,
    hypotheses: list,
    workspace_inputs: dict | None,
) -> tuple[Any, list[dict]] | None:
    source_files = (
        workspace_inputs.get("code_files")
        if isinstance(workspace_inputs, dict)
        and isinstance(workspace_inputs.get("code_files"), list)
        else []
    )
    facts: list[dict] = [
        {
            "fact_ref": f"scope:campaign:{campaign.id}",
            "fact_type": "scope_context",
            "artifact_kind": "scope",
        },
        {
            "fact_ref": f"policy:campaign:{campaign.id}",
            "fact_type": "policy_context",
            "artifact_kind": "policy",
        },
    ]
    baselines: list[dict] = []
    for hypothesis in hypotheses:
        baseline = _runtime_cross_source_advisory_baseline_candidate(hypothesis)
        if baseline is None:
            continue
        candidate, source_facts = baseline
        baselines.append(candidate)
        facts.extend(source_facts)
    try:
        return (
            build_fact_pack(
                pipeline_run_id=pipeline_run_id,
                scope_status=campaign.scope_status,
                source_files=source_files,
                facts=facts,
                baseline_candidates=baselines,
                source_snapshot_digest=source_snapshot_digest.removeprefix("sha256:"),
            ),
            baselines,
        )
    except (TypeError, ValueError):
        return None


def _runtime_cross_source_advisory_task_has_bound_inputs(
    *,
    task: CampaignTaskRecord,
    campaign: CampaignRecord,
    pipeline_run_id: str,
    source_snapshot_digest: str,
    candidate_model_config: CandidateModelConfig,
) -> bool:
    input_refs = task.input_refs if isinstance(task.input_refs, list) else []
    config_digest = candidate_model_config_digest(candidate_model_config)
    return all(
        input_refs.count(reference) == 1
        for reference in (
            f"campaign:{campaign.id}",
            f"source_snapshot:{source_snapshot_digest}",
            f"pipeline_run:{pipeline_run_id}",
            f"candidate_model_config:{config_digest}",
        )
    )


def _model_advisory_text_is_safe(value: object) -> bool:
    return (
        isinstance(value, str)
        and 1 <= len(value.strip()) <= 500
        and not any(pattern.search(value) for pattern in _MODEL_ADVISORY_TEXT_PATTERNS)
    )


def _model_advisory_texts(value: object, *, maximum: int) -> list[str] | None:
    if not isinstance(value, list) or len(value) > maximum:
        return None
    texts: list[str] = []
    for item in value:
        if not _model_advisory_text_is_safe(item):
            return None
        text = item.strip()
        if text not in texts:
            texts.append(text)
    return texts


def _model_advisory_fact_refs(value: object, *, maximum: int) -> list[str] | None:
    if not isinstance(value, list) or not 1 <= len(value) <= maximum:
        return None
    refs: list[str] = []
    for item in value:
        if not _model_advisory_text_is_safe(item):
            return None
        ref = item.strip()
        if ref not in refs:
            refs.append(ref)
    return refs


def _candidate_model_priority(value: object) -> int:
    return (
        value
        if isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= 100
        else 0
    )


def _model_advisory_difference(values: object, baseline: object) -> list[str] | None:
    safe_values = _model_advisory_texts(values, maximum=8)
    safe_baseline = _model_advisory_texts(baseline, maximum=8)
    if safe_values is None or safe_baseline is None:
        return None
    return [value for value in safe_values if value not in safe_baseline]


def _model_advisory_hash_or_empty(value: object) -> str | None:
    if value == "":
        return ""
    if isinstance(value, str) and _SHA256_PATTERN.fullmatch(value):
        return value
    return None


def _model_advisory_failure_reason(value: object) -> str | None:
    text = _worker_safe_string(value)
    return text if text and re.fullmatch(r"[a-z][a-z0-9_:-]{0,127}", text) else None


def _build_cross_source_llm_advisory_projection(
    *,
    campaign: CampaignRecord,
    pipeline_run_id: str,
    source_snapshot_digest: str,
    hypotheses: list,
    fact_pack: Any,
    baselines: list[dict],
    candidate_model_config: CandidateModelConfig,
    generation: Any,
    llm_run: LLMRunRecord,
) -> dict | None:
    if (
        not isinstance(getattr(generation, "model_status", None), str)
        or generation.model_status not in {"completed", "needs_model_review"}
        or llm_run.provider != candidate_model_config.provider.value
        or llm_run.model != candidate_model_config.model
        or llm_run.purpose != "autonomous_cross_source_advisory"
        or llm_run.mode != "live"
    ):
        return None
    baseline_by_id = {
        item["hypothesis_id"]: item
        for item in baselines
        if isinstance(item.get("hypothesis_id"), str)
    }
    advisories: list[dict] = []
    for candidate in getattr(generation, "working_candidates", []):
        if not isinstance(candidate, dict) or candidate.get("origin") != "baseline+model":
            continue
        candidate_id = _worker_safe_string(candidate.get("candidate_id"))
        baseline = baseline_by_id.get(candidate_id)
        if baseline is None:
            continue
        source_fact_refs = _model_advisory_fact_refs(
            candidate.get("source_fact_refs"),
            maximum=20,
        )
        baseline_refs = _model_advisory_fact_refs(
            baseline.get("source_fact_refs"),
            maximum=20,
        )
        evidence_requirements = _model_advisory_difference(
            candidate.get("evidence_requirements"),
            baseline.get("evidence_needed"),
        )
        refutation_questions = _model_advisory_difference(
            candidate.get("refutation_questions"),
            baseline.get("false_positive_checks"),
        )
        model_priority_score = _candidate_model_priority(
            candidate.get("model_priority_score")
        )
        if (
            source_fact_refs is None
            or baseline_refs is None
            or not set(source_fact_refs).issubset(set(baseline_refs))
            or evidence_requirements is None
            or refutation_questions is None
            or model_priority_score <= 0
        ):
            continue
        advisories.append(
            {
                "candidate_id": candidate_id,
                "source_fact_refs": source_fact_refs,
                "evidence_requirements": evidence_requirements,
                "refutation_questions": refutation_questions,
                "model_priority_score": model_priority_score,
            }
        )
    model_failure_reason = _model_advisory_failure_reason(
        getattr(generation, "model_failure_reason", None)
    )
    if generation.model_status == "completed" and model_failure_reason is not None:
        return None
    if generation.model_status == "needs_model_review":
        advisories = []
    prompt_hash = _model_advisory_hash_or_empty(getattr(generation, "prompt_hash", ""))
    model_request_key = _model_advisory_hash_or_empty(
        getattr(generation, "model_request_key", "")
    )
    model_response_digest = _model_advisory_hash_or_empty(
        getattr(generation, "model_response_digest", "")
    )
    if (
        prompt_hash is None
        or model_request_key is None
        or model_response_digest is None
        or llm_run.prompt_hash != prompt_hash
        or llm_run.error != model_failure_reason
    ):
        return None
    model_response_schema = _worker_safe_string(
        getattr(generation, "model_response_schema", "")
    )
    model_reasoner = _worker_safe_string(getattr(generation, "model_reasoner", ""))
    model_replay_binding = _worker_safe_string(
        getattr(generation, "model_replay_binding", "")
    )
    if (
        model_response_schema not in {"", "cross_source_candidate_model_v1"}
        or model_reasoner != "registry"
        or model_replay_binding != "not_applicable"
        or not _MODEL_ADVISORY_LLM_RUN_ID_PATTERN.fullmatch(llm_run.id)
    ):
        return None
    if generation.model_status == "completed" and (
        not prompt_hash
        or not model_request_key
        or not model_response_digest
        or model_response_schema != "cross_source_candidate_model_v1"
    ):
        return None
    if generation.model_status == "needs_model_review" and (
        model_failure_reason is None
        or not model_request_key
        or model_response_digest
        or model_response_schema
    ):
        return None
    source_hypothesis_refs = [item["hypothesis_id"] for item in baselines]
    return {
        "schema_version": _AUTONOMOUS_CROSS_SOURCE_LLM_ADVISORY_SCHEMA,
        "artifact_kind": "cross_source_llm_advisory_projection",
        "campaign_id": campaign.id,
        "pipeline_run_id": pipeline_run_id,
        "source_snapshot_digest": source_snapshot_digest,
        "source_hypothesis_refs": source_hypothesis_refs,
        "source_hypothesis_digest": _canonical_digest(hypotheses),
        "fact_pack_digest": _canonical_digest(fact_pack.model_dump(mode="json")),
        "candidate_model_config_digest": candidate_model_config_digest(
            candidate_model_config
        ),
        "model_provider": candidate_model_config.provider.value,
        "model_name": candidate_model_config.model,
        "model_mode": "live",
        "llm_run_id": llm_run.id,
        "model_status": generation.model_status,
        "model_failure_reason": model_failure_reason,
        "prompt_hash": prompt_hash,
        "model_latency_ms": generation.model_latency_ms,
        "model_request_key": model_request_key,
        "model_response_digest": model_response_digest,
        "model_response_schema": model_response_schema,
        "model_reasoner": model_reasoner,
        "model_replay_binding": model_replay_binding,
        "model_proposed_count": generation.proposed_count,
        "model_accepted_count": len(generation.accepted_candidates),
        "advisory_count": len(advisories),
        "advisories": advisories,
        "advisory_digest": _canonical_digest(advisories),
        "human_review_required": True,
        "candidate_creation_allowed": False,
        "raw_payload_processed": False,
        "execution_allowed": False,
        "dispatch_allowed": False,
        "validation_allowed": False,
        "candidate_promotion_allowed": False,
        "report_submission_allowed": False,
    }


def _safe_cross_source_llm_advisory_projection(
    value: object,
    *,
    campaign: CampaignRecord,
    pipeline_run_id: str,
    source_snapshot_digest: str,
    hypotheses: list,
    fact_pack: Any,
    baselines: list[dict],
    candidate_model_config: CandidateModelConfig,
    llm_run: LLMRunRecord,
) -> dict | None:
    if not isinstance(value, dict):
        return None
    if (
        llm_run.provider != candidate_model_config.provider.value
        or llm_run.model != candidate_model_config.model
        or llm_run.purpose != "autonomous_cross_source_advisory"
        or llm_run.mode != "live"
        or not _MODEL_ADVISORY_LLM_RUN_ID_PATTERN.fullmatch(llm_run.id)
    ):
        return None
    required_keys = {
        "schema_version",
        "artifact_kind",
        "campaign_id",
        "pipeline_run_id",
        "source_snapshot_digest",
        "source_hypothesis_refs",
        "source_hypothesis_digest",
        "fact_pack_digest",
        "candidate_model_config_digest",
        "model_provider",
        "model_name",
        "model_mode",
        "llm_run_id",
        "model_status",
        "model_failure_reason",
        "prompt_hash",
        "model_latency_ms",
        "model_request_key",
        "model_response_digest",
        "model_response_schema",
        "model_reasoner",
        "model_replay_binding",
        "model_proposed_count",
        "model_accepted_count",
        "advisory_count",
        "advisories",
        "advisory_digest",
        "human_review_required",
        "candidate_creation_allowed",
        "raw_payload_processed",
        "execution_allowed",
        "dispatch_allowed",
        "validation_allowed",
        "candidate_promotion_allowed",
        "report_submission_allowed",
    }
    if set(value) != required_keys:
        return None
    source_hypothesis_refs = [item["hypothesis_id"] for item in baselines]
    model_failure_reason = value.get("model_failure_reason")
    if model_failure_reason is not None:
        model_failure_reason = _model_advisory_failure_reason(model_failure_reason)
        if model_failure_reason is None:
            return None
    advisories = value.get("advisories")
    if (
        value.get("schema_version") != _AUTONOMOUS_CROSS_SOURCE_LLM_ADVISORY_SCHEMA
        or value.get("artifact_kind") != "cross_source_llm_advisory_projection"
        or value.get("campaign_id") != campaign.id
        or value.get("pipeline_run_id") != pipeline_run_id
        or value.get("source_snapshot_digest") != source_snapshot_digest
        or value.get("source_hypothesis_refs") != source_hypothesis_refs
        or value.get("source_hypothesis_digest") != _canonical_digest(hypotheses)
        or value.get("fact_pack_digest") != _canonical_digest(fact_pack.model_dump(mode="json"))
        or value.get("candidate_model_config_digest")
        != candidate_model_config_digest(candidate_model_config)
        or value.get("model_provider") != candidate_model_config.provider.value
        or value.get("model_name") != candidate_model_config.model
        or value.get("model_mode") != "live"
        or value.get("llm_run_id") != llm_run.id
        or value.get("model_status") not in {"completed", "needs_model_review"}
        or value.get("prompt_hash") != llm_run.prompt_hash
        or value.get("model_latency_ms") != llm_run.latency_ms
        or value.get("model_failure_reason") != llm_run.error
        or _model_advisory_hash_or_empty(value.get("prompt_hash")) is None
        or _model_advisory_hash_or_empty(value.get("model_request_key")) is None
        or _model_advisory_hash_or_empty(value.get("model_response_digest")) is None
        or value.get("model_response_schema")
        not in {"", "cross_source_candidate_model_v1"}
        or value.get("model_reasoner") != "registry"
        or value.get("model_replay_binding") != "not_applicable"
        or not isinstance(value.get("model_proposed_count"), int)
        or isinstance(value.get("model_proposed_count"), bool)
        or not 0 <= value.get("model_proposed_count") <= 5
        or not isinstance(value.get("model_accepted_count"), int)
        or isinstance(value.get("model_accepted_count"), bool)
        or not 0 <= value.get("model_accepted_count") <= 5
        or not isinstance(advisories, list)
        or value.get("advisory_count") != len(advisories)
        or len(advisories) > len(baselines)
        or value.get("advisory_digest") != _canonical_digest(advisories)
        or value.get("human_review_required") is not True
        or value.get("candidate_creation_allowed") is not False
        or value.get("raw_payload_processed") is not False
        or any(
            value.get(field) is not False
            for field in (
                "execution_allowed",
                "dispatch_allowed",
                "validation_allowed",
                "candidate_promotion_allowed",
                "report_submission_allowed",
            )
        )
    ):
        return None
    if value["model_status"] == "completed" and model_failure_reason is not None:
        return None
    if value["model_status"] == "needs_model_review" and advisories:
        return None
    if value["model_status"] == "completed" and (
        not value["prompt_hash"]
        or not value["model_request_key"]
        or not value["model_response_digest"]
        or value["model_response_schema"] != "cross_source_candidate_model_v1"
    ):
        return None
    if value["model_status"] == "needs_model_review" and (
        model_failure_reason is None
        or not value["model_request_key"]
        or value["model_response_digest"]
        or value["model_response_schema"]
        or value["model_proposed_count"] != 0
        or value["model_accepted_count"] != 0
    ):
        return None
    baseline_by_id = {
        item["hypothesis_id"]: item
        for item in baselines
        if isinstance(item.get("hypothesis_id"), str)
    }
    seen_candidate_ids: set[str] = set()
    for advisory in advisories:
        if not isinstance(advisory, dict) or set(advisory) != {
            "candidate_id",
            "source_fact_refs",
            "evidence_requirements",
            "refutation_questions",
            "model_priority_score",
        }:
            return None
        candidate_id = advisory.get("candidate_id")
        baseline = baseline_by_id.get(candidate_id)
        source_fact_refs = _model_advisory_fact_refs(
            advisory.get("source_fact_refs"),
            maximum=20,
        )
        baseline_refs = _model_advisory_fact_refs(
            baseline.get("source_fact_refs") if baseline is not None else None,
            maximum=20,
        )
        if (
            not isinstance(candidate_id, str)
            or _MODEL_ADVISORY_CANDIDATE_ID_PATTERN.fullmatch(candidate_id) is None
            or candidate_id in seen_candidate_ids
            or source_fact_refs is None
            or baseline_refs is None
            or not set(source_fact_refs).issubset(set(baseline_refs))
            or _model_advisory_texts(
                advisory.get("evidence_requirements"),
                maximum=8,
            ) is None
            or _model_advisory_texts(
                advisory.get("refutation_questions"),
                maximum=8,
            ) is None
            or not 1 <= _candidate_model_priority(advisory.get("model_priority_score"))
        ):
            return None
        seen_candidate_ids.add(candidate_id)
    return dict(value)


def _run_cross_source_llm_advisory_task(
    *,
    task: CampaignTaskRecord,
    campaign: CampaignRecord,
    repository: DatabaseRepository,
    workspace_inputs: dict | None,
) -> dict:
    from app.autonomous_research_runtime import record_autonomous_research_task_completion

    candidate_model_config, config_stop_reason = (
        _runtime_cross_source_candidate_model_config(task=task, campaign=campaign)
    )
    if candidate_model_config is None or config_stop_reason is not None:
        return _block_agent_task(
            task=task,
            repository=repository,
            stop_reason=config_stop_reason or "candidate_model_config_missing",
        )
    inputs = _runtime_chain_specialist_inputs(
        task=task,
        campaign=campaign,
        repository=repository,
    )
    if inputs is None:
        return _block_agent_task(
            task=task,
            repository=repository,
            stop_reason="candidate_model_advisory_input_missing",
        )
    pipeline_run, hypotheses, source_snapshot_digest, _ = inputs
    if not _runtime_cross_source_advisory_task_has_bound_inputs(
        task=task,
        campaign=campaign,
        pipeline_run_id=pipeline_run.id,
        source_snapshot_digest=source_snapshot_digest,
        candidate_model_config=candidate_model_config,
    ):
        return _block_agent_task(
            task=task,
            repository=repository,
            stop_reason="candidate_model_advisory_input_missing",
        )
    fact_pack_inputs = _runtime_cross_source_fact_pack(
        campaign=campaign,
        pipeline_run_id=pipeline_run.id,
        source_snapshot_digest=source_snapshot_digest,
        hypotheses=hypotheses,
        workspace_inputs=workspace_inputs,
    )
    if fact_pack_inputs is None:
        return _block_agent_task(
            task=task,
            repository=repository,
            stop_reason="candidate_model_advisory_input_missing",
        )
    fact_pack, baselines = fact_pack_inputs
    projection_ref = f"cross_source_llm_advisory_projection:{task.id}"
    stage_id = _runtime_specialist_projection_stage_id(
        task_id=task.id,
        stage_key="autonomous_cross_source_llm_advisory",
    )
    stage = repository.get_pipeline_stage(stage_id)
    projection: dict | None = None
    if stage is not None:
        llm_run_id = (
            stage.payload.get("llm_run_id")
            if isinstance(stage.payload, dict)
            else None
        )
        llm_run = (
            repository.session.get(LLMRunRecord, llm_run_id)
            if isinstance(llm_run_id, str)
            else None
        )
        projection = (
            _safe_cross_source_llm_advisory_projection(
                stage.payload,
                campaign=campaign,
                pipeline_run_id=pipeline_run.id,
                source_snapshot_digest=source_snapshot_digest,
                hypotheses=hypotheses,
                fact_pack=fact_pack,
                baselines=baselines,
                candidate_model_config=candidate_model_config,
                llm_run=llm_run,
            )
            if llm_run is not None
            else None
        )
        if (
            projection is None
            or stage.status != "completed"
            or stage.safety_gate_state != "safe"
            or projection_ref not in stage.output_refs
        ):
            return _block_agent_task(
                task=task,
                repository=repository,
                stop_reason="candidate_model_advisory_projection_invalid",
            )
    else:
        generation = asyncio.run(
            generate_cross_source_candidates(
                fact_pack=fact_pack,
                baseline_candidates=baselines,
                model_config=candidate_model_config,
                reasoner=RegistryCandidateReasoner(build_default_registry()),
            )
        )
        audit_safety_notes = [
            "prompt_hash_only",
            "no_prompt_storage",
            "provider_response_not_fact",
            "model_proposals_unverified",
            "existing_hypotheses_only",
            "human_approval_still_required",
        ]
        if generation.model_failure_reason:
            audit_safety_notes.append("model_failure_recorded")
        llm_run = repository.save_llm_run(
            provider=candidate_model_config.provider.value,
            model=candidate_model_config.model,
            purpose="autonomous_cross_source_advisory",
            prompt_hash=generation.prompt_hash,
            mode="live",
            latency_ms=generation.model_latency_ms,
            error=generation.model_failure_reason,
            safety_notes=audit_safety_notes,
        )
        projection = _build_cross_source_llm_advisory_projection(
            campaign=campaign,
            pipeline_run_id=pipeline_run.id,
            source_snapshot_digest=source_snapshot_digest,
            hypotheses=hypotheses,
            fact_pack=fact_pack,
            baselines=baselines,
            candidate_model_config=candidate_model_config,
            generation=generation,
            llm_run=llm_run,
        )
        if projection is None:
            return _block_agent_task(
                task=task,
                repository=repository,
                stop_reason="candidate_model_advisory_projection_invalid",
            )
        try:
            stage = repository.save_pipeline_stage(
                pipeline_run_id=pipeline_run.id,
                campaign_id=campaign.id,
                task_id=task.id,
                stage_id=stage_id,
                stage_key="autonomous_cross_source_llm_advisory",
                stage_order=0,
                status="completed",
                input_refs=task.input_refs,
                output_refs=[f"llm_run:{llm_run.id}", projection_ref],
                safety_gate_state="safe",
                stop_reason=None,
                payload=projection,
                strict_idempotency=True,
            )
        except ValueError:
            return _block_agent_task(
                task=task,
                repository=repository,
                stop_reason="candidate_model_advisory_projection_invalid",
            )
    assert stage is not None
    llm_run_id = projection.get("llm_run_id") if isinstance(projection, dict) else None
    if not isinstance(llm_run_id, str):
        return _block_agent_task(
            task=task,
            repository=repository,
            stop_reason="candidate_model_advisory_projection_invalid",
        )
    output_refs = [
        f"pipeline_run:{pipeline_run.id}",
        f"pipeline_stage:{stage.id}",
        f"llm_run:{llm_run_id}",
        projection_ref,
    ]
    completed_execution = _finish_task_execution(
        task=task,
        repository=repository,
        task_status="completed",
        output_refs=output_refs,
        agent_status="completed",
        agent_output_refs=output_refs,
        safety_gate_state="allowed",
        stop_reason=None,
        payload=projection,
    )
    if completed_execution is None:
        return _execution_lease_lost_result(task=task, repository=repository)
    completed_task, agent_run = completed_execution
    record_autonomous_research_task_completion(
        task=completed_task,
        repository=repository,
    )
    return {
        "status": "completed",
        "task_id": task.id,
        "agent_run_id": agent_run.id,
        "stop_reason": None,
    }


def _runtime_cross_source_llm_advisory_projection_for_refutation(
    *,
    task: CampaignTaskRecord,
    campaign: CampaignRecord,
    pipeline_run: Any,
    hypotheses: list,
    workspace_inputs: dict | None,
    repository: DatabaseRepository,
) -> tuple[dict | None, str | None]:
    campaign_payload = campaign.payload if isinstance(campaign.payload, dict) else {}
    if "candidate_model" not in campaign_payload:
        return None, None
    candidate_model_config = candidate_model_config_from_value(
        campaign_payload.get("candidate_model")
    )
    if candidate_model_config is None:
        return None, "candidate_model_config_invalid"
    task_payload = task.payload if isinstance(task.payload, dict) else {}
    source_snapshot_digest = _worker_safe_string(
        task_payload.get("source_snapshot_digest")
    )
    if _SOURCE_SNAPSHOT_DIGEST_PATTERN.fullmatch(source_snapshot_digest) is None:
        return None, "candidate_model_advisory_projection_missing"
    fact_pack_inputs = _runtime_cross_source_fact_pack(
        campaign=campaign,
        pipeline_run_id=pipeline_run.id,
        source_snapshot_digest=source_snapshot_digest,
        hypotheses=hypotheses,
        workspace_inputs=workspace_inputs,
    )
    if fact_pack_inputs is None:
        return None, "candidate_model_advisory_projection_missing"
    fact_pack, baselines = fact_pack_inputs
    advisory_tasks = [
        candidate
        for candidate in repository.list_campaign_tasks(campaign.id)
        if candidate.task_type == "cross_source_llm_advisory"
        and candidate.status == "completed"
        and isinstance(candidate.payload, dict)
        and candidate.payload.get("runtime_schema")
        == _AUTONOMOUS_RESEARCH_RUNTIME_SCHEMA
        and candidate.payload.get("source_snapshot_digest") == source_snapshot_digest
        and candidate.payload.get("pipeline_run_id") == pipeline_run.id
    ]
    if len(advisory_tasks) != 1:
        return None, "candidate_model_advisory_projection_missing"
    advisory_task = advisory_tasks[0]
    task_config, task_config_stop_reason = _runtime_cross_source_candidate_model_config(
        task=advisory_task,
        campaign=campaign,
    )
    if task_config is None or task_config_stop_reason is not None:
        return None, task_config_stop_reason or "candidate_model_config_missing"
    if not _runtime_cross_source_advisory_task_has_bound_inputs(
        task=advisory_task,
        campaign=campaign,
        pipeline_run_id=pipeline_run.id,
        source_snapshot_digest=source_snapshot_digest,
        candidate_model_config=candidate_model_config,
    ):
        return None, "candidate_model_advisory_projection_missing"
    projection_ref = f"cross_source_llm_advisory_projection:{advisory_task.id}"
    task_input_refs = task.input_refs if isinstance(task.input_refs, list) else []
    bound_projection_refs = [
        reference
        for reference in task_input_refs
        if isinstance(reference, str)
        and reference.startswith("cross_source_llm_advisory_projection:")
    ]
    if bound_projection_refs != [projection_ref]:
        return None, "candidate_model_advisory_projection_missing"
    if projection_ref not in advisory_task.output_refs:
        return None, "candidate_model_advisory_projection_missing"
    specialist_stages = [
        stage
        for stage in repository.list_pipeline_stages_for_run(pipeline_run.id)
        if stage.task_id == advisory_task.id
        and stage.stage_key == "autonomous_cross_source_llm_advisory"
        and stage.status == "completed"
        and stage.safety_gate_state == "safe"
        and projection_ref in stage.output_refs
    ]
    if len(specialist_stages) != 1:
        return None, "candidate_model_advisory_projection_missing"
    specialist_stage = specialist_stages[0]
    llm_run_id = (
        specialist_stage.payload.get("llm_run_id")
        if isinstance(specialist_stage.payload, dict)
        else None
    )
    llm_run = (
        repository.session.get(LLMRunRecord, llm_run_id)
        if isinstance(llm_run_id, str)
        else None
    )
    projection = (
        _safe_cross_source_llm_advisory_projection(
            specialist_stage.payload,
            campaign=campaign,
            pipeline_run_id=pipeline_run.id,
            source_snapshot_digest=source_snapshot_digest,
            hypotheses=hypotheses,
            fact_pack=fact_pack,
            baselines=baselines,
            candidate_model_config=candidate_model_config,
            llm_run=llm_run,
        )
        if llm_run is not None
        else None
    )
    if projection is None:
        return None, "candidate_model_advisory_projection_invalid"
    agent_runs = [
        run
        for run in repository.list_campaign_agent_runs(campaign.id)
        if run.task_id == advisory_task.id
        and run.status == "completed"
        and run.safety_gate_state == "allowed"
        and projection_ref in run.output_refs
        and run.payload == projection
    ]
    runtime_stages = [
        stage
        for stage in repository.list_campaign_pipeline_stages(campaign.id)
        if stage.task_id == advisory_task.id
        and stage.stage_key == "autonomous_research:cross_source_llm_advisory"
        and stage.status == "completed"
        and stage.safety_gate_state == "allowed"
        and projection_ref in stage.output_refs
        and isinstance(stage.payload, dict)
        and stage.payload.get("runtime_schema")
        == _AUTONOMOUS_RESEARCH_RUNTIME_SCHEMA
        and stage.payload.get("source_snapshot_digest") == source_snapshot_digest
    ]
    if len(agent_runs) != 1 or len(runtime_stages) != 1:
        return None, "candidate_model_advisory_projection_missing"
    return projection, None


def _merge_cross_source_llm_advisory_strings(
    current: object,
    additions: object,
) -> list[str]:
    values = _worker_safe_string_list(current)
    for item in (additions if isinstance(additions, list) else []):
        if not _model_advisory_text_is_safe(item):
            continue
        text = item.strip()
        if text not in values:
            values.append(text)
        if len(values) >= 8:
            break
    return values[:8]


def _apply_cross_source_llm_advisory(
    *,
    hypotheses: list,
    projection: dict | None,
) -> list[dict]:
    if projection is None:
        return [item for item in hypotheses if isinstance(item, dict)]
    advisories = projection.get("advisories")
    if not isinstance(advisories, list):
        return [item for item in hypotheses if isinstance(item, dict)]
    advisory_by_candidate = {
        item.get("candidate_id"): item
        for item in advisories
        if isinstance(item, dict) and isinstance(item.get("candidate_id"), str)
    }
    enriched: list[dict] = []
    for hypothesis in hypotheses:
        if not isinstance(hypothesis, dict):
            continue
        candidate = dict(hypothesis)
        advisory = advisory_by_candidate.get(candidate.get("hypothesis_id"))
        if advisory is None:
            enriched.append(candidate)
            continue
        baseline = _runtime_cross_source_advisory_baseline_candidate(candidate)
        baseline_candidate = baseline[0] if baseline is not None else None
        advisory_refs = _model_advisory_fact_refs(
            advisory.get("source_fact_refs"),
            maximum=20,
        )
        baseline_refs = _model_advisory_fact_refs(
            baseline_candidate.get("source_fact_refs")
            if isinstance(baseline_candidate, dict)
            else None,
            maximum=20,
        )
        priority = _candidate_model_priority(advisory.get("model_priority_score"))
        if (
            advisory_refs is None
            or baseline_refs is None
            or not set(advisory_refs).issubset(set(baseline_refs))
            or priority <= 0
        ):
            enriched.append(candidate)
            continue
        candidate["evidence_needed"] = _merge_cross_source_llm_advisory_strings(
            candidate.get("evidence_needed"),
            advisory.get("evidence_requirements"),
        )
        candidate["refutation_questions"] = _merge_cross_source_llm_advisory_strings(
            candidate.get("refutation_questions"),
            advisory.get("refutation_questions"),
        )
        candidate["model_priority_score"] = max(
            _candidate_model_priority(candidate.get("model_priority_score")),
            priority,
        )
        enriched.append(candidate)
    return enriched


def _runtime_specialist_projection_stage_id(*, task_id: str, stage_key: str) -> str:
    identity = f"{task_id}:{stage_key}"
    return "pipeline_stage_specialist_" + sha256(identity.encode("utf-8")).hexdigest()


def _run_exploit_chain_reasoning_task(
    *,
    task: CampaignTaskRecord,
    campaign: CampaignRecord,
    repository: DatabaseRepository,
) -> dict:
    from app.autonomous_research_runtime import record_autonomous_research_task_completion
    from app.vuln_chain_builder import build_vuln_chain_builder_plan

    inputs = _runtime_chain_specialist_inputs(
        task=task,
        campaign=campaign,
        repository=repository,
    )
    if inputs is None:
        return _block_agent_task(
            task=task,
            repository=repository,
            stop_reason="exploit_chain_input_missing",
        )
    pipeline_run, _, source_snapshot_digest, source_hypotheses = inputs
    try:
        plan_payload = build_vuln_chain_builder_plan(
            package_id=f"pipeline_run:{pipeline_run.id}",
            source_hypotheses=source_hypotheses,
            human_allow_export_write=False,
        ).to_dict()
    except (TypeError, ValueError):
        return _block_agent_task(
            task=task,
            repository=repository,
            stop_reason="exploit_chain_projection_invalid",
        )
    projection = _build_exploit_chain_projection(
        plan_payload=plan_payload,
        pipeline_run_id=pipeline_run.id,
        source_snapshot_digest=source_snapshot_digest,
        source_hypotheses=source_hypotheses,
    )
    if projection is None:
        return _block_agent_task(
            task=task,
            repository=repository,
            stop_reason="exploit_chain_projection_invalid",
        )
    projection_ref = f"exploit_chain_projection:{task.id}"
    chain_stage = repository.save_pipeline_stage(
        pipeline_run_id=pipeline_run.id,
        campaign_id=campaign.id,
        task_id=task.id,
        stage_id=_runtime_specialist_projection_stage_id(
            task_id=task.id,
            stage_key="autonomous_exploit_chain_reasoning",
        ),
        stage_key="autonomous_exploit_chain_reasoning",
        stage_order=0,
        status="completed",
        input_refs=[
            f"pipeline_run:{pipeline_run.id}",
            f"source_snapshot:{source_snapshot_digest}",
        ],
        output_refs=[projection_ref],
        safety_gate_state="safe",
        stop_reason=None,
        payload=projection,
    )
    output_refs = [
        f"pipeline_run:{pipeline_run.id}",
        f"pipeline_stage:{chain_stage.id}",
        projection_ref,
    ]
    completed_execution = _finish_task_execution(
        task=task,
        repository=repository,
        task_status="completed",
        output_refs=output_refs,
        agent_status="completed",
        agent_output_refs=output_refs,
        safety_gate_state="allowed",
        stop_reason=None,
        payload=projection,
    )
    if completed_execution is None:
        return _execution_lease_lost_result(task=task, repository=repository)
    completed_task, agent_run = completed_execution
    record_autonomous_research_task_completion(
        task=completed_task,
        repository=repository,
    )
    return {
        "status": "completed",
        "task_id": task.id,
        "agent_run_id": agent_run.id,
        "stop_reason": None,
    }


def _run_variant_analysis_task(
    *,
    task: CampaignTaskRecord,
    campaign: CampaignRecord,
    repository: DatabaseRepository,
) -> dict:
    from app.autonomous_research_runtime import record_autonomous_research_task_completion
    from app.variant_analysis import build_variant_analysis_plan

    inputs = _runtime_chain_specialist_inputs(
        task=task,
        campaign=campaign,
        repository=repository,
    )
    if inputs is None:
        return _block_agent_task(
            task=task,
            repository=repository,
            stop_reason="exploit_chain_projection_missing",
        )
    pipeline_run, hypotheses, source_snapshot_digest, source_hypotheses = inputs
    (
        exploit_chain_projection,
        chain_task,
        _,
        chain_stop_reason,
    ) = _runtime_exploit_chain_projection_with_provenance(
        task=task,
        campaign=campaign,
        pipeline_run=pipeline_run,
        hypotheses=hypotheses,
        repository=repository,
    )
    if (
        chain_stop_reason is not None
        or exploit_chain_projection is None
        or chain_task is None
    ):
        return _block_agent_task(
            task=task,
            repository=repository,
            stop_reason=chain_stop_reason or "exploit_chain_projection_missing",
        )
    try:
        plan_payload = build_variant_analysis_plan(
            package_id=f"pipeline_run:{pipeline_run.id}",
            source_hypotheses=source_hypotheses,
            human_allow_export_write=False,
        ).to_dict()
    except (TypeError, ValueError):
        return _block_agent_task(
            task=task,
            repository=repository,
            stop_reason="variant_analysis_projection_invalid",
        )
    projection = _build_variant_analysis_projection(
        plan_payload=plan_payload,
        pipeline_run_id=pipeline_run.id,
        source_snapshot_digest=source_snapshot_digest,
        source_hypotheses=source_hypotheses,
        exploit_chain_projection=exploit_chain_projection,
    )
    if projection is None:
        return _block_agent_task(
            task=task,
            repository=repository,
            stop_reason="variant_analysis_projection_invalid",
        )

    projection_ref = f"variant_analysis_projection:{task.id}"
    stage = repository.save_pipeline_stage(
        pipeline_run_id=pipeline_run.id,
        campaign_id=campaign.id,
        task_id=task.id,
        stage_id=_runtime_specialist_projection_stage_id(
            task_id=task.id,
            stage_key="autonomous_variant_analysis",
        ),
        stage_key="autonomous_variant_analysis",
        stage_order=1,
        status="completed",
        input_refs=[
            f"pipeline_run:{pipeline_run.id}",
            f"source_snapshot:{source_snapshot_digest}",
            f"exploit_chain_projection:{chain_task.id}",
        ],
        output_refs=[projection_ref],
        safety_gate_state="safe",
        stop_reason=None,
        payload=projection,
    )
    output_refs = [
        f"pipeline_run:{pipeline_run.id}",
        f"pipeline_stage:{stage.id}",
        projection_ref,
    ]
    completed_execution = _finish_task_execution(
        task=task,
        repository=repository,
        task_status="completed",
        output_refs=output_refs,
        agent_status="completed",
        agent_output_refs=output_refs,
        safety_gate_state="allowed",
        stop_reason=None,
        payload=projection,
    )
    if completed_execution is None:
        return _execution_lease_lost_result(task=task, repository=repository)
    completed_task, agent_run = completed_execution
    record_autonomous_research_task_completion(
        task=completed_task,
        repository=repository,
    )
    return {
        "status": "completed",
        "task_id": task.id,
        "agent_run_id": agent_run.id,
        "stop_reason": None,
    }


def _deep_code_reasoning_chain_input(exploit_chain_projection: dict) -> dict:
    chains = exploit_chain_projection.get("chains")
    if not isinstance(chains, list):
        return {"chains": []}
    return {
        "chains": [
            {
                "chain_id": _worker_safe_string(chain.get("chain_ref")).removeprefix(
                    "exploit_chain:"
                ),
                "source_hypothesis_id": _worker_safe_string(
                    chain.get("source_hypothesis_ref")
                ),
                "family": _worker_safe_string(chain.get("family")),
                "vuln_type": _worker_safe_string(chain.get("vuln_type")),
            }
            for chain in chains
            if isinstance(chain, dict)
        ]
    }


def _run_deep_code_reasoning_task(
    *,
    task: CampaignTaskRecord,
    campaign: CampaignRecord,
    repository: DatabaseRepository,
) -> dict:
    from app.autonomous_research_runtime import record_autonomous_research_task_completion
    from app.deep_code_reasoning import build_deep_code_reasoning_plan

    inputs = _runtime_chain_specialist_inputs(
        task=task,
        campaign=campaign,
        repository=repository,
    )
    if inputs is None:
        return _block_agent_task(
            task=task,
            repository=repository,
            stop_reason="variant_analysis_projection_missing",
        )
    pipeline_run, hypotheses, source_snapshot_digest, source_hypotheses = inputs
    (
        exploit_chain_projection,
        chain_task,
        _,
        chain_stop_reason,
    ) = _runtime_exploit_chain_projection_with_provenance(
        task=task,
        campaign=campaign,
        pipeline_run=pipeline_run,
        hypotheses=hypotheses,
        repository=repository,
    )
    if (
        chain_stop_reason is not None
        or exploit_chain_projection is None
        or chain_task is None
    ):
        return _block_agent_task(
            task=task,
            repository=repository,
            stop_reason=chain_stop_reason or "exploit_chain_projection_missing",
        )
    variant_analysis_projection, variant_stage, variant_stop_reason = (
        _runtime_variant_analysis_projection_for_report(
            task=task,
            campaign=campaign,
            pipeline_run=pipeline_run,
            repository=repository,
        )
    )
    if (
        variant_stop_reason is not None
        or variant_analysis_projection is None
        or variant_stage is None
    ):
        return _block_agent_task(
            task=task,
            repository=repository,
            stop_reason=variant_stop_reason or "variant_analysis_projection_missing",
        )
    try:
        plan_payload = build_deep_code_reasoning_plan(
            package_id=f"pipeline_run:{pipeline_run.id}",
            source_hypotheses=source_hypotheses,
            vuln_chain_builder=_deep_code_reasoning_chain_input(
                exploit_chain_projection
            ),
            variant_analysis=variant_analysis_projection.get("variant_analysis"),
            human_allow_export_write=False,
        ).to_dict()
    except (TypeError, ValueError):
        return _block_agent_task(
            task=task,
            repository=repository,
            stop_reason="deep_code_reasoning_projection_invalid",
        )
    projection = _build_deep_code_reasoning_projection(
        plan_payload=plan_payload,
        pipeline_run_id=pipeline_run.id,
        source_snapshot_digest=source_snapshot_digest,
        source_hypotheses=source_hypotheses,
        exploit_chain_projection=exploit_chain_projection,
        variant_analysis_projection=variant_analysis_projection,
    )
    if projection is None:
        return _block_agent_task(
            task=task,
            repository=repository,
            stop_reason="deep_code_reasoning_projection_invalid",
        )

    projection_ref = f"deep_code_reasoning_projection:{task.id}"
    stage = repository.save_pipeline_stage(
        pipeline_run_id=pipeline_run.id,
        campaign_id=campaign.id,
        task_id=task.id,
        stage_id=_runtime_specialist_projection_stage_id(
            task_id=task.id,
            stage_key="autonomous_deep_code_reasoning",
        ),
        stage_key="autonomous_deep_code_reasoning",
        stage_order=2,
        status="completed",
        input_refs=[
            f"pipeline_run:{pipeline_run.id}",
            f"source_snapshot:{source_snapshot_digest}",
            f"exploit_chain_projection:{chain_task.id}",
            f"variant_analysis_projection:{variant_stage.task_id}",
        ],
        output_refs=[projection_ref],
        safety_gate_state="safe",
        stop_reason=None,
        payload=projection,
    )
    output_refs = [
        f"pipeline_run:{pipeline_run.id}",
        f"pipeline_stage:{stage.id}",
        projection_ref,
    ]
    completed_execution = _finish_task_execution(
        task=task,
        repository=repository,
        task_status="completed",
        output_refs=output_refs,
        agent_status="completed",
        agent_output_refs=output_refs,
        safety_gate_state="allowed",
        stop_reason=None,
        payload=projection,
    )
    if completed_execution is None:
        return _execution_lease_lost_result(task=task, repository=repository)
    completed_task, agent_run = completed_execution
    record_autonomous_research_task_completion(
        task=completed_task,
        repository=repository,
    )
    return {
        "status": "completed",
        "task_id": task.id,
        "agent_run_id": agent_run.id,
        "stop_reason": None,
    }


def _run_candidate_refutation_task(
    *,
    task: CampaignTaskRecord,
    campaign: CampaignRecord,
    repository: DatabaseRepository,
    workspace_inputs: dict | None,
) -> dict:
    from app.candidate_hunter_loop import (
        build_candidate_hunter_observations,
        run_candidate_hunter_loop,
    )
    from app.cross_source_candidate_generator import (
        registered_local_advisory_fact_references,
        registered_local_dependency_advisory_facts,
    )
    from app.autonomous_research_runtime import (
        record_autonomous_research_task_awaiting_evidence,
        record_autonomous_research_task_completion,
    )

    task_payload = task.payload if isinstance(task.payload, dict) else {}
    pipeline_run_id = task_payload.get("pipeline_run_id")
    pipeline_run = (
        repository.get_pipeline_run(pipeline_run_id)
        if isinstance(pipeline_run_id, str)
        else None
    )
    pipeline_payload = pipeline_run.payload if pipeline_run is not None else {}
    hypotheses = pipeline_payload.get("hypotheses") if isinstance(pipeline_payload, dict) else None
    if (
        pipeline_run is None
        or pipeline_run.asset != campaign.default_asset
        or pipeline_run.scope_status != "in_scope"
        or not isinstance(pipeline_payload, dict)
        or pipeline_payload.get("campaign_id") != campaign.id
        or not isinstance(hypotheses, list)
    ):
        return _block_agent_task(
            task=task,
            repository=repository,
            stop_reason="candidate_hunter_input_missing",
        )

    chain_projection, chain_stop_reason = _runtime_exploit_chain_projection(
        task=task,
        campaign=campaign,
        pipeline_run=pipeline_run,
        hypotheses=hypotheses,
        repository=repository,
    )
    if chain_stop_reason is not None:
        return _block_agent_task(
            task=task,
            repository=repository,
            stop_reason=chain_stop_reason,
        )

    if task_payload.get("runtime_schema") == _AUTONOMOUS_RESEARCH_RUNTIME_SCHEMA:
        variant_projection, _, variant_stop_reason = (
            _runtime_variant_analysis_projection_for_report(
                task=task,
                campaign=campaign,
                pipeline_run=pipeline_run,
                repository=repository,
            )
        )
        deep_projection, _, deep_stop_reason = (
            _runtime_deep_code_reasoning_projection_for_report(
                task=task,
                campaign=campaign,
                pipeline_run=pipeline_run,
                repository=repository,
            )
        )
        if variant_stop_reason is not None or variant_projection is None:
            return _block_agent_task(
                task=task,
                repository=repository,
                stop_reason=variant_stop_reason or "variant_analysis_projection_missing",
            )
        if deep_stop_reason is not None or deep_projection is None:
            return _block_agent_task(
                task=task,
                repository=repository,
                stop_reason=deep_stop_reason or "deep_code_reasoning_projection_missing",
            )
    model_advisory_projection: dict | None = None
    if task_payload.get("runtime_schema") == _AUTONOMOUS_RESEARCH_RUNTIME_SCHEMA:
        model_advisory_projection, model_advisory_stop_reason = (
            _runtime_cross_source_llm_advisory_projection_for_refutation(
                task=task,
                campaign=campaign,
                pipeline_run=pipeline_run,
                hypotheses=hypotheses,
                workspace_inputs=workspace_inputs,
                repository=repository,
            )
        )
        if model_advisory_stop_reason is not None:
            return _block_agent_task(
                task=task,
                repository=repository,
                stop_reason=model_advisory_stop_reason,
            )
    candidates = _apply_cross_source_llm_advisory(
        hypotheses=hypotheses,
        projection=model_advisory_projection,
    )
    source_snapshot_digest = _worker_safe_string(
        task_payload.get("source_snapshot_digest")
    )
    codebase_facts = repository.list_campaign_codebase_facts(campaign.id)
    if task_payload.get("runtime_schema") == _AUTONOMOUS_RESEARCH_RUNTIME_SCHEMA:
        target_model_projection, target_model_stop_reason = (
            _runtime_target_model_projection(
                task=task,
                campaign=campaign,
                repository=repository,
            )
        )
        codebase_facts = (
            _target_model_projected_codebase_facts(
                projection=target_model_projection,
                codebase_facts=codebase_facts,
            )
            if target_model_stop_reason is None and target_model_projection is not None
            else []
        )
    static_advisory_facts = [
        fact.model_dump(mode="json")
        for fact in registered_local_advisory_fact_references(
            artifacts=repository.list_artifacts(
                program_id=campaign.program_id,
                asset=campaign.default_asset,
            ),
            campaign_id=campaign.id,
            source_snapshot_digest=source_snapshot_digest,
            artifact_ids=_candidate_refutation_advisory_artifact_ids(task),
        )
    ]
    dependency_advisory_facts = registered_local_dependency_advisory_facts(
        artifacts=repository.list_artifacts(
            program_id=campaign.program_id,
            asset=campaign.default_asset,
        ),
        campaign_id=campaign.id,
        source_snapshot_digest=source_snapshot_digest,
        artifact_ids=_candidate_refutation_advisory_artifact_ids(task),
    )
    observations = build_candidate_hunter_observations(
        pipeline_run_id=pipeline_run.id,
        candidates=candidates,
        code_files=[],
        supplemental_code_facts=_candidate_hunter_persisted_code_facts(
            codebase_facts
        ),
        static_advisory_facts=static_advisory_facts,
        dependency_advisory_facts=dependency_advisory_facts,
        surface_facts=[],
        context_facts=[
            {"artifact_kind": "scope", "fact_type": "scope_context"},
            {"artifact_kind": "policy", "fact_type": "policy_context"},
            _exploit_chain_context_fact(chain_projection),
        ],
    )
    evidence_context = None
    if workspace_inputs is not None:
        evidence_context = {
            "source_snapshot_digest": workspace_inputs["source_snapshot_digest"],
            "source_manifest": workspace_inputs["source_manifest"],
            "saved_scope_guard": {
                "scope_status": "in_scope",
                "authorized_local_root": workspace_inputs["authorized_local_root"],
            },
        }
    loop_result = run_candidate_hunter_loop(
        repository=repository,
        record=pipeline_run,
        policy_text=campaign.policy_text_hash,
        candidates=candidates,
        observations=observations,
        evidence_context=evidence_context,
    )
    loop_status = loop_result.get("status")
    if loop_status in {"blocked", "scope_not_in_scope"}:
        return _block_agent_task(
            task=task,
            repository=repository,
            stop_reason=_worker_safe_string(loop_result.get("stop_reason"))
            or "candidate_hunter_blocked",
        )

    stage_ids = loop_result.get("stage_refs", [])
    safe_stage_ids = [
        stage_id
        for stage_id in stage_ids
        if isinstance(stage_id, str) and stage_id
    ] if isinstance(stage_ids, list) else []
    output_refs = [
        f"pipeline_run:{pipeline_run.id}",
        *(f"pipeline_stage:{stage_id}" for stage_id in safe_stage_ids),
    ]
    runtime_candidate_hunter_projection: dict | None = None
    if loop_status == "completed":
        (
            runtime_candidate_hunter_projection,
            _candidate_hunter_projection,
            candidate_hunter_stop_reason,
        ) = _load_runtime_candidate_hunter_output_projection(
            task=task,
            campaign=campaign,
            pipeline_run=pipeline_run,
            repository=repository,
        )
        if candidate_hunter_stop_reason is not None:
            return _block_agent_task(
                task=task,
                repository=repository,
                stop_reason=candidate_hunter_stop_reason,
            )
        if runtime_candidate_hunter_projection is not None:
            output_refs.append(f"candidate_hunter_projection:{task.id}")
    agent_run_payload = {
        "artifact_kind": "candidate_hunter_projection",
        "pipeline_run_id": pipeline_run.id,
        "candidate_hunter_status": _worker_safe_string(loop_status),
        "raw_payload_processed": False,
        "execution_allowed": False,
        "dispatch_allowed": False,
        "validation_allowed": False,
        "candidate_promotion_allowed": False,
        "report_submission_allowed": False,
    }
    if runtime_candidate_hunter_projection is not None:
        agent_run_payload["candidate_hunter_projection"] = (
            runtime_candidate_hunter_projection
        )
    if loop_status == "completed":
        completed_execution = _finish_task_execution(
            task=task,
            repository=repository,
            task_status="completed",
            output_refs=output_refs,
            agent_status="completed",
            agent_output_refs=output_refs,
            safety_gate_state="allowed",
            stop_reason=None,
            payload=agent_run_payload,
        )
        if completed_execution is None:
            return _execution_lease_lost_result(task=task, repository=repository)
        completed_task, agent_run = completed_execution
        record_autonomous_research_task_completion(
            task=completed_task,
            repository=repository,
        )
        return {
            "status": "completed",
            "task_id": task.id,
            "agent_run_id": agent_run.id,
            "stop_reason": None,
        }

    awaiting_execution = _finish_task_execution(
        task=task,
        repository=repository,
        task_status="awaiting_evidence",
        output_refs=output_refs,
        agent_status="completed",
        agent_output_refs=output_refs,
        safety_gate_state="allowed",
        stop_reason=None,
        payload=agent_run_payload,
    )
    if awaiting_execution is None:
        return _execution_lease_lost_result(task=task, repository=repository)
    awaiting_task, agent_run = awaiting_execution
    record_autonomous_research_task_awaiting_evidence(
        task=awaiting_task,
        repository=repository,
    )
    return {
        "status": "awaiting_evidence",
        "task_id": task.id,
        "agent_run_id": agent_run.id,
        "stop_reason": "awaiting_evidence",
    }


def _candidate_refutation_advisory_artifact_ids(
    task: CampaignTaskRecord,
) -> list[str] | None:
    payload = task.payload if isinstance(task.payload, dict) else {}
    if payload.get("runtime_schema") != _AUTONOMOUS_RESEARCH_RUNTIME_SCHEMA:
        return None
    input_refs = task.input_refs if isinstance(task.input_refs, list) else []
    return sorted(
        {
            match.group(1)
            for input_ref in input_refs
            if isinstance(input_ref, str)
            if (match := _ADVISORY_ARTIFACT_INPUT_REF_PATTERN.fullmatch(input_ref))
            is not None
        }
    )


def _hypothesis_generation_learning_signals(
    *,
    task: CampaignTaskRecord,
    campaign: CampaignRecord,
    repository: DatabaseRepository,
) -> list[LearningSignalRecord]:
    if not isinstance(campaign.program_id, str):
        return []
    signals = repository.list_learning_signals(campaign.program_id)
    payload = task.payload if isinstance(task.payload, dict) else {}
    if payload.get("runtime_schema") != _AUTONOMOUS_RESEARCH_RUNTIME_SCHEMA:
        return signals
    input_refs = task.input_refs if isinstance(task.input_refs, list) else []
    bound_ids = {
        match.group(1)
        for input_ref in input_refs
        if isinstance(input_ref, str)
        if (match := _LEARNING_SIGNAL_INPUT_REF_PATTERN.fullmatch(input_ref))
        is not None
    }
    return [signal for signal in signals if signal.id in bound_ids]


def _load_runtime_candidate_hunter_output_projection(
    *,
    task: CampaignTaskRecord,
    campaign: CampaignRecord,
    pipeline_run: Any,
    repository: DatabaseRepository,
) -> tuple[dict | None, dict | None, str | None]:
    task_payload = task.payload if isinstance(task.payload, dict) else {}
    if task_payload.get("runtime_schema") != _AUTONOMOUS_RESEARCH_RUNTIME_SCHEMA:
        return None, None, None
    source_snapshot_digest = _worker_safe_string(
        task_payload.get("source_snapshot_digest")
    )
    if _SOURCE_SNAPSHOT_DIGEST_PATTERN.fullmatch(source_snapshot_digest) is None:
        return None, None, "candidate_hunter_projection_missing"
    if (
        task.task_type != "candidate_refutation"
        or task.campaign_id != campaign.id
        or task_payload.get("pipeline_run_id") != pipeline_run.id
    ):
        return None, None, "candidate_hunter_projection_invalid"

    from app.candidate_hunter_loop import load_candidate_hunter_projection

    candidate_hunter_projection = load_candidate_hunter_projection(
        repository=repository,
        pipeline_run_id=pipeline_run.id,
    )
    runtime_projection = _build_runtime_candidate_hunter_projection(
        task=task,
        campaign=campaign,
        pipeline_run_id=pipeline_run.id,
        source_snapshot_digest=source_snapshot_digest,
        candidate_hunter_projection=candidate_hunter_projection,
    )
    if runtime_projection is None:
        return None, None, "candidate_hunter_projection_invalid"
    return runtime_projection, candidate_hunter_projection, None


def _build_runtime_candidate_hunter_projection(
    *,
    task: CampaignTaskRecord,
    campaign: CampaignRecord,
    pipeline_run_id: str,
    source_snapshot_digest: str,
    candidate_hunter_projection: object,
) -> dict | None:
    if (
        _SOURCE_SNAPSHOT_DIGEST_PATTERN.fullmatch(source_snapshot_digest) is None
        or not isinstance(candidate_hunter_projection, dict)
        or candidate_hunter_projection.get("status") != "ready"
        or candidate_hunter_projection.get("pipeline_run_id") != pipeline_run_id
        or any(
            candidate_hunter_projection.get(field) is not False
            for field in (
                "execution_allowed",
                "dispatch_allowed",
                "validation_allowed",
                "candidate_promotion_allowed",
                "report_submission_allowed",
                "raw_payload_processed",
            )
        )
    ):
        return None
    final_candidates = candidate_hunter_projection.get("final_candidates")
    candidate_decisions = candidate_hunter_projection.get("candidate_decisions")
    audit = candidate_hunter_projection.get("audit")
    if (
        not isinstance(final_candidates, list)
        or not isinstance(candidate_decisions, list)
        or not isinstance(audit, dict)
        or audit.get("campaign_id") != campaign.id
        or audit.get("task_id") != task.id
        or not isinstance(audit.get("round_count"), int)
        or isinstance(audit.get("round_count"), bool)
        or not 1 <= audit["round_count"] <= 3
        or not isinstance(audit.get("state_digest"), str)
        or re.fullmatch(r"[0-9a-f]{64}", audit["state_digest"]) is None
        or len(final_candidates) > 5
        or len(candidate_decisions) > 64
    ):
        return None
    stage_records = audit.get("stage_refs")
    if (
        not isinstance(stage_records, list)
        or len(stage_records) != audit["round_count"] * 4
    ):
        return None
    stage_refs: list[str] = []
    expected_stage_keys = (
        "candidate_hunter_snapshot",
        "candidate_hunter_evidence_request",
        "candidate_hunter_decision",
        "candidate_hunter_rerank",
    )
    for index, stage_record in enumerate(stage_records):
        if not isinstance(stage_record, dict):
            return None
        stage_id = _worker_safe_string(stage_record.get("stage_id"))
        expected_round = index // len(expected_stage_keys) + 1
        stage_ref = f"pipeline_stage:{stage_id}"
        if (
            _SAFE_PROVENANCE_REF_PATTERN.fullmatch(stage_ref) is None
            or stage_ref in stage_refs
            or stage_record.get("stage_key")
            != expected_stage_keys[index % len(expected_stage_keys)]
            or stage_record.get("round") != expected_round
        ):
            return None
        stage_refs.append(stage_ref)
    return {
        "projection_schema": _RUNTIME_CANDIDATE_HUNTER_PROJECTION_SCHEMA,
        "pipeline_run_id": pipeline_run_id,
        "source_snapshot_digest": source_snapshot_digest,
        "candidate_hunter_task_id": task.id,
        "candidate_hunter_state_digest": audit["state_digest"],
        "candidate_hunter_stage_refs": stage_refs,
        "final_candidate_count": len(final_candidates),
        "final_candidates_digest": _canonical_digest(final_candidates),
        "candidate_decision_count": len(candidate_decisions),
        "candidate_decisions_digest": _canonical_digest(candidate_decisions),
        "raw_payload_processed": False,
        "execution_allowed": False,
        "dispatch_allowed": False,
        "validation_allowed": False,
        "candidate_promotion_allowed": False,
        "report_submission_allowed": False,
    }


def _runtime_candidate_hunter_projection_for_downstream(
    *,
    task: CampaignTaskRecord,
    campaign: CampaignRecord,
    pipeline_run: Any,
    repository: DatabaseRepository,
) -> tuple[dict | None, str | None]:
    task_payload = task.payload if isinstance(task.payload, dict) else {}
    if task_payload.get("runtime_schema") != _AUTONOMOUS_RESEARCH_RUNTIME_SCHEMA:
        return None, None
    source_snapshot_digest = _worker_safe_string(
        task_payload.get("source_snapshot_digest")
    )
    if _SOURCE_SNAPSHOT_DIGEST_PATTERN.fullmatch(source_snapshot_digest) is None:
        return None, "candidate_hunter_projection_missing"
    candidate_refutation_tasks = [
        candidate
        for candidate in repository.list_campaign_tasks(campaign.id)
        if candidate.task_type == "candidate_refutation"
        and candidate.status == "completed"
        and isinstance(candidate.payload, dict)
        and candidate.payload.get("runtime_schema")
        == _AUTONOMOUS_RESEARCH_RUNTIME_SCHEMA
        and candidate.payload.get("pipeline_run_id") == pipeline_run.id
        and candidate.payload.get("source_snapshot_digest") == source_snapshot_digest
    ]
    if not candidate_refutation_tasks:
        return None, "candidate_hunter_projection_missing"
    if len(candidate_refutation_tasks) != 1:
        return None, "candidate_hunter_projection_invalid"

    candidate_refutation_task = candidate_refutation_tasks[0]
    projection_ref = f"candidate_hunter_projection:{candidate_refutation_task.id}"
    if projection_ref not in candidate_refutation_task.output_refs:
        return None, "candidate_hunter_projection_missing"
    runtime_stages = [
        stage
        for stage in repository.list_campaign_pipeline_stages(campaign.id)
        if stage.task_id == candidate_refutation_task.id
        and stage.stage_key == "autonomous_research:candidate_refutation"
        and stage.status == "completed"
        and stage.safety_gate_state == "allowed"
        and isinstance(stage.payload, dict)
        and stage.payload.get("runtime_schema")
        == _AUTONOMOUS_RESEARCH_RUNTIME_SCHEMA
        and stage.payload.get("source_snapshot_digest") == source_snapshot_digest
        and projection_ref in stage.output_refs
    ]
    agent_runs = [
        run
        for run in repository.list_campaign_agent_runs(campaign.id)
        if run.task_id == candidate_refutation_task.id
        and run.status == "completed"
        and run.safety_gate_state == "allowed"
        and projection_ref in run.output_refs
    ]
    if not runtime_stages or not agent_runs:
        return None, "candidate_hunter_projection_missing"
    if len(runtime_stages) != 1 or len(agent_runs) != 1:
        return None, "candidate_hunter_projection_invalid"
    (
        expected_projection,
        candidate_hunter_projection,
        candidate_hunter_stop_reason,
    ) = _load_runtime_candidate_hunter_output_projection(
        task=candidate_refutation_task,
        campaign=campaign,
        pipeline_run=pipeline_run,
        repository=repository,
    )
    if candidate_hunter_stop_reason is not None:
        return None, candidate_hunter_stop_reason
    run_payload = (
        agent_runs[0].payload if isinstance(agent_runs[0].payload, dict) else {}
    )
    if (
        run_payload.get("artifact_kind") != "candidate_hunter_projection"
        or run_payload.get("pipeline_run_id") != pipeline_run.id
        or run_payload.get("candidate_hunter_status") != "completed"
        or any(
            run_payload.get(field) is not False
            for field in (
                "raw_payload_processed",
                "execution_allowed",
                "dispatch_allowed",
                "validation_allowed",
                "candidate_promotion_allowed",
                "report_submission_allowed",
            )
        )
        or run_payload.get("candidate_hunter_projection") != expected_projection
        or not isinstance(candidate_hunter_projection, dict)
    ):
        return None, "candidate_hunter_projection_invalid"
    return candidate_hunter_projection, None


def _finding_dedup_risk_input_digest(
    *,
    final_candidates: list,
    candidate_decisions: list,
) -> str:
    return _canonical_digest(
        {
            "candidate_decisions": candidate_decisions,
            "final_candidates": final_candidates,
        }
    )


def _build_finding_dedup_risk_projection(
    *,
    plan_payload: object,
    pipeline_run_id: str,
    source_snapshot_digest: str,
    final_candidates: list,
    candidate_decisions: list,
    ranking_payload: dict,
) -> dict | None:
    full_plan = _safe_finding_dedup_risk_plan(
        plan_payload,
        pipeline_run_id=pipeline_run_id,
        final_candidates=final_candidates,
    )
    if full_plan is None:
        return None
    finding_dedup_risk = _finding_dedup_risk_advisory_summary(full_plan)
    return {
        "schema_version": _AUTONOMOUS_FINDING_DEDUP_RISK_PROJECTION_SCHEMA,
        "artifact_kind": "finding_dedup_risk_projection",
        "pipeline_run_id": pipeline_run_id,
        "source_snapshot_digest": source_snapshot_digest,
        "candidate_hunter_input_digest": _finding_dedup_risk_input_digest(
            final_candidates=final_candidates,
            candidate_decisions=candidate_decisions,
        ),
        "ranking_payload_digest": _canonical_digest(ranking_payload),
        "finding_dedup_risk": finding_dedup_risk,
        "finding_dedup_risk_digest": _canonical_digest(finding_dedup_risk),
        "human_review_required": True,
        "raw_payload_processed": False,
        "execution_allowed": False,
        "dispatch_allowed": False,
        "validation_allowed": False,
        "candidate_promotion_allowed": False,
        "report_submission_allowed": False,
    }


def _finding_dedup_risk_advisory_summary(plan: dict) -> dict:
    return {
        "status": plan["status"],
        "execution_mode": "plan_only",
        "seed_count": plan["seed_count"],
        "cluster_count": plan["cluster_count"],
        "risk_queue_count": plan["risk_queue_count"],
        "offline_hint_count": plan["offline_hint_count"],
        "offline_artifact_present": False,
        "human_allow_export_write": False,
        "export_written": False,
        "export_count": 0,
        "execution_allowed": False,
        "validation_allowed": False,
        "report_submission_allowed": False,
        "confirmed_vulnerability": False,
        "finding_promotion_allowed": False,
        "ranking_permission_granted": False,
        "network_access": False,
        "live_validation": False,
        "process_spawn_allowed": False,
    }


def _safe_finding_dedup_risk_plan(
    value: object,
    *,
    pipeline_run_id: str,
    final_candidates: list,
) -> dict | None:
    if not isinstance(value, dict) or not isinstance(final_candidates, list):
        return None
    if len(final_candidates) > 5:
        return None
    candidate_ids = [
        _worker_safe_string(candidate.get("candidate_id"))
        for candidate in final_candidates
        if isinstance(candidate, dict)
    ]
    if (
        len(candidate_ids) != len(final_candidates)
        or not all(candidate_ids)
        or len(candidate_ids) != len(set(candidate_ids))
    ):
        return None
    seeds = value.get("seeds")
    clusters = value.get("clusters")
    risk_queue = value.get("risk_queue")
    seed_count = value.get("seed_count")
    cluster_count = value.get("cluster_count")
    risk_queue_count = value.get("risk_queue_count")
    offline_hint_count = value.get("offline_hint_count")
    export_count = value.get("export_count")
    if (
        value.get("stage") != "v3_finding_dedup_risk"
        or value.get("package_id") != f"pipeline_run:{pipeline_run_id}"
        or value.get("package_root") != ""
        or value.get("execution_mode") != "plan_only"
        or value.get("status")
        not in {
            "finding_dedup_risk_plan_ready",
            "finding_dedup_risk_empty",
        }
        or value.get("human_allow_export_write") is not False
        or value.get("export_written") is not False
        or not isinstance(export_count, int)
        or isinstance(export_count, bool)
        or export_count != 0
        or not isinstance(offline_hint_count, int)
        or isinstance(offline_hint_count, bool)
        or offline_hint_count != 0
        or value.get("offline_artifact_present") is not False
        or value.get("execution_allowed") is not False
        or value.get("validation_allowed") is not False
        or value.get("report_submission_allowed") is not False
        or value.get("confirmed_vulnerability") is not False
        or value.get("finding_promotion_allowed") is not False
        or value.get("ranking_permission_granted") is not False
        or value.get("network_access") is not False
        or value.get("live_validation") is not False
        or value.get("process_spawn_allowed") is not False
        or not isinstance(seeds, list)
        or not isinstance(clusters, list)
        or not isinstance(risk_queue, list)
        or not isinstance(seed_count, int)
        or isinstance(seed_count, bool)
        or not isinstance(cluster_count, int)
        or isinstance(cluster_count, bool)
        or not isinstance(risk_queue_count, int)
        or isinstance(risk_queue_count, bool)
        or seed_count != len(seeds)
        or cluster_count != len(clusters)
        or risk_queue_count != len(risk_queue)
        or not 0 <= seed_count <= 5
        or not 0 <= cluster_count <= seed_count
        or risk_queue_count != seed_count
    ):
        return None
    if value["status"] == "finding_dedup_risk_plan_ready":
        if seed_count != len(candidate_ids) or not seeds or not clusters:
            return None
    elif candidate_ids or seeds or clusters or risk_queue:
        return None

    seen_seed_ids: set[str] = set()
    for seed in seeds:
        if not isinstance(seed, dict):
            return None
        seed_id = _worker_safe_string(seed.get("seed_id"))
        if (
            not seed_id
            or seed_id in seen_seed_ids
            or seed_id not in candidate_ids
        ):
            return None
        seen_seed_ids.add(seed_id)

    seen_cluster_ids: set[str] = set()
    clustered_seed_ids: set[str] = set()
    cluster_by_seed_id: dict[str, str] = {}
    for cluster in clusters:
        if not isinstance(cluster, dict):
            return None
        cluster_id = _worker_safe_string(cluster.get("cluster_id"))
        cluster_seed_ids = cluster.get("seed_ids")
        member_count = cluster.get("member_count")
        if (
            _FINDING_DEDUP_RISK_CLUSTER_ID_PATTERN.fullmatch(cluster_id) is None
            or cluster_id in seen_cluster_ids
            or not isinstance(cluster_seed_ids, list)
            or not cluster_seed_ids
            or any(not isinstance(seed_id, str) for seed_id in cluster_seed_ids)
            or len(cluster_seed_ids) != len(set(cluster_seed_ids))
            or any(seed_id not in seen_seed_ids for seed_id in cluster_seed_ids)
            or any(seed_id in clustered_seed_ids for seed_id in cluster_seed_ids)
            or not isinstance(member_count, int)
            or isinstance(member_count, bool)
            or member_count != len(cluster_seed_ids)
            or cluster.get("execution_allowed") is not False
            or cluster.get("finding_promotion_allowed") is not False
        ):
            return None
        seen_cluster_ids.add(cluster_id)
        clustered_seed_ids.update(cluster_seed_ids)
        for seed_id in cluster_seed_ids:
            cluster_by_seed_id[seed_id] = cluster_id
    if clustered_seed_ids != seen_seed_ids:
        return None

    queued_seed_ids: set[str] = set()
    for priority, item in enumerate(risk_queue, start=1):
        if not isinstance(item, dict):
            return None
        seed_id = _worker_safe_string(item.get("seed_id"))
        cluster_id = _worker_safe_string(item.get("cluster_id"))
        if (
            not seed_id
            or seed_id in queued_seed_ids
            or seed_id not in seen_seed_ids
            or cluster_id not in seen_cluster_ids
            or cluster_by_seed_id.get(seed_id) != cluster_id
            or not isinstance(item.get("priority"), int)
            or isinstance(item.get("priority"), bool)
            or item["priority"] != priority
            or item.get("human_review_only") is not True
            or item.get("ranking_permission_granted") is not False
            or item.get("execution_allowed") is not False
            or item.get("report_submission_allowed") is not False
        ):
            return None
        queued_seed_ids.add(seed_id)
    if queued_seed_ids != seen_seed_ids:
        return None
    return dict(value)


def _safe_finding_dedup_risk_advisory_summary(value: object) -> dict | None:
    if not isinstance(value, dict):
        return None
    required_keys = {
        "status",
        "execution_mode",
        "seed_count",
        "cluster_count",
        "risk_queue_count",
        "offline_hint_count",
        "offline_artifact_present",
        "human_allow_export_write",
        "export_written",
        "export_count",
        "execution_allowed",
        "validation_allowed",
        "report_submission_allowed",
        "confirmed_vulnerability",
        "finding_promotion_allowed",
        "ranking_permission_granted",
        "network_access",
        "live_validation",
        "process_spawn_allowed",
    }
    if set(value) != required_keys:
        return None
    seed_count = value.get("seed_count")
    cluster_count = value.get("cluster_count")
    risk_queue_count = value.get("risk_queue_count")
    offline_hint_count = value.get("offline_hint_count")
    export_count = value.get("export_count")
    if (
        value.get("status")
        not in {
            "finding_dedup_risk_plan_ready",
            "finding_dedup_risk_empty",
        }
        or value.get("execution_mode") != "plan_only"
        or not isinstance(seed_count, int)
        or isinstance(seed_count, bool)
        or not isinstance(cluster_count, int)
        or isinstance(cluster_count, bool)
        or not isinstance(risk_queue_count, int)
        or isinstance(risk_queue_count, bool)
        or not isinstance(offline_hint_count, int)
        or isinstance(offline_hint_count, bool)
        or not isinstance(export_count, int)
        or isinstance(export_count, bool)
        or not 0 <= seed_count <= 5
        or not 0 <= cluster_count <= seed_count
        or risk_queue_count != seed_count
        or offline_hint_count != 0
        or value.get("offline_artifact_present") is not False
        or value.get("human_allow_export_write") is not False
        or value.get("export_written") is not False
        or export_count != 0
        or any(
            value.get(field) is not False
            for field in (
                "execution_allowed",
                "validation_allowed",
                "report_submission_allowed",
                "confirmed_vulnerability",
                "finding_promotion_allowed",
                "ranking_permission_granted",
                "network_access",
                "live_validation",
                "process_spawn_allowed",
            )
        )
    ):
        return None
    if value["status"] == "finding_dedup_risk_plan_ready":
        if seed_count < 1 or cluster_count < 1:
            return None
    elif seed_count != 0 or cluster_count != 0 or risk_queue_count != 0:
        return None
    return dict(value)


def _safe_finding_dedup_risk_projection(
    value: object,
    *,
    pipeline_run_id: str,
    source_snapshot_digest: str,
    final_candidates: list,
    candidate_decisions: list,
    ranking_payload: dict,
) -> dict | None:
    if (
        not isinstance(value, dict)
        or not isinstance(final_candidates, list)
        or not isinstance(candidate_decisions, list)
        or not isinstance(ranking_payload, dict)
    ):
        return None
    required_keys = {
        "schema_version",
        "artifact_kind",
        "pipeline_run_id",
        "source_snapshot_digest",
        "candidate_hunter_input_digest",
        "ranking_payload_digest",
        "finding_dedup_risk",
        "finding_dedup_risk_digest",
        "human_review_required",
        "raw_payload_processed",
        "execution_allowed",
        "dispatch_allowed",
        "validation_allowed",
        "candidate_promotion_allowed",
        "report_submission_allowed",
    }
    if set(value) != required_keys:
        return None
    finding_dedup_risk = _safe_finding_dedup_risk_advisory_summary(
        value.get("finding_dedup_risk")
    )
    if (
        value.get("schema_version")
        != _AUTONOMOUS_FINDING_DEDUP_RISK_PROJECTION_SCHEMA
        or value.get("artifact_kind") != "finding_dedup_risk_projection"
        or value.get("pipeline_run_id") != pipeline_run_id
        or value.get("source_snapshot_digest") != source_snapshot_digest
        or _SOURCE_SNAPSHOT_DIGEST_PATTERN.fullmatch(source_snapshot_digest) is None
        or value.get("candidate_hunter_input_digest")
        != _finding_dedup_risk_input_digest(
            final_candidates=final_candidates,
            candidate_decisions=candidate_decisions,
        )
        or value.get("ranking_payload_digest") != _canonical_digest(ranking_payload)
        or finding_dedup_risk is None
        or value.get("finding_dedup_risk_digest")
        != _canonical_digest(finding_dedup_risk)
        or value.get("human_review_required") is not True
        or value.get("raw_payload_processed") is not False
        or any(
            value.get(field) is not False
            for field in (
                "execution_allowed",
                "dispatch_allowed",
                "validation_allowed",
                "candidate_promotion_allowed",
                "report_submission_allowed",
            )
        )
    ):
        return None
    return dict(value)


def _runtime_finding_dedup_risk_projection_for_report(
    *,
    task: CampaignTaskRecord,
    campaign: CampaignRecord,
    pipeline_run: Any,
    ranking_stage: PipelineStageRecord,
    final_candidates: list,
    candidate_decisions: list,
    repository: DatabaseRepository,
) -> tuple[dict | None, PipelineStageRecord | None, str | None]:
    task_payload = task.payload if isinstance(task.payload, dict) else {}
    source_snapshot_digest = _worker_safe_string(
        task_payload.get("source_snapshot_digest")
    )
    if _SOURCE_SNAPSHOT_DIGEST_PATTERN.fullmatch(source_snapshot_digest) is None:
        return None, None, "finding_dedup_risk_projection_invalid"
    ranking_tasks = [
        candidate
        for candidate in repository.list_campaign_tasks(campaign.id)
        if candidate.task_type == "finding_dedup_and_rank"
        and candidate.status == "completed"
        and isinstance(candidate.payload, dict)
        and candidate.payload.get("runtime_schema")
        == _AUTONOMOUS_RESEARCH_RUNTIME_SCHEMA
        and candidate.payload.get("pipeline_run_id") == pipeline_run.id
        and candidate.payload.get("source_snapshot_digest") == source_snapshot_digest
    ]
    if not ranking_tasks:
        return None, None, None
    if len(ranking_tasks) != 1:
        return None, None, "finding_dedup_risk_projection_invalid"
    ranking_task = ranking_tasks[0]
    projection_ref = f"finding_dedup_risk_projection:{ranking_task.id}"
    if projection_ref not in ranking_task.output_refs:
        return None, None, None
    if (
        ranking_stage.task_id != ranking_task.id
        or ranking_stage.pipeline_run_id != pipeline_run.id
        or ranking_stage.campaign_id != campaign.id
        or ranking_stage.stage_key != "autonomous_finding_dedup_and_rank"
        or ranking_stage.status != "completed"
        or ranking_stage.safety_gate_state != "safe"
        or not isinstance(ranking_stage.payload, dict)
    ):
        return None, None, "finding_dedup_risk_projection_invalid"
    expected_input_refs = [
        f"pipeline_run:{pipeline_run.id}",
        f"pipeline_stage:{ranking_stage.id}",
    ]
    stages = [
        stage
        for stage in repository.list_pipeline_stages_for_run(pipeline_run.id)
        if stage.task_id == ranking_task.id
        and stage.campaign_id == campaign.id
        and stage.stage_key == "autonomous_finding_dedup_risk"
        and stage.status == "completed"
        and stage.safety_gate_state == "safe"
        and stage.input_refs == expected_input_refs
        and stage.output_refs == [projection_ref]
    ]
    if len(stages) != 1:
        return None, None, "finding_dedup_risk_projection_invalid"
    projection = _safe_finding_dedup_risk_projection(
        stages[0].payload,
        pipeline_run_id=pipeline_run.id,
        source_snapshot_digest=source_snapshot_digest,
        final_candidates=final_candidates,
        candidate_decisions=candidate_decisions,
        ranking_payload=ranking_stage.payload,
    )
    if projection is None:
        return None, None, "finding_dedup_risk_projection_invalid"
    return projection, stages[0], None


def _chain_reasoning_hypothesis_seeds(hypotheses: list) -> list[dict[str, str]]:
    seeds: list[dict[str, str]] = []
    seen_refs: set[str] = set()
    for index, hypothesis in enumerate(hypotheses, start=1):
        if not isinstance(hypothesis, dict):
            continue
        source_ref = _safe_chain_hypothesis_ref(hypothesis, index)
        if source_ref in seen_refs:
            source_ref = "hypothesis:sha256:" + sha256(
                f"{index}:{source_ref}".encode("utf-8")
            ).hexdigest()
        seen_refs.add(source_ref)
        vuln_type = _chain_taxonomy_token(
            hypothesis.get("vuln_type") or hypothesis.get("family")
        )
        family = _chain_taxonomy_token(
            hypothesis.get("family") or hypothesis.get("vuln_type")
        )
        seeds.append(
            {
                "hypothesis_id": source_ref,
                "family": family,
                "vuln_type": vuln_type,
                "location": source_ref,
                "origin": "runtime_hypothesis",
            }
        )
        if len(seeds) >= 32:
            break
    return seeds


def _safe_chain_hypothesis_ref(hypothesis: dict, index: int) -> str:
    candidate_id = _worker_safe_string(
        hypothesis.get("hypothesis_id")
        or hypothesis.get("candidate_id")
        or hypothesis.get("id")
    )
    if candidate_id and re.fullmatch(r"[A-Za-z0-9_.:-]{1,100}", candidate_id):
        return f"hypothesis:{candidate_id}"
    return "hypothesis:sha256:" + sha256(
        f"{index}:{candidate_id}".encode("utf-8")
    ).hexdigest()


def _chain_taxonomy_token(value: object) -> str:
    raw = _worker_safe_string(value).lower()
    normalized = re.sub(r"[^a-z0-9]+", "_", raw).strip("_")[:80]
    return normalized if _CHAIN_TOKEN_PATTERN.fullmatch(normalized) else "unknown"


def _build_exploit_chain_projection(
    *,
    plan_payload: object,
    pipeline_run_id: str,
    source_snapshot_digest: str,
    source_hypotheses: list[dict[str, str]],
) -> dict | None:
    if not isinstance(plan_payload, dict):
        return None
    if (
        plan_payload.get("execution_mode") != "plan_only"
        or plan_payload.get("human_allow_export_write") is not False
        or plan_payload.get("export_written") is not False
        or plan_payload.get("export_count") != 0
        or any(
            plan_payload.get(field) is not False
            for field in (
                "network_access",
                "live_validation",
                "process_spawn_allowed",
                "execution_allowed",
                "validation_allowed",
                "report_submission_allowed",
                "confirmed_vulnerability",
                "finding_promotion_allowed",
            )
        )
    ):
        return None
    plan_status = _worker_safe_string(plan_payload.get("status"))
    if plan_status not in {
        "vuln_chain_builder_plan_ready",
        "vuln_chain_builder_waiting_for_seeds",
    }:
        return None
    raw_chains = plan_payload.get("chains")
    if (
        not isinstance(raw_chains, list)
        or plan_payload.get("chain_count") != len(raw_chains)
        or len(raw_chains) > 24
    ):
        return None
    source_hypothesis_refs = [item["hypothesis_id"] for item in source_hypotheses]
    if len(source_hypothesis_refs) != len(set(source_hypothesis_refs)):
        return None
    chains: list[dict] = []
    seen_chain_refs: set[str] = set()
    for item in raw_chains:
        if not isinstance(item, dict):
            return None
        chain_id = _worker_safe_string(item.get("chain_id"))
        source_hypothesis_ref = _worker_safe_string(item.get("source_hypothesis_id"))
        chain_ref = f"exploit_chain:{chain_id}"
        primitives = _safe_chain_primitives(item.get("stages"))
        preconditions = _safe_chain_tokens(item.get("required_evidence"), maximum=8)
        status = _worker_safe_string(item.get("status"))
        if (
            _EXPLOIT_CHAIN_REF_PATTERN.fullmatch(chain_ref) is None
            or chain_ref in seen_chain_refs
            or source_hypothesis_ref not in source_hypothesis_refs
            or primitives is None
            or preconditions is None
            or status
            not in {
                "planned_unverified_chain",
                "unverified_hypothesis_from_confirmed_finding",
            }
            or item.get("execution_allowed") is not False
            or item.get("human_review_required") is not True
        ):
            return None
        seen_chain_refs.add(chain_ref)
        chains.append(
            {
                "chain_ref": chain_ref,
                "source_hypothesis_ref": source_hypothesis_ref,
                "family": _chain_taxonomy_token(item.get("family")),
                "vuln_type": _chain_taxonomy_token(item.get("vuln_type")),
                "primitives": primitives,
                "preconditions": preconditions,
                "refutation_questions": list(_CHAIN_REFUTATION_QUESTIONS),
                "status": status,
                "execution_allowed": False,
                "human_review_required": True,
            }
        )
    if plan_status == "vuln_chain_builder_plan_ready" and not chains:
        return None
    if plan_status == "vuln_chain_builder_waiting_for_seeds" and chains:
        return None
    source_hypothesis_digest = _canonical_digest(source_hypotheses)
    return {
        "schema_version": _AUTONOMOUS_EXPLOIT_CHAIN_PROJECTION_SCHEMA,
        "artifact_kind": "exploit_chain_reasoning_projection",
        "pipeline_run_id": pipeline_run_id,
        "source_snapshot_digest": source_snapshot_digest,
        "source_hypothesis_refs": source_hypothesis_refs,
        "source_hypothesis_digest": source_hypothesis_digest,
        "plan_status": plan_status,
        "execution_mode": "plan_only",
        "chain_count": len(chains),
        "chains": chains,
        "chain_plan_digest": _canonical_digest(chains),
        "human_review_required": True,
        "raw_payload_processed": False,
        "execution_allowed": False,
        "dispatch_allowed": False,
        "validation_allowed": False,
        "candidate_promotion_allowed": False,
        "report_submission_allowed": False,
    }


def _safe_chain_primitives(value: object) -> list[str] | None:
    if not isinstance(value, list) or not 1 <= len(value) <= 12:
        return None
    primitives = []
    for item in value:
        name = _chain_taxonomy_token(item.get("name") if isinstance(item, dict) else None)
        if name == "unknown" or name in primitives:
            return None
        primitives.append(name)
    return primitives


def _safe_chain_tokens(value: object, *, maximum: int) -> list[str] | None:
    if not isinstance(value, list) or not 1 <= len(value) <= maximum:
        return None
    tokens = [_chain_taxonomy_token(item) for item in value]
    if "unknown" in tokens or len(tokens) != len(set(tokens)):
        return None
    return tokens


def _runtime_exploit_chain_projection_with_provenance(
    *,
    task: CampaignTaskRecord,
    campaign: CampaignRecord,
    pipeline_run: Any,
    hypotheses: list,
    repository: DatabaseRepository,
) -> tuple[
    dict | None,
    CampaignTaskRecord | None,
    PipelineStageRecord | None,
    str | None,
]:
    task_payload = task.payload if isinstance(task.payload, dict) else {}
    source_snapshot_digest = _worker_safe_string(
        task_payload.get("source_snapshot_digest")
    )
    if _SOURCE_SNAPSHOT_DIGEST_PATTERN.fullmatch(source_snapshot_digest) is None:
        return None, None, None, "exploit_chain_projection_missing"
    source_hypotheses = _chain_reasoning_hypothesis_seeds(hypotheses)
    chain_tasks = [
        candidate
        for candidate in repository.list_campaign_tasks(campaign.id)
        if candidate.task_type == "exploit_chain_reasoning"
        and candidate.status == "completed"
    ]
    if not chain_tasks:
        return None, None, None, "exploit_chain_projection_missing"
    if len(chain_tasks) != 1:
        return None, None, None, "exploit_chain_projection_invalid"
    chain_task = chain_tasks[0]
    chain_task_payload = (
        chain_task.payload if isinstance(chain_task.payload, dict) else {}
    )
    projection_ref = f"exploit_chain_projection:{chain_task.id}"
    if (
        chain_task_payload.get("runtime_schema")
        != _AUTONOMOUS_RESEARCH_RUNTIME_SCHEMA
        or chain_task_payload.get("pipeline_run_id") != pipeline_run.id
        or chain_task_payload.get("source_snapshot_digest") != source_snapshot_digest
        or projection_ref not in chain_task.output_refs
        or f"pipeline_run:{pipeline_run.id}" not in chain_task.input_refs
    ):
        return None, None, None, "exploit_chain_projection_invalid"
    runtime_stages = [
        stage
        for stage in repository.list_campaign_pipeline_stages(campaign.id)
        if stage.task_id == chain_task.id
        and stage.stage_key == "autonomous_research:exploit_chain_reasoning"
        and stage.status == "completed"
        and stage.safety_gate_state == "allowed"
        and isinstance(stage.payload, dict)
        and stage.payload.get("runtime_schema")
        == _AUTONOMOUS_RESEARCH_RUNTIME_SCHEMA
        and stage.payload.get("source_snapshot_digest") == source_snapshot_digest
        and projection_ref in stage.output_refs
    ]
    plan_stages = [
        stage
        for stage in repository.list_pipeline_stages_for_run(pipeline_run.id)
        if stage.task_id == chain_task.id
        and stage.campaign_id == campaign.id
        and stage.stage_key == "autonomous_exploit_chain_reasoning"
        and stage.status == "completed"
        and stage.safety_gate_state == "safe"
        and stage.input_refs
        == [
            f"pipeline_run:{pipeline_run.id}",
            f"source_snapshot:{source_snapshot_digest}",
        ]
        and stage.output_refs == [projection_ref]
    ]
    agent_runs = [
        run
        for run in repository.list_campaign_agent_runs(campaign.id)
        if run.task_id == chain_task.id
        and run.status == "completed"
        and run.safety_gate_state == "allowed"
        and projection_ref in run.output_refs
    ]
    if not runtime_stages or not plan_stages or not agent_runs:
        return None, None, None, "exploit_chain_projection_missing"
    if len(runtime_stages) != 1 or len(plan_stages) != 1 or len(agent_runs) != 1:
        return None, None, None, "exploit_chain_projection_invalid"
    projection = _safe_exploit_chain_projection(
        agent_runs[0].payload,
        pipeline_run_id=pipeline_run.id,
        source_snapshot_digest=source_snapshot_digest,
        source_hypotheses=source_hypotheses,
    )
    if projection is None or plan_stages[0].payload != projection:
        return None, None, None, "exploit_chain_projection_invalid"
    return projection, chain_task, plan_stages[0], None


def _runtime_exploit_chain_projection(
    *,
    task: CampaignTaskRecord,
    campaign: CampaignRecord,
    pipeline_run: Any,
    hypotheses: list,
    repository: DatabaseRepository,
) -> tuple[dict | None, str | None]:
    projection, _, _, stop_reason = _runtime_exploit_chain_projection_with_provenance(
        task=task,
        campaign=campaign,
        pipeline_run=pipeline_run,
        hypotheses=hypotheses,
        repository=repository,
    )
    return projection, stop_reason


def _safe_exploit_chain_projection(
    value: object,
    *,
    pipeline_run_id: str,
    source_snapshot_digest: str,
    source_hypotheses: list[dict[str, str]],
) -> dict | None:
    if not isinstance(value, dict):
        return None
    required_keys = {
        "schema_version",
        "artifact_kind",
        "pipeline_run_id",
        "source_snapshot_digest",
        "source_hypothesis_refs",
        "source_hypothesis_digest",
        "plan_status",
        "execution_mode",
        "chain_count",
        "chains",
        "chain_plan_digest",
        "human_review_required",
        "raw_payload_processed",
        "execution_allowed",
        "dispatch_allowed",
        "validation_allowed",
        "candidate_promotion_allowed",
        "report_submission_allowed",
    }
    if set(value) != required_keys:
        return None
    source_hypothesis_refs = [item["hypothesis_id"] for item in source_hypotheses]
    chains = value.get("chains")
    if (
        value.get("schema_version") != _AUTONOMOUS_EXPLOIT_CHAIN_PROJECTION_SCHEMA
        or value.get("artifact_kind") != "exploit_chain_reasoning_projection"
        or value.get("pipeline_run_id") != pipeline_run_id
        or value.get("source_snapshot_digest") != source_snapshot_digest
        or value.get("source_hypothesis_refs") != source_hypothesis_refs
        or value.get("source_hypothesis_digest")
        != _canonical_digest(source_hypotheses)
        or value.get("plan_status")
        not in {
            "vuln_chain_builder_plan_ready",
            "vuln_chain_builder_waiting_for_seeds",
        }
        or value.get("execution_mode") != "plan_only"
        or value.get("human_review_required") is not True
        or value.get("raw_payload_processed") is not False
        or any(
            value.get(field) is not False
            for field in (
                "execution_allowed",
                "dispatch_allowed",
                "validation_allowed",
                "candidate_promotion_allowed",
                "report_submission_allowed",
            )
        )
        or not isinstance(chains, list)
        or value.get("chain_count") != len(chains)
        or len(chains) > 24
        or value.get("chain_plan_digest") != _canonical_digest(chains)
    ):
        return None
    seen_chain_refs: set[str] = set()
    for chain in chains:
        if not isinstance(chain, dict) or set(chain) != {
            "chain_ref",
            "source_hypothesis_ref",
            "family",
            "vuln_type",
            "primitives",
            "preconditions",
            "refutation_questions",
            "status",
            "execution_allowed",
            "human_review_required",
        }:
            return None
        chain_ref = chain.get("chain_ref")
        if (
            not isinstance(chain_ref, str)
            or _EXPLOIT_CHAIN_REF_PATTERN.fullmatch(chain_ref) is None
            or chain_ref in seen_chain_refs
            or chain.get("source_hypothesis_ref") not in source_hypothesis_refs
            or _CHAIN_TOKEN_PATTERN.fullmatch(_worker_safe_string(chain.get("family")))
            is None
            or _CHAIN_TOKEN_PATTERN.fullmatch(_worker_safe_string(chain.get("vuln_type")))
            is None
            or _safe_chain_tokens(chain.get("primitives"), maximum=12) is None
            or _safe_chain_tokens(chain.get("preconditions"), maximum=8) is None
            or chain.get("refutation_questions") != _CHAIN_REFUTATION_QUESTIONS
            or chain.get("status")
            not in {
                "planned_unverified_chain",
                "unverified_hypothesis_from_confirmed_finding",
            }
            or chain.get("execution_allowed") is not False
            or chain.get("human_review_required") is not True
        ):
            return None
        seen_chain_refs.add(chain_ref)
    if value["plan_status"] == "vuln_chain_builder_plan_ready" and not chains:
        return None
    if value["plan_status"] == "vuln_chain_builder_waiting_for_seeds" and chains:
        return None
    return dict(value)


def _build_variant_analysis_projection(
    *,
    plan_payload: object,
    pipeline_run_id: str,
    source_snapshot_digest: str,
    source_hypotheses: list[dict[str, str]],
    exploit_chain_projection: dict,
) -> dict | None:
    full_plan = _safe_variant_analysis_plan(
        plan_payload,
        pipeline_run_id=pipeline_run_id,
        source_hypotheses=source_hypotheses,
    )
    if full_plan is None:
        return None
    variant_analysis = _variant_analysis_advisory_summary(full_plan)
    source_hypothesis_refs = [item["hypothesis_id"] for item in source_hypotheses]
    return {
        "schema_version": _AUTONOMOUS_VARIANT_ANALYSIS_PROJECTION_SCHEMA,
        "artifact_kind": "variant_analysis_projection",
        "pipeline_run_id": pipeline_run_id,
        "source_snapshot_digest": source_snapshot_digest,
        "source_hypothesis_refs": source_hypothesis_refs,
        "source_hypothesis_digest": _canonical_digest(source_hypotheses),
        "exploit_chain_projection_digest": _canonical_digest(
            exploit_chain_projection
        ),
        "variant_analysis": variant_analysis,
        "variant_analysis_digest": _canonical_digest(variant_analysis),
        "human_review_required": True,
        "raw_payload_processed": False,
        "execution_allowed": False,
        "dispatch_allowed": False,
        "validation_allowed": False,
        "candidate_promotion_allowed": False,
        "report_submission_allowed": False,
    }


def _variant_analysis_advisory_summary(plan: dict) -> dict:
    return {
        "status": plan["status"],
        "execution_mode": "plan_only",
        "variant_count": plan["variant_count"],
        "seed_count": plan["seed_count"],
        "offline_hint_count": plan["offline_hint_count"],
        "bridge_seed_count": plan["bridge_seed_count"],
        "human_allow_export_write": False,
        "export_written": False,
        "export_count": 0,
        "network_access": False,
        "live_validation": False,
        "process_spawn_allowed": False,
        "execution_allowed": False,
        "validation_allowed": False,
        "report_submission_allowed": False,
        "confirmed_vulnerability": False,
        "finding_promotion_allowed": False,
    }


def _safe_variant_analysis_plan(
    value: object,
    *,
    pipeline_run_id: str,
    source_hypotheses: list[dict[str, str]],
) -> dict | None:
    if not isinstance(value, dict):
        return None
    variants = value.get("variants")
    variant_count = value.get("variant_count")
    seed_count = value.get("seed_count")
    offline_hint_count = value.get("offline_hint_count")
    bridge_seed_count = value.get("bridge_seed_count")
    allowed_statuses = {
        "variant_analysis_plan_ready",
        "variant_analysis_waiting_for_seeds",
        "variant_analysis_empty",
    }
    if (
        value.get("stage") != "v4_variant_analysis"
        or value.get("package_id") != f"pipeline_run:{pipeline_run_id}"
        or value.get("package_root") != ""
        or value.get("execution_mode") != "plan_only"
        or value.get("status") not in allowed_statuses
        or value.get("human_allow_export_write") is not False
        or value.get("export_written") is not False
        or value.get("export_count") != 0
        or value.get("offline_hint_count") != 0
        or value.get("network_access") is not False
        or value.get("live_validation") is not False
        or value.get("process_spawn_allowed") is not False
        or value.get("execution_allowed") is not False
        or value.get("validation_allowed") is not False
        or value.get("report_submission_allowed") is not False
        or value.get("confirmed_vulnerability") is not False
        or value.get("finding_promotion_allowed") is not False
        or value.get("human_approval_required_before_action") is not True
        or not isinstance(variants, list)
        or not isinstance(variant_count, int)
        or isinstance(variant_count, bool)
        or not isinstance(seed_count, int)
        or isinstance(seed_count, bool)
        or not isinstance(offline_hint_count, int)
        or isinstance(offline_hint_count, bool)
        or not isinstance(bridge_seed_count, int)
        or isinstance(bridge_seed_count, bool)
        or variant_count != len(variants)
        or not 0 <= variant_count <= 24
        or not 0 <= seed_count <= 32
        or not 0 <= bridge_seed_count <= seed_count
        or bridge_seed_count != seed_count
        or variant_count > seed_count
    ):
        return None
    if value["status"] == "variant_analysis_plan_ready":
        if not variants or seed_count < 1:
            return None
    elif variants or variant_count != 0 or seed_count != 0 or bridge_seed_count != 0:
        return None

    source_hypothesis_refs = {item["hypothesis_id"] for item in source_hypotheses}
    seen_variant_ids: set[str] = set()
    for variant in variants:
        if not isinstance(variant, dict):
            return None
        variant_id = _worker_safe_string(variant.get("variant_id"))
        if (
            _VARIANT_ANALYSIS_ID_PATTERN.fullmatch(variant_id) is None
            or variant_id in seen_variant_ids
            or variant.get("source_hypothesis_id") not in source_hypothesis_refs
            or _CHAIN_TOKEN_PATTERN.fullmatch(
                _worker_safe_string(variant.get("family"))
            )
            is None
            or _CHAIN_TOKEN_PATTERN.fullmatch(
                _worker_safe_string(variant.get("vuln_type"))
            )
            is None
            or variant.get("status")
            not in {
                "planned_local_code_search_only",
                "unverified_hypothesis_from_confirmed_finding",
            }
            or variant.get("written") is not False
            or variant.get("execution_allowed") is not False
            or variant.get("human_review_required") is not True
        ):
            return None
        seen_variant_ids.add(variant_id)
    return dict(value)


def _safe_variant_analysis_advisory_summary(value: object) -> dict | None:
    if not isinstance(value, dict):
        return None
    required_keys = {
        "status",
        "execution_mode",
        "variant_count",
        "seed_count",
        "offline_hint_count",
        "bridge_seed_count",
        "human_allow_export_write",
        "export_written",
        "export_count",
        "network_access",
        "live_validation",
        "process_spawn_allowed",
        "execution_allowed",
        "validation_allowed",
        "report_submission_allowed",
        "confirmed_vulnerability",
        "finding_promotion_allowed",
    }
    if set(value) != required_keys:
        return None
    variant_count = value.get("variant_count")
    seed_count = value.get("seed_count")
    offline_hint_count = value.get("offline_hint_count")
    bridge_seed_count = value.get("bridge_seed_count")
    if (
        value.get("status")
        not in {
            "variant_analysis_plan_ready",
            "variant_analysis_waiting_for_seeds",
            "variant_analysis_empty",
        }
        or value.get("execution_mode") != "plan_only"
        or value.get("human_allow_export_write") is not False
        or value.get("export_written") is not False
        or value.get("export_count") != 0
        or not isinstance(variant_count, int)
        or isinstance(variant_count, bool)
        or not isinstance(seed_count, int)
        or isinstance(seed_count, bool)
        or not isinstance(offline_hint_count, int)
        or isinstance(offline_hint_count, bool)
        or not isinstance(bridge_seed_count, int)
        or isinstance(bridge_seed_count, bool)
        or not 0 <= variant_count <= 24
        or not 0 <= seed_count <= 32
        or offline_hint_count != 0
        or bridge_seed_count != seed_count
        or variant_count > seed_count
        or any(
            value.get(field) is not False
            for field in (
                "network_access",
                "live_validation",
                "process_spawn_allowed",
                "execution_allowed",
                "validation_allowed",
                "report_submission_allowed",
                "confirmed_vulnerability",
                "finding_promotion_allowed",
            )
        )
    ):
        return None
    if value["status"] == "variant_analysis_plan_ready":
        if variant_count < 1 or seed_count < 1:
            return None
    elif variant_count != 0 or seed_count != 0 or bridge_seed_count != 0:
        return None
    return dict(value)


def _safe_variant_analysis_projection(
    value: object,
    *,
    pipeline_run_id: str,
    source_snapshot_digest: str,
    source_hypotheses: list[dict[str, str]],
    exploit_chain_projection: dict,
) -> dict | None:
    if not isinstance(value, dict):
        return None
    required_keys = {
        "schema_version",
        "artifact_kind",
        "pipeline_run_id",
        "source_snapshot_digest",
        "source_hypothesis_refs",
        "source_hypothesis_digest",
        "exploit_chain_projection_digest",
        "variant_analysis",
        "variant_analysis_digest",
        "human_review_required",
        "raw_payload_processed",
        "execution_allowed",
        "dispatch_allowed",
        "validation_allowed",
        "candidate_promotion_allowed",
        "report_submission_allowed",
    }
    if set(value) != required_keys:
        return None
    source_hypothesis_refs = [item["hypothesis_id"] for item in source_hypotheses]
    variant_analysis = _safe_variant_analysis_advisory_summary(
        value.get("variant_analysis")
    )
    if (
        value.get("schema_version")
        != _AUTONOMOUS_VARIANT_ANALYSIS_PROJECTION_SCHEMA
        or value.get("artifact_kind") != "variant_analysis_projection"
        or value.get("pipeline_run_id") != pipeline_run_id
        or value.get("source_snapshot_digest") != source_snapshot_digest
        or value.get("source_hypothesis_refs") != source_hypothesis_refs
        or value.get("source_hypothesis_digest")
        != _canonical_digest(source_hypotheses)
        or value.get("exploit_chain_projection_digest")
        != _canonical_digest(exploit_chain_projection)
        or variant_analysis is None
        or value.get("variant_analysis_digest")
        != _canonical_digest(variant_analysis)
        or value.get("human_review_required") is not True
        or value.get("raw_payload_processed") is not False
        or any(
            value.get(field) is not False
            for field in (
                "execution_allowed",
                "dispatch_allowed",
                "validation_allowed",
                "candidate_promotion_allowed",
                "report_submission_allowed",
            )
        )
    ):
        return None
    return dict(value)


def _build_deep_code_reasoning_projection(
    *,
    plan_payload: object,
    pipeline_run_id: str,
    source_snapshot_digest: str,
    source_hypotheses: list[dict[str, str]],
    exploit_chain_projection: dict,
    variant_analysis_projection: dict,
) -> dict | None:
    full_plan = _safe_deep_code_reasoning_plan(
        plan_payload,
        pipeline_run_id=pipeline_run_id,
        source_hypotheses=source_hypotheses,
    )
    if full_plan is None:
        return None
    deep_code_reasoning = _deep_code_reasoning_advisory_summary(full_plan)
    source_hypothesis_refs = [item["hypothesis_id"] for item in source_hypotheses]
    return {
        "schema_version": _AUTONOMOUS_DEEP_CODE_REASONING_PROJECTION_SCHEMA,
        "artifact_kind": "deep_code_reasoning_projection",
        "pipeline_run_id": pipeline_run_id,
        "source_snapshot_digest": source_snapshot_digest,
        "source_hypothesis_refs": source_hypothesis_refs,
        "source_hypothesis_digest": _canonical_digest(source_hypotheses),
        "exploit_chain_projection_digest": _canonical_digest(
            exploit_chain_projection
        ),
        "variant_analysis_projection_digest": _canonical_digest(
            variant_analysis_projection
        ),
        "deep_code_reasoning": deep_code_reasoning,
        "deep_code_reasoning_digest": _canonical_digest(deep_code_reasoning),
        "human_review_required": True,
        "raw_payload_processed": False,
        "execution_allowed": False,
        "dispatch_allowed": False,
        "validation_allowed": False,
        "candidate_promotion_allowed": False,
        "report_submission_allowed": False,
    }


def _deep_code_reasoning_advisory_summary(plan: dict) -> dict:
    return {
        "status": plan["status"],
        "execution_mode": "plan_only",
        "path_count": plan["path_count"],
        "permission_model_count": plan["permission_model_count"],
        "seed_count": plan["seed_count"],
        "offline_hint_count": plan["offline_hint_count"],
        "human_allow_export_write": False,
        "export_written": False,
        "export_count": 0,
        "network_access": False,
        "live_validation": False,
        "process_spawn_allowed": False,
        "execution_allowed": False,
        "validation_allowed": False,
        "report_submission_allowed": False,
        "confirmed_vulnerability": False,
        "finding_promotion_allowed": False,
    }


def _safe_deep_code_reasoning_plan(
    value: object,
    *,
    pipeline_run_id: str,
    source_hypotheses: list[dict[str, str]],
) -> dict | None:
    if not isinstance(value, dict):
        return None
    paths = value.get("paths")
    permission_models = value.get("permission_models")
    path_count = value.get("path_count")
    permission_model_count = value.get("permission_model_count")
    seed_count = value.get("seed_count")
    allowed_statuses = {
        "deep_code_reasoning_plan_ready",
        "deep_code_reasoning_waiting_for_seeds",
        "deep_code_reasoning_empty",
    }
    if (
        value.get("stage") != "v4_deep_code_reasoning"
        or value.get("package_id") != f"pipeline_run:{pipeline_run_id}"
        or value.get("package_root") != ""
        or value.get("execution_mode") != "plan_only"
        or value.get("status") not in allowed_statuses
        or value.get("human_allow_export_write") is not False
        or value.get("export_written") is not False
        or value.get("export_count") != 0
        or value.get("offline_hint_count") != 0
        or value.get("network_access") is not False
        or value.get("live_validation") is not False
        or value.get("process_spawn_allowed") is not False
        or value.get("execution_allowed") is not False
        or value.get("validation_allowed") is not False
        or value.get("report_submission_allowed") is not False
        or value.get("confirmed_vulnerability") is not False
        or value.get("finding_promotion_allowed") is not False
        or value.get("human_approval_required_before_action") is not True
        or not isinstance(paths, list)
        or not isinstance(permission_models, list)
        or not isinstance(path_count, int)
        or isinstance(path_count, bool)
        or not isinstance(permission_model_count, int)
        or isinstance(permission_model_count, bool)
        or not isinstance(seed_count, int)
        or isinstance(seed_count, bool)
        or path_count != len(paths)
        or permission_model_count != len(permission_models)
        or not 0 <= path_count <= 24
        or not 0 <= permission_model_count <= 16
        or not 0 <= seed_count <= 32
    ):
        return None
    if value["status"] == "deep_code_reasoning_plan_ready":
        if not paths or not permission_models:
            return None
    elif paths or permission_models:
        return None

    source_hypothesis_refs = {item["hypothesis_id"] for item in source_hypotheses}
    seen_path_ids: set[str] = set()
    for path in paths:
        if not isinstance(path, dict):
            return None
        path_id = _worker_safe_string(path.get("path_id"))
        if (
            _DEEP_CODE_REASONING_PATH_ID_PATTERN.fullmatch(path_id) is None
            or path_id in seen_path_ids
            or path.get("source_hypothesis_id") not in source_hypothesis_refs
            or _CHAIN_TOKEN_PATTERN.fullmatch(
                _worker_safe_string(path.get("family"))
            )
            is None
            or _CHAIN_TOKEN_PATTERN.fullmatch(
                _worker_safe_string(path.get("vuln_type"))
            )
            is None
            or path.get("execution_allowed") is not False
            or path.get("human_review_required") is not True
            or path.get("written") is not False
        ):
            return None
        seen_path_ids.add(path_id)

    seen_model_ids: set[str] = set()
    for model in permission_models:
        if not isinstance(model, dict):
            return None
        model_id = _worker_safe_string(model.get("model_id"))
        if (
            _DEEP_CODE_REASONING_MODEL_ID_PATTERN.fullmatch(model_id) is None
            or model_id in seen_model_ids
            or model.get("execution_allowed") is not False
            or model.get("human_review_required") is not True
        ):
            return None
        seen_model_ids.add(model_id)
    return dict(value)


def _safe_deep_code_reasoning_advisory_summary(value: object) -> dict | None:
    if not isinstance(value, dict):
        return None
    required_keys = {
        "status",
        "execution_mode",
        "path_count",
        "permission_model_count",
        "seed_count",
        "offline_hint_count",
        "human_allow_export_write",
        "export_written",
        "export_count",
        "network_access",
        "live_validation",
        "process_spawn_allowed",
        "execution_allowed",
        "validation_allowed",
        "report_submission_allowed",
        "confirmed_vulnerability",
        "finding_promotion_allowed",
    }
    if set(value) != required_keys:
        return None
    path_count = value.get("path_count")
    permission_model_count = value.get("permission_model_count")
    seed_count = value.get("seed_count")
    offline_hint_count = value.get("offline_hint_count")
    if (
        value.get("status")
        not in {
            "deep_code_reasoning_plan_ready",
            "deep_code_reasoning_waiting_for_seeds",
            "deep_code_reasoning_empty",
        }
        or value.get("execution_mode") != "plan_only"
        or value.get("human_allow_export_write") is not False
        or value.get("export_written") is not False
        or value.get("export_count") != 0
        or not isinstance(path_count, int)
        or isinstance(path_count, bool)
        or not isinstance(permission_model_count, int)
        or isinstance(permission_model_count, bool)
        or not isinstance(seed_count, int)
        or isinstance(seed_count, bool)
        or not isinstance(offline_hint_count, int)
        or isinstance(offline_hint_count, bool)
        or not 0 <= path_count <= 24
        or not 0 <= permission_model_count <= 16
        or not 0 <= seed_count <= 32
        or offline_hint_count != 0
        or any(
            value.get(field) is not False
            for field in (
                "network_access",
                "live_validation",
                "process_spawn_allowed",
                "execution_allowed",
                "validation_allowed",
                "report_submission_allowed",
                "confirmed_vulnerability",
                "finding_promotion_allowed",
            )
        )
    ):
        return None
    if value["status"] == "deep_code_reasoning_plan_ready":
        if path_count < 1 or permission_model_count < 1:
            return None
    elif path_count != 0 or permission_model_count != 0:
        return None
    return dict(value)


def _safe_deep_code_reasoning_projection(
    value: object,
    *,
    pipeline_run_id: str,
    source_snapshot_digest: str,
    source_hypotheses: list[dict[str, str]],
    exploit_chain_projection: dict,
    variant_analysis_projection: dict,
) -> dict | None:
    if not isinstance(value, dict):
        return None
    required_keys = {
        "schema_version",
        "artifact_kind",
        "pipeline_run_id",
        "source_snapshot_digest",
        "source_hypothesis_refs",
        "source_hypothesis_digest",
        "exploit_chain_projection_digest",
        "variant_analysis_projection_digest",
        "deep_code_reasoning",
        "deep_code_reasoning_digest",
        "human_review_required",
        "raw_payload_processed",
        "execution_allowed",
        "dispatch_allowed",
        "validation_allowed",
        "candidate_promotion_allowed",
        "report_submission_allowed",
    }
    if set(value) != required_keys:
        return None
    source_hypothesis_refs = [item["hypothesis_id"] for item in source_hypotheses]
    deep_code_reasoning = _safe_deep_code_reasoning_advisory_summary(
        value.get("deep_code_reasoning")
    )
    if (
        value.get("schema_version")
        != _AUTONOMOUS_DEEP_CODE_REASONING_PROJECTION_SCHEMA
        or value.get("artifact_kind") != "deep_code_reasoning_projection"
        or value.get("pipeline_run_id") != pipeline_run_id
        or value.get("source_snapshot_digest") != source_snapshot_digest
        or value.get("source_hypothesis_refs") != source_hypothesis_refs
        or value.get("source_hypothesis_digest")
        != _canonical_digest(source_hypotheses)
        or value.get("exploit_chain_projection_digest")
        != _canonical_digest(exploit_chain_projection)
        or value.get("variant_analysis_projection_digest")
        != _canonical_digest(variant_analysis_projection)
        or deep_code_reasoning is None
        or value.get("deep_code_reasoning_digest")
        != _canonical_digest(deep_code_reasoning)
        or value.get("human_review_required") is not True
        or value.get("raw_payload_processed") is not False
        or any(
            value.get(field) is not False
            for field in (
                "execution_allowed",
                "dispatch_allowed",
                "validation_allowed",
                "candidate_promotion_allowed",
                "report_submission_allowed",
            )
        )
    ):
        return None
    return dict(value)


def _runtime_variant_analysis_projection_for_report(
    *,
    task: CampaignTaskRecord,
    campaign: CampaignRecord,
    pipeline_run: Any,
    repository: DatabaseRepository,
) -> tuple[dict | None, PipelineStageRecord | None, str | None]:
    task_payload = task.payload if isinstance(task.payload, dict) else {}
    source_snapshot_digest = _worker_safe_string(
        task_payload.get("source_snapshot_digest")
    )
    pipeline_payload = (
        pipeline_run.payload if isinstance(pipeline_run.payload, dict) else {}
    )
    hypotheses = pipeline_payload.get("hypotheses")
    if _SOURCE_SNAPSHOT_DIGEST_PATTERN.fullmatch(source_snapshot_digest) is None:
        return None, None, "variant_analysis_projection_invalid"
    specialist_tasks = [
        candidate
        for candidate in repository.list_campaign_tasks(campaign.id)
        if candidate.task_type == "variant_analysis"
        and candidate.status == "completed"
        and isinstance(candidate.payload, dict)
        and candidate.payload.get("runtime_schema")
        == _AUTONOMOUS_RESEARCH_RUNTIME_SCHEMA
        and candidate.payload.get("pipeline_run_id") == pipeline_run.id
        and candidate.payload.get("source_snapshot_digest") == source_snapshot_digest
    ]
    if not specialist_tasks:
        return None, None, None
    if len(specialist_tasks) != 1:
        return None, None, "variant_analysis_projection_invalid"
    if not isinstance(hypotheses, list):
        return None, None, "variant_analysis_projection_invalid"
    source_hypotheses = _chain_reasoning_hypothesis_seeds(hypotheses)
    specialist_task = specialist_tasks[0]
    projection_ref = f"variant_analysis_projection:{specialist_task.id}"
    if projection_ref not in specialist_task.output_refs:
        return None, None, "variant_analysis_projection_invalid"

    (
        exploit_chain_projection,
        chain_task,
        _,
        exploit_chain_stop_reason,
    ) = _runtime_exploit_chain_projection_with_provenance(
        task=task,
        campaign=campaign,
        pipeline_run=pipeline_run,
        hypotheses=hypotheses,
        repository=repository,
    )
    if (
        exploit_chain_stop_reason is not None
        or exploit_chain_projection is None
        or chain_task is None
    ):
        return None, None, "variant_analysis_projection_invalid"
    expected_input_refs = [
        f"pipeline_run:{pipeline_run.id}",
        f"source_snapshot:{source_snapshot_digest}",
        f"exploit_chain_projection:{chain_task.id}",
    ]
    runtime_stages = [
        stage
        for stage in repository.list_campaign_pipeline_stages(campaign.id)
        if stage.task_id == specialist_task.id
        and stage.stage_key == "autonomous_research:variant_analysis"
        and stage.status == "completed"
        and stage.safety_gate_state == "allowed"
        and stage.input_refs == specialist_task.input_refs
        and stage.output_refs == specialist_task.output_refs
        and isinstance(stage.payload, dict)
        and stage.payload.get("runtime_schema")
        == _AUTONOMOUS_RESEARCH_RUNTIME_SCHEMA
        and stage.payload.get("source_snapshot_digest") == source_snapshot_digest
        and projection_ref in stage.output_refs
    ]
    stages = [
        stage
        for stage in repository.list_pipeline_stages_for_run(pipeline_run.id)
        if stage.task_id == specialist_task.id
        and stage.campaign_id == campaign.id
        and stage.stage_key == "autonomous_variant_analysis"
        and stage.status == "completed"
        and stage.safety_gate_state == "safe"
        and stage.input_refs == expected_input_refs
        and stage.output_refs == [projection_ref]
    ]
    agent_runs = [
        run
        for run in repository.list_campaign_agent_runs(campaign.id)
        if run.task_id == specialist_task.id
        and run.status == "completed"
        and run.safety_gate_state == "allowed"
        and projection_ref in run.output_refs
    ]
    if len(runtime_stages) != 1 or len(stages) != 1 or len(agent_runs) != 1:
        return None, None, "variant_analysis_projection_invalid"
    projection = _safe_variant_analysis_projection(
        agent_runs[0].payload,
        pipeline_run_id=pipeline_run.id,
        source_snapshot_digest=source_snapshot_digest,
        source_hypotheses=source_hypotheses,
        exploit_chain_projection=exploit_chain_projection,
    )
    if projection is None or stages[0].payload != projection:
        return None, None, "variant_analysis_projection_invalid"
    return projection, stages[0], None


def _runtime_deep_code_reasoning_projection_for_report(
    *,
    task: CampaignTaskRecord,
    campaign: CampaignRecord,
    pipeline_run: Any,
    repository: DatabaseRepository,
) -> tuple[dict | None, PipelineStageRecord | None, str | None]:
    task_payload = task.payload if isinstance(task.payload, dict) else {}
    source_snapshot_digest = _worker_safe_string(
        task_payload.get("source_snapshot_digest")
    )
    pipeline_payload = (
        pipeline_run.payload if isinstance(pipeline_run.payload, dict) else {}
    )
    hypotheses = pipeline_payload.get("hypotheses")
    if _SOURCE_SNAPSHOT_DIGEST_PATTERN.fullmatch(source_snapshot_digest) is None:
        return None, None, "deep_code_reasoning_projection_invalid"
    specialist_tasks = [
        candidate
        for candidate in repository.list_campaign_tasks(campaign.id)
        if candidate.task_type == "deep_code_reasoning"
        and candidate.status == "completed"
        and isinstance(candidate.payload, dict)
        and candidate.payload.get("runtime_schema")
        == _AUTONOMOUS_RESEARCH_RUNTIME_SCHEMA
        and candidate.payload.get("pipeline_run_id") == pipeline_run.id
        and candidate.payload.get("source_snapshot_digest") == source_snapshot_digest
    ]
    if not specialist_tasks:
        return None, None, None
    if len(specialist_tasks) != 1:
        return None, None, "deep_code_reasoning_projection_invalid"
    if not isinstance(hypotheses, list):
        return None, None, "deep_code_reasoning_projection_invalid"
    source_hypotheses = _chain_reasoning_hypothesis_seeds(hypotheses)
    specialist_task = specialist_tasks[0]
    projection_ref = f"deep_code_reasoning_projection:{specialist_task.id}"
    if projection_ref not in specialist_task.output_refs:
        return None, None, "deep_code_reasoning_projection_invalid"

    (
        exploit_chain_projection,
        chain_task,
        _,
        exploit_chain_stop_reason,
    ) = _runtime_exploit_chain_projection_with_provenance(
        task=task,
        campaign=campaign,
        pipeline_run=pipeline_run,
        hypotheses=hypotheses,
        repository=repository,
    )
    if (
        exploit_chain_stop_reason is not None
        or exploit_chain_projection is None
        or chain_task is None
    ):
        return None, None, "deep_code_reasoning_projection_invalid"
    variant_analysis_projection, variant_stage, variant_stop_reason = (
        _runtime_variant_analysis_projection_for_report(
            task=task,
            campaign=campaign,
            pipeline_run=pipeline_run,
            repository=repository,
        )
    )
    if (
        variant_stop_reason is not None
        or variant_analysis_projection is None
        or variant_stage is None
    ):
        return None, None, "deep_code_reasoning_projection_invalid"
    expected_input_refs = [
        f"pipeline_run:{pipeline_run.id}",
        f"source_snapshot:{source_snapshot_digest}",
        f"exploit_chain_projection:{chain_task.id}",
        f"variant_analysis_projection:{variant_stage.task_id}",
    ]
    runtime_stages = [
        stage
        for stage in repository.list_campaign_pipeline_stages(campaign.id)
        if stage.task_id == specialist_task.id
        and stage.stage_key == "autonomous_research:deep_code_reasoning"
        and stage.status == "completed"
        and stage.safety_gate_state == "allowed"
        and stage.input_refs == specialist_task.input_refs
        and stage.output_refs == specialist_task.output_refs
        and isinstance(stage.payload, dict)
        and stage.payload.get("runtime_schema")
        == _AUTONOMOUS_RESEARCH_RUNTIME_SCHEMA
        and stage.payload.get("source_snapshot_digest") == source_snapshot_digest
        and projection_ref in stage.output_refs
    ]
    stages = [
        stage
        for stage in repository.list_pipeline_stages_for_run(pipeline_run.id)
        if stage.task_id == specialist_task.id
        and stage.campaign_id == campaign.id
        and stage.stage_key == "autonomous_deep_code_reasoning"
        and stage.status == "completed"
        and stage.safety_gate_state == "safe"
        and stage.input_refs == expected_input_refs
        and stage.output_refs == [projection_ref]
    ]
    agent_runs = [
        run
        for run in repository.list_campaign_agent_runs(campaign.id)
        if run.task_id == specialist_task.id
        and run.status == "completed"
        and run.safety_gate_state == "allowed"
        and projection_ref in run.output_refs
    ]
    if len(runtime_stages) != 1 or len(stages) != 1 or len(agent_runs) != 1:
        return None, None, "deep_code_reasoning_projection_invalid"
    projection = _safe_deep_code_reasoning_projection(
        agent_runs[0].payload,
        pipeline_run_id=pipeline_run.id,
        source_snapshot_digest=source_snapshot_digest,
        source_hypotheses=source_hypotheses,
        exploit_chain_projection=exploit_chain_projection,
        variant_analysis_projection=variant_analysis_projection,
    )
    if projection is None or stages[0].payload != projection:
        return None, None, "deep_code_reasoning_projection_invalid"
    return projection, stages[0], None


def _exploit_chain_context_fact(projection: dict | None) -> dict:
    if not isinstance(projection, dict):
        return {
            "artifact_kind": "exploit_chain_plan",
            "fact_type": "exploit_chain_reasoning_missing",
        }
    return {
        "artifact_kind": "exploit_chain_plan",
        "fact_type": "exploit_chain_reasoning",
        "chain_count": projection["chain_count"],
        "chain_plan_digest": projection["chain_plan_digest"],
        "source_hypothesis_digest": projection["source_hypothesis_digest"],
    }


def _run_finding_dedup_and_rank_task(
    *,
    task: CampaignTaskRecord,
    campaign: CampaignRecord,
    repository: DatabaseRepository,
) -> dict:
    from app.autonomous_research_runtime import record_autonomous_research_task_completion
    from app.candidate_hunter_loop import load_candidate_hunter_projection
    from app.finding_dedup_risk import build_finding_dedup_risk

    task_payload = task.payload if isinstance(task.payload, dict) else {}
    pipeline_run_id = task_payload.get("pipeline_run_id")
    pipeline_run = (
        repository.get_pipeline_run(pipeline_run_id)
        if isinstance(pipeline_run_id, str)
        else None
    )
    pipeline_payload = pipeline_run.payload if pipeline_run is not None else {}
    if (
        pipeline_run is None
        or pipeline_run.asset != campaign.default_asset
        or pipeline_run.scope_status != "in_scope"
        or not isinstance(pipeline_payload, dict)
        or pipeline_payload.get("campaign_id") != campaign.id
    ):
        return _block_agent_task(
            task=task,
            repository=repository,
            stop_reason="candidate_hunter_projection_missing",
        )

    projection, projection_stop_reason = (
        _runtime_candidate_hunter_projection_for_downstream(
            task=task,
            campaign=campaign,
            pipeline_run=pipeline_run,
            repository=repository,
        )
    )
    if projection_stop_reason is not None:
        return _block_agent_task(
            task=task,
            repository=repository,
            stop_reason=projection_stop_reason,
        )
    if projection is None:
        projection = load_candidate_hunter_projection(
            repository=repository,
            pipeline_run_id=pipeline_run.id,
        )
    final_candidates = projection.get("final_candidates")
    decisions = projection.get("candidate_decisions")
    if (
        projection.get("status") != "ready"
        or not isinstance(final_candidates, list)
        or not isinstance(decisions, list)
    ):
        return _block_agent_task(
            task=task,
            repository=repository,
            stop_reason="candidate_hunter_projection_invalid",
        )

    retained_ids = {
        _worker_safe_string(decision.get("candidate_id"))
        for decision in decisions
        if isinstance(decision, dict)
        and decision.get("disposition") == "retained"
        and _worker_safe_string(decision.get("candidate_id"))
    }
    retained_decisions_by_id = {
        _worker_safe_string(decision.get("candidate_id")): decision
        for decision in decisions
        if isinstance(decision, dict)
        and decision.get("disposition") == "retained"
        and _worker_safe_string(decision.get("candidate_id"))
    }
    excluded_candidate_ids = {
        candidate_id
        for decision in decisions
        if isinstance(decision, dict)
        if decision.get("disposition") != "retained"
        if (candidate_id := _worker_safe_string(decision.get("candidate_id")))
    }
    historical_reports = _historical_report_candidates(
        repository=repository,
        campaign=campaign,
        pipeline_run=pipeline_run,
        source_snapshot_digest=_worker_safe_string(
            task_payload.get("source_snapshot_digest")
        ),
        historical_report_stage_ids=_finding_dedup_historical_report_stage_ids(task),
    )
    cross_run_duplicates = []
    rankable_candidates = []
    for candidate in final_candidates:
        if not isinstance(candidate, dict):
            return _block_agent_task(
                task=task,
                repository=repository,
                stop_reason="candidate_hunter_projection_invalid",
            )
        candidate_id = _worker_safe_string(candidate.get("candidate_id"))
        if candidate_id not in retained_ids:
            continue
        decision = retained_decisions_by_id.get(candidate_id)
        if decision is None:
            return _block_agent_task(
                task=task,
                repository=repository,
                stop_reason="candidate_hunter_projection_invalid",
            )
        if any(
            candidate.get(field) is not False
            for field in (
                "execution_allowed",
                "dispatch_allowed",
                "validation_allowed",
                "candidate_promotion_allowed",
                "report_submission_allowed",
            )
        ):
            return _block_agent_task(
                task=task,
                repository=repository,
                stop_reason="candidate_hunter_projection_invalid",
            )
        candidate_fingerprint = _candidate_fingerprint(candidate)
        prior_report = (
            historical_reports.get(candidate_fingerprint)
            if candidate_fingerprint is not None
            else None
        )
        if prior_report is not None:
            excluded_candidate_ids.add(candidate_id)
            cross_run_duplicates.append(
                {
                    "candidate_id": candidate_id,
                    "candidate_fingerprint": candidate_fingerprint,
                    "duplicate_of": prior_report,
                }
            )
            continue
        rankable_candidates.append(
            {
                "candidate_id": candidate_id,
                "survived_kill_score": _candidate_ranking_score(
                    candidate=candidate,
                    decision=decision,
                    field="survived_kill_score",
                ),
                "evidence_completeness_score": _candidate_ranking_score(
                    candidate=candidate,
                    decision=decision,
                    field="evidence_completeness_score",
                ),
                "priority_score": _candidate_ranking_score(
                    candidate=candidate,
                    decision=decision,
                    field="priority_score",
                ),
            }
        )
    ranked_candidates = sorted(
        rankable_candidates,
        key=lambda candidate: (
            -candidate["survived_kill_score"],
            -candidate["evidence_completeness_score"],
            -candidate["priority_score"],
            candidate["candidate_id"],
        ),
    )[:5]
    top_candidates = [
        {
            "candidate_id": candidate["candidate_id"],
            "rank": rank,
            "survived_kill_score": candidate["survived_kill_score"],
            "evidence_completeness_score": candidate["evidence_completeness_score"],
            "priority_score": candidate["priority_score"],
            "execution_allowed": False,
            "dispatch_allowed": False,
            "validation_allowed": False,
            "candidate_promotion_allowed": False,
            "report_submission_allowed": False,
        }
        for rank, candidate in enumerate(ranked_candidates, start=1)
    ]
    ranking_payload = {
        "schema_version": "autonomous_finding_dedup_and_rank_v1",
        "pipeline_run_id": pipeline_run.id,
        "idempotency_key": sha256(
            f"{task.id}:{pipeline_run.id}:finding_dedup_and_rank".encode("utf-8")
        ).hexdigest(),
        "top_candidates": top_candidates,
        "excluded_candidate_ids": sorted(excluded_candidate_ids),
        "cross_run_duplicates": sorted(
            cross_run_duplicates,
            key=lambda item: item["candidate_id"],
        ),
        "submission_blocked": True,
        "raw_payload_processed": False,
        "execution_allowed": False,
        "dispatch_allowed": False,
        "validation_allowed": False,
        "candidate_promotion_allowed": False,
        "report_submission_allowed": False,
    }
    finding_dedup_risk_projection = None
    if task_payload.get("runtime_schema") == _AUTONOMOUS_RESEARCH_RUNTIME_SCHEMA:
        source_snapshot_digest = _worker_safe_string(
            task_payload.get("source_snapshot_digest")
        )
        if _SOURCE_SNAPSHOT_DIGEST_PATTERN.fullmatch(source_snapshot_digest) is None:
            return _block_agent_task(
                task=task,
                repository=repository,
                stop_reason="finding_dedup_risk_projection_invalid",
            )
        try:
            finding_dedup_risk_plan = build_finding_dedup_risk(
                package_id=f"pipeline_run:{pipeline_run.id}",
                bridge_result={
                    "package_id": f"pipeline_run:{pipeline_run.id}",
                    "scope_allowed": True,
                    "candidates": final_candidates,
                },
                human_allow_export_write=False,
            ).to_dict()
        except (TypeError, ValueError):
            return _block_agent_task(
                task=task,
                repository=repository,
                stop_reason="finding_dedup_risk_projection_invalid",
            )
        finding_dedup_risk_projection = _build_finding_dedup_risk_projection(
            plan_payload=finding_dedup_risk_plan,
            pipeline_run_id=pipeline_run.id,
            source_snapshot_digest=source_snapshot_digest,
            final_candidates=final_candidates,
            candidate_decisions=decisions,
            ranking_payload=ranking_payload,
        )
        if finding_dedup_risk_projection is None:
            return _block_agent_task(
                task=task,
                repository=repository,
                stop_reason="finding_dedup_risk_projection_invalid",
            )
    ranking_stage = repository.save_pipeline_stage(
        pipeline_run_id=pipeline_run.id,
        campaign_id=campaign.id,
        task_id=task.id,
        stage_key="autonomous_finding_dedup_and_rank",
        stage_order=30,
        status="completed",
        input_refs=[f"pipeline_run:{pipeline_run.id}"],
        output_refs=[],
        safety_gate_state="safe",
        stop_reason=None,
        payload=ranking_payload,
    )
    finding_dedup_risk_stage = None
    finding_dedup_risk_ref = None
    if finding_dedup_risk_projection is not None:
        finding_dedup_risk_ref = f"finding_dedup_risk_projection:{task.id}"
        finding_dedup_risk_stage = repository.save_pipeline_stage(
            pipeline_run_id=pipeline_run.id,
            campaign_id=campaign.id,
            task_id=task.id,
            stage_key="autonomous_finding_dedup_risk",
            stage_order=31,
            status="completed",
            input_refs=[
                f"pipeline_run:{pipeline_run.id}",
                f"pipeline_stage:{ranking_stage.id}",
            ],
            output_refs=[finding_dedup_risk_ref],
            safety_gate_state="safe",
            stop_reason=None,
            payload=finding_dedup_risk_projection,
        )
    output_refs = [
        f"pipeline_run:{pipeline_run.id}",
        f"pipeline_stage:{ranking_stage.id}",
    ]
    if finding_dedup_risk_stage is not None and finding_dedup_risk_ref is not None:
        output_refs.extend(
            [
                f"pipeline_stage:{finding_dedup_risk_stage.id}",
                finding_dedup_risk_ref,
            ]
        )
    agent_run_payload = {
        "artifact_kind": "candidate_dedup_projection",
        "pipeline_run_id": pipeline_run.id,
        "top_candidate_count": len(top_candidates),
        "finding_dedup_risk_attached": finding_dedup_risk_stage is not None,
        "raw_payload_processed": False,
        "execution_allowed": False,
        "dispatch_allowed": False,
        "validation_allowed": False,
        "candidate_promotion_allowed": False,
        "report_submission_allowed": False,
    }
    completed_execution = _finish_task_execution(
        task=task,
        repository=repository,
        task_status="completed",
        output_refs=output_refs,
        agent_status="completed",
        agent_output_refs=output_refs,
        safety_gate_state="allowed",
        stop_reason=None,
        payload=agent_run_payload,
    )
    if completed_execution is None:
        return _execution_lease_lost_result(task=task, repository=repository)
    completed_task, agent_run = completed_execution
    record_autonomous_research_task_completion(
        task=completed_task,
        repository=repository,
    )
    return {
        "status": "completed",
        "task_id": task.id,
        "agent_run_id": agent_run.id,
        "stop_reason": None,
    }


def _projection_score(value: object) -> int | float:
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return max(0, value)
    return 0


def _candidate_ranking_score(
    *,
    candidate: dict,
    decision: dict,
    field: str,
) -> int | float:
    value = candidate.get(field)
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return _projection_score(value)
    return _projection_score(decision.get(field))


def _historical_report_candidates(
    *,
    repository: DatabaseRepository,
    campaign: CampaignRecord,
    pipeline_run: Any,
    source_snapshot_digest: str,
    historical_report_stage_ids: set[str] | None = None,
) -> dict[str, dict[str, str]]:
    history: list[tuple[tuple[str, str, str, str], str, dict[str, str]]] = []
    for prior_run in repository.list_pipeline_runs():
        if not _same_report_dedup_boundary(
            prior_run=prior_run,
            campaign=campaign,
            pipeline_run=pipeline_run,
        ):
            continue
        for stage in repository.list_pipeline_stages_for_run(prior_run.id):
            if (
                historical_report_stage_ids is not None
                and stage.id not in historical_report_stage_ids
            ):
                continue
            for provenance in _trusted_report_stage_provenance(
                stage=stage,
                pipeline_run=prior_run,
                repository=repository,
            ):
                if provenance["source_snapshot_digest"] != source_snapshot_digest:
                    continue
                history.append(
                    (
                        (
                            str(prior_run.created_at),
                            prior_run.id,
                            str(stage.created_at),
                            stage.id,
                        ),
                        provenance["candidate_fingerprint"],
                        {
                            "pipeline_run_id": prior_run.id,
                            "pipeline_stage_id": stage.id,
                            "candidate_id": provenance["candidate_id"],
                            "source_snapshot_digest": provenance[
                                "source_snapshot_digest"
                            ],
                        },
                    )
                )
    canonical: dict[str, dict[str, str]] = {}
    for _sort_key, fingerprint, candidate in sorted(history):
        canonical.setdefault(fingerprint, candidate)
    return canonical


def historical_report_stage_refs_for_dedup(
    *,
    campaign: CampaignRecord,
    repository: DatabaseRepository,
    pipeline_run_id: str,
    source_snapshot_digest: str,
) -> list[str]:
    if _SOURCE_SNAPSHOT_DIGEST_PATTERN.fullmatch(source_snapshot_digest) is None:
        return []
    pipeline_run = repository.get_pipeline_run(pipeline_run_id)
    if pipeline_run is None:
        return []
    stage_ids: set[str] = set()
    for prior_run in repository.list_pipeline_runs():
        if not _same_report_dedup_boundary(
            prior_run=prior_run,
            campaign=campaign,
            pipeline_run=pipeline_run,
        ):
            continue
        for stage in repository.list_pipeline_stages_for_run(prior_run.id):
            if (
                _HISTORICAL_REPORT_STAGE_INPUT_REF_PATTERN.fullmatch(
                    f"historical_report_stage:{stage.id}"
                )
                is None
            ):
                continue
            if any(
                provenance["source_snapshot_digest"] == source_snapshot_digest
                for provenance in _trusted_report_stage_provenance(
                    stage=stage,
                    pipeline_run=prior_run,
                    repository=repository,
                )
            ):
                stage_ids.add(stage.id)
    return [f"historical_report_stage:{stage_id}" for stage_id in sorted(stage_ids)]


def _finding_dedup_historical_report_stage_ids(
    task: CampaignTaskRecord,
) -> set[str] | None:
    payload = task.payload if isinstance(task.payload, dict) else {}
    if payload.get("runtime_schema") != _AUTONOMOUS_RESEARCH_RUNTIME_SCHEMA:
        return None
    input_refs = task.input_refs if isinstance(task.input_refs, list) else []
    return {
        match.group(1)
        for input_ref in input_refs
        if isinstance(input_ref, str)
        if (
            match := _HISTORICAL_REPORT_STAGE_INPUT_REF_PATTERN.fullmatch(input_ref)
        )
        is not None
    }


def _same_report_dedup_boundary(
    *,
    prior_run: Any,
    campaign: CampaignRecord,
    pipeline_run: Any,
) -> bool:
    if (
        prior_run.id == pipeline_run.id
        or prior_run.asset != pipeline_run.asset
        or prior_run.scope_status != "in_scope"
    ):
        return False
    prior_payload = prior_run.payload if isinstance(prior_run.payload, dict) else {}
    if prior_payload.get("campaign_id") == campaign.id:
        return True
    return (
        campaign.program_id is not None
        and pipeline_run.program_id == campaign.program_id
        and prior_run.program_id == campaign.program_id
    )


def _trusted_report_stage_provenance(
    *,
    stage: PipelineStageRecord,
    pipeline_run: Any,
    repository: DatabaseRepository,
) -> list[dict[str, Any]]:
    payload = stage.payload if isinstance(stage.payload, dict) else {}
    if (
        stage.stage_key != "autonomous_report_review"
        or stage.status != "completed"
        or stage.safety_gate_state != "awaiting_review"
        or stage.stop_reason != "human_review_required"
        or payload.get("schema_version") != _AUTONOMOUS_REPORT_REVIEW_SCHEMA
        or payload.get("pipeline_run_id") != pipeline_run.id
        or payload.get("submission_blocked") is not True
        or payload.get("human_review_required") is not True
        or payload.get("raw_payload_processed") is not False
        or any(
            payload.get(field) is not False
            for field in (
                "execution_allowed",
                "dispatch_allowed",
                "validation_allowed",
                "candidate_promotion_allowed",
                "report_submission_allowed",
            )
        )
    ):
        return []
    drafts = payload.get("report_drafts")
    provenance_records = payload.get("report_provenance")
    if (
        not isinstance(drafts, list)
        or not isinstance(provenance_records, list)
        or payload.get("report_provenance_digest")
        != _canonical_digest(provenance_records)
    ):
        return []
    drafts_by_candidate_id = {
        _worker_safe_string(draft.get("candidate_id")): draft
        for draft in drafts
        if isinstance(draft, dict) and _worker_safe_string(draft.get("candidate_id"))
    }
    if len(drafts_by_candidate_id) != len(drafts):
        return []
    trusted: list[dict[str, Any]] = []
    for provenance in provenance_records:
        if not _autonomous_report_provenance_is_valid(provenance):
            return []
        candidate_id = provenance["candidate_id"]
        draft = drafts_by_candidate_id.get(candidate_id)
        multi_engine_verdict = (
            draft.get("multi_engine_verdict") if isinstance(draft, dict) else None
        )
        falsification_summary = (
            draft.get("falsification_summary") if isinstance(draft, dict) else None
        )
        if (
            draft is None
            or draft.get("status") != "unverified_hypothesis"
            or draft.get("submission_blocked") is not True
            or draft.get("human_review_required") is not True
            or draft.get("execution_allowed") is not False
            or draft.get("validation_allowed") is not False
            or draft.get("report_submission_allowed") is not False
            or draft.get("confirmed_vulnerability") is not False
            or draft.get("autonomous_provenance") != provenance
            or provenance.get("pipeline_run_id") != pipeline_run.id
            or stage.campaign_id != provenance.get("campaign_id")
            or not _runtime_report_multi_engine_verdict_is_valid(
                multi_engine_verdict,
                candidate_id=candidate_id,
            )
            or provenance.get("multi_engine_status")
            != multi_engine_verdict.get("status")
            or provenance.get("multi_engine_verdict_digest")
            != _canonical_digest(multi_engine_verdict)
            or not _runtime_report_falsification_summary_is_valid(
                falsification_summary
            )
            or not isinstance(draft.get("report_draft"), dict)
            or draft["report_draft"].get("falsification_summary")
            != falsification_summary
            or provenance.get("falsification_status")
            != falsification_summary.get("decision_status")
            or provenance.get("falsification_summary_digest")
            != _canonical_digest(falsification_summary)
            or _report_draft_candidate_fingerprint(draft)
            != provenance.get("candidate_fingerprint")
            or not _report_provenance_stage_chain_is_valid(
                provenance=provenance,
                pipeline_run=pipeline_run,
                repository=repository,
            )
        ):
            return []
        trusted.append(provenance)
    if len(trusted) != len(drafts) or len(
        {item["candidate_id"] for item in trusted}
    ) != len(trusted):
        return []
    return trusted


def _report_draft_candidate_fingerprint(draft: dict) -> str | None:
    route_label = _worker_safe_string(draft.get("route"))
    route_parts = route_label.split(maxsplit=1)
    if len(route_parts) != 2:
        return None
    return _candidate_fingerprint(
        {
            "candidate_id": draft.get("candidate_id"),
            "vuln_type": draft.get("vuln_type"),
            "root_cause_id": draft.get("root_cause_id"),
            "route": {"method": route_parts[0], "path": route_parts[1]},
            "affected_code_path": draft.get("affected_code_path"),
            "source_fact_refs": draft.get("source_fact_refs"),
        }
    )


def _report_provenance_stage_chain_is_valid(
    *,
    provenance: dict[str, Any],
    pipeline_run: Any,
    repository: DatabaseRepository,
) -> bool:
    ranking_stage = repository.get_pipeline_stage(provenance["ranking_stage_id"])
    decision_stage = repository.get_pipeline_stage(
        provenance["candidate_decision_stage_id"]
    )
    ranking_payload = (
        ranking_stage.payload
        if ranking_stage is not None and isinstance(ranking_stage.payload, dict)
        else {}
    )
    decision_payload = (
        decision_stage.payload
        if decision_stage is not None and isinstance(decision_stage.payload, dict)
        else {}
    )
    persisted_decisions = decision_payload.get("candidate_decisions")
    candidate_id = provenance["candidate_id"]
    required_safety_fields = (
        "execution_allowed",
        "dispatch_allowed",
        "validation_allowed",
        "candidate_promotion_allowed",
        "report_submission_allowed",
    )
    finding_dedup_risk_stage_id = provenance.get("finding_dedup_risk_stage_id")
    finding_dedup_risk_projection_digest = provenance.get(
        "finding_dedup_risk_projection_digest"
    )
    if (finding_dedup_risk_stage_id is None) != (
        finding_dedup_risk_projection_digest is None
    ):
        return False
    finding_dedup_risk_is_valid = True
    if finding_dedup_risk_stage_id is not None:
        finding_dedup_risk_stage = repository.get_pipeline_stage(
            finding_dedup_risk_stage_id
        )
        finding_dedup_risk_payload = (
            finding_dedup_risk_stage.payload
            if finding_dedup_risk_stage is not None
            and isinstance(finding_dedup_risk_stage.payload, dict)
            else {}
        )
        finding_dedup_risk_summary = _safe_finding_dedup_risk_advisory_summary(
            finding_dedup_risk_payload.get("finding_dedup_risk")
        )
        finding_dedup_risk_is_valid = bool(
            finding_dedup_risk_stage is not None
            and ranking_stage is not None
            and finding_dedup_risk_stage.pipeline_run_id == pipeline_run.id
            and finding_dedup_risk_stage.campaign_id == provenance["campaign_id"]
            and finding_dedup_risk_stage.task_id == ranking_stage.task_id
            and finding_dedup_risk_stage.stage_key == "autonomous_finding_dedup_risk"
            and finding_dedup_risk_stage.status == "completed"
            and finding_dedup_risk_stage.safety_gate_state == "safe"
            and finding_dedup_risk_stage.input_refs
            == [
                f"pipeline_run:{pipeline_run.id}",
                f"pipeline_stage:{ranking_stage.id}",
            ]
            and finding_dedup_risk_payload.get("schema_version")
            == _AUTONOMOUS_FINDING_DEDUP_RISK_PROJECTION_SCHEMA
            and finding_dedup_risk_payload.get("artifact_kind")
            == "finding_dedup_risk_projection"
            and finding_dedup_risk_payload.get("pipeline_run_id") == pipeline_run.id
            and finding_dedup_risk_payload.get("source_snapshot_digest")
            == provenance["source_snapshot_digest"]
            and finding_dedup_risk_summary is not None
            and finding_dedup_risk_payload.get("finding_dedup_risk_digest")
            == _canonical_digest(finding_dedup_risk_summary)
            and finding_dedup_risk_payload.get("finding_dedup_risk_digest")
            == finding_dedup_risk_projection_digest
            and finding_dedup_risk_payload.get("human_review_required") is True
            and finding_dedup_risk_payload.get("raw_payload_processed") is False
            and all(
                finding_dedup_risk_payload.get(field) is False
                for field in required_safety_fields
            )
        )
    variant_analysis_stage_id = provenance.get("variant_analysis_stage_id")
    variant_analysis_projection_digest = provenance.get(
        "variant_analysis_projection_digest"
    )
    if (variant_analysis_stage_id is None) != (
        variant_analysis_projection_digest is None
    ):
        return False
    variant_analysis_is_valid = True
    if variant_analysis_stage_id is not None:
        variant_analysis_stage = repository.get_pipeline_stage(
            variant_analysis_stage_id
        )
        variant_analysis_payload = (
            variant_analysis_stage.payload
            if variant_analysis_stage is not None
            and isinstance(variant_analysis_stage.payload, dict)
            else {}
        )
        variant_analysis_summary = _safe_variant_analysis_advisory_summary(
            variant_analysis_payload.get("variant_analysis")
        )
        variant_analysis_is_valid = bool(
            variant_analysis_stage is not None
            and variant_analysis_stage.pipeline_run_id == pipeline_run.id
            and variant_analysis_stage.campaign_id == provenance["campaign_id"]
            and variant_analysis_stage.stage_key == "autonomous_variant_analysis"
            and variant_analysis_stage.status == "completed"
            and variant_analysis_stage.safety_gate_state == "safe"
            and variant_analysis_payload.get("schema_version")
            == _AUTONOMOUS_VARIANT_ANALYSIS_PROJECTION_SCHEMA
            and variant_analysis_payload.get("artifact_kind")
            == "variant_analysis_projection"
            and variant_analysis_payload.get("pipeline_run_id") == pipeline_run.id
            and variant_analysis_payload.get("source_snapshot_digest")
            == provenance["source_snapshot_digest"]
            and variant_analysis_summary is not None
            and variant_analysis_payload.get("variant_analysis_digest")
            == _canonical_digest(variant_analysis_summary)
            and variant_analysis_payload.get("variant_analysis_digest")
            == variant_analysis_projection_digest
            and variant_analysis_payload.get("human_review_required") is True
            and variant_analysis_payload.get("raw_payload_processed") is False
            and all(
                variant_analysis_payload.get(field) is False
                for field in required_safety_fields
            )
        )
    deep_code_reasoning_stage_id = provenance.get("deep_code_reasoning_stage_id")
    deep_code_reasoning_projection_digest = provenance.get(
        "deep_code_reasoning_projection_digest"
    )
    if (deep_code_reasoning_stage_id is None) != (
        deep_code_reasoning_projection_digest is None
    ):
        return False
    deep_code_reasoning_is_valid = True
    if deep_code_reasoning_stage_id is not None:
        deep_code_reasoning_stage = repository.get_pipeline_stage(
            deep_code_reasoning_stage_id
        )
        deep_code_reasoning_payload = (
            deep_code_reasoning_stage.payload
            if deep_code_reasoning_stage is not None
            and isinstance(deep_code_reasoning_stage.payload, dict)
            else {}
        )
        deep_code_reasoning_is_valid = bool(
            deep_code_reasoning_stage is not None
            and deep_code_reasoning_stage.pipeline_run_id == pipeline_run.id
            and deep_code_reasoning_stage.campaign_id == provenance["campaign_id"]
            and deep_code_reasoning_stage.stage_key == "autonomous_deep_code_reasoning"
            and deep_code_reasoning_stage.status == "completed"
            and deep_code_reasoning_stage.safety_gate_state == "safe"
            and deep_code_reasoning_payload.get("schema_version")
            == _AUTONOMOUS_DEEP_CODE_REASONING_PROJECTION_SCHEMA
            and deep_code_reasoning_payload.get("artifact_kind")
            == "deep_code_reasoning_projection"
            and deep_code_reasoning_payload.get("pipeline_run_id") == pipeline_run.id
            and deep_code_reasoning_payload.get("source_snapshot_digest")
            == provenance["source_snapshot_digest"]
            and deep_code_reasoning_payload.get("deep_code_reasoning_digest")
            == deep_code_reasoning_projection_digest
            and deep_code_reasoning_payload.get("human_review_required") is True
            and deep_code_reasoning_payload.get("raw_payload_processed") is False
            and all(
                deep_code_reasoning_payload.get(field) is False
                for field in required_safety_fields
            )
        )
    return bool(
        ranking_stage is not None
        and ranking_stage.pipeline_run_id == pipeline_run.id
        and ranking_stage.campaign_id == provenance["campaign_id"]
        and ranking_stage.stage_key == "autonomous_finding_dedup_and_rank"
        and ranking_stage.status == "completed"
        and ranking_stage.safety_gate_state == "safe"
        and ranking_payload.get("pipeline_run_id") == pipeline_run.id
        and ranking_payload.get("submission_blocked") is True
        and ranking_payload.get("raw_payload_processed") is False
        and all(ranking_payload.get(field) is False for field in required_safety_fields)
        and decision_stage is not None
        and decision_stage.pipeline_run_id == pipeline_run.id
        and decision_stage.campaign_id == provenance["campaign_id"]
        and decision_stage.stage_key == "candidate_hunter_decision"
        and decision_stage.status == "completed"
        and decision_stage.safety_gate_state == "safe"
        and decision_payload.get("raw_payload_processed") is False
        and all(decision_payload.get(field) is False for field in required_safety_fields)
        and isinstance(persisted_decisions, list)
        and any(
            isinstance(decision, dict)
            and _worker_safe_string(decision.get("candidate_id")) == candidate_id
            and decision.get("disposition") == "retained"
            for decision in persisted_decisions
        )
        and finding_dedup_risk_is_valid
        and variant_analysis_is_valid
        and deep_code_reasoning_is_valid
    )


def _candidate_fingerprint(candidate: dict) -> str | None:
    route = candidate.get("route") if isinstance(candidate.get("route"), dict) else {}
    method = _worker_safe_string(route.get("method")).upper()
    path = _worker_safe_string(route.get("path"))
    source_fact_refs = _safe_provenance_refs(candidate.get("source_fact_refs"))
    identity_source_fact_refs = _candidate_identity_provenance_refs(source_fact_refs)
    identity = {
        "vuln_type": _worker_safe_string(candidate.get("vuln_type")).lower(),
        "root_cause_id": _worker_safe_string(candidate.get("root_cause_id")).lower(),
        "route": {"method": method, "path": path},
        "affected_code_path": _worker_safe_string(
            candidate.get("affected_code_path")
        ),
        "source_fact_refs": identity_source_fact_refs,
    }
    if (
        not identity["vuln_type"]
        or not identity["root_cause_id"]
        or not method
        or not path.startswith("/")
        or not identity["affected_code_path"]
        or identity_source_fact_refs is None
    ):
        return None
    return _canonical_digest(identity)


def _candidate_identity_provenance_refs(
    source_fact_refs: list[str] | None,
) -> list[str] | None:
    if source_fact_refs is None:
        return None
    stable_refs = [
        fact_ref
        for fact_ref in source_fact_refs
        if not fact_ref.startswith("codebase_fact:")
    ]
    return stable_refs or source_fact_refs


def _safe_provenance_refs(value: object) -> list[str] | None:
    if not isinstance(value, list) or not value or len(value) > 20:
        return None
    refs = [_worker_safe_string(item) for item in value]
    if any(
        not ref or _SAFE_PROVENANCE_REF_PATTERN.fullmatch(ref) is None
        for ref in refs
    ):
        return None
    normalized = sorted(set(refs))
    return normalized if len(normalized) == len(refs) else None


def _autonomous_report_provenance_is_valid(value: object) -> bool:
    if not isinstance(value, dict):
        return False
    required_keys = {
        "schema_version",
        "pipeline_run_id",
        "campaign_id",
        "source_snapshot_digest",
        "candidate_id",
        "candidate_fingerprint",
        "candidate_decision_stage_id",
        "ranking_stage_id",
        "source_fact_refs",
        "multi_engine_status",
        "multi_engine_verdict_digest",
        "falsification_status",
        "falsification_summary_digest",
        "provenance_digest",
    }
    if not required_keys.issubset(value):
        return False
    has_finding_dedup_risk_stage = "finding_dedup_risk_stage_id" in value
    has_finding_dedup_risk_digest = "finding_dedup_risk_projection_digest" in value
    if has_finding_dedup_risk_stage != has_finding_dedup_risk_digest:
        return False
    if has_finding_dedup_risk_stage and (
        not _worker_safe_string(value.get("finding_dedup_risk_stage_id")).startswith(
            "pipeline_stage_"
        )
        or _SHA256_PATTERN.fullmatch(
            _worker_safe_string(value.get("finding_dedup_risk_projection_digest"))
        )
        is None
    ):
        return False
    has_variant_analysis_stage = "variant_analysis_stage_id" in value
    has_variant_analysis_digest = "variant_analysis_projection_digest" in value
    if has_variant_analysis_stage != has_variant_analysis_digest:
        return False
    if has_variant_analysis_stage and (
        not _worker_safe_string(value.get("variant_analysis_stage_id")).startswith(
            "pipeline_stage_"
        )
        or _SHA256_PATTERN.fullmatch(
            _worker_safe_string(value.get("variant_analysis_projection_digest"))
        )
        is None
    ):
        return False
    has_deep_code_reasoning_stage = "deep_code_reasoning_stage_id" in value
    has_deep_code_reasoning_digest = "deep_code_reasoning_projection_digest" in value
    if has_deep_code_reasoning_stage != has_deep_code_reasoning_digest:
        return False
    if has_deep_code_reasoning_stage and (
        not _worker_safe_string(value.get("deep_code_reasoning_stage_id")).startswith(
            "pipeline_stage_"
        )
        or _SHA256_PATTERN.fullmatch(
            _worker_safe_string(value.get("deep_code_reasoning_projection_digest"))
        )
        is None
    ):
        return False
    if (
        value.get("schema_version") != _AUTONOMOUS_REPORT_PROVENANCE_SCHEMA
        or not _worker_safe_string(value.get("pipeline_run_id"))
        or not _worker_safe_string(value.get("campaign_id"))
        or _SOURCE_SNAPSHOT_DIGEST_PATTERN.fullmatch(
            _worker_safe_string(value.get("source_snapshot_digest"))
        ) is None
        or not _worker_safe_string(value.get("candidate_id"))
        or _SHA256_PATTERN.fullmatch(
            _worker_safe_string(value.get("candidate_fingerprint"))
        ) is None
        or not _worker_safe_string(value.get("candidate_decision_stage_id")).startswith(
            "pipeline_stage_"
        )
        or not _worker_safe_string(value.get("ranking_stage_id")).startswith(
            "pipeline_stage_"
        )
        or _safe_provenance_refs(value.get("source_fact_refs"))
        != value.get("source_fact_refs")
        or not isinstance(value.get("multi_engine_status"), str)
        or value.get("multi_engine_status")
        not in _RUNTIME_REPORT_MULTI_ENGINE_STATUSES
        or _SHA256_PATTERN.fullmatch(
            _worker_safe_string(value.get("multi_engine_verdict_digest"))
        ) is None
        or value.get("falsification_status") != "retained"
        or _SHA256_PATTERN.fullmatch(
            _worker_safe_string(value.get("falsification_summary_digest"))
        ) is None
        or _SHA256_PATTERN.fullmatch(
            _worker_safe_string(value.get("provenance_digest"))
        ) is None
    ):
        return False
    unsigned = {key: item for key, item in value.items() if key != "provenance_digest"}
    return value["provenance_digest"] == _canonical_digest(unsigned)


def _runtime_report_multi_engine_verdict_is_valid(
    value: object,
    *,
    candidate_id: str,
) -> bool:
    return bool(
        isinstance(value, dict)
        and value.get("candidate_id") == candidate_id
        and isinstance(value.get("status"), str)
        and value.get("status") in _RUNTIME_REPORT_MULTI_ENGINE_STATUSES
        and all(
            value.get(field) is False
            for field in _RUNTIME_REPORT_MULTI_ENGINE_SAFETY_FIELDS
        )
    )


def _runtime_report_falsification_summary_is_valid(value: object) -> bool:
    if not isinstance(value, dict):
        return False
    why_still_alive = value.get("why_still_alive")
    why_dead = value.get("why_dead")
    open_dimensions = value.get("open_dimensions")
    survived_kill_score = value.get("survived_kill_score")
    return bool(
        value.get("schema_version") == _RUNTIME_REPORT_FALSIFICATION_SCHEMA
        and value.get("decision_status") == "retained"
        and isinstance(value.get("broken_invariant"), str)
        and bool(value["broken_invariant"].strip())
        and isinstance(why_still_alive, list)
        and bool(why_still_alive)
        and all(isinstance(item, str) and bool(item.strip()) for item in why_still_alive)
        and isinstance(why_dead, list)
        and not why_dead
        and isinstance(open_dimensions, list)
        and all(isinstance(item, str) and bool(item.strip()) for item in open_dimensions)
        and isinstance(survived_kill_score, int)
        and not isinstance(survived_kill_score, bool)
        and survived_kill_score >= 0
        and all(
            value.get(field) is False
            for field in _RUNTIME_REPORT_FALSIFICATION_SAFETY_FIELDS
        )
    )


def _canonical_digest(value: object) -> str:
    return sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def _candidate_validation_handoff_context(
    candidate: dict,
    *,
    candidate_id: str,
) -> dict[str, Any]:
    vuln_type = _worker_safe_string(candidate.get("vuln_type")).lower()
    if re.fullmatch(r"[a-z][a-z0-9_]{0,100}", vuln_type) is None:
        vuln_type = "unknown"
    validation_mode = _worker_safe_string(candidate.get("validation_mode")).lower()
    if re.fullmatch(r"[a-z][a-z0-9_]{0,100}", validation_mode) is None:
        validation_mode = "non_destructive_request_review"
    evidence_needed = []
    for item in _worker_safe_string_list(candidate.get("evidence_needed")):
        token = item.lower()
        if (
            re.fullmatch(r"[a-z][a-z0-9_]{0,100}", token) is not None
            and token not in evidence_needed
        ):
            evidence_needed.append(token)
        if len(evidence_needed) >= 8:
            break
    return {
        "candidate_id": candidate_id,
        "vuln_type": vuln_type,
        "suggested_validation_mode": validation_mode,
        "evidence_needed": evidence_needed,
        "safe_validation_step_count": min(
            len(_worker_safe_string_list(candidate.get("safe_validation_plan"))),
            8,
        ),
    }


def _candidate_validation_handoff_spec(
    *,
    task: CampaignTaskRecord,
    pipeline_run: Any,
    source_snapshot_digest: object,
    ranking_stage: PipelineStageRecord,
    candidate_decision_stage_refs: list[str],
    report_provenance_digest: str,
    candidate: dict,
    candidate_id: str,
) -> dict[str, Any]:
    context = _candidate_validation_handoff_context(
        candidate,
        candidate_id=candidate_id,
    )
    handoff_task_id = "campaign_task_validation_handoff_" + sha256(
        f"{task.id}:{pipeline_run.id}:{candidate_id}:validation_handoff".encode("utf-8")
    ).hexdigest()
    return {
        "task_id": handoff_task_id,
        "input_refs": [
            f"pipeline_run:{pipeline_run.id}",
            f"campaign_task:{task.id}",
            f"pipeline_stage:{ranking_stage.id}",
            *candidate_decision_stage_refs,
            f"candidate:{candidate_id}",
        ],
        "payload": {
            "schema_version": "autonomous_validation_handoff_v1",
            "pipeline_run_id": pipeline_run.id,
            "report_review_task_id": task.id,
            "source_snapshot_digest": source_snapshot_digest,
            "candidate_id": candidate_id,
            "candidate_ids": [candidate_id],
            "candidate_validation_context": context,
            "report_provenance_digest": report_provenance_digest,
            "submission_blocked": True,
            "human_review_required": True,
            "approval_required": True,
            "allowed_to_execute": False,
            "execution_allowed": False,
            "dispatch_allowed": False,
            "validation_allowed": False,
            "candidate_promotion_allowed": False,
            "report_submission_allowed": False,
            "raw_payload_processed": False,
        },
    }


def _build_autonomous_report_provenance(
    *,
    candidate: dict,
    candidate_decisions: list,
    projection: dict,
    pipeline_run: Any,
    campaign: CampaignRecord,
    task: CampaignTaskRecord,
    ranking_stage: PipelineStageRecord,
    repository: DatabaseRepository,
    multi_engine_verdict: dict,
    falsification_summary: dict,
    finding_dedup_risk_stage: PipelineStageRecord | None,
    finding_dedup_risk_projection: dict | None,
    variant_analysis_stage: PipelineStageRecord | None,
    variant_analysis_projection: dict | None,
    deep_code_reasoning_stage: PipelineStageRecord | None,
    deep_code_reasoning_projection: dict | None,
) -> dict[str, Any] | None:
    task_payload = task.payload if isinstance(task.payload, dict) else {}
    source_snapshot_digest = _worker_safe_string(
        task_payload.get("source_snapshot_digest")
    )
    candidate_id = _worker_safe_string(candidate.get("candidate_id"))
    candidate_fingerprint = _candidate_fingerprint(candidate)
    source_fact_refs = _safe_provenance_refs(candidate.get("source_fact_refs"))
    decision_stage = _candidate_decision_stage_for_report(
        candidate_id=candidate_id,
        candidate_decisions=candidate_decisions,
        projection=projection,
        pipeline_run=pipeline_run,
        campaign=campaign,
        repository=repository,
    )
    if (
        _SOURCE_SNAPSHOT_DIGEST_PATTERN.fullmatch(source_snapshot_digest) is None
        or not candidate_id
        or candidate_fingerprint is None
        or source_fact_refs is None
        or decision_stage is None
        or not _runtime_report_multi_engine_verdict_is_valid(
            multi_engine_verdict,
            candidate_id=candidate_id,
        )
        or not _runtime_report_falsification_summary_is_valid(
            falsification_summary
        )
        or (finding_dedup_risk_stage is None)
        != (finding_dedup_risk_projection is None)
        or (variant_analysis_stage is None)
        != (variant_analysis_projection is None)
        or (deep_code_reasoning_stage is None)
        != (deep_code_reasoning_projection is None)
    ):
        return None
    provenance = {
        "schema_version": _AUTONOMOUS_REPORT_PROVENANCE_SCHEMA,
        "pipeline_run_id": pipeline_run.id,
        "campaign_id": campaign.id,
        "source_snapshot_digest": source_snapshot_digest,
        "candidate_id": candidate_id,
        "candidate_fingerprint": candidate_fingerprint,
        "candidate_decision_stage_id": decision_stage.id,
        "ranking_stage_id": ranking_stage.id,
        "source_fact_refs": source_fact_refs,
        "multi_engine_status": multi_engine_verdict["status"],
        "multi_engine_verdict_digest": _canonical_digest(multi_engine_verdict),
        "falsification_status": falsification_summary["decision_status"],
        "falsification_summary_digest": _canonical_digest(falsification_summary),
    }
    if finding_dedup_risk_stage is not None:
        finding_dedup_risk_digest = _worker_safe_string(
            finding_dedup_risk_projection.get("finding_dedup_risk_digest")
        )
        if (
            finding_dedup_risk_stage.pipeline_run_id != pipeline_run.id
            or finding_dedup_risk_stage.campaign_id != campaign.id
            or finding_dedup_risk_stage.stage_key != "autonomous_finding_dedup_risk"
            or finding_dedup_risk_stage.status != "completed"
            or finding_dedup_risk_stage.safety_gate_state != "safe"
            or _SHA256_PATTERN.fullmatch(finding_dedup_risk_digest) is None
        ):
            return None
        provenance["finding_dedup_risk_stage_id"] = finding_dedup_risk_stage.id
        provenance["finding_dedup_risk_projection_digest"] = finding_dedup_risk_digest
    if variant_analysis_stage is not None:
        variant_analysis_digest = _worker_safe_string(
            variant_analysis_projection.get("variant_analysis_digest")
        )
        if (
            variant_analysis_stage.pipeline_run_id != pipeline_run.id
            or variant_analysis_stage.campaign_id != campaign.id
            or variant_analysis_stage.stage_key != "autonomous_variant_analysis"
            or variant_analysis_stage.status != "completed"
            or variant_analysis_stage.safety_gate_state != "safe"
            or _SHA256_PATTERN.fullmatch(variant_analysis_digest) is None
        ):
            return None
        provenance["variant_analysis_stage_id"] = variant_analysis_stage.id
        provenance["variant_analysis_projection_digest"] = variant_analysis_digest
    if deep_code_reasoning_stage is not None:
        deep_code_reasoning_digest = _worker_safe_string(
            deep_code_reasoning_projection.get("deep_code_reasoning_digest")
        )
        if (
            deep_code_reasoning_stage.pipeline_run_id != pipeline_run.id
            or deep_code_reasoning_stage.campaign_id != campaign.id
            or deep_code_reasoning_stage.stage_key != "autonomous_deep_code_reasoning"
            or deep_code_reasoning_stage.status != "completed"
            or deep_code_reasoning_stage.safety_gate_state != "safe"
            or _SHA256_PATTERN.fullmatch(deep_code_reasoning_digest) is None
        ):
            return None
        provenance["deep_code_reasoning_stage_id"] = deep_code_reasoning_stage.id
        provenance["deep_code_reasoning_projection_digest"] = deep_code_reasoning_digest
    return {
        **provenance,
        "provenance_digest": _canonical_digest(provenance),
    }


def _candidate_decision_stage_for_report(
    *,
    candidate_id: str,
    candidate_decisions: list,
    projection: dict,
    pipeline_run: Any,
    campaign: CampaignRecord,
    repository: DatabaseRepository,
) -> PipelineStageRecord | None:
    audit = projection.get("audit") if isinstance(projection.get("audit"), dict) else {}
    state_digest = _worker_safe_string(audit.get("state_digest"))
    stage_refs = audit.get("stage_refs")
    if not candidate_id or not state_digest or not isinstance(stage_refs, list):
        return None
    decision_refs = [
        item
        for item in stage_refs
        if isinstance(item, dict)
        and item.get("stage_key") == "candidate_hunter_decision"
        and isinstance(item.get("round"), int)
        and not isinstance(item.get("round"), bool)
        and item["round"] >= 1
        and _worker_safe_string(item.get("stage_id"))
    ]
    if not decision_refs:
        return None
    latest_ref = max(
        decision_refs,
        key=lambda item: (item["round"], _worker_safe_string(item["stage_id"])),
    )
    stage = repository.get_pipeline_stage(_worker_safe_string(latest_ref["stage_id"]))
    payload = stage.payload if stage is not None and isinstance(stage.payload, dict) else {}
    if (
        stage is None
        or stage.pipeline_run_id != pipeline_run.id
        or stage.campaign_id != campaign.id
        or stage.stage_key != "candidate_hunter_decision"
        or stage.status != "completed"
        or stage.safety_gate_state != "safe"
        or payload.get("state_digest") != state_digest
        or payload.get("candidate_decisions") != candidate_decisions
        or any(
            payload.get(field) is not False
            for field in (
                "execution_allowed",
                "dispatch_allowed",
                "validation_allowed",
                "candidate_promotion_allowed",
                "report_submission_allowed",
                "raw_payload_processed",
            )
        )
    ):
        return None
    if not any(
        isinstance(decision, dict)
        and _worker_safe_string(decision.get("candidate_id")) == candidate_id
        and decision.get("disposition") == "retained"
        for decision in candidate_decisions
    ):
        return None
    return stage


def recover_report_review_task(
    *,
    task: CampaignTaskRecord,
    campaign: CampaignRecord,
    repository: DatabaseRepository,
) -> dict:
    if (
        campaign.status != "running"
        or task.campaign_id != campaign.id
        or task.task_type != "report_review"
        or task.status not in {"running", "completed"}
    ):
        return {
            "status": "blocked",
            "task_id": task.id,
            "stop_reason": "report_review_recovery_integrity_invalid",
        }
    return _run_report_review_task(
        task=task,
        campaign=campaign,
        repository=repository,
    )


def _run_report_review_task(
    *,
    task: CampaignTaskRecord,
    campaign: CampaignRecord,
    repository: DatabaseRepository,
) -> dict:
    from app.autonomous_research_runtime import record_autonomous_research_task_completion
    from app.candidate_hunter_loop import load_candidate_hunter_projection
    from app.intelligence_benchmark.candidate_report_bridge import (
        build_submission_blocked_report_bundle,
    )
    from app.multi_engine_verifier import deepen_multi_engine_verdict
    from app.mythos_report import build_report_preview_response

    task_payload = task.payload if isinstance(task.payload, dict) else {}
    pipeline_run_id = task_payload.get("pipeline_run_id")
    pipeline_run = (
        repository.get_pipeline_run(pipeline_run_id)
        if isinstance(pipeline_run_id, str)
        else None
    )
    pipeline_payload = pipeline_run.payload if pipeline_run is not None else {}
    if (
        pipeline_run is None
        or pipeline_run.asset != campaign.default_asset
        or pipeline_run.scope_status != "in_scope"
        or not isinstance(pipeline_payload, dict)
        or pipeline_payload.get("campaign_id") != campaign.id
    ):
        return _block_agent_task(
            task=task,
            repository=repository,
            stop_reason="report_review_input_missing",
        )

    ranking_stages = [
        stage
        for stage in repository.list_pipeline_stages_for_run(pipeline_run.id)
        if stage.stage_key == "autonomous_finding_dedup_and_rank"
        and stage.campaign_id == campaign.id
        and stage.status == "completed"
        and stage.safety_gate_state == "safe"
    ]
    if len(ranking_stages) != 1 or not isinstance(ranking_stages[0].payload, dict):
        return _block_agent_task(
            task=task,
            repository=repository,
            stop_reason="report_review_input_missing",
        )
    ranking_payload = ranking_stages[0].payload
    top_candidates = ranking_payload.get("top_candidates")
    if (
        not isinstance(top_candidates, list)
        or ranking_payload.get("submission_blocked") is not True
        or any(ranking_payload.get(field) is not False for field in (
            "execution_allowed",
            "dispatch_allowed",
            "validation_allowed",
            "candidate_promotion_allowed",
            "report_submission_allowed",
        ))
    ):
        return _block_agent_task(
            task=task,
            repository=repository,
            stop_reason="report_review_input_invalid",
        )

    projection, projection_stop_reason = (
        _runtime_candidate_hunter_projection_for_downstream(
            task=task,
            campaign=campaign,
            pipeline_run=pipeline_run,
            repository=repository,
        )
    )
    if projection_stop_reason is not None:
        return _block_agent_task(
            task=task,
            repository=repository,
            stop_reason=projection_stop_reason,
        )
    if projection is None:
        projection = load_candidate_hunter_projection(
            repository=repository,
            pipeline_run_id=pipeline_run.id,
        )
    final_candidates = projection.get("final_candidates")
    decisions = projection.get("candidate_decisions")
    if (
        projection.get("status") != "ready"
        or not isinstance(final_candidates, list)
        or not isinstance(decisions, list)
    ):
        return _block_agent_task(
            task=task,
            repository=repository,
            stop_reason="candidate_hunter_projection_invalid",
        )
    retained_ids = {
        _worker_safe_string(decision.get("candidate_id"))
        for decision in decisions
        if isinstance(decision, dict)
        and decision.get("disposition") == "retained"
        and _worker_safe_string(decision.get("candidate_id"))
    }
    candidates_by_id = {
        _worker_safe_string(candidate.get("candidate_id")): candidate
        for candidate in final_candidates
        if isinstance(candidate, dict)
        and _worker_safe_string(candidate.get("candidate_id")) in retained_ids
    }
    ordered_candidate_ids = [
        _worker_safe_string(candidate.get("candidate_id"))
        for candidate in top_candidates
        if isinstance(candidate, dict)
        and _worker_safe_string(candidate.get("candidate_id"))
    ]
    if len(ordered_candidate_ids) != len(set(ordered_candidate_ids)) or any(
        candidate_id not in candidates_by_id for candidate_id in ordered_candidate_ids
    ):
        return _block_agent_task(
            task=task,
            repository=repository,
            stop_reason="report_review_input_invalid",
        )
    if not ordered_candidate_ids:
        return _complete_no_reportable_candidates_report_review(
            task=task,
            campaign=campaign,
            repository=repository,
            pipeline_run=pipeline_run,
            ranking_stage=ranking_stages[0],
        )
    (
        finding_dedup_risk_projection,
        finding_dedup_risk_stage,
        finding_dedup_risk_stop_reason,
    ) = _runtime_finding_dedup_risk_projection_for_report(
        task=task,
        campaign=campaign,
        pipeline_run=pipeline_run,
        ranking_stage=ranking_stages[0],
        final_candidates=final_candidates,
        candidate_decisions=decisions,
        repository=repository,
    )
    if finding_dedup_risk_stop_reason is not None:
        return _block_agent_task(
            task=task,
            repository=repository,
            stop_reason=finding_dedup_risk_stop_reason,
        )
    finding_dedup_risk = (
        finding_dedup_risk_projection.get("finding_dedup_risk")
        if isinstance(finding_dedup_risk_projection, dict)
        else None
    )
    if finding_dedup_risk_projection is not None and not isinstance(
        finding_dedup_risk, dict
    ):
        return _block_agent_task(
            task=task,
            repository=repository,
            stop_reason="finding_dedup_risk_projection_invalid",
        )
    (
        variant_analysis_projection,
        variant_analysis_stage,
        variant_analysis_stop_reason,
    ) = _runtime_variant_analysis_projection_for_report(
        task=task,
        campaign=campaign,
        pipeline_run=pipeline_run,
        repository=repository,
    )
    if variant_analysis_stop_reason is not None:
        return _block_agent_task(
            task=task,
            repository=repository,
            stop_reason=variant_analysis_stop_reason,
        )
    variant_analysis = (
        variant_analysis_projection.get("variant_analysis")
        if isinstance(variant_analysis_projection, dict)
        else None
    )
    if variant_analysis_projection is not None and not isinstance(
        variant_analysis, dict
    ):
        return _block_agent_task(
            task=task,
            repository=repository,
            stop_reason="variant_analysis_projection_invalid",
        )
    (
        deep_code_reasoning_projection,
        deep_code_reasoning_stage,
        deep_code_reasoning_stop_reason,
    ) = _runtime_deep_code_reasoning_projection_for_report(
        task=task,
        campaign=campaign,
        pipeline_run=pipeline_run,
        repository=repository,
    )
    if deep_code_reasoning_stop_reason is not None:
        return _block_agent_task(
            task=task,
            repository=repository,
            stop_reason=deep_code_reasoning_stop_reason,
        )
    deep_code_reasoning = (
        deep_code_reasoning_projection.get("deep_code_reasoning")
        if isinstance(deep_code_reasoning_projection, dict)
        else None
    )
    if deep_code_reasoning_projection is not None and not isinstance(
        deep_code_reasoning, dict
    ):
        return _block_agent_task(
            task=task,
            repository=repository,
            stop_reason="deep_code_reasoning_projection_invalid",
        )
    try:
        report_bundles_by_candidate_id = {}
        for candidate_id in ordered_candidate_ids:
            report_draft = build_submission_blocked_report_bundle(
                candidates_by_id[candidate_id]
            )
            if (
                not isinstance(report_draft, dict)
                or _worker_safe_string(report_draft.get("candidate_id")) != candidate_id
                or not _runtime_report_multi_engine_verdict_is_valid(
                    report_draft.get("multi_engine_verdict"),
                    candidate_id=candidate_id,
                )
                or not _runtime_report_falsification_summary_is_valid(
                    report_draft.get("falsification_summary")
                )
                or not isinstance(report_draft.get("report_draft"), dict)
                or report_draft["report_draft"].get("falsification_summary")
                != report_draft.get("falsification_summary")
            ):
                return _block_agent_task(
                    task=task,
                    repository=repository,
                    stop_reason="report_review_bundle_invalid",
                )
            if (
                finding_dedup_risk is not None
                or variant_analysis is not None
                or deep_code_reasoning is not None
            ):
                deepened_verdict = deepen_multi_engine_verdict(
                    report_draft["multi_engine_verdict"],
                    candidate=candidates_by_id[candidate_id],
                    finding_dedup_risk=finding_dedup_risk,
                    variant_analysis=variant_analysis,
                    deep_code_reasoning=deep_code_reasoning,
                ).model_dump()
                if not _runtime_report_multi_engine_verdict_is_valid(
                    deepened_verdict,
                    candidate_id=candidate_id,
                ):
                    return _block_agent_task(
                        task=task,
                        repository=repository,
                        stop_reason="report_review_bundle_invalid",
                    )
                report_draft = {
                    **report_draft,
                    "multi_engine_verdict": deepened_verdict,
                }
            report_bundles_by_candidate_id[candidate_id] = report_draft
    except (TypeError, ValueError):
        return _block_agent_task(
            task=task,
            repository=repository,
            stop_reason="report_review_bundle_invalid",
        )
    provenance_by_candidate_id = {}
    for candidate_id in ordered_candidate_ids:
        provenance = _build_autonomous_report_provenance(
            candidate=candidates_by_id[candidate_id],
            candidate_decisions=decisions,
            projection=projection,
            pipeline_run=pipeline_run,
            campaign=campaign,
            task=task,
            ranking_stage=ranking_stages[0],
            repository=repository,
            multi_engine_verdict=report_bundles_by_candidate_id[candidate_id][
                "multi_engine_verdict"
            ],
            falsification_summary=report_bundles_by_candidate_id[candidate_id][
                "falsification_summary"
            ],
            finding_dedup_risk_stage=finding_dedup_risk_stage,
            finding_dedup_risk_projection=finding_dedup_risk_projection,
            variant_analysis_stage=variant_analysis_stage,
            variant_analysis_projection=variant_analysis_projection,
            deep_code_reasoning_stage=deep_code_reasoning_stage,
            deep_code_reasoning_projection=deep_code_reasoning_projection,
        )
        if provenance is None:
            return _block_agent_task(
                task=task,
                repository=repository,
                stop_reason="report_review_provenance_invalid",
            )
        provenance_by_candidate_id[candidate_id] = provenance
    report_drafts = [
        {
            **report_bundles_by_candidate_id[candidate_id],
            "autonomous_provenance": provenance_by_candidate_id[candidate_id],
        }
        for candidate_id in ordered_candidate_ids
    ]
    if any(
        not isinstance(draft, dict)
        or draft.get("submission_blocked") is not True
        or draft.get("human_review_required") is not True
        or draft.get("execution_allowed") is not False
        or draft.get("validation_allowed") is not False
        or draft.get("report_submission_allowed") is not False
        or not _runtime_report_falsification_summary_is_valid(
            draft.get("falsification_summary")
        )
        or not isinstance(draft.get("report_draft"), dict)
        or draft["report_draft"].get("falsification_summary")
        != draft.get("falsification_summary")
        or draft.get("autonomous_provenance")
        != provenance_by_candidate_id.get(_worker_safe_string(draft.get("candidate_id")))
        for draft in report_drafts
    ):
        return _block_agent_task(
            task=task,
            repository=repository,
            stop_reason="report_review_bundle_invalid",
        )
    try:
        build_report_preview_response(pipeline_run)
    except ValueError:
        report_preview_available = False
    else:
        report_preview_available = True
    report_provenance = [
        provenance_by_candidate_id[candidate_id]
        for candidate_id in ordered_candidate_ids
    ]
    report_provenance_digest = _canonical_digest(report_provenance)
    candidate_decision_stage_refs = list(
        dict.fromkeys(
            f"pipeline_stage:{provenance['candidate_decision_stage_id']}"
            for provenance in report_provenance
        )
    )
    report_input_refs = [
        f"pipeline_run:{pipeline_run.id}",
        f"pipeline_stage:{ranking_stages[0].id}",
        *candidate_decision_stage_refs,
    ]
    if finding_dedup_risk_stage is not None:
        report_input_refs.append(f"pipeline_stage:{finding_dedup_risk_stage.id}")
    if variant_analysis_stage is not None:
        report_input_refs.append(f"pipeline_stage:{variant_analysis_stage.id}")
    if deep_code_reasoning_stage is not None:
        report_input_refs.append(f"pipeline_stage:{deep_code_reasoning_stage.id}")
    handoff_specs = [
        _candidate_validation_handoff_spec(
            task=task,
            pipeline_run=pipeline_run,
            source_snapshot_digest=task_payload.get("source_snapshot_digest"),
            ranking_stage=ranking_stages[0],
            candidate_decision_stage_refs=candidate_decision_stage_refs,
            report_provenance_digest=report_provenance_digest,
            candidate=candidates_by_id[candidate_id],
            candidate_id=candidate_id,
        )
        for candidate_id in ordered_candidate_ids
    ]
    existing_handoffs = [
        item
        for item in repository.list_campaign_tasks(campaign.id)
        if item.task_type == "validation_handoff"
        and isinstance(item.payload, dict)
        and item.payload.get("report_review_task_id") == task.id
    ]
    existing_handoffs_by_id = {item.id: item for item in existing_handoffs}
    expected_handoff_ids = {spec["task_id"] for spec in handoff_specs}
    existing_report_stages = [
        stage
        for stage in repository.list_pipeline_stages_for_run(pipeline_run.id)
        if stage.task_id == task.id and stage.stage_key == "autonomous_report_review"
    ]
    if (
        len(existing_handoffs_by_id) != len(existing_handoffs)
        or any(handoff_id not in expected_handoff_ids for handoff_id in existing_handoffs_by_id)
        or (existing_report_stages and not existing_handoffs)
    ):
        return _block_report_review_recovery(
            task=task,
            campaign=campaign,
            repository=repository,
        )
    validation_handoffs = []
    for spec in handoff_specs:
        validation_handoff = existing_handoffs_by_id.get(spec["task_id"])
        if validation_handoff is None:
            validation_handoff, _ = repository.claim_campaign_task(
                task_id=spec["task_id"],
                campaign_id=campaign.id,
                task_type="validation_handoff",
                agent_type="human_review",
                title="Review submission-blocked validation handoff",
                input_refs=spec["input_refs"],
                payload=spec["payload"],
            )
        if not _report_validation_handoff_is_valid(
            handoff=validation_handoff,
            campaign=campaign,
            report_task=task,
            input_refs=spec["input_refs"],
            payload=spec["payload"],
        ):
            return _block_report_review_recovery(
                task=task,
                campaign=campaign,
                repository=repository,
            )
        if validation_handoff.status == "queued":
            validation_handoff = (
                repository.update_campaign_task_status(
                    validation_handoff.id,
                    "awaiting_approval",
                )
                or validation_handoff
            )
        if validation_handoff.status != "awaiting_approval":
            return _block_report_review_recovery(
                task=task,
                campaign=campaign,
                repository=repository,
            )
        validation_handoffs.append(validation_handoff)
    report_output_refs = [
        f"campaign_task:{validation_handoff.id}"
        for validation_handoff in validation_handoffs
    ]
    report_payload = {
        "schema_version": "autonomous_report_review_v1",
        "pipeline_run_id": pipeline_run.id,
        "idempotency_key": sha256(
            f"{task.id}:{pipeline_run.id}:report_review".encode("utf-8")
        ).hexdigest(),
        "submission_blocked": True,
        "human_review_required": True,
        "report_preview_available": report_preview_available,
        "report_drafts": report_drafts,
        "report_provenance": report_provenance,
        "report_provenance_digest": report_provenance_digest,
        "finding_dedup_risk_attached": finding_dedup_risk_stage is not None,
        "variant_analysis_attached": variant_analysis_stage is not None,
        "deep_code_reasoning_attached": deep_code_reasoning_stage is not None,
        "validation_handoff_ids": [
            validation_handoff.id for validation_handoff in validation_handoffs
        ],
        "raw_payload_processed": False,
        "execution_allowed": False,
        "dispatch_allowed": False,
        "validation_allowed": False,
        "candidate_promotion_allowed": False,
        "report_submission_allowed": False,
    }
    if finding_dedup_risk_stage is not None:
        report_payload["finding_dedup_risk_stage_id"] = finding_dedup_risk_stage.id
        report_payload["finding_dedup_risk_projection_digest"] = (
            finding_dedup_risk_projection["finding_dedup_risk_digest"]
        )
    if variant_analysis_stage is not None:
        report_payload["variant_analysis_stage_id"] = variant_analysis_stage.id
        report_payload["variant_analysis_projection_digest"] = (
            variant_analysis_projection["variant_analysis_digest"]
        )
    if deep_code_reasoning_stage is not None:
        report_payload["deep_code_reasoning_stage_id"] = deep_code_reasoning_stage.id
        report_payload["deep_code_reasoning_projection_digest"] = (
            deep_code_reasoning_projection["deep_code_reasoning_digest"]
        )
    if len(existing_report_stages) > 1 or (
        existing_report_stages
        and not _report_stage_is_valid(
            stage=existing_report_stages[0],
            campaign=campaign,
            report_task=task,
            pipeline_run_id=pipeline_run.id,
            input_refs=report_input_refs,
            output_refs=report_output_refs,
            payload=report_payload,
        )
    ):
        return _block_report_review_recovery(
            task=task,
            campaign=campaign,
            repository=repository,
        )
    report_stage = repository.save_pipeline_stage(
        pipeline_run_id=pipeline_run.id,
        campaign_id=campaign.id,
        task_id=task.id,
        stage_key="autonomous_report_review",
        stage_order=40,
        status="completed",
        input_refs=report_input_refs,
        output_refs=report_output_refs,
        safety_gate_state="awaiting_review",
        stop_reason="human_review_required",
        payload=report_payload,
    )
    if not _report_stage_is_valid(
        stage=report_stage,
        campaign=campaign,
        report_task=task,
        pipeline_run_id=pipeline_run.id,
        input_refs=report_input_refs,
        output_refs=report_output_refs,
        payload=report_payload,
    ):
        return _block_report_review_recovery(
            task=task,
            campaign=campaign,
            repository=repository,
        )
    output_refs = [
        f"pipeline_run:{pipeline_run.id}",
        f"pipeline_stage:{report_stage.id}",
        *report_output_refs,
    ]
    agent_run_payload = {
        "artifact_kind": "submission_blocked_report_review",
        "pipeline_run_id": pipeline_run.id,
        "report_draft_count": len(report_drafts),
        "finding_dedup_risk_attached": finding_dedup_risk_stage is not None,
        "variant_analysis_attached": variant_analysis_stage is not None,
        "deep_code_reasoning_attached": deep_code_reasoning_stage is not None,
        "raw_payload_processed": False,
        "execution_allowed": False,
        "dispatch_allowed": False,
        "validation_allowed": False,
        "candidate_promotion_allowed": False,
        "report_submission_allowed": False,
    }
    completed_task, agent_run, completion_failure = _complete_report_review_execution(
        task=task,
        campaign=campaign,
        repository=repository,
        output_refs=output_refs,
        agent_run_payload=agent_run_payload,
    )
    if completion_failure == "integrity_invalid":
        return _block_report_review_recovery(
            task=task,
            campaign=campaign,
            repository=repository,
        )
    if completion_failure is not None or completed_task is None or agent_run is None:
        return _execution_lease_lost_result(task=task, repository=repository)
    record_autonomous_research_task_completion(
        task=completed_task,
        repository=repository,
    )
    return {
        "status": "completed",
        "task_id": task.id,
        "agent_run_id": agent_run.id,
        "stop_reason": "human_review_required",
    }


def _complete_no_reportable_candidates_report_review(
    *,
    task: CampaignTaskRecord,
    campaign: CampaignRecord,
    repository: DatabaseRepository,
    pipeline_run: Any,
    ranking_stage: PipelineStageRecord,
) -> dict:
    from app.autonomous_research_runtime import record_autonomous_research_task_completion

    report_input_refs = [
        f"pipeline_run:{pipeline_run.id}",
        f"pipeline_stage:{ranking_stage.id}",
    ]
    report_payload = {
        "schema_version": "autonomous_report_review_v1",
        "pipeline_run_id": pipeline_run.id,
        "idempotency_key": sha256(
            f"{task.id}:{pipeline_run.id}:report_review".encode("utf-8")
        ).hexdigest(),
        "submission_blocked": True,
        "human_review_required": False,
        "report_preview_available": False,
        "report_drafts": [],
        "report_provenance": [],
        "report_provenance_digest": _canonical_digest([]),
        "terminal_outcome": "no_reportable_candidates",
        "raw_payload_processed": False,
        "execution_allowed": False,
        "dispatch_allowed": False,
        "validation_allowed": False,
        "candidate_promotion_allowed": False,
        "report_submission_allowed": False,
    }
    existing_handoffs = [
        candidate
        for candidate in repository.list_campaign_tasks(campaign.id)
        if candidate.task_type == "validation_handoff"
        and isinstance(candidate.payload, dict)
        and candidate.payload.get("report_review_task_id") == task.id
    ]
    existing_report_stages = [
        stage
        for stage in repository.list_pipeline_stages_for_run(pipeline_run.id)
        if stage.task_id == task.id and stage.stage_key == "autonomous_report_review"
    ]
    if (
        existing_handoffs
        or len(existing_report_stages) > 1
        or (
            existing_report_stages
            and not _no_reportable_report_stage_is_valid(
                stage=existing_report_stages[0],
                campaign=campaign,
                report_task=task,
                pipeline_run_id=pipeline_run.id,
                input_refs=report_input_refs,
                payload=report_payload,
            )
        )
    ):
        return _block_report_review_recovery(
            task=task,
            campaign=campaign,
            repository=repository,
        )
    report_stage = repository.save_pipeline_stage(
        pipeline_run_id=pipeline_run.id,
        campaign_id=campaign.id,
        task_id=task.id,
        stage_key="autonomous_report_review",
        stage_order=40,
        status="completed",
        input_refs=report_input_refs,
        output_refs=[],
        safety_gate_state="safe",
        stop_reason="no_reportable_candidates",
        payload=report_payload,
    )
    if not _no_reportable_report_stage_is_valid(
        stage=report_stage,
        campaign=campaign,
        report_task=task,
        pipeline_run_id=pipeline_run.id,
        input_refs=report_input_refs,
        payload=report_payload,
    ):
        return _block_report_review_recovery(
            task=task,
            campaign=campaign,
            repository=repository,
        )
    output_refs = [
        f"pipeline_run:{pipeline_run.id}",
        f"pipeline_stage:{report_stage.id}",
    ]
    agent_run_payload = {
        "artifact_kind": "submission_blocked_report_review",
        "pipeline_run_id": pipeline_run.id,
        "report_draft_count": 0,
        "terminal_outcome": "no_reportable_candidates",
        "raw_payload_processed": False,
        "execution_allowed": False,
        "dispatch_allowed": False,
        "validation_allowed": False,
        "candidate_promotion_allowed": False,
        "report_submission_allowed": False,
    }
    completed_task, agent_run, completion_failure = _complete_report_review_execution(
        task=task,
        campaign=campaign,
        repository=repository,
        output_refs=output_refs,
        agent_run_payload=agent_run_payload,
    )
    if completion_failure == "integrity_invalid":
        return _block_report_review_recovery(
            task=task,
            campaign=campaign,
            repository=repository,
        )
    if completion_failure is not None or completed_task is None or agent_run is None:
        return _execution_lease_lost_result(task=task, repository=repository)
    record_autonomous_research_task_completion(
        task=completed_task,
        repository=repository,
        terminal_stop_reason="no_reportable_candidates",
        terminal_campaign_status="completed",
    )
    return {
        "status": "completed",
        "task_id": task.id,
        "agent_run_id": agent_run.id,
        "stop_reason": "no_reportable_candidates",
    }


def _complete_report_review_execution(
    *,
    task: CampaignTaskRecord,
    campaign: CampaignRecord,
    repository: DatabaseRepository,
    output_refs: list[str],
    agent_run_payload: dict,
) -> tuple[CampaignTaskRecord | None, AgentRunRecord | None, str | None]:
    has_execution_claim = task.execution_claim_id is not None
    active_run = _active_agent_run_for_task(task=task, repository=repository)
    completed_task: CampaignTaskRecord | None = None
    completed_runs = [
        run
        for run in repository.list_campaign_agent_runs(campaign.id)
        if run.task_id == task.id
        and run.status == "completed"
        and run.safety_gate_state == "allowed"
    ]
    if active_run is not None and completed_runs:
        return None, None, "integrity_invalid"
    if active_run is not None:
        if not _active_report_agent_run_is_valid(
            run=active_run,
            campaign=campaign,
            report_task=task,
        ):
            return None, None, "integrity_invalid"
        if has_execution_claim:
            completed_execution = _finish_task_execution(
                task=task,
                repository=repository,
                task_status="completed",
                output_refs=output_refs,
                agent_status="completed",
                agent_output_refs=output_refs,
                safety_gate_state="allowed",
                stop_reason=None,
                payload=agent_run_payload,
            )
            if completed_execution is None:
                return None, None, "execution_lease_lost"
            completed_task, agent_run = completed_execution
        else:
            agent_run = repository.finish_agent_run(
                active_run.id,
                status="completed",
                output_refs=output_refs,
                safety_gate_state="allowed",
                stop_reason=None,
                payload=agent_run_payload,
            )
    elif len(completed_runs) == 1 and _completed_report_agent_run_is_valid(
        run=completed_runs[0],
        campaign=campaign,
        report_task=task,
        output_refs=output_refs,
        payload=agent_run_payload,
    ):
        agent_run = completed_runs[0]
    else:
        return None, None, "integrity_invalid"
    if agent_run is None or not _completed_report_agent_run_is_valid(
        run=agent_run,
        campaign=campaign,
        report_task=task,
        output_refs=output_refs,
        payload=agent_run_payload,
    ):
        return None, None, "integrity_invalid"
    if not has_execution_claim:
        completed_task = repository.update_campaign_task_status(
            task.id,
            "completed",
            output_refs=[f"agent_run:{agent_run.id}", *output_refs],
        )
    if completed_task is None:
        return None, None, "execution_lease_lost"
    return completed_task, agent_run, None


def _block_report_review_recovery(
    *,
    task: CampaignTaskRecord,
    campaign: CampaignRecord,
    repository: DatabaseRepository,
) -> dict:
    task_payload = task.payload if isinstance(task.payload, dict) else {}
    pipeline_run_id = task_payload.get("pipeline_run_id")
    expected_handoff_id = (
        "campaign_task_validation_handoff_"
        + sha256(
            f"{task.id}:{pipeline_run_id}:validation_handoff".encode("utf-8")
        ).hexdigest()
        if isinstance(pipeline_run_id, str)
        else None
    )
    for handoff in repository.list_campaign_tasks(campaign.id):
        handoff_payload = handoff.payload if isinstance(handoff.payload, dict) else {}
        if (
            handoff.task_type == "validation_handoff"
            and handoff.status in {"queued", "awaiting_approval"}
            and (
                handoff.id == expected_handoff_id
                or handoff_payload.get("report_review_task_id") == task.id
            )
        ):
            handoff.status = "blocked"
            repository.session.add(handoff)
    return _block_agent_task(
        task=task,
        repository=repository,
        stop_reason="report_review_recovery_integrity_invalid",
    )


def _report_validation_handoff_is_valid(
    *,
    handoff: CampaignTaskRecord,
    campaign: CampaignRecord,
    report_task: CampaignTaskRecord,
    input_refs: list[str],
    payload: dict,
) -> bool:
    return (
        handoff.campaign_id == campaign.id
        and handoff.task_type == "validation_handoff"
        and handoff.agent_type == "human_review"
        and handoff.title == "Review submission-blocked validation handoff"
        and handoff.status in {"queued", "awaiting_approval"}
        and handoff.input_refs == input_refs
        and handoff.output_refs == []
        and handoff.payload == payload
        and payload.get("report_review_task_id") == report_task.id
    )


def _report_stage_is_valid(
    *,
    stage: PipelineStageRecord,
    campaign: CampaignRecord,
    report_task: CampaignTaskRecord,
    pipeline_run_id: str,
    input_refs: list[str],
    output_refs: list[str],
    payload: dict,
) -> bool:
    return (
        stage.pipeline_run_id == pipeline_run_id
        and stage.campaign_id == campaign.id
        and stage.task_id == report_task.id
        and stage.stage_key == "autonomous_report_review"
        and stage.stage_order == 40
        and stage.status == "completed"
        and stage.input_refs == input_refs
        and stage.output_refs == output_refs
        and stage.safety_gate_state == "awaiting_review"
        and stage.stop_reason == "human_review_required"
        and stage.payload == payload
    )


def _no_reportable_report_stage_is_valid(
    *,
    stage: PipelineStageRecord,
    campaign: CampaignRecord,
    report_task: CampaignTaskRecord,
    pipeline_run_id: str,
    input_refs: list[str],
    payload: dict,
) -> bool:
    return (
        stage.pipeline_run_id == pipeline_run_id
        and stage.campaign_id == campaign.id
        and stage.task_id == report_task.id
        and stage.stage_key == "autonomous_report_review"
        and stage.stage_order == 40
        and stage.status == "completed"
        and stage.input_refs == input_refs
        and stage.output_refs == []
        and stage.safety_gate_state == "safe"
        and stage.stop_reason == "no_reportable_candidates"
        and stage.payload == payload
    )


def _active_report_agent_run_is_valid(
    *,
    run: AgentRunRecord,
    campaign: CampaignRecord,
    report_task: CampaignTaskRecord,
) -> bool:
    payload = run.payload if isinstance(run.payload, dict) else {}
    return (
        run.campaign_id == campaign.id
        and run.task_id == report_task.id
        and run.agent_type == report_task.agent_type
        and run.status in {"dispatched", "running", "awaiting_approval"}
        and run.input_refs == [f"campaign_task:{report_task.id}"]
        and run.output_refs == []
        and run.tool_calls == []
        and run.safety_gate_state == "allowed"
        and run.stop_reason is None
        and payload.get("raw_payload_processed") is False
    )


def _completed_report_agent_run_is_valid(
    *,
    run: AgentRunRecord,
    campaign: CampaignRecord,
    report_task: CampaignTaskRecord,
    output_refs: list[str],
    payload: dict,
) -> bool:
    return (
        run.campaign_id == campaign.id
        and run.task_id == report_task.id
        and run.agent_type == report_task.agent_type
        and run.status == "completed"
        and run.input_refs == [f"campaign_task:{report_task.id}"]
        and run.output_refs == output_refs
        and run.tool_calls == []
        and run.safety_gate_state == "allowed"
        and run.stop_reason is None
        and run.payload == payload
        and run.finished_at is not None
    )


def _agent_task_stop_reason(
    *,
    campaign: CampaignRecord | None,
    repository: DatabaseRepository,
) -> str | None:
    if campaign is None:
        return "scope_not_in_scope"
    if campaign.scope_status != "in_scope":
        return "scope_not_in_scope"
    if campaign.status == "paused":
        return "campaign_paused"
    if campaign.status == "awaiting_review":
        return "human_review_required"
    if campaign.status in {"blocked", "canceled", "completed", "failed"}:
        return f"campaign_{campaign.status}"
    if campaign.status != "running":
        return "campaign_not_running"

    budget = repository.get_campaign_budget(campaign.id)
    if budget is None:
        return None
    budgets = [
        budget.time_budget_minutes,
        budget.token_budget,
    ]
    if any(value is not None and value <= 0 for value in budgets):
        return "budget_exhausted"
    if (
        budget.time_budget_minutes is not None
        and campaign_elapsed_minutes(campaign) >= budget.time_budget_minutes
    ):
        return "budget_exhausted"
    if (
        budget.token_budget is not None
        and campaign_token_used_from_runs(repository.list_campaign_agent_runs(campaign.id))
        >= budget.token_budget
    ):
        return "budget_exhausted"
    return None


def _materialize_read_only_artifacts(
    *,
    task: CampaignTaskRecord,
    campaign: CampaignRecord,
    repository: DatabaseRepository,
    workspace_inputs: dict | None,
    security_invariants: list[dict] | None = None,
    target_model_projection: dict | None = None,
    observed_target_intake: dict | None = None,
    observed_target_intake_ref: str | None = None,
) -> tuple[list[str], dict]:
    task_payload = task.payload if isinstance(task.payload, dict) else {}
    if (
        task.task_type == "campaign_observation"
        and task_payload.get("runtime_schema")
        == _AUTONOMOUS_RESEARCH_RUNTIME_SCHEMA
    ):
        source_snapshot_digest = _worker_safe_string(
            task_payload.get("source_snapshot_digest")
        )
        if _SOURCE_SNAPSHOT_DIGEST_PATTERN.fullmatch(source_snapshot_digest) is None:
            source_snapshot_digest = "unavailable"
        source_manifest = (
            workspace_inputs.get("source_manifest")
            if isinstance(workspace_inputs, dict)
            else None
        )
        code_files = (
            workspace_inputs.get("code_files")
            if isinstance(workspace_inputs, dict)
            else None
        )
        api_artifacts = (
            workspace_inputs.get("api_artifacts")
            if isinstance(workspace_inputs, dict)
            else None
        )
        advisory_artifacts = (
            workspace_inputs.get("advisory_artifacts")
            if isinstance(workspace_inputs, dict)
            else None
        )
        target_intake = _runtime_target_intake_projection(
            authorized_code_files=code_files,
        )
        return (
            [f"campaign_observation_projection:{task.id}"],
            {
                "artifact_kind": "campaign_observation_projection",
                "projection_schema": _CAMPAIGN_OBSERVATION_PROJECTION_SCHEMA,
                "source_snapshot_digest": source_snapshot_digest,
                "workspace_loaded": workspace_inputs is not None,
                "source_manifest_count": len(source_manifest)
                if isinstance(source_manifest, list)
                else 0,
                "authorized_code_file_count": len(code_files)
                if isinstance(code_files, list)
                else 0,
                "authorized_api_artifact_count": len(api_artifacts)
                if isinstance(api_artifacts, list)
                else 0,
                "authorized_advisory_artifact_count": len(advisory_artifacts)
                if isinstance(advisory_artifacts, list)
                else 0,
                "target_intake": target_intake,
                "target_intake_digest": _canonical_digest(target_intake),
                "raw_payload_processed": False,
                "execution_allowed": False,
                "dispatch_allowed": False,
                "validation_allowed": False,
                "candidate_promotion_allowed": False,
                "report_submission_allowed": False,
            },
        )

    if task.task_type == "attack_surface_mapping":
        mapping_payload = task.payload
        if workspace_inputs is not None:
            mapping_payload = {
                **task.payload,
                "authorized_code_files": workspace_inputs["code_files"],
                "authorized_api_artifacts": workspace_inputs["api_artifacts"],
                "authorized_advisory_artifacts": workspace_inputs[
                    "advisory_artifacts"
                ],
            }
        try:
            static_map = _map_authorized_attack_surface(mapping_payload)
        except Exception as exc:
            raise _WorkerExecutionFailure from exc
        if static_map.facts:
            output_refs, artifact_payload = _materialize_static_codebase_map(
                task=task,
                campaign=campaign,
                repository=repository,
                static_map=static_map,
            )
            return _attach_runtime_target_model_projection(
                task=task,
                campaign=campaign,
                repository=repository,
                output_refs=output_refs,
                artifact_payload=artifact_payload,
                target_intake=observed_target_intake,
                target_intake_ref=observed_target_intake_ref,
            )
        codebase_map = repository.save_codebase_map(
            campaign_id=campaign.id,
            source_ref=f"campaign_task:{task.id}",
            repository=campaign.default_asset,
            commit_ref=None,
            status="mapped",
            route_count=1,
            handler_count=1,
            model_count=1,
            authz_check_count=0,
            sensitive_sink_count=1,
            provenance_refs=[f"campaign:{campaign.id}", f"campaign_task:{task.id}"],
            safety_gate_state="allowed",
            payload={"raw_payload_processed": False, "mapping_mode": "metadata_only"},
        )
        fact = repository.save_codebase_fact(
            codebase_map_id=codebase_map.id,
            campaign_id=campaign.id,
            fact_type="route",
            source_path="campaign/default_asset",
            symbol_name="authorized_surface",
            route_method="GET",
            route_path=campaign.default_asset,
            authz_hint="authorization_boundary_candidate",
            sensitivity_label="metadata_only",
            provenance_refs=[f"codebase_map:{codebase_map.id}"],
            payload={"raw_payload_processed": False},
        )
        scanner_run = repository.save_scanner_run(
            campaign_id=campaign.id,
            codebase_map_id=codebase_map.id,
            tool_name="mythos_static_mapper",
            command_hash=_stable_ref_hash(f"campaign_task:{task.id}:static_mapper"),
            status="completed",
            finding_count=0,
            candidate_count=1,
            summary="Static metadata mapped; no live request or scanner stdout stored.",
            safety_gate_state="allowed",
            payload={
                "raw_stdout": None,
                "fact_refs": [f"codebase_fact:{fact.id}"],
            },
        )
        return _attach_runtime_target_model_projection(
            task=task,
            campaign=campaign,
            repository=repository,
            output_refs=[
                f"codebase_map:{codebase_map.id}",
                f"codebase_fact:{fact.id}",
                f"scanner_run:{scanner_run.id}",
            ],
            artifact_payload={
                "artifact_kind": "attack_surface_map",
                "codebase_map_id": codebase_map.id,
                "scanner_run_id": scanner_run.id,
            },
            target_intake=observed_target_intake,
            target_intake_ref=observed_target_intake_ref,
        )

    if task.task_type == "security_invariant_generation":
        codebase_facts = _target_model_projected_codebase_facts(
            projection=target_model_projection,
            codebase_facts=repository.list_campaign_codebase_facts(campaign.id),
        )
        invariants = _build_security_invariant_projection(
            codebase_facts,
            attack_surface_queue=(
                target_model_projection.get("attack_surface_queue")
                if isinstance(target_model_projection, dict)
                else None
            ),
        )
        task_payload = task.payload if isinstance(task.payload, dict) else {}
        source_snapshot_digest = task_payload.get("source_snapshot_digest")
        artifact_payload = {
            "artifact_kind": "security_invariant_projection",
            "projection_schema": _SECURITY_INVARIANT_PROJECTION_SCHEMA,
            "invariants": invariants,
            "raw_payload_processed": False,
            "execution_allowed": False,
            "validation_allowed": False,
            "candidate_promotion_allowed": False,
            "report_submission_allowed": False,
        }
        if isinstance(source_snapshot_digest, str):
            artifact_payload["source_snapshot_digest"] = source_snapshot_digest
        return (
            [f"security_invariant_projection:{task.id}"],
            artifact_payload,
        )

    if task.task_type == "hypothesis_generation":
        codebase_facts = _target_model_projected_codebase_facts(
            projection=target_model_projection,
            codebase_facts=repository.list_campaign_codebase_facts(campaign.id),
        )
        try:
            hypothesis_payload = (
                _codebase_fact_hypothesis_payload(
                    campaign=campaign,
                    task=task,
                    codebase_facts=codebase_facts,
                    learning_signals=_hypothesis_generation_learning_signals(
                        task=task,
                        campaign=campaign,
                        repository=repository,
                    ),
                    security_invariants=security_invariants,
                    target_model_projection=target_model_projection,
                )
                if codebase_facts
                else _fallback_hypothesis_payload(campaign=campaign, task=task)
            )
        except Exception as exc:
            raise _WorkerExecutionFailure from exc
        pipeline_run = repository.save_pipeline_run(
            program_id=campaign.program_id,
            asset=campaign.default_asset,
            policy_text=campaign.policy_text_hash,
            policy_text_is_hash=True,
            scope_status=campaign.scope_status,
            hypothesis_count=len(hypothesis_payload["hypotheses"]),
            blocked_count=1,
            report_title="Campaign hypothesis candidate requires human review",
            payload=hypothesis_payload,
        )
        repository.save_pipeline_stage(
            pipeline_run_id=pipeline_run.id,
            campaign_id=campaign.id,
            task_id=task.id,
            stage_key="campaign_report_preview",
            stage_order=20,
            status="awaiting_review",
            input_refs=[f"campaign_task:{task.id}"],
            output_refs=[f"pipeline_run:{pipeline_run.id}"],
            safety_gate_state="awaiting_review",
            stop_reason=None,
            payload={
                "review_gate": "human_review_required",
                "submission_allowed": False,
                "raw_payload_processed": False,
            },
        )
        return (
            [f"pipeline_run:{pipeline_run.id}"],
            {
                "artifact_kind": "hypothesis_candidates",
                "pipeline_run_id": pipeline_run.id,
            },
        )

    if task.task_type == "report_chain_review":
        validation_target = _validation_target_from_codebase_facts(
            campaign=campaign,
            repository=repository,
        )
        plan_digest = _stable_ref_hash(
            f"campaign_task:{task.id}:validation_plan:{validation_target['target_ref']}"
        )
        approval = repository.create_approval_record(
            campaign_id=campaign.id,
            task_id=task.id,
            program_id=campaign.program_id,
            approval_type="validation_batch",
            actor="worker",
            reason="Validation plan requires human approval before execution.",
            requested_action="two_account_authorization_check",
            asset=campaign.default_asset,
            validation_mode="two_account_authorization_check",
            plan_digest=plan_digest,
            autonomy_level=campaign.autonomy_level,
            safety_gate_state="awaiting_approval",
            payload={"raw_payload_processed": False},
        )
        validation_run = repository.save_validation_run(
            campaign_id=campaign.id,
            task_id=task.id,
            approval_id=None,
            validation_mode="two_account_authorization_check",
            target_ref=validation_target["target_ref"],
            status="planned",
            safety_gate_state="awaiting_approval",
            plan_digest=approval.plan_digest,
            approval_required=True,
            allowed_to_execute=False,
            evidence_ref_count=0,
            summary=validation_target["summary"],
            payload={
                "approval_record_id": approval.id,
                "raw_payload_processed": False,
                "no_live_requests": True,
                **validation_target["payload"],
            },
        )
        return (
            [f"approval:{approval.id}", f"validation_run:{validation_run.id}"],
            {
                "artifact_kind": "report_chain_gate",
                "approval_id": approval.id,
                "validation_run_id": validation_run.id,
            },
        )

    return (
        [],
        {"artifact_kind": "task_completion_marker"},
    )


def _runtime_target_intake_projection(
    *,
    authorized_code_files: object,
) -> dict:
    from app.intake_agent import build_intake_profile

    code_files = authorized_code_files if isinstance(authorized_code_files, list) else []
    profile = build_intake_profile(authorized_code_files=code_files)
    languages = sorted(
        language
        for language in profile.language
        if language in _RUNTIME_TARGET_INTAKE_LANGUAGES
    )
    frameworks = sorted(
        framework
        for framework in profile.framework
        if framework in _RUNTIME_TARGET_INTAKE_FRAMEWORKS
    )
    status = (
        profile.status
        if profile.status in _RUNTIME_TARGET_INTAKE_STATUSES
        else "intake_no_artifacts"
    )
    return {
        "artifact_kind": "target_intake_projection",
        "projection_schema": _RUNTIME_TARGET_INTAKE_PROJECTION_SCHEMA,
        "status": status,
        "languages": languages,
        "frameworks": frameworks,
        "source_files_scanned": min(max(profile.source_files_scanned, 0), 400),
        "entrypoint_count": min(len(profile.entrypoints), 80),
        "auth_component_count": min(len(profile.auth_components), 60),
        "raw_payload_processed": False,
        "execution_allowed": False,
        "dispatch_allowed": False,
        "validation_allowed": False,
        "candidate_promotion_allowed": False,
        "report_submission_allowed": False,
    }


def _runtime_target_intake_projection_is_valid(value: object) -> bool:
    required_keys = {
        "artifact_kind",
        "projection_schema",
        "status",
        "languages",
        "frameworks",
        "source_files_scanned",
        "entrypoint_count",
        "auth_component_count",
        *_RUNTIME_TARGET_INTAKE_SAFETY_FIELDS,
    }
    if not isinstance(value, dict) or set(value) != required_keys:
        return False
    if (
        value.get("artifact_kind") != "target_intake_projection"
        or value.get("projection_schema") != _RUNTIME_TARGET_INTAKE_PROJECTION_SCHEMA
        or value.get("status") not in _RUNTIME_TARGET_INTAKE_STATUSES
        or not _runtime_target_intake_labels_are_valid(
            value.get("languages"),
            _RUNTIME_TARGET_INTAKE_LANGUAGES,
        )
        or not _runtime_target_intake_labels_are_valid(
            value.get("frameworks"),
            _RUNTIME_TARGET_INTAKE_FRAMEWORKS,
        )
        or any(
            type(value.get(field)) is not int
            or not 0 <= value[field] <= maximum
            for field, maximum in (
                ("source_files_scanned", 400),
                ("entrypoint_count", 80),
                ("auth_component_count", 60),
            )
        )
    ):
        return False
    return all(
        value.get(field) is False for field in _RUNTIME_TARGET_INTAKE_SAFETY_FIELDS
    )


def _runtime_target_intake_labels_are_valid(
    value: object,
    allowed_values: set[str],
) -> bool:
    return (
        isinstance(value, list)
        and len(value) <= len(allowed_values)
        and all(isinstance(label, str) and label in allowed_values for label in value)
        and value == sorted(set(value))
    )


def _runtime_observed_target_intake_projection(
    *,
    task: CampaignTaskRecord,
    campaign: CampaignRecord,
    repository: DatabaseRepository,
    expected_target_intake: dict | None = None,
) -> tuple[dict | None, str | None, str | None]:
    task_payload = task.payload if isinstance(task.payload, dict) else {}
    if task_payload.get("runtime_schema") != _AUTONOMOUS_RESEARCH_RUNTIME_SCHEMA:
        return None, None, None
    source_snapshot_digest = _worker_safe_string(
        task_payload.get("source_snapshot_digest")
    )
    if _SOURCE_SNAPSHOT_DIGEST_PATTERN.fullmatch(source_snapshot_digest) is None:
        return None, None, "target_intake_projection_missing"

    observation_tasks = [
        candidate
        for candidate in repository.list_campaign_tasks(campaign.id)
        if candidate.task_type == "campaign_observation"
        and candidate.status == "completed"
        and isinstance(candidate.payload, dict)
        and candidate.payload.get("runtime_schema")
        == _AUTONOMOUS_RESEARCH_RUNTIME_SCHEMA
        and candidate.payload.get("source_snapshot_digest") == source_snapshot_digest
    ]
    if not observation_tasks:
        return None, None, "target_intake_projection_missing"
    if len(observation_tasks) != 1:
        return None, None, "target_intake_projection_invalid"

    observation_task = observation_tasks[0]
    projection_ref = f"campaign_observation_projection:{observation_task.id}"
    if projection_ref not in observation_task.output_refs:
        return None, None, "target_intake_projection_missing"
    runtime_stages = [
        stage
        for stage in repository.list_campaign_pipeline_stages(campaign.id)
        if stage.task_id == observation_task.id
        and stage.stage_key == "autonomous_research:campaign_observation"
        and stage.status == "completed"
        and stage.safety_gate_state == "allowed"
        and isinstance(stage.payload, dict)
        and stage.payload.get("runtime_schema")
        == _AUTONOMOUS_RESEARCH_RUNTIME_SCHEMA
        and stage.payload.get("source_snapshot_digest") == source_snapshot_digest
        and projection_ref in stage.output_refs
    ]
    agent_runs = [
        run
        for run in repository.list_campaign_agent_runs(campaign.id)
        if run.task_id == observation_task.id
        and run.status == "completed"
        and run.safety_gate_state == "allowed"
        and projection_ref in run.output_refs
    ]
    if not runtime_stages or not agent_runs:
        return None, None, "target_intake_projection_missing"
    if len(runtime_stages) != 1 or len(agent_runs) != 1:
        return None, None, "target_intake_projection_invalid"

    run_payload = (
        agent_runs[0].payload if isinstance(agent_runs[0].payload, dict) else {}
    )
    target_intake = run_payload.get("target_intake")
    if (
        run_payload.get("artifact_kind") != "campaign_observation_projection"
        or run_payload.get("projection_schema")
        != _CAMPAIGN_OBSERVATION_PROJECTION_SCHEMA
        or run_payload.get("source_snapshot_digest") != source_snapshot_digest
        or any(
            run_payload.get(field) is not False
            for field in _RUNTIME_TARGET_INTAKE_SAFETY_FIELDS
        )
        or not isinstance(target_intake, dict)
        or not _runtime_target_intake_projection_is_valid(target_intake)
        or run_payload.get("target_intake_digest") != _canonical_digest(target_intake)
        or (
            expected_target_intake is not None
            and (
                not _runtime_target_intake_projection_is_valid(expected_target_intake)
                or target_intake != expected_target_intake
            )
        )
    ):
        return None, None, "target_intake_projection_invalid"
    return target_intake, projection_ref, None


def _runtime_target_model_projection(
    *,
    task: CampaignTaskRecord,
    campaign: CampaignRecord,
    repository: DatabaseRepository,
) -> tuple[dict | None, str | None]:
    task_payload = task.payload if isinstance(task.payload, dict) else {}
    if task_payload.get("runtime_schema") != _AUTONOMOUS_RESEARCH_RUNTIME_SCHEMA:
        return None, None
    source_snapshot_digest = _worker_safe_string(
        task_payload.get("source_snapshot_digest")
    )
    if _SOURCE_SNAPSHOT_DIGEST_PATTERN.fullmatch(source_snapshot_digest) is None:
        return None, "target_model_projection_missing"
    (
        target_intake,
        target_intake_ref,
        target_intake_stop_reason,
    ) = _runtime_observed_target_intake_projection(
        task=task,
        campaign=campaign,
        repository=repository,
    )
    if target_intake_stop_reason is not None:
        return None, (
            "target_model_projection_invalid"
            if target_intake_stop_reason == "target_intake_projection_invalid"
            else "target_model_projection_missing"
        )
    mapping_tasks = [
        candidate
        for candidate in repository.list_campaign_tasks(campaign.id)
        if candidate.task_type == "attack_surface_mapping"
        and candidate.status == "completed"
        and isinstance(candidate.payload, dict)
        and candidate.payload.get("runtime_schema")
        == _AUTONOMOUS_RESEARCH_RUNTIME_SCHEMA
        and candidate.payload.get("source_snapshot_digest") == source_snapshot_digest
    ]
    if not mapping_tasks:
        return None, "target_model_projection_missing"
    if len(mapping_tasks) != 1:
        return None, "target_model_projection_invalid"
    mapping_task = mapping_tasks[0]
    projection_ref = f"target_model_projection:{mapping_task.id}"
    if projection_ref not in mapping_task.output_refs:
        return None, "target_model_projection_missing"
    runtime_stages = [
        stage
        for stage in repository.list_campaign_pipeline_stages(campaign.id)
        if stage.task_id == mapping_task.id
        and stage.stage_key == "autonomous_research:attack_surface_mapping"
        and stage.status == "completed"
        and stage.safety_gate_state == "allowed"
        and isinstance(stage.payload, dict)
        and stage.payload.get("runtime_schema")
        == _AUTONOMOUS_RESEARCH_RUNTIME_SCHEMA
        and stage.payload.get("source_snapshot_digest") == source_snapshot_digest
        and projection_ref in stage.output_refs
    ]
    runs = [
        run
        for run in repository.list_campaign_agent_runs(campaign.id)
        if run.task_id == mapping_task.id
        and run.status == "completed"
        and run.safety_gate_state == "allowed"
        and projection_ref in run.output_refs
    ]
    if not runtime_stages or not runs:
        return None, "target_model_projection_missing"
    if len(runtime_stages) != 1 or len(runs) != 1:
        return None, "target_model_projection_invalid"
    run_payload = runs[0].payload if isinstance(runs[0].payload, dict) else {}
    projection = run_payload.get("target_model_projection")
    if not isinstance(projection, dict):
        return None, "target_model_projection_missing"
    codebase_map_id = _worker_safe_string(projection.get("codebase_map_id"))
    codebase_map = next(
        (
            item
            for item in repository.list_campaign_codebase_maps(campaign.id)
            if item.id == codebase_map_id
        ),
        None,
    )
    if (
        codebase_map is None
        or codebase_map.status != "mapped"
        or codebase_map.safety_gate_state != "allowed"
    ):
        return None, "target_model_projection_invalid"
    expected_projection = _build_runtime_target_model_projection(
        codebase_map_id=codebase_map.id,
        source_snapshot_digest=source_snapshot_digest,
        codebase_facts=repository.list_codebase_facts(codebase_map.id),
        target_intake=target_intake,
        target_intake_ref=target_intake_ref,
    )
    if expected_projection is None or projection != expected_projection:
        return None, "target_model_projection_invalid"
    return expected_projection, None


def _runtime_security_invariant_projection(
    *,
    task: CampaignTaskRecord,
    campaign: CampaignRecord,
    repository: DatabaseRepository,
) -> tuple[list[dict] | None, str | None]:
    task_payload = task.payload if isinstance(task.payload, dict) else {}
    if task_payload.get("runtime_schema") != _AUTONOMOUS_RESEARCH_RUNTIME_SCHEMA:
        return None, None
    source_snapshot_digest = task_payload.get("source_snapshot_digest")
    if not isinstance(source_snapshot_digest, str) or not _SOURCE_SNAPSHOT_DIGEST_PATTERN.fullmatch(
        source_snapshot_digest
    ):
        return None, "security_invariant_projection_missing"

    invariant_tasks = [
        candidate
        for candidate in repository.list_campaign_tasks(campaign.id)
        if candidate.task_type == "security_invariant_generation"
        and candidate.status == "completed"
        and isinstance(candidate.payload, dict)
        and candidate.payload.get("runtime_schema")
        == _AUTONOMOUS_RESEARCH_RUNTIME_SCHEMA
        and candidate.payload.get("source_snapshot_digest") == source_snapshot_digest
    ]
    if len(invariant_tasks) != 1:
        return None, "security_invariant_projection_missing"
    invariant_task = invariant_tasks[0]
    expected_ref = f"security_invariant_projection:{invariant_task.id}"
    if expected_ref not in invariant_task.output_refs:
        return None, "security_invariant_projection_missing"
    invariant_stages = [
        stage
        for stage in repository.list_campaign_pipeline_stages(campaign.id)
        if stage.task_id == invariant_task.id
        and stage.stage_key == "autonomous_research:security_invariant_generation"
        and stage.status == "completed"
        and stage.safety_gate_state == "allowed"
        and expected_ref in stage.output_refs
        and isinstance(stage.payload, dict)
        and stage.payload.get("runtime_schema")
        == _AUTONOMOUS_RESEARCH_RUNTIME_SCHEMA
        and stage.payload.get("source_snapshot_digest") == source_snapshot_digest
    ]
    if len(invariant_stages) != 1:
        return None, "security_invariant_projection_missing"

    runs = [
        run
        for run in repository.list_campaign_agent_runs(campaign.id)
        if run.task_id == invariant_task.id and run.status == "completed"
    ]
    if len(runs) != 1 or expected_ref not in runs[0].output_refs:
        return None, "security_invariant_projection_missing"
    invariants = _safe_security_invariant_projection(
        runs[0].payload,
        source_snapshot_digest=source_snapshot_digest,
    )
    if invariants is None:
        return None, "security_invariant_projection_missing"
    return invariants, None


def _build_security_invariant_projection(
    codebase_facts: list[CodebaseFactRecord],
    *,
    attack_surface_queue: list[dict] | None = None,
) -> list[dict]:
    invariants: list[dict] = []
    for route in _worker_prioritized_routes(
        codebase_facts,
        attack_surface_queue=attack_surface_queue,
    ):
        route_fact_ref = _codebase_fact_ref(route)
        if not route_fact_ref:
            continue
        authz = _related_fact(codebase_facts, route, "authz_check")
        sink = _related_fact(codebase_facts, route, "sensitive_sink")
        authz_gap = _related_fact(codebase_facts, route, "authorization_gap_candidate")
        family = _security_invariant_family(
            route=route,
            sink=sink,
            authz_gap=authz_gap,
        )
        status = (
            "needs_refutation"
            if authz_gap is not None
            else "guard_observed"
            if authz is not None
            else "needs_evidence"
        )
        source_fact_refs = [route_fact_ref]
        for related_fact in (authz, authz_gap, sink):
            if related_ref := _codebase_fact_ref(related_fact):
                _append_unique(source_fact_refs, related_ref)
        invariant_ref = "security_invariant:" + sha256(
            "\x1f".join([family, *source_fact_refs]).encode("utf-8")
        ).hexdigest()
        invariants.append(
            {
                "invariant_ref": invariant_ref,
                "family": family,
                "statement": _SECURITY_INVARIANT_FAMILIES[family],
                "status": status,
                "route_fact_ref": route_fact_ref,
                "source_fact_refs": source_fact_refs,
            }
        )
    return invariants[:100]


def _security_invariant_family(
    *,
    route: CodebaseFactRecord,
    sink: CodebaseFactRecord | None,
    authz_gap: CodebaseFactRecord | None,
) -> str:
    static_gap_profile = _worker_static_gap_profile(authz_gap)
    static_gap_family = _worker_safe_string(
        static_gap_profile.get("security_invariant_family")
        if static_gap_profile is not None
        else None
    )
    if static_gap_family in _SECURITY_INVARIANT_FAMILIES:
        return static_gap_family
    route_path = route.route_path or ""
    if authz_gap is not None or _route_path_has_template_placeholder(route_path):
        return "object_authorization_boundary"
    if sink is not None:
        return "sensitive_sink_boundary"
    return "route_authorization_boundary"


def _safe_security_invariant_projection(
    payload: object,
    *,
    source_snapshot_digest: str,
) -> list[dict] | None:
    if not isinstance(payload, dict):
        return None
    if (
        payload.get("artifact_kind") != "security_invariant_projection"
        or payload.get("projection_schema") != _SECURITY_INVARIANT_PROJECTION_SCHEMA
        or payload.get("source_snapshot_digest") != source_snapshot_digest
        or payload.get("raw_payload_processed") is not False
        or any(
            payload.get(field) is not False
            for field in (
                "execution_allowed",
                "validation_allowed",
                "candidate_promotion_allowed",
                "report_submission_allowed",
            )
        )
    ):
        return None
    values = payload.get("invariants")
    if not isinstance(values, list) or len(values) > 100:
        return None

    invariants: list[dict] = []
    seen_refs: set[str] = set()
    seen_routes: set[str] = set()
    for value in values:
        if not isinstance(value, dict) or set(value) != {
            "invariant_ref",
            "family",
            "statement",
            "status",
            "route_fact_ref",
            "source_fact_refs",
        }:
            return None
        invariant_ref = value.get("invariant_ref")
        family = value.get("family")
        statement = value.get("statement")
        status = value.get("status")
        route_fact_ref = value.get("route_fact_ref")
        source_fact_refs = value.get("source_fact_refs")
        if (
            not isinstance(invariant_ref, str)
            or not _SECURITY_INVARIANT_REF_PATTERN.fullmatch(invariant_ref)
            or invariant_ref in seen_refs
            or not isinstance(family, str)
            or family not in _SECURITY_INVARIANT_FAMILIES
            or statement != _SECURITY_INVARIANT_FAMILIES[family]
            or not isinstance(status, str)
            or status not in _SECURITY_INVARIANT_STATUSES
            or not isinstance(route_fact_ref, str)
            or not _CODEBASE_FACT_REF_PATTERN.fullmatch(route_fact_ref)
            or route_fact_ref in seen_routes
            or not isinstance(source_fact_refs, list)
            or not 1 <= len(source_fact_refs) <= 4
            or route_fact_ref not in source_fact_refs
            or any(
                not isinstance(item, str)
                or not _CODEBASE_FACT_REF_PATTERN.fullmatch(item)
                for item in source_fact_refs
            )
            or len(set(source_fact_refs)) != len(source_fact_refs)
        ):
            return None
        seen_refs.add(invariant_ref)
        seen_routes.add(route_fact_ref)
        invariants.append(
            {
                "invariant_ref": invariant_ref,
                "family": family,
                "statement": statement,
                "status": status,
                "route_fact_ref": route_fact_ref,
                "source_fact_refs": list(source_fact_refs),
            }
        )
    return invariants


def _codebase_fact_ref(fact: CodebaseFactRecord | None) -> str:
    if fact is None or not isinstance(fact.id, str):
        return ""
    fact_ref = f"codebase_fact:{fact.id}"
    return fact_ref if _CODEBASE_FACT_REF_PATTERN.fullmatch(fact_ref) else ""


def _validation_target_from_codebase_facts(
    *,
    campaign: CampaignRecord,
    repository: DatabaseRepository,
) -> dict:
    codebase_facts = repository.list_campaign_codebase_facts(campaign.id)
    route = next(
        (
            fact
            for fact in codebase_facts
            if fact.fact_type == "route_handler"
            and _route_artifact_kind(fact) != "sarif"
        ),
        None,
    )
    if route is None:
        return {
            "target_ref": f"campaign:{campaign.id}",
            "summary": "Validation is planned but blocked pending durable human approval.",
            "payload": {},
        }

    authz = _related_fact(codebase_facts, route, "authz_check")
    sink = _related_fact(codebase_facts, route, "sensitive_sink")
    authz_gap = _related_fact(codebase_facts, route, "authorization_gap_candidate")
    route_label = _route_label(route)
    source_facts = _hypothesis_source_facts(
        codebase_facts=codebase_facts,
        route=route,
        authz=authz,
        sink=sink,
        authz_gap=authz_gap,
    )
    return {
        "target_ref": _codebase_fact_ref(route),
        "summary": (
            f"Validation is planned for mapped code fact {route_label} "
            "but blocked pending durable human approval."
        ),
        "payload": {
            "source_fact_refs": [fact["fact_ref"] for fact in source_facts],
            "target_route": route_label,
        },
    }


def _fallback_hypothesis_payload(
    *,
    campaign: CampaignRecord,
    task: CampaignTaskRecord,
) -> dict:
    candidate_id = "campaign_worker_hypothesis_1"
    hypothesis = {
        "hypothesis_id": candidate_id,
        "hypothesis": "Authorized object access may have a review-worthy boundary.",
        "vuln_type": "authorization_boundary",
        "broken_invariant": "Users should only access objects permitted by role and ownership.",
        "validation_mode": "two_account_authorization_check",
        "risk_level": "medium",
        "policy_risk": "medium",
        "evidence_needed": ["test_account_role_matrix", "redacted_request_response_diff"],
    }
    return {
        "campaign_id": campaign.id,
        "source_task_id": task.id,
        "target_model": {
            "objects": ["authorized_surface"],
            "roles": ["user", "owner"],
            "sensitive_actions": [],
        },
        "hypotheses": [hypothesis],
        "hypothesis_assessments": [
            {
                "candidate_id": candidate_id,
                "hypothesis_index": 0,
                "hypothesis": hypothesis,
                "candidate_status": "needs_human_review",
                "refutation": {
                    "status": "needs_human_review",
                    "reasons": ["worker_generated_candidate"],
                    "questions": [
                        "Which blocker must be resolved before any validation planning?",
                        "What safe artifact or manual observation would resolve the blocker?",
                    ],
                    "human_review_required": True,
                },
                "exploit_chain": {
                    "primitives": [
                        "authorization boundary review",
                        "non-destructive evidence comparison",
                    ],
                    "preconditions": [
                        "authorized test accounts only",
                        "human approval before validation",
                        "synthetic fixtures only",
                    ],
                    "impact": "Potential medium impact if the invariant is broken.",
                    "confidence": 0.4,
                    "safety_notes": [
                        "non_executable_chain_summary",
                        "no_payloads_or_requests",
                        "human_review_required",
                    ],
                },
                "validation_plan": {
                    "status": "approval_required",
                    "methods": ["manual_review"],
                    "steps": ["Review with test accounts only."],
                    "human_approval_required": True,
                },
            }
        ],
        "timeline": [
            {
                "name": "hypothesis_generation",
                "status": "completed",
                "summary": "Worker generated one advisory hypothesis candidate.",
                "safety_notes": ["no_live_requests", "human_review_required"],
            }
        ],
    }


def _candidate_hunter_persisted_code_facts(
    codebase_facts: list[CodebaseFactRecord],
) -> list[CodebaseFactCandidate]:
    allowed_fact_types = {
        "route_handler",
        "authz_check",
        "sensitive_sink",
        "service_call",
        "unverified_token_decode",
        "authorization_gap_candidate",
    }
    projected: list[CodebaseFactCandidate] = []
    seen: set[tuple[object, ...]] = set()
    for fact in codebase_facts:
        if fact.fact_type not in allowed_fact_types:
            continue
        payload = fact.payload if isinstance(fact.payload, dict) else {}
        if payload.get("mapping_mode") in {
            "authorized_api_artifact",
            "authorized_advisory_artifact",
        }:
            continue
        source_path = _worker_safe_string(fact.source_path)
        symbol_name = _worker_safe_string(fact.symbol_name)
        if not source_path or not symbol_name:
            continue
        handler = _worker_safe_string(payload.get("handler")) or symbol_name
        caller = _worker_safe_string(payload.get("caller"))
        line = payload.get("line")
        safe_line = line if isinstance(line, int) and 0 < line <= 1_000_000 else 0
        column = payload.get("column")
        safe_column = (
            column if isinstance(column, int) and 0 <= column <= 1_000_000 else 0
        )
        token_ref = _worker_safe_string(payload.get("token_ref"))
        safe_token_ref = (
            token_ref if _TOKEN_REFERENCE_PATTERN.fullmatch(token_ref) else ""
        )
        safe_claim_ref = safe_claim_reference(payload.get("claims_ref")) or ""
        safe_input_ref = safe_input_reference(payload.get("input_ref")) or ""
        safe_validated_output_ref = (
            safe_input_reference(payload.get("validated_output_ref")) or ""
        )
        safe_input_ref_kind = (
            INPUT_REFERENCE_KIND_STRAIGHT_LINE
            if (
                (safe_input_ref or safe_validated_output_ref)
                and payload.get("input_ref_kind")
                == INPUT_REFERENCE_KIND_STRAIGHT_LINE
            )
            else ""
        )
        if not safe_input_ref_kind:
            safe_input_ref = ""
            safe_validated_output_ref = ""
        safe_service_class = _worker_safe_typescript_identifier(
            payload.get("service_class")
        )
        safe_service_receiver = _worker_safe_typescript_identifier(
            payload.get("service_receiver")
        )
        safe_target_service_class = _worker_safe_typescript_identifier(
            payload.get("target_service_class")
        )
        safe_target_service_source_path = _worker_safe_typescript_source_path(
            payload.get("target_service_source_path")
        )
        key = (
            _worker_safe_string(fact.fact_type),
            source_path,
            symbol_name,
            _worker_safe_string(fact.route_method),
            _worker_safe_string(fact.route_path),
            _worker_safe_string(fact.authz_hint),
            handler,
            safe_line,
            safe_column,
            safe_token_ref,
            safe_claim_ref,
            safe_input_ref,
            safe_validated_output_ref,
            safe_service_class,
            safe_service_receiver,
            safe_target_service_class,
            safe_target_service_source_path,
        )
        if key in seen:
            continue
        seen.add(key)
        safe_payload: dict[str, object] = {
            "handler": handler,
            "mapping_mode": "persisted_codebase_fact_projection",
            "raw_payload_processed": False,
        }
        if caller:
            safe_payload["caller"] = caller
        if safe_line:
            safe_payload["line"] = safe_line
        if safe_column:
            safe_payload["column"] = safe_column
        if safe_token_ref:
            safe_payload["token_ref"] = safe_token_ref
        if safe_claim_ref:
            safe_payload["claims_ref"] = safe_claim_ref
        if safe_input_ref:
            safe_payload["input_ref"] = safe_input_ref
            safe_payload["input_ref_kind"] = safe_input_ref_kind
        if safe_validated_output_ref:
            safe_payload["validated_output_ref"] = safe_validated_output_ref
        if safe_service_class:
            safe_payload["service_class"] = safe_service_class
        if safe_service_receiver:
            safe_payload["service_receiver"] = safe_service_receiver
        if safe_target_service_class:
            safe_payload["target_service_class"] = safe_target_service_class
        if safe_target_service_source_path:
            safe_payload["target_service_source_path"] = (
                safe_target_service_source_path
            )
        for name in ("root_cause", "root_symbol"):
            if value := _worker_safe_string(payload.get(name)):
                safe_payload[name] = value
        if sink_symbols := _worker_safe_string_list(payload.get("sink_symbols")):
            safe_payload["sink_symbols"] = sink_symbols
        if decoder_symbols := _worker_safe_string_list(payload.get("decoder_symbols")):
            safe_payload["decoder_symbols"] = decoder_symbols
        projected.append(
            CodebaseFactCandidate(
                fact_type=_worker_safe_string(fact.fact_type),
                source_path=source_path,
                symbol_name=symbol_name,
                route_method=_worker_safe_string(fact.route_method) or None,
                route_path=_worker_safe_string(fact.route_path) or None,
                authz_hint=_worker_safe_string(fact.authz_hint) or None,
                sensitivity_label=_worker_safe_string(fact.sensitivity_label)
                or "authorized_local_code",
                payload=safe_payload,
            )
        )
    return projected


def _codebase_fact_hypothesis_payload(
    *,
    campaign: CampaignRecord,
    task: CampaignTaskRecord,
    codebase_facts: list[CodebaseFactRecord],
    learning_signals: list[LearningSignalRecord] | None = None,
    security_invariants: list[dict] | None = None,
    target_model_projection: dict | None = None,
) -> dict:
    routes = _worker_prioritized_routes(
        codebase_facts,
        attack_surface_queue=(
            target_model_projection.get("attack_surface_queue")
            if isinstance(target_model_projection, dict)
            else None
        ),
    )
    if not routes:
        return _fallback_hypothesis_payload(campaign=campaign, task=task)

    hypotheses: list[dict] = []
    assessments: list[dict] = []
    object_names: list[str] = []
    sensitive_actions: list[str] = []
    source_fact_refs: list[str] = []
    security_invariant_refs: list[str] = []
    security_invariants_by_route = {
        invariant["route_fact_ref"]: invariant
        for invariant in security_invariants or []
        if isinstance(invariant, dict)
        and isinstance(invariant.get("route_fact_ref"), str)
        and isinstance(invariant.get("invariant_ref"), str)
    }
    lessons = _worker_mythos_lessons(learning_signals or [])

    for index, route in enumerate(routes, start=1):
        candidate = _codebase_route_hypothesis(
            codebase_facts=codebase_facts,
            route=route,
            index=index,
            lessons=lessons,
            security_invariant=security_invariants_by_route.get(_codebase_fact_ref(route)),
        )
        hypotheses.append(candidate["hypothesis"])
        assessments.append(candidate["assessment"])
        _append_unique(object_names, candidate["object_name"])
        _append_unique(sensitive_actions, candidate["route_label"])
        for fact_ref in candidate["source_fact_refs"]:
            _append_unique(source_fact_refs, fact_ref)
        if security_invariant_ref := candidate.get("security_invariant_ref"):
            _append_unique(security_invariant_refs, security_invariant_ref)

    target_model = {
        "objects": object_names,
        "roles": ["user", "owner"],
        "sensitive_actions": sensitive_actions,
        "source_fact_refs": source_fact_refs,
    }
    if security_invariant_refs:
        target_model["security_invariant_refs"] = security_invariant_refs
    target_model.update(
        _runtime_target_intake_context_for_hypothesis(target_model_projection)
    )
    target_model.update(
        _runtime_attack_surface_context_for_hypothesis(target_model_projection)
    )

    return {
        "campaign_id": campaign.id,
        "source_task_id": task.id,
        "target_model": target_model,
        "hypotheses": hypotheses,
        "hypothesis_assessments": assessments,
        "autonomous_hunt_queue": _worker_autonomous_hunt_queue(assessments),
        "timeline": [
            {
                "name": "hypothesis_generation",
                "status": "completed",
                "summary": (
                    f"Worker generated {len(hypotheses)} advisory hypothesis candidate(s) "
                    "from mapped codebase facts."
                ),
                "safety_notes": [
                    "no_live_requests",
                    "codebase_facts_are_not_confirmed_findings",
                    "human_review_required",
                ],
            }
        ],
    }


def _runtime_target_intake_context_for_hypothesis(
    target_model_projection: dict | None,
) -> dict:
    if not isinstance(target_model_projection, dict):
        return {}
    target_intake = target_model_projection.get("target_intake")
    target_intake_ref = target_model_projection.get("target_intake_ref")
    target_intake_digest = target_model_projection.get("target_intake_digest")
    if (
        not isinstance(target_intake, dict)
        or not _runtime_target_intake_projection_is_valid(target_intake)
        or not isinstance(target_intake_ref, str)
        or not target_intake_ref.startswith("campaign_observation_projection:")
        or target_intake_digest != _canonical_digest(target_intake)
    ):
        return {}
    return {
        "target_intake_ref": target_intake_ref,
        "target_intake_digest": target_intake_digest,
        "target_intake": {
            "status": target_intake["status"],
            "languages": list(target_intake["languages"]),
            "frameworks": list(target_intake["frameworks"]),
            "source_files_scanned": target_intake["source_files_scanned"],
            "entrypoint_count": target_intake["entrypoint_count"],
            "auth_component_count": target_intake["auth_component_count"],
        },
    }


def _runtime_attack_surface_context_for_hypothesis(
    target_model_projection: dict | None,
) -> dict:
    if not isinstance(target_model_projection, dict):
        return {}
    queue = target_model_projection.get("attack_surface_queue")
    schema = target_model_projection.get("attack_surface_queue_schema")
    digest = target_model_projection.get("attack_surface_queue_digest")
    if (
        schema != _RUNTIME_ATTACK_SURFACE_QUEUE_SCHEMA
        or not isinstance(queue, list)
        or digest != _canonical_digest(queue)
    ):
        return {}
    selected_count = target_model_projection.get("attack_surface_selected_count")
    route_count = target_model_projection.get("attack_surface_route_count")
    if (
        not isinstance(selected_count, int)
        or isinstance(selected_count, bool)
        or not isinstance(route_count, int)
        or isinstance(route_count, bool)
        or selected_count != len(queue)
        or selected_count > route_count
    ):
        return {}
    return {
        "attack_surface_queue_schema": schema,
        "attack_surface_queue_digest": digest,
        "attack_surface_route_count": route_count,
        "attack_surface_selected_count": selected_count,
    }


def _worker_autonomous_hunt_queue(assessments: list[dict]) -> list[dict]:
    queue = []
    for assessment in assessments:
        hunter_assessment = assessment.get("hunter_assessment", {})
        quality_gate = _worker_candidate_quality_gate(assessment)
        item = {
            "queue_id": f"hunt_queue_{assessment['candidate_id']}",
            "candidate_id": assessment["candidate_id"],
            "playbook_id": hunter_assessment.get(
                "playbook_id",
                "codebase_authorization_boundary",
            ),
            "priority_score": quality_gate["priority_score"],
            "status": quality_gate["status"],
            "next_action": quality_gate["next_action"],
            "human_approval_required": True,
            "blocked_actions": [
                "execute_live_validation",
                "touch_real_user_data",
                "submit_report",
                "bypass_scope_guard",
            ],
            "safety_notes": [
                "scope_guard_required",
                "non_destructive_validation_only",
                "human_review_required",
            ],
        }
        similarity_key = _worker_candidate_similarity_key(assessment)
        if similarity_key:
            item["_candidate_similarity_key"] = similarity_key
        evidence_trace_summary = _worker_evidence_trace_summary(assessment)
        if evidence_trace_summary:
            item["evidence_trace_summary"] = evidence_trace_summary
        if quality_gate["required_evidence"]:
            item["required_evidence"] = quality_gate["required_evidence"]
        if quality_gate["satisfied_evidence"]:
            item["satisfied_evidence"] = quality_gate["satisfied_evidence"]
        review_summary = _worker_queue_review_summary(assessment)
        if review_summary:
            item.update(review_summary)
        if quality_gate["quality_gate_reasons"]:
            item["raw_priority_score"] = quality_gate["raw_priority_score"]
            item["quality_gate_reasons"] = quality_gate["quality_gate_reasons"]
        queue.append(item)
    _worker_apply_candidate_similarity_dedup(queue)
    for item in queue:
        item["report_readiness"] = _worker_report_readiness_summary(item)
    ranked_queue = sorted(queue, key=lambda item: item["priority_score"], reverse=True)[:5]
    for index, item in enumerate(ranked_queue, start=1):
        item.pop("_candidate_similarity_key", None)
        item["top_candidate_rank"] = index
    return ranked_queue


def _worker_queue_review_summary(assessment: dict) -> dict:
    hypothesis = assessment.get("hypothesis")
    if not isinstance(hypothesis, dict):
        return {}
    source_facts = hypothesis.get("source_facts")
    if not isinstance(source_facts, list) or not _source_facts_include_api_or_har(source_facts):
        return {}

    validation_plan = assessment.get("validation_plan")
    validation_steps = []
    validation_status = "approval_required"
    if isinstance(validation_plan, dict):
        validation_steps = _worker_safe_string_list(validation_plan.get("steps", []))
        validation_status = _worker_safe_string(validation_plan.get("status", "approval_required"))

    evidence_needed = _worker_safe_string_list(hypothesis.get("evidence_needed", []))
    if not evidence_needed and not validation_steps:
        return {}
    return {
        "evidence_needed": evidence_needed,
        "safe_validation_plan": validation_steps,
        "safe_validation_step_count": len(validation_steps),
        "validation_plan_status": validation_status,
    }


def _source_facts_include_api_or_har(source_facts: list[object]) -> bool:
    return any(
        isinstance(fact, dict) and fact.get("artifact_kind") in {"api", "har"}
        for fact in source_facts
    )


def _worker_evidence_trace_summary(assessment: dict) -> dict:
    hypothesis = assessment.get("hypothesis")
    if not isinstance(hypothesis, dict):
        return {}
    source_facts = hypothesis.get("source_facts")
    if not isinstance(source_facts, list):
        return {}

    artifact_kinds: list[str] = []
    source_fact_types: list[str] = []
    route_fact_count = 0
    traceable_count = 0
    for fact in source_facts:
        if not isinstance(fact, dict):
            continue
        artifact_kind = _worker_safe_trace_label(fact.get("artifact_kind", ""))
        fact_type = _worker_safe_trace_label(fact.get("fact_type", ""))
        if artifact_kind:
            _append_unique(artifact_kinds, artifact_kind)
        if fact_type:
            _append_unique(source_fact_types, fact_type)
        if fact_type == "route_handler":
            route_fact_count += 1
        if fact.get("fact_ref") and artifact_kind:
            traceable_count += 1

    source_fact_count = sum(1 for fact in source_facts if isinstance(fact, dict))
    trace_status = (
        "traceable"
        if source_fact_count > 0 and traceable_count == source_fact_count
        else "needs_evidence"
    )
    return {
        "trace_status": trace_status,
        "source_fact_count": source_fact_count,
        "traceable_source_fact_count": traceable_count,
        "route_fact_count": route_fact_count,
        "artifact_kinds": artifact_kinds,
        "source_fact_types": source_fact_types,
        "report_submission_allowed": False,
    }


def _worker_report_readiness_summary(item: dict) -> dict:
    required_evidence = _worker_safe_string_list(item.get("required_evidence", []))
    evidence_trace = item.get("evidence_trace_summary")
    trace_status = (
        evidence_trace.get("trace_status", "needs_evidence")
        if isinstance(evidence_trace, dict)
        else "needs_evidence"
    )
    safe_validation_step_count = (
        item.get("safe_validation_step_count")
        if isinstance(item.get("safe_validation_step_count"), int)
        else 0
    )

    if required_evidence:
        status = "blocked_by_required_evidence"
        next_allowed_action = "Resolve required evidence gaps before report drafting."
    elif trace_status != "traceable":
        status = "blocked_by_evidence_trace"
        next_allowed_action = "Confirm candidate source facts are traceable before report drafting."
    elif safe_validation_step_count <= 0:
        status = "needs_safe_validation_plan"
        next_allowed_action = "Draft a non-destructive validation plan before report drafting."
    else:
        status = "submission_blocked_draft_ready"
        next_allowed_action = "Prepare a submission-blocked draft for human redaction review."

    return {
        "status": status,
        "submission_blocked": True,
        "report_submission_allowed": False,
        "required_evidence_count": len(required_evidence),
        "safe_validation_step_count": max(0, safe_validation_step_count),
        "trace_status": _worker_safe_string(trace_status) or "needs_evidence",
        "next_allowed_action": next_allowed_action,
    }


def _worker_safe_trace_label(value: object) -> str:
    text = _worker_safe_string(value).lower().replace("-", "_")
    if not text or any(
        marker in text
        for marker in ("authorization", "cookie", "token", "secret", "password", "session")
    ):
        return ""
    if not all(character.isalnum() or character == "_" for character in text):
        return ""
    return text[:80]


def _worker_candidate_similarity_key(assessment: dict) -> str:
    hypothesis = assessment.get("hypothesis")
    hunter_assessment = assessment.get("hunter_assessment", {})
    if not isinstance(hypothesis, dict) or not isinstance(hunter_assessment, dict):
        return ""
    source_facts = hypothesis.get("source_facts")
    if not isinstance(source_facts, list):
        return ""

    playbook_id = _worker_safe_string(
        hunter_assessment.get("playbook_id", "codebase_authorization_boundary")
    ).lower()
    route_keys: list[str] = []
    code_route_keys: list[str] = []
    for fact in source_facts:
        if not isinstance(fact, dict) or fact.get("fact_type") != "route_handler":
            continue
        route_path = _route_shape_path(
            _route_match_path(_worker_safe_string(fact.get("route_path", "")))
        ).lower().rstrip("/")
        if not route_path:
            continue
        route_method = (
            _worker_safe_string(fact.get("route_method", "")).upper() or "ANY"
        )
        _append_unique(route_keys, f"{route_method} {route_path or '/'}")
        if fact.get("artifact_kind") == "code":
            source_path = _worker_safe_string(fact.get("source_path", ""))
            symbol_name = _worker_safe_string(fact.get("symbol_name", ""))
            if source_path:
                _append_unique(code_route_keys, f"{source_path}:{symbol_name}")
    if not route_keys:
        return ""
    route_key = f"{playbook_id}|{sorted(route_keys)[0]}"
    if not code_route_keys:
        return route_key
    return f"{route_key}|{sorted(code_route_keys)[0]}"


def _worker_apply_candidate_similarity_dedup(queue: list[dict]) -> None:
    best_by_key: set[str] = set()
    for item in sorted(queue, key=lambda candidate: candidate["priority_score"], reverse=True):
        similarity_key = item.get("_candidate_similarity_key")
        if not isinstance(similarity_key, str) or not similarity_key:
            continue
        if similarity_key not in best_by_key:
            best_by_key.add(similarity_key)
            continue

        original_priority = item["priority_score"]
        item["priority_score"] = max(0, original_priority - 20)
        item["status"] = "awaiting_deduplication_review"
        item["next_action"] = "deduplicate_candidate"
        if "raw_priority_score" not in item:
            item["raw_priority_score"] = original_priority
        required_evidence = item.setdefault("required_evidence", [])
        _append_unique(required_evidence, "prior_submission_search")
        _append_unique(required_evidence, "candidate_similarity_review")
        quality_gate_reasons = item.setdefault("quality_gate_reasons", [])
        _append_unique(quality_gate_reasons, "similar_candidate_shape")


def _worker_safe_string_list(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    return [_worker_safe_string(item) for item in value if _worker_safe_string(item)]


def _worker_safe_string(value: object) -> str:
    if not isinstance(value, str):
        return ""
    return value.strip()[:500]


def _worker_safe_typescript_identifier(value: object) -> str:
    text = _worker_safe_string(value)
    return text if re.fullmatch(r"[A-Za-z_$][A-Za-z0-9_$]*", text) else ""


def _worker_safe_typescript_source_path(value: object) -> str:
    text = _worker_safe_string(value).replace("\\", "/")
    if (
        not text
        or len(text) > 200
        or text.startswith("/")
        or ":" in text
        or any(segment in {"", ".", ".."} for segment in text.split("/"))
        or not text.lower().endswith((".ts", ".tsx", ".mts", ".cts"))
    ):
        return ""
    return text


def _worker_candidate_quality_gate(assessment: dict) -> dict:
    hunter_assessment = assessment.get("hunter_assessment", {})
    raw_priority_score = hunter_assessment.get("hunter_priority_score", 65)
    priority_score = raw_priority_score
    status = "awaiting_human_approval"
    next_action = "review_validation_plan"
    required_evidence = _worker_required_evidence_from_hunter_reasons(
        hunter_assessment.get("reasons", [])
    )
    satisfied_evidence = _worker_satisfied_evidence_from_source_facts(assessment)
    required_evidence = [
        evidence for evidence in required_evidence if evidence not in satisfied_evidence
    ]
    quality_gate_reasons: list[str] = []

    if required_evidence:
        priority_score = max(0, priority_score - 25)
        status = "awaiting_evidence_review"
        next_action = "resolve_evidence_gaps"
        _append_unique(quality_gate_reasons, "required_evidence_missing")

    if _worker_candidate_source_trace_missing(assessment):
        priority_score = max(0, priority_score - 25)
        status = "awaiting_evidence_review"
        next_action = "resolve_evidence_gaps"
        _append_unique(required_evidence, "traceable_source_fact")
        _append_unique(quality_gate_reasons, "source_trace_missing")

    if hunter_assessment.get("duplicate_risk_score", 0) >= 70:
        priority_score = max(0, priority_score - 30)
        status = "awaiting_deduplication_review"
        next_action = "deduplicate_candidate"
        _append_unique(required_evidence, "prior_submission_search")
        _append_unique(required_evidence, "candidate_similarity_review")
        _append_unique(quality_gate_reasons, "duplicate_risk_high")

    return {
        "raw_priority_score": raw_priority_score,
        "priority_score": priority_score,
        "status": status,
        "next_action": next_action,
        "required_evidence": required_evidence,
        "satisfied_evidence": satisfied_evidence,
        "quality_gate_reasons": quality_gate_reasons,
    }


def _worker_candidate_source_trace_missing(assessment: dict) -> bool:
    hypothesis = assessment.get("hypothesis")
    if not isinstance(hypothesis, dict) or "source_facts" not in hypothesis:
        return False

    source_facts = hypothesis.get("source_facts")
    if not isinstance(source_facts, list) or not source_facts:
        return True

    return not any(
        isinstance(fact, dict)
        and fact.get("fact_ref")
        and fact.get("artifact_kind")
        for fact in source_facts
    )


def _worker_required_evidence_from_hunter_reasons(reasons: object) -> list[str]:
    if not isinstance(reasons, list):
        return []
    required: list[str] = []
    for reason in reasons:
        if not isinstance(reason, str):
            continue
        if "missing_evidence:independent_cross_check" in reason:
            _append_unique(required, "independent_refutation_or_static_rule")
        if "missing_evidence:authz_bypass_or_misbind_trace" in reason:
            _append_unique(required, "authz_bypass_or_misbind_trace")
        if reason == "authorization_gap_candidate":
            _append_unique(required, "independent_refutation_or_static_rule")
        if reason == "api_artifact_candidate":
            _append_unique(required, "local_code_or_har_correlation")
        if reason == "har_artifact_candidate":
            _append_unique(required, "local_code_or_api_schema_correlation")
        if "missing_evidence:declared_authentication_or_scope_model" in reason:
            _append_unique(required, "declared_authentication_or_scope_model")
        if "missing_required_artifact:policy" in reason:
            _append_unique(required, "policy")
    return required


def _worker_satisfied_evidence_from_source_facts(assessment: dict) -> list[str]:
    hypothesis = assessment.get("hypothesis")
    if not isinstance(hypothesis, dict):
        return []
    source_facts = hypothesis.get("source_facts")
    if not isinstance(source_facts, list):
        return []

    artifact_kinds = {
        fact.get("artifact_kind")
        for fact in source_facts
        if isinstance(fact, dict) and fact.get("fact_type") == "route_handler"
    }
    satisfied: list[str] = []
    if "api" in artifact_kinds and artifact_kinds.intersection({"code", "har"}):
        _append_unique(satisfied, "local_code_or_har_correlation")
    if "har" in artifact_kinds and artifact_kinds.intersection({"code", "api"}):
        _append_unique(satisfied, "local_code_or_api_schema_correlation")
    return satisfied


def _codebase_route_hypothesis(
    *,
    codebase_facts: list[CodebaseFactRecord],
    route: CodebaseFactRecord,
    index: int,
    lessons: list[MythosLesson] | None = None,
    security_invariant: dict | None = None,
) -> dict:
    authz = _related_fact(codebase_facts, route, "authz_check")
    sink = _related_fact(codebase_facts, route, "sensitive_sink")
    authz_gap = _related_fact(codebase_facts, route, "authorization_gap_candidate")
    static_gap_profile = _worker_static_gap_profile(authz_gap)
    static_gap_invariant_family = _worker_safe_string(
        static_gap_profile.get("security_invariant_family")
        if static_gap_profile is not None
        else None
    )
    static_invariant_matches = (
        static_gap_profile is not None
        and static_gap_invariant_family in _SECURITY_INVARIANT_FAMILIES
        and isinstance(security_invariant, dict)
        and security_invariant.get("family") == static_gap_invariant_family
        and security_invariant.get("statement")
        == _SECURITY_INVARIANT_FAMILIES[static_gap_invariant_family]
    )
    route_label = _route_label(route)
    source_facts = _hypothesis_source_facts(
        codebase_facts=codebase_facts,
        route=route,
        authz=authz,
        sink=sink,
        authz_gap=authz_gap,
    )
    candidate_id = f"codebase_fact_hypothesis_{index}"
    broken_invariant = (
        _worker_safe_string(static_gap_profile.get("broken_invariant"))
        if static_gap_profile is not None
        else "Route handlers that touch sensitive sinks must preserve object ownership and role boundaries."
    )
    if (
        static_gap_profile is None
        and isinstance(security_invariant, dict)
        and isinstance(security_invariant.get("statement"), str)
    ):
        broken_invariant = security_invariant["statement"]
    elif static_invariant_matches:
        broken_invariant = security_invariant["statement"]
    hypothesis_text = (
        _worker_safe_string(static_gap_profile.get("hypothesis")).format(
            route_label=route_label
        )
        if static_gap_profile is not None
        else f"Review {route_label} for object authorization boundary drift."
    )
    validation_mode = (
        _worker_safe_string(static_gap_profile.get("validation_mode"))
        if static_gap_profile is not None
        else "two_account_authorization_check"
    )
    evidence_needed = (
        _worker_profile_strings(static_gap_profile, "evidence_needed")
        if static_gap_profile is not None
        else _worker_evidence_needed(source_facts)
    )
    refutation_questions = (
        _worker_profile_strings(static_gap_profile, "refutation_questions")
        if static_gap_profile is not None
        else _worker_refutation_questions(authz_gap_present=authz_gap is not None)
    )
    validation_steps = (
        _worker_profile_strings(static_gap_profile, "validation_steps")
        if static_gap_profile is not None
        else _worker_validation_plan_steps(source_facts)
    )
    impact_rationale = (
        _worker_safe_string(static_gap_profile.get("impact"))
        if static_gap_profile is not None
        else "Potential object-level authorization impact if the mapped route and sink can be reached across ownership boundaries."
    )
    hypothesis = {
        "hypothesis_id": candidate_id,
        "hypothesis": hypothesis_text,
        "vuln_type": (
            _worker_safe_string(static_gap_profile.get("vuln_type"))
            if static_gap_profile is not None
            else "authorization_boundary"
        ),
        "broken_invariant": broken_invariant,
        "validation_mode": validation_mode,
        "impact_rationale": impact_rationale,
        "risk_level": "medium",
        "policy_risk": "medium",
        "evidence_needed": evidence_needed,
        "refutation_questions": refutation_questions,
        "safe_validation_plan": validation_steps,
        "source_facts": source_facts,
    }
    if static_gap_profile is not None:
        hypothesis["root_cause"] = static_gap_profile["root_cause"]
    if (
        isinstance(security_invariant, dict)
        and (static_gap_profile is None or static_invariant_matches)
    ):
        invariant_ref = security_invariant.get("invariant_ref")
        invariant_status = security_invariant.get("status")
        if isinstance(invariant_ref, str) and _SECURITY_INVARIANT_REF_PATTERN.fullmatch(
            invariant_ref
        ):
            hypothesis["security_invariant_ref"] = invariant_ref
        if isinstance(invariant_status, str) and invariant_status in _SECURITY_INVARIANT_STATUSES:
            hypothesis["security_invariant_status"] = invariant_status
    primitives = [route_label]
    if authz is not None and authz.authz_hint:
        primitives.append(authz.authz_hint)
    if authz_gap is not None and authz_gap.authz_hint:
        primitives.append(authz_gap.authz_hint)
    if sink is not None and sink.symbol_name:
        primitives.append(sink.symbol_name)
    hunter_assessment = _worker_hunter_assessment(
        route_label=route_label,
        hypothesis=hypothesis["hypothesis"],
        primitives=primitives,
        authz_gap_present=authz_gap is not None,
        sink_present=sink is not None,
        static_gap_profile=static_gap_profile,
    )
    _apply_worker_lessons(
        hunter_assessment,
        lessons or [],
        surface_key=_worker_route_surface_key(route),
    )
    if static_gap_profile is None:
        _apply_same_handler_authz_refutation(
            hunter_assessment,
            authz=authz,
            authz_gap_present=authz_gap is not None,
        )
    else:
        _apply_same_handler_static_gap_refutation(
            hunter_assessment,
            authz=authz,
            static_gap_profile=static_gap_profile,
        )
    if _worker_route_from_api_artifact(route):
        _append_unique(hunter_assessment["reasons"], "api_artifact_candidate")
        _append_unique(hunter_assessment["evidence_focus"], "local_code_or_har_correlation")
    if _worker_route_from_har_artifact(route):
        _append_unique(hunter_assessment["reasons"], "har_artifact_candidate")
        _append_unique(hunter_assessment["evidence_focus"], "local_code_or_api_schema_correlation")
    _apply_cross_artifact_route_evidence(hunter_assessment, source_facts)
    _apply_api_shape_signals(hunter_assessment, source_facts)
    hypothesis["hunter_assessment"] = hunter_assessment
    hypothesis["priority_score"] = hunter_assessment["hunter_priority_score"]
    impact_score = hunter_assessment.get("impact_score")
    hypothesis["impact_score"] = (
        impact_score
        if isinstance(impact_score, int) and not isinstance(impact_score, bool)
        else 0
    )
    return {
        "assessment": {
            "candidate_id": candidate_id,
            "hypothesis_index": index - 1,
            "hypothesis": hypothesis,
            "candidate_status": "needs_human_review",
            "refutation": {
                "status": "needs_human_review",
                "reasons": ["codebase_fact_candidate_not_validated"],
                "questions": refutation_questions,
                "human_review_required": True,
            },
            "exploit_chain": {
                "primitives": primitives,
                "preconditions": [
                    "authorized code facts only",
                    (
                        "synthetic fixtures only"
                        if static_gap_profile is not None
                        else "authorized test accounts only"
                    ),
                    "human approval before validation",
                ],
                "impact": impact_rationale,
                "confidence": 0.45,
                "safety_notes": [
                    "non_executable_chain_summary",
                    "no_payloads_or_requests",
                    "human_review_required",
                ],
            },
            "validation_plan": {
                "status": "approval_required",
                "methods": ["manual_review", validation_mode],
                "steps": validation_steps,
                "human_approval_required": True,
            },
            "hunter_assessment": hunter_assessment,
        },
        "hypothesis": hypothesis,
        "object_name": _object_from_route(route.route_path),
        "route_label": route_label,
        "source_fact_refs": [fact["fact_ref"] for fact in source_facts],
        "security_invariant_ref": hypothesis.get("security_invariant_ref"),
    }


def _worker_hunter_assessment(
    *,
    route_label: str,
    hypothesis: str,
    primitives: list[str],
    authz_gap_present: bool,
    sink_present: bool,
    static_gap_profile: dict | None = None,
) -> dict:
    if static_gap_profile is not None:
        return _worker_static_gap_hunter_assessment(
            hypothesis=hypothesis,
            static_gap_profile=static_gap_profile,
            sink_present=sink_present,
        )
    signals = " ".join([route_label, *primitives]).lower()
    reasons = ["codebase_route_candidate"]
    if authz_gap_present:
        reasons.append("authorization_gap_candidate")
    if sink_present:
        reasons.append("sensitive_sink_present")
    reasons.append("human_approval_required")

    if any(signal in signals for signal in ["team", "invite", "role_check", "update_role"]):
        assessment = {
            "playbook_id": "role_boundary",
            "playbook_label": "Role boundary / privilege escalation",
            "hunter_priority_score": 72,
            "impact_score": 82,
            "duplicate_risk_score": 20,
            "policy_risk_score": 35,
            "rejection_risk_score": 30,
            "recommendation": "needs_human_review",
            "next_action": "Prepare human-approved, test-account-only validation.",
            "reasons": reasons,
            "evidence_focus": [
                "role_matrix_snapshot",
                "member_vs_admin_request_diff",
                "permission_denial_expected_result",
            ],
            "safety_notes": [
                "advisory_only",
                "scope_guard_required",
                "human_review_required",
                "no_live_requests",
            ],
            "hypothesis": hypothesis,
        }
        _boost_authorization_gap_candidate(assessment, authz_gap_present=authz_gap_present)
        return assessment

    if any(signal in signals for signal in ["file", "export", "download", "send_file"]):
        assessment = {
            "playbook_id": "bola_idor",
            "playbook_label": "BOLA / IDOR object boundary",
            "hunter_priority_score": 68,
            "impact_score": 78,
            "duplicate_risk_score": 25,
            "policy_risk_score": 35,
            "rejection_risk_score": 30,
            "recommendation": "needs_human_review",
            "next_action": "Prepare human-approved, test-account-only validation.",
            "reasons": reasons,
            "evidence_focus": [
                "two_test_accounts",
                "same_object_id_cross_account_diff",
                "request_response_diff",
            ],
            "safety_notes": [
                "advisory_only",
                "scope_guard_required",
                "human_review_required",
                "no_live_requests",
            ],
            "hypothesis": hypothesis,
        }
        _boost_authorization_gap_candidate(assessment, authz_gap_present=authz_gap_present)
        return assessment

    assessment = {
        "playbook_id": "codebase_authorization_boundary",
        "playbook_label": "Codebase authorization boundary",
        "hunter_priority_score": 65,
        "impact_score": 75,
        "duplicate_risk_score": 25,
        "policy_risk_score": 35,
        "rejection_risk_score": 30,
        "recommendation": "needs_human_review",
        "next_action": "Prepare human-approved, test-account-only validation.",
        "reasons": reasons,
        "evidence_focus": [
            "provenance_review",
            "scope_guard_review",
            "minimal_safe_reproduction_plan",
        ],
        "safety_notes": [
            "advisory_only",
            "scope_guard_required",
            "human_review_required",
            "no_live_requests",
        ],
        "hypothesis": hypothesis,
    }
    _boost_authorization_gap_candidate(assessment, authz_gap_present=authz_gap_present)
    return assessment


def _worker_static_gap_profile(
    authz_gap: CodebaseFactRecord | None,
) -> dict | None:
    payload = authz_gap.payload if authz_gap is not None and isinstance(authz_gap.payload, dict) else {}
    root_cause = _worker_safe_string(payload.get("root_cause"))
    profile = _STATIC_GAP_PROFILES.get(root_cause)
    if not isinstance(profile, dict):
        return None
    return {**profile, "root_cause": root_cause}


def _worker_profile_strings(profile: dict | None, key: str) -> list[str]:
    if not isinstance(profile, dict):
        return []
    values = profile.get(key)
    if not isinstance(values, (list, tuple)):
        return []
    return [
        value
        for item in values
        if (value := _worker_safe_string(item))
    ]


def _worker_static_gap_hunter_assessment(
    *,
    hypothesis: str,
    static_gap_profile: dict,
    sink_present: bool,
) -> dict:
    priority_score = static_gap_profile.get("priority_score")
    impact_score = static_gap_profile.get("impact_score")
    root_cause = _worker_safe_string(static_gap_profile.get("root_cause"))
    reasons = [
        "codebase_route_candidate",
        "static_gap_candidate",
        f"root_cause:{root_cause}",
        "human_approval_required",
    ]
    if sink_present:
        reasons.insert(2, "sensitive_sink_present")
    return {
        "playbook_id": _worker_safe_string(static_gap_profile.get("playbook_id")),
        "playbook_label": _worker_safe_string(static_gap_profile.get("playbook_label")),
        "hunter_priority_score": (
            priority_score
            if isinstance(priority_score, int) and not isinstance(priority_score, bool)
            else 65
        ),
        "impact_score": (
            impact_score
            if isinstance(impact_score, int) and not isinstance(impact_score, bool)
            else 75
        ),
        "duplicate_risk_score": 25,
        "policy_risk_score": 35,
        "rejection_risk_score": 30,
        "recommendation": "needs_human_review",
        "next_action": "Prepare a human-approved, local-only refutation review.",
        "reasons": reasons,
        "evidence_focus": [
            "mapped_static_gap_review",
            "same_handler_control_trace",
            "non_destructive_refutation_only",
        ],
        "safety_notes": [
            "advisory_only",
            "scope_guard_required",
            "human_review_required",
            "no_live_requests",
        ],
        "hypothesis": hypothesis,
    }


def _worker_evidence_needed(source_facts: list[dict]) -> list[str]:
    evidence = [
        "redacted_route_authorization_trace",
        "test_account_role_matrix",
        "sanitized_request_response_diff",
    ]
    if _source_facts_have_api_object_identifier(source_facts):
        _append_unique(evidence, "approved_test_object_id_matrix")
    if _source_facts_have_request_body(source_facts):
        _append_unique(evidence, "request_body_field_policy_review")
    if _source_facts_missing_security_declaration(source_facts):
        _append_unique(evidence, "declared_authentication_or_scope_model")
    return evidence


def _worker_validation_plan_steps(source_facts: list[dict]) -> list[str]:
    steps = [
        "Review mapped route, authz hint, and sensitive sink provenance.",
        "Confirm scope, policy, and approved test accounts before any validation.",
    ]
    if _source_facts_have_api_object_identifier(source_facts):
        steps.append(
            "Map API object identifier fields to approved test objects before any two-account comparison."
        )
    if _source_facts_have_request_body(source_facts):
        steps.append(
            "Review request body field names locally; do not store raw body values or secrets."
        )
    if _source_facts_missing_security_declaration(source_facts):
        steps.append(
            "Resolve the declared authentication or scope model before preparing validation evidence."
        )
    if any(fact.get("artifact_kind") == "har" for fact in source_facts if isinstance(fact, dict)):
        steps.append(
            "Use only redacted HAR method and path evidence; ignore headers, cookies, and request values."
        )
    steps.append(
        "Use test accounts only after approval to compare authorized and unauthorized object access."
    )
    return steps


def _source_facts_have_api_object_identifier(source_facts: list[dict]) -> bool:
    return any(
        isinstance(fact, dict)
        and isinstance(fact.get("api_shape"), dict)
        and _api_shape_has_object_identifier(fact["api_shape"])
        for fact in source_facts
    )


def _source_facts_have_request_body(source_facts: list[dict]) -> bool:
    return any(
        isinstance(fact, dict)
        and isinstance(fact.get("api_shape"), dict)
        and bool(fact["api_shape"].get("request_body_present"))
        for fact in source_facts
    )


def _source_facts_missing_security_declaration(source_facts: list[dict]) -> bool:
    return any(
        isinstance(fact, dict)
        and fact.get("artifact_kind") == "api"
        and isinstance(fact.get("api_shape"), dict)
        and not fact["api_shape"].get("security_declared")
        for fact in source_facts
    )


def _worker_refutation_questions(*, authz_gap_present: bool) -> list[str]:
    questions = [
        "Does the mapped authorization check actually enforce the route object's owner boundary?",
        "Can redacted test-account evidence refute cross-object access before validation?",
    ]
    if not authz_gap_present:
        return questions
    return [
        "Can same-handler authorization evidence refute the missing access-control check candidate?",
        *questions,
    ]


def _boost_authorization_gap_candidate(
    assessment: dict,
    *,
    authz_gap_present: bool,
) -> None:
    if not authz_gap_present:
        return

    assessment["hunter_priority_score"] = min(100, assessment["hunter_priority_score"] + 8)
    _append_unique(assessment["evidence_focus"], "same_handler_authz_evidence")
    _append_unique(assessment["evidence_focus"], "missing_check_refutation_trace")


def _apply_same_handler_authz_refutation(
    assessment: dict,
    *,
    authz: CodebaseFactRecord | None,
    authz_gap_present: bool,
) -> None:
    if authz_gap_present or authz is None:
        return
    if authz.authz_hint not in {"owner_or_admin_check", "ownership_boundary_check"}:
        return

    assessment["hunter_priority_score"] = max(0, assessment["hunter_priority_score"] - 12)
    _append_unique(assessment["reasons"], "refutation_evidence:same_handler_object_authz")
    _append_unique(assessment["reasons"], "missing_evidence:authz_bypass_or_misbind_trace")
    _append_unique(assessment["evidence_focus"], "same_handler_object_authz_trace")
    _append_unique(assessment["evidence_focus"], "authz_bypass_or_misbind_trace")


def _apply_same_handler_static_gap_refutation(
    assessment: dict,
    *,
    authz: CodebaseFactRecord | None,
    static_gap_profile: dict,
) -> None:
    if authz is None:
        return
    guard_hints = {
        _worker_safe_string(item)
        for item in static_gap_profile.get("guard_hints", ())
    }
    if not guard_hints or authz.authz_hint not in guard_hints:
        return
    assessment["hunter_priority_score"] = max(
        0,
        assessment["hunter_priority_score"] - 12,
    )
    _append_unique(
        assessment["reasons"],
        "refutation_evidence:same_handler_static_control",
    )
    _append_unique(
        assessment["reasons"],
        "missing_evidence:static_control_bypass_trace",
    )
    _append_unique(assessment["evidence_focus"], "same_handler_static_control_trace")
    _append_unique(assessment["evidence_focus"], "static_control_bypass_trace")


def _worker_mythos_lessons(signals: list[LearningSignalRecord]) -> list[MythosLesson]:
    if not signals:
        return []
    return build_mythos_lessons(
        [
            LearningSignal(
                id=signal.id,
                program_id=signal.program_id,
                playbook_id=signal.playbook_id,
                outcome=signal.outcome,
                surface_key=signal.surface_key,
                notes="",
                bounty_amount=signal.bounty_amount,
                severity_delta=signal.severity_delta,
                evidence_quality=signal.evidence_quality,
                triager_feedback=None,
                target_relationships=(
                    signal.target_relationships
                    if isinstance(signal.target_relationships, list)
                    else []
                ),
                created_at=signal.created_at.isoformat() if signal.created_at else None,
            )
            for signal in signals
        ]
    )


def _apply_worker_lessons(
    hunter_assessment: dict,
    lessons: list[MythosLesson],
    *,
    surface_key: str | None,
) -> None:
    if not surface_key:
        return

    for lesson in lessons:
        if lesson.playbook_id != hunter_assessment["playbook_id"]:
            continue
        if lesson.surface_pattern != surface_key:
            continue
        bounded_delta = max(-10, min(10, lesson.score_delta))
        if lesson.recommendation == "boost":
            hunter_assessment["hunter_priority_score"] = min(
                100,
                hunter_assessment["hunter_priority_score"] + bounded_delta,
            )
            _append_unique(hunter_assessment["reasons"], "lesson:applied:boost")
        elif lesson.recommendation == "duplicate_watch":
            hunter_assessment["duplicate_risk_score"] = min(
                100,
                hunter_assessment["duplicate_risk_score"] + abs(bounded_delta),
            )
            hunter_assessment["hunter_priority_score"] = max(
                0,
                hunter_assessment["hunter_priority_score"] - round(abs(bounded_delta) * 0.5),
            )
            _append_unique(hunter_assessment["reasons"], "lesson:applied:duplicate_watch")
        elif lesson.recommendation in {"penalize", "evidence_needed"}:
            hunter_assessment["hunter_priority_score"] = max(
                0,
                hunter_assessment["hunter_priority_score"] + bounded_delta,
            )
            _append_unique(
                hunter_assessment["reasons"],
                f"lesson:applied:{lesson.recommendation}",
            )

        for reason in lesson.reasons:
            _append_unique(hunter_assessment["reasons"], reason)
        for note in lesson.safety_notes:
            _append_unique(hunter_assessment["safety_notes"], note)


def _worker_route_surface_key(route: CodebaseFactRecord) -> str | None:
    if not route.route_path:
        return None
    segments = [segment for segment in route.route_path.strip("/").split("/") if segment]
    for index, segment in enumerate(segments):
        if segment.startswith("{") and segment.endswith("}"):
            object_key = segment.strip("{}")
            action = next(
                (
                    candidate
                    for candidate in segments[index + 1 :]
                    if not (candidate.startswith("{") and candidate.endswith("}"))
                ),
                None,
            )
            return f"{object_key}:{action or _worker_method_action(route.route_method)}"
    return None


def _worker_method_action(method: str | None) -> str:
    return {
        "GET": "read",
        "POST": "write",
        "PUT": "write",
        "PATCH": "write",
        "DELETE": "delete",
    }.get((method or "GET").upper(), "review")


def _apply_cross_artifact_route_evidence(
    hunter_assessment: dict,
    source_facts: list[dict],
) -> None:
    artifact_kinds = {
        fact.get("artifact_kind")
        for fact in source_facts
        if isinstance(fact, dict) and fact.get("fact_type") == "route_handler"
    }
    if "api" in artifact_kinds and artifact_kinds.intersection({"code", "har"}):
        _append_unique(hunter_assessment["reasons"], "evidence_satisfied:local_code_or_har_correlation")
        _append_unique(hunter_assessment["evidence_focus"], "cross_artifact_route_correlation")
    if "har" in artifact_kinds and artifact_kinds.intersection({"code", "api"}):
        _append_unique(hunter_assessment["reasons"], "evidence_satisfied:local_code_or_api_schema_correlation")
        _append_unique(hunter_assessment["evidence_focus"], "cross_artifact_route_correlation")
    if "sarif" in artifact_kinds and artifact_kinds.intersection({"code", "api", "har"}):
        _append_unique(
            hunter_assessment["reasons"],
            "evidence_satisfied:independent_static_signal",
        )
        _append_unique(hunter_assessment["evidence_focus"], "sarif_route_signal_review")
def _apply_api_shape_signals(
    hunter_assessment: dict,
    source_facts: list[dict],
) -> None:
    api_shapes = [
        fact.get("api_shape")
        for fact in source_facts
        if isinstance(fact, dict)
        and fact.get("artifact_kind") == "api"
        and isinstance(fact.get("api_shape"), dict)
    ]
    if not api_shapes:
        return

    if any(_api_shape_has_object_identifier(shape) for shape in api_shapes):
        hunter_assessment["hunter_priority_score"] = min(
            100,
            hunter_assessment.get("hunter_priority_score", 65) + 4,
        )
        _append_unique(hunter_assessment["reasons"], "api_shape:object_identifier_present")
        _append_unique(hunter_assessment["evidence_focus"], "api_object_identifier_shape")

    if any(shape.get("request_body_present") for shape in api_shapes):
        _append_unique(hunter_assessment["reasons"], "api_shape:request_body_present")
        _append_unique(hunter_assessment["evidence_focus"], "request_body_field_review")

    if any(not shape.get("security_declared") for shape in api_shapes):
        _append_unique(
            hunter_assessment["reasons"],
            "missing_evidence:declared_authentication_or_scope_model",
        )
        _append_unique(hunter_assessment["evidence_focus"], "declared_authentication_or_scope_model")


def _api_shape_has_object_identifier(shape: dict) -> bool:
    values: list[str] = []
    for key in ("path_parameters", "query_parameters", "body_fields"):
        names = shape.get(key)
        if isinstance(names, list):
            values.extend(name for name in names if isinstance(name, str))
    return any(_api_shape_name_looks_like_object_id(name) for name in values)


def _api_shape_name_looks_like_object_id(name: str) -> bool:
    normalized = name.lower().replace("-", "_")
    return normalized == "id" or normalized.endswith("_id")


def _append_unique(values: list[str], value: str) -> None:
    if value not in values:
        values.append(value)


def _related_fact(
    facts: list[CodebaseFactRecord],
    route: CodebaseFactRecord,
    fact_type: str,
) -> CodebaseFactRecord | None:
    route_handler = route.payload.get("handler") if isinstance(route.payload, dict) else None
    return next(
        (
            fact
            for fact in facts
            if fact.fact_type == fact_type
            and fact.source_path == route.source_path
            and _same_handler_or_legacy_fact(route_handler, fact)
        ),
        None,
    )


def _worker_candidate_routes(
    codebase_facts: list[CodebaseFactRecord],
) -> list[CodebaseFactRecord]:
    code_routes = [
        fact
        for fact in codebase_facts
        if fact.fact_type == "route_handler"
        and _route_artifact_kind(fact) == "code"
    ]
    route_groups: list[list[CodebaseFactRecord]] = []
    for fact in codebase_facts:
        if (
            fact.fact_type != "route_handler"
            or _route_artifact_kind(fact) in {"code", "sarif"}
        ):
            continue
        group = next(
            (
                group
                for group in route_groups
                if _routes_equivalent(fact, group[0])
            ),
            None,
        )
        if group is None:
            route_groups.append([fact])
            continue
        group.append(fact)

    artifact_routes: list[CodebaseFactRecord] = []
    for group in route_groups:
        if any(
            _routes_equivalent(code_route, group[0])
            for code_route in code_routes
        ):
            continue
        artifact_routes.append(
            sorted(
                group,
                key=lambda fact: (
                    _route_candidate_priority(fact),
                    fact.source_path,
                    fact.symbol_name or "",
                ),
            )[0]
        )
    return sorted(
        [*code_routes, *artifact_routes],
        key=lambda fact: (
            fact.source_path,
            fact.route_method or "",
            fact.route_path or "",
            fact.symbol_name,
        ),
    )


def _route_candidate_priority(fact: CodebaseFactRecord) -> int:
    payload = fact.payload if isinstance(fact.payload, dict) else {}
    if payload.get("mapping_mode") != "authorized_api_artifact":
        return 0
    if payload.get("artifact_kind") == "har":
        return 2
    return 1


def _routes_equivalent(left: CodebaseFactRecord, right: CodebaseFactRecord) -> bool:
    if (left.route_method or "GET").upper() != (right.route_method or "GET").upper():
        return False

    left_path = _route_match_path(left.route_path or left.source_path)
    right_path = _route_match_path(right.route_path or right.source_path)
    if left_path == right_path:
        return True
    if not (
        _route_path_has_template_placeholder(left_path)
        or _route_path_has_template_placeholder(right_path)
    ):
        return False
    return _route_shape_path(left_path) == _route_shape_path(right_path)


def _route_match_path(path: str | None) -> str:
    if not path:
        return ""
    return path.split("?", 1)[0].strip()


def _route_path_has_template_placeholder(path: str) -> bool:
    return any(
        _route_segment_is_template_placeholder(segment)
        for segment in path.strip("/").split("/")
        if segment
    )


def _route_shape_path(path: str) -> str:
    leading_slash = path.startswith("/")
    segments = [segment for segment in path.strip("/").split("/") if segment]
    equivalent_segments = [
        "{}" if _route_segment_is_dynamic(segment) else segment
        for segment in segments
    ]
    equivalent_path = "/".join(equivalent_segments)
    if leading_slash:
        return f"/{equivalent_path}" if equivalent_path else "/"
    return equivalent_path


def _route_segment_is_dynamic(segment: str) -> bool:
    if _route_segment_is_template_placeholder(segment):
        return True
    return _har_route_segment_looks_dynamic(segment)


def _route_segment_is_template_placeholder(segment: str) -> bool:
    if len(segment) >= 2 and segment.startswith("{") and segment.endswith("}"):
        return True
    if len(segment) >= 2 and segment.startswith(":"):
        return True
    if len(segment) >= 2 and segment.startswith("<") and segment.endswith(">"):
        return True
    return False


def _har_route_segment_looks_dynamic(segment: str) -> bool:
    if segment.isdigit():
        return True
    lowered = segment.lower()
    parts = lowered.split("-")
    if (
        len(parts) == 5
        and [len(part) for part in parts] == [8, 4, 4, 4, 12]
        and all(_is_hex(part) for part in parts)
    ):
        return True
    compact = lowered.replace("-", "")
    if len(compact) >= 16 and compact.isalnum() and not compact.isalpha():
        return True
    return False


def _is_hex(value: str) -> bool:
    return bool(value) and all(character in "0123456789abcdef" for character in value)


def _same_handler_or_legacy_fact(
    route_handler: object,
    fact: CodebaseFactRecord,
) -> bool:
    if not route_handler:
        return True
    fact_handler = fact.payload.get("handler") if isinstance(fact.payload, dict) else None
    if _has_static_mapper_scope(fact):
        return fact_handler == route_handler
    return fact_handler in {None, route_handler}


def _has_static_mapper_scope(fact: CodebaseFactRecord) -> bool:
    if not isinstance(fact.payload, dict):
        return False
    return fact.payload.get("mapping_mode") == "static_code_snippet_analysis"


def _route_label(route: CodebaseFactRecord) -> str:
    method = route.route_method or "GET"
    path = route.route_path or route.source_path
    return f"{method} {path}"


def _hypothesis_source_facts(
    *,
    codebase_facts: list[CodebaseFactRecord],
    route: CodebaseFactRecord,
    authz: CodebaseFactRecord | None,
    sink: CodebaseFactRecord | None,
    authz_gap: CodebaseFactRecord | None = None,
) -> list[dict]:
    facts = [_route_source_fact(route)]
    for related_route in _related_route_artifact_facts(codebase_facts, route):
        facts.append(_route_source_fact(related_route))
    if authz is not None:
        facts.append(_authz_source_fact(authz))
    if authz_gap is not None:
        facts.append(_authz_gap_source_fact(authz_gap))
    if sink is not None:
        facts.append(_sink_source_fact(sink))
    return facts


def _related_route_artifact_facts(
    facts: list[CodebaseFactRecord],
    route: CodebaseFactRecord,
) -> list[CodebaseFactRecord]:
    related: list[CodebaseFactRecord] = []
    for fact in facts:
        if fact.id == route.id or fact.fact_type != "route_handler":
            continue
        if not _routes_equivalent(fact, route):
            continue
        if _route_artifact_kind(fact) not in {"api", "har", "sarif"}:
            continue
        related.append(fact)
    return sorted(related, key=lambda fact: (_route_artifact_kind(fact), fact.source_path))


def _route_source_fact(fact: CodebaseFactRecord) -> dict:
    artifact_kind = _route_artifact_kind(fact)
    payload = fact.payload if isinstance(fact.payload, dict) else {}
    source_fact = {
        "fact_ref": _codebase_fact_ref(fact),
        "artifact_kind": artifact_kind,
        "fact_type": fact.fact_type,
        "route_method": fact.route_method,
        "route_path": fact.route_path,
        "source_path": fact.source_path,
        "symbol_name": fact.symbol_name,
    }
    api_shape = payload.get("api_shape")
    if isinstance(api_shape, dict) and api_shape:
        source_fact["api_shape"] = api_shape
    return source_fact


def _route_artifact_kind(fact: CodebaseFactRecord) -> str:
    payload = fact.payload if isinstance(fact.payload, dict) else {}
    artifact_kind = payload.get("artifact_kind")
    if artifact_kind == "har":
        return "har"
    if payload.get("mapping_mode") == "authorized_api_artifact":
        return "api"
    if (
        payload.get("mapping_mode") == "authorized_advisory_artifact"
        and payload.get("artifact_kind") == "sarif"
    ):
        return "sarif"
    return "code"


def _authz_source_fact(fact: CodebaseFactRecord) -> dict:
    return {
        "fact_ref": _codebase_fact_ref(fact),
        "artifact_kind": "code",
        "authz_hint": fact.authz_hint,
        "fact_type": fact.fact_type,
        "source_path": fact.source_path,
        "symbol_name": fact.symbol_name,
    }


def _sink_source_fact(fact: CodebaseFactRecord) -> dict:
    return {
        "fact_ref": _codebase_fact_ref(fact),
        "artifact_kind": "code",
        "fact_type": fact.fact_type,
        "source_path": fact.source_path,
        "symbol_name": fact.symbol_name,
    }


def _authz_gap_source_fact(fact: CodebaseFactRecord) -> dict:
    payload = fact.payload if isinstance(fact.payload, dict) else {}
    return {
        "fact_ref": _codebase_fact_ref(fact),
        "artifact_kind": "code",
        "authz_hint": fact.authz_hint,
        "fact_type": fact.fact_type,
        "route_method": fact.route_method,
        "route_path": fact.route_path,
        "source_path": fact.source_path,
        "symbol_name": fact.symbol_name,
        "root_cause": payload.get(
            "root_cause",
            "missing_object_ownership_check",
        ),
        "security_invariant": payload.get(
            "security_invariant",
            "Object-level actions must verify requester ownership or role before sensitive sinks run.",
        ),
        "sink_count": payload.get("sink_count", 0),
        "sink_symbols": payload.get("sink_symbols", []),
        "decoder_symbols": payload.get("decoder_symbols", []),
        "review_state": payload.get("review_state", "needs_human_review"),
        "execution_allowed": False,
        "validation_allowed": False,
        "report_submission_allowed": False,
    }


def _object_from_route(route_path: str | None) -> str:
    if not route_path:
        return "object"
    first_segment = route_path.strip("/").split("/", 1)[0]
    if first_segment.endswith("ies"):
        return f"{first_segment[:-3]}y"
    if first_segment.endswith("s") and len(first_segment) > 1:
        return first_segment[:-1]
    return first_segment or "object"


def _map_authorized_attack_surface(payload: dict) -> CodebaseMapResult:
    code_map = map_authorized_code_files(payload)
    api_facts = _map_authorized_api_artifacts(payload)
    advisory_facts = _annotate_route_reachable_dependency_advisories(
        code_facts=code_map.facts,
        advisory_facts=_map_authorized_advisory_artifacts(payload),
    )
    return CodebaseMapResult(
        facts=[*code_map.facts, *api_facts, *advisory_facts],
        file_count=code_map.file_count,
    )


def _annotate_route_reachable_dependency_advisories(
    *,
    code_facts: list[CodebaseFactCandidate],
    advisory_facts: list[CodebaseFactCandidate],
) -> list[CodebaseFactCandidate]:
    route_sources_by_reachable_path: dict[str, set[str]] = {}
    for route in code_facts:
        route_payload = route.payload if isinstance(route.payload, dict) else {}
        handler = route_payload.get("handler")
        if (
            route.fact_type != "route_handler"
            or route_payload.get("mapping_mode") != "static_code_snippet_analysis"
            or not isinstance(handler, str)
            or not handler
        ):
            continue
        for reachable_path in reachable_service_source_paths(
            code_facts,
            source_path=route.source_path,
            handler=handler,
        ):
            route_sources_by_reachable_path.setdefault(reachable_path, set()).add(
                route.source_path
            )

    annotated: list[CodebaseFactCandidate] = []
    for fact in advisory_facts:
        fact_payload = fact.payload if isinstance(fact.payload, dict) else {}
        route_sources = sorted(route_sources_by_reachable_path.get(fact.source_path, set()))
        if (
            fact.fact_type != "dependency_signal"
            or fact_payload.get("artifact_kind") != "sbom"
            or fact_payload.get("reachability") != "direct_local_import"
            or not route_sources
        ):
            annotated.append(fact)
            continue
        annotated.append(
            CodebaseFactCandidate(
                fact_type=fact.fact_type,
                source_path=fact.source_path,
                symbol_name=fact.symbol_name,
                route_method=fact.route_method,
                route_path=fact.route_path,
                authz_hint=fact.authz_hint,
                sensitivity_label=fact.sensitivity_label,
                payload={
                    **fact_payload,
                    "reachable_route_sources": route_sources[:50],
                    "route_reachability": (
                        "direct_route_import"
                        if fact.source_path in route_sources
                        else "unique_static_call_path"
                    ),
                },
            )
        )
    return annotated


def _map_authorized_api_artifacts(payload: dict) -> list[CodebaseFactCandidate]:
    artifacts = payload.get("authorized_api_artifacts")
    if not isinstance(artifacts, list):
        return []

    facts: list[CodebaseFactCandidate] = []
    seen_routes: set[tuple[str, str, str]] = set()
    for index, artifact in enumerate(artifacts, start=1):
        if not isinstance(artifact, dict):
            continue
        kind = artifact.get("kind")
        artifact_payload = artifact.get("payload")
        if not isinstance(kind, str) or not isinstance(artifact_payload, dict):
            continue
        try:
            normalized = normalize_artifact(kind, artifact_payload)
        except ValueError:
            continue
        source_name = (
            artifact.get("source_name")
            if isinstance(artifact.get("source_name"), str)
            else f"authorized_{normalized.kind}_{index}"
        )
        paths = normalized.openapi_like.get("paths", {})
        if not isinstance(paths, dict):
            continue
        for path, path_item in sorted(paths.items()):
            if not isinstance(path, str) or not isinstance(path_item, dict):
                continue
            for method, operation in sorted(path_item.items()):
                if not isinstance(method, str) or not _api_artifact_http_method(method):
                    continue
                route_method = method.upper()
                dedupe_key = (normalized.kind, route_method, path)
                if dedupe_key in seen_routes:
                    continue
                seen_routes.add(dedupe_key)
                operation_id = _api_operation_id(
                    kind=normalized.kind,
                    method=method,
                    operation=operation,
                    path=path,
                )
                facts.append(
                    CodebaseFactCandidate(
                        fact_type="route_handler",
                        source_path=str(source_name),
                        symbol_name=operation_id,
                        route_method=route_method,
                        route_path=path,
                        authz_hint=None,
                        sensitivity_label="authorized_api_artifact",
                        payload={
                            "api_shape": _api_operation_shape(
                                operation=operation,
                                path_item=path_item,
                                artifact_kind=normalized.kind,
                            ),
                            "artifact_kind": normalized.kind,
                            "handler": operation_id,
                            "mapping_mode": "authorized_api_artifact",
                            "operation_id": operation_id,
                            "raw_payload_processed": False,
                            "source_name": str(source_name),
                        },
                    )
                )
    return facts


def _map_authorized_advisory_artifacts(payload: dict) -> list[CodebaseFactCandidate]:
    artifacts = payload.get("authorized_advisory_artifacts")
    if not isinstance(artifacts, list):
        return []

    facts: list[CodebaseFactCandidate] = []
    for index, artifact in enumerate(artifacts, start=1):
        if not isinstance(artifact, dict):
            continue
        kind = artifact.get("kind")
        artifact_payload = artifact.get("payload")
        if not isinstance(artifact_payload, dict):
            continue
        if kind == "sbom":
            facts.extend(
                _map_authorized_sbom_advisory_artifact(
                    artifact_payload,
                    source_name=_safe_advisory_source_name(
                        artifact.get("source_name"),
                        index,
                        kind="sbom",
                    ),
                    code_files=payload.get("authorized_code_files"),
                )
            )
            continue
        if kind != "sarif":
            continue
        try:
            normalized = normalize_artifact("sarif", artifact_payload)
        except ValueError:
            continue
        source_name = _safe_advisory_source_name(artifact.get("source_name"), index)
        route_count = 0
        paths = normalized.openapi_like.get("paths", {})
        if isinstance(paths, dict):
            for path, path_item in sorted(paths.items()):
                if not isinstance(path, str) or not isinstance(path_item, dict):
                    continue
                for method, operation in sorted(path_item.items()):
                    if not isinstance(method, str) or not _api_artifact_http_method(method):
                        continue
                    route_count += 1
                    facts.append(
                        CodebaseFactCandidate(
                            fact_type="route_handler",
                            source_path=source_name,
                            symbol_name=_api_operation_id(
                                kind="sarif",
                                method=method,
                                operation=operation,
                                path=path,
                            ),
                            route_method=method.upper(),
                            route_path=path,
                            authz_hint=None,
                            sensitivity_label="authorized_advisory",
                            payload={
                                "artifact_kind": "sarif",
                                "mapping_mode": "authorized_advisory_artifact",
                                "advisory_only": True,
                                "raw_payload_processed": False,
                            },
                        )
                    )
        if route_count == 0:
            facts.append(
                CodebaseFactCandidate(
                    fact_type="scanner_signal",
                    source_path=source_name,
                    symbol_name="sarif_advisory",
                    route_method=None,
                    route_path=None,
                    authz_hint=None,
                    sensitivity_label="authorized_advisory",
                    payload={
                        "artifact_kind": "sarif",
                        "mapping_mode": "authorized_advisory_artifact",
                        "advisory_only": True,
                        "raw_payload_processed": False,
                    },
                )
            )
    return facts


def _map_authorized_sbom_advisory_artifact(
    artifact_payload: dict,
    *,
    source_name: str,
    code_files: object,
) -> list[CodebaseFactCandidate]:
    facts: list[CodebaseFactCandidate] = []
    for signal in extract_sbom_dependency_signals(artifact_payload):
        if not signal.get("vulnerability_id"):
            continue
        for source_path in _direct_dependency_reference_paths(
            code_files,
            package_name=signal["package_name"],
            ecosystem=signal["ecosystem"],
        ):
            facts.append(
                CodebaseFactCandidate(
                    fact_type="dependency_signal",
                    source_path=source_path,
                    symbol_name=signal["package_name"],
                    route_method=None,
                    route_path=None,
                    authz_hint=None,
                    sensitivity_label="authorized_advisory",
                    payload={
                        "artifact_kind": "sbom",
                        "mapping_mode": "authorized_advisory_artifact",
                        "advisory_only": True,
                        "raw_payload_processed": False,
                        "source_name": source_name,
                        "package_name": signal["package_name"],
                        "package_version": signal["package_version"],
                        "ecosystem": signal["ecosystem"],
                        "vulnerability_id": signal["vulnerability_id"],
                        "severity": signal.get("severity", "unknown"),
                        "reachability": "direct_local_import",
                    },
                )
            )
    return facts


def _direct_dependency_reference_paths(
    code_files: object,
    *,
    package_name: str,
    ecosystem: str,
) -> list[str]:
    if not isinstance(code_files, list):
        return []
    paths: list[str] = []
    for index, code_file in enumerate(code_files, start=1):
        if not isinstance(code_file, dict):
            continue
        source_path = _safe_advisory_source_name(
            code_file.get("path"),
            index,
            kind="code",
        )
        content = code_file.get("content")
        if (
            source_path
            and isinstance(content, str)
            and _code_references_dependency(
                content[:20_000],
                package_name=package_name,
                ecosystem=ecosystem,
            )
            and source_path not in paths
        ):
            paths.append(source_path)
    return paths


def _code_references_dependency(
    content: str,
    *,
    package_name: str,
    ecosystem: str,
) -> bool:
    package_variants = {package_name}
    if ecosystem == "pypi":
        package_variants.add(package_name.replace("-", "_"))
    for package in sorted(package_variants):
        escaped = re.escape(package)
        if ecosystem == "pypi" and re.search(
            rf"(?m)^\s*(?:from\s+{escaped}(?:[.\s]|$)|import\s+{escaped}(?:[.\s,]|$))",
            content,
        ):
            return True
        if re.search(
            rf"(?:from\s*|require\(\s*)[\"']{escaped}(?:/[^\"']*)?[\"']",
            content,
        ):
            return True
    return False


def _api_operation_shape(
    *,
    operation: object,
    path_item: dict,
    artifact_kind: str,
) -> dict:
    if artifact_kind == "har":
        return {"observed_request_shape": True}
    if not isinstance(operation, dict):
        return {}

    path_parameters: list[str] = []
    query_parameters: list[str] = []
    parameter_sources = [path_item.get("parameters"), operation.get("parameters")]
    for parameters in parameter_sources:
        if not isinstance(parameters, list):
            continue
        for parameter in parameters:
            if not isinstance(parameter, dict):
                continue
            name = parameter.get("name")
            location = parameter.get("in")
            if not isinstance(name, str) or not isinstance(location, str):
                continue
            if not _safe_api_shape_name(name):
                continue
            if location == "path":
                _append_unique(path_parameters, name)
            elif location == "query":
                _append_unique(query_parameters, name)

    request_body = operation.get("requestBody")
    body_fields = _api_request_body_fields(request_body)
    shape = {
        "path_parameters": path_parameters,
        "query_parameters": query_parameters,
        "body_fields": body_fields,
        "request_body_present": isinstance(request_body, dict),
        "security_declared": bool(operation.get("security") or path_item.get("security")),
    }
    return {key: value for key, value in shape.items() if value not in ([], False)}


def _api_artifact_http_method(method: str) -> bool:
    return method.lower() in {
        "get",
        "post",
        "put",
        "patch",
        "delete",
        "options",
        "head",
    }


def _api_request_body_fields(request_body: object) -> list[str]:
    if not isinstance(request_body, dict):
        return []
    content = request_body.get("content")
    if not isinstance(content, dict):
        return []

    fields: list[str] = []
    for media_type in sorted(content):
        media = content.get(media_type)
        if not isinstance(media, dict):
            continue
        schema = media.get("schema")
        for field in _api_schema_property_names(schema):
            if _safe_api_shape_name(field):
                _append_unique(fields, field)
    return fields


def _api_schema_property_names(schema: object) -> list[str]:
    if not isinstance(schema, dict):
        return []
    properties = schema.get("properties")
    if isinstance(properties, dict):
        return [name for name in properties if isinstance(name, str)]
    nested_names: list[str] = []
    for key in ("allOf", "anyOf", "oneOf"):
        variants = schema.get(key)
        if not isinstance(variants, list):
            continue
        for variant in variants:
            for name in _api_schema_property_names(variant):
                _append_unique(nested_names, name)
    return nested_names


def _safe_api_shape_name(name: str) -> bool:
    lowered = name.lower()
    sensitive_terms = (
        "authorization",
        "cookie",
        "token",
        "secret",
        "password",
        "passwd",
        "session",
        "credential",
        "api_key",
        "apikey",
    )
    return not any(term in lowered for term in sensitive_terms)


def _safe_advisory_source_name(value: object, index: int, *, kind: str = "sarif") -> str:
    fallback = f"authorized_{kind}_{index}"
    if not isinstance(value, str):
        return fallback
    source_name = value.replace("\\", "/").strip()
    if (
        not source_name
        or len(source_name) > 200
        or source_name.startswith("/")
        or ":" in source_name
        or ".." in source_name.split("/")
        or any(
            marker in source_name.lower()
            for marker in ("authorization", "cookie", "token", "secret", "password")
        )
    ):
        return fallback
    return source_name


def _api_operation_id(
    *,
    kind: str,
    method: str,
    operation: object,
    path: str,
) -> str:
    if isinstance(operation, dict) and isinstance(operation.get("operationId"), str):
        operation_id = operation["operationId"].strip()
        if operation_id:
            return operation_id
    suffix = path.strip("/").replace("{", "").replace("}", "").replace("/", "_")
    return f"{kind}_{method.lower()}_{suffix or 'root'}"


def _worker_route_from_api_artifact(route: CodebaseFactRecord) -> bool:
    payload = route.payload if isinstance(route.payload, dict) else {}
    artifact_kind = payload.get("artifact_kind")
    return payload.get("mapping_mode") == "authorized_api_artifact" and artifact_kind != "har"


def _worker_route_from_har_artifact(route: CodebaseFactRecord) -> bool:
    payload = route.payload if isinstance(route.payload, dict) else {}
    return (
        payload.get("mapping_mode") == "authorized_api_artifact"
        and payload.get("artifact_kind") == "har"
    )


def _materialize_static_codebase_map(
    *,
    task: CampaignTaskRecord,
    campaign: CampaignRecord,
    repository: DatabaseRepository,
    static_map: CodebaseMapResult,
) -> tuple[list[str], dict]:
    codebase_map = repository.save_codebase_map(
        campaign_id=campaign.id,
        source_ref=f"campaign_task:{task.id}",
        repository=campaign.default_asset,
        commit_ref=None,
        status="mapped",
        route_count=static_map.route_count,
        handler_count=static_map.handler_count,
        model_count=static_map.model_count,
        authz_check_count=static_map.authz_check_count,
        sensitive_sink_count=static_map.sensitive_sink_count,
        provenance_refs=[f"campaign:{campaign.id}", f"campaign_task:{task.id}"],
        safety_gate_state="allowed",
        payload={
            "file_count": static_map.file_count,
            "mapping_mode": _static_map_mapping_mode(static_map),
            **_static_map_api_artifact_counts(static_map),
            **_static_map_advisory_artifact_counts(static_map),
            "raw_payload_processed": False,
        },
    )
    fact_refs: list[str] = []
    for candidate in static_map.facts:
        fact = repository.save_codebase_fact(
            codebase_map_id=codebase_map.id,
            campaign_id=campaign.id,
            fact_type=candidate.fact_type,
            source_path=candidate.source_path,
            symbol_name=candidate.symbol_name,
            route_method=candidate.route_method,
            route_path=candidate.route_path,
            authz_hint=candidate.authz_hint,
            sensitivity_label=candidate.sensitivity_label,
            provenance_refs=[f"codebase_map:{codebase_map.id}"],
            payload=candidate.payload,
        )
        fact_refs.append(f"codebase_fact:{fact.id}")

    scanner_run = repository.save_scanner_run(
        campaign_id=campaign.id,
        codebase_map_id=codebase_map.id,
        tool_name="mythos_static_code_mapper",
        command_hash=_stable_ref_hash(f"campaign_task:{task.id}:static_code_mapper"),
        status="completed",
        finding_count=0,
        candidate_count=len(fact_refs),
        summary="Authorized static code snippets mapped; no code body or scanner stdout stored.",
        safety_gate_state="allowed",
        payload={
            "raw_stdout": None,
            "fact_refs": fact_refs,
        },
    )
    return (
        [
            f"codebase_map:{codebase_map.id}",
            *fact_refs,
            f"scanner_run:{scanner_run.id}",
        ],
        {
            "artifact_kind": "attack_surface_map",
            "codebase_map_id": codebase_map.id,
            "scanner_run_id": scanner_run.id,
            "static_fact_count": len(fact_refs),
        },
    )


def _attach_runtime_target_model_projection(
    *,
    task: CampaignTaskRecord,
    campaign: CampaignRecord,
    repository: DatabaseRepository,
    output_refs: list[str],
    artifact_payload: dict,
    target_intake: dict | None,
    target_intake_ref: str | None,
) -> tuple[list[str], dict]:
    task_payload = task.payload if isinstance(task.payload, dict) else {}
    if task_payload.get("runtime_schema") != _AUTONOMOUS_RESEARCH_RUNTIME_SCHEMA:
        return output_refs, artifact_payload
    source_snapshot_digest = _worker_safe_string(
        task_payload.get("source_snapshot_digest")
    )
    codebase_map_id = _worker_safe_string(artifact_payload.get("codebase_map_id"))
    codebase_map = next(
        (
            item
            for item in repository.list_campaign_codebase_maps(campaign.id)
            if item.id == codebase_map_id
        ),
        None,
    )
    if (
        _SOURCE_SNAPSHOT_DIGEST_PATTERN.fullmatch(source_snapshot_digest) is None
        or codebase_map is None
        or codebase_map.status != "mapped"
        or codebase_map.safety_gate_state != "allowed"
    ):
        raise _WorkerExecutionFailure
    projection = _build_runtime_target_model_projection(
        codebase_map_id=codebase_map.id,
        source_snapshot_digest=source_snapshot_digest,
        codebase_facts=repository.list_codebase_facts(codebase_map.id),
        target_intake=target_intake,
        target_intake_ref=target_intake_ref,
    )
    if projection is None:
        raise _WorkerExecutionFailure
    projection_ref = f"target_model_projection:{task.id}"
    return (
        [*output_refs, projection_ref],
        {
            **artifact_payload,
            "target_model_projection": projection,
        },
    )


def _build_runtime_target_model_projection(
    *,
    codebase_map_id: str,
    source_snapshot_digest: str,
    codebase_facts: list[CodebaseFactRecord],
    target_intake: dict | None,
    target_intake_ref: str | None,
) -> dict | None:
    if (
        not isinstance(target_intake_ref, str)
        or not target_intake_ref.startswith("campaign_observation_projection:")
        or not _runtime_target_intake_projection_is_valid(target_intake)
    ):
        return None
    fact_refs = sorted(
        f"codebase_fact:{fact.id}"
        for fact in codebase_facts
        if isinstance(fact.id, str)
        and _CODEBASE_FACT_REF_PATTERN.fullmatch(f"codebase_fact:{fact.id}")
    )
    if not fact_refs or len(fact_refs) != len(codebase_facts):
        return None
    if len(fact_refs) != len(set(fact_refs)):
        return None
    attack_surface_queue = _build_runtime_attack_surface_queue(codebase_facts)
    route_fact_refs = sorted(
        f"codebase_fact:{fact.id}"
        for fact in codebase_facts
        if fact.fact_type in {"route", "route_handler"}
    )
    artifact_counts: dict[str, int] = {}
    for fact in codebase_facts:
        artifact_kind = _target_model_fact_artifact_kind(fact)
        artifact_counts[artifact_kind] = artifact_counts.get(artifact_kind, 0) + 1
    return {
        "projection_schema": _RUNTIME_TARGET_MODEL_PROJECTION_SCHEMA,
        "codebase_map_id": codebase_map_id,
        "source_snapshot_digest": source_snapshot_digest,
        "fact_refs": fact_refs,
        "route_fact_refs": route_fact_refs,
        "fact_digest": _canonical_digest(fact_refs),
        "attack_surface_queue_schema": _RUNTIME_ATTACK_SURFACE_QUEUE_SCHEMA,
        "attack_surface_queue": attack_surface_queue,
        "attack_surface_queue_digest": _canonical_digest(attack_surface_queue),
        "attack_surface_route_count": len(_worker_candidate_routes(codebase_facts)),
        "attack_surface_selected_count": len(attack_surface_queue),
        "artifact_counts": dict(sorted(artifact_counts.items())),
        "target_intake_ref": target_intake_ref,
        "target_intake": target_intake,
        "target_intake_digest": _canonical_digest(target_intake),
        "raw_payload_processed": False,
        "execution_allowed": False,
        "dispatch_allowed": False,
        "validation_allowed": False,
        "candidate_promotion_allowed": False,
        "report_submission_allowed": False,
    }


def _build_runtime_attack_surface_queue(
    codebase_facts: list[CodebaseFactRecord],
) -> list[dict]:
    """Rank traceable routes so later research stages focus on high-value surfaces."""
    entries: list[dict] = []
    for route in _worker_candidate_routes(codebase_facts):
        route_ref = _codebase_fact_ref(route)
        method = _worker_safe_string(route.route_method).upper() or "ANY"
        path = _worker_safe_string(route.route_path)
        if (
            not route_ref
            or not path.startswith("/")
            or not re.fullmatch(r"[A-Z]+", method)
        ):
            continue
        authz = _related_fact(codebase_facts, route, "authz_check")
        authz_gap = _related_fact(codebase_facts, route, "authorization_gap_candidate")
        sink = _related_fact(codebase_facts, route, "sensitive_sink")
        family = _security_invariant_family(
            route=route,
            sink=sink,
            authz_gap=authz_gap,
        )
        source_fact_refs = [route_ref]
        reason_codes: list[str] = []
        priority_score = 20
        if sink is not None:
            priority_score += 30
            _append_unique(reason_codes, "sensitive_sink")
            if sink_ref := _codebase_fact_ref(sink):
                _append_unique(source_fact_refs, sink_ref)
        if authz_gap is not None:
            priority_score += 35
            _append_unique(reason_codes, "authorization_gap")
            if gap_ref := _codebase_fact_ref(authz_gap):
                _append_unique(source_fact_refs, gap_ref)
        elif authz is not None:
            priority_score += 5
            _append_unique(reason_codes, "authorization_control_observed")
            if authz_ref := _codebase_fact_ref(authz):
                _append_unique(source_fact_refs, authz_ref)
        if _route_path_has_template_placeholder(path):
            priority_score += 15
            _append_unique(reason_codes, "object_identifier_route")
        if method in {"POST", "PUT", "PATCH", "DELETE"}:
            priority_score += 10
            _append_unique(reason_codes, "state_changing_method")
        artifact_kind = _route_artifact_kind(route)
        if artifact_kind in {"api", "har"}:
            priority_score += 5
            _append_unique(reason_codes, f"{artifact_kind}_correlation")
        if artifact_kind == "code":
            priority_score += 5
            _append_unique(reason_codes, "local_code_trace")
        identity = "\x1f".join([route_ref, family, *source_fact_refs])
        entries.append(
            {
                "surface_ref": "attack_surface:" + sha256(
                    identity.encode("utf-8")
                ).hexdigest(),
                "route_fact_ref": route_ref,
                "route_method": method,
                "route_path": path,
                "focus_family": family,
                "priority_score": min(100, priority_score),
                "reason_codes": reason_codes[:8],
                "source_fact_refs": source_fact_refs[:6],
            }
        )
    entries.sort(
        key=lambda item: (
            -item["priority_score"],
            item["route_method"],
            item["route_path"],
            item["route_fact_ref"],
        )
    )
    selected = entries[:20]
    for rank, item in enumerate(selected, start=1):
        item["selection_rank"] = rank
        item["selection_status"] = "selected"
    return selected


def _worker_prioritized_routes(
    codebase_facts: list[CodebaseFactRecord],
    *,
    attack_surface_queue: list[dict] | None = None,
) -> list[CodebaseFactRecord]:
    routes = _worker_candidate_routes(codebase_facts)
    if not isinstance(attack_surface_queue, list) or not attack_surface_queue:
        return routes
    routes_by_ref = {
        fact_ref: route
        for route in routes
        if (fact_ref := _codebase_fact_ref(route))
    }
    ordered: list[CodebaseFactRecord] = []
    seen: set[str] = set()
    for item in attack_surface_queue:
        if not isinstance(item, dict):
            continue
        route_ref = item.get("route_fact_ref")
        if (
            not isinstance(route_ref, str)
            or _CODEBASE_FACT_REF_PATTERN.fullmatch(route_ref) is None
            or route_ref in seen
        ):
            continue
        route = routes_by_ref.get(route_ref)
        if route is None:
            continue
        seen.add(route_ref)
        ordered.append(route)
    return ordered or routes


def _target_model_fact_artifact_kind(fact: CodebaseFactRecord) -> str:
    payload = fact.payload if isinstance(fact.payload, dict) else {}
    artifact_kind = payload.get("artifact_kind")
    if artifact_kind in {"sarif", "sbom"}:
        return artifact_kind
    if payload.get("mapping_mode") == "authorized_api_artifact":
        return "har" if artifact_kind == "har" else "api"
    return "code"


def _target_model_projected_codebase_facts(
    *,
    projection: dict | None,
    codebase_facts: list[CodebaseFactRecord],
) -> list[CodebaseFactRecord]:
    if projection is None:
        return codebase_facts
    fact_refs = projection.get("fact_refs")
    if not isinstance(fact_refs, list):
        return []
    allowed_refs = set(fact_refs)
    return [
        fact
        for fact in codebase_facts
        if f"codebase_fact:{fact.id}" in allowed_refs
    ]


def _static_map_mapping_mode(static_map: CodebaseMapResult) -> str:
    if _static_map_api_artifact_counts(static_map) or _static_map_advisory_artifact_counts(
        static_map
    ):
        return "authorized_attack_surface_analysis"
    return "static_code_snippet_analysis"


def _static_map_api_artifact_counts(static_map: CodebaseMapResult) -> dict:
    route_count = sum(
        1
        for fact in static_map.facts
        if isinstance(fact.payload, dict)
        and fact.payload.get("mapping_mode") == "authorized_api_artifact"
    )
    if route_count == 0:
        return {}
    return {"api_artifact_route_count": route_count}


def _static_map_advisory_artifact_counts(static_map: CodebaseMapResult) -> dict:
    sarif_route_count = sum(
        1
        for fact in static_map.facts
        if isinstance(fact.payload, dict)
        and fact.payload.get("mapping_mode") == "authorized_advisory_artifact"
        and fact.payload.get("artifact_kind") == "sarif"
        and fact.fact_type == "route_handler"
    )
    sarif_signal_count = sum(
        1
        for fact in static_map.facts
        if isinstance(fact.payload, dict)
        and fact.payload.get("mapping_mode") == "authorized_advisory_artifact"
        and fact.payload.get("artifact_kind") == "sarif"
    )
    sbom_signal_count = sum(
        1
        for fact in static_map.facts
        if isinstance(fact.payload, dict)
        and fact.payload.get("mapping_mode") == "authorized_advisory_artifact"
        and fact.payload.get("artifact_kind") == "sbom"
        and fact.fact_type == "dependency_signal"
    )
    if sarif_signal_count == 0 and sbom_signal_count == 0:
        return {}
    counts = {}
    if sarif_signal_count:
        counts["sarif_advisory_route_count"] = sarif_route_count
        counts["sarif_advisory_signal_count"] = sarif_signal_count
    if sbom_signal_count:
        counts["sbom_reachable_advisory_signal_count"] = sbom_signal_count
    return counts


def _stable_ref_hash(value: str) -> str:
    return f"sha256:{sha256(value.encode('utf-8')).hexdigest()}"
