"""Patch suggestion scaffold — advisory-only fix / regression guidance.

Final-scheme Patch Agent v0:
- Locate root-cause family from candidate signals
- Suggest minimal root-cause fixes (not payload filters)
- Suggest regression tests (unit/integration style text only)
- Explain why the fix works
- Never opens PRs, never writes exploit PoCs, never executes validation
- Never sets confirmed_vulnerability / report_submission_allowed

This is human-review material only.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

from app.human_review_approvals import (
    APPROVAL_KIND_PATCH,
    attach_human_review_approvals_to_bridge_result,
    patch_context_from_approval,
    resolve_human_review_approvals,
    select_approval_for_candidate,
)


STATUS_ADVISORY = "advisory_patch_suggestion"
STATUS_SKIPPED = "skipped_no_candidate"
STATUS_NOT_APPLICABLE = "not_applicable_refuted_or_unverified"


class PatchAntiPattern(BaseModel):
    wrong_fix: str
    correct_direction: str


class RegressionTestSuggestion(BaseModel):
    test_id: str
    title: str
    intent: str
    style: str = "unit_or_integration_text_only"
    steps: list[str] = Field(default_factory=list)


class PatchSuggestion(BaseModel):
    status: str = STATUS_ADVISORY
    package_id: str = ""
    candidate_id: str = ""
    root_cause_id: str = ""
    vuln_type: str = ""
    affected_code_path: str = ""
    affected_route: str = ""
    root_cause_summary: str = ""
    fix_principles: list[str] = Field(default_factory=list)
    suggested_changes: list[str] = Field(default_factory=list)
    why_effective: list[str] = Field(default_factory=list)
    anti_patterns: list[PatchAntiPattern] = Field(default_factory=list)
    regression_tests: list[RegressionTestSuggestion] = Field(default_factory=list)
    shared_layer_note: str = ""
    confidence: str = "low"
    human_review_required: bool = True
    patch_ready: bool = False
    auto_pr_allowed: bool = False
    pr_opened: bool = False
    exploit_poc_included: bool = False
    execution_allowed: bool = False
    validation_allowed: bool = False
    report_submission_allowed: bool = False
    confirmed_vulnerability: bool = False
    finding_promotion_allowed: bool = False
    next_allowed_action: str = (
        "Human reviews advisory patch suggestion only; no auto-PR or live validation."
    )
    safety_blockers: list[str] = Field(
        default_factory=lambda: [
            "auto_open_pull_request",
            "write_exploit_poc",
            "execute_live_validation",
            "submit_report",
            "auto_promote_finding",
        ]
    )


class PatchSuggestionError(ValueError):
    pass


# Generic principles from final scheme 5.11
_GENERIC_PRINCIPLES = [
    "Fix the root cause, not a single payload.",
    "Enforce controls on the shared service / authorization layer when multiple entry points exist.",
    "Prefer safe APIs and explicit allowlists over ad-hoc string filters.",
    "Backend enforcement over frontend hiding.",
]


def build_patch_suggestion(
    *,
    candidate: dict[str, Any] | None = None,
    package_id: str = "",
    multi_engine_verdict: dict[str, Any] | None = None,
    report_draft: dict[str, Any] | None = None,
) -> PatchSuggestion:
    """Build a non-executing advisory patch suggestion for one candidate."""
    candidate = candidate if isinstance(candidate, dict) else {}
    multi_engine_verdict = (
        multi_engine_verdict if isinstance(multi_engine_verdict, dict) else {}
    )
    report_draft = report_draft if isinstance(report_draft, dict) else {}

    if not candidate and not multi_engine_verdict:
        return PatchSuggestion(
            status=STATUS_SKIPPED,
            package_id=str(package_id or ""),
            confidence="none",
            next_allowed_action="No candidate available for patch suggestion.",
        )

    candidate_id = str(
        candidate.get("candidate_id")
        or multi_engine_verdict.get("candidate_id")
        or report_draft.get("candidate_id")
        or ""
    )
    root_cause_id = str(
        candidate.get("root_cause_id")
        or multi_engine_verdict.get("root_cause_id")
        or ""
    )
    vuln_type = str(
        candidate.get("vuln_type")
        or multi_engine_verdict.get("vuln_type")
        or _infer_vuln_from_root(root_cause_id)
        or "unknown"
    ).lower()
    code_path = str(
        candidate.get("affected_code_path")
        or multi_engine_verdict.get("affected_code_path")
        or ""
    )
    route = _format_route(candidate.get("route") or candidate.get("affected_route"))

    family = _detect_family(vuln_type, root_cause_id)
    playbook = _PLAYBOOKS.get(family, _PLAYBOOKS["generic"])

    mev_status = str(multi_engine_verdict.get("status") or "")
    # Advisory only; never patch_ready until human verification outside this system.
    confidence = "medium" if family != "generic" else "low"
    if mev_status == "false_positive_likely":
        confidence = "low"

    return PatchSuggestion(
        status=STATUS_ADVISORY,
        package_id=str(package_id or ""),
        candidate_id=candidate_id,
        root_cause_id=root_cause_id,
        vuln_type=vuln_type,
        affected_code_path=code_path,
        affected_route=route,
        root_cause_summary=playbook["root_cause_summary"].format(
            root_cause_id=root_cause_id or "unknown",
            code_path=code_path or "unknown",
            route=route or "unknown",
            vuln_type=vuln_type,
        ),
        fix_principles=list(_GENERIC_PRINCIPLES) + list(playbook.get("extra_principles") or []),
        suggested_changes=[
            step.format(
                root_cause_id=root_cause_id or "unknown",
                code_path=code_path or "unknown",
                route=route or "unknown",
                vuln_type=vuln_type,
            )
            for step in playbook["suggested_changes"]
        ],
        why_effective=list(playbook["why_effective"]),
        anti_patterns=[
            PatchAntiPattern(wrong_fix=a["wrong"], correct_direction=a["right"])
            for a in playbook["anti_patterns"]
        ],
        regression_tests=[
            RegressionTestSuggestion(
                test_id=f"RT-{family.upper()[:8]}-{index+1:02d}",
                title=item["title"],
                intent=item["intent"],
                steps=list(item.get("steps") or []),
            )
            for index, item in enumerate(playbook["regression_tests"])
        ],
        shared_layer_note=str(playbook.get("shared_layer_note") or ""),
        confidence=confidence,
        human_review_required=True,
        patch_ready=False,
        auto_pr_allowed=False,
        pr_opened=False,
        exploit_poc_included=False,
        execution_allowed=False,
        validation_allowed=False,
        report_submission_allowed=False,
        confirmed_vulnerability=False,
        finding_promotion_allowed=False,
        next_allowed_action=(
            "Human reviews advisory patch and regression suggestions only. "
            "Do not auto-open PRs, do not write exploit PoCs, do not execute live validation."
        ),
    )


def attach_patch_suggestions_to_bridge_result(
    bridge_result: dict[str, Any],
    *,
    human_review_approvals: list[dict[str, Any]] | None = None,
    human_review_approvals_bundle: dict[str, Any] | None = None,
    package_root: str | Path | None = None,
) -> dict[str, Any]:
    """Attach advisory patch suggestions to each draft / multi-engine verdict.

    Optional durable patch_review approvals stamp review context only —
    never set patch_ready / auto_pr_allowed / report_submission_allowed.
    """
    if not isinstance(bridge_result, dict):
        raise PatchSuggestionError("bridge_result_must_be_object")

    package_id = str(bridge_result.get("package_id") or "")
    resolved_root = package_root or bridge_result.get("package_root")
    resolved_approvals = resolve_human_review_approvals(
        approvals=human_review_approvals,
        approvals_bundle=human_review_approvals_bundle,
        package_root=resolved_root,
        bridge_result=bridge_result,
    )
    drafts = bridge_result.get("drafts") if isinstance(bridge_result.get("drafts"), list) else []
    suggestions: list[dict[str, Any]] = []
    enriched_drafts: list[dict[str, Any]] = []

    for draft in drafts:
        if not isinstance(draft, dict):
            continue
        suggestion = build_patch_suggestion(
            package_id=package_id,
            candidate={
                "candidate_id": draft.get("candidate_id"),
                "root_cause_id": draft.get("root_cause_id"),
                "vuln_type": draft.get("vuln_type"),
                "affected_code_path": draft.get("affected_code_path"),
                "route": draft.get("route"),
                "affected_route": draft.get("route"),
            },
            multi_engine_verdict=draft.get("multi_engine_verdict")
            if isinstance(draft.get("multi_engine_verdict"), dict)
            else {},
            report_draft=draft.get("report_draft")
            if isinstance(draft.get("report_draft"), dict)
            else {},
        )
        payload = _force_safety(suggestion.model_dump())
        patch_app = select_approval_for_candidate(
            resolved_approvals,
            approval_kind=APPROVAL_KIND_PATCH,
            package_id=package_id,
            candidate_id=str(draft.get("candidate_id") or ""),
        )
        pctx = patch_context_from_approval(patch_app)
        payload["human_patch_reviewed"] = bool(pctx.get("human_patch_reviewed"))
        payload["patch_review_accepted"] = bool(pctx.get("patch_review_accepted"))
        payload["patch_review_rejected"] = bool(pctx.get("patch_review_rejected"))
        payload["patch_review_disposition"] = pctx.get("disposition")
        payload = _force_safety(payload)
        suggestions.append(payload)
        report_draft = (
            draft.get("report_draft") if isinstance(draft.get("report_draft"), dict) else {}
        )
        enriched_report = {
            **report_draft,
            "suggested_fix": _render_suggested_fix_section(payload),
            "regression_test": _render_regression_section(payload),
            "patch_suggestion_status": payload["status"],
        }
        enriched_drafts.append(
            {
                **draft,
                "patch_suggestion": payload,
                "report_draft": enriched_report,
                "execution_allowed": False,
                "validation_allowed": False,
                "report_submission_allowed": False,
                "confirmed_vulnerability": False,
            }
        )

    # Refute / no-draft packages still get advisory "why control works" notes from verdicts
    if not suggestions:
        for verdict in bridge_result.get("multi_engine_verdicts") or []:
            if not isinstance(verdict, dict):
                continue
            suggestion = build_patch_suggestion(
                package_id=package_id,
                candidate={
                    "candidate_id": verdict.get("candidate_id"),
                    "root_cause_id": verdict.get("root_cause_id"),
                    "vuln_type": verdict.get("vuln_type"),
                    "affected_code_path": verdict.get("affected_code_path"),
                    "route": verdict.get("route"),
                },
                multi_engine_verdict=verdict,
            )
            payload = _force_safety(suggestion.model_dump())
            # For false_positive_likely, reframe as control retention note
            if str(verdict.get("status") or "") == "false_positive_likely":
                payload["status"] = STATUS_NOT_APPLICABLE
                payload["suggested_changes"] = [
                    "No product patch recommended from this static trial — control evidence currently opposes the candidate.",
                    "If human reopens, re-check the same root-cause layer rather than adding payload filters.",
                ]
                payload["next_allowed_action"] = (
                    "Candidate appears false-positive-likely; retain control tests, do not open a fix PR."
                )
            suggestions.append(payload)

    out = {
        **bridge_result,
        "drafts": enriched_drafts if enriched_drafts else drafts,
        "patch_suggestions": suggestions,
        "patch_suggestion_present": bool(suggestions),
        "auto_pr_allowed": False,
        "pr_opened": False,
        "exploit_poc_included": False,
        "execution_allowed": False,
        "validation_allowed": False,
        "report_submission_allowed": False,
        "confirmed_vulnerability": False,
        "patch_ready": False,
    }
    out = attach_human_review_approvals_to_bridge_result(
        out,
        approvals=resolved_approvals or human_review_approvals,
        approvals_bundle=human_review_approvals_bundle,
        package_root=resolved_root,
    )
    out["auto_pr_allowed"] = False
    out["pr_opened"] = False
    out["exploit_poc_included"] = False
    out["patch_ready"] = False
    out["execution_allowed"] = False
    out["validation_allowed"] = False
    out["report_submission_allowed"] = False
    out["confirmed_vulnerability"] = False
    return out


def _force_safety(payload: dict[str, Any]) -> dict[str, Any]:
    payload = dict(payload)
    payload["auto_pr_allowed"] = False
    payload["pr_opened"] = False
    payload["exploit_poc_included"] = False
    payload["patch_ready"] = False
    payload["execution_allowed"] = False
    payload["validation_allowed"] = False
    payload["report_submission_allowed"] = False
    payload["confirmed_vulnerability"] = False
    payload["finding_promotion_allowed"] = False
    payload["human_review_required"] = True
    blockers = list(payload.get("safety_blockers") or [])
    for required in (
        "auto_open_pull_request",
        "write_exploit_poc",
        "execute_live_validation",
        "submit_report",
        "auto_promote_finding",
    ):
        if required not in blockers:
            blockers.append(required)
    payload["safety_blockers"] = blockers
    return payload


def _format_route(route: Any) -> str:
    if isinstance(route, dict):
        method = str(route.get("method") or "").strip().upper()
        path = str(route.get("path") or route.get("route") or "").strip()
        if method and path:
            return f"{method} {path}"
        return path or method
    return str(route or "").strip()


def _infer_vuln_from_root(root_cause_id: str) -> str:
    root = (root_cause_id or "").lower()
    if "ssrf" in root:
        return "ssrf"
    if "path" in root or "traversal" in root:
        return "path_traversal"
    if "mass_assignment" in root or "mass-assignment" in root:
        return "mass_assignment"
    if "inject" in root or "sqli" in root or "xss" in root:
        return "injection"
    if "auth" in root or "ownership" in root or "idor" in root or "permission" in root:
        return "authorization"
    return "unknown"


def _detect_family(vuln_type: str, root_cause_id: str) -> str:
    blob = f"{vuln_type} {root_cause_id}".lower()
    if "ssrf" in blob:
        return "ssrf"
    if "path" in blob or "traversal" in blob:
        return "path_traversal"
    if "mass_assignment" in blob or "mass-assignment" in blob:
        return "mass_assignment"
    if "inject" in blob or "sqli" in blob or "command_injection" in blob:
        return "injection"
    if "auth" in blob or "ownership" in blob or "idor" in blob or "permission" in blob:
        return "authorization"
    return "generic"


_PLAYBOOKS: dict[str, dict[str, Any]] = {
    "ssrf": {
        "root_cause_summary": (
            "Suspected missing/insufficient URL allowlist or private-network guard before outbound fetch "
            "({root_cause_id} at {code_path}; route {route})."
        ),
        "extra_principles": [
            "Validate destination before any network connect, not after response is received.",
            "Block link-local / private / metadata hosts; prefer explicit allowlists for production webhooks.",
        ],
        "suggested_changes": [
            "Introduce a shared URL validation helper (scheme allowlist, hostname denylist, private-IP block) used by all outbound fetch entry points.",
            "Call the helper immediately before HTTP client requests for user-controlled URLs (e.g. subscriberUrl / webhook targets).",
            "Reject redirects that re-target private/metadata hosts (or disable redirects when not required).",
            "Apply the same helper at the service layer so additional routes cannot bypass a single controller check.",
        ],
        "why_effective": [
            "Root-cause validation prevents the network edge from ever contacting disallowed destinations.",
            "Shared service-layer helper closes alternate entry points that only controller-level filters would miss.",
        ],
        "anti_patterns": [
            {
                "wrong": "Only block one known metadata IP or one payload string.",
                "right": "Enforce scheme + hostname + private-IP policy on every outbound URL.",
            },
            {
                "wrong": "Validate only on the frontend form.",
                "right": "Server-side validation before connect.",
            },
        ],
        "regression_tests": [
            {
                "title": "Private IP destination rejected",
                "intent": "User-controlled URL pointing at private/link-local targets is rejected before fetch.",
                "steps": [
                    "Unit-test validator with 127.0.0.1, 10.0.0.1, 169.254.169.254, localhost.",
                    "Assert no HTTP client call is made when validation fails.",
                ],
            },
            {
                "title": "Allowlisted public HTTPS still works",
                "intent": "Legitimate external HTTPS targets permitted by policy continue to work.",
                "steps": [
                    "Pass an allowlisted example host through the same helper.",
                    "Assert validation success without relaxing private-IP rules.",
                ],
            },
        ],
        "shared_layer_note": "Prefer one outbound URL policy module used by all webhook/fetch features.",
    },
    "authorization": {
        "root_cause_summary": (
            "Suspected missing object ownership / permission check before sensitive read/write "
            "({root_cause_id} at {code_path}; route {route})."
        ),
        "extra_principles": [
            "Authorize on the resource server side using subject + object relationship, not only UI gates.",
        ],
        "suggested_changes": [
            "Add an ownership/permission assertion in the shared service method that loads the target object.",
            "Deny by default when the subject lacks relation to the object (fail closed).",
            "Reuse the same guard for related endpoints (export, update, delete, share) that touch the same object type.",
            "Return generic 403/404 without leaking existence when policy requires.",
        ],
        "why_effective": [
            "Object-level checks close IDOR-style access even when the caller knows a valid ID.",
            "Shared service enforcement covers multiple controllers that would otherwise re-implement checks inconsistently.",
        ],
        "anti_patterns": [
            {
                "wrong": "Hide the button in the UI only.",
                "right": "Enforce ownership in the backend service before data access.",
            },
            {
                "wrong": "Check role globally but not object membership.",
                "right": "Bind authorization to the specific object id being accessed.",
            },
        ],
        "regression_tests": [
            {
                "title": "Cross-user object access denied",
                "intent": "User A cannot read/export User B object by id.",
                "steps": [
                    "Create two subjects with separate objects in a local fixture.",
                    "Call the sensitive route as subject A with subject B object id; expect deny.",
                ],
            },
            {
                "title": "Owner access still allowed",
                "intent": "Legitimate owner retains access after the guard is added.",
                "steps": [
                    "Call the same route as the object owner; expect success.",
                ],
            },
        ],
        "shared_layer_note": "Put ownership checks in the domain service, not only each controller.",
    },
    "path_traversal": {
        "root_cause_summary": (
            "Suspected path concatenation / insufficient path canonicalization for user-influenced file paths "
            "({root_cause_id} at {code_path}; route {route})."
        ),
        "extra_principles": [
            "Resolve then verify the final path stays inside an allowed root.",
        ],
        "suggested_changes": [
            "Canonicalize the resolved path and require it to be a child of the configured base directory.",
            "Reject path segments that escape the root (`..`, absolute paths, symlink escapes where applicable).",
            "Prefer OS path APIs that enforce root confinement over manual string sanitization alone.",
            "Apply the same confinement helper to all file read/write entry points sharing that storage root.",
        ],
        "why_effective": [
            "Root confinement checks the actual resolved location, not just surface substrings.",
            "Shared helper prevents alternate endpoints from reintroducing traversal.",
        ],
        "anti_patterns": [
            {
                "wrong": "Only strip `../` once or block a single payload.",
                "right": "Canonicalize and verify containment under the allowed root.",
            }
        ],
        "regression_tests": [
            {
                "title": "Traversal rejected",
                "intent": "Paths that resolve outside the base directory are rejected.",
                "steps": [
                    "Feed `../` and absolute path cases into the confinement helper.",
                    "Assert rejection before file open.",
                ],
            },
            {
                "title": "In-root path allowed",
                "intent": "Normal relative paths under the base directory still resolve.",
                "steps": [
                    "Resolve a safe child path; assert success.",
                ],
            },
        ],
        "shared_layer_note": "Centralize storage-root confinement for every file API.",
    },
    "mass_assignment": {
        "root_cause_summary": (
            "Suspected binding of untrusted request fields onto privileged model attributes "
            "({root_cause_id} at {code_path}; route {route})."
        ),
        "extra_principles": [
            "Use explicit allowlists / DTO mapping; never pass raw request bodies into privileged models.",
        ],
        "suggested_changes": [
            "Introduce an explicit update DTO / allowlist of client-writable fields.",
            "Map only allowlisted fields onto the domain entity; ignore role/admin/owner flags from clients.",
            "Set privileged fields only in server-side workflows with separate authorization.",
            "Apply the same DTO at all create/update entry points for that entity.",
        ],
        "why_effective": [
            "Allowlists remove attacker control of privileged attributes regardless of extra JSON keys.",
            "Server-side assignment of privileged fields preserves intended admin workflows safely.",
        ],
        "anti_patterns": [
            {
                "wrong": "Blacklist a few field names and still accept free-form dict updates.",
                "right": "Allowlist writable fields via typed DTO.",
            }
        ],
        "regression_tests": [
            {
                "title": "Privileged field ignored",
                "intent": "Client-supplied role/is_admin/owner fields do not change entity privileges.",
                "steps": [
                    "Submit update payload including privileged keys.",
                    "Assert entity privileges unchanged.",
                ],
            },
            {
                "title": "Allowlisted fields still update",
                "intent": "Normal writable fields continue to update.",
                "steps": [
                    "Submit only allowlisted fields; assert expected mutation.",
                ],
            },
        ],
        "shared_layer_note": "Keep write mapping next to the domain update service.",
    },
    "injection": {
        "root_cause_summary": (
            "Suspected unsafe concatenation of untrusted input into query/command/template evaluation "
            "({root_cause_id} at {code_path}; route {route})."
        ),
        "extra_principles": [
            "Use parameterized queries / safe template APIs; treat user input as data, never code.",
        ],
        "suggested_changes": [
            "Replace string-built queries/commands with parameterized APIs or bound arguments.",
            "Encode/escape at the correct layer when output encoding is required (context-aware).",
            "Reject unexpected control characters where a strict grammar applies.",
            "Apply the safe API in the shared data-access layer used by all call sites.",
        ],
        "why_effective": [
            "Parameterization prevents untrusted input from changing query/command structure.",
            "Shared data-access fixes cover multiple controllers that share the same sink.",
        ],
        "anti_patterns": [
            {
                "wrong": "Block a single quote character or one payload sample.",
                "right": "Use parameterized / safe APIs for all untrusted inputs.",
            }
        ],
        "regression_tests": [
            {
                "title": "Metacharacters treated as data",
                "intent": "Inputs with SQL/command metacharacters do not alter structure.",
                "steps": [
                    "Unit-test repository/query builder with adversarial strings.",
                    "Assert parameters are bound, not concatenated.",
                ],
            }
        ],
        "shared_layer_note": "Fix sinks in the data-access layer, not only one handler.",
    },
    "generic": {
        "root_cause_summary": (
            "Unverified candidate ({vuln_type} / {root_cause_id}) at {code_path} ({route}) needs human-confirmed root cause before any code change."
        ),
        "extra_principles": [],
        "suggested_changes": [
            "Confirm the true root-cause layer with local authorized evidence before editing production code.",
            "Prefer a shared enforcement point over a one-off filter at a single route.",
            "Document the invariant the fix should enforce and where it must hold for all entry points.",
        ],
        "why_effective": [
            "Root-cause fixes survive payload variants and alternate entry points.",
        ],
        "anti_patterns": [
            {
                "wrong": "Ship a patch based only on model output without human residual review.",
                "right": "Keep suggestions advisory until human confirmation.",
            }
        ],
        "regression_tests": [
            {
                "title": "Invariant regression placeholder",
                "intent": "After a human-approved fix, add a test that fails if the invariant regresses.",
                "steps": [
                    "Encode the security invariant as a unit/integration assertion.",
                    "Run only in authorized CI / local environments.",
                ],
            }
        ],
        "shared_layer_note": "Identify whether multiple routes share the same service sink.",
    },
}


__all__ = [
    "STATUS_ADVISORY",
    "STATUS_NOT_APPLICABLE",
    "STATUS_SKIPPED",
    "PatchAntiPattern",
    "PatchSuggestion",
    "PatchSuggestionError",
    "RegressionTestSuggestion",
    "attach_patch_suggestions_to_bridge_result",
    "build_patch_suggestion",
]


def _render_suggested_fix_section(payload: dict[str, Any]) -> str:
    lines = [
        str(payload.get("root_cause_summary") or "").strip(),
        "",
        "Suggested changes (advisory only; no auto-PR):",
    ]
    for item in payload.get("suggested_changes") or []:
        if str(item).strip():
            lines.append(f"- {item}")
    why = payload.get("why_effective") or []
    if why:
        lines.append("")
        lines.append("Why this direction works:")
        for item in why:
            if str(item).strip():
                lines.append(f"- {item}")
    return "\n".join(lines).strip()


def _render_regression_section(payload: dict[str, Any]) -> str:
    lines = ["Regression tests (text suggestions only; not executed):"]
    for item in payload.get("regression_tests") or []:
        if not isinstance(item, dict):
            continue
        title = str(item.get("title") or item.get("test_id") or "test").strip()
        intent = str(item.get("intent") or "").strip()
        lines.append(f"- {title}: {intent}".rstrip(": "))
        for step in item.get("steps") or []:
            if str(step).strip():
                lines.append(f"  - {step}")
    lines.append("")
    lines.append("Do not treat these as exploit PoCs or live validation steps.")
    return "\n".join(lines).strip()