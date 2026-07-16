"""Local-lab observation for black-box differential plans.

Explicit local_lab mode only. Never contacts remote targets: plans are rebound
to the in-process synthetic widgets lab (loopback) for observation.
"""

from __future__ import annotations

from typing import Any, Literal

from app.black_box_hunter import (
    DifferentialEvidenceBundle,
    DifferentialEvidenceDecision,
    DifferentialPlan,
    DifferentialTrial,
    ObservedWorkflowModel,
    PlannedDifferentialTrial,
    TestObjectAlias,
    WorkflowPathParameter,
    WorkflowStep,
    evaluate_differential_evidence,
    plan_differential_trials,
)
from app.black_box_hunter.har_intake import (
    build_observed_workflow_model_from_role_hars,
    project_plan_only_candidates,
)
from app.black_box_hunter.local_lab import (
    CHILD_OBJECT_BY_OWNER,
    LOOPBACK_ORIGIN,
    LocalLabMode,
    LocalLabTransport,
    PRIMARY_OBJECT_BY_OWNER,
    SYNTHETIC_CHILD_ALTERNATE_PARENTS,
    SYNTHETIC_CHILD_PARENTS,
    SYNTHETIC_OBJECT_OWNERS,
)

DecisionStatus = Literal[
    "retained",
    "refuted",
    "suppressed",
    "needs_evidence",
]


def planned_trial_to_local_lab_trial(
    planned: PlannedDifferentialTrial,
) -> DifferentialTrial:
    """Convert a planned stage into a loopback lab DifferentialTrial."""
    as_child = (
        planned.trial_class == "owned_parent_child_swap"
        and planned.phase != "session_control"
    )
    lab_object = _lab_test_object(planned.test_object, as_child=as_child)
    return DifferentialTrial(
        trial_class=planned.trial_class,
        workflow=_lab_workflow(
            planned.workflow,
            test_object=lab_object,
            parent_object_alias=planned.parent_object_alias,
            as_child=as_child,
        ),
        session=planned.session,
        test_object=lab_object,
        generated_requests_in_workflow=0,
        active_generated_requests=0,
        elapsed_seconds=0,
        seconds_since_last_generated_request=3,
        requires_rollback=planned.requires_rollback,
        rollback_ready=planned.rollback_ready,
    )


def observe_plan_on_local_lab(
    plan: DifferentialPlan,
    *,
    mode: LocalLabMode = "bola",
) -> tuple[DifferentialEvidenceBundle, DifferentialEvidenceDecision]:
    """Execute all stages of one plan against the synthetic local lab."""
    transport = LocalLabTransport(mode=mode)
    try:
        baseline = transport.execute(planned_trial_to_local_lab_trial(plan.baseline))
        # Dual stable baseline: owner baseline + alternate-owned control read.
        baseline_b = transport.execute(
            planned_trial_to_local_lab_trial(plan.session_control)
        )
        trial = transport.execute(planned_trial_to_local_lab_trial(plan.trial))
        owner_control = transport.execute(
            planned_trial_to_local_lab_trial(plan.owner_control)
        )
        session_control = transport.execute(
            planned_trial_to_local_lab_trial(plan.session_control)
        )
        repeat = transport.execute(planned_trial_to_local_lab_trial(plan.repeat))
        rollback = None
        if plan.rollback is not None:
            rollback = transport.execute(
                planned_trial_to_local_lab_trial(plan.rollback)
            )
    finally:
        transport.close()

    rollback_required = plan.rollback is not None or plan.trial.requires_rollback
    bundle = DifferentialEvidenceBundle(
        baseline_a=baseline,
        baseline_b=baseline_b,
        trial=trial,
        owner_control=owner_control,
        session_control=session_control,
        repeat=repeat,
        rollback=rollback,
        independent_repeat=True,
        rollback_required=rollback_required,
    )
    decision = evaluate_differential_evidence(bundle)
    return bundle, decision


def run_model_local_lab_pipeline(
    model: ObservedWorkflowModel,
    *,
    mode: LocalLabMode = "bola",
    local_lab: bool = True,
    trial_classes: set[str] | None = None,
    schema_version: str = "model_local_lab_pipeline_v1",
    source: str | None = None,
) -> dict[str, Any]:
    """ObservedWorkflowModel -> plans -> local-lab observe -> ranked candidates.

    Shared observe path for HAR, Browser Demo, and Studio recording exports.
    Requires ``local_lab=True``. Remote observation is intentionally unsupported.
    """
    if not local_lab:
        raise ValueError("local_lab_flag_required")

    _require_local_lab_accounts(model)

    plans = plan_differential_trials(model, require_all_classes=False)
    selected = [
        plan
        for plan in plans
        if trial_classes is None or plan.trial_class in trial_classes
    ]
    if not selected:
        raise ValueError("no_matching_differential_plans")

    observed_candidates: list[dict[str, Any]] = []
    observations: list[dict[str, Any]] = []

    for plan in selected:
        bundle, evidence = observe_plan_on_local_lab(plan, mode=mode)
        decision = _map_evidence_to_decision(evidence)
        observations.append(
            {
                "plan_trial_class": plan.trial_class,
                "evidence_status": evidence.status,
                "evidence_reason": evidence.reason,
                "decision": decision,
                "trial_status_class": bundle.trial.status_class,
                "trial_stop": (
                    bundle.trial.stop.reason if bundle.trial.stop is not None else None
                ),
                "intended_sharing": bundle.trial.intended_sharing,
                "strong_signal": _bundle_trial_strong(bundle),
            }
        )
        observed_candidates.append(
            _project_observed_candidate(
                model=model,
                plan=plan,
                evidence=evidence,
                decision=decision,
                rank=len(observed_candidates) + 1,
                bundle=bundle,
            )
        )

    # Rank: retained first (more survive falsify steps first), then
    # needs_evidence, then refuted/suppressed (more kill steps first).
    rank_order = {"retained": 0, "needs_evidence": 1, "refuted": 2, "suppressed": 3}

    def _rank_key(card: dict[str, Any]) -> tuple:
        decision = str(card.get("decision") or "")
        attempts = list(card.get("falsify_attempts") or [])
        survives = sum(1 for item in attempts if item.get("outcome") == "survive")
        kills = sum(1 for item in attempts if item.get("outcome") == "kill")
        decision_rank = rank_order.get(decision, 9)
        if decision == "retained":
            return (decision_rank, -survives, str(card.get("candidate_id") or ""))
        if decision in {"refuted", "suppressed"}:
            return (decision_rank, -kills, str(card.get("candidate_id") or ""))
        return (decision_rank, 0, str(card.get("candidate_id") or ""))

    observed_candidates.sort(key=_rank_key)
    for index, card in enumerate(observed_candidates, start=1):
        card["rank"] = index

    retained = [c for c in observed_candidates if c["decision"] == "retained"]
    plan_only_fallback = project_plan_only_candidates(model, selected)

    result: dict[str, Any] = {
        "schema_version": schema_version,
        "mode": "local_lab_observe",
        "lab_mode": mode,
        "local_lab": True,
        "workflow_model": model.safe_projection(),
        "plan_classes": [plan.trial_class for plan in selected],
        "observations": observations,
        "candidates": observed_candidates,
        "retained_candidates": retained,
        "plan_only_reference": plan_only_fallback,
        "execution_allowed": False,
        "dispatch_allowed": False,
        "validation_allowed": False,
        "candidate_promotion_allowed": False,
        "report_submission_allowed": False,
        "raw_secrets_persisted": False,
    }
    if source is not None:
        result["source"] = source
    return result


def run_har_local_lab_pipeline(
    role_hars: dict[str, dict[str, Any]],
    *,
    mode: LocalLabMode = "bola",
    local_lab: bool = True,
    trial_classes: set[str] | None = None,
    role_ranks: dict[str, int] | None = None,
    role_aliases: dict[str, str] | None = None,
    account_aliases: dict[str, str] | None = None,
) -> dict[str, Any]:
    """HAR -> plans -> local-lab observe -> ranked research candidates.

    Requires ``local_lab=True``. Remote observation is intentionally unsupported.
    """
    model = build_observed_workflow_model_from_role_hars(
        role_hars,
        role_ranks=role_ranks,
        role_aliases=role_aliases,
        account_aliases=account_aliases,
    )
    return run_model_local_lab_pipeline(
        model,
        mode=mode,
        local_lab=local_lab,
        trial_classes=trial_classes,
        schema_version="har_local_lab_pipeline_v1",
    )


def _lab_workflow(
    step: WorkflowStep,
    *,
    test_object: TestObjectAlias | None = None,
    parent_object_alias: str | None = None,
    as_child: bool = False,
) -> WorkflowStep:
    method = step.method.upper()
    if method in {"GET", "HEAD"}:
        if as_child and test_object is not None:
            if parent_object_alias is not None:
                parent = SYNTHETIC_CHILD_ALTERNATE_PARENTS[test_object.alias]
            else:
                parent = SYNTHETIC_CHILD_PARENTS[test_object.alias]
            # Concrete parent segment (lab alias, not raw id) + child {object}.
            route = f"/widgets/{parent}/{{object}}"
            object_segment = 3
        else:
            route = "/widgets/{object}"
            object_segment = 2
        action = "read_only_replay"
    elif method in {"PUT", "PATCH"}:
        route = "/widgets/{object}/state"
        object_segment = 2
        action = "reversible_update"
        method = "PATCH"
    elif method == "POST":
        # Local lab has no create route; map create probes to owner read path.
        route = "/widgets/{object}"
        object_segment = 2
        action = "read_only_replay"
        method = "GET"
    else:
        raise ValueError("local_lab_method_unsupported")

    return WorkflowStep(
        workflow_index=step.workflow_index,
        origin=LOOPBACK_ORIGIN,
        route_template=route,
        path_parameters=[
            WorkflowPathParameter(name="object", segment=object_segment, type="string"),
        ],
        method=method,
        action=action,
        state="active",
    )


def _lab_test_object(
    test_object: TestObjectAlias,
    *,
    as_child: bool = False,
) -> TestObjectAlias:
    if test_object.alias in SYNTHETIC_OBJECT_OWNERS:
        alias = test_object.alias
        owner = SYNTHETIC_OBJECT_OWNERS[alias]
        return TestObjectAlias(
            alias=alias,
            owner_alias=owner,
            test_owned=True,
            reversible=True,
            state=test_object.state or "active",
        )
    owner = test_object.owner_alias
    if as_child:
        if owner not in CHILD_OBJECT_BY_OWNER:
            raise ValueError("local_lab_owner_binding_required")
        alias = CHILD_OBJECT_BY_OWNER[owner]
    else:
        if owner not in PRIMARY_OBJECT_BY_OWNER:
            raise ValueError("local_lab_owner_binding_required")
        alias = PRIMARY_OBJECT_BY_OWNER[owner]
    return TestObjectAlias(
        alias=alias,
        owner_alias=owner,
        test_owned=True,
        reversible=True,
        state=test_object.state or "active",
    )


def _require_local_lab_accounts(model: ObservedWorkflowModel) -> None:
    accounts = {workflow.session.account_alias for workflow in model.workflows}
    required = set(SYNTHETIC_OBJECT_OWNERS.values())
    if not required.issubset(accounts):
        raise ValueError("local_lab_requires_account_a_and_account_b")


def _bundle_trial_strong(bundle: DifferentialEvidenceBundle) -> bool:
    trial = bundle.trial
    return any(
        (
            trial.canary_match is True,
            trial.structural_identity_match is True,
            trial.state_effect is True,
        )
    )


def _map_evidence_to_decision(evidence: DifferentialEvidenceDecision) -> DecisionStatus:
    if evidence.status == "review_ready":
        return "retained"
    if evidence.status == "refuted":
        return "refuted"
    if evidence.status in {"hypothesis", "observed", "reproduced"}:
        return "needs_evidence"
    # inconclusive: secure denial / stop / weak signal
    if evidence.reason in {
        "status_only_signal_insufficient",
        "intended_sharing_observed",
    }:
        return "suppressed"
    if evidence.reason == "terminal_transport_stop":
        return "suppressed"
    return "needs_evidence"


def _project_observed_candidate(
    *,
    model: ObservedWorkflowModel,
    plan: DifferentialPlan,
    evidence: DifferentialEvidenceDecision,
    decision: DecisionStatus,
    rank: int,
    bundle: DifferentialEvidenceBundle | None = None,
) -> dict[str, Any]:
    trial = plan.trial
    route = trial.workflow.route_template
    method = trial.workflow.method
    why_alive: list[str] = []
    why_dead: list[str] = []
    gaps: list[str] = []
    falsify_attempts = _falsify_attempts_for_evidence(
        evidence=evidence,
        decision=decision,
        trial_class=plan.trial_class,
        bundle=bundle,
    )

    if decision == "retained":
        why_alive.extend(
            [
                f"evidence_status:{evidence.status}",
                f"evidence_reason:{evidence.reason}",
                "local_lab_controls_and_repeat_passed",
            ]
        )
    elif decision == "refuted":
        why_dead.append(f"evidence_reason:{evidence.reason}")
    elif decision == "suppressed":
        why_dead.append(f"evidence_reason:{evidence.reason}")
    else:
        gaps.append(f"evidence_status:{evidence.status}")
        gaps.append(f"evidence_reason:{evidence.reason}")

    return {
        "schema_version": "bb_candidate_v1",
        "candidate_id": f"bbc_lab_{plan.trial_class}",
        "rank": rank,
        "family": plan.trial_class,
        "title": (
            f"{trial.session.account_alias} access check on "
            f"{trial.test_object.owner_alias}-owned object via {method} {route}"
        ),
        "affected_endpoint": f"{method} {route}",
        "broken_invariant": (
            "Only the owning account may read an object by identifier"
            if plan.trial_class == "cross_account_object_swap"
            else f"Authorization boundary must hold for {plan.trial_class}"
        ),
        "plan_trial_class": plan.trial_class,
        "workflow_aliases": [workflow.workflow_alias for workflow in model.workflows],
        "evidence_status": evidence.status,
        "evidence_reason": evidence.reason,
        "why_alive": why_alive,
        "why_dead_or_weak": why_dead,
        "evidence_gaps": gaps,
        "falsify_attempts": falsify_attempts,
        "decision_reason": evidence.reason,
        "safe_validation_plan": [
            "Local-lab observation only; not a confirmed vulnerability.",
            "Human recheck on operator-owned test objects before any report draft.",
            "Do not submit reports automatically.",
        ],
        "decision": decision,
        "execution_allowed": False,
        "dispatch_allowed": False,
        "validation_allowed": False,
        "candidate_promotion_allowed": False,
        "report_submission_allowed": False,
        "mode": "local_lab_observe",
        "local_lab": True,
    }


def _falsify_attempts_for_evidence(
    *,
    evidence: DifferentialEvidenceDecision,
    decision: DecisionStatus,
    trial_class: str,
    bundle: DifferentialEvidenceBundle | None = None,
) -> list[dict[str, Any]]:
    """Map differential evidence into ordered kill/survive attempts.

    When a bundle is present, emit the full falsification checklist that mirrors
    evaluate_differential_evidence. Without a bundle, fall back to a single
    terminal attempt from the evidence decision.
    """
    if bundle is None:
        return _single_falsify_attempt(
            evidence=evidence,
            decision=decision,
            trial_class=trial_class,
        )

    attempts: list[dict[str, Any]] = []
    observations = [
        observation
        for observation in (
            bundle.baseline_a,
            bundle.baseline_b,
            bundle.trial,
            bundle.owner_control,
            bundle.session_control,
            bundle.repeat,
            bundle.rollback,
        )
        if observation is not None
    ]

    def add(rule_id: str, outcome: str, note: str, refs: list[str]) -> None:
        attempts.append(
            {
                "attempt_id": f"fa_{trial_class}_{rule_id}_{len(attempts)+1}",
                "rule_id": f"differential:{rule_id}",
                "outcome": outcome,
                "evidence_refs": refs,
                "note": note,
            }
        )

    # 1) transport stop
    if any(observation.stop is not None for observation in observations):
        add(
            "terminal_transport_stop",
            "kill" if decision in {"refuted", "suppressed"} else "insufficient",
            "A trial stage stopped before differential evidence completed.",
            [f"evidence_reason:{evidence.reason}"],
        )
        return attempts

    # 2) intended sharing
    if bundle.trial.intended_sharing:
        add(
            "intended_sharing_observed",
            "kill",
            "Cross-account access matches intended sharing; not a vulnerability.",
            ["trial:intended_sharing=true"],
        )
        return attempts
    add(
        "intended_sharing_observed",
        "survive",
        "No intended-sharing marker on the trial observation.",
        ["trial:intended_sharing=false"],
    )

    # 3) strong signal
    trial = bundle.trial
    strong = any(
        (
            trial.canary_match is True,
            trial.structural_identity_match is True,
            trial.state_effect is True,
        )
    )
    if not strong:
        add(
            "status_only_signal_insufficient",
            "kill" if decision in {"refuted", "suppressed"} else "insufficient",
            "Trial lacked canary/structural/state signal beyond status class.",
            ["trial:strong_signal=false"],
        )
        return attempts
    add(
        "strong_signal_required",
        "survive",
        "Trial produced a strong differential signal.",
        ["trial:strong_signal=true"],
    )

    # 4) dual baseline stability (status-only summary when full helpers unavailable)
    baselines_ok = (
        bundle.baseline_a is not None
        and bundle.baseline_b is not None
        and bundle.baseline_a.status_class == "2xx"
        and bundle.baseline_b.status_class == "2xx"
        and bundle.baseline_a.response_schema_fingerprint
        == bundle.baseline_b.response_schema_fingerprint
    )
    if not baselines_ok:
        add(
            "stable_dual_baseline_required",
            "kill" if decision in {"refuted", "suppressed"} else "insufficient",
            "Owner/alternate baselines were not dual-stable.",
            ["baseline:stable=false"],
        )
        return attempts
    add(
        "stable_dual_baseline_required",
        "survive",
        "Dual baselines were stable and consistent.",
        ["baseline:stable=true"],
    )

    # 5) controls
    controls_ok = (
        bundle.owner_control is not None
        and bundle.session_control is not None
        and bundle.owner_control.status_class == "2xx"
        and bundle.session_control.status_class == "2xx"
    )
    if not controls_ok:
        add(
            "owner_and_session_controls_required",
            "insufficient",
            "Owner and session controls were incomplete.",
            ["controls:complete=false"],
        )
        return attempts
    add(
        "owner_and_session_controls_required",
        "survive",
        "Owner and session controls returned safe observations.",
        ["controls:complete=true"],
    )

    # 6) independent repeat
    if bundle.repeat is None or not bundle.independent_repeat:
        add(
            "independent_repeat_required",
            "insufficient",
            "Independent repeat observation was missing.",
            ["repeat:present=false"],
        )
        return attempts
    add(
        "independent_repeat_required",
        "survive",
        "Independent repeat matched the trial observation.",
        ["repeat:present=true"],
    )

    # 7) terminal decision
    if decision == "retained":
        add(
            evidence.reason,
            "survive",
            "All falsification checks passed; candidate remains review-ready only.",
            [f"evidence_status:{evidence.status}"],
        )
    elif decision in {"refuted", "suppressed"}:
        add(
            evidence.reason,
            "kill",
            f"Terminal kill after checklist: {evidence.reason}.",
            [f"evidence_status:{evidence.status}"],
        )
    else:
        add(
            evidence.reason,
            "insufficient",
            f"Evidence still incomplete: {evidence.reason}.",
            [f"evidence_status:{evidence.status}"],
        )
    return attempts


def _single_falsify_attempt(
    *,
    evidence: DifferentialEvidenceDecision,
    decision: DecisionStatus,
    trial_class: str,
) -> list[dict[str, Any]]:
    rule_id = f"differential:{evidence.reason}"
    if decision == "retained":
        outcome = "survive"
        note = "Controls, stable baselines, and strong signal survived falsification."
    elif decision in {"refuted", "suppressed"}:
        outcome = "kill"
        note = f"Candidate killed by differential evidence reason {evidence.reason}."
    else:
        outcome = "insufficient"
        note = f"Evidence incomplete for {trial_class}: {evidence.reason}."
    return [
        {
            "attempt_id": f"fa_{trial_class}_{evidence.reason}",
            "rule_id": rule_id,
            "outcome": outcome,
            "evidence_refs": [
                f"evidence_status:{evidence.status}",
                f"evidence_reason:{evidence.reason}",
            ],
            "note": note,
        }
    ]
