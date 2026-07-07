from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from app.campaign_orchestrator import tick_campaign
from app.repository import DatabaseRepository
from app.source_audit import collect_authorized_code_files, evaluate_source_scope
from app.worker.tasks import run_agent_task


@dataclass(frozen=True)
class AgentGoal:
    goal: str
    repo_path: Path
    scope_path: Path
    campaign_id: str | None = None
    max_steps: int = 6


@dataclass(frozen=True)
class AgentStep:
    action: str
    status: str
    stop_reasons: list[str] = field(default_factory=list)
    next_actions: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "action": self.action,
            "status": self.status,
            "stop_reasons": self.stop_reasons,
            "next_actions": self.next_actions,
        }


@dataclass(frozen=True)
class AgentResult:
    status: str
    campaign_id: str | None
    stop_reasons: list[str]
    steps: list[AgentStep]
    goal: str
    repo_path: str
    scope_path: str
    next_actions: list[str] = field(default_factory=list)
    execution_allowed: bool = False

    def to_text(self) -> str:
        lines = [
            "mythos agent",
            f"status: {self.status}",
            f"campaign_id: {self.campaign_id or 'none'}",
            f"stop_reasons: {', '.join(self.stop_reasons) if self.stop_reasons else 'none'}",
            f"next_actions: {', '.join(self.next_actions) if self.next_actions else 'none'}",
            f"execution_allowed: {str(self.execution_allowed).lower()}",
            "steps:",
        ]
        for step in self.steps:
            lines.append(f"- {step.action}: {step.status}")
            if step.stop_reasons:
                lines.append(f"  stop_reasons: {', '.join(step.stop_reasons)}")
            if step.next_actions:
                lines.append(f"  next_actions: {', '.join(step.next_actions)}")
        return "\n".join(lines)

    def to_dict(self) -> dict:
        return {
            "status": self.status,
            "campaign_id": self.campaign_id,
            "goal": self.goal,
            "repo_path": self.repo_path,
            "scope_path": self.scope_path,
            "stop_reasons": self.stop_reasons,
            "next_actions": self.next_actions,
            "execution_allowed": self.execution_allowed,
            "steps": [step.to_dict() for step in self.steps],
        }


@dataclass(frozen=True)
class AgentStatus:
    status: str
    campaign_id: str | None
    goal: str
    repo_path: str
    scope_path: str
    pending_approval_count: int
    awaiting_validation_count: int
    next_actions: list[str] = field(default_factory=list)
    execution_allowed: bool = False

    def to_text(self) -> str:
        return "\n".join(
            [
                "mythos agent status",
                f"status: {self.status}",
                f"campaign_id: {self.campaign_id or 'none'}",
                f"pending_approval_count: {self.pending_approval_count}",
                f"awaiting_validation_count: {self.awaiting_validation_count}",
                f"next_actions: {', '.join(self.next_actions) if self.next_actions else 'none'}",
                f"execution_allowed: {str(self.execution_allowed).lower()}",
            ]
        )

    def to_dict(self) -> dict:
        return {
            "status": self.status,
            "campaign_id": self.campaign_id,
            "goal": self.goal,
            "repo_path": self.repo_path,
            "scope_path": self.scope_path,
            "pending_approval_count": self.pending_approval_count,
            "awaiting_validation_count": self.awaiting_validation_count,
            "next_actions": self.next_actions,
            "execution_allowed": self.execution_allowed,
        }


@dataclass(frozen=True)
class AgentGates:
    campaign_id: str | None
    approvals: list[dict]
    validation_runs: list[dict]
    execution_allowed: bool = False

    def to_text(self) -> str:
        lines = [
            "mythos agent gates",
            f"campaign_id: {self.campaign_id or 'none'}",
            f"execution_allowed: {str(self.execution_allowed).lower()}",
            "approvals:",
        ]
        if not self.approvals:
            lines.append("- none")
        for approval in self.approvals:
            latest_review_note = approval.get("latest_review_note") or {}
            lines.append(
                "- "
                f"id: {approval['id']}; "
                f"status: {approval['status']}; "
                f"validation_mode: {approval['validation_mode']}; "
                f"plan_digest: {approval['plan_digest']}; "
                f"review_note_count: {approval.get('review_note_count', 0)}; "
                f"latest_review_decision: {latest_review_note.get('decision', 'none')}; "
                f"latest_review_reviewer: {latest_review_note.get('reviewer', 'none')}; "
                f"latest_review_stage_id: {latest_review_note.get('stage_id', 'none')}"
            )
        lines.append("validation_runs:")
        if not self.validation_runs:
            lines.append("- none")
        for run in self.validation_runs:
            latest_review_note = run.get("latest_review_note") or {}
            lines.append(
                "- "
                f"id: {run['id']}; "
                f"status: {run['status']}; "
                f"target_ref: {run['target_ref']}; "
                f"plan_digest: {run['plan_digest']}; "
                f"execution_allowed: {str(run['execution_allowed']).lower()}; "
                f"review_note_count: {run.get('review_note_count', 0)}; "
                f"latest_review_decision: {latest_review_note.get('decision', 'none')}; "
                f"latest_review_reviewer: {latest_review_note.get('reviewer', 'none')}; "
                f"latest_review_stage_id: {latest_review_note.get('stage_id', 'none')}"
            )
        return "\n".join(lines)

    def to_dict(self) -> dict:
        return {
            "campaign_id": self.campaign_id,
            "approvals": self.approvals,
            "validation_runs": self.validation_runs,
            "execution_allowed": self.execution_allowed,
        }


@dataclass(frozen=True)
class AgentReviewNote:
    status: str
    campaign_id: str | None
    gate_ref: str
    reviewer: str
    decision: str
    note: str
    stage_id: str | None = None
    stop_reasons: list[str] = field(default_factory=list)
    execution_allowed: bool = False
    approval_allowed: bool = False

    def to_text(self) -> str:
        return "\n".join(
            [
                "mythos agent review note",
                f"status: {self.status}",
                f"campaign_id: {self.campaign_id or 'none'}",
                f"gate_ref: {self.gate_ref}",
                f"stage_id: {self.stage_id or 'none'}",
                f"reviewer: {self.reviewer}",
                f"decision: {self.decision}",
                f"stop_reasons: {', '.join(self.stop_reasons) if self.stop_reasons else 'none'}",
                f"execution_allowed: {str(self.execution_allowed).lower()}",
                f"approval_allowed: {str(self.approval_allowed).lower()}",
            ]
        )

    def to_dict(self) -> dict:
        return {
            "status": self.status,
            "campaign_id": self.campaign_id,
            "gate_ref": self.gate_ref,
            "reviewer": self.reviewer,
            "decision": self.decision,
            "note": self.note,
            "stage_id": self.stage_id,
            "stop_reasons": self.stop_reasons,
            "execution_allowed": self.execution_allowed,
            "approval_allowed": self.approval_allowed,
        }


@dataclass(frozen=True)
class AgentNext:
    status: str
    campaign_id: str | None
    actions: list[dict]
    execution_allowed: bool = False
    approval_allowed: bool = False

    def to_text(self) -> str:
        lines = [
            "mythos agent next",
            f"status: {self.status}",
            f"campaign_id: {self.campaign_id or 'none'}",
            f"execution_allowed: {str(self.execution_allowed).lower()}",
            f"approval_allowed: {str(self.approval_allowed).lower()}",
            "recommended_actions:",
        ]
        if not self.actions:
            lines.append("- none")
        for action in self.actions:
            lines.append(
                "- "
                f"{action['action']}: "
                f"gate_ref={action.get('gate_ref', 'none')}; "
                f"reason={action.get('reason', 'none')}"
            )
        return "\n".join(lines)

    def to_dict(self) -> dict:
        return {
            "status": self.status,
            "campaign_id": self.campaign_id,
            "actions": self.actions,
            "execution_allowed": self.execution_allowed,
            "approval_allowed": self.approval_allowed,
        }


def run_agent_goal(goal: AgentGoal, *, repository: DatabaseRepository) -> AgentResult:
    repo_path = goal.repo_path.expanduser().resolve()
    scope_path = goal.scope_path.expanduser().resolve()
    steps: list[AgentStep] = []

    scope = evaluate_source_scope(repo_path, scope_path)
    if not scope.allowed:
        steps.append(AgentStep("scope_check", "blocked", [scope.reason]))
        return AgentResult(
            status="blocked",
            campaign_id=None,
            stop_reasons=[scope.reason],
            steps=steps,
            goal=goal.goal,
            repo_path=str(repo_path),
            scope_path=str(scope_path),
        )

    if goal.campaign_id is None:
        campaign_id = _create_agent_campaign(
            goal=goal,
            repo_path=repo_path,
            scope_path=scope_path,
            repository=repository,
        )
        steps.append(AgentStep("create_campaign", "running"))
    else:
        campaign_id = goal.campaign_id

    if goal.campaign_id is not None and repository.get_campaign(campaign_id) is None:
        steps.append(AgentStep("load_campaign", "blocked", ["campaign_not_found"]))
        return AgentResult(
            status="blocked",
            campaign_id=campaign_id,
            stop_reasons=["campaign_not_found"],
            steps=steps,
            goal=goal.goal,
            repo_path=str(repo_path),
            scope_path=str(scope_path),
        )

    for _ in range(max(goal.max_steps, 1)):
        tick_result = tick_campaign(
            campaign_id,
            repository=repository,
            dispatcher=lambda **kwargs: run_agent_task(
                kwargs["campaign_task_id"],
                repository=repository,
            ),
        )
        step = AgentStep(
            action=_agent_action_for_tick(tick_result),
            status=str(tick_result.get("status", "unknown")),
            stop_reasons=_string_list(tick_result.get("stop_reasons", [])),
            next_actions=_string_list(tick_result.get("next_actions", [])),
        )
        steps.append(step)
        if step.status == "awaiting_review":
            stop_reasons = _primary_stop_reasons(
                step.stop_reasons or ["campaign_cycle_review_required"]
            )
            return AgentResult(
                status="awaiting_human_review",
                campaign_id=campaign_id,
                stop_reasons=stop_reasons,
                next_actions=_next_actions_for_stop_reasons(stop_reasons, step.next_actions),
                steps=steps,
                goal=goal.goal,
                repo_path=str(repo_path),
                scope_path=str(scope_path),
            )
        if step.status in {"blocked", "paused"}:
            return AgentResult(
                status=step.status,
                campaign_id=campaign_id,
                stop_reasons=step.stop_reasons,
                steps=steps,
                goal=goal.goal,
                repo_path=str(repo_path),
                scope_path=str(scope_path),
            )

    return AgentResult(
        status="max_steps_reached",
        campaign_id=campaign_id,
        stop_reasons=["max_steps_reached"],
        steps=steps,
        goal=goal.goal,
        repo_path=str(repo_path),
        scope_path=str(scope_path),
    )


def get_agent_status(
    *,
    campaign_id: str | None,
    repository: DatabaseRepository,
    goal: str,
    repo_path: str,
    scope_path: str,
) -> AgentStatus:
    if campaign_id is None or repository.get_campaign(campaign_id) is None:
        return AgentStatus(
            status="blocked",
            campaign_id=campaign_id,
            goal=goal,
            repo_path=repo_path,
            scope_path=scope_path,
            pending_approval_count=0,
            awaiting_validation_count=0,
            next_actions=["start_agent"],
        )

    approvals = repository.list_campaign_approval_records(campaign_id)
    validation_runs = repository.list_campaign_validation_runs(campaign_id)
    pending_approval_count = sum(
        1 for approval in approvals if approval.status in {"pending", "requested"}
    )
    awaiting_validation_count = sum(
        1
        for run in validation_runs
        if run.approval_required and run.allowed_to_execute is False
    )
    next_actions = _status_next_actions(
        pending_approval_count=pending_approval_count,
        awaiting_validation_count=awaiting_validation_count,
    )
    return AgentStatus(
        status="awaiting_human_review" if next_actions else "ready",
        campaign_id=campaign_id,
        goal=goal,
        repo_path=repo_path,
        scope_path=scope_path,
        pending_approval_count=pending_approval_count,
        awaiting_validation_count=awaiting_validation_count,
        next_actions=next_actions,
    )


def get_agent_gates(
    *,
    campaign_id: str | None,
    repository: DatabaseRepository,
) -> AgentGates:
    if campaign_id is None or repository.get_campaign(campaign_id) is None:
        return AgentGates(campaign_id=campaign_id, approvals=[], validation_runs=[])

    review_notes = _gate_review_note_summaries(
        campaign_id=campaign_id,
        repository=repository,
    )
    approvals = [
        {
            "id": approval.id,
            "status": approval.status,
            "approval_type": approval.approval_type,
            "requested_action": approval.requested_action,
            "asset": approval.asset,
            "validation_mode": approval.validation_mode,
            "plan_digest": approval.plan_digest,
            "safety_gate_state": approval.safety_gate_state,
            **review_notes.get(
                f"approval:{approval.id}",
                {"review_note_count": 0, "latest_review_note": None},
            ),
        }
        for approval in repository.list_campaign_approval_records(campaign_id)
        if approval.status in {"pending", "requested"}
    ]
    validation_runs = [
        {
            "id": run.id,
            "status": run.status,
            "target_ref": run.target_ref,
            "validation_mode": run.validation_mode,
            "plan_digest": run.plan_digest,
            "approval_required": run.approval_required,
            "execution_allowed": run.allowed_to_execute,
            "safety_gate_state": run.safety_gate_state,
            **review_notes.get(
                f"validation_run:{run.id}",
                {"review_note_count": 0, "latest_review_note": None},
            ),
        }
        for run in repository.list_campaign_validation_runs(campaign_id)
        if run.approval_required and run.allowed_to_execute is False
    ]
    return AgentGates(
        campaign_id=campaign_id,
        approvals=approvals,
        validation_runs=validation_runs,
    )


def get_agent_next(
    *,
    campaign_id: str | None,
    repository: DatabaseRepository,
    goal: str,
    repo_path: str,
    scope_path: str,
) -> AgentNext:
    status = get_agent_status(
        campaign_id=campaign_id,
        repository=repository,
        goal=goal,
        repo_path=repo_path,
        scope_path=scope_path,
    )
    if campaign_id is None or status.status == "blocked":
        return AgentNext(
            status=status.status,
            campaign_id=campaign_id,
            actions=[
                {
                    "action": "start_agent",
                    "reason": "campaign_not_ready",
                }
            ],
        )

    gates = get_agent_gates(campaign_id=campaign_id, repository=repository)
    actions = _agent_next_actions(gates)
    return AgentNext(
        status=status.status,
        campaign_id=campaign_id,
        actions=actions,
    )


def record_agent_review_note(
    *,
    campaign_id: str | None,
    gate_ref: str,
    reviewer: str,
    decision: str,
    note: str,
    repository: DatabaseRepository,
) -> AgentReviewNote:
    if campaign_id is None or repository.get_campaign(campaign_id) is None:
        return AgentReviewNote(
            status="blocked",
            campaign_id=campaign_id,
            gate_ref=gate_ref,
            reviewer=reviewer,
            decision=decision,
            note=note,
            stop_reasons=["campaign_not_found"],
        )
    if not _gate_ref_exists(campaign_id=campaign_id, gate_ref=gate_ref, repository=repository):
        return AgentReviewNote(
            status="blocked",
            campaign_id=campaign_id,
            gate_ref=gate_ref,
            reviewer=reviewer,
            decision=decision,
            note=note,
            stop_reasons=["gate_not_found"],
        )

    stage = repository.save_pipeline_stage(
        pipeline_run_id=None,
        campaign_id=campaign_id,
        task_id=None,
        stage_key="agent_gate_review_note",
        stage_order=len(repository.list_campaign_pipeline_stages(campaign_id)),
        status="recorded",
        input_refs=[gate_ref],
        output_refs=[],
        safety_gate_state="human_review_recorded",
        stop_reason=None,
        payload={
            "reviewer": reviewer,
            "decision": decision,
            "note": note,
            "execution_allowed": False,
            "approval_allowed": False,
        },
    )
    return AgentReviewNote(
        status="recorded",
        campaign_id=campaign_id,
        gate_ref=gate_ref,
        reviewer=reviewer,
        decision=decision,
        note=note,
        stage_id=stage.id,
    )


def _create_agent_campaign(
    *,
    goal: AgentGoal,
    repo_path: Path,
    scope_path: Path,
    repository: DatabaseRepository,
) -> str:
    policy_text = _read_text(scope_path)
    campaign = repository.create_campaign(
        program_id=None,
        name=f"Mythos agent: {goal.goal[:80]}",
        autonomy_level="level_0_read_only",
        scope_status="in_scope",
        policy_text=policy_text,
        default_asset=str(repo_path),
        target_classes=["local_code"],
        allowed_tools=[
            "static_code_map",
            "hypothesis_generation",
            "report_chain_review",
        ],
        created_by="mythos_agent",
        payload={
            "goal": goal.goal,
            "repo_path": str(repo_path),
            "scope_path": str(scope_path),
            "authorized_code_files": collect_authorized_code_files(repo_path),
            "execution_allowed": False,
        },
    )
    repository.update_campaign_status(campaign.id, "running")
    return campaign.id


def _agent_action_for_tick(tick_result: dict[str, Any]) -> str:
    if tick_result.get("status") == "awaiting_review":
        return "review_gate"
    return "campaign_tick"


def _read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8-sig")
    except OSError:
        return "source scope policy unavailable"


def _string_list(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, str)]


def _primary_stop_reasons(stop_reasons: list[str]) -> list[str]:
    if "validation_approval_required" in stop_reasons:
        return ["validation_approval_required"]
    if "approval_required" in stop_reasons:
        return ["approval_required"]
    return stop_reasons


def _next_actions_for_stop_reasons(
    stop_reasons: list[str],
    fallback: list[str],
) -> list[str]:
    if "validation_approval_required" in stop_reasons:
        return ["review_validation_queue"]
    if "approval_required" in stop_reasons:
        return ["review_approval_queue"]
    return fallback


def _status_next_actions(
    *,
    pending_approval_count: int,
    awaiting_validation_count: int,
) -> list[str]:
    if awaiting_validation_count:
        return ["review_validation_queue"]
    if pending_approval_count:
        return ["review_approval_queue"]
    return []


def _gate_ref_exists(
    *,
    campaign_id: str,
    gate_ref: str,
    repository: DatabaseRepository,
) -> bool:
    if gate_ref.startswith("approval:"):
        approval_id = gate_ref.removeprefix("approval:")
        return any(
            approval.id == approval_id
            for approval in repository.list_campaign_approval_records(campaign_id)
        )
    if gate_ref.startswith("validation_run:"):
        validation_run_id = gate_ref.removeprefix("validation_run:")
        return any(
            run.id == validation_run_id
            for run in repository.list_campaign_validation_runs(campaign_id)
        )
    return False


def _gate_review_note_summaries(
    *,
    campaign_id: str,
    repository: DatabaseRepository,
) -> dict[str, dict]:
    summaries: dict[str, dict] = {}
    for stage in repository.list_campaign_pipeline_stages(campaign_id):
        if stage.stage_key != "agent_gate_review_note":
            continue
        if not stage.input_refs:
            continue
        gate_ref = stage.input_refs[0]
        payload = stage.payload if isinstance(stage.payload, dict) else {}
        summary = summaries.setdefault(
            gate_ref,
            {"review_note_count": 0, "latest_review_note": None},
        )
        summary["review_note_count"] += 1
        summary["latest_review_note"] = {
            "stage_id": stage.id,
            "reviewer": payload.get("reviewer", "unknown"),
            "decision": payload.get("decision", "unknown"),
        }
    return summaries


def _agent_next_actions(gates: AgentGates) -> list[dict]:
    if not gates.approvals and not gates.validation_runs:
        return [{"action": "continue_agent", "reason": "no_open_gates"}]

    actions = [{"action": "inspect_gates", "reason": "human_review_required"}]
    for gate in [*gates.approvals, *gates.validation_runs]:
        gate_ref = _gate_ref_for_gate(gate)
        if gate.get("review_note_count", 0) == 0:
            actions.append(
                {
                    "action": "write_review_note",
                    "gate_ref": gate_ref,
                    "reason": "gate_has_no_review_note",
                }
            )
            return actions
        latest_note = gate.get("latest_review_note") or {}
        latest_decision = latest_note.get("decision")
        if latest_decision == "needs_evidence":
            actions.append(
                {
                    "action": "collect_redacted_evidence",
                    "gate_ref": gate_ref,
                    "reason": "latest_review_decision_needs_evidence",
                }
            )
            return actions
    actions.append({"action": "continue_human_review", "reason": "review_notes_recorded"})
    return actions


def _gate_ref_for_gate(gate: dict) -> str:
    gate_id = str(gate.get("id", ""))
    if gate_id.startswith("approval_"):
        return f"approval:{gate_id}"
    if gate_id.startswith("validation_run_"):
        return f"validation_run:{gate_id}"
    return gate_id
