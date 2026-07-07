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
            lines.append(
                "- "
                f"id: {approval['id']}; "
                f"status: {approval['status']}; "
                f"validation_mode: {approval['validation_mode']}; "
                f"plan_digest: {approval['plan_digest']}"
            )
        lines.append("validation_runs:")
        if not self.validation_runs:
            lines.append("- none")
        for run in self.validation_runs:
            lines.append(
                "- "
                f"id: {run['id']}; "
                f"status: {run['status']}; "
                f"target_ref: {run['target_ref']}; "
                f"plan_digest: {run['plan_digest']}; "
                f"execution_allowed: {str(run['execution_allowed']).lower()}"
            )
        return "\n".join(lines)

    def to_dict(self) -> dict:
        return {
            "campaign_id": self.campaign_id,
            "approvals": self.approvals,
            "validation_runs": self.validation_runs,
            "execution_allowed": self.execution_allowed,
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
        }
        for run in repository.list_campaign_validation_runs(campaign_id)
        if run.approval_required and run.allowed_to_execute is False
    ]
    return AgentGates(
        campaign_id=campaign_id,
        approvals=approvals,
        validation_runs=validation_runs,
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
