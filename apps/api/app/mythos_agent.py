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


@dataclass(frozen=True)
class AgentResult:
    status: str
    campaign_id: str | None
    stop_reasons: list[str]
    steps: list[AgentStep]
    execution_allowed: bool = False

    def to_text(self) -> str:
        lines = [
            "mythos agent",
            f"status: {self.status}",
            f"campaign_id: {self.campaign_id or 'none'}",
            f"stop_reasons: {', '.join(self.stop_reasons) if self.stop_reasons else 'none'}",
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
            return AgentResult(
                status="awaiting_human_review",
                campaign_id=campaign_id,
                stop_reasons=_primary_stop_reasons(
                    step.stop_reasons or ["campaign_cycle_review_required"]
                ),
                steps=steps,
            )
        if step.status in {"blocked", "paused"}:
            return AgentResult(
                status=step.status,
                campaign_id=campaign_id,
                stop_reasons=step.stop_reasons,
                steps=steps,
            )

    return AgentResult(
        status="max_steps_reached",
        campaign_id=campaign_id,
        stop_reasons=["max_steps_reached"],
        steps=steps,
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
