from typing import Any, Literal

from pydantic import BaseModel, Field

from app.models import Program


LearningOutcome = Literal["accepted", "duplicate", "informative", "na", "rejected"]
LearningSeverityDelta = Literal["up", "down", "same"]
LearningEvidenceQuality = Literal["strong", "adequate", "weak"]


class LearningSignal(BaseModel):
    id: str | None = None
    program_id: str
    playbook_id: str
    outcome: LearningOutcome
    surface_key: str | None = None
    notes: str = Field(default="", max_length=1000)
    bounty_amount: int | None = Field(default=None, ge=0)
    severity_delta: LearningSeverityDelta | None = None
    evidence_quality: LearningEvidenceQuality | None = None
    triager_feedback: str | None = Field(default=None, max_length=1000)
    target_relationships: list[str] = Field(default_factory=list)
    created_at: str | None = None


class AttackSurfaceAction(BaseModel):
    action: str
    method: str
    path: str
    roles: list[str] = Field(default_factory=list)
    operation_id: str | None = None


class AttackSurfaceRelationship(BaseModel):
    parent_object: str
    child_object: str
    relationship: str = "contains"
    paths: list[str] = Field(default_factory=list)


class AttackSurfaceMemory(BaseModel):
    objects: list[str] = Field(default_factory=list)
    roles: list[str] = Field(default_factory=list)
    sensitive_actions: list[AttackSurfaceAction] = Field(default_factory=list)
    relationships: list[AttackSurfaceRelationship] = Field(default_factory=list)
    run_count: int = 0


class HighValueSurface(BaseModel):
    surface_key: str
    object_name: str
    action: str
    score: int = Field(ge=0, le=100)
    paths: list[str] = Field(default_factory=list)
    playbooks: list[str] = Field(default_factory=list)
    reasons: list[str] = Field(default_factory=list)


class LearningSummary(BaseModel):
    accepted_count: int = 0
    duplicate_count: int = 0
    informative_count: int = 0
    na_count: int = 0
    rejected_count: int = 0
    rejection_risk_delta: int = 0
    bounty_total: int = 0
    strong_evidence_count: int = 0
    adequate_evidence_count: int = 0
    weak_evidence_count: int = 0
    severity_up_count: int = 0
    severity_down_count: int = 0
    triager_feedback_count: int = 0
    evidence_score_delta: int = 0
    boosted_playbooks: list[str] = Field(default_factory=list)
    penalized_playbooks: list[str] = Field(default_factory=list)


class ProgramIntelligenceProfile(BaseModel):
    program_id: str
    program_name: str
    program_score: int = Field(ge=0, le=100)
    attack_surface_memory: AttackSurfaceMemory
    high_value_surfaces: list[HighValueSurface] = Field(default_factory=list)
    learning_summary: LearningSummary
    recent_learning_signals: list[LearningSignal] = Field(default_factory=list)
    safety_notes: list[str]


def build_program_intelligence(
    *,
    program: Program,
    pipeline_runs: list[dict[str, Any]],
    learning_signals: list[LearningSignal],
) -> ProgramIntelligenceProfile:
    memory = _build_attack_surface_memory(pipeline_runs)
    learning_summary = _summarize_learning(learning_signals)
    high_value_surfaces = _rank_surfaces(
        memory=memory,
        pipeline_runs=pipeline_runs,
        learning_signals=learning_signals,
        program=program,
    )
    return ProgramIntelligenceProfile(
        program_id=program.id,
        program_name=program.name,
        program_score=_program_score(program, memory, learning_summary),
        attack_surface_memory=memory,
        high_value_surfaces=high_value_surfaces,
        learning_summary=learning_summary,
        recent_learning_signals=learning_signals[:5],
        safety_notes=[
            "no_live_requests",
            "test_accounts_only",
            "human_review_required",
            "no_real_user_data",
            "advisory_memory_only",
        ],
    )


def build_learning_signal_from_outcome(
    *,
    program_id: str,
    outcome: LearningOutcome,
    notes: str = "",
    pipeline_run: dict[str, Any] | None = None,
    playbook_id: str | None = None,
    surface_key: str | None = None,
    bounty_amount: int | None = None,
    severity_delta: LearningSeverityDelta | None = None,
    evidence_quality: LearningEvidenceQuality | None = None,
    triager_feedback: str | None = None,
    target_relationships: list[str] | None = None,
) -> LearningSignal:
    run = pipeline_run or {}
    signal_surface_key = surface_key or _first_surface_key(run)
    return LearningSignal(
        program_id=program_id,
        playbook_id=playbook_id or _first_playbook_id(run) or "unknown_playbook",
        outcome=outcome,
        surface_key=signal_surface_key,
        notes=notes,
        bounty_amount=bounty_amount,
        severity_delta=severity_delta,
        evidence_quality=evidence_quality,
        triager_feedback=triager_feedback,
        target_relationships=(
            target_relationships
            if target_relationships is not None
            else _surface_target_relationships(run, signal_surface_key)
        ),
    )


def _build_attack_surface_memory(pipeline_runs: list[dict[str, Any]]) -> AttackSurfaceMemory:
    objects: set[str] = set()
    roles: set[str] = set()
    action_keys: set[tuple[str, str, str, str | None]] = set()
    actions: list[AttackSurfaceAction] = []
    relationship_paths: dict[tuple[str, str, str], set[str]] = {}

    for run in pipeline_runs:
        target_model = _target_model_from_run(run)
        for item in target_model.get("objects", []):
            name = _object_name(item)
            if name:
                objects.add(name)
        for role in target_model.get("roles", []):
            if isinstance(role, str) and role:
                roles.add(role)
        for item in target_model.get("sensitive_actions", []):
            action = _action_from_item(item)
            if action is None:
                continue
            roles.update(action.roles)
            key = (action.action, action.method, action.path, action.operation_id)
            if key not in action_keys:
                action_keys.add(key)
                actions.append(action)
        for relationship in _relationships_from_target_model(target_model):
            key = (
                relationship.parent_object,
                relationship.child_object,
                relationship.relationship,
            )
            relationship_paths.setdefault(key, set()).update(relationship.paths)

    return AttackSurfaceMemory(
        objects=sorted(objects),
        roles=sorted(roles),
        sensitive_actions=actions,
        relationships=[
            AttackSurfaceRelationship(
                parent_object=parent_object,
                child_object=child_object,
                relationship=relationship,
                paths=sorted(paths),
            )
            for parent_object, child_object, relationship in sorted(relationship_paths)
            for paths in [relationship_paths[(parent_object, child_object, relationship)]]
        ],
        run_count=len(pipeline_runs),
    )


def _rank_surfaces(
    *,
    memory: AttackSurfaceMemory,
    pipeline_runs: list[dict[str, Any]],
    learning_signals: list[LearningSignal],
    program: Program,
) -> list[HighValueSurface]:
    surfaces: dict[str, dict[str, Any]] = {}
    playbook_scores = _playbook_scores(pipeline_runs)
    signal_index = _signals_by_surface(learning_signals)
    relationship_context_by_object = _relationship_context_by_object(memory.relationships)

    for action in memory.sensitive_actions:
        related_objects = [
            object_name for object_name in memory.objects if f"{{{object_name}}}" in action.path
        ] or memory.objects or ["unknown_object"]
        for object_name in related_objects:
            surface_key = f"{object_name}:{action.action}"
            surface = surfaces.setdefault(
                surface_key,
                {
                    "object_name": object_name,
                    "action": action.action,
                    "paths": set(),
                    "playbooks": set(),
                    "base": 45,
                    "relationship_bonus": 0,
                    "reasons": set(),
                },
            )
            surface["paths"].add(action.path)
            surface["base"] += _action_weight(action.action)
            surface["reasons"].add(f"action:{action.action}")
            relationship_context = relationship_context_by_object.get(object_name, [])
            surface["relationship_bonus"] = max(
                surface["relationship_bonus"],
                _relationship_context_bonus(relationship_context),
            )
            for context in relationship_context:
                surface["reasons"].add(f"target_relationship:{context}")
            for playbook_id, playbook_score in playbook_scores.items():
                surface["playbooks"].add(playbook_id)
                surface["base"] += min(playbook_score, 80) * 0.2
                surface["reasons"].add(f"playbook:{playbook_id}")

    ranked: list[HighValueSurface] = []
    for surface_key, data in surfaces.items():
        score = data["base"] + data["relationship_bonus"] + _program_priority_bonus(program)
        reasons = set(data["reasons"])
        for signal in signal_index.get(surface_key, []):
            delta, signal_reasons = _learning_delta(signal)
            score += delta
            reasons.update(signal_reasons)

        ranked.append(
            HighValueSurface(
                surface_key=surface_key,
                object_name=str(data["object_name"]),
                action=str(data["action"]),
                score=_bounded_score(score),
                paths=sorted(data["paths"]),
                playbooks=sorted(data["playbooks"]),
                reasons=sorted(reasons),
            )
        )

    return sorted(ranked, key=lambda item: (-item.score, item.surface_key))


def _summarize_learning(learning_signals: list[LearningSignal]) -> LearningSummary:
    accepted = [signal for signal in learning_signals if signal.outcome == "accepted"]
    duplicates = [signal for signal in learning_signals if signal.outcome == "duplicate"]
    informative = [signal for signal in learning_signals if signal.outcome == "informative"]
    na = [signal for signal in learning_signals if signal.outcome == "na"]
    rejected = [signal for signal in learning_signals if signal.outcome == "rejected"]
    penalized = duplicates + na + rejected
    bounty_total = sum(signal.bounty_amount or 0 for signal in accepted)

    return LearningSummary(
        accepted_count=len(accepted),
        duplicate_count=len(duplicates),
        informative_count=len(informative),
        na_count=len(na),
        rejected_count=len(rejected),
        rejection_risk_delta=len(duplicates) * 12 + len(na) * 12 + len(rejected) * 10,
        bounty_total=bounty_total,
        strong_evidence_count=sum(
            1 for signal in learning_signals if signal.evidence_quality == "strong"
        ),
        adequate_evidence_count=sum(
            1 for signal in learning_signals if signal.evidence_quality == "adequate"
        ),
        weak_evidence_count=sum(
            1 for signal in learning_signals if signal.evidence_quality == "weak"
        ),
        severity_up_count=sum(1 for signal in learning_signals if signal.severity_delta == "up"),
        severity_down_count=sum(
            1 for signal in learning_signals if signal.severity_delta == "down"
        ),
        triager_feedback_count=sum(
            1 for signal in learning_signals if signal.triager_feedback
        ),
        evidence_score_delta=_evidence_summary_delta(learning_signals),
        boosted_playbooks=sorted(
            {
                signal.playbook_id
                for signal in accepted
                if signal.evidence_quality != "weak"
            }
        ),
        penalized_playbooks=sorted({signal.playbook_id for signal in penalized}),
    )


def _program_score(
    program: Program,
    memory: AttackSurfaceMemory,
    learning_summary: LearningSummary,
) -> int:
    score = 50
    score += _program_priority_bonus(program)
    if program.testing_accounts == "configured":
        score += 8
    if program.api_docs in {"imported", "available"}:
        score += 8
    score += min(len(memory.sensitive_actions) * 6, 12)
    score += min(learning_summary.accepted_count * 10, 20)
    score += learning_summary.evidence_score_delta
    score -= round(learning_summary.rejection_risk_delta * 0.5)
    return _bounded_score(score)


def _first_playbook_id(pipeline_run: dict[str, Any]) -> str | None:
    payload = pipeline_run.get("payload", {})
    if not isinstance(payload, dict):
        return None
    intelligence = payload.get("hunter_intelligence", {})
    if not isinstance(intelligence, dict):
        return None
    assessments = intelligence.get("assessments", [])
    if not isinstance(assessments, list):
        return None
    for assessment in assessments:
        if isinstance(assessment, dict) and isinstance(assessment.get("playbook_id"), str):
            return assessment["playbook_id"]
    return None


def _first_surface_key(pipeline_run: dict[str, Any]) -> str | None:
    target_model = _target_model_from_run(pipeline_run)
    objects = [_object_name(item) for item in target_model.get("objects", [])]
    object_names = [name for name in objects if name]
    relationship_context_by_object = _relationship_context_by_object(
        _relationships_from_target_model(target_model)
    )
    for item in target_model.get("sensitive_actions", []):
        action = _action_from_item(item)
        if action is None:
            continue
        path_objects = [
            name for name in object_names if f"{{{name}}}" in action.path
        ]
        object_name = (
            _preferred_surface_object(path_objects, relationship_context_by_object)
            or (object_names[0] if object_names else None)
        )
        if object_name:
            return f"{object_name}:{action.action}"
    return None


def _surface_target_relationships(
    pipeline_run: dict[str, Any],
    surface_key: str | None,
) -> list[str]:
    if surface_key is None or ":" not in surface_key:
        return []
    object_name = surface_key.split(":", 1)[0]
    target_model = _target_model_from_run(pipeline_run)
    relationship_context_by_object = _relationship_context_by_object(
        _relationships_from_target_model(target_model)
    )
    return relationship_context_by_object.get(object_name, [])


def _target_model_from_run(run: dict[str, Any]) -> dict[str, Any]:
    payload = run.get("payload", {})
    if not isinstance(payload, dict):
        return {}
    target_model = payload.get("target_model", {})
    return target_model if isinstance(target_model, dict) else {}


def _object_name(item: Any) -> str | None:
    if isinstance(item, dict):
        name = item.get("name")
        return name if isinstance(name, str) and name else None
    return item if isinstance(item, str) and item else None


def _action_from_item(item: Any) -> AttackSurfaceAction | None:
    if not isinstance(item, dict):
        return None
    action = item.get("action")
    method = item.get("method")
    path = item.get("path")
    if not isinstance(action, str) or not isinstance(method, str) or not isinstance(path, str):
        return None
    roles = [role for role in item.get("roles", []) if isinstance(role, str)]
    operation_id = item.get("operation_id")
    return AttackSurfaceAction(
        action=action,
        method=method,
        path=path,
        roles=sorted(set(roles)),
        operation_id=operation_id if isinstance(operation_id, str) else None,
    )


def _relationships_from_target_model(
    target_model: dict[str, Any],
) -> list[AttackSurfaceRelationship]:
    relationships: list[AttackSurfaceRelationship] = []
    seen: set[tuple[str, str, str, str]] = set()
    for item in target_model.get("relationships", []):
        if not isinstance(item, dict):
            continue
        parent_object = item.get("parent_object")
        child_object = item.get("child_object")
        relationship = str(item.get("relationship", "contains"))
        path = item.get("path")
        if not isinstance(parent_object, str) or not parent_object:
            continue
        if not isinstance(child_object, str) or not child_object:
            continue
        path_value = path if isinstance(path, str) and path else ""
        key = (parent_object, child_object, relationship, path_value)
        if key in seen:
            continue
        seen.add(key)
        relationships.append(
            AttackSurfaceRelationship(
                parent_object=parent_object,
                child_object=child_object,
                relationship=relationship,
                paths=[path_value] if path_value else [],
            )
        )
    return relationships


def _relationship_context_by_object(
    relationships: list[AttackSurfaceRelationship],
) -> dict[str, list[str]]:
    children_by_parent: dict[str, list[str]] = {}
    parents: set[str] = set()
    children: set[str] = set()
    for relationship in relationships:
        if relationship.relationship != "contains":
            continue
        parent = relationship.parent_object
        child = relationship.child_object
        if child not in children_by_parent.setdefault(parent, []):
            children_by_parent[parent].append(child)
        parents.add(parent)
        children.add(child)

    roots = sorted(parents - children) or sorted(parents)
    context_by_object: dict[str, list[str]] = {}
    for root in roots:
        for path in _relationship_paths(root, children_by_parent, []):
            for index, object_name in enumerate(path):
                if index == 0:
                    continue
                context = ">".join(path[: index + 1])
                context_by_object.setdefault(object_name, [])
                if context not in context_by_object[object_name]:
                    context_by_object[object_name].append(context)
    return context_by_object


def _relationship_paths(
    node: str,
    children_by_parent: dict[str, list[str]],
    path: list[str],
) -> list[list[str]]:
    if node in path:
        return [path]

    next_path = [*path, node]
    children = children_by_parent.get(node, [])
    if not children:
        return [next_path]

    paths: list[list[str]] = []
    for child in sorted(children):
        paths.extend(_relationship_paths(child, children_by_parent, next_path))
    return paths


def _preferred_surface_object(
    object_names: list[str],
    relationship_context_by_object: dict[str, list[str]],
) -> str | None:
    if not object_names:
        return None
    return sorted(
        object_names,
        key=lambda name: (
            -_relationship_context_depth(relationship_context_by_object.get(name, [])),
            name,
        ),
    )[0]


def _relationship_context_bonus(relationship_context: list[str]) -> int:
    return min(12, _relationship_context_depth(relationship_context) * 4)


def _relationship_context_depth(relationship_context: list[str]) -> int:
    if not relationship_context:
        return 0
    return max(len(context.split(">")) - 1 for context in relationship_context)


def _playbook_scores(pipeline_runs: list[dict[str, Any]]) -> dict[str, int]:
    scores: dict[str, int] = {}
    for run in pipeline_runs:
        payload = run.get("payload", {})
        if not isinstance(payload, dict):
            continue
        intelligence = payload.get("hunter_intelligence", {})
        if not isinstance(intelligence, dict):
            continue
        assessments = intelligence.get("assessments", [])
        if not isinstance(assessments, list):
            continue
        for assessment in assessments:
            if not isinstance(assessment, dict):
                continue
            playbook_id = assessment.get("playbook_id")
            score = assessment.get("hunter_priority_score")
            if isinstance(playbook_id, str) and isinstance(score, int):
                scores[playbook_id] = max(scores.get(playbook_id, 0), score)
    return scores


def _signals_by_surface(
    learning_signals: list[LearningSignal],
) -> dict[str, list[LearningSignal]]:
    grouped: dict[str, list[LearningSignal]] = {}
    for signal in learning_signals:
        if signal.surface_key:
            grouped.setdefault(signal.surface_key, []).append(signal)
    return grouped


def _learning_delta(signal: LearningSignal) -> tuple[int, list[str]]:
    reasons: list[str]
    if signal.outcome == "accepted":
        if signal.evidence_quality == "weak":
            delta = 0
            reasons = ["learning:weak_accepted_evidence_not_boosted"]
        else:
            delta = 18
            reasons = ["learning:accepted"]
    elif signal.outcome == "duplicate":
        delta = -14
        reasons = ["learning:duplicate_or_na"]
    elif signal.outcome == "na":
        delta = -12
        reasons = ["learning:duplicate_or_na"]
    elif signal.outcome == "rejected":
        delta = -10
        reasons = ["learning:rejected"]
    elif signal.outcome == "informative":
        delta = -5
        reasons = ["learning:informative"]
    else:
        delta = 0
        reasons = ["learning:neutral"]

    evidence_delta, evidence_reasons = _evidence_signal_delta(signal)
    return delta + evidence_delta, reasons + evidence_reasons


def _evidence_summary_delta(learning_signals: list[LearningSignal]) -> int:
    return max(
        -12,
        min(
            12,
            sum(_evidence_signal_delta(signal)[0] for signal in learning_signals),
        ),
    )


def _evidence_signal_delta(signal: LearningSignal) -> tuple[int, list[str]]:
    delta = 0
    reasons: list[str] = []

    if signal.bounty_amount and signal.bounty_amount > 0 and signal.outcome == "accepted":
        delta += min(8, 3 + signal.bounty_amount // 1000)
        reasons.append("learning:bounty_paid")

    if signal.evidence_quality == "strong":
        delta += 5
        reasons.append("learning:strong_evidence")
    elif signal.evidence_quality == "adequate":
        delta += 2
        reasons.append("learning:adequate_evidence")
    elif signal.evidence_quality == "weak":
        delta -= 6
        reasons.append("learning:weak_evidence")

    if signal.severity_delta == "up":
        delta += 4
        reasons.append("learning:severity_up")
    elif signal.severity_delta == "down":
        delta -= 4
        reasons.append("learning:severity_down")

    if signal.triager_feedback:
        reasons.append("learning:triager_feedback")

    return max(-10, min(14, delta)), reasons


def _action_weight(action: str) -> int:
    return {
        "refund": 18,
        "export": 16,
        "delete": 14,
        "share": 12,
        "write": 10,
        "read": 6,
    }.get(action, 8)


def _program_priority_bonus(program: Program) -> int:
    return {
        "A": 8,
        "B": 4,
        "C": 2,
    }.get(program.priority.upper(), 0)


def _bounded_score(value: float) -> int:
    return max(0, min(100, round(value)))


__all__ = [
    "AttackSurfaceAction",
    "AttackSurfaceMemory",
    "AttackSurfaceRelationship",
    "HighValueSurface",
    "LearningSignal",
    "LearningSeverityDelta",
    "LearningEvidenceQuality",
    "LearningSummary",
    "ProgramIntelligenceProfile",
    "build_learning_signal_from_outcome",
    "build_program_intelligence",
]
