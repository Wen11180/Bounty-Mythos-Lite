from collections.abc import Iterable
from typing import Any

from pydantic import BaseModel


class SecurityInvariant(BaseModel):
    rule_id: str
    invariant: str
    objects: list[str]
    actions: list[str]
    risk_level: str
    policy_risk: str


class VulnerabilityHypothesis(BaseModel):
    hypothesis: str
    vuln_type: str
    broken_invariant: str
    evidence_needed: list[str]
    validation_mode: str
    risk_level: str
    policy_risk: str


_RULES = [
    {
        "rule_id": "private_file_access_control",
        "objects": {"file", "document", "doc", "attachment"},
        "actions": {"read", "download", "export", "share"},
        "invariant": "用户不能访问其他用户私有文件",
        "risk_level": "high",
        "policy_risk": "low",
        "hypothesis": "修改文件标识符或所有者上下文可能读取、导出或分享其他用户的私有文件。",
        "vuln_type": "broken_access_control",
        "evidence_needed": [
            "两个低权限测试账户",
            "一个账户创建的私有文件标识符",
            "另一个账户访问同一文件的授权结果",
        ],
        "validation_mode": "two_account_authorization_check",
    },
    {
        "rule_id": "member_admin_boundary",
        "objects": {"org", "organization", "team", "workspace", "member", "role"},
        "actions": {"invite", "settings", "delete", "remove", "update"},
        "invariant": "普通成员不能修改管理员级设置",
        "risk_level": "high",
        "policy_risk": "low",
        "hypothesis": "普通成员可能通过邀请、设置或删除类接口执行管理员级团队/组织操作。",
        "vuln_type": "privilege_escalation",
        "evidence_needed": [
            "普通成员账户",
            "管理员级设置或成员管理接口",
            "请求被拒绝或被错误接受的响应记录",
        ],
        "validation_mode": "role_based_authorization_check",
    },
    {
        "rule_id": "server_authoritative_money_flow",
        "objects": {"invoice", "refund", "payment", "charge", "checkout"},
        "actions": {"invoice", "refund", "payment", "pay", "checkout"},
        "invariant": "金额/退款不能由客户端越权控制",
        "risk_level": "critical",
        "policy_risk": "medium",
        "hypothesis": "客户端请求中的金额、币种或退款参数可能被服务端信任，导致越权改价或退款。",
        "vuln_type": "business_logic_authorization",
        "evidence_needed": [
            "客户端提交的金额或退款参数",
            "服务端重新计算金额的证据",
            "不执行真实付款/退款的请求审查记录",
        ],
        "validation_mode": "non_destructive_request_review",
    },
]


def generate_invariants(target_model_like: dict[str, Any]) -> list[SecurityInvariant]:
    facts = _extract_object_action_facts(target_model_like)
    invariants: list[SecurityInvariant] = []

    for rule in _RULES:
        matching_objects: list[str] = []
        matching_actions: list[str] = []

        for object_name, actions in facts:
            object_matches = _matches(object_name, rule["objects"])
            matched_actions = [
                action for action in actions if _matches(action, rule["actions"])
            ]
            if object_matches and matched_actions:
                _append_unique(matching_objects, object_name)
                for action in matched_actions:
                    _append_unique(matching_actions, action)

        if matching_objects:
            invariants.append(
                SecurityInvariant(
                    rule_id=rule["rule_id"],
                    invariant=rule["invariant"],
                    objects=matching_objects,
                    actions=matching_actions,
                    risk_level=rule["risk_level"],
                    policy_risk=rule["policy_risk"],
                )
            )

    return invariants


def generate_hypotheses(
    invariants: Iterable[SecurityInvariant],
) -> list[VulnerabilityHypothesis]:
    hypotheses: list[VulnerabilityHypothesis] = []

    for invariant in invariants:
        rule = _rule_by_id(invariant.rule_id)
        if rule is None:
            continue
        hypotheses.append(
            VulnerabilityHypothesis(
                hypothesis=rule["hypothesis"],
                vuln_type=rule["vuln_type"],
                broken_invariant=invariant.invariant,
                evidence_needed=rule["evidence_needed"],
                validation_mode=rule["validation_mode"],
                risk_level=invariant.risk_level,
                policy_risk=invariant.policy_risk,
            )
        )

    return hypotheses


def _extract_object_action_facts(
    target_model_like: dict[str, Any],
) -> list[tuple[str, list[str]]]:
    objects = target_model_like.get("objects", [])
    sensitive_actions = _extract_sensitive_actions(
        target_model_like.get("sensitive_actions", [])
    )
    if isinstance(objects, dict):
        objects = [
            {"name": object_name, "actions": actions}
            for object_name, actions in objects.items()
        ]

    facts: list[tuple[str, list[str]]] = []
    for item in objects:
        if not isinstance(item, dict):
            continue
        object_name = _clean_term(item.get("name") or item.get("type") or "")
        actions = [_clean_term(action) for action in _as_list(item.get("actions", []))]
        if not actions and sensitive_actions:
            actions = [
                action
                for action, path, _refs in sensitive_actions
                if path and object_name in _clean_term(path)
            ]
        if not actions and sensitive_actions:
            object_refs = _provenance_refs(item)
            if object_refs:
                actions = [
                    action
                    for action, _path, action_refs in sensitive_actions
                    if object_refs & action_refs
                ]
        if not actions and sensitive_actions:
            actions = [action for action, path, _refs in sensitive_actions if not path]
        actions = [action for action in actions if action]
        if object_name and actions:
            facts.append((object_name, actions))

    return facts


def _extract_sensitive_actions(value: Any) -> list[tuple[str, str, set[str]]]:
    actions: list[tuple[str, str, set[str]]] = []
    for item in _as_list(value):
        if isinstance(item, dict):
            action = _clean_term(item.get("action") or item.get("name") or "")
            path = _clean_term(item.get("path") or "")
            refs = _provenance_refs(item)
        else:
            action = _clean_term(item)
            path = ""
            refs = set()
        if action:
            actions.append((action, path, refs))
    return actions


def _provenance_refs(item: dict[str, Any]) -> set[str]:
    refs = {str(ref) for ref in _as_list(item.get("provenance_refs", [])) if ref}
    for edge in _as_list(item.get("provenance_edges", [])):
        if isinstance(edge, dict) and edge.get("ref"):
            refs.add(str(edge["ref"]))
    return refs


def _rule_by_id(rule_id: str) -> dict[str, Any] | None:
    for rule in _RULES:
        if rule["rule_id"] == rule_id:
            return rule
    return None


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, (tuple, set)):
        return list(value)
    return [value]


def _clean_term(value: Any) -> str:
    return str(value).strip().lower().replace(" ", "_").replace("-", "_")


def _matches(value: str, terms: set[str]) -> bool:
    return any(term == value or term in value for term in terms)


def _append_unique(values: list[str], value: str) -> None:
    if value not in values:
        values.append(value)


__all__ = [
    "SecurityInvariant",
    "VulnerabilityHypothesis",
    "generate_hypotheses",
    "generate_invariants",
]
