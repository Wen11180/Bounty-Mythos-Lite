from app.mythos_hypothesis import (
    SecurityInvariant,
    VulnerabilityHypothesis,
    generate_hypotheses,
    generate_invariants,
)


def test_generates_core_security_invariants_from_objects_and_actions():
    target_model = {
        "objects": [
            {"name": "file", "actions": ["read", "export", "share"]},
            {"name": "team", "actions": ["invite", "settings", "delete"]},
            {"name": "invoice", "actions": ["payment", "refund"]},
            {"name": "profile", "actions": ["view"]},
        ],
    }

    invariants = generate_invariants(target_model)

    assert all(isinstance(invariant, SecurityInvariant) for invariant in invariants)
    assert [invariant.invariant for invariant in invariants] == [
        "用户不能访问其他用户私有文件",
        "普通成员不能修改管理员级设置",
        "金额/退款不能由客户端越权控制",
    ]
    assert [invariant.rule_id for invariant in invariants] == [
        "private_file_access_control",
        "member_admin_boundary",
        "server_authoritative_money_flow",
    ]


def test_invariant_generation_deduplicates_rule_families_to_avoid_noise():
    target_model = {
        "objects": [
            {"name": "file", "actions": ["read"]},
            {"name": "document", "actions": ["export", "share"]},
            {"name": "organization", "actions": ["settings"]},
            {"name": "org", "actions": ["delete"]},
        ],
    }

    invariants = generate_invariants(target_model)

    assert [invariant.rule_id for invariant in invariants] == [
        "private_file_access_control",
        "member_admin_boundary",
    ]
    assert invariants[0].objects == ["file", "document"]
    assert invariants[0].actions == ["read", "export", "share"]


def test_generates_invariants_from_target_model_objects_and_sensitive_actions():
    target_model = {
        "objects": [
            {"name": "file_id"},
            {"name": "team_id"},
            {"name": "invoice_id"},
        ],
        "sensitive_actions": [
            {"action": "export", "path": "/files/{file_id}/export"},
            {"action": "invite", "path": "/teams/{team_id}/invite"},
            {"action": "refund", "path": "/invoices/{invoice_id}/refund"},
        ],
    }

    invariants = generate_invariants(target_model)

    assert [invariant.rule_id for invariant in invariants] == [
        "private_file_access_control",
        "member_admin_boundary",
        "server_authoritative_money_flow",
    ]
    assert invariants[0].objects == ["file_id"]
    assert invariants[0].actions == ["export"]


def test_generates_required_high_value_hypothesis_fields_from_invariants():
    invariants = generate_invariants(
        {
            "objects": [
                {"name": "file", "actions": ["read"]},
                {"name": "invoice", "actions": ["refund"]},
            ],
        }
    )

    hypotheses = generate_hypotheses(invariants)

    assert all(
        isinstance(hypothesis, VulnerabilityHypothesis) for hypothesis in hypotheses
    )
    assert len(hypotheses) == 2
    assert hypotheses[0].model_dump() == {
        "hypothesis": "修改文件标识符或所有者上下文可能读取、导出或分享其他用户的私有文件。",
        "vuln_type": "broken_access_control",
        "broken_invariant": "用户不能访问其他用户私有文件",
        "evidence_needed": [
            "两个低权限测试账户",
            "一个账户创建的私有文件标识符",
            "另一个账户访问同一文件的授权结果",
        ],
        "validation_mode": "two_account_authorization_check",
        "risk_level": "high",
        "policy_risk": "low",
    }
    assert hypotheses[1].vuln_type == "business_logic_authorization"
    assert hypotheses[1].validation_mode == "non_destructive_request_review"
    assert hypotheses[1].policy_risk == "medium"


def test_hypothesis_generation_accepts_model_instances_and_keeps_order():
    invariant = SecurityInvariant(
        rule_id="member_admin_boundary",
        invariant="普通成员不能修改管理员级设置",
        objects=["team"],
        actions=["settings"],
        risk_level="high",
        policy_risk="low",
    )

    hypotheses = generate_hypotheses([invariant])

    assert [hypothesis.broken_invariant for hypothesis in hypotheses] == [
        "普通成员不能修改管理员级设置"
    ]
    assert hypotheses[0].hypothesis == "普通成员可能通过邀请、设置或删除类接口执行管理员级团队/组织操作。"
