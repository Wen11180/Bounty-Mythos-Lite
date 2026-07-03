from app.models import Finding, PolicyStatus, Program, ReportDraft, ScopeStatus, ValidationStatus


PROGRAMS = [
    Program(
        id="program_example",
        name="Example Program",
        platform="HackerOne / Bugcrowd / VDP",
        bounty_range="Medium $500 / High $3000 / Critical $10000",
        scope_status=ScopeStatus.IN_SCOPE,
        automation="limited",
        testing_accounts="configured",
        api_docs="imported",
        public_code="available",
        duplicate_risk="medium",
        priority="A",
    )
]

FINDINGS = [
    Finding(
        id="finding_2026_001",
        program="Example Program",
        asset="api.example.com",
        title="普通用户可访问其他用户私有文件 metadata",
        vuln_type="BOLA",
        severity_estimate="high",
        confidence=0.86,
        scope_status=ScopeStatus.IN_SCOPE,
        policy_status=PolicyStatus.ALLOWED,
        broken_invariant="用户不能访问其他用户的私有文件。",
        validation_status=ValidationStatus.SAFELY_VALIDATED,
        refutation_status="passed",
        duplicate_likelihood="medium",
        submission_recommendation="human_review_required",
        evidence_refs=["evidence/request-user-a-to-user-b-metadata.json"],
    )
]

REPORTS = [
    ReportDraft(
        id="report_2026_001",
        finding_id="finding_2026_001",
        title="普通用户可访问其他用户私有文件 metadata",
        draft=(
            "标题：普通用户可访问其他用户私有文件 metadata\n"
            "漏洞类型：BOLA\n"
            "严重等级：High\n"
            "受影响资产：api.example.com\n"
            "安全不变量：用户不能访问其他用户的私有文件。\n"
            "误报排除：非自我影响，非 UI 问题，使用测试账号，未触碰真实用户数据。"
        ),
    )
]
