# 数据、报告与学习闭环

## Finding DB

每个 finding 都是结构化对象。

```json
{
  "id": "finding_2026_001",
  "program": "example",
  "asset": "api.example.com",
  "vuln_type": "BOLA",
  "severity_estimate": "high",
  "confidence": 0.86,
  "scope_status": "in_scope",
  "policy_status": "allowed",
  "broken_invariant": "用户不能访问其他用户的私有文件",
  "validation_status": "safely_validated",
  "refutation_status": "passed",
  "duplicate_likelihood": "medium",
  "submission_recommendation": "human_review_required",
  "evidence_refs": [],
  "report_draft": ""
}
```

如果接入静态分析结果，建议支持 SARIF，用于统一承接 CodeQL、Semgrep 等工具输出。

## Report Builder

报告生成器输出的是可人工复核后提交给 HackerOne/Bugcrowd 的报告草稿，而不是泛泛的漏洞描述。

报告结构：

- 标题
- 漏洞类型
- 严重等级
- 受影响资产
- 是否在 scope 内
- 测试账号角色
- 前置条件
- 安全不变量
- 复现步骤
- 实际结果
- 预期结果
- 安全影响
- 证据
- 误报排除
- 修复建议
- 回归测试建议

严重性评估建议对齐 Bugcrowd VRT 这类公开漏洞评级分类体系。

## Learning Loop

Learning Loop 记录每次提交后的结果。

```json
{
  "program": "example",
  "vuln_type": "IDOR",
  "claimed_severity": "high",
  "awarded_severity": "medium",
  "status": "accepted",
  "bounty": 1500,
  "triager_feedback": "impact accepted, severity reduced",
  "what_worked": "two-account proof was clear",
  "what_failed": "business impact not strong enough",
  "new_rule": "导出类接口比只读 metadata 更容易被评为 high"
}
```

长期沉淀：

- 哪些项目适合做
- 哪些漏洞类型容易被接受
- 哪些 endpoint 容易 duplicate
- 哪些证据最有说服力
- 哪些报告会被判 informative
- 哪些严重性评估容易偏高

