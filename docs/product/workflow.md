# 产品流程

## 完整流程

1. 创建 research campaign，录入 program、scope、预算、autonomy level 和允许工具。
2. 导入 program policy，Scope Guard 生成机器可执行规则。
3. 导入用户提供或明确授权的 OpenAPI、HAR、本地代码快照、扫描输出和文档。
4. 生成 attack surface map、codebase map、角色-对象-动作矩阵和安全不变量。
5. 多 Agent 并行生成漏洞假设、证据需求、风险估计和可反证问题。
6. Refutation Agent 优先排除 out-of-scope、低影响、重复、policy-risky 或缺少证据路径的候选。
7. 对幸存候选生成低风险 validation plan，并先通过 Scope Guard。
8. 需要线上、测试账号、状态变化或敏感流程时，进入 approval queue；approval record 只记录人工同意计划，不代表可绕过后续门禁。
9. 执行前再次 preflight：重新检查 scope、approval、预算、账号、redaction 和禁止测试类型。
10. 只记录允许的 local/static/manual/test-account validation observation；禁止 destructive、DoS、credential、social engineering、真实用户数据和未授权公网扫描。
11. 将观察结果进入 Evidence Review，完成 provenance、redaction、claim coverage 和 report-chain eligibility 检查。
12. Claim Review 决定哪些观察能变成 finding candidate；模型、scanner 或第三方输入不能直接变成事实。
13. Report Builder 生成 submission-blocked report draft。
14. 人工在外部平台提交后，系统只记录 manual submission result。
15. accepted、duplicate、informative、N/A、rejected、bounty、severity delta 和脱敏 triager feedback 回灌到 Mythos Brain，作为 advisory learning signal。

## Gate-Aware Campaign State Machine

```text
campaign_created
-> scope_guard_checked
-> authorized_artifacts_ingested
-> target_modeled
-> hypothesis_drafted
-> refutation_reviewed
-> validation_plan_ready
-> awaiting_approval | local_static_allowed | blocked
-> approval_recorded
-> preflight_passed | preflight_blocked
-> validation_observed
-> evidence_reviewed
-> claim_reviewed
-> finding_candidate_created | refuted | parked
-> report_draft_created
-> report_draft_reviewed
-> manual_submission_recorded
-> accepted | duplicate | informative | NA
-> learned
```

`approval_recorded` 不是执行许可。任何 retry、manual result、evidence promotion 或 report draft promotion 都必须重新检查当前 campaign scope、approval 状态、preflight 状态和 redaction 状态。

## 关键控制点

- 导入项目后必须先完成 policy 解析。
- 任何验证计划进入执行前必须经过 Scope Guard。
- 线上、测试账号、状态变化或敏感验证前必须有人确认，并形成 approval record。
- Preflight 必须独立于 approval 再次执行；scope 变化、approval 失效或预算不足时必须 fail closed。
- 验证必须使用测试账号、本地 fixture、静态检查或非破坏性动作。
- 证据进入报告链前必须完成 provenance、redaction 和人工 review。
- 报告只能生成草稿，默认 submission blocked，不能自动提交。
- 学习信号只能影响排序、解释和建议，不能授予执行权限。
