# 产品流程

## 完整流程

1. 选择赏金项目
2. 导入项目 policy
3. Scope Guard 生成规则
4. 导入 OpenAPI、HAR、公开代码和文档
5. 生成项目安全地图
6. 生成角色-对象-动作矩阵
7. 生成安全不变量
8. 生成漏洞假设
9. Refutation Agent 第一轮反证
10. 生成低风险验证计划
11. 人工确认
12. 安全验证
13. Refutation Agent 第二轮反证
14. 证据构建
15. 报告草稿
16. 人工提交
17. 结果回灌

## 验证状态机

```text
candidate
-> plausible
-> policy_checked
-> validation_plan_ready
-> human_approved
-> safely_validated
-> refuted_or_confirmed
-> report_ready
-> human_submitted
-> accepted | duplicate | informative | NA
-> learned
```

## 关键控制点

- 导入项目后必须先完成 policy 解析。
- 任何验证计划进入执行前必须经过 Scope Guard。
- 线上验证前必须有人确认。
- 验证必须使用测试账号和非破坏性动作。
- 报告只能生成草稿，不能自动提交。
- 提交结果必须回灌到 Learning Loop。

