# 产品模块

## Campaign Control Center

首页是自主研究 campaign 的操作台，展示工作质量、风险控制、预算消耗和下一步动作，不展示“扫到多少漏洞”。

今日任务指标：

- 活跃 campaign 数
- 高价值候选数
- 需要证据/审批/反证的候选数
- 需要人工确认数
- Policy 风险拦截数
- 被 Scope Guard 或 preflight 阻断的动作数

核心 KPI：

- Accepted rate：目标 30%+
- Duplicate rate：目标低于 25%
- Informative / N/A rate：目标低于 15%
- Policy violation：必须为 0
- 每个 accepted bounty 的人工小时：持续下降

最终主指标是 `accepted bounty / human hour`。

## Campaign Intake / Program Center

每个赏金项目先生成 program 记录，再在明确授权边界内启动 research campaign：

- 项目名称
- 平台：HackerOne、Bugcrowd、自建 VDP 等
- 奖金范围
- Scope 清晰度
- 自动化允许程度
- 测试账号配置状态
- API 文档导入状态
- 授权 artifact / 本地代码快照状态
- 历史重复率
- 推荐优先级

系统第一步必须读取项目 policy。平台规则和项目方规则可能同时生效，因此 policy 需要转换成机器可执行限制。没有 scope、授权 artifact、测试账号或人工审批记录时，campaign 只能停留在只读建模和假设阶段。

## Scope Guard

Scope Guard 是产品的刹车系统，负责拦截：

- 非 scope 资产
- 禁止测试类型
- 破坏性行为
- 高频请求
- 未授权账号
- 真实用户数据访问
- 自动提交报告
- 未经人工确认的线上验证

所有 Agent 都不能绕过 Scope Guard。

规则对象至少包含：

```json
{
  "asset": "api.example.com",
  "scope_status": "in_scope",
  "automation": "limited",
  "allowed_validation": [
    "two_account_authorization_check",
    "local_code_review",
    "non_destructive_business_logic_test"
  ],
  "forbidden": [
    "DoS",
    "credential_stuffing",
    "social_engineering",
    "destructive_testing",
    "real_user_data_access"
  ],
  "human_approval_required": true
}
```

## Artifact Ingestion

资料摄入层支持的输入：

1. Program policy
2. OpenAPI / Swagger
3. Postman Collection
4. HAR 浏览器流量
5. 前端 JS bundle
6. 用户提供或明确授权的本地代码仓库/代码快照
7. 用户提供或明确授权的移动端资源
8. 用户提供或明确授权的帮助中心/开发者文档
9. 用户提供或明确授权的历史公开漏洞报告
10. 用户提供或明确授权的静态扫描/SARIF 输出
11. 平台评级标准

Artifact Ingestion 不能自动抓取公共目标、公共仓库或第三方报告。所有输入都必须带有来源、授权说明、敏感度、redaction 状态和 provenance ref。

统一输出结构：

```json
{
  "assets": [],
  "endpoints": [],
  "roles": [],
  "objects": [],
  "business_flows": [],
  "sensitive_actions": [],
  "security_invariants": []
}
```

## Target Understanding

目标理解层不是直接扫描，而是先生成：

- `program_security_map.md`
- `api_object_model.json`
- `role_permission_matrix.json`
- `business_flow_graph.json`
- `sensitive_action_index.json`

它需要理解：

- 用户角色
- 组织、团队、租户关系
- 敏感对象
- 读、写、删除、邀请、导出等敏感动作
- `user_id`、`org_id`、`team_id`、`file_id`、`invoice_id` 等关键参数
- 支付、退款、邀请、权限、文件分享等业务流程

产品应优先围绕 API 授权边界和对象级权限建模。

## Security Invariant Engine

安全不变量引擎关注系统本来应该保证什么，而不是只问单个接口有没有漏洞。

示例不变量：

- 用户 A 不能读取用户 B 的私有资源。
- 普通成员不能修改管理员设置。
- 被移出团队后不能继续访问团队文件。
- 订单金额不能由客户端控制。
- 退款不能重复产生余额。
- 私有文件不能被未授权用户下载。
- RAG 不能返回用户无权限的文档。
- AI Agent 不能执行用户无权执行的工具调用。

这个模块决定产品能否发现业务逻辑漏洞，而不是只产出低价值扫描结果。

## Hypothesis Engine

漏洞假设引擎基于 API、角色、对象和业务流程生成候选。

```json
{
  "hypothesis": "普通成员可能可以修改团队邀请设置",
  "vuln_type": "authorization_bypass",
  "broken_invariant": "普通成员不能修改管理员级团队设置",
  "asset": "api.example.com",
  "evidence_needed": [
    "普通成员账号",
    "管理员账号",
    "团队对象",
    "权限对比结果"
  ],
  "validation_mode": "two_account_non_destructive_check",
  "risk_level": "high",
  "policy_risk": "low"
}
```

候选目标不是数量，而是少量、高置信、高影响、可形成低风险验证计划，并满足报告草稿前置条件。candidate 不代表漏洞已验证或报告可提交。

## Mythos Brain

Mythos Brain 是 program 维度的猎人记忆层，不是自动执行器。

它记录和计算：

- Attack Surface Memory：哪些 object、role、sensitive action 和 path 组合值得继续投入。
- Learning Signals：accepted、duplicate、informative、N/A、rejected、bounty、severity delta、evidence quality 和脱敏 triager 反馈。
- Program Intelligence：program score、高价值 surface 排序、boosted playbook 和 penalized playbook。

Brain 的输出只能用于建议、排序和解释下一步人工判断。triager feedback 只做脱敏保存和计数，不被自由文本解析成执行权限。它不能绕过 Scope Guard，不能自动验证，不能访问公网目标，不能触碰真实用户数据，不能保存 raw secret/token/cookie，不能自动提交报告。

## Hunter Operating Loop

Hunter Operating Loop 把 run、claim quality、hunter assessment、LLM audit 和 Finding DB 接成闭环。

它允许系统把高质量、已人工审查、仍被提交门锁住的 observed claim 生成 finding candidate。candidate 只代表“值得继续跟进的结构化发现”，不代表漏洞已验证或报告可提交。

它记录：

- Finding candidate：title、asset、severity estimate、broken invariant、evidence refs、duplicate likelihood、policy status、hunter operating recommendation。
- LLM audit：provider、model、purpose、prompt hash、latency、error、safety notes。
- Hunter operating action：promote、needs stronger evidence、park duplicate risk、policy blocked。

它不能自动验证，不能访问公网目标，不能保存 prompt 原文里的 secret，不能把 LLM 输出当事实，不能自动提交报告。

## Multi-Agent 研究团队

最终版本至少包含这些 Agent：

1. Policy Agent：解析项目规则
2. Scope Guard Agent：拦截越界行为
3. ROI Agent：判断哪个项目值得做
4. Recon Agent：整理 campaign 内已授权资料，不主动抓取公网目标
5. API Modeling Agent：建 endpoint / object / role 模型
6. Business Invariant Agent：生成业务安全不变量
7. Code Audit Agent：审授权本地代码、代码快照和补丁 diff
8. Hypothesis Agent：生成漏洞假设
9. Validation Planner Agent：设计低风险验证计划
10. Refutation Agent：专门证明这是误报
11. Evidence Agent：整理证据
12. Report Agent：生成 submission-blocked 报告草稿，不能提交报告

关键角色是 Refutation Agent。它需要持续追问：

- 是否真的 in scope？
- 是否违反项目规则？
- 是否只影响自己账号？
- 是否只是 best practice？
- 是否没有真实安全影响？
- 是否已有重复披露？
- 是否可稳定复现？
- 是否会被判 informative / N/A？
- 是否触碰真实用户数据？

## Validation Layer

验证层只能在 Scope Guard、approval record、preflight 和人工操作门禁允许时做：

- 双账号权限对比
- 多角色权限矩阵
- 本地代码复现
- 单元测试回归测试
- 非破坏性业务流程验证
- 请求响应差异分析
- 脱敏后的证据截图和日志候选留存
- Claim Quality 评分：只根据已脱敏 evidence、provenance、人审决定和 gate 状态解释 claim readiness

验证层不能做：

- 自动攻击公网
- 高频扫描
- DoS
- 触碰真实用户数据
- 凭证撞库
- 社工
- 自动提交报告
- 未经确认的破坏性利用
- 用 claim quality 分数绕过人工审核或提交门
- 用全局/program-only approval 解锁 campaign-bound validation run
- 重放已记录的 manual result 来绕过新的 scope 或 approval 状态

所有验证必须绑定 campaign approval，只能使用授权账号和脱敏 evidence。截图、日志和请求响应差异只能作为候选证据，晋升为 report evidence 需要人工确认。
