# 产品模块

## Dashboard

首页展示工作质量和风险控制，不展示“扫到多少漏洞”。

今日任务指标：

- 已解析项目数
- 高价值候选数
- 可提交报告数
- 需要人工确认数
- Policy 风险拦截数

核心 KPI：

- Accepted rate：目标 30%+
- Duplicate rate：目标低于 25%
- Informative / N/A rate：目标低于 15%
- Policy violation：必须为 0
- 每个 accepted bounty 的人工小时：持续下降

最终主指标是 `accepted bounty / human hour`。

## Program Center

每个赏金项目生成一张项目卡：

- 项目名称
- 平台：HackerOne、Bugcrowd、自建 VDP 等
- 奖金范围
- Scope 清晰度
- 自动化允许程度
- 测试账号配置状态
- API 文档导入状态
- 公开代码状态
- 历史重复率
- 推荐优先级

系统第一步必须读取项目 policy。平台规则和项目方规则可能同时生效，因此 policy 需要转换成机器可执行限制。

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
6. 公开 GitHub/GitLab 代码
7. 移动端公开资源
8. 帮助中心/开发者文档
9. 历史公开漏洞报告
10. 平台评级标准

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

候选目标不是数量，而是少量、高置信、高影响、能复现、能提交。

## Multi-Agent 研究团队

最终版本至少包含这些 Agent：

1. Policy Agent：解析项目规则
2. Scope Guard Agent：拦截越界行为
3. ROI Agent：判断哪个项目值得做
4. Recon Agent：整理授权范围内资料
5. API Modeling Agent：建 endpoint / object / role 模型
6. Business Invariant Agent：生成业务安全不变量
7. Code Audit Agent：审公开代码和补丁 diff
8. Hypothesis Agent：生成漏洞假设
9. Validation Planner Agent：设计低风险验证计划
10. Refutation Agent：专门证明这是误报
11. Evidence Agent：整理证据
12. Report Agent：生成赏金报告

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

验证层只能做：

- 双账号权限对比
- 多角色权限矩阵
- 本地代码复现
- 单元测试回归测试
- 非破坏性业务流程验证
- 请求响应差异分析
- 证据截图和日志留存

验证层不能做：

- 自动攻击公网
- 高频扫描
- DoS
- 触碰真实用户数据
- 凭证撞库
- 社工
- 自动提交报告
- 未经确认的破坏性利用

