0. 总目标

你的目标不是做一个“自动黑客工具”，而是做一个：

自动理解目标 → 建模攻击面 → 生成漏洞假设 → 调用工具验证 → 去重降噪 → 生成报告 → 给出补丁建议 → 人工最终审核
的授权漏洞研究系统。

系统最终形态应该接近：

Mythos 的深度推理能力
+ MDASH 的多 Agent 工业化调度
+ XBOW 的 Bug Bounty 流程
+ Buttercup / ATLANTIS 的 CRS 架构
+ OSS-Fuzz / AFL++ 的持续 fuzzing 思路
+ 人类研究员的最终审核
1. 总体架构
┌──────────────────────────────────────┐
│  0. 合规范围控制层                    │
│  Scope / Allowlist / Rate Limit / Log │
└───────────────────┬──────────────────┘
                    ↓
┌──────────────────────────────────────┐
│  1. 目标接入层                        │
│  Git Repo / 本地代码 / API 文档 / BB范围 │
└───────────────────┬──────────────────┘
                    ↓
┌──────────────────────────────────────┐
│  2. 攻击面建模层                      │
│  路由 / API / 权限 / 数据流 / 依赖 / Parser │
└───────────────────┬──────────────────┘
                    ↓
┌──────────────────────────────────────┐
│  3. 多引擎分析层                      │
│  CodeQL / Semgrep / Joern / Fuzz / SCA │
└───────────────────┬──────────────────┘
                    ↓
┌──────────────────────────────────────┐
│  4. 多 Agent 推理层                   │
│  Planner / Auditor / Hypothesis / Verifier │
└───────────────────┬──────────────────┘
                    ↓
┌──────────────────────────────────────┐
│  5. 隔离验证层                        │
│  Docker / Sanitizer / Test Harness / Logs │
└───────────────────┬──────────────────┘
                    ↓
┌──────────────────────────────────────┐
│  6. 结果治理层                        │
│  去重 / 严重性评级 / 证据 / 报告 / 补丁 │
└───────────────────┬──────────────────┘
                    ↓
┌──────────────────────────────────────┐
│  7. 人工审核与提交层                  │
│  Human Review / H1 Report / Patch PR  │
└──────────────────────────────────────┘

核心原则：

AI 负责推理，工具负责验证，人类负责最终判断。

2. 系统定位
允许场景
场景	是否支持
自己的代码库	支持
本地靶场 / CTF / Lab	支持
开源项目安全审计	支持
明确授权的 Bug Bounty 范围	支持
公司内部代码安全审计	支持
未授权互联网目标	不支持
大规模无授权扫描	不支持
破坏性利用、持久化、绕过检测	不支持

你这个系统应该从设计上就禁止越界：

无授权范围 → 不执行
无 allowlist → 不执行
高风险动作 → 需要人工确认
真实目标破坏性验证 → 禁止
所有操作 → 记录审计日志
3. 第一性原理

AI 自主找漏洞最强的地方不是“跑扫描器”，而是这四件事：

能力	说明
跨文件理解	理解 Controller、Service、DAO、Middleware、权限模型之间的关系
漏洞假设生成	发现“这里可能少了权限检查”“这个解析链可能出错”
验证路径设计	设计最小、低风险、可复现的验证方式
报告与修复闭环	把漏洞变成高质量报告、补丁建议和回归测试

所以你的系统不能只是：

nuclei + burp + LLM总结

而应该是：

代码理解 + 静态分析 + 动态验证 + fuzzing + 多 Agent 推理 + 人工审核
4. 技术选型
4.1 编排层
模块	推荐
主语言	Python
API 服务	FastAPI
任务队列	Celery / RQ / Dramatiq
数据库	PostgreSQL
缓存	Redis
向量库	Qdrant / Chroma / pgvector
文件存储	本地 MinIO / S3
容器隔离	Docker
高隔离沙箱	Firecracker / gVisor
前端	Next.js / React
工作流	LangGraph / 自研 DAG
4.2 静态分析工具
工具	作用
CodeQL	代码查询、数据流分析、漏洞模式识别
Semgrep	规则扫描、快速 SAST、安全编码规则
Joern	C/C++/Java/Scala 等代码属性图分析
Bandit	Python 安全扫描
Gosec	Go 安全扫描
ESLint Security	JavaScript / TypeScript 安全扫描
OSV-Scanner	开源依赖漏洞
Syft / Grype	SBOM 和镜像漏洞分析

CodeQL 官方文档说明它可用于识别代码中的漏洞和错误；Semgrep 官方仓库说明它是快速开源静态分析工具，可查找 bugs、执行安全规则和编码标准。

4.3 Fuzzing 工具
工具	适合对象
AFL++	C/C++、二进制、Parser
libFuzzer	C/C++ 库函数 fuzz
Honggfuzz	Native fuzzing
Jazzer	Java / JVM
go-fuzz	Go
cargo-fuzz	Rust
ClusterFuzzLite	持续 fuzzing

OSS-Fuzz 的公开说明是通过现代 fuzzing 技术和可扩展分布式执行来提升开源软件安全性与稳定性；AFL++ 官方文档提供从 quickstart 到 fuzzing in depth 的完整流程。

4.4 Web / API 安全工具
工具	作用
OWASP ZAP	授权 Web 动态测试
Burp Suite API	手工审核与扩展
ffuf	授权范围内目录/API发现
httpx	授权目标探测
nuclei	自定义低风险模板验证
Postman / OpenAPI parser	API 建模
Playwright	浏览器自动化、角色差异测试

注意：
这些工具只能接入 Scope Agent 之后运行。没有授权范围，不允许执行。

5. 多 Agent 设计

最终系统建议分成 12 个 Agent。

5.1 Scope Agent：范围控制

职责：

读取授权范围
解析域名、IP、仓库、API、测试账号
生成 allowlist
阻止越界任务
限制请求速率
记录审计日志

输出：

{
  "target_id": "target_001",
  "allowed_repos": ["github.com/org/project"],
  "allowed_domains": ["test.example.com"],
  "disallowed_actions": [
    "destructive_test",
    "credential_theft",
    "persistence",
    "unapproved_mass_scan"
  ],
  "rate_limit": "low",
  "human_approval_required": true
}
5.2 Intake Agent：目标接入

职责：

读取 Git 仓库
识别技术栈
识别框架
识别入口点
识别构建方式
生成项目画像

输出：

{
  "language": ["TypeScript", "Python"],
  "framework": ["Next.js", "FastAPI"],
  "package_managers": ["npm", "pip"],
  "entrypoints": [
    "src/app/api",
    "backend/routes",
    "backend/controllers"
  ],
  "auth_components": [
    "middleware/auth.ts",
    "backend/auth/jwt.py"
  ]
}
5.3 Attack Surface Agent：攻击面建模

职责：

提取路由
提取 API
提取用户输入点
提取文件上传点
提取权限边界
提取数据流
提取外部服务调用

重点关注：

攻击面	示例
路由	/api/user/:id
权限	admin/user/guest
文件	upload/import/parser
外部请求	webhook、SSRF 风险点
反序列化	pickle、yaml、java serialization
SQL/ORM	raw query、动态 filter
模板	render、eval、expression
队列任务	worker、cron、background job
5.4 Static Analyzer Agent：静态分析

职责：

调用 CodeQL
调用 Semgrep
调用语言专用扫描器
归一化结果
删除明显误报
提取高危路径

输出统一格式：

{
  "tool": "semgrep",
  "rule_id": "python.django.security.audit",
  "file": "backend/views.py",
  "line": 128,
  "category": "injection",
  "confidence": "medium",
  "raw_result": "...",
  "needs_llm_review": true
}
5.5 Dependency Agent：依赖与供应链分析

职责：

生成 SBOM
识别高危依赖
判断是否可达
识别危险版本
给出升级建议

输出：

{
  "package": "example-lib",
  "version": "1.2.3",
  "ecosystem": "npm",
  "known_advisory": true,
  "reachable": "unknown",
  "used_by": ["src/parser.ts"],
  "priority": "medium"
}

重点不是“有 CVE 就报”，而是判断：

依赖是否真的被调用？
危险函数是否可达？
是否暴露在用户输入路径上？
是否有补丁版本？
5.6 Code Auditor Agent：语义代码审计

这是最接近 Mythos 的核心 Agent。

职责：

跨文件阅读代码
理解业务逻辑
理解权限模型
理解状态机
理解对象所有权
发现扫描器发现不了的问题

重点找：

类型	说明
IDOR	对象归属校验缺失
Auth Bypass	某些路径绕过认证
Business Logic	状态机错误、余额/积分/优惠券问题
SSRF	服务端可控请求
File Upload	上传、解析、存储链
Race Condition	并发状态错误
Mass Assignment	多传字段导致越权
JWT/OAuth/SAML	token、签名、回调校验问题
Deserialization	不安全反序列化
Path Traversal	路径拼接问题
5.7 Hypothesis Agent：漏洞假设生成

职责：

把攻击面 + 静态分析 + 代码语义变成漏洞假设
每个假设必须有验证计划
不能直接认定漏洞成立

输出：

{
  "hypothesis_id": "H-001",
  "vuln_type": "IDOR",
  "location": "GET /api/invoices/{invoice_id}",
  "reason": "controller checks authentication but service layer may not verify object ownership",
  "evidence_needed": [
    "two test users",
    "invoice owned by user A",
    "request from user B"
  ],
  "safe_verification": true,
  "risk": "high"
}
5.8 Harness Agent：测试 Harness 生成

职责：

为本地代码生成测试入口
为 parser / decoder / validator 生成 fuzz harness
为 API 生成低风险测试用例
为疑似漏洞生成单元测试

注意：
这部分只在本地沙箱或授权测试环境执行。

5.9 Fuzzer Agent：Fuzzing 执行

职责：

选择 fuzz 引擎
构建 target
运行 sanitizer
收集 crash
最小化样本
去重 crash
交给 Verifier 分析

支持：

ASAN
UBSAN
TSAN
MSAN
Coverage
Crash Minimize
Corpus 保存

输出：

{
  "crash_id": "C-001",
  "target": "image_parser_fuzz",
  "sanitizer": "ASAN",
  "crash_type": "heap-buffer-overflow",
  "reproducible": true,
  "minimized_input": "stored_in_artifacts",
  "needs_root_cause": true
}
5.10 Verifier Agent：验证 Agent

这是整个系统最关键的降噪模块。

职责：

复现漏洞
确认影响
过滤误报
确认是否越界
确认是否需要人工审核

判断标准：

项目	要求
可复现	必须
影响明确	必须
证据完整	必须
未越界	必须
非破坏性	必须
可解释根因	最好有
可修复建议	最好有

状态机：

new_hypothesis
    ↓
needs_verification
    ↓
verified / false_positive / duplicate / needs_human_review
    ↓
report_ready / patch_ready
5.11 Patch Agent：修复与回归测试

职责：

定位根因
生成最小补丁建议
生成回归测试
解释为什么修复有效
避免只做表层过滤

修复原则：

错误修复	正确修复
只在前端隐藏按钮	后端权限强制校验
只过滤某个字符	使用安全 API / 参数化查询
只 block 单个 payload	修复根因
只 try-catch	正确状态检查
只修一个入口	修共同 service 层
5.12 Report Agent：报告 Agent

职责：

生成漏洞报告
生成 HackerOne 风格报告
生成 GitHub Security Advisory 风格报告
生成内部安全报告
生成修复建议
生成复测清单

报告模板：

# 漏洞标题

## Summary
一句话说明问题。

## Affected Component
受影响组件、接口、文件、函数。

## Impact
攻击者能造成什么影响。

## Root Cause
根因分析。

## Reproduction
仅包含授权环境中的安全复现步骤。

## Evidence
日志、截图、请求响应摘要、crash 信息。

## Suggested Fix
修复建议。

## Regression Test
建议添加的测试。

## Severity
CVSS / 业务影响评级。

## Scope Confirmation
确认目标在授权范围内。
6. 数据库设计
6.1 核心表
targets
scopes
repositories
scan_runs
artifacts
attack_surfaces
static_findings
hypotheses
verification_runs
findings
patches
reports
audit_logs
knowledge_items
6.2 Finding 统一结构
{
  "finding_id": "F-2026-0001",
  "target_id": "target_001",
  "title": "Missing object ownership check in invoice endpoint",
  "vuln_type": "IDOR",
  "cwe": "CWE-639",
  "severity": "high",
  "confidence": "high",
  "status": "verified",
  "affected_files": [
    {
      "path": "backend/routes/invoices.py",
      "line_start": 42,
      "line_end": 76
    }
  ],
  "affected_endpoint": "GET /api/invoices/{id}",
  "root_cause": "Authentication is checked, but invoice ownership is not verified before returning invoice data.",
  "safe_reproduction": {
    "environment": "local_or_authorized_test_env",
    "requires_human_review": true
  },
  "evidence": [
    "request_response_diff",
    "log_excerpt",
    "code_path"
  ],
  "suggested_fix": "Enforce ownership check in service layer before returning invoice records.",
  "regression_test": "Add test ensuring user B cannot access user A's invoice.",
  "created_at": "2026-07-07T00:00:00Z"
}
7. 知识库设计

你的知识库不要只是“资料堆积”，要转成结构化漏洞模式。

7.1 知识库格式
{
  "pattern_id": "WEB-IDOR-001",
  "name": "Object ownership check missing",
  "category": "authorization",
  "cwe": "CWE-639",
  "applies_to": ["REST API", "GraphQL", "MVC"],
  "code_signals": [
    "route accepts object id",
    "authentication exists",
    "ownership check missing",
    "direct database lookup by id"
  ],
  "verification_strategy": [
    "use two authorized test accounts",
    "compare access to object owned by another user",
    "verify response difference safely"
  ],
  "fix_strategy": [
    "enforce ownership check in service layer",
    "add regression test",
    "avoid relying only on frontend checks"
  ],
  "false_positive_checks": [
    "object may be intentionally public",
    "admin role may be allowed",
    "ownership enforced in middleware"
  ]
}
7.2 需要收集的数据
数据	用途
CWE	漏洞分类
OWASP Top 10	Web 风险模式
OWASP ASVS	安全控制要求
CAPEC	攻击模式
CVE / NVD	历史漏洞
GitHub Security Advisory	开源漏洞
公开 HackerOne 报告	赏金漏洞表达方式
CTF 非常规解法	创造性路径
顶会论文	新型漏洞思路
Patch diff	学习真实修复方式
框架安全文档	框架特定漏洞模式
Fuzz crash 案例	Parser / memory bug 训练
8. 工作流设计
8.1 源码审计工作流
输入 Git 仓库
    ↓
Scope Agent 检查授权
    ↓
Intake Agent 识别技术栈
    ↓
Attack Surface Agent 建模
    ↓
Static Analyzer Agent 跑工具
    ↓
Code Auditor Agent 语义审计
    ↓
Hypothesis Agent 生成漏洞假设
    ↓
Verifier Agent 本地验证
    ↓
Dedup + Severity
    ↓
Patch Agent 生成修复建议
    ↓
Report Agent 输出报告
    ↓
Human Review
8.2 Fuzzing 工作流
识别 parser / decoder / validator / protocol handler
    ↓
Harness Agent 生成 fuzz harness
    ↓
Fuzzer Agent 运行 AFL++ / libFuzzer / Jazzer
    ↓
Sanitizer 捕获 crash
    ↓
Crash 去重和最小化
    ↓
Verifier Agent 复现
    ↓
Code Auditor Agent 分析根因
    ↓
Patch Agent 生成修复建议
    ↓
Regression Test
8.3 Bug Bounty 授权范围工作流
导入授权范围
    ↓
Scope Agent 生成 allowlist
    ↓
低速资产识别
    ↓
API / 路由 / 功能点建模
    ↓
测试账号和角色建模
    ↓
低风险验证 IDOR / Auth / Logic / SSRF 等
    ↓
Verifier Agent 复现
    ↓
人工审核
    ↓
Report Agent 生成报告

注意：
Bug Bounty 模块一定要有人工审核。
不要让系统自动提交报告，也不要让它自动执行高风险验证。

9. 版本路线

不要一开始就做完整 Mythos。你应该按下面的路线推进。

V0：本地源码审计 MVP

目标：

输入一个仓库，输出一份安全审计报告。

功能：

模块	状态
Git 仓库读取	必须
技术栈识别	必须
Semgrep 扫描	必须
CodeQL 扫描	建议
LLM 复核	必须
漏洞假设生成	必须
报告输出	必须
Web 动态测试	暂不做
Fuzzing	暂不做

V0 完成标准：

给它一个 Python / JS / Go 项目
它能识别框架
它能跑静态分析
它能列出高危代码路径
它能让 LLM 解释风险
它能生成可读报告
它不会越界执行任何目标请求
V1：CRS + Fuzzing

目标：

能对本地开源项目做自动 fuzzing 和 crash triage。

新增：

模块	功能
Harness Agent	生成 fuzz harness
Fuzzer Agent	调用 AFL++ / libFuzzer / Jazzer
Crash Triage	去重、最小化、分类
Sanitizer 集成	ASAN / UBSAN / TSAN
Root Cause Agent	分析崩溃根因
Regression Test	生成回归测试

V1 完成标准：

能识别 parser 类函数
能生成 harness
能跑 fuzz
能收集 crash
能判断 crash 是否可复现
能生成 root cause 分析
V2：授权 Web / API 安全测试

目标：

在明确授权范围内做 Web/API 自动化安全测试。

新增：

模块	功能
Scope Parser	解析 Bug Bounty 范围
Auth Manager	管理测试账号
API Modeler	解析 OpenAPI / Swagger
Role Diff Tester	测权限差异
Business Logic Agent	分析业务流程
Evidence Packer	证据整理
Human Gate	提交前人工确认

V2 完成标准：

能导入授权范围
能识别 API
能使用测试账号建模角色
能发现疑似 IDOR / Auth / Logic 问题
能生成报告草稿
不会自动提交
不会执行越界请求
V3：多 Agent 工业化调度

目标：

接近 MDASH 风格的多 Agent 漏洞研究流水线。

新增：

模块	功能
DAG 调度	多任务并发
Agent Memory	保存历史发现
Finding Dedup	漏洞去重
Risk Prioritization	风险排序
Continuous Scan	对授权仓库持续审计
Patch Validation	验证补丁有效性

V3 完成标准：

多个 Agent 可以并行工作
每个发现有完整生命周期
误报能被持续降低
历史知识能复用
修复后能自动复测
V4：高级研究模式

目标：

接近 Mythos / Big Sleep 类型的深度漏洞研究能力。

新增：

模块	功能
Deep Code Reasoning	跨文件、跨模块推理
Vulnerability Chain Builder	漏洞链假设
Protocol-Aware Fuzzing	协议感知 fuzz
Patch Diff Learner	从补丁学习漏洞模式
Variant Analysis	找相似漏洞
Long-Horizon Agent	长任务规划和反思

V4 完成标准：

能从一个漏洞推导同类漏洞
能理解复杂权限模型
能构造多阶段漏洞假设
能在失败后自动换路径
能把经验沉淀进知识库
10. 项目目录结构

你可以直接让 Codex 按这个目录生成项目。

aegis-mythos/
├── README.md
├── docker-compose.yml
├── .env.example
├── configs/
│   ├── tools.yaml
│   ├── models.yaml
│   ├── scope_policy.yaml
│   └── severity.yaml
├── apps/
│   ├── api/
│   │   ├── main.py
│   │   ├── routes/
│   │   └── schemas/
│   └── web/
│       ├── package.json
│       └── src/
├── core/
│   ├── orchestrator/
│   │   ├── dag.py
│   │   ├── scheduler.py
│   │   └── task_state.py
│   ├── agents/
│   │   ├── scope_agent.py
│   │   ├── intake_agent.py
│   │   ├── attack_surface_agent.py
│   │   ├── static_analyzer_agent.py
│   │   ├── dependency_agent.py
│   │   ├── code_auditor_agent.py
│   │   ├── hypothesis_agent.py
│   │   ├── harness_agent.py
│   │   ├── fuzzer_agent.py
│   │   ├── verifier_agent.py
│   │   ├── patch_agent.py
│   │   └── report_agent.py
│   ├── tools/
│   │   ├── semgrep_runner.py
│   │   ├── codeql_runner.py
│   │   ├── osv_runner.py
│   │   ├── zap_runner.py
│   │   ├── afl_runner.py
│   │   └── docker_sandbox.py
│   ├── knowledge/
│   │   ├── rag.py
│   │   ├── embeddings.py
│   │   ├── pattern_loader.py
│   │   └── vuln_patterns/
│   ├── verification/
│   │   ├── reproducer.py
│   │   ├── evidence.py
│   │   ├── dedup.py
│   │   └── severity.py
│   ├── reporting/
│   │   ├── markdown_report.py
│   │   ├── hackerone_report.py
│   │   ├── advisory_report.py
│   │   └── patch_report.py
│   └── database/
│       ├── models.py
│       ├── migrations/
│       └── repositories.py
├── sandbox/
│   ├── Dockerfile.base
│   ├── policies/
│   └── runners/
├── tests/
│   ├── unit/
│   ├── integration/
│   └── fixtures/
└── examples/
    ├── sample_scope.yaml
    ├── sample_repo_scan.yaml
    └── sample_report.md
11. Scope Policy 设计

configs/scope_policy.yaml

default_mode: safe

allow_unscoped_targets: false
allow_destructive_tests: false
allow_credential_collection: false
allow_persistence: false
allow_exfiltration: false
allow_unapproved_mass_scan: false

network:
  default_deny: true
  require_allowlist: true
  max_requests_per_minute: 30
  user_agent: "Aegis-Mythos-Authorized-Security-Research"

human_approval:
  required_for:
    - external_network_test
    - authenticated_role_test
    - file_upload_test
    - ssrf_verification
    - race_condition_test
    - report_submission

logging:
  audit_all_actions: true
  store_request_metadata: true
  store_sensitive_values: false
12. Agent 输入输出标准

每个 Agent 都必须遵守统一接口。

{
  "task_id": "task_001",
  "agent": "code_auditor",
  "input": {},
  "output": {},
  "status": "success",
  "confidence": "medium",
  "evidence": [],
  "next_actions": [],
  "requires_human_review": false,
  "scope_checked": true
}

没有 scope_checked: true 的任务，后续 Agent 不能执行。

13. 漏洞优先级策略

系统应该优先找高价值漏洞，而不是低价值噪声。

高优先级
类型	原因
Auth Bypass	影响大
IDOR / BOLA	Bug Bounty 高价值
SSRF	可能打到内网/云元数据
RCE	严重性最高
文件上传链	常见高危
反序列化	高危
供应链可达漏洞	真实影响大
权限提升	企业系统常见
Race Condition	扫描器难发现
Business Logic	AI 比传统工具更适合
低优先级
类型	原因
无影响版本泄露	价值低
普通 header 缺失	噪声大
无利用条件的低危 CVE	容易误报
纯理论漏洞	不适合提交
无复现证据的问题	不进入报告
14. 最终运行流程

用户输入：

scan repo ./target-project --mode source-audit

系统流程：

1. Scope Agent 检查是否允许
2. Intake Agent 识别技术栈
3. Dependency Agent 生成依赖风险
4. Static Analyzer Agent 跑 Semgrep / CodeQL
5. Attack Surface Agent 建模入口点
6. Code Auditor Agent 深度审计高危路径
7. Hypothesis Agent 生成漏洞假设
8. Verifier Agent 本地验证
9. Dedup Agent 去重
10. Severity Agent 评级
11. Patch Agent 生成修复建议
12. Report Agent 输出报告
13. Human Review

输出：

reports/
├── executive_summary.md
├── technical_findings.md
├── verified_findings.json
├── false_positives.json
├── suggested_patches.md
└── regression_tests.md
15. Codex 执行任务书

你可以把下面这段直接丢给 Codex。

你要帮我开发一个名为 Aegis-Mythos 的私人 AI 漏洞研究系统。

系统定位：
仅用于授权代码库、本地靶场、开源项目和合规 Bug Bounty 范围内的安全研究。
必须内置 Scope allowlist、审计日志、低风险验证策略和人工审核 Gate。
禁止未授权目标扫描、破坏性测试、持久化、凭证窃取、绕过检测、自动提交漏洞报告。

第一阶段目标：
实现 V0：本地源码审计 MVP。

请按以下目录创建项目：
- FastAPI 后端
- PostgreSQL 数据库模型
- Agent 模块
- Tool runner 模块
- Report 模块
- Sandbox 模块
- configs 配置
- tests 测试

V0 必须实现：
1. 输入本地 Git 仓库路径
2. Scope Agent 检查目标是否允许
3. Intake Agent 识别语言、框架、入口点
4. Semgrep Runner 运行静态扫描
5. CodeQL Runner 预留接口
6. Dependency Agent 读取依赖文件
7. Code Auditor Agent 读取关键文件并生成风险解释
8. Hypothesis Agent 生成漏洞假设
9. Verifier Agent 只做本地非破坏性验证
10. Report Agent 输出 Markdown 报告
11. 所有任务写入 audit log
12. 所有结果使用统一 Finding JSON schema

优先保证：
- 架构清晰
- 安全边界清晰
- 模块可扩展
- 每个 Agent 有统一接口
- 每个工具 runner 有独立封装
- 报告可读
- 测试可跑

不要实现：
- 未授权互联网扫描
- 自动提交 HackerOne 报告
- 高风险 payload
- 破坏性漏洞利用
- 绕过检测或持久化功能

先生成：
1. 完整目录结构
2. requirements.txt / pyproject.toml
3. FastAPI main.py
4. 数据库 models
5. Agent base class
6. Scope Agent
7. Intake Agent
8. Semgrep Runner
9. Report Agent
10. 一个 CLI：aegis scan --repo ./target --scope ./scope.yaml
16. MVP 最小闭环

V0 只需要实现这个闭环：

本地仓库
  ↓
识别技术栈
  ↓
跑 Semgrep
  ↓
LLM 复核高风险代码
  ↓
生成漏洞假设
  ↓
输出报告

不要一开始做：

自动 Web 扫描
自动 fuzzing
自动提交报告
自动攻击真实目标

你先把本地源码审计闭环跑通，后面再加能力。

17. 最终能力目标

系统成熟后应该具备这 10 个能力：

能力	目标
代码理解	跨文件理解架构和权限
静态扫描	自动运行多工具
依赖分析	判断依赖漏洞是否可达
漏洞假设	自动提出高质量假设
本地验证	非破坏性复现
Fuzzing	找 parser / memory / logic bug
去重降噪	降低误报
报告生成	自动生成高质量报告
补丁建议	给出根因级修复
知识沉淀	每次审计反哺知识库
18. 评分指标

你要用这些指标衡量系统强不强：

指标	目标
Verified Finding Rate	真实漏洞比例
False Positive Rate	误报率
Reproducibility	可复现率
Time to Triage	分析速度
Patch Validity	修复建议有效率
Regression Coverage	回归测试覆盖
Scope Violation Count	必须为 0
Human Review Pass Rate	人工审核通过率
Duplicate Rate	重复发现比例
High Impact Finding Ratio	高价值漏洞比例

最重要的不是发现数量，而是：

真实
可复现
高价值
不越界
能修复
19. 最终组合公式

你的最终路线就是：

第一步：V0 本地源码审计
第二步：V1 CRS + Fuzzing
第三步：V2 授权 Bug Bounty 流程
第四步：V3 多 Agent 工业化调度
第五步：V4 深度漏洞研究模式

对应借鉴对象：

V0 学 Semgrep / CodeQL / LLM 审计
V1 学 Buttercup / ATLANTIS / OSS-Fuzz / AFL++
V2 学 XBOW 的赏金流程
V3 学 MDASH 的多 Agent 工业化
V4 学 Mythos / Big Sleep 的深度推理
20. 最终版一句话

你要做的不是“一个 AI 黑客”，而是一个合规、安全、可验证、可复现、可审计的 AI 漏洞研究工厂。

真正强的最终形态是：

Scope 控制
+ 多 Agent 调度
+ 静态分析
+ 语义代码审计
+ Fuzzing
+ 本地验证
+ 去重降噪
+ 报告生成
+ 补丁建议
+ 人工审核
+ 知识库持续进化

这就是你最应该打造的 私人 Mythos-grade 漏洞研究系统最终方案。