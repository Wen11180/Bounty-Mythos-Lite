# 推荐路线图

## 1. 提交基线

目标：

- 固化当前 monorepo scaffold 的最小可运行基线。
- 确认 FastAPI、Next、Celery、Docker 的启动方式和边界。
- 给后续改动建立可回退、可验证的起点。

验收标准：

- 当前 scaffold 能按 README 或既有命令启动。
- 根目录文档、产品说明和 scaffold 状态清晰可见。
- git 状态中基线改动被明确识别，准备好由用户决定何时提交。

明确不做：

- 不设计数据库 schema。
- 不接真实 LLM。
- 不做漏洞扫描或线上验证。
- 不引入新技术栈。

## 2. 数据库

目标：

- 建立产品最小数据模型：program、asset、policy rule、finding、validation plan、report draft、learning record。
- 让后端能持久化项目、规则、候选和报告草稿。
- 为后续 API 打通提供稳定数据契约。

验收标准：

- 数据表或 ORM 模型覆盖最小核心对象。
- 有本地迁移或初始化方式。
- 后端可创建、读取、更新核心对象。
- 测试覆盖关键字段和状态流转。

明确不做：

- 不做复杂知识图谱。
- 不接 pgvector / Qdrant，除非已有明确检索需求。
- 不做 Neo4j。
- 不追求完整 Finding DB 终态字段。

## 3. 前后端 API 打通

目标：

- 让 Next 前端通过 FastAPI 展示真实后端数据。
- 打通 Program Center、Dashboard、Finding 基础列表和详情。
- 形成从 program 到 finding/report draft 的最小工作流界面。

验收标准：

- 前端不再只依赖静态 mock。
- 至少能创建或读取 program，展示 finding 状态和 report draft。
- API 错误和加载状态有基本处理。
- 本地端到端手动流程可走通。

明确不做：

- 不做复杂权限系统。
- 不做完整报告编辑器。
- 不做自动化验证执行。
- 不做多 Agent 编排。

## 4. LLM dry-run

目标：

- 在不触碰真实目标、不执行线上验证的前提下，跑通 LLM 辅助流程。
- 输入项目 policy 或示例 API 文档，输出结构化 policy、候选假设、反证问题和报告草稿。
- 先验证产品闭环和提示词边界。

验收标准：

- dry-run 明确标记为非执行模式。
- 输出可保存到数据库。
- 每个候选包含 scope/policy 判断、broken invariant、evidence needed、validation mode。
- 报告草稿必须标记为 human review required。

明确不做：

- 不自动访问公网目标。
- 不发起扫描、爆破、DoS 或破坏性请求。
- 不自动提交报告。
- 不把 LLM 输出当成已验证事实。

## 5. Scope Guard

目标：

- 把项目 policy 转为可执行规则，作为所有 Agent 和验证计划前的统一拦截层。
- 先覆盖最关键风险：scope、禁止测试类型、自动化限制、真实用户数据、人工审批。
- 让 dry-run 产物也必须经过 Scope Guard 标记。

验收标准：

- 有明确的 Scope Guard rule 数据结构。
- 后端提供 policy check 接口或内部服务。
- 候选和验证计划能得到 allowed / blocked / human_approval_required 结果。
- 被拦截原因可展示给前端和报告草稿。
- 有测试覆盖典型允许、禁止和需人工审批场景。

明确不做：

- 不宣称完整理解所有平台 policy。
- 不允许任何 Agent 绕过 Scope Guard。
- 不实现自动线上验证。
- 不把规则做成不可解释的黑盒。

## 6. Mythos-like Pipeline V1

目标：

- 串起第一条可测试链路：Policy Ingestion -> Target Understanding -> Security Invariants -> Hypothesis -> Refutation -> Safe Validation Plan -> Report Draft。
- 让系统开始从“Dashboard + API 骨架”变成“能解释目标、提出假设、主动反证、生成安全验证计划”的研究工作台。

验收标准：

- 后端提供 dry-run pipeline，不调用真实目标，不消耗 LLM token。
- 每个 hypothesis 都绑定 broken invariant 和 evidence needed。
- Refutation 和 Scope Guard 决定验证是否可继续。
- 验证计划只能包含非破坏性、测试账号、本地审查和请求/响应差异分析。

明确不做：

- 不自动攻击公网。
- 不触碰真实用户数据。
- 不自动提交报告。
- 不把候选假设当成已验证漏洞。
