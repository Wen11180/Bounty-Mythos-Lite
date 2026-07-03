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

## 7. Artifact Ingestion

目标：

- 把 dry-run 的一次性示例输入升级为可复用的研究材料入口。
- 支持研究员导入授权范围内的 HAR、Postman collection、OpenAPI 文档、本地笔记、代码片段、SARIF 输出和 policy 文档。
- 为 Target Understanding、Invariant、Hypothesis 和 Evidence 后续阶段提供可追溯来源。

输入：

- 用户明确提供的项目 policy、资产说明、API 文档、请求样本、本地分析笔记、代码片段和工具输出。

输出：

- 归一化 artifact 记录。
- artifact 与 program、asset、source type、capture time、ingestion status 的关联。
- 可被 pipeline 使用的 endpoint、object、role、policy hint 和来源引用。

验收标准：

- 支持的格式能稳定解析，失败时返回清晰原因。
- 每个派生事实都能追溯到原始 artifact。
- 重复导入不会破坏 provenance。
- 导入后不触发任何公网访问或主动验证。
- 发现疑似 secret、token 或真实用户数据时必须标记并要求脱敏处理。

明确不做：

- 不爬取公网目标。
- 不发起扫描、爆破、DoS 或破坏性请求。
- 不导入真实用户数据作为研究素材。
- 不把第三方工具输出直接当成已确认漏洞。

## 8. Pipeline Run Persistence

目标：

- 把 dry-run 的即时推理结果保存为可复盘、可比较、可审计的 pipeline run。
- 让研究员能看到每个阶段为什么继续、为什么停止、用了哪些输入、产出了哪些安全决策。
- 为报告草稿、学习回路和后续复跑建立稳定记录。

输入：

- Scope Guard rule、artifact、target model、security invariant、hypothesis、refutation result、safe validation plan、report draft candidate 和人工审核结果。

输出：

- 持久化 pipeline run 记录。
- 每个 stage 的状态、时间、输入摘要、输出摘要、错误、Scope Guard 决策和关联 artifact/evidence。
- 可供前端展示和报告引用的 run timeline。

验收标准：

- 单次 run 可从数据库完整查看。
- 同一批输入的多次 run 可以比较差异。
- 被 Scope Guard 拦截的原因会持久保存并展示。
- 失败阶段不会覆盖先前成功阶段。
- 报告草稿能引用生成它的具体 run。

明确不做：

- 不在后台自动攻击公网。
- 不允许 Agent 绕过 blocked 或 human_approval_required 决策。
- 不自动提交报告。
- 不把 run history 当成可随意覆盖的临时缓存。

## 9. Evidence Model

目标：

- 把安全验证计划中的观察结果变成可审查、可脱敏、可引用的 evidence。
- 区分模型推理、人工观察和实际验证材料，避免把候选假设误写成事实。
- 支撑从 dry-run 推理到可工作研究流的关键闭环：安全输入、可复盘执行、可审查证据、人工确认报告。

输入：

- 本地请求/响应差异、测试账号观察、角色矩阵检查、截图、脱敏日志、复现步骤、验证备注和人工 reviewer annotation。

输出：

- 与 hypothesis、validation plan、pipeline run、report draft 关联的 evidence 记录。
- source metadata、sensitivity label、redaction status、review status 和引用路径。

验收标准：

- 每条报告 claim 都能关联到具体 evidence。
- evidence 在展示、导出或进入报告草稿前完成脱敏。
- 真实用户数据必须被拒绝、移除或替换为安全说明。
- reviewer 能清楚区分 observed fact、model reasoning 和 unverified claim。
- evidence 不会绕过 Scope Guard 或人工审核。

明确不做：

- 不保存 raw secret、token、cookie 或真实用户数据。
- 不执行破坏性验证。
- 不自动提交平台报告。
- 不声称未人工确认的 evidence 已证明漏洞影响。
