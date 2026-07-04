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

## 10. Artifact Repository + Provenance

目标：

- 把已导入 artifact 从“pipeline 可用输入”升级为研究员可检索、可审计、可复用的资料库。
- 让每个 endpoint、object、role、policy hint、hypothesis 和 evidence 都能回到明确来源。
- 建立 artifact 版本、派生关系、脱敏状态和使用历史，避免研究材料变成不可解释的临时附件。

输入：

- 已归一化 artifact、原始文件 metadata、ingestion result、派生 target facts、pipeline run 引用、evidence 引用、人工 reviewer annotation 和脱敏记录。

输出：

- Artifact repository 视图与查询接口。
- artifact version、source reference、derived fact、provenance edge、redaction status、sensitivity label 和 usage record。
- 可供 pipeline、timeline、validation workspace 和报告草稿引用的稳定 provenance path。

验收标准：

- 研究员能按 program、asset、source type、capture time、sensitivity、ingestion status 和使用状态查找 artifact。
- 任一派生事实都能展示 source artifact、解析阶段、派生时间和被哪些 run、hypothesis、evidence 使用。
- artifact 重新导入或更新时保留历史版本，不静默覆盖已有 provenance。
- 被标记为 secret、token、cookie 或真实用户数据的内容不得进入展示、导出或报告引用，必须先完成脱敏或拒绝使用。
- Scope Guard 决策和人工批准状态会随 artifact 使用路径展示，blocked 或 human_approval_required 不能被下游阶段绕过。

明确不做：

- 不自动抓取公网目标作为资料来源。
- 不触碰、保存或展示真实用户数据。
- 不保存 raw secret、token、cookie 或授权凭据。
- 不把 artifact 中的第三方结论当成已验证漏洞。
- 不允许绕过 Scope Guard 或人工批准使用敏感 artifact。

## 11. Stage-based Pipeline Run Timeline

目标：

- 把持久化 run 记录升级为按阶段展开的可解释 timeline。
- 让研究员能复盘每个阶段的输入、输出、耗时、错误、Scope Guard 决策、人工审批和 provenance 引用。
- 支持从一次 run 的 timeline 直接定位可重跑、可修正、可审查的阶段。

输入：

- pipeline run、stage record、artifact provenance path、Scope Guard decision、human approval record、refutation result、validation plan、evidence link、report draft link 和 stage error。

输出：

- Stage-based timeline API 和前端展示模型。
- 每个 stage 的 status、started_at、finished_at、input summary、output summary、safety decision、approval requirement、error summary、provenance links 和 next allowed action。
- run comparison 所需的 stage diff 数据。

验收标准：

- 单次 run 能按 Policy Ingestion、Target Understanding、Invariant、Hypothesis、Refutation、Safe Validation Plan、Evidence、Report Draft 等阶段清晰展示。
- blocked、failed、human_approval_required 和 completed 状态有不同展示和可解释原因。
- timeline 中的每个阶段都能跳转到相关 artifact、hypothesis、validation plan、evidence 或 report draft。
- 失败阶段不会覆盖前序成功阶段；重跑必须产生新的 stage attempt 或新的 run 记录。
- 没有人工批准时，human_approval_required 之后的执行入口保持禁用。

明确不做：

- 不在 timeline 中提供自动攻击公网目标的入口。
- 不让 Agent 在 blocked 或 human_approval_required 后继续执行。
- 不自动提交报告或自动外发 evidence。
- 不隐藏 Scope Guard 拦截原因。
- 不把 timeline 当成可随意改写的日志。

## 12. Validation Workspace

目标：

- 把安全验证计划、evidence、人工审查和报告草稿连接成一个受控工作台。
- 让研究员在 Scope Guard 和人工批准硬门内记录安全验证结果、整理证据、标注反证和决定是否进入报告。
- 把“模型建议”与“人工观察事实”严格分开，减少误报和越界验证风险。

输入：

- Safe validation plan、hypothesis、Scope Guard decision、artifact provenance、pipeline timeline、evidence record、redaction status、reviewer annotation 和 report draft candidate。

输出：

- Validation workspace 页面与后端状态流。
- validation task、manual check result、evidence attachment、redaction review、claim mapping、review decision 和 report readiness state。
- claim quality score、quality reasons、readiness level 和不可绕过的 submission blockers。
- 可回写到 report draft 的人工确认 claim 与安全说明。

验收标准：

- 研究员只能执行 Scope Guard 允许或人工批准后的非破坏性验证任务。
- workspace 明确区分 unverified claim、model reasoning、manual observation、refuted finding 和 report-ready claim。
- 每条 report-ready claim 都必须绑定已脱敏 evidence 和 provenance path。
- 每条 claim 都显示质量分、证据/provenance/脱敏/人审原因和 readiness level；分数不能解锁自动提交。
- 发现 raw secret、token、cookie 或真实用户数据时，系统必须阻断保存到报告链路并要求脱敏、替换或删除。
- 提交报告前必须显示 human review required，且不会自动提交到任何平台。

明确不做：

- 不自动攻击公网、不扫描、不爆破、不做 DoS、不做社工。
- 不触碰真实用户数据，不保存 raw secret、token、cookie 或授权凭据。
- 不自动执行验证步骤，不自动提交平台报告。
- 不把没有 evidence 和人工确认的 claim 标成已验证。
- 不把 Scope Guard 或人工批准做成可选项；它们是硬门。

## 13. Hunter Intelligence

目标：

- 把顶级猎人的判断标准产品化：高价值 playbook、impact、duplicate risk、policy risk、rejection risk 和下一步行动建议。
- 在验证前给候选排序和去噪，帮助研究员决定哪些值得投入人工时间。
- 让候选报告从“模型觉得可能”升级为“猎人认为值得审查，但仍需证据和人工确认”。

输入：

- target model、hypothesis、refutation result、Scope Guard decision、artifact provenance、evidence hints 和 validation mode。

输出：

- hunter priority score、playbook match、impact score、duplicate risk、policy risk、rejection risk、recommendation、next action 和 evidence focus。
- 可进入 pipeline run payload 和 workbench 的猎人视角摘要。

验收标准：

- BOLA/IDOR、role boundary、money-flow tampering 等高价值 playbook 能被稳定匹配。
- out_of_scope、真实用户数据、best-practice-only、self-impact-only 等候选必须被降权或阻断。
- human_approval_required 只能进入人工审查建议，不会触发任何自动验证。
- 前端能展示 playbook、priority、recommendation、risk 和 next action。
- 所有建议都保留 no_live_requests、test_accounts_only、no_real_user_data 和 human_review_required 安全说明。

明确不做：

- 不自动验证、不自动攻击公网、不自动提交报告。
- 不把 hunter score 当成已确认漏洞。
- 不绕过 Scope Guard、Validation Workspace 或人工批准。
- 不使用真实用户数据或 raw secret 作为评分依据。

## 14. Mythos Brain V1

目标：

- 把 program 维度的攻击面、hunter playbook、历史提交结果和 triager 反馈沉淀成可复用的猎人记忆。
- 用 Attack Surface Memory 标出哪些 object/action/role 组合值得继续投入人工时间。
- 用 Learning Signals 把 accepted、duplicate、informative、N/A、rejected、bounty、severity delta、evidence quality 和脱敏 triager feedback 转成未来优先级调整。

输入：

- program metadata、pipeline run、target model、hunter intelligence、artifact provenance 和人工录入的 learning signal。

输出：

- program intelligence profile、program score、attack surface memory、高价值 surface 排序、learning summary、recent learning signals、evidence-aware outcome intake API 和 advisory score reasons。

验收标准：

- Brain 能从已有 run 中提取 objects、roles 和 sensitive actions。
- accepted signal 会提升相似 playbook 或 surface 的优先级。
- duplicate、N/A 和 rejected signal 会提高 rejection risk 并降低相似候选优先级。
- outcome intake 能从 run_id 派生 playbook/surface，写入 learning signal，并返回更新后的 Brain profile。
- outcome intake 能保存 bounty amount、severity delta、evidence quality 和脱敏 triager feedback。
- Dashboard 能展示 program score、高价值 surfaces 和最近学习信号。
- 所有输出都带 no_live_requests、test_accounts_only、human_review_required、no_real_user_data 和 advisory_memory_only 边界。

明确不做：

- 不做完整知识图谱或自动学习执行器。
- 不自动验证、不自动攻击公网、不扫描、不爆破、不做 DoS、不做社工。
- 不触碰真实用户数据，不保存 raw secret、token、cookie 或授权凭据。
- 不把 learning signal 或 brain score 当成已验证漏洞。
- 不解析 triager 自由文本来授予执行权限。
- 不绕过 Scope Guard、Validation Workspace 或人工批准。

## 15. Hunter Operating Loop V1

目标：

- 把 run、claim quality、hunter assessment、LLM audit 和 Finding DB 接成一个可审计的候选沉淀闭环。
- 让高质量、已人工审查但仍被 submission gate 锁住的 claim 可以进入 finding candidate。
- 记录 LLM/Agent 辅助判断的 provider、model、purpose、prompt hash、latency、error 和 safety notes。

输入：

- pipeline run、report preview、claim ledger、claim review decision、hunter assessment、LLM request/response metadata。

输出：

- finding candidate 记录、hunter operating action、LLM run audit record。

验收标准：

- reviewed observed claim 可以生成 `finding_candidate_*`，但 validation status 仍停留在 `validation_plan_ready`。
- finding candidate 带 evidence refs、broken invariant、duplicate likelihood、policy status 和 hunter operating recommendation。
- LLM audit 不保存 prompt 原文，只保存 prompt hash 和安全说明。
- hunter operating action 至少区分 promote、needs stronger evidence、park duplicate risk、policy blocked。

明确不做：

- 不自动验证、不访问公网、不扫描、不提交报告。
- 不把 LLM 输出或 hunter action 当作事实证明。
- 不把 finding candidate 标成 accepted、report ready 或 human submitted。
- 不保存 raw secret、token、cookie 或真实用户数据。
