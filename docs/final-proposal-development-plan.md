# 私人 AI 漏洞研究系统开发计划

来源：根目录 `私人 AI 漏洞研究系统最终方案.md`。

本文把最终方案整理为可执行开发计划。原则是先补齐本地源码审计闭环，再逐步扩展 fuzzing、授权 Web/API、工业化调度和深度研究能力。任何阶段都不得绕过 Scope Guard、人工审核、脱敏审核或报告提交门禁。

## 假设

- 当前项目已经有 FastAPI 后端、Next.js 前端、数据库迁移、Scope Guard、source audit、pipeline、report preview 和测试基础，不需要重新 scaffold 整个仓库。
- 第一阶段目标不是完整 Mythos，而是把 V0 本地源码审计做成稳定、可测、可审计的 MVP。
- “验证”默认指本地、静态、非破坏性验证；线上、测试账号、状态变化或敏感流程只进入人工审批后的计划，不自动执行。

## 成功标准

- Scope violation count 必须为 0。
- 没有 allowlist 的目标不能执行。
- 所有发现先是 hypothesis，不能被 scanner 或 LLM 直接标为 verified。
- 报告只能生成草稿，默认 submission blocked。
- 所有关键输出能追溯到输入 artifact、scope decision、pipeline run 和 evidence。

## Phase 0：现状确认与边界冻结

目标：

- 确认现有代码中已经具备哪些 V0/V1 能力。
- 冻结安全边界，避免后续实现向“自动攻击工具”偏移。

已发现的可复用入口：

- `apps/api/app/source_audit/__init__.py`：已有 `run_source_audit`，包含本地 repo allowlist 检查、授权代码文件收集、技术栈识别、依赖读取、Semgrep runner、CodeQL 预留、hypothesis、audit log 和 Markdown report。
- `apps/api/app/scope_guard/__init__.py`：已有 `ScopeGuardRule`、`ValidationRequest`、`evaluate_validation_request`。
- `apps/api/app/mythos_report/__init__.py`：已有 report preview、claim ledger、readiness blocker、redaction 和 human review gate 相关模型。
- `docs/product/workflow.md`：已有 gate-aware campaign state machine。
- `docs/product/modules.md`：已有 Scope Guard、Artifact Ingestion、Target Understanding、Hypothesis、Validation Layer 等产品模块描述。
- `docs/roadmap.md`：已有从基线到 Hunter Operating Loop 的历史路线。

验收：

- 形成当前模块能力清单。
- 明确 V0 只补齐本地源码审计闭环，不引入公网扫描、自动提交或破坏性验证。
- 所有后续阶段引用现有模块名，不重新发明平行架构。

明确不做：

- 不重命名项目。
- 不删除现有模块。
- 不把最终方案里的 `aegis-mythos/` 目录结构原样复制到当前 monorepo。

## Phase 1：V0 本地源码审计 MVP 固化

目标：

- 让用户输入本地仓库和 scope 文件后，稳定输出一份本地安全审计报告。
- 把 “repo -> scope check -> intake -> Semgrep -> dependency summary -> hypothesis -> report” 做成可重复运行的闭环。

实现范围：

- CLI：固化 `aegis scan --repo ./target --scope ./scope.yaml` 或当前项目等价命令。
- Scope：要求 `allowed_repos` 命中本地仓库路径，否则 fail closed。
- Intake：识别 Python、TypeScript/JavaScript、Go，识别 FastAPI、Django、Next.js、Express 等最小框架集合。
- Dependency：读取 `package.json`、`requirements.txt`、`go.mod`，只做 manifest summary，不直接报 CVE。
- Static Analyzer：运行 Semgrep；CodeQL 继续保留 skipped/not configured 状态。
- Hypothesis：所有输出状态为 `unverified_hypothesis`，带 evidence needed、safe verification 和 human review required。
- Report：输出 Markdown，并包含 Scope Confirmation、Semgrep summary、Hypotheses、Human Review Gate。

验收：

- 有测试覆盖：
  - repo 不存在时阻断。
  - scope 缺少 allowlist 时阻断。
  - repo 不在 allowlist 时阻断。
  - Semgrep 未安装时不会崩溃，而是记录 skipped。
  - report 中明确写出 local files only、no network validation、no report submission。
- 运行 `python -m pytest` 通过。

明确不做：

- 不执行 Web 请求。
- 不运行 exploit payload。
- 不自动提交 HackerOne/Bugcrowd 报告。
- 不把 Semgrep 结果直接当确认漏洞。

## Phase 2：V0 质量闸与数据持久化

目标：

- 把 V0 从一次性函数调用升级为可审计的 pipeline run。
- 每一步都有状态、输入摘要、输出摘要、安全决策和错误信息。

实现范围：

- Pipeline Run：记录 scope、intake、dependencies、static findings、hypotheses、report path。
- Audit Log：保留 scope_checked、intake_profiled、dependencies_read、semgrep_scanned、hypotheses_generated、report_generated。
- Finding JSON：统一字段包括 finding id、title、vuln type、severity、confidence、status、affected file/endpoint、root cause、evidence、suggested fix、regression test、scope confirmation。
- Report Chain：报告草稿引用 run id 和 finding ids。

验收：

- 单次 scan 可从数据库或持久化记录完整复盘。
- 失败阶段不覆盖前序成功阶段。
- 每个 finding candidate 都能追溯到 Semgrep finding 或 codebase fact。
- 测试覆盖 audit log 顺序和 report draft submission blocked。

明确不做：

- 不做复杂知识图谱。
- 不做向量库。
- 不保存 raw secret、token、cookie、authorization header。

## Phase 3：V0.5 代码语义审计与反证

目标：

- 提高 hypothesis 质量，减少“扫描器噪声”。
- 引入轻量 Code Auditor 和 Refutation，但仍然只做本地静态推理。

实现范围：

- Code Auditor：围绕 route handler、auth middleware、service/DAO、敏感操作读取有限文件上下文。
- Security Invariant：生成少量业务不变量，例如对象归属、角色权限、状态转换、金额不可由客户端控制。
- Refutation：为每个 hypothesis 记录可能反证，例如对象可能公开、权限可能在 middleware/service 层、仅 self-impact、缺少可达输入路径。
- Priority：优先 IDOR/BOLA、Auth Bypass、SSRF、RCE、文件上传链、反序列化、业务逻辑和 race condition；降权低影响 header、纯理论问题和无复现路径候选。

验收：

- 每个高优先级 hypothesis 至少包含 broken invariant、evidence needed、false positive checks。
- report 明确区分 model reasoning、scanner finding、observed fact。
- 测试覆盖 refuted/parked/unverified 状态。

明确不做：

- 不让 LLM 输出成为事实。
- 不跨越 allowlist 读取外部目标。
- 不生成高风险 payload。

## Phase 4：V1 CRS + Fuzzing 计划层

目标：

- 为 parser、decoder、validator、protocol handler 生成 fuzzing 计划，但默认不自动执行。
- 先实现 harness 识别和 crash triage 数据模型，再接入实际执行器。

实现范围：

- Harness Agent：识别候选 parser 函数和输入入口。
- Fuzzer Plan：为 AFL++、libFuzzer、Jazzer、go-fuzz、cargo-fuzz 生成执行建议。
- Sanitizer Plan：记录 ASAN、UBSAN、TSAN、MSAN 等建议。
- Crash Triage Model：定义 crash id、target、sanitizer、crash type、reproducible、minimized input artifact ref、needs root cause。

验收：

- 对本地代码只输出 plan，不启动 fuzzing，除非用户明确批准本地沙箱执行。
- crash artifact 必须是本地、脱敏、可追溯引用。
- 测试覆盖 parser candidate detection 和 no execution by default。

明确不做：

- 不对公网目标 fuzz。
- 不保存真实用户样本。
- 不默认运行耗时或破坏性任务。

## Phase 5：V2 授权 Web/API 安全测试计划层

目标：

- 支持明确授权范围内的 Web/API 测试建模和验证计划，但执行前必须经过 Scope Guard、approval record、preflight 和人工操作。

实现范围：

- Scope Parser：解析 program policy、allowed domains/assets、automation 限制、禁止行为。
- API Modeler：解析 OpenAPI、Postman、HAR、用户提供的授权文档。
- Role Modeler：记录测试账号角色，但不保存凭证原文。
- Validation Planner：生成双账号权限对比、角色矩阵、非破坏性业务流程验证计划。
- Evidence Packer：只接受脱敏 request/response diff、role matrix snapshot、screenshot ref、log ref。

验收：

- 无 scope、无 allowlist、无 approval 时只能建模和生成 hypothesis。
- human_approval_required 后续执行入口保持 blocked。
- 所有 validation plan 都能解释为什么 allowed、blocked 或需要人工审批。

明确不做：

- 不自动访问公网目标。
- 不做高频扫描、DoS、撞库、社工、持久化或绕过检测。
- 不触碰真实用户数据。
- 不自动提交报告。

## Phase 6：V3 多 Agent 工业化调度

目标：

- 把单次 pipeline 扩展为可并行、可恢复、可审计的研究流水线。
- 每个 Agent 输出统一结构，且必须带 `scope_checked: true` 才能进入后续阶段。

实现范围：

- DAG Scheduler：定义 agent task、dependencies、status、retry policy。
- Agent Interface：统一 `task_id`、`agent`、`input`、`output`、`status`、`confidence`、`evidence`、`next_actions`、`requires_human_review`、`scope_checked`。
- Finding Dedup：按 affected component、vuln type、root cause、evidence ref 做去重。
- Risk Prioritization：按 impact、confidence、policy risk、duplicate risk、evidence quality 排序。
- Patch Validation：只验证本地补丁和回归测试，不验证线上目标。

验收：

- 多 Agent 可以并行处理独立任务。
- blocked 或 human_approval_required 状态不能被下游绕过。
- pipeline timeline 能显示每个阶段的输入、输出、耗时、错误和 gate decision。

明确不做：

- 不把 agent autonomy 升级成自动攻击。
- 不允许学习信号授予执行权限。
- 不自动提交报告。

## Phase 7：V4 深度研究与知识沉淀

目标：

- 接近 Mythos-grade 深度推理：跨文件权限模型、漏洞链假设、variant analysis、patch diff learner 和知识库持续进化。

实现范围：

- Deep Code Reasoning：跨 controller/service/DAO/middleware/queue/job 建模。
- Vulnerability Chain Builder：只生成链式 hypothesis 和非破坏验证计划。
- Variant Analysis：从已确认根因寻找同类代码路径。
- Patch Diff Learner：从补丁学习漏洞模式和修复策略。
- Knowledge Base：结构化保存 CWE、OWASP ASVS、CAPEC、历史报告表达、patch diff、框架安全规则和 fuzz crash pattern。

验收：

- 一个已确认 finding 能生成同类候选，但仍为 unverified hypothesis。
- 知识库输出只能影响排序、解释和建议。
- 每条知识更新有来源和适用边界。

明确不做：

- 不让知识库绕过 Scope Guard。
- 不把历史经验当成当前漏洞证明。
- 不生成可用于未授权攻击的执行链。

## 总体里程碑

1. V0：本地源码审计闭环，目标是稳定、可测、可审计。
2. V0.5：语义审计、反证和报告质量提升，目标是降低误报。
3. V1：CRS/fuzzing 计划与本地沙箱能力，目标是支持 parser/memory bug 研究。
4. V2：授权 Web/API 建模和人工门禁验证计划，目标是合规 bug bounty 工作流。
5. V3：多 Agent 调度和 Finding 生命周期，目标是工业化研究流水线。
6. V4：深度推理和知识沉淀，目标是高价值漏洞研究能力。

## 近期建议执行顺序

1. 先跑完整后端测试，确认当前基线。
2. 补齐 `source_audit` CLI 和 report artifact 输出。
3. 增加 V0 阻断类测试和 Semgrep skipped 测试。
4. 把 V0 scan 结果持久化为 pipeline run。
5. 给 report preview 接入 V0 finding json。
6. 再考虑 LLM reviewer、CodeQL、fuzzing 和 Web/API 模块。

