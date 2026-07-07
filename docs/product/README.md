# Bounty Mythos-Lite 产品总览

## 北极星目标

长期目标以仓库根目录的 `私人 AI 漏洞研究系统最终方案.md` 为准；短版工作目标见 `docs/product/north-star.md`。

当前阶段优先实现 A+B Autonomous Candidate Hunter：把授权 policy/scope/API/HAR 和授权本地代码结合起来，自动产出少量高质量漏洞候选，并为每个候选提供接口路径、代码路径、风险原因、反证问题、证据需求、安全验证计划和 submission-blocked 报告草稿状态。

## 核心目标

Bounty Mythos-Lite 面向合法赏金项目：系统以 research campaign 为核心，读取项目规则和授权 artifact，完成目标建模、攻击面选择、漏洞假设生成、误报反证、低风险验证计划、证据审查、报告草稿生成，并把人工提交结果回灌为长期经验。

产品不追求“扫到多少漏洞”，而是追求更高质量、证据链更完整的候选发现：

- accepted bounty / human hour 持续提升
- Accepted rate 目标 30%+
- Duplicate rate 目标低于 25%
- Informative / N/A rate 目标低于 15%
- Policy violation 必须为 0

## 产品原则

- 规则先行：任何项目的第一步都是读取 program policy，并转成机器可执行限制。
- Scope Guard 不可绕过：所有 Agent、验证计划和报告生成都必须经过范围与策略检查。
- 建模优先于扫描：先理解角色、对象、权限、业务流程和安全不变量，再生成候选。
- 少量高质量候选：候选应高置信、高影响、可形成低风险验证计划，并满足报告草稿前置条件。
- 反证优先：Refutation Agent 负责主动证明候选不是漏洞，降低噪声。
- 记忆先于自动化：历史提交结果只能调整建议和排序，不能变成自动验证权限。
- 人工确认：线上验证、报告提交和敏感动作必须有人确认。
- 低风险验证：只允许测试账号、本地复现、非破坏性流程和请求响应差异分析。
- 授权 artifact 优先：不自动抓取公共目标、公共仓库或第三方报告。

## 推荐产品结构

- Campaign Control Center：campaign 状态、预算、阻断原因、agent run、下一步动作和人工门禁。
- Program Center：项目、奖金、scope、自动化限制、测试账号、授权 artifact 和历史重复率。
- Scope Guard：把项目 policy 转为统一规则，拦截越界行为。
- Artifact Ingestion：摄入 policy、OpenAPI、HAR、授权本地代码快照、文档、扫描输出和历史报告。
- Target Understanding：生成安全地图、对象模型、角色权限矩阵和业务流程图。
- Security Invariant Engine：抽取系统应保证的业务安全不变量。
- Hypothesis Engine：基于模型和不变量生成高价值漏洞假设。
- Mythos Brain：沉淀 program 维度攻击面记忆、hunter 判断和学习信号。
- Multi-Agent 研究团队：分工完成 policy、建模、审计、反证、证据和报告。
- Validation Layer：生成低风险验证计划，并只在 Scope Guard、approval、preflight 和人工操作门禁允许时记录验证观察。
- Finding DB：保存结构化 finding、状态、证据、报告草稿和学习数据。
- Report Builder：生成 submission-blocked 的 HackerOne/Bugcrowd 风格报告草稿。
- Learning Loop：从提交结果、赏金、严重性变化、证据质量和脱敏 triager 反馈中沉淀经验。

## 源材料

本目录内容整理自原始中文 `.txt` 产品说明文件。当前以本目录的结构化产品文档为准；原始 `.txt` 文件可能已由项目维护者移动到其他文件夹。
