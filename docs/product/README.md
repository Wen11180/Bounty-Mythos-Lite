# Bounty Mythos-Lite 产品总览

## 北极星目标

现役北极星以 `docs/product/north-star.md` 为准。仓库根目录的 `私人 AI 漏洞研究系统最终方案.md` 保留为长期能力参考，不再决定近期实现优先级。

**现役方向：SRC/HackerOne 优先的自动化高质量漏洞发现系统。**

产品自动处理明确授权的项目规则、范围、API/HAR、代码和研究笔记，产出少量高质量、可反证、可追踪证据链的漏洞候选，以及供人工审核的报告草稿。近期衡量的是自动发现质量、更高的 accepted bounty / human hour 和更少的重复/无效候选，不是通用自治平台的完整度。

产品既不是普通安全 dashboard，也不是扫描器结果总结器，更不是无限制的自动化线上执行平台。它应自动理解项目规则和攻击面、提出并主动反驳高价值假设、明确证据缺口和安全验证计划，并在满足证据条件后生成 submission-blocked 报告草稿。

## 当前阶段

当前阶段是 **H1/SRC Autonomous Candidate Discovery Track**：

- 结合明确的项目 policy/scope 与操作员提供的 API/HAR、文档、笔记或授权本地代码；
- 自动完成目标建模、攻击面分析、假设生成、反证、去重和排序，产出短而有序的候选队列，包含受影响面、风险原因、反证问题、证据需求、安全验证计划和报告草稿状态；
- 系统自动生成验证计划；人工仅在项目规则要求时批准线上或敏感验证，并始终手动提交报告，把 accepted、duplicate、informative、N/A、rejected 等结果回灌给排序系统。

当前实现中的安全边界、artifact 摄入、候选生成、报告阻塞、候选审核和 Mythos Studio 工作台都应服务于自动发现闭环。下一步优先是自动 Candidate Hunter 深度、研究语义覆盖、影响校准、重复规避、平台格式报告质量和真实结果学习。现有 durable loop、scheduler 与 Autopilot 能力应直接服务自动发现，而不是成为独立交付主线。

## 核心目标

Bounty Mythos-Lite 面向合法 SRC 和 HackerOne 项目：系统以研究 campaign 为核心，读取项目规则和授权 artifact，完成目标建模、攻击面选择、漏洞假设生成、误报反证、低风险验证计划、证据审查、报告草稿生成，并把人工提交结果回灌为长期经验。

成熟形态下，系统应具备真实自动候选发现能力：不是被动罗列规则命中，而是能基于代码路径、API 行为、权限模型、业务不变量和历史学习信号，自主提出高价值漏洞候选并持续反驳弱候选。自动化研究循环是主能力；通用线上执行能力只在它已被证明能消除研究瓶颈时才扩展。

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
- 自动化研究循环是当前优先级；自动化线上验证和提交始终不能绕过 Scope Guard、人工批准与提交许可。

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
- 自动化研究循环（durable loop / wakeup / specialist jobs）：持续推进目标建模、审计、假设、反证和排序；不授予自我批准权限。
- Validation Layer：生成低风险验证计划，并只在 Scope Guard、approval、preflight 和人工操作门禁允许时记录验证观察。
- Finding DB：保存结构化 finding、状态、证据、报告草稿和学习数据。
- Report Builder：生成 submission-blocked 的 HackerOne/Bugcrowd 风格报告草稿。
- Learning Loop：从提交结果、赏金、严重性变化、证据质量和脱敏 triager 反馈中沉淀经验。

## 权威文档指针

| 用途 | 文档 |
|---|---|
| Agent 工作边界与北向 | `AGENTS.md` |
| 现役阶段目标 | `docs/product/north-star.md` |
| 能力与实现快照 | `docs/product/requirements-and-features.md` |
| 仓库使用与启动 | `README.md` |
| 近期设计/实现计划 | `docs/superpowers/specs/`、`docs/superpowers/plans/` |

`docs/roadmap.md`、`docs/mythos-gap.md`、`docs/hunter-ab-status.md` 为历史或阶段性记录，不作为现役能力声明。

## 源材料

本目录内容整理自原始中文 `.txt` 产品说明文件。当前以本目录的结构化产品文档为准；原始 `.txt` 文件可能已由项目维护者移动到其他文件夹。
