# Bounty Mythos-Lite 产品总览

## 核心目标

Bounty Mythos-Lite 面向合法赏金项目：系统读取项目规则，完成目标建模、攻击面选择、漏洞假设生成、误报反证、低风险验证计划、报告草稿生成，并把提交结果回灌为长期经验。

产品不追求“扫到多少漏洞”，而是追求更高质量的可提交发现：

- accepted bounty / human hour 持续提升
- Accepted rate 目标 30%+
- Duplicate rate 目标低于 25%
- Informative / N/A rate 目标低于 15%
- Policy violation 必须为 0

## 产品原则

- 规则先行：任何项目的第一步都是读取 program policy，并转成机器可执行限制。
- Scope Guard 不可绕过：所有 Agent、验证计划和报告生成都必须经过范围与策略检查。
- 建模优先于扫描：先理解角色、对象、权限、业务流程和安全不变量，再生成候选。
- 少量高质量候选：候选应高置信、高影响、能复现、能提交。
- 反证优先：Refutation Agent 负责主动证明候选不是漏洞，降低噪声。
- 人工确认：线上验证、报告提交和敏感动作必须有人确认。
- 低风险验证：只允许测试账号、本地复现、非破坏性流程和请求响应差异分析。

## 推荐产品结构

- Program Center：项目、奖金、scope、自动化限制、测试账号、文档和历史重复率。
- Scope Guard：把项目 policy 转为统一规则，拦截越界行为。
- Artifact Ingestion：摄入 policy、OpenAPI、HAR、公开代码、文档和历史报告。
- Target Understanding：生成安全地图、对象模型、角色权限矩阵和业务流程图。
- Security Invariant Engine：抽取系统应保证的业务安全不变量。
- Hypothesis Engine：基于模型和不变量生成高价值漏洞假设。
- Multi-Agent 研究团队：分工完成 policy、建模、审计、反证、证据和报告。
- Validation Layer：生成并执行低风险验证计划。
- Finding DB：保存结构化 finding、状态、证据、报告草稿和学习数据。
- Report Builder：生成可人工复核后提交的 HackerOne/Bugcrowd 风格报告草稿。
- Learning Loop：从提交结果、triager 反馈和奖金结果中沉淀经验。

## 源材料

本目录内容整理自根目录中文 `.txt` 产品说明文件。原始文件保留在根目录，未移动、未删除。

