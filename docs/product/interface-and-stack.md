# 界面与技术栈

## 信息架构

左侧菜单：

- Campaigns
- Campaign Control Center
- Agent Runs
- Tasks
- Attack Surface Map
- Codebase Map
- Hypothesis Board
- Validation Queue
- Validation Runs / Audit
- Evidence Review
- Finding Candidates
- Report Drafts
- Mythos Brain
- Settings / Scope Guard

## Finding Candidate / Report Draft 页面

示例 finding：

- 标题：普通用户可访问其他用户私有文件 metadata
- 状态：Draft Review Blocked
- 严重性：High
- 置信度：86%
- Scope Gate：通过，带 campaign scope snapshot 和审计记录
- Policy Gate：通过，但仍需人审记录
- 验证方式：双账号非破坏性验证，需绑定 campaign approval、preflight 和 manual observation
- Duplicate 风险：中
- 推荐：补齐证据审查和报告草稿审查；系统不得自动提交

破坏的不变量：

> 用户不能访问其他用户私有文件。

证据：

- User A 请求 User B 私有文件 metadata
- 响应包含文件名、大小、owner_id
- User A 正常情况下不应拥有该文件权限

反证结果：

- 非自我影响
- 非 UI 问题
- 非 best practice
- 使用测试账号
- 未触碰真实用户数据

页面必须清楚区分：

- finding candidate：值得继续跟进的结构化候选，不等于已确认漏洞。
- observed claim：有证据支持的观察，不等于最终报告主张。
- report draft：人工复核材料，默认 submission blocked。
- manual submission record：人工在平台提交后的记录，不是系统自动提交。

## 技术栈边界

当前推荐技术栈保持为现有 scaffold 方向，不新增技术栈。

前端：

- Next.js
- Tailwind
- Campaign Control Center + Report Draft Review

后端：

- Python
- FastAPI
- Celery
- Redis

数据库：

- PostgreSQL
- pgvector / Qdrant
- Neo4j 可选

代码分析：

- Tree-sitter
- Semgrep
- CodeQL
- Syft / Grype
- SARIF importer

API 分析：

- OpenAPI / Swagger parser
- Postman parser
- HAR parser

验证：

- Playwright，仅限测试账号和低风险流程
- Docker sandbox
- 本地 unit test / regression test
- 手动 validation observation 和 redaction review

模型：

- 可选择不同模型用于推理、建模、反证和报告
- 小模型用于分类、去重和模板化任务

安全：

- Scope Guard
- Rate limiter
- Secret manager
- 全量审计日志
- 人工审批队列
