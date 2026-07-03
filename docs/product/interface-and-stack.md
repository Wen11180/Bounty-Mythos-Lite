# 界面与技术栈

## 信息架构

左侧菜单：

- Dashboard
- Programs
- Assets
- API Model
- Business Flows
- Hypotheses
- Validation Plans
- Findings
- Reports
- Submissions
- Knowledge Base
- Settings / Policy Guard

## Finding 页面

示例 finding：

- 标题：普通用户可访问其他用户私有文件 metadata
- 状态：Report Ready
- 严重性：High
- 置信度：86%
- Scope：通过
- Policy：通过
- 验证方式：双账号非破坏性验证
- Duplicate 风险：中
- 推荐：人工复核后提交

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

## 技术栈边界

当前推荐技术栈保持为现有 scaffold 方向，不新增技术栈。

前端：

- Next.js
- Tailwind
- Dashboard + Report Editor

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

模型：

- 可选择不同模型用于推理、建模、反证和报告
- 小模型用于分类、去重和模板化任务

安全：

- Scope Guard
- Rate limiter
- Secret manager
- 全量审计日志
- 人工审批队列

