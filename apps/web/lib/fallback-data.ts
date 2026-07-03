import type { Finding, Program, ReportDraft } from "./api";

export const fallbackPrograms: Program[] = [
  {
    id: "program_example",
    name: "Example Program",
    platform: "HackerOne / Bugcrowd / VDP",
    bounty_range: "Medium $500 / High $3000 / Critical $10000",
    scope_status: "in_scope",
    automation: "limited",
    testing_accounts: "configured",
    api_docs: "imported",
    public_code: "available",
    duplicate_risk: "medium",
    priority: "A",
  },
];

export const fallbackFindings: Finding[] = [
  {
    id: "finding_2026_001",
    program: "Example Program",
    asset: "api.example.com",
    title: "普通用户可访问其他用户私有文件 metadata",
    vuln_type: "BOLA",
    severity_estimate: "high",
    confidence: 0.86,
    scope_status: "in_scope",
    policy_status: "allowed",
    broken_invariant: "用户不能访问其他用户的私有文件。",
    validation_status: "safely_validated",
    refutation_status: "passed",
    duplicate_likelihood: "medium",
    submission_recommendation: "human_review_required",
    evidence_refs: ["evidence/request-user-a-to-user-b-metadata.json"],
  },
  {
    id: "finding_2026_002",
    program: "Example Program",
    asset: "app.example.com",
    title: "普通成员可能修改团队邀请设置",
    vuln_type: "Broken access control",
    severity_estimate: "medium",
    confidence: 0.71,
    scope_status: "needs_review",
    policy_status: "needs_review",
    broken_invariant: "普通成员不能修改团队级邀请策略。",
    validation_status: "validation_plan_ready",
    refutation_status: "pending",
    duplicate_likelihood: "medium",
    submission_recommendation: "human_review_required",
    evidence_refs: [],
  },
];

export const fallbackReports: ReportDraft[] = [
  {
    id: "report_2026_001",
    finding_id: "finding_2026_001",
    title: "普通用户可访问其他用户私有文件 metadata",
    draft:
      "标题：普通用户可访问其他用户私有文件 metadata\n漏洞类型：BOLA\n严重等级：High\n受影响资产：api.example.com\n安全不变量：用户不能访问其他用户的私有文件。\n误报排除：非自我影响，非 UI 问题，使用测试账号，未触碰真实用户数据。",
  },
  {
    id: "report_2026_002",
    finding_id: "finding_2026_002",
    title: "普通成员可能修改团队邀请设置",
    draft: "等待低风险验证计划和人工确认。",
  },
];
