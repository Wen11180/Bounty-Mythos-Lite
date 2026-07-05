import type {
  Finding,
  ProgramIntelligenceProfile,
  Program,
  ReportDraft,
  ScopeGuardDecision,
  ScopeGuardRequest,
  ScopeGuardRule,
} from "./api";

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
    operating_reasons: ["hunter_recommendation:needs_human_review", "claim_quality:high"],
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
    operating_reasons: ["hunter_recommendation:needs_human_review", "claim_quality:needs_stronger_evidence"],
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

export const fallbackScopeGuardRule: ScopeGuardRule = {
  asset: "api.example.com",
  scope_status: "in_scope",
  automation: "limited",
  allowed_validation: ["two_account_authorization_check"],
  forbidden: ["DoS", "credential_stuffing", "real_user_data_access"],
  human_approval_required: true,
};

export const fallbackScopeGuardRequest: ScopeGuardRequest = {
  asset: "api.example.com",
  validation_type: "two_account_authorization_check",
  human_approved: false,
};

export const fallbackScopeGuardDecision: ScopeGuardDecision = {
  allowed: false,
  reason: "human_approval_required",
};

export const fallbackMythosBrainProfile: ProgramIntelligenceProfile = {
  program_id: "program_example",
  program_name: "Example Program",
  program_score: 88,
  attack_surface_memory: {
    objects: ["file_id", "team_id"],
    roles: ["admin", "member"],
    sensitive_actions: [
      {
        action: "export",
        method: "GET",
        path: "/files/{file_id}/export",
        roles: ["member"],
        operation_id: "exportFile",
      },
      {
        action: "share",
        method: "POST",
        path: "/teams/{team_id}/shares",
        roles: ["admin", "member"],
        operation_id: "shareTeam",
      },
    ],
    run_count: 3,
  },
  high_value_surfaces: [
    {
      surface_key: "file_id:export",
      object_name: "file_id",
      action: "export",
      score: 94,
      paths: ["/files/{file_id}/export"],
      playbooks: ["bola_idor"],
      reasons: [
        "action:export",
        "learning:accepted",
        "lesson:applied:surface_match",
        "lesson:boost:accepted_strong_evidence",
        "playbook:bola_idor",
      ],
    },
    {
      surface_key: "team_id:share",
      object_name: "team_id",
      action: "share",
      score: 78,
      paths: ["/teams/{team_id}/shares"],
      playbooks: ["role_boundary"],
      reasons: ["action:share", "playbook:role_boundary"],
    },
  ],
  learning_summary: {
    accepted_count: 1,
    duplicate_count: 0,
    informative_count: 0,
    na_count: 0,
    rejected_count: 0,
    rejection_risk_delta: 0,
    bounty_total: 3000,
    strong_evidence_count: 1,
    adequate_evidence_count: 1,
    weak_evidence_count: 0,
    severity_up_count: 1,
    severity_down_count: 0,
    triager_feedback_count: 1,
    evidence_score_delta: 12,
    boosted_playbooks: ["bola_idor"],
    penalized_playbooks: [],
  },
  recent_learning_signals: [
    {
      id: "learning_signal_fallback_001",
      program_id: "program_example",
      playbook_id: "bola_idor",
      outcome: "accepted",
      surface_key: "file_id:export",
      notes: "Accepted BOLA report improved file export priority.",
      bounty_amount: 3000,
      severity_delta: "up",
      evidence_quality: "strong",
      triager_feedback: "[REDACTED]",
      target_relationships: ["org_id>team_id>file_id"],
      created_at: "2026-07-03T00:00:00.000Z",
    },
  ],
  applied_lessons: [
    {
      id: "lesson_fallback_boost_file_export",
      scope_type: "program",
      scope_key: "program_example",
      playbook_id: "bola_idor",
      surface_pattern: "file_id:export",
      outcome_counts: { accepted: 2 },
      evidence_quality_counts: { strong: 2 },
      bounty_total: 3500,
      severity_delta_counts: { up: 1 },
      confidence: 84,
      recommendation: "boost",
      score_delta: 8,
      reasons: [
        "lesson:boost:accepted_strong_evidence",
        "target_relationship:org_id>team_id>file_id",
      ],
      source_signal_ids: ["learning_signal_fallback_001", "learning_signal_fallback_002"],
      safety_notes: [
        "no_live_requests",
        "test_accounts_only",
        "human_review_required",
        "no_real_user_data",
        "advisory_memory_only",
        "scope_guard_wins",
      ],
    },
  ],
  skipped_lessons: [
    {
      lesson_id: "lesson_fallback_duplicate_team_share",
      reason: "lesson:skipped:surface_mismatch",
      scope_type: "program",
      scope_key: "program_example",
    },
  ],
  lesson_adjusted_surfaces: [
    {
      surface_key: "file_id:export",
      lesson_id: "lesson_fallback_boost_file_export",
      recommendation: "boost",
      score_delta: 8,
      score_before: 86,
      score_after: 94,
    },
  ],
  safety_notes: [
    "no_live_requests",
    "test_accounts_only",
    "human_review_required",
    "no_real_user_data",
    "advisory_memory_only",
  ],
};
