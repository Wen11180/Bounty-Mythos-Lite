import assert from "node:assert/strict";
import test from "node:test";
import type { ArtifactRecord, PipelineRunDetail, ProgramIntelligenceProfile, ReportPreview } from "./api.ts";
import {
  toCampaignAgentRunSummaries,
  toCampaignAttackSurfaceMapView,
  toCampaignArtifactSummaries,
  toCampaignBrainSummary,
  toCampaignCodebaseMapView,
  toCampaignControlSummary,
  toCampaignEvidenceReviewSummaries,
  toCampaignFindingCandidateGateSummary,
  toCampaignHypothesisBoardSummaries,
  toCampaignLearningReviewSummary,
  toCampaignReportDraftEvidenceSummary,
  toCampaignReportDraftSummaries,
  toCampaignPromotionBlockReviewSummaries,
  toCampaignResearchFeedbackEvidenceSummaries,
  toCampaignResearchTaskReviewSummary,
  toCampaignTaskSummaries,
  toCampaignTimelineSummaries,
  toCampaignValidationEvidenceReviewSummaries,
  toCampaignValidationEvidenceQualitySummary,
  toCampaignValidationRunSummaries,
  toCampaignValidationQueueSummaries,
  type CampaignControlCenter,
  type CampaignValidationRun,
} from "./campaigns-data.ts";

const controlCenter = {
  campaign: {
    allowed_tools: ["static_analyzer"],
    autonomy_level: "level_0_read_only",
    created_at: "2026-07-05T00:00:00Z",
    created_by: "operator",
    default_asset: "https://api.example.com/path?session=secret",
    id: "campaign_1",
    name: "Authorized campaign",
    program_id: "program_example",
    scope_status: "in_scope",
    status: "running",
    target_classes: ["idor"],
  },
  budget: {
    campaign_id: "campaign_1",
    created_at: "2026-07-05T00:00:00Z",
    id: "budget_1",
    status: "active",
    time_budget_minutes: 30,
    token_budget: 5000,
    tool_call_budget: 10,
    tool_call_used: 2,
    tool_call_remaining: 8,
    validation_budget: 1,
    validation_budget_used: 1,
    validation_budget_remaining: 0,
  },
  tasks: [
    {
      agent_type: "orchestrator_agent",
      campaign_id: "campaign_1",
      created_at: "2026-07-05T00:00:00Z",
      id: "task_1",
      input_refs: ["campaign:campaign_1"],
      output_refs: [],
      status: "queued",
      task_type: "campaign_observation",
      title: "Observe campaign; token=secret-token",
    },
  ],
  agent_runs: [
    {
      agent_type: "orchestrator_agent",
      campaign_id: "campaign_1",
      created_at: "2026-07-05T00:00:00Z",
      finished_at: null,
      id: "run_1",
      input_refs: ["campaign_task:task_1"],
      output_refs: [],
      safety_gate_state: "allowed",
      status: "dispatched",
      stop_reason: null,
      task_id: "task_1",
    },
  ],
  approvals: [
    {
      actor: "operator",
      approval_type: "validation_batch",
      asset: null,
      autonomy_level: null,
      campaign_id: "campaign_1",
      created_at: "2026-07-05T00:00:00Z",
      decided_at: null,
      decided_by: null,
      decision_reason: null,
      expires_at: null,
      id: "approval_1",
      plan_digest: null,
      program_id: null,
      reason: "[REDACTED]",
      requested_action: "two_account_authorization_check",
      run_id: null,
      safety_gate_state: "awaiting_approval",
      scope_reference: null,
      status: "pending",
      task_id: "task_1",
      validation_mode: null,
    },
  ],
  pipeline_stages: [
    {
      campaign_id: "campaign_1",
      created_at: "2026-07-05T00:00:00Z",
      id: "stage_1",
      input_refs: ["campaign:campaign_1"],
      output_refs: [],
      pipeline_run_id: null,
      safety_gate_state: "blocked",
      stage_key: "campaign_tick",
      stage_order: 0,
      status: "blocked",
      stop_reason: "approval_required",
      task_id: "task_1",
    },
  ],
  validation_runs: [
    {
      allowed_to_execute: false,
      approval_id: "approval_1",
      approval_required: true,
      campaign_id: "campaign_1",
      created_at: "2026-07-05T00:00:00Z",
      evidence_ref_count: 1,
      finished_at: "2026-07-05T00:03:00Z",
      id: "validation_run_1",
      plan_digest: "plan_digest_1",
      safety_gate_state: "manual_evidence_recorded",
      status: "evidence_recorded",
      summary: "人工验证结果 recorded: observed",
      target_ref: "campaign:campaign_1",
      task_id: "task_1",
      validation_mode: "two_account_authorization_check",
    },
    {
      allowed_to_execute: false,
      approval_id: "approval_1",
      approval_required: true,
      campaign_id: "campaign_1",
      created_at: "2026-07-05T00:04:00Z",
      evidence_ref_count: 0,
      finished_at: "2026-07-05T00:05:00Z",
      id: "validation_run_2",
      plan_digest: "plan_digest_2",
      safety_gate_state: "manual_evidence_gap_recorded",
      status: "needs_evidence",
      summary: "Needs more evidence; Authorization: Bearer secret-token",
      target_ref: "campaign:campaign_1?session=secret",
      task_id: "task_1",
      validation_mode: "two_account_authorization_check",
    },
  ],
  blocked_reasons: ["approval_required"],
  execution_allowed: false,
  safe_next_action: "review_approval_queue",
  research_queue_suggestions: [
    {
      blocked_action_count: 0,
      candidate_status: null,
      execution_allowed: false,
      human_approval_required: true,
      next_allowed_action: "审核假设看板并规划非破坏性证据工作。",
      playbook_id: "bola_idor",
      priority_score: 69,
      queue_key: "reasoning_memory:bola_idor",
      refutation_question_count: 0,
      safety_gate: "advisory_memory_only",
      source: "mythos_brain_reasoning_memory",
      surface_key: "file_id:export",
      title: "Review bola_idor reasoning memory",
      validation_step_count: 0,
    },
  ],
} satisfies CampaignControlCenter;

const brainProfile = {
  program_id: "program_example",
  program_name: "示例项目",
  program_score: 84,
  attack_surface_memory: {
    objects: ["workspace", "invoice"],
    roles: ["member", "admin"],
    run_count: 7,
    sensitive_actions: [
      {
        action: "transfer_ownership",
        method: "POST",
        path: "/workspaces/{id}/owners?session=secret",
        roles: ["admin"],
      },
    ],
  },
  high_value_surfaces: [
    {
      action: "transfer_ownership",
      object_name: "workspace",
      paths: ["/workspaces/{id}/owners?token=secret-token"],
      playbooks: ["idor_role_boundary"],
      reasons: ["accepted_history"],
      score: 92,
      surface_key: "workspace:transfer_ownership",
    },
  ],
  learning_summary: {
    accepted_count: 2,
    adequate_evidence_count: 1,
    bounty_total: 1500,
    duplicate_count: 1,
    evidence_score_delta: 3,
    informative_count: 0,
    na_count: 0,
    penalized_playbooks: [],
    rejected_count: 0,
    rejection_risk_delta: -1,
    severity_down_count: 0,
    severity_up_count: 1,
    strong_evidence_count: 2,
    triager_feedback_count: 1,
    weak_evidence_count: 0,
    boosted_playbooks: ["idor_role_boundary"],
  },
  reasoning_memory: {
    source: "artifact_usage",
    highest_reasoning_review_score: 88,
    learning_signal_context_count: 2,
    candidate_context_count: 3,
    top_playbooks: [
      {
        playbook_id: "idor_role_boundary",
        highest_reasoning_review_score: 88,
        learning_signal_context_count: 2,
        candidate_context_count: 3,
      },
    ],
    safety_notes: [
      "advisory_memory_only",
      "no_execution_permission",
      "does_not_confirm_vulnerability",
    ],
  },
  recent_learning_signals: [
    {
      created_at: "2026-07-05T00:00:00Z",
      evidence_quality: "strong",
      id: "signal_1",
      notes: "Triager accepted; cookie=session=secret",
      outcome: "accepted",
      playbook_id: "idor_role_boundary",
      program_id: "program_example",
      surface_key: "workspace:transfer_ownership",
    },
  ],
  applied_lessons: [
    {
      bounty_total: 1500,
      confidence: 0.82,
      created_at: "2026-07-05T00:00:00Z",
      evidence_quality_counts: { strong: 2 },
      id: "lesson_1",
      outcome_counts: { accepted: 2 },
      playbook_id: "idor_role_boundary",
      reasons: ["accepted_history", "token=secret-token"],
      recommendation: "boost",
      scope_key: "program_example",
      scope_type: "program",
      score_delta: 8,
      severity_delta_counts: { up: 1 },
      source_signal_ids: ["signal_1"],
      surface_pattern: "workspace ownership",
      safety_notes: ["advisory_only"],
      updated_at: "2026-07-05T00:00:00Z",
    },
  ],
  skipped_lessons: [
    {
      lesson_id: "lesson_skipped",
      reason: "scope_guard_blocked",
      scope_key: "program_example",
      scope_type: "program",
    },
  ],
  lesson_adjusted_surfaces: [
    {
      lesson_id: "lesson_1",
      recommendation: "boost",
      score_after: 92,
      score_before: 84,
      score_delta: 8,
      surface_key: "workspace:transfer_ownership",
    },
  ],
  safety_notes: ["advisory_only", "cannot_authorize_execution"],
} satisfies ProgramIntelligenceProfile;

const reportPreview = {
  claim_labels: {
    model_reasoning: "Model reasoning",
    observed_facts: "Observed facts",
    unverified_claims: "Unverified claims",
  },
  claim_ledger: [
    {
      claim_id: "claim_1",
      claim_type: "observed_fact",
      evidence_refs: ["request_response_diff", "Authorization: Bearer secret-token"],
      human_review_required: true,
      provenance_refs: ["artifact:openapi?session=secret"],
      quality_reasons: ["has_manual_observation"],
      quality_score: 82,
      readiness_blockers: [],
      readiness_level: "human_reviewed_gated",
      redaction_status: "redacted",
      review_evidence_refs: ["sanitized_request_response"],
      review_rationale: "Confirmed with cookie=session=secret",
      review_status: "confirmed_observed_fact",
      reviewed_at: "2026-07-05T00:00:00Z",
      reviewer: "operator",
      status: "report_ready",
      text: "Observed access-control drift; token=secret-token",
    },
    {
      claim_id: "claim_2",
      claim_type: "unverified_claim",
      evidence_refs: [],
      human_review_required: true,
      provenance_refs: [],
      quality_reasons: ["manual_observation_missing_safe_evidence"],
      quality_score: 20,
      readiness_blockers: ["missing_evidence_refs"],
      readiness_level: "blocked",
      redaction_status: "none",
      review_evidence_refs: [],
      review_rationale: null,
      review_status: "needs_evidence",
      reviewed_at: null,
      reviewer: null,
      status: "needs_review",
      text: "Model-only claim; session=secret",
    },
  ],
  evidence_refs: ["request_response_diff", "Authorization: Bearer secret-token"],
  human_review_required: true,
  run_id: "run_1",
  safety_notes: ["human_review_required"],
  scope_status: "in_scope",
  sections: {
    model_reasoning: [],
    observed_facts: [],
    unverified_claims: [],
  },
  severity: "high",
  submission_blocked: true,
  title: "Private object access",
} satisfies ReportPreview;

const pipelineRunDetail = {
  asset: "api.example.com",
  blocked_count: 1,
  created_at: "2026-07-05T00:00:00Z",
  evidence_count: 0,
  hypothesis_count: 2,
  id: "run_1",
  policy_text_hash: "hash",
  program_id: "program_example",
  report_title: null,
  scope_status: "in_scope",
  payload: {
    target_model: {
      endpoints: [
        {
          method: "GET",
          path: "/files/{file_id}?token=secret-token",
          summary: "Read private file metadata",
        },
      ],
      objects: [
        {
          name: "file",
          identifiers: ["file_id", "session=secret"],
        },
      ],
      relationships: [
        {
          child_object: "file",
          parent_object: "workspace",
          paths: ["/workspaces/{workspace_id}/files?cookie=session"],
          relationship: "contains",
        },
      ],
      roles: ["member", "admin"],
      sensitive_actions: [
        {
          action: "export_file",
          method: "POST",
          path: "/files/{file_id}/export?Authorization=Bearer secret-token",
          roles: ["admin"],
        },
      ],
    },
    hypothesis_assessments: [
      {
        candidate_id: "candidate_low",
        candidate_status: "parked",
        hypothesis_index: 1,
        hypothesis: {
          broken_invariant: "Tenant isolation",
          evidence_needed: ["role matrix; token=secret-token"],
          hypothesis: "Low-value candidate with cookie=session=secret",
          policy_risk: "medium",
          risk_level: "medium",
          validation_mode: "static_local_check",
          vuln_type: "idor",
        },
        hunter_assessment: {
          duplicate_risk_score: 30,
          evidence_focus: ["sanitized request"],
          hunter_priority_score: 41,
          impact_score: 50,
          next_action: "Park until stronger evidence.",
          playbook_id: "idor_low",
          playbook_label: "Low IDOR",
          policy_risk_score: 40,
          reasons: ["weak_evidence"],
          recommendation: "park",
          rejection_risk_score: 60,
        },
        refutation: {
          human_review_required: true,
          reasons: ["needs_evidence"],
          status: "needs_review",
        },
      },
      {
        candidate_id: "candidate_high",
        candidate_status: "validation_ready",
        hypothesis_index: 0,
        hypothesis: {
          broken_invariant: "Private object access control",
          evidence_needed: ["sanitized role matrix"],
          hypothesis: "Changing object id may expose private files; Authorization: Bearer secret-token",
          policy_risk: "low",
          risk_level: "high",
          validation_mode: "two_account_authorization_check",
          vuln_type: "idor",
        },
        hunter_assessment: {
          duplicate_risk_score: 18,
          evidence_focus: ["parent_child_authorization_matrix"],
          hunter_priority_score: 92,
          impact_score: 88,
          next_action: "Prepare human-approved validation.",
          playbook_id: "bola_idor",
          playbook_label: "BOLA / IDOR",
          policy_risk_score: 12,
          reasons: ["high_impact", "token=secret-token"],
          recommendation: "pursue_with_evidence",
          rejection_risk_score: 14,
        },
        refutation: {
          human_review_required: true,
          questions: [
            "Does ownership check bind workspace_id?",
            "Can Authorization: Bearer secret-token influence scope?",
          ],
          reasons: ["approval_required"],
          status: "plausible",
        },
        exploit_chain: {
          confidence: 0.74,
          impact: "Cross tenant read with cookie=session=secret",
          preconditions: ["attacker has workspace member role", "token=secret-token"],
          primitives: ["object id swap", "Authorization: Bearer secret-token"],
        },
      },
    ],
  },
} satisfies PipelineRunDetail;

const campaignArtifacts = [
  {
    id: "artifact_safe",
    program_id: "program_example",
    asset: "https://api.example.com/path?session=secret",
    kind: "openapi",
    source_type: "dry_run_inline",
    source_hash: "sha256:safe",
    ingestion_status: "normalized",
    provenance: {
      source_name: "openapi.json",
      usage_records: [
        {
          usage_type: "pipeline_run",
          ref: "run:run_1?token=secret-token",
          run_id: "run_1",
          stage: "target_model",
        },
      ],
    },
    payload_summary: {
      sample_request: "Authorization: Bearer secret-token",
    },
    derived_facts: {
      paths: ["/files/{file_id}?session=secret"],
    },
    sensitivity_label: "low",
    redaction_status: "clean",
    report_chain_allowed: true,
    safety_blockers: [],
    usage_records: [
      {
        usage_type: "pipeline_run",
        ref: "run:run_1?token=secret-token",
        run_id: "run_1",
        stage: "target_model",
      },
    ],
    created_at: "2026-07-05T00:00:00Z",
  },
  {
    id: "artifact_blocked",
    program_id: "program_example",
    asset: "api.example.com",
    kind: "har",
    source_type: "manual_upload",
    source_hash: "sha256:blocked",
    ingestion_status: "normalized",
    provenance: {
      source_name: "capture.har",
    },
    payload_summary: {
      raw_payload: "GET /private Authorization: Bearer secret-token",
    },
    derived_facts: {
      notes: ["raw evidence: response body"],
    },
    sensitivity_label: "sensitive",
    redaction_status: "redacted",
    report_chain_allowed: false,
    safety_blockers: ["contains_secret_like_value", "contains_real_user_data_risk"],
    usage_records: [],
    created_at: "2026-07-05T00:01:00Z",
  },
] satisfies ArtifactRecord[];

test("toCampaignControlSummary keeps campaign control center read-only and redacted", () => {
  const summary = toCampaignControlSummary(controlCenter);

  assert.equal(summary.campaignId, "campaign_1");
  assert.equal(summary.executionAllowed, false);
  assert.equal(summary.safeNextAction, "审核门请求");
  assert.equal(summary.safeNextHref, "/campaigns/campaign_1/validation-queue");
  assert.deepEqual(summary.blockedReasons, ["需要审核"]);
  assert.doesNotMatch(JSON.stringify(summary), /Review approval requests|Approval required/i);
  assert.equal(
    summary.budgetLabel,
    "30 分钟 / 5000 个令牌 / 2/10 次工具调用，剩余 8 / 1/1 次验证，剩余 0",
  );
  assert.equal(summary.taskCount, 1);
  assert.equal(summary.agentRunCount, 1);
  assert.equal(summary.pendingApprovalCount, 1);
  assert.deepEqual(summary.researchQueueSuggestions, [
    {
      blockedActionCount: 0,
      candidateStatus: null,
      executionAllowed: false,
      humanApprovalRequired: true,
      nextAllowedAction: "审核假设看板并规划非破坏性证据工作。",
      playbookId: "bola_idor",
      priorityScore: 69,
      rawPriorityScore: null,
      qualityGateReasons: [],
      evidenceNeeded: [],
      evidenceTraceSummary: {
        artifactKinds: [],
        reportSubmissionAllowed: false,
        routeFactCount: 0,
        sourceFactCount: 0,
        sourceFactTypes: [],
        traceStatus: "needs_evidence",
        traceableSourceFactCount: 0,
      },
      reportReadiness: {
        nextAllowedAction: "起草报告前请审核证据门。",
        reportSubmissionAllowed: false,
        requiredEvidenceCount: 0,
        safeValidationStepCount: 0,
        status: "blocked_by_evidence_trace",
        submissionBlocked: true,
        traceStatus: "needs_evidence",
      },
      queueKey: "reasoning_memory:bola_idor",
      refutationQuestionCount: 0,
      requiredEvidence: [],
      satisfiedEvidence: [],
      safetyGate: "仅作建议性记忆",
      source: "研究大脑推理记忆",
      surfaceKey: "file_id:export",
      title: "Review bola_idor reasoning memory",
      topCandidateRank: null,
      validationStepCount: 0,
    },
  ]);
  assert.equal(summary.blockedStageCount, 1);
  assert.equal(summary.validationRunCount, 2);
  assert.equal(summary.validationEvidenceCount, 1);
  assert.equal(summary.validationEvidenceGapCount, 1);
  assert.equal(summary.defaultAsset, "api.example.com/path");
  assert.doesNotMatch(JSON.stringify(summary), /secret-token|session=secret|token=secret/i);
});

test("toCampaignControlSummary keeps research queue advisory even if upstream sends execution", () => {
  const summary = toCampaignControlSummary({
    ...controlCenter,
    research_queue_suggestions: [
      {
        ...controlCenter.research_queue_suggestions[0],
        execution_allowed: true,
        priority_score: 140,
      },
    ],
  });

  assert.equal(summary.researchQueueSuggestions[0].executionAllowed, false);
  assert.equal(summary.researchQueueSuggestions[0].priorityScore, 100);
});

test("toCampaignControlSummary exposes autonomous hunt queue safety counts only", () => {
  const summary = toCampaignControlSummary({
    ...controlCenter,
    research_queue_suggestions: [
      {
        blocked_action_count: 4,
        candidate_status: "awaiting_human_approval",
        execution_allowed: true,
        human_approval_required: true,
        next_allowed_action: "执行前请审核验证计划。",
        playbook_id: "bola_idor",
        priority_score: 91,
        raw_priority_score: 116,
        quality_gate_reasons: ["required_evidence_missing", "Authorization: Bearer secret-token"],
        evidence_needed: ["approved_test_object_id_matrix"],
        evidence_trace_summary: {
          artifact_kinds: ["api", "Authorization: Bearer secret-token"],
          report_submission_allowed: true,
          route_fact_count: 2,
          source_fact_count: 3,
          source_fact_types: ["route_handler", "session_token=secret-token"],
          trace_status: "traceable",
          traceable_source_fact_count: 3,
        },
        report_readiness: {
          next_allowed_action: "Resolve required evidence gaps before report drafting.",
          report_submission_allowed: true,
          required_evidence_count: 2,
          safe_validation_step_count: 2,
          status: "blocked_by_required_evidence",
          submission_blocked: false,
          trace_status: "traceable",
        },
        queue_key: "autonomous_hunt:run_1:hunt_queue_candidate_1",
        refutation_question_count: 3,
        required_evidence: ["independent_refutation_or_static_rule", "policy"],
        satisfied_evidence: ["local_code_or_har_correlation"],
        safety_gate: "awaiting_human_approval",
        source: "mythos_pipeline_autonomous_hunt_queue",
        surface_key: null,
        title: "审核自动挖掘候选 candidate_1",
        top_candidate_rank: 1,
        validation_step_count: 2,
      },
    ],
  });

  assert.deepEqual(summary.researchQueueSuggestions, [
    {
      blockedActionCount: 4,
      candidateStatus: "等待人工审核",
      executionAllowed: false,
      humanApprovalRequired: true,
      nextAllowedAction: "执行前请审核验证计划。",
      playbookId: "bola_idor",
      priorityScore: 91,
      rawPriorityScore: 100,
      qualityGateReasons: ["缺少必需证据", "[已脱敏]"],
      evidenceNeeded: ["已批准测试对象 ID 矩阵"],
      evidenceTraceSummary: {
        artifactKinds: ["API", "[已脱敏]"],
        reportSubmissionAllowed: false,
        routeFactCount: 2,
        sourceFactCount: 3,
        sourceFactTypes: ["路由处理器", "[已脱敏]"],
        traceStatus: "traceable",
        traceableSourceFactCount: 3,
      },
      reportReadiness: {
        nextAllowedAction: "Resolve required evidence gaps before report drafting.",
        reportSubmissionAllowed: false,
        requiredEvidenceCount: 2,
        safeValidationStepCount: 2,
        status: "blocked_by_required_evidence",
        submissionBlocked: true,
        traceStatus: "traceable",
      },
      queueKey: "autonomous_hunt:run_1:hunt_queue_candidate_1",
      refutationQuestionCount: 3,
      requiredEvidence: ["独立反证或静态规则", "策略"],
      satisfiedEvidence: ["本地代码或 HAR 关联"],
      safetyGate: "等待人工审核",
      source: "研究流程自动挖掘队列",
      surfaceKey: null,
      title: "审核自动挖掘候选 candidate_1",
      topCandidateRank: 1,
      validationStepCount: 2,
    },
  ]);
  assert.doesNotMatch(
    JSON.stringify(summary.researchQueueSuggestions),
    /hypothesis|Authorization|secret-token|validation step/i,
  );
});

test("toCampaignControlSummary routes validation review actions to validation audit", () => {
  const summary = toCampaignControlSummary({
    ...controlCenter,
    safe_next_action: "review_validation_queue",
    approvals: [],
    blocked_reasons: [],
    pipeline_stages: [],
  });

  assert.equal(summary.safeNextAction, "审核验证审计");
  assert.equal(summary.safeNextHref, "/campaigns/campaign_1/validation-runs");
});

test("toCampaignControlSummary routes preflight-passed validation to manual observation review", () => {
  const summary = toCampaignControlSummary({
    ...controlCenter,
    safe_next_action: "record_validation_observation",
    approvals: [],
    blocked_reasons: [],
    pipeline_stages: [],
  });

  assert.equal(summary.safeNextAction, "审核人工验证观察");
  assert.equal(summary.safeNextHref, "/campaigns/campaign_1/validation-runs");
  assert.doesNotMatch(summary.safeNextAction, /execute|submit|dispatch|record/i);
});

test("recordCampaignValidationRunManualResult posts only validation-run manual results", async () => {
  const originalFetch = globalThis.fetch;
  const requests: { body: unknown; url: string }[] = [];
  const fallback = controlCenter.validation_runs[0];
  globalThis.fetch = (async (input: string | URL | Request, init?: RequestInit) => {
    requests.push({
      body: init?.body ? JSON.parse(String(init.body)) : null,
      url: input.toString(),
    });
    return new Response(JSON.stringify(fallback), {
      headers: { "Content-Type": "application/json" },
      status: 200,
    });
  }) as typeof fetch;

  try {
    const { recordCampaignValidationRunManualResult } = await import("./api.ts");
    const result = await recordCampaignValidationRunManualResult(
      "validation_run_1",
      {
        evidence_refs: ["sanitized_request_response"],
        outcome: "observed",
        reviewer: "operator",
        summary: "Redacted manual observation only.",
      },
    );

    assert.equal(result.id, "validation_run_1");
    assert.equal(
      requests[0].url,
      "http://localhost:8000/mythos/validation-runs/validation_run_1/manual-results",
    );
    assert.deepEqual(requests[0].body, {
      evidence_refs: ["sanitized_request_response"],
      outcome: "observed",
      reviewer: "operator",
      summary: "Redacted manual observation only.",
    });
    assert.doesNotMatch(requests[0].url, /pipeline\/runs|manual-observations/);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("toCampaignControlSummary routes target model review to attack surface map", () => {
  const summary = toCampaignControlSummary({
    ...controlCenter,
    safe_next_action: "review_attack_surface_map",
    approvals: [],
    blocked_reasons: [],
    pipeline_stages: [],
  });

  assert.equal(summary.safeNextAction, "审核攻击面映射");
  assert.equal(summary.safeNextHref, "/campaigns/campaign_1/attack-surface-map");
  assert.equal(summary.executionAllowed, false);
});

test("toCampaignControlSummary routes ready research tasks to review-only task list", () => {
  const summary = toCampaignControlSummary({
    ...controlCenter,
    safe_next_action: "review_ready_tasks",
    approvals: [],
    blocked_reasons: [],
    pipeline_stages: [],
  });

  assert.equal(summary.safeNextAction, "审核研究任务");
  assert.equal(summary.safeNextHref, "/campaigns/campaign_1/tasks");
  assert.doesNotMatch(summary.safeNextAction, /dispatch|execute|run/i);
});

test("toCampaignControlSummary counts requested approvals as pending review", () => {
  const summary = toCampaignControlSummary({
    ...controlCenter,
    approvals: [
      {
        ...controlCenter.approvals[0],
        status: "requested",
      },
    ],
  });

  assert.equal(summary.pendingApprovalCount, 1);
});

test("toCampaignControlSummary does not count expired approvals as pending review", () => {
  const summary = toCampaignControlSummary({
    ...controlCenter,
    approvals: [
      {
        ...controlCenter.approvals[0],
        expires_at: "2000-01-01T00:00:00Z",
        status: "pending",
      },
    ],
  });

  assert.equal(summary.pendingApprovalCount, 0);
});

test("toCampaignControlSummary routes manual evidence actions to evidence review", () => {
  const summary = toCampaignControlSummary({
    ...controlCenter,
    safe_next_action: "review_evidence_or_report_drafts",
    approvals: [],
    blocked_reasons: [],
    pipeline_stages: [],
  });

  assert.equal(summary.safeNextAction, "审核证据或报告草稿");
  assert.equal(summary.safeNextHref, "/campaigns/campaign_1/evidence-review");
});

test("toCampaignControlSummary routes promotion block review to evidence review", () => {
  const summary = toCampaignControlSummary({
    ...controlCenter,
    safe_next_action: "review_blocked_promotion",
    approvals: [],
    blocked_reasons: ["blocked_by_research_feedback_gate"],
    promotion_review: {
      blocked_attempt_count: 1,
      finding_promotion_allowed: false,
      latest_reason: "blocked_by_research_feedback_gate",
      next_allowed_action: "再次晋级漏洞候选前，请审核被阻断的晋级证据。",
      provenance_ref_count: 6,
      report_submission_allowed: false,
    },
    pipeline_stages: [
      {
        campaign_id: "campaign_1",
        created_at: "2026-07-05T00:13:00Z",
        id: "stage_promotion_blocked",
        input_refs: ["pipeline_run:run_1?Authorization=Bearer secret-token"],
        output_refs: [],
        pipeline_run_id: "run_1",
        safety_gate_state: "manual_review_required",
        stage_key: "finding_promotion_blocked",
        stage_order: 10,
        status: "blocked",
        stop_reason: "blocked_by_research_feedback_gate",
        task_id: null,
      },
    ],
  });

  assert.equal(summary.safeNextAction, "审核被阻断的晋级证据");
  assert.equal(summary.safeNextHref, "/campaigns/campaign_1/evidence-review");
  assert.deepEqual(summary.blockedReasons, ["被研究反馈审核门阻断"]);
  assert.equal(summary.executionAllowed, false);
  assert.equal(summary.promotionReviewBlockedCount, 1);
  assert.equal(summary.promotionReviewLatestReason, "被研究反馈审核门阻断");
  assert.equal(
    summary.promotionReviewNextAllowedAction,
    "再次晋级漏洞候选前，请审核被阻断的晋级证据。",
  );
  assert.equal(summary.promotionReviewProvenanceRefCount, 6);
  assert.equal(summary.promotionReviewRequiredEvidenceBlockedCount, 0);
  assert.equal(summary.promotionReviewFindingPromotionAllowed, false);
  assert.equal(summary.promotionReviewReportSubmissionAllowed, false);
  assert.doesNotMatch(JSON.stringify(summary), /secret-token|authorization/i);
});

test("toCampaignControlSummary routes reviewed validation feedback to finding promotion", () => {
  const summary = toCampaignControlSummary({
    ...controlCenter,
    safe_next_action: "promote_finding_candidate",
    approvals: [],
    blocked_reasons: [],
    promotion_review: {
      blocked_attempt_count: 0,
      finding_promotion_allowed: true,
      latest_reason: "validation_feedback_review_allowed_finding_promotion",
      next_allowed_action: "Promote to finding candidate only after explicit human action.",
      provenance_ref_count: 6,
      report_submission_allowed: false,
      validation_feedback_review_count: 1,
    },
    pipeline_stages: [],
  });

  assert.equal(summary.safeNextAction, "晋级漏洞候选");
  assert.equal(summary.safeNextHref, "/campaigns/campaign_1/report-drafts");
  assert.equal(summary.executionAllowed, false);
  assert.equal(summary.promotionReviewFindingPromotionAllowed, true);
  assert.equal(summary.promotionReviewReportSubmissionAllowed, false);
  assert.equal(summary.promotionReviewRequiredEvidenceBlockedCount, 0);
  assert.equal(summary.promotionReviewValidationFeedbackReviewCount, 1);
  assert.equal(
    summary.promotionReviewNextAllowedAction,
    "Promote to finding candidate only after explicit human action.",
  );
  assert.doesNotMatch(JSON.stringify(summary), /secret-token|authorization/i);
});

test("toCampaignControlSummary routes learning outcome actions to report drafts", () => {
  const summary = toCampaignControlSummary({
    ...controlCenter,
    safe_next_action: "record_learning_outcome",
    approvals: [],
    blocked_reasons: [],
    pipeline_stages: [],
  });

  assert.equal(summary.safeNextAction, "审核学习结果");
  assert.equal(summary.safeNextHref, "/campaigns/campaign_1/report-drafts");
});

test("toCampaignControlSummary routes learning review actions to brain", () => {
  const summary = toCampaignControlSummary({
    ...controlCenter,
    safe_next_action: "review_learning_outcome",
    approvals: [],
    blocked_reasons: [],
    pipeline_stages: [],
  });

  assert.equal(summary.safeNextAction, "审核学习结果");
  assert.equal(summary.safeNextHref, "/campaigns/campaign_1/brain");
});

test("toCampaignControlSummary routes cycle review completion actions to timeline", () => {
  const summary = toCampaignControlSummary({
    ...controlCenter,
    safe_next_action: "complete_cycle_review",
    approvals: [],
    blocked_reasons: ["campaign_cycle_review_required"],
    pipeline_stages: [
      {
        campaign_id: "campaign_1",
        created_at: "2026-07-05T00:14:00Z",
        id: "stage_cycle_review_awaiting",
        input_refs: ["campaign:campaign_1?cookie=session=secret"],
        output_refs: ["notes:Authorization: Bearer secret-token"],
        pipeline_run_id: null,
        safety_gate_state: "allowed",
        stage_key: "campaign_cycle_review",
        stage_order: 5,
        status: "awaiting_review",
        stop_reason: "campaign_cycle_review_required",
        task_id: null,
      },
      {
        campaign_id: "campaign_1",
        created_at: "2026-07-05T00:15:00Z",
        id: "stage_cycle_review_completed",
        input_refs: ["campaign:campaign_1?cookie=session=secret"],
        output_refs: ["notes:Authorization: Bearer secret-token"],
        pipeline_run_id: null,
        safety_gate_state: "allowed",
        stage_key: "campaign_cycle_review",
        stage_order: 4,
        status: "completed",
        stop_reason: null,
        task_id: null,
      },
    ],
  });

  assert.equal(summary.safeNextAction, "审核活动周期");
  assert.equal(summary.safeNextHref, "/campaigns/campaign_1/timeline");
  assert.equal(summary.cycleReviewAwaitingCount, 1);
  assert.equal(summary.cycleReviewCompletedCount, 1);
  assert.doesNotMatch(JSON.stringify(summary), /secret-token|session=secret|authorization: bearer/i);
});

test("toCampaignControlSummary routes blocker resolution to campaign detail", () => {
  const summary = toCampaignControlSummary({
    ...controlCenter,
    safe_next_action: "resolve_blockers",
    approvals: [],
    blocked_reasons: ["budget_exhausted"],
    pipeline_stages: [],
  });

  assert.equal(summary.safeNextAction, "处理阻断项");
  assert.equal(summary.safeNextHref, "/campaigns/campaign_1");
  assert.deepEqual(summary.blockedReasons, ["预算已耗尽"]);
});

test("toCampaignControlSummary keeps next action labels on a review-only allowlist", () => {
  const actions = [
    "execute_validation",
    "submit_report",
    "dispatch_ready_tasks",
    "review_ready_tasks",
    "record_learning_outcome",
    "unknown_future_action",
  ];

  for (const action of actions) {
    const summary = toCampaignControlSummary({
      ...controlCenter,
      safe_next_action: action,
      approvals: [],
      blocked_reasons: [],
      pipeline_stages: [],
    });

    assert.doesNotMatch(summary.safeNextAction, /execute|submit|dispatch|record/i);
    assert.doesNotMatch(summary.safeNextAction, /queue/i);
  }
});

test("toCampaignAgentRunSummaries keeps refs counted but not displayed", () => {
  const summaries = toCampaignAgentRunSummaries([
    {
      ...controlCenter.agent_runs[0],
      input_refs: ["campaign:campaign_1", "artifact:token=secret-token"],
      output_refs: ["evidence:session=secret"],
      safety_gate_state: "allowed",
      stop_reason: "approval_required",
    },
  ]);

  assert.deepEqual(summaries, [
    {
      agentType: "编排智能体",
      finishedAt: null,
      id: "run_1",
      inputRefCount: 2,
      outputRefCount: 1,
      safetyGateState: "范围守卫已审核",
      startedAt: "2026-07-05T00:00:00Z",
      status: "已分派",
      stopReason: "需要审核",
      taskId: "task_1",
    },
  ]);
  assert.doesNotMatch(JSON.stringify(summaries), /范围守卫 clear/);
  assert.doesNotMatch(JSON.stringify(summaries), /secret-token|session=secret|token=secret/i);
  assert.doesNotMatch(JSON.stringify(summaries), /Approval review requested|Approval required/i);
});

test("toCampaignTaskSummaries keeps task queue display redacted", () => {
  const summaries = toCampaignTaskSummaries([
    {
      ...controlCenter.tasks[0],
      input_refs: ["campaign:campaign_1", "artifact:token=secret-token"],
      output_refs: ["stage:cookie=session-secret"],
      title: "Observe campaign with X-API-Key: secret-token",
    },
  ]);

  assert.deepEqual(summaries, [
    {
      agentType: "编排智能体",
      createdAt: "2026-07-05T00:00:00Z",
      id: "task_1",
      inputRefCount: 2,
      outputRefCount: 1,
      status: "排队中",
      taskType: "活动观察",
      title: "未命名任务",
    },
  ]);
  assert.doesNotMatch(JSON.stringify(summaries), /secret-token|session-secret|cookie=session|X-API-Key/i);
});

test("toCampaignResearchTaskReviewSummary keeps research workspace advisory and redacted", () => {
  const summary = toCampaignResearchTaskReviewSummary({
    autonomous_candidate_context: null,
    campaign_id: "campaign_1",
    dispatch_allowed: true,
    execution_allowed: true,
    next_allowed_action: "审核假设看板并规划非破坏性证据工作。",
    latest_refutation_decision: {
      approval_id: "approval_1",
      campaign_id: "campaign_1",
      decision: "needs_evidence",
      decision_id: "refutation_decision_1",
      dispatch_allowed: true,
      execution_allowed: true,
      next_allowed_action: "验证前请收集脱敏证据或完善假设。",
      plan_id: "research_plan_1",
      rationale: "Needs proof before validation; Authorization: Bearer secret-token",
      refutation_answers: ["Current artifact summaries do not prove missing checks."],
      report_submission_allowed: true,
      task_id: "task_1",
      validation_allowed: true,
      validation_run_id: "validation_run_1",
    },
    suggested_refutation_decision: {
      decision: "needs_validation_review",
      dispatch_allowed: true,
      execution_allowed: true,
      human_review_required: true,
      next_allowed_action: "Prepare a human-approved validation plan without executing it.",
      plan_id: "auto_research_plan_1",
      rationale: "Autonomous suggestion with Authorization: Bearer secret-token",
      refutation_answer_count: 0,
      refutation_question_count: 2,
      report_submission_allowed: true,
      target_ref: "campaign:campaign_1?token=secret-token",
      validation_allowed: true,
      validation_mode: "two_account_authorization_check",
    },
    latest_validation_feedback: {
      approval_id: "approval_1",
      campaign_id: "campaign_1",
      decision_id: "refutation_decision_1",
      dispatch_allowed: true,
      evidence_ref_count: 2,
      execution_allowed: true,
      feedback_stage_id: "stage_feedback_1",
      finding_confirmation_allowed: true,
      next_allowed_action: "晋级漏洞候选前，请审核验证证据。",
      outcome: "observed",
      plan_id: "research_plan_1",
      report_submission_allowed: true,
      safety_gate: "advisory_validation_feedback_only",
      status: "evidence_recorded",
      task_id: "task_1",
      validation_allowed: true,
      validation_run_id: "validation_run_1",
    },
    latest_review_plan: {
      campaign_id: "campaign_1",
      dispatch_allowed: true,
      evidence_plan: ["Collect redacted summaries only."],
      execution_allowed: true,
      hypothesis: "BOLA may affect export boundaries with Authorization: Bearer secret-token",
      next_allowed_action: "Review hypothesis board and request approval before validation.",
      plan_id: "research_plan_1",
      refutation_questions: ["Can redacted provenance disprove this?"],
      report_submission_allowed: true,
      required_human_gates: ["scope_guard_review"],
      safety_gate: "advisory_plan_only",
      status: "drafted",
      task_id: "task_1",
      validation_allowed: true,
    },
    non_destructive_plan: [
      "Review existing hypothesis board entries for Authorization: Bearer secret-token",
      "仅收集已脱敏资料摘要和溯源计数。",
    ],
    playbook_id: "bola_idor",
    priority_score: 140,
    queue_key: "reasoning_memory:bola_idor",
    report_submission_allowed: true,
    required_human_gates: [
      "scope_guard_review",
      "redaction_review",
      "approval_required_before_validation",
    ],
    safety_gate: "advisory_memory_only",
    source: "mythos_brain_reasoning_memory",
    status: "queued_review",
    surface_key: "file_id:export",
    task_id: "task_1",
    title: "Review bola_idor reasoning memory with session=secret",
  });

  assert.deepEqual(summary, {
    autonomousCandidateContext: null,
    campaignId: "campaign_1",
    dispatchAllowed: false,
    executionAllowed: false,
    latestReviewPlan: {
      campaignId: "campaign_1",
      dispatchAllowed: false,
      evidencePlan: ["Collect redacted summaries only."],
      executionAllowed: false,
      hypothesis: "[已脱敏]",
      nextAllowedAction: "验证前请审核假设看板并请求审核。",
      planId: "research_plan_1",
      refutationQuestions: ["Can redacted provenance disprove this"],
      reportSubmissionAllowed: false,
      requiredHumanGates: ["范围守卫审核"],
      safetyGate: "仅作建议性计划",
      status: "已起草",
      taskId: "task_1",
      validationAllowed: false,
    },
    latestRefutationDecision: {
      approvalId: "approval_1",
      campaignId: "campaign_1",
      decision: "需要补充证据",
      decisionId: "refutation_decision_1",
      dispatchAllowed: false,
      executionAllowed: false,
      nextAllowedAction: "验证前请收集脱敏证据或完善假设。",
      planId: "research_plan_1",
      rationale: "[已脱敏]",
      refutationAnswers: ["Current artifact summaries do not prove missing checks."],
      reportSubmissionAllowed: false,
      taskId: "task_1",
      validationAllowed: false,
      validationRunId: "validation_run_1",
    },
    suggestedRefutationDecision: {
      decision: "需要验证审核",
      dispatchAllowed: false,
      executionAllowed: false,
      humanReviewRequired: true,
      nextAllowedAction: "准备经人工审核的验证计划，不执行验证。",
      planId: "auto_research_plan_1",
      rationale: "[已脱敏]",
      refutationAnswerCount: 0,
      refutationQuestionCount: 2,
      reportSubmissionAllowed: false,
      targetRef: "campaign:campaign_1",
      validationAllowed: false,
      validationMode: "双账号授权检查",
    },
    latestValidationFeedback: {
      approvalId: "approval_1",
      campaignId: "campaign_1",
      decisionId: "refutation_decision_1",
      dispatchAllowed: false,
      evidenceRefCount: 2,
      executionAllowed: false,
      feedbackStageId: "stage_feedback_1",
      findingConfirmationAllowed: false,
      nextAllowedAction: "晋级漏洞候选前，请审核验证证据。",
      outcome: "已观察",
      planId: "research_plan_1",
      reportSubmissionAllowed: false,
      safetyGate: "仅作建议性验证反馈",
      status: "证据已记录",
      taskId: "task_1",
      validationAllowed: false,
      validationRunId: "validation_run_1",
    },
    nextAllowedAction: "审核假设看板并规划非破坏性证据工作。",
    nonDestructivePlan: [
      "Review existing hypothesis board entries for Authorization=[已脱敏]",
      "仅收集已脱敏资料摘要和溯源计数。",
    ],
    playbookId: "bola_idor",
    priorityScore: 100,
    queueKey: "reasoning_memory:bola_idor",
    reportSubmissionAllowed: false,
    requiredHumanGates: [
      "范围守卫审核",
      "脱敏审核",
      "验证前需要人工审核",
    ],
    safetyGate: "仅作建议性记忆",
    source: "研究大脑推理记忆",
    status: "已排入审核队列",
    surfaceKey: "file_id:export",
    taskId: "task_1",
    title: "Review bola_idor reasoning memory with session=[已脱敏]",
  });
  assert.doesNotMatch(JSON.stringify(summary), /secret-token|session=secret|Authorization: Bearer/i);
  assert.doesNotMatch(
    JSON.stringify(summary),
    /request approval before validation|Approval required before validation|human-approved/i,
  );
});

test("toCampaignResearchTaskReviewSummary maps autonomous candidate context as advisory", () => {
  const summary = toCampaignResearchTaskReviewSummary({
    campaign_id: "campaign_1",
    dispatch_allowed: true,
    execution_allowed: true,
    latest_refutation_decision: null,
    latest_validation_feedback: null,
    latest_review_plan: null,
    next_allowed_action: "执行前请审核验证计划。",
    non_destructive_plan: ["准备经人工审核的验证计划，不执行验证。"],
    playbook_id: "bola_idor",
    priority_score: 88,
    queue_key: "autonomous_hunt:pipeline_run_1:hunt_queue_hypothesis_1",
    report_submission_allowed: true,
    required_human_gates: ["scope_guard_review", "approval_required_before_validation"],
    safety_gate: "awaiting_human_approval",
    source: "mythos_pipeline_autonomous_hunt_queue",
    status: "queued_review",
    surface_key: null,
    task_id: "task_1",
    title: "审核自动挖掘候选 hypothesis_1",
    autonomous_candidate_context: {
      blocked_actions: [
        "execute_live_validation",
        "touch_real_user_data",
        "submit_report",
      ],
      candidate_id: "hypothesis_1",
      candidate_status: "awaiting_human_approval",
      dispatch_allowed: true,
      execution_allowed: true,
      human_approval_required: true,
      hypothesis: "BOLA may expose Authorization: Bearer secret-token",
      pipeline_run_id: "pipeline_run_1",
      raw_priority_score: 111,
      quality_gate_reasons: [
        "required_evidence_missing",
        "Authorization: Bearer secret-token",
      ],
      evidence_focus: [
        "same_handler_authz_evidence",
        "Authorization: Bearer secret-token",
      ],
      evidence_needed: [
        "approved_test_object_id_matrix",
        "Authorization: Bearer secret-token",
      ],
      evidence_trace_summary: {
        artifact_kinds: ["api", "Authorization: Bearer secret-token"],
        report_submission_allowed: true,
        route_fact_count: 1,
        source_fact_count: 2,
        source_fact_types: ["authorization_gap_candidate", "session_token=secret-token"],
        trace_status: "traceable",
        traceable_source_fact_count: 2,
      },
      report_readiness: {
        next_allowed_action: "Prepare a submission-blocked draft for human 脱敏审查.",
        report_submission_allowed: true,
        required_evidence_count: 0,
        safe_validation_step_count: 2,
        status: "submission_blocked_draft_ready",
        submission_blocked: false,
        trace_status: "traceable",
      },
      refutation_questions: [
        "Can same-handler authorization evidence refute the missing access-control check candidate?",
        "Can existing redacted artifacts disprove this?",
        "Does 范围守卫 allow validation?",
      ],
      refutation_status: "needs_evidence",
      required_evidence: [
        "independent_refutation_or_static_rule",
        "policy",
        "Authorization: Bearer secret-token",
      ],
      satisfied_evidence: ["local_code_or_har_correlation"],
      report_submission_allowed: true,
      safety_notes: ["scope_guard_required", "human_review_required"],
      source_fact_types: ["authorization_gap_candidate", "sensitive_sink"],
      triage_signals: [
        "authorization_gap_candidate",
        "sensitive_sink_present",
        "human_approval_required",
      ],
      validation_allowed: true,
      validation_plan_status: "requires_approval",
      validation_steps: [
        "Use two authorized test accounts only.",
        "Do not touch real user data.",
      ],
    },
  });

  assert.deepEqual(summary.autonomousCandidateContext, {
    blockedActions: [
      "执行实时验证",
      "已阻断操作",
      "提交报告",
    ],
    candidateId: "hypothesis_1",
    candidateStatus: "等待人工审核",
    dispatchAllowed: false,
    evidenceNeeded: ["已批准测试对象 ID 矩阵", "[已脱敏]"],
    evidenceTraceSummary: {
      artifactKinds: ["API", "[已脱敏]"],
      reportSubmissionAllowed: false,
      routeFactCount: 1,
      sourceFactCount: 2,
      sourceFactTypes: ["访问控制缺口候选", "[已脱敏]"],
      traceStatus: "traceable",
      traceableSourceFactCount: 2,
    },
    reportReadiness: {
      nextAllowedAction: "Prepare a submission-blocked draft for human 脱敏审查.",
      reportSubmissionAllowed: false,
      requiredEvidenceCount: 0,
      safeValidationStepCount: 2,
      status: "submission_blocked_draft_ready",
      submissionBlocked: true,
      traceStatus: "traceable",
    },
    evidenceFocus: ["同处理器访问控制证据", "[已脱敏]"],
    executionAllowed: false,
    humanApprovalRequired: true,
    hypothesis: "[已脱敏]",
    pipelineRunId: "pipeline_run_1",
    rawPriorityScore: 100,
    qualityGateReasons: ["缺少必需证据", "[已脱敏]"],
    refutationQuestions: [
      "Can same-handler authorization evidence refute the missing access-control check candidate",
      "Can existing redacted artifacts disprove this",
      "Does 范围守卫 allow validation",
    ],
    refutationStatus: "需要补充证据",
    requiredEvidence: [
      "独立反证或静态规则",
      "策略",
      "[已脱敏]",
    ],
    satisfiedEvidence: ["本地代码或 HAR 关联"],
    reportSubmissionAllowed: false,
    safetyNotes: ["需要范围守卫审核", "需要人工审核"],
    sourceFactTypes: ["访问控制缺口候选", "敏感汇点"],
    triageSignals: [
      "访问控制缺口候选",
      "存在敏感汇点",
      "需要人工审核",
    ],
    validationAllowed: false,
    validationPlanStatus: "需要审核",
    validationSteps: [
      "Use two authorized test accounts only.",
      "验证步骤已脱敏",
    ],
  });
  assert.equal(summary.executionAllowed, false);
  assert.equal(summary.dispatchAllowed, false);
  assert.equal(summary.reportSubmissionAllowed, false);
  assert.doesNotMatch(JSON.stringify(summary), /secret-token|Authorization: Bearer/i);
  assert.doesNotMatch(
    JSON.stringify(summary),
    /Awaiting human approval|Requires approval|human-approved/i,
  );
});

test("toCampaignValidationQueueSummaries redacts approval details for display", () => {
  const summaries = toCampaignValidationQueueSummaries([
    {
      ...controlCenter.approvals[0],
      asset: "https://api.example.com/path?cookie=session=secret",
      plan_digest: "plan_digest_1",
      reason: "Needs approval; Authorization: Bearer secret-token",
      validation_mode: "two_account_authorization_check",
    },
    {
      ...controlCenter.approvals[0],
      approval_type: "",
      asset: "https://api.example.com",
      id: "approval_2",
      reason: "Approval required",
      requested_action: null,
      task_id: null,
      validation_mode: null,
    },
  ]);

  assert.deepEqual(summaries, [
    {
      approvalType: "验证批次",
      asset: "api.example.com/path",
      createdAt: "2026-07-05T00:00:00Z",
      expiresAt: null,
      id: "approval_1",
      planDigest: "plan_digest_1",
      reason: "需要审核; Authorization=[已脱敏]",
      requestedAction: "双账号授权检查",
      runId: null,
      safetyGateState: "等待审核门",
      status: "待处理",
      taskId: "task_1",
      validationMode: "双账号授权检查",
      nextAction: "审核门记录后，再执行范围守卫预检。",
    },
    {
      approvalType: "审核门",
      asset: "api.example.com",
      createdAt: "2026-07-05T00:00:00Z",
      expiresAt: null,
      id: "approval_2",
      planDigest: null,
      reason: "需要审核",
      requestedAction: null,
      runId: null,
      safetyGateState: "等待审核门",
      status: "待处理",
      taskId: null,
      validationMode: null,
      nextAction: "审核门记录后，再执行范围守卫预检。",
    },
  ]);
  assert.doesNotMatch(JSON.stringify(summaries), /secret-token|session=secret|cookie=session/i);
  assert.doesNotMatch(JSON.stringify(summaries), /Awaiting approval|Needs approval|authorization check|approvalType":"Approval/i);
});

test("toCampaignValidationRunSummaries keeps validation run audit state redacted", () => {
  const summaries = toCampaignValidationRunSummaries([
    {
      allowed_to_execute: false,
      approval_id: null,
      approval_required: true,
      campaign_id: "campaign_1",
      created_at: "2026-07-05T00:00:00Z",
      evidence_ref_count: 0,
      finished_at: null,
      id: "validation_run_1",
      plan_digest: "plan_digest_1",
      safety_gate_state: "awaiting_approval",
      status: "awaiting_approval",
      summary: "Needs approval; Authorization: Bearer secret-token",
      target_ref: "candidate:idor?token=secret-token",
      task_id: "task_1",
      validation_mode: "two_account_authorization_check",
    },
  ]);

  assert.deepEqual(summaries, [
    {
      allowedToExecute: false,
      approvalId: null,
      approvalRequired: true,
      createdAt: "2026-07-05T00:00:00Z",
      evidenceRefCount: 0,
      executionStarted: false,
      executionState: "等待审核门",
      finishedAt: null,
      id: "validation_run_1",
      attentionState: "缺少审核门",
      planDigest: "plan_digest_1",
      preflightPassed: false,
      safetyGateState: "等待审核门",
      status: "等待审核门",
      summary: "需要审核; Authorization=[已脱敏]",
      targetRef: "candidate:idor",
      taskId: "task_1",
      validationMode: "双账号授权检查",
      nextAction: "预检前请审核验证门。",
    },
  ]);
  assert.doesNotMatch(JSON.stringify(summaries), /secret-token|token=secret|authorization: bearer/i);
  assert.doesNotMatch(JSON.stringify(summaries), /Awaiting approval|authorization check/i);
});

test("toCampaignValidationRunSummaries marks approved validation as preflight-required", () => {
  const summaries = toCampaignValidationRunSummaries([
    {
      allowed_to_execute: false,
      approval_id: "approval_1",
      approval_required: true,
      campaign_id: "campaign_1",
      created_at: "2026-07-05T00:00:00Z",
      evidence_ref_count: 0,
      finished_at: null,
      id: "validation_run_approved",
      plan_digest: "plan_digest_1",
      safety_gate_state: "approved_validation_record",
      status: "ready",
      summary: "Approved for preflight only.",
      target_ref: "campaign:campaign_1",
      task_id: "task_1",
      validation_mode: "two_account_authorization_check",
    },
  ]);

  assert.equal(summaries[0].allowedToExecute, false);
  assert.equal(summaries[0].executionState, "需要预检");
  assert.equal(summaries[0].attentionState, "需要预检");
  assert.equal(summaries[0].nextAction, "验证前请执行范围守卫预检。");
});

test("toCampaignValidationRunSummaries treats passed preflight as review state, not execution permission", () => {
  const summaries = toCampaignValidationRunSummaries([
    {
      allowed_to_execute: true,
      approval_id: "approval_1",
      approval_required: true,
      campaign_id: "campaign_1",
      created_at: "2026-07-05T00:00:00Z",
      evidence_ref_count: 0,
      execution_started: false,
      finished_at: null,
      id: "validation_run_preflight",
      plan_digest: "plan_digest_1",
      preflight_passed: true,
      safety_gate_state: "scope_guard_preflight_passed",
      status: "preflight_passed",
      summary: "范围守卫 preflight passed.",
      target_ref: "campaign:campaign_1",
      task_id: "task_1",
      validation_mode: "two_account_authorization_check",
    },
  ]);

  assert.equal(summaries[0].allowedToExecute, true);
  assert.equal(summaries[0].preflightPassed, true);
  assert.equal(summaries[0].executionStarted, false);
  assert.equal(summaries[0].executionState, "预检已通过");
  assert.equal(summaries[0].attentionState, "预检已通过");
  assert.equal(
    summaries[0].nextAction,
    "在晋级任何证据前审核人工验证观察。",
  );
  assert.doesNotMatch(summaries[0].nextAction, /record|execute|run|submit|dispatch/i);
});

test("toCampaignValidationRunSummaries labels started and blocked validation as audit state", () => {
  const summaries = toCampaignValidationRunSummaries([
    {
      allowed_to_execute: true,
      approval_id: "approval_1",
      approval_required: true,
      campaign_id: "campaign_1",
      created_at: "2026-07-05T00:00:00Z",
      evidence_ref_count: 0,
      execution_started: true,
      finished_at: null,
      id: "validation_run_started",
      plan_digest: "plan_digest_1",
      preflight_passed: true,
      safety_gate_state: "scope_guard_preflight_passed",
      status: "running",
      summary: "验证已启动.",
      target_ref: "campaign:campaign_1",
      task_id: "task_1",
      validation_mode: "two_account_authorization_check",
    },
    {
      allowed_to_execute: false,
      approval_id: null,
      approval_required: false,
      campaign_id: "campaign_1",
      created_at: "2026-07-05T00:00:00Z",
      evidence_ref_count: 0,
      finished_at: null,
      id: "validation_run_blocked",
      plan_digest: "plan_digest_1",
      safety_gate_state: "scope_guard_blocked",
      status: "blocked",
      summary: "预检已阻断.",
      target_ref: "campaign:campaign_1",
      task_id: "task_1",
      validation_mode: "two_account_authorization_check",
    },
  ]);

  assert.equal(summaries[0].executionState, "验证已启动");
  assert.equal(summaries[1].executionState, "预检已阻断");
  assert.doesNotMatch(JSON.stringify(summaries), /Execution started|Execution blocked/);
});

test("toCampaignArtifactSummaries exposes campaign artifact safety without raw material", () => {
  const summaries = toCampaignArtifactSummaries(campaignArtifacts);

  assert.deepEqual(summaries, [
    {
      asset: "api.example.com/path",
      createdAt: "2026-07-05T00:00:00Z",
      id: "artifact_safe",
      ingestionStatus: "已规范化",
      kind: "OpenAPI",
      reportChainAllowed: true,
      safetyBlockerCount: 0,
      sensitivityLabel: "低",
      sourceType: "内联演练运行",
      usageCount: 1,
      usageStages: [{ count: 1, label: "目标模型" }],
      usageTypes: [{ count: 1, label: "流程运行" }],
    },
    {
      asset: "api.example.com",
      createdAt: "2026-07-05T00:01:00Z",
      id: "artifact_blocked",
      ingestionStatus: "已规范化",
      kind: "HAR",
      reportChainAllowed: false,
      safetyBlockerCount: 2,
      sensitivityLabel: "敏感",
      sourceType: "人工上传",
      usageCount: 0,
      usageStages: [],
      usageTypes: [],
    },
  ]);
  assert.doesNotMatch(JSON.stringify(summaries), /secret-token|session=secret|raw payload|raw evidence/i);
});

test("toCampaignTimelineSummaries keeps stage refs counted but not displayed", () => {
  const summaries = toCampaignTimelineSummaries([
    {
      ...controlCenter.pipeline_stages[0],
      input_refs: ["campaign:campaign_1", "artifact:token=secret-token"],
      output_refs: ["evidence:session=secret"],
    },
  ]);

  assert.deepEqual(summaries, [
    {
      auditLabel: "活动轮次",
      id: "stage_1",
      inputRefCount: 2,
      isCycleReview: false,
      isLearningOutcome: false,
      isManualValidationResult: false,
      outputRefCount: 1,
      safetyGateState: "已阻断",
      stageKey: "活动轮次",
      stageOrder: 0,
      status: "已阻断",
      stopReason: "需要审核",
      taskId: "task_1",
    },
  ]);
  assert.doesNotMatch(JSON.stringify(summaries), /secret-token|session=secret|token=secret/i);
  assert.doesNotMatch(JSON.stringify(summaries), /Approval required/i);
});

test("toCampaignTimelineSummaries exposes safe timing and error summaries", () => {
  const summaries = toCampaignTimelineSummaries([
    {
      ...controlCenter.pipeline_stages[0],
      duration_seconds: 42,
      error_summary: "api_key=timeline-secret",
    },
  ]);

  assert.equal(summaries[0]?.durationSeconds, 42);
  assert.equal(summaries[0]?.errorSummary, "[已脱敏]");
  assert.doesNotMatch(JSON.stringify(summaries), /timeline-secret|api_key/i);
});

test("toCampaignTimelineSummaries highlights manual validation result stages without refs", () => {
  const summaries = toCampaignTimelineSummaries([
    {
      campaign_id: "campaign_1",
      created_at: "2026-07-05T00:10:00Z",
      id: "stage_manual_result",
      input_refs: ["validation_run:run_1?cookie=session=secret"],
      output_refs: ["validation_run:run_1", "evidence:Authorization: Bearer secret-token"],
      pipeline_run_id: null,
      payload: {
        evidence_ref_count: 1,
        execution_started: false,
        outcome: "observed",
        reviewer: "lead_reviewer",
        validation_result_review: {
          evidence_quality: "adequate",
          promotion_review_ready: false,
          quality_reasons: [
            "manual_result_recorded",
            "has_report_safe_evidence",
            "promotion_blocked_by_redaction_review",
          ],
          quality_score: 45,
          redaction_status: "redacted",
          safe_evidence_ref_count: 1,
          source_type: "manual_safe_observation",
          unsafe_evidence_ref_count: 1,
        },
      },
      safety_gate_state: "manual_evidence_recorded",
      stage_key: "validation_manual_result",
      stage_order: 3,
      status: "evidence_recorded",
      stop_reason: null,
      task_id: "task_1",
    },
  ]);

  assert.deepEqual(summaries, [
    {
      auditLabel: "人工验证结果",
      id: "stage_manual_result",
      inputRefCount: 1,
      isCycleReview: false,
      isLearningOutcome: false,
      isManualValidationResult: true,
      manualValidationReview: {
        evidenceQuality: "充分",
        promotionReviewReady: false,
        qualityReasons: [
          "人工结果已记录",
          "包含报告安全证据",
          "因脱敏审核阻断晋级",
        ],
        qualityScore: 45,
        redactionStatus: "已脱敏",
        safeEvidenceRefCount: 1,
        sourceType: "人工安全观察",
        unsafeEvidenceRefCount: 1,
      },
      outputRefCount: 2,
      safetyGateState: "人工证据已记录",
      stageKey: "人工验证结果",
      stageOrder: 3,
      status: "证据已记录",
      stopReason: null,
      taskId: "task_1",
    },
  ]);
  assert.doesNotMatch(JSON.stringify(summaries), /secret-token|session=secret|authorization: bearer/i);
});

test("toCampaignTimelineSummaries highlights research validation feedback stages", () => {
  const summaries = toCampaignTimelineSummaries([
    {
      campaign_id: "campaign_1",
      created_at: "2026-07-05T00:11:00Z",
      id: "stage_research_feedback",
      input_refs: [
        "research_plan:research_plan_1",
        "refutation_decision:refutation_decision_1",
        "authorization=secret-token",
      ],
      output_refs: ["validation_run:validation_run_1"],
      pipeline_run_id: null,
      safety_gate_state: "advisory_validation_feedback_only",
      stage_key: "research_task_validation_feedback",
      stage_order: 9,
      status: "evidence_recorded",
      stop_reason: null,
      task_id: "task_1",
    },
  ]);

  assert.deepEqual(summaries, [
    {
      auditLabel: "研究验证反馈",
      id: "stage_research_feedback",
      inputRefCount: 3,
      isCycleReview: false,
      isLearningOutcome: false,
      isManualValidationResult: false,
      isResearchValidationFeedback: true,
      outputRefCount: 1,
      safetyGateState: "仅作建议性验证反馈",
      stageKey: "研究任务验证反馈",
      stageOrder: 9,
      status: "证据已记录",
      stopReason: null,
      taskId: "task_1",
    },
  ]);
  assert.doesNotMatch(JSON.stringify(summaries), /secret-token|authorization=secret/i);
});

test("toCampaignTimelineSummaries highlights finding promotion blocked audit stages", () => {
  const summaries = toCampaignTimelineSummaries([
    {
      campaign_id: "campaign_1",
      created_at: "2026-07-05T00:13:00Z",
      id: "stage_promotion_blocked",
      input_refs: ["pipeline_run:run_1?Authorization=Bearer secret-token"],
      output_refs: [],
      pipeline_run_id: "run_1",
      safety_gate_state: "manual_review_required",
      stage_key: "finding_promotion_blocked",
      stage_order: 10,
      status: "blocked",
      stop_reason: "blocked_by_research_feedback_gate",
      task_id: null,
    },
  ]);

  assert.deepEqual(summaries, [
    {
      auditLabel: "漏洞候选晋级已阻断",
      id: "stage_promotion_blocked",
      inputRefCount: 1,
      isCycleReview: false,
      isFindingPromotionBlocked: true,
      isLearningOutcome: false,
      isManualValidationResult: false,
      outputRefCount: 0,
      safetyGateState: "需要人工审核",
      stageKey: "漏洞候选晋级已阻断",
      stageOrder: 10,
      status: "已阻断",
      stopReason: "被研究反馈审核门阻断",
      taskId: null,
    },
  ]);
  assert.doesNotMatch(JSON.stringify(summaries), /secret-token|authorization=secret/i);
});

test("toCampaignTimelineSummaries highlights finding candidate creation audit stages", () => {
  const summaries = toCampaignTimelineSummaries([
    {
      campaign_id: "campaign_1",
      created_at: "2026-07-05T00:14:00Z",
      id: "stage_promotion_created",
      input_refs: ["pipeline_run:run_1?Authorization=Bearer secret-token", "claim:claim_1"],
      output_refs: ["finding_candidate:finding_candidate_1"],
      pipeline_run_id: "run_1",
      safety_gate_state: "manual_review_required",
      stage_key: "finding_promotion",
      stage_order: 11,
      status: "candidate_created",
      stop_reason: null,
      task_id: null,
    },
  ]);

  assert.deepEqual(summaries, [
    {
      auditLabel: "漏洞候选晋级审核",
      id: "stage_promotion_created",
      inputRefCount: 2,
      isCycleReview: false,
      isFindingPromotion: true,
      isLearningOutcome: false,
      isManualValidationResult: false,
      outputRefCount: 1,
      safetyGateState: "需要人工审核",
      stageKey: "漏洞候选晋级",
      stageOrder: 11,
      status: "候选已创建",
      stopReason: null,
      taskId: null,
    },
  ]);
  assert.doesNotMatch(JSON.stringify(summaries), /secret-token|authorization=secret/i);
});

test("toCampaignTimelineSummaries exposes finding promotion provenance counts", () => {
  const summaries = toCampaignTimelineSummaries([
    {
      campaign_id: "campaign_1",
      created_at: "2026-07-05T00:14:00Z",
      id: "stage_promotion_created",
      input_refs: ["pipeline_run:run_1?Authorization=Bearer secret-token", "claim:claim_1"],
      output_refs: ["finding_candidate:finding_1"],
      payload: {
        claim_provenance_ref_count: 2,
        hunter_operating_action: "promote_to_finding_candidate",
        llm_audit: {
          error: null,
          mode: "audit_only",
          model: "hunter_operating_loop_v1",
          prompt_hash: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
          prompt_text_stored: false,
          provider: "internal_hunter_loop",
          purpose: "finding_promotion_recommendation",
        },
        review_evidence_ref_count: 2,
        raw_payload_processed: false,
      },
      pipeline_run_id: "run_1",
      safety_gate_state: "manual_review_required",
      stage_key: "finding_promotion",
      stage_order: 11,
      status: "candidate_created",
      stop_reason: null,
      task_id: null,
    },
  ]);

  assert.deepEqual(summaries, [
    {
      auditLabel: "漏洞候选晋级审核",
      id: "stage_promotion_created",
      inputRefCount: 2,
      isCycleReview: false,
      isFindingPromotion: true,
      isLearningOutcome: false,
      isManualValidationResult: false,
      hunterOperatingAction: "晋级为漏洞候选",
      llmAuditMode: "仅审核",
      llmAuditPromptHash: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
      llmAuditPromptTextStored: false,
      outputRefCount: 1,
      promotionProvenanceRefCount: 2,
      reviewEvidenceRefCount: 2,
      safetyGateState: "需要人工审核",
      stageKey: "漏洞候选晋级",
      stageOrder: 11,
      status: "候选已创建",
      stopReason: null,
      taskId: null,
    },
  ]);
  assert.doesNotMatch(
    JSON.stringify(summaries),
    /secret-token|authorization=secret|session=secret|prompt text|raw prompt/i,
  );
});

test("toCampaignTimelineSummaries highlights validation feedback review gates without rationale", () => {
  const summaries = toCampaignTimelineSummaries([
    {
      campaign_id: "campaign_1",
      created_at: "2026-07-05T00:15:00Z",
      id: "stage_validation_feedback_review",
      input_refs: [
        "campaign:campaign_1",
        "pipeline_stage:stage_feedback?Authorization=secret-token",
        "validation_run:validation_run_1",
      ],
      output_refs: ["pipeline_stage:stage_feedback"],
      payload: {
        decision: "allow_finding_promotion",
        execution_allowed: true,
        finding_confirmation_allowed: true,
        rationale: "Reviewed Authorization: Bearer secret-token",
        report_submission_allowed: true,
        validation_allowed: true,
      },
      pipeline_run_id: "run_1",
      safety_gate_state: "manual_review_required",
      stage_key: "research_task_validation_feedback_review",
      stage_order: 12,
      status: "completed",
      stop_reason: null,
      task_id: "task_1",
    },
  ]);

  assert.deepEqual(summaries, [
    {
      auditLabel: "验证反馈审核",
      decision: "允许晋级漏洞候选",
      executionAllowed: false,
      findingConfirmationAllowed: true,
      id: "stage_validation_feedback_review",
      inputRefCount: 3,
      isCycleReview: false,
      isLearningOutcome: false,
      isManualValidationResult: false,
      isValidationFeedbackReview: true,
      outputRefCount: 1,
      reportSubmissionAllowed: false,
      safetyGateState: "需要人工审核",
      stageKey: "研究任务验证反馈审核",
      stageOrder: 12,
      status: "已完成",
      stopReason: null,
      taskId: "task_1",
      validationAllowed: false,
    },
  ]);
  assert.doesNotMatch(JSON.stringify(summaries), /secret-token|Authorization|rationale/i);
});

test("toCampaignTimelineSummaries highlights research queue materialization safety counts", () => {
  const summaries = toCampaignTimelineSummaries([
    {
      campaign_id: "campaign_1",
      created_at: "2026-07-05T00:15:00Z",
      id: "stage_research_queue_materialized",
      input_refs: [
        "campaign:campaign_1",
        "research_queue:autonomous_hunt:run_1:hunt_queue_candidate_1?Authorization=secret",
        "pipeline_run:run_1",
        "candidate:candidate_1",
      ],
      output_refs: ["campaign_task:task_1"],
      payload: {
        blocked_action_count: 4,
        candidate_status: "awaiting_human_approval",
        human_approval_required: true,
        required_evidence: [
          "independent_refutation_or_static_rule",
          "policy",
          "Authorization: Bearer secret-token",
        ],
        refutation_question_count: 3,
        validation_step_count: 2,
        raw_hypothesis: "Authorization: Bearer secret-token",
      },
      pipeline_run_id: "run_1",
      safety_gate_state: "manual_review_required",
      stage_key: "research_queue_materialized",
      stage_order: 12,
      status: "queued_review",
      stop_reason: null,
      task_id: "task_1",
    },
  ]);

  assert.deepEqual(summaries, [
    {
      auditLabel: "研究审核已排队",
      blockedActionCount: 4,
      candidateStatus: "等待人工审核",
      humanApprovalRequired: true,
      id: "stage_research_queue_materialized",
      inputRefCount: 4,
      isCycleReview: false,
      isLearningOutcome: false,
      isManualValidationResult: false,
      isResearchQueueMaterialized: true,
      outputRefCount: 1,
      refutationQuestionCount: 3,
      requiredEvidence: [
        "独立反证或静态规则",
        "策略",
        "[已脱敏]",
      ],
      safetyGateState: "需要人工审核",
      stageKey: "研究队列已生成",
      stageOrder: 12,
      status: "已排入审核队列",
      stopReason: null,
      taskId: "task_1",
      validationStepCount: 2,
    },
  ]);
  assert.doesNotMatch(JSON.stringify(summaries), /secret-token|Authorization\s*[:=]|raw_hypothesis/i);
});

test("toCampaignTimelineSummaries highlights research plan audit counts without raw text", () => {
  const summaries = toCampaignTimelineSummaries([
    {
      campaign_id: "campaign_1",
      created_at: "2026-07-05T00:16:00Z",
      id: "stage_research_plan",
      input_refs: ["campaign:campaign_1", "campaign_task:task_1"],
      output_refs: ["research_plan:plan_1"],
      payload: {
        blocked_action_count: 4,
        candidate_id: "candidate_1",
        evidence_focus_count: 2,
        evidence_step_count: 2,
        has_authorization_gap_candidate: true,
        human_approval_required: true,
        priority_reason_count: 3,
        raw_hypothesis: "Authorization: Bearer secret-token",
        refutation_question_count: 3,
        required_evidence: [
          "independent_refutation_or_static_rule",
          "policy",
          "Authorization: Bearer secret-token",
        ],
        source_fact_type_count: 1,
        triage_signal_count: 1,
      },
      pipeline_run_id: "run_1",
      safety_gate_state: "advisory_plan_only",
      stage_key: "research_task_review_plan",
      stage_order: 13,
      status: "drafted",
      stop_reason: null,
      task_id: "task_1",
    },
  ]);

  assert.deepEqual(summaries, [
    {
      auditLabel: "研究计划已起草",
      blockedActionCount: 4,
      evidenceFocusCount: 2,
      evidenceStepCount: 2,
      hasAuthorizationGapCandidate: true,
      humanApprovalRequired: true,
      id: "stage_research_plan",
      inputRefCount: 2,
      isCycleReview: false,
      isLearningOutcome: false,
      isManualValidationResult: false,
      isResearchPlan: true,
      outputRefCount: 1,
      priorityReasonCount: 3,
      refutationQuestionCount: 3,
      requiredEvidence: [
        "独立反证或静态规则",
        "策略",
        "[已脱敏]",
      ],
      sourceFactTypeCount: 1,
      safetyGateState: "仅作建议性计划",
      stageKey: "研究任务审核计划",
      stageOrder: 13,
      status: "已起草",
      stopReason: null,
      taskId: "task_1",
      triageSignalCount: 1,
    },
  ]);
  assert.doesNotMatch(JSON.stringify(summaries), /secret-token|Authorization\s*[:=]|raw_hypothesis/i);
});

test("toCampaignTimelineSummaries highlights refutation decision gates without raw answers", () => {
  const summaries = toCampaignTimelineSummaries([
    {
      campaign_id: "campaign_1",
      created_at: "2026-07-05T00:17:00Z",
      id: "stage_refutation_decision",
      input_refs: ["campaign:campaign_1", "campaign_task:task_1", "research_plan:plan_1"],
      output_refs: [
        "refutation_decision:decision_1",
        "approval:approval_1",
        "validation_run:validation_run_1",
      ],
      payload: {
        approval_created: true,
        blocked_action_count: 4,
        decision: "needs_validation_review",
        evidence_focus_count: 2,
        has_authorization_gap_candidate: true,
        human_approval_required: true,
        priority_reason_count: 3,
        raw_answer: "Authorization: Bearer secret-token",
        refutation_answer_count: 1,
        source_fact_type_count: 1,
        triage_signal_count: 1,
        validation_run_created: true,
      },
      pipeline_run_id: "run_1",
      safety_gate_state: "advisory_refutation_only",
      stage_key: "research_task_refutation_decision",
      stage_order: 14,
      status: "needs_validation_review",
      stop_reason: null,
      task_id: "task_1",
    },
  ]);

  assert.deepEqual(summaries, [
    {
      approvalCreated: true,
      auditLabel: "反证决策",
      blockedActionCount: 4,
      decision: "需要验证审核",
      evidenceFocusCount: 2,
      hasAuthorizationGapCandidate: true,
      humanApprovalRequired: true,
      id: "stage_refutation_decision",
      inputRefCount: 3,
      isCycleReview: false,
      isLearningOutcome: false,
      isManualValidationResult: false,
      isResearchRefutationDecision: true,
      outputRefCount: 3,
      priorityReasonCount: 3,
      refutationAnswerCount: 1,
      sourceFactTypeCount: 1,
      safetyGateState: "仅作建议性反证",
      stageKey: "研究任务反证决策",
      stageOrder: 14,
      status: "需要验证审核",
      stopReason: null,
      taskId: "task_1",
      triageSignalCount: 1,
      validationRunCreated: true,
    },
  ]);
  assert.doesNotMatch(JSON.stringify(summaries), /secret-token|Authorization\s*[:=]|raw_answer/i);
});

test("toCampaignTimelineSummaries highlights advisory learning outcome stages without refs", () => {
  const summaries = toCampaignTimelineSummaries([
    {
      campaign_id: "campaign_1",
      created_at: "2026-07-05T00:12:00Z",
      id: "stage_learning_result",
      input_refs: ["pipeline_run:run_1?cookie=session=secret"],
      output_refs: ["learning_signal:signal_1", "notes:Authorization: Bearer secret-token"],
      pipeline_run_id: "run_1",
      safety_gate_state: "advisory_memory_only",
      stage_key: "learning_outcome_recorded",
      stage_order: 4,
      status: "recorded",
      stop_reason: null,
      task_id: "task_1",
    },
  ]);

  assert.deepEqual(summaries, [
    {
      auditLabel: "建议性大脑学习",
      id: "stage_learning_result",
      inputRefCount: 1,
      isCycleReview: false,
      isLearningOutcome: true,
      isManualValidationResult: false,
      outputRefCount: 2,
      safetyGateState: "仅作建议性记忆",
      stageKey: "学习结果已记录",
      stageOrder: 4,
      status: "已记录",
      stopReason: null,
      taskId: "task_1",
    },
  ]);
  assert.doesNotMatch(JSON.stringify(summaries), /secret-token|session=secret|authorization: bearer/i);
});

test("toCampaignTimelineSummaries highlights cycle review gates without refs", () => {
  const summaries = toCampaignTimelineSummaries([
    {
      campaign_id: "campaign_1",
      created_at: "2026-07-05T00:14:00Z",
      id: "stage_cycle_review",
      input_refs: ["campaign:campaign_1?cookie=session=secret"],
      output_refs: ["pipeline_run:run_1", "notes:Authorization: Bearer secret-token"],
      pipeline_run_id: null,
      safety_gate_state: "allowed",
      stage_key: "campaign_cycle_review",
      stage_order: 5,
      status: "awaiting_review",
      stop_reason: "campaign_cycle_review_required",
      task_id: null,
    },
  ]);

  assert.deepEqual(summaries, [
    {
      auditLabel: "活动周期审核",
      id: "stage_cycle_review",
      inputRefCount: 1,
      isCycleReview: true,
      isLearningOutcome: false,
      isManualValidationResult: false,
      outputRefCount: 2,
      safetyGateState: "已允许",
      stageKey: "活动周期审核",
      stageOrder: 5,
      status: "等待审核",
      stopReason: "需要审核活动周期",
      taskId: null,
    },
  ]);
  assert.doesNotMatch(JSON.stringify(summaries), /secret-token|session=secret|authorization: bearer/i);
});

test("toCampaignBrainSummary keeps 研究大脑 advisory and redacted", () => {
  const summary = toCampaignBrainSummary(brainProfile);

  assert.equal(summary.programId, "program_example");
  assert.equal(summary.programName, "示例项目");
  assert.equal(summary.programScore, 84);
  assert.equal(summary.objectCount, 2);
  assert.equal(summary.roleCount, 2);
  assert.equal(summary.sensitiveActionCount, 1);
  assert.equal(summary.signalCount, 1);
  assert.equal(summary.appliedLessonCount, 1);
  assert.equal(summary.skippedLessonCount, 1);
  assert.equal(summary.advisoryOnly, true);
  assert.equal(summary.executionAllowed, false);
  assert.deepEqual(summary.reasoningMemory, {
    highestReasoningReviewScore: 88,
    learningSignalContextCount: 2,
    candidateContextCount: 3,
    topPlaybooks: [
      {
        candidateContextCount: 3,
        highestReasoningReviewScore: 88,
        learningSignalContextCount: 2,
        playbookId: "idor_role_boundary",
      },
    ],
    safetyNotes: [
      "仅作建议性记忆",
      "执行需经人工审核",
      "不确认漏洞",
    ],
  });
  assert.equal(summary.topSurfaces[0].path, "/workspaces/{id}/owners");
  assert.equal(summary.recentSignals[0].notes, "Triager accepted; cookie=[已脱敏]");
  assert.equal(summary.appliedLessons[0].reasons[1], "[已脱敏]");
  assert.doesNotMatch(JSON.stringify(summary), /secret-token|session=secret|token=secret/i);
});

test("campaign display mappers suppress restricted raw research text", () => {
  const timeline = toCampaignTimelineSummaries([
    {
      ...controlCenter.pipeline_stages[0],
      stop_reason:
        "scanner stdout: GET /private Authorization: Bearer secret-token for alice@example.com",
    },
  ]);
  const brain = toCampaignBrainSummary({
    ...brainProfile,
    recent_learning_signals: [
      {
        ...brainProfile.recent_learning_signals[0],
        notes: "policy text: targets outside scope are excluded; personal data present",
      },
    ],
  });
  const drafts = toCampaignReportDraftSummaries([
    {
      ...reportPreview,
      safety_notes: ["raw evidence: full request response transcript"],
      title: "raw payload: POST /api/private jwt=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.signature",
      claim_ledger: [
        {
          ...reportPreview.claim_ledger[0],
          text: "raw evidence: admin response body with production user data",
        },
      ],
    },
  ]);

  const display = JSON.stringify({ timeline, brain, drafts });
  assert.doesNotMatch(display, /scanner stdout|policy text|raw payload|raw evidence/i);
  assert.doesNotMatch(display, /GET \/private|targets outside scope|POST \/api\/private|admin response body/i);
  assert.doesNotMatch(display, /alice@example\.com|eyJhbGciOiJIUzI1NiJ9|personal data|production user/i);
});

test("toCampaignLearningReviewSummary explains campaign learning review without raw feedback", () => {
  const summary = toCampaignLearningReviewSummary(
    {
      ...controlCenter,
      blocked_reasons: [],
      pipeline_stages: [
        ...controlCenter.pipeline_stages,
        {
          campaign_id: "campaign_1",
          created_at: "2026-07-05T00:02:00Z",
          id: "stage_report_preview_1",
          input_refs: ["campaign:campaign_1?session=secret"],
          output_refs: ["pipeline_run:run_1"],
          pipeline_run_id: "run_1",
          safety_gate_state: "awaiting_review",
          stage_key: "campaign_report_preview",
          stage_order: 20,
          status: "awaiting_review",
          stop_reason: null,
          task_id: "task_1",
        },
        {
          campaign_id: "campaign_1",
          created_at: "2026-07-05T00:03:00Z",
          id: "stage_report_preview_2",
          input_refs: ["campaign:campaign_1"],
          output_refs: ["pipeline_run:run_1"],
          pipeline_run_id: "run_1",
          safety_gate_state: "awaiting_review",
          stage_key: "campaign_report_preview",
          stage_order: 21,
          status: "awaiting_review",
          stop_reason: null,
          task_id: "task_1",
        },
      ],
      safe_next_action: "review_learning_outcome",
    },
    brainProfile,
  );

  assert.deepEqual(summary, {
    advisoryOnly: true,
    appliedLessonCount: 1,
    executionAllowed: false,
    linkedRunCount: 1,
    recentSignalCount: 1,
    reviewReady: true,
    safeNextAction: "审核学习结果",
    skippedLessonCount: 1,
    strongEvidenceSignalCount: 1,
  });
  assert.doesNotMatch(JSON.stringify(summary), /secret-token|session=secret|authorization: bearer/i);
});

test("toCampaignCodebaseMapView summarizes code facts without raw scanner leakage", () => {
  const view = toCampaignCodebaseMapView({
    maps: [
      {
        authz_check_count: 1,
        campaign_id: "campaign_1",
        commit_ref: "abc123",
        created_at: "2026-07-05T00:00:00Z",
        handler_count: 2,
        id: "codebase_map_1",
        model_count: 1,
        provenance_refs: ["artifact:repo_snapshot"],
        repository: "authorized/service",
        route_count: 2,
        safety_gate_state: "allowed",
        sensitive_sink_count: 1,
        source_ref: "artifact:repo_snapshot",
        status: "mapped",
      },
    ],
    facts: [
      {
        authz_hint: "owner_or_admin",
        campaign_id: "campaign_1",
        codebase_map_id: "codebase_map_1",
        created_at: "2026-07-05T00:00:00Z",
        fact_type: "route_handler",
        id: "codebase_fact_1",
        provenance_refs: ["codebase_map:route:1"],
        route_method: "GET",
        route_path: "/users/{id}",
        sensitivity_label: "low",
        source_path: "apps/api/users.py?token=secret-token",
        symbol_name: "get_user",
      },
      {
        authz_hint: "scanner stdout",
        campaign_id: "campaign_1",
        codebase_map_id: "codebase_map_1",
        created_at: "2026-07-05T00:00:00Z",
        fact_type: "route_handler",
        id: "codebase_fact_2",
        provenance_refs: ["codebase_map:route:2"],
        route_method: "POST",
        route_path: "/admin",
        sensitivity_label: "high",
        source_path: "apps/api/admin.py",
        symbol_name: "admin_panel",
      },
      {
        authz_hint: "missing_handler_authz_check",
        campaign_id: "campaign_1",
        codebase_map_id: "codebase_map_1",
        created_at: "2026-07-05T00:00:00Z",
        fact_type: "authorization_gap_candidate",
        id: "codebase_fact_3",
        provenance_refs: ["codebase_map:route:2"],
        route_method: "POST",
        route_path: "/admin",
        sensitivity_label: "high",
        source_path: "apps/api/admin.py",
        symbol_name: "admin_panel",
      },
    ],
    scanner_runs: [
      {
        campaign_id: "campaign_1",
        candidate_count: 2,
        codebase_map_id: "codebase_map_1",
        command_hash: "sha256:scanner-command",
        created_at: "2026-07-05T00:00:00Z",
        finding_count: 2,
        id: "scanner_run_1",
        safety_gate_state: "allowed",
        status: "candidate_findings",
        summary: "Static candidates only; Authorization: Bearer secret-token",
        tool_name: "semgrep",
      },
    ],
  });

  assert.equal(view.routeCount, 2);
  assert.equal(view.authzCheckCount, 1);
  assert.equal(view.authorizationGapCandidateCount, 1);
  assert.equal(view.candidateCount, 2);
  assert.equal(view.facts[0].sourcePath, "apps/api/users.py");
  assert.equal(view.facts[1].authzHint, "访问控制提示");
  assert.equal(view.facts[2].authzHint, "缺少处理器访问控制检查");
  assert.equal(view.facts[2].factType, "访问控制缺口候选");
  assert.equal(view.scannerRuns[0].summary, "Static candidates only; Authorization=[已脱敏]");
  assert.doesNotMatch(JSON.stringify(view), /secret-token|token=secret|authorization: bearer/i);
  assert.doesNotMatch(JSON.stringify(view), /confirmed finding|vulnerability/i);
  assert.doesNotMatch(JSON.stringify(view), /Authz hint/);
});

test("toCampaignEvidenceReviewSummaries keeps claim evidence review redacted and gated", () => {
  const summaries = toCampaignEvidenceReviewSummaries([reportPreview]);

  assert.equal(summaries.length, 2);
  assert.equal(summaries[0].runId, "run_1");
  assert.equal(summaries[0].claimId, "claim_1");
  assert.equal(summaries[0].claimText, "Observed access-control drift; token=[已脱敏]");
  assert.equal(summaries[0].evidenceRefCount, 2);
  assert.equal(summaries[0].provenanceRefCount, 1);
  assert.equal(summaries[0].reviewEvidenceRefCount, 1);
  assert.equal(summaries[0].reportChainEligible, true);
  assert.equal(summaries[0].reviewRationale, "已人工审核 with cookie=[已脱敏]");
  assert.equal(summaries[0].reviewStatus, "已确认的观察事实");
  assert.equal(summaries[0].status, "报告审核受控");
  assert.equal(summaries[1].reportChainEligible, false);
  assert.deepEqual(summaries[1].readinessBlockers, ["缺少证据引用"]);
  assert.doesNotMatch(JSON.stringify(summaries), /secret-token|session=secret|authorization: bearer/i);
  assert.doesNotMatch(
    [
      summaries[0].reviewRationale,
      summaries[0].reviewStatus,
      summaries[0].status,
      summaries[1].reviewStatus,
      summaries[1].status,
    ].join(" "),
    /confirmed|eligible|ready|submission|execute/i,
  );
});

test("toCampaignResearchFeedbackEvidenceSummaries keeps validation feedback promotion-gated", () => {
  const summaries = toCampaignResearchFeedbackEvidenceSummaries([
    {
      autonomous_candidate_context: null,
      campaign_id: "campaign_1",
      dispatch_allowed: true,
      execution_allowed: true,
      latest_refutation_decision: null,
      latest_review_plan: null,
      latest_validation_feedback: {
        approval_id: "approval_1",
        campaign_id: "campaign_1",
        decision_id: "refutation_decision_1",
        dispatch_allowed: true,
        evidence_ref_count: 2,
        execution_allowed: true,
        feedback_stage_id: "stage_feedback_1",
        finding_confirmation_allowed: true,
        next_allowed_action: "晋级漏洞候选前，请审核验证证据。",
        outcome: "observed",
        plan_id: "research_plan_1",
        promotion_gate: {
          status: "manual_review_required",
          reason: "research_validation_feedback_is_advisory",
          provenance_refs: [
            "campaign:campaign_1",
            "campaign_task:task_1",
            "research_plan:research_plan_1",
            "refutation_decision:refutation_decision_1",
            "approval:approval_1",
            "validation_run:validation_run_1",
          ],
          evidence_ref_count: 2,
          finding_promotion_allowed: true,
          report_submission_allowed: true,
          next_allowed_action: "Unsafe upstream action should not win.",
        },
        report_submission_allowed: true,
        safety_gate: "advisory_validation_feedback_only",
        status: "evidence_recorded",
        task_id: "task_1",
        validation_allowed: true,
        validation_run_id: "validation_run_1",
      },
      next_allowed_action: "审核假设看板并规划非破坏性证据工作。",
      non_destructive_plan: [],
      playbook_id: "bola_idor",
      priority_score: 80,
      queue_key: "reasoning_memory:bola_idor",
      report_submission_allowed: true,
      required_human_gates: ["scope_guard_review"],
      safety_gate: "advisory_memory_only",
      source: "mythos_brain_reasoning_memory",
      status: "queued_review",
      surface_key: "file_id:export",
      task_id: "task_1",
      title: "研究反馈 with Authorization: Bearer secret-token",
    },
  ]);

  assert.deepEqual(summaries, [
    {
      approvalId: "approval_1",
      evidenceRefCount: 2,
      feedbackStageId: "stage_feedback_1",
      findingPromotionAllowed: false,
      nextAllowedAction: "晋级漏洞候选前，请审核验证证据。",
      outcome: "已观察",
      planId: "research_plan_1",
      promotionGate: "需要人工审核",
      promotionGateReason: "研究验证反馈仅作建议性参考",
      promotionProvenanceRefCount: 6,
      reviewTitle: "研究反馈 with Authorization=[已脱敏]",
      safetyGate: "仅作建议性验证反馈",
      status: "证据已记录",
      taskId: "task_1",
      validationRunId: "validation_run_1",
    },
  ]);
  assert.doesNotMatch(JSON.stringify(summaries), /secret-token|authorization: bearer/i);
});

test("toCampaignPromotionBlockReviewSummaries turns blocked feedback into review queue items", () => {
  const feedback = toCampaignResearchFeedbackEvidenceSummaries([
    {
      autonomous_candidate_context: null,
      campaign_id: "campaign_1",
      dispatch_allowed: true,
      execution_allowed: true,
      latest_refutation_decision: null,
      latest_review_plan: null,
      latest_validation_feedback: {
        approval_id: "approval_1",
        campaign_id: "campaign_1",
        decision_id: "refutation_decision_1",
        dispatch_allowed: true,
        evidence_ref_count: 2,
        execution_allowed: true,
        feedback_stage_id: "stage_feedback_1",
        finding_confirmation_allowed: true,
        next_allowed_action: "晋级漏洞候选前，请审核验证证据。",
        outcome: "observed",
        plan_id: "research_plan_1",
        promotion_gate: {
          status: "manual_review_required",
          reason: "blocked_by_research_feedback_gate",
          provenance_refs: ["Authorization: Bearer secret-token"],
          evidence_ref_count: 2,
          finding_promotion_allowed: true,
          report_submission_allowed: true,
          next_allowed_action: "Unsafe upstream action should not win.",
        },
        report_submission_allowed: true,
        safety_gate: "advisory_validation_feedback_only",
        status: "evidence_recorded",
        task_id: "task_1",
        validation_allowed: true,
        validation_run_id: "validation_run_1",
      },
      next_allowed_action: "审核假设看板并规划非破坏性证据工作。",
      non_destructive_plan: [],
      playbook_id: "bola_idor",
      priority_score: 80,
      queue_key: "reasoning_memory:bola_idor",
      report_submission_allowed: true,
      required_human_gates: ["scope_guard_review"],
      safety_gate: "advisory_memory_only",
      source: "mythos_brain_reasoning_memory",
      status: "queued_review",
      surface_key: "file_id:export",
      task_id: "task_1",
      title: "研究反馈 with Authorization: Bearer secret-token",
    },
  ]);

  const summaries = toCampaignPromotionBlockReviewSummaries(feedback);

  assert.deepEqual(summaries, [
    {
      approvalId: "approval_1",
      evidenceRefCount: 2,
      feedbackStageId: "stage_feedback_1",
      nextAllowedAction: "晋级漏洞候选前，请审核验证证据。",
      planId: "research_plan_1",
      promotionGateReason: "被研究反馈审核门阻断",
      promotionProvenanceRefCount: 1,
      reviewTitle: "研究反馈 with Authorization=[已脱敏]",
      taskId: "task_1",
      validationRunId: "validation_run_1",
    },
  ]);
  assert.equal(feedback[0].findingPromotionAllowed, false);
  assert.doesNotMatch(JSON.stringify(summaries), /secret-token|session=secret|authorization: bearer|cookie=session/i);
});

test("toCampaignValidationEvidenceReviewSummaries turns manual results into candidate evidence reviews", () => {
  const validationRuns: CampaignValidationRun[] = [
    {
      allowed_to_execute: true,
      approval_id: "approval_1",
      approval_required: true,
      campaign_id: "campaign_1",
      created_at: "2026-07-05T00:00:00Z",
      evidence_ref_count: 2,
      finished_at: "2026-07-05T00:05:00Z",
      id: "validation_1",
      plan_digest: "digest_1",
      safety_gate_state: "manual_evidence_recorded",
      status: "evidence_recorded",
      summary: "Manual observation recorded; cookie=session=secret",
      target_ref: "https://api.example.com/files?token=secret",
      task_id: "task_1",
      validation_mode: "two_account_authorization_check",
    },
    {
      allowed_to_execute: false,
      approval_id: "approval_2",
      approval_required: true,
      campaign_id: "campaign_1",
      created_at: "2026-07-05T00:06:00Z",
      evidence_ref_count: 0,
      finished_at: "2026-07-05T00:08:00Z",
      id: "validation_2",
      plan_digest: "digest_2",
      safety_gate_state: "manual_evidence_gap_recorded",
      status: "needs_evidence",
      summary: "Evidence redacted; Authorization: Bearer secret-token",
      target_ref: "api.example.com",
      task_id: "task_2",
      validation_mode: "manual_review",
    },
  ];

  const summaries = toCampaignValidationEvidenceReviewSummaries(validationRuns, [
    {
      campaign_id: "campaign_1",
      created_at: "2026-07-05T00:06:00Z",
      id: "stage_manual_validation_1",
      input_refs: ["validation_run:validation_1?Authorization=Bearer secret-token"],
      output_refs: ["validation_run:validation_1"],
      payload: {
        validation_result_review: {
          evidence_quality: "adequate",
          promotion_review_ready: false,
          quality_reasons: [
            "manual_result_recorded",
            "has_report_safe_evidence",
            "promotion_blocked_by_redaction_review",
          ],
          quality_score: 45,
          redaction_status: "redacted",
          safe_evidence_ref_count: 1,
          source_type: "manual_safe_observation",
          unsafe_evidence_ref_count: 1,
        },
      },
      pipeline_run_id: null,
      safety_gate_state: "manual_evidence_recorded",
      stage_key: "validation_manual_result",
      stage_order: 3,
      status: "evidence_recorded",
      stop_reason: null,
      task_id: "task_1",
    },
  ]);

  assert.deepEqual(summaries, [
    {
      candidateEvidenceState: "候选证据需要审核",
      evidenceRefCount: 2,
      nextReviewAction: "报告链使用前请审核脱敏、溯源与声明覆盖情况。",
      planDigest: "digest_1",
      preflightState: "人工结果已记录",
      reportChainState: "报告链需要审核",
      reviewGate: "approval_1",
      reviewItem: "task_1",
      manualValidationReview: {
        evidenceQuality: "充分",
        promotionReviewState: "漏洞候选晋级审核受控",
        qualityReasons: [
          "人工结果已记录",
          "包含报告安全证据",
          "因脱敏审核阻断晋级",
        ],
        qualityScore: 45,
        redactionStatus: "已脱敏",
        safeEvidenceRefCount: 1,
        sourceType: "人工安全观察",
        unsafeEvidenceRefCount: 1,
      },
      status: "证据已记录",
      summary: "Manual observation recorded; Cookie [已脱敏]",
      targetRef: "api.example.com/files",
      validationMode: "双账号授权检查",
      validationRunId: "validation_1",
    },
    {
      candidateEvidenceState: "证据缺口需要审核",
      evidenceRefCount: 0,
      nextReviewAction: "报告链使用前请收集脱敏证据引用。",
      planDigest: "digest_2",
      preflightState: "人工结果已记录",
      reportChainState: "报告链已阻断",
      reviewGate: "approval_2",
      reviewItem: "task_2",
      status: "需要补充证据",
      summary: "Evidence redacted; 授权信息 [已脱敏]",
      targetRef: "api.example.com",
      validationMode: "人工审核",
      validationRunId: "validation_2",
    },
  ]);
  assert.doesNotMatch(JSON.stringify(summaries), /secret-token|session=secret|authorization\s*[:=]|cookie=/i);
  assert.doesNotMatch(JSON.stringify(summaries), /eligible|confirmed|submission/i);
});

test("toCampaignValidationEvidenceQualitySummary counts review quality without raw evidence", () => {
  const summary = toCampaignValidationEvidenceQualitySummary([
    {
      candidateEvidenceState: "候选证据需要审核",
      evidenceRefCount: 2,
      manualValidationReview: {
        evidenceQuality: "强",
        promotionReviewState: "漏洞候选晋级审核需要人工决策",
        qualityReasons: ["Clean 脱敏审查"],
        qualityScore: 80,
        redactionStatus: "已清理",
        safeEvidenceRefCount: 3,
        sourceType: "人工安全观察",
        unsafeEvidenceRefCount: 0,
      },
      nextReviewAction: "报告链使用前请审核脱敏、溯源与声明覆盖情况。",
      planDigest: "digest_1",
      preflightState: "人工结果已记录",
      reportChainState: "报告链需要审核",
      reviewGate: "approval_1",
      reviewItem: "task_1",
      status: "证据已记录",
      summary: "人工结果已记录.",
      targetRef: "api.example.com",
      validationMode: "Fixture replay",
      validationRunId: "validation_1",
    },
    {
      candidateEvidenceState: "候选证据需要审核",
      evidenceRefCount: 1,
      manualValidationReview: {
        evidenceQuality: "充分",
        promotionReviewState: "漏洞候选晋级审核受控",
        qualityReasons: ["漏洞候选晋级已阻断 by 脱敏审查"],
        qualityScore: 45,
        redactionStatus: "已脱敏",
        safeEvidenceRefCount: 1,
        sourceType: "人工安全观察",
        unsafeEvidenceRefCount: 1,
      },
      nextReviewAction: "报告链使用前请审核脱敏、溯源与声明覆盖情况。",
      planDigest: "digest_2",
      preflightState: "人工结果已记录",
      reportChainState: "报告链需要审核",
      reviewGate: "approval_2",
      reviewItem: "task_2",
      status: "证据已记录",
      summary: "人工结果已记录.",
      targetRef: "api.example.com",
      validationMode: "Test account review",
      validationRunId: "validation_2",
    },
  ]);

  assert.deepEqual(summary, {
    cleanReviewCount: 1,
    gatedPromotionReviewCount: 1,
    redactedReviewCount: 1,
    reviewedEvidenceCount: 2,
    strongEvidenceCount: 1,
    unsafeEvidenceRefCount: 1,
  });
  assert.doesNotMatch(JSON.stringify(summary), /raw evidence|evidence_refs|secret-token|session=secret/i);
});

test("toCampaignReportDraftSummaries keeps report draft status redacted and gated", () => {
  const summaries = toCampaignReportDraftSummaries([
    {
      ...reportPreview,
      safety_notes: ["human_review_required", "cookie=session=secret"],
      title: "Private object access with Authorization: Bearer secret-token",
    },
  ]);

  assert.deepEqual(summaries, [
    {
      blockedClaimCount: 1,
      claimCount: 2,
      evidenceRefCount: 2,
      humanReviewRequired: true,
      readyClaimCount: 1,
      runId: "run_1",
      safetyNotes: ["需要人工审核", "cookie=[已脱敏]"],
      scopeStatus: "范围内",
      severity: "高",
      submissionBlocked: true,
      title: "Private object access with Authorization=[已脱敏]",
      topClaims: [
        "Observed access-control drift; token=[已脱敏]",
        "Model-only claim; session=[已脱敏]",
      ],
    },
  ]);
  assert.doesNotMatch(JSON.stringify(summaries), /secret-token|session=secret|authorization: bearer/i);
});

test("toCampaignReportDraftEvidenceSummary exposes manual validation state without raw evidence", () => {
  const validationRuns: CampaignValidationRun[] = [
    {
      allowed_to_execute: false,
      approval_id: "approval_1",
      approval_required: true,
      campaign_id: "campaign_1",
      created_at: "2026-07-05T00:00:00Z",
      evidence_ref_count: 2,
      finished_at: "2026-07-05T00:05:00Z",
      id: "validation_1",
      plan_digest: "digest_1",
      safety_gate_state: "manual_evidence_recorded",
      status: "evidence_recorded",
      summary: "Manual observation recorded; cookie=session=secret",
      target_ref: "https://api.example.com/files?token=secret",
      task_id: "task_1",
      validation_mode: "two_account_authorization_check",
    },
    {
      allowed_to_execute: false,
      approval_id: "approval_2",
      approval_required: true,
      campaign_id: "campaign_1",
      created_at: "2026-07-05T00:06:00Z",
      evidence_ref_count: 0,
      finished_at: "2026-07-05T00:08:00Z",
      id: "validation_2",
      plan_digest: "digest_2",
      safety_gate_state: "manual_evidence_gap_recorded",
      status: "needs_evidence",
      summary: "Evidence redacted; Authorization: Bearer secret-token",
      target_ref: "api.example.com",
      task_id: "task_2",
      validation_mode: "manual_review",
    },
  ];

  const summary = toCampaignReportDraftEvidenceSummary(validationRuns);

  assert.deepEqual(summary, {
    evidenceGapCount: 1,
    evidenceRefCount: 2,
    manualEvidenceCount: 1,
    validationRunCount: 2,
  });
  assert.doesNotMatch(JSON.stringify(summary), /secret-token|session=secret|authorization: bearer/i);
});

test("toCampaignFindingCandidateGateSummary exposes manual promotion readiness without raw evidence", () => {
  const researchFeedback = toCampaignResearchFeedbackEvidenceSummaries([
    {
      autonomous_candidate_context: null,
      campaign_id: "campaign_1",
      dispatch_allowed: true,
      execution_allowed: true,
      latest_refutation_decision: null,
      latest_review_plan: null,
      latest_validation_feedback: {
        approval_id: "approval_1",
        campaign_id: "campaign_1",
        decision_id: "refutation_decision_1",
        dispatch_allowed: true,
        evidence_ref_count: 2,
        execution_allowed: true,
        finding_confirmation_allowed: true,
        next_allowed_action: "晋级漏洞候选前，请审核验证证据。",
        outcome: "observed",
        plan_id: "research_plan_1",
        report_submission_allowed: true,
        safety_gate: "advisory_validation_feedback_only",
        status: "evidence_recorded",
        task_id: "task_1",
        validation_allowed: true,
        validation_run_id: "validation_run_1",
      },
      next_allowed_action: "审核假设看板并规划非破坏性证据工作。",
      non_destructive_plan: [],
      playbook_id: "bola_idor",
      priority_score: 80,
      queue_key: "reasoning_memory:bola_idor",
      report_submission_allowed: true,
      required_human_gates: ["scope_guard_review"],
      safety_gate: "advisory_memory_only",
      source: "mythos_brain_reasoning_memory",
      status: "queued_review",
      surface_key: "file_id:export",
      task_id: "task_1",
      title: "研究反馈 with Authorization: Bearer secret-token",
    },
  ]);
  const summary = toCampaignFindingCandidateGateSummary(
    [
      {
        ...reportPreview,
        claim_ledger: [
          ...reportPreview.claim_ledger,
          {
            ...reportPreview.claim_ledger[1],
            claim_id: "claim_3",
            readiness_blockers: ["Authorization: Bearer secret-token"],
            review_rationale: "Blocked because cookie=session=secret needs redaction.",
            text: "Blocked candidate; token=secret-token",
          },
        ],
        evidence_refs: ["Authorization: Bearer secret-token"],
      },
    ],
    researchFeedback,
    [
      {
        campaign_id: "campaign_1",
        created_at: "2026-07-05T00:13:00Z",
        id: "stage_promotion_blocked",
        input_refs: ["pipeline_run:run_1?Authorization=Bearer secret-token"],
        output_refs: [],
        pipeline_run_id: "run_1",
        safety_gate_state: "manual_review_required",
        stage_key: "finding_promotion_blocked",
        stage_order: 10,
        status: "blocked",
        stop_reason: "blocked_by_research_feedback_gate",
        task_id: null,
      },
      {
        campaign_id: "campaign_1",
        created_at: "2026-07-05T00:14:00Z",
        id: "stage_promotion_created",
        input_refs: ["pipeline_run:run_1", "claim:claim_1"],
        output_refs: ["finding_candidate:finding_1"],
        payload: {
          claim_provenance_ref_count: 2,
          review_evidence_ref_count: 2,
        },
        pipeline_run_id: "run_1",
        safety_gate_state: "manual_review_required",
        stage_key: "finding_promotion",
        stage_order: 11,
        status: "candidate_created",
        stop_reason: null,
        task_id: null,
      },
    ],
  );

  assert.deepEqual(summary, {
    blockedClaimCount: 2,
    eligibleClaimCount: 1,
    manualPromotionOnly: true,
    nextAllowedAction: "再次晋级漏洞候选前，请审核被阻断的晋级证据。",
    promotionAuditBlockedCount: 1,
    promotionAuditCreatedCount: 1,
    promotionAuditLatestReason: "被研究反馈审核门阻断",
    promotionAuditProvenanceRefCount: 2,
    promotionAuditReviewEvidenceRefCount: 2,
    requiredEvidenceBlockedCount: 0,
    researchEvidenceRefCount: 2,
    researchFeedbackCount: 1,
    researchPromotionBlockedCount: 1,
    readyRunIds: [],
    runCount: 1,
    status: "blocked_by_promotion_audit",
  });
  assert.doesNotMatch(JSON.stringify(summary), /secret-token|session=secret|authorization: bearer/i);
});

test("toCampaignFindingCandidateGateSummary exposes ready report preview run ids", () => {
  const summary = toCampaignFindingCandidateGateSummary([
    {
      ...reportPreview,
      run_id: "run_ready_1",
      claim_ledger: [
        {
          ...reportPreview.claim_ledger[0],
          claim_id: "claim_ready_1",
          readiness_blockers: [],
          review_evidence_refs: ["sanitized_request_response"],
          review_status: "confirmed_observed_fact",
          readiness_level: "human_reviewed_gated",
          text: "Ready claim with Authorization: Bearer secret-token",
        },
      ],
      evidence_refs: ["Authorization: Bearer secret-token"],
    },
  ]);

  assert.equal(summary.status, "ready_for_manual_promotion");
  assert.equal(
    summary.nextAllowedAction,
    "已审核声明需要在人工审核后由人工决定是否晋级。",
  );
  assert.doesNotMatch(summary.nextAllowedAction, /eligible|ready|confirmed|submission|execute/i);
  assert.deepEqual(summary.readyRunIds, ["run_ready_1"]);
  assert.doesNotMatch(JSON.stringify(summary), /human approval/i);
  assert.doesNotMatch(JSON.stringify(summary), /secret-token|authorization: bearer/i);
});

test("toCampaignFindingCandidateGateSummary blocks readiness on unresolved required evidence", () => {
  const summary = toCampaignFindingCandidateGateSummary(
    [
      {
        ...reportPreview,
        run_id: "run_ready_1",
        claim_ledger: [
          {
            ...reportPreview.claim_ledger[0],
            claim_id: "claim_ready_1",
            readiness_blockers: [],
            review_evidence_refs: ["sanitized_request_response"],
            review_status: "confirmed_observed_fact",
            readiness_level: "human_reviewed_gated",
            text: "Ready claim with Authorization: Bearer secret-token",
          },
        ],
        evidence_refs: ["Authorization: Bearer secret-token"],
      },
    ],
    [],
    [
      {
        campaign_id: "campaign_1",
        created_at: "2026-07-05T00:12:00Z",
        id: "stage_required_evidence",
        input_refs: ["campaign:campaign_1", "Authorization: Bearer secret-token"],
        output_refs: ["research_plan:research_plan_1"],
        payload: {
          required_evidence: ["independent_refutation_or_static_rule", "policy"],
        },
        pipeline_run_id: "run_ready_1",
        safety_gate_state: "advisory_plan_only",
        stage_key: "research_task_review_plan",
        stage_order: 8,
        status: "auto_drafted",
        stop_reason: null,
        task_id: "task_1",
      },
    ],
  );

  assert.equal(summary.eligibleClaimCount, 1);
  assert.equal(summary.requiredEvidenceBlockedCount, 1);
  assert.equal(summary.status, "blocked_by_required_evidence");
  assert.equal(
    summary.nextAllowedAction,
    "晋级漏洞候选前，请处理必需证据缺口。",
  );
  assert.deepEqual(summary.readyRunIds, []);
  assert.doesNotMatch(JSON.stringify(summary), /secret-token|authorization: bearer/i);
});

test("toCampaignFindingCandidateGateSummary blocks readiness on advisory validation feedback before promotion attempts", () => {
  const researchFeedback = toCampaignResearchFeedbackEvidenceSummaries([
    {
      autonomous_candidate_context: null,
      campaign_id: "campaign_1",
      dispatch_allowed: true,
      execution_allowed: true,
      latest_refutation_decision: null,
      latest_review_plan: null,
      latest_validation_feedback: {
        approval_id: "approval_1",
        campaign_id: "campaign_1",
        decision_id: "refutation_decision_1",
        dispatch_allowed: true,
        evidence_ref_count: 2,
        execution_allowed: true,
        finding_confirmation_allowed: true,
        next_allowed_action: "晋级漏洞候选前，请审核验证证据。",
        outcome: "observed",
        plan_id: "research_plan_1",
        promotion_gate: {
          status: "manual_review_required",
          reason: "research_validation_feedback_is_advisory",
          provenance_refs: [
            "campaign:campaign_1",
            "campaign_task:task_1",
            "Authorization: Bearer secret-token",
          ],
          evidence_ref_count: 2,
          finding_promotion_allowed: true,
          report_submission_allowed: true,
          next_allowed_action: "Unsafe upstream action should not win.",
        },
        report_submission_allowed: true,
        safety_gate: "advisory_validation_feedback_only",
        status: "evidence_recorded",
        task_id: "task_1",
        validation_allowed: true,
        validation_run_id: "validation_run_1",
      },
      next_allowed_action: "审核假设看板并规划非破坏性证据工作。",
      non_destructive_plan: [],
      playbook_id: "bola_idor",
      priority_score: 80,
      queue_key: "reasoning_memory:bola_idor",
      report_submission_allowed: true,
      required_human_gates: ["scope_guard_review"],
      safety_gate: "advisory_memory_only",
      source: "mythos_brain_reasoning_memory",
      status: "queued_review",
      surface_key: "file_id:export",
      task_id: "task_1",
      title: "研究反馈 with Authorization: Bearer secret-token",
    },
  ]);

  const summary = toCampaignFindingCandidateGateSummary(
    [reportPreview],
    researchFeedback,
    [],
  );

  assert.equal(summary.eligibleClaimCount, 1);
  assert.equal(summary.researchFeedbackCount, 1);
  assert.equal(summary.researchPromotionBlockedCount, 1);
  assert.equal(summary.promotionAuditBlockedCount, 0);
  assert.equal(summary.requiredEvidenceBlockedCount, 0);
  assert.equal(summary.status, "blocked_by_research_feedback");
  assert.equal(
    summary.nextAllowedAction,
    "晋级漏洞候选前，请审核验证反馈。",
  );
  assert.doesNotMatch(JSON.stringify(summary), /secret-token|authorization: bearer/i);
});

test("toCampaignHypothesisBoardSummaries ranks and redacts campaign candidates", () => {
  const runDetailWithSensitiveDisplayValues = {
    ...pipelineRunDetail,
    payload: {
      ...pipelineRunDetail.payload,
      hypothesis_assessments: [
        pipelineRunDetail.payload.hypothesis_assessments[0],
        {
          ...pipelineRunDetail.payload.hypothesis_assessments[1],
          exploit_chain: {
            ...pipelineRunDetail.payload.hypothesis_assessments[1].exploit_chain,
            primitives: [
              "object id swap",
              "Compare sanitized jwt eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.signature",
            ],
          },
          hypothesis:
            {
              ...pipelineRunDetail.payload.hypothesis_assessments[1].hypothesis,
              hypothesis: "Changing object id may expose private files for alice@example.com",
              source_facts: [
                {
                  authz_hint: "missing_handler_authz_check",
                  fact_ref: "codebase_fact:authorization_gap_candidate:/files/{file_id}/export",
                  fact_type: "authorization_gap_candidate",
                  route_method: "GET",
                  route_path: "/files/{file_id}/export",
                  source_path: "apps/api/routes/files.py?token=secret-token",
                  symbol_name: "export_file",
                },
                {
                  fact_ref: "codebase_fact:sensitive_sink:send_file",
                  fact_type: "sensitive_sink",
                  source_path: "apps/api/routes/files.py",
                  symbol_name: "send_file",
                },
              ],
            },
          hunter_assessment: {
            ...pipelineRunDetail.payload.hypothesis_assessments[1].hunter_assessment,
            evidence_focus: [
              "same_handler_authz_evidence",
              "missing_check_refutation_trace",
              "Authorization: Bearer secret-token",
            ],
            reasons: [
              "authorization_gap_candidate",
              "sensitive_sink_present",
              "human_approval_required",
            ],
          },
          refutation: {
            ...pipelineRunDetail.payload.hypothesis_assessments[1].refutation,
            questions: [
              "Can same-handler authorization evidence refute the missing access-control check candidate?",
              "Does ownership check bind workspace_id?",
              "Can personal data influence scope?",
            ],
          },
        },
      ],
    },
  };
  const summaries = toCampaignHypothesisBoardSummaries(
    [runDetailWithSensitiveDisplayValues],
    [
      {
        campaign_id: "campaign_1",
        dispatch_allowed: false,
        evidence_plan: ["Collect redacted summaries only."],
        execution_allowed: false,
        hypothesis: "Review export IDOR with Authorization: Bearer secret-token",
        next_allowed_action: "Review hypothesis board and request approval before validation.",
        plan_id: "research_plan_1",
        refutation_questions: ["Can ownership checks refute export access?"],
        report_submission_allowed: false,
        required_human_gates: ["scope_guard_review", "redaction_review"],
        safety_gate: "advisory_plan_only",
        status: "drafted",
        task_id: "task_1",
        validation_allowed: false,
      },
    ],
    [
      {
        blockedActionCount: 3,
        candidateStatus: "Awaiting human approval",
        evidenceTraceSummary: {
          artifactKinds: ["API"],
          reportSubmissionAllowed: false,
          routeFactCount: 1,
          sourceFactCount: 1,
          sourceFactTypes: ["authorization"],
          traceableSourceFactCount: 0,
          traceStatus: "needs_evidence",
        },
        executionAllowed: false,
        humanApprovalRequired: true,
        nextAllowedAction: "执行前请审核验证计划。",
        playbookId: "bola_idor",
        priorityScore: 91,
        rawPriorityScore: 91,
        qualityGateReasons: ["required_evidence_missing"],
        reportReadiness: {
          nextAllowedAction: "Review trace gaps before drafting.",
          reportSubmissionAllowed: false,
          requiredEvidenceCount: 1,
          safeValidationStepCount: 2,
          status: "blocked_by_required_evidence",
          submissionBlocked: true,
          traceStatus: "needs_evidence",
        },
        queueKey: "autonomous_hunt:run_1:hunt_queue_candidate_high",
        refutationQuestionCount: 2,
        evidenceNeeded: ["approved test object id matrix"],
        requiredEvidence: ["independent refutation or static rule", "Policy"],
        satisfiedEvidence: [],
        safetyGate: "等待人工审核",
        source: "研究流程自动挖掘队列",
        surfaceKey: null,
        title: "审核自动挖掘候选 candidate_high; Authorization: Bearer secret-token",
        topCandidateRank: 1,
        validationStepCount: 2,
      },
    ],
  );

  assert.equal(summaries.length, 3);
  assert.equal(summaries[0].candidateId, "candidate_high");
  assert.equal(summaries[0].source, "流程运行");
  assert.equal(summaries[0].hunterPriorityScore, 92);
  assert.equal(summaries[0].reviewPriorityScore, 100);
  assert.equal(summaries[0].impactScore, 88);
  assert.equal(summaries[0].duplicateRiskScore, 18);
  assert.equal(summaries[0].policyRiskScore, 12);
  assert.equal(summaries[0].hypothesis, "假设已脱敏");
  assert.equal(summaries[0].evidenceNeededCount, 1);
  assert.equal(summaries[0].evidenceFocusCount, 3);
  assert.deepEqual(summaries[0].triageSignals, [
    "访问控制缺口候选",
    "存在敏感汇点",
    "需要人工审核",
  ]);
  assert.deepEqual(summaries[0].evidenceFocus, [
    "同处理器访问控制证据",
    "缺少检查反证轨迹",
    "[已脱敏]",
  ]);
  assert.deepEqual(summaries[0].sourceFactTypes, [
    "访问控制缺口候选",
    "敏感汇点",
  ]);
  assert.deepEqual(summaries[0].priorityReasons, [
    "访问控制缺口候选",
    "需要同处理器访问控制证据",
    "存在敏感汇点",
  ]);
  assert.equal(summaries[0].refutationStatus, "具有合理性");
  assert.equal(summaries[0].researchQueueHandoff?.queueKey, "autonomous_hunt:run_1:hunt_queue_candidate_high");
  assert.equal(summaries[0].researchQueueHandoff?.title, "审核自动挖掘候选 candidate_high; Authorization=[已脱敏]");
  assert.equal(summaries[0].researchQueueHandoff?.humanApprovalRequired, true);
  assert.equal(summaries[0].researchQueueHandoff?.executionAllowed, false);
  assert.equal(summaries[0].researchQueueHandoff?.reviewHref, "/campaigns/campaign_1/tasks");
  assert.equal(summaries[0].researchQueueHandoff?.blockedActionCount, 3);
  assert.equal(summaries[0].researchQueueHandoff?.topCandidateRank, 1);
  assert.deepEqual(summaries[0].researchQueueHandoff?.requiredEvidence, [
    "independent refutation or static rule",
    "Policy",
  ]);
  assert.deepEqual(summaries[0].researchQueueHandoff?.evidenceNeeded, [
    "approved test object id matrix",
  ]);
  assert.equal(summaries[0].researchQueueHandoff?.validationStepCount, 2);
  assert.equal(summaries[0].researchQueueHandoff?.refutationQuestionCount, 2);
  assert.equal(summaries[0].chainConfidence, 74);
  assert.equal(summaries[0].chainImpact, "Cross tenant read with cookie=[已脱敏]");
  assert.equal(summaries[0].primitiveCount, 2);
  assert.equal(summaries[0].preconditionCount, 2);
  assert.equal(summaries[0].refutationQuestionCount, 3);
  assert.deepEqual(summaries[0].primitives, ["object id swap", "原语"]);
  assert.deepEqual(summaries[0].preconditions, ["attacker has workspace member role", "token=[已脱敏]"]);
  assert.deepEqual(summaries[0].refutationQuestions, [
    "Can same-handler authorization evidence refute the missing access-control check candidate",
    "Does ownership check bind workspace_id",
    "反证问题",
  ]);
  assert.equal(summaries[0].reasons[0], "访问控制缺口候选");
  assert.equal(summaries[1].candidateId, "research_plan_1");
  assert.equal(summaries[1].source, "研究审核计划");
  assert.equal(summaries[1].researchQueueHandoff, null);
  assert.equal(summaries[1].hypothesis, "Review export IDOR with Authorization=[已脱敏]");
  assert.equal(summaries[1].reviewPriorityScore, 55);
  assert.equal(summaries[1].refutationQuestionCount, 1);
  assert.deepEqual(summaries[1].refutationQuestions, ["Can ownership checks refute export access"]);
  assert.equal(summaries[1].nextAction, "验证前请审核假设看板并请求审核。");
  assert.doesNotMatch(
    JSON.stringify(summaries[1]),
    /request approval before validation|Approval required before validation/i,
  );
  assert.equal(summaries[2].candidateId, "candidate_low");
  assert.equal(summaries[2].researchQueueHandoff, null);
  assert.equal(summaries[2].reviewPriorityScore, 41);
  assert.doesNotMatch(
    JSON.stringify(summaries[2].priorityReasons),
    /访问控制缺口候选|需要同处理器访问控制证据/i,
  );
  assert.doesNotMatch(
    JSON.stringify(summaries),
    /secret-token|session=secret|token=secret|alice@example\.com|eyJhbGciOiJIUzI1NiJ9|personal data/i,
  );
});

test("toCampaignHypothesisBoardSummaries maps restricted authz rationale labels before redaction", () => {
  const runDetailWithRestrictedRationaleLabels = {
    ...pipelineRunDetail,
    payload: {
      ...pipelineRunDetail.payload,
      hypothesis_assessments: [
        {
          ...pipelineRunDetail.payload.hypothesis_assessments[1],
          hunter_assessment: {
            ...pipelineRunDetail.payload.hypothesis_assessments[1].hunter_assessment,
            evidence_focus: [
              "same_handler_authorization_evidence",
              "Authorization: Bearer secret-token",
            ],
            reasons: [
              "authorization_gap_candidate",
              "sensitive_sink_present",
            ],
          },
          hypothesis: {
            ...pipelineRunDetail.payload.hypothesis_assessments[1].hypothesis,
            source_facts: [
              {
                fact_ref: "codebase_fact:authorization_gap_candidate:/files/{file_id}/export",
                fact_type: "authorization_gap_candidate",
              },
              {
                fact_ref: "codebase_fact:sensitive_sink:send_file",
                fact_type: "sensitive_sink",
              },
            ],
          },
        },
      ],
    },
  };

  const [summary] = toCampaignHypothesisBoardSummaries([runDetailWithRestrictedRationaleLabels]);

  assert.deepEqual(summary.priorityReasons, [
    "访问控制缺口候选",
    "需要同处理器访问控制证据",
    "存在敏感汇点",
  ]);
  assert.deepEqual(summary.evidenceFocus, [
    "同处理器访问控制证据",
    "[已脱敏]",
  ]);
  assert.doesNotMatch(
    JSON.stringify(summary.priorityReasons),
    /Authorization|Bearer|secret-token|token=|eyJ|@/,
  );
});

test("toCampaignAttackSurfaceMapView summarizes target model facts without secret leakage", () => {
  const view = toCampaignAttackSurfaceMapView([pipelineRunDetail]);

  assert.equal(view.runCount, 1);
  assert.equal(view.endpointCount, 1);
  assert.equal(view.objectCount, 1);
  assert.equal(view.roleCount, 2);
  assert.equal(view.sensitiveActionCount, 1);
  assert.equal(view.relationshipCount, 1);
  assert.equal(view.endpoints[0].route, "GET /files/{file_id}");
  assert.equal(view.objects[0].name, "file");
  assert.equal(view.objects[0].identifierCount, 2);
  assert.equal(view.sensitiveActions[0].route, "POST /files/{file_id}/export");
  assert.equal(view.relationships[0].summary, "workspace -> file");
  assert.doesNotMatch(JSON.stringify(view), /secret-token|session=secret|authorization=Bearer/i);
});

test("campaign control page exposes a safe launchpad without validation or submission entrypoints", async () => {
  const page = await import("node:fs/promises").then((fs) =>
    fs.readFile(new URL("../app/campaigns/page.tsx", import.meta.url), "utf8"),
  );

  assert.match(page, /getCampaigns/);
  assert.match(page, /已授权研究活动启动台/);
  assert.match(page, /launchCampaignAction/);
  assert.match(page, /launchAuthorizedCampaign/);
  assert.match(page, /name="policy_text"/);
  assert.match(page, /name="default_asset"/);
  assert.match(page, /name="allowed_tools"/);
  assert.match(page, /name="authorized_code_path"/);
  assert.match(page, /name="authorized_code_content"/);
  assert.match(page, /authorizedCodeFilesFromForm/);
  assert.match(page, /name="authorized_api_artifact_kind"/);
  assert.match(page, /name="authorized_api_artifact_source"/);
  assert.match(page, /name="authorized_api_artifact_payload"/);
  assert.match(page, /authorizedApiArtifactsFromForm/);
  assert.match(page, /jsonObjectValue/);
  assert.match(page, /已授权工具/);
  assert.doesNotMatch(page, /Allowed tools/);
  assert.match(page, /name="autonomy_level"/);
  assert.match(page, /范围守卫/);
  assert.match(page, /人工审核门/);
  assert.match(page, /\/campaigns\/\$\{encodeURIComponent\(campaign\.id\)\}/);
  assert.match(page, />预算</);
  assert.match(page, /campaignBudgetLabel\(campaign\.budget/);
  assert.doesNotMatch(page, /getCampaignControlCenter/);
  assert.doesNotMatch(page, /resumeCampaign|pauseCampaign|executeValidation|approveValidation|submitReport/);
});

test("campaign launch API helper creates and starts only the safe campaign loop", async () => {
  const api = await import("node:fs/promises").then((fs) =>
    fs.readFile(new URL("./api.ts", import.meta.url), "utf8"),
  );

  assert.match(api, /export type AuthorizedCampaignLaunchInput/);
  assert.match(api, /authorized_api_artifacts\?:/);
  assert.match(api, /authorized_code_files\?:/);
  assert.match(api, /launchAuthorizedCampaign/);
  assert.match(api, /launchStudioWorkspaceCampaignHunter/);
  assert.match(api, /\/mythos\/studio\/workspaces\/campaigns\/launch/);
  assert.match(api, /\/mythos\/campaigns/);
  assert.match(api, /\/start/);
  assert.doesNotMatch(api, /executeValidation|approveValidation|submitReport/);
});

test("campaigns page uses redacted display helpers for campaign list values", async () => {
  const page = await import("node:fs/promises").then((fs) =>
    fs.readFile(new URL("../app/campaigns/page.tsx", import.meta.url), "utf8"),
  );

  assert.match(page, /safeDisplay/);
  assert.match(page, /formatLabel/);
  assert.match(page, /审核门、预算/);
  assert.doesNotMatch(page, /blockers, approvals, budgets/);
  assert.match(page, /safeDisplay\(campaign\.name/);
  assert.match(page, /safeDisplay\(campaign\.default_asset/);
  assert.doesNotMatch(page, /\{campaign\.name\}/);
  assert.doesNotMatch(page, /\{campaign\.default_asset\}/);
  assert.doesNotMatch(page, /function formatLabel/);
});

test("campaign detail page reads the audited control center and queues review items only", async () => {
  const page = await import("node:fs/promises").then((fs) =>
    fs.readFile(new URL("../app/campaigns/[campaignId]/page.tsx", import.meta.url), "utf8"),
  );

  assert.match(page, /params: Promise<\{ campaignId: string \}>/);
  assert.match(page, /getCampaignControlCenter\(campaignId, null\)/);
  assert.match(page, /materializeResearchQueueTask/);
  assert.match(page, /revalidatePath/);
  assert.match(page, /queueResearchReviewAction/);
  assert.match(page, /"use server"/);
  assert.match(page, /研究活动控制信息暂不可用/);
  assert.match(page, /此研究活动未返回已审计的控制摘要。/);
  assert.doesNotMatch(page, /No audited control-center record/);
  assert.match(page, /\/campaigns\/\$\{encodeURIComponent\(campaignId\)\}\/tasks/);
  assert.match(page, /\/campaigns\/\$\{encodeURIComponent\(campaignId\)\}\/agent-runs/);
  assert.match(page, /\/campaigns\/\$\{encodeURIComponent\(campaignId\)\}\/attack-surface-map/);
  assert.match(page, /\/campaigns\/\$\{encodeURIComponent\(campaignId\)\}\/codebase-map/);
  assert.match(page, /\/campaigns\/\$\{encodeURIComponent\(campaignId\)\}\/validation-queue/);
  assert.match(page, /\/campaigns\/\$\{encodeURIComponent\(campaignId\)\}\/validation-runs/);
  assert.match(page, /\/campaigns\/\$\{encodeURIComponent\(campaignId\)\}\/hypothesis-board/);
  assert.match(page, /\/campaigns\/\$\{encodeURIComponent\(campaignId\)\}\/evidence-review/);
  assert.match(page, /\/campaigns\/\$\{encodeURIComponent\(campaignId\)\}\/report-drafts/);
  assert.match(page, /\/campaigns\/\$\{encodeURIComponent\(campaignId\)\}\/timeline/);
  assert.match(page, /\/campaigns\/\$\{encodeURIComponent\(campaignId\)\}\/brain/);
  assert.match(page, /\/campaigns\/\$\{encodeURIComponent\(campaignId\)\}\/artifacts/);
  assert.match(page, /label="智能体审计"/);
  assert.match(page, /label="审核门"/);
  assert.doesNotMatch(page, /label="Approval Review"/);
  assert.match(page, /label="验证审计"/);
  assert.match(page, /label="报告就绪度"/);
  assert.match(page, /label="研究大脑"/);
  assert.match(page, /label="代码审计地图"/);
  assert.match(page, /label="资料审核"/);
  assert.match(page, /label="研究审核"/);
  assert.match(page, /label="审核时间线"/);
  assert.doesNotMatch(page, /<AuditLink[^\r\n]*label="Tasks"/);
  assert.doesNotMatch(page, /label="Agent Runs"/);
  assert.doesNotMatch(page, /label="Validation Queue"/);
  assert.doesNotMatch(page, /label="Validation Runs"/);
  assert.doesNotMatch(page, /label="报告草稿s"/);
  assert.doesNotMatch(page, /label="Brain"/);
  assert.doesNotMatch(page, /label="Artifacts"/);
  assert.doesNotMatch(page, /label="Artifact Repository"/);
  assert.doesNotMatch(page, /label="Codebase Map"/);
  assert.doesNotMatch(page, /label="Research Tasks"/);
  assert.doesNotMatch(page, /label="Timeline"/);
  assert.match(page, /executionAllowed/);
  assert.match(page, /safeNextAction/);
  assert.match(page, /晋级审核/);
  assert.match(page, /promotionReviewBlockedCount/);
  assert.match(page, /promotionReviewNextAllowedAction/);
  assert.match(page, /promotionReviewProvenanceRefCount/);
  assert.match(page, /promotionReviewRequiredEvidenceBlockedCount/);
  assert.match(page, /审核要求/);
  assert.match(page, /summary\.blockedReasons\.map/);
  assert.doesNotMatch(page, /Blocked Reasons/);
  assert.doesNotMatch(page, /Action blockers/);
  assert.match(page, /validationEvidenceCount/);
  assert.match(page, /validationEvidenceGapCount/);
  assert.match(page, /控制就绪度/);
  assert.match(page, /范围守卫已审核/);
  assert.doesNotMatch(page, /范围守卫 clear/);
  assert.match(page, /研究记忆审核/);
  assert.doesNotMatch(page, />Research Queue</);
  assert.match(page, /researchQueueSuggestions/);
  assert.match(page, /加入审核队列/);
  assert.match(page, /name="queue_key"/);
  assert.match(page, /value=\{suggestion\.queueKey\}/);
  assert.match(page, /requester: "operator"/);
  assert.match(page, /从控制中心加入审核项。/);
  assert.match(page, /\/campaigns\/\$\{encodeURIComponent\(campaignId\)\}\/tasks/);
  assert.match(page, /nextAllowedAction/);
  assert.match(page, /审核门/);
  assert.match(page, /操作门/);
  assert.match(page, /仅供审核/);
  assert.match(page, /candidateStatus/);
  assert.match(page, /humanApprovalRequired/);
  assert.match(page, /refutationQuestionCount/);
  assert.match(page, /validationStepCount/);
  assert.match(page, /blockedActionCount/);
  assert.match(page, /rawPriorityScore/);
  assert.match(page, /requiredEvidence/);
  assert.match(page, /所需证据/);
  assert.match(page, /qualityGateReasons/);
  assert.match(page, /质量门原因/);
  assert.match(page, /需要人工审核/);
  assert.match(page, /label="验证审计"/);
  assert.match(page, /label="审核项"/);
  assert.match(page, /label="智能体审计"/);
  assert.doesNotMatch(page, /Execution permission/);
  assert.doesNotMatch(page, /No execution permission/);
  assert.doesNotMatch(page, /do not grant execution/i);
  assert.doesNotMatch(page, /label="Validation runs"/);
  assert.doesNotMatch(page, /label="Tasks"/);
  assert.doesNotMatch(page, /label="Agent runs"/);
  assert.doesNotMatch(page, /label="Execution" value="Blocked"/);
  assert.doesNotMatch(page, />Safety gate</);
  assert.match(page, /label="审核门"/);
  assert.doesNotMatch(page, /label="Approval queue"/);
  assert.doesNotMatch(page, /label="Approval review"/);
  assert.match(page, /label="待审核门"/);
  assert.doesNotMatch(page, /label="Pending approvals"/);
  assert.match(page, /验证审计/);
  assert.match(page, /证据审核/);
  assert.match(page, /资料审核/);
  assert.doesNotMatch(page, /Artifact repository/);
  assert.match(page, /报告就绪度/);
  assert.match(page, /研究记忆审核/);
  assert.match(page, /周期审核/);
  assert.match(page, /label="审核阻塞项"/);
  assert.doesNotMatch(page, /label="Blocked stages"/);
  assert.match(page, /周期审核/);
  assert.match(page, /cycleReviewAwaitingCount/);
  assert.match(page, /cycleReviewCompletedCount/);
  assert.match(page, /人工审核门/);
  assert.match(page, /运行时审核门/);
  assert.match(page, /范围守卫/);
  assert.match(page, /当前没有待处理的审核要求。/);
  assert.doesNotMatch(page, /No active action blockers/);
  assert.doesNotMatch(page, /No active blocker recorded/);
  assert.doesNotMatch(page, /Operator mode/);
  assert.doesNotMatch(page, /startCampaign|resumeCampaign|pauseCampaign|executeValidation|approveValidation|submitReport|createFindingCandidate/);
  assert.match(page, /<form/);
  assert.match(page, /action=\{queueResearchReviewAction\}/);
});

test("campaign artifacts page filters authorized materials and stays read-only", async () => {
  const page = await import("node:fs/promises").then((fs) =>
    fs.readFile(new URL("../app/campaigns/[campaignId]/artifacts/page.tsx", import.meta.url), "utf8"),
  );

  assert.match(page, /params: Promise<\{ campaignId: string \}>/);
  assert.match(page, /getCampaignControlCenter\(campaignId, null\)/);
  assert.match(page, /getArtifacts\(\[\], \{/);
  assert.match(page, /programId: controlCenter\.campaign\.program_id/);
  assert.match(page, /asset: controlCenter\.campaign\.default_asset/);
  assert.match(page, /toCampaignArtifactSummaries/);
  assert.match(page, /资料审核/);
  assert.match(page, /仅显示此研究活动的资料摘要/);
  assert.doesNotMatch(page, /Authorized material summaries/);
  assert.doesNotMatch(page, /Artifact Repository/);
  assert.doesNotMatch(page, /Campaign Artifacts/);
  assert.match(page, /暂无已审核资料。/);
  assert.doesNotMatch(page, /No authorized artifacts ready/);
  assert.doesNotMatch(page, /No campaign artifacts recorded/);
  assert.match(page, /reportChainAllowedCount/);
  assert.match(page, /reportChainBlockedCount/);
  assert.match(page, /报告链审核就绪/);
  assert.match(page, /报告链需审核/);
  assert.match(page, /报告链审核已就绪/);
  assert.match(page, /报告链需要审核/);
  assert.doesNotMatch(page, /Report-chain eligible/);
  assert.doesNotMatch(page, /Report-chain blocked/);
  assert.doesNotMatch(page, /Eligible for report chain/);
  assert.doesNotMatch(page, /Blocked for report chain/);
  assert.doesNotMatch(page, /Report-chain allowed/);
  assert.doesNotMatch(page, /\? "Allowed"/);
  assert.match(page, /使用溯源/);
  assert.match(page, /usageStages/);
  assert.match(page, /usageTypes/);
  assert.doesNotMatch(page, /raw payload|raw evidence|payload_summary|derived_facts/);
  assert.doesNotMatch(page, /run_id|candidate_id|learning_signal_id/);
  assert.doesNotMatch(page, /startCampaign|resumeCampaign|pauseCampaign|executeValidation|submitReport|uploadArtifact/);
  assert.doesNotMatch(page, /<form|method="post"|action=\{/);
});

test("campaign validation runs page reads harness records and stays read-only", async () => {
  const page = await import("node:fs/promises").then((fs) =>
    fs.readFile(new URL("../app/campaigns/[campaignId]/validation-runs/page.tsx", import.meta.url), "utf8"),
  );

  assert.match(page, /params: Promise<\{ campaignId: string \}>/);
  assert.match(page, /getCampaignValidationRuns\(campaignId, \[\]\)/);
  assert.match(page, /toCampaignValidationRunSummaries/);
  assert.match(page, /验证审计/);
  assert.doesNotMatch(page, />Validation Runs</);
  assert.doesNotMatch(page, /Validation runs/);
  assert.match(page, /验证审计/);
  assert.match(page, /预检摘要/);
  assert.match(page, /人工审核门不是验证启动门。/);
  assert.match(page, /关注状态/);
  assert.match(page, /下一步操作/);
  assert.match(page, /attentionState/);
  assert.match(page, /nextAction/);
  assert.doesNotMatch(page, /validation start permission/);
  assert.doesNotMatch(page, /Approval is not validation start permission/);
  assert.doesNotMatch(page, /Approval is not execution permission/);
  assert.match(page, /executionState/);
  assert.match(page, /预检已审核/);
  assert.match(page, /预检已审核/);
  assert.doesNotMatch(page, /Preflight ready/);
  assert.doesNotMatch(page, /Preflight clear/);
  assert.match(page, /预检已阻断/);
  assert.match(page, /预检决策/);
  assert.match(page, /<span>证据引用<\/span>/);
  assert.doesNotMatch(page, /<span>Evidence<\/span>/);
  assert.match(page, /等待审核门/);
  assert.match(page, /需要审核门/);
  assert.match(page, /无需审核门/);
  assert.match(page, /label="审核门"/);
  assert.doesNotMatch(page, /Awaiting approval/);
  assert.doesNotMatch(page, /Approval required/);
  assert.doesNotMatch(page, /No approval required/);
  assert.doesNotMatch(page, /label="Approval"/);
  assert.doesNotMatch(page, /No approval/);
  assert.match(page, /label="验证审计"/);
  assert.match(page, /label="审核项"/);
  assert.match(page, /\/campaigns\/\$\{encodeURIComponent\(campaignId\)\}\/validation-runs\/\$\{encodeURIComponent\(run\.id\)\}/);
  assert.match(page, /审核人工观察/);
  assert.match(page, /暂无可查看的验证审计。/);
  assert.doesNotMatch(page, /No validation run records/);
  assert.doesNotMatch(page, /label="Run"/);
  assert.doesNotMatch(page, /label="Task"/);
  assert.doesNotMatch(page, />Safety gate</);
  assert.match(page, /已启动验证：/);
  assert.doesNotMatch(page, /Execution started/);
  assert.doesNotMatch(page, /Allowed by preflight/);
  assert.doesNotMatch(page, /runValidation|executeValidation|approveValidation|submitReport/);
  assert.doesNotMatch(page, /Executable/);
  assert.doesNotMatch(page, /<form|method="post"|action=\{/);
});

test("campaign validation run manual result page records only reviewed observations", async () => {
  const page = await import("node:fs/promises").then((fs) =>
    fs.readFile(
      new URL("../app/campaigns/[campaignId]/validation-runs/[validationRunId]/page.tsx", import.meta.url),
      "utf8",
    ),
  );

  assert.match(page, /params: Promise<\{ campaignId: string; validationRunId: string \}>/);
  assert.match(page, /getCampaignValidationRuns\(campaignId, \[\]\)/);
  assert.match(page, /recordCampaignValidationRunManualResult/);
  assert.match(page, /人工验证观察审核/);
  assert.match(page, /仅候选证据/);
  assert.match(page, /证据晋级/);
  assert.match(page, /报告提交/);
  assert.match(page, /审核人工观察/);
  assert.match(page, /outcome: formOutcome\(formData\)/);
  assert.match(page, /evidence_refs: formLines\(formData, "evidence_refs"\)/);
  assert.match(page, /action=\{recordManualResultAction\}/);
  assert.match(page, /revalidatePath\(`\/campaigns\/\$\{encodeURIComponent\(campaignId\)\}\/validation-runs`\)/);
  assert.doesNotMatch(page, /fallbackManualResultRun/);
  assert.doesNotMatch(page, /allowed_to_execute/);
  assert.match(page, /label="执行门" value="受控"/);
  assert.match(page, /label="报告提交门" value="受控"/);
  assert.doesNotMatch(page, /validation-workspace/);
  assert.doesNotMatch(page, /recordManualObservation|recordClaimReviewDecision|createFindingCandidate|executeValidation|submitReport|approveValidation/);
});

test("campaign hypothesis board page reads run candidates and stays read-only", async () => {
  const page = await import("node:fs/promises").then((fs) =>
    fs.readFile(new URL("../app/campaigns/[campaignId]/hypothesis-board/page.tsx", import.meta.url), "utf8"),
  );

  assert.match(page, /params: Promise<\{ campaignId: string \}>/);
  assert.match(page, /getCampaignControlCenter\(campaignId, null\)/);
  assert.match(page, /getPipelineRun\(runId, null\)/);
  assert.match(page, /toCampaignHypothesisBoardSummaries\(\s*runs,\s*controlCenter\?\.research_review_plans \?\? \[\],\s*researchQueueSuggestions,\s*campaignId,\s*\)/);
  assert.match(page, /toCampaignControlSummary\(controlCenter\)/);
  assert.match(page, /researchQueueHandoff/);
  assert.match(page, /candidate\.researchQueueHandoff\.reviewHref/);
  assert.match(page, /审核队列交接/);
  assert.match(page, /所需证据/);
  assert.match(page, /candidate\.researchQueueHandoff\.requiredEvidence/);
  assert.match(page, /来源/);
  assert.match(page, /candidate\.source/);
  assert.match(page, /研究审计/);
  assert.match(page, /label="研究审计"/);
  assert.match(page, /已映射利用链/);
  assert.match(page, /审核优先级/);
  assert.match(page, /优先级依据/);
  assert.match(page, /priorityReasons/);
  assert.match(page, /candidate\.priorityReasons/);
  assert.match(page, /利用链置信度/);
  assert.match(page, /利用链影响/);
  assert.match(page, /反证问题/);
  assert.match(page, /暂无可审核的假设。/);
  assert.doesNotMatch(page, /No campaign-linked hypothesis candidates recorded/);
  assert.doesNotMatch(page, /<Metric label="Runs"/);
  assert.doesNotMatch(page, /label="Run"/);
  assert.match(page, /PreviewList/);
  assert.doesNotMatch(page, /executeValidation|approveValidation|createFindingCandidate|submitReport|materializeResearchQueueTask/);
  assert.doesNotMatch(page, /<form|method="post"|action=\{/);
});

test("campaign attack surface map page reads target models and stays read-only", async () => {
  const page = await import("node:fs/promises").then((fs) =>
    fs.readFile(new URL("../app/campaigns/[campaignId]/attack-surface-map/page.tsx", import.meta.url), "utf8"),
  );

  assert.match(page, /params: Promise<\{ campaignId: string \}>/);
  assert.match(page, /getCampaignControlCenter\(campaignId, null\)/);
  assert.match(page, /getPipelineRun\(runId, null\)/);
  assert.match(page, /toCampaignAttackSurfaceMapView/);
  assert.match(page, /尚未映射端点。/);
  assert.match(page, /尚未映射敏感操作。/);
  assert.match(page, /尚未映射关系。/);
  assert.match(page, /尚未映射对象。/);
  assert.match(page, /尚未映射角色。/);
  assert.match(page, /已审计来源/);
  assert.match(page, /已审计研究来源/);
  assert.doesNotMatch(page, /authorized audit sources/);
  assert.match(page, /审核边界/);
  assert.match(page, /仅显示审计事实；执行审核门不在此视图中操作/);
  assert.doesNotMatch(page, /Not available from this read-only view/);
  assert.doesNotMatch(page, /Execution permission/);
  assert.doesNotMatch(page, /label="Runs"/);
  assert.doesNotMatch(page, /No endpoint facts recorded/);
  assert.doesNotMatch(page, /No sensitive action facts recorded/);
  assert.doesNotMatch(page, /No relationship facts recorded/);
  assert.doesNotMatch(page, /No objects recorded/);
  assert.doesNotMatch(page, /No roles recorded/);
  assert.doesNotMatch(page, /label="Execution" value="Not available from this page"/);
  assert.doesNotMatch(page, /executeValidation|approveValidation|createFindingCandidate|submitReport/);
  assert.doesNotMatch(page, /<form|method="post"|action=\{/);
});

test("campaign brain page reads program brain and stays advisory-only", async () => {
  const page = await import("node:fs/promises").then((fs) =>
    fs.readFile(new URL("../app/campaigns/[campaignId]/brain/page.tsx", import.meta.url), "utf8"),
  );

  assert.match(page, /params: Promise<\{ campaignId: string \}>/);
  assert.match(page, /getCampaignControlCenter\(campaignId, null\)/);
  assert.match(page, /getMythosBrainProgram/);
  assert.match(page, /toCampaignBrainSummary/);
  assert.match(page, /toCampaignLearningReviewSummary/);
  assert.match(page, /学习信号审核/);
  assert.match(page, /推理记忆/);
  assert.match(page, /reasoningMemory/);
  assert.match(page, /advisoryOnly/);
  assert.match(page, /用于排序与解释的建议性研究记忆，仅作建议使用。/);
  assert.match(page, /审核就绪度/);
  assert.match(page, /可审核/);
  assert.match(page, /已加入审核队列/);
  assert.doesNotMatch(page, /label="Ready"/);
  assert.match(page, /关联审计/);
  assert.match(page, /审核边界/);
  assert.match(page, /研究大脑建议性记忆/);
  assert.match(page, /仅建议性记忆/);
  assert.match(page, /审核门生效中/);
  assert.doesNotMatch(page, /value=\{learningReview\.reviewReady \? "Yes" : "No"\}/);
  assert.doesNotMatch(page, /value=\{advisoryOnly \? "Yes" : "No"\}/);
  assert.doesNotMatch(page, /Permission source/);
  assert.doesNotMatch(page, /Linked runs/);
  assert.doesNotMatch(page, /cannot authorize execution/);
  assert.doesNotMatch(page, /范围守卫 only/);
  assert.doesNotMatch(page, /Brain advisory only/);
  assert.doesNotMatch(page, /Execution allowed/);
  assert.doesNotMatch(page, /startCampaign|resumeCampaign|pauseCampaign|executeValidation|submitReport|approveValidation/);
  assert.doesNotMatch(page, /<form|method="post"|action=\{/);
});

test("campaign codebase map page reads fact-layer records and stays read-only", async () => {
  const page = await import("node:fs/promises").then((fs) =>
    fs.readFile(new URL("../app/campaigns/[campaignId]/codebase-map/page.tsx", import.meta.url), "utf8"),
  );

  assert.match(page, /params: Promise<\{ campaignId: string \}>/);
  assert.match(page, /getCampaignCodebaseMap\(campaignId, emptyCampaignCodebaseMap\)/);
  assert.match(page, /toCampaignCodebaseMapView/);
  assert.match(page, /代码审计地图/);
  assert.doesNotMatch(page, /Codebase Map/);
  assert.match(page, /访问控制检查/);
  assert.match(page, /授权缺口候选项/);
  assert.match(page, /暂无访问控制提示/);
  assert.doesNotMatch(page, /Authz checks/);
  assert.doesNotMatch(page, /No authz hint/);
  assert.doesNotMatch(page, /Confirmed finding|Vulnerability/);
  assert.match(page, /暂无已映射仓库。/);
  assert.match(page, /暂无代码事实。/);
  assert.match(page, /暂无扫描器审计。/);
  assert.match(page, /扫描器审计/);
  assert.doesNotMatch(page, /Scanner Runs/);
  assert.doesNotMatch(page, /Scanner runs/);
  assert.doesNotMatch(page, /No codebase map records/);
  assert.doesNotMatch(page, /No code facts recorded/);
  assert.doesNotMatch(page, /No scanner runs recorded/);
  assert.match(page, /扫描器边界/);
  assert.match(page, /扫描器控制项不在此审计视图中提供/);
  assert.doesNotMatch(page, /Not available from this read-only view/);
  assert.match(page, /审核门/);
  assert.doesNotMatch(page, /Scanner permission/);
  assert.doesNotMatch(page, /Scanner execution/);
  assert.doesNotMatch(page, />Safety gate</);
  assert.doesNotMatch(page, /runScanner|startScan|executeScan|executeValidation|submitReport/);
  assert.doesNotMatch(page, /<form|method="post"|action=\{/);
});

test("campaign evidence review page reads report previews and validation runs while staying read-only", async () => {
  const page = await import("node:fs/promises").then((fs) =>
    fs.readFile(new URL("../app/campaigns/[campaignId]/evidence-review/page.tsx", import.meta.url), "utf8"),
  );

  assert.match(page, /params: Promise<\{ campaignId: string \}>/);
  assert.match(page, /getCampaignControlCenter\(campaignId, null\)/);
  assert.match(page, /getReportPreview\(runId, null\)/);
  assert.match(page, /getCampaignValidationRuns\(campaignId, \[\]\)/);
  assert.match(page, /getCampaignPipelineStages\(campaignId, \[\]\)/);
  assert.match(page, /getCampaignTasks\(campaignId, \[\]\)/);
  assert.match(page, /getCampaignResearchTaskReview\(campaignId, task\.id, null\)/);
  assert.match(page, /toCampaignEvidenceReviewSummaries/);
  assert.match(page, /toCampaignFindingCandidateGateSummary/);
  assert.match(page, /toCampaignResearchFeedbackEvidenceSummaries/);
  assert.match(page, /toCampaignValidationEvidenceReviewSummaries/);
  assert.match(page, /已阻断晋级审核/);
  assert.match(page, /晋级阻塞审核队列/);
  assert.match(page, /promotionBlockReviews/);
  assert.match(page, /\/tasks\/\$\{encodeURIComponent\(item\.taskId\)\}/);
  assert.match(page, /feedbackStageId/);
  assert.match(page, /label="反馈阶段"/);
  assert.match(page, /\/feedback-reviews\/\$\{encodeURIComponent\(item\.feedbackStageId\)\}/);
  assert.match(page, /\/feedback-reviews\/\$\{encodeURIComponent\(feedback\.feedbackStageId\)\}/);
  assert.match(page, /审核晋级门/);
  assert.match(page, /promotionProvenanceRefCount/);
  assert.match(page, /已阻断晋级尝试/);
  assert.match(page, /promotionAuditLatestReason/);
  assert.match(page, /promotionAuditCreatedCount/);
  assert.match(page, /promotionAuditProvenanceRefCount/);
  assert.match(page, /promotionAuditReviewEvidenceRefCount/);
  assert.match(page, /nextAllowedAction/);
  assert.match(page, /label="下一步审核操作"/);
  assert.doesNotMatch(page, /label="下一步操作" value=\{findingCandidateGate\.nextAllowedAction\}/);
  assert.match(page, /<span>证据引用<\/span>/);
  assert.doesNotMatch(page, /<span>Evidence<\/span>/);
  assert.match(page, /label="审核项"/);
  assert.doesNotMatch(page, /label="Task" value=\{item\.taskId\}/);
  assert.match(page, /label="审核门"/);
  assert.match(page, /reviewGate/);
  assert.match(page, /candidateEvidenceState/);
  assert.match(page, /reportChainState/);
  assert.doesNotMatch(page, /label="Approval"/);
  assert.doesNotMatch(page, /Approval required/);
  assert.doesNotMatch(page, /No approval/);
  assert.match(page, /研究审计/);
  assert.match(page, /label="研究审计"/);
  assert.match(page, /label="验证审计"/);
  assert.doesNotMatch(page, /label="Task" value=\{run\.taskId/);
  assert.doesNotMatch(page, /label="Task" value=\{feedback\.taskId\}/);
  assert.match(page, /reviewItem/);
  assert.match(page, /已具备报告链证据/);
  assert.match(page, /报告链需要审核/);
  assert.doesNotMatch(page, /claim\.reportChainEligible \? "Eligible" : "Blocked"/);
  assert.match(page, /验证证据/);
  assert.match(page, /candidateEvidenceState/);
  assert.match(page, /reportChainState/);
  assert.match(page, /nextReviewAction/);
  assert.match(page, /preflightState/);
  assert.match(page, /toCampaignValidationEvidenceReviewSummaries\(validationRuns, pipelineStages\)/);
  assert.match(page, /toCampaignValidationEvidenceQualitySummary\(validationEvidence\)/);
  assert.match(page, /validationEvidenceQuality/);
  assert.match(page, /已清理审核/);
  assert.match(page, /已脱敏审核/);
  assert.match(page, /不安全引用/);
  assert.match(page, /强证据/);
  assert.match(page, /晋级受控/);
  assert.match(page, /manualValidationReview/);
  assert.match(page, /质量审核/);
  assert.match(page, /qualityScore/);
  assert.match(page, /redactionStatus/);
  assert.match(page, /promotionReviewState/);
  assert.match(page, /研究反馈证据/);
  assert.match(page, /需要人工审核/);
  assert.match(page, /晋级审核已阻断/);
  assert.doesNotMatch(page, /Promotion ready/);
  assert.match(page, /暂无加入证据审核队列的报告声明。/);
  assert.match(page, /暂无加入审核队列的验证证据。/);
  assert.match(page, /暂无加入审核队列的研究验证反馈。/);
  assert.doesNotMatch(page, /No campaign-linked report preview claims recorded/);
  assert.doesNotMatch(page, /No manual validation evidence recorded/);
  assert.doesNotMatch(page, /<Metric label="Runs"/);
  assert.doesNotMatch(page, /label="Run"/);
  assert.match(page, /报告链/);
  assert.doesNotMatch(page, /Preflight active/);
  assert.doesNotMatch(page, />Safety gate</);
  assert.doesNotMatch(page, /Execution allowed/);
  assert.doesNotMatch(page, /recordManualObservation|recordClaimReviewDecision|createFindingCandidate|executeValidation|submitReport/);
  assert.doesNotMatch(page, /报告链审核已就绪|晋级审核已就绪|No report claims ready|No validation evidence ready|No research validation feedback ready|Review-ready claims/);
  assert.doesNotMatch(page, /<form|method="post"|action=\{/);
});

test("campaign validation feedback review page records only the finding promotion gate", async () => {
  const page = await import("node:fs/promises").then((fs) =>
    fs.readFile(
      new URL("../app/campaigns/[campaignId]/feedback-reviews/[stageId]/page.tsx", import.meta.url),
      "utf8",
    ),
  );

  assert.match(page, /params: Promise<\{ campaignId: string; stageId: string \}>/);
  assert.match(page, /reviewValidationFeedbackForFindingPromotion/);
  assert.match(page, /decision: "allow_finding_promotion"/);
  assert.match(page, /发现候选项晋级审核/);
  assert.match(page, /可进行发现候选项晋级审核/);
  assert.match(page, /晋级审核已就绪/);
  assert.doesNotMatch(page, /Review may allow/);
  assert.doesNotMatch(page, /eligible for finding candidate promotion review/);
  assert.match(page, /验证执行/);
  assert.match(page, /报告提交/);
  assert.match(page, /label="执行门"/);
  assert.match(page, /label="验证门"/);
  assert.match(page, /label="报告提交门"/);
  assert.doesNotMatch(page, /label="execution_allowed"/);
  assert.doesNotMatch(page, /label="validation_allowed"/);
  assert.doesNotMatch(page, /label="report_submission_allowed"/);
  assert.doesNotMatch(page, /execution_allowed/);
  assert.doesNotMatch(page, /validation_allowed/);
  assert.doesNotMatch(page, /report_submission_allowed/);
  assert.match(page, /revalidatePath/);
  assert.doesNotMatch(page, /createFindingCandidate|executeValidation|submitReport/);
  assert.doesNotMatch(page, /Authorization|Bearer|secret-token|cookie=/);
});

test("campaign cycle review completion page records only the cycle review gate", async () => {
  const page = await import("node:fs/promises").then((fs) =>
    fs.readFile(
      new URL("../app/campaigns/[campaignId]/cycle-reviews/[stageId]/page.tsx", import.meta.url),
      "utf8",
    ),
  );

  assert.match(page, /params: Promise<\{ campaignId: string; stageId: string \}>/);
  assert.match(page, /completeCampaignCycleReview/);
  assert.match(page, /活动周期审核/);
  assert.match(page, /下一轮只读周期/);
  assert.match(page, /验证执行/);
  assert.match(page, /报告提交/);
  assert.match(page, /label="执行门"/);
  assert.match(page, /label="提交门"/);
  assert.doesNotMatch(page, /label="execution_allowed"/);
  assert.doesNotMatch(page, /label="submission_allowed"/);
  assert.doesNotMatch(page, /execution_allowed/);
  assert.doesNotMatch(page, /submission_allowed/);
  assert.match(page, /revalidatePath/);
  assert.doesNotMatch(page, /startCampaign|resumeCampaign|pauseCampaign|executeValidation|submitReport/);
  assert.doesNotMatch(page, /Authorization|Bearer|secret-token|cookie=/);
});

test("campaign report drafts page reads report previews and manual validation state while staying read-only", async () => {
  const page = await import("node:fs/promises").then((fs) =>
    fs.readFile(new URL("../app/campaigns/[campaignId]/report-drafts/page.tsx", import.meta.url), "utf8"),
  );

  assert.match(page, /params: Promise<\{ campaignId: string \}>/);
  assert.match(page, /getCampaignControlCenter\(campaignId, null\)/);
  assert.match(page, /getReportPreview\(runId, null\)/);
  assert.match(page, /getCampaignValidationRuns\(campaignId, \[\]\)/);
  assert.match(page, /getCampaignPipelineStages\(campaignId, \[\]\)/);
  assert.match(page, /getCampaignTasks\(campaignId, \[\]\)/);
  assert.match(page, /getCampaignResearchTaskReview\(campaignId, task\.id, null\)/);
  assert.match(page, /toCampaignFindingCandidateGateSummary/);
  assert.match(page, /toCampaignResearchFeedbackEvidenceSummaries/);
  assert.match(page, /报告就绪度/);
  assert.doesNotMatch(page, />报告草稿s</);
  assert.match(page, /验证审计/);
  assert.match(page, /label="研究审计"/);
  assert.match(page, /发现候选项审核门/);
  assert.match(page, /已审核声明/);
  assert.match(page, /已加入队列的发现候选项审核/);
  assert.doesNotMatch(page, /label="Ready"/);
  assert.doesNotMatch(page, /Ready claims/);
  assert.doesNotMatch(page, /Ready finding candidate reviews/);
  assert.doesNotMatch(page, /Review-ready claims/);
  assert.doesNotMatch(page, /Review-ready finding candidate reviews/);
  assert.doesNotMatch(page, /label="Eligible"/);
  assert.match(page, /研究反馈/);
  assert.match(page, /需要审核的声明/);
  assert.match(page, /晋级审核阻塞项/);
  assert.match(page, /所需证据阻塞项/);
  assert.match(page, /requiredEvidenceBlockedCount/);
  assert.match(page, /晋级审计阻塞项/);
  assert.match(page, /promotionAuditBlockedCount/);
  assert.match(page, /promotionAuditCreatedCount/);
  assert.match(page, /promotionAuditProvenanceRefCount/);
  assert.match(page, /promotionAuditReviewEvidenceRefCount/);
  assert.match(page, /promotionAuditLatestReason/);
  assert.match(page, /readyRunIds/);
  assert.match(page, /\/reports\/\$\{encodeURIComponent\(runId\)\}/);
  assert.match(page, /审核发现候选项/);
  assert.match(page, /需要人工审核/);
  assert.match(page, /需要审核/);
  assert.match(page, /label="审核阻塞项"/);
  assert.doesNotMatch(page, /Blocked claims/);
  assert.doesNotMatch(page, /漏洞候选晋级已阻断/);
  assert.doesNotMatch(page, /已阻断晋级尝试/);
  assert.doesNotMatch(page, /label="Blocked"/);
  assert.match(page, /toCampaignReportDraftEvidenceSummary/);
  assert.match(page, /toCampaignReportDraftSummaries/);
  assert.match(page, /人工提交门/);
  assert.match(page, /<span>证据引用<\/span>/);
  assert.doesNotMatch(page, /<span>Evidence<\/span>/);
  assert.match(page, /人工审核需要人工决策/);
  assert.match(page, /报告提交已阻断/);
  assert.match(page, /暂无加入审核队列的报告草稿。/);
  assert.doesNotMatch(page, /No campaign-linked report drafts recorded/);
  assert.doesNotMatch(page, /label="Runs"/);
  assert.doesNotMatch(page, /label="Run"/);
  assert.doesNotMatch(page, /审核已就绪/);
  assert.doesNotMatch(page, /recordManualObservation|recordClaimReviewDecision|createFindingCandidate|recordMythosBrainOutcome|executeValidation|submitReport/);
  assert.doesNotMatch(page, /<form|method="post"|action=\{/);
});

test("campaign tasks page reads task records and stays read-only", async () => {
  const page = await import("node:fs/promises").then((fs) =>
    fs.readFile(new URL("../app/campaigns/[campaignId]/tasks/page.tsx", import.meta.url), "utf8"),
  );

  assert.match(page, /params: Promise<\{ campaignId: string \}>/);
  assert.match(page, /getCampaignTasks\(campaignId, \[\]\)/);
  assert.match(page, /toCampaignTaskSummaries/);
  assert.match(page, /研究审核/);
  assert.doesNotMatch(page, /Research Tasks/);
  assert.doesNotMatch(page, /Campaign Tasks/);
  assert.match(page, /\/tasks\/\$\{encodeURIComponent\(task\.id\)\}/);
  assert.match(page, /仅供审核的研究工作项/);
  assert.match(page, /暂无可审核的研究工作项/);
  assert.doesNotMatch(page, /No campaign task records/);
  assert.doesNotMatch(page, /No research tasks ready/);
  assert.match(page, /研究工作台准备好仅供审核的工作后，研究审核项会显示在这里。/);
  assert.doesNotMatch(page, /Research tasks will appear here/);
  assert.doesNotMatch(page, /Tasks will appear here/);
  assert.match(page, />\s*审核项\s*</);
  assert.match(page, /label="审核项"/);
  assert.doesNotMatch(page, />\s*Task\s*</);
  assert.doesNotMatch(page, /label="Task"/);
  assert.doesNotMatch(page, /Queued autonomous work items/);
  assert.doesNotMatch(page, /dispatchTask|runTask|startCampaign|resumeCampaign|pauseCampaign|executeValidation|submitReport/);
  assert.doesNotMatch(page, /<form|method="post"|action=\{/);
});

test("campaign research task review page drafts 审查计划s without execution", async () => {
  const page = await import("node:fs/promises").then((fs) =>
    fs.readFile(
      new URL("../app/campaigns/[campaignId]/tasks/[taskId]/page.tsx", import.meta.url),
      "utf8",
    ),
  );

  assert.match(page, /params: Promise<\{ campaignId: string; taskId: string \}>/);
  assert.match(page, /getCampaignResearchTaskReview\(campaignId, taskId, null\)/);
  assert.match(page, /createResearchReviewPlan/);
  assert.match(page, /createResearchRefutationDecision/);
  assert.match(page, /createReviewPlanAction/);
  assert.match(page, /recordNeedsEvidenceDecisionAction/);
  assert.match(page, /"use server"/);
  assert.match(page, /revalidatePath/);
  assert.match(page, /toCampaignResearchTaskReviewSummary/);
  assert.match(page, /最近审核计划/);
  assert.match(page, /最近反证决策/);
  assert.match(page, /建议反证决策/);
  assert.match(page, /suggestedRefutationDecision/);
  assert.match(page, /refutationQuestionCount/);
  assert.match(page, /refutationAnswerCount/);
  assert.match(page, /validationMode/);
  assert.match(page, /targetRef/);
  assert.match(page, /label="验证模式"/);
  assert.match(page, /label="下一步审核操作"/);
  assert.doesNotMatch(page, /label="下一步操作"/);
  assert.match(page, /等待验证审核/);
  assert.doesNotMatch(page, /Not allowed yet/);
  assert.match(page, /label="目标"/);
  assert.match(page, /最近验证反馈/);
  assert.match(page, /自主候选项审核/);
  assert.match(page, /autonomousCandidateContext/);
  assert.match(page, /candidateId/);
  assert.match(page, /refutationQuestions/);
  assert.match(page, /triageSignals/);
  assert.match(page, /evidenceFocus/);
  assert.match(page, /sourceFactTypes/);
  assert.match(page, /候选项分诊信号/);
  assert.match(page, /候选项证据重点/);
  assert.match(page, /候选项所需证据/);
  assert.match(page, /requiredEvidence/);
  assert.match(page, /候选项质量门原因/);
  assert.match(page, /qualityGateReasons/);
  assert.match(page, /rawPriorityScore/);
  assert.match(page, /候选项源代码事实/);
  assert.match(page, /validationSteps/);
  assert.match(page, /blockedActions/);
  assert.match(page, /需要人工审核/);
  assert.doesNotMatch(page, /Human approval required/);
  assert.match(page, /latestValidationFeedback/);
  assert.match(page, /findingConfirmationAllowed/);
  assert.match(page, /\/feedback-reviews\/\$\{encodeURIComponent\(summary\.latestValidationFeedback\.feedbackStageId\)\}/);
  assert.match(page, /审核晋级门/);
  assert.match(page, /latestRefutationDecision/);
  assert.match(page, /approvalId/);
  assert.match(page, /validationRunId/);
  assert.match(page, /审核门/);
  assert.match(page, /label="人工审核"/);
  assert.match(page, /label="审核门记录"/);
  assert.match(page, /无审核门/);
  assert.doesNotMatch(page, /label="Human approval"/);
  assert.doesNotMatch(page, /label="Approval"/);
  assert.doesNotMatch(page, /No approval request/);
  assert.match(page, /非破坏性计划/);
  assert.match(page, /起草审核计划/);
  assert.match(page, /起草审核计划/);
  assert.match(page, /记录需要证据/);
  assert.match(page, /记录需要证据/);
  assert.match(page, /latestReviewPlan\.planId/);
  assert.match(page, /decision: "needs_evidence"/);
  assert.match(page, /candidate_context_summary/);
  assert.match(page, /triage_signal_count/);
  assert.match(page, /evidence_focus_count/);
  assert.match(page, /source_fact_type_count/);
  assert.match(page, /has_authorization_gap_candidate/);
  assert.match(page, /rationale: "验证前需要更多已脱敏证据。"/);
  assert.match(page, /refutation_answers/);
  assert.match(page, /action=\{recordNeedsEvidenceDecisionAction\}/);
  assert.match(page, /reviewHypothesis/);
  assert.match(page, /reviewRefutationQuestions/);
  assert.match(page, /reviewEvidencePlan/);
  assert.match(page, /reviewer: "operator"/);
  assert.match(page, /rationale: "根据已脱敏研究审核上下文起草。"/);
  assert.match(page, /action=\{createReviewPlanAction\}/);
  assert.match(page, /操作门/);
  assert.match(page, /仅供审核/);
  assert.doesNotMatch(page, /label="Execution"/);
  assert.doesNotMatch(page, /Execution blocked/);
  assert.match(page, /验证审计/);
  assert.match(page, /暂无验证审计/);
  assert.doesNotMatch(page, /Validation run/);
  assert.doesNotMatch(page, /No validation run/);
  assert.match(page, /label="审核门"/);
  assert.match(page, /label="审核项"/);
  assert.doesNotMatch(page, /Task review gate/);
  assert.doesNotMatch(page, /label="Task"/);
  assert.match(page, /推理记忆键/);
  assert.doesNotMatch(page, /Research memory key/);
  assert.match(page, />\s*研究审核\s*</);
  assert.doesNotMatch(page, />\s*Research Tasks\s*</);
  assert.match(page, /必需人工审核门/);
  assert.doesNotMatch(page, /label="Queue"/);
  assert.doesNotMatch(page, />\s*Tasks\s*</);
  assert.doesNotMatch(page, />Safety gate</);
  assert.doesNotMatch(page, /dispatchTask|runTask|approveValidation|executeValidation|submitReport|materializeResearchQueueTask|createFindingCandidate/);
  assert.match(page, /<form/);
});

test("campaign agent runs page reads audit records and stays read-only", async () => {
  const page = await import("node:fs/promises").then((fs) =>
    fs.readFile(new URL("../app/campaigns/[campaignId]/agent-runs/page.tsx", import.meta.url), "utf8"),
  );

  assert.match(page, /params: Promise<\{ campaignId: string \}>/);
  assert.match(page, /getCampaignAgentRuns\(campaignId, \[\]\)/);
  assert.match(page, /toCampaignAgentRunSummaries/);
  assert.match(page, /智能体审计/);
  assert.match(page, /智能体审计/);
  assert.match(page, /审核门/);
  assert.match(page, /暂无可查看的智能体审计。/);
  assert.doesNotMatch(page, /Agent runs/);
  assert.doesNotMatch(page, /Agent run audit/);
  assert.doesNotMatch(page, /No agent runs recorded/);
  assert.match(page, /<span>输入引用<\/span>/);
  assert.match(page, /<span>输出引用<\/span>/);
  assert.doesNotMatch(page, /<span>Inputs<\/span>/);
  assert.doesNotMatch(page, /<span>Outputs<\/span>/);
  assert.doesNotMatch(page, /safety gates/);
  assert.match(page, /范围守卫决策/);
  assert.doesNotMatch(page, />Safety gate</);
  assert.doesNotMatch(page, /startCampaign|resumeCampaign|pauseCampaign|executeValidation|submitReport/);
  assert.doesNotMatch(page, /<form|method="post"|action=\{/);
});

test("campaign validation queue page reads approval records and stays read-only", async () => {
  const page = await import("node:fs/promises").then((fs) =>
    fs.readFile(new URL("../app/campaigns/[campaignId]/validation-queue/page.tsx", import.meta.url), "utf8"),
  );

  assert.match(page, /params: Promise<\{ campaignId: string \}>/);
  assert.match(page, /getCampaignApprovals\(campaignId, \[\]\)/);
  assert.match(page, /toCampaignValidationQueueSummaries/);
  assert.match(page, /审核门队列/);
  assert.match(page, /下一步操作/);
  assert.match(page, /nextAction/);
  assert.doesNotMatch(page, /Approval Review/);
  assert.doesNotMatch(page, />Validation Queue</);
  assert.match(page, /审核门请求/);
  assert.match(page, /暂无可处理的审核门请求/);
  assert.match(page, /研究活动进入人工审核门后，请求会显示在这里。/);
  assert.doesNotMatch(page, /Approval review records/);
  assert.doesNotMatch(page, /No approval review records/);
  assert.doesNotMatch(page, /Approval records will appear/);
  assert.match(page, /任何验证启动前仍需完成预检。/);
  assert.match(page, /审核门/);
  assert.match(page, /审核门状态/);
  assert.match(page, /label="审核门"/);
  assert.doesNotMatch(page, /label="Approval"/);
  assert.match(page, /label="审核项"/);
  assert.match(page, /label="研究审计"/);
  assert.doesNotMatch(page, /label="Task"/);
  assert.doesNotMatch(page, /label="Run"/);
  assert.doesNotMatch(page, />Safety gate</);
  assert.doesNotMatch(page, /Approval-required validation records/);
  assert.doesNotMatch(page, /decideApproval|approveValidation|denyValidation|executeValidation|submitReport/);
  assert.doesNotMatch(page, /<form|method="post"|action=\{/);
});

test("campaign timeline page reads pipeline stage records and stays read-only", async () => {
  const page = await import("node:fs/promises").then((fs) =>
    fs.readFile(new URL("../app/campaigns/[campaignId]/timeline/page.tsx", import.meta.url), "utf8"),
  );

  assert.match(page, /params: Promise<\{ campaignId: string \}>/);
  assert.match(page, /getCampaignPipelineStages\(campaignId, \[\]\)/);
  assert.match(page, /toCampaignTimelineSummaries/);
  assert.match(page, /审核时间线/);
  assert.doesNotMatch(page, /Pipeline timeline/);
  assert.match(page, /<span>输入引用<\/span>/);
  assert.match(page, /<span>输出引用<\/span>/);
  assert.match(page, /<span>耗时<\/span>/);
  assert.match(page, /<span>错误<\/span>/);
  assert.match(page, /formatDuration/);
  assert.match(page, /stage\.durationSeconds/);
  assert.match(page, /stage\.errorSummary/);
  assert.match(page, /未记录/);
  assert.doesNotMatch(page, /<span>Inputs<\/span>/);
  assert.doesNotMatch(page, /<span>Outputs<\/span>/);
  assert.match(page, /manualValidationResultCount/);
  assert.match(page, /manualValidationReview/);
  assert.match(page, /质量审核/);
  assert.match(page, /qualityScore/);
  assert.match(page, /redactionStatus/);
  assert.match(page, /promotionReviewReady/);
  assert.match(page, /researchValidationFeedbackCount/);
  assert.match(page, /isResearchValidationFeedback/);
  assert.match(page, /研究反馈/);
  assert.match(page, /validationFeedbackReviewCount/);
  assert.match(page, /isValidationFeedbackReview/);
  assert.match(page, /反馈审核/);
  assert.match(page, /审核门：\{stage\.approvalCreated \? "已记录" : "待处理"\}/);
  assert.doesNotMatch(page, /审核门: \{stage\.approvalCreated \? "created" : "not created"\}/);
  assert.doesNotMatch(page, /Approval: \{stage\.approvalCreated/);
  assert.match(page, /发现确认门：/);
  assert.match(page, /报告提交门：/);
  assert.match(page, /验证门：/);
  assert.match(page, /执行门：/);
  assert.match(page, /stage\.reportSubmissionAllowed \? "已审核" : "受控"/);
  assert.match(page, /stage\.validationAllowed \? "已审核" : "受控"/);
  assert.match(page, /stage\.executionAllowed \? "已审核" : "受控"/);
  assert.doesNotMatch(page, /submission: \{stage\.reportSubmissionAllowed \? "open" : "gated"\}/);
  assert.doesNotMatch(page, /Validation: \{stage\.validationAllowed \? "open" : "gated"\}/);
  assert.doesNotMatch(page, /Execution:\{"\\s*"\}\s*\{stage\.executionAllowed \? "open" : "gated"\}/);
  assert.match(page, /decision/);
  assert.match(page, /findingPromotionBlockedCount/);
  assert.match(page, /isFindingPromotionBlocked/);
  assert.match(page, /isFindingPromotion/);
  assert.match(page, /promotionProvenanceRefCount/);
  assert.match(page, /reviewEvidenceRefCount/);
  assert.match(page, /isResearchQueueMaterialized/);
  assert.match(page, /refutationQuestionCount/);
  assert.match(page, /validationStepCount/);
  assert.match(page, /blockedActionCount/);
  assert.match(page, /requiredEvidence/);
  assert.match(page, /所需证据/);
  assert.match(page, /evidenceFocusCount/);
  assert.match(page, /sourceFactTypeCount/);
  assert.match(page, /triageSignalCount/);
  assert.match(page, /priorityReasonCount/);
  assert.match(page, /优先级原因/);
  assert.match(page, /hasAuthorizationGapCandidate/);
  assert.match(page, /候选项上下文/);
  assert.match(page, /访问控制缺口候选/);
  assert.match(page, /candidateStatus/);
  assert.match(page, /研究审核已入队/);
  assert.match(page, /晋级审核/);
  assert.match(page, /LLM 审计/);
  assert.match(page, /仅提示词哈希/);
  assert.match(page, /hunterOperatingAction/);
  assert.match(page, /llmAuditPromptHash/);
  assert.doesNotMatch(page, /prompt_text|raw prompt|promptText|evidence_refs|raw evidence/);
  assert.match(page, /晋级阻塞项/);
  assert.match(page, /learningOutcomeCount/);
  assert.match(page, /cycleReviewCount/);
  assert.match(page, /\/cycle-reviews\/\$\{encodeURIComponent\(stage\.id\)\}/);
  assert.match(page, /完成周期审核/);
  assert.match(page, /审核门/);
  assert.match(page, /审核门/);
  assert.match(page, /暂无可查看的审核时间线。/);
  assert.doesNotMatch(page, /No pipeline stages recorded/);
  assert.doesNotMatch(page, />Safety gate</);
  assert.doesNotMatch(page, /startCampaign|resumeCampaign|pauseCampaign|executeValidation|submitReport/);
  assert.doesNotMatch(page, /<form|method="post"|action=\{/);
});
