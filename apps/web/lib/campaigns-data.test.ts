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
      summary: "Manual validation result recorded: observed",
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
      next_allowed_action: "Review hypothesis board and plan non-destructive evidence work.",
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
  program_name: "Example Program",
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
  assert.equal(summary.safeNextAction, "Review gate requests");
  assert.equal(summary.safeNextHref, "/campaigns/campaign_1/validation-queue");
  assert.deepEqual(summary.blockedReasons, ["Review required"]);
  assert.doesNotMatch(JSON.stringify(summary), /Review approval requests|Approval required/i);
  assert.equal(
    summary.budgetLabel,
    "30m / 5000 tokens / 2/10 tools used, 8 remaining / 1/1 validations used, 0 remaining",
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
      nextAllowedAction: "Review hypothesis board and plan non-destructive evidence work.",
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
        nextAllowedAction: "Review evidence gates before report drafting.",
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
      safetyGate: "Advisory memory only",
      source: "Mythos brain reasoning memory",
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
        next_allowed_action: "Review validation plan before any execution.",
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
        title: "Review autonomous hunt candidate candidate_1",
        top_candidate_rank: 1,
        validation_step_count: 2,
      },
    ],
  });

  assert.deepEqual(summary.researchQueueSuggestions, [
    {
      blockedActionCount: 4,
      candidateStatus: "Awaiting human approval",
      executionAllowed: false,
      humanApprovalRequired: true,
      nextAllowedAction: "Review validation plan before any execution.",
      playbookId: "bola_idor",
      priorityScore: 91,
      rawPriorityScore: 100,
      qualityGateReasons: ["Required evidence missing", "[redacted]"],
      evidenceNeeded: ["Approved test object id matrix"],
      evidenceTraceSummary: {
        artifactKinds: ["Api", "[redacted]"],
        reportSubmissionAllowed: false,
        routeFactCount: 2,
        sourceFactCount: 3,
        sourceFactTypes: ["Route handler", "[redacted]"],
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
      requiredEvidence: ["Independent refutation or static rule", "Policy"],
      satisfiedEvidence: ["Local code or har correlation"],
      safetyGate: "Awaiting human approval",
      source: "Mythos pipeline autonomous hunt queue",
      surfaceKey: null,
      title: "Review autonomous hunt candidate candidate_1",
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

  assert.equal(summary.safeNextAction, "Review validation audit");
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

  assert.equal(summary.safeNextAction, "Review manual validation observation");
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
      fallback,
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

  assert.equal(summary.safeNextAction, "Review attack surface map");
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

  assert.equal(summary.safeNextAction, "Review research tasks");
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

  assert.equal(summary.safeNextAction, "Review evidence or report drafts");
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
      next_allowed_action: "Review blocked promotion evidence before retrying candidate promotion.",
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

  assert.equal(summary.safeNextAction, "Review blocked promotion evidence");
  assert.equal(summary.safeNextHref, "/campaigns/campaign_1/evidence-review");
  assert.deepEqual(summary.blockedReasons, ["Blocked by research feedback gate"]);
  assert.equal(summary.executionAllowed, false);
  assert.equal(summary.promotionReviewBlockedCount, 1);
  assert.equal(summary.promotionReviewLatestReason, "Blocked by research feedback gate");
  assert.equal(
    summary.promotionReviewNextAllowedAction,
    "Review blocked promotion evidence before retrying candidate promotion.",
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

  assert.equal(summary.safeNextAction, "Promote finding candidate");
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

  assert.equal(summary.safeNextAction, "Review learning outcome");
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

  assert.equal(summary.safeNextAction, "Review learning outcome");
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

  assert.equal(summary.safeNextAction, "Review campaign cycle");
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

  assert.equal(summary.safeNextAction, "Resolve blockers");
  assert.equal(summary.safeNextHref, "/campaigns/campaign_1");
  assert.deepEqual(summary.blockedReasons, ["Budget exhausted"]);
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
      agentType: "Orchestrator agent",
      finishedAt: null,
      id: "run_1",
      inputRefCount: 2,
      outputRefCount: 1,
      safetyGateState: "Scope Guard reviewed",
      startedAt: "2026-07-05T00:00:00Z",
      status: "Dispatched",
      stopReason: "Review required",
      taskId: "task_1",
    },
  ]);
  assert.doesNotMatch(JSON.stringify(summaries), /Scope Guard clear/);
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
      agentType: "Orchestrator agent",
      createdAt: "2026-07-05T00:00:00Z",
      id: "task_1",
      inputRefCount: 2,
      outputRefCount: 1,
      status: "Queued",
      taskType: "Campaign observation",
      title: "Untitled task",
    },
  ]);
  assert.doesNotMatch(JSON.stringify(summaries), /secret-token|session-secret|cookie=session|X-API-Key/i);
});

test("toCampaignResearchTaskReviewSummary keeps research workspace advisory and redacted", () => {
  const summary = toCampaignResearchTaskReviewSummary({
    campaign_id: "campaign_1",
    dispatch_allowed: true,
    execution_allowed: true,
    next_allowed_action: "Review hypothesis board and plan non-destructive evidence work.",
    latest_refutation_decision: {
      approval_id: "approval_1",
      campaign_id: "campaign_1",
      decision: "needs_evidence",
      decision_id: "refutation_decision_1",
      dispatch_allowed: true,
      execution_allowed: true,
      next_allowed_action: "Collect redacted evidence or refine the hypothesis before validation.",
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
      next_allowed_action: "Review validation evidence before finding promotion.",
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
      "Collect only redacted artifact summaries and provenance counts.",
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
      hypothesis: "[redacted]",
      nextAllowedAction: "Review hypothesis board and request review before validation.",
      planId: "research_plan_1",
      refutationQuestions: ["Can redacted provenance disprove this"],
      reportSubmissionAllowed: false,
      requiredHumanGates: ["Scope guard review"],
      safetyGate: "Advisory plan only",
      status: "Drafted",
      taskId: "task_1",
      validationAllowed: false,
    },
    latestRefutationDecision: {
      approvalId: "approval_1",
      campaignId: "campaign_1",
      decision: "Needs evidence",
      decisionId: "refutation_decision_1",
      dispatchAllowed: false,
      executionAllowed: false,
      nextAllowedAction: "Collect redacted evidence or refine the hypothesis before validation.",
      planId: "research_plan_1",
      rationale: "[redacted]",
      refutationAnswers: ["Current artifact summaries do not prove missing checks."],
      reportSubmissionAllowed: false,
      taskId: "task_1",
      validationAllowed: false,
      validationRunId: "validation_run_1",
    },
    suggestedRefutationDecision: {
      decision: "Needs validation review",
      dispatchAllowed: false,
      executionAllowed: false,
      humanReviewRequired: true,
      nextAllowedAction: "Prepare a human-reviewed validation plan without executing it.",
      planId: "auto_research_plan_1",
      rationale: "[redacted]",
      refutationAnswerCount: 0,
      refutationQuestionCount: 2,
      reportSubmissionAllowed: false,
      targetRef: "campaign:campaign_1",
      validationAllowed: false,
      validationMode: "Two account review check",
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
      nextAllowedAction: "Review validation evidence before finding promotion.",
      outcome: "Observed",
      planId: "research_plan_1",
      reportSubmissionAllowed: false,
      safetyGate: "Advisory validation feedback only",
      status: "Evidence recorded",
      taskId: "task_1",
      validationAllowed: false,
      validationRunId: "validation_run_1",
    },
    nextAllowedAction: "Review hypothesis board and plan non-destructive evidence work.",
    nonDestructivePlan: [
      "Review existing hypothesis board entries for Authorization=[redacted]",
      "Collect only redacted artifact summaries and provenance counts.",
    ],
    playbookId: "bola_idor",
    priorityScore: 100,
    queueKey: "reasoning_memory:bola_idor",
    reportSubmissionAllowed: false,
    requiredHumanGates: [
      "Scope guard review",
      "Redaction review",
      "Review required before validation",
    ],
    safetyGate: "Advisory memory only",
    source: "Mythos brain reasoning memory",
    status: "Queued review",
    surfaceKey: "file_id:export",
    taskId: "task_1",
    title: "Review bola_idor reasoning memory with session=[redacted]",
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
    next_allowed_action: "Review validation plan before any execution.",
    non_destructive_plan: ["Prepare a human-reviewed validation plan without executing it."],
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
    title: "Review autonomous hunt candidate hypothesis_1",
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
        next_allowed_action: "Prepare a submission-blocked draft for human redaction review.",
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
        "Does Scope Guard allow validation?",
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
      "Execute live validation",
      "Blocked action",
      "Submit report",
    ],
    candidateId: "hypothesis_1",
    candidateStatus: "Awaiting human review",
    dispatchAllowed: false,
    evidenceNeeded: ["Approved test object id matrix", "[redacted]"],
    evidenceTraceSummary: {
      artifactKinds: ["Api", "[redacted]"],
      reportSubmissionAllowed: false,
      routeFactCount: 1,
      sourceFactCount: 2,
      sourceFactTypes: ["Access control gap candidate", "[redacted]"],
      traceStatus: "traceable",
      traceableSourceFactCount: 2,
    },
    reportReadiness: {
      nextAllowedAction: "Prepare a submission-blocked draft for human redaction review.",
      reportSubmissionAllowed: false,
      requiredEvidenceCount: 0,
      safeValidationStepCount: 2,
      status: "submission_blocked_draft_ready",
      submissionBlocked: true,
      traceStatus: "traceable",
    },
    evidenceFocus: ["Same handler authz evidence", "[redacted]"],
    executionAllowed: false,
    humanApprovalRequired: true,
    hypothesis: "[redacted]",
    pipelineRunId: "pipeline_run_1",
    rawPriorityScore: 100,
    qualityGateReasons: ["Required evidence missing", "[redacted]"],
    refutationQuestions: [
      "Can same-handler authorization evidence refute the missing access-control check candidate",
      "Can existing redacted artifacts disprove this",
      "Does Scope Guard allow validation",
    ],
    refutationStatus: "Needs evidence",
    requiredEvidence: [
      "Independent refutation or static rule",
      "Policy",
      "[redacted]",
    ],
    satisfiedEvidence: ["Local code or har correlation"],
    reportSubmissionAllowed: false,
    safetyNotes: ["Scope guard required", "Human review required"],
    sourceFactTypes: ["Access-control gap candidate", "Sensitive sink"],
    triageSignals: [
      "Access control gap candidate",
      "Sensitive sink present",
      "Human review required",
    ],
    validationAllowed: false,
    validationPlanStatus: "Requires review",
    validationSteps: [
      "Use two authorized test accounts only.",
      "Validation step redacted",
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
      approvalType: "Validation batch",
      asset: "api.example.com/path",
      createdAt: "2026-07-05T00:00:00Z",
      expiresAt: null,
      id: "approval_1",
      planDigest: "plan_digest_1",
      reason: "Needs review; Authorization=[redacted]",
      requestedAction: "Two account review check",
      runId: null,
      safetyGateState: "Awaiting review gate",
      status: "Pending",
      taskId: "task_1",
      validationMode: "Two account review check",
      nextAction: "Review the gate record, then run Scope Guard preflight before validation.",
    },
    {
      approvalType: "Review gate",
      asset: "api.example.com",
      createdAt: "2026-07-05T00:00:00Z",
      expiresAt: null,
      id: "approval_2",
      planDigest: null,
      reason: "Review required",
      requestedAction: null,
      runId: null,
      safetyGateState: "Awaiting review gate",
      status: "Pending",
      taskId: null,
      validationMode: null,
      nextAction: "Review the gate record, then run Scope Guard preflight before validation.",
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
      executionState: "Awaiting review gate",
      finishedAt: null,
      id: "validation_run_1",
      attentionState: "Review gate missing",
      planDigest: "plan_digest_1",
      preflightPassed: false,
      safetyGateState: "Awaiting review gate",
      status: "Awaiting review gate",
      summary: "Needs review; Authorization=[redacted]",
      targetRef: "candidate:idor",
      taskId: "task_1",
      validationMode: "Two account review check",
      nextAction: "Review the validation gate before preflight.",
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
  assert.equal(summaries[0].executionState, "Preflight required");
  assert.equal(summaries[0].attentionState, "Preflight required");
  assert.equal(summaries[0].nextAction, "Run Scope Guard preflight before validation.");
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
      summary: "Scope Guard preflight passed.",
      target_ref: "campaign:campaign_1",
      task_id: "task_1",
      validation_mode: "two_account_authorization_check",
    },
  ]);

  assert.equal(summaries[0].allowedToExecute, true);
  assert.equal(summaries[0].preflightPassed, true);
  assert.equal(summaries[0].executionStarted, false);
  assert.equal(summaries[0].executionState, "Preflight passed");
  assert.equal(summaries[0].attentionState, "Preflight passed");
  assert.equal(
    summaries[0].nextAction,
    "Review manual validation observation before any evidence promotion.",
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
      summary: "Validation started.",
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
      summary: "Preflight blocked.",
      target_ref: "campaign:campaign_1",
      task_id: "task_1",
      validation_mode: "two_account_authorization_check",
    },
  ]);

  assert.equal(summaries[0].executionState, "Validation started");
  assert.equal(summaries[1].executionState, "Preflight blocked");
  assert.doesNotMatch(JSON.stringify(summaries), /Execution started|Execution blocked/);
});

test("toCampaignArtifactSummaries exposes campaign artifact safety without raw material", () => {
  const summaries = toCampaignArtifactSummaries(campaignArtifacts);

  assert.deepEqual(summaries, [
    {
      asset: "api.example.com/path",
      createdAt: "2026-07-05T00:00:00Z",
      id: "artifact_safe",
      ingestionStatus: "Normalized",
      kind: "Openapi",
      reportChainAllowed: true,
      safetyBlockerCount: 0,
      sensitivityLabel: "Low",
      sourceType: "Dry run inline",
      usageCount: 1,
      usageStages: [{ count: 1, label: "Target model" }],
      usageTypes: [{ count: 1, label: "Pipeline run" }],
    },
    {
      asset: "api.example.com",
      createdAt: "2026-07-05T00:01:00Z",
      id: "artifact_blocked",
      ingestionStatus: "Normalized",
      kind: "Har",
      reportChainAllowed: false,
      safetyBlockerCount: 2,
      sensitivityLabel: "Sensitive",
      sourceType: "Manual upload",
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
      auditLabel: "Campaign tick",
      id: "stage_1",
      inputRefCount: 2,
      isCycleReview: false,
      isLearningOutcome: false,
      isManualValidationResult: false,
      outputRefCount: 1,
      safetyGateState: "Blocked",
      stageKey: "Campaign tick",
      stageOrder: 0,
      status: "Blocked",
      stopReason: "Review required",
      taskId: "task_1",
    },
  ]);
  assert.doesNotMatch(JSON.stringify(summaries), /secret-token|session=secret|token=secret/i);
  assert.doesNotMatch(JSON.stringify(summaries), /Approval required/i);
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
      auditLabel: "Manual validation result",
      id: "stage_manual_result",
      inputRefCount: 1,
      isCycleReview: false,
      isLearningOutcome: false,
      isManualValidationResult: true,
      manualValidationReview: {
        evidenceQuality: "Adequate",
        promotionReviewReady: false,
        qualityReasons: [
          "Manual result recorded",
          "Has report safe evidence",
          "Promotion blocked by redaction review",
        ],
        qualityScore: 45,
        redactionStatus: "Redacted",
        safeEvidenceRefCount: 1,
        sourceType: "Manual safe observation",
        unsafeEvidenceRefCount: 1,
      },
      outputRefCount: 2,
      safetyGateState: "Manual evidence recorded",
      stageKey: "Validation manual result",
      stageOrder: 3,
      status: "Evidence recorded",
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
      auditLabel: "Research validation feedback",
      id: "stage_research_feedback",
      inputRefCount: 3,
      isCycleReview: false,
      isLearningOutcome: false,
      isManualValidationResult: false,
      isResearchValidationFeedback: true,
      outputRefCount: 1,
      safetyGateState: "Advisory validation feedback only",
      stageKey: "Research task validation feedback",
      stageOrder: 9,
      status: "Evidence recorded",
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
      auditLabel: "Finding promotion blocked",
      id: "stage_promotion_blocked",
      inputRefCount: 1,
      isCycleReview: false,
      isFindingPromotionBlocked: true,
      isLearningOutcome: false,
      isManualValidationResult: false,
      outputRefCount: 0,
      safetyGateState: "Manual review required",
      stageKey: "Finding promotion blocked",
      stageOrder: 10,
      status: "Blocked",
      stopReason: "Blocked by research feedback gate",
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
      auditLabel: "Finding promotion review",
      id: "stage_promotion_created",
      inputRefCount: 2,
      isCycleReview: false,
      isFindingPromotion: true,
      isLearningOutcome: false,
      isManualValidationResult: false,
      outputRefCount: 1,
      safetyGateState: "Manual review required",
      stageKey: "Finding promotion",
      stageOrder: 11,
      status: "Candidate created",
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
      auditLabel: "Finding promotion review",
      id: "stage_promotion_created",
      inputRefCount: 2,
      isCycleReview: false,
      isFindingPromotion: true,
      isLearningOutcome: false,
      isManualValidationResult: false,
      hunterOperatingAction: "Promote to finding candidate",
      llmAuditMode: "Audit only",
      llmAuditPromptHash: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
      llmAuditPromptTextStored: false,
      outputRefCount: 1,
      promotionProvenanceRefCount: 2,
      reviewEvidenceRefCount: 2,
      safetyGateState: "Manual review required",
      stageKey: "Finding promotion",
      stageOrder: 11,
      status: "Candidate created",
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
      auditLabel: "Validation feedback review",
      decision: "Allow finding promotion",
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
      safetyGateState: "Manual review required",
      stageKey: "Research task validation feedback review",
      stageOrder: 12,
      status: "Completed",
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
      auditLabel: "Research review queued",
      blockedActionCount: 4,
      candidateStatus: "Awaiting human approval",
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
        "Independent refutation or static rule",
        "Policy",
        "[redacted]",
      ],
      safetyGateState: "Manual review required",
      stageKey: "Research queue materialized",
      stageOrder: 12,
      status: "Queued review",
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
      auditLabel: "Research plan drafted",
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
        "Independent refutation or static rule",
        "Policy",
        "[redacted]",
      ],
      sourceFactTypeCount: 1,
      safetyGateState: "Advisory plan only",
      stageKey: "Research task review plan",
      stageOrder: 13,
      status: "Drafted",
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
      auditLabel: "Refutation decision",
      blockedActionCount: 4,
      decision: "Needs validation review",
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
      safetyGateState: "Advisory refutation only",
      stageKey: "Research task refutation decision",
      stageOrder: 14,
      status: "Needs validation review",
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
      auditLabel: "Advisory Brain learning",
      id: "stage_learning_result",
      inputRefCount: 1,
      isCycleReview: false,
      isLearningOutcome: true,
      isManualValidationResult: false,
      outputRefCount: 2,
      safetyGateState: "Advisory memory only",
      stageKey: "Learning outcome recorded",
      stageOrder: 4,
      status: "Recorded",
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
      auditLabel: "Campaign cycle review",
      id: "stage_cycle_review",
      inputRefCount: 1,
      isCycleReview: true,
      isLearningOutcome: false,
      isManualValidationResult: false,
      outputRefCount: 2,
      safetyGateState: "Allowed",
      stageKey: "Campaign cycle review",
      stageOrder: 5,
      status: "Awaiting review",
      stopReason: "Campaign cycle review required",
      taskId: null,
    },
  ]);
  assert.doesNotMatch(JSON.stringify(summaries), /secret-token|session=secret|authorization: bearer/i);
});

test("toCampaignBrainSummary keeps Mythos Brain advisory and redacted", () => {
  const summary = toCampaignBrainSummary(brainProfile);

  assert.equal(summary.programId, "program_example");
  assert.equal(summary.programName, "Example Program");
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
      "Advisory memory only",
      "No execution permission",
      "Does not confirm vulnerability",
    ],
  });
  assert.equal(summary.topSurfaces[0].path, "/workspaces/{id}/owners");
  assert.equal(summary.recentSignals[0].notes, "Triager accepted; cookie=[redacted]");
  assert.equal(summary.appliedLessons[0].reasons[1], "[redacted]");
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
    safeNextAction: "Review learning outcome",
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
  assert.equal(view.facts[1].authzHint, "Access-control hint");
  assert.equal(view.facts[2].authzHint, "Missing handler access-control check");
  assert.equal(view.facts[2].factType, "Access-control gap candidate");
  assert.equal(view.scannerRuns[0].summary, "Static candidates only; Authorization=[redacted]");
  assert.doesNotMatch(JSON.stringify(view), /secret-token|token=secret|authorization: bearer/i);
  assert.doesNotMatch(JSON.stringify(view), /confirmed finding|vulnerability/i);
  assert.doesNotMatch(JSON.stringify(view), /Authz hint/);
});

test("toCampaignEvidenceReviewSummaries keeps claim evidence review redacted and gated", () => {
  const summaries = toCampaignEvidenceReviewSummaries([reportPreview]);

  assert.equal(summaries.length, 2);
  assert.equal(summaries[0].runId, "run_1");
  assert.equal(summaries[0].claimId, "claim_1");
  assert.equal(summaries[0].claimText, "Observed access-control drift; token=[redacted]");
  assert.equal(summaries[0].evidenceRefCount, 2);
  assert.equal(summaries[0].provenanceRefCount, 1);
  assert.equal(summaries[0].reviewEvidenceRefCount, 1);
  assert.equal(summaries[0].reportChainEligible, true);
  assert.equal(summaries[0].reviewRationale, "Human reviewed with cookie=[redacted]");
  assert.equal(summaries[0].reviewStatus, "Human reviewed observed fact");
  assert.equal(summaries[0].status, "Report review gated");
  assert.equal(summaries[1].reportChainEligible, false);
  assert.deepEqual(summaries[1].readinessBlockers, ["Missing evidence refs"]);
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
        next_allowed_action: "Review validation evidence before finding promotion.",
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
      next_allowed_action: "Review hypothesis board and plan non-destructive evidence work.",
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
      title: "Research feedback with Authorization: Bearer secret-token",
    },
  ]);

  assert.deepEqual(summaries, [
    {
      approvalId: "approval_1",
      evidenceRefCount: 2,
      feedbackStageId: "stage_feedback_1",
      findingPromotionAllowed: false,
      nextAllowedAction: "Review validation evidence before finding promotion.",
      outcome: "Observed",
      planId: "research_plan_1",
      promotionGate: "Manual review required",
      promotionGateReason: "Research validation feedback is advisory",
      promotionProvenanceRefCount: 6,
      reviewTitle: "Research feedback with Authorization=[redacted]",
      safetyGate: "Advisory validation feedback only",
      status: "Evidence recorded",
      taskId: "task_1",
      validationRunId: "validation_run_1",
    },
  ]);
  assert.doesNotMatch(JSON.stringify(summaries), /secret-token|authorization: bearer/i);
});

test("toCampaignPromotionBlockReviewSummaries turns blocked feedback into review queue items", () => {
  const feedback = toCampaignResearchFeedbackEvidenceSummaries([
    {
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
        next_allowed_action: "Review validation evidence before finding promotion.",
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
      next_allowed_action: "Review hypothesis board and plan non-destructive evidence work.",
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
      title: "Research feedback with Authorization: Bearer secret-token",
    },
  ]);

  const summaries = toCampaignPromotionBlockReviewSummaries(feedback);

  assert.deepEqual(summaries, [
    {
      approvalId: "approval_1",
      evidenceRefCount: 2,
      feedbackStageId: "stage_feedback_1",
      nextAllowedAction: "Review validation evidence before finding promotion.",
      planId: "research_plan_1",
      promotionGateReason: "Blocked by research feedback gate",
      promotionProvenanceRefCount: 1,
      reviewTitle: "Research feedback with Authorization=[redacted]",
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
      candidateEvidenceState: "Candidate evidence review required",
      evidenceRefCount: 2,
      nextReviewAction: "Review redaction, provenance, and claim coverage before report-chain use.",
      planDigest: "digest_1",
      preflightState: "Manual result recorded",
      reportChainState: "Report chain review required",
      reviewGate: "approval_1",
      reviewItem: "task_1",
      manualValidationReview: {
        evidenceQuality: "Adequate",
        promotionReviewState: "Promotion review gated",
        qualityReasons: [
          "Manual result recorded",
          "Has report safe evidence",
          "Promotion blocked by redaction review",
        ],
        qualityScore: 45,
        redactionStatus: "Redacted",
        safeEvidenceRefCount: 1,
        sourceType: "Manual safe observation",
        unsafeEvidenceRefCount: 1,
      },
      status: "Evidence recorded",
      summary: "Manual observation recorded; cookie [redacted]",
      targetRef: "api.example.com/files",
      validationMode: "Two account review check",
      validationRunId: "validation_1",
    },
    {
      candidateEvidenceState: "Evidence gap review required",
      evidenceRefCount: 0,
      nextReviewAction: "Collect redacted evidence refs before report-chain use.",
      planDigest: "digest_2",
      preflightState: "Manual result recorded",
      reportChainState: "Report chain blocked",
      reviewGate: "approval_2",
      reviewItem: "task_2",
      status: "Needs evidence",
      summary: "Evidence redacted; Authorization [redacted]",
      targetRef: "api.example.com",
      validationMode: "Manual review",
      validationRunId: "validation_2",
    },
  ]);
  assert.doesNotMatch(JSON.stringify(summaries), /secret-token|session=secret|authorization\s*[:=]|cookie=/i);
  assert.doesNotMatch(JSON.stringify(summaries), /eligible|confirmed|submission/i);
});

test("toCampaignValidationEvidenceQualitySummary counts review quality without raw evidence", () => {
  const summary = toCampaignValidationEvidenceQualitySummary([
    {
      candidateEvidenceState: "Candidate evidence review required",
      evidenceRefCount: 2,
      manualValidationReview: {
        evidenceQuality: "Strong",
        promotionReviewState: "Promotion review requires human decision",
        qualityReasons: ["Clean redaction review"],
        qualityScore: 80,
        redactionStatus: "Clean",
        safeEvidenceRefCount: 3,
        sourceType: "Manual safe observation",
        unsafeEvidenceRefCount: 0,
      },
      nextReviewAction: "Review redaction, provenance, and claim coverage before report-chain use.",
      planDigest: "digest_1",
      preflightState: "Manual result recorded",
      reportChainState: "Report chain review required",
      reviewGate: "approval_1",
      reviewItem: "task_1",
      status: "Evidence recorded",
      summary: "Manual result recorded.",
      targetRef: "api.example.com",
      validationMode: "Fixture replay",
      validationRunId: "validation_1",
    },
    {
      candidateEvidenceState: "Candidate evidence review required",
      evidenceRefCount: 1,
      manualValidationReview: {
        evidenceQuality: "Adequate",
        promotionReviewState: "Promotion review gated",
        qualityReasons: ["Promotion blocked by redaction review"],
        qualityScore: 45,
        redactionStatus: "Redacted",
        safeEvidenceRefCount: 1,
        sourceType: "Manual safe observation",
        unsafeEvidenceRefCount: 1,
      },
      nextReviewAction: "Review redaction, provenance, and claim coverage before report-chain use.",
      planDigest: "digest_2",
      preflightState: "Manual result recorded",
      reportChainState: "Report chain review required",
      reviewGate: "approval_2",
      reviewItem: "task_2",
      status: "Evidence recorded",
      summary: "Manual result recorded.",
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
      safetyNotes: ["Human review required", "cookie=[redacted]"],
      scopeStatus: "In scope",
      severity: "High",
      submissionBlocked: true,
      title: "Private object access with Authorization=[redacted]",
      topClaims: [
        "Observed access-control drift; token=[redacted]",
        "Model-only claim; session=[redacted]",
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
        next_allowed_action: "Review validation evidence before finding promotion.",
        outcome: "observed",
        plan_id: "research_plan_1",
        report_submission_allowed: true,
        safety_gate: "advisory_validation_feedback_only",
        status: "evidence_recorded",
        task_id: "task_1",
        validation_allowed: true,
        validation_run_id: "validation_run_1",
      },
      next_allowed_action: "Review hypothesis board and plan non-destructive evidence work.",
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
      title: "Research feedback with Authorization: Bearer secret-token",
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
    nextAllowedAction: "Review blocked promotion evidence before retrying candidate promotion.",
    promotionAuditBlockedCount: 1,
    promotionAuditCreatedCount: 1,
    promotionAuditLatestReason: "Blocked by research feedback gate",
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
    "Reviewed claims require a manual promotion decision after human review.",
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
    "Resolve required evidence gaps before candidate promotion.",
  );
  assert.deepEqual(summary.readyRunIds, []);
  assert.doesNotMatch(JSON.stringify(summary), /secret-token|authorization: bearer/i);
});

test("toCampaignFindingCandidateGateSummary blocks readiness on advisory validation feedback before promotion attempts", () => {
  const researchFeedback = toCampaignResearchFeedbackEvidenceSummaries([
    {
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
        next_allowed_action: "Review validation evidence before finding promotion.",
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
      next_allowed_action: "Review hypothesis board and plan non-destructive evidence work.",
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
      title: "Research feedback with Authorization: Bearer secret-token",
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
    "Review validation feedback before candidate promotion.",
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
        executionAllowed: false,
        humanApprovalRequired: true,
        nextAllowedAction: "Review validation plan before any execution.",
        playbookId: "bola_idor",
        priorityScore: 91,
        queueKey: "autonomous_hunt:run_1:hunt_queue_candidate_high",
        refutationQuestionCount: 2,
        evidenceNeeded: ["approved test object id matrix"],
        requiredEvidence: ["independent refutation or static rule", "Policy"],
        safetyGate: "Awaiting human approval",
        source: "Mythos pipeline autonomous hunt queue",
        surfaceKey: null,
        title: "Review autonomous hunt candidate candidate_high; Authorization: Bearer secret-token",
        topCandidateRank: 1,
        validationStepCount: 2,
      },
    ],
  );

  assert.equal(summaries.length, 3);
  assert.equal(summaries[0].candidateId, "candidate_high");
  assert.equal(summaries[0].source, "Pipeline run");
  assert.equal(summaries[0].hunterPriorityScore, 92);
  assert.equal(summaries[0].reviewPriorityScore, 100);
  assert.equal(summaries[0].impactScore, 88);
  assert.equal(summaries[0].duplicateRiskScore, 18);
  assert.equal(summaries[0].policyRiskScore, 12);
  assert.equal(summaries[0].hypothesis, "Hypothesis redacted");
  assert.equal(summaries[0].evidenceNeededCount, 1);
  assert.equal(summaries[0].evidenceFocusCount, 3);
  assert.deepEqual(summaries[0].triageSignals, [
    "Access control gap candidate",
    "Sensitive sink present",
    "Human review required",
  ]);
  assert.deepEqual(summaries[0].evidenceFocus, [
    "Same handler authz evidence",
    "Missing check refutation trace",
    "[redacted]",
  ]);
  assert.deepEqual(summaries[0].sourceFactTypes, [
    "Access-control gap candidate",
    "Sensitive sink",
  ]);
  assert.deepEqual(summaries[0].priorityReasons, [
    "Access-control gap candidate",
    "Same-handler access-control evidence needed",
    "Sensitive sink present",
  ]);
  assert.equal(summaries[0].refutationStatus, "Plausible");
  assert.equal(summaries[0].researchQueueHandoff?.queueKey, "autonomous_hunt:run_1:hunt_queue_candidate_high");
  assert.equal(summaries[0].researchQueueHandoff?.title, "Review autonomous hunt candidate candidate_high; Authorization=[redacted]");
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
  assert.equal(summaries[0].chainImpact, "Cross tenant read with cookie=[redacted]");
  assert.equal(summaries[0].primitiveCount, 2);
  assert.equal(summaries[0].preconditionCount, 2);
  assert.equal(summaries[0].refutationQuestionCount, 3);
  assert.deepEqual(summaries[0].primitives, ["object id swap", "Primitive"]);
  assert.deepEqual(summaries[0].preconditions, ["attacker has workspace member role", "token=[redacted]"]);
  assert.deepEqual(summaries[0].refutationQuestions, [
    "Can same-handler authorization evidence refute the missing access-control check candidate",
    "Does ownership check bind workspace_id",
    "Refutation question",
  ]);
  assert.equal(summaries[0].reasons[0], "Authorization gap candidate");
  assert.equal(summaries[1].candidateId, "research_plan_1");
  assert.equal(summaries[1].source, "Research review plan");
  assert.equal(summaries[1].researchQueueHandoff, null);
  assert.equal(summaries[1].hypothesis, "Review export IDOR with Authorization=[redacted]");
  assert.equal(summaries[1].reviewPriorityScore, 55);
  assert.equal(summaries[1].refutationQuestionCount, 1);
  assert.deepEqual(summaries[1].refutationQuestions, ["Can ownership checks refute export access"]);
  assert.equal(summaries[1].nextAction, "Review hypothesis board and request review before validation.");
  assert.doesNotMatch(
    JSON.stringify(summaries[1]),
    /request approval before validation|Approval required before validation/i,
  );
  assert.equal(summaries[2].candidateId, "candidate_low");
  assert.equal(summaries[2].researchQueueHandoff, null);
  assert.equal(summaries[2].reviewPriorityScore, 41);
  assert.doesNotMatch(
    JSON.stringify(summaries[2].priorityReasons),
    /Access-control gap candidate|Same-handler access-control evidence needed/i,
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
    "Access-control gap candidate",
    "Same-handler access-control evidence needed",
    "Sensitive sink present",
  ]);
  assert.deepEqual(summary.evidenceFocus, [
    "Same handler access-control evidence",
    "[redacted]",
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
  assert.match(page, /Authorized Campaign Launchpad/);
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
  assert.match(page, /Authorized tools/);
  assert.doesNotMatch(page, /Allowed tools/);
  assert.match(page, /name="autonomy_level"/);
  assert.match(page, /Scope Guard/);
  assert.match(page, /human review/i);
  assert.match(page, /\/campaigns\/\$\{encodeURIComponent\(campaign\.id\)\}/);
  assert.match(page, />Budget</);
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
  assert.match(page, /review gates, budgets/);
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
  assert.match(page, /Campaign control unavailable/);
  assert.match(page, /No audited control summary was returned for this campaign/);
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
  assert.match(page, /label="Agent Audit"/);
  assert.match(page, /label="Review Gate"/);
  assert.doesNotMatch(page, /label="Approval Review"/);
  assert.match(page, /label="Validation Audit"/);
  assert.match(page, /label="Report Readiness"/);
  assert.match(page, /label="Mythos Brain"/);
  assert.match(page, /label="Code Review Map"/);
  assert.match(page, /label="Artifact Review"/);
  assert.match(page, /label="Research Review"/);
  assert.match(page, /label="Review Timeline"/);
  assert.doesNotMatch(page, /<AuditLink[^\r\n]*label="Tasks"/);
  assert.doesNotMatch(page, /label="Agent Runs"/);
  assert.doesNotMatch(page, /label="Validation Queue"/);
  assert.doesNotMatch(page, /label="Validation Runs"/);
  assert.doesNotMatch(page, /label="Report Drafts"/);
  assert.doesNotMatch(page, /label="Brain"/);
  assert.doesNotMatch(page, /label="Artifacts"/);
  assert.doesNotMatch(page, /label="Artifact Repository"/);
  assert.doesNotMatch(page, /label="Codebase Map"/);
  assert.doesNotMatch(page, /label="Research Tasks"/);
  assert.doesNotMatch(page, /label="Timeline"/);
  assert.match(page, /executionAllowed/);
  assert.match(page, /safeNextAction/);
  assert.match(page, /Promotion review/);
  assert.match(page, /promotionReviewBlockedCount/);
  assert.match(page, /promotionReviewNextAllowedAction/);
  assert.match(page, /promotionReviewProvenanceRefCount/);
  assert.match(page, /promotionReviewRequiredEvidenceBlockedCount/);
  assert.match(page, /Review requirements/);
  assert.match(page, /summary\.blockedReasons\.map/);
  assert.doesNotMatch(page, /Blocked Reasons/);
  assert.doesNotMatch(page, /Action blockers/);
  assert.match(page, /validationEvidenceCount/);
  assert.match(page, /validationEvidenceGapCount/);
  assert.match(page, /Control readiness/);
  assert.match(page, /Scope Guard reviewed/);
  assert.doesNotMatch(page, /Scope Guard clear/);
  assert.match(page, /Research Memory Review/);
  assert.doesNotMatch(page, />Research Queue</);
  assert.match(page, /researchQueueSuggestions/);
  assert.match(page, /Queue review item/);
  assert.match(page, /name="queue_key"/);
  assert.match(page, /value=\{suggestion\.queueKey\}/);
  assert.match(page, /requester: "operator"/);
  assert.match(page, /Queue review item from control center/);
  assert.match(page, /\/campaigns\/\$\{encodeURIComponent\(campaignId\)\}\/tasks/);
  assert.match(page, /nextAllowedAction/);
  assert.match(page, /Review gate/);
  assert.match(page, /Action gate/);
  assert.match(page, /Review only/);
  assert.match(page, /candidateStatus/);
  assert.match(page, /humanApprovalRequired/);
  assert.match(page, /refutationQuestionCount/);
  assert.match(page, /validationStepCount/);
  assert.match(page, /blockedActionCount/);
  assert.match(page, /rawPriorityScore/);
  assert.match(page, /requiredEvidence/);
  assert.match(page, /Required evidence/);
  assert.match(page, /qualityGateReasons/);
  assert.match(page, /Quality Gate Reasons/);
  assert.match(page, /Human review required/);
  assert.match(page, /label="Validation audits"/);
  assert.match(page, /label="Review items"/);
  assert.match(page, /label="Agent audits"/);
  assert.doesNotMatch(page, /Execution permission/);
  assert.doesNotMatch(page, /No execution permission/);
  assert.doesNotMatch(page, /do not grant execution/i);
  assert.doesNotMatch(page, /label="Validation runs"/);
  assert.doesNotMatch(page, /label="Tasks"/);
  assert.doesNotMatch(page, /label="Agent runs"/);
  assert.doesNotMatch(page, /label="Execution" value="Blocked"/);
  assert.doesNotMatch(page, />Safety gate</);
  assert.match(page, /label="Review gate"/);
  assert.doesNotMatch(page, /label="Approval queue"/);
  assert.doesNotMatch(page, /label="Approval review"/);
  assert.match(page, /label="Pending review gates"/);
  assert.doesNotMatch(page, /label="Pending approvals"/);
  assert.match(page, /Validation audit/);
  assert.match(page, /Evidence review/);
  assert.match(page, /Artifact review/);
  assert.doesNotMatch(page, /Artifact repository/);
  assert.match(page, /Report readiness/);
  assert.match(page, /Learning review/);
  assert.match(page, /Cycle review/);
  assert.match(page, /label="Review holds"/);
  assert.doesNotMatch(page, /label="Blocked stages"/);
  assert.match(page, /Cycle reviews/);
  assert.match(page, /cycleReviewAwaitingCount/);
  assert.match(page, /cycleReviewCompletedCount/);
  assert.match(page, /Human review gate/);
  assert.match(page, /Runtime gate/);
  assert.match(page, /Scope Guard/);
  assert.match(page, /No active review requirements/);
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
  assert.match(page, /Artifact Review/);
  assert.match(page, /Campaign artifact summaries filtered to this campaign/);
  assert.doesNotMatch(page, /Authorized material summaries/);
  assert.doesNotMatch(page, /Artifact Repository/);
  assert.doesNotMatch(page, /Campaign Artifacts/);
  assert.match(page, /No reviewed artifacts ready/);
  assert.doesNotMatch(page, /No authorized artifacts ready/);
  assert.doesNotMatch(page, /No campaign artifacts recorded/);
  assert.match(page, /reportChainAllowedCount/);
  assert.match(page, /reportChainBlockedCount/);
  assert.match(page, /Report-chain review ready/);
  assert.match(page, /Report-chain review required/);
  assert.match(page, /Report chain review ready/);
  assert.match(page, /Report chain review required/);
  assert.doesNotMatch(page, /Report-chain eligible/);
  assert.doesNotMatch(page, /Report-chain blocked/);
  assert.doesNotMatch(page, /Eligible for report chain/);
  assert.doesNotMatch(page, /Blocked for report chain/);
  assert.doesNotMatch(page, /Report-chain allowed/);
  assert.doesNotMatch(page, /\? "Allowed"/);
  assert.match(page, /Usage provenance/);
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
  assert.match(page, /Validation Audit/);
  assert.doesNotMatch(page, />Validation Runs</);
  assert.doesNotMatch(page, /Validation runs/);
  assert.match(page, /Validation audits/);
  assert.match(page, /Preflight summary/);
  assert.match(page, /Human review gates are not validation start gates/);
  assert.match(page, /Attention/);
  assert.match(page, /Next action/);
  assert.match(page, /attentionState/);
  assert.match(page, /nextAction/);
  assert.doesNotMatch(page, /validation start permission/);
  assert.doesNotMatch(page, /Approval is not validation start permission/);
  assert.doesNotMatch(page, /Approval is not execution permission/);
  assert.match(page, /executionState/);
  assert.match(page, /Preflight passed/);
  assert.match(page, /Preflight reviewed/);
  assert.doesNotMatch(page, /Preflight ready/);
  assert.doesNotMatch(page, /Preflight clear/);
  assert.match(page, /Preflight blocked/);
  assert.match(page, /Preflight decision/);
  assert.match(page, /<span>Evidence refs<\/span>/);
  assert.doesNotMatch(page, /<span>Evidence<\/span>/);
  assert.match(page, /Awaiting review gate/);
  assert.match(page, /Review gate required/);
  assert.match(page, /No review gate required/);
  assert.match(page, /label="Review gate"/);
  assert.doesNotMatch(page, /Awaiting approval/);
  assert.doesNotMatch(page, /Approval required/);
  assert.doesNotMatch(page, /No approval required/);
  assert.doesNotMatch(page, /label="Approval"/);
  assert.doesNotMatch(page, /No approval/);
  assert.match(page, /label="Validation audit"/);
  assert.match(page, /label="Review item"/);
  assert.match(page, /\/campaigns\/\$\{encodeURIComponent\(campaignId\)\}\/validation-runs\/\$\{encodeURIComponent\(run\.id\)\}/);
  assert.match(page, /Review manual observation/);
  assert.match(page, /No validation audits ready/);
  assert.doesNotMatch(page, /No validation run records/);
  assert.doesNotMatch(page, /label="Run"/);
  assert.doesNotMatch(page, /label="Task"/);
  assert.doesNotMatch(page, />Safety gate</);
  assert.match(page, /Validation started:/);
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
  assert.match(page, /Manual validation observation review/);
  assert.match(page, /Candidate evidence only/);
  assert.match(page, /Evidence promotion/);
  assert.match(page, /Report submission/);
  assert.match(page, /Review manual observation/);
  assert.match(page, /outcome: formOutcome\(formData\)/);
  assert.match(page, /evidence_refs: formLines\(formData, "evidence_refs"\)/);
  assert.match(page, /action=\{recordManualResultAction\}/);
  assert.match(page, /revalidatePath\(`\/campaigns\/\$\{encodeURIComponent\(campaignId\)\}\/validation-runs`\)/);
  assert.doesNotMatch(page, /fallbackManualResultRun/);
  assert.doesNotMatch(page, /allowed_to_execute/);
  assert.match(page, /label="Execution gate" value="Gated"/);
  assert.match(page, /label="Report submission gate" value="Gated"/);
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
  assert.match(page, /Review queue handoff/);
  assert.match(page, /Required evidence/);
  assert.match(page, /candidate\.researchQueueHandoff\.requiredEvidence/);
  assert.match(page, /Source/);
  assert.match(page, /candidate\.source/);
  assert.match(page, /Research audits/);
  assert.match(page, /label="Research audit"/);
  assert.match(page, /Chains mapped/);
  assert.match(page, /Review priority/);
  assert.match(page, /Priority rationale/);
  assert.match(page, /priorityReasons/);
  assert.match(page, /candidate\.priorityReasons/);
  assert.match(page, /Chain confidence/);
  assert.match(page, /primitive\(s\)/);
  assert.match(page, /refutation question\(s\)/);
  assert.match(page, /No hypotheses ready for review/);
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
  assert.match(page, /No endpoints mapped yet/);
  assert.match(page, /No sensitive actions mapped yet/);
  assert.match(page, /No relationships mapped yet/);
  assert.match(page, /No objects mapped yet/);
  assert.match(page, /No roles mapped yet/);
  assert.match(page, /Audited sources/);
  assert.match(page, /audited review sources/);
  assert.doesNotMatch(page, /authorized audit sources/);
  assert.match(page, /Review boundary/);
  assert.match(page, /Audit facts only; execution gates stay outside this view/);
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
  assert.match(page, /Learning Review/);
  assert.match(page, /Reasoning Memory/);
  assert.match(page, /reasoningMemory/);
  assert.match(page, /advisoryOnly/);
  assert.match(page, /Advisory research memory for ranking and explanation\. It stays advisory only\./);
  assert.match(page, /Review readiness/);
  assert.match(page, /Review ready/);
  assert.match(page, /Review queued/);
  assert.doesNotMatch(page, /label="Ready"/);
  assert.match(page, /Linked audits/);
  assert.match(page, /Review boundary/);
  assert.match(page, /Brain advisory memory/);
  assert.match(page, /Advisory memory only/);
  assert.match(page, /Review gate active/);
  assert.doesNotMatch(page, /value=\{learningReview\.reviewReady \? "Yes" : "No"\}/);
  assert.doesNotMatch(page, /value=\{advisoryOnly \? "Yes" : "No"\}/);
  assert.doesNotMatch(page, /Permission source/);
  assert.doesNotMatch(page, /Linked runs/);
  assert.doesNotMatch(page, /cannot authorize execution/);
  assert.doesNotMatch(page, /Scope Guard only/);
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
  assert.match(page, /Code Review Map/);
  assert.doesNotMatch(page, /Codebase Map/);
  assert.match(page, /Access-control checks/);
  assert.match(page, /Authorization gap candidates/);
  assert.match(page, /No access-control hint/);
  assert.doesNotMatch(page, /Authz checks/);
  assert.doesNotMatch(page, /No authz hint/);
  assert.doesNotMatch(page, /Confirmed finding|Vulnerability/);
  assert.match(page, /No mapped repositories ready/);
  assert.match(page, /No code facts ready/);
  assert.match(page, /No scanner audits ready/);
  assert.match(page, /Scanner audits/);
  assert.doesNotMatch(page, /Scanner Runs/);
  assert.doesNotMatch(page, /Scanner runs/);
  assert.doesNotMatch(page, /No codebase map records/);
  assert.doesNotMatch(page, /No code facts recorded/);
  assert.doesNotMatch(page, /No scanner runs recorded/);
  assert.match(page, /Scanner boundary/);
  assert.match(page, /Scanner controls stay outside this audit view/);
  assert.doesNotMatch(page, /Not available from this read-only view/);
  assert.match(page, /Review gate/);
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
  assert.match(page, /Blocked Promotion Review/);
  assert.match(page, /Promotion Block Review Queue/);
  assert.match(page, /promotionBlockReviews/);
  assert.match(page, /\/tasks\/\$\{encodeURIComponent\(item\.taskId\)\}/);
  assert.match(page, /feedbackStageId/);
  assert.match(page, /label="Feedback stage"/);
  assert.match(page, /\/feedback-reviews\/\$\{encodeURIComponent\(item\.feedbackStageId\)\}/);
  assert.match(page, /\/feedback-reviews\/\$\{encodeURIComponent\(feedback\.feedbackStageId\)\}/);
  assert.match(page, /Review promotion gate/);
  assert.match(page, /promotionProvenanceRefCount/);
  assert.match(page, /Promotion attempts blocked/);
  assert.match(page, /promotionAuditLatestReason/);
  assert.match(page, /promotionAuditCreatedCount/);
  assert.match(page, /promotionAuditProvenanceRefCount/);
  assert.match(page, /promotionAuditReviewEvidenceRefCount/);
  assert.match(page, /nextAllowedAction/);
  assert.match(page, /label="Next review action"/);
  assert.doesNotMatch(page, /label="Next action" value=\{findingCandidateGate\.nextAllowedAction\}/);
  assert.match(page, /<span>Evidence refs<\/span>/);
  assert.doesNotMatch(page, /<span>Evidence<\/span>/);
  assert.match(page, /label="Review item"/);
  assert.doesNotMatch(page, /label="Task" value=\{item\.taskId\}/);
  assert.match(page, /label="Review gate"/);
  assert.match(page, /reviewGate/);
  assert.match(page, /candidateEvidenceState/);
  assert.match(page, /reportChainState/);
  assert.doesNotMatch(page, /label="Approval"/);
  assert.doesNotMatch(page, /Approval required/);
  assert.doesNotMatch(page, /No approval/);
  assert.match(page, /Research audits/);
  assert.match(page, /label="Research audit"/);
  assert.match(page, /label="Validation audit"/);
  assert.doesNotMatch(page, /label="Task" value=\{run\.taskId/);
  assert.doesNotMatch(page, /label="Task" value=\{feedback\.taskId\}/);
  assert.match(page, /reviewItem/);
  assert.match(page, /Report chain evidence present/);
  assert.match(page, /Report chain review required/);
  assert.doesNotMatch(page, /claim\.reportChainEligible \? "Eligible" : "Blocked"/);
  assert.match(page, /Validation Evidence/);
  assert.match(page, /candidateEvidenceState/);
  assert.match(page, /reportChainState/);
  assert.match(page, /nextReviewAction/);
  assert.match(page, /preflightState/);
  assert.match(page, /toCampaignValidationEvidenceReviewSummaries\(validationRuns, pipelineStages\)/);
  assert.match(page, /toCampaignValidationEvidenceQualitySummary\(validationEvidence\)/);
  assert.match(page, /validationEvidenceQuality/);
  assert.match(page, /Clean reviews/);
  assert.match(page, /Redacted reviews/);
  assert.match(page, /Unsafe refs/);
  assert.match(page, /Strong evidence/);
  assert.match(page, /Promotion gated/);
  assert.match(page, /manualValidationReview/);
  assert.match(page, /Quality review/);
  assert.match(page, /qualityScore/);
  assert.match(page, /redactionStatus/);
  assert.match(page, /promotionReviewState/);
  assert.match(page, /Research Feedback Evidence/);
  assert.match(page, /Manual review required/);
  assert.match(page, /Promotion review blocked/);
  assert.doesNotMatch(page, /Promotion ready/);
  assert.match(page, /No report claims queued for evidence review/);
  assert.match(page, /No validation evidence queued for review/);
  assert.match(page, /No research validation feedback queued for review/);
  assert.doesNotMatch(page, /No campaign-linked report preview claims recorded/);
  assert.doesNotMatch(page, /No manual validation evidence recorded/);
  assert.doesNotMatch(page, /<Metric label="Runs"/);
  assert.doesNotMatch(page, /label="Run"/);
  assert.match(page, /Report chain/);
  assert.doesNotMatch(page, /Preflight active/);
  assert.doesNotMatch(page, />Safety gate</);
  assert.doesNotMatch(page, /Execution allowed/);
  assert.doesNotMatch(page, /recordManualObservation|recordClaimReviewDecision|createFindingCandidate|executeValidation|submitReport/);
  assert.doesNotMatch(page, /Report chain review ready|Promotion review ready|No report claims ready|No validation evidence ready|No research validation feedback ready|Review-ready claims/);
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
  assert.match(page, /Finding candidate promotion review/);
  assert.match(page, /review-ready for finding candidate promotion review/);
  assert.match(page, /Promotion review ready/);
  assert.doesNotMatch(page, /Review may allow/);
  assert.doesNotMatch(page, /eligible for finding candidate promotion review/);
  assert.match(page, /Validation execution/);
  assert.match(page, /Report submission/);
  assert.match(page, /label="Execution gate"/);
  assert.match(page, /label="Validation gate"/);
  assert.match(page, /label="Report submission gate"/);
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
  assert.match(page, /Campaign cycle review/);
  assert.match(page, /Next read-only cycle/);
  assert.match(page, /Validation execution/);
  assert.match(page, /Report submission/);
  assert.match(page, /label="Execution gate"/);
  assert.match(page, /label="Submission gate"/);
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
  assert.match(page, /Report Readiness/);
  assert.doesNotMatch(page, />Report Drafts</);
  assert.match(page, /Validation audits/);
  assert.match(page, /label="Research audit"/);
  assert.match(page, /Finding candidate gate/);
  assert.match(page, /Reviewed claims/);
  assert.match(page, /Finding candidate reviews queued/);
  assert.doesNotMatch(page, /label="Ready"/);
  assert.doesNotMatch(page, /Ready claims/);
  assert.doesNotMatch(page, /Ready finding candidate reviews/);
  assert.doesNotMatch(page, /Review-ready claims/);
  assert.doesNotMatch(page, /Review-ready finding candidate reviews/);
  assert.doesNotMatch(page, /label="Eligible"/);
  assert.match(page, /Research feedback/);
  assert.match(page, /Claims needing review/);
  assert.match(page, /Promotion review holds/);
  assert.match(page, /Required evidence holds/);
  assert.match(page, /requiredEvidenceBlockedCount/);
  assert.match(page, /Promotion audit holds/);
  assert.match(page, /promotionAuditBlockedCount/);
  assert.match(page, /promotionAuditCreatedCount/);
  assert.match(page, /promotionAuditProvenanceRefCount/);
  assert.match(page, /promotionAuditReviewEvidenceRefCount/);
  assert.match(page, /promotionAuditLatestReason/);
  assert.match(page, /readyRunIds/);
  assert.match(page, /\/reports\/\$\{encodeURIComponent\(runId\)\}/);
  assert.match(page, /Review finding candidate/);
  assert.match(page, /Manual review required/);
  assert.match(page, /Review required/);
  assert.match(page, /label="Review holds"/);
  assert.doesNotMatch(page, /Blocked claims/);
  assert.doesNotMatch(page, /Promotion blocked/);
  assert.doesNotMatch(page, /Promotion attempts blocked/);
  assert.doesNotMatch(page, /label="Blocked"/);
  assert.match(page, /toCampaignReportDraftEvidenceSummary/);
  assert.match(page, /toCampaignReportDraftSummaries/);
  assert.match(page, /Manual submission gate/);
  assert.match(page, /<span>Evidence refs<\/span>/);
  assert.doesNotMatch(page, /<span>Evidence<\/span>/);
  assert.match(page, /Human review requires manual decision/);
  assert.match(page, /Submission blocked/);
  assert.match(page, /No report drafts queued for review/);
  assert.doesNotMatch(page, /No campaign-linked report drafts recorded/);
  assert.doesNotMatch(page, /label="Runs"/);
  assert.doesNotMatch(page, /label="Run"/);
  assert.doesNotMatch(page, /Review ready/);
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
  assert.match(page, /Research Review/);
  assert.doesNotMatch(page, /Research Tasks/);
  assert.doesNotMatch(page, /Campaign Tasks/);
  assert.match(page, /\/tasks\/\$\{encodeURIComponent\(task\.id\)\}/);
  assert.match(page, /Review-only research work items/);
  assert.match(page, /No research review items ready/);
  assert.doesNotMatch(page, /No campaign task records/);
  assert.doesNotMatch(page, /No research tasks ready/);
  assert.match(page, /Research review items will appear here/);
  assert.doesNotMatch(page, /Research tasks will appear here/);
  assert.doesNotMatch(page, /Tasks will appear here/);
  assert.match(page, />\s*Review item\s*</);
  assert.match(page, /label="Review item"/);
  assert.doesNotMatch(page, />\s*Task\s*</);
  assert.doesNotMatch(page, /label="Task"/);
  assert.doesNotMatch(page, /Queued autonomous work items/);
  assert.doesNotMatch(page, /dispatchTask|runTask|startCampaign|resumeCampaign|pauseCampaign|executeValidation|submitReport/);
  assert.doesNotMatch(page, /<form|method="post"|action=\{/);
});

test("campaign research task review page drafts review plans without execution", async () => {
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
  assert.match(page, /Latest Review Plan/);
  assert.match(page, /Latest Refutation Decision/);
  assert.match(page, /Suggested Refutation Decision/);
  assert.match(page, /suggestedRefutationDecision/);
  assert.match(page, /refutationQuestionCount/);
  assert.match(page, /refutationAnswerCount/);
  assert.match(page, /validationMode/);
  assert.match(page, /targetRef/);
  assert.match(page, /label="Validation mode"/);
  assert.match(page, /label="Next review action"/);
  assert.doesNotMatch(page, /label="Next action"/);
  assert.match(page, /Validation review pending/);
  assert.doesNotMatch(page, /Not allowed yet/);
  assert.match(page, /label="Target"/);
  assert.match(page, /Latest Validation Feedback/);
  assert.match(page, /Autonomous Candidate Review/);
  assert.match(page, /autonomousCandidateContext/);
  assert.match(page, /candidateId/);
  assert.match(page, /refutationQuestions/);
  assert.match(page, /triageSignals/);
  assert.match(page, /evidenceFocus/);
  assert.match(page, /sourceFactTypes/);
  assert.match(page, /Candidate Triage Signals/);
  assert.match(page, /Candidate Evidence Focus/);
  assert.match(page, /Candidate Required Evidence/);
  assert.match(page, /requiredEvidence/);
  assert.match(page, /Candidate Quality Gate Reasons/);
  assert.match(page, /qualityGateReasons/);
  assert.match(page, /rawPriorityScore/);
  assert.match(page, /Candidate Source Facts/);
  assert.match(page, /validationSteps/);
  assert.match(page, /blockedActions/);
  assert.match(page, /Human review required/);
  assert.doesNotMatch(page, /Human approval required/);
  assert.match(page, /latestValidationFeedback/);
  assert.match(page, /findingConfirmationAllowed/);
  assert.match(page, /\/feedback-reviews\/\$\{encodeURIComponent\(summary\.latestValidationFeedback\.feedbackStageId\)\}/);
  assert.match(page, /Review promotion gate/);
  assert.match(page, /latestRefutationDecision/);
  assert.match(page, /approvalId/);
  assert.match(page, /validationRunId/);
  assert.match(page, /Review gate/);
  assert.match(page, /label="Human review"/);
  assert.match(page, /label="Review gate record"/);
  assert.match(page, /No review gate/);
  assert.doesNotMatch(page, /label="Human approval"/);
  assert.doesNotMatch(page, /label="Approval"/);
  assert.doesNotMatch(page, /No approval request/);
  assert.match(page, /Non-Destructive Plan/);
  assert.match(page, /Draft Review Plan/);
  assert.match(page, /Draft review plan/);
  assert.match(page, /Record Needs Evidence/);
  assert.match(page, /Record needs evidence/);
  assert.match(page, /latestReviewPlan\.planId/);
  assert.match(page, /decision: "needs_evidence"/);
  assert.match(page, /candidate_context_summary/);
  assert.match(page, /triage_signal_count/);
  assert.match(page, /evidence_focus_count/);
  assert.match(page, /source_fact_type_count/);
  assert.match(page, /has_authorization_gap_candidate/);
  assert.match(page, /rationale: "Needs more redacted evidence before validation."/);
  assert.match(page, /refutation_answers/);
  assert.match(page, /action=\{recordNeedsEvidenceDecisionAction\}/);
  assert.match(page, /reviewHypothesis/);
  assert.match(page, /reviewRefutationQuestions/);
  assert.match(page, /reviewEvidencePlan/);
  assert.match(page, /reviewer: "operator"/);
  assert.match(page, /rationale: "Drafted from redacted research review context."/);
  assert.match(page, /action=\{createReviewPlanAction\}/);
  assert.match(page, /Action gate/);
  assert.match(page, /Review only/);
  assert.doesNotMatch(page, /label="Execution"/);
  assert.doesNotMatch(page, /Execution blocked/);
  assert.match(page, /Validation audit/);
  assert.match(page, /No validation audit/);
  assert.doesNotMatch(page, /Validation run/);
  assert.doesNotMatch(page, /No validation run/);
  assert.match(page, /label="Review gate"/);
  assert.match(page, /label="Review item"/);
  assert.doesNotMatch(page, /Task review gate/);
  assert.doesNotMatch(page, /label="Task"/);
  assert.match(page, /Reasoning memory key/);
  assert.doesNotMatch(page, /Research memory key/);
  assert.match(page, />\s*Research Review\s*</);
  assert.doesNotMatch(page, />\s*Research Tasks\s*</);
  assert.match(page, /Required Human Gates/);
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
  assert.match(page, /Agent Audit/);
  assert.match(page, /Agent audits/);
  assert.match(page, /review gates/);
  assert.match(page, /No agent audits ready/);
  assert.doesNotMatch(page, /Agent runs/);
  assert.doesNotMatch(page, /Agent run audit/);
  assert.doesNotMatch(page, /No agent runs recorded/);
  assert.match(page, /<span>Input refs<\/span>/);
  assert.match(page, /<span>Output refs<\/span>/);
  assert.doesNotMatch(page, /<span>Inputs<\/span>/);
  assert.doesNotMatch(page, /<span>Outputs<\/span>/);
  assert.doesNotMatch(page, /safety gates/);
  assert.match(page, /Scope Guard decision/);
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
  assert.match(page, /Review Gate Queue/);
  assert.match(page, /Next action/);
  assert.match(page, /nextAction/);
  assert.doesNotMatch(page, /Approval Review/);
  assert.doesNotMatch(page, />Validation Queue</);
  assert.match(page, /Review gate requests/);
  assert.match(page, /No review gate requests ready/);
  assert.match(page, /Review gate requests will appear here/);
  assert.doesNotMatch(page, /Approval review records/);
  assert.doesNotMatch(page, /No approval review records/);
  assert.doesNotMatch(page, /Approval records will appear/);
  assert.match(page, /Preflight still required/);
  assert.match(page, /Review gate/);
  assert.match(page, /Review gate state/);
  assert.match(page, /label="Review gate"/);
  assert.doesNotMatch(page, /label="Approval"/);
  assert.match(page, /label="Review item"/);
  assert.match(page, /label="Research audit"/);
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
  assert.match(page, /Review Timeline/);
  assert.doesNotMatch(page, /Pipeline timeline/);
  assert.match(page, /<span>Input refs<\/span>/);
  assert.match(page, /<span>Output refs<\/span>/);
  assert.doesNotMatch(page, /<span>Inputs<\/span>/);
  assert.doesNotMatch(page, /<span>Outputs<\/span>/);
  assert.match(page, /manualValidationResultCount/);
  assert.match(page, /manualValidationReview/);
  assert.match(page, /Quality review/);
  assert.match(page, /qualityScore/);
  assert.match(page, /redactionStatus/);
  assert.match(page, /promotionReviewReady/);
  assert.match(page, /researchValidationFeedbackCount/);
  assert.match(page, /isResearchValidationFeedback/);
  assert.match(page, /Research feedback/);
  assert.match(page, /validationFeedbackReviewCount/);
  assert.match(page, /isValidationFeedbackReview/);
  assert.match(page, /Feedback reviews/);
  assert.match(page, /Review gate: \{stage\.approvalCreated \? "recorded" : "pending"\}/);
  assert.doesNotMatch(page, /Review gate: \{stage\.approvalCreated \? "created" : "not created"\}/);
  assert.doesNotMatch(page, /Approval: \{stage\.approvalCreated/);
  assert.match(page, /Finding confirmation gate:/);
  assert.match(page, /Report\s+submission gate:/);
  assert.match(page, /Validation gate:/);
  assert.match(page, /Execution gate:/);
  assert.match(page, /stage\.reportSubmissionAllowed \? "reviewed" : "gated"/);
  assert.match(page, /stage\.validationAllowed \? "reviewed" : "gated"/);
  assert.match(page, /stage\.executionAllowed \? "reviewed" : "gated"/);
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
  assert.match(page, /Required evidence/);
  assert.match(page, /evidenceFocusCount/);
  assert.match(page, /sourceFactTypeCount/);
  assert.match(page, /triageSignalCount/);
  assert.match(page, /priorityReasonCount/);
  assert.match(page, /Priority reasons/);
  assert.match(page, /hasAuthorizationGapCandidate/);
  assert.match(page, /Candidate context/);
  assert.match(page, /Access-control gap candidate/);
  assert.match(page, /candidateStatus/);
  assert.match(page, /Research review queued/);
  assert.match(page, /Promotion reviews/);
  assert.match(page, /LLM audit/);
  assert.match(page, /Prompt hash only/);
  assert.match(page, /hunterOperatingAction/);
  assert.match(page, /llmAuditPromptHash/);
  assert.doesNotMatch(page, /prompt_text|raw prompt|promptText|evidence_refs|raw evidence/);
  assert.match(page, /Promotion blocks/);
  assert.match(page, /learningOutcomeCount/);
  assert.match(page, /cycleReviewCount/);
  assert.match(page, /\/cycle-reviews\/\$\{encodeURIComponent\(stage\.id\)\}/);
  assert.match(page, /Complete cycle review/);
  assert.match(page, /Review gates/);
  assert.match(page, /Review gate/);
  assert.match(page, /No review timeline ready/);
  assert.doesNotMatch(page, /No pipeline stages recorded/);
  assert.doesNotMatch(page, />Safety gate</);
  assert.doesNotMatch(page, /startCampaign|resumeCampaign|pauseCampaign|executeValidation|submitReport/);
  assert.doesNotMatch(page, /<form|method="post"|action=\{/);
});
