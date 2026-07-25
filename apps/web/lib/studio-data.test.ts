import assert from "node:assert/strict";
import fs from "node:fs/promises";
import test from "node:test";
import {
  toStudioArtifactChecklist,
  toStudioBlackBoxRemoteStatus,
  toStudioCampaignHunterCandidateCards,
  toStudioCandidateCards,
  toStudioConversationActorLabel,
  toStudioControlCenterView,
  toStudioMissionHandoffBrief,
  toStudioMissionPanel,
  toStudioResearchReadiness,
  toStudioWorkspaceSummary,
} from "./studio-data.ts";
import type { StudioMissionSummary } from "./studio-data.ts";

test("workspace summary maps manifest safety state", () => {
  const summary = toStudioWorkspaceSummary({
    name: "acme-api",
    artifacts: [],
    runs: [],
    safety: {
      scope_guard_status: "missing_scope",
      blocked_actions: ["execute_live_validation"],
    },
  });

  assert.equal(summary.name, "acme-api");
  assert.equal(summary.scopeGuardLabel, "缺少范围");
  assert.deepEqual(summary.blockedActions, ["execute_live_validation"]);
});

test("remote human-lease status exposes expiry and fails closed on gate drift", () => {
  const active = toStudioBlackBoxRemoteStatus({
    profile: "remote_human_lease",
    enabled: true,
    state: "active",
    expires_at: "2026-07-15T12:30:00Z",
    relogin_required: false,
    stop_reason: null,
    report_submission_allowed: false,
    human_confirmation_allowed: false,
  });
  assert.equal(active.label, "人工租约生效中");
  assert.equal(active.warning, false);
  assert.match(active.detail, /2026-07-15T12:30:00Z/);

  const expired = toStudioBlackBoxRemoteStatus({
    profile: "remote_human_lease",
    enabled: true,
    state: "expired",
    expires_at: "2026-07-15T12:30:00Z",
    relogin_required: true,
    stop_reason: null,
    report_submission_allowed: false,
    human_confirmation_allowed: false,
  });
  assert.equal(expired.label, "已过期，需要重新登录");
  assert.equal(expired.warning, true);

  const gateDrift = toStudioBlackBoxRemoteStatus({
    profile: "remote_human_lease",
    enabled: true,
    state: "active",
    expires_at: null,
    relogin_required: false,
    stop_reason: null,
    report_submission_allowed: true,
    human_confirmation_allowed: false,
  });
  assert.equal(gateDrift.label, "状态契约无效，已阻断");
  assert.equal(gateDrift.warning, true);
});

test("workspace summary counts campaign hunter runs as desktop sessions", () => {
  const summary = toStudioWorkspaceSummary({
    name: "acme-api",
    campaign_hunter_runs: [
      {
        campaign_id: "campaign-1",
        execution_allowed: false,
        report_submission_allowed: false,
        validation_allowed: false,
      },
    ],
    runs: [{ run_id: "run-1" }],
  });

  assert.equal(summary.runCount, 2);
});

test("candidate cards map missing endpoint and code path to review fallbacks", () => {
  const [card] = toStudioCandidateCards([
    {
      hypothesis_id: "H-001",
      vuln_type: "IDOR",
      risk: "high",
      location: "",
      reason: "Object ownership is not proven at the route boundary.",
      evidence_needed: ["two test accounts"],
      false_positive_checks: ["ownership may be enforced in middleware"],
      safe_verification: true,
      priority_score: 80,
    },
  ]);

  assert.equal(card.id, "H-001");
  assert.equal(card.affectedEndpoint, "端点需要审核");
  assert.equal(card.affectedCodePath, "代码路径需要审核");
  assert.equal(card.status, "needs_review");
});

test("mission panel maps Studio mission summary into safe desktop workbench state", () => {
  const panel = toStudioMissionPanel({
    artifacts: {
      missing: [],
      present: ["scope", "policy", "code", "api", "har"],
      required: ["scope", "policy", "code", "api", "har"],
    },
    advisory_artifacts: {
      present: ["strategy"],
      supported: ["sarif", "sbom", "fuzzing", "strategy"],
    },
    blocked_actions: [
      "execute_live_validation",
      "touch_real_user_data",
      "submit_report",
    ],
    candidate_count: 1,
    candidate_hunter_backlog: [
      {
        work_item_id: "H-002:draft_validation_plan",
        candidate_id: "H-002",
        gap: "missing_safe_validation_plan",
        status: "needs_review",
        review_focus: ["safe_validation_plan", "non_destructive_plan_only"],
        required_evidence: ["non_destructive_validation_plan"],
        next_action: "Draft a non-destructive validation plan for H-002.",
        safety_gate: "review_only_no_execution",
        execution_allowed: true,
        validation_allowed: true,
        report_submission_allowed: true,
      },
    ],
    candidate_hunter_iteration: {
      iteration_id: "candidate_hunter:next_review",
      status: "needs_review",
      work_item_count: 1,
      priority_order: ["H-002:draft_validation_plan"],
      next_review_agent: "证据计划ner",
      review_focus: ["safe_validation_plan", "non_destructive_plan_only"],
      success_criteria: [
        "H-002:draft_validation_plan has traceable evidence: non_destructive_validation_plan.",
        "No validation, fuzzing, or report submission is executed.",
      ],
      safety_gate: "review_only_no_execution",
      completion_gate: "human_review_required",
      execution_allowed: true,
      validation_allowed: true,
      report_submission_allowed: true,
    },
    candidate_hunter_plan: {
      plan_id: "candidate_hunter:autonomous_review_plan",
      status: "needs_review",
      work_item_count: 1,
      step_count: 1,
      next_review_agent: "证据计划ner",
      hallucination_governance: {
        claim_promotion_rule: "no_verified_evidence_no_high_confidence",
        model_output_policy: "llm_claims_start_unverified",
        knowledge_policy: "rag_few_shot_context_only_not_cross_validation",
        required_consensus: [
          "authorized_local_artifact_evidence",
          "independent_refutation_or_static_rule",
          "human_review_decision",
        ],
        independent_challenge_sources: [
          "sarif_static_analysis",
          "fuzzing_artifact",
          "second_model_refutation",
          "manual_code_review",
        ],
        candidate_promotion_allowed: true,
      },
      plan_steps: [
        {
          step_id: "candidate_hunter:plan:H-002:draft_validation_plan",
          work_item_id: "H-002:draft_validation_plan",
          candidate_id: "H-002",
          status: "needs_review",
          assigned_agent: "证据计划ner",
          gap: "missing_safe_validation_plan",
          input_refs: ["scope", "policy", "code", "api", "har"],
          review_focus: ["safe_validation_plan", "non_destructive_plan_only"],
          required_evidence: ["non_destructive_validation_plan"],
          next_action: "Draft a non-destructive validation plan for H-002.",
          success_criteria: [
            "H-002:draft_validation_plan is reviewed against authorized local artifacts.",
            "证据引用 required: non_destructive_validation_plan.",
            "No validation, fuzzing, or report submission is executed.",
          ],
          hallucination_governance_refs: [
            "LLM output remains an unverified claim until local evidence is traced.",
            "Knowledge/RAG context is few-shot guidance only and cannot satisfy cross-validation.",
          ],
          review_checklist: [
            {
              key: "safe_validation_plan",
              label: "Draft or review a non-destructive validation plan without execution.",
              status: "needs_review",
              required: true,
              execution_allowed: true,
              validation_allowed: true,
              report_submission_allowed: true,
            },
          ],
          safety_gate: "review_only_no_execution",
          execution_allowed: true,
          validation_allowed: true,
          report_submission_allowed: true,
        },
      ],
      safety_gate: "review_only_no_execution",
      completion_gate: "human_review_required",
      execution_allowed: true,
      validation_allowed: true,
      report_submission_allowed: true,
    },
    candidate_hunter_review_loop: {
      loop_id: "candidate_hunter:next_review_loop",
      status: "needs_review",
      source_plan_id: "candidate_hunter:autonomous_review_plan",
      active_step_count: 1,
      next_review_agent: "证据计划ner",
      review_agents: ["证据计划ner"],
      required_evidence: ["non_destructive_validation_plan"],
      active_steps: [
        {
          step_id: "candidate_hunter:plan:H-002:draft_validation_plan",
          work_item_id: "H-002:draft_validation_plan",
          candidate_id: "H-002",
          assigned_agent: "证据计划ner",
          gap: "missing_safe_validation_plan",
          required_evidence: ["non_destructive_validation_plan"],
          governance_refs: [
            "LLM output remains an unverified claim until local evidence is traced.",
          ],
          review_checklist: [
            {
              key: "safe_validation_plan",
              label: "Draft or review a non-destructive validation plan without execution.",
              status: "needs_review",
              required: true,
              execution_allowed: true,
              validation_allowed: true,
              report_submission_allowed: true,
            },
          ],
          next_action: "Draft a non-destructive validation plan for H-002.",
          success_criteria: [
            "No validation, fuzzing, or report submission is executed.",
          ],
          safety_gate: "unsafe_override",
          execution_allowed: true,
          validation_allowed: true,
          report_submission_allowed: true,
        },
      ],
      governance_summary: {
        claim_promotion_rule: "no_verified_evidence_no_high_confidence",
        required_consensus: ["authorized_local_artifact_evidence"],
        candidate_promotion_allowed: true,
      },
      blocked_actions: ["execute_live_validation", "run_fuzzer", "submit_report"],
      safety_gate: "unsafe_override",
      completion_gate: "unsafe_override",
      execution_allowed: true,
      validation_allowed: true,
      report_submission_allowed: true,
    },
    candidate_review_packets: [
      {
        candidate_id: "H-001",
        status: "review_ready",
        completed_items: [
          "endpoint_trace",
          "code_path_trace",
          "evidence_needs",
          "refutation_checks",
        ],
        missing_items: [],
        checklist: [
          {
            key: "endpoint_trace",
            status: "complete",
            label: "Affected endpoint is traced.",
          },
          {
            key: "safe_validation_plan",
            status: "complete",
            label: "Non-destructive validation plan is drafted.",
          },
        ],
        next_human_action: "Human evidence and 脱敏审查 required.",
        safety_gate: "human_review_required",
        evidence_need_count: 2,
        false_positive_check_count: 2,
        safe_validation_step_count: 3,
        quality_score: 95,
        report_review_priority: "redaction_review_ready",
        report_status: "submission_blocked",
        hallucination_guard_status: "cross_checked",
        execution_allowed: true,
        validation_allowed: true,
        report_submission_allowed: true,
      },
    ],
    submission_blocked_report_summary: {
      status: "ready_for_redaction_review",
      candidate_count: 1,
      ready_candidate_ids: ["H-001"],
      needs_review_candidate_ids: [],
      missing_review_items: {},
      report_review_queue: [
        {
          candidate_id: "H-001",
          priority: "redaction_review_ready",
          quality_score: 95,
          next_human_action: "Human evidence and 脱敏审查 required.",
          safety_gate: "submission_blocked_human_review",
          report_submission_allowed: true,
          validation_execution_allowed: true,
        },
      ],
      next_human_actions: ["Human evidence and 脱敏审查 required."],
      safety_gate: "submission_blocked_human_review",
      redaction_review_required: true,
      report_submission_allowed: true,
      validation_execution_allowed: true,
    },
    agent_handoff_pack: {
      pack_id: "studio:agent_handoff:next_review",
      status: "needs_review",
      handoff_item_count: 1,
      next_review_agent: "证据计划ner",
      priority_order: ["H-002:draft_validation_plan"],
      review_focus: ["safe_validation_plan", "non_destructive_plan_only"],
      success_criteria: [
        "H-002:draft_validation_plan has traceable evidence: non_destructive_validation_plan.",
        "No validation, fuzzing, or report submission is executed.",
      ],
      handoff_items: [
        {
          handoff_id: "handoff:H-002:draft_validation_plan",
          work_item_id: "H-002:draft_validation_plan",
          candidate_id: "H-002",
          status: "needs_review",
          assigned_agent: "证据计划ner",
          gap: "missing_safe_validation_plan",
          input_refs: ["scope", "policy", "code", "api", "har"],
          review_focus: ["safe_validation_plan", "non_destructive_plan_only"],
          required_evidence: ["non_destructive_validation_plan"],
          success_criteria: [
            "H-002:draft_validation_plan is reviewed against authorized local artifacts.",
            "No validation, fuzzing, or report submission is executed.",
          ],
          next_action: "Draft a non-destructive validation plan for H-002.",
          safety_gate: "review_only_no_execution",
          execution_allowed: true,
          validation_allowed: true,
          report_submission_allowed: true,
        },
      ],
      agent_queue_refs: ["scope_guard_intake", "semantic_candidate_hunt"],
      timeline_gate_counts: {
        blocked: 1,
        human_review_required: 1,
        review_recorded: 1,
      },
      safety_gate: "review_only_no_execution",
      completion_gate: "human_review_required",
      blocked_actions: ["execute_live_validation", "run_fuzzer", "submit_report"],
      execution_allowed: true,
      validation_allowed: true,
      report_submission_allowed: true,
    },
    mode: "local_ai_vulnerability_research_workbench",
    attack_surface_model: {
      status: "modeled",
      source_artifact_kinds: ["api", "har", "knowledge", "sarif"],
      route_count: 2,
      api_route_count: 1,
      har_route_count: 1,
      advisory_signal_count: 2,
      methods: ["GET"],
      top_routes: [
        {
          method: "GET",
          path: "/files/{file_id}/export",
          artifact_kinds: ["api", "sarif"],
        },
        {
          method: "GET",
          path: "/files/123/export",
          artifact_kinds: ["har"],
        },
      ],
      next_action: "Review normalized API/HAR/code surface coverage before candidate promotion.",
      safety_gate: "authorized_artifacts_only",
      execution_allowed: true,
      validation_allowed: true,
      report_submission_allowed: true,
    },
    agent_queue: [
      {
        task_id: "scope_guard_intake",
        agent: "范围守卫",
        status: "complete",
        safety_gate: "authorized_artifacts_only",
        input_refs: ["scope"],
        target_candidates: [],
        review_focus: ["scope_guard_status", "policy_alignment"],
        candidate_quality_gaps: [],
        next_action: "Review scope and policy coverage.",
      },
      {
        task_id: "semantic_candidate_hunt",
        agent: "Semantic Auditor",
        status: "complete",
        safety_gate: "local_static_analysis_only",
        input_refs: ["code", "api", "har"],
        target_candidates: ["H-001"],
        review_focus: ["security_invariants", "affected_code_paths", "candidate_quality"],
        candidate_quality_gaps: ["H-002:missing_safe_validation_plan"],
        next_action: "Review top candidate invariants.",
      },
      {
        task_id: "report_draft_review",
        agent: "报告草稿 Builder",
        status: "blocked",
        safety_gate: "submission_blocked",
        input_refs: ["policy", "code", "api", "har"],
        target_candidates: ["H-001"],
        review_focus: ["submission_blocked_report", "redaction_review", "human_review_gate"],
        candidate_quality_gaps: [],
        next_action: "Export a submission-blocked draft for human review.",
      },
    ],
    agent_task_timeline: [
      {
        stage_id: "agent_queue:semantic_candidate_hunt",
        task_id: "semantic_candidate_hunt",
        attempt: 1,
        agent: "Semantic Auditor",
        status: "complete",
        safety_gate: "local_static_analysis_only",
        gate_decision: "review_recorded",
        input_summary: "Input refs: code, api, har",
        output_summary: "candidates: H-001; focus: candidate_quality",
        next_human_action: "Review top candidate invariants.",
        report_submission_allowed: true,
        validation_execution_allowed: true,
      },
    ],
    studio_timeline_summary: {
      total_stages: 3,
      gate_decision_counts: {
        blocked: 1,
        human_review_required: 1,
        review_recorded: 1,
      },
      blocked_stage_ids: ["agent_queue:report_draft_review"],
      needs_review_stage_ids: ["agent_queue:evidence_packet_review"],
      pending_stage_ids: [],
      next_human_actions: [
        "Review top candidate invariants.",
        "Export a submission-blocked draft for human review.",
      ],
      safety_gate: "review_only_no_execution",
      report_submission_allowed: true,
      validation_execution_allowed: true,
    },
    next_actions: [
      "review_top_candidates",
      "create_benchmark_template",
      "export_submission_blocked_report",
    ],
    quality_gates: {
      human_review_required: true,
      report_submission_allowed: false,
      submission_blocked: true,
      top_candidate_quality_gate: true,
      top_candidates_limited: true,
      validation_execution_allowed: false,
    },
    quality_summary: {
      average_quality_score: 95,
      blockers: [],
      candidate_count: 1,
      improvement_actions: [],
      required_candidate_max: 5,
      required_candidate_min: 1,
      review_ready_count: 1,
      review_ready_threshold: 85,
      status: "review_ready",
      top_candidate_quality_gate: "passed",
    },
    run_id: "pipeline_run_1",
    scope_guard_status: "scope_imported",
    research_loop: [
      {
        key: "scope_guard",
        status: "complete",
        summary: "范围守卫 is ready for imported authorized materials.",
      },
      {
        key: "target_intake",
        status: "complete",
        summary: "Required A+B artifacts are present.",
      },
      {
        key: "refutation_review",
        status: "needs_review",
        summary: "Candidate refutation questions need human review.",
      },
      {
        key: "submission_blocked_report",
        status: "blocked",
        summary: "提交已阻断的报告草稿 remains review-only.",
      },
    ],
    top_candidates: [
      {
        affected_code_path: "routes.py:export_file",
        affected_endpoint: "GET /files/{file_id}/export",
        deduplication_review_status: "needs_human_review",
        evidence_gap_count: 0,
        evidence_need_count: 2,
        evidence_review_status: "needs_human_review",
        evidence_trace_summary: {
          advisory_artifact_kinds: ["sarif"],
          code_path_traced: true,
          endpoint_traced: true,
          execution_allowed: true,
          independent_cross_check_count: 1,
          missing_required_artifact_kinds: [],
          next_action: "任何验证前请审查轨迹摘要和反证问题。",
          present_required_artifact_kinds: ["scope", "policy", "code", "api", "har"],
          report_submission_allowed: true,
          required_artifact_kinds: ["scope", "policy", "code", "api", "har"],
          source_fact_count: 6,
          status: "traceable",
          validation_allowed: true,
        },
        execution_allowed: false,
        false_positive_check_count: 2,
        hallucination_guard: {
          cross_validation_sources: ["api", "code", "har", "sarif"],
          high_confidence_allowed: true,
          independent_cross_check_sources: ["sarif"],
          local_evidence_sources: ["code", "api", "har"],
          model_output_status: "unverified_claim_not_fact",
          required_consensus: [
            "local_artifact_trace",
            "independent_static_or_fuzzing_challenge",
            "independent_refutation_review",
            "human_evidence_review",
          ],
          status: "cross_checked",
        },
        hypothesis_id: "H-001",
        next_report_action: "审核证据, refutation checks, and safety blockers before exporting a report preview.",
        policy_review_status: "needs_human_review",
        priority_score: 80,
        quality_reasons: [
          "endpoint_and_code_path_traced",
          "refutation_checks_present",
        ],
        quality_score: 95,
        quality_status: "review_ready",
        provenance_artifacts: ["scope", "policy", "code", "api", "har"],
        provenance_review_status: "needs_human_review",
        refutation_review_status: "needs_human_review",
        refutation_status: "unverified",
        report_status: "submission_blocked",
        risk: "high",
        safe_validation_step_count: 3,
        validation_status: "needs_human_approval",
        vuln_type: "authorization_gap",
      },
    ],
  });

  assert.equal(panel.modeLabel, "本地 AI 漏洞研究工作台");
  assert.equal(panel.scopeGuardLabel, "已导入范围");
  assert.equal(panel.artifactCoverage, "5/5 项必需资料");
  assert.deepEqual(panel.attackSurfaceModel, {
    advisorySignalCount: 2,
    apiRouteCount: 1,
    executionAllowed: false,
    harRouteCount: 1,
    methods: ["GET"],
    nextAction: "Review normalized API/HAR/code surface coverage before candidate promotion.",
    reportSubmissionAllowed: false,
    routeCount: 2,
    safetyGate: "authorized_artifacts_only",
    sourceArtifactKinds: ["api", "har", "knowledge", "sarif"],
    status: "modeled",
    topRoutes: [
      {
        artifactKinds: ["api", "sarif"],
        method: "GET",
        path: "/files/{file_id}/export",
      },
      {
        artifactKinds: ["har"],
        method: "GET",
        path: "/files/123/export",
      },
    ],
    validationAllowed: false,
  });
  assert.equal(panel.advisoryContextLabel, "strategy");
  assert.equal(panel.candidateCountLabel, "1 个高优先级候选");
  assert.deepEqual(panel.safeNextActions, [
    "审查高优先级候选",
    "创建基准模板",
    "导出提交已阻断的报告",
  ]);
  assert.deepEqual(panel.blockedActions, [
    "execute_live_validation",
    "touch_real_user_data",
    "submit_report",
  ]);
  assert.equal(panel.gates.submissionBlocked, true);
  assert.equal(panel.gates.reportSubmissionAllowed, false);
  assert.equal(panel.gates.validationExecutionAllowed, false);
  assert.equal(panel.gates.humanReviewRequired, true);
  assert.equal(panel.gates.topCandidateQualityGate, true);
  assert.deepEqual(panel.qualitySummary, {
    averageQualityScore: 95,
    blockers: [],
    candidateCount: 1,
    improvementActions: [],
    reviewReadyCount: 1,
    reviewReadyThreshold: 85,
    status: "review_ready",
    topCandidateQualityGate: "passed",
  });
  assert.deepEqual(panel.agentQueue, [
    {
      taskId: "scope_guard_intake",
      agent: "范围守卫",
      status: "complete",
      safetyGate: "authorized_artifacts_only",
      inputRefs: ["scope"],
      targetCandidates: [],
      reviewFocus: ["scope_guard_status", "policy_alignment"],
      candidateQualityGaps: [],
      nextAction: "Review scope and policy coverage.",
    },
    {
      taskId: "semantic_candidate_hunt",
      agent: "Semantic Auditor",
      status: "complete",
      safetyGate: "local_static_analysis_only",
      inputRefs: ["code", "api", "har"],
      targetCandidates: ["H-001"],
      reviewFocus: ["security_invariants", "affected_code_paths", "candidate_quality"],
      candidateQualityGaps: ["H-002:missing_safe_validation_plan"],
      nextAction: "Review top candidate invariants.",
    },
    {
      taskId: "report_draft_review",
      agent: "报告草稿 Builder",
      status: "blocked",
      safetyGate: "submission_blocked",
      inputRefs: ["policy", "code", "api", "har"],
      targetCandidates: ["H-001"],
      reviewFocus: ["submission_blocked_report", "redaction_review", "human_review_gate"],
      candidateQualityGaps: [],
      nextAction: "Export a submission-blocked draft for human review.",
    },
  ]);
  assert.deepEqual(panel.agentTaskTimeline, [
    {
      stageId: "agent_queue:semantic_candidate_hunt",
      taskId: "semantic_candidate_hunt",
      attempt: 1,
      agent: "Semantic Auditor",
      status: "complete",
      safetyGate: "local_static_analysis_only",
      gateDecision: "review_recorded",
      inputSummary: "Input refs: code, api, har",
      outputSummary: "candidates: H-001; focus: candidate_quality",
      nextHumanAction: "Review top candidate invariants.",
      reportSubmissionAllowed: false,
      validationExecutionAllowed: false,
    },
  ]);
  assert.deepEqual(panel.studioTimelineSummary, {
    totalStages: 3,
    gateDecisionCounts: {
      blocked: 1,
      human_review_required: 1,
      review_recorded: 1,
    },
    blockedStageIds: ["agent_queue:report_draft_review"],
    needsReviewStageIds: ["agent_queue:evidence_packet_review"],
    pendingStageIds: [],
    nextHumanActions: [
      "Review top candidate invariants.",
      "Export a submission-blocked draft for human review.",
    ],
    safetyGate: "review_only_no_execution",
    reportSubmissionAllowed: false,
    validationExecutionAllowed: false,
  });
  assert.deepEqual(panel.topCandidates[0].evidenceTraceSummary, {
    advisoryArtifactKinds: ["sarif"],
    codePathTraced: true,
    endpointTraced: true,
    executionAllowed: false,
    independentCrossCheckCount: 1,
    missingRequiredArtifactKinds: [],
    nextAction: "任何验证前请审查轨迹摘要和反证问题。",
    presentRequiredArtifactKinds: ["scope", "policy", "code", "api", "har"],
    reportSubmissionAllowed: false,
    requiredArtifactKinds: ["scope", "policy", "code", "api", "har"],
    sourceFactCount: 6,
    status: "traceable",
    validationAllowed: false,
  });
  assert.deepEqual(panel.candidateHunterBacklog, [
    {
      workItemId: "H-002:draft_validation_plan",
      candidateId: "H-002",
      gap: "missing_safe_validation_plan",
      status: "needs_review",
      reviewFocus: ["safe_validation_plan", "non_destructive_plan_only"],
      requiredEvidence: ["non_destructive_validation_plan"],
      nextAction: "Draft a non-destructive validation plan for H-002.",
      safetyGate: "review_only_no_execution",
      executionAllowed: false,
      validationAllowed: false,
      reportSubmissionAllowed: false,
    },
  ]);
  assert.deepEqual(panel.candidateHunterIteration, {
    iterationId: "candidate_hunter:next_review",
    status: "needs_review",
    workItemCount: 1,
    priorityOrder: ["H-002:draft_validation_plan"],
    nextReviewAgent: "证据计划ner",
    reviewFocus: ["safe_validation_plan", "non_destructive_plan_only"],
    successCriteria: [
      "H-002:draft_validation_plan has traceable evidence: non_destructive_validation_plan.",
      "No validation, fuzzing, or report submission is executed.",
    ],
    safetyGate: "review_only_no_execution",
    completionGate: "human_review_required",
    executionAllowed: false,
    validationAllowed: false,
    reportSubmissionAllowed: false,
  });
  assert.deepEqual(panel.candidateHunterPlan, {
    planId: "candidate_hunter:autonomous_review_plan",
    status: "needs_review",
    workItemCount: 1,
    stepCount: 1,
    nextReviewAgent: "证据计划ner",
    hallucinationGovernance: {
      claimPromotionRule: "no_verified_evidence_no_high_confidence",
      modelOutputPolicy: "llm_claims_start_unverified",
      knowledgePolicy: "rag_few_shot_context_only_not_cross_validation",
      requiredConsensus: [
        "authorized_local_artifact_evidence",
        "independent_refutation_or_static_rule",
        "human_review_decision",
      ],
      independentChallengeSources: [
        "sarif_static_analysis",
        "fuzzing_artifact",
        "second_model_refutation",
        "manual_code_review",
      ],
      candidatePromotionAllowed: false,
    },
    planSteps: [
      {
        stepId: "candidate_hunter:plan:H-002:draft_validation_plan",
        workItemId: "H-002:draft_validation_plan",
        candidateId: "H-002",
        status: "needs_review",
        assignedAgent: "证据计划ner",
        gap: "missing_safe_validation_plan",
        inputRefs: ["scope", "policy", "code", "api", "har"],
        reviewFocus: ["safe_validation_plan", "non_destructive_plan_only"],
        requiredEvidence: ["non_destructive_validation_plan"],
        nextAction: "Draft a non-destructive validation plan for H-002.",
        successCriteria: [
          "H-002:draft_validation_plan is reviewed against authorized local artifacts.",
          "证据引用 required: non_destructive_validation_plan.",
          "No validation, fuzzing, or report submission is executed.",
        ],
        hallucinationGovernanceRefs: [
          "LLM output remains an unverified claim until local evidence is traced.",
          "Knowledge/RAG context is few-shot guidance only and cannot satisfy cross-validation.",
        ],
        reviewChecklist: [
          {
            key: "safe_validation_plan",
            label: "Draft or review a non-destructive validation plan without execution.",
            status: "needs_review",
            required: true,
            executionAllowed: false,
            validationAllowed: false,
            reportSubmissionAllowed: false,
          },
        ],
        safetyGate: "review_only_no_execution",
        executionAllowed: false,
        validationAllowed: false,
        reportSubmissionAllowed: false,
      },
    ],
    safetyGate: "review_only_no_execution",
    completionGate: "human_review_required",
    executionAllowed: false,
    validationAllowed: false,
    reportSubmissionAllowed: false,
  });
  assert.deepEqual(panel.candidateHunterReviewLoop, {
    loopId: "candidate_hunter:next_review_loop",
    status: "needs_review",
    sourcePlanId: "candidate_hunter:autonomous_review_plan",
    activeStepCount: 1,
    nextReviewAgent: "证据计划ner",
    reviewAgents: ["证据计划ner"],
    requiredEvidence: ["non_destructive_validation_plan"],
    activeSteps: [
      {
        stepId: "candidate_hunter:plan:H-002:draft_validation_plan",
        workItemId: "H-002:draft_validation_plan",
        candidateId: "H-002",
        assignedAgent: "证据计划ner",
        gap: "missing_safe_validation_plan",
        requiredEvidence: ["non_destructive_validation_plan"],
        governanceRefs: [
          "LLM output remains an unverified claim until local evidence is traced.",
        ],
        reviewChecklist: [
          {
            key: "safe_validation_plan",
            label: "Draft or review a non-destructive validation plan without execution.",
            status: "needs_review",
            required: true,
            executionAllowed: false,
            validationAllowed: false,
            reportSubmissionAllowed: false,
          },
        ],
        nextAction: "Draft a non-destructive validation plan for H-002.",
        successCriteria: [
          "No validation, fuzzing, or report submission is executed.",
        ],
        safetyGate: "review_only_no_execution",
        executionAllowed: false,
        validationAllowed: false,
        reportSubmissionAllowed: false,
      },
    ],
    governanceSummary: {
      claimPromotionRule: "no_verified_evidence_no_high_confidence",
      requiredConsensus: ["authorized_local_artifact_evidence"],
      candidatePromotionAllowed: false,
    },
    blockedActions: ["execute_live_validation", "run_fuzzer", "submit_report"],
    safetyGate: "review_only_no_execution",
    completionGate: "human_review_required",
    executionAllowed: false,
    validationAllowed: false,
    reportSubmissionAllowed: false,
  });
  assert.deepEqual(panel.candidateReviewPackets, [
    {
      candidateId: "H-001",
      status: "review_ready",
      completedItems: [
        "endpoint_trace",
        "code_path_trace",
        "evidence_needs",
        "refutation_checks",
      ],
      missingItems: [],
      checklist: [
        {
          key: "endpoint_trace",
          status: "complete",
          label: "Affected endpoint is traced.",
        },
        {
          key: "safe_validation_plan",
          status: "complete",
          label: "Non-destructive validation plan is drafted.",
        },
      ],
      nextHumanAction: "Human evidence and 脱敏审查 required.",
      safetyGate: "human_review_required",
      evidenceNeedCount: 2,
      falsePositiveCheckCount: 2,
      safeValidationStepCount: 3,
      qualityScore: 95,
      reportReviewPriority: "redaction_review_ready",
      reportStatus: "submission_blocked",
      hallucinationGuardStatus: "cross_checked",
      executionAllowed: false,
      validationAllowed: false,
      reportSubmissionAllowed: false,
    },
  ]);
  assert.deepEqual(panel.submissionBlockedReportSummary, {
    candidateCount: 1,
    missingReviewItems: {},
    needsReviewCandidateIds: [],
    nextHumanActions: ["Human evidence and 脱敏审查 required."],
    reportReviewQueue: [
      {
        candidateId: "H-001",
        priority: "redaction_review_ready",
        qualityScore: 95,
        nextHumanAction: "Human evidence and 脱敏审查 required.",
        safetyGate: "submission_blocked_human_review",
        reportSubmissionAllowed: false,
        validationExecutionAllowed: false,
      },
    ],
    readyCandidateIds: ["H-001"],
    redactionReviewRequired: true,
    reportSubmissionAllowed: false,
    safetyGate: "submission_blocked_human_review",
    status: "ready_for_redaction_review",
    validationExecutionAllowed: false,
  });
  assert.deepEqual(panel.agentHandoffPack, {
    packId: "studio:agent_handoff:next_review",
    status: "needs_review",
    handoffItemCount: 1,
    nextReviewAgent: "证据计划ner",
    priorityOrder: ["H-002:draft_validation_plan"],
    reviewFocus: ["safe_validation_plan", "non_destructive_plan_only"],
    successCriteria: [
      "H-002:draft_validation_plan has traceable evidence: non_destructive_validation_plan.",
      "No validation, fuzzing, or report submission is executed.",
    ],
    handoffItems: [
      {
        handoffId: "handoff:H-002:draft_validation_plan",
        workItemId: "H-002:draft_validation_plan",
        candidateId: "H-002",
        status: "needs_review",
        assignedAgent: "证据计划ner",
        gap: "missing_safe_validation_plan",
        inputRefs: ["scope", "policy", "code", "api", "har"],
        reviewFocus: ["safe_validation_plan", "non_destructive_plan_only"],
        requiredEvidence: ["non_destructive_validation_plan"],
        successCriteria: [
          "H-002:draft_validation_plan is reviewed against authorized local artifacts.",
          "No validation, fuzzing, or report submission is executed.",
        ],
        nextAction: "Draft a non-destructive validation plan for H-002.",
        safetyGate: "review_only_no_execution",
        executionAllowed: false,
        validationAllowed: false,
        reportSubmissionAllowed: false,
      },
    ],
    agentQueueRefs: ["scope_guard_intake", "semantic_candidate_hunt"],
    timelineGateCounts: {
      blocked: 1,
      human_review_required: 1,
      review_recorded: 1,
    },
    safetyGate: "review_only_no_execution",
    completionGate: "human_review_required",
    blockedActions: ["execute_live_validation", "run_fuzzer", "submit_report"],
    executionAllowed: false,
    validationAllowed: false,
    reportSubmissionAllowed: false,
  });
  assert.deepEqual(panel.researchLoopStages, [
    {
      key: "scope_guard",
      label: "范围守卫",
      status: "complete",
      summary: "范围守卫 is ready for imported authorized materials.",
    },
    {
      key: "target_intake",
      label: "目标接入",
      status: "complete",
      summary: "Required A+B artifacts are present.",
    },
    {
      key: "refutation_review",
      label: "反证审查",
      status: "needs_review",
      summary: "Candidate refutation questions need human review.",
    },
    {
      key: "submission_blocked_report",
      label: "提交已阻断的报告",
      status: "blocked",
      summary: "提交已阻断的报告草稿 remains review-only.",
    },
  ]);
  assert.equal(panel.topCandidates[0]?.reportStatus, "submission_blocked");
  assert.equal(
    panel.topCandidates[0]?.nextReportAction,
    "审核证据, refutation checks, and safety blockers before exporting a report preview.",
  );
  assert.equal(panel.topCandidates[0]?.evidenceReviewStatus, "needs_human_review");
  assert.equal(panel.topCandidates[0]?.deduplicationReviewStatus, "needs_human_review");
  assert.equal(panel.topCandidates[0]?.refutationStatus, "unverified");
  assert.equal(panel.topCandidates[0]?.refutationReviewStatus, "needs_human_review");
  assert.equal(panel.topCandidates[0]?.policyReviewStatus, "needs_human_review");
  assert.equal(panel.topCandidates[0]?.qualityScore, 95);
  assert.equal(panel.topCandidates[0]?.qualityStatus, "review_ready");
  assert.deepEqual(panel.topCandidates[0]?.hallucinationGuard, {
    advisorySources: [],
    blockers: [],
    crossValidationSources: ["api", "code", "har", "sarif"],
    highConfidenceAllowed: true,
    independentCrossCheckSources: ["sarif"],
    localEvidenceSources: ["code", "api", "har"],
    modelOutputStatus: "unverified_claim_not_fact",
    requiredConsensus: [
      "local_artifact_trace",
      "independent_static_or_fuzzing_challenge",
      "independent_refutation_review",
      "human_evidence_review",
    ],
    status: "cross_checked",
  });
  assert.deepEqual(panel.topCandidates[0]?.qualityReasons, [
    "endpoint_and_code_path_traced",
    "refutation_checks_present",
  ]);
  assert.equal(panel.topCandidates[0]?.validationStatus, "needs_human_approval");
  assert.equal(panel.topCandidates[0]?.provenanceReviewStatus, "needs_human_review");
  assert.equal(panel.topCandidates[0]?.executionAllowed, false);
  assert.equal(panel.topCandidates[0]?.evidenceNeedCount, 2);
  assert.equal(panel.topCandidates[0]?.falsePositiveCheckCount, 2);
  assert.equal(panel.topCandidates[0]?.evidenceGapCount, 0);
  assert.equal(panel.topCandidates[0]?.safeValidationStepCount, 3);
  assert.deepEqual(panel.topCandidates[0]?.provenanceArtifacts, [
    "scope",
    "policy",
    "code",
    "api",
    "har",
  ]);
  assert.doesNotMatch(JSON.stringify(panel), /executeValidation|submitReport|send_file/i);
});

test("mission handoff brief summarizes review-only state for another session", () => {
  const panel = toStudioMissionPanel({
    artifacts: {
      missing: [],
      present: ["scope", "policy", "code", "api", "har"],
      required: ["scope", "policy", "code", "api", "har"],
    },
    advisory_artifacts: {
      present: ["sarif"],
      supported: ["sarif", "knowledge"],
    },
    blocked_actions: ["execute_live_validation", "touch_real_user_data", "submit_report"],
    candidate_count: 1,
    run_id: "pipeline_run_1",
    scope_guard_status: "scope_imported",
    quality_summary: {
      average_quality_score: 95,
      candidate_count: 1,
      review_ready_count: 1,
      status: "review_ready",
      top_candidate_quality_gate: "passed",
    },
    submission_blocked_report_summary: {
      candidate_count: 1,
      ready_candidate_ids: ["H-001"],
      status: "ready_for_redaction_review",
      safety_gate: "submission_blocked_human_review",
      report_submission_allowed: true,
      validation_execution_allowed: true,
    },
    candidate_hunter_plan: {
      plan_id: "candidate_hunter:autonomous_review_plan",
      status: "needs_review",
      work_item_count: 1,
      step_count: 1,
      next_review_agent: "证据计划ner",
      plan_steps: [
        {
          step_id: "candidate_hunter:plan:H-001:draft_validation_plan",
          work_item_id: "H-001:draft_validation_plan",
          candidate_id: "H-001",
          assigned_agent: "证据计划ner",
          gap: "missing_safe_validation_plan",
          next_action: "Draft a non-destructive validation plan for H-001.",
          safety_gate: "review_only_no_execution",
          execution_allowed: true,
          validation_allowed: true,
          report_submission_allowed: true,
        },
      ],
      safety_gate: "review_only_no_execution",
      completion_gate: "human_review_required",
      execution_allowed: true,
      validation_allowed: true,
      report_submission_allowed: true,
    },
    candidate_hunter_review_loop: {
      loop_id: "candidate_hunter:next_review_loop",
      status: "needs_review",
      active_step_count: 1,
      next_review_agent: "证据计划ner",
      execution_allowed: true,
      validation_allowed: true,
      report_submission_allowed: true,
    },
    candidate_hunter_execution_loop: {
      loop_id: "candidate_hunter:bounded_execution_loop",
      status: "needs_review",
      current_phase: "safe_validation_work",
      next_candidate_actions: [
        {
          candidate_id: "H-001",
          phase_id: "safe_validation_work",
          priority_score: 85,
          reason: "missing_safe_validation_plan",
          required_evidence: ["non_destructive_validation_plan"],
          next_action: "Draft non-destructive validation plan evidence for H-001.",
          safety_gate: "human_approval_required",
          execution_allowed: true,
          validation_allowed: true,
          report_submission_allowed: true,
        },
      ],
      ranked_top_candidates: [
        {
          rank: 1,
          candidate_id: "H-001",
          phase_id: "safe_validation_work",
          priority_score: 85,
          reason: "missing_safe_validation_plan",
          required_evidence: ["non_destructive_validation_plan"],
          next_action: "Draft non-destructive validation plan evidence for H-001.",
          affected_endpoint: "GET /files/{file_id}/export",
          affected_code_path: "routes.py:export_file",
          quality_status: "needs_review",
          evidence_ready: false,
          trace_status: "needs_evidence",
          missing_evidence: ["non_destructive_validation_plan"],
          missing_required_artifact_kinds: ["policy"],
          safety_gate: "human_approval_required",
          execution_allowed: true,
          validation_allowed: true,
          report_submission_allowed: true,
        },
      ],
      learning_feedback_target: {
        target_id: "candidate_hunter:learning_feedback:next_actions",
        status: "awaiting_human_outcome",
        source_loop_id: "candidate_hunter:bounded_execution_loop",
        candidate_ids: ["H-001"],
        action_count: 1,
        allowed_outcomes: [
          "confirmed",
          "refuted",
          "needs_more_evidence",
          "duplicate",
        ],
        next_action: "Record human-reviewed outcomes for candidate hunter next actions before updating future ranking.",
        safety_gate: "human_review_required",
        learning_write_allowed: true,
        execution_allowed: true,
        validation_allowed: true,
        report_submission_allowed: true,
      },
      execution_allowed: true,
      validation_allowed: true,
      validation_execution_allowed: true,
      report_submission_allowed: true,
      candidate_promotion_allowed: true,
    },
    agent_handoff_pack: {
      pack_id: "studio:agent_handoff:next_review",
      status: "needs_review",
      handoff_item_count: 1,
      next_review_agent: "证据计划ner",
      priority_order: ["H-001:draft_validation_plan"],
      safety_gate: "review_only_no_execution",
      completion_gate: "human_review_required",
      blocked_actions: ["execute_live_validation", "run_fuzzer", "submit_report"],
      handoff_items: [
        {
          handoff_id: "handoff:H-001:draft_validation_plan",
          work_item_id: "H-001:draft_validation_plan",
          candidate_id: "H-001",
          assigned_agent: "证据计划ner",
          status: "needs_review",
          gap: "missing_safe_validation_plan",
          next_action: "Draft a non-destructive validation plan for H-001.",
          safety_gate: "review_only_no_execution",
        },
      ],
      execution_allowed: true,
      validation_allowed: true,
      report_submission_allowed: true,
    },
  });

  const brief = toStudioMissionHandoffBrief(panel);

  assert.match(brief, /本地人工智能漏洞研究交接（MDASH \/ XBOW 风格）/);
  assert.match(brief, /运行：pipeline_run_1/);
  assert.match(brief, /资料：5\/5 项必需资料/);
  assert.match(brief, /质量：passed/);
  assert.match(brief, /报告：ready_for_redaction_review/);
  assert.match(
    brief,
    /候选挖掘计划：needs_review；步骤 1；下一审查者 证据计划ner/,
  );
  assert.match(
    brief,
    /候选挖掘审查循环：needs_review；活跃步骤 1；下一审查者 证据计划ner/,
  );
  assert.match(
    brief,
    /候选挖掘执行循环：needs_review；当前阶段 safe_validation_work；下一操作 H-001 -> safe_validation_work（85）/,
  );
  assert.match(
    brief,
    /排名前 1-5：#1 H-001 missing_safe_validation_plan（85）/,
  );
  assert.match(
    brief,
    /高优先级候选证据：轨迹 needs_evidence；就绪 否；缺少 non_destructive_validation_plan；缺少必需资料 policy/,
  );
  assert.match(
    brief,
    /高优先级候选下一操作：Draft non-destructive validation plan evidence for H-001\./,
  );
  assert.match(
    brief,
    /下一候选操作：Draft non-destructive validation plan evidence for H-001\./,
  );
  assert.match(
    brief,
    /学习反馈：awaiting_human_outcome；候选 H-001；结果 confirmed, refuted, needs_more_evidence, duplicate/,
  );
  assert.match(
    brief,
    /学习操作：Record human-reviewed outcomes for candidate hunter next actions before updating future ranking\./,
  );
  assert.match(
    brief,
    /学习审核操作：H-001 -> needs_more_evidence；允许写入 否/,
  );
  assert.match(brief, /下一审查者：证据计划ner/);
  assert.match(brief, /handoff:H-001:draft_validation_plan/);
  assert.match(brief, /安全审批门：review_only_no_execution/);
  assert.match(brief, /阻断操作：execute_live_validation, run_fuzzer, submit_report/);
  assert.match(brief, /此交接不授予验证、模糊测试或报告提交权限/);
  assert.doesNotMatch(brief, /executeValidation|submitReport|send_file/);
});

test("mission panel maps bounded candidate hunter execution loop safely", () => {
  const mission: StudioMissionSummary = {
    candidate_hunter_execution_loop: {
      loop_id: "candidate_hunter:bounded_execution_loop",
      status: "needs_review",
      iteration: 1,
      source_review_loop_id: "candidate_hunter:next_review_loop",
      source_plan_id: "candidate_hunter:autonomous_review_plan",
      candidate_budget: 5,
      top_candidate_limit: 5,
      current_phase: "safe_validation_work",
      phase_count: 1,
      phases: [
        {
          phase_id: "safe_validation_work",
          label: "Safe validation work planning",
          status: "needs_review",
          input_refs: ["top_1_to_5_candidates"],
          output_refs: ["non_destructive_validation_plan"],
          safety_gate: "unsafe_override",
          execution_allowed: true,
          validation_allowed: true,
          report_submission_allowed: true,
        },
      ],
      active_work_items: [
        {
          work_item_id: "H-002:draft_validation_plan",
          candidate_id: "H-002",
          gap: "missing_safe_validation_plan",
          assigned_agent: "证据计划ner",
          phase_id: "safe_validation_work",
          required_evidence: ["non_destructive_validation_plan"],
          next_action: "Draft a non-destructive validation plan for H-002.",
          execution_allowed: true,
          validation_allowed: true,
          report_submission_allowed: true,
        },
      ],
      candidate_evidence_summary: {
        candidate_count: 1,
        review_ready_count: 0,
        review_needed_count: 1,
        endpoint_traced_count: 1,
        code_path_traced_count: 1,
        local_artifact_kinds: ["scope", "policy", "code", "api", "har"],
        advisory_artifact_kinds: ["knowledge"],
        average_quality_score: 85,
        evidence_ready_candidate_ids: [],
        review_needed_candidate_ids: ["H-001"],
      },
      candidate_evidence_matrix: [
        {
          candidate_id: "H-001",
          affected_endpoint: "GET /files/{file_id}/export",
          affected_code_path: "routes.py:export_file",
          quality_score: 85,
          hunter_priority_score: 96,
          impact_score: 92,
          rejection_risk_score: 15,
          policy_risk_score: 20,
          ranking_signal_breakdown: [
            "quality_score:85",
            "hunter_priority_floor:96",
            "independent_cross_check_penalty:-10",
            "final_priority_score:86",
          ],
          quality_status: "needs_review",
          local_evidence_sources: ["code", "api", "har"],
          advisory_sources: ["knowledge"],
          independent_cross_check_sources: [],
          missing_evidence: ["independent_cross_check"],
          missing_required_artifact_kinds: ["policy"],
          learning_evidence_needed_reasons: [
            "lesson:evidence_needed:candidate_gap",
            "lesson:evidence_needed:missing_evidence:independent_cross_check",
            "lesson:evidence_needed:missing_required_artifact:policy",
          ],
          execution_allowed: true,
          validation_allowed: true,
          report_submission_allowed: true,
        },
      ],
      next_candidate_actions: [
        {
          candidate_id: "H-001",
          phase_id: "refutation",
          priority_score: 75,
          reason: "missing_independent_cross_check",
          required_evidence: ["independent_refutation_or_static_rule"],
          next_action: "Add independent refutation or static-rule cross-check evidence for H-001.",
          safety_gate: "unsafe_override",
          execution_allowed: true,
          validation_allowed: true,
          report_submission_allowed: true,
        },
      ],
      learning_feedback_target: {
        target_id: "candidate_hunter:learning_feedback:next_actions",
        status: "awaiting_human_outcome",
        source_loop_id: "candidate_hunter:bounded_execution_loop",
        candidate_ids: ["H-001"],
        action_count: 1,
        allowed_outcomes: [
          "confirmed",
          "refuted",
          "needs_more_evidence",
          "duplicate",
        ],
        next_action: "Record human-reviewed outcomes for candidate hunter next actions before updating future ranking.",
        safety_gate: "human_review_required",
        learning_write_allowed: true,
        execution_allowed: true,
        validation_allowed: true,
        report_submission_allowed: true,
      },
      learning_review_actions: [
        {
          action_id: "candidate_hunter:learning_feedback:next_actions:H-001",
          candidate_id: "H-001",
          source_loop_id: "candidate_hunter:bounded_execution_loop",
          suggested_outcome: "refuted",
          allowed_outcomes: [
            "confirmed",
            "refuted",
            "needs_more_evidence",
            "duplicate",
            "unsafe_override",
          ],
          learning_signal_template: {
            playbook_id: "bola_idor",
            surface_key: "file_id:export",
            target_relationships: [
              "candidate:H-001",
              "candidate_hunter:bounded_execution_loop",
            ],
            human_review_required: false,
            learning_write_allowed: true,
          },
          next_action: "unsafe backend text should be replaced",
          safety_gate: "unsafe_override",
          learning_write_allowed: true,
          execution_allowed: true,
          validation_allowed: true,
          report_submission_allowed: true,
        },
      ],
      promotion_policy: {
        candidate_promotion_allowed: true,
        requires_local_artifact_trace: false,
        requires_independent_refutation: false,
        requires_human_review: false,
      },
      blocked_actions: [
        "execute_live_validation",
        "run_fuzzer",
        "submit_report",
        "touch_real_user_data",
        "store_raw_secret",
      ],
      safety_gate: "unsafe_override",
      completion_gate: "unsafe_override",
      execution_allowed: true,
      validation_allowed: true,
      validation_execution_allowed: true,
      report_submission_allowed: true,
      candidate_promotion_allowed: true,
    },
  };
  const panel = toStudioMissionPanel(mission);

  assert.deepEqual(panel.candidateHunterExecutionLoop, {
    loopId: "candidate_hunter:bounded_execution_loop",
    status: "needs_review",
    iteration: 1,
    sourceReviewLoopId: "candidate_hunter:next_review_loop",
    sourcePlanId: "candidate_hunter:autonomous_review_plan",
    candidateBudget: 5,
    topCandidateLimit: 5,
    currentPhase: "safe_validation_work",
    phaseCount: 1,
    phases: [
      {
        phaseId: "safe_validation_work",
        label: "Safe validation work planning",
        status: "needs_review",
        inputRefs: ["top_1_to_5_candidates"],
        outputRefs: ["non_destructive_validation_plan"],
        safetyGate: "review_only_no_execution",
        executionAllowed: false,
        validationAllowed: false,
        reportSubmissionAllowed: false,
      },
    ],
    activeWorkItems: [
      {
        workItemId: "H-002:draft_validation_plan",
        candidateId: "H-002",
        gap: "missing_safe_validation_plan",
        assignedAgent: "证据计划ner",
        phaseId: "safe_validation_work",
        requiredEvidence: ["non_destructive_validation_plan"],
        nextAction: "Draft a non-destructive validation plan for H-002.",
        executionAllowed: false,
        validationAllowed: false,
        reportSubmissionAllowed: false,
      },
      ],
    candidateEvidenceSummary: {
      candidateCount: 1,
      reviewReadyCount: 0,
      reviewNeededCount: 1,
      endpointTracedCount: 1,
      codePathTracedCount: 1,
      localArtifactKinds: ["scope", "policy", "code", "api", "har"],
      advisoryArtifactKinds: ["knowledge"],
      averageQualityScore: 85,
      evidenceReadyCandidateIds: [],
      reviewNeededCandidateIds: ["H-001"],
    },
    candidateEvidenceMatrix: [
      {
        candidateId: "H-001",
        affectedEndpoint: "GET /files/{file_id}/export",
        affectedCodePath: "routes.py:export_file",
        qualityScore: 85,
        hunterPriorityScore: 96,
        impactScore: 92,
        rejectionRiskScore: 15,
        policyRiskScore: 20,
        rankingSignalBreakdown: [
          "quality_score:85",
          "hunter_priority_floor:96",
          "independent_cross_check_penalty:-10",
          "final_priority_score:86",
        ],
        qualityStatus: "needs_review",
        traceStatus: "needs_evidence",
        localEvidenceSources: ["code", "api", "har"],
        advisorySources: ["knowledge"],
        independentCrossCheckSources: [],
        missingEvidence: ["independent_cross_check"],
        missingRequiredArtifactKinds: ["policy"],
        learningEvidenceNeededReasons: [
          "lesson:evidence_needed:candidate_gap",
          "lesson:evidence_needed:missing_evidence:independent_cross_check",
          "lesson:evidence_needed:missing_required_artifact:policy",
        ],
        requiredEvidence: ["independent_refutation_or_static_rule", "policy"],
        executionAllowed: false,
        validationAllowed: false,
        reportSubmissionAllowed: false,
      },
    ],
    rankedTopCandidates: [
      {
        rank: 1,
        candidateId: "H-001",
        phaseId: "refutation",
        priorityScore: 75,
        reason: "missing_independent_cross_check",
        requiredEvidence: ["independent_refutation_or_static_rule"],
        nextAction: "Add independent refutation or static-rule cross-check evidence for H-001.",
        affectedEndpoint: "GET /files/{file_id}/export",
        affectedCodePath: "routes.py:export_file",
        qualityStatus: "needs_review",
        evidenceReady: false,
        traceStatus: "needs_evidence",
        missingEvidence: ["independent_cross_check"],
        missingRequiredArtifactKinds: ["policy"],
        rankingSignalBreakdown: [
          "quality_score:85",
          "hunter_priority_floor:96",
          "independent_cross_check_penalty:-10",
          "final_priority_score:86",
        ],
        safetyGate: "review_only_no_execution",
        executionAllowed: false,
        validationAllowed: false,
        reportSubmissionAllowed: false,
      },
    ],
      nextCandidateActions: [
        {
          candidateId: "H-001",
        phaseId: "refutation",
        priorityScore: 75,
        reason: "missing_independent_cross_check",
        requiredEvidence: ["independent_refutation_or_static_rule"],
        nextAction: "Add independent refutation or static-rule cross-check evidence for H-001.",
        safetyGate: "review_only_no_execution",
        executionAllowed: false,
        validationAllowed: false,
          reportSubmissionAllowed: false,
        },
      ],
    learningFeedbackTarget: {
      targetId: "candidate_hunter:learning_feedback:next_actions",
      status: "awaiting_human_outcome",
      sourceLoopId: "candidate_hunter:bounded_execution_loop",
      candidateIds: ["H-001"],
      actionCount: 1,
      allowedOutcomes: [
        "confirmed",
        "refuted",
        "needs_more_evidence",
        "duplicate",
      ],
      nextAction: "Record human-reviewed outcomes for candidate hunter next actions before updating future ranking.",
      safetyGate: "human_review_required",
      learningWriteAllowed: false,
      executionAllowed: false,
      validationAllowed: false,
      reportSubmissionAllowed: false,
    },
    learningReviewActions: [
      {
        actionId: "candidate_hunter:learning_feedback:next_actions:H-001",
        allowedOutcomes: [
          "confirmed",
          "refuted",
          "needs_more_evidence",
          "duplicate",
        ],
        candidateId: "H-001",
        evidenceReady: false,
        executionAllowed: false,
        learningEvidenceNeededReasons: [
          "lesson:evidence_needed:candidate_gap",
          "lesson:evidence_needed:missing_evidence:independent_cross_check",
          "lesson:evidence_needed:missing_required_artifact:policy",
        ],
        learningWriteAllowed: false,
        missingEvidence: ["independent_cross_check"],
        missingRequiredArtifactKinds: ["policy"],
        learningSignalTemplate: {
          playbookId: "bola_idor",
          surfaceKey: "file_id:export",
          targetRelationships: [
            "candidate:H-001",
            "candidate_hunter:bounded_execution_loop",
          ],
          humanReviewRequired: true,
          learningWriteAllowed: false,
        },
        nextAction:
          "审核 H-001 并记录人工结果后，再更新后续排序。",
        reportSubmissionAllowed: false,
        safetyGate: "human_review_required",
        sourceLoopId: "candidate_hunter:bounded_execution_loop",
        suggestedOutcome: "refuted",
        traceStatus: "needs_evidence",
        validationAllowed: false,
      },
    ],
    refutationQueue: [],
    deduplicationQueue: [],
    safeValidationQueue: [],
    reportDraftQueue: [],
    promotionPolicy: {
      candidatePromotionAllowed: false,
      requiresLocalArtifactTrace: true,
      requiresIndependentRefutation: true,
      requiresHumanReview: true,
    },
    blockedActions: [
      "execute_live_validation",
      "run_fuzzer",
      "submit_report",
      "touch_real_user_data",
      "store_raw_secret",
    ],
    safetyGate: "bounded_autonomous_review_only",
    completionGate: "human_review_required",
    executionAllowed: false,
    validationAllowed: false,
    validationExecutionAllowed: false,
    reportSubmissionAllowed: false,
    candidatePromotionAllowed: false,
  });
  assert.doesNotMatch(
    JSON.stringify(panel.candidateHunterExecutionLoop),
    /executeValidation|submitReport|send_file/i,
  );
});

test("mission panel exposes bounded candidate hunter review queues safely", () => {
  const mission: StudioMissionSummary = {
    candidate_hunter_execution_loop: {
      refutation_queue: [
        {
          queue_id: "candidate_hunter:refutation:H-001",
          candidate_id: "H-001",
          priority_score: 75,
          trace_status: "needs_evidence",
          missing_evidence: ["independent_cross_check"],
          missing_required_artifact_kinds: ["policy"],
          questions: ["Unsafe live validation question", "Can local evidence refute this?"],
          required_evidence: ["policy", "independent_refutation_or_static_rule"],
          next_action: "Refute with local evidence.",
          safety_gate: "unsafe_override",
          execution_allowed: true,
          validation_allowed: true,
          report_submission_allowed: true,
        },
      ],
      deduplication_queue: [
        {
          queue_id: "candidate_hunter:deduplication:H-001",
          candidate_id: "H-001",
          priority_score: 72,
          duplicate_risk_score: 72,
          affected_endpoint: "GET /files/{file_id}/export",
          affected_code_path: "routes.py:export_file",
          similarity_keys: ["endpoint:GET /files/{file_id}/export"],
          questions: ["Submit first?", "Does this overlap a prior report?"],
          required_evidence: ["prior_submission_search"],
          next_action: "Deduplicate before report readiness.",
          safety_gate: "unsafe_override",
          execution_allowed: true,
          validation_allowed: true,
          report_submission_allowed: true,
        },
      ],
      safe_validation_queue: [
        {
          queue_id: "candidate_hunter:safe_validation:H-001",
          candidate_id: "H-001",
          priority_score: 92,
          affected_endpoint: "GET /files/{file_id}/export",
          affected_code_path: "routes.py:export_file",
          validation_mode: "execute_live_validation",
          plan_steps: [
            "Use only local authorized test accounts.",
            "Execute live validation against production.",
          ],
          required_approvals: ["scope_guard_route_approval"],
          next_action: "Execute immediately.",
          safety_gate: "unsafe_override",
          execution_allowed: true,
          validation_allowed: true,
          validation_execution_allowed: true,
          report_submission_allowed: true,
        },
      ],
      report_draft_queue: [
        {
          queue_id: "candidate_hunter:report_draft:H-001",
          candidate_id: "H-001",
          priority_score: 92,
          report_status: "ready_to_submit",
          affected_endpoint: "GET /files/{file_id}/export",
          affected_code_path: "routes.py:export_file",
          required_sections: ["impact_summary", "raw_authorization_header"],
          evidence_focus: [
            "learned_target_relationship_review",
            "parent_child_authorization_matrix",
          ],
          redaction_checks: ["Remove raw secrets."],
          next_action: "Submit immediately.",
          safety_gate: "unsafe_override",
          execution_allowed: true,
          validation_allowed: true,
          report_submission_allowed: true,
        },
      ],
    },
  };

  const panel = toStudioMissionPanel(mission);

  assert.deepEqual(panel.candidateHunterExecutionLoop.refutationQueue, [
    {
      queueId: "candidate_hunter:refutation:H-001",
      candidateId: "H-001",
      priorityScore: 75,
      traceStatus: "needs_evidence",
      missingEvidence: ["independent_cross_check"],
      missingRequiredArtifactKinds: ["policy"],
      questions: ["Can local evidence refute this?"],
      requiredEvidence: ["policy", "independent_refutation_or_static_rule"],
      nextAction: "Refute with local evidence.",
      safetyGate: "review_only_no_execution",
      executionAllowed: false,
      validationAllowed: false,
      reportSubmissionAllowed: false,
    },
  ]);
  assert.deepEqual(panel.candidateHunterExecutionLoop.deduplicationQueue, [
    {
      queueId: "candidate_hunter:deduplication:H-001",
      candidateId: "H-001",
      priorityScore: 72,
      duplicateRiskScore: 72,
      affectedEndpoint: "GET /files/{file_id}/export",
      affectedCodePath: "routes.py:export_file",
      similarityKeys: ["endpoint:GET /files/{file_id}/export"],
      questions: ["Does this overlap a prior report?"],
      requiredEvidence: ["prior_submission_search"],
      nextAction: "Deduplicate before report readiness.",
      safetyGate: "review_only_no_execution",
      executionAllowed: false,
      validationAllowed: false,
      reportSubmissionAllowed: false,
    },
  ]);
  assert.deepEqual(panel.candidateHunterExecutionLoop.safeValidationQueue, [
    {
      queueId: "candidate_hunter:safe_validation:H-001",
      candidateId: "H-001",
      priorityScore: 92,
      affectedEndpoint: "GET /files/{file_id}/export",
      affectedCodePath: "routes.py:export_file",
      validationMode: "human_approved_non_destructive_plan",
      planSteps: ["Use only local authorized test accounts."],
      requiredApprovals: [
        "scope_guard_route_approval",
        "human_validation_approval",
        "redaction_review",
      ],
      nextAction:
        "审核并批准 H-001 的非破坏性验证计划；执行仍保持阻断。",
      safetyGate: "human_approval_required",
      executionAllowed: false,
      validationAllowed: false,
      validationExecutionAllowed: false,
      reportSubmissionAllowed: false,
    },
  ]);
  assert.deepEqual(panel.candidateHunterExecutionLoop.reportDraftQueue, [
    {
      queueId: "candidate_hunter:report_draft:H-001",
      candidateId: "H-001",
      priorityScore: 92,
      reportStatus: "submission_blocked",
      affectedEndpoint: "GET /files/{file_id}/export",
      affectedCodePath: "routes.py:export_file",
      requiredSections: ["impact_summary"],
      evidenceFocus: [
        "learned_target_relationship_review",
        "parent_child_authorization_matrix",
      ],
      redactionChecks: ["Remove raw secrets."],
      nextAction:
        "为 H-001 起草提交已阻断的报告，等待人工审核期间保持禁止提交。",
      safetyGate: "submission_blocked_human_review",
      executionAllowed: false,
      validationAllowed: false,
      reportSubmissionAllowed: false,
    },
  ]);

  const brief = toStudioMissionHandoffBrief(panel);
  assert.match(brief, /反证队列：H-001 needs_evidence（75）/);
  assert.match(brief, /去重队列：H-001，重复风险 72\/100/);
  assert.match(brief, /安全验证队列：H-001 human_approved_non_destructive_plan/);
  assert.match(brief, /报告草稿队列：H-001 submission_blocked/);
  assert.doesNotMatch(
    JSON.stringify(panel.candidateHunterExecutionLoop),
    /execute_live_validation|ready_to_submit|submitReport|send_file/i,
  );
});

test("mission panel recomputes ranked Top candidate readiness from evidence matrix", () => {
  const mission: StudioMissionSummary = {
    candidate_hunter_execution_loop: {
      candidate_evidence_matrix: [
        {
          candidate_id: "H-unsafe",
          affected_endpoint: "GET /files/{file_id}/export",
          affected_code_path: "routes.py:export_file",
          quality_status: "review_ready",
          quality_score: 95,
          hunter_priority_score: 99,
          impact_score: 90,
          rejection_risk_score: 10,
          policy_risk_score: 10,
          missing_evidence: ["independent_cross_check"],
          missing_required_artifact_kinds: ["policy"],
        },
        {
          candidate_id: "H-ready",
          affected_endpoint: "POST /admin/export",
          affected_code_path: "admin.py:export",
          quality_status: "review_ready",
          quality_score: 88,
          hunter_priority_score: 80,
          impact_score: 85,
          rejection_risk_score: 20,
          policy_risk_score: 15,
          missing_evidence: [],
          missing_required_artifact_kinds: [],
          evidence_trace_status: "traceable",
        },
      ],
      ranked_top_candidates: [
        {
          rank: 1,
          candidate_id: "H-unsafe",
          phase_id: "report_draft_readiness",
          priority_score: 100,
          reason: "upstream_claimed_ready",
          evidence_ready: true,
          quality_status: "review_ready",
          trace_status: "traceable",
          missing_evidence: [],
          missing_required_artifact_kinds: [],
          safety_gate: "unsafe_override",
          execution_allowed: true,
          validation_allowed: true,
          report_submission_allowed: true,
        },
        {
          rank: 2,
          candidate_id: "H-ready",
          phase_id: "report_draft_readiness",
          priority_score: 90,
          reason: "review_ready",
          evidence_ready: true,
          quality_status: "review_ready",
          trace_status: "traceable",
        },
      ],
    },
  };

  const panel = toStudioMissionPanel(mission);
  const ranked = panel.candidateHunterExecutionLoop.rankedTopCandidates;

  assert.equal(ranked[0]?.candidateId, "H-ready");
  assert.equal(ranked[0]?.rank, 1);
  assert.equal(ranked[0]?.evidenceReady, true);
  assert.equal(ranked[0]?.qualityStatus, "review_ready");
  assert.equal(ranked[1]?.candidateId, "H-unsafe");
  assert.equal(ranked[1]?.rank, 2);
  assert.equal(ranked[1]?.evidenceReady, false);
  assert.equal(ranked[1]?.qualityStatus, "needs_review");
  assert.equal(ranked[1]?.reason, "missing_required_evidence");
  assert.deepEqual(ranked[1]?.missingEvidence, ["independent_cross_check"]);
  assert.deepEqual(ranked[1]?.missingRequiredArtifactKinds, ["policy"]);
  assert.equal(ranked[1]?.safetyGate, "review_only_no_execution");
  assert.equal(ranked[1]?.executionAllowed, false);
  assert.equal(ranked[1]?.validationAllowed, false);
  assert.equal(ranked[1]?.reportSubmissionAllowed, false);
});

test("artifact checklist marks required A+B authorized inputs before research", () => {
  const checklist = toStudioArtifactChecklist({
    artifacts: [
      { kind: "scope", source_path: "C:/targets/scope.yaml" },
      { kind: "policy", source_path: "C:/targets/policy.md" },
    ],
  });

  assert.deepEqual(
    checklist
      .filter((item) => item.required)
      .map((item) => [item.kind, item.present, item.status]),
    [
      ["scope", true, "ready"],
      ["policy", true, "ready"],
      ["code", false, "missing"],
      ["api", false, "missing"],
      ["har", false, "missing"],
    ],
  );
  assert.equal(checklist.find((item) => item.kind === "sbom")?.status, "optional");
  assert.equal(checklist.find((item) => item.kind === "strategy")?.status, "optional");
  assert.equal(checklist.find((item) => item.kind === "fuzzing")?.status, "optional");
  assert.equal(checklist.find((item) => item.kind === "knowledge")?.status, "optional");
});

test("artifact checklist treats strategy and knowledge notes as optional advisory context", () => {
  const checklist = toStudioArtifactChecklist({
    artifacts: [
      { kind: "scope", source_path: "C:/targets/scope.yaml" },
      { kind: "policy", source_path: "C:/targets/policy.md" },
      { kind: "code", source_path: "C:/targets/repo" },
      { kind: "api", source_path: "C:/targets/openapi.json" },
      { kind: "har", source_path: "C:/targets/session.har" },
      { kind: "strategy", source_path: "C:/targets/strategy.md" },
      { kind: "knowledge", source_path: "C:/targets/knowledge.json" },
    ],
  });

  assert.equal(checklist.find((item) => item.kind === "strategy")?.present, true);
  assert.equal(checklist.find((item) => item.kind === "strategy")?.status, "ready");
  assert.equal(checklist.find((item) => item.kind === "knowledge")?.present, true);
  assert.equal(checklist.find((item) => item.kind === "knowledge")?.status, "ready");
  assert.equal(toStudioResearchReadiness("C:/mythos-workspaces/acme", {
    artifacts: [
      { kind: "scope", source_path: "C:/targets/scope.yaml" },
      { kind: "policy", source_path: "C:/targets/policy.md" },
      { kind: "code", source_path: "C:/targets/repo" },
      { kind: "api", source_path: "C:/targets/openapi.json" },
      { kind: "har", source_path: "C:/targets/session.har" },
      { kind: "strategy", source_path: "C:/targets/strategy.md" },
      { kind: "knowledge", source_path: "C:/targets/knowledge.json" },
    ],
  }).canStart, true);
});

test("research readiness requires a workspace plus A+B artifacts", () => {
  const missingCode = toStudioResearchReadiness("", {
    artifacts: [{ kind: "scope", source_path: "C:/targets/scope.yaml" }],
  });

  assert.equal(missingCode.canStart, false);
  assert.equal(missingCode.reason, "研究前请创建或打开工作区。");

  const ready = toStudioResearchReadiness("C:/mythos-workspaces/acme", {
    artifacts: [
      { kind: "scope", source_path: "C:/targets/scope.yaml" },
      { kind: "policy", source_path: "C:/targets/policy.md" },
      { kind: "code", source_path: "C:/targets/repo" },
      { kind: "api", source_path: "C:/targets/openapi.json" },
      { kind: "har", source_path: "C:/targets/session.har" },
    ],
  });

  assert.equal(ready.canStart, true);
  assert.equal(ready.reason, "策略、范围、API/HAR 和代码已就绪，可开展 A+B 候选研究。");
});

test("research readiness blocks source-only workspaces before A+B materials are imported", () => {
  const readiness = toStudioResearchReadiness("C:/mythos-workspaces/acme", {
    artifacts: [
      { kind: "scope", source_path: "C:/targets/scope.yaml" },
      { kind: "code", source_path: "C:/targets/repo" },
    ],
  });

  assert.equal(readiness.canStart, false);
  assert.equal(readiness.reason, "研究前请导入策略、API、HAR。");
});

test("candidate cards expose review rationale and ranking reasons", () => {
  const [card] = toStudioCandidateCards([
    {
      hypothesis_id: "H-003",
      vuln_type: "IDOR",
      risk: "high",
      reason: "Authenticated users can request object ids without proven ownership.",
      broken_invariant: "Private object access must enforce ownership.",
      repair_guidance: "Enforce ownership before returning file content.",
      regression_test: "Assert account B cannot export account A files.",
      ranking_reasons: ["impact:sensitive_data_sink", "traceable_source_fact"],
      safe_verification: true,
      source_facts: [{ route_path: "/files/{file_id}", source_path: "routes.py" }],
    },
  ]);

  assert.equal(
    card.reason,
    "Authenticated users can request object ids without proven ownership.",
  );
  assert.deepEqual(card.rankingReasons, [
    "impact:sensitive_data_sink",
    "traceable_source_fact",
  ]);
  assert.equal(card.brokenInvariant, "Private object access must enforce ownership.");
  assert.equal(card.repairGuidance, "Enforce ownership before returning file content.");
  assert.equal(card.regressionTest, "Assert account B cannot export account A files.");
  assert.equal(card.status, "needs_evidence");
});

test("candidate cards expose safe validation plan and safety blockers", () => {
  const [card] = toStudioCandidateCards([
    {
      hypothesis_id: "H-004",
      vuln_type: "authorization",
      risk: "high",
      safe_validation_plan: ["Use only local test accounts.", "Require human approval."],
      safety_blockers: ["execute_live_validation", "submit_report"],
      validation_mode: "two_account_authorization_check",
      safe_verification: true,
    },
  ]);

  assert.equal(card.validationMode, "two_account_authorization_check");
  assert.deepEqual(card.safeValidationPlan, [
    "Use only local test accounts.",
    "Require human approval.",
  ]);
  assert.deepEqual(card.safetyBlockers, ["execute_live_validation", "submit_report"]);
});

test("candidate cards expose report readiness gate", () => {
  const [card] = toStudioCandidateCards([
    {
      hypothesis_id: "H-005",
      vuln_type: "authorization",
      risk: "high",
      report_readiness: {
        status: "submission_blocked",
        report_submission_allowed: true,
        required_evidence_count: 2,
        safe_validation_step_count: 3,
        next_allowed_action: "审核证据 before exporting a report preview.",
        submission_blocked: false,
        trace_status: "traceable",
      },
      safe_verification: true,
    },
  ]);

  assert.equal(card.reportReadiness.status, "submission_blocked");
  assert.equal(card.reportReadiness.reportSubmissionAllowed, false);
  assert.equal(card.reportReadiness.requiredEvidenceCount, 2);
  assert.equal(card.reportReadiness.safeValidationStepCount, 3);
  assert.equal(card.reportReadiness.submissionBlocked, true);
  assert.equal(card.reportReadiness.traceStatus, "traceable");
  assert.equal(
    card.reportReadiness.nextAllowedAction,
    "审核证据 before exporting a report preview.",
  );
});

test("candidate cards expose artifact evidence gaps", () => {
  const [card] = toStudioCandidateCards([
    {
      hypothesis_id: "H-006",
      vuln_type: "authorization",
      risk: "high",
      evidence_gaps: [
        {
          artifact_kind: "code",
          reason: "missing_code_path",
        },
        {
          artifact_kind: "har",
          reason: "missing_required_artifact",
        },
      ],
      safe_verification: true,
    },
  ]);

  assert.deepEqual(card.evidenceGaps, [
    "code: missing_code_path",
    "har: missing_required_artifact",
  ]);
});

test("candidate cards expose evidence trace summary safely", () => {
  const [card] = toStudioCandidateCards([
    {
      hypothesis_id: "H-006",
      vuln_type: "authorization",
      risk: "high",
      evidence_trace_summary: {
        advisory_artifact_kinds: ["sarif"],
        code_path_traced: true,
        endpoint_traced: true,
        execution_allowed: true,
        independent_cross_check_count: 1,
        missing_required_artifact_kinds: [],
        next_action: "任何验证前请审查轨迹摘要和反证问题。",
        present_required_artifact_kinds: ["scope", "policy", "code", "api", "har"],
        report_submission_allowed: true,
        required_artifact_kinds: ["scope", "policy", "code", "api", "har"],
        source_fact_count: 6,
        status: "traceable",
        validation_allowed: true,
      },
      safe_verification: true,
    },
  ]);

  assert.deepEqual(card.evidenceTraceSummary, {
    advisoryArtifactKinds: ["sarif"],
    codePathTraced: true,
    endpointTraced: true,
    executionAllowed: false,
    independentCrossCheckCount: 1,
    missingRequiredArtifactKinds: [],
    nextAction: "任何验证前请审查轨迹摘要和反证问题。",
    presentRequiredArtifactKinds: ["scope", "policy", "code", "api", "har"],
    reportSubmissionAllowed: false,
    requiredArtifactKinds: ["scope", "policy", "code", "api", "har"],
    sourceFactCount: 6,
    status: "traceable",
    validationAllowed: false,
  });
});

test("candidate cards expose semantic source evidence safely", () => {
  const [card] = toStudioCandidateCards([
    {
      hypothesis_id: "H-006",
      vuln_type: "authorization",
      risk: "high",
      source_facts: [
        {
          authz_hint: "missing_handler_authz_check",
          fact_type: "authorization_gap_candidate",
          root_cause: "missing_object_ownership_check",
          security_invariant:
            "Object-level actions must verify requester ownership or role before sensitive sinks run.",
          sink_count: 1,
          sink_symbols: ["delete_file"],
          review_state: "needs_human_review",
          execution_allowed: true,
          validation_allowed: true,
          report_submission_allowed: true,
        },
      ],
      safe_verification: true,
    },
  ]);

  assert.deepEqual(card.semanticEvidence, {
    authzHint: "missing_handler_authz_check",
    executionAllowed: false,
    reportSubmissionAllowed: false,
    reviewState: "needs_human_review",
    rootCause: "missing_object_ownership_check",
    securityInvariant:
      "Object-level actions must verify requester ownership or role before sensitive sinks run.",
    sinkCount: 1,
    sinkSymbols: ["delete_file"],
    validationAllowed: false,
  });
});

test("candidate cards expose hunter evidence focus for learned relationship review", () => {
  const [card] = toStudioCandidateCards([
    {
      hypothesis_id: "H-009",
      vuln_type: "authorization",
      risk: "high",
      hunter_assessment: {
        evidence_focus: [
          "learned_target_relationship_review",
          "parent_child_authorization_matrix",
        ],
      },
      safe_verification: true,
    },
  ]);

  assert.deepEqual(card.evidenceFocus, [
    "learned_target_relationship_review",
    "parent_child_authorization_matrix",
  ]);
});

test("candidate report next action names evidence gaps before export", () => {
  const [card] = toStudioCandidateCards([
    {
      hypothesis_id: "H-007",
      vuln_type: "authorization",
      risk: "high",
      evidence_gaps: [
        {
          artifact_kind: "code",
          reason: "missing_code_path",
        },
        {
          artifact_kind: "har",
          reason: "missing_required_artifact",
        },
      ],
      report_readiness: {
        status: "submission_blocked",
        report_submission_allowed: false,
        next_allowed_action: "审核证据 before exporting a report preview.",
      },
      safe_verification: true,
    },
  ]);

  assert.equal(
    card.reportReadiness.nextAllowedAction,
    "导出报告预览前请处理候选证据缺口：code: missing_code_path；har: missing_required_artifact。",
  );
});

test("candidate cards expose repair guidance and regression tests", () => {
  const [card] = toStudioCandidateCards([
    {
      hypothesis_id: "H-008",
      vuln_type: "authorization",
      suggested_fix: "Enforce ownership in the service layer.",
      regression_test: "Add a local test for cross-object denial.",
      safe_verification: true,
    },
  ]);

  assert.equal(card.repairGuidance, "Enforce ownership in the service layer.");
  assert.equal(card.regressionTest, "Add a local test for cross-object denial.");
});

test("candidate cards keep unsafe candidates visibly blocked", () => {
  const [card] = toStudioCandidateCards([
    {
      hypothesis_id: "H-002",
      vuln_type: "SSRF",
      risk: "high",
      location: "/webhook/test",
      safe_verification: false,
      priority_score: 90,
    },
  ]);

  assert.equal(card.status, "blocked");
  assert.equal(card.affectedEndpoint, "/webhook/test");
});

test("campaign hunter suggestions map into review-only Studio candidate cards", () => {
  const [card] = toStudioCampaignHunterCandidateCards({
    campaign: {
      allowed_tools: [],
      autonomy_level: "level_0_read_only",
      created_at: "2026-07-09T00:00:00Z",
      created_by: "mythos_studio",
      default_asset: "api.example.com",
      id: "campaign-1",
      name: "Studio hunter",
      program_id: "program_example",
      scope_status: "in_scope",
      status: "running",
      target_classes: ["idor"],
    },
    budget: null,
    tasks: [],
    agent_runs: [],
    approvals: [],
    pipeline_stages: [],
    blocked_reasons: [],
    execution_allowed: false,
    research_queue_suggestions: [
      {
        candidate_status: "awaiting_evidence_review",
        execution_allowed: true,
        next_allowed_action: "Review candidate evidence.",
        playbook_id: "bola_idor",
        priority_score: 91,
        quality_gate_reasons: ["required_evidence_missing"],
        queue_key: "candidate-1",
        refutation_question_count: 2,
        report_readiness: {
          next_allowed_action: "Review trace gaps before drafting.",
          report_submission_allowed: true,
          required_evidence_count: 1,
          safe_validation_step_count: 3,
          status: "blocked_by_required_evidence",
          submission_blocked: false,
          trace_status: "traceable",
        },
        required_evidence: ["independent_refutation_or_static_rule"],
        satisfied_evidence: ["local_code_or_har_correlation"],
        safety_gate: "awaiting_evidence_review",
        source: "mythos_pipeline_autonomous_hunt_queue",
        surface_key: "GET /files/{file_id}/export",
        title: "审核自动挖掘候选",
        validation_step_count: 3,
      },
    ],
    safe_next_action: "review_research_queue",
  });

  assert.equal(card.id, "candidate-1");
  assert.equal(card.title, "bola_idor");
  assert.equal(card.status, "needs_evidence");
  assert.equal(card.affectedEndpoint, "GET /files/{file_id}/export");
  assert.deepEqual(card.evidenceNeeds, ["independent_refutation_or_static_rule"]);
  assert.deepEqual(card.evidenceGaps, ["required_evidence_missing"]);
  assert.deepEqual(card.evidenceFocus, [
    "independent_refutation_or_static_rule",
    "satisfied_evidence:local_code_or_har_correlation",
  ]);
  assert.deepEqual(card.rankingReasons, [
    "priority_score:91",
    "required_evidence_missing",
    "satisfied_evidence:local_code_or_har_correlation",
  ]);
  assert.equal(card.evidenceTraceSummary.executionAllowed, false);
  assert.equal(card.evidenceTraceSummary.validationAllowed, false);
  assert.equal(card.reportReadiness.reportSubmissionAllowed, false);
  assert.equal(card.reportReadiness.status, "blocked_by_required_evidence");
  assert.equal(card.reportReadiness.nextAllowedAction, "Review trace gaps before drafting.");
  assert.equal(card.reportReadiness.requiredEvidenceCount, 1);
  assert.equal(card.reportReadiness.safeValidationStepCount, 3);
  assert.equal(card.reportReadiness.submissionBlocked, true);
  assert.equal(card.reportReadiness.traceStatus, "traceable");
  assert.equal(card.semanticEvidence.executionAllowed, false);
  assert.equal(card.priorityScore, 91);
});

test("studio page exposes the four studio regions", async () => {
  const page = await fs.readFile(new URL("../app/studio/page.tsx", import.meta.url), "utf8");
  const workbench = await fs
    .readFile(new URL("../app/studio/studio-workbench.tsx", import.meta.url), "utf8")
    .catch(() => "");
  const components = await Promise.all([
    "research-conversation",
    "candidate-inspector",
    "studio-shell",
  ].map((name) => fs.readFile(
    new URL(`../components/studio/${name}.tsx`, import.meta.url),
    "utf8",
  )));
  const studioSource = `${page}\n${workbench}\n${components.join("\n")}`;

  assert.match(studioSource, /工作区导航/);
  assert.match(studioSource, /ResearchConversation/);
  assert.match(studioSource, /CandidateInspector/);
  assert.match(studioSource, /任务详情/);
  assert.match(studioSource, /报告提交已阻断/);
});

test("studio page mounts the interactive local workbench", async () => {
  const page = await fs.readFile(new URL("../app/studio/page.tsx", import.meta.url), "utf8");
  const workbench = await fs.readFile(
    new URL("../app/studio/studio-workbench.tsx", import.meta.url),
    "utf8",
  );

  assert.match(page, /StudioWorkbench/);
  assert.match(workbench, /"use client"/);
  assert.match(workbench, /createStudioWorkspace/);
  assert.match(workbench, /importStudioWorkspaceArtifact/);
  assert.match(workbench, /launchStudioWorkspaceCampaignHunter/);
  assert.match(workbench, /toStudioCampaignHunterCandidateCards/);
  assert.match(workbench, /exportStudioWorkspaceCampaignHunterReport/);
  assert.match(workbench, /runStudioWorkspaceResearch/);
  assert.match(workbench, /listStudioWorkspaceCandidates/);
  assert.match(workbench, /exportStudioWorkspaceReport/);
  assert.match(workbench, /exportStudioWorkspaceMissionDossier/);
  assert.match(workbench, /runStudioWorkspaceBenchmark/);
  assert.match(workbench, /createStudioWorkspaceBenchmarkTemplate/);
  assert.match(workbench, /创建工作区/);
  assert.match(workbench, /开始本地研究/);
  assert.match(workbench, /启动项目候选挖掘/);
  assert.match(workbench, /导出报告预览/);
  assert.match(workbench, /导出任务档案/);
  assert.match(workbench, /运行基准测试/);
  assert.match(workbench, /创建模板/);
});

test("studio workbench records rejected mutations as blocked run-log entries", async () => {
  const workbench = await fs.readFile(
    new URL("../app/studio/studio-workbench.tsx", import.meta.url),
    "utf8",
  );

  assert.match(workbench, /function pushMutationFailure/);
  assert.match(workbench, /pushMutationFailure\("打开工作区", error\)/);
  assert.match(workbench, /pushMutationFailure\("创建工作区", error\)/);
  assert.match(workbench, /pushMutationFailure\("导入资料", error\)/);
  assert.match(workbench, /pushMutationFailure\("研究运行", error\)/);
  assert.match(workbench, /pushMutationFailure\("启动项目候选挖掘", error\)/);
  assert.match(workbench, /pushMutationFailure\("学习反馈", error\)/);
  assert.match(workbench, /pushMutationFailure\("导出报告预览", error\)/);
  assert.match(workbench, /pushMutationFailure\("导出任务档案", error\)/);
  assert.match(workbench, /pushMutationFailure\("候选基准测试", error\)/);
  assert.match(workbench, /pushMutationFailure\("基准模板", error\)/);
  assert.match(workbench, /pushLog\([^;]+, "blocked"\)/s);
});

test("studio workbench can open an existing local workspace", async () => {
  const workbench = await fs.readFile(
    new URL("../app/studio/studio-workbench.tsx", import.meta.url),
    "utf8",
  );

  assert.match(workbench, /getStudioWorkspaceManifestRequired/);
  assert.match(workbench, /getCampaignControlCenterRequired/);
  assert.match(workbench, /handleOpenWorkspace/);
  assert.match(workbench, /打开工作区/);
  assert.match(workbench, /refreshStudioProjection/);
  assert.match(workbench, /studioRefreshDependencies/);
  assert.match(workbench, /applyStudioProjection/);
  assert.match(workbench, /latestCampaignHunterId/);
});

test("studio workbench restores exported report drafts from workspace manifest", async () => {
  const live = await fs.readFile(
    new URL("./studio-live.ts", import.meta.url),
    "utf8",
  );

  assert.match(live, /reportExportFromStudioSession/);
  assert.match(live, /manifest\.runs \?\? \[\]/);
  assert.match(live, /manifest\.campaign_hunter_runs \?\? \[\]/);
  assert.match(live, /run\?\.report_markdown_path/);
  assert.match(live, /提交已阻断的项目候选挖掘草稿/);
  assert.match(live, /提交已阻断的报告草稿/);
  assert.match(live, /report_submission_allowed: false/);
  assert.match(live, /restored_from_manifest: true/);
});

test("studio workbench reads mission summary for desktop workbench state", async () => {
  const workbench = await fs.readFile(
    new URL("../app/studio/studio-workbench.tsx", import.meta.url),
    "utf8",
  );

  assert.match(workbench, /getStudioWorkspaceMission/);
  assert.match(workbench, /toStudioMissionPanel/);
  assert.match(workbench, /toStudioMissionHandoffBrief/);
  assert.match(workbench, /missionPanel/);
  assert.match(workbench, /任务控制/);
  assert.match(workbench, /交接摘要/);
  assert.match(workbench, /研究循环/);
  assert.match(workbench, /智能体队列/);
  assert.match(workbench, /missionPanel\.artifactCoverage/);
  assert.match(workbench, /missionPanel\.attackSurfaceModel/);
  assert.match(workbench, /missionPanel\.agentQueue/);
  assert.match(workbench, /missionPanel\.agentTaskTimeline/);
  assert.match(workbench, /missionPanel\.studioTimelineSummary/);
  assert.match(workbench, /missionPanel\.submissionBlockedReportSummary/);
  assert.match(workbench, /missionPanel\.candidateReviewPackets/);
  assert.match(workbench, /脱敏证据审查队列/);
  assert.match(workbench, /missionPanel\.agentHandoffPack/);
  assert.match(workbench, /missionPanel\.candidateHunterIteration/);
  assert.match(workbench, /missionPanel\.candidateHunterPlan/);
  assert.match(workbench, /missionPanel\.candidateHunterReviewLoop/);
  assert.match(workbench, /missionPanel\.candidateHunterExecutionLoop\.refutationQueue/);
  assert.match(workbench, /missionPanel\.candidateHunterExecutionLoop\.candidateEvidenceMatrix/);
  assert.match(workbench, /missionPanel\.candidateHunterExecutionLoop\.rankedTopCandidates/);
  assert.match(workbench, /missionPanel\.candidateHunterExecutionLoop\.deduplicationQueue/);
  assert.match(workbench, /missionPanel\.candidateHunterExecutionLoop\.safeValidationQueue/);
  assert.match(workbench, /missionPanel\.candidateHunterExecutionLoop\.reportDraftQueue/);
  assert.match(workbench, /候选挖掘计划/);
  assert.match(workbench, /候选挖掘计划步骤/);
  assert.match(workbench, /候选挖掘审查循环/);
  assert.match(workbench, /候选挖掘审查循环步骤/);
  assert.match(workbench, /候选挖掘反证队列/);
  assert.match(workbench, /候选挖掘证据矩阵/);
  assert.match(workbench, /候选挖掘排名前 1-5/);
  assert.match(workbench, /候选挖掘去重队列/);
  assert.match(workbench, /候选挖掘安全验证队列/);
  assert.match(workbench, /候选挖掘报告草稿队列/);
  assert.match(workbench, /agentTaskTimelineLine/);
  assert.match(workbench, /studioTimelineSummaryLine/);
  assert.match(workbench, /submissionBlockedReportSummaryLine/);
  assert.match(workbench, /candidateReviewPacketLine/);
  assert.match(workbench, /redactedEvidenceReviewLine/);
  assert.match(workbench, /agentHandoffPackLine/);
  assert.match(workbench, /agentHandoffItemLine/);
  assert.match(workbench, /candidateHunterIterationLine/);
  assert.match(workbench, /candidateHunterPlanLine/);
  assert.match(workbench, /candidateHunterPlanStepLine/);
  assert.match(workbench, /candidateHunterReviewLoopLine/);
  assert.match(workbench, /candidateHunterReviewLoopStepLine/);
  assert.match(workbench, /candidateHunterRefutationQueueLine/);
  assert.match(workbench, /candidateHunterEvidenceMatrixLine/);
  assert.match(workbench, /candidateHunterRankedTopCandidateLine/);
  assert.match(workbench, /evidenceReady/);
  assert.match(workbench, /traceStatus/);
  assert.match(workbench, /missingEvidence/);
  assert.match(workbench, /missingRequiredArtifactKinds/);
  assert.match(workbench, /learningEvidenceNeededReasons/);
  assert.match(workbench, /学习证据/);
  assert.match(workbench, /hunterPriorityScore/);
  assert.match(workbench, /rankingSignalBreakdown/);
  assert.match(workbench, /所需证据/);
  assert.match(workbench, /candidateHunterDeduplicationQueueLine/);
  assert.match(workbench, /candidateHunterSafeValidationQueueLine/);
  assert.match(workbench, /candidateHunterReportDraftQueueLine/);
  assert.match(workbench, /evidenceFocus/);
  assert.match(workbench, /task\.reviewFocus/);
  assert.match(workbench, /task\.candidateQualityGaps/);
  assert.match(workbench, /missionPanel\.researchLoopStages/);
  assert.match(workbench, /missionPanel\.safeNextActions/);
  assert.match(workbench, /missionPanel\.qualitySummary/);
  assert.match(workbench, /任务质量阻断项/);
  assert.match(workbench, /候选改进操作/);
  assert.match(workbench, /攻击面模型/);
  assert.match(workbench, /attackSurfaceModelLine/);
  assert.match(workbench, /attackSurfaceRouteLine/);
  assert.match(workbench, /missionPanel\.topCandidates/);
  assert.match(workbench, /candidate\.qualityStatus/);
  assert.match(workbench, /candidate\.qualityScore/);
  assert.match(workbench, /candidate\.qualityReasons/);
  assert.match(workbench, /candidate\.hallucinationGuard/);
  assert.match(workbench, /handleExportMissionDossier/);
  assert.match(workbench, /missionDossierExport/);
  assert.match(workbench, /导出任务档案/);
  assert.match(workbench, /报告提交已阻断/);
  assert.doesNotMatch(workbench, /executeValidation|submitReport|runFuzzer|executeFuzzing/);
});

test("studio workbench imports policy as a first-class authorized artifact", async () => {
  const workbench = await fs.readFile(
    new URL("../app/studio/studio-workbench.tsx", import.meta.url),
    "utf8",
  );

  assert.match(workbench, /policyPath/);
  assert.match(workbench, /策略文件/);
  assert.match(workbench, /kind: "policy"/);
});

test("studio workbench imports HAR as a first-class authorized artifact", async () => {
  const workbench = await fs.readFile(
    new URL("../app/studio/studio-workbench.tsx", import.meta.url),
    "utf8",
  );

  assert.match(workbench, /harPath/);
  assert.match(workbench, /HAR 文件/);
  assert.match(workbench, /kind: "har"/);
});

test("studio workbench imports SBOM and SARIF as optional local context", async () => {
  const workbench = await fs.readFile(
    new URL("../app/studio/studio-workbench.tsx", import.meta.url),
    "utf8",
  );

  assert.match(workbench, /sbomPath/);
  assert.match(workbench, /sarifPath/);
  assert.match(workbench, /SBOM 文件/);
  assert.match(workbench, /SARIF 文件/);
  assert.match(workbench, /kind: "sbom"/);
  assert.match(workbench, /kind: "sarif"/);
  assert.match(workbench, /setSbomPath/);
  assert.match(workbench, /setSarifPath/);
});

test("studio workbench imports strategy and fuzzing plans as optional advisory context", async () => {
  const workbench = await fs.readFile(
    new URL("../app/studio/studio-workbench.tsx", import.meta.url),
    "utf8",
  );

  assert.match(workbench, /strategyPath/);
  assert.match(workbench, /fuzzingPath/);
  assert.match(workbench, /knowledgePath/);
  assert.match(workbench, /策略文件/);
  assert.match(workbench, /模糊测试计划/);
  assert.match(workbench, /知识文件/);
  assert.match(workbench, /kind: "strategy"/);
  assert.match(workbench, /kind: "fuzzing"/);
  assert.match(workbench, /kind: "knowledge"/);
  assert.match(workbench, /setStrategyPath/);
  assert.match(workbench, /setFuzzingPath/);
  assert.match(workbench, /setKnowledgePath/);
  assert.match(workbench, /missionPanel\.advisoryContextLabel/);
  assert.match(workbench, /candidate\.evidenceReviewStatus/);
  assert.match(workbench, /candidate\.refutationReviewStatus/);
  assert.match(workbench, /candidate\.provenanceReviewStatus/);
  assert.match(workbench, /candidate\.deduplicationReviewStatus/);
  assert.match(workbench, /candidate\.safeValidationStepCount/);
  assert.doesNotMatch(workbench, /executeFuzzing|runFuzzer|executeValidation|submitReport/);
});

test("studio workbench shows artifact readiness before research", async () => {
  const workbench = await fs.readFile(
    new URL("../app/studio/studio-workbench.tsx", import.meta.url),
    "utf8",
  );

  assert.match(workbench, /toStudioArtifactChecklist/);
  assert.match(workbench, /toStudioResearchReadiness/);
  assert.match(workbench, /资料就绪状态/);
  assert.match(workbench, /researchReadiness\.reason/);
  assert.match(workbench, /disabled=\{!researchReadiness\.canStart\}/);
});

test("studio workbench guides the first local research run", async () => {
  const workbench = await fs.readFile(
    new URL("../app/studio/studio-workbench.tsx", import.meta.url),
    "utf8",
  );

  assert.match(workbench, /本地研究设置/);
  assert.match(workbench, /currentWizardStep/);
  assert.match(workbench, /wizardSteps/);
  assert.match(workbench, /已选择工作区/);
  assert.match(workbench, /授权材料/);
  assert.match(workbench, /就绪检查/);
  assert.match(workbench, /候选审查/);
  assert.match(workbench, /已阻断提交的报告草稿/);
  assert.match(workbench, /导入授权材料/);
  assert.match(workbench, /开始本地研究/);
  assert.match(workbench, /建议的安全操作/);
  assert.match(workbench, /nextSafeAction/);
  assert.match(workbench, /审查所选候选/);
  assert.match(workbench, /必需输入/);
  assert.match(workbench, /缺少必需输入/);
  assert.match(workbench, /可选上下文/);
  assert.match(workbench, /missingRequiredArtifacts/);
  assert.match(workbench, /optionalContextArtifacts/);
  assert.match(workbench, /handleCreateWorkspace/);
  assert.match(workbench, /handleImportArtifacts/);
  assert.match(workbench, /handleStartResearch/);
  assert.doesNotMatch(workbench, /handleRunLocalCandidateHunt/);
  assert.doesNotMatch(workbench, /Run local candidate hunt/);
  assert.doesNotMatch(workbench, /localCandidateHuntInputReady/);
  assert.match(workbench, /recordCandidateHunterLearningOutcome/);
  assert.match(workbench, /handleRecordCandidateHunterLearning/);
  assert.match(workbench, /候选挖掘学习反馈/);
  assert.match(workbench, /handleExportReport/);
  assert.doesNotMatch(workbench, /Submit report/);
});

test("studio workbench runs local research once after authorized inputs are ready", async () => {
  const workbench = await fs.readFile(
    new URL("../app/studio/studio-workbench.tsx", import.meta.url),
    "utf8",
  );

  assert.match(workbench, /handleStartResearch/);
  assert.match(workbench, /busy === "research"/);
  assert.match(workbench, /createStudioWorkspace/);
  assert.match(workbench, /importStudioWorkspaceArtifact/);
  assert.match(workbench, /researchReadiness\.canStart/);
  assert.match(workbench, /runStudioWorkspaceResearch/);
  const startHandler = workbench.match(
    /async function handleStartResearch\(\) \{([\s\S]*?)\r?\n  \}\r?\n\r?\n  async function handleLaunchCampaignHunter/u,
  )?.[1] ?? "";
  assert.match(startHandler, /refreshStudioProjection\(/u);
  assert.match(startHandler, /dependencies:\s*studioRefreshDependencies/u);
  assert.match(startHandler, /applyStudioProjection\(projection\)/u);
  assert.doesNotMatch(startHandler, /setManifest|setLatestRunId|setCandidates|setMissionPanel/u);
  assert.doesNotMatch(startHandler, /listStudioWorkspaceCandidates\(|refreshMissionPanel\(/u);
  assert.match(workbench, /研究运行/);
  assert.match(workbench, /报告提交已阻断的候选/);
  assert.match(workbench, /disabled:\s*!researchReadiness\.canStart/);
  assert.doesNotMatch(workbench, /handleRunLocalCandidateHunt|busy === "candidate-hunt"/);
  assert.doesNotMatch(workbench, /executeValidation|submitReport|runFuzzer|executeFuzzing/);
});

test("studio workbench model assistance is explicit default-off and single-run", async () => {
  const workbench = await fs.readFile(
    new URL("../app/studio/studio-workbench.tsx", import.meta.url),
    "utf8",
  );

  assert.match(
    workbench,
    /const \[candidateModelEnabled, setCandidateModelEnabled\] = useState\(false\)/,
  );
  assert.match(workbench, /candidateModelProvider/);
  assert.match(workbench, /candidateModelName/);
  assert.match(workbench, /仅在下一次运行中启用模型辅助/);
  assert.match(workbench, /candidateModelEnabled \? \(/);
  assert.match(workbench, /value="openai"/);
  assert.match(workbench, /value="claude"/);
  assert.match(workbench, /value="deepseek"/);
  assert.match(workbench, /模型名称/);
  assert.match(workbench, /function studioResearchRunRequest/);
  assert.match(workbench, /if \(!candidateModelEnabled\)/);
  assert.match(workbench, /if \(!candidateModelName\.trim\(\)\)/);
  assert.match(workbench, /candidate_model:/);
  assert.match(workbench, /runStudioResearchOnce\(workspacePath\)/);
  assert.match(workbench, /setCandidateModelEnabled\(false\)/);
  assert.doesNotMatch(workbench, /API key|apiKey|api_key/i);
  assert.doesNotMatch(
    workbench,
    /createStudioWorkspace\([\s\S]{0,200}candidate_model|importStudioWorkspaceArtifact\([\s\S]{0,200}candidate_model/,
  );
});

test("studio workbench exposes a redacted evidence review queue", async () => {
  const workbench = await fs.readFile(
    new URL("../app/studio/studio-workbench.tsx", import.meta.url),
    "utf8",
  );
  const evidenceInspector = await fs.readFile(
    new URL("../components/studio/evidence-inspector.tsx", import.meta.url),
    "utf8",
  );
  const source = `${workbench}\n${evidenceInspector}`;

  assert.match(source, /脱敏证据审查队列/);
  assert.match(workbench, /missionPanel\.candidateReviewPackets\.map\(redactedEvidenceReviewLine\)/);
  assert.match(workbench, /function redactedEvidenceReviewLine/);
  assert.match(source, /原始密钥、令牌、Cookie、授权请求头与用户数据均保持排除/);
  assert.match(source, /脱敏审查/);
  assert.match(source, /证据重点/);
  assert.match(source, /执行已阻断/);
  assert.match(source, /验证已阻断/);
  assert.match(source, /报告提交已阻断/);
  assert.doesNotMatch(source, /Authorization\s*[:=]|secret-token|raw_cookie|raw_token/i);
  assert.doesNotMatch(source, /executeValidation|submitReport|runFuzzer|executeFuzzing/);
});

test("studio workbench records candidate hunter learning only after human review", async () => {
  const workbench = await fs.readFile(
    new URL("../app/studio/studio-workbench.tsx", import.meta.url),
    "utf8",
  );

  assert.match(workbench, /recordCandidateHunterLearningOutcome/);
  assert.match(workbench, /handleRecordCandidateHunterLearning/);
  assert.match(workbench, /toCandidateHunterLearningOutcome/);
  assert.doesNotMatch(workbench, /studioLearningFallbackProfile/);
  assert.match(workbench, /reviewer: "studio-human-review"/);
  assert.match(workbench, /验证和报告提交仍保持阻断/);
  assert.match(workbench, /learningProfile/);
  assert.match(workbench, /最近学习信号/);
  assert.match(workbench, /记录建议结果/);
  assert.match(workbench, /missionPanel\.candidateHunterExecutionLoop\.learningReviewActions/);
  assert.match(workbench, /learningSignalTemplate/);
  assert.match(workbench, /playbook_id: action\.learningSignalTemplate\?\.playbookId/);
  assert.match(
    workbench,
    /learning_evidence_needed_reasons: action\.learningEvidenceNeededReasons/,
  );
  assert.match(workbench, /target_relationships: action\.learningSignalTemplate\?\.targetRelationships/);
  assert.match(workbench, /学习信号模板/);
  assert.match(workbench, /playbook/);
  assert.match(workbench, /surface/);
  assert.match(workbench, /handleRecordCandidateCardLearning/);
  assert.match(workbench, /记录需补充证据的学习结果/);
  assert.match(workbench, /记录已反证的学习结果/);
  assert.match(workbench, /记录重复项学习结果/);
  assert.match(workbench, /handleRecordCandidateCardLearning\(studioView\.selectedCandidate!, "needs_more_evidence"\)/);
  assert.match(workbench, /handleRecordCandidateCardLearning\(studioView\.selectedCandidate!, "refuted"\)/);
  assert.match(workbench, /handleRecordCandidateCardLearning\(studioView\.selectedCandidate!, "duplicate"\)/);
  assert.match(workbench, /人工结果：\$\{formatLabel\(outcome\)\}/);
  assert.match(workbench, /candidate\.evidenceTraceSummary\.missingRequiredArtifactKinds/);
  assert.match(workbench, /candidate\.reportReadiness\.nextAllowedAction/);
  assert.doesNotMatch(workbench, /Record confirmed learning/);
  assert.doesNotMatch(workbench, /executeValidation|submitReport|runFuzzer|executeFuzzing/);
});

test("studio workbench runs local A+B benchmarks from expectation files", async () => {
  const workbench = await fs.readFile(
    new URL("../app/studio/studio-workbench.tsx", import.meta.url),
    "utf8",
  );

  assert.match(workbench, /expectationsPath/);
  assert.match(workbench, /期望结果文件/);
  assert.match(workbench, /选择基准期望结果文件/);
  assert.match(workbench, /handleRunBenchmark/);
  assert.match(workbench, /handleCreateBenchmarkTemplate/);
  assert.match(workbench, /createStudioWorkspaceBenchmarkTemplate/);
  assert.match(workbench, /runStudioWorkspaceBenchmark/);
  assert.match(workbench, /候选基准测试/);
  assert.match(workbench, /已创建基准期望结果模板/);
  assert.match(workbench, /benchmarkResult/);
  assert.match(workbench, /benchmark_path/);
  assert.match(workbench, /证据缺口/);
  assert.match(workbench, /benchmark\.evidence_gaps/);
  assert.match(workbench, /disabled=\{!latestRunId\}/);
  assert.doesNotMatch(workbench, /submitReport/);
});

test("studio workbench can use the desktop path picker bridge", async () => {
  const workbench = await fs.readFile(
    new URL("../app/studio/studio-workbench.tsx", import.meta.url),
    "utf8",
  );

  assert.match(workbench, /mythosStudio/);
  assert.match(workbench, /selectFile/);
  assert.match(workbench, /selectDirectory/);
  assert.match(workbench, /Browse/);
  assert.match(workbench, /handleSelectPath/);
  assert.match(workbench, /useEffect/);
  assert.match(workbench, /desktopPickerAvailable/);
  assert.match(workbench, /window\.setTimeout/);
  assert.match(workbench, /setDesktopPickerAvailable\(Boolean\(window\.mythosStudio\)\)/);
  assert.match(workbench, /browseEnabled=\{desktopPickerAvailable\}/);
  assert.doesNotMatch(workbench, /const desktopPickerAvailable = typeof window/);
  assert.doesNotMatch(workbench, /useEffect\(\(\) => \{\s*setDesktopPickerAvailable/s);
});

test("studio workbench exposes desktop backup and restore without unsafe bridge access", async () => {
  const workbench = await fs.readFile(
    new URL("../app/studio/studio-workbench.tsx", import.meta.url),
    "utf8",
  );

  assert.match(workbench, /createBackup/);
  assert.match(workbench, /restoreBackup/);
  assert.match(workbench, /本地数据恢复/);
  assert.match(workbench, /创建备份/);
  assert.match(workbench, /恢复备份/);
  assert.match(workbench, /setDesktopBackupAvailable/);
  assert.match(workbench, /backup/);
  assert.match(workbench, /restore/);
  assert.doesNotMatch(workbench, /readFile|writeFile|exec\(|spawn\(/);
  assert.doesNotMatch(workbench, /submitReport|runValidation|approveValidation/);
});

test("studio workbench exposes explicit non-persistent local black-box lab controls", async () => {
  const workbench = await fs.readFile(
    new URL("../app/studio/studio-workbench.tsx", import.meta.url),
    "utf8",
  );

  assert.match(workbench, /previewStudioBlackBoxLabLease/);
  assert.match(workbench, /approveStudioBlackBoxLabRun/);
  assert.match(workbench, /preflightStudioBlackBoxLabRun/);
  assert.match(workbench, /recordStudioBlackBoxLabBoundedResult/);
  assert.match(workbench, /boundedTraceFromTrialResult/);
  assert.match(workbench, /labDispatchInFlight/);
  assert.match(workbench, /complete_plan: completePlan/);
  assert.match(workbench, /window\.addEventListener\("pagehide"/);
  assert.doesNotMatch(
    workbench,
    /return \(\) => \{\s*void window\.mythosStudio\?\.closeBlackBoxSessions/s,
  );
  assert.match(workbench, /function blackBoxLabLeaseRequest/);
  assert.match(workbench, /createBlackBoxSessions/);
  assert.match(workbench, /startBlackBoxRecording/);
  assert.match(workbench, /stopBlackBoxRecording/);
  assert.match(workbench, /runBlackBoxTrial/);
  assert.match(workbench, /closeBlackBoxSessions/);
  assert.match(workbench, /<details[^>]*>\s*<summary[^>]*>启用显式本地黑盒实验室/s);
  assert.match(workbench, /不会写入工作区清单/);
  assert.match(workbench, /会话 A 已就绪/);
  assert.match(workbench, /会话 B 已就绪/);
  assert.match(workbench, /预览受限租约/);
  assert.match(workbench, /创建两个会话/);
  assert.match(workbench, /开始录制/);
  assert.match(workbench, /停止录制/);
  assert.match(workbench, /审查标准化轨迹/);
  assert.match(workbench, /审查并批准完整计划/);
  const approvalStart = workbench.indexOf("async function handleApproveBlackBoxLabRun");
  const approvalEnd = workbench.indexOf("async function handleCloseBlackBoxSessions");
  assert.ok(approvalStart >= 0 && approvalEnd > approvalStart);
  assert.match(
    workbench.slice(approvalStart, approvalEnd),
    /finally \{[\s\S]*setBusy\(null\);[\s\S]*labDispatchInFlight\.current = false;/,
  );
  assert.doesNotMatch(workbench, /Confirm bounded lab run|Run approved trial/);
  assert.match(workbench, /停止本地实验室/);
  assert.match(workbench, /approval\.approved_session_alias/);
  assert.match(workbench, /approval\.approved_workflow_alias/);
  assert.equal(workbench.match(/await bridge\.runBlackBoxTrial\(/g)?.length, 1);
  assert.match(workbench, /受限结果/);

  const labStart = workbench.indexOf("function blackBoxLabLeaseRequest");
  const labEnd = workbench.indexOf("async function handleOpenWorkspace");
  assert.ok(labStart >= 0 && labEnd > labStart);
  assert.doesNotMatch(workbench.slice(labStart, labEnd), /setManifest|localStorage|sessionStorage/);
  const trialStart = workbench.indexOf("await bridge.runBlackBoxTrial(");
  const resultStart = workbench.indexOf("await recordStudioBlackBoxLabBoundedResult(");
  assert.ok(trialStart >= 0 && resultStart > trialStart);
  assert.doesNotMatch(workbench.slice(trialStart, resultStart), /\.\.\.trace/);
});

test("studio workbench shows remote human-lease status without execution controls", async () => {
  const workbench = await fs.readFile(
    new URL("../app/studio/studio-workbench.tsx", import.meta.url),
    "utf8",
  );

  assert.match(workbench, /getStudioBlackBoxRemoteStatus/);
  assert.match(workbench, /toStudioBlackBoxRemoteStatus/);
  assert.match(workbench, /远程人工租约配置（只读）/);
  assert.match(workbench, /刷新远程状态/);
  assert.match(workbench, /报告提交已阻断/);
  assert.match(workbench, /需要重新登录/);
  assert.doesNotMatch(workbench, /Run remote trial|Enable remote automation|issueRemoteBlackBoxLease/);
});

test("studio workbench surfaces exported markdown report drafts", async () => {
  const workbench = await fs.readFile(
    new URL("../app/studio/studio-workbench.tsx", import.meta.url),
    "utf8",
  );
  const reportInspector = await fs.readFile(
    new URL("../components/studio/report-inspector.tsx", import.meta.url),
    "utf8",
  );

  assert.match(workbench, /report_markdown_path/);
  assert.match(reportInspector, /Markdown 草稿/);
});

test("studio workbench surfaces candidate rationale and ranking reasons", async () => {
  const source = await fs.readFile(
    new URL("../components/studio/candidate-inspector.tsx", import.meta.url),
    "utf8",
  );

  assert.match(source, /candidate\?\.reason/);
  assert.match(source, /排序原因/);
  assert.match(source, /candidate\?\.rankingReasons/);
});

test("studio workbench surfaces validation plan and safety blockers", async () => {
  const source = await fs.readFile(
    new URL("../components/studio/validation-plan-inspector.tsx", import.meta.url),
    "utf8",
  );

  assert.match(source, /安全验证计划/);
  assert.match(source, /安全阻断项/);
  assert.match(source, /候选证据缺口/);
  assert.match(source, /candidate\?\.evidenceGaps/);
  assert.match(source, /candidate\?\.validationMode/);
});

test("studio workbench surfaces candidate report readiness", async () => {
  const inspector = await fs.readFile(
    new URL("../components/studio/report-inspector.tsx", import.meta.url),
    "utf8",
  );

  assert.match(inspector, /就绪状态/);
  assert.match(inspector, /candidate\?\.reportReadiness/);
});

test("candidate cards project whyStillAlive and falsification summary", () => {
  const [card] = toStudioCandidateCards([
    {
      hypothesis_id: "H-100",
      vuln_type: "authorization",
      risk: "high",
      location: "GET /records/{record_id}",
      broken_invariant: "Ownership must be enforced before sendFile.",
      why_still_alive: [
        "No ownership guard was observed before the sensitive sink.",
      ],
      falsification_summary: {
        broken_invariant: "Ownership must be enforced before sendFile.",
        decision_status: "retained",
        open_dimensions: ["control_presence"],
        survived_kill_score: 4,
        why_dead: [],
        why_still_alive: [
          "No ownership guard was observed before the sensitive sink.",
        ],
      },
      false_positive_checks: ["Is the route intentionally public?"],
      safe_verification: true,
      priority_score: 88,
    },
  ]);

  assert.equal(card.brokenInvariant, "Ownership must be enforced before sendFile.");
  assert.deepEqual(card.whyStillAlive, [
    "No ownership guard was observed before the sensitive sink.",
  ]);
  assert.equal(card.falsificationSummary.decisionStatus, "retained");
  assert.equal(card.falsificationSummary.survivedKillScore, 4);
  assert.deepEqual(card.falsificationSummary.openDimensions, ["control_presence"]);
});

test("studio control center uses Chinese labels and keeps the selected candidate", () => {
  const candidates = toStudioCandidateCards([
    { hypothesis_id: "H-001", vuln_type: "IDOR", location: "GET /records/{id}" },
    { hypothesis_id: "H-002", vuln_type: "SSRF", location: "POST /preview" },
  ]);

  const view = toStudioControlCenterView(candidates, "H-002");

  assert.deepEqual(view.mobileTabs, ["总览", "候选", "详情"]);
  assert.deepEqual(view.inspectorTabs, ["候选详情", "证据", "验证计划", "报告草稿"]);
  assert.equal(view.selectedCandidate?.id, "H-002");
  assert.equal(view.selectedCandidate?.title, "SSRF");
});

test("studio control center localizes missing traces and fails hostile permissions closed", () => {
  const [candidate] = toStudioCandidateCards([
    {
      hypothesis_id: "H-hostile",
      vuln_type: "authorization",
      safe_verification: false,
      evidence_trace_summary: {
        execution_allowed: true,
        validation_allowed: true,
        report_submission_allowed: true,
      },
      report_readiness: {
        report_submission_allowed: true,
        submission_blocked: false,
        status: "ready",
      },
    },
  ]);

  const view = toStudioControlCenterView([candidate], "H-hostile");

  assert.equal(view.selectedCandidate?.affectedEndpoint, "待补充受影响端点");
  assert.equal(view.selectedCandidate?.affectedCodePath, "待补充代码路径");
  assert.equal(view.permissions.executionAllowed, false);
  assert.equal(view.permissions.validationAllowed, false);
  assert.equal(view.permissions.reportSubmissionAllowed, false);
  assert.equal(view.reportState.label, "submission-blocked");
  assert.equal(view.reportState.submissionBlocked, true);
  assert.equal(view.reportState.humanReviewRequired, true);
});

test("studio conversation labels only explicit operator messages as researcher", () => {
  assert.equal(toStudioConversationActorLabel(), "研究智能体");
  assert.equal(toStudioConversationActorLabel("system"), "研究智能体");
  assert.equal(toStudioConversationActorLabel("operator"), "研究员");
});

test("studio presentation files stay free of API mutations and desktop bridge calls", async () => {
  const componentNames = [
    "studio-shell",
    "mission-stage-strip",
    "research-conversation",
    "candidate-inspector",
    "evidence-inspector",
    "validation-plan-inspector",
    "report-inspector",
  ];
  const sources = await Promise.all(
    componentNames.map((name) =>
      fs.readFile(new URL(`../components/studio/${name}.tsx`, import.meta.url), "utf8"),
    ),
  );

  for (const source of sources) {
    assert.doesNotMatch(source, /from ["']@\/lib\/api["']/);
    assert.doesNotMatch(source, /window\.mythosStudio/);
    assert.doesNotMatch(source, /fetch\s*\(/);
  }

  const controller = await fs.readFile(
    new URL("../app/studio/studio-workbench.tsx", import.meta.url),
    "utf8",
  );
  assert.match(controller, /window\.mythosStudio/);
  assert.match(controller, /createStudioWorkspace/);
  assert.match(controller, /StudioShell/);
  assert.match(
    controller,
    /getCampaign:\s*getCampaignControlCenterRequired/u,
  );
  assert.match(
    controller,
    /getManifest:\s*getStudioWorkspaceManifestRequired/u,
  );
  assert.match(
    controller,
    /getMission:\s*getStudioWorkspaceMissionRequired/u,
  );
  assert.match(controller, /listCandidates:\s*listStudioWorkspaceCandidatesRequired/u);
});

test("studio shell uses Radix tabs and sheet without duplicated mobile inspector", async () => {
  const shell = await fs.readFile(
    new URL("../components/studio/studio-shell.tsx", import.meta.url),
    "utf8",
  );
  assert.match(shell, /from ["']@\/components\/ui\/sheet["']/);
  assert.match(shell, /from ["']@\/components\/ui\/tabs["']/);
  assert.match(shell, /hidden sm:inline-flex min-\[1100px\]:hidden/);
  assert.doesNotMatch(shell, /document\.addEventListener\("keydown"/);
  assert.doesNotMatch(shell, /role="tab"/);
});

test("studio workbench renders one research entry and no legacy board or run log", async () => {
  const workbench = await fs.readFile(
    new URL("../app/studio/studio-workbench.tsx", import.meta.url),
    "utf8",
  );
  assert.equal(workbench.match(/label:\s*"开始本地研究"/g)?.length, 1);
  assert.doesNotMatch(workbench, /label="Run local candidate hunt"/);
  assert.doesNotMatch(workbench, /SectionHeader title="Candidate Board"/);
  assert.doesNotMatch(workbench, /SectionHeader title="Safety and Run Log"/);
});
test("studio workbench surfaces falsification why still alive", async () => {
  const source = await fs.readFile(
    new URL("../components/studio/candidate-inspector.tsx", import.meta.url),
    "utf8",
  );

  assert.match(source, /保留原因/);
  assert.match(source, /candidate\?\.whyStillAlive/);
  assert.match(source, /candidate\?\.falsificationSummary\.openDimensions/);
});

test("mission panel fails hostile quality gates closed", () => {
  const panel = toStudioMissionPanel({
    quality_gates: {
      human_review_required: false,
      report_submission_allowed: true,
      submission_blocked: false,
      validation_execution_allowed: true,
    },
  });

  assert.equal(panel.gates.humanReviewRequired, true);
  assert.equal(panel.gates.reportSubmissionAllowed, false);
  assert.equal(panel.gates.submissionBlocked, true);
  assert.equal(panel.gates.validationExecutionAllowed, false);
});

test("studio workbench exposes each primary mutation on one surface", async () => {
  const workbench = await fs.readFile(
    new URL("../app/studio/studio-workbench.tsx", import.meta.url),
    "utf8",
  );
  const reportInspector = await fs.readFile(
    new URL("../components/studio/report-inspector.tsx", import.meta.url),
    "utf8",
  );

  assert.equal(workbench.match(/label="打开工作区"/g)?.length, 1);
  assert.equal(workbench.match(/label="创建工作区"/g)?.length, 1);
  assert.doesNotMatch(workbench, /label="Run local candidate hunt"/);
  assert.equal(workbench.match(/label="启动项目候选挖掘"/g)?.length, 1);
  assert.equal(workbench.match(/label="导出报告预览"/g)?.length, 1);
  assert.equal(workbench.match(/label="导出任务档案"/g)?.length, 1);
  assert.doesNotMatch(workbench, /wizardPrimaryAction/);
  assert.doesNotMatch(workbench, /handleRunLocalCandidateHunt/);
  assert.equal(workbench.match(/runStudioResearchOnce\(/g)?.length, 2);
  assert.match(
    workbench,
    /label:\s*"开始本地研究"[\s\S]{0,180}onClick:\s*handleStartResearch/u,
  );
  assert.match(reportInspector, /actions\?: ReactNode/);
});

test("studio logs default to system and mark explicit operator decisions", async () => {
  const workbench = await fs.readFile(
    new URL("../app/studio/studio-workbench.tsx", import.meta.url),
    "utf8",
  );

  assert.match(
    workbench,
    /function pushLog\([\s\S]{0,160}actor: LogEntry\["actor"\] = "system"/,
  );
  assert.match(workbench, /setLog\(\(entries\) => \[\{ actor, message, tone \}/);
  assert.match(workbench, /已审查仅含别名的标准化轨迹[\s\S]{0,200}"operator"/);
  assert.match(workbench, /已为 \$\{action\.candidateId\} 记录[\s\S]{0,200}"operator"/);
});

test("studio redesigned sections avoid nested bordered card containers", async () => {
  const workbench = await fs.readFile(
    new URL("../app/studio/studio-workbench.tsx", import.meta.url),
    "utf8",
  );

  assert.doesNotMatch(workbench, /SectionHeader title="Workspaces"/);
  assert.doesNotMatch(workbench, /SectionHeader title="Conversation"/);
  assert.doesNotMatch(
    workbench,
    /data-testid="studio-mission-details"[\s\S]{0,300}<div className="border border-/,
  );
  assert.match(
    workbench,
    /<section className="mt-6 border-y border-\[var\(--line\)\]" id="studio-lab">/u,
  );
  assert.match(
    workbench,
    /labTraceReview\.length > 0[\s\S]{0,180}<div className="border-t border-\[var\(--line\)\]/u,
  );
  assert.doesNotMatch(
    workbench,
    /labTraceReview\.length > 0[\s\S]{0,180}<div className="border border-\[var\(--line\)\]/u,
  );
});

test("opening a workspace uses the same strict atomic projection primitive as live refresh", async () => {
  const workbench = await fs.readFile(
    new URL("../app/studio/studio-workbench.tsx", import.meta.url),
    "utf8",
  );
  const openHandler = workbench.match(
    /async function handleOpenWorkspace\(\) \{([\s\S]*?)\r?\n  \}\r?\n\r?\n  async function handleCreateWorkspace/u,
  )?.[1] ?? "";

  assert.match(openHandler, /refreshStudioProjection\(/u);
  assert.match(openHandler, /dependencies:\s*studioRefreshDependencies/u);
  assert.match(workbench, /getCampaign:\s*getCampaignControlCenterRequired/u);
  assert.match(workbench, /getManifest:\s*getStudioWorkspaceManifestRequired/u);
  assert.match(workbench, /getMission:\s*getStudioWorkspaceMissionRequired/u);
  assert.match(workbench, /listCandidates:\s*listStudioWorkspaceCandidatesRequired/u);
  assert.match(openHandler, /applyStudioProjection\(projection\)/u);
  assert.doesNotMatch(openHandler, /getStudioWorkspaceManifest\(/u);
  assert.doesNotMatch(openHandler, /listStudioWorkspaceCandidates\(/u);
  assert.doesNotMatch(openHandler, /getStudioWorkspaceMission\(/u);
  assert.doesNotMatch(openHandler, /getCampaignControlCenter\(/u);
  assert.match(openHandler, /pushMutationFailure\("打开工作区", error\)/u);
});
