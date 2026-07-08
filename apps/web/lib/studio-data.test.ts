import assert from "node:assert/strict";
import fs from "node:fs/promises";
import test from "node:test";
import {
  toStudioArtifactChecklist,
  toStudioCandidateCards,
  toStudioMissionPanel,
  toStudioResearchReadiness,
  toStudioWorkspaceSummary,
} from "./studio-data.ts";

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
  assert.equal(summary.scopeGuardLabel, "Missing scope");
  assert.deepEqual(summary.blockedActions, ["execute_live_validation"]);
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
  assert.equal(card.affectedEndpoint, "Endpoint needs review");
  assert.equal(card.affectedCodePath, "Code path needs review");
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
      next_review_agent: "Evidence Planner",
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
        next_human_action: "Human evidence and redaction review required.",
        safety_gate: "human_review_required",
        evidence_need_count: 2,
        false_positive_check_count: 2,
        safe_validation_step_count: 3,
        report_status: "submission_blocked",
        hallucination_guard_status: "cross_checked",
        execution_allowed: true,
        validation_allowed: true,
        report_submission_allowed: true,
      },
    ],
    agent_handoff_pack: {
      pack_id: "studio:agent_handoff:next_review",
      status: "needs_review",
      handoff_item_count: 1,
      next_review_agent: "Evidence Planner",
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
          assigned_agent: "Evidence Planner",
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
    agent_queue: [
      {
        task_id: "scope_guard_intake",
        agent: "Scope Guard",
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
        agent: "Report Draft Builder",
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
        summary: "Scope Guard is ready for imported authorized materials.",
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
        summary: "Submission-blocked report draft remains review-only.",
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
        next_report_action: "Review evidence, refutation checks, and safety blockers before exporting a report preview.",
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

  assert.equal(panel.modeLabel, "Local AI vulnerability research workbench");
  assert.equal(panel.scopeGuardLabel, "Scope imported");
  assert.equal(panel.artifactCoverage, "5/5 required artifacts");
  assert.equal(panel.advisoryContextLabel, "strategy");
  assert.equal(panel.candidateCountLabel, "1 Top candidate");
  assert.deepEqual(panel.safeNextActions, [
    "Review top candidates",
    "Create benchmark template",
    "Export submission-blocked report",
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
      agent: "Scope Guard",
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
      agent: "Report Draft Builder",
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
    nextReviewAgent: "Evidence Planner",
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
      nextHumanAction: "Human evidence and redaction review required.",
      safetyGate: "human_review_required",
      evidenceNeedCount: 2,
      falsePositiveCheckCount: 2,
      safeValidationStepCount: 3,
      reportStatus: "submission_blocked",
      hallucinationGuardStatus: "cross_checked",
      executionAllowed: false,
      validationAllowed: false,
      reportSubmissionAllowed: false,
    },
  ]);
  assert.deepEqual(panel.agentHandoffPack, {
    packId: "studio:agent_handoff:next_review",
    status: "needs_review",
    handoffItemCount: 1,
    nextReviewAgent: "Evidence Planner",
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
        assignedAgent: "Evidence Planner",
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
      label: "Scope Guard",
      status: "complete",
      summary: "Scope Guard is ready for imported authorized materials.",
    },
    {
      key: "target_intake",
      label: "Target intake",
      status: "complete",
      summary: "Required A+B artifacts are present.",
    },
    {
      key: "refutation_review",
      label: "Refutation review",
      status: "needs_review",
      summary: "Candidate refutation questions need human review.",
    },
    {
      key: "submission_blocked_report",
      label: "Submission-blocked report",
      status: "blocked",
      summary: "Submission-blocked report draft remains review-only.",
    },
  ]);
  assert.equal(panel.topCandidates[0]?.reportStatus, "submission_blocked");
  assert.equal(
    panel.topCandidates[0]?.nextReportAction,
    "Review evidence, refutation checks, and safety blockers before exporting a report preview.",
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
  assert.equal(missingCode.reason, "Create or open a workspace before research.");

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
  assert.equal(ready.reason, "Policy, scope, API/HAR, and code are ready for A+B candidate research.");
});

test("research readiness blocks source-only workspaces before A+B materials are imported", () => {
  const readiness = toStudioResearchReadiness("C:/mythos-workspaces/acme", {
    artifacts: [
      { kind: "scope", source_path: "C:/targets/scope.yaml" },
      { kind: "code", source_path: "C:/targets/repo" },
    ],
  });

  assert.equal(readiness.canStart, false);
  assert.equal(readiness.reason, "Import policy and API and HAR before research.");
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
        report_submission_allowed: false,
        next_allowed_action: "Review evidence before exporting a report preview.",
      },
      safe_verification: true,
    },
  ]);

  assert.equal(card.reportReadiness.status, "submission_blocked");
  assert.equal(card.reportReadiness.reportSubmissionAllowed, false);
  assert.equal(
    card.reportReadiness.nextAllowedAction,
    "Review evidence before exporting a report preview.",
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
        next_allowed_action: "Review evidence before exporting a report preview.",
      },
      safe_verification: true,
    },
  ]);

  assert.equal(
    card.reportReadiness.nextAllowedAction,
    "Resolve candidate evidence gaps before exporting a report preview: code: missing_code_path; har: missing_required_artifact.",
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

test("studio page exposes the four studio regions", async () => {
  const page = await fs.readFile(new URL("../app/studio/page.tsx", import.meta.url), "utf8");
  const workbench = await fs
    .readFile(new URL("../app/studio/studio-workbench.tsx", import.meta.url), "utf8")
    .catch(() => "");
  const studioSource = `${page}\n${workbench}`;

  assert.match(studioSource, /Workspaces/);
  assert.match(studioSource, /Conversation/);
  assert.match(studioSource, /Candidate Board/);
  assert.match(studioSource, /Safety and Run Log/);
  assert.match(studioSource, /submission-blocked/);
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
  assert.match(workbench, /runStudioWorkspaceResearch/);
  assert.match(workbench, /listStudioWorkspaceCandidates/);
  assert.match(workbench, /exportStudioWorkspaceReport/);
  assert.match(workbench, /exportStudioWorkspaceMissionDossier/);
  assert.match(workbench, /runStudioWorkspaceBenchmark/);
  assert.match(workbench, /createStudioWorkspaceBenchmarkTemplate/);
  assert.match(workbench, /Create workspace/);
  assert.match(workbench, /Start research/);
  assert.match(workbench, /Export report preview/);
  assert.match(workbench, /Export mission dossier/);
  assert.match(workbench, /Run benchmark/);
  assert.match(workbench, /Create template/);
});

test("studio workbench can open an existing local workspace", async () => {
  const workbench = await fs.readFile(
    new URL("../app/studio/studio-workbench.tsx", import.meta.url),
    "utf8",
  );

  assert.match(workbench, /getStudioWorkspaceManifest/);
  assert.match(workbench, /handleOpenWorkspace/);
  assert.match(workbench, /Open workspace/);
  assert.match(workbench, /latestRunFromManifest/);
  assert.match(workbench, /listStudioWorkspaceCandidates\(workspacePath/);
});

test("studio workbench reads mission summary for desktop workbench state", async () => {
  const workbench = await fs.readFile(
    new URL("../app/studio/studio-workbench.tsx", import.meta.url),
    "utf8",
  );

  assert.match(workbench, /getStudioWorkspaceMission/);
  assert.match(workbench, /toStudioMissionPanel/);
  assert.match(workbench, /missionPanel/);
  assert.match(workbench, /Mission control/);
  assert.match(workbench, /Research loop/);
  assert.match(workbench, /Agent queue/);
  assert.match(workbench, /missionPanel\.artifactCoverage/);
  assert.match(workbench, /missionPanel\.agentQueue/);
  assert.match(workbench, /missionPanel\.agentTaskTimeline/);
  assert.match(workbench, /missionPanel\.studioTimelineSummary/);
  assert.match(workbench, /missionPanel\.candidateReviewPackets/);
  assert.match(workbench, /missionPanel\.agentHandoffPack/);
  assert.match(workbench, /missionPanel\.candidateHunterIteration/);
  assert.match(workbench, /agentTaskTimelineLine/);
  assert.match(workbench, /studioTimelineSummaryLine/);
  assert.match(workbench, /candidateReviewPacketLine/);
  assert.match(workbench, /agentHandoffPackLine/);
  assert.match(workbench, /agentHandoffItemLine/);
  assert.match(workbench, /candidateHunterIterationLine/);
  assert.match(workbench, /task\.reviewFocus/);
  assert.match(workbench, /task\.candidateQualityGaps/);
  assert.match(workbench, /missionPanel\.researchLoopStages/);
  assert.match(workbench, /missionPanel\.safeNextActions/);
  assert.match(workbench, /missionPanel\.qualitySummary/);
  assert.match(workbench, /Mission quality blockers/);
  assert.match(workbench, /Candidate improvement actions/);
  assert.match(workbench, /missionPanel\.topCandidates/);
  assert.match(workbench, /candidate\.qualityStatus/);
  assert.match(workbench, /candidate\.qualityScore/);
  assert.match(workbench, /candidate\.qualityReasons/);
  assert.match(workbench, /candidate\.hallucinationGuard/);
  assert.match(workbench, /handleExportMissionDossier/);
  assert.match(workbench, /missionDossierExport/);
  assert.match(workbench, /Mission dossier exported/);
  assert.match(workbench, /review-only/);
  assert.doesNotMatch(workbench, /executeValidation|submitReport|runFuzzer|executeFuzzing/);
});

test("studio workbench imports policy as a first-class authorized artifact", async () => {
  const workbench = await fs.readFile(
    new URL("../app/studio/studio-workbench.tsx", import.meta.url),
    "utf8",
  );

  assert.match(workbench, /policyPath/);
  assert.match(workbench, /Policy file/);
  assert.match(workbench, /kind: "policy"/);
});

test("studio workbench imports HAR as a first-class authorized artifact", async () => {
  const workbench = await fs.readFile(
    new URL("../app/studio/studio-workbench.tsx", import.meta.url),
    "utf8",
  );

  assert.match(workbench, /harPath/);
  assert.match(workbench, /HAR file/);
  assert.match(workbench, /kind: "har"/);
});

test("studio workbench imports SBOM and SARIF as optional local context", async () => {
  const workbench = await fs.readFile(
    new URL("../app/studio/studio-workbench.tsx", import.meta.url),
    "utf8",
  );

  assert.match(workbench, /sbomPath/);
  assert.match(workbench, /sarifPath/);
  assert.match(workbench, /SBOM file/);
  assert.match(workbench, /SARIF file/);
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
  assert.match(workbench, /Strategy file/);
  assert.match(workbench, /Fuzzing plan/);
  assert.match(workbench, /Knowledge file/);
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
  assert.match(workbench, /Artifact readiness/);
  assert.match(workbench, /researchReadiness\.reason/);
  assert.match(workbench, /disabled=\{!researchReadiness\.canStart\}/);
});

test("studio workbench guides the first local research run", async () => {
  const workbench = await fs.readFile(
    new URL("../app/studio/studio-workbench.tsx", import.meta.url),
    "utf8",
  );

  assert.match(workbench, /Local research setup/);
  assert.match(workbench, /currentWizardStep/);
  assert.match(workbench, /wizardSteps/);
  assert.match(workbench, /Workspace selected/);
  assert.match(workbench, /Authorized materials/);
  assert.match(workbench, /Readiness check/);
  assert.match(workbench, /Candidate review/);
  assert.match(workbench, /submission-blocked report draft/);
  assert.match(workbench, /Import authorized materials/);
  assert.match(workbench, /Start local research/);
  assert.match(workbench, /Next safe action/);
  assert.match(workbench, /wizardPrimaryAction/);
  assert.match(workbench, /Export submission-blocked draft/);
  assert.match(workbench, /Required inputs/);
  assert.match(workbench, /Missing required inputs/);
  assert.match(workbench, /Optional context/);
  assert.match(workbench, /missingRequiredArtifacts/);
  assert.match(workbench, /optionalContextArtifacts/);
  assert.match(workbench, /handleCreateWorkspace/);
  assert.match(workbench, /handleImportArtifacts/);
  assert.match(workbench, /handleStartResearch/);
  assert.match(workbench, /handleExportReport/);
  assert.doesNotMatch(workbench, /Submit report/);
});

test("studio workbench runs local A+B benchmarks from expectation files", async () => {
  const workbench = await fs.readFile(
    new URL("../app/studio/studio-workbench.tsx", import.meta.url),
    "utf8",
  );

  assert.match(workbench, /expectationsPath/);
  assert.match(workbench, /Expectation file/);
  assert.match(workbench, /Select benchmark expectation file/);
  assert.match(workbench, /handleRunBenchmark/);
  assert.match(workbench, /handleCreateBenchmarkTemplate/);
  assert.match(workbench, /createStudioWorkspaceBenchmarkTemplate/);
  assert.match(workbench, /runStudioWorkspaceBenchmark/);
  assert.match(workbench, /Candidate benchmark/);
  assert.match(workbench, /Benchmark expectation template created for human review/);
  assert.match(workbench, /benchmarkResult/);
  assert.match(workbench, /benchmark_path/);
  assert.match(workbench, /Evidence gaps/);
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

test("studio workbench surfaces exported markdown report drafts", async () => {
  const workbench = await fs.readFile(
    new URL("../app/studio/studio-workbench.tsx", import.meta.url),
    "utf8",
  );

  assert.match(workbench, /report_markdown_path/);
  assert.match(workbench, /Markdown draft/);
});

test("studio workbench surfaces candidate rationale and ranking reasons", async () => {
  const workbench = await fs.readFile(
    new URL("../app/studio/studio-workbench.tsx", import.meta.url),
    "utf8",
  );

  assert.match(workbench, /candidate\.reason/);
  assert.match(workbench, /Ranking reasons/);
});

test("studio workbench surfaces validation plan and safety blockers", async () => {
  const workbench = await fs.readFile(
    new URL("../app/studio/studio-workbench.tsx", import.meta.url),
    "utf8",
  );

  assert.match(workbench, /Safe validation plan/);
  assert.match(workbench, /Safety blockers/);
  assert.match(workbench, /Candidate evidence gaps/);
  assert.match(workbench, /candidate\.evidenceGaps/);
  assert.match(workbench, /candidate\.validationMode/);
});

test("studio workbench surfaces candidate report readiness", async () => {
  const workbench = await fs.readFile(
    new URL("../app/studio/studio-workbench.tsx", import.meta.url),
    "utf8",
  );

  assert.match(workbench, /Report readiness/);
  assert.match(workbench, /candidate\.reportReadiness/);
});
