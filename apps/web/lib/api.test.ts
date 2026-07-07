import assert from "node:assert/strict";
import test from "node:test";
import {
  ApiRequestError,
  completeCampaignCycleReview,
  createResearchReviewPlan,
  createResearchRefutationDecision,
  createFindingCandidate,
  materializeResearchQueueTask,
  reviewValidationFeedbackForFindingPromotion,
  type Finding,
} from "./api.ts";
import type {
  CampaignPipelineStage,
  CampaignResearchRefutationDecision,
  CampaignResearchReviewPlan,
  CampaignTask,
} from "./campaigns-data.ts";

const fallbackFinding: Finding = {
  asset: "api.example.com",
  broken_invariant: "Object ownership must be enforced.",
  confidence: 80,
  duplicate_likelihood: "low",
  evidence_refs: ["evidence_1"],
  id: "finding_fallback",
  operating_reasons: ["human_reviewed"],
  policy_status: "allowed",
  program: "program_1",
  refutation_status: "passed",
  scope_status: "in_scope",
  severity_estimate: "high",
  submission_recommendation: "manual_review",
  title: "Fallback finding",
  validation_status: "report_ready",
  vuln_type: "idor",
};

test("createFindingCandidate exposes research feedback gate failures", async () => {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async () =>
    new Response(
      JSON.stringify({
        detail: {
          blocked_stage_count: 1,
          finding_promotion_allowed: false,
          provenance_ref_count: 6,
          reason: "blocked_by_research_feedback_gate",
          report_submission_allowed: false,
        },
      }),
      { headers: { "Content-Type": "application/json" }, status: 409 },
    );

  try {
    await assert.rejects(
      () => createFindingCandidate("run_1", null),
      (error) => {
        assert.equal(error instanceof ApiRequestError, true);
        assert.equal((error as ApiRequestError).status, 409);
        assert.deepEqual((error as ApiRequestError).detail, {
          blocked_stage_count: 1,
          finding_promotion_allowed: false,
          provenance_ref_count: 6,
          reason: "blocked_by_research_feedback_gate",
          report_submission_allowed: false,
        });
        return true;
      },
    );
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("createFindingCandidate keeps network failures on the safe fallback path", async () => {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async () => {
    throw new Error("offline");
  };

  try {
    assert.equal(await createFindingCandidate("run_1", fallbackFinding), fallbackFinding);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("reviewValidationFeedbackForFindingPromotion posts only the manual promotion review gate", async () => {
  const originalFetch = globalThis.fetch;
  const fallbackStage: CampaignPipelineStage = {
    campaign_id: "campaign_1",
    created_at: "2026-07-05T00:00:00Z",
    id: "fallback_stage",
    input_refs: [],
    output_refs: [],
    payload: {},
    pipeline_run_id: null,
    safety_gate_state: "manual_review_required",
    stage_key: "research_task_validation_feedback_review",
    stage_order: 1,
    status: "fallback",
    stop_reason: null,
    task_id: null,
  };
  let requestedUrl = "";
  let requestedBody: unknown = null;

  globalThis.fetch = async (input, init) => {
    requestedUrl = String(input);
    requestedBody = JSON.parse(String(init?.body));
    return new Response(
      JSON.stringify({
        ...fallbackStage,
        id: "stage_review_1",
        payload: {
          decision: "allow_finding_promotion",
          execution_allowed: false,
          finding_confirmation_allowed: true,
          report_submission_allowed: false,
          validation_allowed: false,
        },
        status: "completed",
      }),
      { headers: { "Content-Type": "application/json" }, status: 200 },
    );
  };

  try {
    const stage = await reviewValidationFeedbackForFindingPromotion(
      "campaign_1",
      "stage_feedback_1",
      {
        decision: "allow_finding_promotion",
        rationale: "Safe evidence reviewed. Authorization: Bearer secret-token",
        reviewer: "lead_reviewer",
      },
      fallbackStage,
    );

    assert.match(
      requestedUrl,
      /\/mythos\/campaigns\/campaign_1\/pipeline-stages\/stage_feedback_1\/validation-feedback-review$/,
    );
    assert.deepEqual(requestedBody, {
      decision: "allow_finding_promotion",
      rationale: "Safe evidence reviewed. Authorization: Bearer secret-token",
      reviewer: "lead_reviewer",
    });
    assert.deepEqual(stage.payload, {
      decision: "allow_finding_promotion",
      execution_allowed: false,
      finding_confirmation_allowed: true,
      report_submission_allowed: false,
      validation_allowed: false,
    });
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("completeCampaignCycleReview posts only the manual cycle review gate", async () => {
  const originalFetch = globalThis.fetch;
  const fallbackStage: CampaignPipelineStage = {
    campaign_id: "campaign_1",
    created_at: "2026-07-05T00:00:00Z",
    id: "fallback_cycle_stage",
    input_refs: [],
    output_refs: [],
    payload: {},
    pipeline_run_id: null,
    safety_gate_state: "manual_review_required",
    stage_key: "campaign_cycle_review",
    stage_order: 1,
    status: "fallback",
    stop_reason: "campaign_cycle_review_required",
    task_id: null,
  };
  let requestedUrl = "";
  let requestedBody: unknown = null;

  globalThis.fetch = async (input, init) => {
    requestedUrl = String(input);
    requestedBody = JSON.parse(String(init?.body));
    return new Response(
      JSON.stringify({
        ...fallbackStage,
        id: "stage_cycle_completed",
        payload: {
          execution_allowed: false,
          raw_payload_processed: false,
          review_gate: "human_review_completed",
          submission_allowed: false,
        },
        safety_gate_state: "allowed",
        status: "completed",
        stop_reason: null,
      }),
      { headers: { "Content-Type": "application/json" }, status: 200 },
    );
  };

  try {
    const stage = await completeCampaignCycleReview(
      "campaign_1",
      "stage_cycle_1",
      {
        actor: "lead_reviewer",
        reason: "Cycle reviewed. Authorization: Bearer secret-token",
      },
      fallbackStage,
    );

    assert.match(
      requestedUrl,
      /\/mythos\/campaigns\/campaign_1\/cycle-reviews\/stage_cycle_1\/complete$/,
    );
    assert.deepEqual(requestedBody, {
      actor: "lead_reviewer",
      reason: "Cycle reviewed. Authorization: Bearer secret-token",
    });
    assert.deepEqual(stage.payload, {
      execution_allowed: false,
      raw_payload_processed: false,
      review_gate: "human_review_completed",
      submission_allowed: false,
    });
    assert.equal(stage.safety_gate_state, "allowed");
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("materializeResearchQueueTask posts only a review queue materialization request", async () => {
  const originalFetch = globalThis.fetch;
  const fallbackTask: CampaignTask = {
    agent_type: "human_research_reviewer",
    campaign_id: "campaign_1",
    created_at: "2026-07-05T00:00:00Z",
    id: "fallback_task",
    input_refs: [],
    output_refs: [],
    status: "fallback",
    task_type: "research_queue_review",
    title: "Fallback review item",
  };
  let requestedUrl = "";
  let requestedBody: unknown = null;

  globalThis.fetch = async (input, init) => {
    requestedUrl = String(input);
    requestedBody = JSON.parse(String(init?.body));
    return new Response(
      JSON.stringify({
        ...fallbackTask,
        id: "task_review_1",
        input_refs: [
          "campaign:campaign_1",
          "research_queue:autonomous_hunt:run_1:hunt_queue_candidate_1",
        ],
        status: "queued_review",
      }),
      { headers: { "Content-Type": "application/json" }, status: 200 },
    );
  };

  try {
    const task = await materializeResearchQueueTask(
      "campaign_1",
      {
        queue_key: "autonomous_hunt:run_1:hunt_queue_candidate_1",
        reason: "Queue review item from control center.",
        requester: "operator",
      },
      fallbackTask,
    );

    assert.match(
      requestedUrl,
      /\/mythos\/campaigns\/campaign_1\/research-queue\/tasks$/,
    );
    assert.deepEqual(requestedBody, {
      queue_key: "autonomous_hunt:run_1:hunt_queue_candidate_1",
      reason: "Queue review item from control center.",
      requester: "operator",
    });
    assert.equal(task.status, "queued_review");
    assert.equal(task.task_type, "research_queue_review");
    assert.doesNotMatch(JSON.stringify(requestedBody), /execute|approve|submit|Authorization:|secret-token/i);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("createResearchReviewPlan posts only advisory refutation and evidence planning", async () => {
  const originalFetch = globalThis.fetch;
  const fallbackPlan: CampaignResearchReviewPlan = {
    campaign_id: "campaign_1",
    dispatch_allowed: false,
    evidence_plan: [],
    execution_allowed: false,
    hypothesis: "Fallback hypothesis",
    next_allowed_action: "Review hypothesis board and request approval before validation.",
    plan_id: "fallback_plan",
    refutation_questions: [],
    report_submission_allowed: false,
    required_human_gates: [],
    safety_gate: "advisory_plan_only",
    status: "fallback",
    task_id: "task_1",
    validation_allowed: false,
  };
  let requestedUrl = "";
  let requestedBody: unknown = null;

  globalThis.fetch = async (input, init) => {
    requestedUrl = String(input);
    requestedBody = JSON.parse(String(init?.body));
    return new Response(
      JSON.stringify({
        ...fallbackPlan,
        evidence_plan: ["Collect redacted artifact summaries only."],
        plan_id: "research_plan_1",
        refutation_questions: ["Can existing evidence refute the candidate?"],
        status: "drafted",
      }),
      { headers: { "Content-Type": "application/json" }, status: 200 },
    );
  };

  try {
    const plan = await createResearchReviewPlan(
      "campaign_1",
      "task_1",
      {
        evidence_plan: ["Collect redacted artifact summaries only."],
        hypothesis: "Review private file access boundary.",
        rationale: "Draft from redacted review context.",
        refutation_questions: ["Can existing evidence refute the candidate?"],
        reviewer: "operator",
      },
      fallbackPlan,
    );

    assert.match(
      requestedUrl,
      /\/mythos\/campaigns\/campaign_1\/research-queue\/tasks\/task_1\/review-plans$/,
    );
    assert.deepEqual(requestedBody, {
      evidence_plan: ["Collect redacted artifact summaries only."],
      hypothesis: "Review private file access boundary.",
      rationale: "Draft from redacted review context.",
      refutation_questions: ["Can existing evidence refute the candidate?"],
      reviewer: "operator",
    });
    assert.equal(plan.status, "drafted");
    assert.equal(plan.execution_allowed, false);
    assert.equal(plan.dispatch_allowed, false);
    assert.equal(plan.validation_allowed, false);
    assert.equal(plan.report_submission_allowed, false);
    assert.doesNotMatch(JSON.stringify(requestedBody), /execute|approve|submit|Authorization:|secret-token/i);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("createResearchRefutationDecision records needs-evidence without validation", async () => {
  const originalFetch = globalThis.fetch;
  const fallbackDecision: CampaignResearchRefutationDecision = {
    campaign_id: "campaign_1",
    decision: "needs_evidence",
    decision_id: "fallback_decision",
    dispatch_allowed: false,
    execution_allowed: false,
    next_allowed_action: "Collect redacted evidence or refine the hypothesis before validation.",
    plan_id: "research_plan_1",
    rationale: "Fallback rationale",
    refutation_answers: [],
    report_submission_allowed: false,
    task_id: "task_1",
    validation_allowed: false,
    validation_run_id: null,
  };
  let requestedUrl = "";
  let requestedBody: unknown = null;

  globalThis.fetch = async (input, init) => {
    requestedUrl = String(input);
    requestedBody = JSON.parse(String(init?.body));
    return new Response(
      JSON.stringify({
        ...fallbackDecision,
        decision_id: "refutation_decision_1",
        refutation_answers: ["Current redacted evidence is insufficient."],
      }),
      { headers: { "Content-Type": "application/json" }, status: 200 },
    );
  };

  try {
    const decision = await createResearchRefutationDecision(
      "campaign_1",
      "task_1",
      {
        candidate_context_summary: {
          evidence_focus_count: 2,
          has_authorization_gap_candidate: true,
          source_fact_type_count: 1,
          triage_signal_count: 1,
        },
        decision: "needs_evidence",
        plan_id: "research_plan_1",
        rationale: "Needs more redacted evidence before validation.",
        refutation_answers: ["Current redacted evidence is insufficient."],
        reviewer: "operator",
      },
      fallbackDecision,
    );

    assert.match(
      requestedUrl,
      /\/mythos\/campaigns\/campaign_1\/research-queue\/tasks\/task_1\/review-decisions$/,
    );
    assert.deepEqual(requestedBody, {
      candidate_context_summary: {
        evidence_focus_count: 2,
        has_authorization_gap_candidate: true,
        source_fact_type_count: 1,
        triage_signal_count: 1,
      },
      decision: "needs_evidence",
      plan_id: "research_plan_1",
      rationale: "Needs more redacted evidence before validation.",
      refutation_answers: ["Current redacted evidence is insufficient."],
      reviewer: "operator",
    });
    assert.equal(decision.decision, "needs_evidence");
    assert.equal(decision.validation_run_id, null);
    assert.equal(decision.execution_allowed, false);
    assert.equal(decision.dispatch_allowed, false);
    assert.equal(decision.validation_allowed, false);
    assert.equal(decision.report_submission_allowed, false);
    assert.doesNotMatch(JSON.stringify(requestedBody), /execute|approve|submit|Authorization\s*[:=]|secret-token/i);
  } finally {
    globalThis.fetch = originalFetch;
  }
});
