import assert from "node:assert/strict";
import test from "node:test";
import {
  ApiRequestError,
  completeCampaignCycleReview,
  createResearchReviewPlan,
  createResearchRefutationDecision,
  createStudioWorkspace,
  createFindingCandidate,
  getStudioWorkspaceManifest,
  importStudioWorkspaceArtifact,
  exportStudioWorkspaceReport,
  listStudioWorkspaceCandidates,
  materializeResearchQueueTask,
  recordClaimReviewDecision,
  recordManualObservation,
  runStudioWorkspaceBenchmark,
  runStudioWorkspaceResearch,
  reviewValidationFeedbackForFindingPromotion,
  runSourceAuditScan,
  SourceAuditScanError,
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

test("runSourceAuditScan posts only the local source audit request", async () => {
  const originalFetch = globalThis.fetch;
  let requestedUrl = "";
  let requestedBody: unknown = null;

  globalThis.fetch = async (input, init) => {
    requestedUrl = String(input);
    requestedBody = JSON.parse(String(init?.body));
    return new Response(
      JSON.stringify({
        artifact_id: "artifact_source_1",
        hypothesis_count: 1,
        report_title: "Source audit: target",
        run_id: "pipeline_run_source_1",
        safety_notes: [
          "scope_guard_required",
          "local_files_only",
          "no_live_requests",
          "no_auto_submission",
        ],
        scope_status: "in_scope",
        submission_blocked: true,
      }),
      { headers: { "Content-Type": "application/json" }, status: 200 },
    );
  };

  try {
    const result = await runSourceAuditScan(
      {
        policy_text: "local source audit scope policy",
        repo_path: "C:/workspace/target",
        scope_path: "C:/workspace/scope.yaml",
      },
      null,
    );

    assert.match(requestedUrl, /\/mythos\/source-audit\/scans$/);
    assert.deepEqual(requestedBody, {
      policy_text: "local source audit scope policy",
      repo_path: "C:/workspace/target",
      scope_path: "C:/workspace/scope.yaml",
    });
    assert.equal(result?.run_id, "pipeline_run_source_1");
    assert.equal(result?.submission_blocked, true);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("runSourceAuditScan exposes Scope Guard block reasons", async () => {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async () =>
    new Response(JSON.stringify({ detail: "repo_not_allowlisted" }), {
      headers: { "Content-Type": "application/json" },
      status: 403,
    });

  try {
    await assert.rejects(
      () =>
        runSourceAuditScan(
          {
            repo_path: "C:/workspace/target",
            scope_path: "C:/workspace/scope.yaml",
          },
          null,
        ),
      (error) => {
        assert.equal(error instanceof SourceAuditScanError, true);
        assert.equal((error as SourceAuditScanError).status, 403);
        assert.equal((error as SourceAuditScanError).detail, "repo_not_allowlisted");
        return true;
      },
    );
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("studio workspace API helpers pass only local paths and manifest metadata", async () => {
  const originalFetch = globalThis.fetch;
  const calls: Array<{ body: unknown; url: string }> = [];

  globalThis.fetch = async (input, init) => {
    const url = String(input);
    const body = init?.body ? JSON.parse(String(init.body)) : null;
    calls.push({ body, url });

    if (url.endsWith("/mythos/studio/workspaces")) {
      return new Response(
        JSON.stringify({
          path: "C:/workspaces/acme-api",
          manifest: {
            artifacts: [],
            name: "acme-api",
            runs: [],
            safety: {
              blocked_actions: ["execute_live_validation", "submit_report"],
              scope_guard_status: "missing_scope",
            },
          },
        }),
        { headers: { "Content-Type": "application/json" }, status: 200 },
      );
    }

    if (url.includes("/mythos/studio/workspaces/manifest")) {
      return new Response(
        JSON.stringify({
          artifacts: [],
          name: "acme-api",
          runs: [],
          safety: { blocked_actions: [], scope_guard_status: "scope_imported" },
        }),
        { headers: { "Content-Type": "application/json" }, status: 200 },
      );
    }

    if (url.endsWith("/mythos/studio/workspaces/imports")) {
      return new Response(
        JSON.stringify({
          artifacts: [
            {
              kind: "scope",
              redaction_status: "not_required",
              source_path: "C:/authorized/scope.yaml",
            },
          ],
          name: "acme-api",
          runs: [],
          safety: { blocked_actions: [], scope_guard_status: "scope_imported" },
        }),
        { headers: { "Content-Type": "application/json" }, status: 200 },
      );
    }

    return new Response(JSON.stringify({ detail: "unexpected request" }), {
      headers: { "Content-Type": "application/json" },
      status: 500,
    });
  };

  try {
    const workspace = await createStudioWorkspace(
      { name: "acme-api", root_path: "C:/workspaces" },
      null,
    );
    assert.equal(workspace?.path, "C:/workspaces/acme-api");

    const manifest = await getStudioWorkspaceManifest("C:/workspaces/acme-api", null);
    assert.equal(manifest?.safety?.scope_guard_status, "scope_imported");

    const imported = await importStudioWorkspaceArtifact(
      {
        kind: "scope",
        source_path: "C:/authorized/scope.yaml",
        workspace_path: "C:/workspaces/acme-api",
      },
      null,
    );
    assert.equal(imported?.artifacts?.[0]?.kind, "scope");

    assert.deepEqual(calls.map((call) => new URL(call.url).pathname), [
      "/mythos/studio/workspaces",
      "/mythos/studio/workspaces/manifest",
      "/mythos/studio/workspaces/imports",
    ]);
    assert.deepEqual(calls[0]?.body, { name: "acme-api", root_path: "C:/workspaces" });
    assert.deepEqual(calls[2]?.body, {
      kind: "scope",
      source_path: "C:/authorized/scope.yaml",
      workspace_path: "C:/workspaces/acme-api",
    });
    assert.doesNotMatch(
      JSON.stringify(calls),
      /Authorization\s*[:=]|Bearer|secret-token|cookie|raw_policy/i,
    );
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("studio research API helpers keep reports submission-blocked", async () => {
  const originalFetch = globalThis.fetch;
  const calls: Array<{ body: unknown; url: string }> = [];

  globalThis.fetch = async (input, init) => {
    const url = String(input);
    const body = init?.body ? JSON.parse(String(init.body)) : null;
    calls.push({ body, url });

    if (url.endsWith("/mythos/studio/workspaces/runs")) {
      return new Response(
        JSON.stringify({
          candidate_count: 1,
          manifest: { runs: [{ run_id: "pipeline_run_1", report_path: null }] },
          report_title: "Source audit: target",
          run_id: "pipeline_run_1",
          safety_notes: ["no_live_requests", "no_auto_submission"],
          submission_blocked: true,
        }),
        { headers: { "Content-Type": "application/json" }, status: 200 },
      );
    }

    if (url.includes("/mythos/studio/workspaces/candidates")) {
      return new Response(
        JSON.stringify({
          candidates: [
            {
              evidence_needed: ["sanitized local evidence"],
              false_positive_checks: ["middleware may enforce ownership"],
              hypothesis_id: "H-001",
              location: "GET /files/{file_id}/export",
              risk: "high",
              safe_verification: true,
              submission_blocked: true,
              vuln_type: "authorization",
            },
          ],
          run_id: "pipeline_run_1",
        }),
        { headers: { "Content-Type": "application/json" }, status: 200 },
      );
    }

    if (url.endsWith("/mythos/studio/workspaces/reports/export")) {
      return new Response(
        JSON.stringify({
          manifest: {
            runs: [
              {
                report_path: "C:/workspaces/acme-api/reports/pipeline_run_1-report-preview.json",
                run_id: "pipeline_run_1",
              },
            ],
          },
          report: { submission_blocked: true, title: "Source audit: target" },
          report_markdown_path:
            "C:/workspaces/acme-api/reports/pipeline_run_1-report-draft.md",
          report_submission_allowed: false,
          run_id: "pipeline_run_1",
          submission_blocked: true,
          title: "Source audit: target",
        }),
        { headers: { "Content-Type": "application/json" }, status: 200 },
      );
    }

    if (url.endsWith("/mythos/studio/workspaces/benchmarks/run")) {
      return new Response(
        JSON.stringify({
          benchmark: {
            candidate_count: 1,
            expected_count: 1,
            failures: [],
            matched: 1,
            safety: { forbidden_text_present: [] },
            status: "passed",
          },
          benchmark_path:
            "C:/workspaces/acme-api/benchmarks/pipeline_run_1-benchmark-result.json",
          manifest: {
            benchmarks: [
              {
                benchmark_path:
                  "C:/workspaces/acme-api/benchmarks/pipeline_run_1-benchmark-result.json",
                run_id: "pipeline_run_1",
                status: "passed",
              },
            ],
            runs: [{ benchmark_status: "passed", run_id: "pipeline_run_1" }],
          },
          run_id: "pipeline_run_1",
        }),
        { headers: { "Content-Type": "application/json" }, status: 200 },
      );
    }

    return new Response(JSON.stringify({ detail: "unexpected request" }), {
      headers: { "Content-Type": "application/json" },
      status: 500,
    });
  };

  try {
    const run = await runStudioWorkspaceResearch(
      { workspace_path: "C:/workspaces/acme-api" },
      null,
    );
    assert.equal(run?.submission_blocked, true);

    const candidates = await listStudioWorkspaceCandidates(
      "C:/workspaces/acme-api",
      "pipeline_run_1",
      { candidates: [], run_id: null },
    );
    assert.equal(candidates.candidates[0]?.submission_blocked, true);

    const exported = await exportStudioWorkspaceReport(
      { run_id: "pipeline_run_1", workspace_path: "C:/workspaces/acme-api" },
      null,
    );
    assert.equal(exported?.report_submission_allowed, false);
    assert.equal(
      exported?.report_markdown_path,
      "C:/workspaces/acme-api/reports/pipeline_run_1-report-draft.md",
    );
    assert.equal(exported?.submission_blocked, true);

    const benchmark = await runStudioWorkspaceBenchmark(
      {
        expectations_path: "C:/authorized/studio-expectations.json",
        run_id: "pipeline_run_1",
        workspace_path: "C:/workspaces/acme-api",
      },
      null,
    );
    assert.equal(benchmark?.benchmark.status, "passed");
    assert.equal(
      benchmark?.benchmark_path,
      "C:/workspaces/acme-api/benchmarks/pipeline_run_1-benchmark-result.json",
    );

    assert.deepEqual(calls.map((call) => new URL(call.url).pathname), [
      "/mythos/studio/workspaces/runs",
      "/mythos/studio/workspaces/candidates",
      "/mythos/studio/workspaces/reports/export",
      "/mythos/studio/workspaces/benchmarks/run",
    ]);
    assert.deepEqual(calls[3]?.body, {
      expectations_path: "C:/authorized/studio-expectations.json",
      run_id: "pipeline_run_1",
      workspace_path: "C:/workspaces/acme-api",
    });
    assert.doesNotMatch(
      JSON.stringify(calls),
      /Authorization\s*[:=]|Bearer|secret-token|cookie|send_file\(file_id\)|submitReport/i,
    );
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("source audit gated workflow smoke posts only manual review-gated calls", async () => {
  const originalFetch = globalThis.fetch;
  const calls: Array<{ body: unknown; url: string }> = [];
  let promotionAttempts = 0;

  globalThis.fetch = async (input, init) => {
    const url = String(input);
    const body = init?.body ? JSON.parse(String(init.body)) : null;
    calls.push({ body, url });

    if (url.endsWith("/mythos/source-audit/scans")) {
      return new Response(
        JSON.stringify({
          artifact_id: "artifact_source_1",
          hypothesis_count: 1,
          report_title: "Source audit: target",
          run_id: "pipeline_run_source_1",
          safety_notes: [
            "scope_guard_required",
            "local_files_only",
            "no_live_requests",
            "no_auto_submission",
          ],
          scope_status: "in_scope",
          submission_blocked: true,
        }),
        { headers: { "Content-Type": "application/json" }, status: 200 },
      );
    }

    if (url.endsWith("/mythos/pipeline/runs/pipeline_run_source_1/finding-candidates")) {
      promotionAttempts += 1;
      if (promotionAttempts === 1) {
        return new Response(
          JSON.stringify({ detail: "No claim is ready for candidate promotion" }),
          { headers: { "Content-Type": "application/json" }, status: 422 },
        );
      }

      return new Response(
        JSON.stringify({
          ...fallbackFinding,
          evidence_refs: ["request_response_diff"],
          id: "finding_candidate_source_1",
          submission_recommendation: "promote_to_finding_candidate",
          validation_status: "validation_plan_ready",
        }),
        { headers: { "Content-Type": "application/json" }, status: 200 },
      );
    }

    if (url.endsWith("/mythos/pipeline/runs/pipeline_run_source_1/manual-observations")) {
      return new Response(
        JSON.stringify({
          claim_id: "claim_observed_1",
          created_at: "2026-07-07T00:00:00Z",
          evidence_refs: ["request_response_diff"],
          execution_allowed: false,
          observation: "Reviewer attached a sanitized local fixture diff.",
          observation_id: "manual_observation_1",
          observation_type: "request_response_diff",
          observer: "lead_reviewer",
          redaction_status: "redacted",
          report_chain_blocked: true,
          safety_notes: [
            "test_accounts_only",
            "no_real_user_data",
            "human_review_required",
          ],
        }),
        { headers: { "Content-Type": "application/json" }, status: 200 },
      );
    }

    if (url.endsWith("/mythos/pipeline/runs/pipeline_run_source_1/claim-review-decisions")) {
      return new Response(
        JSON.stringify({
          claim_id: "claim_observed_1",
          decision: "confirmed_observed_fact",
          evidence_refs: ["request_response_diff"],
          rationale: "Confirmed from sanitized local fixture only.",
          reviewed_at: "2026-07-07T00:00:00Z",
          reviewer: "lead_reviewer",
        }),
        { headers: { "Content-Type": "application/json" }, status: 200 },
      );
    }

    return new Response(JSON.stringify({ detail: "unexpected request" }), {
      headers: { "Content-Type": "application/json" },
      status: 500,
    });
  };

  try {
    const scan = await runSourceAuditScan(
      {
        policy_text: "local source audit scope policy",
        repo_path: "C:/workspace/target",
        scope_path: "C:/workspace/scope.yaml",
      },
      null,
    );
    assert.equal(scan?.run_id, "pipeline_run_source_1");
    assert.equal(scan?.submission_blocked, true);

    const blockedCandidate = await createFindingCandidate("pipeline_run_source_1", null);
    assert.equal(blockedCandidate, null);

    const observation = await recordManualObservation(
      "pipeline_run_source_1",
      {
        claim_id: "claim_observed_1",
        evidence_refs: ["request_response_diff"],
        observation: "Reviewer attached a sanitized local fixture diff.",
        observation_type: "request_response_diff",
        observer: "lead_reviewer",
        safety_notes: [
          "test_accounts_only",
          "no_real_user_data",
          "human_review_required",
        ],
      },
      {
        claim_id: "claim_observed_1",
        created_at: "fallback",
        evidence_refs: [],
        execution_allowed: false,
        observation: "fallback",
        observation_id: "fallback_observation",
        observation_type: "request_response_diff",
        observer: "lead_reviewer",
        redaction_status: "redacted",
        report_chain_blocked: true,
        safety_notes: [],
      },
    );
    assert.equal(observation.observation_type, "request_response_diff");
    assert.equal(observation.execution_allowed, false);
    assert.equal(observation.report_chain_blocked, true);

    const review = await recordClaimReviewDecision(
      "pipeline_run_source_1",
      {
        claim_id: "claim_observed_1",
        decision: "confirmed_observed_fact",
        evidence_refs: ["request_response_diff"],
        rationale: "Confirmed from sanitized local fixture only.",
        reviewer: "lead_reviewer",
      },
      {
        claim_id: "claim_observed_1",
        decision: "needs_evidence",
        evidence_refs: [],
        rationale: "fallback",
        reviewed_at: "fallback",
        reviewer: "lead_reviewer",
      },
    );
    assert.equal(review.decision, "confirmed_observed_fact");
    assert.deepEqual(review.evidence_refs, ["request_response_diff"]);

    const candidate = await createFindingCandidate("pipeline_run_source_1", null);
    assert.equal(candidate?.id, "finding_candidate_source_1");
    assert.equal(candidate?.validation_status, "validation_plan_ready");
    assert.equal(candidate?.submission_recommendation, "promote_to_finding_candidate");
    assert.deepEqual(candidate?.evidence_refs, ["request_response_diff"]);

    assert.deepEqual(
      calls.map((call) => new URL(call.url).pathname),
      [
        "/mythos/source-audit/scans",
        "/mythos/pipeline/runs/pipeline_run_source_1/finding-candidates",
        "/mythos/pipeline/runs/pipeline_run_source_1/manual-observations",
        "/mythos/pipeline/runs/pipeline_run_source_1/claim-review-decisions",
        "/mythos/pipeline/runs/pipeline_run_source_1/finding-candidates",
      ],
    );
    assert.doesNotMatch(
      JSON.stringify(calls),
      /executeValidation|approveValidation|submitReport|Authorization\s*[:=]|secret-token/i,
    );
  } finally {
    globalThis.fetch = originalFetch;
  }
});

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
