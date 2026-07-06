import assert from "node:assert/strict";
import test from "node:test";
import {
  deriveIntelligenceRadar,
  fallbackPipelineRuns,
  resolvePipelineRunRows,
  toPipelineRunSummary,
  type PipelineRunSummary,
} from "./pipeline-runs-data.ts";
import type { PipelineRun } from "./api.ts";

function run(overrides: Partial<PipelineRunSummary>): PipelineRunSummary {
  return {
    asset: "api.example.com",
    blockedCount: 0,
    evidenceCount: 0,
    hypothesisCount: 1,
    reportTitle: null,
    runId: "run_1",
    stages: [],
    artifact: {
      artifactId: "artifact_1",
      evidenceCount: 0,
      kind: "api_bundle",
      provenance: "test fixture",
      source: "research vault",
    },
    hunter: {
      impactScore: 80,
      nextAction: "Collect redacted test-account evidence.",
      playbook: "BOLA",
      priorityScore: 70,
      recommendation: "pursue",
      rejectionRiskScore: 20,
    },
    memory: null,
    validationGate: {
      approval: "Human approval required.",
      evidenceCount: 0,
      label: "Approval required",
      status: "waiting_human",
    },
    ...overrides,
  };
}

test("toPipelineRunSummary maps run-list evidence support summary for radar use", () => {
  const apiRun = {
    asset: "api.example.com",
    blocked_count: 0,
    created_at: "2026-07-05T00:00:00Z",
    evidence_count: 1,
    evidence_support_summary: {
      missing_required_count: 2,
      partially_supported_count: 1,
      safety_notes: ["metadata_only", "human_review_required"],
      satisfied_human_gated_count: 0,
      status_counts: { partially_supported: 1 },
      top_support_status: "partially_supported",
      total_count: 1,
      unsafe_or_redacted_requirement_count: 0,
    },
    hypothesis_count: 1,
    id: "run_1",
    policy_text_hash: "hash",
    report_title: null,
    scope_status: "in_scope",
  } satisfies PipelineRun;

  const summary = toPipelineRunSummary(apiRun);

  assert.deepEqual(summary.evidenceSupportSummary, apiRun.evidence_support_summary);
});

test("toPipelineRunSummary preserves program learning lesson traces", () => {
  const apiRun = {
    asset: "api.example.com",
    blocked_count: 0,
    created_at: "2026-07-05T00:00:00Z",
    evidence_count: 0,
    hypothesis_count: 1,
    id: "run_1",
    policy_text_hash: "hash",
    report_title: null,
    scope_status: "in_scope",
    timeline: [
      {
        name: "program_learning",
        status: "completed",
        input_summary: "2 program learning signal(s) reviewed.",
        output_summary: "Program memory adjusted hunter intelligence priorities.",
        safety_notes: ["advisory_memory_only"],
        details: {
          lesson_traces: [
            {
              lesson_id: "program:program_example:bola_idor:file_id:export:boost",
              playbook_id: "bola_idor",
              surface_pattern: "file_id:export",
              recommendation: "boost",
              action: "applied",
              source_signal_count: 2,
              source_signal_ids: ["learning_signal_1", "learning_signal_2"],
              reasons: ["lesson:boost:accepted_strong_evidence"],
            },
          ],
        },
      },
    ],
  } satisfies PipelineRun;

  const summary = toPipelineRunSummary(apiRun);

  assert.deepEqual(summary.stages[0].lessonTraces, [
    {
      action: "applied",
      lessonId: "program:program_example:bola_idor:file_id:export:boost",
      playbook: "bola_idor",
      recommendation: "boost",
      reasons: ["lesson:boost:accepted_strong_evidence"],
      sourceSignalCount: 2,
      sourceSignalIds: ["learning_signal_1", "learning_signal_2"],
      surface: "file_id:export",
    },
  ]);
});

test("toPipelineRunSummary maps stage agent task boundaries", () => {
  const apiRun = {
    asset: "api.example.com",
    blocked_count: 0,
    created_at: "2026-07-05T00:00:00Z",
    evidence_count: 0,
    hypothesis_count: 1,
    id: "run_boundary",
    policy_text_hash: "hash",
    report_title: null,
    scope_status: "in_scope",
    timeline: [
      {
        name: "validation_plan",
        status: "needs_review",
        input_summary: "One candidate.",
        output_summary: "Manual plan drafted.",
        safety_notes: ["human_review_required"],
        details: {
          agent_boundary: {
            role: "Validation Planner Agent",
            allowed_actions: ["draft_non_destructive_manual_steps"],
            blocked_actions: ["execute_live_validation", "submit_report"],
            requires_human_review: true,
          },
        },
      },
    ],
  } satisfies PipelineRun;

  const summary = toPipelineRunSummary(apiRun);

  assert.deepEqual(summary.stages[0].agentBoundary, {
    allowedActions: ["draft_non_destructive_manual_steps"],
    blockedActions: ["execute_live_validation", "submit_report"],
    requiresHumanReview: true,
    role: "Validation Planner Agent",
  });
});

test("toPipelineRunSummary maps closed-loop memory readiness", () => {
  const apiRun = {
    asset: "api.example.com",
    blocked_count: 0,
    closed_loop_summary: {
      status: "brain_memory_ready",
      manual_observation_count: 1,
      reviewed_claim_count: 1,
      finding_candidate_count: 1,
      learning_signal_count: 2,
      lesson_count: 1,
      brain_memory_status: "lesson_ready",
      memory_lessons: [
        {
          lesson_id: "program:program_example:bola_idor:file_id:export:boost",
          scope_type: "program",
          scope_key: "program_example",
          playbook_id: "bola_idor",
          surface_pattern: "file_id:export",
          recommendation: "boost",
          confidence: 76,
          source_signal_count: 2,
          source_signal_ids: ["learning_signal_1", "learning_signal_2"],
          reasons: ["lesson:boost:accepted_strong_evidence"],
          safety_notes: ["advisory_memory_only"],
        },
      ],
      blocked_reasons: [],
      safety_notes: ["advisory_memory_only"],
      steps: [],
    },
    created_at: "2026-07-05T00:00:00Z",
    evidence_count: 0,
    hypothesis_count: 1,
    id: "run_memory",
    policy_text_hash: "hash",
    report_title: null,
    scope_status: "in_scope",
  } satisfies PipelineRun;

  const summary = toPipelineRunSummary(apiRun);

  assert.deepEqual(summary.memory, {
    lessonCount: 1,
    status: "brain_memory_ready",
    topLesson: "Boost memory on file_id:export",
  });
});

test("deriveIntelligenceRadar exposes top research value and safe next action", () => {
  const radar = deriveIntelligenceRadar([
    run({
      runId: "low",
      evidenceCount: 0,
      hunter: {
        impactScore: 40,
        nextAction: "Park until stronger provenance appears.",
        playbook: "Generic business logic",
        priorityScore: 35,
        recommendation: "park",
        rejectionRiskScore: 55,
      },
      validationGate: {
        approval: "Needs approval.",
        evidenceCount: 0,
        label: "Awaiting approval",
        status: "waiting_human",
      },
    }),
    run({
      runId: "top",
      asset: "api.example.com",
      evidenceCount: 2,
      reportTitle: "Private file metadata exposed",
      hunter: {
        impactScore: 90,
        nextAction: "Collect boundary matrix with test accounts only.",
        playbook: "BOLA / IDOR",
        priorityScore: 82,
        recommendation: "pursue_with_evidence",
        rejectionRiskScore: 20,
      },
      validationGate: {
        approval: "Human review still required.",
        evidenceCount: 2,
        label: "Human gated",
        status: "waiting_human",
      },
      memory: {
        lessonCount: 2,
        status: "brain_memory_ready",
        topLesson: "Boost memory on file_id:export",
      },
    }),
    run({
      runId: "learning",
      evidenceCount: 1,
      memory: {
        lessonCount: 1,
        status: "learning_recorded",
        topLesson: null,
      },
      validationGate: {
        approval: "Already approved.",
        evidenceCount: 1,
        label: "Approved",
        status: "approved",
      },
    }),
  ]);

  assert.equal(radar.topSignal?.run.runId, "top");
  assert.equal(radar.topSignal?.nextSafeAction, "Collect boundary matrix with test accounts only.");
  assert.equal(radar.humanGatePressure, 2);
  assert.equal(radar.evidenceGapCount, 1);
  assert.equal(radar.memoryReadyRuns, 1);
  assert.equal(radar.reusableLessonCount, 3);
  assert.equal(radar.reportableMomentum, 1);
  assert.equal(radar.topSignal?.reportDistance, "1 gate to report review");
});

test("dashboard radar keeps unsafe requirements visible beside memory lessons", async () => {
  const page = await import("node:fs/promises").then((fs) =>
    fs.readFile(new URL("../app/page.tsx", import.meta.url), "utf8"),
  );

  assert.match(page, /label="Memory lessons"/);
  assert.match(page, /value=\{intelligenceRadar\.reusableLessonCount\}/);
  assert.match(page, /label="Unsafe requirements"/);
  assert.match(page, /value=\{intelligenceRadar\.unsafeOrRedactedRequirementCount\}/);
});

test("dashboard labels fallback pipeline runs as demo data", async () => {
  const liveRun = {
    asset: "api.example.com",
    blocked_count: 0,
    created_at: "2026-07-05T00:00:00Z",
    evidence_count: 1,
    hypothesis_count: 1,
    id: "run_live",
    policy_text_hash: "hash",
    report_title: null,
    scope_status: "in_scope",
  } satisfies PipelineRun;

  const demoRows = resolvePipelineRunRows([]);

  assert.equal(demoRows.dataMode, "Demo data");
  assert.equal(demoRows.runs, fallbackPipelineRuns);
  assert.equal(demoRows.runs.length > 0, true);
  assert.deepEqual(resolvePipelineRunRows([liveRun]), {
    dataMode: "Live data",
    runs: [toPipelineRunSummary(liveRun)],
  });

  const page = await import("node:fs/promises").then((fs) =>
    fs.readFile(new URL("../app/page.tsx", import.meta.url), "utf8"),
  );

  assert.match(page, /pipelineRunDataMode/);
  assert.match(page, /Demo data/);
  assert.match(page, /Mythos Evidence Snapshot/);
  assert.match(page, /sample Mythos research audit summaries/);
  assert.match(page, /audits ready/);
  assert.match(page, /Audit ID/);
  assert.match(page, />\s*Review\s*</);
  assert.doesNotMatch(page, /Pipeline Runs \/ Evidence Snapshot/);
  assert.doesNotMatch(page, /pipeline run records were returned/);
  assert.doesNotMatch(page, /sample Mythos run summaries/);
  assert.doesNotMatch(page, /runs ready/);
  assert.doesNotMatch(page, /Run ID/);
  assert.doesNotMatch(page, />\s*Run\s*</);
});

test("dashboard labels fallback shell data as demo data", async () => {
  const page = await import("node:fs/promises").then((fs) =>
    fs.readFile(new URL("../app/page.tsx", import.meta.url), "utf8"),
  );

  assert.match(page, /dashboardDataMode/);
  assert.match(page, /programs === fallbackPrograms/);
  assert.match(page, /findings === fallbackFindings/);
  assert.match(page, /reports === fallbackReports/);
  assert.match(page, /brainProfile === fallbackBrainProfile/);
  assert.match(page, /scopeGuardDecision === fallbackScopeGuardDecision/);
  assert.match(page, /Demo data/);
  assert.match(page, /sample Mythos workspace summaries/);
  assert.doesNotMatch(page, /fallback records/);
});

test("dashboard labels Scope Guard state as clearance, not allowed execution", async () => {
  const page = await import("node:fs/promises").then((fs) =>
    fs.readFile(new URL("../app/page.tsx", import.meta.url), "utf8"),
  );

  assert.match(page, /Scope Guard decision/);
  assert.match(page, /Scope Guard clear/);
  assert.match(page, /Scope Guard blocked/);
  assert.doesNotMatch(page, /\? "Allowed" : "Blocked"/);
});

test("dashboard navigation uses Mythos review workspace labels", async () => {
  const page = await import("node:fs/promises").then((fs) =>
    fs.readFile(new URL("../app/page.tsx", import.meta.url), "utf8"),
  );

  assert.match(page, /Approval Review/);
  assert.match(page, /Program Scope/);
  assert.match(page, /Target Map/);
  assert.match(page, /Attack Surface Map/);
  assert.match(page, /Invariant Review/);
  assert.match(page, /Hypothesis Board/);
  assert.match(page, /Finding Candidates/);
  assert.match(page, /Report Readiness/);
  assert.match(page, /Manual Submission Gate/);
  assert.match(page, /Mythos Brain/);
  assert.match(page, /Scope Guard/);
  assert.doesNotMatch(page, /label: "Programs"/);
  assert.doesNotMatch(page, /label: "Assets"/);
  assert.doesNotMatch(page, /label: "API Model"/);
  assert.doesNotMatch(page, /label: "Business Flows"/);
  assert.doesNotMatch(page, /label: "Hypotheses"/);
  assert.doesNotMatch(page, /label: "Validation Plans"/);
  assert.doesNotMatch(page, /label: "Findings"/);
  assert.doesNotMatch(page, /label: "Reports"/);
  assert.doesNotMatch(page, /label: "Submissions"/);
  assert.doesNotMatch(page, /label: "Knowledge Base"/);
  assert.doesNotMatch(page, /label: "Settings \/ Policy Guard"/);
});

test("run detail labels fallback research audits as demo data", async () => {
  const page = await import("node:fs/promises").then((fs) =>
    fs.readFile(new URL("../app/runs/[runId]/page.tsx", import.meta.url), "utf8"),
  );

  assert.match(page, /runDataMode/);
  assert.match(page, /fallback-only/);
  assert.match(page, /Demo data/);
  assert.match(page, /Research Audit/);
  assert.match(page, /sample Mythos research summary/);
  assert.match(page, /Mythos Review Timeline/);
  assert.doesNotMatch(page, /Run Detail/);
  assert.doesNotMatch(page, /fallback record/);
  assert.doesNotMatch(page, /Stage Timeline/);
});

test("run detail shows stage agent boundaries", async () => {
  const page = await import("node:fs/promises").then((fs) =>
    fs.readFile(new URL("../app/runs/[runId]/page.tsx", import.meta.url), "utf8"),
  );

  assert.match(page, /agentBoundary/);
  assert.match(page, /Agent Boundary/);
  assert.match(page, /blockedActions/);
});

test("run detail shows read-only exploit-chain reasoning summaries", async () => {
  const page = await import("node:fs/promises").then((fs) =>
    fs.readFile(new URL("../app/runs/[runId]/page.tsx", import.meta.url), "utf8"),
  );

  assert.match(page, /exploit_chain/);
  assert.match(page, /Chain confidence/);
  assert.match(page, /Primitive\(s\)/);
  assert.match(page, /Precondition\(s\)/);
  assert.match(page, /Refutation question\(s\)/);
  assert.doesNotMatch(page, /executeValidation|approveValidation|submitReport/);
});

test("run detail shows advisory reasoning memory context", async () => {
  const page = await import("node:fs/promises").then((fs) =>
    fs.readFile(new URL("../app/runs/[runId]/page.tsx", import.meta.url), "utf8"),
  );

  assert.match(page, /Reasoning memory/);
  assert.match(page, /highest_reasoning_review_score/);
  assert.match(page, /advisory_memory_only/);
  assert.doesNotMatch(page, /execution_allowed|submission_allowed/);
});

test("fallback run detail includes stage agent boundaries", async () => {
  const source = await import("node:fs/promises").then((fs) =>
    fs.readFile(new URL("./workbench-detail-data.ts", import.meta.url), "utf8"),
  );

  assert.match(source, /agent_boundary/);
  assert.match(source, /execute_live_validation/);
  assert.match(source, /bypass_scope_guard/);
});

test("report preview labels fallback claim ledgers as demo data", async () => {
  const page = await import("node:fs/promises").then((fs) =>
    fs.readFile(new URL("../app/reports/[runId]/page.tsx", import.meta.url), "utf8"),
  );

  assert.match(page, /reportDataMode/);
  assert.match(page, /fallback-only/);
  assert.match(page, /Demo data/);
});

test("report preview can promote reviewed claims to finding candidates", async () => {
  const page = await import("node:fs/promises").then((fs) =>
    fs.readFile(new URL("../app/reports/[runId]/page.tsx", import.meta.url), "utf8"),
  );

  assert.match(page, /hasPromotionCandidate/);
  assert.match(page, /reportDataMode === "Live data"/);
  assert.match(page, /promotionBlockingReadinessBlockers/);
  assert.match(page, /claim\.quality_score >= 80/);
  assert.match(page, /createFindingCandidate/);
  assert.match(page, /promoteFindingCandidateAction/);
  assert.match(page, /Promote Finding Candidate/);
  assert.match(page, /human-reviewed observed claim/);
  assert.match(page, /Research feedback gates can still block promotion/);
  assert.match(page, /promotionGateStatus/);
  assert.match(page, /blocked_by_research_feedback_gate/);
  assert.match(page, /Research feedback gate blocked finding promotion/);
  assert.match(page, /blockedStageCount/);
  assert.match(page, /provenanceRefCount/);
  assert.match(page, /Promotion waits for a live, human-reviewed observed claim/);
  assert.match(page, /submission_blocked/);
});

test("report preview keeps submission status behind a manual gate", async () => {
  const page = await import("node:fs/promises").then((fs) =>
    fs.readFile(new URL("../app/reports/[runId]/page.tsx", import.meta.url), "utf8"),
  );

  assert.match(page, /Manual submission gate/);
  assert.match(page, /Research audit/);
  assert.match(page, /Human review ready/);
  assert.match(page, /Submission blocked/);
  assert.match(page, /No claim ledger entries ready for review/);
  assert.match(page, /No review rationale ready/);
  assert.match(page, /No report section claims ready/);
  assert.match(page, /No safety notes ready/);
  assert.match(page, /No evidence references ready/);
  assert.doesNotMatch(page, /No claim ledger entries recorded/);
  assert.doesNotMatch(page, /No review rationale recorded/);
  assert.doesNotMatch(page, /No claims recorded/);
  assert.doesNotMatch(page, /No safety notes recorded/);
  assert.doesNotMatch(page, /No evidence refs recorded/);
  assert.doesNotMatch(page, /label="Submission"/);
  assert.doesNotMatch(page, /label="Run"/);
  assert.doesNotMatch(page, />\s*Run\s*</);
  assert.doesNotMatch(page, /\? "Blocked" : "Ready"/);
});

test("report preview can record advisory learning outcomes", async () => {
  const page = await import("node:fs/promises").then((fs) =>
    fs.readFile(new URL("../app/reports/[runId]/page.tsx", import.meta.url), "utf8"),
  );

  assert.match(page, /recordMythosBrainOutcome/);
  assert.match(page, /recordLearningOutcomeAction/);
  assert.match(page, /name="outcome"/);
  assert.match(page, /name="evidence_quality"/);
  assert.match(page, /name="severity_delta"/);
  assert.match(page, /name="bounty_amount"/);
  assert.match(page, /name="notes"/);
  assert.match(page, /advisory_memory_only/);
});

test("validation workspace labels fallback workspaces as demo data", async () => {
  const page = await import("node:fs/promises").then((fs) =>
    fs.readFile(new URL("../app/validation-workspace/[runId]/page.tsx", import.meta.url), "utf8"),
  );

  assert.match(page, /workspaceDataMode/);
  assert.match(page, /fallback-only/);
  assert.match(page, /Demo data/);
});

test("validation workspace labels execution state as preflight, not permission", async () => {
  const page = await import("node:fs/promises").then((fs) =>
    fs.readFile(new URL("../app/validation-workspace/[runId]/page.tsx", import.meta.url), "utf8"),
  );

  assert.match(page, /Preflight gate/);
  assert.match(page, /Preflight clear/);
  assert.match(page, /Preflight blocked/);
  assert.match(page, /Observation boundary/);
  assert.match(page, /Preflight reviewed/);
  assert.match(page, /Review only/);
  assert.doesNotMatch(page, /Execution permission/);
  assert.doesNotMatch(page, /No execution permission/);
  assert.doesNotMatch(page, /Allowed to execute/);
  assert.doesNotMatch(page, /Execution allowed/);
  assert.doesNotMatch(page, /\? "Allowed" : "Blocked"/);
});

test("validation workspace empty states read as review readiness, not records", async () => {
  const page = await import("node:fs/promises").then((fs) =>
    fs.readFile(new URL("../app/validation-workspace/[runId]/page.tsx", import.meta.url), "utf8"),
  );

  assert.match(page, /Claim Review/);
  assert.match(page, /No validation steps ready/);
  assert.match(page, /No claim review items ready/);
  assert.match(page, /No manual observations ready for review/);
  assert.match(page, /No active blocking reasons/);
  assert.match(page, /No evidence hints ready/);
  assert.doesNotMatch(page, /Claim Tasks/);
  assert.doesNotMatch(page, /No validation steps recorded/);
  assert.doesNotMatch(page, /No claim tasks ready/);
  assert.doesNotMatch(page, /No claim tasks recorded/);
  assert.doesNotMatch(page, /No manual observations recorded/);
  assert.doesNotMatch(page, /No blocking reason recorded/);
  assert.doesNotMatch(page, /No evidence hints recorded/);
});

test("validation workspace can record safe manual observations", async () => {
  const page = await import("node:fs/promises").then((fs) =>
    fs.readFile(new URL("../app/validation-workspace/[runId]/page.tsx", import.meta.url), "utf8"),
  );

  assert.match(page, /recordManualObservation/);
  assert.match(page, /recordManualObservationAction/);
  assert.match(page, /name="claim_id"/);
  assert.match(page, /name="observation"/);
  assert.match(page, /name="evidence_refs"/);
  assert.match(page, /test_accounts_only/);
  assert.match(page, /no_real_user_data/);
});

test("validation workspace explains redacted-only evidence gaps", async () => {
  const page = await import("node:fs/promises").then((fs) =>
    fs.readFile(new URL("../app/validation-workspace/[runId]/page.tsx", import.meta.url), "utf8"),
  );

  assert.match(page, /manual_observation_missing_safe_evidence/);
  assert.match(page, /Report-safe evidence required/);
  assert.match(page, /request_response_diff/);
});

test("artifact repository labels fallback artifacts as demo data", async () => {
  const page = await import("node:fs/promises").then((fs) =>
    fs.readFile(new URL("../app/artifacts/page.tsx", import.meta.url), "utf8"),
  );

  assert.match(page, /artifactDataMode/);
  assert.match(page, /fallback-only/);
  assert.match(page, /Demo data/);
  assert.match(page, /sample Mythos artifact summaries/);
  assert.match(page, /Artifact Review/);
  assert.match(page, /Usage audit/);
  assert.doesNotMatch(page, /Usage run/);
  assert.doesNotMatch(page, /artifact records came from fallback summaries/);
  assert.doesNotMatch(page, />Repository View</);
});

test("artifact detail labels fallback artifacts as demo data", async () => {
  const page = await import("node:fs/promises").then((fs) =>
    fs.readFile(new URL("../app/artifacts/[artifactId]/page.tsx", import.meta.url), "utf8"),
  );

  assert.match(page, /artifactDataMode/);
  assert.match(page, /fallback-only/);
  assert.match(page, /Demo data/);
  assert.match(page, /No payload summary ready/);
  assert.match(page, /No provenance summary ready/);
  assert.match(page, /No derived facts ready/);
  assert.match(page, /No artifact usage ready/);
  assert.doesNotMatch(page, /No payload summary recorded/);
  assert.doesNotMatch(page, /No provenance summary recorded/);
  assert.doesNotMatch(page, /No derived facts recorded/);
  assert.doesNotMatch(page, /No artifact usage recorded/);
});

test("artifact detail describes report-chain eligibility without allowed wording", async () => {
  const page = await import("node:fs/promises").then((fs) =>
    fs.readFile(new URL("../app/artifacts/[artifactId]/page.tsx", import.meta.url), "utf8"),
  );

  assert.match(page, /Report-chain eligibility/);
  assert.match(page, /Eligible for report chain/);
  assert.match(page, /Blocked for report chain/);
  assert.doesNotMatch(page, /\? "Allowed" : "Blocked"/);
});
