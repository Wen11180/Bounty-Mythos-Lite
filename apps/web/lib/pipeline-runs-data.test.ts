import assert from "node:assert/strict";
import test from "node:test";
import {
  deriveIntelligenceRadar,
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
