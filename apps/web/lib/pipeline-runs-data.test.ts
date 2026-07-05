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
    }),
  ]);

  assert.equal(radar.topSignal?.run.runId, "top");
  assert.equal(radar.topSignal?.nextSafeAction, "Collect boundary matrix with test accounts only.");
  assert.equal(radar.humanGatePressure, 2);
  assert.equal(radar.evidenceGapCount, 1);
  assert.equal(radar.reportableMomentum, 1);
  assert.equal(radar.topSignal?.reportDistance, "1 gate to report review");
});
