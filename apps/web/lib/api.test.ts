import assert from "node:assert/strict";
import test from "node:test";
import { ApiRequestError, createFindingCandidate, type Finding } from "./api.ts";

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
