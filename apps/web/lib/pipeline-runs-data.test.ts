import assert from "node:assert/strict";
import test from "node:test";
import {
  deriveIntelligenceRadar,
  fallbackPipelineRuns,
  resolvePipelineRunRows,
  toPipelineRunSummary,
  type PipelineRunSummary,
} from "./pipeline-runs-data.ts";
import { mythosPipelineStages } from "./mythos-pipeline-data.ts";
import { formatLabel } from "./workbench-display.ts";
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
    refutationSummary: {
      parked: 0,
      refuted: 0,
      total: 0,
      unverified: 0,
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

test("mythos pipeline strip labels validation planning as a review gate", () => {
  const policy = mythosPipelineStages.find((stage) => stage.label === "Policy");
  const refutation = mythosPipelineStages.find((stage) => stage.label === "Refutation");
  const reportDraft = mythosPipelineStages.find((stage) => stage.label === "Report Draft");
  const validationPlan = mythosPipelineStages.find((stage) => stage.label === "Validation Plan");

  assert.equal(policy?.status, "Policy reviewed");
  assert.equal(policy?.risk, "Human review gate");
  assert.equal(refutation?.status, "Needs evidence");
  assert.equal(reportDraft?.status, "Review draft");
  assert.equal(reportDraft?.risk, "Human review gate");
  assert.equal(validationPlan?.risk, "Review gate required");
  assert.doesNotMatch(JSON.stringify(mythosPipelineStages), /"Candidate"/i);
  assert.doesNotMatch(JSON.stringify(mythosPipelineStages), /"Blocking"/i);
  assert.notEqual(reportDraft?.risk, "Human review");
  assert.doesNotMatch(JSON.stringify(mythosPipelineStages), /Human gate/i);
  assert.doesNotMatch(JSON.stringify(mythosPipelineStages), /Rule Ready/i);
  assert.doesNotMatch(JSON.stringify(mythosPipelineStages), /Approval required/i);
});

test("formatLabel describes validation blockers as review requirements", () => {
  const label = formatLabel("validation_gate_not_approved");

  assert.equal(label, "Validation review required");
  assert.doesNotMatch(label, /not approved/i);
});

test("formatLabel describes human approval blockers as review requirements", () => {
  const label = formatLabel("human_approval_required");

  assert.equal(label, "Human review required");
  assert.doesNotMatch(label, /approval/i);
});

test("formatLabel describes execution permission blockers as review gates", () => {
  const label = formatLabel("no_execution_permission");

  assert.equal(label, "Execution review gated");
  assert.doesNotMatch(label, /permission/i);
});

test("formatLabel describes authorization blockers as review gates", () => {
  const label = formatLabel("cannot_authorize_execution");

  assert.equal(label, "Execution remains review-gated");
  assert.doesNotMatch(label, /authorize/i);
});

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
  const hypothesisStage = summary.stages.find((stage) => stage.label === "Hypothesis engine");
  assert.match(hypothesisStage?.detail ?? "", /hypotheses generated from scoped artifacts/);
  assert.doesNotMatch(hypothesisStage?.detail ?? "", /allowed artifacts/);
  const scopeStage = summary.stages.find((stage) => stage.label === "Scope Guard");
  assert.match(scopeStage?.detail ?? "", /reviewed for low-risk planning/);
  assert.doesNotMatch(scopeStage?.detail ?? "", /cleared for low-risk planning/);
});

test("toPipelineRunSummary counts source audit refutation review states", () => {
  const summary = toPipelineRunSummary({
    asset: "api.example.com",
    blocked_count: 0,
    created_at: "2026-07-05T00:00:00Z",
    evidence_count: 0,
    hypothesis_count: 4,
    id: "run_refutation_counts",
    payload: {
      hypotheses: [
        { hypothesis: "authorization gap", refutation_status: "unverified" },
        { hypothesis: "low-risk static finding", refutation_status: "parked" },
        { hypothesis: "false positive", refutation_status: "refuted" },
        { hypothesis: "legacy hypothesis without status" },
      ],
    },
    policy_text_hash: "hash",
    report_title: null,
    scope_status: "in_scope",
  });

  assert.deepEqual(summary.refutationSummary, {
    parked: 1,
    refuted: 1,
    total: 4,
    unverified: 2,
  });
});

test("toPipelineRunSummary suppresses identity and token-shaped display text", () => {
  const apiRun = {
    asset: "api.example.com/users/alice@example.com",
    blocked_count: 0,
    created_at: "2026-07-05T00:00:00Z",
    evidence_count: 1,
    hypothesis_count: 1,
    id: "run_1",
    policy_text_hash: "hash",
    report_title: "Draft for production user data",
    scope_status: "in_scope",
    timeline: [
      {
        name: "hypothesis_engine",
        status: "completed",
        input_summary: "JWT eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.signature observed.",
        output_summary: "alice@example.com linked to customer data.",
        safety_notes: ["personal data present"],
      },
    ],
    artifact: {
      source: "alice@example.com upload",
      kind: "har",
      provenance: "production user fixture",
      evidence_count: 1,
    },
    hunter_intelligence: {
      top_recommendation: "pursue",
      assessments: [
        {
          hunter_priority_score: 88,
          impact_score: 80,
          rejection_risk_score: 10,
          next_action: "Review JWT eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.signature",
          playbook_label: "BOLA",
          recommendation: "pursue",
        },
      ],
    },
    closed_loop_summary: {
      status: "brain_memory_ready",
      lesson_count: 1,
      memory_lessons: [
        {
          recommendation: "boost",
          surface_pattern: "alice@example.com",
        },
      ],
    },
  } satisfies PipelineRun;

  const summary = toPipelineRunSummary(apiRun);

  assert.doesNotMatch(
    JSON.stringify(summary),
    /alice@example\.com|eyJhbGciOiJIUzI1NiJ9|production user|customer data|personal data/i,
  );
});

test("pipeline validation gates describe review state without approval-as-permission wording", () => {
  const waitingSummary = toPipelineRunSummary({
    asset: "api.example.com",
    blocked_count: 0,
    created_at: "2026-07-05T00:00:00Z",
    evidence_count: 0,
    hypothesis_count: 1,
    id: "run_waiting",
    policy_text_hash: "hash",
    report_title: null,
    scope_status: "in_scope",
  });
  const blockedSummary = toPipelineRunSummary({
    asset: "api.example.com",
    blocked_count: 2,
    created_at: "2026-07-05T00:00:00Z",
    evidence_count: 0,
    hypothesis_count: 1,
    id: "run_blocked",
    policy_text_hash: "hash",
    report_title: null,
    scope_status: "in_scope",
  });
  const liveSummary = toPipelineRunSummary({
    asset: "api.example.com",
    blocked_count: 0,
    created_at: "2026-07-05T00:00:00Z",
    evidence_count: 1,
    hypothesis_count: 1,
    id: "run_reviewed",
    policy_text_hash: "hash",
    report_title: null,
    scope_status: "in_scope",
  });
  const display = JSON.stringify({
    fallback: fallbackPipelineRuns.map((run) => run.validationGate),
    fallbackHunters: fallbackPipelineRuns.map((run) => run.hunter),
    fallbackStages: fallbackPipelineRuns.map((run) => run.stages),
    blocked: blockedSummary,
    live: liveSummary.validationGate,
    waiting: waitingSummary,
  });

  assert.equal(waitingSummary.validationGate.label, "Awaiting review gate");
  assert.equal(waitingSummary.validationGate.approval, "Needs human review and evidence before report drafting.");
  assert.equal(blockedSummary.validationGate.label, "Review gate blocked");
  assert.equal(blockedSummary.hunter.nextAction, "Resolve Scope Guard or review blockers before validation.");
  assert.equal(liveSummary.validationGate.label, "Low-risk validation reviewed");
  assert.match(display, /Human review required before live target validation\./);
  assert.match(display, /Review gate required/);
  assert.match(display, /Awaiting human review/);
  assert.match(display, /Two mutation checks are waiting for human review\./);
  assert.doesNotMatch(display, /Low-risk validation approved|Low-risk path approved/i);
  assert.doesNotMatch(
    display,
    /Human approval required before live target validation|Approval gate blocked|Awaiting approval gate|approval blockers|Approval required|Awaiting human approval|manual approval|human-approved|blocked until approval|before approval|program approval|scoped approval/i,
  );
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
  assert.equal(radar.unverifiedHypothesisCount, 0);
  assert.equal(radar.topSignal?.reportDistance, "1 gate to report review");
});

test("deriveIntelligenceRadar summarizes refutation review pressure", () => {
  const radar = deriveIntelligenceRadar([
    run({
      runId: "unverified",
      refutationSummary: {
        parked: 1,
        refuted: 0,
        total: 3,
        unverified: 2,
      },
    }),
    run({
      runId: "refuted",
      refutationSummary: {
        parked: 0,
        refuted: 1,
        total: 1,
        unverified: 0,
      },
    }),
  ]);

  assert.equal(radar.unverifiedHypothesisCount, 2);
  assert.equal(radar.parkedHypothesisCount, 1);
  assert.equal(radar.refutedHypothesisCount, 1);
});

test("dashboard radar keeps unsafe requirements visible beside memory lessons", async () => {
  const page = await import("node:fs/promises").then((fs) =>
    fs.readFile(new URL("../app/page.tsx", import.meta.url), "utf8"),
  );

  assert.match(page, /label="Memory lessons"/);
  assert.match(page, /value=\{intelligenceRadar\.reusableLessonCount\}/);
  assert.match(page, /label="Unsafe requirements"/);
  assert.match(page, /value=\{intelligenceRadar\.unsafeOrRedactedRequirementCount\}/);
  assert.match(page, /label="Unverified hypotheses"/);
  assert.match(page, /value=\{intelligenceRadar\.unverifiedHypothesisCount\}/);
  assert.match(page, /Refutation review needed/);
  assert.match(page, /Review gate still required/);
  assert.doesNotMatch(page, /Approval or review still required/);
  assert.doesNotMatch(page, /Kept out of report chain/);
  assert.doesNotMatch(page, /executeValidation|approveValidation|submitReport/);
});

test("dashboard redacts legacy finding and brain display fields", async () => {
  const page = await import("node:fs/promises").then((fs) =>
    fs.readFile(new URL("../app/page.tsx", import.meta.url), "utf8"),
  );

  assert.match(page, /safeDisplay/);
  assert.match(page, /formatLabel/);
  assert.match(page, /safeDisplay\(finding\.title/);
  assert.match(page, /safeDisplay\(brainProfile\.program_name/);
  assert.match(page, /safeDisplay\(surface\.surface_key/);
  assert.match(page, /safeDisplay\(surface\.paths\[0\]/);
  assert.match(page, /safeDisplay\(lesson\.surface_pattern/);
  assert.match(page, /safeDisplay\(signal\.playbook_id/);
  assert.match(page, /safeDisplay\(signal\.surface_key/);
  assert.doesNotMatch(page, /\{finding\.title\}/);
  assert.doesNotMatch(page, /\{brainProfile\.program_name\}/);
  assert.doesNotMatch(page, /\{surface\.surface_key\}/);
  assert.doesNotMatch(page, /\{surface\.paths\[0\]/);
  assert.doesNotMatch(page, /\{lesson\.surface_pattern\}/);
  assert.doesNotMatch(page, /\{signal\.playbook_id\}/);
  assert.doesNotMatch(page, /\{signal\.surface_key/);
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
  assert.match(page, /Evidence refs/);
  assert.doesNotMatch(page, />Evidence</);
  assert.match(page, />\s*Review\s*</);
  assert.match(page, />\s*Review validation\s*</);
  assert.doesNotMatch(page, />\s*Validate\s*</);
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
  assert.match(page, /const scopeGuardDecision = fallbackScopeGuardDecision/);
  assert.doesNotMatch(page, /evaluateScopeGuard/);
  assert.match(page, /Demo data/);
  assert.match(page, /sample Mythos workspace summaries/);
  assert.doesNotMatch(page, /fallback records/);
});

test("dashboard labels Scope Guard state as review state, not clearance", async () => {
  const page = await import("node:fs/promises").then((fs) =>
    fs.readFile(new URL("../app/page.tsx", import.meta.url), "utf8"),
  );

  assert.match(page, /Scope Guard decision/);
  assert.match(page, /Scope Guard reviewed/);
  assert.match(page, /Scope Guard blocked/);
  assert.doesNotMatch(page, /Scope Guard clear/);
  assert.doesNotMatch(page, /\? "Allowed" : "Blocked"/);
});

test("dashboard navigation uses Mythos review workspace labels", async () => {
  const page = await import("node:fs/promises").then((fs) =>
    fs.readFile(new URL("../app/page.tsx", import.meta.url), "utf8"),
  );

  assert.match(page, /Review Gate/);
  assert.doesNotMatch(page, /Approval Review/);
  assert.match(page, /Program Scope/);
  assert.match(page, /Attack Surface Map/);
  assert.match(page, /Hypothesis Board/);
  assert.match(page, /Report Readiness/);
  assert.match(page, /Mythos Brain/);
  assert.match(page, /Scope Guard/);
  assert.match(page, /Source Audit/);
  assert.match(page, /href: "\/source-audit"/);
  assert.match(page, /resolveNavigationHref/);
  assert.match(page, /activeCampaignId/);
  assert.match(page, /if \(!activeCampaignId\) \{\s*return "\/campaigns";\s*\}/);
  assert.equal(page.match(/campaignPath: "attack-surface-map"/g)?.length ?? 0, 1);
  assert.equal(page.match(/campaignPath: "hypothesis-board"/g)?.length ?? 0, 1);
  assert.equal(page.match(/campaignPath: "report-drafts"/g)?.length ?? 0, 1);
  assert.doesNotMatch(page, /activeCampaignId = programs\[0\]\?\.id/);
  assert.doesNotMatch(page, /href=\{item\.href \?\? "#"\}/);
  assert.doesNotMatch(page, /href="#"/);
  assert.doesNotMatch(page, /label: "Programs"/);
  assert.doesNotMatch(page, /label: "Assets"/);
  assert.doesNotMatch(page, /label: "Target Map"/);
  assert.doesNotMatch(page, /label: "API Model"/);
  assert.doesNotMatch(page, /label: "Business Flows"/);
  assert.doesNotMatch(page, /label: "Invariant Review"/);
  assert.doesNotMatch(page, /label: "Hypotheses"/);
  assert.doesNotMatch(page, /label: "Validation Plans"/);
  assert.doesNotMatch(page, /label: "Finding Candidates"/);
  assert.doesNotMatch(page, /label: "Findings"/);
  assert.doesNotMatch(page, /label: "Manual Submission Gate"/);
  assert.doesNotMatch(page, /label: "Reports"/);
  assert.doesNotMatch(page, /label: "Submissions"/);
  assert.doesNotMatch(page, /label: "Knowledge Base"/);
  assert.doesNotMatch(page, /label: "Settings \/ Policy Guard"/);
});

test("source audit page starts only the local human-gated audit flow", async () => {
  const page = await import("node:fs/promises").then((fs) =>
    fs.readFile(new URL("../app/source-audit/page.tsx", import.meta.url), "utf8"),
  );

  assert.match(page, /runSourceAuditScan/);
  assert.match(page, /sourceAuditScanAction/);
  assert.match(page, /name="repo_path"/);
  assert.match(page, /name="scope_path"/);
  assert.match(page, /name="policy_text"/);
  assert.match(page, /\/runs\/\$\{encodeURIComponent\(result\.run_id\)\}/);
  assert.match(page, /local_files_only/);
  assert.match(page, /no_live_requests/);
  assert.match(page, /no_auto_submission/);
  assert.match(page, /human_review_required/);
  assert.match(page, /Scope Guard/);
  assert.match(page, /submission_blocked/);
  assert.doesNotMatch(
    page,
    /executeValidation|approveValidation|submitReport|createFindingCandidate|recordManualObservation|recordClaimReviewDecision/,
  );
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
  assert.match(page, />\s*Review validation\s*</);
  assert.doesNotMatch(page, />\s*Validation\s*</);
  assert.match(page, /<Metric label="Evidence refs"/);
  assert.doesNotMatch(page, /<Metric label="Evidence"/);
  assert.match(page, /<Metric label="Review holds"/);
  assert.doesNotMatch(page, /<Metric label="Blocked"/);
  assert.doesNotMatch(page, /Run Detail/);
  assert.doesNotMatch(page, /fallback record/);
  assert.doesNotMatch(page, /Stage Timeline/);
});

test("run detail shows stage agent boundaries", async () => {
  const page = await import("node:fs/promises").then((fs) =>
    fs.readFile(new URL("../app/runs/[runId]/page.tsx", import.meta.url), "utf8"),
  );

  assert.match(page, /agentBoundary/);
  assert.match(page, /Agent Review Boundary/);
  assert.doesNotMatch(page, /Agent Boundary/);
  assert.match(page, /label="Human review gate"/);
  assert.match(page, /Review only/);
  assert.doesNotMatch(page, /Not required/);
  assert.match(page, /Scoped review actions/);
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

test("run detail exposes source audit hypothesis refutation review state", async () => {
  const page = await import("node:fs/promises").then((fs) =>
    fs.readFile(new URL("../app/runs/[runId]/page.tsx", import.meta.url), "utf8"),
  );

  assert.match(page, /sourceAuditHypotheses/);
  assert.match(page, /Source Audit Hypotheses/);
  assert.match(page, /Refutation status/);
  assert.match(page, /Priority score/);
  assert.match(page, /ranking_reasons/);
  assert.match(page, /Ranking reasons/);
  assert.match(page, /false_positive_checks/);
  assert.match(page, /False positive checks/);
  assert.match(page, /Evidence needed/);
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

test("run detail labels safety next steps as review actions", async () => {
  const page = await import("node:fs/promises").then((fs) =>
    fs.readFile(new URL("../app/runs/[runId]/page.tsx", import.meta.url), "utf8"),
  );

  assert.match(page, /label="Next review action"/);
  assert.match(page, /Review Requirements/);
  assert.match(page, /<p className="font-semibold">Review requirements<\/p>/);
  assert.doesNotMatch(page, /label="Next" value=\{step\.next_allowed_action\}/);
  assert.doesNotMatch(page, /Blocked Reasons/);
  assert.doesNotMatch(page, /<p className="font-semibold">Blocked<\/p>/);
});

test("fallback run detail includes stage agent boundaries", async () => {
  const source = await import("node:fs/promises").then((fs) =>
    fs.readFile(new URL("./workbench-detail-data.ts", import.meta.url), "utf8"),
  );

  assert.match(source, /agent_boundary/);
  assert.match(source, /execute_live_validation/);
  assert.match(source, /bypass_scope_guard/);
  assert.match(source, /Create a candidate from a review-ready observed claim/);
  assert.doesNotMatch(source, /eligible reviewed observed claim/);
});

test("report preview labels fallback claim ledgers as demo data", async () => {
  const page = await import("node:fs/promises").then((fs) =>
    fs.readFile(new URL("../app/reports/[runId]/page.tsx", import.meta.url), "utf8"),
  );

  assert.match(page, /reportDataMode/);
  assert.match(page, /fallback-only/);
  assert.match(page, /Demo data/);
  assert.match(page, />\s*Review validation\s*</);
  assert.doesNotMatch(page, />\s*Validation\s*</);
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
  assert.match(page, /review-ready human-reviewed observed claim/);
  assert.doesNotMatch(page, /eligible human-reviewed observed claim/);
  assert.match(page, /Research feedback gates can still block promotion/);
  assert.match(page, /promotionGateStatus/);
  assert.match(page, /blocked_by_research_feedback_gate/);
  assert.match(page, /Research feedback gate blocked finding promotion/);
  assert.match(page, /blockedStageCount/);
  assert.match(page, /provenanceRefCount/);
  assert.match(page, /Review holds/);
  assert.match(page, /Review requirements/);
  assert.doesNotMatch(page, /label="Blocked stages"/);
  assert.doesNotMatch(page, />Blockers</);
  assert.match(page, /Promotion waits for a live, human-reviewed observed claim/);
  assert.match(page, /submission_blocked/);
});

test("report preview summarizes source audit refutation review state", async () => {
  const page = await import("node:fs/promises").then((fs) =>
    fs.readFile(new URL("../app/reports/[runId]/page.tsx", import.meta.url), "utf8"),
  );

  assert.match(page, /sourceAuditHypotheses/);
  assert.match(page, /Refutation Review/);
  assert.match(page, /refutation_status/);
  assert.match(page, /priority_score/);
  assert.match(page, /ranking_reasons/);
  assert.match(page, /Ranking reasons/);
  assert.match(page, /false_positive_checks/);
  assert.match(page, /False positive checks/);
  assert.match(page, /Evidence needed/);
  assert.doesNotMatch(page, /approveValidation|executeValidation|submitReport/);
});

test("report preview can record human claim review decisions", async () => {
  const page = await import("node:fs/promises").then((fs) =>
    fs.readFile(new URL("../app/reports/[runId]/page.tsx", import.meta.url), "utf8"),
  );

  assert.match(page, /recordClaimReviewDecision/);
  assert.match(page, /recordClaimReviewDecisionAction/);
  assert.match(page, /name="claim_id"/);
  assert.match(page, /name="decision"/);
  assert.match(page, /name="reviewer"/);
  assert.match(page, /name="rationale"/);
  assert.match(page, /name="evidence_refs"/);
  assert.match(page, /confirmed_observed_fact/);
  assert.match(page, /needs_evidence/);
  assert.match(page, /refuted/);
  assert.match(page, /not_reportable/);
  assert.match(page, /Record Claim Review/);
  assert.match(page, /Submission remains manual/);
  assert.doesNotMatch(page, /approveValidation|executeValidation|submitReport/);
});

test("report preview labels blocked promotion query flags as review gates", async () => {
  const page = await import("node:fs/promises").then((fs) =>
    fs.readFile(new URL("../app/reports/[runId]/page.tsx", import.meta.url), "utf8"),
  );

  assert.match(page, /Finding promotion gate/);
  assert.match(page, /Submission gate/);
  assert.match(page, /formatReviewGateFlag/);
  assert.match(page, /Review blocked/);
  assert.match(page, /Review ready/);
  assert.doesNotMatch(page, /Finding promotion allowed/);
  assert.doesNotMatch(page, /Report submission allowed/);
});

test("report preview keeps submission status behind a manual gate", async () => {
  const page = await import("node:fs/promises").then((fs) =>
    fs.readFile(new URL("../app/reports/[runId]/page.tsx", import.meta.url), "utf8"),
  );

  assert.match(page, /Manual submission gate/);
  assert.match(page, /Research audit/);
  assert.match(page, /Human review ready/);
  assert.match(page, /Review captured/);
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
  assert.doesNotMatch(page, /Cleared/);
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
  assert.match(page, /validation gate state/);
  assert.doesNotMatch(page, /validation permission/);
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
  assert.match(page, /Observation boundary/);
  assert.match(page, /Preflight reviewed/);
  assert.match(page, /Preflight blocked/);
  assert.match(page, /Review only/);
  assert.match(page, /Promotion gate/);
  assert.match(page, /Review ready/);
  assert.match(page, /Human review gate/);
  assert.match(page, /Review captured/);
  assert.match(page, /Review required/);
  assert.doesNotMatch(page, /label="Promotion" value=\{task\.promotion_eligible \? "Eligible" : "Blocked"\}/);
  assert.doesNotMatch(page, /report_chain_blocked \? "Blocked" : "Open"/);
  assert.doesNotMatch(page, /Execution permission/);
  assert.doesNotMatch(page, /No execution permission/);
  assert.doesNotMatch(page, /Allowed to execute/);
  assert.doesNotMatch(page, /Execution allowed/);
  assert.doesNotMatch(page, /Human approval/);
  assert.doesNotMatch(page, /Preflight clear/);
  assert.doesNotMatch(page, /\? "Approved" : "Required"/);
  assert.doesNotMatch(page, /\? "Allowed" : "Blocked"/);
});

test("validation workspace empty states read as review readiness, not records", async () => {
  const page = await import("node:fs/promises").then((fs) =>
    fs.readFile(new URL("../app/validation-workspace/[runId]/page.tsx", import.meta.url), "utf8"),
  );

  assert.match(page, /Claim Review/);
  assert.match(page, /Review Requirements/);
  assert.match(page, /No validation steps ready/);
  assert.match(page, /No claim review items ready/);
  assert.match(page, /No manual observations ready for review/);
  assert.match(page, /No active review requirements/);
  assert.match(page, /No evidence hints ready/);
  assert.doesNotMatch(page, /Claim Tasks/);
  assert.doesNotMatch(page, /No validation steps recorded/);
  assert.doesNotMatch(page, /No claim tasks ready/);
  assert.doesNotMatch(page, /No claim tasks recorded/);
  assert.doesNotMatch(page, /No manual observations recorded/);
  assert.doesNotMatch(page, /Blocked Reasons/);
  assert.doesNotMatch(page, /No active blocking reasons/);
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
  assert.match(page, /name="observation_type"/);
  assert.match(page, /name="observation"/);
  assert.match(page, /name="evidence_refs"/);
  assert.match(page, /request_response_diff/);
  assert.match(page, /role_matrix_observation/);
  assert.match(page, /formText\(formData, "observation_type"\)/);
  assert.match(page, /test_accounts_only/);
  assert.match(page, /no_real_user_data/);
  assert.doesNotMatch(page, /observation_type: "manual_observation"/);
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
  assert.match(page, /Research Artifact Review/);
  assert.match(page, /Artifact Review/);
  assert.match(page, /No artifacts ready for review/);
  assert.match(page, /Usage audit/);
  assert.doesNotMatch(page, /Authorized Research Materials/);
  assert.doesNotMatch(page, /No artifacts available/);
  assert.doesNotMatch(page, /Usage run/);
  assert.doesNotMatch(page, /artifact records came from fallback summaries/);
  assert.doesNotMatch(page, />Repository View</);
});

test("artifact repository describes report-chain state as review readiness", async () => {
  const page = await import("node:fs/promises").then((fs) =>
    fs.readFile(new URL("../app/artifacts/page.tsx", import.meta.url), "utf8"),
  );

  assert.match(page, /Report chain review ready/);
  assert.match(page, /Report chain review required/);
  assert.doesNotMatch(page, /report chain allowed/);
  assert.doesNotMatch(page, /report chain blocked/);
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

test("artifact detail describes report-chain state as review readiness", async () => {
  const page = await import("node:fs/promises").then((fs) =>
    fs.readFile(new URL("../app/artifacts/[artifactId]/page.tsx", import.meta.url), "utf8"),
  );

  assert.match(page, /Report-chain review readiness/);
  assert.match(page, /Report chain review ready/);
  assert.match(page, /Report chain review required/);
  assert.doesNotMatch(page, /Report-chain eligibility/);
  assert.doesNotMatch(page, /Eligible for report chain/);
  assert.doesNotMatch(page, /Blocked for report chain/);
  assert.doesNotMatch(page, /\? "Allowed" : "Blocked"/);
});

test("web API types carry source audit hypothesis refutation metadata", async () => {
  const source = await import("node:fs/promises").then((fs) =>
    fs.readFile(new URL("./api.ts", import.meta.url), "utf8"),
  );

  assert.match(source, /export type PipelineHypothesis = \{[\s\S]*refutation_status\?: string/);
  assert.match(source, /export type PipelineHypothesis = \{[\s\S]*false_positive_checks\?: string\[\]/);
  assert.match(source, /export type PipelineHypothesis = \{[\s\S]*priority_score\?: number/);
  assert.match(source, /export type PipelineHypothesis = \{[\s\S]*ranking_reasons\?: string\[\]/);
});
