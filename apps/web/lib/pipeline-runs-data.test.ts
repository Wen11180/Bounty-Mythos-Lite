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
    evidenceSupportSummary: null,
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
  const policy = mythosPipelineStages.find((stage) => stage.label === "策略");
  const refutation = mythosPipelineStages.find((stage) => stage.label === "反证");
  const reportDraft = mythosPipelineStages.find((stage) => stage.label === "报告草稿");
  const validationPlan = mythosPipelineStages.find((stage) => stage.label === "验证计划");

  assert.equal(policy?.status, "策略已审核");
  assert.equal(policy?.risk, "人工审核门");
  assert.equal(refutation?.status, "需要证据");
  assert.equal(reportDraft?.status, "审核草稿");
  assert.equal(reportDraft?.risk, "人工审核门");
  assert.equal(validationPlan?.risk, "需要审核门");
  assert.doesNotMatch(JSON.stringify(mythosPipelineStages), /"Candidate"/i);
  assert.doesNotMatch(JSON.stringify(mythosPipelineStages), /"Blocking"/i);
  assert.notEqual(reportDraft?.risk, "人工审核");
  assert.match(JSON.stringify(mythosPipelineStages), /人工审核门/);
  assert.doesNotMatch(JSON.stringify(mythosPipelineStages), /Rule Ready/i);
  assert.doesNotMatch(JSON.stringify(mythosPipelineStages), /Approval required/i);
});

test("formatLabel describes validation blockers as review requirements", () => {
  const label = formatLabel("validation_gate_not_approved");

  assert.equal(label, "验证需要人工审核");
  assert.doesNotMatch(label, /not approved/i);
});

test("formatLabel describes human approval blockers as review requirements", () => {
  const label = formatLabel("human_approval_required");

  assert.equal(label, "需要人工审核");
  assert.doesNotMatch(label, /approval/i);
});

test("formatLabel describes execution permission blockers as review gates", () => {
  const label = formatLabel("no_execution_permission");

  assert.equal(label, "执行需经人工审核");
  assert.doesNotMatch(label, /permission/i);
});

test("formatLabel describes authorization blockers as review gates", () => {
  const label = formatLabel("cannot_authorize_execution");

  assert.equal(label, "执行仍需人工审核");
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
  const hypothesisStage = summary.stages.find((stage) => stage.label === "假设引擎");
  assert.match(hypothesisStage?.detail ?? "", /已从范围内资料生成/);
  assert.doesNotMatch(hypothesisStage?.detail ?? "", /allowed artifacts/);
  const scopeStage = summary.stages.find((stage) => stage.label === "范围守卫");
  assert.match(scopeStage?.detail ?? "", /已完成低风险规划审核。/);
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
      manual_observation_count: 1,
      reviewed_claim_count: 1,
      finding_candidate_count: 0,
      learning_signal_count: 1,
      lesson_count: 1,
      memory_lessons: [
        {
          lesson_id: "lesson_1",
          scope_type: "program",
          scope_key: "program_example",
          playbook_id: "bola_idor",
          recommendation: "boost",
          surface_pattern: "alice@example.com",
          confidence: 76,
          source_signal_count: 1,
          source_signal_ids: ["signal_1"],
          reasons: ["accepted_history"],
          safety_notes: ["advisory_only"],
        },
      ],
      blocked_reasons: [],
      safety_notes: ["advisory_only"],
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

  assert.equal(waitingSummary.validationGate.label, "等待审核门");
  assert.equal(waitingSummary.validationGate.approval, "起草报告前需要人工审核和证据。");
  assert.equal(blockedSummary.validationGate.label, "审核门已阻断");
  assert.equal(blockedSummary.hunter.nextAction, "验证前请处理范围守卫或审核阻断项。");
  assert.equal(liveSummary.validationGate.label, "低风险验证已审核");
  assert.match(display, /对实时目标验证前需要人工审核。/);
  assert.match(display, /需要审核门/);
  assert.match(display, /等待人工审核/);
  assert.match(display, /两项状态修改检查正在等待人工审核。/);
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
            role: "验证规划智能体",
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
    role: "验证规划智能体",
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
    topLesson: "file_id:export 上的提升记忆",
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
        approval: "人工审核 still required.",
        evidenceCount: 2,
        label: "人工审核门d",
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
  assert.equal(radar.topSignal?.reportDistance, "距离报告审核还差 1 个审核门");
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

test("dashboard keeps safety pressure visible without execution or submission controls", async () => {
  const page = await import("node:fs/promises").then((fs) =>
    fs.readFile(new URL("../app/page.tsx", import.meta.url), "utf8"),
  );
  const overview = await import("node:fs/promises").then((fs) =>
    fs.readFile(new URL("../components/control-center/control-center-overview.tsx", import.meta.url), "utf8"),
  );

  assert.match(page, /getControlCenterOverview/);
  assert.match(overview, /高价值保留候选/);
  assert.match(overview, /等待人工批准/);
  assert.match(overview, /安全与政策阻断/);
  assert.match(overview, /仍需反证与人工复核/);
  assert.doesNotMatch(`${page}\n${overview}`, /executeValidation|approveValidation|submitReport/);
});

test("dashboard renders only the display-safe control-center projection", async () => {
  const page = await import("node:fs/promises").then((fs) =>
    fs.readFile(new URL("../app/page.tsx", import.meta.url), "utf8"),
  );
  const mapper = await import("node:fs/promises").then((fs) =>
    fs.readFile(new URL("./control-center-data.ts", import.meta.url), "utf8"),
  );

  assert.match(page, /mapControlCenterOverview/);
  assert.match(mapper, /reportSubmissionAllowed: false/);
  assert.match(mapper, /submissionBlocked: true/);
  assert.match(mapper, /humanReviewRequired: true/);
  assert.doesNotMatch(page, /getFindings|getMythosBrainProgram|getReports/);
});

test("dashboard does not use legacy pipeline-run demo fallbacks", async () => {
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

  assert.equal(demoRows.dataMode, "演示数据");
  assert.equal(demoRows.runs, fallbackPipelineRuns);
  assert.equal(demoRows.runs.length > 0, true);
  assert.deepEqual(resolvePipelineRunRows([liveRun]), {
    dataMode: "实时数据",
    runs: [toPipelineRunSummary(liveRun)],
  });

  const page = await import("node:fs/promises").then((fs) =>
    fs.readFile(new URL("../app/page.tsx", import.meta.url), "utf8"),
  );

  assert.match(page, /getControlCenterOverview/);
  assert.match(page, /createOfflineControlCenterSnapshot/);
  assert.doesNotMatch(page, /resolvePipelineRunRows|fallbackPipelineRuns|演示数据/);
});

test("dashboard live request failure stays visibly offline instead of becoming demo data", async () => {
  const page = await import("node:fs/promises").then((fs) =>
    fs.readFile(new URL("../app/page.tsx", import.meta.url), "utf8"),
  );

  assert.match(page, /catch \(error\)/);
  assert.match(page, /createOfflineControlCenterSnapshot/);
  assert.doesNotMatch(page, /fallbackPrograms|fallbackFindings|fallbackReports|fallbackScopeGuardDecision/);
  assert.doesNotMatch(page, /演示数据/);
});

test("dashboard labels 范围守卫 state as review state, not clearance", async () => {
  const overview = await import("node:fs/promises").then((fs) =>
    fs.readFile(new URL("../components/control-center/control-center-overview.tsx", import.meta.url), "utf8"),
  );

  assert.match(overview, /范围守卫优先/);
  assert.match(overview, /范围守卫与安全门/);
  assert.match(overview, /等待人工批准/);
  assert.doesNotMatch(overview, /范围守卫 clear|范围守卫 放行/);
});

test("dashboard navigation uses Mythos review workspace labels", async () => {
  const overview = await import("node:fs/promises").then((fs) =>
    fs.readFile(new URL("../components/control-center/control-center-overview.tsx", import.meta.url), "utf8"),
  );

  assert.match(overview, /label: "研究任务"/);
  assert.match(overview, /label: "漏洞候选"/);
  assert.match(overview, /label: "验证批准"/);
  assert.match(overview, /label: "报告草稿"/);
  assert.match(overview, /label: "范围守卫"/);
  assert.match(overview, /href: "\/source-audit"/);
  assert.match(overview, /if \(!campaign\) \{\s*return navigation;\s*\}/);
  assert.match(overview, /项目工作区导航已禁用/);
  assert.doesNotMatch(overview, /href: "#"|href="#"/);
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
  assert.match(page, /范围守卫/);
  assert.match(page, /报告提交已阻断/);
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
  assert.match(page, /演示数据/);
  assert.match(page, /研究审计/);
  assert.match(page, /研究摘要样例/);
  assert.match(page, /研究审核时间线/);
  assert.match(page, />\s*审核验证\s*</);
  assert.doesNotMatch(page, />\s*Validation\s*</);
  assert.match(page, /<Metric label="证据引用"/);
  assert.doesNotMatch(page, /<Metric label="Evidence"/);
  assert.match(page, /<Metric label="审核阻塞项"/);
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
  assert.match(page, /智能体审核边界/);
  assert.doesNotMatch(page, /Agent Boundary/);
  assert.match(page, /label="人工审核门"/);
  assert.match(page, /仅供审核/);
  assert.doesNotMatch(page, /无需处理/);
  assert.match(page, /范围内审核操作/);
  assert.match(page, /blockedActions/);
});

test("run detail shows read-only exploit-chain reasoning summaries", async () => {
  const page = await import("node:fs/promises").then((fs) =>
    fs.readFile(new URL("../app/runs/[runId]/page.tsx", import.meta.url), "utf8"),
  );

  assert.match(page, /exploit_chain/);
  assert.match(page, /利用链置信度/);
  assert.match(page, /原语/);
  assert.match(page, /前提条件/);
  assert.match(page, /反证问题/);
  assert.doesNotMatch(page, /executeValidation|approveValidation|submitReport/);
});

test("run detail exposes source audit hypothesis refutation review state", async () => {
  const page = await import("node:fs/promises").then((fs) =>
    fs.readFile(new URL("../app/runs/[runId]/page.tsx", import.meta.url), "utf8"),
  );

  assert.match(page, /sourceAuditHypotheses/);
  assert.match(page, /源代码审计假设/);
  assert.match(page, /反证状态/);
  assert.match(page, /优先级评分/);
  assert.match(page, /ranking_reasons/);
  assert.match(page, /排序原因/);
  assert.match(page, /false_positive_checks/);
  assert.match(page, /误报检查/);
  assert.match(page, /所需证据/);
  assert.doesNotMatch(page, /executeValidation|approveValidation|submitReport/);
});

test("run detail shows advisory reasoning memory context", async () => {
  const page = await import("node:fs/promises").then((fs) =>
    fs.readFile(new URL("../app/runs/[runId]/page.tsx", import.meta.url), "utf8"),
  );

  assert.match(page, /推理记忆/);
  assert.match(page, /highest_reasoning_review_score/);
  assert.match(page, /advisory_memory_only/);
  assert.doesNotMatch(page, /execution_allowed|submission_allowed/);
});

test("run detail labels safety next steps as review actions", async () => {
  const page = await import("node:fs/promises").then((fs) =>
    fs.readFile(new URL("../app/runs/[runId]/page.tsx", import.meta.url), "utf8"),
  );

  assert.match(page, /label="下一步审核操作"/);
  assert.match(page, /审核要求/);
  assert.match(page, /<p className="font-semibold">审核要求<\/p>/);
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
  assert.match(source, /从可审核的观察声明创建候选。/);
  assert.doesNotMatch(source, /eligible reviewed observed claim/);
});

test("report preview labels fallback claim ledgers as demo data", async () => {
  const page = await import("node:fs/promises").then((fs) =>
    fs.readFile(new URL("../app/reports/[runId]/page.tsx", import.meta.url), "utf8"),
  );

  assert.match(page, /reportDataMode/);
  assert.match(page, /fallback-only/);
  assert.match(page, /演示数据/);
  assert.match(page, />\s*审核验证\s*</);
  assert.doesNotMatch(page, />\s*Validation\s*</);
});

test("report preview can promote reviewed claims to finding candidates", async () => {
  const page = await import("node:fs/promises").then((fs) =>
    fs.readFile(new URL("../app/reports/[runId]/page.tsx", import.meta.url), "utf8"),
  );

  assert.match(page, /hasPromotionCandidate/);
  assert.match(page, /canPromoteFindingCandidate = !isDemoData && hasPromotionCandidate/);
  assert.match(page, /promotionBlockingReadinessBlockers/);
  assert.match(page, /claim\.quality_score >= 80/);
  assert.match(page, /createFindingCandidate/);
  assert.match(page, /promoteFindingCandidateAction/);
  assert.match(page, /晋级发现候选项/);
  assert.match(page, /可审核、已人工审核的观察声明/);
  assert.doesNotMatch(page, /eligible human-reviewed observed claim/);
  assert.match(page, /研究反馈门仍可阻断晋级/);
  assert.match(page, /promotionGateStatus/);
  assert.match(page, /blocked_by_research_feedback_gate/);
  assert.match(page, /研究反馈门已阻断发现晋级。/);
  assert.match(page, /blockedStageCount/);
  assert.match(page, /provenanceRefCount/);
  assert.match(page, /审核阻塞项/);
  assert.match(page, /审核要求/);
  assert.doesNotMatch(page, /label="Blocked stages"/);
  assert.doesNotMatch(page, />Blockers</);
  assert.match(page, /晋级须等待在线的、经人工审核的观察声明。/);
  assert.match(page, /submission_blocked/);
});

test("report preview summarizes source audit refutation review state", async () => {
  const page = await import("node:fs/promises").then((fs) =>
    fs.readFile(new URL("../app/reports/[runId]/page.tsx", import.meta.url), "utf8"),
  );

  assert.match(page, /sourceAuditHypotheses/);
  assert.match(page, /反证审核/);
  assert.match(page, /refutation_status/);
  assert.match(page, /priority_score/);
  assert.match(page, /ranking_reasons/);
  assert.match(page, /排序原因/);
  assert.match(page, /false_positive_checks/);
  assert.match(page, /误报检查/);
  assert.match(page, /所需证据/);
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
  assert.match(page, /记录声明审核/);
  assert.match(page, /报告提交仍需人工操作。/);
  assert.doesNotMatch(page, /approveValidation|executeValidation|submitReport/);
});

test("report preview labels blocked promotion query flags as review gates", async () => {
  const page = await import("node:fs/promises").then((fs) =>
    fs.readFile(new URL("../app/reports/[runId]/page.tsx", import.meta.url), "utf8"),
  );

  assert.match(page, /发现晋级门/);
  assert.match(page, /提交门/);
  assert.match(page, /formatReviewGateFlag/);
  assert.match(page, /审核已阻断/);
  assert.match(page, /审核已就绪/);
  assert.doesNotMatch(page, /发现晋级 allowed/);
  assert.doesNotMatch(page, /Report 报告提交已允许/);
});

test("report preview keeps submission status behind a manual gate", async () => {
  const page = await import("node:fs/promises").then((fs) =>
    fs.readFile(new URL("../app/reports/[runId]/page.tsx", import.meta.url), "utf8"),
  );

  assert.match(page, /人工提交门/);
  assert.match(page, /研究审计/);
  assert.match(page, /人工审核已就绪/);
  assert.match(page, /已记录审核/);
  assert.match(page, /报告提交已阻断/);
  assert.match(page, /暂无可审核的声明台账条目。/);
  assert.match(page, /暂无审核依据。/);
  assert.match(page, /暂无可用报告章节声明。/);
  assert.match(page, /暂无安全说明。/);
  assert.match(page, /暂无证据引用。/);
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
  assert.match(page, /仅建议性记忆/);
  assert.match(page, /验证门状态/);
  assert.doesNotMatch(page, /validation permission/);
});

test("validation workspace labels fallback workspaces as demo data", async () => {
  const page = await import("node:fs/promises").then((fs) =>
    fs.readFile(new URL("../app/validation-workspace/[runId]/page.tsx", import.meta.url), "utf8"),
  );

  assert.match(page, /workspaceDataMode/);
  assert.match(page, /fallback-only/);
  assert.match(page, /演示数据/);
});

test("validation workspace labels execution state as preflight, not permission", async () => {
  const page = await import("node:fs/promises").then((fs) =>
    fs.readFile(new URL("../app/validation-workspace/[runId]/page.tsx", import.meta.url), "utf8"),
  );

  assert.match(page, /预检门/);
  assert.match(page, /观察边界/);
  assert.match(page, /预检已审核/);
  assert.match(page, /预检已阻断/);
  assert.match(page, /仅供审核/);
  assert.match(page, /晋级门/);
  assert.match(page, /审核已就绪/);
  assert.match(page, /人工审核门/);
  assert.match(page, /已记录审核/);
  assert.match(page, /需要审核/);
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

  assert.match(page, /声明审核/);
  assert.match(page, /审核要求/);
  assert.match(page, /暂无验证步骤。/);
  assert.match(page, /暂无声明审核项。/);
  assert.match(page, /暂无可审核的人工观察。/);
  assert.match(page, /当前没有待处理的审核要求。/);
  assert.match(page, /暂无证据提示。/);
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
  assert.match(page, /需要可用于报告的安全证据/);
  assert.match(page, /request_response_diff/);
});

test("artifact repository labels fallback artifacts as demo data", async () => {
  const page = await import("node:fs/promises").then((fs) =>
    fs.readFile(new URL("../app/artifacts/page.tsx", import.meta.url), "utf8"),
  );

  assert.match(page, /artifactDataMode/);
  assert.match(page, /fallback-only/);
  assert.match(page, /演示数据/);
  assert.match(page, /研究资料摘要样例/);
  assert.match(page, /研究资料审核/);
  assert.match(page, /资料审核/);
  assert.match(page, /暂无可审核资料。/);
  assert.match(page, /使用审计/);
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

  assert.match(page, /报告链审核已就绪/);
  assert.match(page, /报告链需要审核/);
  assert.doesNotMatch(page, /report chain allowed/);
  assert.doesNotMatch(page, /report chain blocked/);
});

test("artifact detail labels fallback artifacts as demo data", async () => {
  const page = await import("node:fs/promises").then((fs) =>
    fs.readFile(new URL("../app/artifacts/[artifactId]/page.tsx", import.meta.url), "utf8"),
  );

  assert.match(page, /artifactDataMode/);
  assert.match(page, /fallback-only/);
  assert.match(page, /演示数据/);
  assert.match(page, /暂无载荷摘要。/);
  assert.match(page, /暂无溯源摘要。/);
  assert.match(page, /暂无派生事实。/);
  assert.match(page, /暂无资料使用记录。/);
  assert.doesNotMatch(page, /No payload summary recorded/);
  assert.doesNotMatch(page, /No provenance summary recorded/);
  assert.doesNotMatch(page, /No derived facts recorded/);
  assert.doesNotMatch(page, /No artifact usage recorded/);
});

test("artifact detail describes report-chain state as review readiness", async () => {
  const page = await import("node:fs/promises").then((fs) =>
    fs.readFile(new URL("../app/artifacts/[artifactId]/page.tsx", import.meta.url), "utf8"),
  );

  assert.match(page, /报告链审核就绪度/);
  assert.match(page, /报告链审核已就绪/);
  assert.match(page, /报告链需要审核/);
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
