import assert from "node:assert/strict";
import test from "node:test";
import type { ProgramIntelligenceProfile } from "./api.ts";
import {
  toCampaignAgentRunSummaries,
  toCampaignBrainSummary,
  toCampaignCodebaseMapView,
  toCampaignControlSummary,
  toCampaignTaskSummaries,
  toCampaignTimelineSummaries,
  toCampaignValidationQueueSummaries,
  type CampaignControlCenter,
} from "./campaigns-data.ts";

const controlCenter = {
  campaign: {
    allowed_tools: ["static_analyzer"],
    autonomy_level: "level_0_read_only",
    created_at: "2026-07-05T00:00:00Z",
    created_by: "operator",
    default_asset: "https://api.example.com/path?session=secret",
    id: "campaign_1",
    name: "Authorized campaign",
    program_id: "program_example",
    scope_status: "in_scope",
    status: "running",
    target_classes: ["idor"],
  },
  budget: {
    campaign_id: "campaign_1",
    created_at: "2026-07-05T00:00:00Z",
    id: "budget_1",
    status: "active",
    time_budget_minutes: 30,
    token_budget: 5000,
    tool_call_budget: 10,
    validation_budget: 1,
  },
  tasks: [
    {
      agent_type: "orchestrator_agent",
      campaign_id: "campaign_1",
      created_at: "2026-07-05T00:00:00Z",
      id: "task_1",
      input_refs: ["campaign:campaign_1"],
      output_refs: [],
      status: "queued",
      task_type: "campaign_observation",
      title: "Observe campaign; token=secret-token",
    },
  ],
  agent_runs: [
    {
      agent_type: "orchestrator_agent",
      campaign_id: "campaign_1",
      created_at: "2026-07-05T00:00:00Z",
      finished_at: null,
      id: "run_1",
      input_refs: ["campaign_task:task_1"],
      output_refs: [],
      safety_gate_state: "allowed",
      status: "dispatched",
      stop_reason: null,
      task_id: "task_1",
    },
  ],
  approvals: [
    {
      actor: "operator",
      approval_type: "validation_batch",
      asset: null,
      autonomy_level: null,
      campaign_id: "campaign_1",
      created_at: "2026-07-05T00:00:00Z",
      decided_at: null,
      decided_by: null,
      decision_reason: null,
      id: "approval_1",
      plan_digest: null,
      program_id: null,
      reason: "[REDACTED]",
      requested_action: "two_account_authorization_check",
      run_id: null,
      safety_gate_state: "awaiting_approval",
      scope_reference: null,
      status: "pending",
      task_id: "task_1",
      validation_mode: null,
    },
  ],
  pipeline_stages: [
    {
      campaign_id: "campaign_1",
      created_at: "2026-07-05T00:00:00Z",
      id: "stage_1",
      input_refs: ["campaign:campaign_1"],
      output_refs: [],
      pipeline_run_id: null,
      safety_gate_state: "blocked",
      stage_key: "campaign_tick",
      stage_order: 0,
      status: "blocked",
      stop_reason: "approval_required",
      task_id: "task_1",
    },
  ],
  blocked_reasons: ["approval_required"],
  execution_allowed: false,
  safe_next_action: "review_approval_queue",
} satisfies CampaignControlCenter;

const brainProfile = {
  program_id: "program_example",
  program_name: "Example Program",
  program_score: 84,
  attack_surface_memory: {
    objects: ["workspace", "invoice"],
    roles: ["member", "admin"],
    run_count: 7,
    sensitive_actions: [
      {
        action: "transfer_ownership",
        method: "POST",
        path: "/workspaces/{id}/owners?session=secret",
        roles: ["admin"],
      },
    ],
  },
  high_value_surfaces: [
    {
      action: "transfer_ownership",
      object_name: "workspace",
      paths: ["/workspaces/{id}/owners?token=secret-token"],
      playbooks: ["idor_role_boundary"],
      reasons: ["accepted_history"],
      score: 92,
      surface_key: "workspace:transfer_ownership",
    },
  ],
  learning_summary: {
    accepted_count: 2,
    adequate_evidence_count: 1,
    bounty_total: 1500,
    duplicate_count: 1,
    evidence_score_delta: 3,
    informative_count: 0,
    na_count: 0,
    penalized_playbooks: [],
    rejected_count: 0,
    rejection_risk_delta: -1,
    severity_down_count: 0,
    severity_up_count: 1,
    strong_evidence_count: 2,
    triager_feedback_count: 1,
    weak_evidence_count: 0,
    boosted_playbooks: ["idor_role_boundary"],
  },
  recent_learning_signals: [
    {
      created_at: "2026-07-05T00:00:00Z",
      evidence_quality: "strong",
      id: "signal_1",
      notes: "Triager accepted; cookie=session=secret",
      outcome: "accepted",
      playbook_id: "idor_role_boundary",
      program_id: "program_example",
      surface_key: "workspace:transfer_ownership",
    },
  ],
  applied_lessons: [
    {
      bounty_total: 1500,
      confidence: 0.82,
      created_at: "2026-07-05T00:00:00Z",
      evidence_quality_counts: { strong: 2 },
      id: "lesson_1",
      outcome_counts: { accepted: 2 },
      playbook_id: "idor_role_boundary",
      reasons: ["accepted_history", "token=secret-token"],
      recommendation: "boost",
      scope_key: "program_example",
      scope_type: "program",
      score_delta: 8,
      severity_delta_counts: { up: 1 },
      source_signal_ids: ["signal_1"],
      surface_pattern: "workspace ownership",
      safety_notes: ["advisory_only"],
      updated_at: "2026-07-05T00:00:00Z",
    },
  ],
  skipped_lessons: [
    {
      lesson_id: "lesson_skipped",
      reason: "scope_guard_blocked",
      scope_key: "program_example",
      scope_type: "program",
    },
  ],
  lesson_adjusted_surfaces: [
    {
      lesson_id: "lesson_1",
      recommendation: "boost",
      score_after: 92,
      score_before: 84,
      score_delta: 8,
      surface_key: "workspace:transfer_ownership",
    },
  ],
  safety_notes: ["advisory_only", "cannot_authorize_execution"],
} satisfies ProgramIntelligenceProfile;

test("toCampaignControlSummary keeps campaign control center read-only and redacted", () => {
  const summary = toCampaignControlSummary(controlCenter);

  assert.equal(summary.campaignId, "campaign_1");
  assert.equal(summary.executionAllowed, false);
  assert.equal(summary.safeNextAction, "Review approval queue");
  assert.deepEqual(summary.blockedReasons, ["Approval required"]);
  assert.equal(summary.budgetLabel, "30m / 5000 tokens / 10 tools / 1 validations");
  assert.equal(summary.taskCount, 1);
  assert.equal(summary.agentRunCount, 1);
  assert.equal(summary.pendingApprovalCount, 1);
  assert.equal(summary.blockedStageCount, 1);
  assert.equal(summary.defaultAsset, "api.example.com/path");
  assert.doesNotMatch(JSON.stringify(summary), /secret-token|session=secret|token=secret/i);
});

test("toCampaignAgentRunSummaries keeps refs counted but not displayed", () => {
  const summaries = toCampaignAgentRunSummaries([
    {
      ...controlCenter.agent_runs[0],
      input_refs: ["campaign:campaign_1", "artifact:token=secret-token"],
      output_refs: ["evidence:session=secret"],
      stop_reason: "approval_required",
    },
  ]);

  assert.deepEqual(summaries, [
    {
      agentType: "Orchestrator agent",
      finishedAt: null,
      id: "run_1",
      inputRefCount: 2,
      outputRefCount: 1,
      safetyGateState: "Allowed",
      startedAt: "2026-07-05T00:00:00Z",
      status: "Dispatched",
      stopReason: "Approval required",
      taskId: "task_1",
    },
  ]);
  assert.doesNotMatch(JSON.stringify(summaries), /secret-token|session=secret|token=secret/i);
});

test("toCampaignTaskSummaries keeps task queue display redacted", () => {
  const summaries = toCampaignTaskSummaries([
    {
      ...controlCenter.tasks[0],
      input_refs: ["campaign:campaign_1", "artifact:token=secret-token"],
      output_refs: ["stage:cookie=session-secret"],
      title: "Observe campaign with Authorization: Bearer secret-token",
    },
  ]);

  assert.deepEqual(summaries, [
    {
      agentType: "Orchestrator agent",
      createdAt: "2026-07-05T00:00:00Z",
      id: "task_1",
      inputRefCount: 2,
      outputRefCount: 1,
      status: "Queued",
      taskType: "Campaign observation",
      title: "Observe campaign with Authorization=[redacted]",
    },
  ]);
  assert.doesNotMatch(JSON.stringify(summaries), /secret-token|session-secret|cookie=session/i);
});

test("toCampaignValidationQueueSummaries redacts approval details for display", () => {
  const summaries = toCampaignValidationQueueSummaries([
    {
      ...controlCenter.approvals[0],
      asset: "https://api.example.com/path?cookie=session=secret",
      plan_digest: "plan_digest_1",
      reason: "Needs approval; Authorization: Bearer secret-token",
      validation_mode: "two_account_authorization_check",
    },
  ]);

  assert.deepEqual(summaries, [
    {
      approvalType: "Validation batch",
      asset: "api.example.com/path",
      createdAt: "2026-07-05T00:00:00Z",
      id: "approval_1",
      planDigest: "plan_digest_1",
      reason: "Needs approval; Authorization=[redacted]",
      requestedAction: "Two account authorization check",
      runId: null,
      safetyGateState: "Awaiting approval",
      status: "Pending",
      taskId: "task_1",
      validationMode: "Two account authorization check",
    },
  ]);
  assert.doesNotMatch(JSON.stringify(summaries), /secret-token|session=secret|cookie=session/i);
});

test("toCampaignTimelineSummaries keeps stage refs counted but not displayed", () => {
  const summaries = toCampaignTimelineSummaries([
    {
      ...controlCenter.pipeline_stages[0],
      input_refs: ["campaign:campaign_1", "artifact:token=secret-token"],
      output_refs: ["evidence:session=secret"],
    },
  ]);

  assert.deepEqual(summaries, [
    {
      id: "stage_1",
      inputRefCount: 2,
      outputRefCount: 1,
      safetyGateState: "Blocked",
      stageKey: "Campaign tick",
      stageOrder: 0,
      status: "Blocked",
      stopReason: "Approval required",
      taskId: "task_1",
    },
  ]);
  assert.doesNotMatch(JSON.stringify(summaries), /secret-token|session=secret|token=secret/i);
});

test("toCampaignBrainSummary keeps Mythos Brain advisory and redacted", () => {
  const summary = toCampaignBrainSummary(brainProfile);

  assert.equal(summary.programId, "program_example");
  assert.equal(summary.programName, "Example Program");
  assert.equal(summary.programScore, 84);
  assert.equal(summary.objectCount, 2);
  assert.equal(summary.roleCount, 2);
  assert.equal(summary.sensitiveActionCount, 1);
  assert.equal(summary.signalCount, 1);
  assert.equal(summary.appliedLessonCount, 1);
  assert.equal(summary.skippedLessonCount, 1);
  assert.equal(summary.advisoryOnly, true);
  assert.equal(summary.executionAllowed, false);
  assert.equal(summary.topSurfaces[0].path, "/workspaces/{id}/owners");
  assert.equal(summary.recentSignals[0].notes, "Triager accepted; cookie=[redacted]");
  assert.equal(summary.appliedLessons[0].reasons[1], "[redacted]");
  assert.doesNotMatch(JSON.stringify(summary), /secret-token|session=secret|token=secret/i);
});

test("toCampaignCodebaseMapView summarizes code facts without raw scanner leakage", () => {
  const view = toCampaignCodebaseMapView({
    maps: [
      {
        authz_check_count: 1,
        campaign_id: "campaign_1",
        commit_ref: "abc123",
        created_at: "2026-07-05T00:00:00Z",
        handler_count: 2,
        id: "codebase_map_1",
        model_count: 1,
        provenance_refs: ["artifact:repo_snapshot"],
        repository: "authorized/service",
        route_count: 2,
        safety_gate_state: "allowed",
        sensitive_sink_count: 1,
        source_ref: "artifact:repo_snapshot",
        status: "mapped",
      },
    ],
    facts: [
      {
        authz_hint: "owner_or_admin",
        campaign_id: "campaign_1",
        codebase_map_id: "codebase_map_1",
        created_at: "2026-07-05T00:00:00Z",
        fact_type: "route_handler",
        id: "codebase_fact_1",
        provenance_refs: ["codebase_map:route:1"],
        route_method: "GET",
        route_path: "/users/{id}",
        sensitivity_label: "low",
        source_path: "apps/api/users.py?token=secret-token",
        symbol_name: "get_user",
      },
    ],
    scanner_runs: [
      {
        campaign_id: "campaign_1",
        candidate_count: 2,
        codebase_map_id: "codebase_map_1",
        command_hash: "sha256:scanner-command",
        created_at: "2026-07-05T00:00:00Z",
        finding_count: 2,
        id: "scanner_run_1",
        safety_gate_state: "allowed",
        status: "candidate_findings",
        summary: "Static candidates only; Authorization: Bearer secret-token",
        tool_name: "semgrep",
      },
    ],
  });

  assert.equal(view.routeCount, 2);
  assert.equal(view.authzCheckCount, 1);
  assert.equal(view.candidateCount, 2);
  assert.equal(view.facts[0].sourcePath, "apps/api/users.py");
  assert.equal(view.scannerRuns[0].summary, "Static candidates only; Authorization=[redacted]");
  assert.doesNotMatch(JSON.stringify(view), /secret-token|token=secret|authorization: bearer/i);
});

test("campaign control page stays read-only with no execution entrypoints", async () => {
  const page = await import("node:fs/promises").then((fs) =>
    fs.readFile(new URL("../app/campaigns/page.tsx", import.meta.url), "utf8"),
  );

  assert.match(page, /getCampaigns/);
  assert.match(page, /\/campaigns\/\$\{encodeURIComponent\(campaign\.id\)\}/);
  assert.doesNotMatch(page, /getCampaignControlCenter/);
  assert.doesNotMatch(page, /startCampaign|resumeCampaign|pauseCampaign|executeValidation|submitReport/);
  assert.doesNotMatch(page, /<form|method="post"|action=\{/);
});

test("campaign detail page reads the audited control center and stays read-only", async () => {
  const page = await import("node:fs/promises").then((fs) =>
    fs.readFile(new URL("../app/campaigns/[campaignId]/page.tsx", import.meta.url), "utf8"),
  );

  assert.match(page, /params: Promise<\{ campaignId: string \}>/);
  assert.match(page, /getCampaignControlCenter\(campaignId, null\)/);
  assert.match(page, /\/campaigns\/\$\{encodeURIComponent\(campaignId\)\}\/tasks/);
  assert.match(page, /\/campaigns\/\$\{encodeURIComponent\(campaignId\)\}\/agent-runs/);
  assert.match(page, /\/campaigns\/\$\{encodeURIComponent\(campaignId\)\}\/codebase-map/);
  assert.match(page, /\/campaigns\/\$\{encodeURIComponent\(campaignId\)\}\/validation-queue/);
  assert.match(page, /\/campaigns\/\$\{encodeURIComponent\(campaignId\)\}\/timeline/);
  assert.match(page, /\/campaigns\/\$\{encodeURIComponent\(campaignId\)\}\/brain/);
  assert.match(page, /executionAllowed/);
  assert.match(page, /safeNextAction/);
  assert.doesNotMatch(page, /startCampaign|resumeCampaign|pauseCampaign|executeValidation|submitReport/);
  assert.doesNotMatch(page, /<form|method="post"|action=\{/);
});

test("campaign brain page reads program brain and stays advisory-only", async () => {
  const page = await import("node:fs/promises").then((fs) =>
    fs.readFile(new URL("../app/campaigns/[campaignId]/brain/page.tsx", import.meta.url), "utf8"),
  );

  assert.match(page, /params: Promise<\{ campaignId: string \}>/);
  assert.match(page, /getCampaignControlCenter\(campaignId, null\)/);
  assert.match(page, /getMythosBrainProgram/);
  assert.match(page, /toCampaignBrainSummary/);
  assert.match(page, /advisoryOnly/);
  assert.doesNotMatch(page, /startCampaign|resumeCampaign|pauseCampaign|executeValidation|submitReport|approveValidation/);
  assert.doesNotMatch(page, /<form|method="post"|action=\{/);
});

test("campaign codebase map page reads fact-layer records and stays read-only", async () => {
  const page = await import("node:fs/promises").then((fs) =>
    fs.readFile(new URL("../app/campaigns/[campaignId]/codebase-map/page.tsx", import.meta.url), "utf8"),
  );

  assert.match(page, /params: Promise<\{ campaignId: string \}>/);
  assert.match(page, /getCampaignCodebaseMap\(campaignId, emptyCampaignCodebaseMap\)/);
  assert.match(page, /toCampaignCodebaseMapView/);
  assert.doesNotMatch(page, /runScanner|startScan|executeScan|executeValidation|submitReport/);
  assert.doesNotMatch(page, /<form|method="post"|action=\{/);
});

test("campaign tasks page reads task records and stays read-only", async () => {
  const page = await import("node:fs/promises").then((fs) =>
    fs.readFile(new URL("../app/campaigns/[campaignId]/tasks/page.tsx", import.meta.url), "utf8"),
  );

  assert.match(page, /params: Promise<\{ campaignId: string \}>/);
  assert.match(page, /getCampaignTasks\(campaignId, \[\]\)/);
  assert.match(page, /toCampaignTaskSummaries/);
  assert.doesNotMatch(page, /dispatchTask|runTask|startCampaign|resumeCampaign|pauseCampaign|executeValidation|submitReport/);
  assert.doesNotMatch(page, /<form|method="post"|action=\{/);
});

test("campaign agent runs page reads audit records and stays read-only", async () => {
  const page = await import("node:fs/promises").then((fs) =>
    fs.readFile(new URL("../app/campaigns/[campaignId]/agent-runs/page.tsx", import.meta.url), "utf8"),
  );

  assert.match(page, /params: Promise<\{ campaignId: string \}>/);
  assert.match(page, /getCampaignAgentRuns\(campaignId, \[\]\)/);
  assert.match(page, /toCampaignAgentRunSummaries/);
  assert.doesNotMatch(page, /startCampaign|resumeCampaign|pauseCampaign|executeValidation|submitReport/);
  assert.doesNotMatch(page, /<form|method="post"|action=\{/);
});

test("campaign validation queue page reads approval records and stays read-only", async () => {
  const page = await import("node:fs/promises").then((fs) =>
    fs.readFile(new URL("../app/campaigns/[campaignId]/validation-queue/page.tsx", import.meta.url), "utf8"),
  );

  assert.match(page, /params: Promise<\{ campaignId: string \}>/);
  assert.match(page, /getCampaignApprovals\(campaignId, \[\]\)/);
  assert.match(page, /toCampaignValidationQueueSummaries/);
  assert.doesNotMatch(page, /decideApproval|approveValidation|denyValidation|executeValidation|submitReport/);
  assert.doesNotMatch(page, /<form|method="post"|action=\{/);
});

test("campaign timeline page reads pipeline stage records and stays read-only", async () => {
  const page = await import("node:fs/promises").then((fs) =>
    fs.readFile(new URL("../app/campaigns/[campaignId]/timeline/page.tsx", import.meta.url), "utf8"),
  );

  assert.match(page, /params: Promise<\{ campaignId: string \}>/);
  assert.match(page, /getCampaignPipelineStages\(campaignId, \[\]\)/);
  assert.match(page, /toCampaignTimelineSummaries/);
  assert.doesNotMatch(page, /startCampaign|resumeCampaign|pauseCampaign|executeValidation|submitReport/);
  assert.doesNotMatch(page, /<form|method="post"|action=\{/);
});
