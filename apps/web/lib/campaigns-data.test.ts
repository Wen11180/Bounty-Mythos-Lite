import assert from "node:assert/strict";
import test from "node:test";
import {
  toCampaignAgentRunSummaries,
  toCampaignControlSummary,
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
  assert.match(page, /\/campaigns\/\$\{encodeURIComponent\(campaignId\)\}\/agent-runs/);
  assert.match(page, /\/campaigns\/\$\{encodeURIComponent\(campaignId\)\}\/validation-queue/);
  assert.match(page, /executionAllowed/);
  assert.match(page, /safeNextAction/);
  assert.doesNotMatch(page, /startCampaign|resumeCampaign|pauseCampaign|executeValidation|submitReport/);
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
