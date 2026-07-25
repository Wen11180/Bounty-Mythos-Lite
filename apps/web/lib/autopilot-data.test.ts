import assert from "node:assert/strict";
import test from "node:test";

import {
  budgetMonitorRows,
  canDecideAutopilotApproval,
  classifyAutopilotAssetStatus,
  classifyAutopilotProjectionFreshness,
  emptyAutopilotProjection,
  formatAutopilotLabel,
  orderAutopilotTimeline,
  summarizeAutopilotProjection,
} from "./autopilot-data.ts";

test("empty projection is permanently submission blocked", () => {
  const projection = emptyAutopilotProjection("camp_1");
  assert.equal(projection.report_submission_allowed, false);
  assert.equal(projection.candidate_promotion_allowed, false);
  assert.equal(projection.submission_blocked, true);
  assert.match(summarizeAutopilotProjection(projection), /没有可执行的分支/);
  assert.equal(projection.budgets.budget_ledger_valid, true);
});

test("summary reflects emergency stop", () => {
  const projection = emptyAutopilotProjection("camp_1");
  projection.emergency_stopped = true;
  assert.match(summarizeAutopilotProjection(projection), /紧急停止/);
});

test("asset map classifies admitted and review states", () => {
  assert.equal(classifyAutopilotAssetStatus("admitted"), "admitted");
  assert.equal(classifyAutopilotAssetStatus("needs-review"), "review_required");
  assert.equal(classifyAutopilotAssetStatus("weird"), "unknown");
});

test("autopilot statuses have Chinese display labels", () => {
  assert.equal(formatAutopilotLabel("active"), "生效中");
  assert.equal(formatAutopilotLabel("awaiting_r3"), "等待 R3 审批");
  assert.equal(formatAutopilotLabel("unmapped_status"), "未知");
});

test("timeline keeps stable plan→report ordering on equal timestamps", () => {
  const ordered = orderAutopilotTimeline([
    { event_id: "e2", kind: "report", created_at: "2026-01-01T00:00:00Z" },
    { event_id: "e1", kind: "plan", created_at: "2026-01-01T00:00:00Z" },
    { event_id: "e0", kind: "lease", created_at: "2026-01-01T00:00:00Z" },
  ]);
  assert.deepEqual(
    ordered.map((item) => item.event_id),
    ["e1", "e0", "e2"],
  );
});

test("approval inbox blocks R4, consumed, and expired decisions", () => {
  assert.equal(canDecideAutopilotApproval({ status: "pending", risk_tier: "R4" }).allowed, false);
  assert.equal(
    canDecideAutopilotApproval({ status: "pending", consumed: true }).allowed,
    false,
  );
  assert.equal(
    canDecideAutopilotApproval({ status: "pending", expired: true }).allowed,
    false,
  );
  assert.equal(canDecideAutopilotApproval({ status: "pending" }).allowed, true);
});

test("budget monitor exposes remaining counters", () => {
  const rows = budgetMonitorRows({
    budget_ledger_valid: true,
    campaign_max_requests: 10,
    campaign_requests_used: 3,
    campaign_requests_remaining: 7,
    campaign_max_duration_seconds: 60,
    campaign_duration_reserved_seconds: 20,
    campaign_duration_remaining_seconds: 40,
    campaign_max_cost_units: 10,
    campaign_cost_units_reserved: 3,
    campaign_cost_units_remaining: 7,
    active_leases: 1,
    reserved_requests: 0,
    completed_requests: 2,
    open_approvals: 1,
  });
  assert.equal(rows.length, 7);
  assert.match(rows[0].value, /3\/10/);
});

test("invalid budget ledger blocks the displayed next work", () => {
  const projection = emptyAutopilotProjection("camp_1");
  projection.next_branch_id = "branch_legacy";
  projection.next_reason = "highest_priority_eligible";
  projection.budgets.budget_ledger_valid = false;
  assert.equal(projection.budgets.budget_ledger_valid, false);
  assert.match(summarizeAutopilotProjection(projection), /执行已阻断/);
  assert.equal(budgetMonitorRows(projection.budgets)[0].label, "账本状态");
});

test("autopilot projection freshness fails closed for missing, malformed, and old timestamps", () => {
  const now = Date.parse("2026-07-25T00:00:00Z");
  const projection = emptyAutopilotProjection("camp_1");
  assert.equal(classifyAutopilotProjectionFreshness(projection, now), "stale");
  projection.projection_generated_at = "not-a-date";
  assert.equal(classifyAutopilotProjectionFreshness(projection, now), "stale");
  projection.projection_generated_at = "2026-07-24T23:55:00Z";
  assert.equal(classifyAutopilotProjectionFreshness(projection, now), "stale");
  projection.projection_generated_at = "2026-07-24T23:59:30Z";
  assert.equal(classifyAutopilotProjectionFreshness(projection, now), "fresh");
});
