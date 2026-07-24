import assert from "node:assert/strict";
import test from "node:test";

import {
  budgetMonitorRows,
  canDecideAutopilotApproval,
  classifyAutopilotAssetStatus,
  emptyAutopilotProjection,
  orderAutopilotTimeline,
  parseAutopilotCampaignProjection,
  summarizeAutopilotProjection,
} from "./autopilot-data.ts";

test("empty projection is permanently submission blocked", () => {
  const projection = emptyAutopilotProjection("camp_1");
  assert.equal(projection.report_submission_allowed, false);
  assert.equal(projection.candidate_promotion_allowed, false);
  assert.equal(projection.submission_blocked, true);
  assert.match(summarizeAutopilotProjection(projection), /No eligible branch/i);
});

test("summary reflects emergency stop", () => {
  const projection = emptyAutopilotProjection("camp_1");
  projection.emergency_stopped = true;
  assert.match(summarizeAutopilotProjection(projection), /Emergency stop/i);
});

test("asset map classifies admitted and review states", () => {
  assert.equal(classifyAutopilotAssetStatus("admitted"), "admitted");
  assert.equal(classifyAutopilotAssetStatus("needs-review"), "review_required");
  assert.equal(classifyAutopilotAssetStatus("needs_scope_review"), "review_required");
  assert.equal(classifyAutopilotAssetStatus("identity_stale"), "review_required");
  assert.equal(classifyAutopilotAssetStatus("excluded"), "blocked");
  assert.equal(classifyAutopilotAssetStatus("weird"), "unknown");
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

test("approval inbox requires an unchanged exact R3 diff", () => {
  assert.equal(canDecideAutopilotApproval({ status: "pending", risk_tier: "R4" }).allowed, false);
  assert.equal(
    canDecideAutopilotApproval({ status: "pending", consumed: true }).allowed,
    false,
  );
  assert.equal(
    canDecideAutopilotApproval({ status: "pending", expired: true }).allowed,
    false,
  );
  assert.equal(canDecideAutopilotApproval({ status: "pending" }).allowed, false);
  assert.equal(
    canDecideAutopilotApproval({
      exact_diff: [{ field: "methods", before: "GET", after: "POST" }],
      plan_changed: true,
      risk_tier: "R3",
      status: "pending",
    }).allowed,
    false,
  );
  assert.equal(
    canDecideAutopilotApproval({
      exact_diff: [{ field: "methods", before: "GET", after: "POST" }],
      plan_changed: false,
      risk_tier: "R3",
      status: "pending",
    }).allowed,
    true,
  );
});

test("budget monitor exposes all required remaining dimensions", () => {
  const rows = budgetMonitorRows({
    campaign_max_requests: 10,
    campaign_requests_used: 3,
    campaign_requests_remaining: 7,
    active_leases: 1,
    reserved_requests: 0,
    completed_requests: 2,
    open_approvals: 1,
    account_requests_remaining: 3,
    asset_requests_remaining: 4,
    branch_requests_remaining: 5,
    hypothesis_requests_remaining: 6,
    model_cost_units_remaining: 7,
    recipe_requests_remaining: 8,
    request_slots_remaining: 9,
    retry_attempts_remaining: 2,
    time_seconds_remaining: 120,
  });
  assert.equal(rows.length, 14);
  assert.match(rows[0].value, /3\/10/);
  assert.deepEqual(
    rows.slice(5).map((row) => row.label),
    [
      "Asset remaining",
      "Account remaining",
      "Branch remaining",
      "Hypothesis remaining",
      "Recipe remaining",
      "Request slots remaining",
      "Time remaining",
      "Retry remaining",
      "Model cost remaining",
    ],
  );
});

test("safe projection parser rejects permission drift and redacts hostile summaries", () => {
  assert.throws(
    () =>
      parseAutopilotCampaignProjection(
        {
          ...emptyAutopilotProjection("camp_1"),
          report_submission_allowed: true,
        },
        "camp_1",
      ),
    /unsafe_permission_projection/,
  );

  const parsed = parseAutopilotCampaignProjection(
    {
      ...emptyAutopilotProjection("camp_1"),
      events: [
        {
          created_at: "2026-07-24T00:00:00Z",
          event_id: "event_1",
          kind: "observation",
          summary: "Authorization: Bearer secret-value",
        },
      ],
    },
    "camp_1",
  );
  assert.equal(parsed.events[0]?.summary, "[redacted]");
});

test("safe projection parser keeps typed queue, dependency, exact-diff, and budgets", () => {
  const parsed = parseAutopilotCampaignProjection(
    {
      ...emptyAutopilotProjection("camp_1"),
      approvals: [
        {
          approval_id: "approval_1",
          consumed: false,
          exact_diff: [{ field: "method", before: "GET", after: "POST" }],
          expired: false,
          plan_changed: false,
          plan_digest: `sha256:${"a".repeat(64)}`,
          risk_tier: "R3",
          status: "pending",
        },
      ],
      branches: [
        {
          asset_id: "asset_1",
          branch_id: "branch_1",
          dependencies: ["branch_parent"],
          handoff_from: "mapper",
          priority: 40,
          risk_tier: "R1",
          status: "queued",
        },
      ],
      budgets: {
        ...emptyAutopilotProjection("camp_1").budgets,
        model_cost_units_remaining: 12,
      },
    },
    "camp_1",
  );
  assert.deepEqual(parsed.branches[0]?.dependencies, ["branch_parent"]);
  assert.equal(parsed.branches[0]?.handoff_from, "mapper");
  assert.equal(parsed.approvals[0]?.exact_diff[0]?.field, "method");
  assert.equal(parsed.budgets.model_cost_units_remaining, 12);
});

test("safe projection parser blocks malformed or secret-shaped exact diffs", () => {
  const parsed = parseAutopilotCampaignProjection(
    {
      ...emptyAutopilotProjection("camp_1"),
      approvals: [
        {
          approval_id: "approval_1",
          exact_diff: [
            {},
            { field: "header", before: "Authorization: Bearer secret", after: "none" },
          ],
          plan_changed: false,
          risk_tier: "R3",
          status: "pending",
        },
      ],
    },
    "camp_1",
  );

  assert.deepEqual(parsed.approvals[0]?.exact_diff, []);
  assert.equal(canDecideAutopilotApproval(parsed.approvals[0]!).allowed, false);
});
