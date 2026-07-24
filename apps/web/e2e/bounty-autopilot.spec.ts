import { expect, test, type Page } from "@playwright/test";

const mockApiPort = Number(process.env.E2E_MOCK_API_PORT ?? 46087);

type MockState = {
  approvalDecisionBodies: Array<Record<string, unknown>>;
  approvalStatus: "approved" | "pending";
  emergencyCommitBodies: Array<Record<string, unknown>>;
  emergencyPrepareBodies: Array<Record<string, unknown>>;
  steeringBodies: Array<Record<string, unknown>>;
  stopped: boolean;
};

function autopilotProjection(state: MockState) {
  return {
    campaign_id: "camp_lab",
    campaign_mode: "bounty_autopilot",
    emergency_stopped: state.stopped,
    authorization_digest: `sha256:${"a".repeat(64)}`,
    scope_snapshot_digest: `sha256:${"b".repeat(64)}`,
    policy_mode: "authorized_local_lab",
    next_branch_id: state.stopped ? null : "branch_authz",
    next_reason: state.stopped ? "emergency_stopped" : "highest_priority_eligible",
    budgets: {
      campaign_max_requests: 10,
      campaign_requests_used: 1,
      campaign_requests_remaining: 9,
      active_leases: state.stopped ? 0 : 1,
      reserved_requests: 0,
      completed_requests: 1,
      open_approvals: state.approvalStatus === "pending" ? 1 : 0,
      asset_requests_remaining: 7,
      account_requests_remaining: 4,
      branch_requests_remaining: 6,
      hypothesis_requests_remaining: 5,
      recipe_requests_remaining: 8,
      request_slots_remaining: 9,
      time_seconds_remaining: 120,
      retry_attempts_remaining: 2,
      model_cost_units_remaining: 12,
    },
    assets: [
      {
        asset_id: "asset_lab",
        alias: "owned-lab-api",
        status: "admitted",
        host: "lab.example.test",
        scheme: "https",
        port: 443,
        admitted: true,
      },
    ],
    branches: [
      {
        branch_id: "branch_authz",
        asset_id: "asset_lab",
        status: "queued",
        priority: 50,
        risk_tier: "R1",
        reason: "highest_value_owned_account_check",
        dependencies: ["branch_mapper"],
        handoff_from: "mapper",
        handoff_to: "validator",
        specialist: "authorization-reviewer",
        queue_rank: 1,
      },
    ],
    approvals: [
      {
        approval_id: "approval_r3",
        consumed: state.approvalStatus === "approved",
        exact_diff: [{ field: "method", before: "GET", after: "POST" }],
        expired: false,
        expires_at: new Date(Date.now() + 60_000).toISOString(),
        plan_changed: false,
        plan_digest: `sha256:${"c".repeat(64)}`,
        risk_tier: "R3",
        status: state.approvalStatus,
      },
    ],
    events: [
      {
        created_at: "2026-07-24T00:00:00Z",
        event_id: "plan:plan_1",
        kind: "plan",
        refs: { branch_id: "branch_authz", plan_id: "plan_1" },
        summary: "plan plan_1 pending review",
      },
    ],
    candidate_promotion_allowed: false,
    report_submission_allowed: false,
    submission_blocked: true,
  };
}

async function installAutopilotApi(page: Page): Promise<MockState> {
  const state: MockState = {
    approvalDecisionBodies: [],
    approvalStatus: "pending",
    emergencyCommitBodies: [],
    emergencyPrepareBodies: [],
    steeringBodies: [],
    stopped: false,
  };
  const corsHeaders = {
    "Access-Control-Allow-Headers": "Content-Type",
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Access-Control-Allow-Origin": "*",
    "Cache-Control": "no-cache",
  };

  await page.route(`http://127.0.0.1:${mockApiPort}/**`, async (route) => {
    const request = route.request();
    const url = new URL(request.url());
    if (request.method() === "OPTIONS") {
      await route.fulfill({ headers: corsHeaders, status: 204 });
      return;
    }
    if (url.pathname === "/mythos/control-center/events") {
      await route.fulfill({
        body:
          "event: control-center-invalidated\n" +
          `id: ${"d".repeat(64)}\n` +
          "retry: 5000\n" +
          `data: {"snapshot_version":"${"d".repeat(64)}","scope":"campaign","changed":["autopilot"]}\n\n`,
        headers: {
          ...corsHeaders,
          "Content-Type": "text/event-stream",
          "X-Accel-Buffering": "no",
        },
        status: 200,
      });
      return;
    }
    if (
      url.pathname === "/mythos/campaigns/camp_lab/autopilot" &&
      request.method() === "GET"
    ) {
      await route.fulfill({
        body: JSON.stringify(autopilotProjection(state)),
        headers: { ...corsHeaders, "Content-Type": "application/json" },
        status: 200,
      });
      return;
    }
    if (
      url.pathname === "/mythos/campaigns/camp_lab/autopilot/steering" &&
      request.method() === "POST"
    ) {
      state.steeringBodies.push(request.postDataJSON() as Record<string, unknown>);
      await route.fulfill({
        body: JSON.stringify({
          candidate_promotion_allowed: false,
          report_submission_allowed: false,
          submission_blocked: true,
        }),
        headers: { ...corsHeaders, "Content-Type": "application/json" },
        status: 200,
      });
      return;
    }
    if (
      url.pathname ===
        "/mythos/campaigns/camp_lab/autopilot/approvals/approval_r3/decision" &&
      request.method() === "POST"
    ) {
      state.approvalDecisionBodies.push(
        request.postDataJSON() as Record<string, unknown>,
      );
      state.approvalStatus = "approved";
      await route.fulfill({
        body: JSON.stringify({
          candidate_promotion_allowed: false,
          report_submission_allowed: false,
          submission_blocked: true,
          status: "approved",
        }),
        headers: { ...corsHeaders, "Content-Type": "application/json" },
        status: 200,
      });
      return;
    }
    if (
      url.pathname ===
        "/mythos/campaigns/camp_lab/autopilot/emergency-stop/prepare" &&
      request.method() === "POST"
    ) {
      state.emergencyPrepareBodies.push(
        request.postDataJSON() as Record<string, unknown>,
      );
      await route.fulfill({
        body: JSON.stringify({
          confirmation_nonce: "stop-confirmation-nonce-1",
          expires_at: new Date(Date.now() + 60_000).toISOString(),
        }),
        headers: { ...corsHeaders, "Content-Type": "application/json" },
        status: 200,
      });
      return;
    }
    if (
      url.pathname === "/mythos/campaigns/camp_lab/autopilot/emergency-stop" &&
      request.method() === "POST"
    ) {
      const body = request.postDataJSON() as Record<string, unknown>;
      state.emergencyCommitBodies.push(body);
      if (body.confirmation_nonce !== "stop-confirmation-nonce-1") {
        await route.fulfill({
          body: JSON.stringify({ detail: "invalid_confirmation_nonce" }),
          headers: { ...corsHeaders, "Content-Type": "application/json" },
          status: 409,
        });
        return;
      }
      state.stopped = true;
      await route.fulfill({
        body: JSON.stringify({
          active_leases: 0,
          emergency_stopped: true,
          report_submission_allowed: false,
          revoked_leases: 1,
        }),
        headers: { ...corsHeaders, "Content-Type": "application/json" },
        status: 200,
      });
      return;
    }
    await route.fulfill({
      body: JSON.stringify({ detail: "not_found" }),
      headers: { ...corsHeaders, "Content-Type": "application/json" },
      status: 404,
    });
  });
  return state;
}

test("routed autopilot workspace enforces bounded commands and confirmed stop", async ({
  page,
}) => {
  await page.addInitScript(() => {
    const localStops: Array<Record<string, unknown>> = [];
    Object.assign(window, {
      __autopilotLocalStops: localStops,
      mythosStudio: {
        async emergencyStopAutopilotLocal(payload: Record<string, unknown>) {
          localStops.push(payload);
          return { revoked: true, revokedHandles: 2 };
        },
      },
    });
  });
  const state = await installAutopilotApi(page);
  await page.goto("/campaigns/camp_lab/autopilot");

  await expect(page.getByTestId("autopilot-panel")).toBeVisible();
  await expect(page.getByTestId("autopilot-submission-blocked")).toHaveText("blocked");
  await expect(page.getByTestId("autopilot-exact-diff-approval_r3")).toContainText(
    "method",
  );
  await expect(page.getByTestId("autopilot-exact-diff-approval_r3")).toContainText("GET");
  await expect(page.getByTestId("autopilot-exact-diff-approval_r3")).toContainText("POST");

  await page.getByTestId("autopilot-priority-branch_authz").click();
  await expect.poll(() => state.steeringBodies.length).toBe(1);
  expect(state.steeringBodies[0]).toEqual({
    branch_id: "branch_authz",
    directive: "set_priority",
    priority: 60,
    reason: "operator_priority",
  });
  expect(JSON.stringify(state.steeringBodies[0])).not.toMatch(
    /admitted_asset_ids|branches|budgets|campaign_max|policy|recipe|risk_tier|scope/,
  );

  await page.getByTestId("autopilot-guidance-input").fill("Compare owned account A and B.");
  await page.getByTestId("autopilot-guidance-submit").click();
  await expect.poll(() => state.steeringBodies.length).toBe(2);
  expect(state.steeringBodies[1]).toEqual({
    branch_id: "branch_authz",
    directive: "add_hypothesis_guidance",
    hypothesis_guidance: "Compare owned account A and B.",
    reason: "operator_hypothesis_guidance",
  });

  await page.getByTestId("autopilot-approval-approval_r3-approve").click();
  await expect.poll(() => state.approvalDecisionBodies.length).toBe(1);
  expect(state.approvalDecisionBodies[0]).toEqual({
    actor: "operator",
    decision: "approved",
    reason: "operator_r3_decision",
  });

  await page.getByTestId("autopilot-emergency-stop").click();
  await expect.poll(() => state.emergencyPrepareBodies.length).toBe(1);
  await expect(page.getByTestId("autopilot-emergency-stop-confirmation")).toBeVisible();
  expect(state.emergencyCommitBodies).toHaveLength(0);
  await page.getByTestId("autopilot-emergency-stop-cancel").click();
  await expect(page.getByTestId("autopilot-emergency-stop-confirmation")).toHaveCount(0);
  expect(state.emergencyCommitBodies).toHaveLength(0);

  await page.getByTestId("autopilot-emergency-stop").click();
  await expect.poll(() => state.emergencyPrepareBodies.length).toBe(2);
  await page.getByTestId("autopilot-emergency-stop-confirm").click();
  await expect.poll(() => state.emergencyCommitBodies.length).toBe(1);
  expect(state.emergencyCommitBodies[0]).toEqual({
    actor: "operator",
    confirmation_nonce: "stop-confirmation-nonce-1",
    reason: "operator_emergency_stop",
  });
  await expect.poll(() =>
    page.evaluate(() =>
      (window as unknown as { __autopilotLocalStops: unknown[] })
        .__autopilotLocalStops,
    )
  ).toEqual([{ campaignId: "camp_lab" }]);
  await expect(page.getByTestId("autopilot-active-leases")).toHaveText("0");
  await expect(page.getByTestId("autopilot-summary")).toContainText("all leases revoked");
});

test("mobile routed workspace keeps stop and approval state visible", async ({ page }) => {
  await page.setViewportSize({ height: 844, width: 390 });
  await installAutopilotApi(page);
  await page.goto("/campaigns/camp_lab/autopilot");

  await expect(page.getByTestId("autopilot-emergency-stop")).toBeVisible();
  await expect(page.getByTestId("autopilot-approval-approval_r3")).toBeVisible();
  await expect(page.getByTestId("autopilot-exact-diff-approval_r3")).toContainText("GET");
});
