import { expect, test } from "@playwright/test";

const mockApiPort = Number(process.env.E2E_MOCK_API_PORT ?? 46087);

test("routed autopilot workspace retains LKG projection after refresh failure", async ({
  page,
}) => {
  let projectionReads = 0;
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
          `id: ${"e".repeat(64)}\n` +
          "retry: 5000\n" +
          `data: {"snapshot_version":"${"e".repeat(64)}","scope":"campaign","changed":["autopilot"]}\n\n`,
        headers: { ...corsHeaders, "Content-Type": "text/event-stream" },
        status: 200,
      });
      return;
    }
    if (
      url.pathname === "/mythos/campaigns/camp_lab/autopilot" &&
      request.method() === "GET"
    ) {
      projectionReads += 1;
      if (projectionReads > 1) {
        await route.fulfill({
          body: JSON.stringify({ detail: "projection_temporarily_unavailable" }),
          headers: { ...corsHeaders, "Content-Type": "application/json" },
          status: 503,
        });
        return;
      }
      await route.fulfill({
        body: JSON.stringify({
          campaign_id: "camp_lab",
          campaign_mode: "bounty_autopilot",
          emergency_stopped: false,
          authorization_digest: null,
          scope_snapshot_digest: null,
          policy_mode: "authorized_local_lab",
          next_branch_id: "branch_lkg",
          next_reason: "highest_priority_eligible",
          budgets: {
            campaign_max_requests: 5,
            campaign_requests_used: 1,
            campaign_requests_remaining: 4,
            active_leases: 0,
            reserved_requests: 0,
            completed_requests: 1,
            open_approvals: 0,
          },
          assets: [],
          branches: [
            {
              asset_id: "asset_lab",
              branch_id: "branch_lkg",
              dependencies: [],
              priority: 40,
              risk_tier: "R1",
              status: "queued",
            },
          ],
          approvals: [],
          events: [],
          candidate_promotion_allowed: false,
          report_submission_allowed: false,
          submission_blocked: true,
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

  await page.goto("/campaigns/camp_lab/autopilot");
  await expect(page.getByTestId("autopilot-summary")).toContainText("branch_lkg");
  await expect.poll(() => projectionReads).toBeGreaterThan(1);
  await expect(page.getByTestId("autopilot-error")).toContainText("last known good");
  await expect(page.getByTestId("autopilot-summary")).toContainText("branch_lkg");
});
