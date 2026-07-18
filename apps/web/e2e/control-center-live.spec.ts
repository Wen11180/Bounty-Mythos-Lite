import { expect, test } from "@playwright/test";

const mockApiPort = Number(process.env.E2E_MOCK_API_PORT ?? 46087);

test("control center refetches after a safe SSE invalidation without navigation", async ({
  page,
}) => {
  let eventReads = 0;
  let overviewReads = 0;

  await page.route(`http://127.0.0.1:${mockApiPort}/**`, async (route) => {
    const url = new URL(route.request().url());
    const corsHeaders = {
      "Access-Control-Allow-Origin": "*",
      "Cache-Control": "no-cache",
    };
    if (url.pathname === "/mythos/control-center/events") {
      eventReads += 1;
      await route.fulfill({
        body:
          "event: control-center-invalidated\n" +
          `id: ${"e".repeat(64)}\n` +
          "retry: 5000\n" +
          `data: {"snapshot_version":"${"e".repeat(64)}","scope":"global","changed":["overview"]}\n\n`,
        headers: {
          ...corsHeaders,
          "Content-Type": "text/event-stream",
          "X-Accel-Buffering": "no",
        },
        status: 200,
      });
      return;
    }
    if (url.pathname === "/mythos/control-center/overview") {
      overviewReads += 1;
      await route.fulfill({
        body: JSON.stringify({
          agent_stages: [],
          authorized_assets: [],
          campaigns: [],
          candidates: [],
          data_mode: "live",
          empty_state: true,
          generated_at: new Date().toISOString(),
          metrics: {
            approval_pressure_count: 1,
            retained_high_value_candidate_count: 3,
            running_task_count: 7,
            safety_block_count: 2,
          },
          recent_events: [],
          report_readiness: {
            available: false,
            human_review_required: true,
            report_submission_allowed: false,
            status: "unavailable",
            submission_blocked: true,
          },
          research_quality: {
            evidence_completeness: null,
            median_human_review_seconds: null,
            refutation_kill_rate: null,
            retention_rate: null,
          },
          snapshot_version: "e".repeat(64),
        }),
        headers: { ...corsHeaders, "Content-Type": "application/json" },
        status: 200,
      });
      return;
    }
    await route.fulfill({ body: "not found", status: 404 });
  });

  await page.goto("/");
  await page.evaluate(() => {
    (window as Window & { controlCenterNavigationMarker?: string })
      .controlCenterNavigationMarker = "same-document";
  });

  await expect(page.getByTestId("control-center-live-state")).toHaveAttribute(
    "data-state",
    "live",
  );
  await expect(page.getByText("7", { exact: true })).toBeVisible();
  await expect.poll(() => eventReads).toBeGreaterThan(0);
  await expect.poll(() => overviewReads).toBeGreaterThan(0);
  await expect(
    page.getByText("系统没有回退到演示数据。", { exact: false }),
  ).toHaveCount(0);
  await expect
    .poll(() =>
      page.evaluate(
        () =>
          (window as Window & { controlCenterNavigationMarker?: string })
            .controlCenterNavigationMarker,
      ),
    )
    .toBe("same-document");
});
