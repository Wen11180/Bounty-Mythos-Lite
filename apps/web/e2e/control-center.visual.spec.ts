import { expect, test, type Locator, type Page, type TestInfo } from "@playwright/test";

const fixedSnapshotVersion = "a".repeat(64);

const controlCenterOverview = {
  agent_stages: [
    { record_count: 3, stage: "policy", status: "completed" },
    { record_count: 2, stage: "target_modeling", status: "completed" },
    { record_count: 4, stage: "code_api_audit", status: "running" },
    { record_count: 2, stage: "refutation", status: "waiting" },
    { record_count: 1, stage: "report_drafting", status: "approval_required" },
  ],
  authorized_assets: [
    {
      asset: "api.local.test",
      campaign_id: "campaign_visual",
      campaign_status: "running",
      scope_status: "in_scope",
    },
  ],
  campaigns: [
    {
      blocked_reasons: [],
      id: "campaign_visual",
      name: "视觉回归授权研究",
      safe_next_action: "审查候选证据和批准状态",
      scope_status: "in_scope",
      status: "running",
    },
  ],
  candidates: [
    {
      affected_code_path: "src/routes/records.ts:42",
      affected_endpoint: "GET /records/{record}",
      candidate_id: "candidate_visual",
      campaign_id: "campaign_visual",
      evidence_trace_status: "needs_evidence",
      human_validation_readiness: "approval_required",
      pipeline_run_id: "pipeline_visual",
      rank: 1,
      report_submission_allowed: false,
      vuln_type: "越权访问候选（IDOR）",
    },
  ],
  data_mode: "live",
  empty_state: false,
  generated_at: "2099-01-01T00:00:00Z",
  metrics: {
    approval_pressure_count: 2,
    retained_high_value_candidate_count: 3,
    running_task_count: 7,
    safety_block_count: 1,
  },
  recent_events: [
    {
      campaign_id: "campaign_visual",
      event_id: "event_visual",
      event_type: "research_task",
      occurred_at: "2099-01-01T00:00:00Z",
      status: "running",
    },
  ],
  report_readiness: {
    available: true,
    claim_count: 3,
    evidence_ref_count: 2,
    human_review_required: true,
    pipeline_run_id: "pipeline_visual",
    report_submission_allowed: false,
    status: "approval_required",
    submission_blocked: true,
    title: "视觉回归报告草稿",
  },
  research_quality: {
    evidence_completeness: 0.76,
    median_human_review_seconds: 5400,
    refutation_kill_rate: 0.42,
    retention_rate: 0.58,
  },
  snapshot_version: fixedSnapshotVersion,
};

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Cache-Control": "no-cache",
};

async function disableMotion(page: Page) {
  await page.emulateMedia({ reducedMotion: "reduce" });
  await page.addStyleTag({
    content: "*,*::before,*::after{animation-duration:0.001ms!important;animation-delay:0ms!important;transition-duration:0.001ms!important;scroll-behavior:auto!important;caret-color:transparent!important}",
  });
}

async function mockControlCenter(page: Page) {
  await page.route("**/mythos/control-center/overview**", async (route) => {
    await route.fulfill({
      headers: { ...corsHeaders, "Content-Type": "application/json" },
      json: controlCenterOverview,
      status: 200,
    });
  });
  await page.route("**/mythos/control-center/events**", async (route) => {
    await route.fulfill({
      body: ": visual keepalive\n\n",
      headers: { ...corsHeaders, "Content-Type": "text/event-stream" },
      status: 200,
    });
  });
}

async function mockStudio(page: Page) {
  await page.addInitScript(() => {
    window.mythosStudio = {
      closeBlackBoxSessions: async () => JSON.stringify({ event: "sessions_closed" }),
      createBlackBoxSessions: async () => JSON.stringify({ event: "sessions_created" }),
      refreshProgramRules: async () => ({ next_due_at: null, processed: false, status: "idle" }),
      runBlackBoxTrial: async () => JSON.stringify({ event: "trial_complete" }),
      selectDirectory: async () => "C:/authorized/visual-workspace",
      selectFile: async () => "C:/authorized/visual-policy.yaml",
      startBlackBoxRecording: async () => JSON.stringify({ event: "recording_started" }),
      stopBlackBoxRecording: async () => JSON.stringify({ event: "recording_stopped", traces: [] }),
    };
  });
  await page.route("**/mythos/control-center/events**", async (route) => {
    await route.fulfill({
      body: ": visual keepalive\n\n",
      headers: { ...corsHeaders, "Content-Type": "text/event-stream" },
      status: 200,
    });
  });
  await page.route("**/mythos/studio/black-box-remote/status", async (route) => {
    await route.fulfill({
      headers: { ...corsHeaders, "Content-Type": "application/json" },
      json: {
        enabled: false,
        expires_at: null,
        human_confirmation_allowed: false,
        profile: "remote_human_lease",
        relogin_required: true,
        report_submission_allowed: false,
        state: "relogin_required",
        stop_reason: "relogin_required",
      },
      status: 200,
    });
  });
  await page.route("**/mythos/studio/workspaces/manifest**", async (route) => {
    await route.fulfill({
      headers: { ...corsHeaders, "Content-Type": "application/json" },
      json: {
        artifacts: [
          { kind: "policy", source_path: "policy.yaml" },
          { kind: "scope", source_path: "scope.yaml" },
          { kind: "code", source_path: "src" },
          { kind: "api", source_path: "openapi.json" },
          { kind: "har", source_path: "safe.har" },
        ],
        name: "视觉回归研究工作区",
        runs: [{ recorded_at: "2099-01-01T00:00:00Z", run_id: "visual-run", status: "review" }],
        safety: {
          blocked_actions: ["execute_live_validation", "submit_report"],
          scope_guard_status: "in_scope",
        },
      },
      status: 200,
    });
  });
  await page.route("**/mythos/studio/workspaces/candidates**", async (route) => {
    await route.fulfill({
      headers: { ...corsHeaders, "Content-Type": "application/json" },
      json: {
        candidates: [
          {
            affected_code_path: "src/routes/records.ts:42",
            affected_endpoint: "GET /records/{record}",
            evidence_needed: ["所有权守卫的本地代码路径"],
            false_positive_checks: ["确认中间件是否统一执行对象授权"],
            hypothesis_id: "H-VISUAL-001",
            location: "GET /records/{record}",
            priority_score: 91,
            reason: "对象所有权校验尚未在敏感读取前得到证明。",
            report_readiness: { status: "needs_evidence", submission_blocked: true },
            risk: "high",
            safe_validation_plan: ["在隔离 local-lab 中使用两个别名账户比较状态类别"],
            safe_verification: true,
            vuln_type: "越权访问候选（IDOR）",
          },
        ],
        run_id: "visual-run",
      },
      status: 200,
    });
  });
  await page.route("**/mythos/studio/workspaces/mission**", async (route) => {
    await route.fulfill({
      headers: { ...corsHeaders, "Content-Type": "application/json" },
      json: {
        artifacts: { present: ["policy", "scope", "code", "api", "har"], required: ["policy", "scope", "code", "api", "har"] },
        blocked_actions: ["execute_live_validation", "submit_report"],
        candidate_count: 1,
        gates: { submission_blocked: true, validation_execution_allowed: false },
        mode: "live",
        research_loop_stages: [
          { key: "policy", status: "complete", summary: "范围守卫 已审查" },
          { key: "audit", status: "needs_review", summary: "候选需要人工证据审查" },
        ],
        run_id: "visual-run",
        scope_guard_status: "in_scope",
      },
      status: 200,
    });
  });
}

function viewportFor(testInfo: TestInfo) {
  const viewport = testInfo.project.use.viewport;
  if (!viewport) {
    throw new Error("Visual project viewport is required.");
  }
  return viewport;
}

async function expectNoHorizontalOverflow(page: Page) {
  await expect.poll(async () => {
    return page.evaluate(() => ({
      scrollWidth: document.documentElement.scrollWidth,
      viewportWidth: document.documentElement.clientWidth,
    }));
  }).toEqual({
    scrollWidth: await page.evaluate(() => document.documentElement.clientWidth),
    viewportWidth: await page.evaluate(() => document.documentElement.clientWidth),
  });
}

async function expectInViewport(locator: Locator) {
  const box = await locator.boundingBox();
  expect(box).not.toBeNull();
  expect(box!.y).toBeLessThan(await locator.evaluate(() => window.innerHeight));
  expect(box!.y + box!.height).toBeGreaterThan(0);
}

async function expectCanvasPixels(canvas: Locator) {
  expect(
    await canvas.evaluate((element) => {
      const drawing = element as HTMLCanvasElement;
      const context = drawing.getContext("2d");
      if (!context || drawing.width === 0 || drawing.height === 0) {
        return 0;
      }
      const pixels = context.getImageData(0, 0, drawing.width, drawing.height).data;
      let opaquePixels = 0;
      for (let index = 3; index < pixels.length; index += 4) {
        if (pixels[index] > 16) {
          opaquePixels += 1;
        }
      }
      return opaquePixels;
    }),
  ).toBeGreaterThan(100);
}

async function expectInspectorTabsToFit(page: Page) {
  const tabs = page.getByRole("tab").filter({ hasText: /候选详情|证据|验证计划|报告草稿/ });
  const measurements = await tabs.evaluateAll((elements) =>
    elements
      .filter((element) => element.checkVisibility())
      .map((element) => {
        const rect = element.getBoundingClientRect();
        return {
          clientWidth: (element as HTMLElement).clientWidth,
          display: window.getComputedStyle(element.parentElement!).display,
          left: Math.round(rect.left),
          right: Math.round(rect.right),
          scrollWidth: (element as HTMLElement).scrollWidth,
          text: element.textContent,
          width: Math.round(rect.width),
        };
      }),
  );
  expect(measurements, JSON.stringify(measurements)).toHaveLength(4);
  for (const measurement of measurements) {
    expect(measurement.scrollWidth, JSON.stringify(measurements)).toBeLessThanOrEqual(
      measurement.clientWidth,
    );
  }
  for (let index = 1; index < measurements.length; index += 1) {
    expect(measurements[index - 1]!.right, JSON.stringify(measurements)).toBeLessThanOrEqual(
      measurements[index]!.left + 1,
    );
  }
}

async function openVisualStudio(page: Page) {
  await mockStudio(page);
  await page.goto("/studio");
  await disableMotion(page);
  await page.getByLabel("工作区路径").fill("C:/authorized/visual-workspace");
  await page.getByRole("button", { name: "打开工作区" }).click();
  await expect(
    page.locator('[data-testid="studio-candidate-list"]:visible').getByRole("button", { name: /H-VISUAL-001/ }),
  ).toHaveCount(1);
  await page.evaluate(() => window.scrollTo(0, 0));
}

test("control center remains framed, responsive, and visually stable", async ({ page }, testInfo) => {
  await mockControlCenter(page);
  await page.goto("/");
  await disableMotion(page);
  await expect(page.getByRole("heading", { level: 1, name: "赏金神话·轻量版控制中心" })).toBeVisible();
  await expect(page.getByText("越权访问候选（IDOR）", { exact: true })).toBeVisible();
  await expectInViewport(page.getByRole("region", { name: "运行指标" }));
  await expectNoHorizontalOverflow(page);

  const chart = page.getByRole("img", { name: "候选保留率、反证淘汰率和证据完整率柱状图" });
  await expect(chart).toBeVisible();
  const canvas = chart.locator("canvas");
  await expect(canvas).toHaveCount(1);
  await expectCanvasPixels(canvas);

  const viewport = viewportFor(testInfo);
  if (viewport.width >= 1100) {
    await page.setViewportSize({ height: viewport.height, width: viewport.width - 160 });
    await expectNoHorizontalOverflow(page);
    await expectCanvasPixels(canvas);
    await page.setViewportSize(viewport);
  }
  await expect(page).toHaveScreenshot("control-center.png", {
    animations: "disabled",
  });
});

test("Studio remains framed and visually stable at each approved viewport", async ({ page }, testInfo) => {
  await openVisualStudio(page);
  await expect(page.getByText("赏金神话研究工作台", { exact: true }).first()).toBeVisible();
  await expectInViewport(page.getByRole("heading", { name: "研究阶段" }));
  await expectNoHorizontalOverflow(page);

  if (viewportFor(testInfo).width < 640) {
    await page.getByRole("tab", { name: "候选" }).click();
    await expect(page.getByRole("region", { name: "候选列表" })).toBeVisible();
    await page.getByRole("tab", { name: "总览" }).click();
  } else {
    await expect(page.getByRole("complementary", { name: "候选检查器" })).toBeVisible();
    await expectInspectorTabsToFit(page);
  }
  await expect(page).toHaveScreenshot("studio.png", {
    animations: "disabled",
  });
});

test("Studio drawer restores focus at tablet width", async ({ page }, testInfo) => {
  test.skip(testInfo.project.name !== "visual-1440", "One tablet focus journey is sufficient.");
  await openVisualStudio(page);
  await page.setViewportSize({ height: 900, width: 900 });
  const trigger = page.getByRole("button", { name: "打开详情检查器" });
  await trigger.focus();
  await trigger.click();
  const drawer = page.getByRole("dialog", { name: "候选详情抽屉" });
  await expect(drawer).toBeVisible();
  await page.keyboard.press("Escape");
  await expect(drawer).toBeHidden();
  await expect(trigger).toBeFocused();
});

test("Studio mobile tabs stay keyboard operable", async ({ page }, testInfo) => {
  test.skip(testInfo.project.name !== "visual-390", "Mobile tab navigation is covered once.");
  await openVisualStudio(page);
  const overview = page.getByRole("tab", { name: "总览" });
  await overview.focus();
  await page.keyboard.press("ArrowRight");
  await expect(page.getByRole("tab", { name: "候选" })).toBeFocused();
  await page.keyboard.press("Enter");
  await expect(page.getByRole("region", { name: "候选列表" })).toBeVisible();
});
