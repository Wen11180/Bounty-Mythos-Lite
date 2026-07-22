import { expect, test, type Page } from "@playwright/test";

const runId = "studio-e2e-run";
const workspacePath = "C:/authorized/mythos-workspace";
const mockApiPort = Number(process.env.E2E_MOCK_API_PORT ?? 46087);

async function installStudioBridge(page: Page) {
  await page.addInitScript(() => {
    const bridge = {
      closeBlackBoxSessions: async () => JSON.stringify({ event: "sessions_closed" }),
      createBlackBoxSessions: async () => JSON.stringify({ event: "sessions_created" }),
      refreshProgramRules: async () => ({ next_due_at: null, processed: false, status: "idle" }),
      runBlackBoxTrial: async () => JSON.stringify({ event: "trial_complete" }),
      selectDirectory: async () => "C:/authorized/selected-directory",
      selectFile: async () => "C:/authorized/selected-policy.yaml",
      startBlackBoxRecording: async () => JSON.stringify({ event: "recording_started" }),
      stopBlackBoxRecording: async () => JSON.stringify({ event: "recording_stopped", traces: [] }),
    } satisfies NonNullable<Window["mythosStudio"]>;
    window.mythosStudio = bridge;
  });
}

async function mockStudioApi(
  page: Page,
  options: {
    candidatesUnavailable?: boolean;
    queuedInvalidations?: boolean;
    startProjectionUnavailable?: boolean;
  } = {},
) {
  const requests = { candidates: 0, manifest: 0, mission: 0 };
  let researchStarted = false;
  let invalidated = false;
  let failNextCandidates = false;
  let queuedInvalidations = 0;
  let eventSequence = 0;
  let releaseInvalidation: (() => void) | null = null;
  const invalidationReady = new Promise<void>((resolve) => {
    releaseInvalidation = resolve;
  });
  let eventSent = false;

  function emitInvalidation() {
    invalidated = true;
    if (options.queuedInvalidations) {
      queuedInvalidations += 1;
    } else {
      releaseInvalidation?.();
    }
  }

  await page.route("**/mythos/control-center/events**", async (route) => {
    if (!options.queuedInvalidations) {
      if (!eventSent) {
        await invalidationReady;
        eventSent = true;
        await route.fulfill({
          body: `event: control-center-invalidated\nid: ${"a".repeat(64)}\ndata: {"changed":["overview"]}\n\n`,
          contentType: "text/event-stream",
          headers: { "Cache-Control": "no-cache" },
          status: 200,
        });
        return;
      }
      await route.fulfill({
        body: ": keepalive\n\n",
        contentType: "text/event-stream",
        headers: { "Cache-Control": "no-cache" },
        status: 200,
      });
      return;
    }
    if (queuedInvalidations === 0) {
      await route.fulfill({
        body: ": keepalive\nretry: 500\n\n",
        contentType: "text/event-stream",
        headers: { "Cache-Control": "no-cache" },
        status: 200,
      });
      return;
    }
    queuedInvalidations -= 1;
    eventSequence += 1;
    await route.fulfill({
      body: `event: control-center-invalidated\nid: ${eventSequence.toString(16).padStart(64, "0")}\nretry: 500\ndata: {"changed":["overview"]}\n\n`,
      contentType: "text/event-stream",
      headers: { "Cache-Control": "no-cache" },
      status: 200,
    });
  });
  await page.route("**/mythos/studio/black-box-lab/runs/bounded-result", async (route) => {
    emitInvalidation();
    await route.fulfill({
      json: {
        campaign_id: "campaign-e2e",
        difference_labels: ["response_schema_changed"],
        evidence_ref_count: 1,
        execution_allowed: false,
        human_review_required: true,
        pipeline_run_id: runId,
        report_preview_refreshed: true,
        report_submission_allowed: false,
        result_digest: `sha256:${"e".repeat(64)}`,
        submission_blocked: true,
        validation_run_id: "validation-e2e",
        validation_status: "needs_evidence",
      },
      status: 200,
    });
  });
  await page.route("**/mythos/studio/black-box-remote/status", async (route) => {
    await route.fulfill({
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
    });
  });
  await page.route("**/mythos/studio/workspaces/manifest**", async (route) => {
    requests.manifest += 1;
    await route.fulfill({
      json: {
        artifacts: [
          { kind: "policy", source_path: "policy.yaml" },
          { kind: "scope", source_path: "scope.yaml" },
          { kind: "code", source_path: "src" },
          { kind: "api", source_path: "openapi.json" },
          { kind: "har", source_path: "safe.har" },
        ],
        name: "授权研究演练",
        runs: [{
          recorded_at: "2026-07-18T04:00:00Z",
          report_markdown_path: invalidated ? "C:/drafts/studio-e2e-run-v2.md" : undefined,
          run_id: runId,
          status: "review",
        }],
        safety: {
          blocked_actions: ["execute_live_validation", "submit_report"],
          scope_guard_status: "in_scope",
        },
      },
    });
  });
  await page.route("**/mythos/studio/workspaces/candidates**", async (route) => {
    requests.candidates += 1;
    if (failNextCandidates) {
      failNextCandidates = false;
      await route.fulfill({ json: { detail: "candidate projection unavailable" }, status: 503 });
      return;
    }
    if (options.candidatesUnavailable || (options.startProjectionUnavailable && researchStarted)) {
      await route.fulfill({ json: { detail: "candidate projection unavailable" }, status: 503 });
      return;
    }
    if (options.startProjectionUnavailable) {
      await route.fulfill({ json: { candidates: [], run_id: runId } });
      return;
    }
    await route.fulfill({
      json: {
        candidates: [
          {
            affected_code_path: "src/routes/records.ts:42",
            affected_endpoint: "GET /records/{id}",
            evidence_needed: ["所有权守卫的本地代码路径"],
            false_positive_checks: ["确认中间件是否统一执行对象授权"],
            hypothesis_id: "H-001",
            location: "GET /records/{id}",
            priority_score: 87,
            reason: "对象所有权校验尚未在敏感读取前得到证明。",
            report_readiness: { status: "needs_evidence", submission_blocked: true },
            risk: "high",
            safe_validation_plan: ["在隔离 local-lab 中使用两个别名账户比较状态类别"],
            safe_verification: true,
            vuln_type: "IDOR candidate",
          },
          {
            affected_code_path: "src/services/preview.ts:18",
            affected_endpoint: "POST /preview",
            evidence_needed: ["URL allowlist 分支的静态证据"],
            false_positive_checks: ["确认解析后地址是否再次校验"],
            hypothesis_id: "H-002",
            location: "POST /preview",
            priority_score: 74,
            reason: "重定向后的目标约束需要人工复核。",
            report_readiness: { status: "needs_review", submission_blocked: true },
            risk: "medium",
            safe_validation_plan: ["仅审查本地路由与 allowlist 分支，不发送公网请求"],
            safe_verification: true,
            vuln_type: "SSRF candidate",
          },
          ...(invalidated ? [{
            affected_code_path: "src/routes/export.ts:27",
            affected_endpoint: "GET /exports/{id}",
            hypothesis_id: "H-003",
            location: "GET /exports/{id}",
            priority_score: 69,
            reason: "导出对象边界需要审查。",
            report_readiness: { status: "needs_review", submission_blocked: true },
            risk: "medium",
            safe_verification: true,
            vuln_type: "Export authorization candidate",
          }] : []),
        ],
        run_id: runId,
      },
    });
  });
  await page.route("**/mythos/studio/workspaces/mission**", async (route) => {
    requests.mission += 1;
    await route.fulfill({
      json: {
        artifacts: { present: ["policy", "scope", "code", "api", "har"], required: ["policy", "scope", "code", "api", "har"] },
        blocked_actions: ["execute_live_validation", "submit_report"],
        candidate_count: 2,
        gates: { submission_blocked: true, validation_execution_allowed: false },
        mode: "live",
        research_loop_stages: [
          { key: "policy", status: "complete", summary: "Scope Guard 已审查" },
          { key: "audit", status: "needs_review", summary: "候选需要人工证据审查" },
        ],
        run_id: runId,
        scope_guard_status: "in_scope",
      },
    });
  });
  await page.route("**/mythos/studio/workspaces/runs", async (route) => {
    researchStarted = true;
    await route.fulfill({
      json: {
        candidate_count: 9,
        manifest: {
          artifacts: [],
          name: "Research POST partial manifest",
          runs: [{ run_id: "post-run" }],
          safety: { blocked_actions: ["submit_report"], scope_guard_status: "in_scope" },
        },
        run_id: "post-run",
      },
      status: 200,
    });
  });
  return {
    async recordBoundedResult() {
      await page.evaluate(async ({ port }) => {
        const response = await fetch(
          `http://127.0.0.1:${port}/mythos/studio/black-box-lab/runs/bounded-result`,
          {
            body: JSON.stringify({ normalized_result: true }),
            headers: { "Content-Type": "application/json" },
            method: "POST",
          },
        );
        if (!response.ok) {
          throw new Error("bounded_result_post_failed");
        }
      }, { port: mockApiPort });
    },
    emitInvalidation,
    failNextRefresh() {
      failNextCandidates = true;
      emitInvalidation();
    },
    requests,
  };
}

async function openWorkspace(
  page: Page,
  options: Parameters<typeof mockStudioApi>[1] = {},
) {
  await installStudioBridge(page);
  const mock = await mockStudioApi(page, options);
  await page.goto("/studio");
  const workspaceInput = page.getByLabel("Workspace path");
  await expect(workspaceInput).toHaveCount(1);
  await workspaceInput.fill(workspacePath);
  const openButton = page.getByRole("button", { name: "Open workspace" });
  await expect(openButton).toHaveCount(1);
  await openButton.click();
  await expect(page.locator('[data-testid="studio-candidate-list"]:visible').getByRole("button", { name: /H-001/ })).toBeVisible();
  return mock;
}

test("Studio desktop keeps three columns and candidate selection preserves conversation", async ({ page }) => {
  await page.setViewportSize({ height: 900, width: 1440 });
  const mock = await openWorkspace(page);

  const navigation = page.getByRole("complementary", { name: "工作区导航" });
  const main = page.locator("#studio-main");
  const inspector = page.getByRole("complementary", { name: "候选检查器" });
  const [navigationBox, mainBox, inspectorBox] = await Promise.all([
    navigation.boundingBox(),
    main.boundingBox(),
    inspector.boundingBox(),
  ]);
  expect(navigationBox).not.toBeNull();
  expect(mainBox).not.toBeNull();
  expect(inspectorBox).not.toBeNull();
  expect(navigationBox!.x).toBeLessThan(mainBox!.x);
  expect(mainBox!.x).toBeLessThan(inspectorBox!.x);

  await expect(page.getByText("Studio ready.")).toHaveCount(1);
  await expect(page.getByText("Studio ready.")).toBeVisible();
  await page.getByLabel("候选漏洞").selectOption("H-002");
  await expect(page.getByTestId("studio-inspector").getByRole("heading", { name: "SSRF candidate" })).toBeVisible();
  await expect(page.getByText("Studio ready.")).toBeVisible();
  await expect(page.getByTestId("studio-inspector").getByText("POST /preview")).toBeVisible();

  const before = { ...mock.requests };
  mock.emitInvalidation();
  await expect.poll(() => mock.requests.manifest).toBeGreaterThan(before.manifest);
  await expect.poll(() => mock.requests.mission).toBeGreaterThan(before.mission);
  await expect.poll(() => mock.requests.candidates).toBeGreaterThan(before.candidates);
  await expect(page.locator('[data-testid="studio-candidate-list"]:visible').getByRole("button", { name: /H-003/ })).toBeVisible();
  await page.getByRole("tab", { name: "报告草稿" }).click();
  await expect(page.getByText("C:/drafts/studio-e2e-run-v2.md", { exact: true })).toBeVisible();
});

test("bounded result invalidation refreshes the report inspector and preserves LKG on failure", async ({
  page,
}) => {
  await page.setViewportSize({ height: 900, width: 1440 });
  const mock = await openWorkspace(page, { queuedInvalidations: true });
  await page.getByRole("tab", { name: "报告草稿" }).click();
  await expect(page.getByText("C:/drafts/studio-e2e-run-v2.md", { exact: true })).toHaveCount(0);

  const beforeBoundedResult = { ...mock.requests };
  await mock.recordBoundedResult();

  await expect.poll(() => mock.requests.manifest).toBeGreaterThan(beforeBoundedResult.manifest);
  await expect.poll(() => mock.requests.mission).toBeGreaterThan(beforeBoundedResult.mission);
  await expect.poll(() => mock.requests.candidates).toBeGreaterThan(beforeBoundedResult.candidates);
  await expect(page.getByText("C:/drafts/studio-e2e-run-v2.md", { exact: true })).toBeVisible();
  await expect(
    page.locator('[data-testid="studio-candidate-list"]:visible').getByRole("button", { name: /H-003/ }),
  ).toBeVisible();
  await expect(page.getByText("实时连接：live", { exact: true })).toBeVisible();

  const beforeFailure = { ...mock.requests };
  mock.failNextRefresh();

  await expect.poll(() => mock.requests.candidates).toBeGreaterThan(beforeFailure.candidates);
  await expect(page.getByText("实时连接：degraded", { exact: true })).toBeVisible();
  await expect(page.getByText("C:/drafts/studio-e2e-run-v2.md", { exact: true })).toBeVisible();
  await expect(
    page.locator('[data-testid="studio-candidate-list"]:visible').getByRole("button", { name: /H-003/ }),
  ).toBeVisible();
  await expect(page.getByRole("button", { name: /submit report/i })).toHaveCount(0);
});

test("Studio below 1100 uses an accessible inspector drawer", async ({ page }) => {
  await page.setViewportSize({ height: 900, width: 700 });
  await openWorkspace(page);

  const trigger = page.getByRole("button", { name: "打开详情检查器" });
  await trigger.focus();
  await expect(trigger).toBeFocused();
  await trigger.click();
  const drawer = page.getByRole("dialog", { name: "候选详情抽屉" });
  await expect(drawer).toBeVisible();
  await expect(page.getByRole("button", { name: "关闭详情检查器" }).last()).toBeFocused();
  await page.keyboard.press("Escape");
  await expect(drawer).toBeHidden();
  await expect(trigger).toBeFocused();
});

test("Studio mobile tabs and desktop path selectors remain keyboard operable", async ({ page }) => {
  await page.setViewportSize({ height: 844, width: 390 });
  await openWorkspace(page);

  await expect(page.getByRole("tab", { name: "总览" })).toHaveAttribute("aria-selected", "true");
  await page.getByRole("tab", { name: "候选" }).click();
  await expect(page.getByRole("region", { name: "候选列表" })).toBeVisible();
  await page.getByRole("tab", { name: "详情" }).click();
  const mobileDetails = page.getByRole("region", { name: "候选详情" });
  await expect(mobileDetails.getByTestId("studio-inspector")).toBeVisible();
  await page.keyboard.press("Tab");
  await expect(mobileDetails.getByRole("tab", { name: "候选详情" })).toBeFocused();

  await page.getByRole("tab", { name: "总览" }).click();
  const workspaceBrowse = page.getByLabel("Workspace path").locator("..").getByRole("button", { name: "Browse" });
  await workspaceBrowse.click();
  await expect(page.getByLabel("Workspace path")).toHaveValue("C:/authorized/selected-directory");

  const policyLabel = page.getByText("Policy file", { exact: true });
  await policyLabel.locator("..").getByRole("button", { name: "Browse" }).click();
  await expect(policyLabel.locator("..").locator("input")).toHaveValue("C:/authorized/selected-policy.yaml");
});

test("Studio workspace open keeps its last-known-good projection when candidates return 503", async ({ page }) => {
  await page.setViewportSize({ height: 900, width: 1440 });
  await installStudioBridge(page);
  await mockStudioApi(page, { candidatesUnavailable: true });
  await page.goto("/studio");
  await page.getByLabel("Workspace path").fill(workspacePath);
  await page.getByRole("button", { name: "Open workspace" }).click();

  await expect(page.getByText(/Workspace open failed \(API 503\)/)).toBeVisible();
  await expect(page.getByText("Workspace opened locally.")).toHaveCount(0);
  await expect(page.getByText("授权研究演练")).toHaveCount(0);
  await expect(page.locator('[data-testid="studio-candidate-list"]:visible').getByRole("button"))
    .toHaveCount(0);
});

test("Studio research start publishes nothing when strict candidates refresh returns 503", async ({ page }) => {
  await page.setViewportSize({ height: 900, width: 1440 });
  await installStudioBridge(page);
  await mockStudioApi(page, { startProjectionUnavailable: true });
  await page.goto("/studio");
  await page.getByLabel("Workspace path").fill(workspacePath);
  await page.getByRole("button", { name: "Open workspace" }).click();
  await expect(page.getByText("授权研究演练")).toBeVisible();

  await page.getByRole("button", { name: "Start local research" }).click();

  await expect(page.getByText(/Research run failed \(API 503\)/)).toBeVisible();
  await expect(page.getByText(/Research run post-run produced/)).toHaveCount(0);
  await expect(page.getByText("授权研究演练")).toBeVisible();
  await expect(page.getByText("Research POST partial manifest")).toHaveCount(0);
  await expect(page.locator('[data-testid="studio-candidate-list"]:visible').getByRole("button"))
    .toHaveCount(0);
});
