import { expect, test, type Page, type Route } from "@playwright/test";

const mockApiPort = Number(process.env.E2E_MOCK_API_PORT ?? 46087);
const publicRuleUrl = "https://rules.example.test/program";
const sha = "a".repeat(64);
const permissions = {
  execution_allowed: false,
  lease_grant_allowed: false,
  report_submission_allowed: false,
  review_bypass_allowed: false,
  scope_change_allowed: false,
} as const;

test("Studio registers, refreshes, and reviews one public rule source without browser acquisition", async ({ page }) => {
  const publicRequests: string[] = [];
  await blockPublicRuleRequests(page, publicRequests);
  await installProgramRuleBridge(page);
  const mock = await mockProgramRuleApi(page);

  await page.goto("/studio");
  const intake = page.getByTestId("program-rule-intake");
  await expect(intake).toBeVisible();

  await intake.getByLabel("项目别名").fill("synthetic_program");
  await intake.getByLabel("公开 HTTPS 规则 URL").fill(publicRuleUrl);
  await intake.getByRole("button", { name: "注册来源" }).click();

  await expect(intake.getByText("synthetic_program", { exact: true })).toBeVisible();
  await expect(intake.getByText("人工快照审核")).toBeVisible();
  expect(mock.registrationBodies).toEqual([{
    program_alias: "synthetic_program",
    public_rule_url: publicRuleUrl,
  }]);
  await expect.poll(() => page.evaluate(() => window.__programRuleRefreshCalls)).toBe(1);

  await expect(intake.getByText("获取状态", { exact: true })).toBeVisible();
  await expect(intake.getByText("生效状态", { exact: true })).toBeVisible();
  await expect(intake.getByText("审核状态", { exact: true }).first()).toBeVisible();
  await expect(intake.getByText(/已禁止：自动扫描/u).first()).toBeVisible();
  await expect(intake.getByText(/5 次\/分钟/u).first()).toBeVisible();
  await expect(intake.getByText("英语", { exact: true })).toBeVisible();
  await expect(intake.getByText("未请求", { exact: true })).toBeVisible();
  expect(await intake.locator("blockquote p").textContent()).toHaveLength(500);
  await expect(intake).not.toContainText("RAW_POLICY_SECRET_SENTINEL");

  await intake.getByLabel("审核人别名").fill("reviewer_one");
  await intake.getByRole("checkbox").check();
  await intake.getByRole("button", { name: "批准快照" }).click();

  await expect(intake.getByText("已批准", { exact: true }).first()).toBeVisible();
  expect(mock.reviewBodies).toEqual([{
    expected_review_digest: sha,
    operator_confirmed: true,
    reviewer_alias: "reviewer_one",
  }]);
  expect(publicRequests).toEqual([]);
  await expect(intake.getByRole("button", { name: /execute|claim|submit/i })).toHaveCount(0);
});

test("browser-only registration fails closed with studio_required and never fetches the policy URL", async ({ page }) => {
  const publicRequests: string[] = [];
  await blockPublicRuleRequests(page, publicRequests);
  const mock = await mockProgramRuleApi(page);

  await page.goto("/studio");
  const intake = page.getByTestId("program-rule-intake");
  await intake.getByLabel("项目别名").fill("browser_only_program");
  await intake.getByLabel("公开 HTTPS 规则 URL").fill(publicRuleUrl);
  await intake.getByRole("button", { name: "注册来源" }).click();

  await expect(intake.getByText("studio_required", { exact: true })).toBeVisible();
  expect(mock.registrationBodies).toEqual([{
    program_alias: "browser_only_program",
    public_rule_url: publicRuleUrl,
  }]);
  expect(mock.reviewBodies).toEqual([]);
  expect(publicRequests).toEqual([]);
});

test("snapshot selection clears the prior diff and keeps a non-pending review blocked", async ({ page }) => {
  const mock = await mockTwoSnapshotApi(page, { delayInitialDiff: false, delaySelectedDiff: true });

  await page.goto("/studio");
  const intake = page.getByTestId("program-rule-intake");
  await expect(intake.getByText("Diff Marker A", { exact: true })).toBeVisible();

  await intake.getByRole("button", { name: /2026-07-19T03:00:00Z · 待处理/u }).click();
  await expect(intake.getByText("快照差异", { exact: true })).toHaveCount(0);
  await intake.getByLabel("审核人别名").fill("reviewer_two");
  await intake.getByRole("checkbox").check();
  await expect(intake.getByRole("button", { name: "批准快照" })).toBeDisabled();

  mock.releaseSelectedDiff();
  await expect(intake.getByText("Diff Marker B", { exact: true })).toBeVisible();
  await expect(intake.getByRole("button", { name: "批准快照" })).toBeDisabled();
  expect(mock.reviewPaths).toEqual([]);
  expect(mock.reviewBodies).toEqual([]);
});

test("out-of-order diff responses cannot replace the selected snapshot binding", async ({ page }) => {
  const mock = await mockTwoSnapshotApi(page, { delayInitialDiff: true, delaySelectedDiff: false });

  await page.goto("/studio");
  const intake = page.getByTestId("program-rule-intake");
  await intake.getByRole("button", { name: /2026-07-19T03:00:00Z · 待处理/u }).click();
  await expect(intake.getByText("Diff Marker B", { exact: true })).toBeVisible();

  mock.releaseInitialDiff();
  await expect.poll(() => mock.initialDiffFulfilled).toBe(1);
  await expect(intake.getByText("Diff Marker B", { exact: true })).toBeVisible();
  await expect(intake.getByText("Diff Marker A", { exact: true })).toHaveCount(0);

  await intake.getByLabel("审核人别名").fill("reviewer_two");
  await intake.getByRole("checkbox").check();
  await expect(intake.getByRole("button", { name: "批准快照" })).toBeDisabled();
  expect(mock.reviewPaths).toEqual([]);
  expect(mock.reviewBodies).toEqual([]);
});

test("invalid contracts and authority drift are explicit and block both review decisions", async ({ page }) => {
  await mockInvalidProgramRuleApi(page);

  await page.goto("/studio");
  const intake = page.getByTestId("program-rule-intake");
  await expect(intake.getByText(/已禁用审核：来源、快照、显示的差异/u)).toBeVisible();
  await expect(intake.getByText("契约", { exact: true }).first()).toBeVisible();
  await expect(intake.getByText("权限", { exact: true }).first()).toBeVisible();
  await expect(intake).not.toContainText("固定为否");

  await intake.getByLabel("审核人别名").fill("reviewer_one");
  await intake.getByRole("checkbox").check();
  await expect(intake.getByRole("button", { name: "批准快照" })).toBeDisabled();
  await expect(intake.getByRole("button", { name: "拒绝快照" })).toBeDisabled();
});

async function installProgramRuleBridge(page: Page) {
  await page.addInitScript(() => {
    window.__programRuleRefreshCalls = 0;
    const bridge = {
      closeBlackBoxSessions: async () => JSON.stringify({ event: "sessions_closed" }),
      createBlackBoxSessions: async () => JSON.stringify({ event: "sessions_created" }),
      refreshProgramRules: async () => {
        window.__programRuleRefreshCalls += 1;
        return { next_due_at: null, processed: true, status: "completed" };
      },
      runBlackBoxTrial: async () => JSON.stringify({ event: "trial_complete" }),
      selectDirectory: async () => null,
      selectFile: async () => null,
      startBlackBoxRecording: async () => JSON.stringify({ event: "recording_started" }),
      stopBlackBoxRecording: async () => JSON.stringify({ event: "recording_stopped", traces: [] }),
    } satisfies NonNullable<Window["mythosStudio"]>;
    window.mythosStudio = bridge;
  });
}

async function blockPublicRuleRequests(page: Page, requests: string[]) {
  await page.route("https://rules.example.test/**", async (route) => {
    requests.push(route.request().url());
    await route.abort("blockedbyclient");
  });
}

async function mockProgramRuleApi(page: Page) {
  const registrationBodies: unknown[] = [];
  const reviewBodies: unknown[] = [];
  let registered = false;
  let approved = false;

  await page.route(`http://127.0.0.1:${mockApiPort}/**`, async (route) => {
    const request = route.request();
    const method = request.method();
    const path = new URL(request.url()).pathname;

    if (method === "OPTIONS") {
      await route.fulfill({ headers: corsHeaders(), status: 204 });
      return;
    }
    if (method === "GET" && path === "/program-rule-sources") {
      await fulfillJson(route, registered ? [sourceFixture(approved)] : []);
      return;
    }
    if (method === "POST" && path === "/program-rule-sources") {
      registrationBodies.push(request.postDataJSON());
      registered = true;
      await fulfillJson(route, sourceFixture(false));
      return;
    }
    if (method === "GET" && path === "/program-rule-sources/source_synthetic/snapshots") {
      await fulfillJson(route, [snapshotFixture(approved ? "approved" : "pending")]);
      return;
    }
    if (method === "GET" && path === "/program-rule-sources/source_synthetic/snapshots/snapshot_pending/diff") {
      await fulfillJson(route, diffFixture());
      return;
    }
    if (method === "GET" && path === "/programs/program_synthetic/scope-rules") {
      await fulfillJson(route, [scopeRuleFixture()]);
      return;
    }
    if (method === "POST" && path === "/program-rule-sources/source_synthetic/snapshots/snapshot_pending/approve") {
      reviewBodies.push(request.postDataJSON());
      approved = true;
      await fulfillJson(route, snapshotFixture("approved"));
      return;
    }
    await fulfillJson(route, { detail: "not_found" }, 404);
  });

  return { registrationBodies, reviewBodies };
}

async function mockTwoSnapshotApi(
  page: Page,
  options: { delayInitialDiff: boolean; delaySelectedDiff: boolean },
) {
  const initialDiffGate = deferredGate();
  const selectedDiffGate = deferredGate();
  const reviewBodies: unknown[] = [];
  const reviewPaths: string[] = [];
  let initialDiffFulfilled = 0;

  await page.route(`http://127.0.0.1:${mockApiPort}/**`, async (route) => {
    const request = route.request();
    const method = request.method();
    const path = new URL(request.url()).pathname;
    if (method === "OPTIONS") {
      await route.fulfill({ headers: corsHeaders(), status: 204 });
      return;
    }
    if (method === "GET" && path === "/program-rule-sources") {
      await fulfillJson(route, [sourceFixture(false)]);
      return;
    }
    if (method === "GET" && path === "/program-rule-sources/source_synthetic/snapshots") {
      await fulfillJson(route, [
        snapshotVariant("snapshot_pending", sha, "2026-07-19T02:00:00Z"),
        snapshotVariant("snapshot_new", "b".repeat(64), "2026-07-19T03:00:00Z"),
      ]);
      return;
    }
    if (method === "GET" && path === "/program-rule-sources/source_synthetic/snapshots/snapshot_pending/diff") {
      if (options.delayInitialDiff) await initialDiffGate.wait;
      await fulfillJson(route, diffVariant("snapshot_pending", sha, "diff_marker_a"));
      initialDiffFulfilled += 1;
      return;
    }
    if (method === "GET" && path === "/program-rule-sources/source_synthetic/snapshots/snapshot_new/diff") {
      if (options.delaySelectedDiff) await selectedDiffGate.wait;
      await fulfillJson(route, diffVariant("snapshot_new", "b".repeat(64), "diff_marker_b"));
      return;
    }
    if (method === "GET" && path === "/programs/program_synthetic/scope-rules") {
      await fulfillJson(route, []);
      return;
    }
    if (method === "POST" && path.endsWith("/approve")) {
      reviewPaths.push(path);
      reviewBodies.push(request.postDataJSON());
      await fulfillJson(route, snapshotVariant("snapshot_new", "b".repeat(64), "2026-07-19T03:00:00Z"));
      return;
    }
    await fulfillJson(route, { detail: "not_found" }, 404);
  });

  return {
    get initialDiffFulfilled() {
      return initialDiffFulfilled;
    },
    releaseInitialDiff: initialDiffGate.release,
    releaseSelectedDiff: selectedDiffGate.release,
    reviewBodies,
    reviewPaths,
  };
}

async function mockInvalidProgramRuleApi(page: Page) {
  await page.route(`http://127.0.0.1:${mockApiPort}/**`, async (route) => {
    const request = route.request();
    const method = request.method();
    const path = new URL(request.url()).pathname;
    if (method === "OPTIONS") {
      await route.fulfill({ headers: corsHeaders(), status: 204 });
      return;
    }
    if (method === "GET" && path === "/program-rule-sources") {
      await fulfillJson(route, [{ ...sourceFixture(false), execution_allowed: true }]);
      return;
    }
    if (method === "GET" && path === "/program-rule-sources/source_synthetic/snapshots") {
      await fulfillJson(route, [{ ...snapshotFixture("pending"), execution_allowed: true }]);
      return;
    }
    if (method === "GET" && path.endsWith("/snapshot_pending/diff")) {
      await fulfillJson(route, { ...diffFixture(), execution_allowed: true });
      return;
    }
    if (method === "GET" && path === "/programs/program_synthetic/scope-rules") {
      await fulfillJson(route, [{ ...scopeRuleFixture(), execution_allowed: true }]);
      return;
    }
    await fulfillJson(route, { detail: "not_found" }, 404);
  });
}

function sourceFixture(approved: boolean) {
  return {
    approved_snapshot_id: approved ? "snapshot_pending" : null,
    canonical_url: publicRuleUrl,
    effective_scope_status: approved ? "active" : "needs_review",
    fetch_status: "ok",
    last_success_at: "2026-07-19T02:00:00Z",
    next_check_at: "2026-07-20T02:00:00Z",
    pending_snapshot_id: approved ? null : "snapshot_pending",
    program_alias: "synthetic_program",
    program_id: "program_synthetic",
    registered_url: publicRuleUrl,
    source_id: "source_synthetic",
    warning: null,
  };
}

function snapshotFixture(reviewStatus: "approved" | "pending") {
  return {
    ...permissions,
    ai_status: "not_requested",
    artifact_warning: "openapi_promotion_pending",
    content_types: ["text/html"],
    detected_language: "en",
    evidence: [{
      document_sha256: sha,
      evidence_id: sha,
      excerpt: "E".repeat(520),
      locator: "line:1",
      raw_html: "RAW_POLICY_SECRET_SENTINEL",
    }],
    extraction: { review_issues: [], review_state: "ready", rules: [candidateFixture()] },
    fetched_at: "2026-07-19T02:00:00Z",
    fetch_mode: "static",
    linked_documents: [{
      content_type: "text/plain",
      depth: 1,
      kind: "text",
      normalized_sha256: sha,
      raw_sha256: sha,
      url: "https://rules.example.test/linked",
    }],
    normalized_sha256: sha,
    openapi_candidates: [linkedArtifactFixture()],
    raw_aggregate_sha256: sha,
    raw_body: "RAW_POLICY_SECRET_SENTINEL",
    review_digest: sha,
    review_status: reviewStatus,
    reviewed_at: reviewStatus === "approved" ? "2026-07-19T03:00:00Z" : null,
    reviewer_alias: reviewStatus === "approved" ? "reviewer_one" : null,
    snapshot_id: "snapshot_pending",
    source_id: "source_synthetic",
  };
}

function snapshotVariant(snapshotId: string, reviewDigest: string, fetchedAt: string) {
  return {
    ...snapshotFixture("pending"),
    fetched_at: fetchedAt,
    review_digest: reviewDigest,
    snapshot_id: snapshotId,
  };
}

function candidateFixture() {
  return {
    allowed_validation: ["manual_read_only"],
    asset: "api.example.test",
    asset_kind: "exact_host",
    automation: "limited",
    automation_evidence_ids: [sha],
    human_approval_required: true,
    prohibited: ["automated_scanning"],
    prohibited_evidence_ids: { automated_scanning: [sha] },
    rate_limit: { evidence_ids: [sha], period: 1, requests: 5, unit: "minute" },
    review_issues: [],
    review_state: "ready",
    scope_evidence_ids: [sha],
    scope_status: "in_scope",
    specificity: 4,
  };
}

function linkedArtifactFixture() {
  return {
    evidence_ids: [sha],
    kind: "openapi",
    normalized_sha256: sha,
    openapi_like: { path_count: 1 },
    promotion_allowed: false,
    url: "https://rules.example.test/openapi.json",
    url_sha256: sha,
  };
}

function diffFixture() {
  return {
    ...permissions,
    added_linked_artifacts: [linkedArtifactFixture()],
    added_prohibitions: ["automated_scanning"],
    added_rules: [candidateFixture()],
    approved_snapshot_id: null,
    modified_rules: [],
    pending_snapshot_id: "snapshot_pending",
    removed_linked_artifacts: [],
    removed_prohibitions: [],
    removed_rules: [],
    review_digest: sha,
    source_id: "source_synthetic",
  };
}

function diffVariant(snapshotId: string, reviewDigest: string, marker: string) {
  return {
    ...diffFixture(),
    added_prohibitions: [marker],
    pending_snapshot_id: snapshotId,
    review_digest: reviewDigest,
  };
}

function scopeRuleFixture() {
  return {
    ...permissions,
    allowed_validation: ["manual_read_only"],
    approval_digest: sha,
    approved_snapshot_id: "snapshot_pending",
    asset_kind: "exact_host",
    automation: "limited",
    canonical_asset: "api.example.test",
    effective_at: "2026-07-19T03:00:00Z",
    effective_scope_status: "active",
    prohibited: ["automated_scanning"],
    program_id: "program_synthetic",
    rate_limit: { evidence_ids: [sha], period: 1, requests: 5, unit: "minute" },
    rule_id: "rule_synthetic",
    scope_status: "in_scope",
    source_evidence_refs: [sha],
    source_id: "source_synthetic",
    warning: null,
  };
}

async function fulfillJson(route: Route, json: unknown, status = 200) {
  await route.fulfill({ headers: corsHeaders(), json, status });
}

function deferredGate() {
  let release = () => {};
  const wait = new Promise<void>((resolve) => {
    release = resolve;
  });
  return { release, wait };
}

function corsHeaders() {
  return {
    "Access-Control-Allow-Headers": "Content-Type",
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Access-Control-Allow-Origin": "*",
  };
}
