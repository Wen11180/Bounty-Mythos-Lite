import { createServer, type IncomingMessage, type ServerResponse } from "node:http";

import { expect, test, type Page } from "@playwright/test";
import type { AutopilotCampaignProjection } from "../lib/autopilot-data";

const campaignId = "camp_lab";
const mockApiPort = Number(process.env.E2E_MOCK_API_PORT ?? 46087);
const apiOrigin = `http://127.0.0.1:${mockApiPort}`;

test.describe.configure({ mode: "serial" });

type ProjectionOverrides = Partial<AutopilotCampaignProjection>;

function projection(
  overrides: ProjectionOverrides = {},
): AutopilotCampaignProjection {
  return {
    campaign_id: campaignId,
    campaign_mode: "bounty_autopilot",
    projection_generated_at: new Date().toISOString(),
    emergency_stopped: false,
    authorization_digest: null,
    scope_snapshot_digest: null,
    policy_mode: "authorized_local_lab",
    next_branch_id: "branch_authz",
    next_reason: "highest_priority_eligible",
    budgets: {
      budget_ledger_valid: true,
      campaign_max_requests: 10,
      campaign_requests_used: 1,
      campaign_requests_remaining: 9,
      campaign_max_duration_seconds: 60,
      campaign_duration_reserved_seconds: 10,
      campaign_duration_remaining_seconds: 50,
      campaign_max_cost_units: 10,
      campaign_cost_units_reserved: 1,
      campaign_cost_units_remaining: 9,
      active_leases: 1,
      reserved_requests: 0,
      completed_requests: 1,
      open_approvals: 0,
    },
    assets: [{ asset_id: "asset_lab", status: "admitted" }],
    branches: [
      {
        branch_id: "branch_authz",
        asset_id: "asset_lab",
        status: "queued",
        priority: 50,
        risk_tier: "R1",
      },
    ],
    approvals: [],
    events: [],
    candidate_promotion_allowed: false,
    report_submission_allowed: false,
    submission_blocked: true,
    ...overrides,
  };
}

function corsHeaders() {
  return {
    "Access-Control-Allow-Headers": "Content-Type",
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Access-Control-Allow-Origin": "*",
    "Cache-Control": "no-cache",
  };
}

type AutopilotApiServer = {
  close: () => Promise<void>;
};

let activeAutopilotApiServer: AutopilotApiServer | null = null;

test.afterEach(async () => {
  await activeAutopilotApiServer?.close();
  activeAutopilotApiServer = null;
});

async function readJsonBody(request: IncomingMessage): Promise<Record<string, unknown>> {
  const chunks: Buffer[] = [];
  for await (const chunk of request) {
    chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
  }
  if (chunks.length === 0) {
    return {};
  }
  try {
    return JSON.parse(Buffer.concat(chunks).toString("utf8")) as Record<string, unknown>;
  } catch {
    return {};
  }
}

function sendJson(
  response: ServerResponse,
  status: number,
  payload: Record<string, unknown>,
) {
  const body = JSON.stringify(payload);
  response.writeHead(status, {
    ...corsHeaders(),
    "Content-Length": Buffer.byteLength(body),
    "Content-Type": "application/json",
  });
  response.end(body);
}

async function installAutopilotApi(
  options: {
    currentProjection: AutopilotCampaignProjection;
    failProjection?: boolean;
    onPrepare?: (body: Record<string, unknown>) => void;
    onStop?: (body: Record<string, unknown>) => void;
    onProjectionRead?: () => void;
  },
): Promise<AutopilotApiServer> {
  const server = createServer(async (request, response) => {
    const url = new URL(request.url ?? "/", apiOrigin);
    const method = request.method ?? "GET";
    const basePath = `/mythos/campaigns/${campaignId}/autopilot`;

    if (method === "OPTIONS") {
      response.writeHead(204, corsHeaders());
      response.end();
      return;
    }
    if (url.pathname === basePath && method === "GET") {
      options.onProjectionRead?.();
      if (options.failProjection) {
        sendJson(response, 503, { detail: "projection_unavailable" });
        return;
      }
      sendJson(response, 200, options.currentProjection as unknown as Record<string, unknown>);
      return;
    }
    if (url.pathname === `${basePath}/emergency-stop/prepare` && method === "POST") {
      options.onPrepare?.(await readJsonBody(request));
      sendJson(response, 200, {
        campaign_id: campaignId,
        confirmation_nonce: "nonce_lab",
        expires_at: new Date(Date.now() + 60_000).toISOString(),
      });
      return;
    }
    if (url.pathname === `${basePath}/emergency-stop` && method === "POST") {
      options.onStop?.(await readJsonBody(request));
      options.currentProjection = projection({
        ...options.currentProjection,
        emergency_stopped: true,
        next_branch_id: null,
        next_reason: "emergency_stopped",
        budgets: { ...options.currentProjection.budgets, active_leases: 0 },
      });
      sendJson(response, 200, { campaign_id: campaignId, emergency_stopped: true });
      return;
    }
    sendJson(response, 404, { detail: "not_found" });
  });
  await new Promise<void>((resolve, reject) => {
    const onError = (error: Error) => reject(error);
    server.once("error", onError);
    server.listen(mockApiPort, "127.0.0.1", () => {
      server.off("error", onError);
      resolve();
    });
  });
  activeAutopilotApiServer = {
    close: () =>
      new Promise<void>((resolve, reject) => {
        server.close((err) => (err ? reject(err) : resolve()));
      }),
  };
  return activeAutopilotApiServer;
}

async function installDesktopStopBridge(
  page: Page,
  stopSteps: string[],
  tracking: boolean,
  localCampaignIds: string[] = [],
  apiBaseUrl = apiOrigin,
) {
  await page.exposeFunction("__recordAutopilotEmergencyStopStep", async (
    step: "local",
    localCampaignId: string,
  ) => {
    stopSteps.push(step);
    localCampaignIds.push(localCampaignId);
  });
  await page.addInitScript(({ apiBaseUrl: bridgeApiBaseUrl, localStopTracked }) => {
    const bridge = {
      apiBaseUrl: bridgeApiBaseUrl,
      closeBlackBoxSessions: async () => JSON.stringify({ event: "sessions_closed" }),
      createBlackBoxSessions: async () => JSON.stringify({ event: "sessions_created" }),
      refreshProgramRules: async () => ({ next_due_at: null, processed: false, status: "idle" }),
      runBlackBoxTrial: async () => JSON.stringify({ event: "trial_complete" }),
      selectDirectory: async () => "C:/authorized/selected-directory",
      selectFile: async () => "C:/authorized/selected-policy.yaml",
      startBlackBoxRecording: async () => JSON.stringify({ event: "recording_started" }),
      stopBlackBoxRecording: async () => JSON.stringify({ event: "recording_stopped", traces: [] }),
    } satisfies NonNullable<Window["mythosStudio"]>;
    Object.assign(bridge, {
      emergencyStopAutopilotLocal: async (localCampaignId: string) => {
        await window.__recordAutopilotEmergencyStopStep("local", localCampaignId);
        if (!localStopTracked) {
          throw new Error("autopilot_local_stop_tracking_failed");
        }
        return { tracking: true };
      },
    });
    window.mythosStudio = bridge;
  }, { apiBaseUrl, localStopTracked: tracking });
}

test("Autopilot route renders a live projection and completes the emergency-stop flow", async ({
  page,
}) => {
  const apiRequests: string[] = [];
  const clientErrors: string[] = [];
  let projectionReads = 0;
  const stopSteps: string[] = [];
  const localCampaignIds: string[] = [];
  const prepareRequests: Array<Record<string, unknown>> = [];
  const stopRequests: Array<Record<string, unknown>> = [];
  page.on("request", (request) => {
    if (new URL(request.url()).pathname.includes("/mythos/campaigns/")) {
      apiRequests.push(request.url());
    }
  });
  page.on("pageerror", (error) => clientErrors.push(error.message));
  page.on("console", (message) => {
    if (message.type() === "error") {
      clientErrors.push(message.text());
    }
  });
  await installDesktopStopBridge(page, stopSteps, true, localCampaignIds);
  await installAutopilotApi({
    currentProjection: projection(),
    onPrepare: (body) => {
      stopSteps.push("prepare");
      prepareRequests.push(body);
    },
    onProjectionRead: () => {
      projectionReads += 1;
    },
    onStop: (body) => {
      stopSteps.push("server");
      stopRequests.push(body);
    },
  });

  await page.goto(`/campaigns/${campaignId}/autopilot`);

  await expect(page).toHaveURL(new RegExp(`/campaigns/${campaignId}/autopilot$`));
  await page.waitForTimeout(500);
  expect(clientErrors).toEqual([]);
  await expect.poll(() => apiRequests).toEqual([
    `${apiOrigin}/mythos/campaigns/${campaignId}/autopilot`,
  ]);
  await expect(page.getByRole("heading", { level: 1, name: "漏洞赏金自动驾驶" })).toBeVisible();
  await expect(page.getByTestId("autopilot-data-state")).toHaveText("实时数据");
  await expect(page.getByTestId("autopilot-summary")).toContainText("下一分支：branch_authz");
  await expect(page.getByTestId("autopilot-active-leases")).toHaveText("1");
  await expect(page.getByTestId("autopilot-submission-blocked")).toHaveText("已阻断");

  page.once("dialog", async (dialog) => {
    expect(dialog.type()).toBe("confirm");
    expect(dialog.message()).toBe("确认紧急停止当前活动，并撤销所有生效租约？");
    await dialog.accept();
  });
  await page.getByTestId("autopilot-emergency-stop").click();

  await expect.poll(() => prepareRequests).toEqual([
    { actor: "operator", reason: "operator_emergency_stop" },
  ]);
  await expect.poll(() => stopRequests).toEqual([
    {
      actor: "operator",
      confirmation_nonce: "nonce_lab",
      reason: "operator_emergency_stop",
    },
  ]);
  await expect.poll(() => stopSteps).toEqual(["prepare", "server", "local"]);
  await expect.poll(() => localCampaignIds).toEqual([campaignId]);
  await expect(page.getByTestId("autopilot-summary")).toHaveText(
    "紧急停止已启用，所有租约已撤销",
  );
  await expect(page.getByTestId("autopilot-active-leases")).toHaveText("0");
  await expect(page.getByTestId("autopilot-emergency-stop")).toBeDisabled();
  await expect.poll(() => projectionReads).toBeGreaterThanOrEqual(2);
});

test("Autopilot server stop remains authoritative when local watcher tracking fails", async ({ page }) => {
  const stopSteps: string[] = [];
  const stopRequests: Array<Record<string, unknown>> = [];
  await installDesktopStopBridge(page, stopSteps, false);
  await installAutopilotApi({
    currentProjection: projection(),
    onPrepare: () => {
      stopSteps.push("prepare");
    },
    onStop: (body) => {
      stopSteps.push("server");
      stopRequests.push(body);
    },
  });

  await page.goto(`/campaigns/${campaignId}/autopilot`);
  page.once("dialog", (dialog) => dialog.accept());
  await page.getByTestId("autopilot-emergency-stop").click();

  await expect.poll(() => stopSteps).toEqual(["prepare", "server", "local"]);
  await expect.poll(() => stopRequests).toEqual([
    {
      actor: "operator",
      confirmation_nonce: "nonce_lab",
      reason: "operator_emergency_stop",
    },
  ]);
  await expect(page.getByTestId("autopilot-summary")).toHaveText(
    "紧急停止已启用，所有租约已撤销",
  );
  await expect(page.getByTestId("autopilot-emergency-stop")).toBeDisabled();
  await expect(page.getByTestId("autopilot-error")).toHaveCount(0);
});

test("Autopilot route marks an old projection stale and disables non-stop controls", async ({
  page,
}) => {
  await installDesktopStopBridge(page, [], true);
  await installAutopilotApi({
    currentProjection: projection({
      projection_generated_at: new Date(Date.now() - 121_000).toISOString(),
    }),
  });

  await page.goto(`/campaigns/${campaignId}/autopilot`);

  await expect(page.getByTestId("autopilot-data-state")).toHaveText(
    "数据已过期，执行状态未知",
  );
  await expect(page.getByRole("button", { name: "提高优先级" })).toBeDisabled();
  await expect(page.getByTestId("autopilot-emergency-stop")).toBeEnabled();
});

test("Autopilot route expires a previously live projection and locks non-stop controls", async ({
  page,
}) => {
  const startAt = new Date("2026-01-01T00:00:00.000Z").getTime();
  await page.clock.install({ time: startAt });
  await installDesktopStopBridge(page, [], true);
  await installAutopilotApi({
    currentProjection: projection({
      projection_generated_at: new Date(startAt).toISOString(),
    }),
  });

  await page.goto(`/campaigns/${campaignId}/autopilot`);

  await expect(page.getByTestId("autopilot-data-state")).toHaveText("实时数据");
  await page.clock.fastForward(120_001);
  await expect(page.getByTestId("autopilot-data-state")).toHaveText(
    "数据已过期，执行状态未知",
  );
  await expect(page.getByRole("button", { name: "提高优先级" })).toBeDisabled();
  await expect(page.getByTestId("autopilot-emergency-stop")).toBeEnabled();
});

test("Autopilot route shows an unavailable state when the required projection fails", async ({
  page,
}) => {
  await installDesktopStopBridge(page, [], true);
  await installAutopilotApi({
    currentProjection: projection(),
    failProjection: true,
  });

  await page.goto(`/campaigns/${campaignId}/autopilot`);

  await expect(page.getByTestId("autopilot-data-state")).toHaveText(
    "数据不可用，执行状态未知",
  );
  await expect(page.getByTestId("autopilot-error")).toBeVisible();
  await expect(page.getByTestId("autopilot-summary")).toHaveText("没有可执行的分支");
});
