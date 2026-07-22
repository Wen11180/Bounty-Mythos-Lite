import { createServer, type IncomingMessage, type Server } from "node:http";
import { expect, test, type Page } from "@playwright/test";

const mockApiPort = Number(process.env.E2E_MOCK_API_PORT ?? 46087);
const labPort = Number(process.env.E2E_LAB_PORT ?? 43110);
const webPort = Number(process.env.E2E_WEB_PORT ?? 3100);
const fallbackRunId = "dry_run_2026_07_03_001";

let mockApi: Server;
let localLab: Server;
const labApiRequests: Array<{ body: unknown; path: string }> = [];
const labHttpRequests: string[] = [];
let latestLabApprovalExpiry = "";

test.beforeAll(async () => {
  mockApi = createServer(async (request, response) => {
    const responseHeaders = {
      "Access-Control-Allow-Headers": "Content-Type",
      "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
      "Access-Control-Allow-Origin": `http://127.0.0.1:${webPort}`,
      "Content-Type": "application/json",
    };
    if (request.method === "OPTIONS") {
      response.writeHead(204, responseHeaders);
      response.end();
      return;
    }
    if (request.method === "POST" && request.url === "/mythos/source-audit/scans") {
      response.writeHead(200, responseHeaders);
      response.end(
        JSON.stringify({
          artifact_id: "artifact_e2e_source_audit",
          hypothesis_count: 1,
          report_title: "Browser E2E source audit",
          run_id: fallbackRunId,
          safety_notes: [
            "scope_guard_required",
            "local_files_only",
            "no_live_requests",
            "human_review_required",
          ],
          scope_status: "in_scope",
          submission_blocked: true,
        }),
      );
      return;
    }

    if (
      request.method === "POST" &&
      request.url === "/mythos/studio/black-box-lab/leases/preview"
    ) {
      const body = await readJsonBody(request);
      labApiRequests.push({ body, path: request.url });
      const lease = body as {
        active_origin?: unknown;
        sessions?: Array<{ ready?: unknown; session_alias?: unknown }>;
        workflows?: Array<{ origin?: unknown; workflow_alias?: unknown }>;
      };
      const activeOrigin = `http://127.0.0.1:${labPort}`;
      const valid =
        lease.active_origin === activeOrigin &&
        lease.sessions?.length === 2 &&
        lease.workflows?.length === 1 &&
        lease.workflows[0]?.origin === activeOrigin;
      if (!valid || !lease.sessions || !lease.workflows) {
        response.writeHead(422, responseHeaders);
        response.end(JSON.stringify({ detail: "bounded_loopback_lease_required" }));
        return;
      }
      response.writeHead(200, responseHeaders);
      response.end(
        JSON.stringify({
          active_origin: activeOrigin,
          blocked_actions: [
            "remote_origin",
            "credential_input",
            "session_persistence",
            "automatic_report_submission",
          ],
          execution_allowed: false,
          human_approval_required: true,
          persist_session_state: false,
          profile: "local_lab",
          session_aliases: lease.sessions.map((session) => session.session_alias),
          sessions_ready: lease.sessions.every((session) => session.ready === true),
          trace_review_required: true,
          workflow_aliases: lease.workflows.map((workflow) => workflow.workflow_alias),
        }),
      );
      return;
    }

    if (
      request.method === "POST" &&
      request.url === "/mythos/studio/black-box-lab/runs/approve"
    ) {
      const body = await readJsonBody(request);
      labApiRequests.push({ body, path: request.url });
      const approval = body as {
        operator_confirmed?: unknown;
        trace_review?: Array<{ redacted?: unknown }>;
        validation_run_id?: unknown;
      };
      if (
        approval.operator_confirmed !== true ||
        approval.validation_run_id !== "validation-e2e" ||
        approval.trace_review?.length !== 1 ||
        approval.trace_review[0]?.redacted !== true
      ) {
        response.writeHead(409, responseHeaders);
        response.end(JSON.stringify({ detail: "reviewed_trace_set_required" }));
        return;
      }
      latestLabApprovalExpiry = new Date(Date.now() + 15 * 60 * 1000).toISOString();
      response.writeHead(200, responseHeaders);
      response.end(
        JSON.stringify({
          approval_id: "approval-e2e",
          approval_status: "approved",
          approved_session_alias: "session_b",
          approved_workflow_alias: "read_widget_a",
          complete_plan_digest: `sha256:${"d".repeat(64)}`,
          execution_allowed: false,
          expires_at: latestLabApprovalExpiry,
          lease_digest: `sha256:${"b".repeat(64)}`,
          local_runner_dispatch_allowed: true,
          plan_digest: "plan_sha256_local_lab",
          reason: "bounded_local_lab_run_approved",
          report_submission_allowed: false,
          scope_reference: `sha256:${"c".repeat(64)}`,
          validation_run_id: "validation-e2e",
        }),
      );
      return;
    }

    if (
      request.method === "POST" &&
      request.url === "/mythos/studio/black-box-lab/runs/preflight"
    ) {
      const body = await readJsonBody(request);
      labApiRequests.push({ body, path: request.url });
      const preflight = body as {
        approval_id?: unknown;
        complete_plan?: { validation_run_id?: unknown };
        complete_plan_digest?: unknown;
        lease_digest?: unknown;
      };
      if (
        preflight.approval_id !== "approval-e2e" ||
        preflight.complete_plan?.validation_run_id !== "validation-e2e" ||
        preflight.complete_plan_digest !== `sha256:${"d".repeat(64)}` ||
        preflight.lease_digest !== `sha256:${"b".repeat(64)}`
      ) {
        response.writeHead(409, responseHeaders);
        response.end(JSON.stringify({ detail: "fresh_complete_local_plan_preflight_required" }));
        return;
      }
      response.writeHead(200, responseHeaders);
      response.end(
        JSON.stringify({
          approval_id: "approval-e2e",
          approved_session_alias: "session_b",
          approved_workflow_alias: "read_widget_a",
          complete_plan_digest: `sha256:${"d".repeat(64)}`,
          execution_allowed: false,
          expires_at: latestLabApprovalExpiry,
          lease_digest: `sha256:${"b".repeat(64)}`,
          local_runner_dispatch_allowed: true,
          plan_digest: "plan_sha256_local_lab",
          report_submission_allowed: false,
          scope_reference: `sha256:${"c".repeat(64)}`,
          validation_run_id: "validation-e2e",
        }),
      );
      return;
    }

    if (
      request.method === "POST" &&
      request.url === "/mythos/studio/black-box-lab/runs/bounded-result"
    ) {
      const body = await readJsonBody(request);
      labApiRequests.push({ body, path: request.url });
      const result = body as {
        exact_preflight?: {
          approval_id?: unknown;
          complete_plan?: { validation_run_id?: unknown };
          complete_plan_digest?: unknown;
          lease_digest?: unknown;
        };
        trace?: {
          aliases?: { account_alias?: unknown; session_alias?: unknown; workflow_alias?: unknown };
          method?: unknown;
          parameters?: Array<{ location?: unknown; name?: unknown; value_type?: unknown }>;
          response_schema_fingerprint?: unknown;
          route_template?: unknown;
          status_class?: unknown;
          timing_bucket?: unknown;
        };
      };
      const valid =
        result.exact_preflight?.approval_id === "approval-e2e" &&
        result.exact_preflight.complete_plan?.validation_run_id === "validation-e2e" &&
        result.exact_preflight.complete_plan_digest === `sha256:${"d".repeat(64)}` &&
        result.exact_preflight.lease_digest === `sha256:${"b".repeat(64)}` &&
        result.trace?.aliases?.account_alias === "account_b" &&
        result.trace.aliases?.session_alias === "session_b" &&
        result.trace.aliases?.workflow_alias === "read_widget_a" &&
        result.trace.method === "GET" &&
        result.trace.parameters?.length === 1 &&
        result.trace.parameters[0]?.location === "path" &&
        result.trace.parameters[0]?.name === "object" &&
        result.trace.parameters[0]?.value_type === "object_alias" &&
        typeof result.trace.response_schema_fingerprint === "string" &&
        /^sha256:[0-9a-f]{64}$/u.test(result.trace.response_schema_fingerprint) &&
        result.trace.route_template === "/widgets/{object}" &&
        result.trace.status_class === "2xx" &&
        result.trace.timing_bucket === "over_2s" &&
        !/authorization|cookie|password|secret|storage_state|raw_headers|raw_body|token/i.test(
          JSON.stringify(body),
        );
      if (!valid) {
        response.writeHead(422, responseHeaders);
        response.end(JSON.stringify({ detail: "bounded_result_required" }));
        return;
      }
      response.writeHead(200, responseHeaders);
      response.end(
        JSON.stringify({
          campaign_id: "campaign-e2e",
          difference_labels: ["response_schema_changed"],
          evidence_ref_count: 1,
          execution_allowed: false,
          human_review_required: true,
          pipeline_run_id: "pipeline-e2e",
          report_preview_refreshed: true,
          report_submission_allowed: false,
          result_digest: `sha256:${"e".repeat(64)}`,
          submission_blocked: true,
          validation_run_id: "validation-e2e",
          validation_status: "needs_evidence",
        }),
      );
      return;
    }

    response.writeHead(404, responseHeaders);
    response.end(JSON.stringify({ detail: "not_found" }));
  });

  localLab = createServer((request, response) => {
    const origin = `http://127.0.0.1:${webPort}`;
    if (request.method === "OPTIONS") {
      response.writeHead(204, {
        "Access-Control-Allow-Headers": "X-Lab-Session",
        "Access-Control-Allow-Methods": "GET, OPTIONS",
        "Access-Control-Allow-Origin": origin,
      });
      response.end();
      return;
    }
    if (request.method === "GET" && request.url === "/widgets/object-a") {
      labHttpRequests.push(request.url);
      response.writeHead(200, {
        "Access-Control-Allow-Origin": origin,
        "Content-Type": "application/json",
      });
      response.end(JSON.stringify({ kind: "synthetic_widget" }));
      return;
    }
    response.writeHead(404, {
      "Access-Control-Allow-Origin": origin,
      "Content-Type": "application/json",
    });
    response.end(JSON.stringify({ kind: "not_found" }));
  });

  await Promise.all([
    listen(mockApi, mockApiPort),
    listen(localLab, labPort),
  ]);
});

test.afterAll(async () => {
  await Promise.all([close(mockApi), close(localLab)]);
});

test("V0 rendered source-audit flow stays human gated", async ({ page }) => {
  await page.goto("/source-audit");

  await expect(page.getByRole("heading", { name: "Source Audit" })).toBeVisible();
  await expect(page.getByText("submission_blocked")).toBeVisible();

  await page.getByLabel("Repository path").fill("C:/authorized/local/repo");
  await page.getByLabel("Scope policy path").fill("C:/authorized/scope.yaml");
  await page.getByLabel("Policy text").fill("allowed_repos only; no live validation");
  await page.getByRole("button", { name: "Start Source Audit" }).click();

  await expect(page).toHaveURL(new RegExp(`/runs/${fallbackRunId}$`));
  await expect(page.getByRole("heading", { level: 1 })).toBeVisible();
  await expect(page.getByRole("heading", { name: "Validation Gate" })).toBeVisible();
  await expect(page.getByRole("link", { name: "Review validation" })).toBeVisible();
  await expect(page.getByRole("link", { name: "Report" })).toBeVisible();

  await expect(page.getByRole("button", { name: /execute validation/i })).toHaveCount(0);
  await expect(page.getByRole("button", { name: /submit report/i })).toHaveCount(0);
  await expect(page.getByRole("button", { name: /approve validation/i })).toHaveCount(0);

  await page.getByRole("link", { name: "Report" }).click();
  await expect(page).toHaveURL(new RegExp(`/reports/${fallbackRunId}$`));
  await expect(page.getByRole("heading", { name: "Manual submission gate" })).toBeVisible();
  await expect(
    page.getByText("Manual submission gate", { exact: true }).locator("..").getByText("Submission blocked"),
  ).toBeVisible({ timeout: 10000 });
  await expect(page.getByRole("button", { name: /submit report/i })).toHaveCount(0);

  await page.getByRole("link", { name: "Review validation" }).click();
  await expect(page).toHaveURL(new RegExp(`/validation-workspace/${fallbackRunId}$`));
  await expect(page.getByRole("heading", { name: "Validation Workspace" })).toBeVisible();
  await expect(page.getByRole("heading", { name: "Preflight Gate" })).toBeVisible();
  await expect(page.getByText("Preflight blocked")).toBeVisible();
  await expect(page.getByRole("button", { name: /execute validation/i })).toHaveCount(0);
  await expect(page.getByRole("button", { name: /approve validation/i })).toHaveCount(0);
});

test("Studio completes one explicit bounded trial over real loopback HTTP", async ({ page }) => {
  const labOrigin = `http://127.0.0.1:${labPort}`;
  labApiRequests.length = 0;
  labHttpRequests.length = 0;
  await page.addInitScript(
    ({ origin }) => {
      const labWindow = window as typeof window & { __mythosTrialCalls: number };
      labWindow.__mythosTrialCalls = 0;
      type Workflow = {
        aliases: {
          account_alias: string;
          object_aliases: string[];
          role_alias: string;
          session_alias: "session_a" | "session_b";
          workflow_alias: string;
        };
        method: string;
        route_template: string;
      };
      type SafeTrace = {
        aliases: Workflow["aliases"];
        method: string;
        parameters: Array<{ location: string; name: string; value_type: string }>;
        response_schema_fingerprint: string;
        route_template: string;
        status_class: string;
        timing_bucket: string;
      };

      let sessionsCreated = false;
      let recording = false;
      let workflow: Workflow | null = null;
      let recordedTrace: SafeTrace | null = null;

      async function fingerprint(response: Response) {
        const contentType = (response.headers.get("content-type") ?? "unknown").split(";")[0];
        const statusClass = `${Math.floor(response.status / 100)}xx`;
        const bytes = await crypto.subtle.digest(
          "SHA-256",
          new TextEncoder().encode(`${statusClass}|${contentType}`),
        );
        return `sha256:${Array.from(new Uint8Array(bytes), (value) =>
          value.toString(16).padStart(2, "0"),
        ).join("")}`;
      }

      async function buildTrace(
        response: Response,
        sessionAlias: "session_a" | "session_b",
        accountAlias: string,
        timingBucket = "under_500ms",
      ): Promise<SafeTrace> {
        if (!workflow) {
          throw new Error("workflow_required");
        }
        return {
          aliases: {
            ...workflow.aliases,
            account_alias: accountAlias,
            session_alias: sessionAlias,
          },
          method: workflow.method,
          parameters: [
            { location: "path", name: "object", value_type: "object_alias" },
          ],
          response_schema_fingerprint: await fingerprint(response),
          route_template: workflow.route_template,
          status_class: `${Math.floor(response.status / 100)}xx`,
          timing_bucket: timingBucket,
        };
      }

      window.__recordMythosLabRequest = async () => {
        if (!recording) {
          throw new Error("recording_required");
        }
        const response = await fetch(`${origin}/widgets/object-a`, {
          headers: { "X-Lab-Session": "account_a" },
        });
        recordedTrace = await buildTrace(response, "session_a", "account_a");
      };
      const bridge = {
        async createBlackBoxSessions(payload) {
          const request = payload as {
            lease?: { active_origins?: unknown[] };
            sessions?: unknown[];
          };
          if (
            request.lease?.active_origins?.length !== 1 ||
            request.lease.active_origins[0] !== origin ||
            request.sessions?.length !== 2
          ) {
            throw new Error("bounded_sessions_required");
          }
          sessionsCreated = true;
          return `${JSON.stringify({
            event: "sessions_created",
            session_aliases: ["session_a", "session_b"],
            state: "awaiting_sessions_ready",
          })}\n`;
        },
        async refreshProgramRules() {
          return { next_due_at: null, processed: false, status: "idle" };
        },
        async startBlackBoxRecording(payload) {
          const request = payload as { sessions_ready?: unknown; workflows?: Workflow[] };
          if (!sessionsCreated || request.sessions_ready !== true || request.workflows?.length !== 1) {
            throw new Error("ready_workflow_required");
          }
          workflow = request.workflows[0];
          recording = true;
          recordedTrace = null;
          return `${JSON.stringify({ event: "recording_started", state: "recording" })}\n`;
        },
        async stopBlackBoxRecording() {
          recording = false;
          return `${JSON.stringify({
            event: "recording_stopped",
            traces: recordedTrace ? [recordedTrace] : [],
          })}\n`;
        },
        async runBlackBoxTrial(payload) {
          labWindow.__mythosTrialCalls += 1;
          if (
            payload.session_alias !== "session_b" ||
            payload.workflow_alias !== "read_widget_a"
          ) {
            throw new Error("approved_aliases_required");
          }
          const response = await fetch(`${origin}/widgets/object-a`, {
            headers: { "X-Lab-Session": "account_b" },
          });
          const trace = await buildTrace(response, "session_b", "account_b", "under_3s");
          return `${JSON.stringify({ event: "trial_result", trace })}\n`;
        },
        async closeBlackBoxSessions() {
          sessionsCreated = false;
          recording = false;
          workflow = null;
          recordedTrace = null;
          return `${JSON.stringify({ event: "sessions_closed", reason: "operator_stop" })}\n`;
        },
        async selectDirectory() {
          return null;
        },
        async selectFile() {
          return null;
        },
      } satisfies NonNullable<Window["mythosStudio"]>;
      window.mythosStudio = bridge;
    },
    { origin: labOrigin },
  );

  await page.goto("/studio");
  const summary = page.getByText("Enable explicit local black-box lab");
  await expect(summary).toBeVisible();
  await summary.click();
  await page.getByLabel("Active loopback origin").fill(labOrigin);

  await page.getByRole("button", { name: "Preview bounded lease" }).click();
  await page.getByRole("button", { name: "Create two sessions" }).click();
  await page.getByLabel("Session A ready").check();
  await page.getByLabel("Session B ready").check();
  await page.getByRole("button", { name: "Preview bounded lease" }).click();
  await page.getByRole("button", { name: "Start recording" }).click();
  await page.evaluate(async () => {
    await window.__recordMythosLabRequest();
  });
  await page.getByRole("button", { name: "Stop recording" }).click();

  await expect(page.getByText(/session_a \/ read_widget_a \/ \/widgets\/\{object\}/)).toBeVisible();
  await page.getByRole("button", { name: "Review normalized traces" }).click();
  await page.getByLabel("Durable validation run ID").fill("validation-e2e");
  await page.getByRole("button", { name: "Review and approve complete plan" }).evaluate(
    (button) => {
      (button as HTMLButtonElement).click();
      (button as HTMLButtonElement).click();
    },
  );
  await expect(
    page
      .getByTestId("studio-conversation")
      .getByText("One bounded local differential trial completed; result remains review-only."),
  ).toBeVisible();
  await expect(
    page.getByText(
      "Report preview refreshed from the bounded local-lab result; human review remains required.",
    ),
  ).toBeVisible();
  await page.getByRole("button", { name: "Stop local lab" }).click();
  await expect(
    page
      .getByTestId("studio-conversation")
      .getByText("Local lab stopped; ephemeral session and review state cleared."),
  ).toBeVisible();

  expect(labHttpRequests).toEqual(["/widgets/object-a", "/widgets/object-a"]);
  expect(
    await page.evaluate(
      () => (window as typeof window & { __mythosTrialCalls: number }).__mythosTrialCalls,
    ),
  ).toBe(1);
  expect(labApiRequests.map((request) => request.path)).toEqual([
    "/mythos/studio/black-box-lab/leases/preview",
    "/mythos/studio/black-box-lab/leases/preview",
    "/mythos/studio/black-box-lab/runs/approve",
    "/mythos/studio/black-box-lab/runs/preflight",
    "/mythos/studio/black-box-lab/runs/bounded-result",
  ]);
  expect(JSON.stringify(labApiRequests)).not.toMatch(
    /authorization|cookie|password|secret|storage_state|raw_headers|raw_body|token/i,
  );
});

test("Studio rejects changed approval and exact-preflight dispatch facts without a trial", async ({
  page,
}) => {
  await installSyntheticLocalLabBridge(page);
  await page.route("**/mythos/studio/black-box-lab/runs/approve", async (route) => {
    await route.fulfill({
      contentType: "application/json",
      json: localLabDispatchFacts({ approved_session_alias: "session_changed" }),
      status: 200,
    });
  });
  await prepareSyntheticLocalLabPlan(page);
  await page.getByRole("button", { name: "Review and approve complete plan" }).click();
  await expect(page.getByText(/Complete local lab plan failed/)).toBeVisible();
  expect(await browserTrialCalls(page)).toBe(0);

  await page.unroute("**/mythos/studio/black-box-lab/runs/approve");
  await page.route("**/mythos/studio/black-box-lab/runs/preflight", async (route) => {
    await route.fulfill({
      contentType: "application/json",
      json: localLabDispatchFacts({ lease_digest: `sha256:${"0".repeat(64)}` }),
      status: 200,
    });
  });
  await page.getByRole("button", { name: "Review and approve complete plan" }).click();
  await expect(page.getByText(/Complete local lab plan failed/)).toHaveCount(2);
  expect(await browserTrialCalls(page)).toBe(0);
});

test("Studio rejects expired approval before exact preflight and trial", async ({ page }) => {
  await installSyntheticLocalLabBridge(page);
  await page.route("**/mythos/studio/black-box-lab/runs/approve", async (route) => {
    await route.fulfill({
      contentType: "application/json",
      json: localLabDispatchFacts({ expires_at: "2020-01-01T00:00:00Z" }),
      status: 200,
    });
  });
  await prepareSyntheticLocalLabPlan(page);

  await page.getByRole("button", { name: "Review and approve complete plan" }).click();

  await expect(page.getByText(/Complete local lab plan failed/)).toBeVisible();
  expect(await browserTrialCalls(page)).toBe(0);
});

for (const mutation of ["origin", "readiness", "plan"] as const) {
  test(`Studio rejects ${mutation} generation mutation while approval is pending`, async ({
    page,
  }) => {
    await installSyntheticLocalLabBridge(page);
    await page.route("**/mythos/studio/black-box-lab/runs/approve", async (route) => {
      await new Promise((resolve) => setTimeout(resolve, 150));
      await route.fulfill({
        contentType: "application/json",
        json: localLabDispatchFacts(),
        status: 200,
      });
    });
    await prepareSyntheticLocalLabPlan(page);
    await page.getByRole("button", { name: "Review and approve complete plan" }).click();
    await mutatePendingLocalPlan(page, mutation);

    await expect(page.getByText(/Complete local lab plan failed/)).toBeVisible();
    expect(await browserTrialCalls(page)).toBe(0);
  });
}

test("Studio reload during delayed exact preflight never dispatches a trial", async ({ page }) => {
  labApiRequests.length = 0;
  await installSyntheticLocalLabBridge(page);
  let signalPreflightEntered: () => void = () => undefined;
  const preflightEntered = new Promise<void>((resolve) => {
    signalPreflightEntered = resolve;
  });
  await page.route("**/mythos/studio/black-box-lab/runs/preflight", async (route) => {
    signalPreflightEntered();
    await new Promise((resolve) => setTimeout(resolve, 300));
    await route.fulfill({
      contentType: "application/json",
      json: localLabDispatchFacts(),
      status: 200,
    }).catch(() => undefined);
  });
  await prepareSyntheticLocalLabPlan(page);
  await page.getByRole("button", { name: "Review and approve complete plan" }).click();
  await preflightEntered;

  await page.reload();

  expect(await browserTrialCalls(page)).toBe(0);
});

test("Studio bridge stop does not promote trial completion or report readiness", async ({ page }) => {
  labApiRequests.length = 0;
  await installSyntheticLocalLabBridge(page, "stop");
  const facts = localLabDispatchFacts();
  await page.route("**/mythos/studio/black-box-lab/runs/approve", async (route) => {
    await route.fulfill({ contentType: "application/json", json: facts, status: 200 });
  });
  await page.route("**/mythos/studio/black-box-lab/runs/preflight", async (route) => {
    await route.fulfill({ contentType: "application/json", json: facts, status: 200 });
  });
  await prepareSyntheticLocalLabPlan(page);

  await page.getByRole("button", { name: "Review and approve complete plan" }).click();

  await expect(page.getByText("Local trial stopped: operator_stop.")).toBeVisible();
  await expect(
    page.getByText("One bounded local differential trial completed; result remains review-only."),
  ).toHaveCount(0);
  expect(await browserTrialCalls(page)).toBe(1);
  expect(
    labApiRequests.map((request) => request.path),
  ).not.toContain("/mythos/studio/black-box-lab/runs/bounded-result");
});

function localLabDispatchFacts(overrides: Record<string, unknown> = {}) {
  return {
    approval_id: "approval-e2e",
    approval_status: "approved",
    approved_session_alias: "session_b",
    approved_workflow_alias: "read_widget_a",
    complete_plan_digest: `sha256:${"d".repeat(64)}`,
    execution_allowed: false,
    expires_at: new Date(Date.now() + 15 * 60 * 1000).toISOString(),
    lease_digest: `sha256:${"b".repeat(64)}`,
    local_runner_dispatch_allowed: true,
    plan_digest: "plan_sha256_local_lab",
    reason: "bounded_local_lab_run_approved",
    report_submission_allowed: false,
    scope_reference: `sha256:${"c".repeat(64)}`,
    validation_run_id: "validation-e2e",
    ...overrides,
  };
}

async function installSyntheticLocalLabBridge(
  page: Page,
  trialEvent: "result" | "stop" = "result",
) {
  await page.addInitScript(({ event }) => {
    const labWindow = window as typeof window & { __mythosTrialCalls: number };
    labWindow.__mythosTrialCalls = Number(window.name || "0");
    const trace = {
      aliases: {
        account_alias: "account_a",
        object_aliases: ["widget_a"],
        role_alias: "member",
        session_alias: "session_a",
        workflow_alias: "read_widget_a",
      },
      method: "GET",
      parameters: [{ location: "path", name: "object", value_type: "object_alias" }],
      response_schema_fingerprint: `sha256:${"a".repeat(64)}`,
      route_template: "/widgets/{object}",
      status_class: "2xx",
      timing_bucket: "under_500ms",
    };
    window.mythosStudio = {
      async closeBlackBoxSessions() {
        return `${JSON.stringify({ event: "sessions_closed", reason: "operator_stop" })}\n`;
      },
      async createBlackBoxSessions() {
        return `${JSON.stringify({ event: "sessions_created" })}\n`;
      },
      async refreshProgramRules() {
        return { next_due_at: null, processed: false, status: "idle" };
      },
      async runBlackBoxTrial() {
        labWindow.__mythosTrialCalls += 1;
        window.name = String(labWindow.__mythosTrialCalls);
        return event === "stop"
          ? `${JSON.stringify({ event: "stop", reason: "operator_stop", terminal: true })}\n`
          : `${JSON.stringify({ event: "trial_result", trace })}\n`;
      },
      async selectDirectory() {
        return null;
      },
      async selectFile() {
        return null;
      },
      async startBlackBoxRecording() {
        return `${JSON.stringify({ event: "recording_started" })}\n`;
      },
      async stopBlackBoxRecording() {
        return `${JSON.stringify({ event: "recording_stopped", traces: [trace] })}\n`;
      },
    };
  }, { event: trialEvent });
}

async function prepareSyntheticLocalLabPlan(page: Page) {
  await page.goto("/studio");
  await page.getByText("Enable explicit local black-box lab").click();
  await page.getByLabel("Active loopback origin").fill(`http://127.0.0.1:${labPort}`);
  await page.getByRole("button", { name: "Preview bounded lease" }).click();
  await page.getByRole("button", { name: "Create two sessions" }).click();
  await page.getByLabel("Session A ready").check();
  await page.getByLabel("Session B ready").check();
  await page.getByRole("button", { name: "Preview bounded lease" }).click();
  await page.getByRole("button", { name: "Start recording" }).click();
  await page.getByRole("button", { name: "Stop recording" }).click();
  await page.getByRole("button", { name: "Review normalized traces" }).click();
  await page.getByLabel("Durable validation run ID").fill("validation-e2e");
}

async function mutatePendingLocalPlan(
  page: Page,
  mutation: "origin" | "readiness" | "plan",
) {
  const locator = mutation === "origin"
    ? page.getByLabel("Active loopback origin")
    : mutation === "readiness"
      ? page.getByLabel("Session B ready")
      : page.getByLabel("Durable validation run ID");
  await locator.evaluate((element, kind) => {
    if (kind === "readiness") {
      const input = element as HTMLInputElement;
      const setter = Object.getOwnPropertyDescriptor(
        HTMLInputElement.prototype,
        "checked",
      )?.set;
      setter?.call(input, false);
      input.dispatchEvent(new Event("change", { bubbles: true }));
      return;
    }
    const input = element as HTMLInputElement;
    const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value")?.set;
    setter?.call(
      input,
      kind === "origin" ? "http://127.0.0.1:43111" : "validation-mutated",
    );
    input.dispatchEvent(new Event("input", { bubbles: true }));
  }, mutation);
}

async function browserTrialCalls(page: Page) {
  return page.evaluate(
    () => (window as typeof window & { __mythosTrialCalls: number }).__mythosTrialCalls,
  );
}

async function readJsonBody(request: IncomingMessage): Promise<unknown> {
  const chunks: Buffer[] = [];
  for await (const chunk of request) {
    chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
  }
  return JSON.parse(Buffer.concat(chunks).toString("utf8"));
}

async function listen(server: Server, port: number): Promise<void> {
  await new Promise<void>((resolve) => {
    server.listen(port, "127.0.0.1", resolve);
  });
}

async function close(server: Server): Promise<void> {
  if (!server.listening) {
    return;
  }
  await new Promise<void>((resolve, reject) => {
    server.close((error) => {
      if (error) {
        reject(error);
        return;
      }
      resolve();
    });
    server.closeAllConnections();
  });
}
