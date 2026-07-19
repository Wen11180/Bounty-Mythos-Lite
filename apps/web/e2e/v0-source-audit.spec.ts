import { createServer, type IncomingMessage, type Server } from "node:http";
import { expect, test } from "@playwright/test";

const mockApiPort = Number(process.env.E2E_MOCK_API_PORT ?? 46087);
const labPort = Number(process.env.E2E_LAB_PORT ?? 43110);
const webPort = Number(process.env.E2E_WEB_PORT ?? 3100);
const fallbackRunId = "dry_run_2026_07_03_001";

let mockApi: Server;
let localLab: Server;
const labApiRequests: Array<{ body: unknown; path: string }> = [];
const labHttpRequests: string[] = [];

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
      response.writeHead(200, responseHeaders);
      response.end(
        JSON.stringify({
          approval_id: "approval-e2e",
          approval_status: "approved",
          execution_allowed: false,
          lease_digest: `sha256:${"b".repeat(64)}`,
          local_runner_dispatch_allowed: true,
          reason: "bounded_local_lab_run_approved",
          report_submission_allowed: false,
          validation_run_id: "validation-e2e",
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
  ).toBeVisible();
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
          timing_bucket: "under_500ms",
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
          if (
            payload.session_alias !== "session_b" ||
            payload.workflow_alias !== "read_widget_a"
          ) {
            throw new Error("approved_aliases_required");
          }
          const response = await fetch(`${origin}/widgets/object-a`, {
            headers: { "X-Lab-Session": "account_b" },
          });
          const trace = await buildTrace(response, "session_b", "account_b");
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
  await expect(page.getByRole("button", { name: "Run approved trial" })).toBeHidden();
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
  await page.getByRole("button", { name: "Confirm bounded lab run" }).click();
  await page.getByRole("button", { name: "Run approved trial" }).click();
  await expect(
    page
      .getByTestId("studio-conversation")
      .getByText("One bounded local differential trial completed; result remains review-only."),
  ).toBeVisible();
  await page.getByRole("button", { name: "Stop local lab" }).click();
  await expect(
    page
      .getByTestId("studio-conversation")
      .getByText("Local lab stopped; ephemeral session and review state cleared."),
  ).toBeVisible();

  expect(labHttpRequests).toEqual(["/widgets/object-a", "/widgets/object-a"]);
  expect(labApiRequests.map((request) => request.path)).toEqual([
    "/mythos/studio/black-box-lab/leases/preview",
    "/mythos/studio/black-box-lab/leases/preview",
    "/mythos/studio/black-box-lab/runs/approve",
  ]);
  expect(JSON.stringify(labApiRequests)).not.toMatch(
    /authorization|cookie|password|secret|storage_state|raw_headers|raw_body|token/i,
  );
});

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
  await new Promise<void>((resolve, reject) => {
    server.close((error) => {
      if (error) {
        reject(error);
        return;
      }
      resolve();
    });
  });
}
