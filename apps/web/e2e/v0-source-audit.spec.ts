import { createServer, type Server } from "node:http";
import { expect, test } from "@playwright/test";

const mockApiPort = Number(process.env.E2E_MOCK_API_PORT ?? 46087);
const fallbackRunId = "dry_run_2026_07_03_001";

let mockApi: Server;

test.beforeAll(async () => {
  mockApi = createServer((request, response) => {
    if (request.method === "POST" && request.url === "/mythos/source-audit/scans") {
      response.writeHead(200, { "Content-Type": "application/json" });
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

    response.writeHead(404, { "Content-Type": "application/json" });
    response.end(JSON.stringify({ detail: "not_found" }));
  });

  await new Promise<void>((resolve) => {
    mockApi.listen(mockApiPort, "127.0.0.1", resolve);
  });
});

test.afterAll(async () => {
  await new Promise<void>((resolve, reject) => {
    mockApi.close((error) => {
      if (error) {
        reject(error);
        return;
      }
      resolve();
    });
  });
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
  await expect(page.getByText("Submission blocked").first()).toBeVisible();
  await expect(page.getByRole("button", { name: /submit report/i })).toHaveCount(0);

  await page.getByRole("link", { name: "Review validation" }).click();
  await expect(page).toHaveURL(new RegExp(`/validation-workspace/${fallbackRunId}$`));
  await expect(page.getByRole("heading", { name: "Validation Workspace" })).toBeVisible();
  await expect(page.getByRole("heading", { name: "Preflight Gate" })).toBeVisible();
  await expect(page.getByText("Preflight blocked")).toBeVisible();
  await expect(page.getByRole("button", { name: /execute validation/i })).toHaveCount(0);
  await expect(page.getByRole("button", { name: /approve validation/i })).toHaveCount(0);
});
