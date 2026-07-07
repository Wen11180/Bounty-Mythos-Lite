import { defineConfig, devices } from "@playwright/test";

const webPort = Number(process.env.E2E_WEB_PORT ?? 3100);
const mockApiPort = Number(process.env.E2E_MOCK_API_PORT ?? 46087);

export default defineConfig({
  testDir: "./e2e",
  timeout: 30_000,
  expect: {
    timeout: 10_000,
  },
  use: {
    baseURL: `http://127.0.0.1:${webPort}`,
    trace: "on-first-retry",
  },
  webServer: {
    command: `npm run build && npm run start -- --hostname 127.0.0.1 --port ${webPort}`,
    env: {
      API_BASE_URL: `http://127.0.0.1:${mockApiPort}`,
      NEXT_PUBLIC_API_BASE_URL: `http://127.0.0.1:${mockApiPort}`,
    },
    reuseExistingServer: !process.env.CI,
    timeout: 120_000,
    url: `http://127.0.0.1:${webPort}`,
  },
  projects: [
    {
      name: "chromium",
      use: { ...devices["Desktop Chrome"] },
    },
  ],
});
