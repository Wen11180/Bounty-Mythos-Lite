import { defineConfig, devices } from "@playwright/test";

const webPort = Number(process.env.E2E_WEB_PORT ?? 3100);
const mockApiPort = Number(process.env.E2E_MOCK_API_PORT ?? 46087);

export default defineConfig({
  testDir: "./e2e",
  workers: 1,
  timeout: 30_000,
  expect: {
    timeout: 10_000,
  },
  use: {
    baseURL: `http://127.0.0.1:${webPort}`,
    trace: "on-first-retry",
  },
  webServer: {
    command: "node scripts/start-e2e-server.mjs",
    env: {
      API_BASE_URL: `http://127.0.0.1:${mockApiPort}`,
      HOSTNAME: "127.0.0.1",
      NEXT_PUBLIC_API_BASE_URL: `http://127.0.0.1:${mockApiPort}`,
      PORT: String(webPort),
    },
    reuseExistingServer: false,
    timeout: 120_000,
    url: `http://127.0.0.1:${webPort}`,
  },
  projects: [
    {
      name: "chromium",
      testIgnore: /control-center\.visual\.spec\.ts/,
      use: { ...devices["Desktop Chrome"] },
    },
    {
      name: "visual-1680",
      testMatch: /control-center\.visual\.spec\.ts/,
      use: {
        ...devices["Desktop Chrome"],
        colorScheme: "dark",
        deviceScaleFactor: 1,
        viewport: { width: 1680, height: 944 },
      },
    },
    {
      name: "visual-1440",
      testMatch: /control-center\.visual\.spec\.ts/,
      use: {
        ...devices["Desktop Chrome"],
        colorScheme: "dark",
        deviceScaleFactor: 1,
        viewport: { width: 1440, height: 900 },
      },
    },
    {
      name: "visual-390",
      testMatch: /control-center\.visual\.spec\.ts/,
      use: {
        ...devices["Desktop Chrome"],
        colorScheme: "dark",
        deviceScaleFactor: 1,
        viewport: { width: 390, height: 844 },
      },
    },
  ],
});
