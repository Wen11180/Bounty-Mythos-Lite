const { app, BrowserWindow, dialog, ipcMain } = require("electron");
const { spawn } = require("node:child_process");
const path = require("node:path");

const { createStudioLaunchConfig, startupErrorHtml, waitForUrl } = require("./launcher.cjs");
const { createAppExitHandler, createBlackBoxRunner } = require("./black-box-runner.cjs");
const { createLocalLabDispatchHandler } = require("./local-lab-dispatch.cjs");
const { createLocalResearchWakeup } = require("./local-research-wakeup.cjs");
const { installStudioNavigationGuard } = require("./navigation-guard.cjs");
const { selectStudioDirectory, selectStudioFile } = require("./path-dialog.cjs");
const { createProgramRuleApiClient } = require("./program-rule-api-client.cjs");
const { createProgramRuleRefreshPump } = require("./program-rule-refresh-pump.cjs");
const { createProgramRuleRunner } = require("./program-rule-runner.cjs");
const { createRemoteLeaseApiClient } = require("./remote-api-client.cjs");

const root = path.resolve(__dirname, "..", "..");
const children = [];
const rendererGenerations = new WeakMap();
let studioApiBaseUrl = null;
const localResearchWakeup = createLocalResearchWakeup({
  getBaseUrl: () => studioApiBaseUrl,
});
const remoteLeaseApi = createRemoteLeaseApiClient({
  getBaseUrl: () => studioApiBaseUrl,
});
const programRuleApi = createProgramRuleApiClient({
  getBaseUrl: () => studioApiBaseUrl,
});
const programRuleRunner = createProgramRuleRunner({ apiClient: programRuleApi });
const programRulePump = createProgramRuleRefreshPump({ runner: programRuleRunner });
const blackBoxRunner = createBlackBoxRunner({
  authorizeRemoteRequest: remoteLeaseApi.authorize,
  completeRemoteRequest: remoteLeaseApi.complete,
  stopRemoteLease: remoteLeaseApi.stop,
});
const dispatchBlackBoxLine = createLocalLabDispatchHandler({
  closeRunnerSessions: (reason) => blackBoxRunner.closeSessions(reason),
  getApiBaseUrl: () => studioApiBaseUrl,
  runRunner: (line) => blackBoxRunner.handleLine(line),
});

function spawnChild(command, args, cwd, env = {}) {
  const child = spawn(command, args, {
    cwd,
    shell: true,
    stdio: "inherit",
    env: {
      ...process.env,
      DATABASE_URL: process.env.DATABASE_URL || "sqlite:///./bounty_mythos_studio.db",
      REDIS_URL: process.env.REDIS_URL || "redis://localhost:6379/0",
      WORKER_DISPATCH_MODE: process.env.WORKER_DISPATCH_MODE || "inline",
      ...env,
    },
  });

  children.push(child);
  return child;
}

function startServices(config, workspaceRoot) {
  const studioWebOrigin = new URL(config.studioUrl).origin;
  spawnChild(
    "python",
    [
      "-m",
      "uvicorn",
      "app.main:app",
      "--host",
      "127.0.0.1",
      "--port",
      String(config.apiPort),
    ],
    path.join(root, "apps", "api"),
    {
      STUDIO_WORKSPACE_ROOT: workspaceRoot,
      STUDIO_WEB_ORIGIN: studioWebOrigin,
    },
  );
  spawnChild(
    "npm",
    ["run", "dev", "--", "--hostname", "127.0.0.1", "--port", String(config.webPort)],
    path.join(root, "apps", "web"),
    {
      API_BASE_URL: config.apiBaseUrl,
      NEXT_PUBLIC_API_BASE_URL: config.apiBaseUrl,
      NEXT_PUBLIC_STUDIO_WORKSPACE_ROOT: workspaceRoot,
    },
  );
}

function killChildren() {
  for (const child of children) {
    if (!child.killed) {
      child.kill();
    }
  }
}

const handleBeforeQuit = createAppExitHandler({
  closeSessions: async (reason) => {
    await programRulePump.close(reason);
    await localResearchWakeup.stop();
    await blackBoxRunner.closeSessions(reason);
  },
  exit: (code) => app.exit(code),
  killChildren,
});

function createWindow() {
  const window = new BrowserWindow({
    width: 1440,
    height: 920,
    title: "Mythos Studio",
    webPreferences: {
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true,
      preload: path.join(__dirname, "preload.cjs"),
    },
  });
  rendererGenerations.set(window.webContents, 0);

  window.webContents.on(
    "did-start-navigation",
    (_event, _url, _isInPlace, isMainFrame) => {
      if (isMainFrame) {
        rendererGenerations.set(
          window.webContents,
          (rendererGenerations.get(window.webContents) ?? 0) + 1,
        );
        void blackBoxRunner.closeSessions("page_closed");
      }
    },
  );
  window.webContents.on("render-process-gone", () => {
    rendererGenerations.set(
      window.webContents,
      (rendererGenerations.get(window.webContents) ?? 0) + 1,
    );
    void blackBoxRunner.closeSessions("browser_crash");
  });

  return window;
}

ipcMain.handle("mythos:select-file", (event, options) => {
  return selectStudioFile(dialog, BrowserWindow.fromWebContents(event.sender), options);
});

ipcMain.handle("mythos:select-directory", (event, options) => {
  return selectStudioDirectory(dialog, BrowserWindow.fromWebContents(event.sender), options);
});

ipcMain.handle("mythos:black-box-runner", (event, line) => {
  const sender = event.sender;
  const generation = rendererGenerations.get(sender) ?? 0;
  return dispatchBlackBoxLine(line, {
    isCurrent: () => (
      !sender.isDestroyed()
      && rendererGenerations.get(sender) === generation
    ),
  });
});

ipcMain.handle("mythos:refresh-program-rules", () => {
  return programRulePump.kick();
});

app.whenReady().then(async () => {
  const window = createWindow();
  try {
    const workspaceRoot =
      process.env.STUDIO_WORKSPACE_ROOT || path.join(app.getPath("userData"), "workspaces");
    const config = await createStudioLaunchConfig();
    studioApiBaseUrl = config.apiBaseUrl;
    startServices(config, workspaceRoot);
    await waitForUrl(config.apiBaseUrl);
    await waitForUrl(config.studioUrl);
    localResearchWakeup.start();
    programRulePump.start();
    installStudioNavigationGuard(window, config.studioUrl);
    window.loadURL(config.studioUrl);
  } catch (error) {
    window.loadURL(`data:text/html,${encodeURIComponent(startupErrorHtml(error))}`);
  }
});

app.on("window-all-closed", () => {
  app.quit();
});

app.on("before-quit", handleBeforeQuit);
