const { app, BrowserWindow, dialog, ipcMain, utilityProcess } = require("electron");
const { execFile, spawn } = require("node:child_process");
const path = require("node:path");
const { promisify } = require("node:util");

if (require("electron-squirrel-startup")) {
  app.quit();
}

const {
  createStudioLaunchConfig,
  startupErrorHtml,
  waitForApiHealth,
  waitForStudio,
} = require("./launcher.cjs");
const { createAppExitHandler, createBlackBoxRunner } = require("./black-box-runner.cjs");
const { createLocalLabDispatchHandler } = require("./local-lab-dispatch.cjs");
const { createLocalResearchWakeup } = require("./local-research-wakeup.cjs");
const { installStudioNavigationGuard } = require("./navigation-guard.cjs");
const { createPackagedRuntime } = require("./packaged-runtime.cjs");
const {
  createStartupLiveness,
  diagnosticFromError,
  preflightDevelopmentRuntime,
  resolveDevelopmentDataDirectory,
} = require("./startup-diagnostics.cjs");
const {
  confirmDesktopRestore,
  selectDesktopBackupDestination,
  selectDesktopRestoreArchive,
  selectStudioDirectory,
  selectStudioFile,
} = require("./path-dialog.cjs");
const { createProgramRuleApiClient } = require("./program-rule-api-client.cjs");
const { createProgramRuleRefreshPump } = require("./program-rule-refresh-pump.cjs");
const { createProgramRuleRunner } = require("./program-rule-runner.cjs");
const { createRemoteLeaseApiClient } = require("./remote-api-client.cjs");

const root = path.resolve(__dirname, "..", "..");
const children = [];
const execFileAsync = promisify(execFile);
const rendererGenerations = new WeakMap();
let packagedRuntime = null;
let developmentStartupLiveness = null;
let studioApiBaseUrl = null;
let studioLaunchConfig = null;
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

function startDevelopmentServices(config, workspaceRoot) {
  preflightDevelopmentRuntime({
    apiDirectory: path.join(root, "apps", "api"),
    dataDirectory: resolveDevelopmentDataDirectory(
      process.env.DATABASE_URL || "sqlite:///./bounty_mythos_studio.db",
      path.join(root, "apps", "api"),
    ),
    webDirectory: path.join(root, "apps", "web"),
    workspaceDirectory: workspaceRoot,
  });
  developmentStartupLiveness = createStartupLiveness();
  const studioWebOrigin = new URL(config.studioUrl).origin;
  const apiChild = spawnChild(
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
  developmentStartupLiveness.watch(apiChild, "api_exited");
  const webChild = spawnChild(
    "npm",
    ["run", "dev", "--", "--hostname", "127.0.0.1", "--port", String(config.webPort)],
    path.join(root, "apps", "web"),
    {
      API_BASE_URL: config.apiBaseUrl,
      NEXT_PUBLIC_API_BASE_URL: config.apiBaseUrl,
      NEXT_PUBLIC_STUDIO_WORKSPACE_ROOT: workspaceRoot,
    },
  );
  developmentStartupLiveness.watch(webChild, "web_exited");
  return developmentStartupLiveness;
}

function startServices(config, workspaceRoot) {
  if (app.isPackaged) {
    packagedRuntime = createPackagedRuntime({
      app,
      execFile: execFileAsync,
      processObject: process,
      spawn,
      utilityProcess,
    });
    packagedRuntime.preflight();
    packagedRuntime.start(config);
    return packagedRuntime;
  }
  return startDevelopmentServices(config, workspaceRoot);
}

async function killChildren() {
  developmentStartupLiveness?.stopMonitoring();
  developmentStartupLiveness = null;
  const runtime = packagedRuntime;
  packagedRuntime = null;
  await runtime?.stop();
  await Promise.all(children.splice(0).map(stopDevelopmentChild));
}

async function stopDevelopmentChild(child) {
  if (!child || child.killed) {
    return;
  }
  if (process.platform === "win32" && Number.isInteger(child.pid) && child.pid > 0) {
    try {
      await execFileAsync("taskkill", ["/pid", String(child.pid), "/T", "/F"], {
        windowsHide: true,
      });
      return;
    } catch {}
  }
  try {
    child.kill();
  } catch {}
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

function createWindow(apiBaseUrl) {
  const window = new BrowserWindow({
    width: 1440,
    height: 920,
    title: "Mythos Studio",
    webPreferences: {
      additionalArguments: [`--mythos-api-base-url=${apiBaseUrl}`],
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

ipcMain.handle("mythos:create-backup", async (event) => {
  if (!packagedRuntime || !studioLaunchConfig) {
    return { status: "unavailable" };
  }
  const browserWindow = BrowserWindow.fromWebContents(event.sender);
  const destination = await selectDesktopBackupDestination(dialog, browserWindow);
  if (!destination) {
    return { status: "cancelled" };
  }
  await blackBoxRunner.closeSessions("operator_stop");
  try {
    const result = await packagedRuntime.createBackup(destination);
    await waitForDesktopServices();
    return result;
  } catch {
    await waitForDesktopServices().catch(() => undefined);
    return { status: "failed" };
  }
});

ipcMain.handle("mythos:restore-backup", async (event) => {
  if (!packagedRuntime || !studioLaunchConfig) {
    return { status: "unavailable" };
  }
  const browserWindow = BrowserWindow.fromWebContents(event.sender);
  const archive = await selectDesktopRestoreArchive(dialog, browserWindow);
  if (!archive || !await confirmDesktopRestore(dialog, browserWindow, archive)) {
    return { status: "cancelled" };
  }
  await blackBoxRunner.closeSessions("operator_stop");
  try {
    const result = await packagedRuntime.restoreBackup(archive);
    await waitForDesktopServices();
    return result;
  } catch {
    await waitForDesktopServices().catch(() => undefined);
    return { status: "failed" };
  }
});

ipcMain.handle("mythos:refresh-program-rules", () => {
  return programRulePump.kick();
});

app.whenReady().then(async () => {
  let window;
  try {
    const config = await createStudioLaunchConfig();
    studioLaunchConfig = config;
    window = createWindow(config.apiBaseUrl);
    const workspaceRoot =
      process.env.STUDIO_WORKSPACE_ROOT || path.join(app.getPath("userData"), "workspaces");
    studioApiBaseUrl = config.apiBaseUrl;
    const startupController = startServices(config, workspaceRoot);
    await waitForApiHealth(config.apiBaseUrl, {
      getStartupFailure: () => startupController.getStartupFailure(),
    });
    await waitForStudio(config.studioUrl, {
      getStartupFailure: () => startupController.getStartupFailure(),
    });
    startupController.markStartupReady();
    localResearchWakeup.start();
    programRulePump.start();
    installStudioNavigationGuard(window, config.studioUrl);
    window.loadURL(config.studioUrl);
  } catch (error) {
    await killChildren();
    const diagnostic = diagnosticFromError(error);
    window ??= createWindow("http://127.0.0.1:1");
    window.loadURL(
      `data:text/html,${encodeURIComponent(startupErrorHtml(diagnostic, { packaged: app.isPackaged }))}`,
    );
  }
});

app.on("window-all-closed", () => {
  app.quit();
});

app.on("before-quit", handleBeforeQuit);

async function waitForDesktopServices() {
  if (!studioLaunchConfig) {
    throw new Error("desktop_launch_config_missing");
  }
  const getStartupFailure = () => (
    app.isPackaged
      ? packagedRuntime?.getStartupFailure() ?? null
      : developmentStartupLiveness?.getStartupFailure() ?? null
  );
  await waitForApiHealth(studioLaunchConfig.apiBaseUrl, { getStartupFailure });
  await waitForStudio(studioLaunchConfig.studioUrl, { getStartupFailure });
  if (app.isPackaged) {
    packagedRuntime?.markStartupReady();
  } else {
    developmentStartupLiveness?.markStartupReady();
  }
}
