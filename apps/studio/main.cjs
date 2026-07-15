const { app, BrowserWindow, dialog, ipcMain } = require("electron");
const { spawn } = require("node:child_process");
const path = require("node:path");

const { createStudioLaunchConfig, startupErrorHtml, waitForUrl } = require("./launcher.cjs");
const { createAppExitHandler, createBlackBoxRunner } = require("./black-box-runner.cjs");
const { installStudioNavigationGuard } = require("./navigation-guard.cjs");
const { selectStudioDirectory, selectStudioFile } = require("./path-dialog.cjs");

const root = path.resolve(__dirname, "..", "..");
const children = [];
const blackBoxRunner = createBlackBoxRunner();

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
  closeSessions: (reason) => blackBoxRunner.closeSessions(reason),
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

  return window;
}

ipcMain.handle("mythos:select-file", (event, options) => {
  return selectStudioFile(dialog, BrowserWindow.fromWebContents(event.sender), options);
});

ipcMain.handle("mythos:select-directory", (event, options) => {
  return selectStudioDirectory(dialog, BrowserWindow.fromWebContents(event.sender), options);
});

ipcMain.handle("mythos:black-box-runner", (_event, line) => {
  return blackBoxRunner.handleLine(line);
});

app.whenReady().then(async () => {
  const window = createWindow();
  try {
    const workspaceRoot =
      process.env.STUDIO_WORKSPACE_ROOT || path.join(app.getPath("userData"), "workspaces");
    const config = await createStudioLaunchConfig();
    startServices(config, workspaceRoot);
    await waitForUrl(config.studioUrl);
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
