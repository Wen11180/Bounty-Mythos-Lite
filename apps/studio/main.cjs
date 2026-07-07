const { app, BrowserWindow } = require("electron");
const { spawn } = require("node:child_process");
const path = require("node:path");

const { createStudioLaunchConfig, startupErrorHtml, waitForUrl } = require("./launcher.cjs");

const root = path.resolve(__dirname, "..", "..");
const children = [];

function spawnChild(command, args, cwd, env = {}) {
  const child = spawn(command, args, {
    cwd,
    shell: true,
    stdio: "inherit",
    env: {
      ...process.env,
      DATABASE_URL: process.env.DATABASE_URL || "sqlite:///./bounty_mythos_studio.db",
      REDIS_URL: process.env.REDIS_URL || "redis://localhost:6379/0",
      ...env,
    },
  });

  children.push(child);
  return child;
}

function startServices(config) {
  const apiBaseUrl = process.env.API_BASE_URL || config.apiBaseUrl;
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
  );
  spawnChild(
    "npm",
    ["run", "dev", "--", "--hostname", "127.0.0.1", "--port", String(config.webPort)],
    path.join(root, "apps", "web"),
    {
      API_BASE_URL: apiBaseUrl,
      NEXT_PUBLIC_API_BASE_URL: process.env.NEXT_PUBLIC_API_BASE_URL || apiBaseUrl,
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

function createWindow() {
  const window = new BrowserWindow({
    width: 1440,
    height: 920,
    title: "Mythos Studio",
    webPreferences: {
      contextIsolation: true,
      nodeIntegration: false,
    },
  });

  return window;
}

app.whenReady().then(async () => {
  const window = createWindow();
  try {
    const config = await createStudioLaunchConfig();
    startServices(config);
    await waitForUrl(config.studioUrl);
    window.loadURL(config.studioUrl);
  } catch (error) {
    window.loadURL(`data:text/html,${encodeURIComponent(startupErrorHtml(error))}`);
  }
});

app.on("window-all-closed", () => {
  killChildren();
  app.quit();
});
