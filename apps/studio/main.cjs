const { app, BrowserWindow } = require("electron");
const { spawn } = require("node:child_process");
const path = require("node:path");

const root = path.resolve(__dirname, "..", "..");
const children = [];

function spawnChild(command, args, cwd) {
  const child = spawn(command, args, {
    cwd,
    shell: true,
    stdio: "inherit",
    env: {
      ...process.env,
      DATABASE_URL: process.env.DATABASE_URL || "sqlite:///./bounty_mythos_studio.db",
      REDIS_URL: process.env.REDIS_URL || "redis://localhost:6379/0",
      NEXT_PUBLIC_API_BASE_URL:
        process.env.NEXT_PUBLIC_API_BASE_URL || "http://localhost:8000",
      API_BASE_URL: process.env.API_BASE_URL || "http://localhost:8000",
    },
  });

  children.push(child);
  return child;
}

function startServices() {
  spawnChild(
    "python",
    ["-m", "uvicorn", "app.main:app", "--host", "127.0.0.1", "--port", "8000"],
    path.join(root, "apps", "api"),
  );
  spawnChild(
    "npm",
    ["run", "dev", "--", "--hostname", "127.0.0.1", "--port", "3000"],
    path.join(root, "apps", "web"),
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

  window.loadURL("http://127.0.0.1:3000/studio");
}

app.whenReady().then(() => {
  startServices();
  setTimeout(createWindow, 4500);
});

app.on("window-all-closed", () => {
  killChildren();
  app.quit();
});
