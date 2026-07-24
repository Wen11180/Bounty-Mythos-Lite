const fs = require("node:fs");
const { randomBytes } = require("node:crypto");
const path = require("node:path");
const {
  createStartupDiagnosticError,
  createStartupLiveness,
  probeStartupState,
} = require("./startup-diagnostics.cjs");

function resolvePackagedRuntimePaths({ resourcesPath, userDataPath }) {
  const resources = path.resolve(resourcesPath);
  const userData = path.resolve(userDataPath);
  const apiResources = inside(resources, "api", "_internal");
  const playwrightBrowsers = inside(resources, "playwright");
  return {
    apiAlembic: inside(apiResources, "alembic.ini"),
    apiExecutable: inside(resources, "api", "mythos-api.exe"),
    apiMigrations: inside(apiResources, "migrations"),
    apiResources,
    browserExecutable: findChromiumExecutable(playwrightBrowsers),
    databaseFile: inside(userData, "data", "bounty-mythos.db"),
    playwrightBrowsers,
    userData,
    webDirectory: inside(resources, "web"),
    webPublic: inside(resources, "web", "public"),
    webServer: inside(resources, "web", "server.js"),
    webStatic: inside(resources, "web", ".next", "static"),
    webSwcHelper: inside(
      resources,
      "web",
      "node_modules",
      "@swc",
      "helpers",
      "cjs",
      "_interop_require_default.cjs",
    ),
    workspaceRoot: inside(userData, "workspaces"),
  };
}

function assertPackagedRuntime(paths) {
  const requirements = {
    apiExecutable: "file",
    apiResources: "directory",
    apiAlembic: "file",
    apiMigrations: "directory",
    browserExecutable: "file",
    webPublic: "directory",
    webServer: "file",
    webStatic: "directory",
    webSwcHelper: "file",
  };
  for (const [key, kind] of Object.entries(requirements)) {
    const value = paths[key];
    let valid = false;
    try {
      const stat = fs.statSync(value);
      valid = kind === "file" ? stat.isFile() : stat.isDirectory();
    } catch {
      valid = false;
    }
    if (!valid) {
      throw new Error(`missing_${key}`);
    }
  }
}

function createPackagedRuntime({ app, execFile, processObject = process, spawn, utilityProcess }) {
  let apiChild = null;
  let activeConfig = null;
  let activePaths = null;
  let activeAutonomousResearchCapability = null;
  let childEnvironment = null;
  let maintenancePromise = null;
  let shutdownRequested = false;
  let startupLiveness = createStartupLiveness();
  let webChild = null;

  function preflight() {
    let paths;
    try {
      paths = resolvePackagedRuntimePaths({
        resourcesPath: processObject.resourcesPath,
        userDataPath: app.getPath("userData"),
      });
      assertPackagedRuntime(paths);
    } catch {
      throw createStartupDiagnosticError("resources_missing");
    }
    probeStartupState({
      dataDirectory: path.dirname(paths.databaseFile),
      workspaceDirectory: paths.workspaceRoot,
    });
    return paths;
  }

  function start(config, capability = activeAutonomousResearchCapability || randomBytes(32).toString("base64url")) {
    if (shutdownRequested) {
      throw new Error("packaged_runtime_stopped");
    }
    if (apiChild || webChild) {
      throw new Error("packaged_runtime_already_started");
    }
    assertLoopbackConfig(config);
    if (!/^[A-Za-z0-9_-]{43,128}$/u.test(capability)) {
      throw new Error("packaged_runtime_autonomous_capability_invalid");
    }
    const paths = preflight();
    startupLiveness = createStartupLiveness();

    processObject.env.PLAYWRIGHT_BROWSERS_PATH = paths.playwrightBrowsers;
    processObject.env.MYTHOS_PLAYWRIGHT_CHROMIUM_EXECUTABLE = paths.browserExecutable;
    const { AUTONOMOUS_RESEARCH_CAPABILITY: _ignoredCapability, ...baseEnvironment } = processObject.env;
    const webEnvironment = {
      ...baseEnvironment,
      API_BASE_URL: config.apiBaseUrl,
      HOSTNAME: "127.0.0.1",
      NEXT_PUBLIC_API_BASE_URL: config.apiBaseUrl,
      NEXT_PUBLIC_STUDIO_WORKSPACE_ROOT: paths.workspaceRoot,
      PLAYWRIGHT_BROWSERS_PATH: paths.playwrightBrowsers,
      PORT: String(config.webPort),
      STUDIO_WORKSPACE_ROOT: paths.workspaceRoot,
    };
    childEnvironment = {
      ...webEnvironment,
      AUTONOMOUS_RESEARCH_CAPABILITY: capability,
    };
    activeAutonomousResearchCapability = capability;

    apiChild = spawn(
      paths.apiExecutable,
      [
        "--host", "127.0.0.1",
        "--port", String(config.apiPort),
        "--web-port", String(config.webPort),
        "--user-data-dir", paths.userData,
        "--resources-dir", paths.apiResources,
        "--application-version", app.getVersion(),
      ],
      {
        cwd: path.dirname(paths.apiExecutable),
        env: childEnvironment,
        shell: false,
        stdio: "inherit",
        windowsHide: true,
      },
    );
    startupLiveness.watch(apiChild, "api_exited");
    try {
      webChild = utilityProcess.fork(paths.webServer, [], {
        cwd: paths.webDirectory,
        env: webEnvironment,
        serviceName: "Mythos Web",
        stdio: "inherit",
      });
      startupLiveness.watch(webChild, "web_exited");
    } catch (error) {
      throw error;
    }
    activeConfig = config;
    activePaths = paths;
    return paths;
  }

  async function stop() {
    shutdownRequested = true;
    activeConfig = null;
    activePaths = null;
    startupLiveness.stopMonitoring();
    try {
      await stopChildrenAndWait();
    } catch {}
  }

  async function stopChildrenAndWait() {
    startupLiveness.stopMonitoring();
    const children = [webChild, apiChild].filter(Boolean);
    const exits = children.map(async (child) => {
      await waitForChildExit(child);
      clearStoppedChild(child);
    });
    for (const child of children) {
      try {
        child.kill();
      } catch {}
    }
    await Promise.all(exits);
  }

  function clearStoppedChild(child) {
    if (webChild === child) {
      webChild = null;
    }
    if (apiChild === child) {
      apiChild = null;
    }
  }

  async function runMaintenance(operation, selectedPath) {
    if (maintenancePromise) {
      throw new Error("desktop_maintenance_in_progress");
    }
    if (!activeConfig || !activePaths || typeof execFile !== "function") {
      throw new Error("desktop_maintenance_unavailable");
    }
    if (
      typeof selectedPath !== "string"
      || !(path.isAbsolute(selectedPath) || path.win32.isAbsolute(selectedPath))
    ) {
      throw new Error("desktop_maintenance_path_invalid");
    }
    const config = activeConfig;
    const paths = activePaths;
    maintenancePromise = (async () => {
      let servicesStopped = false;
      let result;
      let maintenanceFailed = false;
      try {
        await stopChildrenAndWait();
        servicesStopped = true;
        const pathFlag = operation === "backup" ? "--destination" : "--archive";
        const maintenanceArgs = [
          "--host", "127.0.0.1",
          "--port", String(config.apiPort),
          "--web-port", String(config.webPort),
          "--user-data-dir", paths.userData,
          "--resources-dir", paths.apiResources,
          "--application-version", app.getVersion(),
          "--maintenance", operation,
          pathFlag, selectedPath,
        ];
        if (operation === "backup") {
          maintenanceArgs.push("--overwrite");
        }
        const { stdout } = await execFile(
          paths.apiExecutable,
          maintenanceArgs,
          {
            cwd: path.dirname(paths.apiExecutable),
            env: childEnvironment,
            encoding: "utf8",
            maxBuffer: 16 * 1024,
            shell: false,
            windowsHide: true,
          },
        );
        result = maintenanceResult(stdout, operation);
      } catch {
        maintenanceFailed = true;
      }
      if (!shutdownRequested && servicesStopped) {
        try {
          start(config);
        } catch {
          await stopChildrenAndWait().catch(() => undefined);
          maintenanceFailed = true;
        }
      }
      if (maintenanceFailed) {
        throw new Error("desktop_maintenance_failed");
      }
      return result;
    })();
    try {
      return await maintenancePromise;
    } finally {
      maintenancePromise = null;
    }
  }

  return {
    createBackup(destination) {
      return runMaintenance("backup", destination);
    },
    getStartupFailure() {
      return startupLiveness.getStartupFailure();
    },
    markStartupReady() {
      startupLiveness.markStartupReady();
    },
    preflight,
    restoreBackup(archive) {
      return runMaintenance("restore", archive);
    },
    start,
    stop,
  };
}

function waitForChildExit(child) {
  if (child.exitCode !== null && child.exitCode !== undefined) {
    return Promise.resolve();
  }
  return new Promise((resolve, reject) => {
    const timeout = setTimeout(() => reject(new Error("desktop_service_stop_timeout")), 10_000);
    child.once("exit", () => {
      clearTimeout(timeout);
      resolve();
    });
  });
}

function maintenanceResult(stdout, operation) {
  let value;
  try {
    value = JSON.parse(String(stdout).trim());
  } catch {
    throw new Error("desktop_maintenance_result_invalid");
  }
  if (!value || typeof value !== "object") {
    throw new Error("desktop_maintenance_result_invalid");
  }
  if (operation === "backup" && value.status === "created") {
    return {
      archive_name: String(value.archive_name || "backup.mythos-backup.zip"),
      file_count: Number(value.file_count) || 0,
      status: "created",
    };
  }
  if (operation === "restore" && value.status === "restored") {
    return {
      archive_name: String(value.archive_name || "backup.mythos-backup.zip"),
      rollback_archive_name: value.rollback_archive_name
        ? String(value.rollback_archive_name)
        : null,
      status: "restored",
    };
  }
  throw new Error("desktop_maintenance_result_invalid");
}

function findChromiumExecutable(playwrightBrowsers) {
  if (!fs.existsSync(playwrightBrowsers)) {
    return path.join(playwrightBrowsers, "missing-chromium.exe");
  }
  const pending = [playwrightBrowsers];
  const matches = [];
  while (pending.length > 0) {
    const current = pending.pop();
    for (const entry of fs.readdirSync(current, { withFileTypes: true })) {
      const candidate = path.join(current, entry.name);
      if (entry.isDirectory()) {
        pending.push(candidate);
      } else if (entry.isFile() && entry.name.toLowerCase() === "chrome.exe") {
        matches.push(candidate);
      }
    }
  }
  matches.sort();
  return matches[0] ?? path.join(playwrightBrowsers, "missing-chromium.exe");
}

function assertLoopbackConfig(config) {
  for (const value of [config.apiBaseUrl, config.studioUrl]) {
    const url = new URL(value);
    if (url.protocol !== "http:" || url.hostname !== "127.0.0.1") {
      throw new Error("packaged_runtime_requires_loopback");
    }
  }
}

function inside(parent, ...parts) {
  const root = path.resolve(parent);
  const candidate = path.resolve(root, ...parts);
  const relative = path.relative(root, candidate);
  if (relative === ".." || relative.startsWith(`..${path.sep}`) || path.isAbsolute(relative)) {
    throw new Error("packaged_path_outside_root");
  }
  return candidate;
}

module.exports = {
  assertPackagedRuntime,
  createPackagedRuntime,
  findChromiumExecutable,
  resolvePackagedRuntimePaths,
};
