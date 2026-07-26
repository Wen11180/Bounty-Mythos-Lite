const assert = require("node:assert/strict");
const { EventEmitter } = require("node:events");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const test = require("node:test");

const {
  assertPackagedRuntime,
  createPackagedRuntime,
  resolvePackagedRuntimePaths,
} = require("./packaged-runtime.cjs");

test("packaged paths stay under resources while mutable state stays under userData", (t) => {
  const fixture = createRuntimeFixture(t);
  const paths = resolvePackagedRuntimePaths({
    resourcesPath: fixture.resources,
    userDataPath: fixture.userData,
  });

  for (const value of [
    paths.apiAlembic,
    paths.apiExecutable,
    paths.apiMigrations,
    paths.apiResources,
    paths.browserExecutable,
    paths.playwrightBrowsers,
    paths.webPublic,
    paths.webServer,
    paths.webStatic,
    paths.webSwcHelper,
  ]) {
    assert.equal(isWithin(fixture.resources, value), true, value);
  }
  assert.equal(isWithin(fixture.userData, paths.databaseFile), true);
  assert.equal(isWithin(fixture.userData, paths.workspaceRoot), true);
  assert.doesNotThrow(() => assertPackagedRuntime(paths));
});

test("packaged runtime fails before launch when a required asset is absent", async (t) => {
  for (const key of [
    "apiAlembic",
    "apiExecutable",
    "apiMigrations",
    "apiResources",
    "browserExecutable",
    "webPublic",
    "webServer",
    "webStatic",
    "webSwcHelper",
  ]) {
    await t.test(key, () => {
      const fixture = createRuntimeFixture(t);
      const paths = resolvePackagedRuntimePaths({
        resourcesPath: fixture.resources,
        userDataPath: fixture.userData,
      });
      fs.rmSync(paths[key], { force: true, recursive: true });

      assert.throws(() => assertPackagedRuntime(paths), new RegExp(`missing_${key}`));
    });
  }
});

test("packaged preflight maps resource and state failures to fixed startup diagnostics", (t) => {
  const missingFixture = createRuntimeFixture(t);
  fs.rmSync(path.join(missingFixture.resources, "api", "mythos-api.exe"));
  const missingRuntime = createPackagedRuntime({
    app: { getPath: () => missingFixture.userData },
    processObject: { env: {}, resourcesPath: missingFixture.resources },
    spawn() {},
    utilityProcess: { fork() {} },
  });

  assert.throws(
    () => missingRuntime.preflight(),
    (error) => error?.code === "resources_missing",
  );

  const stateFixture = createRuntimeFixture(t);
  fs.mkdirSync(stateFixture.userData, { recursive: true });
  fs.writeFileSync(path.join(stateFixture.userData, "data"), "not-a-directory");
  const stateRuntime = createPackagedRuntime({
    app: { getPath: () => stateFixture.userData },
    processObject: { env: {}, resourcesPath: stateFixture.resources },
    spawn() {},
    utilityProcess: { fork() {} },
  });

  assert.throws(
    () => stateRuntime.preflight(),
    (error) => error?.code === "state_unwritable",
  );
});

test("packaged runtime reports early child exits until startup is marked ready", (t) => {
  const fixture = createRuntimeFixture(t);
  const apiChild = serviceChild();
  const webChild = serviceChild();
  const runtime = createPackagedRuntime({
    app: {
      getPath: () => fixture.userData,
      getVersion: () => "0.1.0",
    },
    processObject: { env: {}, resourcesPath: fixture.resources },
    spawn: () => apiChild,
    utilityProcess: { fork: () => webChild },
  });

  runtime.start(startupConfig());
  apiChild.emit("exit", 1, null);

  assert.equal(runtime.getStartupFailure(), "api_exited");

  const readyApiChild = serviceChild();
  const readyWebChild = serviceChild();
  const readyRuntime = createPackagedRuntime({
    app: {
      getPath: () => fixture.userData,
      getVersion: () => "0.1.0",
    },
    processObject: { env: {}, resourcesPath: fixture.resources },
    spawn: () => readyApiChild,
    utilityProcess: { fork: () => readyWebChild },
  });

  readyRuntime.start(startupConfig());
  readyRuntime.markStartupReady();
  readyWebChild.emit("exit", 0, null);

  assert.equal(readyRuntime.getStartupFailure(), null);
  runtime.stop();
  readyRuntime.stop();
});

test("packaged runtime starts only frozen API and bundled Next, then stops both", async (t) => {
  const fixture = createRuntimeFixture(t);
  const calls = { api: [], web: [] };
  const apiChild = serviceChild();
  const webChild = serviceChild();
  const processObject = { env: {}, resourcesPath: fixture.resources };
  const runtime = createPackagedRuntime({
    app: {
      getPath(name) {
        assert.equal(name, "userData");
        return fixture.userData;
      },
      getVersion() {
        return "0.1.0";
      },
    },
    processObject,
    spawn(command, args, options) {
      calls.api.push({ args, command, options });
      return apiChild;
    },
    utilityProcess: {
      fork(modulePath, args, options) {
        calls.web.push({ args, modulePath, options });
        return webChild;
      },
    },
  });

  const capability = "a".repeat(43);
  const paths = runtime.start({
    apiBaseUrl: "http://127.0.0.1:48123",
    apiPort: 48123,
    studioUrl: "http://127.0.0.1:48124/studio",
    webPort: 48124,
  }, capability);

  assert.equal(calls.api.length, 1);
  assert.equal(calls.api[0].command, paths.apiExecutable);
  assert.equal(calls.api[0].options.shell, false);
  assert.equal(calls.api[0].options.windowsHide, true);
  assert.equal(
    calls.api[0].options.env.AUTONOMOUS_RESEARCH_CAPABILITY,
    capability,
  );
  assert.deepEqual(calls.api[0].args, [
    "--host", "127.0.0.1",
    "--port", "48123",
    "--web-port", "48124",
    "--user-data-dir", fixture.userData,
    "--resources-dir", paths.apiResources,
    "--application-version", "0.1.0",
  ]);
  assert.equal(calls.web.length, 1);
  assert.equal(calls.web[0].modulePath, paths.webServer);
  assert.equal(calls.web[0].options.env.HOSTNAME, "127.0.0.1");
  assert.equal(calls.web[0].options.env.PORT, "48124");
  assert.equal(calls.web[0].options.env.API_BASE_URL, "http://127.0.0.1:48123");
  assert.equal(calls.web[0].options.env.AUTONOMOUS_RESEARCH_CAPABILITY, undefined);
  assert.equal(processObject.env.AUTONOMOUS_RESEARCH_CAPABILITY, undefined);
  assert.equal(processObject.env.PLAYWRIGHT_BROWSERS_PATH, paths.playwrightBrowsers);
  assert.equal(processObject.env.MYTHOS_PLAYWRIGHT_CHROMIUM_EXECUTABLE, paths.browserExecutable);

  await runtime.stop();
  assert.equal(apiChild.killCalls, 1);
  assert.equal(webChild.killCalls, 1);
});

test("packaged runtime stop waits for both service exits", async (t) => {
  const fixture = createRuntimeFixture(t);
  const apiChild = stuckServiceChild();
  const webChild = stuckServiceChild();
  const runtime = createPackagedRuntime({
    app: {
      getPath: () => fixture.userData,
      getVersion: () => "0.1.0",
    },
    processObject: { env: {}, resourcesPath: fixture.resources },
    spawn: () => apiChild,
    utilityProcess: { fork: () => webChild },
  });
  runtime.start(startupConfig());

  let stopped = false;
  const stopping = Promise.resolve(runtime.stop()).then(() => {
    stopped = true;
  });
  await new Promise((resolve) => setImmediate(resolve));

  assert.equal(apiChild.killCalls, 1);
  assert.equal(webChild.killCalls, 1);
  assert.equal(stopped, false);

  apiChild.exitCode = 0;
  apiChild.emit("exit", 0, null);
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(stopped, false);

  webChild.exitCode = 0;
  webChild.emit("exit", 0, null);
  await stopping;
  assert.equal(stopped, true);
});

test("packaged maintenance does not restart services after a child shutdown timeout", async (t) => {
  const fixture = createRuntimeFixture(t);
  const archive = path.join(fixture.userData, "portable.mythos-backup.zip");
  const originalSetTimeout = global.setTimeout;
  t.after(() => {
    global.setTimeout = originalSetTimeout;
  });
  global.setTimeout = (callback, delay, ...args) => {
    if (delay === 10_000) {
      queueMicrotask(() => callback(...args));
      return null;
    }
    return originalSetTimeout(callback, delay, ...args);
  };

  const apiChildren = [];
  const webChildren = [];
  const runtime = createPackagedRuntime({
    app: {
      getPath: () => fixture.userData,
      getVersion: () => "0.1.0",
    },
    async execFile() {
      throw new Error("maintenance must not run after stop failure");
    },
    processObject: { env: {}, resourcesPath: fixture.resources },
    spawn() {
      const child = apiChildren.length === 0 ? stuckServiceChild() : serviceChild();
      apiChildren.push(child);
      return child;
    },
    utilityProcess: {
      fork() {
        const child = webChildren.length === 0 ? stuckServiceChild() : serviceChild();
        webChildren.push(child);
        return child;
      },
    },
  });
  runtime.start(startupConfig());

  await assert.rejects(
    runtime.createBackup(archive),
    /desktop_maintenance_failed/,
  );

  assert.equal(apiChildren.length, 1);
  assert.equal(webChildren.length, 1);
  assert.equal(apiChildren[0].killCalls, 1);
  assert.equal(webChildren[0].killCalls, 1);
  apiChildren[0].exitCode = 0;
  apiChildren[0].emit("exit", 0, null);
  webChildren[0].exitCode = 0;
  webChildren[0].emit("exit", 0, null);
  await runtime.stop();
});

test("packaged maintenance stops children, uses only frozen API, and always restarts", async (t) => {
  const fixture = createRuntimeFixture(t);
  const archive = path.join(fixture.userData, "portable.mythos-backup.zip");
  const apiChildren = [];
  const webChildren = [];
  const maintenanceCalls = [];
  let maintenanceFailure = false;
  const runtime = createPackagedRuntime({
    app: {
      getPath(name) {
        assert.equal(name, "userData");
        return fixture.userData;
      },
      getVersion() {
        return "0.1.0";
      },
    },
    async execFile(command, args, options) {
      maintenanceCalls.push({ args, command, options });
      if (maintenanceFailure) {
        throw new Error("raw maintenance detail");
      }
      return {
        stderr: "",
        stdout: JSON.stringify({
          archive_name: "portable.mythos-backup.zip",
          file_count: 3,
          status: "created",
        }),
      };
    },
    processObject: { env: {}, resourcesPath: fixture.resources },
    spawn() {
      const child = serviceChild();
      apiChildren.push(child);
      return child;
    },
    utilityProcess: {
      fork() {
        const child = serviceChild();
        webChildren.push(child);
        return child;
      },
    },
  });
  runtime.start({
    apiBaseUrl: "http://127.0.0.1:48123",
    apiPort: 48123,
    studioUrl: "http://127.0.0.1:48124/studio",
    webPort: 48124,
  });

  const result = await runtime.createBackup(archive);

  assert.deepEqual(result, {
    archive_name: "portable.mythos-backup.zip",
    file_count: 3,
    status: "created",
  });
  assert.equal(apiChildren.length, 2);
  assert.equal(webChildren.length, 2);
  assert.equal(apiChildren[0].killCalls, 1);
  assert.equal(webChildren[0].killCalls, 1);
  assert.equal(maintenanceCalls.length, 1);
  assert.equal(maintenanceCalls[0].command, path.join(fixture.resources, "api", "mythos-api.exe"));
  assert.deepEqual(maintenanceCalls[0].args, [
    "--host", "127.0.0.1",
    "--port", "48123",
    "--web-port", "48124",
    "--user-data-dir", fixture.userData,
    "--resources-dir", path.join(fixture.resources, "api", "_internal"),
    "--application-version", "0.1.0",
    "--maintenance", "backup",
    "--destination", archive,
    "--overwrite",
  ]);
  assert.equal(maintenanceCalls[0].options.shell, false);
  assert.equal(maintenanceCalls[0].options.windowsHide, true);

  maintenanceFailure = true;
  await assert.rejects(
    runtime.restoreBackup(archive),
    /desktop_maintenance_failed/,
  );
  assert.equal(apiChildren.length, 3);
  assert.equal(webChildren.length, 3);
  assert.equal(apiChildren[1].killCalls, 1);
  assert.equal(webChildren[1].killCalls, 1);
  assert.equal(maintenanceCalls.length, 2);
  assert.doesNotMatch(String(maintenanceCalls[1].options), /raw maintenance detail/);

  runtime.stop();
});

test("packaged maintenance waits for a failed restart API child to exit", async (t) => {
  const fixture = createRuntimeFixture(t);
  const archive = path.join(fixture.userData, "portable.mythos-backup.zip");
  const apiChildren = [];
  let releaseRestart;
  const restartStarted = new Promise((resolve) => {
    releaseRestart = resolve;
  });
  let webStarts = 0;
  const runtime = createPackagedRuntime({
    app: {
      getPath: () => fixture.userData,
      getVersion: () => "0.1.0",
    },
    async execFile() {
      return {
        stdout: JSON.stringify({
          archive_name: "portable.mythos-backup.zip",
          file_count: 1,
          status: "created",
        }),
      };
    },
    processObject: { env: {}, resourcesPath: fixture.resources },
    spawn() {
      const child = apiChildren.length === 0 ? serviceChild() : stuckServiceChild();
      apiChildren.push(child);
      if (apiChildren.length === 2) {
        releaseRestart();
      }
      return child;
    },
    utilityProcess: {
      fork() {
        webStarts += 1;
        if (webStarts === 2) {
          throw new Error("web restart failed");
        }
        return serviceChild();
      },
    },
  });
  runtime.start(startupConfig());

  let settled = false;
  const backup = runtime.createBackup(archive);
  backup.then(
    () => { settled = true; },
    () => { settled = true; },
  );
  await restartStarted;
  await new Promise((resolve) => setImmediate(resolve));

  assert.equal(apiChildren[1].killCalls, 1);
  assert.equal(settled, false);

  apiChildren[1].exitCode = 0;
  apiChildren[1].emit("exit", 0, null);
  await assert.rejects(backup, /desktop_maintenance_failed/);
  assert.equal(settled, true);
  await runtime.stop();
});

test("packaged stop during maintenance does not restart services", async (t) => {
  const fixture = createRuntimeFixture(t);
  const archive = path.join(fixture.userData, "portable.mythos-backup.zip");
  const apiChildren = [];
  const webChildren = [];
  let releaseMaintenance;
  let signalMaintenanceStarted;
  const maintenanceStarted = new Promise((resolve) => {
    signalMaintenanceStarted = resolve;
  });
  const maintenanceRelease = new Promise((resolve) => {
    releaseMaintenance = resolve;
  });
  const runtime = createPackagedRuntime({
    app: {
      getPath() {
        return fixture.userData;
      },
      getVersion() {
        return "0.1.0";
      },
    },
    async execFile() {
      signalMaintenanceStarted();
      await maintenanceRelease;
      return {
        stderr: "",
        stdout: JSON.stringify({
          archive_name: "portable.mythos-backup.zip",
          file_count: 2,
          status: "created",
        }),
      };
    },
    processObject: { env: {}, resourcesPath: fixture.resources },
    spawn() {
      const child = serviceChild();
      apiChildren.push(child);
      return child;
    },
    utilityProcess: {
      fork() {
        const child = serviceChild();
        webChildren.push(child);
        return child;
      },
    },
  });
  runtime.start({
    apiBaseUrl: "http://127.0.0.1:48123",
    apiPort: 48123,
    studioUrl: "http://127.0.0.1:48124/studio",
    webPort: 48124,
  });

  const backup = runtime.createBackup(archive);
  await maintenanceStarted;
  runtime.stop();
  releaseMaintenance();
  await backup;

  assert.equal(apiChildren.length, 1);
  assert.equal(webChildren.length, 1);
});

function createRuntimeFixture(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "mythos-packaged-runtime-"));
  t.after(() => fs.rmSync(root, { force: true, recursive: true }));
  const resources = path.join(root, "resources");
  const userData = path.join(root, "user-data");
  for (const directory of [
    path.join(resources, "api", "_internal", "migrations"),
    path.join(resources, "playwright", "chromium-123", "chrome-win"),
    path.join(resources, "web", ".next", "static"),
    path.join(resources, "web", "node_modules", "@swc", "helpers", "cjs"),
    path.join(resources, "web", "public"),
  ]) {
    fs.mkdirSync(directory, { recursive: true });
  }
  for (const file of [
    path.join(resources, "api", "mythos-api.exe"),
    path.join(resources, "api", "_internal", "alembic.ini"),
    path.join(resources, "playwright", "chromium-123", "chrome-win", "chrome.exe"),
    path.join(resources, "web", "server.js"),
    path.join(
      resources,
      "web",
      "node_modules",
      "@swc",
      "helpers",
      "cjs",
      "_interop_require_default.cjs",
    ),
  ]) {
    fs.writeFileSync(file, "fixture");
  }
  return { resources, userData };
}

function isWithin(parent, candidate) {
  const relative = path.relative(path.resolve(parent), path.resolve(candidate));
  return relative !== ".." && !relative.startsWith(`..${path.sep}`) && !path.isAbsolute(relative);
}

function serviceChild() {
  const child = new EventEmitter();
  child.exitCode = null;
  child.killCalls = 0;
  child.kill = function kill() {
    this.killCalls += 1;
    this.exitCode = 0;
    this.emit("exit", 0, null);
  };
  return child;
}

function stuckServiceChild() {
  const child = new EventEmitter();
  child.exitCode = null;
  child.killCalls = 0;
  child.kill = function kill() {
    this.killCalls += 1;
  };
  return child;
}

function startupConfig() {
  return {
    apiBaseUrl: "http://127.0.0.1:48123",
    apiPort: 48123,
    studioUrl: "http://127.0.0.1:48124/studio",
    webPort: 48124,
  };
}
