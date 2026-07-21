const assert = require("node:assert/strict");
const { EventEmitter } = require("node:events");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const test = require("node:test");

const {
  createStartupDiagnostic,
  createStartupLiveness,
  diagnosticFromError,
  preflightDevelopmentRuntime,
  probeStartupState,
  resolveDevelopmentDataDirectory,
} = require("./startup-diagnostics.cjs");

test("startup diagnostics allow only fixed identifiers and discard raw failures", () => {
  const rawFailure = new Error("C:\\Users\\operator\\token=<secret>");
  const diagnostic = diagnosticFromError(rawFailure);
  const unknown = createStartupDiagnostic("not_a_real_startup_code");

  assert.equal(diagnostic.code, "startup_unknown");
  assert.equal(unknown.code, "startup_unknown");
  assert.doesNotMatch(JSON.stringify(diagnostic), /Users|token|secret/i);
  assert.doesNotMatch(JSON.stringify(unknown), /not_a_real_startup_code/);
});

test("development preflight maps a missing local source directory to resources_missing", (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "mythos-startup-diagnostics-"));
  t.after(() => fs.rmSync(root, { force: true, recursive: true }));
  const apiDirectory = path.join(root, "api");
  const webDirectory = path.join(root, "web");
  const dataDirectory = path.join(root, "data");
  const workspaceDirectory = path.join(root, "workspaces");
  fs.mkdirSync(apiDirectory);

  assert.throws(
    () => preflightDevelopmentRuntime({
      apiDirectory,
      dataDirectory,
      webDirectory,
      workspaceDirectory,
    }),
    (error) => error?.code === "resources_missing",
  );
});

test("startup state probe removes its transient file after a successful check", (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "mythos-startup-diagnostics-"));
  t.after(() => fs.rmSync(root, { force: true, recursive: true }));
  const dataDirectory = path.join(root, "data");
  const workspaceDirectory = path.join(root, "workspaces");

  probeStartupState({ dataDirectory, workspaceDirectory });

  assert.deepEqual(fs.readdirSync(dataDirectory), []);
  assert.deepEqual(fs.readdirSync(workspaceDirectory), []);
});

test("startup state probe maps an unwritable state location to state_unwritable", (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "mythos-startup-diagnostics-"));
  t.after(() => fs.rmSync(root, { force: true, recursive: true }));
  const dataDirectory = path.join(root, "data");
  const workspaceDirectory = path.join(root, "workspaces");
  fs.writeFileSync(dataDirectory, "not-a-directory");

  assert.throws(
    () => probeStartupState({ dataDirectory, workspaceDirectory }),
    (error) => error?.code === "state_unwritable",
  );
});

test("development state probing follows only file-backed SQLite database URLs", () => {
  const apiDirectory = path.join("C:", "mythos", "apps", "api");

  assert.equal(
    resolveDevelopmentDataDirectory("sqlite:///./bounty_mythos_studio.db", apiDirectory),
    apiDirectory,
  );
  assert.equal(
    resolveDevelopmentDataDirectory("sqlite:///C:/mythos-data/custom.db", apiDirectory),
    path.join("C:", "mythos-data"),
  );
  assert.equal(resolveDevelopmentDataDirectory("sqlite:///:memory:", apiDirectory), null);
  assert.equal(resolveDevelopmentDataDirectory("postgresql://localhost/mythos", apiDirectory), null);
});

test("startup liveness records the first early exit and ignores exits after readiness", () => {
  const liveness = createStartupLiveness();
  const apiChild = new EventEmitter();
  const webChild = new EventEmitter();
  liveness.watch(apiChild, "api_exited");
  liveness.watch(webChild, "web_exited");

  apiChild.emit("exit", 1);
  webChild.emit("exit", 1);

  assert.equal(liveness.getStartupFailure(), "api_exited");

  const readyLiveness = createStartupLiveness();
  const readyChild = new EventEmitter();
  readyLiveness.watch(readyChild, "api_exited");
  readyLiveness.markStartupReady();
  readyChild.emit("exit", 0);

  assert.equal(readyLiveness.getStartupFailure(), null);
});
