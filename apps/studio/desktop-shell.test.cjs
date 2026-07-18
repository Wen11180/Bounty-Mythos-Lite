const assert = require("node:assert/strict");
const fs = require("node:fs/promises");
const path = require("node:path");
const test = require("node:test");

test("desktop window keeps Node isolated while loading the preload bridge", async () => {
  const main = await fs.readFile(path.join(__dirname, "main.cjs"), "utf8");

  assert.match(main, /contextIsolation:\s*true/);
  assert.match(main, /nodeIntegration:\s*false/);
  assert.match(main, /preload:\s*path\.join\(__dirname,\s*"preload\.cjs"\)/);
});

test("preload exposes only limited Mythos Studio path picker methods", async () => {
  const preload = await fs.readFile(path.join(__dirname, "preload.cjs"), "utf8");

  assert.match(preload, /contextBridge\.exposeInMainWorld\("mythosStudio"/);
  assert.match(preload, /selectFile/);
  assert.match(preload, /selectDirectory/);
  assert.match(preload, /ipcRenderer\.invoke\("mythos:select-file"/);
  assert.match(preload, /ipcRenderer\.invoke\("mythos:select-directory"/);
  assert.doesNotMatch(preload, /readFile|writeFile|exec|spawn/);
});

test("main process registers file and directory picker IPC handlers", async () => {
  const main = await fs.readFile(path.join(__dirname, "main.cjs"), "utf8");

  assert.match(main, /ipcMain\.handle\("mythos:select-file"/);
  assert.match(main, /ipcMain\.handle\("mythos:select-directory"/);
  assert.match(main, /selectStudioFile/);
  assert.match(main, /selectStudioDirectory/);
});

test("main process installs the local-only Studio navigation guard", async () => {
  const main = await fs.readFile(path.join(__dirname, "main.cjs"), "utf8");

  assert.match(main, /installStudioNavigationGuard/);
  assert.match(main, /installStudioNavigationGuard\(window,\s*config\.studioUrl\)/);
});

test("desktop launcher defaults to inline worker dispatch for local campaigns", async () => {
  const main = await fs.readFile(path.join(__dirname, "main.cjs"), "utf8");

  assert.match(main, /WORKER_DISPATCH_MODE/);
  assert.match(main, /process\.env\.WORKER_DISPATCH_MODE\s*\|\|\s*"inline"/);
});

test("desktop shell runs the renderer in a sandbox and supplies only the derived API origin", async () => {
  const main = await fs.readFile(path.join(__dirname, "main.cjs"), "utf8");

  assert.match(main, /sandbox:\s*true/);
  assert.match(main, /API_BASE_URL:\s*config\.apiBaseUrl/);
  assert.match(main, /NEXT_PUBLIC_API_BASE_URL:\s*config\.apiBaseUrl/);
  assert.doesNotMatch(main, /process\.env\.API_BASE_URL/);
  assert.doesNotMatch(main, /process\.env\.NEXT_PUBLIC_API_BASE_URL/);
});

test("desktop shell derives the workspace root after Electron is ready unless explicitly configured", async () => {
  const main = await fs.readFile(path.join(__dirname, "main.cjs"), "utf8");

  assert.match(
    main,
    /process\.env\.STUDIO_WORKSPACE_ROOT\s*\|\|\s*path\.join\(app\.getPath\("userData"\),\s*"workspaces"\)/,
  );
  assert.match(main, /startServices\(config,\s*workspaceRoot\)/);
});

test("desktop shell gives child services the derived workspace root and local Studio origin", async () => {
  const main = await fs.readFile(path.join(__dirname, "main.cjs"), "utf8");

  assert.match(main, /function startServices\(config,\s*workspaceRoot\)/);
  assert.match(main, /const studioWebOrigin\s*=\s*new URL\(config\.studioUrl\)\.origin/);
  assert.match(main, /STUDIO_WORKSPACE_ROOT:\s*workspaceRoot/);
  assert.match(main, /NEXT_PUBLIC_STUDIO_WORKSPACE_ROOT:\s*workspaceRoot/);
  assert.match(main, /STUDIO_WEB_ORIGIN:\s*studioWebOrigin/);
  assert.doesNotMatch(main, /process\.env\.STUDIO_WEB_ORIGIN/);
});

test("desktop runner binds remote lease decisions only to the derived loopback API", async () => {
  const main = await fs.readFile(path.join(__dirname, "main.cjs"), "utf8");

  assert.match(main, /createRemoteLeaseApiClient/);
  assert.match(main, /studioApiBaseUrl\s*=\s*config\.apiBaseUrl/);
  assert.match(main, /authorizeRemoteRequest:\s*remoteLeaseApi\.authorize/);
  assert.match(main, /completeRemoteRequest:\s*remoteLeaseApi\.complete/);
  assert.match(main, /stopRemoteLease:\s*remoteLeaseApi\.stop/);
});

test("desktop shell starts the bounded program-rule pump only after local services are ready", async () => {
  const main = await fs.readFile(path.join(__dirname, "main.cjs"), "utf8");
  const preload = await fs.readFile(path.join(__dirname, "preload.cjs"), "utf8");

  assert.match(main, /createProgramRuleApiClient/);
  assert.match(main, /createProgramRuleRunner\(\{ apiClient: programRuleApi \}\)/);
  assert.match(main, /createProgramRuleRefreshPump\(\{ runner: programRuleRunner \}\)/);
  assert.match(
    main,
    /await waitForUrl\(config\.apiBaseUrl\);\s*await waitForUrl\(config\.studioUrl\);[\s\S]*programRulePump\.start\(\);/,
  );
  assert.match(
    main,
    /ipcMain\.handle\("mythos:refresh-program-rules",\s*\(\) => \{\s*return programRulePump\.kick\(\);\s*\}\);/s,
  );
  assert.match(
    preload,
    /refreshProgramRules\(\) \{\s*return ipcRenderer\.invoke\("mythos:refresh-program-rules"\);\s*\}/s,
  );
  assert.equal(main.match(/app\.on\("before-quit"/gu)?.length, 1);
  assert.doesNotMatch(preload, /refreshProgramRules\([^)]*\w[^)]*\)/u);
});

test("Compose keeps infrastructure private and binds Studio HTTP services to loopback", async () => {
  const compose = await fs.readFile(
    path.join(__dirname, "..", "..", "infra", "docker-compose.yml"),
    "utf8",
  );

  assert.doesNotMatch(composeService(compose, "postgres"), /\n    ports:/);
  assert.doesNotMatch(composeService(compose, "redis"), /\n    ports:/);
  assert.match(
    composeService(compose, "api"),
    /ports:\s*\n\s*- "127\.0\.0\.1:8000:8000"/,
  );
  assert.match(
    composeService(compose, "api"),
    /STUDIO_WEB_ORIGIN:\s*http:\/\/127\.0\.0\.1:3000/,
  );
  assert.match(
    composeService(compose, "web"),
    /ports:\s*\n\s*- "127\.0\.0\.1:3000:3000"/,
  );
});

function composeService(compose, name) {
  const start = compose.indexOf(`  ${name}:`);
  assert.notEqual(start, -1, `missing ${name} service`);

  const serviceStart = start + name.length + 3;
  const next = compose.slice(serviceStart).search(/\n  [A-Za-z][A-Za-z0-9_-]*:/);
  return compose.slice(start, next === -1 ? undefined : serviceStart + next);
}
