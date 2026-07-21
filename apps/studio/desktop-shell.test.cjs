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
  assert.match(preload, /createBackup/);
  assert.match(preload, /restoreBackup/);
  assert.match(preload, /ipcRenderer\.invoke\("mythos:create-backup"/);
  assert.match(preload, /ipcRenderer\.invoke\("mythos:restore-backup"/);
  assert.doesNotMatch(preload, /readFile|writeFile|exec|spawn/);
});

test("main process registers file and directory picker IPC handlers", async () => {
  const main = await fs.readFile(path.join(__dirname, "main.cjs"), "utf8");

  assert.match(main, /ipcMain\.handle\("mythos:select-file"/);
  assert.match(main, /ipcMain\.handle\("mythos:select-directory"/);
  assert.match(main, /selectStudioFile/);
  assert.match(main, /selectStudioDirectory/);
  assert.match(main, /ipcMain\.handle\("mythos:create-backup"/);
  assert.match(main, /ipcMain\.handle\("mythos:restore-backup"/);
  assert.match(main, /selectDesktopBackupDestination/);
  assert.match(main, /selectDesktopRestoreArchive/);
  assert.match(main, /confirmDesktopRestore/);
});

test("main process installs the local-only Studio navigation guard", async () => {
  const main = await fs.readFile(path.join(__dirname, "main.cjs"), "utf8");

  assert.match(main, /installStudioNavigationGuard/);
  assert.match(main, /installStudioNavigationGuard\(window,\s*config\.studioUrl\)/);
});

test("main process closes black-box sessions on main-frame reload and renderer loss", async () => {
  const main = await fs.readFile(path.join(__dirname, "main.cjs"), "utf8");

  assert.match(
    main,
    /webContents\.on\(\s*"did-start-navigation"[\s\S]*isMainFrame[\s\S]*blackBoxRunner\.closeSessions\("page_closed"\)/,
  );
  assert.match(
    main,
    /webContents\.on\("render-process-gone"[\s\S]*blackBoxRunner\.closeSessions\("browser_crash"\)/,
  );
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

test("desktop shell gives preload only the derived loopback API origin", async () => {
  const main = await fs.readFile(path.join(__dirname, "main.cjs"), "utf8");
  const preload = await fs.readFile(path.join(__dirname, "preload.cjs"), "utf8");

  assert.match(main, /function createWindow\(apiBaseUrl\)/);
  assert.match(main, /additionalArguments:\s*\[`--mythos-api-base-url=\$\{apiBaseUrl\}`\]/);
  assert.match(main, /createWindow\(config\.apiBaseUrl\)/);
  assert.match(preload, /apiBaseUrl:\s*apiBaseUrlFromArguments\(process\.argv\)/);
  assert.doesNotMatch(preload, /MYTHOS_API_PORT|API_BASE_URL|NEXT_PUBLIC_API_BASE_URL/);
});

test("desktop main rechecks local trial authority at the derived API immediately before runner dispatch", async () => {
  const main = await fs.readFile(path.join(__dirname, "main.cjs"), "utf8");
  const preload = await fs.readFile(path.join(__dirname, "preload.cjs"), "utf8");

  assert.match(main, /createLocalLabDispatchHandler/);
  assert.match(main, /getApiBaseUrl:\s*\(\) => studioApiBaseUrl/);
  assert.match(main, /runRunner:\s*\(line\) => blackBoxRunner\.handleLine\(line\)/);
  assert.match(
    main,
    /closeRunnerSessions:\s*\(reason\) => blackBoxRunner\.closeSessions\(reason\)/,
  );
  assert.match(main, /rendererGenerations/);
  assert.match(main, /isCurrent/);
  assert.doesNotMatch(preload, /preflight|grant|authority/);
});

test("desktop startup preflights local services and cleans up before rendering a bounded diagnostic", async () => {
  const main = await fs.readFile(path.join(__dirname, "main.cjs"), "utf8");

  assert.match(main, /preflightDevelopmentRuntime/);
  assert.match(main, /packagedRuntime\.preflight\(\)/);
  assert.match(
    main,
    /dataDirectory:\s*resolveDevelopmentDataDirectory\(\s*process\.env\.DATABASE_URL\s*\|\|\s*"sqlite:\/\/\/\.\/bounty_mythos_studio\.db",\s*path\.join\(root,\s*"apps",\s*"api"\),\s*\)/s,
  );
  assert.doesNotMatch(
    main,
    /dataDirectory:\s*path\.join\(app\.getPath\("userData"\),\s*"data"\)/,
  );
  assert.match(
    main,
    /const startupController = startServices\(config,\s*workspaceRoot\);\s*await waitForApiHealth\(config\.apiBaseUrl,\s*\{\s*getStartupFailure:\s*\(\) => startupController\.getStartupFailure\(\),\s*\}\);\s*await waitForStudio\(config\.studioUrl,\s*\{\s*getStartupFailure:\s*\(\) => startupController\.getStartupFailure\(\),\s*\}\);\s*startupController\.markStartupReady\(\);/s,
  );
  assert.match(
    main,
    /catch \(error\) \{\s*await killChildren\(\);\s*const diagnostic = diagnosticFromError\(error\);[\s\S]*startupErrorHtml\(diagnostic,\s*\{ packaged: app\.isPackaged \}\)/,
  );
  assert.match(
    main,
    /async function killChildren\(\)[\s\S]*await runtime\?\.stop\(\)[\s\S]*execFileAsync\("taskkill",\s*\["\/pid",\s*String\(child\.pid\),\s*"\/T",\s*"\/F"\]/,
  );
  assert.doesNotMatch(main, /startupErrorHtml\(error\)/);
});

test("desktop shell wakes only the local read-only research runtime after startup", async () => {
  const main = await fs.readFile(path.join(__dirname, "main.cjs"), "utf8");
  const wakeup = await fs.readFile(path.join(__dirname, "local-research-wakeup.cjs"), "utf8");

  assert.match(main, /createLocalResearchWakeup/);
  assert.match(
    main,
    /const localResearchWakeup = createLocalResearchWakeup\(\{\s*getBaseUrl:\s*\(\) => studioApiBaseUrl,\s*\}\);/s,
  );
  assert.match(
    main,
    /await waitForStudio\(config\.studioUrl,[\s\S]*startupController\.markStartupReady\(\);\s*localResearchWakeup\.start\(\);/s,
  );
  assert.match(
    main,
    /closeSessions:\s*async \(reason\) => \{\s*await programRulePump\.close\(reason\);\s*await localResearchWakeup\.stop\(\);\s*await blackBoxRunner\.closeSessions\(reason\);\s*\}/s,
  );
  assert.doesNotMatch(wakeup, /blackBoxRunner|BrowserWindow|createRemoteLeaseApiClient/);
});

test("desktop shell starts the bounded program-rule pump only after local services are ready", async () => {
  const main = await fs.readFile(path.join(__dirname, "main.cjs"), "utf8");
  const preload = await fs.readFile(path.join(__dirname, "preload.cjs"), "utf8");

  assert.match(main, /createProgramRuleApiClient/);
  assert.match(main, /createProgramRuleRunner\(\{ apiClient: programRuleApi \}\)/);
  assert.match(main, /createProgramRuleRefreshPump\(\{ runner: programRuleRunner \}\)/);
  assert.match(
    main,
    /await waitForApiHealth\(config\.apiBaseUrl,[\s\S]*await waitForStudio\(config\.studioUrl,[\s\S]*startupController\.markStartupReady\(\);[\s\S]*programRulePump\.start\(\);/,
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
