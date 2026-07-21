const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const test = require("node:test");

const { validateStagedRuntime } = require("./package-runtime.cjs");

test("Forge packages an ASAR shell with real external runtime resources and Squirrel x64", () => {
  const config = require("./forge.config.cjs");
  const packageJson = require("./package.json");

  assert.equal(config.packagerConfig.asar, true);
  assert.equal(config.packagerConfig.prune, false);
  assert.equal(config.packagerConfig.ignore("/black-box-runner.test.cjs"), true);
  assert.equal(config.packagerConfig.ignore("/node_modules/@electron-forge/cli/dist/index.js"), true);
  assert.equal(config.packagerConfig.ignore("/node_modules/.pnpm/node_modules/@electron/get"), true);
  assert.equal(config.packagerConfig.ignore("/node_modules/playwright/lib/index.js"), true);
  assert.equal(config.packagerConfig.ignore("/packaged-runtime.cjs"), false);
  assert.equal(typeof config.hooks.packageAfterCopy, "function");
  assert.deepEqual(
    config.packagerConfig.extraResource.map((resource) => path.basename(resource)).sort(),
    ["api", "playwright", "web"],
  );
  const squirrel = config.makers.find((maker) => maker.name === "@electron-forge/maker-squirrel");
  assert.ok(squirrel);
  assert.deepEqual(squirrel.platforms, ["win32"]);
  assert.equal(squirrel.config.setupExe, "BountyMythosLite Setup.exe");
  assert.match(packageJson.scripts.package, /package-runtime\.cjs/);
  assert.match(packageJson.scripts.make, /package-runtime\.cjs/);
  assert.equal(packageJson.devDependencies["@electron-forge/cli"], "7.11.2");
  assert.equal(packageJson.devDependencies["@electron-forge/maker-squirrel"], "7.11.2");
  assert.equal(packageJson.dependencies["electron-squirrel-startup"], "1.0.1");
});

test("desktop main keeps source launch in development and selects packaged runtime explicitly", () => {
  const main = fs.readFileSync(path.join(__dirname, "main.cjs"), "utf8");

  assert.match(main, /electron-squirrel-startup/);
  assert.match(main, /app\.isPackaged/);
  assert.match(main, /createPackagedRuntime/);
  assert.match(main, /utilityProcess/);
  assert.match(main, /startDevelopmentServices/);
  assert.doesNotMatch(main, /nodeIntegration:\s*true|contextIsolation:\s*false|sandbox:\s*false/);
});

test("PyInstaller data collection excludes Python caches from packaged migrations", () => {
  const spec = fs.readFileSync(path.join(__dirname, "..", "api", "mythos-api.spec"), "utf8");

  assert.doesNotMatch(spec, /Tree\(/);
  assert.match(spec, /"__pycache__" in relative\.parts/);
  assert.match(spec, /source\.suffix == "\.pyc"/);
  assert.match(spec, /migration_data\.append\(\(str\(source\), str\(Path\("migrations"\) \/ relative\.parent\)\)\)/);
});

test("staging validation requires frozen API, migrations, standalone assets, and Chromium", async (t) => {
  const fixture = createStagingFixture(t);
  assert.doesNotThrow(() => validateStagedRuntime(fixture));

  for (const target of [
    "api/mythos-api.exe",
    "api/_internal/alembic.ini",
    "api/_internal/migrations",
    "web/server.js",
    "web/.next/static",
    "web/node_modules/@swc/helpers/cjs/_interop_require_default.cjs",
    "web/public",
    "playwright/chromium-123/chrome-win/chrome.exe",
  ]) {
    await t.test(target, () => {
      const current = createStagingFixture(t);
      fs.rmSync(path.join(current, ...target.split("/")), { force: true, recursive: true });
      assert.throws(() => validateStagedRuntime(current), /missing_/);
    });
  }
});

function createStagingFixture(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "mythos-stage-"));
  t.after(() => fs.rmSync(root, { force: true, recursive: true }));
  for (const directory of [
    "api/_internal/migrations",
    "playwright/chromium-123/chrome-win",
    "web/.next/static",
    "web/node_modules/@swc/helpers/cjs",
    "web/public",
  ]) {
    fs.mkdirSync(path.join(root, ...directory.split("/")), { recursive: true });
  }
  for (const file of [
    "api/mythos-api.exe",
    "api/_internal/alembic.ini",
    "playwright/chromium-123/chrome-win/chrome.exe",
    "web/server.js",
    "web/node_modules/@swc/helpers/cjs/_interop_require_default.cjs",
  ]) {
    fs.writeFileSync(path.join(root, ...file.split("/")), "fixture");
  }
  return root;
}
