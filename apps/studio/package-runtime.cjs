const { execFileSync } = require("node:child_process");
const fs = require("node:fs");
const path = require("node:path");

const {
  assertPackagedRuntime,
  resolvePackagedRuntimePaths,
} = require("./packaged-runtime.cjs");

const repositoryRoot = path.resolve(__dirname, "..", "..");
const apiRoot = path.join(repositoryRoot, "apps", "api");
const webRoot = path.join(repositoryRoot, "apps", "web");
const stagingRoot = path.join(__dirname, "runtime");

function validateStagedRuntime(root = stagingRoot) {
  const paths = resolvePackagedRuntimePaths({
    resourcesPath: root,
    userDataPath: path.join(root, ".validation-user-data"),
  });
  assertPackagedRuntime(paths);
  if (containsSymbolicLink(paths.webDirectory)) {
    throw new Error("packaged_web_symlink");
  }
  return paths;
}

function buildRuntime() {
  fs.rmSync(stagingRoot, { force: true, recursive: true });
  fs.mkdirSync(stagingRoot, { recursive: true });
  buildWebRuntime();
  buildApiRuntime();
  installChromium();
  validateStagedRuntime(stagingRoot);
  process.stdout.write(`Packaged runtime staged at ${stagingRoot}\n`);
}

function buildWebRuntime() {
  run(process.execPath, [npmCliPath(), "run", "build"], webRoot, {
    API_BASE_URL: "http://127.0.0.1:8000",
    NEXT_PUBLIC_API_BASE_URL: "http://127.0.0.1:8000",
  });
  const target = path.join(stagingRoot, "web");
  copyDirectory(path.join(webRoot, ".next", "standalone"), target);
  flattenStandaloneNodeModules(path.join(webRoot, ".next", "standalone"), target);
  copyDirectory(path.join(webRoot, ".next", "static"), path.join(target, ".next", "static"));
  copyDirectory(path.join(webRoot, "public"), path.join(target, "public"));
}

function flattenStandaloneNodeModules(sourceRoot, targetRoot) {
  const sourceModules = path.join(sourceRoot, "node_modules");
  const targetModules = path.join(targetRoot, "node_modules");
  fs.rmSync(targetModules, { force: true, recursive: true });
  fs.mkdirSync(targetModules, { recursive: true });
  copyTopLevelPackages(sourceModules, targetModules);
  copyTopLevelPackages(path.join(sourceModules, ".pnpm", "node_modules"), targetModules);
}

function copyTopLevelPackages(sourceModules, targetModules) {
  if (!fs.existsSync(sourceModules)) {
    return;
  }
  for (const entry of fs.readdirSync(sourceModules, { withFileTypes: true })) {
    if (entry.name === ".bin" || entry.name === ".pnpm") {
      continue;
    }
    if (entry.name.startsWith("@")) {
      const scope = path.join(sourceModules, entry.name);
      for (const scopedEntry of fs.readdirSync(scope, { withFileTypes: true })) {
        copyPackage(
          path.join(scope, scopedEntry.name),
          path.join(targetModules, entry.name, scopedEntry.name),
        );
      }
      continue;
    }
    copyPackage(path.join(sourceModules, entry.name), path.join(targetModules, entry.name));
  }
}

function copyPackage(source, target) {
  let resolvedSource;
  try {
    resolvedSource = resolveLinkTarget(source);
  } catch (error) {
    if (error.code === "ENOENT") {
      return;
    }
    throw error;
  }
  fs.mkdirSync(path.dirname(target), { recursive: true });
  fs.cpSync(resolvedSource, target, { dereference: true, recursive: true });
}

function resolveLinkTarget(source) {
  let current = source;
  for (let depth = 0; depth < 8; depth += 1) {
    if (!fs.lstatSync(current).isSymbolicLink()) {
      return current;
    }
    current = path.resolve(path.dirname(current), fs.readlinkSync(current));
  }
  throw new Error(`standalone_link_depth:${source}`);
}

function buildApiRuntime() {
  const python = resolveDesktopPython();
  const buildPath = path.join(apiRoot, "build", "desktop");
  const distPath = path.join(apiRoot, "dist", "desktop");
  fs.rmSync(buildPath, { force: true, recursive: true });
  fs.rmSync(distPath, { force: true, recursive: true });
  run(
    python,
    [
      "-m", "PyInstaller",
      "--clean",
      "--noconfirm",
      "--distpath", distPath,
      "--workpath", buildPath,
      "mythos-api.spec",
    ],
    apiRoot,
  );
  copyDirectory(path.join(distPath, "mythos-api"), path.join(stagingRoot, "api"));
}

function resolveDesktopPython(environment = process.env) {
  if (environment.MYTHOS_DESKTOP_PYTHON) {
    return environment.MYTHOS_DESKTOP_PYTHON;
  }
  const virtualEnvironmentPython = path.join(
    apiRoot,
    ".venv",
    process.platform === "win32" ? "Scripts" : "bin",
    process.platform === "win32" ? "python.exe" : "python",
  );
  return fs.existsSync(virtualEnvironmentPython) ? virtualEnvironmentPython : "python";
}

function installChromium() {
  const browsers = path.join(stagingRoot, "playwright");
  fs.mkdirSync(browsers, { recursive: true });
  run(
    process.execPath,
    [
      path.join(__dirname, "node_modules", "playwright", "cli.js"),
      "install",
      "chromium",
      "--no-shell",
    ],
    __dirname,
    { PLAYWRIGHT_BROWSERS_PATH: browsers },
  );
}

function copyDirectory(source, target) {
  if (!fs.statSync(source).isDirectory()) {
    throw new Error(`missing_source_directory:${source}`);
  }
  fs.cpSync(source, target, { recursive: true, verbatimSymlinks: true });
}

function containsSymbolicLink(root) {
  const pending = [root];
  while (pending.length > 0) {
    const current = pending.pop();
    for (const entry of fs.readdirSync(current, { withFileTypes: true })) {
      const candidate = path.join(current, entry.name);
      if (fs.lstatSync(candidate).isSymbolicLink()) {
        return true;
      }
      if (entry.isDirectory()) {
        pending.push(candidate);
      }
    }
  }
  return false;
}

function run(executable, args, cwd, environment = {}) {
  execFileSync(executable, args, {
    cwd,
    env: { ...process.env, ...environment },
    stdio: "inherit",
    windowsHide: true,
  });
}

function npmCliPath() {
  return process.env.npm_execpath
    || path.join(path.dirname(process.execPath), "node_modules", "npm", "bin", "npm-cli.js");
}

if (require.main === module) {
  buildRuntime();
}

module.exports = { buildRuntime, resolveDesktopPython, validateStagedRuntime };
