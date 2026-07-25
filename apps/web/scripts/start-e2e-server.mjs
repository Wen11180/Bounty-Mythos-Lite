import { spawn, spawnSync } from "node:child_process";
import { cpSync, existsSync, mkdirSync, rmSync } from "node:fs";
import { dirname } from "node:path";

const port = process.env.PORT ?? "3100";
const hostname = process.env.HOSTNAME ?? "127.0.0.1";

const build = spawnSync(
  process.execPath,
  ["node_modules/next/dist/bin/next", "build"],
  { env: process.env, stdio: "inherit" },
);
if (build.error) {
  throw build.error;
}
if (build.status !== 0) {
  process.exit(build.status ?? 1);
}

function ensureStandalonePackage(packageName, entryPath) {
  const packagePath = `.next/standalone/node_modules/${packageName}`;
  const sourceEntryPath = `node_modules/${packageName}/${entryPath}`;
  if (!existsSync(sourceEntryPath)) {
    throw new Error(`source_package_entry_missing:${packageName}`);
  }
  mkdirSync(dirname(packagePath), { recursive: true });
  rmSync(packagePath, { force: true, recursive: true });
  cpSync(`node_modules/${packageName}`, packagePath, { force: true, recursive: true });
  if (!existsSync(`${packagePath}/${entryPath}`)) {
    throw new Error(`standalone_package_entry_missing:${packageName}`);
  }
}

function copyStandaloneDirectory(sourcePath, destinationPath) {
  if (!existsSync(sourcePath)) {
    return;
  }
  mkdirSync(dirname(destinationPath), { recursive: true });
  rmSync(destinationPath, { force: true, recursive: true });
  cpSync(sourcePath, destinationPath, { force: true, recursive: true });
}

ensureStandalonePackage("@swc/helpers", "cjs/_interop_require_default.cjs");
ensureStandalonePackage("@next/env", "dist/index.js");
ensureStandalonePackage("react", "cjs/react.production.js");
ensureStandalonePackage("react-dom", "cjs/react-dom.production.js");
copyStandaloneDirectory(".next/static", ".next/standalone/.next/static");
copyStandaloneDirectory("public", ".next/standalone/public");

const child = spawn(
  process.execPath,
  ["--preserve-symlinks", "--preserve-symlinks-main", ".next/standalone/server.js"],
  { env: { ...process.env, HOSTNAME: hostname, PORT: port }, stdio: "inherit" },
);

for (const signal of ["SIGINT", "SIGTERM"]) {
  process.once(signal, () => child.kill(signal));
}

child.once("exit", (code, signal) => {
  process.exitCode = code ?? (signal ? 1 : 0);
});
