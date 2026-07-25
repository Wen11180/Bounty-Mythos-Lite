const fs = require("node:fs");
const path = require("node:path");

const runtime = path.join(__dirname, "runtime");
const packageLock = require("./package-lock.json");

function ignore(relativePath) {
  const normalized = relativePath.replaceAll("\\", "/");
  if (
    /^\/(?:out|runtime)(?:\/|$)/.test(normalized)
    || /^\/node_modules(?:\/|$)/.test(normalized)
    || /\.test\.cjs$/.test(normalized)
    || /\/(?:README\.md|forge\.config\.cjs|package-lock\.json|package-runtime\.cjs|pnpm-lock\.yaml)$/.test(normalized)
  ) {
    return true;
  }
  return false;
}

function stageProductionDependencies(buildPath) {
  const targetRoot = path.join(buildPath, "node_modules");
  fs.mkdirSync(targetRoot, { recursive: true });
  for (const [packageKey, metadata] of Object.entries(packageLock.packages)) {
    if (!isRootPackage(packageKey) || metadata.dev === true) {
      continue;
    }
    const source = path.join(__dirname, packageKey);
    if (!fs.existsSync(source)) {
      if (metadata.optional) {
        continue;
      }
      throw new Error(`missing_production_dependency:${packageKey}`);
    }
    const target = path.join(buildPath, packageKey);
    fs.mkdirSync(path.dirname(target), { recursive: true });
    fs.cpSync(fs.realpathSync(source), target, { dereference: true, recursive: true });
  }
}

function isRootPackage(packageKey) {
  return /^node_modules\/(?:@[^/]+\/[^/]+|[^/]+)$/.test(packageKey);
}

module.exports = {
  hooks: {
    packageAfterCopy: async (_config, buildPath) => {
      stageProductionDependencies(buildPath);
    },
  },
  packagerConfig: {
    asar: true,
    extraResource: [
      path.join(runtime, "api"),
      path.join(runtime, "web"),
      path.join(runtime, "playwright"),
    ],
    ignore,
    name: "BountyMythosLite",
    platform: "win32",
    arch: "x64",
    prune: false,
  },
  makers: [
    {
      name: "@electron-forge/maker-squirrel",
      platforms: ["win32"],
      config: {
        authors: "赏金神话·轻量版贡献者",
        description: "本地、审核门控的安全研究控制中心。",
        name: "BountyMythosLite",
        setupExe: "BountyMythosLite Setup.exe",
      },
    },
  ],
};
