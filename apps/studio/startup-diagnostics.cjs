const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");

const diagnosticDetails = Object.freeze({
  api_exited: "本地 API 在启动完成前已停止。",
  api_timeout: "本地 API 未在规定时间内就绪。",
  api_unhealthy: "本地 API 未通过健康检查。",
  port_unavailable: "本地启动端口不可用。",
  resources_missing: "缺少所需的本地启动资源。",
  startup_unknown: "本地启动检查未能完成。",
  state_unwritable: "本地应用状态目录不可写。",
  web_exited: "本地研究工作台服务在启动完成前已停止。",
  web_timeout: "本地研究工作台服务未在规定时间内就绪。",
  web_unhealthy: "本地研究工作台服务未通过就绪检查。",
});

const diagnosticCodes = new Set(Object.keys(diagnosticDetails));

function createStartupDiagnostic(code) {
  const normalizedCode = normalizeStartupDiagnosticCode(code);
  return {
    code: normalizedCode,
    detail: diagnosticDetails[normalizedCode],
  };
}

function createStartupDiagnosticError(code) {
  const diagnostic = createStartupDiagnostic(code);
  const error = new Error(diagnostic.code);
  error.code = diagnostic.code;
  return error;
}

function diagnosticFromError(error) {
  return createStartupDiagnostic(error?.code);
}

function preflightDevelopmentRuntime({
  apiDirectory,
  dataDirectory,
  webDirectory,
  workspaceDirectory,
}) {
  try {
    assertDirectory(apiDirectory);
    assertDirectory(webDirectory);
  } catch {
    throw createStartupDiagnosticError("resources_missing");
  }
  probeStartupState({ dataDirectory, workspaceDirectory });
}

function probeStartupState({ dataDirectory, workspaceDirectory }) {
  try {
    if (dataDirectory) {
      probeWritableDirectory(dataDirectory);
    }
    probeWritableDirectory(workspaceDirectory);
  } catch {
    throw createStartupDiagnosticError("state_unwritable");
  }
}

function resolveDevelopmentDataDirectory(databaseUrl, cwd) {
  if (typeof databaseUrl !== "string" || typeof cwd !== "string") {
    return null;
  }
  const match = /^sqlite(?:\+[^:/?#]+)?:\/\/\/([^?#]+)(?:[?#].*)?$/i.exec(databaseUrl);
  if (!match || match[1] === ":memory:" || match[1].startsWith("file:")) {
    return null;
  }
  try {
    return path.dirname(path.resolve(cwd, decodeURIComponent(match[1])));
  } catch {
    return null;
  }
}

function createStartupLiveness() {
  let monitoring = true;
  let startupFailure = null;

  function recordFailure(code) {
    if (monitoring && !startupFailure && diagnosticCodes.has(code)) {
      startupFailure = code;
    }
  }

  return {
    getStartupFailure() {
      return startupFailure;
    },
    markStartupReady() {
      monitoring = false;
      startupFailure = null;
    },
    stopMonitoring() {
      monitoring = false;
    },
    watch(child, code) {
      if (!child || typeof child.once !== "function") {
        return;
      }
      child.once("error", () => recordFailure(code));
      child.once("exit", () => recordFailure(code));
    },
  };
}

function normalizeStartupDiagnosticCode(code) {
  return diagnosticCodes.has(code) ? code : "startup_unknown";
}

function assertDirectory(directory) {
  if (!fs.statSync(directory).isDirectory()) {
    throw new Error("startup_directory_missing");
  }
}

function probeWritableDirectory(directory) {
  fs.mkdirSync(directory, { recursive: true });
  const probe = path.join(directory, `.mythos-startup-${crypto.randomUUID()}.tmp`);
  let created = false;
  try {
    fs.writeFileSync(probe, "", { flag: "wx" });
    created = true;
  } finally {
    if (created) {
      fs.unlinkSync(probe);
    }
  }
}

module.exports = {
  createStartupDiagnostic,
  createStartupDiagnosticError,
  createStartupLiveness,
  diagnosticFromError,
  preflightDevelopmentRuntime,
  probeStartupState,
  resolveDevelopmentDataDirectory,
};
