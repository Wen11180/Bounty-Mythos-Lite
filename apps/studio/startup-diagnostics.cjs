const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");

const diagnosticDetails = Object.freeze({
  api_exited: "The local API stopped before startup completed.",
  api_timeout: "The local API did not become ready in time.",
  api_unhealthy: "The local API did not pass its health check.",
  port_unavailable: "The local startup ports are unavailable.",
  resources_missing: "Required local startup resources are unavailable.",
  startup_unknown: "The local startup check did not complete.",
  state_unwritable: "Local application state is not writable.",
  web_exited: "The local Studio service stopped before startup completed.",
  web_timeout: "The local Studio service did not become ready in time.",
  web_unhealthy: "The local Studio service did not pass its readiness check.",
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
    const databasePath = decodeURIComponent(match[1]);
    if (/^[A-Za-z]:[\\/]/u.test(databasePath)) {
      return path.win32.dirname(databasePath).replace(/[\\/]/gu, path.sep);
    }
    return path.dirname(path.resolve(cwd, databasePath));
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
