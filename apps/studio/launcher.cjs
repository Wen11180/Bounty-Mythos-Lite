const http = require("node:http");
const https = require("node:https");
const net = require("node:net");
const {
  createStartupDiagnostic,
  createStartupDiagnosticError,
} = require("./startup-diagnostics.cjs");

const defaultHost = "127.0.0.1";
const loopbackHosts = new Set(["127.0.0.1", "localhost", "[::1]", "::1"]);
const urlOverrideNames = [
  "MYTHOS_STUDIO_URL",
  "API_BASE_URL",
  "NEXT_PUBLIC_API_BASE_URL",
];

async function createStudioLaunchConfig(env = process.env) {
  assertLoopbackUrlOverrides(env);
  const apiPort = await findAvailablePort(portFromEnv(env.MYTHOS_API_PORT, 8000));
  const webPort = await findAvailablePort(portFromEnv(env.MYTHOS_WEB_PORT, 3000), {
    reservedPorts: new Set([apiPort]),
  });
  const apiBaseUrl = `http://${defaultHost}:${apiPort}`;
  const webBaseUrl = `http://${defaultHost}:${webPort}`;

  return {
    apiBaseUrl,
    apiPort,
    studioUrl: `${webBaseUrl}/studio`,
    webPort,
  };
}

function assertLoopbackUrlOverrides(env) {
  for (const name of urlOverrideNames) {
    const value = env[name];
    if (!value) {
      continue;
    }

    let parsed;
    try {
      parsed = new URL(value);
    } catch {
      throw new Error(`${name} must use a loopback HTTP URL`);
    }

    if (parsed.protocol !== "http:" || !loopbackHosts.has(parsed.hostname)) {
      throw new Error(`${name} must use a loopback HTTP URL`);
    }
  }
}

async function findAvailablePort(preferredPort, options = {}) {
  const host = options.host ?? defaultHost;
  const maxAttempts = options.maxAttempts ?? 50;
  const reservedPorts = options.reservedPorts ?? new Set();
  for (let offset = 0; offset < maxAttempts; offset += 1) {
    const port = preferredPort + offset;
    if (!reservedPorts.has(port) && (await isPortAvailable(port, host))) {
      return port;
    }
  }
  throw createStartupDiagnosticError("port_unavailable");
}

function isPortAvailable(port, host) {
  return new Promise((resolve, reject) => {
    const server = net.createServer();
    server.once("error", (error) => {
      if (error.code === "EADDRINUSE" || error.code === "EACCES") {
        resolve(false);
        return;
      }
      reject(error);
    });
    server.once("listening", () => {
      server.close(() => resolve(true));
    });
    server.listen(port, host);
  });
}

function waitForUrl(url, options = {}) {
  const timeoutMs = options.timeoutMs ?? 60_000;
  const intervalMs = options.intervalMs ?? 750;
  const requestTimeoutMs = options.requestTimeoutMs ?? 3_000;
  const getStartupFailure = options.getStartupFailure;
  const timeoutCode = options.timeoutCode;
  const unhealthyCode = options.unhealthyCode;
  const validateResponse = options.validateResponse ?? validateGenericResponse;
  const deadline = Date.now() + timeoutMs;

  let parsed;
  try {
    parsed = new URL(url);
    assertLoopbackHttpUrl(parsed);
  } catch {
    return Promise.reject(createStartupDiagnosticError("startup_unknown"));
  }

  return new Promise((resolve, reject) => {
    let settled = false;
    let activeRequest = null;
    let activeResponse = null;
    let deadlineTimer = null;

    function complete(callback) {
      if (settled) {
        return;
      }
      settled = true;
      if (deadlineTimer) {
        clearTimeout(deadlineTimer);
      }
      callback();
    }

    function startupFailure() {
      if (typeof getStartupFailure !== "function") {
        return null;
      }
      try {
        return getStartupFailure() || null;
      } catch {
        return "startup_unknown";
      }
    }

    function rejectFor(code, fallbackMessage) {
      complete(() => {
        reject(code ? createStartupDiagnosticError(code) : new Error(fallbackMessage));
      });
    }

    function stopActiveRequest() {
      try {
        activeResponse?.destroy();
      } catch {}
      try {
        activeRequest?.destroy();
      } catch {}
    }

    function rejectForTimeout() {
      rejectFor(timeoutCode, "Timed out waiting for local service");
      stopActiveRequest();
    }

    function retry() {
      const failure = startupFailure();
      if (failure) {
        rejectFor(failure, "Local service stopped during startup");
        return;
      }
      if (Date.now() >= deadline) {
        rejectForTimeout();
        return;
      }
      setTimeout(attempt, Math.min(intervalMs, deadline - Date.now()));
    }

    function attempt() {
      if (settled) {
        return;
      }
      const failure = startupFailure();
      if (failure) {
        rejectFor(failure, "Local service stopped during startup");
        return;
      }
      if (Date.now() >= deadline) {
        retry();
        return;
      }

      const client = parsed.protocol === "https:" ? https : http;
      let attemptComplete = false;
      const completeAttempt = (callback) => {
        if (attemptComplete || settled) {
          return;
        }
        attemptComplete = true;
        if (Date.now() >= deadline) {
          rejectForTimeout();
          return;
        }
        callback();
      };

      let request;
      try {
        request = client.get(parsed, (response) => {
          activeResponse = response;
          Promise.resolve(validateResponse(response)).then(
            (result) => completeAttempt(() => {
              const childFailure = startupFailure();
              if (childFailure) {
                rejectFor(childFailure, "Local service stopped during startup");
                return;
              }
              if (result === "ready") {
                complete(() => resolve(url));
                return;
              }
              if (result === "retry") {
                retry();
                return;
              }
              rejectFor(unhealthyCode, "Local service readiness check failed");
            }),
            () => completeAttempt(() => rejectFor(unhealthyCode, "Local service readiness check failed")),
          );
        });
        activeRequest = request;
        request.setTimeout(requestTimeoutMs, () => {
          request.destroy();
        });
        request.once("error", () => completeAttempt(retry));
      } catch {
        completeAttempt(retry);
      }
    }

    deadlineTimer = setTimeout(rejectForTimeout, timeoutMs);
    attempt();
  });
}

function waitForApiHealth(apiBaseUrl, options = {}) {
  return waitForUrl(endpointUrl(apiBaseUrl, "/health"), {
    intervalMs: 250,
    requestTimeoutMs: 2_000,
    timeoutMs: 45_000,
    ...options,
    timeoutCode: "api_timeout",
    unhealthyCode: "api_unhealthy",
    validateResponse: validateApiHealthResponse,
  });
}

function waitForStudio(studioUrl, options = {}) {
  return waitForUrl(endpointUrl(studioUrl, "/studio"), {
    intervalMs: 250,
    requestTimeoutMs: 2_000,
    timeoutMs: 45_000,
    ...options,
    timeoutCode: "web_timeout",
    unhealthyCode: "web_unhealthy",
    validateResponse: validateStudioResponse,
  });
}

function validateGenericResponse(response) {
  response.resume();
  return response.statusCode && response.statusCode < 500 ? "ready" : "retry";
}

async function validateApiHealthResponse(response) {
  if (response.statusCode !== 200) {
    response.resume();
    return "unhealthy";
  }
  const body = await readBoundedResponseBody(response, 8 * 1024);
  if (body === null) {
    return "unhealthy";
  }
  try {
    return isExactApiHealth(JSON.parse(body)) ? "ready" : "unhealthy";
  } catch {
    return "unhealthy";
  }
}

function validateStudioResponse(response) {
  response.resume();
  return response.statusCode === 200 ? "ready" : "unhealthy";
}

function readBoundedResponseBody(response, maxBytes) {
  return new Promise((resolve) => {
    const chunks = [];
    let byteCount = 0;
    let finished = false;
    const finish = (value) => {
      if (!finished) {
        finished = true;
        resolve(value);
      }
    };
    response.on("data", (chunk) => {
      const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
      byteCount += buffer.length;
      if (byteCount > maxBytes) {
        response.destroy();
        finish(null);
        return;
      }
      chunks.push(buffer);
    });
    response.once("end", () => finish(Buffer.concat(chunks).toString("utf8")));
    response.once("error", () => finish(null));
  });
}

function isExactApiHealth(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    return false;
  }
  const keys = Object.keys(value).sort();
  return (
    keys.length === 2
    && keys[0] === "service"
    && keys[1] === "status"
    && value.service === "bounty-mythos-api"
    && value.status === "ok"
  );
}

function endpointUrl(baseUrl, pathname) {
  const parsed = new URL(baseUrl);
  parsed.hash = "";
  parsed.pathname = pathname;
  parsed.search = "";
  return parsed.toString();
}

function assertLoopbackHttpUrl(parsed) {
  if (
    (parsed.protocol !== "http:" && parsed.protocol !== "https:")
    || !loopbackHosts.has(parsed.hostname)
  ) {
    throw new Error("local_startup_url_required");
  }
}

function startupErrorHtml(diagnostic, { packaged = false } = {}) {
  const safeDiagnostic = createStartupDiagnostic(diagnostic?.code);
  const steps = packaged
    ? [
      "重新启动已安装的应用。",
      "再次尝试前，请关闭其他本地研究工作台实例。",
      "在应用能够打开现有恢复控件前，请保持本地数据不变。",
    ]
    : [
      '<span class="command">apps/api</span>：执行 <span class="command">python -m pip install -r requirements.txt</span>',
      '<span class="command">apps/web</span>：执行 <span class="command">npm install</span>',
      '<span class="command">apps/studio</span>：执行 <span class="command">npm install</span>，然后执行 <span class="command">npm start</span>',
    ];
  return `<!doctype html>
<html lang="zh-CN">
  <head>
    <meta charset="utf-8" />
    <title>赏金神话研究工作台启动失败</title>
    <style>
      body {
        margin: 0;
        min-height: 100vh;
        display: grid;
        place-items: center;
        background: #f7f7f4;
        color: #151515;
        font-family: Arial, sans-serif;
      }
      main {
        width: min(720px, calc(100vw - 48px));
        border: 1px solid #d8d6cf;
        background: #fff;
        padding: 28px;
      }
      code {
        display: block;
        margin-top: 16px;
        white-space: pre-wrap;
        color: #7a2d18;
      }
      ol {
        margin: 18px 0 0;
        padding-left: 22px;
      }
      li {
        margin-top: 10px;
      }
      .command {
        color: #151515;
      }
    </style>
  </head>
  <body>
    <main>
      <h1>赏金神话研究工作台无法启动</h1>
      <p>${escapeHtml(safeDiagnostic.detail)}</p>
      <p>诊断代码：<code>${escapeHtml(safeDiagnostic.code)}</code></p>
      <h2>检查本地前置条件</h2>
      <ol>
        ${steps.map((step) => `<li>${step}</li>`).join("\n        ")}
      </ol>
      <p>尚未启动研究、验证或报告提交。</p>
    </main>
  </body>
</html>`;
}

function escapeHtml(value) {
  return value
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function portFromEnv(value, fallback) {
  const parsed = Number.parseInt(value ?? "", 10);
  return Number.isInteger(parsed) && parsed > 0 ? parsed : fallback;
}

module.exports = {
  createStudioLaunchConfig,
  findAvailablePort,
  startupErrorHtml,
  waitForApiHealth,
  waitForStudio,
  waitForUrl,
};
