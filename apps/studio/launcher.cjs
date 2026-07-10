const http = require("node:http");
const https = require("node:https");
const net = require("node:net");

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
  throw new Error(`No available local port starting at ${preferredPort}`);
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
  const deadline = Date.now() + timeoutMs;

  return new Promise((resolve, reject) => {
    function retry(lastError) {
      if (Date.now() >= deadline) {
        reject(
          new Error(
            `Timed out waiting for ${url}${lastError ? `: ${lastError.message}` : ""}`,
          ),
        );
        return;
      }
      setTimeout(attempt, intervalMs);
    }

    function attempt() {
      const parsed = new URL(url);
      const client = parsed.protocol === "https:" ? https : http;
      const request = client.get(parsed, (response) => {
        response.resume();
        if (response.statusCode && response.statusCode < 500) {
          resolve(url);
          return;
        }
        retry(new Error(`status ${response.statusCode ?? "unknown"}`));
      });

      request.setTimeout(3_000, () => {
        request.destroy(new Error("request timed out"));
      });
      request.on("error", retry);
    }

    attempt();
  });
}

function startupErrorHtml(error) {
  const message = error instanceof Error ? error.message : String(error);
  return `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <title>Mythos Studio startup failed</title>
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
      <h1>Mythos Studio could not start</h1>
      <p>The local app shell started, but the local Studio service did not become ready.</p>
      <h2>Check local prerequisites</h2>
      <ol>
        <li><span class="command">apps/api</span>: run <span class="command">python -m pip install -r requirements.txt</span></li>
        <li><span class="command">apps/web</span>: run <span class="command">npm install</span></li>
        <li><span class="command">apps/studio</span>: run <span class="command">npm install</span>, then <span class="command">npm start</span></li>
      </ol>
      <code>${escapeHtml(message)}</code>
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
  waitForUrl,
};
