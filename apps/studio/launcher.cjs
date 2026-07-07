const http = require("node:http");
const https = require("node:https");

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
    </style>
  </head>
  <body>
    <main>
      <h1>Mythos Studio could not start</h1>
      <p>The local app shell started, but the local Studio service did not become ready.</p>
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

module.exports = {
  startupErrorHtml,
  waitForUrl,
};
