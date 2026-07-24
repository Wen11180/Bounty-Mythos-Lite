const assert = require("node:assert/strict");
const http = require("node:http");
const test = require("node:test");

const {
  createStudioLaunchConfig,
  findAvailablePort,
  startupErrorHtml,
  waitForApiHealth,
  waitForStudio,
  waitForUrl,
} = require("./launcher.cjs");

test("waitForUrl resolves after the local service responds", async () => {
  const server = http.createServer((_, response) => {
    response.writeHead(200);
    response.end("ready");
  });
  await listen(server);

  const address = server.address();
  const url = `http://127.0.0.1:${address.port}/studio`;

  try {
    await assert.doesNotReject(
      waitForUrl(url, { timeoutMs: 500, intervalMs: 10 }),
    );
  } finally {
    server.close();
  }
});

test("waitForUrl rejects when the local service never becomes ready", async () => {
  const server = http.createServer((_, response) => {
    response.writeHead(503);
    response.end("starting");
  });
  await listen(server);

  const address = server.address();
  const url = `http://127.0.0.1:${address.port}/studio`;

  try {
    await assert.rejects(
      waitForUrl(url, { timeoutMs: 40, intervalMs: 5 }),
      /Timed out waiting/,
    );
  } finally {
    server.close();
  }
});

test("waitForApiHealth accepts only the exact local health response", async (t) => {
  for (const [name, statusCode, body] of [
    ["expected", 200, JSON.stringify({ status: "ok", service: "bounty-mythos-api" })],
    ["wrong service", 200, JSON.stringify({ status: "ok", service: "other" })],
    ["extra field", 200, JSON.stringify({ status: "ok", service: "bounty-mythos-api", version: "1" })],
    ["malformed JSON", 200, "not-json"],
    ["non-200", 503, "token=not-for-diagnostics"],
    ["oversized", 200, "x".repeat(16 * 1024)],
  ]) {
    await t.test(name, async () => {
      const server = http.createServer((_, response) => {
        response.writeHead(statusCode, { "content-type": "application/json" });
        response.end(body);
      });
      await listen(server);
      const url = `http://127.0.0.1:${server.address().port}/health`;

      try {
        if (name === "expected") {
          await assert.doesNotReject(
            waitForApiHealth(url, { intervalMs: 5, requestTimeoutMs: 100, timeoutMs: 500 }),
          );
        } else {
          await assert.rejects(
            waitForApiHealth(url, { intervalMs: 5, requestTimeoutMs: 100, timeoutMs: 500 }),
            (error) => (
              error?.code === "api_unhealthy"
              && !/token|diagnostics/i.test(error.message)
            ),
          );
        }
      } finally {
        server.close();
      }
    });
  }
});

test("waitForStudio accepts only HTTP 200 without inspecting its response body", async () => {
  const server = http.createServer((_, response) => {
    response.writeHead(200, { "content-type": "text/html" });
    response.end("<main>local Studio</main>");
  });
  await listen(server);
  const url = `http://127.0.0.1:${server.address().port}/studio`;

  try {
    await assert.doesNotReject(
      waitForStudio(url, { intervalMs: 5, requestTimeoutMs: 100, timeoutMs: 500 }),
    );
  } finally {
    server.close();
  }
});

test("strict local readiness maps bad responses, timeouts, and early exits to fixed codes", async (t) => {
  await t.test("web response", async () => {
    const server = http.createServer((_, response) => {
      response.writeHead(201);
      response.end("not ready");
    });
    await listen(server);
    const url = `http://127.0.0.1:${server.address().port}/studio`;

    try {
      await assert.rejects(
        waitForStudio(url, { intervalMs: 5, requestTimeoutMs: 100, timeoutMs: 500 }),
        (error) => error?.code === "web_unhealthy",
      );
    } finally {
      server.close();
    }
  });

  await t.test("deadline", async () => {
    const server = http.createServer(() => {});
    await listen(server);
    const url = `http://127.0.0.1:${server.address().port}/health`;

    try {
      await assert.rejects(
        waitForApiHealth(url, { intervalMs: 5, requestTimeoutMs: 20, timeoutMs: 60 }),
        (error) => error?.code === "api_timeout",
      );
    } finally {
      server.close();
    }
  });

  await t.test("early API exit", async () => {
    await assert.rejects(
      waitForApiHealth("http://127.0.0.1:1/health", {
        getStartupFailure: () => "api_exited",
        intervalMs: 5,
        requestTimeoutMs: 100,
        timeoutMs: 500,
      }),
      (error) => error?.code === "api_exited",
    );
  });
});

test("waitForApiHealth enforces its total deadline while a response continues streaming", async () => {
  const server = http.createServer((_, response) => {
    response.writeHead(200, { "content-type": "application/json" });
    const stream = setInterval(() => response.write(" "), 5);
    const end = setTimeout(() => {
      clearInterval(stream);
      response.end("not-json");
    }, 250);
    response.once("close", () => {
      clearInterval(stream);
      clearTimeout(end);
    });
  });
  await listen(server);
  const url = `http://127.0.0.1:${server.address().port}/health`;
  const startedAt = Date.now();

  try {
    await assert.rejects(
      waitForApiHealth(url, { intervalMs: 5, requestTimeoutMs: 20, timeoutMs: 60 }),
      (error) => error?.code === "api_timeout",
    );
    assert.ok(Date.now() - startedAt < 200);
  } finally {
    server.close();
  }
});

test("startupErrorHtml renders only the fixed startup diagnostic projection", () => {
  const html = startupErrorHtml({
    code: "api_unhealthy",
    detail: "C:\\Users\\operator\\token=<secret>",
  });

  assert.match(html, /Mythos Studio could not start/);
  assert.match(html, /Diagnostic code:\s*<code>api_unhealthy<\/code>/);
  assert.match(html, /No research, validation, or report submission was started/);
  assert.doesNotMatch(html, /Users|token|secret/i);
});

test("startupErrorHtml gives development-only local recovery steps", () => {
  const html = startupErrorHtml({ code: "startup_unknown" }, { packaged: false });

  assert.match(html, /Check local prerequisites/);
  assert.match(html, /apps\/api/);
  assert.match(html, /python -m pip install -r requirements\.txt/);
  assert.match(html, /apps\/web/);
  assert.match(html, /npm install/);
  assert.match(html, /apps\/studio/);
  assert.match(html, /npm start/);
});

test("startupErrorHtml keeps packaged recovery steps free of source install commands", () => {
  const html = startupErrorHtml({ code: "state_unwritable" }, { packaged: true });

  assert.match(html, /Diagnostic code:\s*<code>state_unwritable<\/code>/);
  assert.match(html, /Restart the installed app/);
  assert.doesNotMatch(html, /python -m pip|npm install|apps\/api|apps\/web/i);
});

test("findAvailablePort returns the preferred port when it is free", async () => {
  const preferred = await reserveAndReleasePort();

  assert.equal(await findAvailablePort(preferred), preferred);
});

test("findAvailablePort skips an occupied preferred port", async () => {
  const server = http.createServer();
  await listen(server);
  const occupiedPort = server.address().port;

  try {
    const availablePort = await findAvailablePort(occupiedPort, { maxAttempts: 3 });

    assert.notEqual(availablePort, occupiedPort);
    assert.equal(availablePort, occupiedPort + 1);
  } finally {
    server.close();
  }
});

test("findAvailablePort maps an exhausted local port search to port_unavailable", async () => {
  await assert.rejects(
    findAvailablePort(8000, { maxAttempts: 0 }),
    (error) => error?.code === "port_unavailable",
  );
});

test("createStudioLaunchConfig uses available local ports and API URLs", async () => {
  const apiPort = await reserveAndReleasePort();
  const webPort = await reserveAndReleasePort();

  const config = await createStudioLaunchConfig({
    MYTHOS_API_PORT: String(apiPort),
    MYTHOS_WEB_PORT: String(webPort),
  });

  assert.equal(config.apiPort, apiPort);
  assert.equal(config.webPort, webPort);
  assert.equal(config.apiBaseUrl, `http://127.0.0.1:${apiPort}`);
  assert.equal(config.studioUrl, `http://127.0.0.1:${webPort}/studio`);
});

test("createStudioLaunchConfig rejects remote URL overrides", async () => {
  const apiPort = await reserveAndReleasePort();
  const webPort = await reserveAndReleasePort();

  for (const [name, value] of [
    ["MYTHOS_STUDIO_URL", "https://studio.example.test/studio"],
    ["API_BASE_URL", "https://api.example.test"],
    ["NEXT_PUBLIC_API_BASE_URL", "https://api.example.test"],
  ]) {
    await assert.rejects(
      createStudioLaunchConfig({
        MYTHOS_API_PORT: String(apiPort),
        MYTHOS_WEB_PORT: String(webPort),
        [name]: value,
      }),
      new RegExp(`${name} must use a loopback HTTP URL`),
    );
  }
});

test("createStudioLaunchConfig derives URLs instead of accepting loopback overrides", async () => {
  const apiPort = await reserveAndReleasePort();
  const webPort = await reserveAndReleasePort();

  const config = await createStudioLaunchConfig({
    MYTHOS_API_PORT: String(apiPort),
    MYTHOS_WEB_PORT: String(webPort),
    MYTHOS_STUDIO_URL: "http://127.0.0.1:9999/not-the-studio",
    API_BASE_URL: "http://127.0.0.1:9998",
    NEXT_PUBLIC_API_BASE_URL: "http://127.0.0.1:9997",
  });

  assert.equal(config.apiBaseUrl, `http://127.0.0.1:${apiPort}`);
  assert.equal(config.studioUrl, `http://127.0.0.1:${webPort}/studio`);
});

test("createStudioLaunchConfig never assigns the same API and Web port", async () => {
  const preferredPort = await reserveAndReleasePort();

  const config = await createStudioLaunchConfig({
    MYTHOS_API_PORT: String(preferredPort),
    MYTHOS_WEB_PORT: String(preferredPort),
  });

  assert.equal(config.apiPort, preferredPort);
  assert.notEqual(config.webPort, preferredPort);
  assert.equal(config.webPort, preferredPort + 1);
});

function listen(server) {
  return new Promise((resolve) => {
    server.listen(0, "127.0.0.1", resolve);
  });
}

async function reserveAndReleasePort() {
  const server = http.createServer();
  await listen(server);
  const port = server.address().port;
  await new Promise((resolve) => server.close(resolve));
  return port;
}
