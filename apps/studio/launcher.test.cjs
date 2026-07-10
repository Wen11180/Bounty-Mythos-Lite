const assert = require("node:assert/strict");
const http = require("node:http");
const test = require("node:test");

const {
  createStudioLaunchConfig,
  findAvailablePort,
  startupErrorHtml,
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

test("startupErrorHtml escapes startup failure details", () => {
  const html = startupErrorHtml(new Error("<token> & bearer"));

  assert.match(html, /Mythos Studio could not start/);
  assert.match(html, /&lt;token&gt; &amp; bearer/);
  assert.doesNotMatch(html, /<token>/);
});

test("startupErrorHtml gives local recovery steps", () => {
  const html = startupErrorHtml(new Error("service failed"));

  assert.match(html, /Check local prerequisites/);
  assert.match(html, /apps\/api/);
  assert.match(html, /python -m pip install -r requirements\.txt/);
  assert.match(html, /apps\/web/);
  assert.match(html, /npm install/);
  assert.match(html, /apps\/studio/);
  assert.match(html, /npm start/);
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
