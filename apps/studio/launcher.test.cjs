const assert = require("node:assert/strict");
const http = require("node:http");
const test = require("node:test");

const { startupErrorHtml, waitForUrl } = require("./launcher.cjs");

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

function listen(server) {
  return new Promise((resolve) => {
    server.listen(0, "127.0.0.1", resolve);
  });
}
