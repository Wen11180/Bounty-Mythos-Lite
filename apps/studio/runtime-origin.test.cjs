const assert = require("node:assert/strict");
const test = require("node:test");

const { apiBaseUrlFromArguments } = require("./runtime-origin.cjs");

test("preload accepts only the derived loopback API argument", () => {
  assert.equal(
    apiBaseUrlFromArguments(["electron", "--mythos-api-base-url=http://127.0.0.1:48123"]),
    "http://127.0.0.1:48123",
  );
  for (const value of [
    "https://127.0.0.1:48123",
    "http://example.test:48123",
    "http://127.0.0.1:48123/path",
    "http://user@127.0.0.1:48123",
  ]) {
    assert.equal(
      apiBaseUrlFromArguments(["electron", `--mythos-api-base-url=${value}`]),
      null,
    );
  }
});
