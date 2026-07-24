import assert from "node:assert/strict";
import test from "node:test";

import { resolveRuntimeApiBaseUrl } from "./api.ts";

test("desktop runtime origin overrides the build fallback only when it is loopback HTTP", () => {
  assert.equal(
    resolveRuntimeApiBaseUrl("http://127.0.0.1:48123", "http://127.0.0.1:8000"),
    "http://127.0.0.1:48123",
  );
  for (const value of [
    "https://127.0.0.1:48123",
    "http://example.test:48123",
    "http://127.0.0.1:48123/path",
    "http://user@127.0.0.1:48123",
  ]) {
    assert.equal(
      resolveRuntimeApiBaseUrl(value, "http://127.0.0.1:8000"),
      "http://127.0.0.1:8000",
    );
  }
});
