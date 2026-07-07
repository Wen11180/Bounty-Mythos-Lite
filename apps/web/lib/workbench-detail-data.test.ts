import assert from "node:assert/strict";
import test from "node:test";
import { safeDisplay, safeRecordEntries, safeStringList } from "./workbench-display.ts";

test("workbench display helpers suppress identity and token-shaped text", () => {
  const values = [
    safeDisplay("alice@example.com"),
    safeDisplay("JWT eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.signature"),
    safeDisplay("api_key=secret-fixture"),
    safeDisplay("production user data in response"),
    ...safeStringList(["customer data", "safe summary"]),
    ...safeRecordEntries({
      owner: "alice@example.com",
      proof: "personal data present",
    }).flatMap(([label, value]) => [label, value]),
  ];

  assert.deepEqual(values, [
    "[REDACTED]",
    "[REDACTED]",
    "[REDACTED]",
    "[REDACTED]",
    "[REDACTED]",
    "safe summary",
    "Owner",
    "[REDACTED]",
    "Proof",
    "[REDACTED]",
  ]);
  assert.doesNotMatch(
    JSON.stringify(values),
    /alice@example\.com|eyJhbGciOiJIUzI1NiJ9|api_key|production user|customer data|personal data/i,
  );
});
