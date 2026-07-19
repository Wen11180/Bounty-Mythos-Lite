import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const componentUrl = new URL("../app/studio/program-rule-intake.tsx", import.meta.url);
const workbenchUrl = new URL("../app/studio/studio-workbench.tsx", import.meta.url);

test("program-rule intake exposes only public URL registration and human review fields", async () => {
  const source = await readFile(componentUrl, "utf8");

  assert.match(source, /name="program_alias"/u);
  assert.match(source, /name="public_rule_url"/u);
  assert.match(source, /name="reviewer_alias"/u);
  assert.match(source, /type="checkbox"/u);
  assert.doesNotMatch(
    source,
    /<input[^>]+name="(?:credential|cookie|token|account|har|proxy|header|crawl_depth)"/iu,
  );
  assert.doesNotMatch(source, /<textarea/iu);
});

test("program-rule intake uses only operator APIs and a no-argument desktop kick", async () => {
  const source = await readFile(componentUrl, "utf8");

  for (const helper of [
    "registerProgramRuleSource",
    "listProgramRuleSources",
    "refreshProgramRuleSource",
    "listProgramRuleSnapshots",
    "getProgramRuleSnapshotDiff",
    "approveProgramRuleSnapshot",
    "rejectProgramRuleSnapshot",
    "listProgramScopeRules",
  ]) {
    assert.match(source, new RegExp(helper, "u"));
  }
  assert.match(source, /window\.mythosStudio\?\.refreshProgramRules\(\)/u);
  assert.match(source, /studio_required/u);
  assert.doesNotMatch(source, /\bfetch\s*\(/u);
  assert.doesNotMatch(source, /program-rule-fetch|claims\/next|claim_token/iu);
});

test("program-rule review keeps fetch, review, and effective states distinct", async () => {
  const source = await readFile(componentUrl, "utf8");

  assert.match(source, /label="Fetch state"/u);
  assert.match(source, /label="Review state"/u);
  assert.match(source, /label="Effective state"/u);
  assert.match(source, /expected_review_digest/u);
  assert.match(source, /operator_confirmed:\s*true/u);
  assert.match(source, /addedRules|removedRules|modifiedRules/u);
  assert.match(source, /addedProhibitions|removedProhibitions/u);
  assert.match(source, /linkedArtifacts|rateLimit|evidence/u);
  assert.doesNotMatch(source, /raw_html|raw_body|response_headers|browser_state/iu);
  assert.doesNotMatch(source, /verified vulnerability|submit report|grant lease/iu);
});

test("studio workbench mounts one intake surface and extends only the fixed bridge status", async () => {
  const workbench = await readFile(workbenchUrl, "utf8");

  assert.match(workbench, /import \{ ProgramRuleIntake \}/u);
  assert.equal(workbench.match(/<ProgramRuleIntake\s*\/>/gu)?.length, 1);
  assert.match(
    workbench,
    /refreshProgramRules:\s*\(\) => Promise<SafeRefreshStatus>/u,
  );
});
