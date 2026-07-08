import assert from "node:assert/strict";
import fs from "node:fs/promises";
import test from "node:test";
import {
  toStudioArtifactChecklist,
  toStudioCandidateCards,
  toStudioResearchReadiness,
  toStudioWorkspaceSummary,
} from "./studio-data.ts";

test("workspace summary maps manifest safety state", () => {
  const summary = toStudioWorkspaceSummary({
    name: "acme-api",
    artifacts: [],
    runs: [],
    safety: {
      scope_guard_status: "missing_scope",
      blocked_actions: ["execute_live_validation"],
    },
  });

  assert.equal(summary.name, "acme-api");
  assert.equal(summary.scopeGuardLabel, "Missing scope");
  assert.deepEqual(summary.blockedActions, ["execute_live_validation"]);
});

test("candidate cards map missing endpoint and code path to review fallbacks", () => {
  const [card] = toStudioCandidateCards([
    {
      hypothesis_id: "H-001",
      vuln_type: "IDOR",
      risk: "high",
      location: "",
      reason: "Object ownership is not proven at the route boundary.",
      evidence_needed: ["two test accounts"],
      false_positive_checks: ["ownership may be enforced in middleware"],
      safe_verification: true,
      priority_score: 80,
    },
  ]);

  assert.equal(card.id, "H-001");
  assert.equal(card.affectedEndpoint, "Endpoint needs review");
  assert.equal(card.affectedCodePath, "Code path needs review");
  assert.equal(card.status, "needs_review");
});

test("artifact checklist marks required A+B authorized inputs before research", () => {
  const checklist = toStudioArtifactChecklist({
    artifacts: [
      { kind: "scope", source_path: "C:/targets/scope.yaml" },
      { kind: "policy", source_path: "C:/targets/policy.md" },
    ],
  });

  assert.deepEqual(
    checklist
      .filter((item) => item.required)
      .map((item) => [item.kind, item.present, item.status]),
    [
      ["scope", true, "ready"],
      ["policy", true, "ready"],
      ["code", false, "missing"],
      ["api", false, "missing"],
      ["har", false, "missing"],
    ],
  );
  assert.equal(checklist.find((item) => item.kind === "sbom")?.status, "optional");
});

test("research readiness requires a workspace plus A+B artifacts", () => {
  const missingCode = toStudioResearchReadiness("", {
    artifacts: [{ kind: "scope", source_path: "C:/targets/scope.yaml" }],
  });

  assert.equal(missingCode.canStart, false);
  assert.equal(missingCode.reason, "Create or open a workspace before research.");

  const ready = toStudioResearchReadiness("C:/mythos-workspaces/acme", {
    artifacts: [
      { kind: "scope", source_path: "C:/targets/scope.yaml" },
      { kind: "policy", source_path: "C:/targets/policy.md" },
      { kind: "code", source_path: "C:/targets/repo" },
      { kind: "api", source_path: "C:/targets/openapi.json" },
      { kind: "har", source_path: "C:/targets/session.har" },
    ],
  });

  assert.equal(ready.canStart, true);
  assert.equal(ready.reason, "Policy, scope, API/HAR, and code are ready for A+B candidate research.");
});

test("research readiness blocks source-only workspaces before A+B materials are imported", () => {
  const readiness = toStudioResearchReadiness("C:/mythos-workspaces/acme", {
    artifacts: [
      { kind: "scope", source_path: "C:/targets/scope.yaml" },
      { kind: "code", source_path: "C:/targets/repo" },
    ],
  });

  assert.equal(readiness.canStart, false);
  assert.equal(readiness.reason, "Import policy and API and HAR before research.");
});

test("candidate cards expose review rationale and ranking reasons", () => {
  const [card] = toStudioCandidateCards([
    {
      hypothesis_id: "H-003",
      vuln_type: "IDOR",
      risk: "high",
      reason: "Authenticated users can request object ids without proven ownership.",
      ranking_reasons: ["impact:sensitive_data_sink", "traceable_source_fact"],
      safe_verification: true,
      source_facts: [{ route_path: "/files/{file_id}", source_path: "routes.py" }],
    },
  ]);

  assert.equal(
    card.reason,
    "Authenticated users can request object ids without proven ownership.",
  );
  assert.deepEqual(card.rankingReasons, [
    "impact:sensitive_data_sink",
    "traceable_source_fact",
  ]);
  assert.equal(card.status, "needs_evidence");
});

test("candidate cards expose safe validation plan and safety blockers", () => {
  const [card] = toStudioCandidateCards([
    {
      hypothesis_id: "H-004",
      vuln_type: "authorization",
      risk: "high",
      safe_validation_plan: ["Use only local test accounts.", "Require human approval."],
      safety_blockers: ["execute_live_validation", "submit_report"],
      validation_mode: "two_account_authorization_check",
      safe_verification: true,
    },
  ]);

  assert.equal(card.validationMode, "two_account_authorization_check");
  assert.deepEqual(card.safeValidationPlan, [
    "Use only local test accounts.",
    "Require human approval.",
  ]);
  assert.deepEqual(card.safetyBlockers, ["execute_live_validation", "submit_report"]);
});

test("candidate cards expose report readiness gate", () => {
  const [card] = toStudioCandidateCards([
    {
      hypothesis_id: "H-005",
      vuln_type: "authorization",
      risk: "high",
      report_readiness: {
        status: "submission_blocked",
        report_submission_allowed: false,
        next_allowed_action: "Review evidence before exporting a report preview.",
      },
      safe_verification: true,
    },
  ]);

  assert.equal(card.reportReadiness.status, "submission_blocked");
  assert.equal(card.reportReadiness.reportSubmissionAllowed, false);
  assert.equal(
    card.reportReadiness.nextAllowedAction,
    "Review evidence before exporting a report preview.",
  );
});

test("candidate cards keep unsafe candidates visibly blocked", () => {
  const [card] = toStudioCandidateCards([
    {
      hypothesis_id: "H-002",
      vuln_type: "SSRF",
      risk: "high",
      location: "/webhook/test",
      safe_verification: false,
      priority_score: 90,
    },
  ]);

  assert.equal(card.status, "blocked");
  assert.equal(card.affectedEndpoint, "/webhook/test");
});

test("studio page exposes the four studio regions", async () => {
  const page = await fs.readFile(new URL("../app/studio/page.tsx", import.meta.url), "utf8");
  const workbench = await fs
    .readFile(new URL("../app/studio/studio-workbench.tsx", import.meta.url), "utf8")
    .catch(() => "");
  const studioSource = `${page}\n${workbench}`;

  assert.match(studioSource, /Workspaces/);
  assert.match(studioSource, /Conversation/);
  assert.match(studioSource, /Candidate Board/);
  assert.match(studioSource, /Safety and Run Log/);
  assert.match(studioSource, /submission-blocked/);
});

test("studio page mounts the interactive local workbench", async () => {
  const page = await fs.readFile(new URL("../app/studio/page.tsx", import.meta.url), "utf8");
  const workbench = await fs.readFile(
    new URL("../app/studio/studio-workbench.tsx", import.meta.url),
    "utf8",
  );

  assert.match(page, /StudioWorkbench/);
  assert.match(workbench, /"use client"/);
  assert.match(workbench, /createStudioWorkspace/);
  assert.match(workbench, /importStudioWorkspaceArtifact/);
  assert.match(workbench, /runStudioWorkspaceResearch/);
  assert.match(workbench, /listStudioWorkspaceCandidates/);
  assert.match(workbench, /exportStudioWorkspaceReport/);
  assert.match(workbench, /Create workspace/);
  assert.match(workbench, /Start research/);
  assert.match(workbench, /Export report preview/);
});

test("studio workbench can open an existing local workspace", async () => {
  const workbench = await fs.readFile(
    new URL("../app/studio/studio-workbench.tsx", import.meta.url),
    "utf8",
  );

  assert.match(workbench, /getStudioWorkspaceManifest/);
  assert.match(workbench, /handleOpenWorkspace/);
  assert.match(workbench, /Open workspace/);
  assert.match(workbench, /latestRunFromManifest/);
  assert.match(workbench, /listStudioWorkspaceCandidates\(workspacePath/);
});

test("studio workbench imports policy as a first-class authorized artifact", async () => {
  const workbench = await fs.readFile(
    new URL("../app/studio/studio-workbench.tsx", import.meta.url),
    "utf8",
  );

  assert.match(workbench, /policyPath/);
  assert.match(workbench, /Policy file/);
  assert.match(workbench, /kind: "policy"/);
});

test("studio workbench imports HAR as a first-class authorized artifact", async () => {
  const workbench = await fs.readFile(
    new URL("../app/studio/studio-workbench.tsx", import.meta.url),
    "utf8",
  );

  assert.match(workbench, /harPath/);
  assert.match(workbench, /HAR file/);
  assert.match(workbench, /kind: "har"/);
});

test("studio workbench imports SBOM and SARIF as optional local context", async () => {
  const workbench = await fs.readFile(
    new URL("../app/studio/studio-workbench.tsx", import.meta.url),
    "utf8",
  );

  assert.match(workbench, /sbomPath/);
  assert.match(workbench, /sarifPath/);
  assert.match(workbench, /SBOM file/);
  assert.match(workbench, /SARIF file/);
  assert.match(workbench, /kind: "sbom"/);
  assert.match(workbench, /kind: "sarif"/);
  assert.match(workbench, /setSbomPath/);
  assert.match(workbench, /setSarifPath/);
});

test("studio workbench shows artifact readiness before research", async () => {
  const workbench = await fs.readFile(
    new URL("../app/studio/studio-workbench.tsx", import.meta.url),
    "utf8",
  );

  assert.match(workbench, /toStudioArtifactChecklist/);
  assert.match(workbench, /toStudioResearchReadiness/);
  assert.match(workbench, /Artifact readiness/);
  assert.match(workbench, /researchReadiness\.reason/);
  assert.match(workbench, /disabled=\{!researchReadiness\.canStart\}/);
});

test("studio workbench guides the first local research run", async () => {
  const workbench = await fs.readFile(
    new URL("../app/studio/studio-workbench.tsx", import.meta.url),
    "utf8",
  );

  assert.match(workbench, /Local research setup/);
  assert.match(workbench, /currentWizardStep/);
  assert.match(workbench, /wizardSteps/);
  assert.match(workbench, /Workspace selected/);
  assert.match(workbench, /Authorized materials/);
  assert.match(workbench, /Readiness check/);
  assert.match(workbench, /Candidate review/);
  assert.match(workbench, /submission-blocked report draft/);
  assert.match(workbench, /Import authorized materials/);
  assert.match(workbench, /Start local research/);
  assert.match(workbench, /Next safe action/);
  assert.match(workbench, /wizardPrimaryAction/);
  assert.match(workbench, /Export submission-blocked draft/);
  assert.match(workbench, /Required inputs/);
  assert.match(workbench, /Missing required inputs/);
  assert.match(workbench, /Optional context/);
  assert.match(workbench, /missingRequiredArtifacts/);
  assert.match(workbench, /optionalContextArtifacts/);
  assert.match(workbench, /handleCreateWorkspace/);
  assert.match(workbench, /handleImportArtifacts/);
  assert.match(workbench, /handleStartResearch/);
  assert.match(workbench, /handleExportReport/);
  assert.doesNotMatch(workbench, /Submit report/);
});

test("studio workbench can use the desktop path picker bridge", async () => {
  const workbench = await fs.readFile(
    new URL("../app/studio/studio-workbench.tsx", import.meta.url),
    "utf8",
  );

  assert.match(workbench, /mythosStudio/);
  assert.match(workbench, /selectFile/);
  assert.match(workbench, /selectDirectory/);
  assert.match(workbench, /Browse/);
  assert.match(workbench, /handleSelectPath/);
  assert.match(workbench, /useEffect/);
  assert.match(workbench, /desktopPickerAvailable/);
  assert.match(workbench, /window\.setTimeout/);
  assert.match(workbench, /setDesktopPickerAvailable\(Boolean\(window\.mythosStudio\)\)/);
  assert.match(workbench, /browseEnabled=\{desktopPickerAvailable\}/);
  assert.doesNotMatch(workbench, /const desktopPickerAvailable = typeof window/);
  assert.doesNotMatch(workbench, /useEffect\(\(\) => \{\s*setDesktopPickerAvailable/s);
});

test("studio workbench surfaces exported markdown report drafts", async () => {
  const workbench = await fs.readFile(
    new URL("../app/studio/studio-workbench.tsx", import.meta.url),
    "utf8",
  );

  assert.match(workbench, /report_markdown_path/);
  assert.match(workbench, /Markdown draft/);
});

test("studio workbench surfaces candidate rationale and ranking reasons", async () => {
  const workbench = await fs.readFile(
    new URL("../app/studio/studio-workbench.tsx", import.meta.url),
    "utf8",
  );

  assert.match(workbench, /candidate\.reason/);
  assert.match(workbench, /Ranking reasons/);
});

test("studio workbench surfaces validation plan and safety blockers", async () => {
  const workbench = await fs.readFile(
    new URL("../app/studio/studio-workbench.tsx", import.meta.url),
    "utf8",
  );

  assert.match(workbench, /Safe validation plan/);
  assert.match(workbench, /Safety blockers/);
  assert.match(workbench, /candidate\.validationMode/);
});

test("studio workbench surfaces candidate report readiness", async () => {
  const workbench = await fs.readFile(
    new URL("../app/studio/studio-workbench.tsx", import.meta.url),
    "utf8",
  );

  assert.match(workbench, /Report readiness/);
  assert.match(workbench, /candidate\.reportReadiness/);
});
