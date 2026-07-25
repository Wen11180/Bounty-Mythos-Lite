import assert from "node:assert/strict";
import test from "node:test";
import {
  ApiRequestError,
  approveProgramRuleSnapshot,
  approveStudioBlackBoxLabRun,
  completeCampaignCycleReview,
  createResearchReviewPlan,
  createResearchRefutationDecision,
  createStudioWorkspaceBenchmarkTemplate,
  createStudioWorkspace,
  createFindingCandidate,
  getCampaignControlCenter,
  getCampaignControlCenterRequired,
  getControlCenterOverview,
  getProgramRuleSnapshotDiff,
  getProgramRuleSource,
  getStudioBlackBoxRemoteStatus,
  getStudioWorkspaceManifest,
  getStudioWorkspaceManifestRequired,
  importStudioWorkspaceArtifact,
  exportStudioWorkspaceCampaignHunterReport,
  exportStudioWorkspaceMissionDossier,
  exportStudioWorkspaceReport,
  listStudioWorkspaceCandidates,
  listStudioWorkspaceCandidatesRequired,
  listProgramRuleSnapshots,
  listProgramRuleSources,
  listProgramScopeRules,
  getStudioWorkspaceMission,
  getStudioWorkspaceMissionRequired,
  getStudioWorkspaceMissionHandoff,
  materializeResearchQueueTask,
  recordCandidateHunterLearningOutcome,
  recordClaimReviewDecision,
  recordManualObservation,
  refreshProgramRuleSource,
  registerProgramRuleSource,
  rejectProgramRuleSnapshot,
  runStudioWorkspaceBenchmark,
  runStudioWorkspaceResearch,
  reviewValidationFeedbackForFindingPromotion,
  runSourceAuditScan,
  previewStudioBlackBoxLabLease,
  preflightMythosValidationRun,
  preflightStudioBlackBoxLabRun,
  recordStudioBlackBoxLabBoundedResult,
  SourceAuditScanError,
  type Finding,
  type ProgramIntelligenceProfile,
  type StudioBlackBoxLabBoundedTrace,
  type StudioBlackBoxLabCompletePlan,
} from "./api.ts";
import type {
  CampaignPipelineStage,
  CampaignResearchRefutationDecision,
  CampaignResearchReviewPlan,
  CampaignTask,
} from "./campaigns-data.ts";

const fallbackFinding: Finding = {
  asset: "api.example.com",
  broken_invariant: "Object ownership must be enforced.",
  confidence: 80,
  duplicate_likelihood: "low",
  evidence_refs: ["evidence_1"],
  id: "finding_fallback",
  operating_reasons: ["human_reviewed"],
  policy_status: "allowed",
  program: "program_1",
  refutation_status: "passed",
  scope_status: "in_scope",
  severity_estimate: "high",
  submission_recommendation: "manual_review",
  title: "Fallback finding",
  validation_status: "report_ready",
  vuln_type: "idor",
};

const fallbackProgramProfile: ProgramIntelligenceProfile = {
  applied_lessons: [],
  attack_surface_memory: {
    objects: [],
    relationships: [],
    roles: [],
    run_count: 0,
    sensitive_actions: [],
  },
  high_value_surfaces: [],
  learning_summary: {
    accepted_count: 0,
    adequate_evidence_count: 0,
    bounty_total: 0,
    boosted_playbooks: [],
    duplicate_count: 0,
    evidence_score_delta: 0,
    informative_count: 0,
    na_count: 0,
    penalized_playbooks: [],
    rejected_count: 0,
    rejection_risk_delta: 0,
    severity_down_count: 0,
    severity_up_count: 0,
    strong_evidence_count: 0,
    triager_feedback_count: 0,
    weak_evidence_count: 0,
  },
  lesson_adjusted_surfaces: [],
  program_id: "program_1",
  program_name: "Program 1",
  program_score: 0,
  recent_learning_signals: [],
  safety_notes: [],
  skipped_lessons: [],
};

test("program-rule operator helpers use only documented non-claim endpoints", async () => {
  const originalFetch = globalThis.fetch;
  const calls: Array<{ body: unknown; method: string; path: string }> = [];
  globalThis.fetch = async (input, init) => {
    const path = new URL(String(input)).pathname;
    const method = init?.method ?? "GET";
    calls.push({
      body: init?.body ? JSON.parse(String(init.body)) : null,
      method,
      path,
    });
    if (path.endsWith("/diff")) return jsonResponse({ review_digest: "a".repeat(64) });
    if (path.endsWith("/scope-rules")) return jsonResponse([]);
    if (path.endsWith("/snapshots")) return jsonResponse([]);
    if (path.endsWith("/approve") || path.endsWith("/reject")) {
      return jsonResponse({ review_status: path.endsWith("/approve") ? "approved" : "rejected" });
    }
    if (path === "/program-rule-sources" && method === "GET") return jsonResponse([]);
    return jsonResponse({ source_id: "source_synthetic" }, method === "POST" ? 202 : 200);
  };

  const review = {
    expected_review_digest: "a".repeat(64),
    operator_confirmed: true as const,
    reviewer_alias: "reviewer_one",
  };
  try {
    await listProgramRuleSources();
    await registerProgramRuleSource({
      program_alias: "synthetic_program",
      public_rule_url: "https://rules.example.test/program",
    });
    await getProgramRuleSource("source_synthetic");
    await refreshProgramRuleSource("source_synthetic");
    await listProgramRuleSnapshots("source_synthetic");
    await getProgramRuleSnapshotDiff("source_synthetic", "snapshot_pending");
    await approveProgramRuleSnapshot("source_synthetic", "snapshot_pending", review);
    await rejectProgramRuleSnapshot("source_synthetic", "snapshot_pending", review);
    await listProgramScopeRules("program_synthetic");

    assert.deepEqual(calls.map(({ method, path }) => ({ method, path })), [
      { method: "GET", path: "/program-rule-sources" },
      { method: "POST", path: "/program-rule-sources" },
      { method: "GET", path: "/program-rule-sources/source_synthetic" },
      { method: "POST", path: "/program-rule-sources/source_synthetic/refresh" },
      { method: "GET", path: "/program-rule-sources/source_synthetic/snapshots" },
      { method: "GET", path: "/program-rule-sources/source_synthetic/snapshots/snapshot_pending/diff" },
      { method: "POST", path: "/program-rule-sources/source_synthetic/snapshots/snapshot_pending/approve" },
      { method: "POST", path: "/program-rule-sources/source_synthetic/snapshots/snapshot_pending/reject" },
      { method: "GET", path: "/programs/program_synthetic/scope-rules" },
    ]);
    assert.deepEqual(calls[1]?.body, {
      program_alias: "synthetic_program",
      public_rule_url: "https://rules.example.test/program",
    });
    assert.deepEqual(calls[3]?.body, {});
    assert.deepEqual(calls[6]?.body, review);
    assert.deepEqual(calls[7]?.body, review);
    assert.doesNotMatch(JSON.stringify(calls), /program-rule-fetch|claims\/next/u);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("program-rule mutations propagate conflict and cooldown errors without fallback success", async () => {
  const originalFetch = globalThis.fetch;
  for (const [status, detail, operation] of [
    [409, "Program rule state conflict", () => registerProgramRuleSource({
      program_alias: "synthetic_program",
      public_rule_url: "https://rules.example.test/program",
    })],
    [429, "Program rule manual refresh is cooling down", () => refreshProgramRuleSource("source_synthetic")],
  ] as const) {
    globalThis.fetch = async () => jsonResponse({ detail }, status);
    await assert.rejects(operation, (error) => {
      assert.equal(error instanceof ApiRequestError, true);
      assert.equal((error as ApiRequestError).status, status);
      assert.equal((error as ApiRequestError).detail, detail);
      return true;
    });
  }
  globalThis.fetch = originalFetch;
});

function jsonResponse(value: unknown, status = 200) {
  return new Response(JSON.stringify(value), {
    headers: { "Content-Type": "application/json" },
    status,
  });
}

test("getControlCenterOverview is strict and forwards an optional campaign filter", async () => {
  const originalFetch = globalThis.fetch;
  const urls: string[] = [];
  const overview = {
    agent_stages: [],
    authorized_assets: [],
    campaigns: [],
    candidates: [],
    data_mode: "live" as const,
    empty_state: true,
    generated_at: "2026-07-18T04:00:00Z",
    metrics: {
      approval_pressure_count: 0,
      retained_high_value_candidate_count: 0,
      running_task_count: 0,
      safety_block_count: 0,
    },
    recent_events: [],
    report_readiness: {
      available: false,
      human_review_required: true,
      report_submission_allowed: false as const,
      status: "unavailable",
      submission_blocked: true,
    },
    research_quality: {
      evidence_completeness: null,
      median_human_review_seconds: null,
      refutation_kill_rate: null,
      retention_rate: null,
    },
    snapshot_version: "a".repeat(64),
  };

  globalThis.fetch = async (input, init) => {
    urls.push(String(input));
    assert.equal(init?.cache, "no-store");
    return new Response(JSON.stringify(overview), {
      headers: { "Content-Type": "application/json" },
      status: 200,
    });
  };

  try {
    assert.deepEqual(await getControlCenterOverview(), overview);
    assert.deepEqual(await getControlCenterOverview("campaign / one"), overview);
    assert.match(urls[0] ?? "", /\/mythos\/control-center\/overview$/);
    assert.match(urls[1] ?? "", /campaign_id=campaign(?:%20|\+)%2F(?:%20|\+)one$/);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("getControlCenterOverview never falls back on HTTP or network failures", async () => {
  const originalFetch = globalThis.fetch;
  try {
    globalThis.fetch = async () =>
      new Response(JSON.stringify({ detail: "overview_unavailable" }), {
        headers: { "Content-Type": "application/json" },
        status: 503,
      });
    await assert.rejects(
      () => getControlCenterOverview(),
      (error) =>
        error instanceof ApiRequestError &&
        error.status === 503 &&
        error.detail === "overview_unavailable",
    );

    globalThis.fetch = async () => {
      throw new TypeError("offline");
    };
    await assert.rejects(
      () => getControlCenterOverview(),
      (error) =>
        error instanceof ApiRequestError && error.status === 0 && error.detail === "network_error",
    );
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("getControlCenterOverview forwards AbortSignal and aborts its strict fetch", async () => {
  const originalFetch = globalThis.fetch;
  const controller = new AbortController();
  let receivedSignal: AbortSignal | null | undefined;
  globalThis.fetch = async (_input, init) => {
    receivedSignal = init?.signal;
    return await new Promise<Response>((_resolve, reject) => {
      if (!init?.signal) {
        reject(new TypeError("missing abort signal"));
        return;
      }
      init.signal.addEventListener("abort", () => {
        reject(new DOMException("The operation was aborted", "AbortError"));
      });
    });
  };

  try {
    const request = getControlCenterOverview("campaign_1", controller.signal);
    controller.abort();

    await assert.rejects(
      request,
      (error) => error instanceof ApiRequestError && error.detail === "network_error",
    );
    assert.equal(receivedSignal, controller.signal);
    assert.equal(receivedSignal?.aborted, true);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("studio live-refresh helpers forward AbortSignal to their GET requests", async () => {
  const originalFetch = globalThis.fetch;
  const controller = new AbortController();
  const receivedSignals: Array<AbortSignal | null | undefined> = [];
  globalThis.fetch = async (_input, init) => {
    receivedSignals.push(init?.signal);
    return await new Promise<Response>((_resolve, reject) => {
      if (!init?.signal) {
        reject(new TypeError("missing abort signal"));
        return;
      }
      init.signal.addEventListener("abort", () => {
        reject(new DOMException("The operation was aborted", "AbortError"));
      });
    });
  };

  try {
    const fallbackCandidates = { candidates: [], run_id: "run_1" };
    const requests = [
      getCampaignControlCenter("campaign_1", null, controller.signal),
      getStudioWorkspaceManifest("C:/authorized/studio", null, controller.signal),
      listStudioWorkspaceCandidates(
        "C:/authorized/studio",
        "run_1",
        fallbackCandidates,
        controller.signal,
      ),
      getStudioWorkspaceMission("C:/authorized/studio", "run_1", null, controller.signal),
    ] as const;
    controller.abort();

    const [campaign, manifest, candidates, mission] = await Promise.all(requests);
    assert.equal(campaign, null);
    assert.equal(manifest, null);
    assert.equal(candidates, fallbackCandidates);
    assert.equal(mission, null);
    assert.deepEqual(receivedSignals, Array.from({ length: 4 }, () => controller.signal));
    assert.equal(controller.signal.aborted, true);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("studio strict live-refresh helpers reject required GET failures without fallbacks", async () => {
  const originalFetch = globalThis.fetch;
  const controller = new AbortController();
  const receivedSignals: Array<AbortSignal | null | undefined> = [];
  globalThis.fetch = async (_input, init) => {
    receivedSignals.push(init?.signal);
    return new Response(JSON.stringify({ detail: "projection unavailable" }), {
      headers: { "Content-Type": "application/json" },
      status: 503,
    });
  };

  try {
    const results = await Promise.allSettled([
      getCampaignControlCenterRequired("campaign_1", controller.signal),
      getStudioWorkspaceManifestRequired("C:/authorized/studio", controller.signal),
      getStudioWorkspaceMissionRequired("C:/authorized/studio", "run_1", controller.signal),
      listStudioWorkspaceCandidatesRequired(
        "C:/authorized/studio",
        "run_1",
        controller.signal,
      ),
    ]);

    assert.deepEqual(results.map((result) => result.status), [
      "rejected",
      "rejected",
      "rejected",
      "rejected",
    ]);
    assert.deepEqual(receivedSignals, Array.from({ length: 4 }, () => controller.signal));
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("runSourceAuditScan posts only the local source audit request", async () => {
  const originalFetch = globalThis.fetch;
  let requestedUrl = "";
  let requestedBody: unknown = null;

  globalThis.fetch = async (input, init) => {
    requestedUrl = String(input);
    requestedBody = JSON.parse(String(init?.body));
    return new Response(
      JSON.stringify({
        artifact_id: "artifact_source_1",
        hypothesis_count: 1,
        report_title: "Source audit: target",
        run_id: "pipeline_run_source_1",
        safety_notes: [
          "scope_guard_required",
          "local_files_only",
          "no_live_requests",
          "no_auto_submission",
        ],
        scope_status: "in_scope",
        submission_blocked: true,
      }),
      { headers: { "Content-Type": "application/json" }, status: 200 },
    );
  };

  try {
    const result = await runSourceAuditScan(
      {
        policy_text: "local source audit scope policy",
        repo_path: "C:/workspace/target",
        scope_path: "C:/workspace/scope.yaml",
      },
    );

    assert.match(requestedUrl, /\/mythos\/source-audit\/scans$/);
    assert.deepEqual(requestedBody, {
      policy_text: "local source audit scope policy",
      repo_path: "C:/workspace/target",
      scope_path: "C:/workspace/scope.yaml",
    });
    assert.equal(result?.run_id, "pipeline_run_source_1");
    assert.equal(result?.submission_blocked, true);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("runSourceAuditScan exposes 范围守卫 block reasons", async () => {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async () =>
    new Response(JSON.stringify({ detail: "repo_not_allowlisted" }), {
      headers: { "Content-Type": "application/json" },
      status: 403,
    });

  try {
    await assert.rejects(
      () =>
        runSourceAuditScan(
          {
            repo_path: "C:/workspace/target",
            scope_path: "C:/workspace/scope.yaml",
          },
        ),
      (error) => {
        assert.equal(error instanceof SourceAuditScanError, true);
        assert.equal((error as SourceAuditScanError).status, 403);
        assert.equal((error as SourceAuditScanError).detail, "repo_not_allowlisted");
        return true;
      },
    );
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("runSourceAuditScan rejects non-Scope-Guard API failures", async () => {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async () =>
    new Response(JSON.stringify({ detail: "source_audit_failed" }), {
      headers: { "Content-Type": "application/json" },
      status: 500,
    });

  try {
    await assert.rejects(
      () =>
        runSourceAuditScan(
          {
            repo_path: "C:/workspace/target",
            scope_path: "C:/workspace/scope.yaml",
          },
        ),
      (error) => {
        assert.equal(error instanceof ApiRequestError, true);
        assert.equal((error as ApiRequestError).status, 500);
        assert.equal((error as ApiRequestError).detail, "source_audit_failed");
        return true;
      },
    );
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("recordCandidateHunterLearningOutcome posts only a Brain learning signal", async () => {
  const originalFetch = globalThis.fetch;
  let requestedUrl = "";
  let requestedBody: unknown = null;

  globalThis.fetch = async (input, init) => {
    requestedUrl = String(input);
    requestedBody = JSON.parse(String(init?.body));
    return new Response(
      JSON.stringify({
        ...fallbackProgramProfile,
        recent_learning_signals: [
          {
            evidence_quality: "adequate",
            id: "learning_signal_1",
            notes:
              "Candidate hunter outcome (confirmed) by analyst: Triager accepted the ownership boundary finding.",
            outcome: "accepted",
            playbook_id: "candidate_hunter:H-001",
            program_id: "program_1",
            surface_key: "account_settings",
            triager_feedback: "Triager accepted the ownership boundary finding.",
          },
        ],
      }),
      { headers: { "Content-Type": "application/json" }, status: 200 },
    );
  };

  try {
    const profile = await recordCandidateHunterLearningOutcome(
      {
        candidate_id: "H-001",
        notes: "Triager accepted the ownership boundary finding.",
        outcome: "confirmed",
        program_id: "program_1",
        reviewer: "analyst",
        run_id: "run_1",
        surface_key: "account_settings",
      },
    );

    assert.match(requestedUrl, /\/mythos\/brain\/outcomes$/);
    assert.deepEqual(requestedBody, {
      evidence_quality: "adequate",
      notes:
        "候选挖掘结果（confirmed），审核人：analyst：Triager accepted the ownership boundary finding.",
      outcome: "accepted",
      playbook_id: "candidate_hunter:H-001",
      program_id: "program_1",
      run_id: "run_1",
      surface_key: "account_settings",
      triager_feedback: "Triager accepted the ownership boundary finding.",
    });
    assert.equal(profile.recent_learning_signals[0]?.outcome, "accepted");
    assert.doesNotMatch(
      JSON.stringify(requestedBody),
      /execution_allowed|validation_allowed|report_submission_allowed|executeValidation|submitReport|Authorization\s*[:=]|secret-token/i,
    );
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("recordCandidateHunterLearningOutcome preserves a reviewed hunter playbook id", async () => {
  const originalFetch = globalThis.fetch;
  let requestedBody: unknown = null;

  globalThis.fetch = async (_input, init) => {
    requestedBody = JSON.parse(String(init?.body));
    return new Response(JSON.stringify(fallbackProgramProfile), {
      headers: { "Content-Type": "application/json" },
      status: 200,
    });
  };

  try {
    await recordCandidateHunterLearningOutcome(
      {
        candidate_id: "H-001",
        notes: "Triager accepted the ownership boundary finding.",
        outcome: "confirmed",
        playbook_id: "bola_idor",
        program_id: "program_1",
        reviewer: "analyst",
        run_id: "run_1",
        surface_key: "account_settings",
        target_relationships: ["org_id>team_id>file_id"],
      },
    );

    assert.equal((requestedBody as { playbook_id?: string } | null)?.playbook_id, "bola_idor");
    assert.deepEqual(
      (requestedBody as { target_relationships?: string[] } | null)?.target_relationships,
      ["org_id>team_id>file_id"],
    );
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("recordCandidateHunterLearningOutcome carries candidate evidence context safely", async () => {
  const originalFetch = globalThis.fetch;
  let requestedBody: unknown = null;

  globalThis.fetch = async (_input, init) => {
    requestedBody = JSON.parse(String(init?.body));
    return new Response(JSON.stringify(fallbackProgramProfile), {
      headers: { "Content-Type": "application/json" },
      status: 200,
    });
  };

  try {
    await recordCandidateHunterLearningOutcome(
      {
        candidate_id: "H-001",
        evidence_ready: false,
        missing_evidence: ["independent_cross_check"],
        missing_required_artifact_kinds: ["policy"],
        notes: "Needs independent evidence before ranking boost.",
        outcome: "needs_more_evidence",
        program_id: "program_1",
        reviewer: "analyst",
        run_id: "run_1",
        surface_key: "account_settings",
        target_relationships: ["candidate:H-001"],
        trace_status: "needs_evidence",
      },
    );

    assert.deepEqual(
      (requestedBody as { target_relationships?: string[] } | null)
        ?.target_relationships,
      [
        "candidate:H-001",
        "evidence_ready:false",
        "trace_status:needs_evidence",
        "missing_evidence:independent_cross_check",
        "missing_required_artifact:policy",
      ],
    );
    assert.match(
      (requestedBody as { notes?: string } | null)?.notes ?? "",
      /证据就绪：否；轨迹：needs_evidence；缺少证据：independent_cross_check；缺少必需资料：policy/,
    );
    assert.equal(
      (requestedBody as { evidence_quality?: string } | null)?.evidence_quality,
      "weak",
    );
    assert.doesNotMatch(
      JSON.stringify(requestedBody),
      /execution_allowed|validation_allowed|report_submission_allowed|Authorization\s*[:=]|secret-token/i,
    );
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("recordCandidateHunterLearningOutcome carries learned evidence reasons safely", async () => {
  const originalFetch = globalThis.fetch;
  let requestedBody: unknown = null;

  globalThis.fetch = async (_input, init) => {
    requestedBody = JSON.parse(String(init?.body));
    return new Response(JSON.stringify(fallbackProgramProfile), {
      headers: { "Content-Type": "application/json" },
      status: 200,
    });
  };

  try {
    await recordCandidateHunterLearningOutcome(
      {
        candidate_id: "H-001",
        learning_evidence_needed_reasons: [
          "lesson:evidence_needed:candidate_gap",
          "lesson:evidence_needed:missing_evidence:independent_cross_check",
          "lesson:evidence_needed:missing_required_artifact:policy",
        ],
        notes: "Needs independent evidence before ranking boost.",
        outcome: "needs_more_evidence",
        program_id: "program_1",
        reviewer: "analyst",
        run_id: "run_1",
        surface_key: "account_settings",
      },
    );

    assert.deepEqual(
      (requestedBody as { target_relationships?: string[] } | null)
        ?.target_relationships,
      [
        "learned_evidence:lesson_evidence_needed_candidate_gap",
        "learned_evidence:lesson_evidence_needed_missing_evidence_independent_cross_check",
        "learned_evidence:lesson_evidence_needed_missing_required_artifact_policy",
      ],
    );
    assert.match(
      (requestedBody as { notes?: string } | null)?.notes ?? "",
      /学习证据：lesson_evidence_needed_candidate_gap, lesson_evidence_needed_missing_evidence_independent_cross_check, lesson_evidence_needed_missing_required_artifact_policy/,
    );
    assert.doesNotMatch(
      JSON.stringify(requestedBody),
      /execution_allowed|validation_allowed|report_submission_allowed|Authorization\s*[:=]|secret-token/i,
    );
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("studio workspace API helpers pass only local paths and manifest metadata", async () => {
  const originalFetch = globalThis.fetch;
  const calls: Array<{ body: unknown; url: string }> = [];

  globalThis.fetch = async (input, init) => {
    const url = String(input);
    const body = init?.body ? JSON.parse(String(init.body)) : null;
    calls.push({ body, url });

    if (url.endsWith("/mythos/studio/workspaces")) {
      return new Response(
        JSON.stringify({
          path: "C:/workspaces/acme-api",
          manifest: {
            artifacts: [],
            name: "acme-api",
            runs: [],
            safety: {
              blocked_actions: ["execute_live_validation", "submit_report"],
              scope_guard_status: "missing_scope",
            },
          },
        }),
        { headers: { "Content-Type": "application/json" }, status: 200 },
      );
    }

    if (url.includes("/mythos/studio/workspaces/manifest")) {
      return new Response(
        JSON.stringify({
          artifacts: [],
          name: "acme-api",
          runs: [],
          safety: { blocked_actions: [], scope_guard_status: "scope_imported" },
        }),
        { headers: { "Content-Type": "application/json" }, status: 200 },
      );
    }

    if (url.endsWith("/mythos/studio/workspaces/imports")) {
      return new Response(
        JSON.stringify({
          artifacts: [
            {
              kind: "scope",
              redaction_status: "not_required",
              source_path: "C:/authorized/scope.yaml",
            },
          ],
          name: "acme-api",
          runs: [],
          safety: { blocked_actions: [], scope_guard_status: "scope_imported" },
        }),
        { headers: { "Content-Type": "application/json" }, status: 200 },
      );
    }

    return new Response(JSON.stringify({ detail: "unexpected request" }), {
      headers: { "Content-Type": "application/json" },
      status: 500,
    });
  };

  try {
    const workspace = await createStudioWorkspace(
      { name: "acme-api", root_path: "C:/workspaces" },
    );
    assert.equal(workspace?.path, "C:/workspaces/acme-api");

    const manifest = await getStudioWorkspaceManifest("C:/workspaces/acme-api", null);
    assert.equal(manifest?.safety?.scope_guard_status, "scope_imported");

    const imported = await importStudioWorkspaceArtifact(
      {
        kind: "scope",
        source_path: "C:/authorized/scope.yaml",
        workspace_path: "C:/workspaces/acme-api",
      },
    );
    assert.equal(imported?.artifacts?.[0]?.kind, "scope");

    assert.deepEqual(calls.map((call) => new URL(call.url).pathname), [
      "/mythos/studio/workspaces",
      "/mythos/studio/workspaces/manifest",
      "/mythos/studio/workspaces/imports",
    ]);
    assert.deepEqual(calls[0]?.body, { name: "acme-api", root_path: "C:/workspaces" });
    assert.deepEqual(calls[2]?.body, {
      kind: "scope",
      source_path: "C:/authorized/scope.yaml",
      workspace_path: "C:/workspaces/acme-api",
    });
    assert.doesNotMatch(
      JSON.stringify(calls),
      /Authorization\s*[:=]|Bearer|secret-token|cookie|raw_policy/i,
    );
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("studio black-box lab helpers send only alias-only local review contracts", async () => {
  const originalFetch = globalThis.fetch;
  const calls: Array<{ body: unknown; url: string }> = [];
  const leasePreview = {
    active_origin: "http://127.0.0.1:43110",
    sessions: [
      {
        account_alias: "account_a",
        ready: true,
        role_alias: "member",
        session_alias: "session_a",
      },
      {
        account_alias: "account_b",
        ready: true,
        role_alias: "member",
        session_alias: "session_b",
      },
    ],
    workflows: [
      {
        action: "read_only_replay",
        method: "GET",
        object_aliases: ["widget_a"],
        origin: "http://127.0.0.1:43110",
        route_template: "/widgets/{object}",
        session_alias: "session_a",
        workflow_alias: "read_widget_a",
      },
    ],
  } as const;

  globalThis.fetch = async (input, init) => {
    const url = String(input);
    const body = init?.body ? JSON.parse(String(init.body)) : null;
    calls.push({ body, url });
    if (url.endsWith("/mythos/studio/black-box-lab/leases/preview")) {
      return new Response(
        JSON.stringify({
          active_origin: leasePreview.active_origin,
          blocked_actions: ["remote_origin", "credential_input"],
          execution_allowed: false,
          human_approval_required: true,
          persist_session_state: false,
          profile: "local_lab",
          session_aliases: ["session_a", "session_b"],
          sessions_ready: true,
          trace_review_required: true,
          workflow_aliases: ["read_widget_a"],
        }),
        { status: 200 },
      );
    }
    return new Response(
      JSON.stringify({
        approval_id: "approval_local_lab",
        approval_status: "approved",
        execution_allowed: false,
        lease_digest: `sha256:${"b".repeat(64)}`,
        local_runner_dispatch_allowed: true,
        reason: "bounded_local_lab_run_approved",
        report_submission_allowed: false,
        validation_run_id: "validation_local_lab",
      }),
      { status: 200 },
    );
  };

  try {
    const preview = await previewStudioBlackBoxLabLease(leasePreview);
    const approval = await approveStudioBlackBoxLabRun({
      lease_preview: leasePreview,
      operator_confirmed: true,
      trace_review: [
        {
          redacted: true,
          response_schema_fingerprint: `sha256:${"a".repeat(64)}`,
          route_template: "/widgets/{object}",
          session_alias: "session_a",
          workflow_alias: "read_widget_a",
        },
      ],
      validation_run_id: "validation_local_lab",
    });

    assert.equal(preview?.execution_allowed, false);
    assert.equal(preview?.persist_session_state, false);
    assert.equal(approval?.local_runner_dispatch_allowed, true);
    assert.equal(approval?.execution_allowed, false);
    assert.deepEqual(
      calls.map((call) => new URL(call.url).pathname),
      [
        "/mythos/studio/black-box-lab/leases/preview",
        "/mythos/studio/black-box-lab/runs/approve",
      ],
    );
    assert.deepEqual(calls[0]?.body, leasePreview);
    assert.deepEqual(calls[1]?.body, {
      lease_preview: leasePreview,
      operator_confirmed: true,
      trace_review: [
        {
          redacted: true,
          response_schema_fingerprint: `sha256:${"a".repeat(64)}`,
          route_template: "/widgets/{object}",
          session_alias: "session_a",
          workflow_alias: "read_widget_a",
        },
      ],
      validation_run_id: "validation_local_lab",
    });
    assert.doesNotMatch(
      JSON.stringify(calls),
      /cookie|credential|password|authorization|session_storage|workspace_manifest/i,
    );
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("validation preflight helper is strict and bound to the requested run", async () => {
  const originalFetch = globalThis.fetch;
  const calls: Array<{ body: unknown; url: string }> = [];
  globalThis.fetch = async (input, init) => {
    calls.push({
      body: init?.body ? JSON.parse(String(init.body)) : null,
      url: String(input),
    });
    return new Response(
      JSON.stringify({
        decision: { allowed: true, reason: "approved_validation_record" },
        execution_started: false,
        validation_run: {
          allowed_to_execute: true,
          id: "validation_local_lab",
          preflight_passed: true,
        },
      }),
      { status: 200 },
    );
  };
  try {
    const response = await preflightMythosValidationRun("validation_local_lab");
    assert.equal(response.decision.allowed, true);
    assert.equal(response.validation_run.id, "validation_local_lab");
    assert.deepEqual(calls, [
      {
        body: {},
        url: "http://localhost:8000/mythos/validation-runs/validation_local_lab/preflight",
      },
    ]);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("studio local-lab exact preflight sends the approval, lease, and original complete plan", async () => {
  const originalFetch = globalThis.fetch;
  let requestedBody: unknown = null;
  let requestedUrl = "";
  const completePlan: StudioBlackBoxLabCompletePlan = {
    lease_preview: {
      active_origin: "http://127.0.0.1:43110",
      sessions: [
        { account_alias: "account_a", ready: true, role_alias: "member", session_alias: "session_a" as const },
        { account_alias: "account_b", ready: true, role_alias: "member", session_alias: "session_b" as const },
      ],
      workflows: [{
        action: "read_only_replay" as const,
        method: "GET" as const,
        object_aliases: ["widget_a"],
        origin: "http://127.0.0.1:43110",
        route_template: "/widgets/{object}",
        session_alias: "session_a" as const,
        workflow_alias: "read_widget_a",
      }],
    },
    operator_confirmed: true,
    trace_review: [{
      redacted: true as const,
      response_schema_fingerprint: `sha256:${"a".repeat(64)}`,
      route_template: "/widgets/{object}",
      session_alias: "session_a",
      workflow_alias: "read_widget_a",
    }],
    validation_run_id: "validation_local_lab",
  };
  globalThis.fetch = async (input, init) => {
    requestedUrl = String(input);
    requestedBody = JSON.parse(String(init?.body));
    return new Response(JSON.stringify({
      approval_id: "approval_local_lab",
      approved_session_alias: "session_b",
      approved_workflow_alias: "read_widget_a",
      complete_plan_digest: `sha256:${"d".repeat(64)}`,
      execution_allowed: false,
      expires_at: "2099-07-19T12:15:00Z",
      lease_digest: `sha256:${"b".repeat(64)}`,
      local_runner_dispatch_allowed: true,
      plan_digest: "plan_sha256_local_lab",
      report_submission_allowed: false,
      scope_reference: `sha256:${"c".repeat(64)}`,
      validation_run_id: "validation_local_lab",
    }), { status: 200 });
  };

  try {
    const response = await preflightStudioBlackBoxLabRun({
      approval_id: "approval_local_lab",
      complete_plan: completePlan,
      complete_plan_digest: `sha256:${"d".repeat(64)}`,
      lease_digest: `sha256:${"b".repeat(64)}`,
    });

    assert.equal(response.local_runner_dispatch_allowed, true);
    assert.equal(
      new URL(requestedUrl).pathname,
      "/mythos/studio/black-box-lab/runs/preflight",
    );
    assert.deepEqual(requestedBody, {
      approval_id: "approval_local_lab",
      complete_plan: completePlan,
      complete_plan_digest: `sha256:${"d".repeat(64)}`,
      lease_digest: `sha256:${"b".repeat(64)}`,
    });
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("studio local-lab bounded result sends only the exact preflight and normalized trace", async () => {
  const originalFetch = globalThis.fetch;
  let requestedBody: unknown = null;
  let requestedUrl = "";
  const exactPreflight = {
    approval_id: "approval_local_lab",
    complete_plan: {
      lease_preview: {
        active_origin: "http://127.0.0.1:43110",
        sessions: [
          { account_alias: "account_a", ready: true, role_alias: "member", session_alias: "session_a" as const },
          { account_alias: "account_b", ready: true, role_alias: "member", session_alias: "session_b" as const },
        ],
        workflows: [{
          action: "read_only_replay" as const,
          method: "GET" as const,
          object_aliases: ["widget_a"],
          origin: "http://127.0.0.1:43110",
          route_template: "/widgets/{object}",
          session_alias: "session_a" as const,
          workflow_alias: "read_widget_a",
        }],
      },
      operator_confirmed: true as const,
      trace_review: [{
        redacted: true as const,
        response_schema_fingerprint: `sha256:${"a".repeat(64)}`,
        route_template: "/widgets/{object}",
        session_alias: "session_a" as const,
        workflow_alias: "read_widget_a",
      }],
      validation_run_id: "validation_local_lab",
    },
    complete_plan_digest: `sha256:${"d".repeat(64)}`,
    lease_digest: `sha256:${"b".repeat(64)}`,
  };
  const trace = {
    aliases: {
      account_alias: "account_b",
      object_aliases: ["widget_a"],
      role_alias: "member",
      session_alias: "session_b" as const,
      workflow_alias: "read_widget_a",
    },
    method: "GET" as const,
    parameters: [{ location: "path" as const, name: "object", value_type: "object_alias" as const }],
    response_schema_fingerprint: `sha256:${"b".repeat(64)}`,
    route_template: "/widgets/{object}",
    status_class: "2xx" as const,
    timing_bucket: "under_500ms" as const,
  } satisfies StudioBlackBoxLabBoundedTrace;
  globalThis.fetch = async (input, init) => {
    requestedUrl = String(input);
    requestedBody = JSON.parse(String(init?.body));
    return new Response(JSON.stringify({
      campaign_id: "campaign_local_lab",
      difference_labels: ["response_schema_changed"],
      evidence_ref_count: 1,
      execution_allowed: false,
      human_review_required: true,
      pipeline_run_id: "pipeline_local_lab",
      report_preview_refreshed: true,
      report_submission_allowed: false,
      result_digest: `sha256:${"e".repeat(64)}`,
      submission_blocked: true,
      validation_run_id: "validation_local_lab",
      validation_status: "needs_evidence",
    }), { status: 200 });
  };

  try {
    const response = await recordStudioBlackBoxLabBoundedResult({ exact_preflight: exactPreflight, trace });

    assert.equal(response.human_review_required, true);
    assert.equal(response.submission_blocked, true);
    assert.equal(
      new URL(requestedUrl).pathname,
      "/mythos/studio/black-box-lab/runs/bounded-result",
    );
    assert.deepEqual(requestedBody, { exact_preflight: exactPreflight, trace });
    assert.doesNotMatch(
      JSON.stringify(requestedBody),
      /authorization|cookie|password|secret|storage_state|raw_headers|raw_body|token/i,
    );
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("studio remote black-box status is read-only and keeps both human gates blocked", async () => {
  const originalFetch = globalThis.fetch;
  let requestedUrl = "";
  let requestedMethod = "";
  globalThis.fetch = async (input, init) => {
    requestedUrl = String(input);
    requestedMethod = init?.method ?? "GET";
    return new Response(
      JSON.stringify({
        profile: "remote_human_lease",
        enabled: true,
        state: "active",
        expires_at: "2026-07-15T12:30:00Z",
        relogin_required: false,
        stop_reason: null,
        report_submission_allowed: false,
        human_confirmation_allowed: false,
      }),
      { status: 200 },
    );
  };

  try {
    const status = await getStudioBlackBoxRemoteStatus();

    assert.equal(new URL(requestedUrl).pathname, "/mythos/studio/black-box-remote/status");
    assert.equal(requestedMethod, "GET");
    assert.equal(status.state, "active");
    assert.equal(status.report_submission_allowed, false);
    assert.equal(status.human_confirmation_allowed, false);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("studio mutation helpers reject API blocks instead of returning fallback state", async () => {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async () =>
    new Response(JSON.stringify({ detail: "artifact_outside_authorized_roots" }), {
      headers: { "Content-Type": "application/json" },
      status: 403,
    });

  try {
    await assert.rejects(
      () =>
        importStudioWorkspaceArtifact(
          {
            kind: "code",
            source_path: "C:/outside/repo",
            workspace_path: "C:/workspaces/acme-api",
          },
        ),
      (error) => {
        assert.equal(error instanceof ApiRequestError, true);
        assert.equal((error as ApiRequestError).status, 403);
        assert.equal((error as ApiRequestError).detail, "artifact_outside_authorized_roots");
        return true;
      },
    );
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("studio research API helpers keep reports submission-blocked", async () => {
  const originalFetch = globalThis.fetch;
  const calls: Array<{ body: unknown; url: string }> = [];

  globalThis.fetch = async (input, init) => {
    const url = String(input);
    const body = init?.body ? JSON.parse(String(init.body)) : null;
    calls.push({ body, url });

    if (url.endsWith("/mythos/studio/workspaces/runs")) {
      return new Response(
        JSON.stringify({
          candidate_count: 1,
          manifest: { runs: [{ run_id: "pipeline_run_1", report_path: null }] },
          report_title: "Source audit: target",
          run_id: "pipeline_run_1",
          safety_notes: ["no_live_requests", "no_auto_submission"],
          submission_blocked: true,
        }),
        { headers: { "Content-Type": "application/json" }, status: 200 },
      );
    }

    if (url.includes("/mythos/studio/workspaces/candidates")) {
      return new Response(
        JSON.stringify({
          candidates: [
            {
              evidence_needed: ["sanitized local evidence"],
              false_positive_checks: ["middleware may enforce ownership"],
              hypothesis_id: "H-001",
              location: "GET /files/{file_id}/export",
              risk: "high",
              safe_verification: true,
              report_readiness: {
                submission_blocked: true,
              },
              vuln_type: "authorization",
            },
          ],
          run_id: "pipeline_run_1",
        }),
        { headers: { "Content-Type": "application/json" }, status: 200 },
      );
    }

    if (url.endsWith("/mythos/studio/workspaces/reports/export")) {
      return new Response(
        JSON.stringify({
          manifest: {
            runs: [
              {
                report_path: "C:/workspaces/acme-api/reports/pipeline_run_1-report-preview.json",
                run_id: "pipeline_run_1",
              },
            ],
          },
          report: { submission_blocked: true, title: "Source audit: target" },
          report_markdown_path:
            "C:/workspaces/acme-api/reports/pipeline_run_1-report-draft.md",
          report_submission_allowed: false,
          run_id: "pipeline_run_1",
          submission_blocked: true,
          title: "Source audit: target",
        }),
        { headers: { "Content-Type": "application/json" }, status: 200 },
      );
    }

    if (url.endsWith("/mythos/studio/workspaces/campaigns/reports/export")) {
      return new Response(
        JSON.stringify({
          campaign_id: "campaign_1",
          manifest: {
            campaign_hunter_runs: [
              {
                campaign_id: "campaign_1",
                report_markdown_path:
                  "C:/workspaces/acme-api/reports/campaign_1-campaign-hunter-report-draft.md",
                report_submission_allowed: false,
              },
            ],
          },
          report: { submission_blocked: true, title: "Campaign hunter draft" },
          report_markdown_path:
            "C:/workspaces/acme-api/reports/campaign_1-campaign-hunter-report-draft.md",
          report_submission_allowed: false,
          run_id: "campaign_1",
          submission_blocked: true,
          title: "Campaign hunter draft",
        }),
        { headers: { "Content-Type": "application/json" }, status: 200 },
      );
    }

    if (url.endsWith("/mythos/studio/workspaces/mission/export")) {
      return new Response(
        JSON.stringify({
          manifest: {
            mission_dossiers: [
              {
                agent_queue_markdown_path:
                  "C:/workspaces/acme-api/reports/pipeline_run_1-agent-queue.md",
                agent_queue_path:
                  "C:/workspaces/acme-api/reports/pipeline_run_1-agent-queue.json",
                dossier_markdown_path:
                  "C:/workspaces/acme-api/reports/pipeline_run_1-mission-dossier.md",
                dossier_path:
                  "C:/workspaces/acme-api/reports/pipeline_run_1-mission-dossier.json",
                report_submission_allowed: false,
                run_id: "pipeline_run_1",
                validation_execution_allowed: false,
              },
            ],
          },
          agent_queue_markdown_path:
            "C:/workspaces/acme-api/reports/pipeline_run_1-agent-queue.md",
          agent_queue_path:
            "C:/workspaces/acme-api/reports/pipeline_run_1-agent-queue.json",
          mission: {
            agent_queue: [],
            mode: "local_ai_vulnerability_research_workbench",
            research_loop: [],
          },
          mission_dossier_markdown_path:
            "C:/workspaces/acme-api/reports/pipeline_run_1-mission-dossier.md",
          mission_dossier_path:
            "C:/workspaces/acme-api/reports/pipeline_run_1-mission-dossier.json",
          report_submission_allowed: false,
          run_id: "pipeline_run_1",
          validation_execution_allowed: false,
        }),
        { headers: { "Content-Type": "application/json" }, status: 200 },
      );
    }

    if (url.endsWith("/mythos/studio/workspaces/benchmarks/run")) {
      return new Response(
        JSON.stringify({
          benchmark: {
            candidate_count: 1,
            expected_count: 1,
            failures: [],
            matched: 1,
            safety: { forbidden_text_present: [] },
            status: "passed",
          },
          benchmark_path:
            "C:/workspaces/acme-api/benchmarks/pipeline_run_1-benchmark-result.json",
          manifest: {
            benchmarks: [
              {
                benchmark_path:
                  "C:/workspaces/acme-api/benchmarks/pipeline_run_1-benchmark-result.json",
                run_id: "pipeline_run_1",
                status: "passed",
              },
            ],
            runs: [{ benchmark_status: "passed", run_id: "pipeline_run_1" }],
          },
          run_id: "pipeline_run_1",
        }),
        { headers: { "Content-Type": "application/json" }, status: 200 },
      );
    }

    if (url.endsWith("/mythos/studio/workspaces/benchmarks/template")) {
      return new Response(
        JSON.stringify({
          manifest: {
            benchmark_templates: [
              {
                draft_review_required: true,
                run_id: "pipeline_run_1",
                template_path:
                  "C:/workspaces/acme-api/benchmarks/pipeline_run_1-expectations-template.json",
              },
            ],
            runs: [
              {
                benchmark_template_path:
                  "C:/workspaces/acme-api/benchmarks/pipeline_run_1-expectations-template.json",
                run_id: "pipeline_run_1",
              },
            ],
          },
          run_id: "pipeline_run_1",
          template: {
            draft_review_required: true,
            expected_candidates: [],
            max_candidates: 5,
          },
          template_path:
            "C:/workspaces/acme-api/benchmarks/pipeline_run_1-expectations-template.json",
        }),
        { headers: { "Content-Type": "application/json" }, status: 200 },
      );
    }

    return new Response(JSON.stringify({ detail: "unexpected request" }), {
      headers: { "Content-Type": "application/json" },
      status: 500,
    });
  };

  try {
    const run = await runStudioWorkspaceResearch(
      { workspace_path: "C:/workspaces/acme-api" },
    );
    assert.equal(run?.submission_blocked, true);

    const candidates = await listStudioWorkspaceCandidates(
      "C:/workspaces/acme-api",
      "pipeline_run_1",
      { candidates: [], run_id: null },
    );
    assert.equal(candidates.candidates[0]?.report_readiness?.submission_blocked, true);

    const exported = await exportStudioWorkspaceReport(
      { run_id: "pipeline_run_1", workspace_path: "C:/workspaces/acme-api" },
    );
    assert.equal(exported?.report_submission_allowed, false);
    assert.equal(
      exported?.report_markdown_path,
      "C:/workspaces/acme-api/reports/pipeline_run_1-report-draft.md",
    );
    assert.equal(exported?.submission_blocked, true);

    const hunterExport = await exportStudioWorkspaceCampaignHunterReport(
      { campaign_id: "campaign_1", workspace_path: "C:/workspaces/acme-api" },
    );
    assert.equal(hunterExport?.report_submission_allowed, false);
    assert.equal(hunterExport?.submission_blocked, true);
    assert.equal(
      hunterExport?.report_markdown_path,
      "C:/workspaces/acme-api/reports/campaign_1-campaign-hunter-report-draft.md",
    );

    const dossier = await exportStudioWorkspaceMissionDossier(
      { run_id: "pipeline_run_1", workspace_path: "C:/workspaces/acme-api" },
    );
    assert.equal(dossier?.report_submission_allowed, false);
    assert.equal(dossier?.validation_execution_allowed, false);
    assert.equal(
      dossier?.mission_dossier_markdown_path,
      "C:/workspaces/acme-api/reports/pipeline_run_1-mission-dossier.md",
    );
    assert.equal(
      dossier?.agent_queue_markdown_path,
      "C:/workspaces/acme-api/reports/pipeline_run_1-agent-queue.md",
    );

    const template = await createStudioWorkspaceBenchmarkTemplate(
      {
        run_id: "pipeline_run_1",
        workspace_path: "C:/workspaces/acme-api",
      },
    );
    assert.equal(
      template?.template_path,
      "C:/workspaces/acme-api/benchmarks/pipeline_run_1-expectations-template.json",
    );

    const benchmark = await runStudioWorkspaceBenchmark(
      {
        expectations_path: "C:/authorized/studio-expectations.json",
        run_id: "pipeline_run_1",
        workspace_path: "C:/workspaces/acme-api",
      },
    );
    assert.equal(benchmark?.benchmark.status, "passed");
    assert.equal(
      benchmark?.benchmark_path,
      "C:/workspaces/acme-api/benchmarks/pipeline_run_1-benchmark-result.json",
    );

    assert.deepEqual(calls.map((call) => new URL(call.url).pathname), [
      "/mythos/studio/workspaces/runs",
      "/mythos/studio/workspaces/candidates",
      "/mythos/studio/workspaces/reports/export",
      "/mythos/studio/workspaces/campaigns/reports/export",
      "/mythos/studio/workspaces/mission/export",
      "/mythos/studio/workspaces/benchmarks/template",
      "/mythos/studio/workspaces/benchmarks/run",
    ]);
    assert.deepEqual(calls[0]?.body, {
      workspace_path: "C:/workspaces/acme-api",
    });
    assert.deepEqual(calls[3]?.body, {
      campaign_id: "campaign_1",
      workspace_path: "C:/workspaces/acme-api",
    });
    assert.deepEqual(calls[4]?.body, {
      run_id: "pipeline_run_1",
      workspace_path: "C:/workspaces/acme-api",
    });
    assert.deepEqual(calls[5]?.body, {
      run_id: "pipeline_run_1",
      workspace_path: "C:/workspaces/acme-api",
    });
    assert.deepEqual(calls[6]?.body, {
      expectations_path: "C:/authorized/studio-expectations.json",
      run_id: "pipeline_run_1",
      workspace_path: "C:/workspaces/acme-api",
    });
    assert.doesNotMatch(
      JSON.stringify(calls),
      /Authorization\s*[:=]|Bearer|secret-token|cookie|send_file\(file_id\)|submitReport/i,
    );
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("studio research API helper sends only the explicit candidate model opt-in", async () => {
  const originalFetch = globalThis.fetch;
  let requestBody: unknown = null;
  globalThis.fetch = async (_input, init) => {
    requestBody = init?.body ? JSON.parse(String(init.body)) : null;
    return new Response(
      JSON.stringify({
        candidate_count: 1,
        candidate_generation: {
          accepted_count: 1,
          baseline_count: 1,
          candidate_promotion_allowed: false,
          dispatch_allowed: false,
          execution_allowed: false,
          model: "gpt-4.1-mini",
          model_failure_reason: null,
          model_latency_ms: 3,
          model_reasoner: "replay",
          model_replay_binding: "bound",
          model_request_key: "a".repeat(64),
          model_response_digest: "b".repeat(64),
          model_response_schema: "cross_source_candidate_model_v1",
          model_requested: true,
          model_status: "completed",
          prompt_hash: "prompt-hash",
          proposed_count: 1,
          provider: "openai",
          rejected_count: 0,
          report_submission_allowed: false,
          raw_payload_processed: false,
          validation_allowed: false,
          working_candidate_count: 1,
        },
        manifest: { runs: [{ run_id: "pipeline_run_1", report_path: null }] },
        report_title: "Source audit: target",
        run_id: "pipeline_run_1",
        safety_notes: [],
        submission_blocked: true,
      }),
      { headers: { "Content-Type": "application/json" }, status: 200 },
    );
  };

  try {
    const run = await runStudioWorkspaceResearch({
      candidate_model: {
        enabled: true,
        model: "gpt-4.1-mini",
        provider: "openai",
      },
      workspace_path: "C:/workspaces/acme-api",
    });

    assert.equal(run?.candidate_generation.model_status, "completed");
    assert.equal(run?.candidate_generation.model_replay_binding, "bound");
    assert.deepEqual(requestBody, {
      candidate_model: {
        enabled: true,
        model: "gpt-4.1-mini",
        provider: "openai",
      },
      workspace_path: "C:/workspaces/acme-api",
    });
    assert.doesNotMatch(
      JSON.stringify(requestBody),
      /api.?key|secret|token|cookie|authorization/i,
    );
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("studio mission API helper reads the local workbench state without unsafe calls", async () => {
  const originalFetch = globalThis.fetch;
  const calls: Array<{ body: unknown; url: string }> = [];

  globalThis.fetch = async (input, init) => {
    const url = String(input);
    const body = init?.body ? JSON.parse(String(init.body)) : null;
    calls.push({ body, url });

    if (url.includes("/mythos/studio/workspaces/mission")) {
      return new Response(
        JSON.stringify({
          artifacts: {
            missing: [],
            present: ["scope", "policy", "code", "api", "har"],
            required: ["scope", "policy", "code", "api", "har"],
          },
          blocked_actions: [
            "execute_live_validation",
            "touch_real_user_data",
            "submit_report",
          ],
          candidate_count: 1,
          mode: "local_ai_vulnerability_research_workbench",
          next_actions: [
            "review_top_candidates",
            "create_benchmark_template",
            "export_submission_blocked_report",
          ],
          quality_gates: {
            human_review_required: true,
            report_submission_allowed: false,
            submission_blocked: true,
            top_candidate_quality_gate: true,
            top_candidates_limited: true,
            validation_execution_allowed: false,
          },
          quality_summary: {
            average_quality_score: 95,
            blockers: [],
            candidate_count: 1,
            improvement_actions: [],
            review_ready_count: 1,
            review_ready_threshold: 85,
            status: "review_ready",
            top_candidate_quality_gate: "passed",
          },
          run_id: "pipeline_run_1",
          scope_guard_status: "scope_imported",
          top_candidates: [
            {
              affected_code_path: "routes.py:export_file",
              affected_endpoint: "GET /files/{file_id}/export",
              execution_allowed: false,
              hypothesis_id: "H-001",
              priority_score: 80,
              provenance_artifacts: ["scope", "policy", "code", "api", "har"],
              report_status: "submission_blocked",
              risk: "high",
              validation_status: "needs_human_approval",
              vuln_type: "authorization_gap",
            },
          ],
        }),
        { headers: { "Content-Type": "application/json" }, status: 200 },
      );
    }

    return new Response(JSON.stringify({ detail: "unexpected request" }), {
      headers: { "Content-Type": "application/json" },
      status: 500,
    });
  };

  try {
    const mission = await getStudioWorkspaceMission(
      "C:/workspaces/acme-api",
      "pipeline_run_1",
      null,
    );

    assert.ok(mission);
    assert.ok(mission.quality_gates);
    assert.ok(mission.top_candidates);
    assert.equal(mission.mode, "local_ai_vulnerability_research_workbench");
    assert.equal(mission.quality_gates.report_submission_allowed, false);
    assert.equal(mission.quality_gates.validation_execution_allowed, false);
    assert.equal(mission.quality_gates.top_candidate_quality_gate, true);
    assert.equal(mission.quality_summary?.top_candidate_quality_gate, "passed");
    assert.equal(mission.top_candidates[0]?.execution_allowed, false);
    assert.deepEqual(calls.map((call) => new URL(call.url).pathname), [
      "/mythos/studio/workspaces/mission",
    ]);
    assert.equal(new URL(calls[0]?.url ?? "").searchParams.get("workspace_path"), "C:/workspaces/acme-api");
    assert.equal(new URL(calls[0]?.url ?? "").searchParams.get("run_id"), "pipeline_run_1");
    assert.deepEqual(calls[0]?.body, null);
    assert.doesNotMatch(
      JSON.stringify(calls),
      /executeValidation|approveValidation|submitReport|Authorization\s*[:=]|secret-token|send_file/i,
    );
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("studio mission handoff helper reads the review-only handoff pack", async () => {
  const originalFetch = globalThis.fetch;
  const calls: Array<{ body: unknown; url: string }> = [];

  globalThis.fetch = async (input, init) => {
    const url = String(input);
    const body = init?.body ? JSON.parse(String(init.body)) : null;
    calls.push({ body, url });

    if (url.includes("/mythos/studio/workspaces/mission/handoff")) {
      return new Response(
        JSON.stringify({
          agent_handoff_pack: {
            execution_allowed: true,
            handoff_item_count: 1,
            handoff_items: [
              {
                assigned_agent: "证据计划ner",
                execution_allowed: true,
                handoff_id: "handoff:H-002:draft_validation_plan",
                report_submission_allowed: true,
                validation_allowed: true,
                work_item_id: "H-002:draft_validation_plan",
              },
            ],
            pack_id: "studio:agent_handoff:next_review",
            report_submission_allowed: true,
            status: "needs_review",
            validation_allowed: true,
          },
          candidate_hunter_plan: {
            execution_allowed: false,
            next_review_agent: "证据计划ner",
            plan_id: "candidate_hunter:autonomous_review_plan",
            plan_steps: [
              {
                assigned_agent: "证据计划ner",
                execution_allowed: false,
                report_submission_allowed: false,
                step_id: "candidate_hunter:plan:H-002:draft_validation_plan",
                validation_allowed: false,
                work_item_id: "H-002:draft_validation_plan",
              },
            ],
            report_submission_allowed: false,
            safety_gate: "review_only_no_execution",
            status: "needs_review",
            step_count: 1,
            validation_allowed: false,
          },
          candidate_hunter_review_loop: {
            active_step_count: 1,
            execution_allowed: true,
            loop_id: "candidate_hunter:next_review_loop",
            next_review_agent: "证据计划ner",
            report_submission_allowed: true,
            safety_gate: "unsafe_override",
            status: "needs_review",
            validation_allowed: true,
          },
          artifacts: {
            missing: [],
            present: ["scope", "policy", "code", "api", "har"],
            required: ["scope", "policy", "code", "api", "har"],
          },
          candidate_count: 1,
          completion_gate: "human_review_required",
          execution_allowed: false,
          quality_summary: {
            status: "needs_review",
            top_candidate_quality_gate: "needs_review",
          },
          report_submission_allowed: false,
          run_id: "pipeline_run_1",
          safety_gate: "review_only_no_execution",
          scope_guard_status: "scope_imported",
          validation_allowed: false,
        }),
        { headers: { "Content-Type": "application/json" }, status: 200 },
      );
    }

    return new Response(JSON.stringify({ detail: "unexpected request" }), {
      headers: { "Content-Type": "application/json" },
      status: 500,
    });
  };

  try {
    const handoff = await getStudioWorkspaceMissionHandoff(
      "C:/workspaces/acme-api",
      "pipeline_run_1",
      null,
    );

    assert.equal(handoff?.run_id, "pipeline_run_1");
    assert.equal(handoff?.scope_guard_status, "scope_imported");
    assert.equal(handoff?.safety_gate, "review_only_no_execution");
    assert.equal(handoff?.completion_gate, "human_review_required");
    assert.equal(handoff?.execution_allowed, false);
    assert.equal(handoff?.validation_allowed, false);
    assert.equal(handoff?.report_submission_allowed, false);
    assert.equal(handoff?.agent_handoff_pack.pack_id, "studio:agent_handoff:next_review");
    assert.equal(handoff?.agent_handoff_pack.handoff_item_count, 1);
    assert.equal(
      handoff?.candidate_hunter_plan.plan_id,
      "candidate_hunter:autonomous_review_plan",
    );
    assert.equal(handoff?.candidate_hunter_plan.safety_gate, "review_only_no_execution");
    assert.equal(handoff?.candidate_hunter_plan.execution_allowed, false);
    assert.equal(handoff?.candidate_hunter_plan.validation_allowed, false);
    assert.equal(handoff?.candidate_hunter_plan.report_submission_allowed, false);
    assert.equal(
      handoff?.candidate_hunter_review_loop.loop_id,
      "candidate_hunter:next_review_loop",
    );
    assert.equal(handoff?.candidate_hunter_review_loop.execution_allowed, true);
    assert.deepEqual(calls.map((call) => new URL(call.url).pathname), [
      "/mythos/studio/workspaces/mission/handoff",
    ]);
    assert.equal(
      new URL(calls[0]?.url ?? "").searchParams.get("workspace_path"),
      "C:/workspaces/acme-api",
    );
    assert.equal(
      new URL(calls[0]?.url ?? "").searchParams.get("run_id"),
      "pipeline_run_1",
    );
    assert.deepEqual(calls[0]?.body, null);
    assert.doesNotMatch(
      JSON.stringify(calls),
      /executeValidation|approveValidation|submitReport|Authorization\s*[:=]|secret-token|send_file/i,
    );
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("source audit gated workflow smoke posts only manual review-gated calls", async () => {
  const originalFetch = globalThis.fetch;
  const calls: Array<{ body: unknown; url: string }> = [];
  let promotionAttempts = 0;

  globalThis.fetch = async (input, init) => {
    const url = String(input);
    const body = init?.body ? JSON.parse(String(init.body)) : null;
    calls.push({ body, url });

    if (url.endsWith("/mythos/source-audit/scans")) {
      return new Response(
        JSON.stringify({
          artifact_id: "artifact_source_1",
          hypothesis_count: 1,
          report_title: "Source audit: target",
          run_id: "pipeline_run_source_1",
          safety_notes: [
            "scope_guard_required",
            "local_files_only",
            "no_live_requests",
            "no_auto_submission",
          ],
          scope_status: "in_scope",
          submission_blocked: true,
        }),
        { headers: { "Content-Type": "application/json" }, status: 200 },
      );
    }

    if (url.endsWith("/mythos/pipeline/runs/pipeline_run_source_1/finding-candidates")) {
      promotionAttempts += 1;
      if (promotionAttempts === 1) {
        return new Response(
          JSON.stringify({ detail: "No claim is ready for candidate promotion" }),
          { headers: { "Content-Type": "application/json" }, status: 422 },
        );
      }

      return new Response(
        JSON.stringify({
          ...fallbackFinding,
          evidence_refs: ["request_response_diff"],
          id: "finding_candidate_source_1",
          submission_recommendation: "promote_to_finding_candidate",
          validation_status: "validation_plan_ready",
        }),
        { headers: { "Content-Type": "application/json" }, status: 200 },
      );
    }

    if (url.endsWith("/mythos/pipeline/runs/pipeline_run_source_1/manual-observations")) {
      return new Response(
        JSON.stringify({
          claim_id: "claim_observed_1",
          created_at: "2026-07-07T00:00:00Z",
          evidence_refs: ["request_response_diff"],
          execution_allowed: false,
          observation: "Reviewer attached a sanitized local fixture diff.",
          observation_id: "manual_observation_1",
          observation_type: "request_response_diff",
          observer: "lead_reviewer",
          redaction_status: "redacted",
          report_chain_blocked: true,
          safety_notes: [
            "test_accounts_only",
            "no_real_user_data",
            "human_review_required",
          ],
        }),
        { headers: { "Content-Type": "application/json" }, status: 200 },
      );
    }

    if (url.endsWith("/mythos/pipeline/runs/pipeline_run_source_1/claim-review-decisions")) {
      return new Response(
        JSON.stringify({
          claim_id: "claim_observed_1",
          decision: "confirmed_observed_fact",
          evidence_refs: ["request_response_diff"],
          rationale: "Confirmed from sanitized local fixture only.",
          reviewed_at: "2026-07-07T00:00:00Z",
          reviewer: "lead_reviewer",
        }),
        { headers: { "Content-Type": "application/json" }, status: 200 },
      );
    }

    return new Response(JSON.stringify({ detail: "unexpected request" }), {
      headers: { "Content-Type": "application/json" },
      status: 500,
    });
  };

  try {
    const scan = await runSourceAuditScan(
      {
        policy_text: "local source audit scope policy",
        repo_path: "C:/workspace/target",
        scope_path: "C:/workspace/scope.yaml",
      },
    );
    assert.equal(scan?.run_id, "pipeline_run_source_1");
    assert.equal(scan?.submission_blocked, true);

    await assert.rejects(
      () => createFindingCandidate("pipeline_run_source_1"),
      (error) => {
        assert.equal(error instanceof ApiRequestError, true);
        assert.equal((error as ApiRequestError).status, 422);
        assert.equal((error as ApiRequestError).detail, "No claim is ready for candidate promotion");
        return true;
      },
    );

    const observation = await recordManualObservation(
      "pipeline_run_source_1",
      {
        claim_id: "claim_observed_1",
        evidence_refs: ["request_response_diff"],
        observation: "Reviewer attached a sanitized local fixture diff.",
        observation_type: "request_response_diff",
        observer: "lead_reviewer",
        safety_notes: [
          "test_accounts_only",
          "no_real_user_data",
          "human_review_required",
        ],
      },
    );
    assert.equal(observation.observation_type, "request_response_diff");
    assert.equal(observation.execution_allowed, false);
    assert.equal(observation.report_chain_blocked, true);

    const review = await recordClaimReviewDecision(
      "pipeline_run_source_1",
      {
        claim_id: "claim_observed_1",
        decision: "confirmed_observed_fact",
        evidence_refs: ["request_response_diff"],
        rationale: "Confirmed from sanitized local fixture only.",
        reviewer: "lead_reviewer",
      },
    );
    assert.equal(review.decision, "confirmed_observed_fact");
    assert.deepEqual(review.evidence_refs, ["request_response_diff"]);

    const candidate = await createFindingCandidate("pipeline_run_source_1");
    assert.equal(candidate?.id, "finding_candidate_source_1");
    assert.equal(candidate?.validation_status, "validation_plan_ready");
    assert.equal(candidate?.submission_recommendation, "promote_to_finding_candidate");
    assert.deepEqual(candidate?.evidence_refs, ["request_response_diff"]);

    assert.deepEqual(
      calls.map((call) => new URL(call.url).pathname),
      [
        "/mythos/source-audit/scans",
        "/mythos/pipeline/runs/pipeline_run_source_1/finding-candidates",
        "/mythos/pipeline/runs/pipeline_run_source_1/manual-observations",
        "/mythos/pipeline/runs/pipeline_run_source_1/claim-review-decisions",
        "/mythos/pipeline/runs/pipeline_run_source_1/finding-candidates",
      ],
    );
    assert.doesNotMatch(
      JSON.stringify(calls),
      /executeValidation|approveValidation|submitReport|Authorization\s*[:=]|secret-token/i,
    );
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("createFindingCandidate exposes research feedback gate failures", async () => {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async () =>
    new Response(
      JSON.stringify({
        detail: {
          blocked_stage_count: 1,
          finding_promotion_allowed: false,
          provenance_ref_count: 6,
          reason: "blocked_by_research_feedback_gate",
          report_submission_allowed: false,
        },
      }),
      { headers: { "Content-Type": "application/json" }, status: 409 },
    );

  try {
    await assert.rejects(
      () => createFindingCandidate("run_1"),
      (error) => {
        assert.equal(error instanceof ApiRequestError, true);
        assert.equal((error as ApiRequestError).status, 409);
        assert.deepEqual((error as ApiRequestError).detail, {
          blocked_stage_count: 1,
          finding_promotion_allowed: false,
          provenance_ref_count: 6,
          reason: "blocked_by_research_feedback_gate",
          report_submission_allowed: false,
        });
        return true;
      },
    );
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("createFindingCandidate rejects network failures instead of returning fallback state", async () => {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async () => {
    throw new Error("offline");
  };

  try {
    await assert.rejects(
      () => createFindingCandidate("run_1"),
      (error) => {
        assert.equal(error instanceof ApiRequestError, true);
        assert.equal((error as ApiRequestError).status, 0);
        assert.equal((error as ApiRequestError).detail, "network_error");
        return true;
      },
    );
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("reviewValidationFeedbackForFindingPromotion posts only the manual promotion review gate", async () => {
  const originalFetch = globalThis.fetch;
  const fallbackStage: CampaignPipelineStage = {
    campaign_id: "campaign_1",
    created_at: "2026-07-05T00:00:00Z",
    id: "fallback_stage",
    input_refs: [],
    output_refs: [],
    payload: {},
    pipeline_run_id: null,
    safety_gate_state: "manual_review_required",
    stage_key: "research_task_validation_feedback_review",
    stage_order: 1,
    status: "fallback",
    stop_reason: null,
    task_id: null,
  };
  let requestedUrl = "";
  let requestedBody: unknown = null;

  globalThis.fetch = async (input, init) => {
    requestedUrl = String(input);
    requestedBody = JSON.parse(String(init?.body));
    return new Response(
      JSON.stringify({
        ...fallbackStage,
        id: "stage_review_1",
        payload: {
          decision: "allow_finding_promotion",
          execution_allowed: false,
          finding_confirmation_allowed: true,
          report_submission_allowed: false,
          validation_allowed: false,
        },
        status: "completed",
      }),
      { headers: { "Content-Type": "application/json" }, status: 200 },
    );
  };

  try {
    const stage = await reviewValidationFeedbackForFindingPromotion(
      "campaign_1",
      "stage_feedback_1",
      {
        decision: "allow_finding_promotion",
        rationale: "Safe evidence reviewed. Authorization: Bearer secret-token",
        reviewer: "lead_reviewer",
      },
    );

    assert.match(
      requestedUrl,
      /\/mythos\/campaigns\/campaign_1\/pipeline-stages\/stage_feedback_1\/validation-feedback-review$/,
    );
    assert.deepEqual(requestedBody, {
      decision: "allow_finding_promotion",
      rationale: "Safe evidence reviewed. Authorization: Bearer secret-token",
      reviewer: "lead_reviewer",
    });
    assert.deepEqual(stage.payload, {
      decision: "allow_finding_promotion",
      execution_allowed: false,
      finding_confirmation_allowed: true,
      report_submission_allowed: false,
      validation_allowed: false,
    });
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("completeCampaignCycleReview posts only the manual cycle review gate", async () => {
  const originalFetch = globalThis.fetch;
  const fallbackStage: CampaignPipelineStage = {
    campaign_id: "campaign_1",
    created_at: "2026-07-05T00:00:00Z",
    id: "fallback_cycle_stage",
    input_refs: [],
    output_refs: [],
    payload: {},
    pipeline_run_id: null,
    safety_gate_state: "manual_review_required",
    stage_key: "campaign_cycle_review",
    stage_order: 1,
    status: "fallback",
    stop_reason: "campaign_cycle_review_required",
    task_id: null,
  };
  let requestedUrl = "";
  let requestedBody: unknown = null;

  globalThis.fetch = async (input, init) => {
    requestedUrl = String(input);
    requestedBody = JSON.parse(String(init?.body));
    return new Response(
      JSON.stringify({
        ...fallbackStage,
        id: "stage_cycle_completed",
        payload: {
          execution_allowed: false,
          raw_payload_processed: false,
          review_gate: "human_review_completed",
          submission_allowed: false,
        },
        safety_gate_state: "allowed",
        status: "completed",
        stop_reason: null,
      }),
      { headers: { "Content-Type": "application/json" }, status: 200 },
    );
  };

  try {
    const stage = await completeCampaignCycleReview(
      "campaign_1",
      "stage_cycle_1",
      {
        actor: "lead_reviewer",
        reason: "周期审核ed. Authorization: Bearer secret-token",
      },
    );

    assert.match(
      requestedUrl,
      /\/mythos\/campaigns\/campaign_1\/cycle-reviews\/stage_cycle_1\/complete$/,
    );
    assert.deepEqual(requestedBody, {
      actor: "lead_reviewer",
      reason: "周期审核ed. Authorization: Bearer secret-token",
    });
    assert.deepEqual(stage.payload, {
      execution_allowed: false,
      raw_payload_processed: false,
      review_gate: "human_review_completed",
      submission_allowed: false,
    });
    assert.equal(stage.safety_gate_state, "allowed");
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("materializeResearchQueueTask posts only a review queue materialization request", async () => {
  const originalFetch = globalThis.fetch;
  const fallbackTask: CampaignTask = {
    agent_type: "human_research_reviewer",
    campaign_id: "campaign_1",
    created_at: "2026-07-05T00:00:00Z",
    id: "fallback_task",
    input_refs: [],
    output_refs: [],
    status: "fallback",
    task_type: "research_queue_review",
    title: "Fallback review item",
  };
  let requestedUrl = "";
  let requestedBody: unknown = null;

  globalThis.fetch = async (input, init) => {
    requestedUrl = String(input);
    requestedBody = JSON.parse(String(init?.body));
    return new Response(
      JSON.stringify({
        ...fallbackTask,
        id: "task_review_1",
        input_refs: [
          "campaign:campaign_1",
          "research_queue:autonomous_hunt:run_1:hunt_queue_candidate_1",
        ],
        status: "queued_review",
      }),
      { headers: { "Content-Type": "application/json" }, status: 200 },
    );
  };

  try {
    const task = await materializeResearchQueueTask(
      "campaign_1",
      {
        queue_key: "autonomous_hunt:run_1:hunt_queue_candidate_1",
        reason: "从控制中心加入审核项。",
        requester: "operator",
      },
    );

    assert.match(
      requestedUrl,
      /\/mythos\/campaigns\/campaign_1\/research-queue\/tasks$/,
    );
    assert.deepEqual(requestedBody, {
      queue_key: "autonomous_hunt:run_1:hunt_queue_candidate_1",
      reason: "从控制中心加入审核项。",
      requester: "operator",
    });
    assert.equal(task.status, "queued_review");
    assert.equal(task.task_type, "research_queue_review");
    assert.doesNotMatch(JSON.stringify(requestedBody), /execute|approve|submit|Authorization:|secret-token/i);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("createResearchReviewPlan posts only advisory refutation and evidence planning", async () => {
  const originalFetch = globalThis.fetch;
  const fallbackPlan: CampaignResearchReviewPlan = {
    campaign_id: "campaign_1",
    dispatch_allowed: false,
    evidence_plan: [],
    execution_allowed: false,
    hypothesis: "Fallback hypothesis",
    next_allowed_action: "审核假设看板 and request approval before validation.",
    plan_id: "fallback_plan",
    refutation_questions: [],
    report_submission_allowed: false,
    required_human_gates: [],
    safety_gate: "advisory_plan_only",
    status: "fallback",
    task_id: "task_1",
    validation_allowed: false,
  };
  let requestedUrl = "";
  let requestedBody: unknown = null;

  globalThis.fetch = async (input, init) => {
    requestedUrl = String(input);
    requestedBody = JSON.parse(String(init?.body));
    return new Response(
      JSON.stringify({
        ...fallbackPlan,
        evidence_plan: ["Collect redacted artifact summaries only."],
        plan_id: "research_plan_1",
        refutation_questions: ["Can existing evidence refute the candidate?"],
        status: "drafted",
      }),
      { headers: { "Content-Type": "application/json" }, status: 200 },
    );
  };

  try {
    const plan = await createResearchReviewPlan(
      "campaign_1",
      "task_1",
      {
        evidence_plan: ["Collect redacted artifact summaries only."],
        hypothesis: "Review private file access boundary.",
        rationale: "Draft from redacted review context.",
        refutation_questions: ["Can existing evidence refute the candidate?"],
        reviewer: "operator",
      },
    );

    assert.match(
      requestedUrl,
      /\/mythos\/campaigns\/campaign_1\/research-queue\/tasks\/task_1\/review-plans$/,
    );
    assert.deepEqual(requestedBody, {
      evidence_plan: ["Collect redacted artifact summaries only."],
      hypothesis: "Review private file access boundary.",
      rationale: "Draft from redacted review context.",
      refutation_questions: ["Can existing evidence refute the candidate?"],
      reviewer: "operator",
    });
    assert.ok(plan);
    assert.equal(plan.status, "drafted");
    assert.equal(plan.execution_allowed, false);
    assert.equal(plan.dispatch_allowed, false);
    assert.equal(plan.validation_allowed, false);
    assert.equal(plan.report_submission_allowed, false);
    assert.doesNotMatch(JSON.stringify(requestedBody), /execute|approve|submit|Authorization:|secret-token/i);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("createResearchRefutationDecision records needs-evidence without validation", async () => {
  const originalFetch = globalThis.fetch;
  const fallbackDecision: CampaignResearchRefutationDecision = {
    campaign_id: "campaign_1",
    decision: "needs_evidence",
    decision_id: "fallback_decision",
    dispatch_allowed: false,
    execution_allowed: false,
    next_allowed_action: "验证前请收集脱敏证据或完善假设。",
    plan_id: "research_plan_1",
    rationale: "Fallback rationale",
    refutation_answers: [],
    report_submission_allowed: false,
    task_id: "task_1",
    validation_allowed: false,
    validation_run_id: null,
  };
  let requestedUrl = "";
  let requestedBody: unknown = null;

  globalThis.fetch = async (input, init) => {
    requestedUrl = String(input);
    requestedBody = JSON.parse(String(init?.body));
    return new Response(
      JSON.stringify({
        ...fallbackDecision,
        decision_id: "refutation_decision_1",
        refutation_answers: ["Current redacted evidence is insufficient."],
      }),
      { headers: { "Content-Type": "application/json" }, status: 200 },
    );
  };

  try {
    const decision = await createResearchRefutationDecision(
      "campaign_1",
      "task_1",
      {
        candidate_context_summary: {
          evidence_focus_count: 2,
          has_authorization_gap_candidate: true,
          source_fact_type_count: 1,
          triage_signal_count: 1,
        },
        decision: "needs_evidence",
        plan_id: "research_plan_1",
        rationale: "验证前需要更多已脱敏证据。",
        refutation_answers: ["Current redacted evidence is insufficient."],
        reviewer: "operator",
      },
    );

    assert.match(
      requestedUrl,
      /\/mythos\/campaigns\/campaign_1\/research-queue\/tasks\/task_1\/review-decisions$/,
    );
    assert.deepEqual(requestedBody, {
      candidate_context_summary: {
        evidence_focus_count: 2,
        has_authorization_gap_candidate: true,
        source_fact_type_count: 1,
        triage_signal_count: 1,
      },
      decision: "needs_evidence",
      plan_id: "research_plan_1",
      rationale: "验证前需要更多已脱敏证据。",
      refutation_answers: ["Current redacted evidence is insufficient."],
      reviewer: "operator",
    });
    assert.equal(decision.decision, "needs_evidence");
    assert.equal(decision.validation_run_id, null);
    assert.equal(decision.execution_allowed, false);
    assert.equal(decision.dispatch_allowed, false);
    assert.equal(decision.validation_allowed, false);
    assert.equal(decision.report_submission_allowed, false);
    assert.doesNotMatch(JSON.stringify(requestedBody), /execute|approve|submit|Authorization\s*[:=]|secret-token/i);
  } finally {
    globalThis.fetch = originalFetch;
  }
});
