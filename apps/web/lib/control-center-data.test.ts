import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import type { ControlCenterOverviewResponse } from "./api.ts";

const webRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

function overview(
  overrides: Partial<ControlCenterOverviewResponse> = {},
): ControlCenterOverviewResponse {
  return {
    agent_stages: [
      { record_count: 2, stage: "policy", status: "completed" },
      { record_count: 1, stage: "target_modeling", status: "running" },
      { record_count: 0, stage: "code_api_audit", status: "not_started" },
      { record_count: 1, stage: "refutation", status: "blocked" },
      { record_count: 0, stage: "report_drafting", status: "waiting" },
    ],
    authorized_assets: [
      {
        asset: "api.authorized.local",
        campaign_id: "campaign_1",
        campaign_status: "running",
        scope_status: "in_scope",
      },
    ],
    campaigns: [
      {
        blocked_reasons: [],
        id: "campaign_1",
        name: "Local API review",
        safe_next_action: "review_candidate_evidence",
        scope_status: "in_scope",
        status: "running",
      },
    ],
    candidates: [
      {
        affected_code_path: null,
        affected_endpoint: "GET /objects/{id}",
        campaign_id: "campaign_1",
        candidate_id: "candidate_b",
        evidence_trace_status: "partial",
        human_validation_readiness: "approval_required",
        pipeline_run_id: "run_1",
        rank: 2,
        report_submission_allowed: false,
        vuln_type: "idor",
      },
      {
        affected_code_path: "src/routes/object.ts",
        affected_endpoint: "PATCH /objects/{id}",
        campaign_id: "campaign_1",
        candidate_id: "candidate_a",
        evidence_trace_status: "complete",
        human_validation_readiness: "ready_for_human_review",
        pipeline_run_id: "run_1",
        rank: 1,
        report_submission_allowed: true as false,
        vuln_type: "access_control",
      },
    ],
    data_mode: "live",
    empty_state: false,
    generated_at: "2026-07-18T04:00:00Z",
    metrics: {
      approval_pressure_count: 1,
      retained_high_value_candidate_count: 2,
      running_task_count: 3,
      safety_block_count: 1,
    },
    recent_events: [
      {
        campaign_id: "campaign_1",
        event_id: "event_1",
        event_type: "research_task",
        occurred_at: "2026-07-18T04:00:00Z",
        status: "running",
      },
    ],
    report_readiness: {
      available: true,
      claim_count: 2,
      evidence_ref_count: 4,
      human_review_required: false,
      pipeline_run_id: "run_1",
      report_submission_allowed: true as false,
      status: "ready",
      submission_blocked: false,
      title: "Object authorization candidate",
    },
    research_quality: {
      evidence_completeness: 0.75,
      median_human_review_seconds: 3600,
      refutation_kill_rate: 0.5,
      retention_rate: 0.4,
    },
    snapshot_version: "a".repeat(64),
    ...overrides,
  };
}

test("mapControlCenterOverview uses safe Chinese labels, stable candidate order, and denies hostile permissions", async () => {
  const { mapControlCenterOverview } = await import("./control-center-data.ts");
  const snapshot = mapControlCenterOverview(overview(), new Date("2026-07-18T04:00:20Z"));

  assert.deepEqual(
    snapshot.agentStages.map((stage) => [stage.label, stage.statusLabel]),
    [
      ["政策与范围", "已完成"],
      ["目标建模", "运行中"],
      ["代码 / API 审计", "未开始"],
      ["反证审查", "已阻止"],
      ["报告草拟", "等待中"],
    ],
  );
  assert.deepEqual(snapshot.candidates.map((candidate) => candidate.id), [
    "candidate_a",
    "candidate_b",
  ]);
  assert.equal(snapshot.candidates[0]?.reportSubmissionAllowed, false);
  assert.equal(snapshot.report.submissionBlocked, true);
  assert.equal(snapshot.report.reportSubmissionAllowed, false);
  assert.equal(snapshot.report.humanReviewRequired, true);
  assert.equal(snapshot.stale, false);
});

test("authorized asset scope mapping fails closed for review and blocked states", async () => {
  const { mapControlCenterOverview } = await import("./control-center-data.ts");
  const snapshot = mapControlCenterOverview(
    overview({
      authorized_assets: [
        { asset: "safe.local", campaign_id: "c1", campaign_status: "running", scope_status: "in_scope" },
        { asset: "review.local", campaign_id: "c1", campaign_status: "waiting", scope_status: "needs_review" },
        { asset: "blocked.local", campaign_id: "c1", campaign_status: "blocked", scope_status: "out_of_scope" },
      ],
    }),
    new Date("2026-07-18T04:00:20Z"),
  );

  assert.deepEqual(
    snapshot.authorizedAssets.map((asset) => [asset.scopeLabel, asset.scopeTone]),
    [
      ["范围内", "safe"],
      ["等待范围复核", "approval"],
      ["范围外", "danger"],
    ],
  );
});

test("mapControlCenterOverview displays safe wakeup health and blocks hostile permissions", async () => {
  const { mapControlCenterOverview } = await import("./control-center-data.ts");
  const active = mapControlCenterOverview(
    overview({
      autonomous_wakeup: {
        status: "active",
        last_heartbeat_at: "2026-07-18T04:00:00Z",
        heartbeat_age_seconds: 0,
        lease_active: true,
        lease_expires_at: "2026-07-18T04:02:00Z",
        has_more_campaigns: false,
        scheduled_interval_seconds: 60,
        last_cycle_completed_at: null,
        last_cycle_status: "not_finished",
        last_cycle_stop_reason: null,
        last_cycle_processed_count: 0,
        last_cycle_outcome_counts: {},
        execution_allowed: false,
        dispatch_allowed: false,
        validation_allowed: false,
        candidate_promotion_allowed: false,
        report_submission_allowed: false,
      },
    }),
    new Date("2026-07-18T04:00:20Z"),
  );

  assert.deepEqual(active.autonomousWakeup, {
    status: "active",
    label: "调度执行中",
    detail: "持久化 wakeup lease 正在处理授权只读任务。",
    tone: "safe",
  });

  const invalidLease = mapControlCenterOverview(
    overview({
      autonomous_wakeup: {
        status: "invalid_lease",
        last_heartbeat_at: "2026-07-18T04:00:00Z",
        heartbeat_age_seconds: 0,
        lease_active: false,
        lease_expires_at: "2026-07-18T04:02:00Z",
        has_more_campaigns: false,
        scheduled_interval_seconds: 60,
        last_cycle_completed_at: null,
        last_cycle_status: "not_finished",
        last_cycle_stop_reason: null,
        last_cycle_processed_count: 0,
        last_cycle_outcome_counts: {},
        execution_allowed: false,
        dispatch_allowed: false,
        validation_allowed: false,
        candidate_promotion_allowed: false,
        report_submission_allowed: false,
      },
    }),
    new Date("2026-07-18T04:00:20Z"),
  );

  assert.deepEqual(invalidLease.autonomousWakeup, {
    status: "invalid_lease",
    label: "调度 lease 状态无效",
    detail: "持久化 wakeup lease 状态不完整或不一致。",
    tone: "danger",
  });

  const unsafe = mapControlCenterOverview(
    overview({
      autonomous_wakeup: {
        status: "healthy",
        last_heartbeat_at: "2026-07-18T04:00:00Z",
        heartbeat_age_seconds: 10,
        lease_active: false,
        lease_expires_at: null,
        has_more_campaigns: false,
        scheduled_interval_seconds: 60,
        last_cycle_completed_at: null,
        last_cycle_status: "not_finished",
        last_cycle_stop_reason: null,
        last_cycle_processed_count: 0,
        last_cycle_outcome_counts: {},
        execution_allowed: true as unknown as false,
        dispatch_allowed: false,
        validation_allowed: false,
        candidate_promotion_allowed: false,
        report_submission_allowed: false,
      },
    }),
    new Date("2026-07-18T04:00:20Z"),
  );

  assert.deepEqual(unsafe.autonomousWakeup, {
    status: "blocked",
    label: "调度状态已阻止",
    detail: "健康摘要的安全字段不满足只读约束。",
    tone: "danger",
  });

  const degraded = mapControlCenterOverview(
    overview({
      autonomous_wakeup: {
        status: "degraded",
        last_heartbeat_at: "2026-07-18T04:00:00Z",
        heartbeat_age_seconds: 10,
        lease_active: false,
        lease_expires_at: null,
        has_more_campaigns: false,
        scheduled_interval_seconds: 60,
        last_cycle_completed_at: "2026-07-18T03:59:55Z",
        last_cycle_status: "failed",
        last_cycle_stop_reason: "wakeup_candidate_query_failed",
        last_cycle_processed_count: 0,
        last_cycle_outcome_counts: {},
        execution_allowed: false,
        dispatch_allowed: false,
        validation_allowed: false,
        candidate_promotion_allowed: false,
        report_submission_allowed: false,
      },
    }),
    new Date("2026-07-18T04:00:20Z"),
  );

  assert.deepEqual(degraded.autonomousWakeup, {
    status: "degraded",
    label: "调度最近运行失败",
    detail: "最近一轮调度未完成；请检查 Beat、Worker 和持久化 wakeup 状态。",
    tone: "danger",
  });
});

test("mapControlCenterOverview marks old snapshots stale and preserves absent quality metrics", async () => {
  const { mapControlCenterOverview } = await import("./control-center-data.ts");
  const snapshot = mapControlCenterOverview(
    overview({
      research_quality: {
        evidence_completeness: null,
        median_human_review_seconds: null,
        refutation_kill_rate: null,
        retention_rate: null,
      },
    }),
    new Date("2026-07-18T04:02:01Z"),
  );

  assert.equal(snapshot.stale, true);
  assert.deepEqual(snapshot.quality, {
    evidenceCompleteness: null,
    medianHumanReviewSeconds: null,
    refutationKillRate: null,
    retentionRate: null,
  });
});

test("buildQualityChartModel returns an explicit empty model without fake axes", async () => {
  const { buildQualityChartModel } = await import("./control-center-data.ts");
  assert.deepEqual(
    buildQualityChartModel({
      evidenceCompleteness: null,
      medianHumanReviewSeconds: null,
      refutationKillRate: null,
      retentionRate: null,
    }),
    { empty: true, option: null },
  );
  const populated = buildQualityChartModel({
    evidenceCompleteness: 0.75,
    medianHumanReviewSeconds: null,
    refutationKillRate: 0.5,
    retentionRate: 0.4,
  });
  assert.equal(populated.empty, false);
  assert.deepEqual(populated.option?.series?.[0]?.data, [40, 50, 75]);
});

test("buildQualityChartModel omits unavailable partial metrics instead of drawing zero bars", async () => {
  const { buildQualityChartModel } = await import("./control-center-data.ts");
  const model = buildQualityChartModel({
    evidenceCompleteness: 0.75,
    medianHumanReviewSeconds: null,
    refutationKillRate: null,
    retentionRate: 0.4,
  });

  assert.equal(model.empty, false);
  assert.deepEqual(model.option?.xAxis.data, ["候选保留", "证据完整"]);
  assert.deepEqual(model.option?.series[0]?.data, [40, 75]);
});

test("offline data mode takes precedence over stale and stale detection honors the 120 second boundary", async () => {
  const { isControlCenterSnapshotStale, resolveControlCenterDataMode } = await import("./control-center-data.ts");
  assert.equal(resolveControlCenterDataMode("offline", true), "offline");
  assert.equal(resolveControlCenterDataMode("live", true), "stale");
  assert.equal(resolveControlCenterDataMode("live", false), "live");
  assert.equal(
    isControlCenterSnapshotStale("2026-07-18T04:00:00Z", new Date("2026-07-18T04:02:00Z")),
    false,
  );
  assert.equal(
    isControlCenterSnapshotStale("2026-07-18T04:00:00Z", new Date("2026-07-18T04:02:00.001Z")),
    true,
  );
});

test("filterControlCenterSnapshot searches safe list fields without changing global metrics", async () => {
  const { filterControlCenterSnapshot, mapControlCenterOverview } = await import("./control-center-data.ts");
  const snapshot = mapControlCenterOverview(overview(), new Date("2026-07-18T04:00:20Z"));
  assert.equal(filterControlCenterSnapshot(snapshot, "  "), snapshot);

  const endpointResult = filterControlCenterSnapshot(snapshot, "patch /OBJECTS");
  assert.deepEqual(endpointResult.candidates.map((candidate) => candidate.id), ["candidate_a"]);
  assert.deepEqual(endpointResult.metrics, snapshot.metrics);
  assert.equal(endpointResult.searchQuery, "patch /OBJECTS");

  const codePathResult = filterControlCenterSnapshot(snapshot, "SRC/ROUTES/OBJECT.TS");
  assert.deepEqual(codePathResult.candidates.map((candidate) => candidate.id), ["candidate_a"]);
  const chineseResult = filterControlCenterSnapshot(snapshot, "研究任务");
  assert.deepEqual(chineseResult.recentEvents.map((event) => event.id), ["event_1"]);
  const idResult = filterControlCenterSnapshot(snapshot, "campaign_1");
  assert.equal(idResult.authorizedAssets.length, 1);
  assert.equal(idResult.candidates.length, 2);
});

test("root page remains a Server Component and passes a serializable initial snapshot", async () => {
  const source = await readFile(path.join(webRoot, "app", "page.tsx"), "utf8");
  assert.doesNotMatch(source, /^\s*["']use client["'];?/);
  assert.match(source, /export default async function/);
  assert.match(source, /getControlCenterOverview\(/);
  assert.match(source, /mapControlCenterOverview\(/);
  assert.match(source, /filterControlCenterSnapshot\(/);
  assert.match(source, /\.q/);
  assert.match(source, /<ControlCenterOverview\s+initialSnapshot=/);
  assert.doesNotMatch(source, /const\s+kpis\s*=|31%|22%|12%/);
});

test("ECharts is isolated in a client leaf with modular registration and cleanup", async () => {
  const source = await readFile(
    path.join(webRoot, "components", "control-center", "echarts-canvas.tsx"),
    "utf8",
  );
  assert.match(source, /^\s*["']use client["'];?/);
  assert.match(source, /from\s+["']echarts\/core["']/);
  assert.doesNotMatch(source, /from\s+["']echarts["']/);
  assert.match(source, /CanvasRenderer/);
  assert.match(source, /ResizeObserver/);
  assert.match(source, /clientWidth/);
  assert.match(source, /\.dispose\(\)/);
});

test("root control-center sections do not duplicate visible headings for assistive technology", async () => {
  const files = [
    "agent-pipeline.tsx",
    "authorized-assets.tsx",
    "candidate-queue.tsx",
    "quality-charts.tsx",
    "report-readiness.tsx",
    "audit-event-stream.tsx",
  ];
  const source = (
    await Promise.all(
      files.map((file) =>
        readFile(path.join(webRoot, "components", "control-center", file), "utf8"),
      ),
    )
  ).join("\n");

  assert.doesNotMatch(source, /<h2[^>]*className="sr-only"/);
});

test("client overview derives stale state after hydration and cleans up the boundary timer", async () => {
  const source = await readFile(
    path.join(webRoot, "components", "control-center", "control-center-overview.tsx"),
    "utf8",
  );
  assert.match(source, /useState\(initialSnapshot\.stale\)/);
  assert.match(source, /isControlCenterSnapshotStale/);
  assert.match(source, /setTimeout\(/);
  assert.match(source, /clearTimeout\(/);
  assert.match(source, /resolveControlCenterDataMode/);
});

test("authorized asset rendering uses scope tone for both icon and badge", async () => {
  const source = await readFile(
    path.join(webRoot, "components", "control-center", "authorized-assets.tsx"),
    "utf8",
  );
  assert.match(source, /asset\.scopeTone/);
  assert.match(source, /ShieldCheck/);
  assert.match(source, /ShieldAlert/);
  assert.match(source, /ShieldX/);
  assert.match(source, /statusToneClassName/);
});
