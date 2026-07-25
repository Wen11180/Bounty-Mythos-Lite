"use client";

import { FileDown, FolderOpen, FolderPlus, Play, ShieldCheck, Upload } from "lucide-react";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";

import { CandidateInspector } from "@/components/studio/candidate-inspector";
import { EvidenceInspector } from "@/components/studio/evidence-inspector";
import { MissionStageStrip } from "@/components/studio/mission-stage-strip";
import { ReportInspector } from "@/components/studio/report-inspector";
import { ResearchConversation } from "@/components/studio/research-conversation";
import { StudioShell } from "@/components/studio/studio-shell";
import { ValidationPlanInspector } from "@/components/studio/validation-plan-inspector";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { ProgramRuleIntake } from "./program-rule-intake";
import {
  ApiRequestError,
  approveStudioBlackBoxLabRun,
  createStudioWorkspace,
  createStudioWorkspaceBenchmarkTemplate,
  exportStudioWorkspaceCampaignHunterReport,
  exportStudioWorkspaceMissionDossier,
  exportStudioWorkspaceReport,
  getCampaignControlCenterRequired,
  getRuntimeApiBaseUrl,
  getStudioBlackBoxRemoteStatus,
  getStudioWorkspaceManifestRequired,
  getStudioWorkspaceMission,
  getStudioWorkspaceMissionRequired,
  importStudioWorkspaceArtifact,
  launchStudioWorkspaceCampaignHunter,
  listStudioWorkspaceCandidatesRequired,
  preflightStudioBlackBoxLabRun,
  previewStudioBlackBoxLabLease,
  recordCandidateHunterLearningOutcome,
  recordStudioBlackBoxLabBoundedResult,
  runStudioWorkspaceBenchmark,
  runStudioWorkspaceResearch,
  type CandidateHunterLearningOutcome,
  type ProgramIntelligenceProfile,
  type StudioBenchmarkRunResponse,
  type StudioBlackBoxLabLeasePreviewRequest,
  type StudioBlackBoxLabLeasePreviewResponse,
  type StudioBlackBoxLabBoundedResultResponse,
  type StudioBlackBoxLabBoundedTrace,
  type StudioBlackBoxLabCompletePlan,
  type StudioBlackBoxLabRunPreflightRequest,
  type StudioBlackBoxLabTraceReviewRequest,
  type StudioBlackBoxRemoteStatusResponse,
  type StudioMissionDossierExportResponse,
  type StudioReportExportResponse,
  type StudioWorkspaceRunRequest,
} from "@/lib/api";
import {
  createControlCenterLiveController,
  type ControlCenterLiveState,
} from "@/lib/control-center-live";
import {
  buildStudioEventsUrl,
  refreshStudioProjection,
  type StudioRefreshProjection,
} from "@/lib/studio-live";
import {
  toStudioArtifactChecklist,
  toStudioBlackBoxRemoteStatus,
  toStudioCampaignHunterCandidateCards,
  toStudioCandidateCards,
  toStudioControlCenterView,
  toStudioMissionHandoffBrief,
  toStudioMissionPanel,
  toStudioResearchReadiness,
  toStudioWorkspaceSummary,
  type StudioWorkspaceManifest,
} from "@/lib/studio-data";
import type { SafeRefreshStatus } from "@/lib/program-rule-data";
import { formatLabel } from "@/lib/workbench-display";

type LogEntry = {
  actor?: "operator" | "system";
  message: string;
  tone: "info" | "safe" | "blocked";
};

type BlackBoxLabRunnerState =
  | "idle"
  | "awaiting_sessions_ready"
  | "recording"
  | "sessions_ready"
  | "trial_complete"
  | "stopped";

type DesktopBackupResult =
  | { status: "cancelled" | "failed" | "unavailable" }
  | { archive_name: string; file_count: number; status: "created" }
  | { archive_name: string; rollback_archive_name: string | null; status: "restored" };

type MythosStudioDesktopBridge = {
  apiBaseUrl?: string | null;
  closeBlackBoxSessions: () => Promise<string>;
  createBackup?: () => Promise<DesktopBackupResult>;
  createBlackBoxSessions: (payload: Readonly<Record<string, unknown>>) => Promise<string>;
  emergencyStopAutopilotLocal?: (campaignId: string) => Promise<{ tracking: boolean }>;
  refreshProgramRules: () => Promise<SafeRefreshStatus>;
  restoreBackup?: () => Promise<DesktopBackupResult>;
  runBlackBoxTrial: (payload: Readonly<Record<string, unknown>>) => Promise<string>;
  selectDirectory: () => Promise<string | null>;
  selectFile: (options?: { title?: string }) => Promise<string | null>;
  startBlackBoxRecording: (payload: Readonly<Record<string, unknown>>) => Promise<string>;
  stopBlackBoxRecording: () => Promise<string>;
};

declare global {
  interface Window {
    mythosStudio?: MythosStudioDesktopBridge;
  }
}

const emptyManifest: StudioWorkspaceManifest = {
  name: "本地赏金神话研究工作台",
  artifacts: [],
  runs: [],
  safety: {
    scope_guard_status: "missing_scope",
    blocked_actions: ["execute_live_validation", "touch_real_user_data", "submit_report"],
  },
};

const remoteStatusFallback: StudioBlackBoxRemoteStatusResponse = {
  profile: "remote_human_lease",
  enabled: false,
  state: "relogin_required",
  expires_at: null,
  relogin_required: true,
  stop_reason: "relogin_required",
  report_submission_allowed: false,
  human_confirmation_allowed: false,
};

const studioRefreshDependencies = {
  getCampaign: getCampaignControlCenterRequired,
  getManifest: getStudioWorkspaceManifestRequired,
  getMission: getStudioWorkspaceMissionRequired,
  listCandidates: listStudioWorkspaceCandidatesRequired,
  mapCampaignCandidates: toStudioCampaignHunterCandidateCards,
  mapMission: toStudioMissionPanel,
  mapResearchCandidates: toStudioCandidateCards,
};

function blackBoxLabLeaseExpiry() {
  return new Date(Date.now() + 15 * 60 * 1000).toISOString();
}

function isFutureExpiry(value: string): boolean {
  const parsed = Date.parse(value);
  return Number.isFinite(parsed) && parsed > Date.now();
}

export function StudioWorkbench() {
  const [workspaceRoot, setWorkspaceRoot] = useState("C:/mythos-workspaces");
  const [workspaceName, setWorkspaceName] = useState("authorized-target");
  const [policyPath, setPolicyPath] = useState("");
  const [scopePath, setScopePath] = useState("");
  const [codePath, setCodePath] = useState("");
  const [apiPath, setApiPath] = useState("");
  const [harPath, setHarPath] = useState("");
  const [sbomPath, setSbomPath] = useState("");
  const [sarifPath, setSarifPath] = useState("");
  const [fuzzingPath, setFuzzingPath] = useState("");
  const [strategyPath, setStrategyPath] = useState("");
  const [knowledgePath, setKnowledgePath] = useState("");
  const [expectationsPath, setExpectationsPath] = useState("");
  const [candidateModelEnabled, setCandidateModelEnabled] = useState(false);
  const [candidateModelProvider, setCandidateModelProvider] = useState<
    "openai" | "claude" | "deepseek"
  >("openai");
  const [candidateModelName, setCandidateModelName] = useState("");
  const [workspacePath, setWorkspacePath] = useState("");
  const [manifest, setManifest] = useState<StudioWorkspaceManifest>(emptyManifest);
  const [candidates, setCandidates] = useState<ReturnType<typeof toStudioCandidateCards>>([]);
  const [missionPanel, setMissionPanel] = useState<ReturnType<typeof toStudioMissionPanel>>(
    toStudioMissionPanel(null),
  );
  const [latestRunId, setLatestRunId] = useState<string | null>(null);
  const [latestCampaignHunterId, setLatestCampaignHunterId] = useState<string | null>(null);
  const [reportExport, setReportExport] = useState<StudioReportExportResponse | null>(null);
  const [missionDossierExport, setMissionDossierExport] =
    useState<StudioMissionDossierExportResponse | null>(null);
  const [benchmarkResult, setBenchmarkResult] = useState<StudioBenchmarkRunResponse | null>(null);
  const [learningProfile, setLearningProfile] = useState<ProgramIntelligenceProfile | null>(null);
  const [labOrigin, setLabOrigin] = useState("http://127.0.0.1:43110");
  const [labValidationRunId, setLabValidationRunId] = useState("");
  const [labSessionAReady, setLabSessionAReady] = useState(false);
  const [labSessionBReady, setLabSessionBReady] = useState(false);
  const [labLeaseRequestSnapshot, setLabLeaseRequestSnapshot] =
    useState<StudioBlackBoxLabLeasePreviewRequest | null>(null);
  const [labLeasePreview, setLabLeasePreview] =
    useState<StudioBlackBoxLabLeasePreviewResponse | null>(null);
  const [labTraceReview, setLabTraceReview] = useState<StudioBlackBoxLabTraceReviewRequest[]>([]);
  const [labTraceReviewConfirmed, setLabTraceReviewConfirmed] = useState(false);
  const [labBoundedResult, setLabBoundedResult] =
    useState<StudioBlackBoxLabBoundedResultResponse | null>(null);
  const [labRunnerState, setLabRunnerState] = useState<BlackBoxLabRunnerState>("idle");
  const labReviewGeneration = useRef(0);
  const labDispatchInFlight = useRef(false);
  const [remoteStatus, setRemoteStatus] =
    useState<StudioBlackBoxRemoteStatusResponse>(remoteStatusFallback);
  const [busy, setBusy] = useState<string | null>(null);
  const [connectionState, setConnectionState] = useState<ControlCenterLiveState>("connecting");
  const [desktopPickerAvailable, setDesktopPickerAvailable] = useState(false);
  const [desktopBackupAvailable, setDesktopBackupAvailable] = useState(false);
  const [inspectorTab, setInspectorTab] = useState<"candidate" | "evidence" | "report" | "validation">("candidate");
  const [selectedCandidateId, setSelectedCandidateId] = useState<string | null>(null);
  const [log, setLog] = useState<LogEntry[]>([
    {
      message: "研究工作台已就绪。",
      tone: "info",
    },
  ]);

  useEffect(() => {
    const handlePageHide = () => {
      void window.mythosStudio?.closeBlackBoxSessions().catch(() => undefined);
    };
    window.addEventListener("pagehide", handlePageHide);
    return () => window.removeEventListener("pagehide", handlePageHide);
  }, []);

  const workspace = useMemo(() => toStudioWorkspaceSummary(manifest), [manifest]);
  const artifactChecklist = useMemo(() => toStudioArtifactChecklist(manifest), [manifest]);
  const missionHandoffBrief = useMemo(
    () => toStudioMissionHandoffBrief(missionPanel),
    [missionPanel],
  );
  const researchReadiness = useMemo(
    () => toStudioResearchReadiness(workspacePath, manifest),
    [manifest, workspacePath],
  );
  const currentWizardStep = useMemo(() => {
    if (candidates.length > 0 || reportExport) {
      return "candidate_review";
    }
    if (researchReadiness.canStart) {
      return "readiness_check";
    }
    if (workspacePath) {
      return "authorized_materials";
    }
    return "workspace";
  }, [candidates.length, reportExport, researchReadiness.canStart, workspacePath]);
  const wizardSteps = useMemo(
    () => [
      {
        id: "workspace",
        label: "工作区",
        detail: workspacePath ? "已选择工作区" : "创建或打开本地工作区",
      },
      {
        id: "authorized_materials",
        label: "授权材料",
        detail: workspacePath ? "导入授权材料" : "请先选择工作区",
      },
      {
        id: "readiness_check",
        label: "就绪检查",
        detail: researchReadiness.canStart ? "开始本地研究" : researchReadiness.reason,
      },
      {
        id: "candidate_review",
        label: "候选审查",
        detail:
          candidates.length > 0
            ? "审查候选并导出已阻断提交的报告草稿"
            : "研究完成后审查候选",
      },
    ],
    [candidates.length, researchReadiness.canStart, researchReadiness.reason, workspacePath],
  );
  const missingRequiredArtifacts = useMemo(
    () => artifactChecklist.filter((item) => item.required && !item.present),
    [artifactChecklist],
  );
  const optionalContextArtifacts = useMemo(
    () => artifactChecklist.filter((item) => !item.required),
    [artifactChecklist],
  );
  const benchmarkEvidenceGaps = benchmarkResult?.benchmark.evidence_gaps ?? [];
  const remoteStatusView = useMemo(
    () => toStudioBlackBoxRemoteStatus(remoteStatus),
    [remoteStatus],
  );
  const remoteReloginRequired = remoteStatusView.warning || remoteStatus.relogin_required;
  const studioView = useMemo(
    () => toStudioControlCenterView(candidates, selectedCandidateId),
    [candidates, selectedCandidateId],
  );

  const applyStudioProjection = useCallback((projection: StudioRefreshProjection) => {
    setManifest(projection.manifest);
    setLatestRunId(projection.latestRunId);
    setLatestCampaignHunterId(projection.latestCampaignHunterId);
    setCandidates(projection.candidates);
    setMissionPanel(projection.missionPanel);
    setReportExport(projection.reportExport);
  }, []);

  useEffect(() => {
    const timer = window.setTimeout(() => {
      setDesktopPickerAvailable(Boolean(window.mythosStudio));
      setDesktopBackupAvailable(
        Boolean(window.mythosStudio?.createBackup && window.mythosStudio?.restoreBackup),
      );
    }, 0);
    return () => window.clearTimeout(timer);
  }, []);

  useEffect(() => {
    if (!workspacePath) {
      return;
    }
    const controller = createControlCenterLiveController({
      eventsUrl: buildStudioEventsUrl(
        getRuntimeApiBaseUrl(),
        latestCampaignHunterId,
      ),
      eventSourceFactory: (url) => new EventSource(url),
      onStateChange: setConnectionState,
      async refetch(signal) {
        const projection = await refreshStudioProjection({
          dependencies: studioRefreshDependencies,
          signal,
          workspacePath,
        });
        if (!projection || signal.aborted) {
          return;
        }
        applyStudioProjection(projection);
      },
      scheduler: {
        clearInterval: (id) => window.clearInterval(id),
        setInterval: (callback, delay) => window.setInterval(callback, delay),
      },
      visibility: {
        addEventListener: (_type, listener) => document.addEventListener("visibilitychange", listener),
        get state() {
          return document.visibilityState === "hidden" ? "hidden" : "visible";
        },
        removeEventListener: (_type, listener) => document.removeEventListener("visibilitychange", listener),
      },
    });
    controller.start();
    return () => controller.stop();
  }, [applyStudioProjection, latestCampaignHunterId, latestRunId, workspacePath]);

  useEffect(() => {
    let mounted = true;
    void getStudioBlackBoxRemoteStatus().then((status) => {
      if (mounted) {
        setRemoteStatus(status);
      }
    });
    return () => {
      mounted = false;
    };
  }, []);

  async function handleRefreshRemoteStatus() {
    setBusy("remote-status");
    try {
      setRemoteStatus(await getStudioBlackBoxRemoteStatus());
    } finally {
      setBusy(null);
    }
  }

  function studioResearchRunRequest(path: string): StudioWorkspaceRunRequest | null {
    if (!candidateModelEnabled) {
      return { workspace_path: path };
    }
    if (!candidateModelName.trim()) {
      pushLog("启用模型辅助候选生成前，请先填写模型名称。", "blocked");
      return null;
    }
    return {
      candidate_model: {
        enabled: true,
        model: candidateModelName.trim(),
        provider: candidateModelProvider,
      },
      workspace_path: path,
    };
  }

  async function runStudioResearchOnce(path: string) {
    const request = studioResearchRunRequest(path);
    if (!request) {
      return undefined;
    }
    try {
      return await runStudioWorkspaceResearch(request);
    } finally {
      setCandidateModelEnabled(false);
    }
  }

  function blackBoxLabLeaseRequest(): StudioBlackBoxLabLeasePreviewRequest {
    const activeOrigin = labOrigin.trim();
    return {
      active_origin: activeOrigin,
      sessions: [
        {
          account_alias: "account_a",
          ready: labSessionAReady,
          role_alias: "member",
          session_alias: "session_a",
        },
        {
          account_alias: "account_b",
          ready: labSessionBReady,
          role_alias: "member",
          session_alias: "session_b",
        },
      ],
      workflows: [
        {
          action: "read_only_replay",
          method: "GET",
          object_aliases: ["widget_a"],
          origin: activeOrigin,
          route_template: "/widgets/{object}",
          session_alias: "session_a",
          workflow_alias: "read_widget_a",
        },
      ],
    };
  }

  function invalidateBlackBoxLabReview() {
    labReviewGeneration.current += 1;
    setLabLeaseRequestSnapshot(null);
    setLabLeasePreview(null);
    setLabTraceReview([]);
    setLabTraceReviewConfirmed(false);
    setLabBoundedResult(null);
  }

  function handleLabOriginChange(value: string) {
    setLabOrigin(value);
    invalidateBlackBoxLabReview();
  }

  function handleLabSessionReadiness(
    sessionAlias: "session_a" | "session_b",
    ready: boolean,
  ) {
    if (sessionAlias === "session_a") {
      setLabSessionAReady(ready);
    } else {
      setLabSessionBReady(ready);
    }
    invalidateBlackBoxLabReview();
  }

  function handleLabValidationRunIdChange(value: string) {
    labReviewGeneration.current += 1;
    setLabValidationRunId(value);
  }

  function parseBlackBoxRunnerEvent(line: string): Record<string, unknown> {
    const serialized = line.trim();
    if (!serialized || serialized.includes("\n")) {
      throw new Error("invalid_black_box_runner_response");
    }
    const event = JSON.parse(serialized) as unknown;
    if (!event || typeof event !== "object" || Array.isArray(event)) {
      throw new Error("invalid_black_box_runner_response");
    }
    const record = event as Record<string, unknown>;
    if (typeof record.event !== "string") {
      throw new Error("invalid_black_box_runner_response");
    }
    return record;
  }

  function reviewedTracesFromRunnerEvent(
    event: Record<string, unknown>,
  ): StudioBlackBoxLabTraceReviewRequest[] {
    if (!Array.isArray(event.traces)) {
      return [];
    }
    return event.traces.flatMap((value) => {
      if (!value || typeof value !== "object" || Array.isArray(value)) {
        return [];
      }
      const trace = value as Record<string, unknown>;
      const aliases = trace.aliases;
      if (!aliases || typeof aliases !== "object" || Array.isArray(aliases)) {
        return [];
      }
      const safeAliases = aliases as Record<string, unknown>;
      const sessionAlias = safeAliases.session_alias;
      if (
        (sessionAlias !== "session_a" && sessionAlias !== "session_b") ||
        typeof safeAliases.workflow_alias !== "string" ||
        typeof trace.route_template !== "string" ||
        typeof trace.response_schema_fingerprint !== "string"
      ) {
        return [];
      }
      return [
        {
          redacted: true as const,
          response_schema_fingerprint: trace.response_schema_fingerprint,
          route_template: trace.route_template,
          session_alias: sessionAlias,
          workflow_alias: safeAliases.workflow_alias,
        },
      ];
    });
  }

  function boundedTraceFromTrialResult(
    event: Record<string, unknown>,
    completePlan: StudioBlackBoxLabCompletePlan,
    preflight: { approved_session_alias: string; approved_workflow_alias: string },
  ): StudioBlackBoxLabBoundedTrace {
    const rawTrace = event.trace;
    if (!rawTrace || typeof rawTrace !== "object" || Array.isArray(rawTrace)) {
      throw new Error("bounded_trial_trace_required");
    }
    const trace = rawTrace as Record<string, unknown>;
    const rawAliases = trace.aliases;
    if (!rawAliases || typeof rawAliases !== "object" || Array.isArray(rawAliases)) {
      throw new Error("bounded_trial_trace_required");
    }
    const aliases = rawAliases as Record<string, unknown>;
    const workflow = completePlan.lease_preview.workflows.find(
      (item) => item.workflow_alias === preflight.approved_workflow_alias,
    );
    const trialSession = completePlan.lease_preview.sessions.find(
      (item) => item.session_alias === preflight.approved_session_alias,
    );
    const objectAliases = aliases.object_aliases;
    const parameters = trace.parameters;
    if (
      !workflow ||
      !trialSession ||
      (workflow.method !== "GET" && workflow.method !== "HEAD") ||
      aliases.account_alias !== trialSession.account_alias ||
      aliases.role_alias !== trialSession.role_alias ||
      aliases.session_alias !== trialSession.session_alias ||
      aliases.workflow_alias !== workflow.workflow_alias ||
      !Array.isArray(objectAliases) ||
      objectAliases.length !== workflow.object_aliases.length ||
      objectAliases.some((value, index) => value !== workflow.object_aliases[index]) ||
      trace.method !== workflow.method ||
      trace.route_template !== workflow.route_template ||
      !Array.isArray(parameters) ||
      parameters.length !== 1
    ) {
      throw new Error("bounded_trial_trace_plan_mismatch");
    }
    const parameter = parameters[0];
    if (
      !parameter ||
      typeof parameter !== "object" ||
      Array.isArray(parameter) ||
      (parameter as Record<string, unknown>).location !== "path" ||
      (parameter as Record<string, unknown>).name !== "object" ||
      (parameter as Record<string, unknown>).value_type !== "object_alias"
    ) {
      throw new Error("bounded_trial_trace_parameter_mismatch");
    }
    if (
      typeof trace.response_schema_fingerprint !== "string" ||
      !/^sha256:[0-9a-f]{64}$/u.test(trace.response_schema_fingerprint)
    ) {
      throw new Error("bounded_trial_trace_fingerprint_required");
    }
    if (
      trace.status_class !== "1xx" &&
      trace.status_class !== "2xx" &&
      trace.status_class !== "3xx" &&
      trace.status_class !== "4xx" &&
      trace.status_class !== "5xx"
    ) {
      throw new Error("bounded_trial_trace_status_required");
    }

    const timingBucket = boundedTrialTimingBucket(trace.timing_bucket);
    return {
      aliases: {
        account_alias: trialSession.account_alias,
        object_aliases: [...workflow.object_aliases],
        role_alias: trialSession.role_alias,
        session_alias: trialSession.session_alias,
        workflow_alias: workflow.workflow_alias,
      },
      method: workflow.method,
      parameters: [{ location: "path", name: "object", value_type: "object_alias" }],
      response_schema_fingerprint: trace.response_schema_fingerprint,
      route_template: workflow.route_template,
      status_class: trace.status_class,
      timing_bucket: timingBucket,
    };
  }

  function boundedTrialTimingBucket(
    value: unknown,
  ): StudioBlackBoxLabBoundedTrace["timing_bucket"] {
    if (value === "under_100ms" || value === "under_500ms" || value === "under_2s" || value === "over_2s") {
      return value;
    }
    if (value === "under_1s") {
      return "under_2s";
    }
    if (value === "under_3s" || value === "over_3s") {
      return "over_2s";
    }
    throw new Error("bounded_trial_trace_timing_required");
  }

  function resetBlackBoxLabState() {
    setLabSessionAReady(false);
    setLabSessionBReady(false);
    invalidateBlackBoxLabReview();
    setLabRunnerState("idle");
  }

  async function handlePreviewBlackBoxLabLease() {
    setBusy("lab-preview");
    try {
      const request = blackBoxLabLeaseRequest();
      const preview = await previewStudioBlackBoxLabLease(request);
      if (!preview) {
        pushLog("未返回本地实验室租约预览。", "blocked");
        return;
      }
      setLabLeaseRequestSnapshot(request);
      setLabLeasePreview(preview);
      pushLog(
        preview.sessions_ready
          ? "已审查受限回环租约；两个会话别名均标记为就绪。"
          : "已审查受限回环租约；请创建会话并完成就绪检查。",
        preview.sessions_ready ? "safe" : "info",
      );
    } catch (error) {
      pushMutationFailure("本地实验室租约预览", error);
    } finally {
      setBusy(null);
    }
  }

  async function handleCreateBlackBoxSessions() {
    const bridge = window.mythosStudio;
    if (!bridge || !labLeaseRequestSnapshot || labRunnerState !== "idle") {
      pushLog("创建会话前，请先在赏金神话研究工作台预览受限本地租约。", "blocked");
      return;
    }
    setBusy("lab-create-sessions");
    try {
      const line = await bridge.createBlackBoxSessions({
        lease: {
          active_origins: [labLeaseRequestSnapshot.active_origin],
          expires_at: blackBoxLabLeaseExpiry(),
          passive_origins: [],
        },
        sessions: labLeaseRequestSnapshot.sessions.map((session) => ({
          account_alias: session.account_alias,
          role_alias: session.role_alias,
          session_alias: session.session_alias,
        })),
      });
      const event = parseBlackBoxRunnerEvent(line);
      if (event.event !== "sessions_created") {
        throw new Error(String(event.reason ?? "sessions_not_created"));
      }
      setLabRunnerState("awaiting_sessions_ready");
      pushLog("已创建两个隔离的本地浏览器会话，请手动完成登录。", "safe");
    } catch (error) {
      pushMutationFailure("本地实验室会话创建", error);
    } finally {
      setBusy(null);
    }
  }

  async function handleStartBlackBoxRecording() {
    const bridge = window.mythosStudio;
    const workflow = labLeaseRequestSnapshot?.workflows[0];
    const session = labLeaseRequestSnapshot?.sessions.find(
      (item) => item.session_alias === workflow?.session_alias,
    );
    if (
      !bridge ||
      !workflow ||
      !session ||
      !labLeasePreview?.sessions_ready ||
      labRunnerState !== "awaiting_sessions_ready"
    ) {
      pushLog("开始录制前，两个隔离会话都必须就绪。", "blocked");
      return;
    }
    setBusy("lab-start-recording");
    try {
      const line = await bridge.startBlackBoxRecording({
        sessions_ready: true,
        workflows: [
          {
            action: workflow.action,
            aliases: {
              account_alias: session.account_alias,
              object_aliases: workflow.object_aliases,
              role_alias: session.role_alias,
              session_alias: session.session_alias,
              workflow_alias: workflow.workflow_alias,
            },
            capture_phase: "post_login",
            method: workflow.method,
            origin: workflow.origin,
            path_parameters: [
              { location: "path", name: "object", segment: 2, value_type: "object_alias" },
            ],
            query_parameters: [],
            route_template: workflow.route_template,
          },
        ],
      });
      const event = parseBlackBoxRunnerEvent(line);
      if (event.event !== "recording_started") {
        throw new Error(String(event.reason ?? "recording_not_started"));
      }
      setLabTraceReview([]);
      setLabTraceReviewConfirmed(false);
      setLabBoundedResult(null);
      setLabRunnerState("recording");
      pushLog("正在为声明的本地工作流录制仅含别名的标准化轨迹。", "safe");
    } catch (error) {
      pushMutationFailure("本地实验室开始录制", error);
    } finally {
      setBusy(null);
    }
  }

  async function handleStopBlackBoxRecording() {
    const bridge = window.mythosStudio;
    if (!bridge || labRunnerState !== "recording") {
      pushLog("当前没有进行中的本地实验室录制。", "blocked");
      return;
    }
    setBusy("lab-stop-recording");
    try {
      const event = parseBlackBoxRunnerEvent(await bridge.stopBlackBoxRecording());
      if (event.event === "stop") {
        setLabRunnerState("stopped");
        pushLog(`本地实验室已停止：${formatLabel(event.reason ?? "safety_stop")}。`, "blocked");
        return;
      }
      if (event.event !== "recording_stopped") {
        throw new Error("recording_not_stopped");
      }
      const traces = reviewedTracesFromRunnerEvent(event);
      setLabTraceReview(traces);
      setLabTraceReviewConfirmed(false);
      setLabRunnerState("sessions_ready");
      pushLog(
        traces.length > 0
          ? `${traces.length} 条标准化轨迹已准备好供人工审核。`
          : "未捕获匹配的标准化轨迹，请停止实验室后重试。",
        traces.length > 0 ? "safe" : "blocked",
      );
    } catch (error) {
      setLabRunnerState("stopped");
      pushMutationFailure("本地实验室停止录制", error);
    } finally {
      setBusy(null);
    }
  }

  function handleReviewBlackBoxTraces() {
    if (labTraceReview.length === 0 || labRunnerState !== "sessions_ready") {
      pushLog("审查前请先捕获匹配的标准化轨迹。", "blocked");
      return;
    }
    setLabTraceReviewConfirmed(true);
    pushLog(
      "已审查仅含别名的标准化轨迹；原始请求头和消息体仍被排除。",
      "safe",
      "operator",
    );
  }

  async function handleApproveBlackBoxLabRun() {
    const bridge = window.mythosStudio;
    if (labDispatchInFlight.current) {
      return;
    }
    if (
      !bridge ||
      !labLeaseRequestSnapshot ||
      !labTraceReviewConfirmed ||
      !labValidationRunId.trim() ||
      labRunnerState !== "sessions_ready"
    ) {
      pushLog("确认前需要持久化验证运行和已审查的轨迹。", "blocked");
      return;
    }
    labDispatchInFlight.current = true;
    const generation = labReviewGeneration.current;
    const leasePreview = labLeaseRequestSnapshot;
    const validationRunId = labValidationRunId.trim();
    let trialDispatched = false;
    setBusy("lab-approve");
    try {
      const completePlan: StudioBlackBoxLabCompletePlan = {
        lease_preview: leasePreview,
        operator_confirmed: true,
        trace_review: labTraceReview,
        validation_run_id: validationRunId,
      };
      const approval = await approveStudioBlackBoxLabRun(completePlan);
      if (
        labReviewGeneration.current !== generation ||
        approval.approval_status !== "approved" ||
        approval.validation_run_id !== validationRunId ||
        approval.local_runner_dispatch_allowed !== true ||
        approval.execution_allowed !== false ||
        approval.report_submission_allowed !== false ||
        !/^sha256:[0-9a-f]{64}$/u.test(approval.complete_plan_digest) ||
        !/^sha256:[0-9a-f]{64}$/u.test(approval.lease_digest) ||
        !approval.plan_digest ||
        !approval.scope_reference ||
        !isFutureExpiry(approval.expires_at) ||
        !leasePreview.sessions.some(
          (session) => session.session_alias === approval.approved_session_alias,
        ) ||
        !leasePreview.workflows.some(
          (workflow) => workflow.workflow_alias === approval.approved_workflow_alias,
        )
      ) {
        throw new Error("local_lab_approval_binding_changed");
      }
      const exactPreflightRequest: StudioBlackBoxLabRunPreflightRequest = {
        approval_id: approval.approval_id,
        complete_plan: completePlan,
        complete_plan_digest: approval.complete_plan_digest,
        lease_digest: approval.lease_digest,
      };
      const preflight = await preflightStudioBlackBoxLabRun(exactPreflightRequest);
      if (
        labReviewGeneration.current !== generation ||
        preflight.approval_id !== approval.approval_id ||
        preflight.validation_run_id !== approval.validation_run_id ||
        preflight.approved_session_alias !== approval.approved_session_alias ||
        preflight.approved_workflow_alias !== approval.approved_workflow_alias ||
        preflight.complete_plan_digest !== approval.complete_plan_digest ||
        preflight.expires_at !== approval.expires_at ||
        preflight.lease_digest !== approval.lease_digest ||
        preflight.plan_digest !== approval.plan_digest ||
        preflight.scope_reference !== approval.scope_reference ||
        preflight.local_runner_dispatch_allowed !== true ||
        preflight.execution_allowed !== false ||
        preflight.report_submission_allowed !== false ||
        !isFutureExpiry(preflight.expires_at)
      ) {
        throw new Error("fresh_local_lab_preflight_required");
      }
      trialDispatched = true;
      const event = parseBlackBoxRunnerEvent(
        await bridge.runBlackBoxTrial({
          exact_preflight_request: exactPreflightRequest,
          session_alias: preflight.approved_session_alias,
          workflow_alias: preflight.approved_workflow_alias,
        }),
      );
      if (event.event === "stop") {
        setLabRunnerState("stopped");
        pushLog(`本地试验已停止：${formatLabel(event.reason ?? "safety_stop")}。`, "blocked");
        return;
      }
      if (event.event !== "trial_result") {
        throw new Error("bounded_trial_result_required");
      }
      const trace = boundedTraceFromTrialResult(event, completePlan, preflight);
      if (labReviewGeneration.current !== generation) {
        throw new Error("local_lab_result_binding_changed");
      }
      const boundedResult = await recordStudioBlackBoxLabBoundedResult({
        exact_preflight: exactPreflightRequest,
        trace,
      });
      if (
        labReviewGeneration.current !== generation ||
        boundedResult.validation_run_id !== validationRunId ||
        !boundedResult.pipeline_run_id ||
        !/^sha256:[0-9a-f]{64}$/u.test(boundedResult.result_digest) ||
        boundedResult.evidence_ref_count < 1 ||
        boundedResult.execution_allowed !== false ||
        boundedResult.report_submission_allowed !== false ||
        boundedResult.submission_blocked !== true ||
        boundedResult.human_review_required !== true
      ) {
        throw new Error("bounded_result_review_gate_required");
      }
      setLabBoundedResult(boundedResult);
      setLabRunnerState("trial_complete");
      pushLog("已完成一次受限本地差异试验；结果仍仅供审核。", "safe");
      pushLog(
        boundedResult.report_preview_refreshed
          ? "受限结果已记录；报告预览已刷新供人工审核。报告提交仍被阻断。"
          : "受限结果已记录供人工审核。报告提交仍被阻断。",
        "safe",
      );
    } catch (error) {
      if (trialDispatched) {
        setLabRunnerState("stopped");
      }
      pushMutationFailure("完成本地实验室计划", error);
    } finally {
      setBusy(null);
      labDispatchInFlight.current = false;
    }
  }

  async function handleCloseBlackBoxSessions() {
    const bridge = window.mythosStudio;
    if (!bridge || labRunnerState === "idle") {
      pushLog("当前没有打开的本地实验室会话。", "blocked");
      return;
    }
    setBusy("lab-close");
    try {
      const event = parseBlackBoxRunnerEvent(await bridge.closeBlackBoxSessions());
      if (event.event !== "sessions_closed" && event.event !== "stop") {
        throw new Error("sessions_not_closed");
      }
      resetBlackBoxLabState();
      pushLog("本地实验室已停止；临时会话和审核状态已清除。", "safe");
    } catch (error) {
      pushMutationFailure("停止本地实验室", error);
    } finally {
      setBusy(null);
    }
  }

  async function handleOpenWorkspace() {
    if (!workspacePath.trim()) {
      pushLog("打开前请填写本地工作区路径。", "blocked");
      return;
    }
    setBusy("open");
    try {
      const projection = await refreshStudioProjection({
        dependencies: studioRefreshDependencies,
        signal: new AbortController().signal,
        workspacePath,
      });
      if (!projection) {
        pushLog("未找到工作区清单。", "blocked");
        return;
      }
      applyStudioProjection(projection);
      setMissionDossierExport(null);
      setBenchmarkResult(null);
      pushLog("已在本地打开工作区。", "safe");
    } catch (error) {
      pushMutationFailure("打开工作区", error);
    } finally {
      setBusy(null);
    }
  }

  async function handleCreateDesktopBackup() {
    const createBackup = window.mythosStudio?.createBackup;
    if (!createBackup) {
      pushLog("桌面备份仅可在赏金神话研究工作台中使用。", "blocked");
      return;
    }
    setBusy("backup");
    try {
      const result = await createBackup();
      if (result.status !== "created") {
        pushLog("未创建备份，状态未发生变化。", "blocked");
        return;
      }
      pushLog(`已创建本地备份：${result.archive_name}。`, "safe");
    } catch {
      pushLog("备份失败，未记录成功状态。", "blocked");
    } finally {
      setBusy(null);
    }
  }

  async function handleRestoreDesktopBackup() {
    const restoreBackup = window.mythosStudio?.restoreBackup;
    if (!restoreBackup) {
      pushLog("桌面恢复仅可在赏金神话研究工作台中使用。", "blocked");
      return;
    }
    setBusy("restore");
    try {
      const result = await restoreBackup();
      if (result.status !== "restored") {
        pushLog("未恢复备份，当前状态保持生效。", "blocked");
        return;
      }
      pushLog("本地状态已恢复，正在重新加载研究工作台。", "safe");
      window.setTimeout(() => window.location.reload(), 50);
    } catch {
      pushLog("恢复失败，当前状态保持生效。", "blocked");
    } finally {
      setBusy(null);
    }
  }

  async function handleCreateWorkspace() {
    setBusy("workspace");
    try {
      const created = await createStudioWorkspace(
        { name: workspaceName, root_path: workspaceRoot },
      );
      if (!created) {
        pushLog("创建工作区失败，请检查本地 API 是否运行。", "blocked");
        return;
      }
      setWorkspacePath(created.path);
      setManifest(created.manifest);
      setCandidates([]);
      setMissionPanel(toStudioMissionPanel(null));
      setLatestRunId(null);
      setLatestCampaignHunterId(null);
      setReportExport(null);
      setMissionDossierExport(null);
      setBenchmarkResult(null);
      pushLog("已在本地创建工作区。范围守卫正在等待授权输入。", "safe");
    } catch (error) {
      pushMutationFailure("创建工作区", error);
    } finally {
      setBusy(null);
    }
  }

  async function handleImportArtifacts() {
    if (!workspacePath) {
      pushLog("导入资料前请创建或打开工作区。", "blocked");
      return;
    }
    setBusy("import");
    try {
      let updated: StudioWorkspaceManifest | null = manifest;
      for (const artifact of studioArtifactInputs(workspacePath)) {
        if (!artifact.source_path.trim()) {
          continue;
        }
        updated = await importStudioWorkspaceArtifact(
          { ...artifact, workspace_path: workspacePath },
        );
      }
      if (updated) {
        setManifest(updated);
        pushLog("已导入授权资料引用，敏感项目仍需审核。", "safe");
      }
    } catch (error) {
      pushMutationFailure("导入资料", error);
    } finally {
      setBusy(null);
    }
  }

  async function handleSelectPath({
    mode,
    setter,
    title,
  }: {
    mode: "directory" | "file";
    setter: (value: string) => void;
    title: string;
  }) {
    const bridge = window.mythosStudio;
    if (!bridge) {
      pushLog("桌面路径选择器仅可在赏金神话研究工作台中使用。", "blocked");
      return;
    }
    const selected =
      mode === "directory" ? await bridge.selectDirectory() : await bridge.selectFile({ title });
    if (selected) {
      setter(selected);
      pushLog("已选择本地路径，资料内容保持本地且仍需审核。", "safe");
    }
  }

  async function handleStartResearch() {
    if (!researchReadiness.canStart) {
      pushLog(researchReadiness.reason, "blocked");
      return;
    }
    setBusy("research");
    try {
      const run = await runStudioResearchOnce(workspacePath);
      if (run === undefined) {
        return;
      }
      if (!run) {
        pushLog("研究运行未启动，需要范围和代码资料。", "blocked");
        return;
      }
      const projection = await refreshStudioProjection({
        dependencies: studioRefreshDependencies,
        signal: new AbortController().signal,
        workspacePath,
      });
      if (!projection) {
        pushLog("研究投影不可用，未记录成功状态。", "blocked");
        return;
      }
      applyStudioProjection(projection);
      setMissionDossierExport(null);
      setBenchmarkResult(null);
      pushLog(
        `研究运行 ${run.run_id} 产生了 ${run.candidate_count} 个报告提交已阻断的候选。`,
        "safe",
      );
    } catch (error) {
      pushMutationFailure("研究运行", error);
    } finally {
      setBusy(null);
    }
  }

  async function handleLaunchCampaignHunter() {
    if (!researchReadiness.canStart) {
      pushLog(researchReadiness.reason, "blocked");
      return;
    }
    setBusy("campaign-hunter");
    try {
      const launched = await launchStudioWorkspaceCampaignHunter(
        {
          default_asset: "studio-authorized-workspace",
          name: `${workspace.name} campaign hunter`,
          workspace_path: workspacePath,
        },
      );
      if (!launched) {
        pushLog("项目候选挖掘启动失败，请检查已导入的 API、HAR 和代码资料。", "blocked");
        return;
      }
      setManifest(launched.manifest);
      setLatestRunId(null);
      setLatestCampaignHunterId(launched.campaign.id);
      setCandidates(toStudioCampaignHunterCandidateCards(launched.control_center));
      setReportExport(null);
      setMissionDossierExport(null);
      setBenchmarkResult(null);
      const suggestionCount = launched.control_center.research_queue_suggestions?.length ?? 0;
      pushLog(
        `项目候选挖掘 ${launched.campaign.id} 已启动，包含 ${suggestionCount} 条需要审核的建议。`,
        "safe",
      );
    } catch (error) {
      pushMutationFailure("启动项目候选挖掘", error);
    } finally {
      setBusy(null);
    }
  }

  async function handleRecordCandidateHunterLearning(
    action: ReturnType<typeof toStudioMissionPanel>["candidateHunterExecutionLoop"]["learningReviewActions"][number],
  ) {
    const outcome = toCandidateHunterLearningOutcome(action.suggestedOutcome);
    setBusy(`learning:${action.actionId}`);
    try {
      const profile = await recordCandidateHunterLearningOutcome(
        {
          candidate_id: action.candidateId,
          evidence_ready: action.evidenceReady,
          learning_evidence_needed_reasons: action.learningEvidenceNeededReasons,
          missing_evidence: action.missingEvidence,
          missing_required_artifact_kinds: action.missingRequiredArtifactKinds,
          notes: `${action.nextAction}；验证和报告提交仍保持阻断。`,
          outcome,
          playbook_id: action.learningSignalTemplate?.playbookId,
          reviewer: "studio-human-review",
          run_id: latestRunId,
          surface_key: action.learningSignalTemplate?.surfaceKey ?? action.candidateId,
          target_relationships: action.learningSignalTemplate?.targetRelationships,
          trace_status: action.traceStatus,
        },
      );
      setLearningProfile(profile);
      pushLog(
        `已为 ${action.candidateId} 记录${formatLabel(outcome)}学习反馈。`,
        "safe",
        "operator",
      );
    } catch (error) {
      pushMutationFailure("学习反馈", error);
    } finally {
      setBusy(null);
    }
  }

  async function handleRecordCandidateCardLearning(
    candidate: ReturnType<typeof toStudioCandidateCards>[number],
    outcome: CandidateHunterLearningOutcome,
  ) {
    setBusy(`candidate-learning:${candidate.id}:${outcome}`);
    try {
      const profile = await recordCandidateHunterLearningOutcome(
        {
          candidate_id: candidate.id,
          evidence_ready: false,
          learning_evidence_needed_reasons: candidate.evidenceGaps,
          missing_evidence: candidate.evidenceNeeds,
          missing_required_artifact_kinds:
            candidate.evidenceTraceSummary.missingRequiredArtifactKinds,
          notes: `${candidate.reportReadiness.nextAllowedAction}；人工结果：${formatLabel(outcome)}；验证和报告提交仍保持阻断。`,
          outcome,
          playbook_id: candidate.title,
          reviewer: "studio-human-review",
          run_id: latestRunId,
          surface_key: candidate.affectedEndpoint,
          trace_status: candidate.evidenceTraceSummary.status,
        },
      );
      setLearningProfile(profile);
      pushLog(`已为 ${candidate.id} 记录${formatLabel(outcome)}学习反馈。`, "safe", "operator");
    } catch (error) {
      pushMutationFailure("学习反馈", error);
    } finally {
      setBusy(null);
    }
  }

  async function handleExportReport() {
    if (!workspacePath || (!latestRunId && !latestCampaignHunterId)) {
      pushLog("导出报告预览前请先运行研究或启动项目候选挖掘。", "blocked");
      return;
    }
    setBusy("export");
    try {
      const exported = latestRunId
        ? await exportStudioWorkspaceReport(
            { run_id: latestRunId, workspace_path: workspacePath },
          )
        : await exportStudioWorkspaceCampaignHunterReport(
            { campaign_id: latestCampaignHunterId ?? "", workspace_path: workspacePath },
          );
      if (!exported) {
        pushLog("导出报告预览失败。", "blocked");
        return;
      }
      setReportExport(exported);
      setManifest(exported.manifest);
      if (latestRunId) {
        await refreshMissionPanel(workspacePath, latestRunId);
      }
      pushLog("已导出报告预览，报告提交仍被阻断。", "safe");
    } catch (error) {
      pushMutationFailure("导出报告预览", error);
    } finally {
      setBusy(null);
    }
  }

  async function handleExportMissionDossier() {
    if (!workspacePath || !latestRunId) {
      pushLog("导出任务档案前请先运行研究。", "blocked");
      return;
    }
    setBusy("mission-dossier");
    try {
      const exported = await exportStudioWorkspaceMissionDossier(
        { run_id: latestRunId, workspace_path: workspacePath },
      );
      if (!exported) {
        pushLog("导出任务档案失败。", "blocked");
        return;
      }
      setMissionDossierExport(exported);
      setManifest(exported.manifest);
      await refreshMissionPanel(workspacePath, latestRunId);
      pushLog("已在本地导出任务档案，验证与报告提交仍被阻断。", "safe");
    } catch (error) {
      pushMutationFailure("导出任务档案", error);
    } finally {
      setBusy(null);
    }
  }

  async function handleRunBenchmark() {
    if (!workspacePath || !latestRunId) {
      pushLog("进行候选基准测试前请先运行研究。", "blocked");
      return;
    }
    if (!expectationsPath.trim()) {
      pushLog("进行基准测试前请选择本地基准期望结果文件。", "blocked");
      return;
    }
    setBusy("benchmark");
    try {
      const benchmark = await runStudioWorkspaceBenchmark(
        {
          expectations_path: expectationsPath,
          run_id: latestRunId,
          workspace_path: workspacePath,
        },
      );
      if (!benchmark) {
        pushLog("候选基准测试运行失败。", "blocked");
        return;
      }
      setBenchmarkResult(benchmark);
      setManifest(benchmark.manifest);
      await refreshMissionPanel(workspacePath, latestRunId);
      pushLog(
        `候选基准测试${formatLabel(benchmark.benchmark.status ?? "finished")}：${benchmark.benchmark.matched ?? 0}/${benchmark.benchmark.expected_count ?? 0} 个期望候选已匹配。`,
        benchmark.benchmark.status === "passed" ? "safe" : "blocked",
      );
    } catch (error) {
      pushMutationFailure("候选基准测试", error);
    } finally {
      setBusy(null);
    }
  }

  async function handleCreateBenchmarkTemplate() {
    if (!workspacePath || !latestRunId) {
      pushLog("创建基准模板前请先运行研究。", "blocked");
      return;
    }
    setBusy("benchmark-template");
    try {
      const template = await createStudioWorkspaceBenchmarkTemplate(
        {
          run_id: latestRunId,
          workspace_path: workspacePath,
        },
      );
      if (!template) {
        pushLog("未创建基准模板。", "blocked");
        return;
      }
      setManifest(template.manifest);
      if (template.template_path) {
        setExpectationsPath(template.template_path);
      }
      await refreshMissionPanel(workspacePath, latestRunId);
      pushLog("已创建基准期望结果模板，等待人工审核。", "safe");
    } catch (error) {
      pushMutationFailure("基准模板", error);
    } finally {
      setBusy(null);
    }
  }

  function pushLog(
    message: string,
    tone: LogEntry["tone"],
    actor: LogEntry["actor"] = "system",
  ) {
    setLog((entries) => [{ actor, message, tone }, ...entries].slice(0, 6));
  }

  function pushMutationFailure(action: string, error: unknown) {
    const status = error instanceof ApiRequestError && error.status > 0 ? `（API ${error.status}）` : "";
    pushLog(`${action}失败${status}，未记录成功状态。`, "blocked");
  }

  async function refreshMissionPanel(path: string, runId: string | null) {
    const mission = await getStudioWorkspaceMission(path, runId, null);
    setMissionPanel(toStudioMissionPanel(mission));
  }

  function studioArtifactInputs(path: string) {
    return [
      { kind: "policy", source_path: policyPath, workspace_path: path },
      { kind: "scope", source_path: scopePath, workspace_path: path },
      { kind: "code", source_path: codePath, workspace_path: path },
      { kind: "api", source_path: apiPath, workspace_path: path },
      { kind: "har", source_path: harPath, workspace_path: path },
      { kind: "sbom", source_path: sbomPath, workspace_path: path },
      { kind: "sarif", source_path: sarifPath, workspace_path: path },
      { kind: "fuzzing", source_path: fuzzingPath, workspace_path: path },
      { kind: "strategy", source_path: strategyPath, workspace_path: path },
      { kind: "knowledge", source_path: knowledgePath, workspace_path: path },
    ];
  }

  const nextSafeAction =
    currentWizardStep === "workspace"
      ? {
          busy: false,
          disabled: true,
          icon: <FolderPlus size={16} aria-hidden="true" />,
          label: "请在导航中完成工作区设置",
          onClick: () => undefined,
        }
      : currentWizardStep === "authorized_materials"
        ? {
            busy: busy === "import",
            disabled: !workspacePath,
            icon: <Upload size={16} aria-hidden="true" />,
            label: "导入授权材料",
            onClick: handleImportArtifacts,
          }
        : currentWizardStep === "readiness_check"
          ? {
              busy: busy === "research",
              disabled: !researchReadiness.canStart,
              icon: <Play size={16} aria-hidden="true" />,
              label: "开始本地研究",
              onClick: handleStartResearch,
            }
          : {
              busy: false,
              disabled: studioView.selectedCandidate === null,
              icon: <ShieldCheck size={16} aria-hidden="true" />,
              label: "审查所选候选",
              onClick: () => setInspectorTab("candidate"),
            };

  const studioCandidateList = (
    <div className="grid gap-1" data-testid="studio-candidate-list">
      {studioView.candidates.length === 0 ? (
        <p className="py-3 text-xs text-[var(--muted)]">暂无候选。导入授权材料后开始本地研究。</p>
      ) : (
        studioView.candidates.map((candidate) => (
          <button
            className={`grid min-h-14 gap-1 rounded-sm border-l-2 px-3 py-2 text-left outline-none transition-colors focus-visible:ring-2 focus-visible:ring-[var(--accent)] ${
              studioView.selectedCandidate?.id === candidate.id
                ? "border-[var(--accent)] bg-[var(--accent-surface)]"
                : "border-transparent hover:bg-[var(--surface-raised)]"
            }`}
            key={candidate.id}
            onClick={() => setSelectedCandidateId(candidate.id)}
            type="button"
          >
            <span className="flex items-center justify-between gap-2">
              <span className="truncate font-mono text-xs">{candidate.id}</span>
              <span className="text-[10px] text-[var(--warning)]">{formatLabel(candidate.status)}</span>
            </span>
            <span className="truncate text-xs text-[var(--muted)]">{candidate.title}</span>
          </button>
        ))
      )}
    </div>
  );

  const studioNavigation = (
    <div className="grid gap-4 text-sm">
      <nav aria-label="研究工作台分区" className="grid gap-1">
        {[
          ["#studio-mission", "研究任务"],
          ["#studio-artifacts", "授权材料"],
          ["#studio-lab", "安全验证"],
          ["#studio-candidates", "候选审查"],
        ].map(([href, label], index) => (
          <a
            className={`rounded-sm border-l-2 px-3 py-2 transition-colors hover:bg-[var(--surface-raised)] focus-visible:ring-2 focus-visible:ring-[var(--accent)] ${index === 0 ? "border-[var(--accent)] bg-[var(--accent-surface)]" : "border-transparent text-[var(--muted)]"}`}
            href={href}
            key={href}
          >
            {label}
          </a>
        ))}
      </nav>
      <div className="border-t border-[var(--line)] pt-4">
        <TextField
          browseEnabled={desktopPickerAvailable}
          label="工作区路径"
          onBrowse={() =>
            handleSelectPath({
              mode: "directory",
              setter: setWorkspacePath,
              title: "选择研究工作台工作区",
            })
          }
          onChange={setWorkspacePath}
          value={workspacePath}
        />
        <ActionButton
          busy={busy === "open"}
          icon={<FolderOpen size={16} aria-hidden="true" />}
          label="打开工作区"
          onClick={handleOpenWorkspace}
        />
        <div className="mt-4 grid gap-3 border-t border-[var(--line)] pt-4">
          <TextField
            browseEnabled={desktopPickerAvailable}
            label="工作区根目录"
            onBrowse={() =>
              handleSelectPath({
                mode: "directory",
                setter: setWorkspaceRoot,
                title: "选择工作区根目录",
              })
            }
            value={workspaceRoot}
            onChange={setWorkspaceRoot}
          />
          <TextField label="工作区名称" value={workspaceName} onChange={setWorkspaceName} />
          <ActionButton
            busy={busy === "workspace"}
            icon={<FolderPlus size={16} aria-hidden="true" />}
            label="创建工作区"
            onClick={handleCreateWorkspace}
          />
        </div>
      </div>
      {desktopBackupAvailable ? (
        <div className="grid gap-2 border-t border-[var(--line)] pt-4" data-testid="desktop-data-recovery">
          <p className="text-xs font-semibold text-[var(--muted)]">本地数据恢复</p>
          <div className="grid gap-2 sm:grid-cols-2">
            <ActionButton
              busy={busy === "backup"}
              icon={<FileDown size={16} aria-hidden="true" />}
              label="创建备份"
              onClick={handleCreateDesktopBackup}
            />
            <ActionButton
              busy={busy === "restore"}
              icon={<Upload size={16} aria-hidden="true" />}
              label="恢复备份"
              onClick={handleRestoreDesktopBackup}
            />
          </div>
        </div>
      ) : null}
      <dl className="grid gap-2 border-t border-[var(--line)] pt-4 text-xs">
        <StatusRow label="范围守卫" value={formatLabel(workspace.scopeGuardLabel)} warning />
        <StatusRow label="授权材料" value={String(workspace.artifactCount)} />
        <StatusRow label="研究运行" value={String(workspace.runCount)} />
      </dl>
      <div className="border-t border-[var(--line)] pt-4">
        <p className="mb-2 text-xs font-semibold text-[var(--muted)]">候选队列</p>
        {studioCandidateList}
      </div>
    </div>
  );

  const inspectorTabs = [
    { id: "candidate", label: "候选详情" },
    { id: "evidence", label: "证据" },
    { id: "validation", label: "验证计划" },
    { id: "report", label: "报告草稿" },
  ] as const;
  const studioInspector = (
    <Tabs
      className="!block w-full gap-0"
      data-testid="studio-inspector"
      onValueChange={(value) =>
        setInspectorTab(value as "candidate" | "evidence" | "report" | "validation")
      }
      value={inspectorTab}
    >
      <TabsList
        aria-label="候选检查器"
        className="!grid h-10 !w-full grid-cols-4 rounded-none border-b border-[var(--line)] bg-transparent p-0"
        variant="line"
      >
        {inspectorTabs.map((tab) => (
          <TabsTrigger
            className="min-w-0 whitespace-nowrap rounded-none px-1 text-xs"
            key={tab.id}
            tabIndex={tab.id === inspectorTab ? 0 : -1}
            value={tab.id}
          >
            {tab.label}
          </TabsTrigger>
        ))}
      </TabsList>
      <TabsContent className="pt-4" tabIndex={-1} value="candidate">
          <CandidateInspector
            actions={studioView.selectedCandidate ? (
              <>
                <ActionButton
                  busy={busy === `candidate-learning:${studioView.selectedCandidate.id}:needs_more_evidence`}
                  icon={<ShieldCheck size={16} aria-hidden="true" />}
                  label="记录需补充证据的学习结果"
                  onClick={() => handleRecordCandidateCardLearning(studioView.selectedCandidate!, "needs_more_evidence")}
                />
                <ActionButton
                  busy={busy === `candidate-learning:${studioView.selectedCandidate.id}:refuted`}
                  icon={<ShieldCheck size={16} aria-hidden="true" />}
                  label="记录已反证的学习结果"
                  onClick={() => handleRecordCandidateCardLearning(studioView.selectedCandidate!, "refuted")}
                />
                <ActionButton
                  busy={busy === `candidate-learning:${studioView.selectedCandidate.id}:duplicate`}
                  icon={<ShieldCheck size={16} aria-hidden="true" />}
                  label="记录重复项学习结果"
                  onClick={() => handleRecordCandidateCardLearning(studioView.selectedCandidate!, "duplicate")}
                />
              </>
            ) : null}
            candidate={studioView.selectedCandidate}
            candidates={studioView.candidates}
            onSelect={setSelectedCandidateId}
          />
      </TabsContent>
      <TabsContent className="pt-4" tabIndex={-1} value="evidence">
        <EvidenceInspector candidate={studioView.selectedCandidate} />
      </TabsContent>
      <TabsContent className="pt-4" tabIndex={-1} value="validation">
        <ValidationPlanInspector candidate={studioView.selectedCandidate} />
      </TabsContent>
      <TabsContent className="pt-4" tabIndex={-1} value="report">
          <ReportInspector
            actions={(
              <>
                <ActionButton
                  busy={busy === "export"}
                  disabled={!latestRunId && !latestCampaignHunterId}
                  icon={<FileDown size={16} aria-hidden="true" />}
                  label="导出报告预览"
                  onClick={handleExportReport}
                />
                <ActionButton
                  busy={busy === "mission-dossier"}
                  disabled={!latestRunId}
                  icon={<FileDown size={16} aria-hidden="true" />}
                  label="导出任务档案"
                  onClick={handleExportMissionDossier}
                />
              </>
            )}
            candidate={studioView.selectedCandidate}
            dossierPaths={[
              missionDossierExport?.mission_dossier_markdown_path,
              missionDossierExport?.agent_queue_markdown_path,
            ].filter((path): path is string => Boolean(path))}
            markdownPath={reportExport?.report_markdown_path}
          />
      </TabsContent>
    </Tabs>
  );

  return (
    <StudioShell
      candidates={studioCandidateList}
      connectionLabel={`实时连接：${connectionState}`}
      inspector={studioInspector}
      navigation={studioNavigation}
      safetyLabel="报告提交已阻断"
      workspaceName={workspace.name}
    >
      <div className="min-w-0 [&_.bg-white]:!bg-[var(--surface)]">
      <header className="border-b border-[var(--line)] pb-5" id="studio-mission">
        <p className="flex items-center gap-2 text-sm font-semibold text-[var(--accent-strong)]">
          <ShieldCheck size={17} aria-hidden="true" />
          赏金神话研究工作台
        </p>
        <h1 className="mt-3 max-w-4xl text-3xl font-semibold leading-tight text-balance">
          授权研究工作台
        </h1>
      </header>

      <MissionStageStrip
        activeStage={missionPanel.researchLoopStages.find((stage) => !/complete|done|passed/i.test(stage.status))?.key ?? ""}
        stages={missionPanel.researchLoopStages}
      />

      <ResearchConversation
        messages={log}
        runId={missionPanel.runId}
      />

      <ProgramRuleIntake />

      <section className="mt-6 border-b border-[var(--line)] pb-5" id="studio-artifacts">
        <SectionHeader title="本地研究设置" />
        <div className="grid gap-3 p-5 text-sm md:grid-cols-4">
          {wizardSteps.map((step, index) => (
            <div
              className={`border-t border-[var(--line)] p-3 ${
                step.id === currentWizardStep ? "bg-[var(--background)]" : "bg-white"
              }`}
              key={step.id}
            >
              <p className="text-xs font-semibold uppercase text-[var(--muted)]">
                {index + 1}. {step.label}
              </p>
              <p className="mt-2 font-semibold">{step.detail}</p>
            </div>
          ))}
        </div>
        <div className="flex flex-wrap items-center gap-3 border-t border-[var(--line)] p-5 text-sm">
          <p className="font-semibold">建议的安全操作</p>
          <ActionButton
            busy={nextSafeAction.busy}
            disabled={nextSafeAction.disabled}
            icon={nextSafeAction.icon}
            label={nextSafeAction.label}
            onClick={nextSafeAction.onClick}
          />
          <ActionButton
            busy={busy === "campaign-hunter"}
            disabled={!researchReadiness.canStart}
            icon={<ShieldCheck size={16} aria-hidden="true" />}
            label="启动项目候选挖掘"
            onClick={handleLaunchCampaignHunter}
          />
        </div>
        <div className="border-t border-[var(--line)] p-5 text-sm">
          <label className="flex items-start gap-3">
            <input
              checked={candidateModelEnabled}
              className="mt-1"
              onChange={(event) => setCandidateModelEnabled(event.target.checked)}
              type="checkbox"
            />
            <span>
              <span className="block font-semibold">仅在下一次运行中启用模型辅助</span>
              <span className="mt-1 block text-[var(--muted)]">
                可选建议仍未验证，所有凭据均只保留在后端环境中。
              </span>
            </span>
          </label>
          {candidateModelEnabled ? (
            <div className="mt-4 grid gap-3 md:grid-cols-2">
              <label className="grid gap-2 text-sm font-medium">
                模型提供方
                <select
                  className="border border-[var(--line)] bg-white px-3 py-2.5 outline-none focus:border-[var(--accent)]"
                  onChange={(event) =>
                    setCandidateModelProvider(
                      event.target.value as "openai" | "claude" | "deepseek",
                    )
                  }
                  value={candidateModelProvider}
                >
                  <option value="openai">OpenAI</option>
                  <option value="claude">Claude</option>
                  <option value="deepseek">DeepSeek</option>
                </select>
              </label>
              <TextField
                label="模型名称"
                onChange={setCandidateModelName}
                value={candidateModelName}
              />
            </div>
          ) : null}
        </div>
        <div className="grid gap-3 border-t border-[var(--line)] p-5 text-sm md:grid-cols-2">
          <div>
            <p className="font-semibold">必需输入</p>
            <p className="mt-2 text-[var(--muted)]">
              {missingRequiredArtifacts.length === 0
                ? "必需输入已就绪。"
                : `缺少必需输入：${missingRequiredArtifacts
                    .map((item) => item.label)
                    .join(", ")}`}
            </p>
          </div>
          <div>
            <p className="font-semibold">可选上下文</p>
            <p className="mt-2 text-[var(--muted)]">
              {optionalContextArtifacts.map((item) => `${item.label}：${formatLabel(item.status)}`).join("、")}
            </p>
          </div>
        </div>
      </section>

      <section className="mt-6 border border-[var(--line)] bg-white">
        <SectionHeader title="远程人工租约配置（只读）" />
        <div className="grid gap-4 p-5 text-sm">
          <div className="flex flex-wrap items-start justify-between gap-3">
            <p className="max-w-3xl text-[var(--muted)]">{remoteStatusView.detail}</p>
            <ActionButton
              busy={busy === "remote-status"}
              disabled={Boolean(busy) && busy !== "remote-status"}
              icon={<ShieldCheck size={16} aria-hidden="true" />}
              label="刷新远程状态"
              onClick={handleRefreshRemoteStatus}
            />
          </div>
          <dl className="grid gap-3 sm:grid-cols-3">
            <StatusRow
              label="租约状态"
              value={remoteStatusView.label}
              warning={remoteStatusView.warning}
            />
            <StatusRow
              label="需要重新登录"
              value={remoteReloginRequired ? "是" : "否"}
              warning={remoteReloginRequired}
            />
            <StatusRow label="报告提交" value="已阻断" />
          </dl>
          <p className="text-xs text-[var(--muted)]">
            报告提交与人工确认均保持阻断。任何首次真实运行都必须由用户操作并使用新的专项批准；
            此处不提供后台调度、重试、发现或 CI 执行。
          </p>
        </div>
      </section>

      <section className="mt-6 border-y border-[var(--line)]" id="studio-lab">
        <SectionHeader title="本地黑盒实验室（显式启用）" />
        <details className="p-5 text-sm">
          <summary className="cursor-pointer font-semibold">启用显式本地黑盒实验室</summary>
          <div className="mt-4 grid gap-4">
            <p className="text-[var(--muted)]">
              仅限回环地址、两个隔离会话、一个声明的只读工作流和一次经批准的回放。仅使用临时状态，
              不会写入工作区清单。
            </p>
            <div className="grid gap-3 md:grid-cols-2">
              <label className="grid gap-1 text-sm">
                <span className="text-xs font-semibold uppercase text-[var(--muted)]">
                  当前回环来源
                </span>
                <input
                  className="min-h-10 rounded-md border border-[var(--line)] bg-white px-3 outline-none focus:border-[var(--accent)] disabled:opacity-60"
                  disabled={labRunnerState !== "idle"}
                  onChange={(event) => handleLabOriginChange(event.target.value)}
                  value={labOrigin}
                />
              </label>
              <label className="grid gap-1 text-sm">
                <span className="text-xs font-semibold uppercase text-[var(--muted)]">
                  持久化验证运行 ID
                </span>
                <input
                  className="min-h-10 rounded-md border border-[var(--line)] bg-white px-3 outline-none focus:border-[var(--accent)] disabled:opacity-60"
                  disabled={Boolean(busy)}
                  onChange={(event) => handleLabValidationRunIdChange(event.target.value)}
                  value={labValidationRunId}
                />
              </label>
            </div>
            <div className="grid gap-3 md:grid-cols-2">
              <label className="flex items-center gap-3 border border-[var(--line)] p-3">
                <input
                  checked={labSessionAReady}
                  disabled={labRunnerState !== "awaiting_sessions_ready"}
                  onChange={(event) =>
                    handleLabSessionReadiness("session_a", event.target.checked)
                  }
                  type="checkbox"
                />
                <span>会话 A 已就绪</span>
              </label>
              <label className="flex items-center gap-3 border border-[var(--line)] p-3">
                <input
                  checked={labSessionBReady}
                  disabled={labRunnerState !== "awaiting_sessions_ready"}
                  onChange={(event) =>
                    handleLabSessionReadiness("session_b", event.target.checked)
                  }
                  type="checkbox"
                />
                <span>会话 B 已就绪</span>
              </label>
            </div>
            <div className="flex flex-wrap gap-2">
              <ActionButton
                busy={busy === "lab-preview"}
                disabled={
                  Boolean(busy) ||
                  !["idle", "awaiting_sessions_ready"].includes(labRunnerState)
                }
                icon={<ShieldCheck size={16} aria-hidden="true" />}
                label="预览受限租约"
                onClick={handlePreviewBlackBoxLabLease}
              />
              <ActionButton
                busy={busy === "lab-create-sessions"}
                disabled={
                  Boolean(busy) ||
                  !desktopPickerAvailable ||
                  !labLeaseRequestSnapshot ||
                  labRunnerState !== "idle"
                }
                icon={<FolderPlus size={16} aria-hidden="true" />}
                label="创建两个会话"
                onClick={handleCreateBlackBoxSessions}
              />
              <ActionButton
                busy={busy === "lab-start-recording"}
                disabled={
                  Boolean(busy) ||
                  !labLeasePreview?.sessions_ready ||
                  labRunnerState !== "awaiting_sessions_ready"
                }
                icon={<Play size={16} aria-hidden="true" />}
                label="开始录制"
                onClick={handleStartBlackBoxRecording}
              />
              <ActionButton
                busy={busy === "lab-stop-recording"}
                disabled={Boolean(busy) || labRunnerState !== "recording"}
                icon={<ShieldCheck size={16} aria-hidden="true" />}
                label="停止录制"
                onClick={handleStopBlackBoxRecording}
              />
              <ActionButton
                busy={false}
                disabled={
                  Boolean(busy) ||
                  labTraceReview.length === 0 ||
                  labRunnerState !== "sessions_ready"
                }
                icon={<ShieldCheck size={16} aria-hidden="true" />}
                label="审查标准化轨迹"
                onClick={handleReviewBlackBoxTraces}
              />
              <ActionButton
                busy={busy === "lab-approve"}
                disabled={
                  Boolean(busy) ||
                  !labTraceReviewConfirmed ||
                  !labValidationRunId.trim() ||
                  labRunnerState !== "sessions_ready"
                }
                icon={<ShieldCheck size={16} aria-hidden="true" />}
                label="审查并批准完整计划"
                onClick={handleApproveBlackBoxLabRun}
              />
              <ActionButton
                busy={busy === "lab-close"}
                disabled={Boolean(busy) || labRunnerState === "idle"}
                icon={<ShieldCheck size={16} aria-hidden="true" />}
                label="停止本地实验室"
                onClick={handleCloseBlackBoxSessions}
              />
            </div>
            <dl className="grid gap-3 sm:grid-cols-4">
              <StatusRow label="运行器状态" value={formatLabel(labRunnerState)} />
              <StatusRow
                label="租约审查"
                value={labLeasePreview ? "已审查" : "需要审查"}
                warning={!labLeasePreview}
              />
              <StatusRow
                label="人工轨迹审查"
                value={labTraceReviewConfirmed ? "已确认" : "需要审查"}
                warning={!labTraceReviewConfirmed}
              />
              <StatusRow
                label="受限结果"
                value={labBoundedResult ? "已记录" : "未记录"}
                warning={!labBoundedResult}
              />
            </dl>
            {labBoundedResult ? (
              <p className="text-xs text-[var(--muted)]">
                {labBoundedResult.report_preview_refreshed
                  ? "已根据受限本地实验结果刷新报告预览；仍需人工审核。"
                  : "受限本地实验结果已记录；仍需人工审核。"}
              </p>
            ) : null}
            {labTraceReview.length > 0 ? (
              <div className="border-t border-[var(--line)] pt-4">
                <p className="font-semibold">标准化轨迹</p>
                <ul className="mt-2 grid gap-2 text-xs text-[var(--muted)]">
                  {labTraceReview.map((trace) => (
                    <li key={`${trace.session_alias}-${trace.workflow_alias}`}>
                      {trace.session_alias} / {trace.workflow_alias} / {trace.route_template} /{" "}
                      {trace.response_schema_fingerprint}
                    </li>
                  ))}
                </ul>
              </div>
            ) : null}
          </div>
        </details>
      </section>

      <div className="mt-6 grid min-w-0 gap-5">
        <section className="min-w-0 border-b border-[var(--line)] pb-5">
          <SectionHeader title="授权材料与评估" />
          <div className="grid gap-4 p-5 text-sm">
            <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-4">
              <TextField
                browseEnabled={desktopPickerAvailable}
                label="策略文件"
                onBrowse={() =>
                  handleSelectPath({
                    mode: "file",
                    setter: setPolicyPath,
                    title: "选择策略文件",
                  })
                }
                value={policyPath}
                onChange={setPolicyPath}
              />
              <TextField
                browseEnabled={desktopPickerAvailable}
                label="范围文件"
                onBrowse={() =>
                  handleSelectPath({
                    mode: "file",
                    setter: setScopePath,
                    title: "选择范围文件",
                  })
                }
                value={scopePath}
                onChange={setScopePath}
              />
              <TextField
                browseEnabled={desktopPickerAvailable}
                label="代码目录"
                onBrowse={() =>
                  handleSelectPath({
                    mode: "directory",
                    setter: setCodePath,
                    title: "选择授权代码目录",
                  })
                }
                value={codePath}
                onChange={setCodePath}
              />
              <TextField
                browseEnabled={desktopPickerAvailable}
                label="API 文件"
                onBrowse={() =>
                  handleSelectPath({
                    mode: "file",
                    setter: setApiPath,
                    title: "选择 API 资料",
                  })
                }
                value={apiPath}
                onChange={setApiPath}
              />
              <TextField
                browseEnabled={desktopPickerAvailable}
                label="HAR 文件"
                onBrowse={() =>
                  handleSelectPath({
                    mode: "file",
                    setter: setHarPath,
                    title: "选择 HAR 文件",
                  })
                }
                value={harPath}
                onChange={setHarPath}
              />
              <TextField
                browseEnabled={desktopPickerAvailable}
                label="SBOM 文件"
                onBrowse={() =>
                  handleSelectPath({
                    mode: "file",
                    setter: setSbomPath,
                    title: "选择 SBOM 文件",
                  })
                }
                value={sbomPath}
                onChange={setSbomPath}
              />
              <TextField
                browseEnabled={desktopPickerAvailable}
                label="SARIF 文件"
                onBrowse={() =>
                  handleSelectPath({
                    mode: "file",
                    setter: setSarifPath,
                    title: "选择 SARIF 文件",
                  })
                }
                value={sarifPath}
                onChange={setSarifPath}
              />
              <TextField
                browseEnabled={desktopPickerAvailable}
                label="模糊测试计划"
                onBrowse={() =>
                  handleSelectPath({
                    mode: "file",
                    setter: setFuzzingPath,
                    title: "选择模糊测试计划",
                  })
                }
                value={fuzzingPath}
                onChange={setFuzzingPath}
              />
              <TextField
                browseEnabled={desktopPickerAvailable}
                label="策略说明"
                onBrowse={() =>
                  handleSelectPath({
                    mode: "file",
                    setter: setStrategyPath,
                    title: "选择策略说明",
                  })
                }
                value={strategyPath}
                onChange={setStrategyPath}
              />
              <TextField
                browseEnabled={desktopPickerAvailable}
                label="知识文件"
                onBrowse={() =>
                  handleSelectPath({
                    mode: "file",
                    setter: setKnowledgePath,
                    title: "选择知识模式文件",
                  })
                }
                value={knowledgePath}
                onChange={setKnowledgePath}
              />
            </div>
            <div className="border-t border-[var(--line)] p-4">
              <p className="font-semibold">资料就绪状态</p>
              <div className="mt-3 grid gap-2 sm:grid-cols-2 xl:grid-cols-3">
                {artifactChecklist.map((item) => (
                  <span
                    className={`border-l-2 border-[var(--line)] px-3 py-2 ${checklistTone(item.status)}`}
                    key={item.kind}
                  >
                    {item.label}：{formatLabel(item.status)}
                  </span>
                ))}
              </div>
              <p className="mt-3 text-[var(--muted)]">{researchReadiness.reason}</p>
            </div>
            <div className="border-t border-[var(--line)] p-4">
              <p className="font-semibold">A+B 基准测试</p>
              <div className="mt-3 grid gap-3 md:grid-cols-[minmax(0,1fr)_auto]">
                <TextField
                  browseEnabled={desktopPickerAvailable}
                  label="期望结果文件"
                  onBrowse={() =>
                    handleSelectPath({
                      mode: "file",
                      setter: setExpectationsPath,
                      title: "选择基准期望结果文件",
                    })
                  }
                  value={expectationsPath}
                  onChange={setExpectationsPath}
                />
                <div className="flex items-end">
                  <div className="flex flex-wrap gap-2">
                    <ActionButton
                      busy={busy === "benchmark-template"}
                      disabled={!latestRunId}
                      icon={<FileDown size={16} aria-hidden="true" />}
                      label="创建模板"
                      onClick={handleCreateBenchmarkTemplate}
                    />
                    <ActionButton
                      busy={busy === "benchmark"}
                      disabled={!latestRunId}
                      icon={<ShieldCheck size={16} aria-hidden="true" />}
                      label="运行基准测试"
                      onClick={handleRunBenchmark}
                    />
                  </div>
                </div>
              </div>
              {benchmarkResult ? (
                <div className="mt-4 space-y-3">
                  <dl className="grid gap-3 sm:grid-cols-3">
                    <StatusRow
                      label="基准测试"
                      value={formatLabel(benchmarkResult.benchmark.status)}
                      warning={benchmarkResult.benchmark.status !== "passed"}
                    />
                    <StatusRow
                      label="匹配数"
                      value={`${benchmarkResult.benchmark.matched ?? 0}/${benchmarkResult.benchmark.expected_count ?? 0}`}
                    />
                    <StatusRow
                      label="结果路径"
                      value={benchmarkResult.benchmark_path ?? "暂无结果路径"}
                    />
                  </dl>
                  {benchmarkEvidenceGaps.length > 0 ? (
                    <div>
                      <p className="text-xs font-semibold uppercase text-[var(--muted)]">
                        证据缺口
                      </p>
                      <ul className="mt-2 space-y-1 text-xs text-[var(--muted)]">
                        {benchmarkEvidenceGaps.map((gap, index) => (
                          <li key={`${gap.name ?? "gap"}-${gap.artifact_kind ?? "artifact"}-${index}`}>
                            {gap.name ?? "候选"}：{gap.artifact_kind ?? "资料"} -{" "}
                            {formatLabel(gap.reason)}
                          </li>
                        ))}
                      </ul>
                    </div>
                  ) : null}
                </div>
              ) : null}
            </div>
            <div className="border-t border-[var(--line)] p-4">
              <p className="font-semibold">研究意图</p>
              <p className="mt-2 text-[var(--muted)]">
                访问控制、角色边界、优先反证。
              </p>
            </div>
          </div>
        </section>

        <section className="min-w-0 border-b border-[var(--line)] pb-5" data-testid="studio-mission-details">
          <SectionHeader title="任务详情" />
          <div className="grid gap-4 p-5 text-sm">
            <div className="border-t border-[var(--line)] pt-4">
              <p className="font-semibold">任务控制</p>
              <dl className="mt-3 grid gap-3">
                <StatusRow label="模式" value={formatLabel(missionPanel.modeLabel)} />
                <StatusRow label="运行" value={missionPanel.runId} />
                <StatusRow label="范围守卫" value={formatLabel(missionPanel.scopeGuardLabel)} warning />
                <StatusRow label="资料覆盖度" value={missionPanel.artifactCoverage} />
                <StatusRow label="参考上下文" value={formatLabel(missionPanel.advisoryContextLabel)} />
                <StatusRow label="候选数" value={missionPanel.candidateCountLabel} />
                <StatusRow
                  label="报告审批门"
                  value={missionPanel.gates.submissionBlocked ? "报告提交已阻断" : "需要审核"}
                  warning
                />
                <StatusRow
                  label="验证审批门"
                  value={
                    missionPanel.gates.validationExecutionAllowed
                      ? "需要人工审核"
                      : "执行已阻断"
                  }
                  warning
                />
                <StatusRow
                  label="候选质量"
                  value={`${formatLabel(missionPanel.qualitySummary.topCandidateQualityGate)}（${missionPanel.qualitySummary.reviewReadyCount}/${missionPanel.qualitySummary.candidateCount} 已可审核，平均 ${missionPanel.qualitySummary.averageQualityScore}）`}
                  warning={!missionPanel.gates.topCandidateQualityGate}
                />
              </dl>
              <ListBlock
                title="任务质量阻断项"
                items={missionPanel.qualitySummary.blockers}
              />
              <ListBlock
                title="候选改进操作"
                items={missionPanel.qualitySummary.improvementActions}
              />
              <ListBlock
                title="攻击面模型"
                items={[
                  attackSurfaceModelLine(missionPanel.attackSurfaceModel),
                  ...missionPanel.attackSurfaceModel.topRoutes.map(attackSurfaceRouteLine),
                ]}
              />
              <ListBlock
                title="候选挖掘待办"
                items={missionPanel.candidateHunterBacklog.map(candidateHunterBacklogLine)}
              />
              <ListBlock
                title="候选挖掘迭代"
                items={[candidateHunterIterationLine(missionPanel.candidateHunterIteration)]}
              />
              <ListBlock
                title="候选挖掘计划"
                items={[candidateHunterPlanLine(missionPanel.candidateHunterPlan)]}
              />
              <ListBlock
                title="候选挖掘计划步骤"
                items={missionPanel.candidateHunterPlan.planSteps.map(candidateHunterPlanStepLine)}
              />
              <ListBlock
                title="候选挖掘审查循环"
                items={[candidateHunterReviewLoopLine(missionPanel.candidateHunterReviewLoop)]}
              />
              <ListBlock
                title="候选挖掘审查循环步骤"
                items={missionPanel.candidateHunterReviewLoop.activeSteps.map(
                  candidateHunterReviewLoopStepLine,
                )}
              />
              <ListBlock
                title="候选挖掘反证队列"
                items={missionPanel.candidateHunterExecutionLoop.refutationQueue.map(
                  candidateHunterRefutationQueueLine,
                )}
              />
              <ListBlock
                title="候选挖掘证据矩阵"
                items={missionPanel.candidateHunterExecutionLoop.candidateEvidenceMatrix.map(
                  candidateHunterEvidenceMatrixLine,
                )}
              />
              <ListBlock
                title="候选挖掘排名前 1-5"
                items={missionPanel.candidateHunterExecutionLoop.rankedTopCandidates.map(
                  candidateHunterRankedTopCandidateLine,
                )}
              />
              <ListBlock
                title="候选挖掘去重队列"
                items={missionPanel.candidateHunterExecutionLoop.deduplicationQueue.map(
                  candidateHunterDeduplicationQueueLine,
                )}
              />
              <ListBlock
                title="候选挖掘安全验证队列"
                items={missionPanel.candidateHunterExecutionLoop.safeValidationQueue.map(
                  candidateHunterSafeValidationQueueLine,
                )}
              />
              <ListBlock
                title="候选挖掘报告草稿队列"
                items={missionPanel.candidateHunterExecutionLoop.reportDraftQueue.map(
                  candidateHunterReportDraftQueueLine,
                )}
              />
              <div className="mt-4">
                <p className="text-xs font-semibold uppercase text-[var(--muted)]">
                  候选挖掘学习反馈
                </p>
                <p className="mt-2 text-[var(--muted)]">
                  {candidateHunterLearningFeedbackLine(
                    missionPanel.candidateHunterExecutionLoop.learningFeedbackTarget,
                  )}
                </p>
                <div className="mt-3 grid gap-2">
                  {missionPanel.candidateHunterExecutionLoop.learningReviewActions.length === 0 ? (
                    <p className="text-[var(--muted)]">需要审核。</p>
                  ) : (
                    missionPanel.candidateHunterExecutionLoop.learningReviewActions.map((action) => (
                      <div
                        className="grid gap-2 border border-[var(--line)] bg-white p-3"
                        key={action.actionId}
                      >
                        <p className="text-[var(--muted)]">
                          {candidateHunterLearningReviewActionLine(action)}
                        </p>
                        <ActionButton
                          busy={busy === `learning:${action.actionId}`}
                          icon={<ShieldCheck size={16} aria-hidden="true" />}
                          label="记录建议结果"
                          onClick={() => handleRecordCandidateHunterLearning(action)}
                        />
                      </div>
                    ))
                  )}
                </div>
                {learningProfile?.recent_learning_signals[0] ? (
                  <p className="mt-3 text-[var(--muted)]">
                    最近学习信号：{" "}
                    {learningProfile.recent_learning_signals[0].playbook_id}：{" "}
                    {formatLabel(learningProfile.recent_learning_signals[0].outcome)}
                  </p>
                ) : null}
              </div>
              <ListBlock
                title="研究循环"
                items={missionPanel.researchLoopStages.map(
                  (stage) => `${formatLabel(stage.label)}：${formatLabel(stage.status)} - ${stage.summary}`,
                )}
              />
              <ListBlock
                title="智能体队列"
                items={missionPanel.agentQueue.map(agentQueueLine)}
              />
              <ListBlock
                title="工作台时间线摘要"
                items={[studioTimelineSummaryLine(missionPanel.studioTimelineSummary)]}
              />
              <ListBlock
                title="候选审查包"
                items={missionPanel.candidateReviewPackets.map(candidateReviewPacketLine)}
              />
              <ListBlock
                title="脱敏证据审查队列"
                items={missionPanel.candidateReviewPackets.map(redactedEvidenceReviewLine)}
              />
              <ListBlock
                title="报告提交阻断摘要"
                items={[
                  submissionBlockedReportSummaryLine(
                    missionPanel.submissionBlockedReportSummary,
                  ),
                ]}
              />
              <TextBlock title="交接摘要" value={missionHandoffBrief} />
              <ListBlock
                title="智能体交接包"
                items={[agentHandoffPackLine(missionPanel.agentHandoffPack)]}
              />
              <ListBlock
                title="智能体交接项"
                items={missionPanel.agentHandoffPack.handoffItems.map(agentHandoffItemLine)}
              />
              <ListBlock
                title="智能体任务时间线"
                items={missionPanel.agentTaskTimeline.map(agentTaskTimelineLine)}
              />
              <ListBlock title="建议的安全操作" items={missionPanel.safeNextActions} />
              <ListBlock
                title="任务高优先级候选"
                items={missionPanel.topCandidates.map(missionCandidateLine)}
              />
            </div>
            <p className="font-semibold text-[var(--warning)]">报告提交已阻断</p>
            <div className="grid gap-2">
              {workspace.blockedActions.map((action) => (
                <span key={action} className="border border-[var(--line)] px-3 py-2 text-[var(--muted)]">
                  {formatLabel(action)}
                </span>
              ))}
            </div>
          </div>
        </section>
      </div>

      <div className="mt-5" id="studio-candidates" />
      </div>
    </StudioShell>
  );
}

function SectionHeader({ title }: { title: string }) {
  return (
    <div className="border-b border-[var(--line)] px-5 py-4">
      <h2 className="text-lg font-semibold">{title}</h2>
    </div>
  );
}

function TextField({
  browseEnabled = false,
  label,
  onBrowse,
  onChange,
  value,
}: {
  browseEnabled?: boolean;
  label: string;
  onBrowse?: () => void;
  onChange: (value: string) => void;
  value: string;
}) {
  return (
    <label className="grid min-w-0 gap-1 text-sm">
      <span className="text-xs font-semibold uppercase text-[var(--muted)]">{label}</span>
      <span className="grid min-w-0 gap-2">
        <input
          className="min-h-10 min-w-0 w-full rounded-md border border-[var(--line)] bg-white px-3 outline-none focus:border-[var(--accent)]"
          onChange={(event) => onChange(event.target.value)}
          value={value}
        />
        {onBrowse ? (
          <button
            className="min-h-9 rounded-md border border-[var(--line)] px-3 text-sm font-semibold disabled:cursor-not-allowed disabled:opacity-60"
            disabled={!browseEnabled}
            onClick={onBrowse}
            type="button"
          >
            <FolderOpen size={16} aria-hidden="true" />
            浏览
          </button>
        ) : null}
      </span>
    </label>
  );
}

function ActionButton({
  busy,
  disabled,
  icon,
  label,
  onClick,
}: {
  busy: boolean;
  disabled?: boolean;
  icon: React.ReactNode;
  label: string;
  onClick: () => void;
}) {
  return (
    <button
      className="inline-flex min-h-10 items-center justify-center gap-2 rounded-md border border-[var(--line)] px-3 text-sm font-semibold disabled:cursor-not-allowed disabled:opacity-60"
      disabled={busy || disabled}
      onClick={onClick}
      type="button"
    >
      {icon}
      {busy ? "处理中" : label}
    </button>
  );
}

function StatusRow({
  label,
  value,
  warning,
}: {
  label: string;
  value: string;
  warning?: boolean;
}) {
  return (
    <div>
      <dt className="text-xs font-semibold uppercase text-[var(--muted)]">{label}</dt>
      <dd className={warning ? "mt-1 font-semibold text-[var(--warning)]" : "mt-1 font-semibold"}>
        {value}
      </dd>
    </div>
  );
}

function ListBlock({ items, title }: { items: string[]; title: string }) {
  return (
    <div className="mt-4">
      <p className="text-xs font-semibold uppercase text-[var(--muted)]">{title}</p>
      {items.length === 0 ? (
        <p className="mt-2 text-[var(--muted)]">需要审核。</p>
      ) : (
        <ul className="mt-2 grid gap-1 text-[var(--muted)]">
          {items.map((item) => (
            <li key={item}>{item}</li>
          ))}
        </ul>
      )}
    </div>
  );
}

function TextBlock({ title, value }: { title: string; value: string }) {
  return (
    <div className="mt-4">
      <p className="text-xs font-semibold uppercase text-[var(--muted)]">{title}</p>
      <pre className="mt-2 max-h-64 overflow-auto whitespace-pre-wrap border border-[var(--line)] bg-[var(--panel)] p-3 text-xs leading-5 text-[var(--muted)]">
        {value}
      </pre>
    </div>
  );
}

function attackSurfaceModelLine(
  model: ReturnType<typeof toStudioMissionPanel>["attackSurfaceModel"],
): string {
  const sources =
    model.sourceArtifactKinds.length > 0 ? model.sourceArtifactKinds.join(", ") : "无";
  const methods = model.methods.length > 0 ? model.methods.join(", ") : "无";
  const gates = [
    model.executionAllowed ? "执行已允许" : "执行已阻断",
    model.validationAllowed ? "验证已允许" : "验证已阻断",
    model.reportSubmissionAllowed ? "报告提交已允许" : "报告提交已阻断",
  ].join(", ");
  return `${formatLabel(model.status)}；路由 ${model.routeCount}（API ${model.apiRouteCount}，HAR ${model.harRouteCount}）；参考信号 ${model.advisorySignalCount}；方法 ${methods}；来源 ${sources}；审批门 ${formatLabel(model.safetyGate)}；下一步 ${model.nextAction}；${gates}`;
}

function attackSurfaceRouteLine(
  route: ReturnType<typeof toStudioMissionPanel>["attackSurfaceModel"]["topRoutes"][number],
): string {
  const sources = route.artifactKinds.length > 0 ? route.artifactKinds.join(", ") : "资料";
  return `${route.method} ${route.path}；来源 ${sources}`;
}

function missionCandidateLine(
  candidate: ReturnType<typeof toStudioMissionPanel>["topCandidates"][number],
): string {
  const qualityReasons = candidate.qualityReasons.join(", ") || "需要审核";
  const crossChecks =
    candidate.hallucinationGuard.independentCrossCheckSources.join(", ") || "无";
  return [
    `${candidate.hypothesisId}: ${candidate.affectedEndpoint} -> ${candidate.affectedCodePath}`,
    `证据 ${formatLabel(candidate.evidenceReviewStatus)}/${candidate.evidenceNeedCount}`,
    `反证 ${formatLabel(candidate.refutationStatus)}/${formatLabel(candidate.refutationReviewStatus)}`,
    `溯源 ${formatLabel(candidate.provenanceReviewStatus)}`,
    `去重 ${formatLabel(candidate.deduplicationReviewStatus)}`,
    `验证 ${formatLabel(candidate.validationStatus)}/${candidate.safeValidationStepCount}`,
    `质量 ${formatLabel(candidate.qualityStatus)}/${candidate.qualityScore}（${qualityReasons}）`,
    `幻觉防护 ${formatLabel(candidate.hallucinationGuard.status)}/${formatLabel(candidate.hallucinationGuard.modelOutputStatus)}`,
    `独立交叉检查 ${crossChecks}`,
    `报告 ${formatLabel(candidate.reportStatus)}`,
  ].join("; ");
}

function agentQueueLine(
  task: ReturnType<typeof toStudioMissionPanel>["agentQueue"][number],
): string {
  const inputs = task.inputRefs.length > 0 ? task.inputRefs.join(", ") : "无引用";
  const focus = task.reviewFocus.length > 0 ? `；重点 ${task.reviewFocus.join(", ")}` : "";
  const gaps =
    task.candidateQualityGaps.length > 0
      ? `；质量缺口 ${task.candidateQualityGaps.join(", ")}`
      : "";
  const candidates =
    task.targetCandidates.length > 0 ? `；候选 ${task.targetCandidates.join(", ")}` : "";
  const prefix = `${task.taskId}：${task.agent} - ${formatLabel(task.status)}`;
  return `${prefix}；审批门 ${formatLabel(task.safetyGate)}；输入 ${inputs}${focus}${candidates}${gaps}；${task.nextAction}`;
}

function agentTaskTimelineLine(
  stage: ReturnType<typeof toStudioMissionPanel>["agentTaskTimeline"][number],
): string {
  return `${stage.stageId}：${formatLabel(stage.status)}/${formatLabel(stage.gateDecision)}；${stage.inputSummary}；${stage.outputSummary}；下一步 ${stage.nextHumanAction}`;
}

function studioTimelineSummaryLine(
  summary: ReturnType<typeof toStudioMissionPanel>["studioTimelineSummary"],
): string {
  const counts = Object.entries(summary.gateDecisionCounts)
    .map(([gate, count]) => `${formatLabel(gate)} ${count}`)
    .join("，") || "无阶段";
  const blocked =
    summary.blockedStageIds.length > 0 ? summary.blockedStageIds.join(", ") : "无";
  const needsReview =
    summary.needsReviewStageIds.length > 0
      ? summary.needsReviewStageIds.join(", ")
      : "无";
  const pending =
    summary.pendingStageIds.length > 0 ? summary.pendingStageIds.join(", ") : "无";
  const nextActions =
    summary.nextHumanActions.length > 0
      ? summary.nextHumanActions.join("; ")
      : "需要审核。";
  const gates = [
    summary.validationExecutionAllowed ? "验证已允许" : "验证已阻断",
    summary.reportSubmissionAllowed ? "报告提交已允许" : "报告提交已阻断",
  ].join(", ");
  return `阶段 ${summary.totalStages}；审批门 ${counts}；已阻断 ${blocked}；需要审核 ${needsReview}；待处理 ${pending}；安全状态 ${formatLabel(summary.safetyGate)}；下一步 ${nextActions}；${gates}`;
}

function candidateReviewPacketLine(
  packet: ReturnType<typeof toStudioMissionPanel>["candidateReviewPackets"][number],
): string {
  const missing =
    packet.missingItems.length > 0 ? packet.missingItems.join(", ") : "无";
  const completed =
    packet.completedItems.length > 0 ? packet.completedItems.join(", ") : "无";
  const gates = [
    packet.executionAllowed ? "执行已允许" : "执行已阻断",
    packet.validationAllowed ? "验证已允许" : "验证已阻断",
    packet.reportSubmissionAllowed ? "报告提交已允许" : "报告提交已阻断",
  ].join(", ");
  return `${packet.candidateId}：${formatLabel(packet.status)}；优先级 ${packet.reportReviewPriority}；质量 ${packet.qualityScore}/100；已完成 ${completed}；缺少 ${missing}；证据 ${packet.evidenceNeedCount}；反证 ${packet.falsePositiveCheckCount}；验证步骤 ${packet.safeValidationStepCount}；幻觉防护 ${formatLabel(packet.hallucinationGuardStatus)}；报告 ${formatLabel(packet.reportStatus)}；审批门 ${formatLabel(packet.safetyGate)}；下一步 ${packet.nextHumanAction}；${gates}`;
}

function redactedEvidenceReviewLine(
  packet: ReturnType<typeof toStudioMissionPanel>["candidateReviewPackets"][number],
): string {
  const missing =
    packet.missingItems.length > 0 ? packet.missingItems.join(", ") : "无";
  const completed =
    packet.completedItems.length > 0 ? packet.completedItems.join(", ") : "无";
  const gates = [
    packet.executionAllowed ? "执行已允许" : "执行已阻断",
    packet.validationAllowed ? "验证已允许" : "验证已阻断",
    packet.reportSubmissionAllowed ? "报告提交已允许" : "报告提交已阻断",
  ].join(", ");
  return `${packet.candidateId}：脱敏审查 ${packet.reportReviewPriority}；证据需求 ${packet.evidenceNeedCount}；缺少 ${missing}；已完成 ${completed}；审批门 ${formatLabel(packet.safetyGate)}；下一步 ${packet.nextHumanAction}；${gates}`;
}

function submissionBlockedReportSummaryLine(
  summary: ReturnType<typeof toStudioMissionPanel>["submissionBlockedReportSummary"],
): string {
  const ready =
    summary.readyCandidateIds.length > 0 ? summary.readyCandidateIds.join(", ") : "无";
  const needsReview =
    summary.needsReviewCandidateIds.length > 0
      ? summary.needsReviewCandidateIds.join(", ")
      : "无";
  const missing = Object.entries(summary.missingReviewItems)
    .map(([candidateId, items]) => `${candidateId}: ${items.join(", ")}`)
    .join("；") || "无";
  const nextActions =
    summary.nextHumanActions.length > 0
      ? summary.nextHumanActions.join("; ")
      : "需要人工脱敏审查。";
  const reviewQueue =
    summary.reportReviewQueue.length > 0
      ? summary.reportReviewQueue
          .map((item) => `${item.candidateId}: ${item.priority} (${item.qualityScore}/100)`)
          .join("；")
      : "无";
  const gates = [
    summary.validationExecutionAllowed ? "验证已允许" : "验证已阻断",
    summary.reportSubmissionAllowed ? "报告提交已允许" : "报告提交已阻断",
  ].join(", ");
  return `${formatLabel(summary.status)}；候选 ${summary.candidateCount}；已就绪 ${ready}；需要审核 ${needsReview}；缺少 ${missing}；报告队列 ${reviewQueue}；审批门 ${formatLabel(summary.safetyGate)}；脱敏审查 ${summary.redactionReviewRequired ? "需要" : "缺失"}；下一步 ${nextActions}；${gates}`;
}

function agentHandoffPackLine(
  pack: ReturnType<typeof toStudioMissionPanel>["agentHandoffPack"],
): string {
  const priority = pack.priorityOrder.length > 0 ? pack.priorityOrder.join(", ") : "无";
  const focus = pack.reviewFocus.length > 0 ? pack.reviewFocus.join(", ") : "审查";
  const queueRefs =
    pack.agentQueueRefs.length > 0 ? pack.agentQueueRefs.join(", ") : "智能体队列";
  const counts = Object.entries(pack.timelineGateCounts)
    .map(([gate, count]) => `${formatLabel(gate)} ${count}`)
    .join("，") || "无时间线审批门";
  const blocked =
    pack.blockedActions.length > 0 ? pack.blockedActions.join(", ") : "无阻断操作";
  const gates = [
    pack.executionAllowed ? "执行已允许" : "执行已阻断",
    pack.validationAllowed ? "验证已允许" : "验证已阻断",
    pack.reportSubmissionAllowed ? "报告提交已允许" : "报告提交已阻断",
  ].join(", ");
  return `${pack.packId}：${formatLabel(pack.status)}；下一审查智能体 ${pack.nextReviewAgent}；项目 ${pack.handoffItemCount}；优先级 ${priority}；重点 ${focus}；队列 ${queueRefs}；时间线 ${counts}；审批门 ${formatLabel(pack.safetyGate)}/${formatLabel(pack.completionGate)}；已阻断 ${blocked}；${gates}`;
}

function agentHandoffItemLine(
  item: ReturnType<typeof toStudioMissionPanel>["agentHandoffPack"]["handoffItems"][number],
): string {
  const refs = item.inputRefs.length > 0 ? item.inputRefs.join(", ") : "无引用";
  const focus = item.reviewFocus.length > 0 ? item.reviewFocus.join(", ") : "审查";
  const evidence =
    item.requiredEvidence.length > 0 ? item.requiredEvidence.join(", ") : "审查说明";
  const criteria =
    item.successCriteria.length > 0 ? item.successCriteria.join("；") : "人工决定";
  const gates = [
    item.executionAllowed ? "执行已允许" : "执行已阻断",
    item.validationAllowed ? "验证已允许" : "验证已阻断",
    item.reportSubmissionAllowed ? "报告提交已允许" : "报告提交已阻断",
  ].join(", ");
  return `${item.handoffId}：${item.assignedAgent} 处理 ${item.workItemId}（${formatLabel(item.status)}/${formatLabel(item.gap)}）；引用 ${refs}；重点 ${focus}；证据 ${evidence}；完成条件 ${criteria}；审批门 ${formatLabel(item.safetyGate)}；下一步 ${item.nextAction}；${gates}`;
}

function candidateHunterBacklogLine(
  item: ReturnType<typeof toStudioMissionPanel>["candidateHunterBacklog"][number],
): string {
  const focus = item.reviewFocus.length > 0 ? item.reviewFocus.join(", ") : "候选质量";
  const evidence =
    item.requiredEvidence.length > 0 ? item.requiredEvidence.join(", ") : "审查说明";
  const gates = [
    item.executionAllowed ? "执行已允许" : "执行已阻断",
    item.validationAllowed ? "验证已允许" : "验证已阻断",
    item.reportSubmissionAllowed ? "报告提交已允许" : "报告提交已阻断",
  ].join(", ");
  return `${item.workItemId}：${formatLabel(item.gap)} - ${formatLabel(item.status)}；审批门 ${formatLabel(item.safetyGate)}；重点 ${focus}；证据 ${evidence}；${gates}；${item.nextAction}`;
}

function candidateHunterIterationLine(
  iteration: ReturnType<typeof toStudioMissionPanel>["candidateHunterIteration"],
): string {
  const priority =
    iteration.priorityOrder.length > 0 ? iteration.priorityOrder.join(", ") : "无待办";
  const focus =
    iteration.reviewFocus.length > 0 ? iteration.reviewFocus.join(", ") : "候选质量";
  const criteria =
    iteration.successCriteria.length > 0
      ? iteration.successCriteria.join("; ")
      : "需要人工审核";
  const gates = [
    iteration.executionAllowed ? "执行已允许" : "执行已阻断",
    iteration.validationAllowed ? "验证已允许" : "验证已阻断",
    iteration.reportSubmissionAllowed ? "报告提交已允许" : "报告提交已阻断",
  ].join(", ");
  return `${iteration.iterationId}：${formatLabel(iteration.status)}；下一审查智能体 ${iteration.nextReviewAgent}；工作项 ${iteration.workItemCount}；审批门 ${formatLabel(iteration.safetyGate)}/${formatLabel(iteration.completionGate)}；优先级 ${priority}；重点 ${focus}；完成条件 ${criteria}；${gates}`;
}

function candidateHunterPlanLine(
  plan: ReturnType<typeof toStudioMissionPanel>["candidateHunterPlan"],
): string {
  const gates = [
    plan.executionAllowed ? "执行已允许" : "执行已阻断",
    plan.validationAllowed ? "验证已允许" : "验证已阻断",
    plan.reportSubmissionAllowed ? "报告提交已允许" : "报告提交已阻断",
  ].join(", ");
  const governance = [
    `声明 ${formatLabel(plan.hallucinationGovernance.claimPromotionRule)}`,
    `知识 ${formatLabel(plan.hallucinationGovernance.knowledgePolicy)}`,
    `提升 ${plan.hallucinationGovernance.candidatePromotionAllowed ? "已允许" : "已阻断"}`,
  ].join(", ");
  return `${plan.planId}：${formatLabel(plan.status)}；下一审查智能体 ${plan.nextReviewAgent}；工作项 ${plan.workItemCount}；步骤 ${plan.stepCount}；治理 ${governance}；审批门 ${formatLabel(plan.safetyGate)}/${formatLabel(plan.completionGate)}；${gates}`;
}

function candidateHunterPlanStepLine(
  step: ReturnType<typeof toStudioMissionPanel>["candidateHunterPlan"]["planSteps"][number],
): string {
  const refs = step.inputRefs.length > 0 ? step.inputRefs.join(", ") : "无引用";
  const focus = step.reviewFocus.length > 0 ? step.reviewFocus.join(", ") : "审查";
  const evidence =
    step.requiredEvidence.length > 0 ? step.requiredEvidence.join(", ") : "审查说明";
  const criteria =
    step.successCriteria.length > 0 ? step.successCriteria.join("；") : "人工决定";
  const checklist =
    step.reviewChecklist.length > 0
      ? step.reviewChecklist
          .map((item) => `${formatLabel(item.key)}：${formatLabel(item.status)}`)
          .join(", ")
      : "检查清单待处理";
  const governance =
    step.hallucinationGovernanceRefs.length > 0
      ? step.hallucinationGovernanceRefs.join("; ")
      : "模型声明需要本地证据与独立审核";
  const gates = [
    step.executionAllowed ? "执行已允许" : "执行已阻断",
    step.validationAllowed ? "验证已允许" : "验证已阻断",
    step.reportSubmissionAllowed ? "报告提交已允许" : "报告提交已阻断",
  ].join(", ");
  return `${step.stepId}：${step.assignedAgent} 处理 ${step.workItemId}（${formatLabel(step.status)}/${formatLabel(step.gap)}）；引用 ${refs}；重点 ${focus}；证据 ${evidence}；检查清单 ${checklist}；完成条件 ${criteria}；治理 ${governance}；审批门 ${formatLabel(step.safetyGate)}；下一步 ${step.nextAction}；${gates}`;
}

function candidateHunterReviewLoopLine(
  loop: ReturnType<typeof toStudioMissionPanel>["candidateHunterReviewLoop"],
): string {
  const agents = loop.reviewAgents.length > 0 ? loop.reviewAgents.join(", ") : "人工审查者";
  const evidence =
    loop.requiredEvidence.length > 0 ? loop.requiredEvidence.join(", ") : "审查说明";
  const consensus =
    loop.governanceSummary.requiredConsensus.length > 0
      ? loop.governanceSummary.requiredConsensus.join(", ")
      : "人工审核决策";
  const gates = [
    loop.executionAllowed ? "执行已允许" : "执行已阻断",
    loop.validationAllowed ? "验证已允许" : "验证已阻断",
    loop.reportSubmissionAllowed ? "报告提交已允许" : "报告提交已阻断",
  ].join(", ");
  return `${loop.loopId}：${formatLabel(loop.status)}；来源 ${loop.sourcePlanId}；活跃步骤 ${loop.activeStepCount}；下一审查智能体 ${loop.nextReviewAgent}；智能体 ${agents}；证据 ${evidence}；共识 ${formatLabel(consensus)}；审批门 ${formatLabel(loop.safetyGate)}/${formatLabel(loop.completionGate)}；${gates}`;
}

function candidateHunterReviewLoopStepLine(
  step: ReturnType<typeof toStudioMissionPanel>["candidateHunterReviewLoop"]["activeSteps"][number],
): string {
  const evidence =
    step.requiredEvidence.length > 0 ? step.requiredEvidence.join(", ") : "审查说明";
  const governance =
    step.governanceRefs.length > 0
      ? step.governanceRefs.join("; ")
      : "模型声明需要本地证据与独立审核";
  const checklist =
    step.reviewChecklist.length > 0
      ? step.reviewChecklist
          .map((item) => `${formatLabel(item.key)}：${formatLabel(item.status)}`)
          .join("、")
      : "检查清单待处理";
  const criteria =
    step.successCriteria.length > 0 ? step.successCriteria.join("；") : "人工决定";
  const gates = [
    step.executionAllowed ? "执行已允许" : "执行已阻断",
    step.validationAllowed ? "验证已允许" : "验证已阻断",
    step.reportSubmissionAllowed ? "报告提交已允许" : "报告提交已阻断",
  ].join(", ");
  return `${step.stepId}：${step.assignedAgent} 处理 ${step.workItemId}（${formatLabel(step.gap)}）；证据 ${evidence}；治理 ${governance}；检查清单 ${checklist}；完成条件 ${criteria}；审批门 ${formatLabel(step.safetyGate)}；下一步 ${step.nextAction}；${gates}`;
}

function candidateHunterRefutationQueueLine(
  item: ReturnType<typeof toStudioMissionPanel>["candidateHunterExecutionLoop"]["refutationQueue"][number],
): string {
  const missingEvidence =
    item.missingEvidence.length > 0 ? item.missingEvidence.join(", ") : "无";
  const missingArtifacts =
    item.missingRequiredArtifactKinds.length > 0
      ? item.missingRequiredArtifactKinds.join(", ")
      : "无";
  const questions = item.questions.length > 0 ? item.questions.join("；") : "审查";
  const requiredEvidence =
    item.requiredEvidence.length > 0 ? item.requiredEvidence.join(", ") : "审查说明";
  const gates = [
    item.executionAllowed ? "执行已允许" : "执行已阻断",
    item.validationAllowed ? "验证已允许" : "验证已阻断",
    item.reportSubmissionAllowed ? "报告提交已允许" : "报告提交已阻断",
  ].join(", ");
  return `${item.queueId}：${item.candidateId}；轨迹 ${formatLabel(item.traceStatus)}；优先级 ${item.priorityScore}；缺少证据 ${missingEvidence}；缺少资料 ${missingArtifacts}；所需证据 ${requiredEvidence}；问题 ${questions}；审批门 ${formatLabel(item.safetyGate)}；下一步 ${item.nextAction}；${gates}`;
}

function candidateHunterEvidenceMatrixLine(
  item: ReturnType<typeof toStudioMissionPanel>["candidateHunterExecutionLoop"]["candidateEvidenceMatrix"][number],
): string {
  const missingEvidence =
    item.missingEvidence.length > 0 ? item.missingEvidence.join(", ") : "无";
  const missingRequiredArtifacts =
    item.missingRequiredArtifactKinds.length > 0
      ? item.missingRequiredArtifactKinds.join(", ")
      : "无";
  const learnedEvidence =
    item.learningEvidenceNeededReasons.length > 0
      ? item.learningEvidenceNeededReasons.join(", ")
      : "无";
  const ranking =
    item.rankingSignalBreakdown.length > 0
      ? item.rankingSignalBreakdown.join(", ")
      : "暂无排序信号";
  const requiredEvidence =
    item.requiredEvidence.length > 0 ? item.requiredEvidence.join(", ") : "审查说明";
  const gates = [
    item.executionAllowed ? "执行已允许" : "执行已阻断",
    item.validationAllowed ? "验证已允许" : "验证已阻断",
    item.reportSubmissionAllowed ? "报告提交已允许" : "报告提交已阻断",
  ].join(", ");
  return `${item.candidateId}：质量 ${item.qualityScore}；挖掘优先级 ${item.hunterPriorityScore}；影响 ${item.impactScore}；拒绝风险 ${item.rejectionRiskScore}；策略风险 ${item.policyRiskScore}；端点 ${item.affectedEndpoint}；代码 ${item.affectedCodePath}；缺少证据 ${missingEvidence}；缺少必需资料 ${missingRequiredArtifacts}；所需证据 ${requiredEvidence}；学习证据 ${learnedEvidence}；排序 ${ranking}；${gates}`;
}

function candidateHunterRankedTopCandidateLine(
  item: ReturnType<typeof toStudioMissionPanel>["candidateHunterExecutionLoop"]["rankedTopCandidates"][number],
): string {
  const ranking =
    item.rankingSignalBreakdown.length > 0
      ? item.rankingSignalBreakdown.join(", ")
      : "暂无排序信号";
  const requiredEvidence =
    item.requiredEvidence.length > 0 ? item.requiredEvidence.join(", ") : "审查说明";
  const missingEvidence =
    item.missingEvidence.length > 0 ? item.missingEvidence.join(", ") : "无";
  const missingRequiredArtifacts =
    item.missingRequiredArtifactKinds.length > 0
      ? item.missingRequiredArtifactKinds.join(", ")
      : "无";
  const gates = [
    item.executionAllowed ? "执行已允许" : "执行已阻断",
    item.validationAllowed ? "验证已允许" : "验证已阻断",
    item.reportSubmissionAllowed ? "报告提交已允许" : "报告提交已阻断",
  ].join(", ");
  return `#${item.rank} ${item.candidateId}：${item.reason}；阶段 ${item.phaseId}；优先级 ${item.priorityScore}；状态 ${formatLabel(item.qualityStatus)}；轨迹 ${formatLabel(item.traceStatus)}；证据就绪 ${item.evidenceReady ? "是" : "否"}；缺少证据 ${missingEvidence}；缺少必需资料 ${missingRequiredArtifacts}；端点 ${item.affectedEndpoint}；代码 ${item.affectedCodePath}；所需 ${requiredEvidence}；下一步 ${item.nextAction}；排序 ${ranking}；审批门 ${formatLabel(item.safetyGate)}；${gates}`;
}

function candidateHunterDeduplicationQueueLine(
  item: ReturnType<typeof toStudioMissionPanel>["candidateHunterExecutionLoop"]["deduplicationQueue"][number],
): string {
  const similarityKeys =
    item.similarityKeys.length > 0 ? item.similarityKeys.join(", ") : "审查";
  const questions = item.questions.length > 0 ? item.questions.join("；") : "审查";
  const gates = [
    item.executionAllowed ? "执行已允许" : "执行已阻断",
    item.validationAllowed ? "验证已允许" : "验证已阻断",
    item.reportSubmissionAllowed ? "报告提交已允许" : "报告提交已阻断",
  ].join(", ");
  return `${item.queueId}：${item.candidateId}；重复风险 ${item.duplicateRiskScore}/100；优先级 ${item.priorityScore}；端点 ${item.affectedEndpoint}；代码 ${item.affectedCodePath}；相似项 ${similarityKeys}；问题 ${questions}；审批门 ${formatLabel(item.safetyGate)}；下一步 ${item.nextAction}；${gates}`;
}

function candidateHunterSafeValidationQueueLine(
  item: ReturnType<typeof toStudioMissionPanel>["candidateHunterExecutionLoop"]["safeValidationQueue"][number],
): string {
  const planSteps = item.planSteps.length > 0 ? item.planSteps.join("；") : "审查计划";
  const approvals =
    item.requiredApprovals.length > 0 ? item.requiredApprovals.join(", ") : "人工审核";
  const gates = [
    item.executionAllowed ? "执行已允许" : "执行已阻断",
    item.validationAllowed ? "验证已允许" : "验证已阻断",
    item.validationExecutionAllowed
      ? "验证执行已允许"
      : "验证执行已阻断",
    item.reportSubmissionAllowed ? "报告提交已允许" : "报告提交已阻断",
  ].join(", ");
  return `${item.queueId}：${item.candidateId}；模式 ${formatLabel(item.validationMode)}；优先级 ${item.priorityScore}；端点 ${item.affectedEndpoint}；代码 ${item.affectedCodePath}；计划 ${planSteps}；审批 ${approvals}；审批门 ${formatLabel(item.safetyGate)}；下一步 ${item.nextAction}；${gates}`;
}

function candidateHunterReportDraftQueueLine(
  item: ReturnType<typeof toStudioMissionPanel>["candidateHunterExecutionLoop"]["reportDraftQueue"][number],
): string {
  const requiredSections =
    item.requiredSections.length > 0 ? item.requiredSections.join(", ") : "报告章节";
  const redactionChecks =
    item.redactionChecks.length > 0 ? item.redactionChecks.join(", ") : "脱敏审查";
  const evidenceFocus =
    item.evidenceFocus.length > 0 ? item.evidenceFocus.join(", ") : "证据重点";
  const gates = [
    item.executionAllowed ? "执行已允许" : "执行已阻断",
    item.validationAllowed ? "验证已允许" : "验证已阻断",
    item.reportSubmissionAllowed ? "报告提交已允许" : "报告提交已阻断",
  ].join(", ");
  return `${item.queueId}：${item.candidateId}；报告 ${formatLabel(item.reportStatus)}；优先级 ${item.priorityScore}；端点 ${item.affectedEndpoint}；代码 ${item.affectedCodePath}；章节 ${requiredSections}；证据重点 ${evidenceFocus}；脱敏 ${redactionChecks}；审批门 ${formatLabel(item.safetyGate)}；下一步 ${item.nextAction}；${gates}`;
}

function candidateHunterLearningFeedbackLine(
  target: ReturnType<typeof toStudioMissionPanel>["candidateHunterExecutionLoop"]["learningFeedbackTarget"],
): string {
  const candidates = target.candidateIds.length > 0 ? target.candidateIds.join(", ") : "无";
  const outcomes =
    target.allowedOutcomes.length > 0
      ? target.allowedOutcomes.join(", ")
      : "已确认、已反证、需要更多证据、重复";
  const gates = [
    target.learningWriteAllowed ? "允许写入学习记录" : "写入学习记录需要审核",
    target.executionAllowed ? "执行已允许" : "执行已阻断",
    target.validationAllowed ? "验证已允许" : "验证已阻断",
    target.reportSubmissionAllowed ? "报告提交已允许" : "报告提交已阻断",
  ].join(", ");
  return `${target.targetId}：${formatLabel(target.status)}；候选 ${candidates}；结果 ${outcomes}；审批门 ${formatLabel(target.safetyGate)}；下一步 ${target.nextAction}；${gates}`;
}

function candidateHunterLearningReviewActionLine(
  action: ReturnType<typeof toStudioMissionPanel>["candidateHunterExecutionLoop"]["learningReviewActions"][number],
): string {
  const outcomes =
    action.allowedOutcomes.length > 0
      ? action.allowedOutcomes.join(", ")
      : "已确认、已反证、需要更多证据、重复";
  const gates = [
    action.learningWriteAllowed ? "允许写入学习记录" : "写入学习记录需要审核",
    action.executionAllowed ? "执行已允许" : "执行已阻断",
    action.validationAllowed ? "验证已允许" : "验证已阻断",
    action.reportSubmissionAllowed ? "报告提交已允许" : "报告提交已阻断",
  ].join(", ");
  const missingEvidence =
    action.missingEvidence.length > 0 ? action.missingEvidence.join(", ") : "无";
  const missingRequiredArtifacts =
    action.missingRequiredArtifactKinds.length > 0
      ? action.missingRequiredArtifactKinds.join(", ")
      : "无";
  const template = action.learningSignalTemplate
    ? `；学习信号模板：手册 ${action.learningSignalTemplate.playbookId}；攻击面 ${action.learningSignalTemplate.surfaceKey}；引用 ${action.learningSignalTemplate.targetRelationships.length}；写入学习记录需要审核`
    : "";
  return `${action.actionId}：${action.candidateId}；建议 ${formatLabel(action.suggestedOutcome)}；轨迹 ${formatLabel(action.traceStatus)}；证据就绪 ${action.evidenceReady ? "是" : "否"}；缺少证据 ${missingEvidence}；缺少必需资料 ${missingRequiredArtifacts}；结果 ${outcomes}；审批门 ${formatLabel(action.safetyGate)}；下一步 ${action.nextAction}；${gates}${template}`;
}

function toCandidateHunterLearningOutcome(value: string): CandidateHunterLearningOutcome {
  if (
    value === "confirmed" ||
    value === "duplicate" ||
    value === "needs_more_evidence" ||
    value === "refuted"
  ) {
    return value;
  }
  return "needs_more_evidence";
}

function checklistTone(status: "ready" | "missing" | "optional"): string {
  if (status === "ready") {
    return "text-[var(--success)]";
  }
  if (status === "missing") {
    return "text-[var(--warning)]";
  }
  return "text-[var(--muted)]";
}
