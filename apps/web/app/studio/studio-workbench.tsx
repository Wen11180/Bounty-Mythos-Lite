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
  name: "Local Mythos Studio",
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
      message: "Studio ready.",
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
        label: "Workspace",
        detail: workspacePath ? "Workspace selected" : "Create or open a local workspace",
      },
      {
        id: "authorized_materials",
        label: "Authorized materials",
        detail: workspacePath ? "Import authorized materials" : "Select a workspace first",
      },
      {
        id: "readiness_check",
        label: "Readiness check",
        detail: researchReadiness.canStart ? "Start local research" : researchReadiness.reason,
      },
      {
        id: "candidate_review",
        label: "Candidate review",
        detail:
          candidates.length > 0
            ? "Review candidates and export a submission-blocked report draft"
            : "Review candidates after research completes",
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
      pushLog("Enter a model name before enabling model-assisted candidate generation.", "blocked");
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
        pushLog("Local lab lease preview was not returned.", "blocked");
        return;
      }
      setLabLeaseRequestSnapshot(request);
      setLabLeasePreview(preview);
      pushLog(
        preview.sessions_ready
          ? "Bounded loopback lease reviewed; both session aliases are marked ready."
          : "Bounded loopback lease reviewed; create sessions and complete readiness checks.",
        preview.sessions_ready ? "safe" : "info",
      );
    } catch (error) {
      pushMutationFailure("Local lab lease preview", error);
    } finally {
      setBusy(null);
    }
  }

  async function handleCreateBlackBoxSessions() {
    const bridge = window.mythosStudio;
    if (!bridge || !labLeaseRequestSnapshot || labRunnerState !== "idle") {
      pushLog("Preview a bounded local lease in Mythos Studio before creating sessions.", "blocked");
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
      pushLog("Two isolated local browser sessions created. Complete login manually.", "safe");
    } catch (error) {
      pushMutationFailure("Local lab session creation", error);
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
      pushLog("Both isolated sessions must be ready before recording.", "blocked");
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
      pushLog("Recording alias-only normalized traces for the declared local workflow.", "safe");
    } catch (error) {
      pushMutationFailure("Local lab recording start", error);
    } finally {
      setBusy(null);
    }
  }

  async function handleStopBlackBoxRecording() {
    const bridge = window.mythosStudio;
    if (!bridge || labRunnerState !== "recording") {
      pushLog("No local lab recording is active.", "blocked");
      return;
    }
    setBusy("lab-stop-recording");
    try {
      const event = parseBlackBoxRunnerEvent(await bridge.stopBlackBoxRecording());
      if (event.event === "stop") {
        setLabRunnerState("stopped");
        pushLog(`Local lab stopped: ${String(event.reason ?? "safety_stop")}.`, "blocked");
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
          ? `${traces.length} normalized trace(s) ready for human review.`
          : "No matching normalized trace was captured. Stop the lab and retry.",
        traces.length > 0 ? "safe" : "blocked",
      );
    } catch (error) {
      setLabRunnerState("stopped");
      pushMutationFailure("Local lab recording stop", error);
    } finally {
      setBusy(null);
    }
  }

  function handleReviewBlackBoxTraces() {
    if (labTraceReview.length === 0 || labRunnerState !== "sessions_ready") {
      pushLog("Capture a matching normalized trace before review.", "blocked");
      return;
    }
    setLabTraceReviewConfirmed(true);
    pushLog(
      "Normalized alias-only traces reviewed; raw headers and bodies remain excluded.",
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
      pushLog("A durable validation run and reviewed traces are required for confirmation.", "blocked");
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
        pushLog(`Local trial stopped: ${String(event.reason ?? "safety_stop")}.`, "blocked");
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
      pushLog("One bounded local differential trial completed; result remains review-only.", "safe");
      pushLog(
        boundedResult.report_preview_refreshed
          ? "Bounded result recorded; report preview refreshed for human review. Submission remains blocked."
          : "Bounded result recorded for human review. Submission remains blocked.",
        "safe",
      );
    } catch (error) {
      if (trialDispatched) {
        setLabRunnerState("stopped");
      }
      pushMutationFailure("Complete local lab plan", error);
    } finally {
      setBusy(null);
      labDispatchInFlight.current = false;
    }
  }

  async function handleCloseBlackBoxSessions() {
    const bridge = window.mythosStudio;
    if (!bridge || labRunnerState === "idle") {
      pushLog("No local lab sessions are open.", "blocked");
      return;
    }
    setBusy("lab-close");
    try {
      const event = parseBlackBoxRunnerEvent(await bridge.closeBlackBoxSessions());
      if (event.event !== "sessions_closed" && event.event !== "stop") {
        throw new Error("sessions_not_closed");
      }
      resetBlackBoxLabState();
      pushLog("Local lab stopped; ephemeral session and review state cleared.", "safe");
    } catch (error) {
      pushMutationFailure("Local lab stop", error);
    } finally {
      setBusy(null);
    }
  }

  async function handleOpenWorkspace() {
    if (!workspacePath.trim()) {
      pushLog("Enter a local workspace path before opening.", "blocked");
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
        pushLog("Workspace manifest was not found.", "blocked");
        return;
      }
      applyStudioProjection(projection);
      setMissionDossierExport(null);
      setBenchmarkResult(null);
      pushLog("Workspace opened locally.", "safe");
    } catch (error) {
      pushMutationFailure("Workspace open", error);
    } finally {
      setBusy(null);
    }
  }

  async function handleCreateDesktopBackup() {
    const createBackup = window.mythosStudio?.createBackup;
    if (!createBackup) {
      pushLog("Desktop backup is available only in Mythos Studio.", "blocked");
      return;
    }
    setBusy("backup");
    try {
      const result = await createBackup();
      if (result.status !== "created") {
        pushLog("Backup was not created. No state was changed.", "blocked");
        return;
      }
      pushLog(`Local backup created: ${result.archive_name}.`, "safe");
    } catch {
      pushLog("Backup failed. No success state was recorded.", "blocked");
    } finally {
      setBusy(null);
    }
  }

  async function handleRestoreDesktopBackup() {
    const restoreBackup = window.mythosStudio?.restoreBackup;
    if (!restoreBackup) {
      pushLog("Desktop restore is available only in Mythos Studio.", "blocked");
      return;
    }
    setBusy("restore");
    try {
      const result = await restoreBackup();
      if (result.status !== "restored") {
        pushLog("Backup was not restored. Current state remains active.", "blocked");
        return;
      }
      pushLog("Local state restored. Reloading Studio.", "safe");
      window.setTimeout(() => window.location.reload(), 50);
    } catch {
      pushLog("Restore failed. Current state remains active.", "blocked");
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
        pushLog("Workspace creation failed. Check that the local API is running.", "blocked");
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
      pushLog("Workspace created locally. Scope Guard is waiting for authorized inputs.", "safe");
    } catch (error) {
      pushMutationFailure("Workspace creation", error);
    } finally {
      setBusy(null);
    }
  }

  async function handleImportArtifacts() {
    if (!workspacePath) {
      pushLog("Create or open a workspace before importing artifacts.", "blocked");
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
        pushLog("Authorized artifact references imported. Sensitive items remain review-gated.", "safe");
      }
    } catch (error) {
      pushMutationFailure("Artifact import", error);
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
      pushLog("Desktop path picker is available only in Mythos Studio.", "blocked");
      return;
    }
    const selected =
      mode === "directory" ? await bridge.selectDirectory() : await bridge.selectFile({ title });
    if (selected) {
      setter(selected);
      pushLog("Local path selected. Artifact contents remain local and review-gated.", "safe");
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
        pushLog("Research run did not start. Scope and code artifacts are required.", "blocked");
        return;
      }
      const projection = await refreshStudioProjection({
        dependencies: studioRefreshDependencies,
        signal: new AbortController().signal,
        workspacePath,
      });
      if (!projection) {
        pushLog("Research projection was not available. No success state was recorded.", "blocked");
        return;
      }
      applyStudioProjection(projection);
      setMissionDossierExport(null);
      setBenchmarkResult(null);
      pushLog(
        `Research run ${run.run_id} produced ${run.candidate_count} submission-blocked candidates.`,
        "safe",
      );
    } catch (error) {
      pushMutationFailure("Research run", error);
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
        pushLog("Campaign hunter launch failed. Check imported API/HAR/code materials.", "blocked");
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
        `Campaign hunter ${launched.campaign.id} started with ${suggestionCount} review-gated suggestions.`,
        "safe",
      );
    } catch (error) {
      pushMutationFailure("Campaign hunter launch", error);
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
          notes: `${action.nextAction}; validation and submission remain blocked.`,
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
        `Recorded ${outcome} learning feedback for ${action.candidateId}.`,
        "safe",
        "operator",
      );
    } catch (error) {
      pushMutationFailure("Learning feedback", error);
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
          notes: `${candidate.reportReadiness.nextAllowedAction}; human outcome ${outcome}; validation and submission remain blocked.`,
          outcome,
          playbook_id: candidate.title,
          reviewer: "studio-human-review",
          run_id: latestRunId,
          surface_key: candidate.affectedEndpoint,
          trace_status: candidate.evidenceTraceSummary.status,
        },
      );
      setLearningProfile(profile);
      pushLog(`Recorded ${outcome} learning feedback for ${candidate.id}.`, "safe", "operator");
    } catch (error) {
      pushMutationFailure("Learning feedback", error);
    } finally {
      setBusy(null);
    }
  }

  async function handleExportReport() {
    if (!workspacePath || (!latestRunId && !latestCampaignHunterId)) {
      pushLog("Run research or launch campaign hunter before exporting a report preview.", "blocked");
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
        pushLog("Report preview export failed.", "blocked");
        return;
      }
      setReportExport(exported);
      setManifest(exported.manifest);
      if (latestRunId) {
        await refreshMissionPanel(workspacePath, latestRunId);
      }
      pushLog("Report preview exported with submission still blocked.", "safe");
    } catch (error) {
      pushMutationFailure("Report preview export", error);
    } finally {
      setBusy(null);
    }
  }

  async function handleExportMissionDossier() {
    if (!workspacePath || !latestRunId) {
      pushLog("Run research before exporting a mission dossier.", "blocked");
      return;
    }
    setBusy("mission-dossier");
    try {
      const exported = await exportStudioWorkspaceMissionDossier(
        { run_id: latestRunId, workspace_path: workspacePath },
      );
      if (!exported) {
        pushLog("Mission dossier export failed.", "blocked");
        return;
      }
      setMissionDossierExport(exported);
      setManifest(exported.manifest);
      await refreshMissionPanel(workspacePath, latestRunId);
      pushLog("Mission dossier exported locally with validation and submission still blocked.", "safe");
    } catch (error) {
      pushMutationFailure("Mission dossier export", error);
    } finally {
      setBusy(null);
    }
  }

  async function handleRunBenchmark() {
    if (!workspacePath || !latestRunId) {
      pushLog("Run research before benchmarking candidates.", "blocked");
      return;
    }
    if (!expectationsPath.trim()) {
      pushLog("Select a local benchmark expectation file before benchmarking.", "blocked");
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
        pushLog("Candidate benchmark failed to run.", "blocked");
        return;
      }
      setBenchmarkResult(benchmark);
      setManifest(benchmark.manifest);
      await refreshMissionPanel(workspacePath, latestRunId);
      pushLog(
        `Candidate benchmark ${benchmark.benchmark.status ?? "finished"}: ${benchmark.benchmark.matched ?? 0}/${benchmark.benchmark.expected_count ?? 0} expected candidates matched.`,
        benchmark.benchmark.status === "passed" ? "safe" : "blocked",
      );
    } catch (error) {
      pushMutationFailure("Candidate benchmark", error);
    } finally {
      setBusy(null);
    }
  }

  async function handleCreateBenchmarkTemplate() {
    if (!workspacePath || !latestRunId) {
      pushLog("Run research before creating a benchmark template.", "blocked");
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
        pushLog("Benchmark template was not created.", "blocked");
        return;
      }
      setManifest(template.manifest);
      if (template.template_path) {
        setExpectationsPath(template.template_path);
      }
      await refreshMissionPanel(workspacePath, latestRunId);
      pushLog("Benchmark expectation template created for human review.", "safe");
    } catch (error) {
      pushMutationFailure("Benchmark template", error);
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
    const status = error instanceof ApiRequestError && error.status > 0 ? ` (API ${error.status})` : "";
    pushLog(`${action} failed${status}. No success state was recorded.`, "blocked");
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
          label: "Complete workspace setup in navigation",
          onClick: () => undefined,
        }
      : currentWizardStep === "authorized_materials"
        ? {
            busy: busy === "import",
            disabled: !workspacePath,
            icon: <Upload size={16} aria-hidden="true" />,
            label: "Import authorized materials",
            onClick: handleImportArtifacts,
          }
        : currentWizardStep === "readiness_check"
          ? {
              busy: busy === "research",
              disabled: !researchReadiness.canStart,
              icon: <Play size={16} aria-hidden="true" />,
              label: "Start local research",
              onClick: handleStartResearch,
            }
          : {
              busy: false,
              disabled: studioView.selectedCandidate === null,
              icon: <ShieldCheck size={16} aria-hidden="true" />,
              label: "Review selected candidate",
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
              <span className="text-[10px] text-[var(--warning)]">{candidate.status}</span>
            </span>
            <span className="truncate text-xs text-[var(--muted)]">{candidate.title}</span>
          </button>
        ))
      )}
    </div>
  );

  const studioNavigation = (
    <div className="grid gap-4 text-sm">
      <nav aria-label="Studio 工作区分区" className="grid gap-1">
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
          label="Workspace path"
          onBrowse={() =>
            handleSelectPath({
              mode: "directory",
              setter: setWorkspacePath,
              title: "Select Mythos workspace",
            })
          }
          onChange={setWorkspacePath}
          value={workspacePath}
        />
        <ActionButton
          busy={busy === "open"}
          icon={<FolderOpen size={16} aria-hidden="true" />}
          label="Open workspace"
          onClick={handleOpenWorkspace}
        />
        <div className="mt-4 grid gap-3 border-t border-[var(--line)] pt-4">
          <TextField
            browseEnabled={desktopPickerAvailable}
            label="Workspace root"
            onBrowse={() =>
              handleSelectPath({
                mode: "directory",
                setter: setWorkspaceRoot,
                title: "Select workspace root",
              })
            }
            value={workspaceRoot}
            onChange={setWorkspaceRoot}
          />
          <TextField label="Workspace name" value={workspaceName} onChange={setWorkspaceName} />
          <ActionButton
            busy={busy === "workspace"}
            icon={<FolderPlus size={16} aria-hidden="true" />}
            label="Create workspace"
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
        <StatusRow label="Scope Guard" value={workspace.scopeGuardLabel} warning />
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
      className="gap-0"
      data-testid="studio-inspector"
      onValueChange={(value) =>
        setInspectorTab(value as "candidate" | "evidence" | "report" | "validation")
      }
      value={inspectorTab}
    >
      <TabsList
        aria-label="候选检查器"
        className="grid h-10 w-full grid-cols-4 rounded-none border-b border-[var(--line)] bg-transparent p-0"
        variant="line"
      >
        {inspectorTabs.map((tab) => (
          <TabsTrigger
            className="rounded-none px-1 text-xs"
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
                  label="Record needs-evidence learning"
                  onClick={() => handleRecordCandidateCardLearning(studioView.selectedCandidate!, "needs_more_evidence")}
                />
                <ActionButton
                  busy={busy === `candidate-learning:${studioView.selectedCandidate.id}:refuted`}
                  icon={<ShieldCheck size={16} aria-hidden="true" />}
                  label="Record refuted learning"
                  onClick={() => handleRecordCandidateCardLearning(studioView.selectedCandidate!, "refuted")}
                />
                <ActionButton
                  busy={busy === `candidate-learning:${studioView.selectedCandidate.id}:duplicate`}
                  icon={<ShieldCheck size={16} aria-hidden="true" />}
                  label="Record duplicate learning"
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
                  label="Export report preview"
                  onClick={handleExportReport}
                />
                <ActionButton
                  busy={busy === "mission-dossier"}
                  disabled={!latestRunId}
                  icon={<FileDown size={16} aria-hidden="true" />}
                  label="Export mission dossier"
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
      safetyLabel="submission-blocked"
      workspaceName={workspace.name}
    >
      <div className="min-w-0 [&_.bg-white]:!bg-[var(--surface)]">
      <header className="border-b border-[var(--line)] pb-5" id="studio-mission">
        <p className="flex items-center gap-2 text-sm font-semibold text-[var(--accent-strong)]">
          <ShieldCheck size={17} aria-hidden="true" />
          Mythos Studio
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
        <SectionHeader title="Local research setup" />
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
          <p className="font-semibold">Next safe action</p>
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
            label="Launch campaign hunter"
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
              <span className="block font-semibold">Model assistance for next run only</span>
              <span className="mt-1 block text-[var(--muted)]">
                Optional proposals remain unverified and all credentials stay in the backend environment.
              </span>
            </span>
          </label>
          {candidateModelEnabled ? (
            <div className="mt-4 grid gap-3 md:grid-cols-2">
              <label className="grid gap-2 text-sm font-medium">
                Provider
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
                label="Model name"
                onChange={setCandidateModelName}
                value={candidateModelName}
              />
            </div>
          ) : null}
        </div>
        <div className="grid gap-3 border-t border-[var(--line)] p-5 text-sm md:grid-cols-2">
          <div>
            <p className="font-semibold">Required inputs</p>
            <p className="mt-2 text-[var(--muted)]">
              {missingRequiredArtifacts.length === 0
                ? "Required inputs are ready."
                : `Missing required inputs: ${missingRequiredArtifacts
                    .map((item) => item.label)
                    .join(", ")}`}
            </p>
          </div>
          <div>
            <p className="font-semibold">Optional context</p>
            <p className="mt-2 text-[var(--muted)]">
              {optionalContextArtifacts.map((item) => `${item.label}: ${item.status}`).join(", ")}
            </p>
          </div>
        </div>
      </section>

      <section className="mt-6 border border-[var(--line)] bg-white">
        <SectionHeader title="Remote human-lease profile (read-only)" />
        <div className="grid gap-4 p-5 text-sm">
          <div className="flex flex-wrap items-start justify-between gap-3">
            <p className="max-w-3xl text-[var(--muted)]">{remoteStatusView.detail}</p>
            <ActionButton
              busy={busy === "remote-status"}
              disabled={Boolean(busy) && busy !== "remote-status"}
              icon={<ShieldCheck size={16} aria-hidden="true" />}
              label="Refresh remote status"
              onClick={handleRefreshRemoteStatus}
            />
          </div>
          <dl className="grid gap-3 sm:grid-cols-3">
            <StatusRow
              label="Lease state"
              value={remoteStatusView.label}
              warning={remoteStatusView.warning}
            />
            <StatusRow
              label="Re-login required"
              value={remoteReloginRequired ? "yes" : "no"}
              warning={remoteReloginRequired}
            />
            <StatusRow label="Report submission" value="blocked" />
          </dl>
          <p className="text-xs text-[var(--muted)]">
            Report submission remains blocked. Human confirmation remains blocked. Any first real
            run must be user-operated with a fresh dedicated approval; no background scheduling,
            retry, discovery, or CI execution is available here.
          </p>
        </div>
      </section>

      <section className="mt-6 border-y border-[var(--line)]" id="studio-lab">
        <SectionHeader title="Local black-box lab (explicit)" />
        <details className="p-5 text-sm">
          <summary className="cursor-pointer font-semibold">Enable explicit local black-box lab</summary>
          <div className="mt-4 grid gap-4">
            <p className="text-[var(--muted)]">
              Loopback only, two isolated sessions, one declared read-only workflow, and one
              approved replay. Ephemeral only - not written to workspace manifest.
            </p>
            <div className="grid gap-3 md:grid-cols-2">
              <label className="grid gap-1 text-sm">
                <span className="text-xs font-semibold uppercase text-[var(--muted)]">
                  Active loopback origin
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
                  Durable validation run ID
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
                <span>Session A ready</span>
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
                <span>Session B ready</span>
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
                label="Preview bounded lease"
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
                label="Create two sessions"
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
                label="Start recording"
                onClick={handleStartBlackBoxRecording}
              />
              <ActionButton
                busy={busy === "lab-stop-recording"}
                disabled={Boolean(busy) || labRunnerState !== "recording"}
                icon={<ShieldCheck size={16} aria-hidden="true" />}
                label="Stop recording"
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
                label="Review normalized traces"
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
                label="Review and approve complete plan"
                onClick={handleApproveBlackBoxLabRun}
              />
              <ActionButton
                busy={busy === "lab-close"}
                disabled={Boolean(busy) || labRunnerState === "idle"}
                icon={<ShieldCheck size={16} aria-hidden="true" />}
                label="Stop local lab"
                onClick={handleCloseBlackBoxSessions}
              />
            </div>
            <dl className="grid gap-3 sm:grid-cols-4">
              <StatusRow label="Runner state" value={labRunnerState} />
              <StatusRow
                label="Lease review"
                value={labLeasePreview ? "reviewed" : "required"}
                warning={!labLeasePreview}
              />
              <StatusRow
                label="Human trace review"
                value={labTraceReviewConfirmed ? "confirmed" : "required"}
                warning={!labTraceReviewConfirmed}
              />
              <StatusRow
                label="Bounded result"
                value={labBoundedResult ? "recorded" : "not recorded"}
                warning={!labBoundedResult}
              />
            </dl>
            {labBoundedResult ? (
              <p className="text-xs text-[var(--muted)]">
                {labBoundedResult.report_preview_refreshed
                  ? "Report preview refreshed from the bounded local-lab result; human review remains required."
                  : "Bounded local-lab result recorded; human review remains required."}
              </p>
            ) : null}
            {labTraceReview.length > 0 ? (
              <div className="border-t border-[var(--line)] pt-4">
                <p className="font-semibold">Normalized traces</p>
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

      <div className="mt-6 grid gap-5">
        <section className="border-b border-[var(--line)] pb-5">
          <SectionHeader title="Authorized materials / evaluation" />
          <div className="grid gap-4 p-5 text-sm">
            <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-4">
              <TextField
                browseEnabled={desktopPickerAvailable}
                label="Policy file"
                onBrowse={() =>
                  handleSelectPath({
                    mode: "file",
                    setter: setPolicyPath,
                    title: "Select policy file",
                  })
                }
                value={policyPath}
                onChange={setPolicyPath}
              />
              <TextField
                browseEnabled={desktopPickerAvailable}
                label="Scope file"
                onBrowse={() =>
                  handleSelectPath({
                    mode: "file",
                    setter: setScopePath,
                    title: "Select scope file",
                  })
                }
                value={scopePath}
                onChange={setScopePath}
              />
              <TextField
                browseEnabled={desktopPickerAvailable}
                label="Code directory"
                onBrowse={() =>
                  handleSelectPath({
                    mode: "directory",
                    setter: setCodePath,
                    title: "Select authorized code directory",
                  })
                }
                value={codePath}
                onChange={setCodePath}
              />
              <TextField
                browseEnabled={desktopPickerAvailable}
                label="API file"
                onBrowse={() =>
                  handleSelectPath({
                    mode: "file",
                    setter: setApiPath,
                    title: "Select API artifact",
                  })
                }
                value={apiPath}
                onChange={setApiPath}
              />
              <TextField
                browseEnabled={desktopPickerAvailable}
                label="HAR file"
                onBrowse={() =>
                  handleSelectPath({
                    mode: "file",
                    setter: setHarPath,
                    title: "Select HAR file",
                  })
                }
                value={harPath}
                onChange={setHarPath}
              />
              <TextField
                browseEnabled={desktopPickerAvailable}
                label="SBOM file"
                onBrowse={() =>
                  handleSelectPath({
                    mode: "file",
                    setter: setSbomPath,
                    title: "Select SBOM file",
                  })
                }
                value={sbomPath}
                onChange={setSbomPath}
              />
              <TextField
                browseEnabled={desktopPickerAvailable}
                label="SARIF file"
                onBrowse={() =>
                  handleSelectPath({
                    mode: "file",
                    setter: setSarifPath,
                    title: "Select SARIF file",
                  })
                }
                value={sarifPath}
                onChange={setSarifPath}
              />
              <TextField
                browseEnabled={desktopPickerAvailable}
                label="Fuzzing plan"
                onBrowse={() =>
                  handleSelectPath({
                    mode: "file",
                    setter: setFuzzingPath,
                    title: "Select fuzzing plan",
                  })
                }
                value={fuzzingPath}
                onChange={setFuzzingPath}
              />
              <TextField
                browseEnabled={desktopPickerAvailable}
                label="Strategy file"
                onBrowse={() =>
                  handleSelectPath({
                    mode: "file",
                    setter: setStrategyPath,
                    title: "Select strategy notes",
                  })
                }
                value={strategyPath}
                onChange={setStrategyPath}
              />
              <TextField
                browseEnabled={desktopPickerAvailable}
                label="Knowledge file"
                onBrowse={() =>
                  handleSelectPath({
                    mode: "file",
                    setter: setKnowledgePath,
                    title: "Select knowledge pattern file",
                  })
                }
                value={knowledgePath}
                onChange={setKnowledgePath}
              />
            </div>
            <div className="border-t border-[var(--line)] p-4">
              <p className="font-semibold">Artifact readiness</p>
              <div className="mt-3 grid gap-2 sm:grid-cols-2 xl:grid-cols-3">
                {artifactChecklist.map((item) => (
                  <span
                    className={`border-l-2 border-[var(--line)] px-3 py-2 ${checklistTone(item.status)}`}
                    key={item.kind}
                  >
                    {item.label}: {item.status}
                  </span>
                ))}
              </div>
              <p className="mt-3 text-[var(--muted)]">{researchReadiness.reason}</p>
            </div>
            <div className="border-t border-[var(--line)] p-4">
              <p className="font-semibold">A+B benchmark</p>
              <div className="mt-3 grid gap-3 md:grid-cols-[minmax(0,1fr)_auto]">
                <TextField
                  browseEnabled={desktopPickerAvailable}
                  label="Expectation file"
                  onBrowse={() =>
                    handleSelectPath({
                      mode: "file",
                      setter: setExpectationsPath,
                      title: "Select benchmark expectation file",
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
                      label="Create template"
                      onClick={handleCreateBenchmarkTemplate}
                    />
                    <ActionButton
                      busy={busy === "benchmark"}
                      disabled={!latestRunId}
                      icon={<ShieldCheck size={16} aria-hidden="true" />}
                      label="Run benchmark"
                      onClick={handleRunBenchmark}
                    />
                  </div>
                </div>
              </div>
              {benchmarkResult ? (
                <div className="mt-4 space-y-3">
                  <dl className="grid gap-3 sm:grid-cols-3">
                    <StatusRow
                      label="Benchmark"
                      value={benchmarkResult.benchmark.status ?? "unknown"}
                      warning={benchmarkResult.benchmark.status !== "passed"}
                    />
                    <StatusRow
                      label="Matched"
                      value={`${benchmarkResult.benchmark.matched ?? 0}/${benchmarkResult.benchmark.expected_count ?? 0}`}
                    />
                    <StatusRow
                      label="Result path"
                      value={benchmarkResult.benchmark_path ?? "No result path"}
                    />
                  </dl>
                  {benchmarkEvidenceGaps.length > 0 ? (
                    <div>
                      <p className="text-xs font-semibold uppercase text-[var(--muted)]">
                        Evidence gaps
                      </p>
                      <ul className="mt-2 space-y-1 text-xs text-[var(--muted)]">
                        {benchmarkEvidenceGaps.map((gap, index) => (
                          <li key={`${gap.name ?? "gap"}-${gap.artifact_kind ?? "artifact"}-${index}`}>
                            {gap.name ?? "candidate"}: {gap.artifact_kind ?? "artifact"} -{" "}
                            {gap.reason ?? "needs_review"}
                          </li>
                        ))}
                      </ul>
                    </div>
                  ) : null}
                </div>
              ) : null}
            </div>
            <div className="border-t border-[var(--line)] p-4">
              <p className="font-semibold">Research intent</p>
              <p className="mt-2 text-[var(--muted)]">
                Access control, role boundaries, refutation first.
              </p>
            </div>
          </div>
        </section>

        <section className="border-b border-[var(--line)] pb-5" data-testid="studio-mission-details">
          <SectionHeader title="Mission details" />
          <div className="grid gap-4 p-5 text-sm">
            <div className="border-t border-[var(--line)] pt-4">
              <p className="font-semibold">Mission control</p>
              <dl className="mt-3 grid gap-3">
                <StatusRow label="Mode" value={missionPanel.modeLabel} />
                <StatusRow label="Run" value={missionPanel.runId} />
                <StatusRow label="Scope Guard" value={missionPanel.scopeGuardLabel} warning />
                <StatusRow label="Artifact coverage" value={missionPanel.artifactCoverage} />
                <StatusRow label="Advisory context" value={missionPanel.advisoryContextLabel} />
                <StatusRow label="Candidates" value={missionPanel.candidateCountLabel} />
                <StatusRow
                  label="Report gate"
                  value={missionPanel.gates.submissionBlocked ? "submission-blocked" : "review required"}
                  warning
                />
                <StatusRow
                  label="Validation gate"
                  value={
                    missionPanel.gates.validationExecutionAllowed
                      ? "human review required"
                      : "execution blocked"
                  }
                  warning
                />
                <StatusRow
                  label="Candidate quality"
                  value={`${missionPanel.qualitySummary.topCandidateQualityGate} (${missionPanel.qualitySummary.reviewReadyCount}/${missionPanel.qualitySummary.candidateCount} review-ready, avg ${missionPanel.qualitySummary.averageQualityScore})`}
                  warning={!missionPanel.gates.topCandidateQualityGate}
                />
              </dl>
              <ListBlock
                title="Mission quality blockers"
                items={missionPanel.qualitySummary.blockers}
              />
              <ListBlock
                title="Candidate improvement actions"
                items={missionPanel.qualitySummary.improvementActions}
              />
              <ListBlock
                title="Attack surface model"
                items={[
                  attackSurfaceModelLine(missionPanel.attackSurfaceModel),
                  ...missionPanel.attackSurfaceModel.topRoutes.map(attackSurfaceRouteLine),
                ]}
              />
              <ListBlock
                title="Candidate hunter backlog"
                items={missionPanel.candidateHunterBacklog.map(candidateHunterBacklogLine)}
              />
              <ListBlock
                title="Candidate hunter iteration"
                items={[candidateHunterIterationLine(missionPanel.candidateHunterIteration)]}
              />
              <ListBlock
                title="Candidate hunter plan"
                items={[candidateHunterPlanLine(missionPanel.candidateHunterPlan)]}
              />
              <ListBlock
                title="Candidate hunter plan steps"
                items={missionPanel.candidateHunterPlan.planSteps.map(candidateHunterPlanStepLine)}
              />
              <ListBlock
                title="Candidate hunter review loop"
                items={[candidateHunterReviewLoopLine(missionPanel.candidateHunterReviewLoop)]}
              />
              <ListBlock
                title="Candidate hunter review loop steps"
                items={missionPanel.candidateHunterReviewLoop.activeSteps.map(
                  candidateHunterReviewLoopStepLine,
                )}
              />
              <ListBlock
                title="Candidate hunter refutation queue"
                items={missionPanel.candidateHunterExecutionLoop.refutationQueue.map(
                  candidateHunterRefutationQueueLine,
                )}
              />
              <ListBlock
                title="Candidate hunter evidence matrix"
                items={missionPanel.candidateHunterExecutionLoop.candidateEvidenceMatrix.map(
                  candidateHunterEvidenceMatrixLine,
                )}
              />
              <ListBlock
                title="Candidate hunter ranked Top 1-5"
                items={missionPanel.candidateHunterExecutionLoop.rankedTopCandidates.map(
                  candidateHunterRankedTopCandidateLine,
                )}
              />
              <ListBlock
                title="Candidate hunter deduplication queue"
                items={missionPanel.candidateHunterExecutionLoop.deduplicationQueue.map(
                  candidateHunterDeduplicationQueueLine,
                )}
              />
              <ListBlock
                title="Candidate hunter safe validation queue"
                items={missionPanel.candidateHunterExecutionLoop.safeValidationQueue.map(
                  candidateHunterSafeValidationQueueLine,
                )}
              />
              <ListBlock
                title="Candidate hunter report draft queue"
                items={missionPanel.candidateHunterExecutionLoop.reportDraftQueue.map(
                  candidateHunterReportDraftQueueLine,
                )}
              />
              <div className="mt-4">
                <p className="text-xs font-semibold uppercase text-[var(--muted)]">
                  Candidate hunter learning feedback
                </p>
                <p className="mt-2 text-[var(--muted)]">
                  {candidateHunterLearningFeedbackLine(
                    missionPanel.candidateHunterExecutionLoop.learningFeedbackTarget,
                  )}
                </p>
                <div className="mt-3 grid gap-2">
                  {missionPanel.candidateHunterExecutionLoop.learningReviewActions.length === 0 ? (
                    <p className="text-[var(--muted)]">Review required.</p>
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
                          label="Record suggested outcome"
                          onClick={() => handleRecordCandidateHunterLearning(action)}
                        />
                      </div>
                    ))
                  )}
                </div>
                {learningProfile?.recent_learning_signals[0] ? (
                  <p className="mt-3 text-[var(--muted)]">
                    Recent learning signal:{" "}
                    {learningProfile.recent_learning_signals[0].playbook_id} -{" "}
                    {learningProfile.recent_learning_signals[0].outcome}
                  </p>
                ) : null}
              </div>
              <ListBlock
                title="Research loop"
                items={missionPanel.researchLoopStages.map(
                  (stage) => `${stage.label}: ${stage.status} - ${stage.summary}`,
                )}
              />
              <ListBlock
                title="Agent queue"
                items={missionPanel.agentQueue.map(agentQueueLine)}
              />
              <ListBlock
                title="Studio timeline summary"
                items={[studioTimelineSummaryLine(missionPanel.studioTimelineSummary)]}
              />
              <ListBlock
                title="Candidate review packets"
                items={missionPanel.candidateReviewPackets.map(candidateReviewPacketLine)}
              />
              <ListBlock
                title="Redacted evidence review queue"
                items={missionPanel.candidateReviewPackets.map(redactedEvidenceReviewLine)}
              />
              <ListBlock
                title="Submission-blocked report summary"
                items={[
                  submissionBlockedReportSummaryLine(
                    missionPanel.submissionBlockedReportSummary,
                  ),
                ]}
              />
              <TextBlock title="Handoff brief" value={missionHandoffBrief} />
              <ListBlock
                title="Agent handoff pack"
                items={[agentHandoffPackLine(missionPanel.agentHandoffPack)]}
              />
              <ListBlock
                title="Agent handoff items"
                items={missionPanel.agentHandoffPack.handoffItems.map(agentHandoffItemLine)}
              />
              <ListBlock
                title="Agent task timeline"
                items={missionPanel.agentTaskTimeline.map(agentTaskTimelineLine)}
              />
              <ListBlock title="Safe next actions" items={missionPanel.safeNextActions} />
              <ListBlock
                title="Mission Top candidates"
                items={missionPanel.topCandidates.map(missionCandidateLine)}
              />
            </div>
            <p className="font-semibold text-[var(--warning)]">submission-blocked</p>
            <div className="grid gap-2">
              {workspace.blockedActions.map((action) => (
                <span key={action} className="border border-[var(--line)] px-3 py-2 text-[var(--muted)]">
                  {action}
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
    <label className="grid gap-1 text-sm">
      <span className="text-xs font-semibold uppercase text-[var(--muted)]">{label}</span>
      <span className="grid gap-2">
        <input
          className="min-h-10 rounded-md border border-[var(--line)] bg-white px-3 outline-none focus:border-[var(--accent)]"
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
            Browse
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
      {busy ? "Working" : label}
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
        <p className="mt-2 text-[var(--muted)]">Review required.</p>
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
    model.sourceArtifactKinds.length > 0 ? model.sourceArtifactKinds.join(", ") : "none";
  const methods = model.methods.length > 0 ? model.methods.join(", ") : "none";
  const gates = [
    model.executionAllowed ? "execution allowed" : "execution blocked",
    model.validationAllowed ? "validation allowed" : "validation blocked",
    model.reportSubmissionAllowed ? "submission allowed" : "submission blocked",
  ].join(", ");
  return `${model.status}; routes ${model.routeCount} (api ${model.apiRouteCount}, har ${model.harRouteCount}); advisory signals ${model.advisorySignalCount}; methods ${methods}; sources ${sources}; gate ${model.safetyGate}; next ${model.nextAction}; ${gates}`;
}

function attackSurfaceRouteLine(
  route: ReturnType<typeof toStudioMissionPanel>["attackSurfaceModel"]["topRoutes"][number],
): string {
  const sources = route.artifactKinds.length > 0 ? route.artifactKinds.join(", ") : "artifact";
  return `${route.method} ${route.path}; sources ${sources}`;
}

function missionCandidateLine(
  candidate: ReturnType<typeof toStudioMissionPanel>["topCandidates"][number],
): string {
  const qualityReasons = candidate.qualityReasons.join(", ") || "needs_review";
  const crossChecks =
    candidate.hallucinationGuard.independentCrossCheckSources.join(", ") || "none";
  return [
    `${candidate.hypothesisId}: ${candidate.affectedEndpoint} -> ${candidate.affectedCodePath}`,
    `evidence ${candidate.evidenceReviewStatus}/${candidate.evidenceNeedCount}`,
    `refutation ${candidate.refutationStatus}/${candidate.refutationReviewStatus}`,
    `provenance ${candidate.provenanceReviewStatus}`,
    `dedup ${candidate.deduplicationReviewStatus}`,
    `validation ${candidate.validationStatus}/${candidate.safeValidationStepCount}`,
    `quality ${candidate.qualityStatus}/${candidate.qualityScore} (${qualityReasons})`,
    `hallucination ${candidate.hallucinationGuard.status}/${candidate.hallucinationGuard.modelOutputStatus}`,
    `independent challenge ${crossChecks}`,
    `report ${candidate.reportStatus}`,
  ].join("; ");
}

function agentQueueLine(
  task: ReturnType<typeof toStudioMissionPanel>["agentQueue"][number],
): string {
  const inputs = task.inputRefs.length > 0 ? task.inputRefs.join(", ") : "no refs";
  const focus = task.reviewFocus.length > 0 ? `; focus ${task.reviewFocus.join(", ")}` : "";
  const gaps =
    task.candidateQualityGaps.length > 0
      ? `; quality gaps ${task.candidateQualityGaps.join(", ")}`
      : "";
  const candidates =
    task.targetCandidates.length > 0 ? `; candidates ${task.targetCandidates.join(", ")}` : "";
  const prefix = `${task.taskId}: ${task.agent} - ${task.status}`;
  return `${prefix}; gate ${task.safetyGate}; inputs ${inputs}${focus}${candidates}${gaps}; ${task.nextAction}`;
}

function agentTaskTimelineLine(
  stage: ReturnType<typeof toStudioMissionPanel>["agentTaskTimeline"][number],
): string {
  return `${stage.stageId}: ${stage.status}/${stage.gateDecision}; ${stage.inputSummary}; ${stage.outputSummary}; next ${stage.nextHumanAction}`;
}

function studioTimelineSummaryLine(
  summary: ReturnType<typeof toStudioMissionPanel>["studioTimelineSummary"],
): string {
  const counts = Object.entries(summary.gateDecisionCounts)
    .map(([gate, count]) => `${gate} ${count}`)
    .join(", ") || "no stages";
  const blocked =
    summary.blockedStageIds.length > 0 ? summary.blockedStageIds.join(", ") : "none";
  const needsReview =
    summary.needsReviewStageIds.length > 0
      ? summary.needsReviewStageIds.join(", ")
      : "none";
  const pending =
    summary.pendingStageIds.length > 0 ? summary.pendingStageIds.join(", ") : "none";
  const nextActions =
    summary.nextHumanActions.length > 0
      ? summary.nextHumanActions.join("; ")
      : "Review required.";
  const gates = [
    summary.validationExecutionAllowed ? "validation allowed" : "validation blocked",
    summary.reportSubmissionAllowed ? "submission allowed" : "submission blocked",
  ].join(", ");
  return `stages ${summary.totalStages}; gates ${counts}; blocked ${blocked}; needs review ${needsReview}; pending ${pending}; safety ${summary.safetyGate}; next ${nextActions}; ${gates}`;
}

function candidateReviewPacketLine(
  packet: ReturnType<typeof toStudioMissionPanel>["candidateReviewPackets"][number],
): string {
  const missing =
    packet.missingItems.length > 0 ? packet.missingItems.join(", ") : "none";
  const completed =
    packet.completedItems.length > 0 ? packet.completedItems.join(", ") : "none";
  const gates = [
    packet.executionAllowed ? "execution allowed" : "execution blocked",
    packet.validationAllowed ? "validation allowed" : "validation blocked",
    packet.reportSubmissionAllowed ? "submission allowed" : "submission blocked",
  ].join(", ");
  return `${packet.candidateId}: ${packet.status}; priority ${packet.reportReviewPriority}; quality ${packet.qualityScore}/100; completed ${completed}; missing ${missing}; evidence ${packet.evidenceNeedCount}; refutation ${packet.falsePositiveCheckCount}; validation steps ${packet.safeValidationStepCount}; hallucination ${packet.hallucinationGuardStatus}; report ${packet.reportStatus}; gate ${packet.safetyGate}; next ${packet.nextHumanAction}; ${gates}`;
}

function redactedEvidenceReviewLine(
  packet: ReturnType<typeof toStudioMissionPanel>["candidateReviewPackets"][number],
): string {
  const missing =
    packet.missingItems.length > 0 ? packet.missingItems.join(", ") : "none";
  const completed =
    packet.completedItems.length > 0 ? packet.completedItems.join(", ") : "none";
  const gates = [
    packet.executionAllowed ? "execution allowed" : "execution blocked",
    packet.validationAllowed ? "validation allowed" : "validation blocked",
    packet.reportSubmissionAllowed ? "submission allowed" : "submission blocked",
  ].join(", ");
  return `${packet.candidateId}: redaction review ${packet.reportReviewPriority}; evidence needs ${packet.evidenceNeedCount}; missing ${missing}; completed ${completed}; gate ${packet.safetyGate}; next ${packet.nextHumanAction}; ${gates}`;
}

function submissionBlockedReportSummaryLine(
  summary: ReturnType<typeof toStudioMissionPanel>["submissionBlockedReportSummary"],
): string {
  const ready =
    summary.readyCandidateIds.length > 0 ? summary.readyCandidateIds.join(", ") : "none";
  const needsReview =
    summary.needsReviewCandidateIds.length > 0
      ? summary.needsReviewCandidateIds.join(", ")
      : "none";
  const missing = Object.entries(summary.missingReviewItems)
    .map(([candidateId, items]) => `${candidateId}: ${items.join(", ")}`)
    .join("; ") || "none";
  const nextActions =
    summary.nextHumanActions.length > 0
      ? summary.nextHumanActions.join("; ")
      : "Human redaction review required.";
  const reviewQueue =
    summary.reportReviewQueue.length > 0
      ? summary.reportReviewQueue
          .map((item) => `${item.candidateId}: ${item.priority} (${item.qualityScore}/100)`)
          .join("; ")
      : "none";
  const gates = [
    summary.validationExecutionAllowed ? "validation allowed" : "validation blocked",
    summary.reportSubmissionAllowed ? "submission allowed" : "submission blocked",
  ].join(", ");
  return `${summary.status}; candidates ${summary.candidateCount}; ready ${ready}; needs review ${needsReview}; missing ${missing}; report queue ${reviewQueue}; gate ${summary.safetyGate}; redaction review ${summary.redactionReviewRequired ? "required" : "missing"}; next ${nextActions}; ${gates}`;
}

function agentHandoffPackLine(
  pack: ReturnType<typeof toStudioMissionPanel>["agentHandoffPack"],
): string {
  const priority = pack.priorityOrder.length > 0 ? pack.priorityOrder.join(", ") : "none";
  const focus = pack.reviewFocus.length > 0 ? pack.reviewFocus.join(", ") : "review";
  const queueRefs =
    pack.agentQueueRefs.length > 0 ? pack.agentQueueRefs.join(", ") : "agent queue";
  const counts = Object.entries(pack.timelineGateCounts)
    .map(([gate, count]) => `${gate} ${count}`)
    .join(", ") || "no timeline gates";
  const blocked =
    pack.blockedActions.length > 0 ? pack.blockedActions.join(", ") : "no blocked actions";
  const gates = [
    pack.executionAllowed ? "execution allowed" : "execution blocked",
    pack.validationAllowed ? "validation allowed" : "validation blocked",
    pack.reportSubmissionAllowed ? "submission allowed" : "submission blocked",
  ].join(", ");
  return `${pack.packId}: ${pack.status}; next ${pack.nextReviewAgent}; items ${pack.handoffItemCount}; priority ${priority}; focus ${focus}; queue ${queueRefs}; timeline ${counts}; gate ${pack.safetyGate}/${pack.completionGate}; blocked ${blocked}; ${gates}`;
}

function agentHandoffItemLine(
  item: ReturnType<typeof toStudioMissionPanel>["agentHandoffPack"]["handoffItems"][number],
): string {
  const refs = item.inputRefs.length > 0 ? item.inputRefs.join(", ") : "no refs";
  const focus = item.reviewFocus.length > 0 ? item.reviewFocus.join(", ") : "review";
  const evidence =
    item.requiredEvidence.length > 0 ? item.requiredEvidence.join(", ") : "review notes";
  const criteria =
    item.successCriteria.length > 0 ? item.successCriteria.join("; ") : "human decision";
  const gates = [
    item.executionAllowed ? "execution allowed" : "execution blocked",
    item.validationAllowed ? "validation allowed" : "validation blocked",
    item.reportSubmissionAllowed ? "submission allowed" : "submission blocked",
  ].join(", ");
  return `${item.handoffId}: ${item.assignedAgent} handles ${item.workItemId} (${item.status}/${item.gap}); refs ${refs}; focus ${focus}; evidence ${evidence}; success ${criteria}; gate ${item.safetyGate}; next ${item.nextAction}; ${gates}`;
}

function candidateHunterBacklogLine(
  item: ReturnType<typeof toStudioMissionPanel>["candidateHunterBacklog"][number],
): string {
  const focus = item.reviewFocus.length > 0 ? item.reviewFocus.join(", ") : "candidate_quality";
  const evidence =
    item.requiredEvidence.length > 0 ? item.requiredEvidence.join(", ") : "review_notes";
  const gates = [
    item.executionAllowed ? "execution allowed" : "execution blocked",
    item.validationAllowed ? "validation allowed" : "validation blocked",
    item.reportSubmissionAllowed ? "submission allowed" : "submission blocked",
  ].join(", ");
  return `${item.workItemId}: ${item.gap} - ${item.status}; gate ${item.safetyGate}; focus ${focus}; evidence ${evidence}; ${gates}; ${item.nextAction}`;
}

function candidateHunterIterationLine(
  iteration: ReturnType<typeof toStudioMissionPanel>["candidateHunterIteration"],
): string {
  const priority =
    iteration.priorityOrder.length > 0 ? iteration.priorityOrder.join(", ") : "no backlog";
  const focus =
    iteration.reviewFocus.length > 0 ? iteration.reviewFocus.join(", ") : "candidate_quality";
  const criteria =
    iteration.successCriteria.length > 0
      ? iteration.successCriteria.join("; ")
      : "human review required";
  const gates = [
    iteration.executionAllowed ? "execution allowed" : "execution blocked",
    iteration.validationAllowed ? "validation allowed" : "validation blocked",
    iteration.reportSubmissionAllowed ? "submission allowed" : "submission blocked",
  ].join(", ");
  return `${iteration.iterationId}: ${iteration.status}; next ${iteration.nextReviewAgent}; work items ${iteration.workItemCount}; gate ${iteration.safetyGate}/${iteration.completionGate}; priority ${priority}; focus ${focus}; success ${criteria}; ${gates}`;
}

function candidateHunterPlanLine(
  plan: ReturnType<typeof toStudioMissionPanel>["candidateHunterPlan"],
): string {
  const gates = [
    plan.executionAllowed ? "execution allowed" : "execution blocked",
    plan.validationAllowed ? "validation allowed" : "validation blocked",
    plan.reportSubmissionAllowed ? "submission allowed" : "submission blocked",
  ].join(", ");
  const governance = [
    `claim ${plan.hallucinationGovernance.claimPromotionRule}`,
    `knowledge ${plan.hallucinationGovernance.knowledgePolicy}`,
    `promotion ${plan.hallucinationGovernance.candidatePromotionAllowed ? "allowed" : "blocked"}`,
  ].join(", ");
  return `${plan.planId}: ${plan.status}; next ${plan.nextReviewAgent}; work items ${plan.workItemCount}; steps ${plan.stepCount}; governance ${governance}; gate ${plan.safetyGate}/${plan.completionGate}; ${gates}`;
}

function candidateHunterPlanStepLine(
  step: ReturnType<typeof toStudioMissionPanel>["candidateHunterPlan"]["planSteps"][number],
): string {
  const refs = step.inputRefs.length > 0 ? step.inputRefs.join(", ") : "no refs";
  const focus = step.reviewFocus.length > 0 ? step.reviewFocus.join(", ") : "review";
  const evidence =
    step.requiredEvidence.length > 0 ? step.requiredEvidence.join(", ") : "review notes";
  const criteria =
    step.successCriteria.length > 0 ? step.successCriteria.join("; ") : "human decision";
  const checklist =
    step.reviewChecklist.length > 0
      ? step.reviewChecklist
          .map((item) => `${item.key}:${item.status}`)
          .join(", ")
      : "checklist pending";
  const governance =
    step.hallucinationGovernanceRefs.length > 0
      ? step.hallucinationGovernanceRefs.join("; ")
      : "LLM claims require local evidence and independent review";
  const gates = [
    step.executionAllowed ? "execution allowed" : "execution blocked",
    step.validationAllowed ? "validation allowed" : "validation blocked",
    step.reportSubmissionAllowed ? "submission allowed" : "submission blocked",
  ].join(", ");
  return `${step.stepId}: ${step.assignedAgent} handles ${step.workItemId} (${step.status}/${step.gap}); refs ${refs}; focus ${focus}; evidence ${evidence}; checklist ${checklist}; success ${criteria}; governance ${governance}; gate ${step.safetyGate}; next ${step.nextAction}; ${gates}`;
}

function candidateHunterReviewLoopLine(
  loop: ReturnType<typeof toStudioMissionPanel>["candidateHunterReviewLoop"],
): string {
  const agents = loop.reviewAgents.length > 0 ? loop.reviewAgents.join(", ") : "Human Reviewer";
  const evidence =
    loop.requiredEvidence.length > 0 ? loop.requiredEvidence.join(", ") : "review notes";
  const consensus =
    loop.governanceSummary.requiredConsensus.length > 0
      ? loop.governanceSummary.requiredConsensus.join(", ")
      : "human_review_decision";
  const gates = [
    loop.executionAllowed ? "execution allowed" : "execution blocked",
    loop.validationAllowed ? "validation allowed" : "validation blocked",
    loop.reportSubmissionAllowed ? "submission allowed" : "submission blocked",
  ].join(", ");
  return `${loop.loopId}: ${loop.status}; source ${loop.sourcePlanId}; active steps ${loop.activeStepCount}; next ${loop.nextReviewAgent}; agents ${agents}; evidence ${evidence}; consensus ${consensus}; gate ${loop.safetyGate}/${loop.completionGate}; ${gates}`;
}

function candidateHunterReviewLoopStepLine(
  step: ReturnType<typeof toStudioMissionPanel>["candidateHunterReviewLoop"]["activeSteps"][number],
): string {
  const evidence =
    step.requiredEvidence.length > 0 ? step.requiredEvidence.join(", ") : "review notes";
  const governance =
    step.governanceRefs.length > 0
      ? step.governanceRefs.join("; ")
      : "LLM claims require local evidence and independent review";
  const checklist =
    step.reviewChecklist.length > 0
      ? step.reviewChecklist.map((item) => `${item.key}:${item.status}`).join(", ")
      : "checklist pending";
  const criteria =
    step.successCriteria.length > 0 ? step.successCriteria.join("; ") : "human decision";
  const gates = [
    step.executionAllowed ? "execution allowed" : "execution blocked",
    step.validationAllowed ? "validation allowed" : "validation blocked",
    step.reportSubmissionAllowed ? "submission allowed" : "submission blocked",
  ].join(", ");
  return `${step.stepId}: ${step.assignedAgent} handles ${step.workItemId} (${step.gap}); evidence ${evidence}; governance ${governance}; checklist ${checklist}; success ${criteria}; gate ${step.safetyGate}; next ${step.nextAction}; ${gates}`;
}

function candidateHunterRefutationQueueLine(
  item: ReturnType<typeof toStudioMissionPanel>["candidateHunterExecutionLoop"]["refutationQueue"][number],
): string {
  const missingEvidence =
    item.missingEvidence.length > 0 ? item.missingEvidence.join(", ") : "none";
  const missingArtifacts =
    item.missingRequiredArtifactKinds.length > 0
      ? item.missingRequiredArtifactKinds.join(", ")
      : "none";
  const questions = item.questions.length > 0 ? item.questions.join("; ") : "review";
  const requiredEvidence =
    item.requiredEvidence.length > 0 ? item.requiredEvidence.join(", ") : "review notes";
  const gates = [
    item.executionAllowed ? "execution allowed" : "execution blocked",
    item.validationAllowed ? "validation allowed" : "validation blocked",
    item.reportSubmissionAllowed ? "submission allowed" : "submission blocked",
  ].join(", ");
  return `${item.queueId}: ${item.candidateId}; trace ${item.traceStatus}; priority ${item.priorityScore}; missing evidence ${missingEvidence}; missing artifacts ${missingArtifacts}; required evidence ${requiredEvidence}; questions ${questions}; gate ${item.safetyGate}; next ${item.nextAction}; ${gates}`;
}

function candidateHunterEvidenceMatrixLine(
  item: ReturnType<typeof toStudioMissionPanel>["candidateHunterExecutionLoop"]["candidateEvidenceMatrix"][number],
): string {
  const missingEvidence =
    item.missingEvidence.length > 0 ? item.missingEvidence.join(", ") : "none";
  const missingRequiredArtifacts =
    item.missingRequiredArtifactKinds.length > 0
      ? item.missingRequiredArtifactKinds.join(", ")
      : "none";
  const learnedEvidence =
    item.learningEvidenceNeededReasons.length > 0
      ? item.learningEvidenceNeededReasons.join(", ")
      : "none";
  const ranking =
    item.rankingSignalBreakdown.length > 0
      ? item.rankingSignalBreakdown.join(", ")
      : "ranking signals unavailable";
  const requiredEvidence =
    item.requiredEvidence.length > 0 ? item.requiredEvidence.join(", ") : "review notes";
  const gates = [
    item.executionAllowed ? "execution allowed" : "execution blocked",
    item.validationAllowed ? "validation allowed" : "validation blocked",
    item.reportSubmissionAllowed ? "submission allowed" : "submission blocked",
  ].join(", ");
  return `${item.candidateId}: quality ${item.qualityScore}; hunter ${item.hunterPriorityScore}; impact ${item.impactScore}; rejection risk ${item.rejectionRiskScore}; policy risk ${item.policyRiskScore}; endpoint ${item.affectedEndpoint}; code ${item.affectedCodePath}; missing evidence ${missingEvidence}; missing required artifacts ${missingRequiredArtifacts}; required evidence ${requiredEvidence}; learned evidence ${learnedEvidence}; ranking ${ranking}; ${gates}`;
}

function candidateHunterRankedTopCandidateLine(
  item: ReturnType<typeof toStudioMissionPanel>["candidateHunterExecutionLoop"]["rankedTopCandidates"][number],
): string {
  const ranking =
    item.rankingSignalBreakdown.length > 0
      ? item.rankingSignalBreakdown.join(", ")
      : "ranking signals unavailable";
  const requiredEvidence =
    item.requiredEvidence.length > 0 ? item.requiredEvidence.join(", ") : "review notes";
  const missingEvidence =
    item.missingEvidence.length > 0 ? item.missingEvidence.join(", ") : "none";
  const missingRequiredArtifacts =
    item.missingRequiredArtifactKinds.length > 0
      ? item.missingRequiredArtifactKinds.join(", ")
      : "none";
  const gates = [
    item.executionAllowed ? "execution allowed" : "execution blocked",
    item.validationAllowed ? "validation allowed" : "validation blocked",
    item.reportSubmissionAllowed ? "submission allowed" : "submission blocked",
  ].join(", ");
  return `#${item.rank} ${item.candidateId}: ${item.reason}; phase ${item.phaseId}; priority ${item.priorityScore}; status ${item.qualityStatus}; trace ${item.traceStatus}; evidence ready ${item.evidenceReady ? "true" : "false"}; missing evidence ${missingEvidence}; missing required artifacts ${missingRequiredArtifacts}; endpoint ${item.affectedEndpoint}; code ${item.affectedCodePath}; required ${requiredEvidence}; next ${item.nextAction}; ranking ${ranking}; gate ${item.safetyGate}; ${gates}`;
}

function candidateHunterDeduplicationQueueLine(
  item: ReturnType<typeof toStudioMissionPanel>["candidateHunterExecutionLoop"]["deduplicationQueue"][number],
): string {
  const similarityKeys =
    item.similarityKeys.length > 0 ? item.similarityKeys.join(", ") : "review";
  const questions = item.questions.length > 0 ? item.questions.join("; ") : "review";
  const gates = [
    item.executionAllowed ? "execution allowed" : "execution blocked",
    item.validationAllowed ? "validation allowed" : "validation blocked",
    item.reportSubmissionAllowed ? "submission allowed" : "submission blocked",
  ].join(", ");
  return `${item.queueId}: ${item.candidateId}; duplicate risk ${item.duplicateRiskScore}/100; priority ${item.priorityScore}; endpoint ${item.affectedEndpoint}; code ${item.affectedCodePath}; similarity ${similarityKeys}; questions ${questions}; gate ${item.safetyGate}; next ${item.nextAction}; ${gates}`;
}

function candidateHunterSafeValidationQueueLine(
  item: ReturnType<typeof toStudioMissionPanel>["candidateHunterExecutionLoop"]["safeValidationQueue"][number],
): string {
  const planSteps = item.planSteps.length > 0 ? item.planSteps.join("; ") : "review plan";
  const approvals =
    item.requiredApprovals.length > 0 ? item.requiredApprovals.join(", ") : "human review";
  const gates = [
    item.executionAllowed ? "execution allowed" : "execution blocked",
    item.validationAllowed ? "validation allowed" : "validation blocked",
    item.validationExecutionAllowed
      ? "validation execution allowed"
      : "validation execution blocked",
    item.reportSubmissionAllowed ? "submission allowed" : "submission blocked",
  ].join(", ");
  return `${item.queueId}: ${item.candidateId}; mode ${item.validationMode}; priority ${item.priorityScore}; endpoint ${item.affectedEndpoint}; code ${item.affectedCodePath}; plan ${planSteps}; approvals ${approvals}; gate ${item.safetyGate}; next ${item.nextAction}; ${gates}`;
}

function candidateHunterReportDraftQueueLine(
  item: ReturnType<typeof toStudioMissionPanel>["candidateHunterExecutionLoop"]["reportDraftQueue"][number],
): string {
  const requiredSections =
    item.requiredSections.length > 0 ? item.requiredSections.join(", ") : "report sections";
  const redactionChecks =
    item.redactionChecks.length > 0 ? item.redactionChecks.join(", ") : "redaction review";
  const evidenceFocus =
    item.evidenceFocus.length > 0 ? item.evidenceFocus.join(", ") : "evidence focus";
  const gates = [
    item.executionAllowed ? "execution allowed" : "execution blocked",
    item.validationAllowed ? "validation allowed" : "validation blocked",
    item.reportSubmissionAllowed ? "submission allowed" : "submission blocked",
  ].join(", ");
  return `${item.queueId}: ${item.candidateId}; report ${item.reportStatus}; priority ${item.priorityScore}; endpoint ${item.affectedEndpoint}; code ${item.affectedCodePath}; sections ${requiredSections}; evidence focus ${evidenceFocus}; redaction ${redactionChecks}; gate ${item.safetyGate}; next ${item.nextAction}; ${gates}`;
}

function candidateHunterLearningFeedbackLine(
  target: ReturnType<typeof toStudioMissionPanel>["candidateHunterExecutionLoop"]["learningFeedbackTarget"],
): string {
  const candidates = target.candidateIds.length > 0 ? target.candidateIds.join(", ") : "none";
  const outcomes =
    target.allowedOutcomes.length > 0
      ? target.allowedOutcomes.join(", ")
      : "confirmed, refuted, needs_more_evidence, duplicate";
  const gates = [
    target.learningWriteAllowed ? "learning write allowed" : "learning write review-gated",
    target.executionAllowed ? "execution allowed" : "execution blocked",
    target.validationAllowed ? "validation allowed" : "validation blocked",
    target.reportSubmissionAllowed ? "submission allowed" : "submission blocked",
  ].join(", ");
  return `${target.targetId}: ${target.status}; candidates ${candidates}; outcomes ${outcomes}; gate ${target.safetyGate}; next ${target.nextAction}; ${gates}`;
}

function candidateHunterLearningReviewActionLine(
  action: ReturnType<typeof toStudioMissionPanel>["candidateHunterExecutionLoop"]["learningReviewActions"][number],
): string {
  const outcomes =
    action.allowedOutcomes.length > 0
      ? action.allowedOutcomes.join(", ")
      : "confirmed, refuted, needs_more_evidence, duplicate";
  const gates = [
    action.learningWriteAllowed ? "learning write allowed" : "learning write review-gated",
    action.executionAllowed ? "execution allowed" : "execution blocked",
    action.validationAllowed ? "validation allowed" : "validation blocked",
    action.reportSubmissionAllowed ? "submission allowed" : "submission blocked",
  ].join(", ");
  const missingEvidence =
    action.missingEvidence.length > 0 ? action.missingEvidence.join(", ") : "none";
  const missingRequiredArtifacts =
    action.missingRequiredArtifactKinds.length > 0
      ? action.missingRequiredArtifactKinds.join(", ")
      : "none";
  const template = action.learningSignalTemplate
    ? `; Learning signal template: playbook ${action.learningSignalTemplate.playbookId}; surface ${action.learningSignalTemplate.surfaceKey}; refs ${action.learningSignalTemplate.targetRelationships.length}; learning write review-gated`
    : "";
  return `${action.actionId}: ${action.candidateId}; suggested ${action.suggestedOutcome}; trace ${action.traceStatus}; evidence ready ${action.evidenceReady ? "true" : "false"}; missing evidence ${missingEvidence}; missing required artifacts ${missingRequiredArtifacts}; outcomes ${outcomes}; gate ${action.safetyGate}; next ${action.nextAction}; ${gates}${template}`;
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
