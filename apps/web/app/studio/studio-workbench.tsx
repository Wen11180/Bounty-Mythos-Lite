"use client";

import { FileDown, FolderOpen, FolderPlus, Play, ShieldCheck, Upload } from "lucide-react";
import { useEffect, useMemo, useState } from "react";

import {
  ApiRequestError,
  createStudioWorkspace,
  createStudioWorkspaceBenchmarkTemplate,
  exportStudioWorkspaceCampaignHunterReport,
  exportStudioWorkspaceMissionDossier,
  exportStudioWorkspaceReport,
  getCampaignControlCenter,
  getStudioWorkspaceManifest,
  getStudioWorkspaceMission,
  importStudioWorkspaceArtifact,
  launchStudioWorkspaceCampaignHunter,
  listStudioWorkspaceCandidates,
  recordCandidateHunterLearningOutcome,
  runStudioWorkspaceBenchmark,
  runStudioWorkspaceResearch,
  type CandidateHunterLearningOutcome,
  type ProgramIntelligenceProfile,
  type StudioBenchmarkRunResponse,
  type StudioMissionDossierExportResponse,
  type StudioReportExportResponse,
} from "@/lib/api";
import {
  toStudioArtifactChecklist,
  toStudioCampaignHunterCandidateCards,
  toStudioCandidateCards,
  toStudioMissionHandoffBrief,
  toStudioMissionPanel,
  toStudioResearchReadiness,
  toStudioWorkspaceSummary,
  type StudioWorkspaceManifest,
} from "@/lib/studio-data";

type LogEntry = {
  message: string;
  tone: "info" | "safe" | "blocked";
};

type MythosStudioDesktopBridge = {
  selectDirectory: () => Promise<string | null>;
  selectFile: (options?: { title?: string }) => Promise<string | null>;
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
  const [busy, setBusy] = useState<string | null>(null);
  const [desktopPickerAvailable, setDesktopPickerAvailable] = useState(false);
  const [log, setLog] = useState<LogEntry[]>([
    {
      message: "Studio ready.",
      tone: "info",
    },
  ]);

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
  const localCandidateHuntInputReady = [policyPath, scopePath, codePath, apiPath, harPath].every(
    (value) => value.trim(),
  );
  const benchmarkEvidenceGaps = benchmarkResult?.benchmark.evidence_gaps ?? [];

  useEffect(() => {
    const timer = window.setTimeout(() => {
      setDesktopPickerAvailable(Boolean(window.mythosStudio));
    }, 0);
    return () => window.clearTimeout(timer);
  }, []);

  async function handleOpenWorkspace() {
    if (!workspacePath.trim()) {
      pushLog("Enter a local workspace path before opening.", "blocked");
      return;
    }
    setBusy("open");
    try {
      const opened = await getStudioWorkspaceManifest(workspacePath, null);
      if (!opened) {
        pushLog("Workspace manifest was not found.", "blocked");
        return;
      }
      setManifest(opened);
      const latest = latestSessionFromManifest(opened);
      setLatestRunId(latest.kind === "research" ? latest.id : null);
      setLatestCampaignHunterId(latest.kind === "campaign_hunter" ? latest.id : null);
      setReportExport(reportExportFromLatestSession(opened, latest));
      setMissionDossierExport(null);
      setBenchmarkResult(null);
      if (latest.kind === "research" && latest.id) {
        const listed = await listStudioWorkspaceCandidates(workspacePath, latest.id, {
          candidates: [],
          run_id: latest.id,
        });
        setCandidates(toStudioCandidateCards(listed.candidates));
        await refreshMissionPanel(workspacePath, latest.id);
      } else if (latest.kind === "campaign_hunter" && latest.id) {
        const controlCenter = await getCampaignControlCenter(latest.id, null);
        setCandidates(toStudioCampaignHunterCandidateCards(controlCenter));
        setMissionPanel(toStudioMissionPanel(null));
      } else {
        setCandidates([]);
        setMissionPanel(toStudioMissionPanel(null));
      }
      pushLog("Workspace opened locally.", "safe");
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

  async function handleRunLocalCandidateHunt() {
    if (!localCandidateHuntInputReady) {
      pushLog("Select policy, scope, code, API, and HAR inputs before starting the local candidate hunt.", "blocked");
      return;
    }
    setBusy("candidate-hunt");
    try {
      let activeWorkspacePath = workspacePath;
      let activeManifest: StudioWorkspaceManifest | null = manifest;
      if (!activeWorkspacePath) {
        const created = await createStudioWorkspace(
          { name: workspaceName, root_path: workspaceRoot },
        );
        if (!created) {
          pushLog("Workspace creation failed. Check that the local API is running.", "blocked");
          return;
        }
        activeWorkspacePath = created.path;
        activeManifest = created.manifest;
        setWorkspacePath(created.path);
      }

      for (const artifact of studioArtifactInputs(activeWorkspacePath)) {
        if (!artifact.source_path.trim()) {
          continue;
        }
        activeManifest = await importStudioWorkspaceArtifact(artifact);
      }
      if (!activeManifest) {
        pushLog("Authorized artifact import failed.", "blocked");
        return;
      }

      setManifest(activeManifest);
      const readiness = toStudioResearchReadiness(activeWorkspacePath, activeManifest);
      if (!readiness.canStart) {
        pushLog(readiness.reason, "blocked");
        return;
      }

      const run = await runStudioWorkspaceResearch({ workspace_path: activeWorkspacePath });
      if (!run) {
        pushLog("Local candidate hunt did not start. Scope and code artifacts are required.", "blocked");
        return;
      }
      setManifest(run.manifest);
      setLatestRunId(run.run_id);
      setLatestCampaignHunterId(null);
      const listed = await listStudioWorkspaceCandidates(activeWorkspacePath, run.run_id, {
        candidates: [],
        run_id: run.run_id,
      });
      setCandidates(toStudioCandidateCards(listed.candidates));
      await refreshMissionPanel(activeWorkspacePath, run.run_id);
      setReportExport(null);
      setMissionDossierExport(null);
      setBenchmarkResult(null);
      pushLog(
        `Local candidate hunt ${run.run_id} produced ${run.candidate_count} submission-blocked candidates.`,
        "safe",
      );
    } catch (error) {
      pushMutationFailure("Local candidate hunt", error);
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
      const run = await runStudioWorkspaceResearch({ workspace_path: workspacePath });
      if (!run) {
        pushLog("Research run did not start. Scope and code artifacts are required.", "blocked");
        return;
      }
      setManifest(run.manifest);
      setLatestRunId(run.run_id);
      setLatestCampaignHunterId(null);
      const listed = await listStudioWorkspaceCandidates(workspacePath, run.run_id, {
        candidates: [],
        run_id: run.run_id,
      });
      setCandidates(toStudioCandidateCards(listed.candidates));
      await refreshMissionPanel(workspacePath, run.run_id);
      setReportExport(null);
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
      pushLog(`Recorded ${outcome} learning feedback for ${action.candidateId}.`, "safe");
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
      pushLog(`Recorded ${outcome} learning feedback for ${candidate.id}.`, "safe");
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

  function pushLog(message: string, tone: LogEntry["tone"]) {
    setLog((entries) => [{ message, tone }, ...entries].slice(0, 6));
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

  const wizardPrimaryAction =
    currentWizardStep === "workspace"
      ? {
          busy: busy === "open" || busy === "workspace",
          disabled: false,
          icon: <FolderPlus size={16} aria-hidden="true" />,
          label: workspacePath.trim() ? "Open workspace" : "Create workspace",
          onClick: workspacePath.trim() ? handleOpenWorkspace : handleCreateWorkspace,
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
              busy: busy === "export",
              disabled: !latestRunId && !latestCampaignHunterId,
              icon: <FileDown size={16} aria-hidden="true" />,
              label: "Export submission-blocked draft",
              onClick: handleExportReport,
            };

  return (
    <main className="min-h-screen px-5 py-6 sm:px-8 lg:px-10">
      <header className="border-b border-[var(--line)] pb-5">
        <p className="flex items-center gap-2 text-sm font-semibold text-[var(--accent-strong)]">
          <ShieldCheck size={17} aria-hidden="true" />
          Mythos Studio
        </p>
        <h1 className="mt-3 max-w-4xl text-3xl font-semibold leading-tight text-balance">
          Authorized research workspace
        </h1>
      </header>

      <section className="mt-6 border border-[var(--line)] bg-white">
        <SectionHeader title="Local research setup" />
        <div className="grid gap-3 p-5 text-sm md:grid-cols-4">
          {wizardSteps.map((step, index) => (
            <div
              className={`border border-[var(--line)] p-3 ${
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
            busy={busy === "candidate-hunt"}
            disabled={!localCandidateHuntInputReady}
            icon={<Play size={16} aria-hidden="true" />}
            label="Run local candidate hunt"
            onClick={handleRunLocalCandidateHunt}
          />
          <ActionButton
            busy={wizardPrimaryAction.busy}
            disabled={wizardPrimaryAction.disabled}
            icon={wizardPrimaryAction.icon}
            label={wizardPrimaryAction.label}
            onClick={wizardPrimaryAction.onClick}
          />
          <ActionButton
            busy={busy === "campaign-hunter"}
            disabled={!researchReadiness.canStart}
            icon={<ShieldCheck size={16} aria-hidden="true" />}
            label="Launch campaign hunter"
            onClick={handleLaunchCampaignHunter}
          />
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

      <div className="mt-6 grid gap-5 xl:grid-cols-[340px_minmax(0,1fr)_360px]">
        <section className="border border-[var(--line)] bg-white">
          <SectionHeader title="Workspaces" />
          <div className="grid gap-4 p-5 text-sm">
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
              value={workspacePath}
              onChange={setWorkspacePath}
            />
            <ActionButton
              busy={busy === "open"}
              icon={<FolderOpen size={16} aria-hidden="true" />}
              label="Open workspace"
              onClick={handleOpenWorkspace}
            />
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

            <div className="border-t border-[var(--line)] pt-4">
              <dl className="grid gap-3">
                <StatusRow label="Name" value={workspace.name} />
                <StatusRow label="Path" value={workspacePath || "No workspace selected"} />
                <StatusRow label="Scope Guard" value={workspace.scopeGuardLabel} warning />
                <StatusRow label="Artifacts" value={String(workspace.artifactCount)} />
                <StatusRow label="Runs" value={String(workspace.runCount)} />
              </dl>
            </div>
          </div>
        </section>

        <section className="border border-[var(--line)] bg-white">
          <SectionHeader title="Conversation" />
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
            <div className="border border-[var(--line)] bg-[var(--background)] p-4">
              <p className="font-semibold">Artifact readiness</p>
              <div className="mt-3 grid gap-2 sm:grid-cols-2 xl:grid-cols-3">
                {artifactChecklist.map((item) => (
                  <span
                    className={`border border-[var(--line)] px-3 py-2 ${checklistTone(item.status)}`}
                    key={item.kind}
                  >
                    {item.label}: {item.status}
                  </span>
                ))}
              </div>
              <p className="mt-3 text-[var(--muted)]">{researchReadiness.reason}</p>
            </div>
            <div className="flex flex-wrap gap-3">
              <ActionButton
                busy={busy === "import"}
                icon={<Upload size={16} aria-hidden="true" />}
                label="Import artifacts"
                onClick={handleImportArtifacts}
              />
              <ActionButton
                busy={busy === "research"}
                disabled={!researchReadiness.canStart}
                icon={<Play size={16} aria-hidden="true" />}
                label="Start research"
                onClick={handleStartResearch}
              />
              <ActionButton
                busy={busy === "candidate-hunt"}
                disabled={!localCandidateHuntInputReady}
                icon={<Play size={16} aria-hidden="true" />}
                label="Run local candidate hunt"
                onClick={handleRunLocalCandidateHunt}
              />
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
            </div>
            <div className="border border-[var(--line)] bg-[var(--background)] p-4">
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
            <div className="border border-[var(--line)] bg-[var(--background)] p-4">
              <p className="font-semibold">Research intent</p>
              <p className="mt-2 text-[var(--muted)]">
                Access control, role boundaries, refutation first.
              </p>
            </div>
          </div>
        </section>

        <section className="border border-[var(--line)] bg-white">
          <SectionHeader title="Safety and Run Log" />
          <div className="grid gap-4 p-5 text-sm">
            <div className="border border-[var(--line)] bg-[var(--background)] p-4">
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
            <div className="grid gap-2 border-t border-[var(--line)] pt-4">
              {log.map((entry, index) => (
                <p key={`${entry.message}-${index}`} className={logTone(entry.tone)}>
                  {entry.message}
                </p>
              ))}
            </div>
          </div>
        </section>
      </div>

      <section className="mt-5 border border-[var(--line)] bg-white">
        <SectionHeader title="Candidate Board" />
        <div className="grid gap-4 p-5 lg:grid-cols-2">
          {candidates.length === 0 ? (
            <p className="text-sm text-[var(--muted)]">
              No candidates yet.
            </p>
          ) : (
            candidates.map((candidate) => (
              <article key={candidate.id} className="border border-[var(--line)] p-4 text-sm">
                <div className="flex items-start justify-between gap-3">
                  <div>
                    <p className="font-semibold">{candidate.id}</p>
                    <h2 className="mt-1 text-lg font-semibold">{candidate.title}</h2>
                  </div>
                  <span className="border border-[var(--line)] px-2 py-1 text-xs uppercase">
                    {candidate.status}
                  </span>
                </div>
                <dl className="mt-4 grid gap-3">
                  <StatusRow label="Severity" value={candidate.severity} />
                  <StatusRow label="Endpoint" value={candidate.affectedEndpoint} />
                  <StatusRow label="Code path" value={candidate.affectedCodePath} />
                  <StatusRow label="Priority" value={String(candidate.priorityScore)} />
                  <StatusRow label="Validation mode" value={candidate.validationMode} />
                  <StatusRow label="Report readiness" value={candidate.reportReadiness.status} warning />
                </dl>
                <div className="mt-4">
                  <p className="text-xs font-semibold uppercase text-[var(--muted)]">Reason</p>
                  <p className="mt-2 text-[var(--muted)]">{candidate.reason}</p>
                </div>
                <div className="mt-4">
                  <p className="text-xs font-semibold uppercase text-[var(--muted)]">Broken invariant</p>
                  <p className="mt-2 text-[var(--muted)]">{candidate.brokenInvariant}</p>
                </div>
                <ListBlock
                  title="Semantic evidence"
                  items={[semanticEvidenceLine(candidate.semanticEvidence)]}
                />
                <ListBlock
                  title="Candidate evidence review packet"
                  items={candidateEvidenceReviewPacketLines(candidate)}
                />
                <ListBlock title="Evidence focus" items={candidate.evidenceFocus} />
                <div className="mt-4">
                  <p className="text-xs font-semibold uppercase text-[var(--muted)]">Repair guidance</p>
                  <p className="mt-2 text-[var(--muted)]">{candidate.repairGuidance}</p>
                </div>
                <div className="mt-4">
                  <p className="text-xs font-semibold uppercase text-[var(--muted)]">Regression test</p>
                  <p className="mt-2 text-[var(--muted)]">{candidate.regressionTest}</p>
                </div>
                <div className="mt-4">
                  <p className="text-xs font-semibold uppercase text-[var(--muted)]">Next report action</p>
                  <p className="mt-2 text-[var(--muted)]">
                    {candidate.reportReadiness.nextAllowedAction}
                  </p>
                </div>
                <ListBlock title="Ranking reasons" items={candidate.rankingReasons} />
                <ListBlock title="Safe validation plan" items={candidate.safeValidationPlan} />
                <ListBlock title="Safety blockers" items={candidate.safetyBlockers} />
                <ListBlock title="Candidate evidence gaps" items={candidate.evidenceGaps} />
                <ListBlock title="Evidence needed" items={candidate.evidenceNeeds} />
                <ListBlock title="False-positive checks" items={candidate.refutationQuestions} />
                <div className="mt-4 flex flex-wrap gap-2">
                  <ActionButton
                    busy={busy === `candidate-learning:${candidate.id}:needs_more_evidence`}
                    icon={<ShieldCheck size={16} aria-hidden="true" />}
                    label="Record needs-evidence learning"
                    onClick={() => handleRecordCandidateCardLearning(candidate, "needs_more_evidence")}
                  />
                  <ActionButton
                    busy={busy === `candidate-learning:${candidate.id}:refuted`}
                    icon={<ShieldCheck size={16} aria-hidden="true" />}
                    label="Record refuted learning"
                    onClick={() => handleRecordCandidateCardLearning(candidate, "refuted")}
                  />
                  <ActionButton
                    busy={busy === `candidate-learning:${candidate.id}:duplicate`}
                    icon={<ShieldCheck size={16} aria-hidden="true" />}
                    label="Record duplicate learning"
                    onClick={() => handleRecordCandidateCardLearning(candidate, "duplicate")}
                  />
                </div>
              </article>
            ))
          )}
        </div>
        {reportExport ? (
          <div className="border-t border-[var(--line)] p-5 text-sm">
            <p className="font-semibold">{reportExport.title}</p>
            {reportExport.report_markdown_path ? (
              <p className="mt-1 text-[var(--muted)]">
                Markdown draft: {reportExport.report_markdown_path}
              </p>
            ) : null}
            <p className="mt-1 text-[var(--muted)]">
              Exported report preview remains submission-blocked and cannot be submitted from
              Studio.
            </p>
          </div>
        ) : null}
        {missionDossierExport ? (
          <div className="border-t border-[var(--line)] p-5 text-sm">
            <p className="font-semibold">Mission dossier exported</p>
            {missionDossierExport.mission_dossier_markdown_path ? (
              <p className="mt-1 text-[var(--muted)]">
                Mission dossier: {missionDossierExport.mission_dossier_markdown_path}
              </p>
            ) : null}
            {missionDossierExport.agent_queue_markdown_path ? (
              <p className="mt-1 text-[var(--muted)]">
                Agent queue audit: {missionDossierExport.agent_queue_markdown_path}
              </p>
            ) : null}
            <p className="mt-1 text-[var(--muted)]">
              Local mission dossiers are review-only and do not grant validation execution or
              report submission.
            </p>
          </div>
        ) : null}
      </section>
    </main>
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

function semanticEvidenceLine(
  evidence: ReturnType<typeof toStudioCandidateCards>[number]["semanticEvidence"],
): string {
  const sinks = evidence.sinkSymbols.length > 0 ? evidence.sinkSymbols.join(", ") : "none";
  const gates = [
    evidence.executionAllowed ? "execution allowed" : "execution blocked",
    evidence.validationAllowed ? "validation allowed" : "validation blocked",
    evidence.reportSubmissionAllowed ? "submission allowed" : "submission blocked",
  ].join(", ");
  return `root ${evidence.rootCause}; invariant ${evidence.securityInvariant}; authz ${evidence.authzHint}; sinks ${evidence.sinkCount} (${sinks}); review ${evidence.reviewState}; ${gates}`;
}

function candidateEvidenceReviewPacketLines(
  candidate: ReturnType<typeof toStudioCandidateCards>[number],
): string[] {
  const trace = candidate.evidenceTraceSummary;
  const missingArtifacts =
    trace.missingRequiredArtifactKinds.length > 0
      ? trace.missingRequiredArtifactKinds.join(", ")
      : "none";
  const evidenceNeeds =
    candidate.evidenceNeeds.length > 0 ? candidate.evidenceNeeds.join(", ") : "review";
  const evidenceGaps =
    candidate.evidenceGaps.length > 0 ? candidate.evidenceGaps.join(", ") : "none";
  const focus =
    candidate.evidenceFocus.length > 0 ? candidate.evidenceFocus.join(", ") : "review";
  const readiness = candidate.reportReadiness;
  return [
    `Trace ${trace.status}; endpoint traced ${trace.endpointTraced ? "true" : "false"}; code traced ${trace.codePathTraced ? "true" : "false"}; source facts ${trace.sourceFactCount}.`,
    `Report readiness ${readiness.status}; trace ${readiness.traceStatus}; required evidence ${readiness.requiredEvidenceCount}; safe validation steps ${readiness.safeValidationStepCount}; submission blocked ${readiness.submissionBlocked ? "true" : "false"}.`,
    `Required artifacts ${trace.requiredArtifactKinds.join(", ")}; present ${trace.presentRequiredArtifactKinds.join(", ") || "none"}; missing ${missingArtifacts}.`,
    `Evidence needs ${evidenceNeeds}; evidence gaps ${evidenceGaps}; focus ${focus}.`,
    "Redaction review required before sharing evidence; raw secrets, tokens, cookies, authorization headers, and user data stay excluded.",
    "Evidence review remains read-only: execution blocked, validation blocked, report submission blocked.",
  ];
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

function logTone(tone: LogEntry["tone"]): string {
  if (tone === "safe") {
    return "text-[var(--success)]";
  }
  if (tone === "blocked") {
    return "text-[var(--warning)]";
  }
  return "text-[var(--muted)]";
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

function latestSessionFromManifest(
  manifest: StudioWorkspaceManifest,
): { id: string | null; kind: "campaign_hunter" | "none" | "research" } {
  let latest: { id: string | null; kind: "campaign_hunter" | "none" | "research"; recordedAt: string } = {
    id: null,
    kind: "none",
    recordedAt: "",
  };
  for (const run of [...(manifest.runs ?? [])].reverse()) {
    if (run.run_id && (!latest.id || safeDateValue(run.recorded_at) >= safeDateValue(latest.recordedAt))) {
      latest = {
        id: run.run_id,
        kind: "research",
        recordedAt: run.recorded_at ?? "",
      };
    }
  }
  for (const run of [...(manifest.campaign_hunter_runs ?? [])].reverse()) {
    if (
      run.campaign_id &&
      (!latest.id || safeDateValue(run.recorded_at) >= safeDateValue(latest.recordedAt))
    ) {
      latest = {
        id: run.campaign_id,
        kind: "campaign_hunter",
        recordedAt: run.recorded_at ?? "",
      };
    }
  }
  return { id: latest.id, kind: latest.kind };
}

function reportExportFromLatestSession(
  manifest: StudioWorkspaceManifest,
  latest: { id: string | null; kind: "campaign_hunter" | "none" | "research" },
): StudioReportExportResponse | null {
  if (!latest.id || latest.kind === "none") {
    return null;
  }
  const run =
    latest.kind === "research"
      ? (manifest.runs ?? []).find((item) => item.run_id === latest.id)
      : (manifest.campaign_hunter_runs ?? []).find((item) => item.campaign_id === latest.id);
  if (!run?.report_markdown_path) {
    return null;
  }
  return {
    manifest,
    report: {
      restored_from_manifest: true,
      submission_blocked: true,
    },
    report_markdown_path: run.report_markdown_path,
    report_submission_allowed: false,
    run_id: latest.id,
    submission_blocked: true,
    title:
      latest.kind === "campaign_hunter"
        ? "Submission-blocked campaign hunter draft"
        : "Submission-blocked report draft",
  };
}

function safeDateValue(value: string | undefined): number {
  if (!value) {
    return 0;
  }
  const timestamp = Date.parse(value);
  return Number.isNaN(timestamp) ? 0 : timestamp;
}
