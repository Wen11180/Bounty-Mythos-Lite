import type {
  StudioReportExportResponse,
  StudioWorkspaceCandidatesResponse,
} from "./api";
import type { CampaignControlCenter } from "./campaigns-data";
import type {
  StudioCandidateCard,
  StudioMissionPanel,
  StudioMissionSummary,
  StudioWorkspaceManifest,
} from "./studio-data";

type StudioRefreshDependencies = {
  getCampaign(campaignId: string, signal: AbortSignal): Promise<CampaignControlCenter | null>;
  getManifest(workspacePath: string, signal: AbortSignal): Promise<StudioWorkspaceManifest | null>;
  getMission(
    workspacePath: string,
    runId: string,
    signal: AbortSignal,
  ): Promise<StudioMissionSummary | null>;
  listCandidates(
    workspacePath: string,
    runId: string,
    signal: AbortSignal,
  ): Promise<StudioWorkspaceCandidatesResponse>;
  mapCampaignCandidates(controlCenter: CampaignControlCenter | null): StudioCandidateCard[];
  mapMission(mission: StudioMissionSummary | null): StudioMissionPanel;
  mapResearchCandidates(candidates: StudioWorkspaceCandidatesResponse["candidates"]): StudioCandidateCard[];
};

export type StudioRefreshProjection = {
  candidates: StudioCandidateCard[];
  latestCampaignHunterId: string | null;
  latestRunId: string | null;
  manifest: StudioWorkspaceManifest;
  missionPanel: StudioMissionPanel;
  reportExport: StudioReportExportResponse | null;
};

export function buildStudioEventsUrl(baseUrl: string, campaignId: string | null): string {
  const url = new URL("/mythos/control-center/events", baseUrl);
  if (campaignId) {
    url.searchParams.set("campaign_id", campaignId);
  }
  return url.toString();
}

export async function refreshStudioProjection({
  dependencies,
  signal,
  workspacePath,
}: {
  dependencies: StudioRefreshDependencies;
  signal: AbortSignal;
  workspacePath: string;
}): Promise<StudioRefreshProjection | null> {
  const manifest = await dependencies.getManifest(workspacePath, signal);
  if (!manifest || signal.aborted) {
    return null;
  }
  const latest = latestStudioSession(manifest);
  if (latest.kind === "research" && latest.id) {
    const [listed, mission] = await Promise.all([
      dependencies.listCandidates(workspacePath, latest.id, signal),
      dependencies.getMission(workspacePath, latest.id, signal),
    ]);
    if (signal.aborted) {
      return null;
    }
    return {
      candidates: dependencies.mapResearchCandidates(listed.candidates),
      latestCampaignHunterId: null,
      latestRunId: latest.id,
      manifest,
      missionPanel: dependencies.mapMission(mission),
      reportExport: reportExportFromStudioSession(manifest, latest),
    };
  }
  if (latest.kind === "campaign_hunter" && latest.id) {
    const controlCenter = await dependencies.getCampaign(latest.id, signal);
    if (signal.aborted) {
      return null;
    }
    return {
      candidates: dependencies.mapCampaignCandidates(controlCenter),
      latestCampaignHunterId: latest.id,
      latestRunId: null,
      manifest,
      missionPanel: dependencies.mapMission(null),
      reportExport: reportExportFromStudioSession(manifest, latest),
    };
  }
  return {
    candidates: [],
    latestCampaignHunterId: null,
    latestRunId: null,
    manifest,
    missionPanel: dependencies.mapMission(null),
    reportExport: null,
  };
}

export function latestStudioSession(
  manifest: StudioWorkspaceManifest,
): { id: string | null; kind: "campaign_hunter" | "none" | "research" } {
  let latest: { id: string | null; kind: "campaign_hunter" | "none" | "research"; recordedAt: string } = {
    id: null,
    kind: "none",
    recordedAt: "",
  };
  for (const run of [...(manifest.runs ?? [])].reverse()) {
    if (run.run_id && (!latest.id || safeDateValue(run.recorded_at) >= safeDateValue(latest.recordedAt))) {
      latest = { id: run.run_id, kind: "research", recordedAt: run.recorded_at ?? "" };
    }
  }
  for (const run of [...(manifest.campaign_hunter_runs ?? [])].reverse()) {
    if (run.campaign_id && (!latest.id || safeDateValue(run.recorded_at) >= safeDateValue(latest.recordedAt))) {
      latest = { id: run.campaign_id, kind: "campaign_hunter", recordedAt: run.recorded_at ?? "" };
    }
  }
  return { id: latest.id, kind: latest.kind };
}

export function reportExportFromStudioSession(
  manifest: StudioWorkspaceManifest,
  latest: { id: string | null; kind: "campaign_hunter" | "none" | "research" },
): StudioReportExportResponse | null {
  if (!latest.id || latest.kind === "none") {
    return null;
  }
  const run = latest.kind === "research"
    ? (manifest.runs ?? []).find((item) => item.run_id === latest.id)
    : (manifest.campaign_hunter_runs ?? []).find((item) => item.campaign_id === latest.id);
  if (!run?.report_markdown_path) {
    return null;
  }
  return {
    manifest,
    report: { restored_from_manifest: true, submission_blocked: true },
    report_markdown_path: run.report_markdown_path,
    report_submission_allowed: false,
    run_id: latest.id,
    submission_blocked: true,
    title: latest.kind === "campaign_hunter"
      ? "提交已阻断的项目候选挖掘草稿"
      : "提交已阻断的报告草稿",
  };
}

function safeDateValue(value: string | undefined): number {
  if (!value) {
    return 0;
  }
  const timestamp = Date.parse(value);
  return Number.isNaN(timestamp) ? 0 : timestamp;
}
