"use client";

import { FileDown, FolderOpen, FolderPlus, Play, ShieldCheck, Upload } from "lucide-react";
import { useMemo, useState } from "react";

import {
  createStudioWorkspace,
  exportStudioWorkspaceReport,
  getStudioWorkspaceManifest,
  importStudioWorkspaceArtifact,
  listStudioWorkspaceCandidates,
  runStudioWorkspaceResearch,
  type StudioReportExportResponse,
} from "@/lib/api";
import {
  toStudioCandidateCards,
  toStudioWorkspaceSummary,
  type StudioWorkspaceManifest,
} from "@/lib/studio-data";

type LogEntry = {
  message: string;
  tone: "info" | "safe" | "blocked";
};

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
  const [workspacePath, setWorkspacePath] = useState("");
  const [manifest, setManifest] = useState<StudioWorkspaceManifest>(emptyManifest);
  const [candidates, setCandidates] = useState<ReturnType<typeof toStudioCandidateCards>>([]);
  const [latestRunId, setLatestRunId] = useState<string | null>(null);
  const [reportExport, setReportExport] = useState<StudioReportExportResponse | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const [log, setLog] = useState<LogEntry[]>([
    {
      message: "Studio ready.",
      tone: "info",
    },
  ]);

  const workspace = useMemo(() => toStudioWorkspaceSummary(manifest), [manifest]);

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
      const latest = latestRunFromManifest(opened);
      setLatestRunId(latest);
      setReportExport(null);
      if (latest) {
        const listed = await listStudioWorkspaceCandidates(workspacePath, latest, {
          candidates: [],
          run_id: latest,
        });
        setCandidates(toStudioCandidateCards(listed.candidates));
      } else {
        setCandidates([]);
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
        null,
      );
      if (!created) {
        pushLog("Workspace creation failed. Check that the local API is running.", "blocked");
        return;
      }
      setWorkspacePath(created.path);
      setManifest(created.manifest);
      setCandidates([]);
      setLatestRunId(null);
      setReportExport(null);
      pushLog("Workspace created locally. Scope Guard is waiting for authorized inputs.", "safe");
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
      for (const artifact of [
        { kind: "policy", source_path: policyPath },
        { kind: "scope", source_path: scopePath },
        { kind: "code", source_path: codePath },
        { kind: "api", source_path: apiPath },
      ]) {
        if (!artifact.source_path.trim()) {
          continue;
        }
        updated = await importStudioWorkspaceArtifact(
          { ...artifact, workspace_path: workspacePath },
          updated,
        );
      }
      if (updated) {
        setManifest(updated);
        pushLog("Authorized artifact references imported. Sensitive items remain review-gated.", "safe");
      }
    } finally {
      setBusy(null);
    }
  }

  async function handleStartResearch() {
    if (!workspacePath) {
      pushLog("Create a workspace and import scope plus code before research.", "blocked");
      return;
    }
    setBusy("research");
    try {
      const run = await runStudioWorkspaceResearch({ workspace_path: workspacePath }, null);
      if (!run) {
        pushLog("Research run did not start. Scope and code artifacts are required.", "blocked");
        return;
      }
      setManifest(run.manifest);
      setLatestRunId(run.run_id);
      const listed = await listStudioWorkspaceCandidates(workspacePath, run.run_id, {
        candidates: [],
        run_id: run.run_id,
      });
      setCandidates(toStudioCandidateCards(listed.candidates));
      setReportExport(null);
      pushLog(
        `Research run ${run.run_id} produced ${run.candidate_count} submission-blocked candidates.`,
        "safe",
      );
    } finally {
      setBusy(null);
    }
  }

  async function handleExportReport() {
    if (!workspacePath || !latestRunId) {
      pushLog("Run research before exporting a report preview.", "blocked");
      return;
    }
    setBusy("export");
    try {
      const exported = await exportStudioWorkspaceReport(
        { run_id: latestRunId, workspace_path: workspacePath },
        null,
      );
      if (!exported) {
        pushLog("Report preview export failed.", "blocked");
        return;
      }
      setReportExport(exported);
      setManifest(exported.manifest);
      pushLog("Report preview exported with submission still blocked.", "safe");
    } finally {
      setBusy(null);
    }
  }

  function pushLog(message: string, tone: LogEntry["tone"]) {
    setLog((entries) => [{ message, tone }, ...entries].slice(0, 6));
  }

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

      <div className="mt-6 grid gap-5 xl:grid-cols-[340px_minmax(0,1fr)_360px]">
        <section className="border border-[var(--line)] bg-white">
          <SectionHeader title="Workspaces" />
          <div className="grid gap-4 p-5 text-sm">
            <TextField label="Workspace path" value={workspacePath} onChange={setWorkspacePath} />
            <ActionButton
              busy={busy === "open"}
              icon={<FolderOpen size={16} aria-hidden="true" />}
              label="Open workspace"
              onClick={handleOpenWorkspace}
            />
            <TextField label="Workspace root" value={workspaceRoot} onChange={setWorkspaceRoot} />
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
            <div className="grid gap-3 lg:grid-cols-4">
              <TextField label="Policy file" value={policyPath} onChange={setPolicyPath} />
              <TextField label="Scope file" value={scopePath} onChange={setScopePath} />
              <TextField label="Code directory" value={codePath} onChange={setCodePath} />
              <TextField label="API or HAR file" value={apiPath} onChange={setApiPath} />
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
                icon={<Play size={16} aria-hidden="true" />}
                label="Start research"
                onClick={handleStartResearch}
              />
              <ActionButton
                busy={busy === "export"}
                disabled={!latestRunId}
                icon={<FileDown size={16} aria-hidden="true" />}
                label="Export report preview"
                onClick={handleExportReport}
              />
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
                </dl>
                <ListBlock title="Evidence needed" items={candidate.evidenceNeeds} />
                <ListBlock title="False-positive checks" items={candidate.refutationQuestions} />
              </article>
            ))
          )}
        </div>
        {reportExport ? (
          <div className="border-t border-[var(--line)] p-5 text-sm">
            <p className="font-semibold">{reportExport.title}</p>
            <p className="mt-1 text-[var(--muted)]">
              Exported report preview remains submission-blocked and cannot be submitted from
              Studio.
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
  label,
  onChange,
  value,
}: {
  label: string;
  onChange: (value: string) => void;
  value: string;
}) {
  return (
    <label className="grid gap-1 text-sm">
      <span className="text-xs font-semibold uppercase text-[var(--muted)]">{label}</span>
      <input
        className="min-h-10 rounded-md border border-[var(--line)] bg-white px-3 outline-none focus:border-[var(--accent)]"
        onChange={(event) => onChange(event.target.value)}
        value={value}
      />
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

function logTone(tone: LogEntry["tone"]): string {
  if (tone === "safe") {
    return "text-[var(--success)]";
  }
  if (tone === "blocked") {
    return "text-[var(--warning)]";
  }
  return "text-[var(--muted)]";
}

function latestRunFromManifest(manifest: StudioWorkspaceManifest): string | null {
  for (const run of [...(manifest.runs ?? [])].reverse()) {
    if (run.run_id) {
      return run.run_id;
    }
  }
  return null;
}
