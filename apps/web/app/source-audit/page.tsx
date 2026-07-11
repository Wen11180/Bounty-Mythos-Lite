import Link from "next/link";
import { redirect } from "next/navigation";
import { ArrowLeft, FileSearch, Lock, ShieldCheck } from "lucide-react";
import { runSourceAuditScan, SourceAuditScanError } from "@/lib/api";
import { formatLabel, safeDisplay } from "@/lib/workbench-detail-data";

type PageProps = {
  searchParams?: Promise<Record<string, string | string[] | undefined>>;
};

const safetyNotes = [
  "scope_guard_required",
  "local_files_only",
  "no_live_requests",
  "no_auto_submission",
  "human_review_required",
];

export default async function SourceAuditPage({ searchParams }: PageProps) {
  const query = (await searchParams) ?? {};
  const scanStatus = firstParam(query.scan_status);
  const scopeError = firstParam(query.scope_error);

  async function sourceAuditScanAction(formData: FormData) {
    "use server";

    const repoPath = formText(formData, "repo_path");
    const scopePath = formText(formData, "scope_path");
    const policyText = optionalFormText(formData, "policy_text");

    if (!repoPath || !scopePath) {
      redirect("/source-audit?scan_status=missing_required");
    }

    let result;
    try {
      result = await runSourceAuditScan(
        {
          ...(policyText ? { policy_text: policyText } : {}),
          repo_path: repoPath,
          scope_path: scopePath,
        },
      );
    } catch (error) {
      if (error instanceof SourceAuditScanError) {
        redirect(
          `/source-audit?scan_status=blocked&scope_error=${encodeURIComponent(error.detail)}`,
        );
      }

      throw error;
    }

    if (!result) {
      redirect("/source-audit?scan_status=failed");
    }

    redirect(`/runs/${encodeURIComponent(result.run_id)}`);
  }

  return (
    <main className="min-h-screen px-5 py-6 sm:px-8 lg:px-10">
      <Link
        href="/"
        className="inline-flex min-h-10 items-center gap-2 rounded-md border border-[var(--line)] bg-white px-3 text-sm font-semibold"
      >
        <ArrowLeft size={17} aria-hidden="true" />
        Dashboard
      </Link>

      <header className="mt-6 border-b border-[var(--line)] pb-6">
        <p className="flex items-center gap-2 text-sm font-semibold text-[var(--accent-strong)]">
          <FileSearch size={17} aria-hidden="true" />
          V0 local source audit
        </p>
        <div className="mt-3 flex flex-col gap-4 lg:flex-row lg:items-end lg:justify-between">
          <div>
            <h1 className="max-w-4xl text-3xl font-semibold leading-tight text-balance">
              Source Audit
            </h1>
            <p className="mt-2 max-w-3xl text-pretty text-[var(--muted)]">
              Start a local repository review that creates a pipeline run, report preview, and
              human review workspace. The scan stores metadata and review artifacts only.
            </p>
          </div>
          <span className="rounded-sm border border-[var(--line)] px-3 py-2 text-xs font-semibold uppercase text-[var(--warning)]">
            submission_blocked
          </span>
        </div>
      </header>

      {scanStatus ? (
        <section className="mt-4 border border-[var(--line)] bg-white px-4 py-3 text-sm">
          <p className="font-semibold text-[var(--warning)]">
            {scanStatus === "blocked"
              ? "Scope Guard blocked this source audit."
              : scanStatus === "missing_required"
                ? "Repository path and scope path are required."
                : "Source audit scan did not create a run."}
          </p>
          {scopeError ? (
            <p className="mt-2 text-[var(--muted)]">{formatLabel(scopeError)}</p>
          ) : null}
        </section>
      ) : null}

      <div className="grid gap-5 py-5 xl:grid-cols-[minmax(0,1fr)_360px]">
        <section className="border border-[var(--line)] bg-white">
          <div className="flex items-center justify-between border-b border-[var(--line)] px-5 py-4">
            <h2 className="text-lg font-semibold">Local Audit Input</h2>
            <ShieldCheck size={19} className="text-[var(--accent)]" aria-hidden="true" />
          </div>
          <form action={sourceAuditScanAction} className="grid gap-4 p-5 text-sm">
            <label className="grid gap-1">
              <span className="text-xs font-semibold uppercase text-[var(--muted)]">
                Repository path
              </span>
              <input
                className="min-h-10 rounded-md border border-[var(--line)] px-3 outline-none focus:border-[var(--accent)]"
                name="repo_path"
                placeholder="C:/Users/Administrator/Desktop/project"
                required
              />
            </label>
            <label className="grid gap-1">
              <span className="text-xs font-semibold uppercase text-[var(--muted)]">
                Scope policy path
              </span>
              <input
                className="min-h-10 rounded-md border border-[var(--line)] px-3 outline-none focus:border-[var(--accent)]"
                name="scope_path"
                placeholder="C:/Users/Administrator/Desktop/scope.yaml"
                required
              />
            </label>
            <label className="grid gap-1">
              <span className="text-xs font-semibold uppercase text-[var(--muted)]">
                Policy text
              </span>
              <textarea
                className="min-h-28 rounded-md border border-[var(--line)] px-3 py-2 outline-none focus:border-[var(--accent)]"
                name="policy_text"
                placeholder="Optional policy summary for provenance."
              />
            </label>
            <button
              type="submit"
              className="min-h-10 justify-self-start rounded-md border border-[var(--line)] bg-[var(--foreground)] px-4 text-sm font-semibold text-white"
            >
              Start Source Audit
            </button>
          </form>
        </section>

        <aside className="grid content-start gap-5">
          <section className="border border-[var(--line)] bg-white">
            <div className="flex items-center justify-between border-b border-[var(--line)] px-5 py-4">
              <h2 className="text-lg font-semibold">Scope Guard</h2>
              <Lock size={19} className="text-[var(--accent)]" aria-hidden="true" />
            </div>
            <div className="grid gap-3 p-5 text-sm">
              <p className="text-pretty font-semibold text-[var(--muted)]">
                The scope file must allowlist the local repository before any source audit run is
                created.
              </p>
              <ul className="grid gap-2 text-[var(--muted)]">
                {safetyNotes.map((note) => (
                  <li key={note}>{safeDisplay(formatLabel(note))}</li>
                ))}
              </ul>
            </div>
          </section>
        </aside>
      </div>
    </main>
  );
}

function firstParam(value: string | string[] | undefined): string | undefined {
  if (Array.isArray(value)) {
    return value[0];
  }

  return value || undefined;
}

function formText(formData: FormData, key: string): string {
  return String(formData.get(key) ?? "").trim();
}

function optionalFormText(formData: FormData, key: string): string | null {
  const value = formText(formData, key);
  return value.length === 0 ? null : value;
}
