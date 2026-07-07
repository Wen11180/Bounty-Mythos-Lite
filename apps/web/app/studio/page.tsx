import Link from "next/link";
import { toStudioCandidateCards, toStudioWorkspaceSummary } from "@/lib/studio-data";

const workspace = toStudioWorkspaceSummary({
  name: "Local Mythos Studio",
  artifacts: [],
  runs: [],
  safety: {
    scope_guard_status: "missing_scope",
    blocked_actions: ["execute_live_validation", "submit_report"],
  },
});

const candidates = toStudioCandidateCards([]);

export default function StudioPage() {
  return (
    <main className="min-h-screen px-5 py-6 sm:px-8 lg:px-10">
      <div className="grid gap-5 xl:grid-cols-[320px_minmax(0,1fr)]">
        <section className="border border-[var(--line)] bg-white">
          <div className="border-b border-[var(--line)] px-5 py-4">
            <h1 className="text-lg font-semibold">Workspaces</h1>
            <p className="mt-1 text-sm text-[var(--muted)]">{workspace.name}</p>
          </div>
          <div className="grid gap-3 p-5 text-sm">
            <div>
              <p className="text-xs font-semibold uppercase text-[var(--muted)]">Scope Guard</p>
              <p className="mt-1 font-semibold text-[var(--warning)]">
                {workspace.scopeGuardLabel}
              </p>
            </div>
            <div>
              <p className="text-xs font-semibold uppercase text-[var(--muted)]">Artifacts</p>
              <p className="mt-1 font-semibold">{workspace.artifactCount}</p>
            </div>
            <Link
              href="/"
              className="inline-flex min-h-10 items-center justify-center rounded-md border border-[var(--line)] px-3 text-sm font-semibold"
            >
              Back to dashboard
            </Link>
          </div>
        </section>

        <div className="grid gap-5">
          <section className="border border-[var(--line)] bg-white">
            <div className="border-b border-[var(--line)] px-5 py-4">
              <h2 className="text-lg font-semibold">Conversation</h2>
            </div>
            <div className="grid gap-3 p-5 text-sm text-[var(--muted)]">
              <p>
                Import authorized policy, scope, API, HAR, or local repository artifacts before
                starting analysis. Candidate output stays hypothesis-only until evidence review.
              </p>
              <code className="block border border-[var(--line)] bg-[var(--background)] px-3 py-2 text-[var(--foreground)]">
                mythos studio import --policy ./policy.md --scope ./scope.yaml --repo ./target
              </code>
            </div>
          </section>

          <section className="border border-[var(--line)] bg-white">
            <div className="border-b border-[var(--line)] px-5 py-4">
              <h2 className="text-lg font-semibold">Candidate Board</h2>
            </div>
            <div className="p-5 text-sm text-[var(--muted)]">
              {candidates.length === 0 ? (
                <p>
                  No candidates yet. Import authorized artifacts to surface the top 1-5
                  submission-blocked candidates for review.
                </p>
              ) : null}
            </div>
          </section>

          <section className="border border-[var(--line)] bg-white">
            <div className="border-b border-[var(--line)] px-5 py-4">
              <h2 className="text-lg font-semibold">Safety and Run Log</h2>
            </div>
            <div className="grid gap-3 p-5 text-sm">
              <p className="font-semibold text-[var(--warning)]">submission-blocked</p>
              <ul className="grid gap-2 text-[var(--muted)]">
                {workspace.blockedActions.map((action) => (
                  <li key={action}>{action}</li>
                ))}
              </ul>
            </div>
          </section>
        </div>
      </div>
    </main>
  );
}
