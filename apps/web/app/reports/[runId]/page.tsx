import Link from "next/link";
import { revalidatePath } from "next/cache";
import { ArrowLeft, ClipboardCheck, FileText, ListChecks, ShieldCheck, Target } from "lucide-react";
import {
  createFindingCandidate,
  getPipelineRun,
  getReportPreview,
  recordMythosBrainOutcome,
  type LearningEvidenceQuality,
  type LearningOutcome,
  type LearningSeverityDelta,
} from "@/lib/api";
import { fallbackMythosBrainProfile } from "@/lib/fallback-data";
import {
  fallbackReportPreview,
  fallbackRunDetail,
  formatLabel,
  safeDisplay,
} from "@/lib/workbench-detail-data";

type PageProps = {
  params: Promise<{ runId: string }>;
};

const sectionMeta = [
  {
    key: "observed_facts",
    label: "Observed Facts",
    icon: ListChecks,
  },
  {
    key: "model_reasoning",
    label: "Model Reasoning",
    icon: Target,
  },
  {
    key: "unverified_claims",
    label: "Unverified Claims",
    icon: ShieldCheck,
  },
] as const;

const promotionBlockingReadinessBlockers = new Set([
  "artifact_report_chain_blocked",
  "missing_security_impact_observation",
]);

export default async function ReportPreviewPage({ params }: PageProps) {
  const { runId } = await params;
  const [run, preview] = await Promise.all([
    getPipelineRun(runId, fallbackRunDetail(runId)),
    getReportPreview(runId, fallbackReportPreview(runId)),
  ]);

  if (!preview) {
    return (
      <main className="min-h-screen px-5 py-6 sm:px-8 lg:px-10">
        <PageBack />
        <section className="mt-6 border border-[var(--line)] bg-white p-6">
          <h1 className="text-2xl font-semibold text-balance">Report preview unavailable</h1>
          <p className="mt-2 text-pretty text-[var(--muted)]">{safeDisplay(runId)}</p>
        </section>
      </main>
    );
  }

  const reportDataMode = run?.policy_text_hash === "fallback-only" ? "Demo data" : "Live data";
  const currentRunId = preview.run_id;
  const hasPromotionCandidate = preview.claim_ledger.some(
    (claim) =>
      claim.claim_type === "observed_fact" &&
      claim.review_status === "confirmed_observed_fact" &&
      claim.readiness_level === "human_reviewed_gated" &&
      claim.quality_score >= 80 &&
      claim.evidence_refs.length > 0 &&
      claim.review_evidence_refs.some((ref) => ref !== "[REDACTED]") &&
      claim.readiness_blockers.every((blocker) => !promotionBlockingReadinessBlockers.has(blocker)),
  );
  const canPromoteFindingCandidate = reportDataMode === "Live data" && hasPromotionCandidate;

  async function promoteFindingCandidateAction() {
    "use server";

    await createFindingCandidate(currentRunId, null);
    revalidatePath(`/reports/${encodeURIComponent(currentRunId)}`);
    revalidatePath(`/runs/${encodeURIComponent(currentRunId)}`);
  }

  async function recordLearningOutcomeAction(formData: FormData) {
    "use server";

    const outcome = formData.get("outcome")?.toString() as LearningOutcome;
    const bountyAmount = optionalFormValue(formData, "bounty_amount");

    await recordMythosBrainOutcome(
      {
        bounty_amount: bountyAmount === null ? null : Number(bountyAmount),
        evidence_quality: optionalFormValue(
          formData,
          "evidence_quality",
        ) as LearningEvidenceQuality | null,
        notes: optionalFormValue(formData, "notes") ?? "",
        outcome,
        run_id: currentRunId,
        severity_delta: optionalFormValue(
          formData,
          "severity_delta",
        ) as LearningSeverityDelta | null,
      },
      fallbackMythosBrainProfile,
    );
    revalidatePath("/");
    revalidatePath(`/reports/${encodeURIComponent(currentRunId)}`);
    revalidatePath(`/runs/${encodeURIComponent(currentRunId)}`);
  }

  return (
    <main className="min-h-screen px-5 py-6 sm:px-8 lg:px-10">
      <PageBack />

      <header className="mt-6 border-b border-[var(--line)] pb-6">
        <p className="flex items-center gap-2 text-sm font-semibold text-[var(--accent-strong)]">
          <FileText size={17} aria-hidden="true" />
          {safeDisplay(preview.run_id)}
          <span className="rounded-sm border border-[var(--line)] px-2 py-0.5 text-xs font-semibold uppercase text-[var(--muted)]">
            {reportDataMode}
          </span>
        </p>
        <div className="mt-3 flex flex-col gap-4 lg:flex-row lg:items-end lg:justify-between">
          <div>
            <h1 className="max-w-4xl text-3xl font-semibold leading-tight text-balance">
              {safeDisplay(preview.title)}
            </h1>
            <p className="mt-2 text-pretty text-[var(--muted)]">
              {safeDisplay(run?.asset, "Unknown asset")}
            </p>
          </div>
          <div className="flex flex-wrap gap-2">
            <ActionLink href={`/runs/${encodeURIComponent(preview.run_id)}`} icon={Target}>
              Run
            </ActionLink>
            <ActionLink href={`/validation-workspace/${encodeURIComponent(preview.run_id)}`} icon={ClipboardCheck}>
              Validation
            </ActionLink>
          </div>
        </div>
      </header>
      {reportDataMode === "Demo data" ? (
        <p className="mt-4 border border-[var(--line)] bg-white px-4 py-3 text-sm font-semibold text-[var(--warning)]">
          Demo data is shown because this claim ledger comes from a fallback report preview.
        </p>
      ) : null}

      <section className="grid gap-3 py-5 sm:grid-cols-2 xl:grid-cols-4">
        <Metric label="Severity" value={formatLabel(preview.severity)} />
        <Metric label="Scope" value={formatLabel(preview.scope_status)} />
        <Metric label="Human review" value={preview.human_review_required ? "Required" : "Not required"} />
        <Metric label="Submission" value={preview.submission_blocked ? "Blocked" : "Ready"} />
      </section>

      <div className="grid gap-5 xl:grid-cols-[minmax(0,1fr)_360px]">
        <section className="grid gap-5">
          <article className="border border-[var(--line)] bg-white">
            <SectionHeader icon={FileText} title="Claim Ledger" />
            {preview.claim_ledger.length === 0 ? (
              <p className="p-5 text-sm text-[var(--muted)]">No claim ledger entries recorded.</p>
            ) : (
              <div className="divide-y divide-[var(--line)]">
                {preview.claim_ledger.map((claim) => (
                  <div
                    key={claim.claim_id}
                    className="grid gap-4 p-5 text-sm xl:grid-cols-[150px_minmax(0,1fr)_150px]"
                  >
                    <div className="grid content-start gap-2">
                      <p className="break-words text-xs font-semibold uppercase text-[var(--muted)]">
                        {safeDisplay(claim.claim_id)}
                      </p>
                      <p className="font-semibold">{formatLabel(claim.claim_type)}</p>
                    </div>
                    <div className="min-w-0">
                      <p className="break-words text-pretty text-[var(--muted)]">
                        {safeDisplay(claim.text)}
                      </p>
                      <dl className="mt-4 grid gap-3 sm:grid-cols-2">
                        <Field
                          label="Evidence"
                          value={claim.evidence_refs.length === 0 ? "Missing" : claim.evidence_refs.join(", ")}
                        />
                        <Field
                          label="Provenance"
                          value={claim.provenance_refs.length === 0 ? "Missing" : claim.provenance_refs.join(", ")}
                        />
                        <Field label="Redaction" value={claim.redaction_status} />
                        <Field
                          label="Review"
                          value={claim.human_review_required ? "Human required" : "Cleared"}
                        />
                        <Field label="Review status" value={claim.review_status} />
                        <Field label="Reviewer" value={claim.reviewer ?? "Unassigned"} />
                        <Field label="Reviewed at" value={claim.reviewed_at ?? "Unreviewed"} />
                        <Field label="Quality" value={`${claim.quality_score}/100`} />
                        <Field label="Readiness" value={claim.readiness_level} />
                        <Field
                          label="Review evidence"
                          value={
                            claim.review_evidence_refs.length === 0
                              ? "Missing"
                              : claim.review_evidence_refs.join(", ")
                          }
                        />
                      </dl>
                      <div className="mt-4">
                        <p className="text-xs font-semibold uppercase text-[var(--muted)]">Review rationale</p>
                        <p className="mt-1 break-words text-[var(--muted)]">
                          {safeDisplay(claim.review_rationale, "No review rationale recorded.")}
                        </p>
                      </div>
                      <div className="mt-4">
                        <p className="text-xs font-semibold uppercase text-[var(--muted)]">Quality reasons</p>
                        {claim.quality_reasons.length === 0 ? (
                          <p className="mt-1 font-semibold">None</p>
                        ) : (
                          <ul className="mt-2 flex flex-wrap gap-x-4 gap-y-2 text-xs font-semibold uppercase text-[var(--muted)]">
                            {claim.quality_reasons.map((reason) => (
                              <li key={`${claim.claim_id}-${reason}`}>{formatLabel(reason)}</li>
                            ))}
                          </ul>
                        )}
                      </div>
                      <div className="mt-4">
                        <p className="text-xs font-semibold uppercase text-[var(--muted)]">Blockers</p>
                        {claim.readiness_blockers.length === 0 ? (
                          <p className="mt-1 font-semibold">None</p>
                        ) : (
                          <ul className="mt-2 flex flex-wrap gap-x-4 gap-y-2 text-xs font-semibold uppercase text-[var(--accent-strong)]">
                            {claim.readiness_blockers.map((blocker) => (
                              <li key={`${claim.claim_id}-${blocker}`}>{formatLabel(blocker)}</li>
                            ))}
                          </ul>
                        )}
                      </div>
                    </div>
                    <div className="grid content-start gap-2">
                      <p className="text-xs font-semibold uppercase text-[var(--muted)]">Status</p>
                      <p className="break-words font-semibold">{formatLabel(claim.status)}</p>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </article>

          {sectionMeta.map((section) => {
            const lines = preview.sections[section.key];
            const claimLabel = preview.claim_labels[section.key] ?? section.key;

            return (
              <article key={section.key} className="border border-[var(--line)] bg-white">
                <SectionHeader icon={section.icon} title={section.label} />
                <div className="border-b border-[var(--line)] px-5 py-3 text-xs font-semibold uppercase text-[var(--accent-strong)]">
                  {safeDisplay(claimLabel)}
                </div>
                {lines.length === 0 ? (
                  <p className="p-5 text-sm text-[var(--muted)]">No claims recorded.</p>
                ) : (
                  <ol className="divide-y divide-[var(--line)] text-sm">
                    {lines.map((line, index) => (
                      <li key={`${section.key}-${index}`} className="grid gap-3 p-5 md:grid-cols-[80px_minmax(0,1fr)]">
                        <p className="font-semibold tabular-nums">#{index + 1}</p>
                        <p className="text-pretty text-[var(--muted)]">{safeDisplay(line)}</p>
                      </li>
                    ))}
                  </ol>
                )}
              </article>
            );
          })}
        </section>

        <aside className="grid content-start gap-5">
          <section className="border border-[var(--line)] bg-white">
            <SectionHeader icon={ShieldCheck} title="Safety Notes" />
            {preview.safety_notes.length === 0 ? (
              <p className="p-5 text-sm text-[var(--muted)]">No safety notes recorded.</p>
            ) : (
              <ul className="grid gap-2 p-5 text-sm text-[var(--muted)]">
                {preview.safety_notes.map((note) => (
                  <li key={note}>{formatLabel(note)}</li>
                ))}
              </ul>
            )}
          </section>

          <section className="border border-[var(--line)] bg-white">
            <SectionHeader icon={ListChecks} title="Evidence Refs" />
            {preview.evidence_refs.length === 0 ? (
              <p className="p-5 text-sm text-[var(--muted)]">No evidence refs recorded.</p>
            ) : (
              <ul className="grid gap-2 p-5 text-sm text-[var(--muted)]">
                {preview.evidence_refs.map((ref) => (
                  <li key={ref}>{safeDisplay(ref)}</li>
                ))}
              </ul>
            )}
          </section>

          <section className="border border-[var(--line)] bg-white">
            <SectionHeader icon={FileText} title="Submission Gate" />
            <dl className="grid gap-3 p-5 text-sm">
              <Field label="Human review" value={preview.human_review_required ? "Required" : "Not required"} />
              <Field label="Submission blocked" value={preview.submission_blocked ? "Yes" : "No"} />
              <Field label="Run" value={preview.run_id} />
            </dl>
            {canPromoteFindingCandidate ? (
              <form action={promoteFindingCandidateAction} className="border-t border-[var(--line)] p-5">
                <p className="mb-3 text-sm text-[var(--muted)]">
                  Promote the eligible human-reviewed observed claim into Finding DB. Submission remains manual.
                </p>
                <button
                  type="submit"
                  className="min-h-10 rounded-md border border-[var(--line)] bg-[var(--foreground)] px-4 text-sm font-semibold text-white"
                >
                  Promote Finding Candidate
                </button>
              </form>
            ) : (
              <p className="border-t border-[var(--line)] p-5 text-sm font-semibold text-[var(--muted)]">
                Promotion waits for a live, human-reviewed observed claim.
              </p>
            )}
          </section>

          <section className="border border-[var(--line)] bg-white">
            <SectionHeader icon={ClipboardCheck} title="Learning Outcome" />
            <form action={recordLearningOutcomeAction} className="grid gap-4 p-5 text-sm">
              <p className="font-semibold text-[var(--muted)]">
                advisory_memory_only. Records triage learning for future prioritization without changing validation
                permission.
              </p>
              <label className="grid gap-1">
                <span className="text-xs font-semibold uppercase text-[var(--muted)]">Outcome</span>
                <select name="outcome" className="min-h-10 border border-[var(--line)] bg-white px-3">
                  <option value="accepted">Accepted</option>
                  <option value="duplicate">Duplicate</option>
                  <option value="informative">Informative</option>
                  <option value="na">N/A</option>
                  <option value="rejected">Rejected</option>
                </select>
              </label>
              <label className="grid gap-1">
                <span className="text-xs font-semibold uppercase text-[var(--muted)]">Evidence quality</span>
                <select name="evidence_quality" className="min-h-10 border border-[var(--line)] bg-white px-3">
                  <option value="">Unspecified</option>
                  <option value="strong">Strong</option>
                  <option value="adequate">Adequate</option>
                  <option value="weak">Weak</option>
                </select>
              </label>
              <label className="grid gap-1">
                <span className="text-xs font-semibold uppercase text-[var(--muted)]">Severity delta</span>
                <select name="severity_delta" className="min-h-10 border border-[var(--line)] bg-white px-3">
                  <option value="">Unspecified</option>
                  <option value="up">Up</option>
                  <option value="same">Same</option>
                  <option value="down">Down</option>
                </select>
              </label>
              <label className="grid gap-1">
                <span className="text-xs font-semibold uppercase text-[var(--muted)]">Bounty amount</span>
                <input
                  name="bounty_amount"
                  type="number"
                  min="0"
                  className="min-h-10 border border-[var(--line)] bg-white px-3"
                />
              </label>
              <label className="grid gap-1">
                <span className="text-xs font-semibold uppercase text-[var(--muted)]">Notes</span>
                <textarea
                  name="notes"
                  className="min-h-24 border border-[var(--line)] bg-white p-3"
                  defaultValue="Outcome recorded from human report review."
                />
              </label>
              <button
                type="submit"
                className="min-h-10 rounded-md border border-[var(--line)] bg-[var(--foreground)] px-4 text-sm font-semibold text-white"
              >
                Record Learning Outcome
              </button>
            </form>
          </section>
        </aside>
      </div>
    </main>
  );
}

function optionalFormValue(formData: FormData, name: string) {
  const value = formData.get(name);
  if (typeof value !== "string") {
    return null;
  }
  const trimmed = value.trim();
  return trimmed.length === 0 ? null : trimmed;
}

function PageBack() {
  return (
    <Link
      href="/"
      className="inline-flex min-h-10 items-center gap-2 rounded-md border border-[var(--line)] bg-white px-3 text-sm font-semibold"
    >
      <ArrowLeft size={17} aria-hidden="true" />
      Dashboard
    </Link>
  );
}

function ActionLink({
  children,
  href,
  icon: Icon,
}: {
  children: React.ReactNode;
  href: string;
  icon: typeof Target;
}) {
  return (
    <Link
      href={href}
      className="inline-flex min-h-10 items-center gap-2 rounded-md border border-[var(--line)] bg-white px-3 text-sm font-semibold"
    >
      <Icon size={17} aria-hidden="true" />
      {children}
    </Link>
  );
}

function Metric({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div className="border border-[var(--line)] bg-white p-4">
      <p className="text-sm text-[var(--muted)]">{label}</p>
      <p className="mt-3 text-2xl font-semibold tabular-nums">{value}</p>
    </div>
  );
}

function SectionHeader({ icon: Icon, title }: { icon: typeof Target; title: string }) {
  return (
    <div className="flex items-center justify-between border-b border-[var(--line)] px-5 py-4">
      <h2 className="text-lg font-semibold">{title}</h2>
      <Icon size={19} className="text-[var(--accent)]" aria-hidden="true" />
    </div>
  );
}

function Field({ label, value }: { label: string; value: unknown }) {
  return (
    <div className="grid gap-1">
      <dt className="text-xs font-semibold uppercase text-[var(--muted)]">{label}</dt>
      <dd className="break-words font-semibold">{safeDisplay(value)}</dd>
    </div>
  );
}
