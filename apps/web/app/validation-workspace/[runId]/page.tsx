import Link from "next/link";
import { revalidatePath } from "next/cache";
import { ArrowLeft, ClipboardCheck, FileText, Lock, ShieldCheck, Target } from "lucide-react";
import { getPipelineRun, recordManualObservation } from "@/lib/api";
import {
  fallbackRunDetail,
  formatLabel,
  safeDisplay,
  safeStringList,
} from "@/lib/workbench-detail-data";

type PageProps = {
  params: Promise<{ runId: string }>;
};

export default async function ValidationWorkspacePage({ params }: PageProps) {
  const { runId } = await params;
  const run = await getPipelineRun(runId, fallbackRunDetail(runId));
  const workspace = run?.payload?.validation_workspace;
  const steps = workspace?.steps ?? [];
  const blockedReasons = safeStringList(workspace?.blocked_reasons);
  const evidenceHints = workspace?.evidence_hints ?? [];
  const manualObservations = workspace?.manual_observations ?? [];
  const claimTasks = workspace?.claim_validation_tasks ?? [];
  const gate = workspace?.approval_gate;

  if (!run || !workspace) {
    return (
      <main className="min-h-screen px-5 py-6 sm:px-8 lg:px-10">
        <PageBack />
        <section className="mt-6 border border-[var(--line)] bg-white p-6">
          <h1 className="text-2xl font-semibold text-balance">Validation workspace unavailable</h1>
          <p className="mt-2 text-pretty text-[var(--muted)]">{safeDisplay(runId)}</p>
        </section>
      </main>
    );
  }

  const workspaceDataMode = run.policy_text_hash === "fallback-only" ? "Demo data" : "Live data";
  const currentRunId = run.id;

  async function recordManualObservationAction(formData: FormData) {
    "use server";

    const claimId = formText(formData, "claim_id");
    const observation = formText(formData, "observation");
    const observationType = formText(formData, "observation_type") || "request_response_diff";
    const observer = formText(formData, "observer") || "lead_reviewer";
    const evidenceRefs = formList(formData, "evidence_refs");
    const safetyNotes = formData.getAll("safety_notes").map((value) => String(value));

    if (!claimId || !observation) {
      return;
    }

    await recordManualObservation(
      currentRunId,
      {
        claim_id: claimId,
        evidence_refs: evidenceRefs,
        observation,
        observation_type: observationType,
        observer,
        safety_notes: safetyNotes,
      },
    );
    revalidatePath(`/validation-workspace/${encodeURIComponent(currentRunId)}`);
  }

  return (
    <main className="min-h-screen px-5 py-6 sm:px-8 lg:px-10">
      <PageBack />

      <header className="mt-6 border-b border-[var(--line)] pb-6">
        <p className="flex items-center gap-2 text-sm font-semibold text-[var(--accent-strong)]">
          <ClipboardCheck size={17} aria-hidden="true" />
          {safeDisplay(run.id)}
          <span className="rounded-sm border border-[var(--line)] px-2 py-0.5 text-xs font-semibold uppercase text-[var(--muted)]">
            {workspaceDataMode}
          </span>
        </p>
        <div className="mt-3 flex flex-col gap-4 lg:flex-row lg:items-end lg:justify-between">
          <div>
            <h1 className="max-w-4xl text-3xl font-semibold leading-tight text-balance">
              Validation Workspace
            </h1>
            <p className="mt-2 text-pretty text-[var(--muted)]">{safeDisplay(run.asset)}</p>
          </div>
          <div className="flex flex-wrap gap-2">
            <ActionLink href={`/runs/${encodeURIComponent(run.id)}`} icon={Target}>
              Run
            </ActionLink>
            <ActionLink href={`/reports/${encodeURIComponent(run.id)}`} icon={FileText}>
              Report
            </ActionLink>
          </div>
        </div>
      </header>
      {workspaceDataMode === "Demo data" ? (
        <p className="mt-4 border border-[var(--line)] bg-white px-4 py-3 text-sm font-semibold text-[var(--warning)]">
          Demo data is shown because this validation workspace comes from a fallback run record.
        </p>
      ) : null}

      <section className="grid gap-3 py-5 sm:grid-cols-2 xl:grid-cols-4">
        <GateMetric
          label="Preflight gate"
          value={workspace.allowed_to_execute === true}
          trueLabel="Preflight reviewed"
          falseLabel="Preflight blocked"
        />
        <GateMetric label="Test accounts only" value={workspace.test_accounts_only !== false} />
        <GateMetric label="No real user data" value={workspace.no_real_user_data !== false} />
        <GateMetric label="Non destructive only" value={workspace.non_destructive_only !== false} />
      </section>

      <div className="grid gap-5 xl:grid-cols-[minmax(0,1fr)_360px]">
        <section className="grid gap-5">
          <section className="border border-[var(--line)] bg-white">
            <SectionHeader icon={ClipboardCheck} title="Safe Steps" />
            {steps.length === 0 ? (
              <p className="p-5 text-sm text-[var(--muted)]">No validation steps ready.</p>
            ) : (
              <ol className="divide-y divide-[var(--line)]">
                {steps.map((step, index) => (
                  <li
                    key={`${safeDisplay(step.method)}-${index}`}
                    className="grid gap-3 p-5 text-sm lg:grid-cols-[80px_180px_minmax(0,1fr)]"
                  >
                    <p className="font-semibold tabular-nums">Step {index + 1}</p>
                    <div>
                      <p className="font-semibold">{formatLabel(step.status)}</p>
                      <p className="mt-1 text-[var(--muted)]">{formatLabel(step.method)}</p>
                    </div>
                    <p className="text-pretty text-[var(--muted)]">
                      {safeDisplay(step.instruction)}
                    </p>
                  </li>
                ))}
              </ol>
            )}
          </section>

          <section className="border border-[var(--line)] bg-white">
            <SectionHeader icon={Target} title="Claim Review" />
            {claimTasks.length === 0 ? (
              <p className="p-5 text-sm text-[var(--muted)]">No claim review items ready.</p>
            ) : (
              <ol className="divide-y divide-[var(--line)]">
                {claimTasks.map((task) => {
                  const requiredTypes = safeStringList(task.required_observation_types);
                  const relationshipContexts = safeStringList(task.relationship_contexts);
                  const evidenceFocus = safeStringList(task.evidence_focus);
                  const evidenceRefs = safeStringList(task.evidence_refs);
                  const blockers = safeStringList(task.readiness_blockers);
                  const safetyNotes = safeStringList(task.safety_notes);
                  const needsReportSafeEvidence = blockers.includes(
                    "manual_observation_missing_safe_evidence",
                  );

                  return (
                    <li
                      key={safeDisplay(task.claim_id)}
                      className="grid gap-4 p-5 text-sm lg:grid-cols-[180px_minmax(0,1fr)]"
                    >
                      <div className="grid content-start gap-2">
                        <p className="break-words text-xs font-semibold uppercase text-[var(--muted)]">
                          {safeDisplay(task.claim_id)}
                        </p>
                        <p className="font-semibold">{formatLabel(task.status)}</p>
                        <p className="text-[var(--muted)]">{formatLabel(task.claim_type)}</p>
                      </div>
                      <div className="min-w-0">
                        <p className="break-words text-pretty text-[var(--muted)]">
                          {safeDisplay(task.claim_text)}
                        </p>
                        <dl className="mt-4 grid gap-3 sm:grid-cols-2">
                          <Field
                            label="Promotion gate"
                            value={task.promotion_eligible ? "Review ready" : "Review required"}
                          />
                          <Field label="Review" value={task.review_status} />
                          <Field label="Readiness" value={task.readiness_level} />
                          <Field label="Quality" value={`${task.quality_score}/100`} />
                          <Field
                            label="Relationship"
                            value={
                              relationshipContexts.length === 0
                                ? "None"
                                : relationshipContexts.join(", ")
                            }
                          />
                          <Field
                            label="Focus"
                            value={evidenceFocus.length === 0 ? "None" : evidenceFocus.join(", ")}
                          />
                          <Field
                            label="Preflight status"
                            value={task.execution_allowed ? "Preflight reviewed" : "Preflight blocked"}
                          />
                          <Field
                            label="Required observation"
                            value={requiredTypes.length === 0 ? "None" : requiredTypes.join(", ")}
                          />
                          <Field
                            label="Evidence"
                            value={evidenceRefs.length === 0 ? "Missing" : evidenceRefs.join(", ")}
                          />
                        </dl>
                        {blockers.length > 0 ? (
                          <ul className="mt-4 flex flex-wrap gap-x-4 gap-y-2 text-xs font-semibold uppercase text-[var(--accent-strong)]">
                            {blockers.map((blocker) => (
                              <li key={`${safeDisplay(task.claim_id)}-${blocker}`}>
                                {formatLabel(blocker)}
                              </li>
                            ))}
                          </ul>
                        ) : null}
                        {needsReportSafeEvidence ? (
                          <div className="mt-4 border border-[var(--line)] bg-[#f7f7f4] p-3">
                            <p className="text-sm font-semibold text-[var(--warning)]">
                              Report-safe evidence required
                            </p>
                            <p className="mt-2 text-sm text-[var(--muted)]">
                              The last manual observation only supplied redacted evidence refs. Add
                              a sanitized request_response_diff or role_matrix_observation before
                              this claim can move toward report review.
                            </p>
                          </div>
                        ) : null}
                        {safetyNotes.length > 0 ? (
                          <ul className="mt-4 flex flex-wrap gap-x-4 gap-y-2 text-xs font-semibold uppercase text-[var(--muted)]">
                            {safetyNotes.map((note) => (
                              <li key={`${safeDisplay(task.claim_id)}-${note}`}>
                                {formatLabel(note)}
                              </li>
                            ))}
                          </ul>
                        ) : null}
                        <form
                          action={recordManualObservationAction}
                          className="mt-4 grid gap-3 border-t border-[var(--line)] pt-4"
                        >
                          <input name="claim_id" type="hidden" value={safeDisplay(task.claim_id)} />
                          <input name="safety_notes" type="hidden" value="test_accounts_only" />
                          <input name="safety_notes" type="hidden" value="no_real_user_data" />
                          <input name="safety_notes" type="hidden" value="human_review_required" />
                          <label className="grid gap-1">
                            <span className="text-xs font-semibold uppercase text-[var(--muted)]">Observation type</span>
                            <select
                              className="min-h-10 rounded-md border border-[var(--line)] bg-white px-3 outline-none focus:border-[var(--accent)]"
                              name="observation_type"
                              defaultValue={requiredTypes[0] ?? "request_response_diff"}
                            >
                              <option value="request_response_diff">Request response diff</option>
                              <option value="role_matrix_observation">Role matrix observation</option>
                            </select>
                          </label>
                          <label className="grid gap-1">
                            <span className="text-xs font-semibold uppercase text-[var(--muted)]">Observer</span>
                            <input
                              className="min-h-10 rounded-md border border-[var(--line)] px-3 outline-none focus:border-[var(--accent)]"
                              name="observer"
                              defaultValue="lead_reviewer"
                            />
                          </label>
                          <label className="grid gap-1">
                            <span className="text-xs font-semibold uppercase text-[var(--muted)]">Observation</span>
                            <textarea
                              className="min-h-24 rounded-md border border-[var(--line)] px-3 py-2 outline-none focus:border-[var(--accent)]"
                              name="observation"
                            />
                          </label>
                          <label className="grid gap-1">
                            <span className="text-xs font-semibold uppercase text-[var(--muted)]">Evidence refs</span>
                            <input
                              className="min-h-10 rounded-md border border-[var(--line)] px-3 outline-none focus:border-[var(--accent)]"
                              name="evidence_refs"
                            />
                          </label>
                          <button
                            type="submit"
                            className="min-h-10 justify-self-start rounded-md border border-[var(--line)] bg-[var(--foreground)] px-4 text-sm font-semibold text-white"
                          >
                            Record Observation
                          </button>
                        </form>
                      </div>
                    </li>
                  );
                })}
              </ol>
            )}
          </section>

          <section className="border border-[var(--line)] bg-white">
            <SectionHeader icon={FileText} title="Manual Observations" />
            {manualObservations.length === 0 ? (
              <p className="p-5 text-sm text-[var(--muted)]">No manual observations ready for review.</p>
            ) : (
              <ol className="divide-y divide-[var(--line)]">
                {manualObservations.map((observation, index) => {
                  const evidenceRefs = safeStringList(observation.evidence_refs);
                  const safetyNotes = safeStringList(observation.safety_notes);

                  return (
                    <li
                      key={`${safeDisplay(observation.observation_id)}-${index}`}
                      className="grid gap-4 p-5 text-sm lg:grid-cols-[180px_minmax(0,1fr)]"
                    >
                      <div className="grid content-start gap-2">
                        <p className="break-words text-xs font-semibold uppercase text-[var(--muted)]">
                          {safeDisplay(observation.observation_id)}
                        </p>
                        <p className="font-semibold">{formatLabel(observation.observation_type)}</p>
                        <p className="text-[var(--muted)]">{safeDisplay(observation.observer)}</p>
                      </div>
                      <div className="min-w-0">
                        <p className="break-words text-pretty text-[var(--muted)]">
                          {safeDisplay(observation.observation)}
                        </p>
                        <dl className="mt-4 grid gap-3 sm:grid-cols-2">
                          <Field label="Claim" value={observation.claim_id} />
                          <Field label="Redaction" value={observation.redaction_status} />
                          <Field
                            label="Observation boundary"
                            value={observation.execution_allowed ? "Preflight reviewed" : "Review only"}
                          />
                          <Field
                            label="Report chain gate"
                            value={observation.report_chain_blocked ? "Review required" : "Review ready"}
                          />
                          <Field label="Created" value={observation.created_at} />
                          <Field
                            label="Evidence"
                            value={evidenceRefs.length === 0 ? "Missing" : evidenceRefs.join(", ")}
                          />
                        </dl>
                        {safetyNotes.length > 0 ? (
                          <ul className="mt-4 flex flex-wrap gap-x-4 gap-y-2 text-xs font-semibold uppercase text-[var(--accent-strong)]">
                            {safetyNotes.map((note) => (
                              <li key={`${safeDisplay(observation.observation_id)}-${note}`}>
                                {formatLabel(note)}
                              </li>
                            ))}
                          </ul>
                        ) : null}
                      </div>
                    </li>
                  );
                })}
              </ol>
            )}
          </section>
        </section>

        <aside className="grid content-start gap-5">
          <section className="border border-[var(--line)] bg-white">
            <SectionHeader icon={ShieldCheck} title="Preflight Gate" />
            <dl className="grid gap-3 p-5 text-sm">
              <Field label="Workspace" value={workspace.status} />
              <Field label="Plan" value={workspace.validation_plan_status} />
              <Field label="Refutation" value={workspace.refutation_status} />
              <Field label="Gate status" value={gate?.status} />
              <Field label="Gate reason" value={gate?.reason} />
              <Field label="Human review gate" value={gate?.human_approved ? "Review captured" : "Review required"} />
            </dl>
          </section>

          <section className="border border-[var(--line)] bg-white">
            <SectionHeader icon={Lock} title="Review Requirements" />
            {blockedReasons.length === 0 ? (
              <p className="p-5 text-sm text-[var(--muted)]">No active review requirements.</p>
            ) : (
              <ul className="grid gap-2 p-5 text-sm text-[var(--muted)]">
                {blockedReasons.map((reason) => (
                  <li key={reason}>{formatLabel(reason)}</li>
                ))}
              </ul>
            )}
          </section>

          <section className="border border-[var(--line)] bg-white">
            <SectionHeader icon={Target} title="Evidence Hints" />
            {evidenceHints.length === 0 ? (
              <p className="p-5 text-sm text-[var(--muted)]">No evidence hints ready.</p>
            ) : (
              <dl className="grid gap-0 divide-y divide-[var(--line)] text-sm">
                {evidenceHints.map((hint, index) => (
                  <div key={`${safeDisplay(hint.type)}-${index}`} className="grid gap-1 p-5">
                    <dt className="font-semibold">{formatLabel(hint.type)}</dt>
                    <dd className="text-pretty text-[var(--muted)]">
                      {safeDisplay(hint.purpose)}
                    </dd>
                  </div>
                ))}
              </dl>
            )}
          </section>
        </aside>
      </div>
    </main>
  );
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

function GateMetric({
  dangerOnTrue = false,
  falseLabel = "false",
  label,
  trueLabel = "true",
  value,
}: {
  dangerOnTrue?: boolean;
  falseLabel?: string;
  label: string;
  trueLabel?: string;
  value: boolean;
}) {
  const risky = dangerOnTrue ? value : !value;

  return (
    <div className="border border-[var(--line)] bg-white p-4">
      <p className="text-sm text-[var(--muted)]">{label}</p>
      <p className={`mt-3 text-2xl font-semibold ${risky ? "text-[var(--danger)]" : "text-[var(--accent-strong)]"}`}>
        {value ? trueLabel : falseLabel}
      </p>
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
      <dd className="break-words font-semibold">{formatLabel(value)}</dd>
    </div>
  );
}

function formText(formData: FormData, key: string): string {
  return String(formData.get(key) ?? "").trim();
}

function formList(formData: FormData, key: string): string[] {
  return formText(formData, key)
    .split(/[\n,]+/)
    .map((item) => item.trim())
    .filter(Boolean);
}
