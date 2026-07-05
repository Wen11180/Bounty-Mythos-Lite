import Link from "next/link";
import {
  ArrowLeft,
  ClipboardCheck,
  Database,
  FileText,
  ShieldCheck,
  Target,
} from "lucide-react";
import { getPipelineRun } from "@/lib/api";
import { toPipelineRunSummary } from "@/lib/pipeline-runs-data";
import {
  fallbackRunDetail,
  formatLabel,
  safeDisplay,
  safeStringList,
} from "@/lib/workbench-detail-data";

type PageProps = {
  params: Promise<{ runId: string }>;
};

export default async function RunDetailPage({ params }: PageProps) {
  const { runId } = await params;
  const run = await getPipelineRun(runId, fallbackRunDetail(runId));

  if (!run) {
    return (
      <main className="min-h-screen px-5 py-6 sm:px-8 lg:px-10">
        <PageBack />
        <section className="mt-6 border border-[var(--line)] bg-white p-6">
          <h1 className="text-2xl font-semibold text-balance">Run not found</h1>
          <p className="mt-2 text-pretty text-[var(--muted)]">{safeDisplay(runId)}</p>
        </section>
      </main>
    );
  }

  const summary = toPipelineRunSummary(run);
  const payload = run.payload;
  const artifactId = summary.artifact.artifactId;
  const validationWorkspace = payload?.validation_workspace;
  const reportDraft = payload?.report_draft;
  const candidateAssessments = payload?.hypothesis_assessments ?? [];
  const refutationReasons = safeStringList(payload?.refutation?.reasons);
  const targetModel = payload?.target_model;
  const hunterAssessment = run.hunter_intelligence?.assessments?.[0];
  const hunterReasons = safeStringList(hunterAssessment?.reasons);
  const closedLoop = payload?.closed_loop_summary;
  const closedLoopBlockedReasons = safeStringList(closedLoop?.blocked_reasons);
  const closedLoopSafetyNotes = safeStringList(closedLoop?.safety_notes);
  const closedLoopSteps = closedLoop?.steps ?? [];

  return (
    <main className="min-h-screen px-5 py-6 sm:px-8 lg:px-10">
      <PageBack />

      <header className="mt-6 border-b border-[var(--line)] pb-6">
        <p className="flex items-center gap-2 text-sm font-semibold text-[var(--accent-strong)]">
          <Database size={17} aria-hidden="true" />
          {safeDisplay(run.id)}
        </p>
        <div className="mt-3 flex flex-col gap-4 lg:flex-row lg:items-end lg:justify-between">
          <div>
            <h1 className="max-w-4xl text-3xl font-semibold leading-tight text-balance">
              {safeDisplay(summary.reportTitle, "Run Detail")}
            </h1>
            <p className="mt-2 text-pretty text-[var(--muted)]">
              {safeDisplay(summary.asset)}
            </p>
          </div>
          <div className="flex flex-wrap gap-2">
            {artifactId ? (
              <ActionLink href={`/artifacts/${encodeURIComponent(artifactId)}`} icon={Database}>
                Artifact
              </ActionLink>
            ) : null}
            <ActionLink href={`/validation-workspace/${encodeURIComponent(run.id)}`} icon={ClipboardCheck}>
              Validation
            </ActionLink>
            <ActionLink href={`/reports/${encodeURIComponent(run.id)}`} icon={FileText}>
              Report
            </ActionLink>
          </div>
        </div>
      </header>

      <section className="grid gap-3 py-5 sm:grid-cols-2 xl:grid-cols-6">
        <Metric label="Hypotheses" value={summary.hypothesisCount} />
        <Metric label="Blocked" value={summary.blockedCount} />
        <Metric label="Evidence" value={summary.evidenceCount} />
        <Metric label="Scope" value={formatLabel(run.scope_status)} />
        <Metric label="Gate" value={formatLabel(summary.validationGate.status)} />
        <Metric label="Loop" value={formatLabel(closedLoop?.status ?? "not_started")} />
      </section>

      <div className="grid gap-5 xl:grid-cols-[minmax(0,1fr)_360px]">
        <section className="grid gap-5">
          {candidateAssessments.length > 0 ? (
            <section className="border border-[var(--line)] bg-white">
              <SectionHeader icon={Target} title="Candidate Lifecycle" />
              <div className="divide-y divide-[var(--line)]">
                {candidateAssessments.map((candidate, index) => {
                  const reasons = safeStringList(candidate.refutation?.reasons);

                  return (
                    <article
                      key={candidate.candidate_id ?? `candidate-${index}`}
                      className="grid gap-4 p-5 text-sm xl:grid-cols-[140px_minmax(0,1fr)_190px]"
                    >
                      <div className="grid content-start gap-2">
                        <p className="break-words text-xs font-semibold uppercase text-[var(--muted)]">
                          {safeDisplay(candidate.candidate_id, `candidate_${index + 1}`)}
                        </p>
                        <p className="font-semibold">{formatLabel(candidate.candidate_status)}</p>
                      </div>
                      <div className="min-w-0">
                        <p className="break-words text-pretty font-semibold">
                          {safeDisplay(candidate.hypothesis?.hypothesis, "Untitled hypothesis")}
                        </p>
                        <dl className="mt-4 grid gap-3 sm:grid-cols-2">
                          <Field label="Validation" value={candidate.hypothesis?.validation_mode} />
                          <Field label="Refutation" value={candidate.refutation?.status} />
                          <Field label="Plan" value={candidate.validation_plan?.status} />
                          <Field
                            label="Evidence hints"
                            value={candidate.evidence_hints?.length ?? 0}
                          />
                        </dl>
                        {reasons.length > 0 ? (
                          <ul className="mt-4 flex flex-wrap gap-1.5">
                            {reasons.map((reason) => (
                              <li
                                key={`${candidate.candidate_id}-${reason}`}
                                className="rounded-sm border border-[var(--line)] px-2 py-0.5 text-xs font-semibold text-[var(--muted)]"
                              >
                                {formatLabel(reason)}
                              </li>
                            ))}
                          </ul>
                        ) : null}
                      </div>
                      <div className="grid content-start gap-2 xl:border-l xl:border-[var(--line)] xl:pl-5">
                        <p className="font-semibold">
                          {safeDisplay(candidate.hunter_assessment?.playbook_label, "No playbook")}
                        </p>
                        <p className="text-2xl font-semibold tabular-nums">
                          {candidate.hunter_assessment?.hunter_priority_score ?? 0}
                        </p>
                        <p className="text-[var(--muted)]">
                          {formatLabel(candidate.hunter_assessment?.recommendation)}
                        </p>
                      </div>
                    </article>
                  );
                })}
              </div>
            </section>
          ) : null}

          <section className="border border-[var(--line)] bg-white">
            <SectionHeader icon={Target} title="Stage Timeline" />
            <ol className="divide-y divide-[var(--line)]">
              {summary.stages.map((stage) => (
                <li
                  key={`${summary.runId}-${stage.label}`}
                  className="grid gap-3 p-5 text-sm lg:grid-cols-[180px_150px_minmax(0,1fr)_80px]"
                >
                  <p className="font-semibold">{safeDisplay(stage.label)}</p>
                  <p className="font-semibold text-[var(--accent-strong)]">
                    {formatLabel(stage.status)}
                  </p>
                  <div className="grid gap-2">
                    <p className="text-pretty text-[var(--muted)]">{safeDisplay(stage.detail)}</p>
                    {stage.safetyNotes && stage.safetyNotes.length > 0 ? (
                      <ul className="flex flex-wrap gap-1.5">
                        {stage.safetyNotes.map((note) => (
                          <li
                            key={`${summary.runId}-${stage.label}-${note}`}
                            className="rounded-sm border border-[var(--line)] px-2 py-0.5 text-xs font-semibold text-[var(--muted)]"
                          >
                            {formatLabel(note)}
                          </li>
                        ))}
                      </ul>
                    ) : null}
                    {stage.lessonTraces && stage.lessonTraces.length > 0 ? (
                      <ul className="grid gap-2 border-t border-[var(--line)] pt-2">
                        {stage.lessonTraces.map((trace) => (
                          <li
                            key={`${summary.runId}-${stage.label}-${trace.lessonId}`}
                            className="grid gap-1 text-xs text-[var(--muted)]"
                          >
                            <p className="break-words font-semibold text-[var(--foreground)]">
                              {formatLabel(trace.action)} lesson: {formatLabel(trace.recommendation)}
                            </p>
                            <p className="break-words">
                              {safeDisplay(trace.playbook)} on {safeDisplay(trace.surface)} from{" "}
                              {trace.sourceSignalCount} learning signal(s)
                            </p>
                            {trace.reasons.length > 0 ? (
                              <ul className="flex flex-wrap gap-1.5">
                                {trace.reasons.map((reason) => (
                                  <li
                                    key={`${trace.lessonId}-${reason}`}
                                    className="rounded-sm border border-[var(--line)] px-2 py-0.5 font-semibold"
                                  >
                                    {formatLabel(reason)}
                                  </li>
                                ))}
                              </ul>
                            ) : null}
                          </li>
                        ))}
                      </ul>
                    ) : null}
                  </div>
                  <p className="tabular-nums text-[var(--muted)]">{stage.evidenceCount} ev</p>
                </li>
              ))}
            </ol>
          </section>
        </section>

        <aside className="grid content-start gap-5">
          <section className="border border-[var(--line)] bg-white">
            <SectionHeader icon={ClipboardCheck} title="Closed Loop" />
            <div className="grid gap-4 p-5 text-sm">
              <p className="font-semibold text-[var(--accent-strong)]">
                {formatLabel(closedLoop?.status ?? "not_started")}
              </p>
              <dl className="grid grid-cols-2 gap-3">
                <Field label="Observations" value={closedLoop?.manual_observation_count ?? 0} />
                <Field label="Reviews" value={closedLoop?.reviewed_claim_count ?? 0} />
                <Field label="Candidates" value={closedLoop?.finding_candidate_count ?? 0} />
                <Field label="Learning" value={closedLoop?.learning_signal_count ?? 0} />
              </dl>
              {closedLoopSteps.length > 0 ? (
                <ol className="grid gap-3 border-t border-[var(--line)] pt-4">
                  {closedLoopSteps.map((step) => (
                    <li
                      key={step.key}
                      className="grid gap-2 border-l-2 border-[var(--line)] pl-3"
                    >
                      <div className="flex items-start justify-between gap-3">
                        <p className="font-semibold">{safeDisplay(step.label)}</p>
                        <span
                          className={`shrink-0 text-xs font-semibold uppercase ${closedLoopStepClass(
                            step.status,
                          )}`}
                        >
                          {formatLabel(step.status)}
                        </span>
                      </div>
                      <p className="text-pretty text-[var(--muted)]">
                        {safeDisplay(step.reason)}
                      </p>
                      <dl className="grid gap-2 border-t border-[var(--line)] pt-2">
                        <Field label="Gate" value={step.safety_gate} />
                        <Field label="Next" value={step.next_allowed_action} />
                      </dl>
                    </li>
                  ))}
                </ol>
              ) : null}
              {closedLoopSafetyNotes.length > 0 ? (
                <ul className="flex flex-wrap gap-1.5">
                  {closedLoopSafetyNotes.map((note) => (
                    <li
                      key={`closed-loop-note-${note}`}
                      className="rounded-sm border border-[var(--line)] px-2 py-0.5 text-xs font-semibold text-[var(--muted)]"
                    >
                      {formatLabel(note)}
                    </li>
                  ))}
                </ul>
              ) : null}
              {closedLoopBlockedReasons.length > 0 ? (
                <div className="border-t border-[var(--line)] pt-3">
                  <p className="font-semibold">Blocked</p>
                  <ul className="mt-2 grid gap-1 text-[var(--muted)]">
                    {closedLoopBlockedReasons.map((reason) => (
                      <li key={`closed-loop-blocked-${reason}`}>{formatLabel(reason)}</li>
                    ))}
                  </ul>
                </div>
              ) : null}
            </div>
          </section>

          <section className="border border-[var(--line)] bg-white">
            <SectionHeader icon={ShieldCheck} title="Validation Gate" />
            <div className="grid gap-3 p-5 text-sm">
              <p className="font-semibold">{safeDisplay(summary.validationGate.label)}</p>
              <p className="text-pretty text-[var(--muted)]">
                {safeDisplay(summary.validationGate.approval)}
              </p>
              <p className="font-semibold tabular-nums text-[var(--muted)]">
                {summary.validationGate.evidenceCount} evidence item(s)
              </p>
            </div>
          </section>

          <section className="border border-[var(--line)] bg-white">
            <SectionHeader icon={Target} title="Hunter Priority" />
            <div className="grid gap-3 p-5 text-sm">
              <div className="flex items-start justify-between gap-4">
                <p className="font-semibold">{safeDisplay(summary.hunter.playbook)}</p>
                <p className="text-2xl font-semibold tabular-nums">
                  {summary.hunter.priorityScore}
                </p>
              </div>
              <p className="font-semibold text-[var(--accent-strong)]">
                {formatLabel(summary.hunter.recommendation)}
              </p>
              <p className="text-pretty text-[var(--muted)]">
                {safeDisplay(hunterAssessment?.next_action ?? summary.hunter.nextAction)}
              </p>
              {hunterReasons.length > 0 ? (
                <ul className="flex flex-wrap gap-1.5">
                  {hunterReasons.map((reason) => (
                    <li
                      key={reason}
                      className="rounded-sm border border-[var(--line)] px-2 py-0.5 text-xs font-semibold text-[var(--muted)]"
                    >
                      {formatLabel(reason)}
                    </li>
                  ))}
                </ul>
              ) : null}
            </div>
          </section>

          <section className="border border-[var(--line)] bg-white">
            <SectionHeader icon={Database} title="Safe Payload Facts" />
            <dl className="grid gap-3 p-5 text-sm">
              <Field label="Artifact kind" value={payload?.artifact_kind ?? summary.artifact.kind} />
              <Field label="Target endpoints" value={targetModel?.endpoints?.length ?? 0} />
              <Field label="Objects" value={targetModel?.objects?.length ?? 0} />
              <Field label="Sensitive actions" value={targetModel?.sensitive_actions?.length ?? 0} />
              <Field label="Workspace" value={validationWorkspace?.status ?? "Unavailable"} />
              <Field label="Report review" value={reportDraft?.human_review_required ? "Required" : "Unavailable"} />
            </dl>
          </section>

          {refutationReasons.length > 0 ? (
            <section className="border border-[var(--line)] bg-white">
              <SectionHeader icon={ClipboardCheck} title="Blocked Reasons" />
              <ul className="grid gap-2 p-5 text-sm text-[var(--muted)]">
                {refutationReasons.map((reason) => (
                  <li key={reason}>{formatLabel(reason)}</li>
                ))}
              </ul>
            </section>
          ) : null}
        </aside>
      </div>
    </main>
  );
}

function closedLoopStepClass(status: string): string {
  switch (status) {
    case "complete":
      return "text-[var(--accent-strong)]";
    case "blocked":
      return "text-[var(--danger)]";
    default:
      return "text-[var(--warning)]";
  }
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
  icon: typeof Database;
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

function SectionHeader({ icon: Icon, title }: { icon: typeof Database; title: string }) {
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
