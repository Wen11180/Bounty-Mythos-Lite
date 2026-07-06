import { AlertTriangle, ArrowLeft, ClipboardCheck, ShieldCheck } from "lucide-react";
import Link from "next/link";
import { getCampaignResearchTaskReview } from "@/lib/api";
import { toCampaignResearchTaskReviewSummary } from "@/lib/campaigns-data";

type PageProps = {
  params: Promise<{ campaignId: string; taskId: string }>;
};

export default async function CampaignResearchTaskReviewPage({ params }: PageProps) {
  const { campaignId, taskId } = await params;
  const review = await getCampaignResearchTaskReview(campaignId, taskId, null);

  if (!review) {
    return (
      <main className="min-h-screen px-5 py-6 sm:px-8 lg:px-10">
        <PageBack campaignId={campaignId} />
        <section className="mt-6 border border-[var(--line)] bg-white p-6">
          <p className="flex items-center gap-2 text-sm font-semibold text-[var(--warning)]">
            <AlertTriangle size={17} aria-hidden="true" />
            Research task review unavailable
          </p>
          <h1 className="mt-3 break-words text-3xl font-semibold text-balance">{taskId}</h1>
          <p className="mt-2 max-w-2xl text-pretty text-[var(--muted)]">
            No audited research review workspace was returned for this task.
          </p>
        </section>
      </main>
    );
  }

  const summary = toCampaignResearchTaskReviewSummary(review);

  return (
    <main className="min-h-screen px-5 py-6 sm:px-8 lg:px-10">
      <PageBack campaignId={campaignId} />

      <header className="mt-6 border-b border-[var(--line)] pb-6">
        <p className="flex items-center gap-2 text-sm font-semibold text-[var(--accent-strong)]">
          <ClipboardCheck size={17} aria-hidden="true" />
          Research Review
          <span className="rounded-sm border border-[var(--line)] px-2 py-0.5 text-xs font-semibold uppercase text-[var(--muted)]">
            Read only
          </span>
        </p>
        <h1 className="mt-3 max-w-4xl break-words text-3xl font-semibold leading-tight text-balance">
          {summary.title}
        </h1>
        <p className="mt-2 max-w-2xl text-pretty text-[var(--muted)]">
          Advisory workspace for planning non-destructive evidence work. It is review-only and
          cannot approve validation, agent work, or report submission.
        </p>
      </header>

      <section className="grid gap-3 py-5 sm:grid-cols-2 xl:grid-cols-4">
        <Metric label="Priority" value={summary.priorityScore} />
        <Metric label="Status" value={summary.status} />
        <Metric label="Task review gate" value={summary.safetyGate} />
        <Metric label="Action gate" value="Review only" />
      </section>

      <div className="grid gap-5 xl:grid-cols-[minmax(0,1fr)_360px]">
        <section className="grid gap-5">
          {summary.latestReviewPlan ? (
            <article className="border border-[var(--line)] bg-white">
              <SectionHeader title="Latest Review Plan" />
              <div className="grid gap-5 p-5 text-sm">
                <Field label="Plan" value={summary.latestReviewPlan.planId} />
                <Field label="Status" value={summary.latestReviewPlan.status} />
                <Field label="Review gate" value={summary.latestReviewPlan.safetyGate} />
                <Field label="Hypothesis" value={summary.latestReviewPlan.hypothesis} />
                <ListBlock
                  items={summary.latestReviewPlan.refutationQuestions}
                  title="Refutation Questions"
                />
                <ListBlock items={summary.latestReviewPlan.evidencePlan} title="Evidence Plan" />
              </div>
            </article>
          ) : null}

          {summary.latestRefutationDecision ? (
            <article className="border border-[var(--line)] bg-white">
              <SectionHeader title="Latest Refutation Decision" />
              <div className="grid gap-5 p-5 text-sm">
                <Field label="Decision" value={summary.latestRefutationDecision.decision} />
                <Field label="Plan" value={summary.latestRefutationDecision.planId} />
                <Field
                  label="Approval"
                  value={summary.latestRefutationDecision.approvalId ?? "No approval request"}
                />
                <Field
                  label="Validation audit"
                  value={summary.latestRefutationDecision.validationRunId ?? "No validation audit"}
                />
                <Field label="Next action" value={summary.latestRefutationDecision.nextAllowedAction} />
                <Field label="Rationale" value={summary.latestRefutationDecision.rationale} />
                <ListBlock
                  items={summary.latestRefutationDecision.refutationAnswers}
                  title="Refutation Answers"
                />
              </div>
            </article>
          ) : null}

          {summary.latestValidationFeedback ? (
            <article className="border border-[var(--line)] bg-white">
              <SectionHeader title="Latest Validation Feedback" />
              <div className="grid gap-5 p-5 text-sm">
                <Field label="Status" value={summary.latestValidationFeedback.status} />
                <Field label="Outcome" value={summary.latestValidationFeedback.outcome} />
                <Field label="Plan" value={summary.latestValidationFeedback.planId} />
                <Field label="Approval" value={summary.latestValidationFeedback.approvalId} />
                <Field
                  label="Validation audit"
                  value={summary.latestValidationFeedback.validationRunId}
                />
                <Field
                  label="Evidence refs"
                  value={String(summary.latestValidationFeedback.evidenceRefCount)}
                />
                <Field label="Review gate" value={summary.latestValidationFeedback.safetyGate} />
                <Field label="Next action" value={summary.latestValidationFeedback.nextAllowedAction} />
                <Field
                  label="Finding confirmation"
                  value={
                    summary.latestValidationFeedback.findingConfirmationAllowed
                      ? "Human review required"
                      : "Confirmation blocked"
                  }
                />
              </div>
            </article>
          ) : null}

          <article className="border border-[var(--line)] bg-white">
            <SectionHeader title="Non-Destructive Plan" />
            <ol className="grid gap-3 p-5 text-sm text-[var(--muted)]">
              {summary.nonDestructivePlan.map((step, index) => (
                <li key={`${index}-${step}`} className="grid grid-cols-[32px_minmax(0,1fr)] gap-3">
                  <span className="font-semibold tabular-nums text-[var(--accent-strong)]">
                    {index + 1}
                  </span>
                  <span className="break-words">{step}</span>
                </li>
              ))}
            </ol>
          </article>
        </section>

        <aside className="grid content-start gap-5">
          <section className="border border-[var(--line)] bg-white">
            <SectionHeader title="Review Context" />
            <dl className="grid gap-3 p-5 text-sm">
              <Field label="Task" value={summary.taskId} />
              <Field label="Reasoning memory key" value={summary.queueKey} />
              <Field label="Source" value={summary.source} />
              <Field label="Playbook" value={summary.playbookId ?? "No playbook"} />
              <Field label="Surface" value={summary.surfaceKey ?? "No surface"} />
              <Field label="Next action" value={summary.nextAllowedAction} />
            </dl>
          </section>

          <section className="border border-[var(--line)] bg-white">
            <SectionHeader title="Required Human Gates" />
            <ul className="grid gap-2 p-5 text-sm text-[var(--muted)]">
              {summary.requiredHumanGates.map((gate) => (
                <li key={gate} className="flex items-start gap-2">
                  <ShieldCheck size={16} className="mt-0.5 text-[var(--accent)]" aria-hidden="true" />
                  <span className="break-words">{gate}</span>
                </li>
              ))}
            </ul>
          </section>
        </aside>
      </div>
    </main>
  );
}

function PageBack({ campaignId }: { campaignId: string }) {
  return (
    <Link
      href={`/campaigns/${encodeURIComponent(campaignId)}/tasks`}
      className="inline-flex min-h-10 items-center gap-2 rounded-md border border-[var(--line)] bg-white px-3 text-sm font-semibold"
    >
      <ArrowLeft size={17} aria-hidden="true" />
      Research Review
    </Link>
  );
}

function SectionHeader({ title }: { title: string }) {
  return (
    <div className="flex items-center justify-between border-b border-[var(--line)] px-5 py-4">
      <h2 className="text-lg font-semibold">{title}</h2>
      <ShieldCheck size={19} className="text-[var(--accent)]" aria-hidden="true" />
    </div>
  );
}

function Metric({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div className="border border-[var(--line)] bg-white p-4">
      <p className="text-sm text-[var(--muted)]">{label}</p>
      <p className="mt-3 break-words text-2xl font-semibold tabular-nums">{value}</p>
    </div>
  );
}

function Field({ label, value }: { label: string; value: string }) {
  return (
    <div className="grid gap-1">
      <dt className="text-xs font-semibold uppercase text-[var(--muted)]">{label}</dt>
      <dd className="break-words font-semibold">{value}</dd>
    </div>
  );
}

function ListBlock({ items, title }: { items: string[]; title: string }) {
  return (
    <div className="grid gap-2">
      <p className="text-xs font-semibold uppercase text-[var(--muted)]">{title}</p>
      <ul className="grid gap-2 text-[var(--muted)]">
        {items.map((item) => (
          <li key={item} className="break-words">
            {item}
          </li>
        ))}
      </ul>
    </div>
  );
}
