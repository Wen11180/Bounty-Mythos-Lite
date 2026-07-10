import { revalidatePath } from "next/cache";
import { AlertTriangle, ArrowLeft, ClipboardCheck, ShieldCheck } from "lucide-react";
import Link from "next/link";
import {
  createResearchRefutationDecision,
  createResearchReviewPlan,
  getCampaignResearchTaskReview,
} from "@/lib/api";
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
            Research review item unavailable
          </p>
          <h1 className="mt-3 break-words text-3xl font-semibold text-balance">{taskId}</h1>
          <p className="mt-2 max-w-2xl text-pretty text-[var(--muted)]">
            No audited research review workspace was returned for this review item.
          </p>
        </section>
      </main>
    );
  }

  const summary = toCampaignResearchTaskReviewSummary(review);
  const reviewHypothesis = summary.autonomousCandidateContext?.hypothesis ?? summary.title;
  const reviewRefutationQuestions =
    summary.autonomousCandidateContext?.refutationQuestions.length
      ? summary.autonomousCandidateContext.refutationQuestions
      : ["Can existing redacted artifacts refute this research candidate?"];
  const reviewEvidencePlan = summary.nonDestructivePlan.length
    ? summary.nonDestructivePlan.slice(0, 5)
    : ["Collect only redacted artifact summaries and provenance counts."];
  const candidateContextSummary = summary.autonomousCandidateContext
    ? {
        evidence_focus_count: summary.autonomousCandidateContext.evidenceFocus.length,
        has_authorization_gap_candidate: hasAuthorizationGapCandidate([
          ...summary.autonomousCandidateContext.sourceFactTypes,
          ...summary.autonomousCandidateContext.triageSignals,
        ]),
        source_fact_type_count: summary.autonomousCandidateContext.sourceFactTypes.length,
        triage_signal_count: summary.autonomousCandidateContext.triageSignals.length,
      }
    : null;

  async function createReviewPlanAction() {
    "use server";

    await createResearchReviewPlan(
      campaignId,
      taskId,
      {
        evidence_plan: reviewEvidencePlan,
        hypothesis: reviewHypothesis,
        rationale: "Drafted from redacted research review context.",
        refutation_questions: reviewRefutationQuestions,
        reviewer: "operator",
      },
      {
        campaign_id: campaignId,
        dispatch_allowed: false,
        evidence_plan: [],
        execution_allowed: false,
        hypothesis: reviewHypothesis,
        next_allowed_action: "Review hypothesis board and request review before validation.",
        plan_id: "fallback_research_plan",
        refutation_questions: [],
        report_submission_allowed: false,
        required_human_gates: [],
        safety_gate: "advisory_plan_only",
        status: "fallback",
        task_id: taskId,
        validation_allowed: false,
      },
    );
    revalidatePath(`/campaigns/${encodeURIComponent(campaignId)}`);
    revalidatePath(`/campaigns/${encodeURIComponent(campaignId)}/tasks`);
    revalidatePath(`/campaigns/${encodeURIComponent(campaignId)}/tasks/${encodeURIComponent(taskId)}`);
    revalidatePath(`/campaigns/${encodeURIComponent(campaignId)}/hypothesis-board`);
    revalidatePath(`/campaigns/${encodeURIComponent(campaignId)}/timeline`);
  }

  async function recordNeedsEvidenceDecisionAction() {
    "use server";

    if (!summary.latestReviewPlan) {
      return;
    }

    await createResearchRefutationDecision(
      campaignId,
      taskId,
      {
        candidate_context_summary: candidateContextSummary,
        decision: "needs_evidence",
        plan_id: summary.latestReviewPlan.planId,
        rationale: "Needs more redacted evidence before validation.",
        refutation_answers: [
          "Current redacted evidence is insufficient for validation review.",
        ],
        reviewer: "operator",
      },
      {
        campaign_id: campaignId,
        decision: "needs_evidence",
        decision_id: "fallback_refutation_decision",
        dispatch_allowed: false,
        execution_allowed: false,
        next_allowed_action: "Collect redacted evidence or refine the hypothesis before validation.",
        plan_id: summary.latestReviewPlan.planId,
        rationale: "Needs more redacted evidence before validation.",
        refutation_answers: [],
        report_submission_allowed: false,
        task_id: taskId,
        validation_allowed: false,
        validation_run_id: null,
      },
    );
    revalidatePath(`/campaigns/${encodeURIComponent(campaignId)}`);
    revalidatePath(`/campaigns/${encodeURIComponent(campaignId)}/tasks`);
    revalidatePath(`/campaigns/${encodeURIComponent(campaignId)}/tasks/${encodeURIComponent(taskId)}`);
    revalidatePath(`/campaigns/${encodeURIComponent(campaignId)}/timeline`);
  }

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
          cannot start validation, agent work, or report submission.
        </p>
      </header>

      <section className="grid gap-3 py-5 sm:grid-cols-2 xl:grid-cols-4">
        <Metric label="Priority" value={summary.priorityScore} />
        <Metric label="Status" value={summary.status} />
        <Metric label="Review gate" value={summary.safetyGate} />
        <Metric label="Action gate" value="Review only" />
      </section>

      <div className="grid gap-5 xl:grid-cols-[minmax(0,1fr)_360px]">
        <section className="grid gap-5">
          {summary.autonomousCandidateContext ? (
            <article className="border border-[var(--line)] bg-white">
              <SectionHeader title="Autonomous Candidate Review" />
              <div className="grid gap-5 p-5 text-sm">
                <div className="grid gap-4 md:grid-cols-2">
                  <Field
                    label="Candidate"
                    value={summary.autonomousCandidateContext.candidateId}
                  />
                  <Field
                    label="Status"
                    value={summary.autonomousCandidateContext.candidateStatus}
                  />
                  <Field
                    label="Pipeline audit"
                    value={summary.autonomousCandidateContext.pipelineRunId}
                  />
                  {summary.autonomousCandidateContext.rawPriorityScore !== null ? (
                    <Field
                      label="Raw score"
                      value={String(summary.autonomousCandidateContext.rawPriorityScore)}
                    />
                  ) : null}
                  <Field
                    label="Refutation"
                    value={summary.autonomousCandidateContext.refutationStatus}
                  />
                  <Field
                    label="Validation plan"
                    value={summary.autonomousCandidateContext.validationPlanStatus}
                  />
                  <Field
                    label="Human review"
                    value={
                      summary.autonomousCandidateContext.humanApprovalRequired
                        ? "Manual review required"
                        : "Human review required"
                    }
                  />
                </div>
                <Field
                  label="Hypothesis"
                  value={summary.autonomousCandidateContext.hypothesis}
                />
                {summary.autonomousCandidateContext.qualityGateReasons.length > 0 ? (
                  <ListBlock
                    items={summary.autonomousCandidateContext.qualityGateReasons}
                    title="Candidate Quality Gate Reasons"
                  />
                ) : null}
                <ListBlock
                  items={summary.autonomousCandidateContext.refutationQuestions}
                  title="Candidate Refutation Questions"
                />
                <ListBlock
                  items={summary.autonomousCandidateContext.triageSignals}
                  title="Candidate Triage Signals"
                />
                <ListBlock
                  items={summary.autonomousCandidateContext.evidenceFocus}
                  title="Candidate Evidence Focus"
                />
                <ListBlock
                  items={summary.autonomousCandidateContext.requiredEvidence}
                  title="Candidate Required Evidence"
                />
                <ListBlock
                  items={summary.autonomousCandidateContext.sourceFactTypes}
                  title="Candidate Source Facts"
                />
                <ListBlock
                  items={summary.autonomousCandidateContext.validationSteps}
                  title="Candidate Validation Steps"
                />
                <ListBlock
                  items={summary.autonomousCandidateContext.blockedActions}
                  title="Blocked Actions"
                />
                <ListBlock
                  items={summary.autonomousCandidateContext.safetyNotes}
                  title="Safety Notes"
                />
              </div>
            </article>
          ) : null}

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

          {summary.latestReviewPlan ? (
            <article className="border border-[var(--line)] bg-white">
              <SectionHeader title="Record Needs Evidence" />
              <div className="grid gap-5 p-5 text-sm">
                <Field label="Plan" value={summary.latestReviewPlan.planId} />
                <Field
                  label="Decision"
                  value="Needs more redacted evidence before validation."
                />
                <form action={recordNeedsEvidenceDecisionAction}>
                  <button
                    type="submit"
                    className="inline-flex min-h-10 items-center rounded-md border border-[var(--line)] px-3 text-sm font-semibold text-[var(--accent-strong)]"
                  >
                    Record needs evidence
                  </button>
                </form>
              </div>
            </article>
          ) : null}

          {summary.suggestedRefutationDecision ? (
            <article className="border border-[var(--line)] bg-white">
              <SectionHeader title="Suggested Refutation Decision" />
              <div className="grid gap-5 p-5 text-sm">
                <div className="grid gap-4 md:grid-cols-2">
                  <Field
                    label="Decision"
                    value={summary.suggestedRefutationDecision.decision}
                  />
                  <Field
                    label="Plan"
                    value={summary.suggestedRefutationDecision.planId}
                  />
                  <Field
                    label="Refutation questions"
                    value={String(summary.suggestedRefutationDecision.refutationQuestionCount)}
                  />
                  <Field
                    label="Refutation answers"
                    value={String(summary.suggestedRefutationDecision.refutationAnswerCount)}
                  />
                  <Field
                    label="Validation mode"
                    value={summary.suggestedRefutationDecision.validationMode ?? "Validation review pending"}
                  />
                  <Field
                    label="Target"
                    value={summary.suggestedRefutationDecision.targetRef ?? "Campaign review required"}
                  />
                </div>
                <Field
                  label="Next review action"
                  value={summary.suggestedRefutationDecision.nextAllowedAction}
                />
                <Field
                  label="Rationale"
                  value={summary.suggestedRefutationDecision.rationale}
                />
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
                  label="Review gate record"
                  value={summary.latestRefutationDecision.approvalId ?? "No review gate"}
                />
                <Field
                  label="Validation audit"
                  value={summary.latestRefutationDecision.validationRunId ?? "No validation audit"}
                />
                <Field label="Next review action" value={summary.latestRefutationDecision.nextAllowedAction} />
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
                <Field label="Review gate record" value={summary.latestValidationFeedback.approvalId} />
                <Field label="Feedback stage" value={summary.latestValidationFeedback.feedbackStageId} />
                <Field
                  label="Validation audit"
                  value={summary.latestValidationFeedback.validationRunId}
                />
                <Field
                  label="Evidence refs"
                  value={String(summary.latestValidationFeedback.evidenceRefCount)}
                />
                <Field label="Review gate" value={summary.latestValidationFeedback.safetyGate} />
                <Field label="Next review action" value={summary.latestValidationFeedback.nextAllowedAction} />
                <Field
                  label="Finding confirmation"
                  value={
                    summary.latestValidationFeedback.findingConfirmationAllowed
                      ? "Human review required"
                      : "Confirmation blocked"
                  }
                />
                <Link
                  href={`/campaigns/${encodeURIComponent(campaignId)}/feedback-reviews/${encodeURIComponent(summary.latestValidationFeedback.feedbackStageId)}`}
                  className="inline-flex min-h-9 items-center justify-self-start rounded-md border border-[var(--line)] px-3 text-xs font-semibold text-[var(--accent-strong)]"
                >
                  Review promotion gate
                </Link>
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

          <article className="border border-[var(--line)] bg-white">
            <SectionHeader title="Draft Review Plan" />
            <div className="grid gap-5 p-5 text-sm">
              <Field label="Hypothesis" value={reviewHypothesis} />
              <ListBlock items={reviewRefutationQuestions} title="Refutation Questions" />
              <ListBlock items={reviewEvidencePlan} title="Evidence Plan" />
              <form action={createReviewPlanAction}>
                <button
                  type="submit"
                  className="inline-flex min-h-10 items-center rounded-md border border-[var(--line)] px-3 text-sm font-semibold text-[var(--accent-strong)]"
                >
                  Draft review plan
                </button>
              </form>
            </div>
          </article>
        </section>

        <aside className="grid content-start gap-5">
          <section className="border border-[var(--line)] bg-white">
            <SectionHeader title="Review Context" />
            <dl className="grid gap-3 p-5 text-sm">
              <Field label="Review item" value={summary.taskId} />
              <Field label="Reasoning memory key" value={summary.queueKey} />
              <Field label="Source" value={summary.source} />
              <Field label="Playbook" value={summary.playbookId ?? "No playbook"} />
              <Field label="Surface" value={summary.surfaceKey ?? "No surface"} />
              <Field label="Next review action" value={summary.nextAllowedAction} />
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

function hasAuthorizationGapCandidate(values: string[]) {
  return values.some((value) => {
    const normalized = value.toLowerCase();
    return (
      normalized.includes("authorization_gap") ||
      normalized.includes("authorization gap") ||
      normalized.includes("access_control_gap") ||
      normalized.includes("access control gap") ||
      normalized.includes("access-control gap")
    );
  });
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
