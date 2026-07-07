import { revalidatePath } from "next/cache";
import { AlertTriangle, ArrowLeft, ClipboardCheck, Gauge, ShieldCheck } from "lucide-react";
import type { LucideIcon } from "lucide-react";
import Link from "next/link";
import { getCampaignControlCenter, materializeResearchQueueTask } from "@/lib/api";
import { toCampaignControlSummary } from "@/lib/campaigns-data";

type PageProps = {
  params: Promise<{ campaignId: string }>;
};

export default async function CampaignDetailPage({ params }: PageProps) {
  const { campaignId } = await params;
  const controlCenter = await getCampaignControlCenter(campaignId, null);

  if (!controlCenter) {
    return (
      <main className="min-h-screen px-5 py-6 sm:px-8 lg:px-10">
        <PageBack />
        <section className="mt-6 border border-[var(--line)] bg-white p-6">
          <p className="flex items-center gap-2 text-sm font-semibold text-[var(--warning)]">
            <AlertTriangle size={17} aria-hidden="true" />
            Campaign control unavailable
          </p>
          <h1 className="mt-3 break-words text-3xl font-semibold text-balance">{campaignId}</h1>
          <p className="mt-2 max-w-2xl text-pretty text-[var(--muted)]">
            No audited control summary was returned for this campaign.
          </p>
        </section>
      </main>
    );
  }

  const summary = toCampaignControlSummary(controlCenter);
  const runtimeGateState = summary.executionAllowed ? "Scope Guard reviewed" : "Scope Guard blocked";
  const safeNextAction = summary.safeNextAction;

  async function queueResearchReviewAction(formData: FormData) {
    "use server";

    const queueKey = formData.get("queue_key");
    if (typeof queueKey !== "string" || queueKey.trim() === "") {
      return;
    }

    await materializeResearchQueueTask(
      campaignId,
      {
        queue_key: queueKey,
        requester: "operator",
        reason: "Queue review item from control center.",
      },
      {
        agent_type: "human_research_reviewer",
        campaign_id: campaignId,
        created_at: "",
        id: "fallback_research_queue_review",
        input_refs: [],
        output_refs: [],
        status: "fallback",
        task_type: "research_queue_review",
        title: "Research review item",
      },
    );
    revalidatePath(`/campaigns/${encodeURIComponent(campaignId)}`);
    revalidatePath(`/campaigns/${encodeURIComponent(campaignId)}/tasks`);
    revalidatePath(`/campaigns/${encodeURIComponent(campaignId)}/timeline`);
  }

  return (
    <main className="min-h-screen px-5 py-6 sm:px-8 lg:px-10">
      <PageBack />

      <header className="mt-6 border-b border-[var(--line)] pb-6">
        <p className="flex items-center gap-2 text-sm font-semibold text-[var(--accent-strong)]">
          <ShieldCheck size={17} aria-hidden="true" />
          {summary.campaignId}
          <span className="rounded-sm border border-[var(--line)] px-2 py-0.5 text-xs font-semibold uppercase text-[var(--muted)]">
            Read only
          </span>
        </p>
        <div className="mt-3 grid gap-3 lg:grid-cols-[minmax(0,1fr)_320px] lg:items-end">
          <div>
            <h1 className="max-w-4xl text-3xl font-semibold leading-tight text-balance">
              {summary.name}
            </h1>
            <p className="mt-2 break-words text-pretty text-[var(--muted)]">
              {summary.defaultAsset}
            </p>
            <nav className="mt-4 flex flex-wrap gap-2">
              <AuditLink href={`/campaigns/${encodeURIComponent(campaignId)}/tasks`} label="Research Review" />
              <AuditLink href={`/campaigns/${encodeURIComponent(campaignId)}/agent-runs`} label="Agent Audit" />
              <AuditLink
                href={`/campaigns/${encodeURIComponent(campaignId)}/attack-surface-map`}
                label="Attack Surface Map"
              />
              <AuditLink
                href={`/campaigns/${encodeURIComponent(campaignId)}/codebase-map`}
                label="Code Review Map"
              />
              <AuditLink
                href={`/campaigns/${encodeURIComponent(campaignId)}/artifacts`}
                label="Artifact Review"
              />
              <AuditLink
                href={`/campaigns/${encodeURIComponent(campaignId)}/validation-queue`}
                label="Review Gate"
              />
              <AuditLink
                href={`/campaigns/${encodeURIComponent(campaignId)}/validation-runs`}
                label="Validation Audit"
              />
              <AuditLink
                href={`/campaigns/${encodeURIComponent(campaignId)}/hypothesis-board`}
                label="Hypothesis Board"
              />
              <AuditLink
                href={`/campaigns/${encodeURIComponent(campaignId)}/evidence-review`}
                label="Evidence Review"
              />
              <AuditLink
                href={`/campaigns/${encodeURIComponent(campaignId)}/report-drafts`}
                label="Report Readiness"
              />
              <AuditLink href={`/campaigns/${encodeURIComponent(campaignId)}/timeline`} label="Review Timeline" />
              <AuditLink href={`/campaigns/${encodeURIComponent(campaignId)}/brain`} label="Mythos Brain" />
            </nav>
          </div>
          <div className="border border-[var(--line)] bg-white p-4">
            <p className="text-xs font-semibold uppercase text-[var(--muted)]">Safe next action</p>
            {summary.safeNextHref ? (
              <Link
                href={summary.safeNextHref}
                className="mt-2 inline-flex min-h-10 items-center gap-2 rounded-md border border-[var(--line)] px-3 text-sm font-semibold text-[var(--accent-strong)]"
              >
                <ClipboardCheck size={17} aria-hidden="true" />
                {safeNextAction}
              </Link>
            ) : (
              <p className="mt-2 font-semibold text-[var(--accent-strong)]">{safeNextAction}</p>
            )}
            {summary.blockedReasons.length > 0 ? (
              <div className="mt-3 border-t border-[var(--line)] pt-3">
                <p className="text-xs font-semibold uppercase text-[var(--muted)]">Review requirements</p>
                <ul className="mt-2 grid gap-1 text-xs leading-5 text-[var(--muted)]">
                  {summary.blockedReasons.map((reason) => (
                    <li key={reason}>{reason}</li>
                  ))}
                </ul>
              </div>
            ) : null}
            {summary.promotionReviewBlockedCount > 0 || summary.promotionReviewLatestReason ? (
              <div className="mt-3 border-t border-[var(--line)] pt-3">
                <p className="text-xs font-semibold uppercase text-[var(--muted)]">Promotion review</p>
                <dl className="mt-2 grid grid-cols-2 gap-2 text-xs">
                  <Field label="Blocked attempts" value={summary.promotionReviewBlockedCount} />
                  <Field label="Provenance refs" value={summary.promotionReviewProvenanceRefCount} />
                </dl>
                {summary.promotionReviewLatestReason ? (
                  <p className="mt-2 break-words text-xs leading-5 text-[var(--muted)]">
                    {summary.promotionReviewLatestReason}
                  </p>
                ) : null}
                <p className="mt-2 break-words text-xs leading-5 text-[var(--muted)]">
                  {summary.promotionReviewNextAllowedAction}
                </p>
              </div>
            ) : null}
            <dl className="mt-3 grid grid-cols-3 gap-2 border-t border-[var(--line)] pt-3 text-xs">
              <Field label="Validation audits" value={summary.validationRunCount} />
              <Field label="Evidence" value={summary.validationEvidenceCount} />
              <Field label="Gaps" value={summary.validationEvidenceGapCount} />
            </dl>
            <div className="mt-3 border-t border-[var(--line)] pt-3">
              <p className="text-xs font-semibold uppercase text-[var(--muted)]">
                Cycle reviews
              </p>
              <dl className="mt-2 grid grid-cols-2 gap-2 text-xs">
                <Field label="Awaiting review" value={summary.cycleReviewAwaitingCount} />
                <Field label="Completed" value={summary.cycleReviewCompletedCount} />
              </dl>
              {summary.cycleReviewAwaitingCount > 0 ? (
                <p className="mt-2 text-xs leading-5 text-[var(--muted)]">
                  Human review gate. Timeline review explains the loop state without starting
                  validation.
                </p>
              ) : null}
            </div>
          </div>
        </div>
      </header>

      <section className="border-b border-[var(--line)] py-5">
        <div className="mb-3 flex flex-wrap items-end justify-between gap-2">
          <div>
            <p className="text-sm font-semibold">Control readiness</p>
            <p className="mt-1 text-sm text-[var(--muted)]">
              Review only checkpoints for the campaign loop. These links cannot start validation.
            </p>
          </div>
          <span className="text-xs font-semibold uppercase text-[var(--muted)]">
            Audited navigation
          </span>
        </div>
        <div className="grid gap-2 sm:grid-cols-2 xl:grid-cols-4">
          <ReadinessLink
            href={`/campaigns/${encodeURIComponent(campaignId)}/artifacts`}
            label="Artifact review"
            value="Review"
          />
          <ReadinessLink
            href={`/campaigns/${encodeURIComponent(campaignId)}/validation-queue`}
            label="Review gate"
            value={summary.pendingApprovalCount}
          />
          <ReadinessLink
            href={`/campaigns/${encodeURIComponent(campaignId)}/validation-runs`}
            label="Validation audit"
            value={summary.validationRunCount}
          />
          <ReadinessLink
            href={`/campaigns/${encodeURIComponent(campaignId)}/evidence-review`}
            label="Evidence review"
            value={summary.validationEvidenceGapCount}
          />
          <ReadinessLink
            href={`/campaigns/${encodeURIComponent(campaignId)}/report-drafts`}
            label="Report readiness"
            value="Review"
          />
          <ReadinessLink
            href={`/campaigns/${encodeURIComponent(campaignId)}/tasks`}
            label="Review items"
            value={summary.taskCount}
          />
          <ReadinessLink
            href={`/campaigns/${encodeURIComponent(campaignId)}/brain`}
            label="Learning review"
            value="Review"
          />
          <ReadinessLink
            href={`/campaigns/${encodeURIComponent(campaignId)}/timeline`}
            label="Cycle review"
            value={summary.cycleReviewAwaitingCount}
          />
          <ReadinessLink
            href={`/campaigns/${encodeURIComponent(campaignId)}/timeline`}
            label="Review holds"
            value={summary.blockedStageCount}
          />
        </div>
      </section>

      {summary.researchQueueSuggestions.length > 0 ? (
        <section className="border-b border-[var(--line)] py-5">
          <div className="mb-3 flex flex-wrap items-end justify-between gap-2">
            <div>
              <p className="text-sm font-semibold">Research Memory Review</p>
              <p className="mt-1 text-sm text-[var(--muted)]">
                Advisory reasoning-memory suggestions for human review. They stay advisory only.
              </p>
            </div>
            <span className="text-xs font-semibold uppercase text-[var(--muted)]">
              Mythos brain
            </span>
          </div>
          <div className="grid gap-3 lg:grid-cols-2">
            {summary.researchQueueSuggestions.map((suggestion) => (
              <article
                key={suggestion.queueKey}
                className="grid gap-3 border border-[var(--line)] bg-white p-4 text-sm"
              >
                <div className="flex items-start justify-between gap-3">
                  <div>
                    <p className="font-semibold">{suggestion.title}</p>
                    <p className="mt-1 text-[var(--muted)]">{suggestion.source}</p>
                  </div>
                  <span className="text-2xl font-semibold tabular-nums text-[var(--accent-strong)]">
                    {suggestion.priorityScore}
                  </span>
                </div>
                <dl className="grid gap-2 sm:grid-cols-2">
                  <Field label="Playbook" value={suggestion.playbookId} />
                  <Field label="Surface" value={suggestion.surfaceKey ?? "No surface"} />
                  <Field label="Review gate" value={suggestion.safetyGate} />
                  <Field label="Action gate" value="Review only" />
                  <Field
                    label="Candidate"
                    value={suggestion.candidateStatus ?? "Memory review"}
                  />
                  <Field
                    label="Human gate"
                    value={suggestion.humanApprovalRequired ? "Human review required" : "Review only"}
                  />
                  <Field
                    label="Refutation questions"
                    value={String(suggestion.refutationQuestionCount)}
                  />
                  <Field
                    label="Validation steps"
                    value={String(suggestion.validationStepCount)}
                  />
                  <Field
                    label="Blocked actions"
                    value={String(suggestion.blockedActionCount)}
                  />
                </dl>
                <p className="text-pretty text-[var(--muted)]">
                  {suggestion.nextAllowedAction}
                </p>
                <form action={queueResearchReviewAction}>
                  <input type="hidden" name="queue_key" value={suggestion.queueKey} />
                  <button
                    type="submit"
                    className="inline-flex min-h-10 items-center rounded-md border border-[var(--line)] px-3 text-sm font-semibold text-[var(--accent-strong)]"
                  >
                    Queue review item
                  </button>
                </form>
              </article>
            ))}
          </div>
        </section>
      ) : null}

      <section className="grid gap-3 py-5 sm:grid-cols-2 xl:grid-cols-4">
        <Metric label="Status" value={summary.status} />
        <Metric label="Scope" value={summary.scopeStatus} />
        <Metric label="Review items" value={summary.taskCount} />
        <Metric label="Agent audits" value={summary.agentRunCount} />
        <Metric label="Pending review gates" value={summary.pendingApprovalCount} />
        <Metric label="Review holds" value={summary.blockedStageCount} />
        <Metric label="Validation evidence" value={summary.validationEvidenceCount} />
        <Metric label="Evidence gaps" value={summary.validationEvidenceGapCount} />
      </section>

      <div className="grid gap-5 xl:grid-cols-[minmax(0,1fr)_360px]">
        <section className="border border-[var(--line)] bg-white">
          <SectionHeader icon={Gauge} title="Budget And Gates" />
          <dl className="grid gap-4 p-5 text-sm sm:grid-cols-2">
            <Field label="Budget" value={summary.budgetLabel} />
            <Field label="Runtime gate" value={runtimeGateState} />
            <Field label="Campaign status" value={summary.status} />
            <Field label="Scope status" value={summary.scopeStatus} />
          </dl>
        </section>

        <aside className="grid content-start gap-5">
          <section className="border border-[var(--line)] bg-white">
            <SectionHeader icon={ClipboardCheck} title="Review requirements" />
            {summary.blockedReasons.length > 0 ? (
              <ul className="grid gap-2 p-5 text-sm text-[var(--muted)]">
                {summary.blockedReasons.map((reason) => (
                  <li key={reason}>{reason}</li>
                ))}
              </ul>
            ) : (
              <p className="p-5 text-sm text-[var(--muted)]">No active review requirements.</p>
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
      href="/campaigns"
      className="inline-flex min-h-10 items-center gap-2 rounded-md border border-[var(--line)] bg-white px-3 text-sm font-semibold"
    >
      <ArrowLeft size={17} aria-hidden="true" />
      Campaigns
    </Link>
  );
}

function AuditLink({ href, label }: { href: string; label: string }) {
  return (
    <Link
      href={href}
      className="inline-flex min-h-10 items-center gap-2 rounded-md border border-[var(--line)] bg-white px-3 text-sm font-semibold"
    >
      <ClipboardCheck size={17} aria-hidden="true" />
      {label}
    </Link>
  );
}

function ReadinessLink({ href, label, value }: { href: string; label: string; value: React.ReactNode }) {
  return (
    <Link
      href={href}
      className="grid min-h-20 gap-2 border border-[var(--line)] bg-white p-3 text-sm"
    >
      <span className="font-semibold">{label}</span>
      <span className="text-2xl font-semibold tabular-nums text-[var(--accent-strong)]">{value}</span>
    </Link>
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

function SectionHeader({ icon: Icon, title }: { icon: LucideIcon; title: string }) {
  return (
    <div className="flex items-center justify-between border-b border-[var(--line)] px-5 py-4">
      <h2 className="text-lg font-semibold">{title}</h2>
      <Icon size={19} className="text-[var(--accent)]" aria-hidden="true" />
    </div>
  );
}

function Field({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div className="grid gap-1">
      <dt className="text-xs font-semibold uppercase text-[var(--muted)]">{label}</dt>
      <dd className="break-words font-semibold">{value}</dd>
    </div>
  );
}
