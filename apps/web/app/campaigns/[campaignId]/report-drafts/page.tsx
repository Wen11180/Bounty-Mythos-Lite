import { AlertTriangle, ArrowLeft, FileText, ShieldCheck } from "lucide-react";
import Link from "next/link";
import {
  getCampaignControlCenter,
  getCampaignPipelineStages,
  getCampaignResearchTaskReview,
  getCampaignTasks,
  getCampaignValidationRuns,
  getReportPreview,
} from "@/lib/api";
import {
  toCampaignFindingCandidateGateSummary,
  toCampaignReportDraftEvidenceSummary,
  toCampaignReportDraftSummaries,
  toCampaignResearchFeedbackEvidenceSummaries,
} from "@/lib/campaigns-data";

type PageProps = {
  params: Promise<{ campaignId: string }>;
};

export default async function CampaignReportDraftsPage({ params }: PageProps) {
  const { campaignId } = await params;
  const controlCenter = await getCampaignControlCenter(campaignId, null);
  const runIds = Array.from(
    new Set(
      controlCenter?.pipeline_stages
        .map((stage) => stage.pipeline_run_id)
        .filter((runId): runId is string => Boolean(runId)) ?? [],
    ),
  );
  const previews = (
    await Promise.all(runIds.map((runId) => getReportPreview(runId, null)))
  ).filter((preview): preview is NonNullable<typeof preview> => preview !== null);
  const validationRuns = await getCampaignValidationRuns(campaignId, []);
  const pipelineStages = await getCampaignPipelineStages(campaignId, []);
  const tasks = (await getCampaignTasks(campaignId, [])).filter(
    (task) => task.task_type === "research_queue_review",
  );
  const researchReviews = (
    await Promise.all(tasks.map((task) => getCampaignResearchTaskReview(campaignId, task.id, null)))
  ).filter((review): review is NonNullable<typeof review> => review !== null);
  const drafts = toCampaignReportDraftSummaries(previews);
  const researchFeedbackEvidence = toCampaignResearchFeedbackEvidenceSummaries(researchReviews);
  const findingCandidateGate = toCampaignFindingCandidateGateSummary(
    previews,
    researchFeedbackEvidence,
    pipelineStages,
  );
  const validationEvidence = toCampaignReportDraftEvidenceSummary(validationRuns);

  return (
    <main className="min-h-screen px-5 py-6 sm:px-8 lg:px-10">
      <PageBack campaignId={campaignId} />

      <header className="mt-6 border-b border-[var(--line)] pb-6">
        <p className="flex items-center gap-2 text-sm font-semibold text-[var(--accent-strong)]">
          <FileText size={17} aria-hidden="true" />
          Report Readiness
          <span className="rounded-sm border border-[var(--line)] px-2 py-0.5 text-xs font-semibold uppercase text-[var(--muted)]">
            Read only
          </span>
        </p>
        <h1 className="mt-3 max-w-4xl break-words text-3xl font-semibold leading-tight text-balance">
          {campaignId}
        </h1>
        <p className="mt-2 max-w-2xl text-pretty text-[var(--muted)]">
          Campaign-linked report previews summarized by review state, claim readiness, manual
          validation state, and evidence ref counts. Draft bodies and raw evidence payloads stay out
          of this view.
        </p>
      </header>

      <section className="grid gap-3 py-5 sm:grid-cols-2 xl:grid-cols-5">
        <Metric label="Drafts" value={drafts.length} />
        <Metric label="Reviewed claims" value={drafts.reduce((total, draft) => total + draft.readyClaimCount, 0)} />
        <Metric
          label="Claims needing review"
          value={drafts.reduce((total, draft) => total + draft.blockedClaimCount, 0)}
        />
        <Metric label="Evidence refs" value={drafts.reduce((total, draft) => total + draft.evidenceRefCount, 0)} />
        <Metric label="Manual evidence" value={validationEvidence.manualEvidenceCount} />
      </section>

      <section className="mb-5 border border-[var(--line)] bg-white px-5 py-4">
        <div className="grid gap-3 text-sm lg:grid-cols-[minmax(0,1fr)_150px_150px_150px_150px]">
          <div className="min-w-0">
            <p className="font-semibold">Manual validation state</p>
            <p className="mt-2 text-pretty text-xs text-[var(--muted)]">
              Report drafts can see reviewed validation outcomes as counts only; raw observations,
              request data, and response data remain outside this view.
            </p>
          </div>
          <Field label="Validation audits" value={String(validationEvidence.validationRunCount)} />
          <Field label="Evidence refs" value={String(validationEvidence.evidenceRefCount)} />
          <Field label="Evidence gaps" value={String(validationEvidence.evidenceGapCount)} />
        </div>
      </section>

      <section className="mb-5 border border-[var(--line)] bg-white px-5 py-4">
        <div className="grid gap-3 text-sm lg:grid-cols-[minmax(0,1fr)_150px_150px_150px_150px_150px]">
          <div className="min-w-0">
            <p className="font-semibold">Finding candidate gate</p>
            <p className="mt-2 text-pretty text-xs text-[var(--muted)]">
              Candidate promotion remains manual-only. This view counts reviewed claims that meet
              the report-chain gate without showing raw evidence refs.
            </p>
          </div>
          <Field label="Reviewed claims" value={String(findingCandidateGate.eligibleClaimCount)} />
          <Field label="Research feedback" value={String(findingCandidateGate.researchFeedbackCount)} />
          <Field
            label="Required evidence holds"
            value={String(findingCandidateGate.requiredEvidenceBlockedCount)}
          />
          <Field label="Promotion review holds" value={String(findingCandidateGate.researchPromotionBlockedCount)} />
          <Field
            label="Promotion audit holds"
            value={String(findingCandidateGate.promotionAuditBlockedCount)}
          />
          <Field
            label="Promotion reviews"
            value={String(findingCandidateGate.promotionAuditCreatedCount)}
          />
          <Field
            label="Provenance refs"
            value={String(findingCandidateGate.promotionAuditProvenanceRefCount)}
          />
          <Field
            label="Review evidence"
            value={String(findingCandidateGate.promotionAuditReviewEvidenceRefCount)}
          />
          <Field
            label="Mode"
            value={
              findingCandidateGate.status === "blocked_by_required_evidence"
                ? "Required evidence blocks promotion"
                : findingCandidateGate.status === "blocked_by_research_feedback"
                ? "Research feedback blocks promotion"
                : findingCandidateGate.promotionAuditLatestReason
                ? findingCandidateGate.promotionAuditLatestReason
                : findingCandidateGate.manualPromotionOnly
                ? `Manual review required; ${findingCandidateGate.blockedClaimCount} claim(s) needing review`
                : "Review required"
            }
          />
        </div>
        {findingCandidateGate.readyRunIds.length > 0 ? (
          <div className="mt-4 border-t border-[var(--line)] pt-4">
            <p className="text-xs font-semibold uppercase text-[var(--muted)]">
              Finding candidate reviews queued
            </p>
            <ul className="mt-3 grid gap-2">
              {findingCandidateGate.readyRunIds.map((runId) => (
                <li
                  key={runId}
                  className="flex flex-wrap items-center justify-between gap-2 text-sm"
                >
                  <span className="break-words font-semibold">{runId}</span>
                  <Link
                    href={`/reports/${encodeURIComponent(runId)}`}
                    className="inline-flex min-h-10 items-center gap-2 rounded-md border border-[var(--line)] px-3 text-sm font-semibold text-[var(--accent-strong)]"
                  >
                    <ShieldCheck size={16} aria-hidden="true" />
                    Review finding candidate
                  </Link>
                </li>
              ))}
            </ul>
          </div>
        ) : null}
      </section>

      <section className="border border-[var(--line)] bg-white">
        <div className="grid gap-3 border-b border-[var(--line)] px-5 py-4 text-sm font-semibold text-[var(--muted)] lg:grid-cols-[minmax(0,1fr)_150px_150px_150px]">
          <span>Draft</span>
          <span>Manual submission gate</span>
          <span>Claims</span>
          <span>Evidence refs</span>
        </div>
        {drafts.length === 0 ? (
          <p className="flex items-center gap-2 p-5 text-sm font-semibold text-[var(--muted)]">
            <AlertTriangle size={16} aria-hidden="true" />
            No report drafts queued for review.
          </p>
        ) : (
          <div className="divide-y divide-[var(--line)]">
            {drafts.map((draft) => (
              <article
                key={draft.runId}
                className="grid gap-3 px-5 py-4 text-sm lg:grid-cols-[minmax(0,1fr)_150px_150px_150px]"
              >
                <div className="min-w-0">
                  <p className="break-words font-semibold">{draft.title}</p>
                  <dl className="mt-2 grid gap-1 text-xs text-[var(--muted)] sm:grid-cols-2">
                    <Field label="Research audit" value={draft.runId} />
                    <Field label="Severity" value={draft.severity} />
                    <Field label="Scope" value={draft.scopeStatus} />
                  </dl>
                  {draft.topClaims.length > 0 ? (
                    <ul className="mt-3 grid gap-1 text-xs text-[var(--muted)]">
                      {draft.topClaims.map((claim) => (
                        <li key={`${draft.runId}-${claim}`} className="break-words">
                          {claim}
                        </li>
                      ))}
                    </ul>
                  ) : null}
                </div>
                <div className="grid content-start gap-2">
                  <GateText value={draft.submissionBlocked ? "Submission blocked" : "Human review requires manual decision"} />
                  <p className="text-xs text-[var(--muted)]">
                    {draft.humanReviewRequired ? "Human review required" : "Human review not required"}
                  </p>
                  {draft.safetyNotes.length > 0 ? (
                    <ul className="grid gap-1 text-xs text-[var(--muted)]">
                      {draft.safetyNotes.map((note) => (
                        <li key={`${draft.runId}-${note}`} className="break-words">
                          {note}
                        </li>
                      ))}
                    </ul>
                  ) : null}
                </div>
                <dl className="grid content-start gap-2 text-xs text-[var(--muted)]">
                  <Field label="Total" value={String(draft.claimCount)} />
                  <Field label="Reviewed" value={String(draft.readyClaimCount)} />
                  <Field label="Review holds" value={String(draft.blockedClaimCount)} />
                </dl>
                <span className="font-semibold tabular-nums">{draft.evidenceRefCount}</span>
              </article>
            ))}
          </div>
        )}
      </section>
    </main>
  );
}

function PageBack({ campaignId }: { campaignId: string }) {
  return (
    <Link
      href={`/campaigns/${encodeURIComponent(campaignId)}`}
      className="inline-flex min-h-10 items-center gap-2 rounded-md border border-[var(--line)] bg-white px-3 text-sm font-semibold"
    >
      <ArrowLeft size={17} aria-hidden="true" />
      Campaign
    </Link>
  );
}

function Metric({ label, value }: { label: string; value: number }) {
  return (
    <div className="border border-[var(--line)] bg-white p-4">
      <p className="text-sm text-[var(--muted)]">{label}</p>
      <p className="mt-3 text-3xl font-semibold tabular-nums">{value}</p>
    </div>
  );
}

function Field({ label, value }: { label: string; value: string }) {
  return (
    <div className="grid gap-0.5">
      <dt className="font-semibold uppercase">{label}</dt>
      <dd className="break-words">{value}</dd>
    </div>
  );
}

function GateText({ value }: { value: string }) {
  return (
    <span className="flex items-start gap-2 break-words font-semibold">
      <ShieldCheck size={16} className="mt-0.5 text-[var(--accent)]" aria-hidden="true" />
      {value}
    </span>
  );
}
