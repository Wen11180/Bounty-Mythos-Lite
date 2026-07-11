import Link from "next/link";
import { revalidatePath } from "next/cache";
import { redirect } from "next/navigation";
import { ArrowLeft, ClipboardCheck, FileText, ListChecks, ShieldCheck, Target } from "lucide-react";
import {
  ApiRequestError,
  createFindingCandidate,
  getPipelineRun,
  getReportPreview,
  isFindingCandidatePromotionGateDetail,
  recordClaimReviewDecision,
  recordMythosBrainOutcome,
  type ClaimReviewDecisionValue,
  type LearningEvidenceQuality,
  type LearningOutcome,
  type LearningSeverityDelta,
} from "@/lib/api";
import {
  fallbackReportPreview,
  fallbackRunDetail,
  formatLabel,
  safeDisplay,
  safeStringList,
} from "@/lib/workbench-detail-data";

type PageProps = {
  params: Promise<{ runId: string }>;
  searchParams?: Promise<Record<string, string | string[] | undefined>>;
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

export default async function ReportPreviewPage({ params, searchParams }: PageProps) {
  const { runId } = await params;
  const query = (await searchParams) ?? {};
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
  const promotionGateStatus = firstParam(query.promotion_status);
  const promotionGateReason = firstParam(query.promotion_reason);
  const blockedStageCount = firstParam(query.blocked_stage_count);
  const provenanceRefCount = firstParam(query.provenance_ref_count);
  const findingPromotionAllowed = firstParam(query.finding_promotion_allowed);
  const reportSubmissionAllowed = firstParam(query.report_submission_allowed);
  const findingPromotionGate = formatReviewGateFlag(findingPromotionAllowed);
  const reportSubmissionGate = formatReviewGateFlag(reportSubmissionAllowed);
  const sourceAuditHypotheses = run?.payload?.hypotheses ?? [];
  const showPromotionGateNotice =
    promotionGateStatus === "blocked" &&
    promotionGateReason === "blocked_by_research_feedback_gate";
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
  const blockedStageDisplayCount = blockedStageCount ?? String(preview.claim_ledger.filter(
    (claim) => claim.readiness_blockers.length > 0,
  ).length);
  const provenanceRefDisplayCount =
    provenanceRefCount ?? String(new Set(preview.claim_ledger.flatMap((claim) => claim.provenance_refs)).size);
  const promotionGateDisplayStatus = showPromotionGateNotice
    ? promotionGateReason
    : canPromoteFindingCandidate
      ? "manual_promotion_review_ready"
      : "awaiting_review_candidate";

  async function promoteFindingCandidateAction() {
    "use server";

    try {
      await createFindingCandidate(currentRunId);
    } catch (error) {
      if (
        error instanceof ApiRequestError &&
        isFindingCandidatePromotionGateDetail(error.detail)
      ) {
        redirect(
          `/reports/${encodeURIComponent(currentRunId)}?promotion_status=blocked` +
            `&promotion_reason=${encodeURIComponent(error.detail.reason)}` +
            `&blocked_stage_count=${encodeURIComponent(String(error.detail.blocked_stage_count))}` +
            `&provenance_ref_count=${encodeURIComponent(String(error.detail.provenance_ref_count))}` +
            `&finding_promotion_allowed=${encodeURIComponent(String(error.detail.finding_promotion_allowed))}` +
            `&report_submission_allowed=${encodeURIComponent(String(error.detail.report_submission_allowed))}`,
        );
      }

      throw error;
    }

    revalidatePath(`/reports/${encodeURIComponent(currentRunId)}`);
    revalidatePath(`/runs/${encodeURIComponent(currentRunId)}`);
  }

  async function recordClaimReviewDecisionAction(formData: FormData) {
    "use server";

    const claimId = optionalFormValue(formData, "claim_id");
    const decision = optionalFormValue(formData, "decision") as ClaimReviewDecisionValue | null;
    const reviewer = optionalFormValue(formData, "reviewer") ?? "lead_reviewer";
    const rationale = optionalFormValue(formData, "rationale") ?? "";
    const evidenceRefs = formList(formData, "evidence_refs");

    if (!claimId || !decision) {
      return;
    }

    await recordClaimReviewDecision(
      currentRunId,
      {
        claim_id: claimId,
        decision,
        evidence_refs: evidenceRefs,
        rationale,
        reviewer,
      },
    );
    revalidatePath(`/reports/${encodeURIComponent(currentRunId)}`);
    revalidatePath(`/runs/${encodeURIComponent(currentRunId)}`);
    revalidatePath(`/validation-workspace/${encodeURIComponent(currentRunId)}`);
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
              Research audit
            </ActionLink>
            <ActionLink href={`/validation-workspace/${encodeURIComponent(preview.run_id)}`} icon={ClipboardCheck}>
              Review validation
            </ActionLink>
          </div>
        </div>
      </header>
      {reportDataMode === "Demo data" ? (
        <p className="mt-4 border border-[var(--line)] bg-white px-4 py-3 text-sm font-semibold text-[var(--warning)]">
          Demo data is shown because this claim ledger comes from a fallback report preview.
        </p>
      ) : null}
      {showPromotionGateNotice ? (
        <section className="mt-4 border border-[var(--line)] bg-white px-4 py-3 text-sm">
          <p className="font-semibold text-[var(--warning)]">
            Research feedback gate blocked finding promotion.
          </p>
          <p className="mt-2 text-[var(--muted)]">
            Finding candidate was not created. Submission remains manual.
          </p>
          <dl className="mt-3 grid gap-3 sm:grid-cols-2">
            <Field label="Reason" value={promotionGateReason} />
            <Field label="Review holds" value={blockedStageCount} />
            <Field label="Provenance refs" value={provenanceRefCount} />
            <Field label="Finding promotion gate" value={findingPromotionGate} />
            <Field label="Submission gate" value={reportSubmissionGate} />
          </dl>
        </section>
      ) : null}

      <section className="grid gap-3 py-5 sm:grid-cols-2 xl:grid-cols-4">
        <Metric label="Severity" value={formatLabel(preview.severity)} />
        <Metric label="Scope" value={formatLabel(preview.scope_status)} />
        <Metric label="Human review" value={preview.human_review_required ? "Required" : "Not required"} />
        <Metric
          label="Manual submission gate"
          value={preview.submission_blocked ? "Submission blocked" : "Human review ready"}
        />
      </section>

      <div className="grid gap-5 xl:grid-cols-[minmax(0,1fr)_360px]">
        <section className="grid gap-5">
          <article className="border border-[var(--line)] bg-white">
            <SectionHeader icon={FileText} title="Claim Ledger" />
            {preview.claim_ledger.length === 0 ? (
              <p className="p-5 text-sm text-[var(--muted)]">No claim ledger entries ready for review.</p>
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
                          value={claim.human_review_required ? "Human required" : "Review captured"}
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
                          {safeDisplay(claim.review_rationale, "No review rationale ready.")}
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
                        <p className="text-xs font-semibold uppercase text-[var(--muted)]">Review requirements</p>
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
                      <form
                        action={recordClaimReviewDecisionAction}
                        className="mt-4 grid gap-3 border-t border-[var(--line)] pt-4"
                      >
                        <input name="claim_id" type="hidden" value={safeDisplay(claim.claim_id)} />
                        <p className="text-sm font-semibold text-[var(--muted)]">
                          Submission remains manual. This records only the human claim review gate.
                        </p>
                        <label className="grid gap-1">
                          <span className="text-xs font-semibold uppercase text-[var(--muted)]">Decision</span>
                          <select
                            className="min-h-10 rounded-md border border-[var(--line)] bg-white px-3"
                            name="decision"
                            defaultValue="needs_evidence"
                          >
                            <option value="confirmed_observed_fact">Confirmed observed fact</option>
                            <option value="needs_evidence">Needs evidence</option>
                            <option value="refuted">Refuted</option>
                            <option value="not_reportable">Not reportable</option>
                          </select>
                        </label>
                        <label className="grid gap-1">
                          <span className="text-xs font-semibold uppercase text-[var(--muted)]">Reviewer</span>
                          <input
                            className="min-h-10 rounded-md border border-[var(--line)] px-3"
                            name="reviewer"
                            defaultValue="lead_reviewer"
                          />
                        </label>
                        <label className="grid gap-1">
                          <span className="text-xs font-semibold uppercase text-[var(--muted)]">Rationale</span>
                          <textarea
                            className="min-h-20 rounded-md border border-[var(--line)] px-3 py-2"
                            name="rationale"
                            defaultValue="Reviewed against sanitized local evidence."
                          />
                        </label>
                        <label className="grid gap-1">
                          <span className="text-xs font-semibold uppercase text-[var(--muted)]">Evidence refs</span>
                          <input
                            className="min-h-10 rounded-md border border-[var(--line)] px-3"
                            name="evidence_refs"
                            placeholder="request_response_diff"
                          />
                        </label>
                        <button
                          type="submit"
                          className="min-h-10 justify-self-start rounded-md border border-[var(--line)] bg-[var(--foreground)] px-4 text-sm font-semibold text-white"
                        >
                          Record Claim Review
                        </button>
                      </form>
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
                  <p className="p-5 text-sm text-[var(--muted)]">No report section claims ready.</p>
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
          {sourceAuditHypotheses.length > 0 ? (
            <section className="border border-[var(--line)] bg-white">
              <SectionHeader icon={ClipboardCheck} title="Refutation Review" />
              <div className="divide-y divide-[var(--line)]">
                {sourceAuditHypotheses.map((hypothesis, index) => {
                  const evidenceNeeded = safeStringList(hypothesis.evidence_needed);
                  const falsePositiveChecks = safeStringList(hypothesis.false_positive_checks);
                  const rankingReasons = safeStringList(hypothesis.ranking_reasons);

                  return (
                    <article key={`refutation-review-${index}`} className="grid gap-3 p-5 text-sm">
                      <p className="break-words font-semibold">
                        {safeDisplay(hypothesis.hypothesis, `Hypothesis ${index + 1}`)}
                      </p>
                      <dl className="grid gap-3">
                        <Field
                          label="Refutation status"
                          value={hypothesis.refutation_status ?? "unverified"}
                        />
                        <Field label="Priority score" value={hypothesis.priority_score ?? 0} />
                        <Field label="Validation" value={hypothesis.validation_mode} />
                        <Field label="Evidence needed" value={evidenceNeeded.length} />
                        <Field label="False positive checks" value={falsePositiveChecks.length} />
                        <Field label="Ranking reasons" value={rankingReasons.length} />
                      </dl>
                      {evidenceNeeded.length > 0 ? (
                        <ul className="grid gap-1 text-[var(--muted)]">
                          {evidenceNeeded.map((item) => (
                            <li key={`evidence-needed-${index}-${item}`}>{safeDisplay(item)}</li>
                          ))}
                        </ul>
                      ) : null}
                      {falsePositiveChecks.length > 0 ? (
                        <ul className="grid gap-1 text-[var(--muted)]">
                          {falsePositiveChecks.map((item) => (
                            <li key={`false-positive-check-${index}-${item}`}>{safeDisplay(item)}</li>
                          ))}
                        </ul>
                      ) : null}
                      {rankingReasons.length > 0 ? (
                        <ul className="grid gap-1 text-[var(--muted)]">
                          {rankingReasons.map((item) => (
                            <li key={`ranking-reason-${index}-${item}`}>{formatLabel(item)}</li>
                          ))}
                        </ul>
                      ) : null}
                    </article>
                  );
                })}
              </div>
            </section>
          ) : null}

          <section className="border border-[var(--line)] bg-white">
            <SectionHeader icon={ShieldCheck} title="Safety Notes" />
            {preview.safety_notes.length === 0 ? (
              <p className="p-5 text-sm text-[var(--muted)]">No safety notes ready.</p>
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
              <p className="p-5 text-sm text-[var(--muted)]">No evidence references ready.</p>
            ) : (
              <ul className="grid gap-2 p-5 text-sm text-[var(--muted)]">
                {preview.evidence_refs.map((ref) => (
                  <li key={ref}>{safeDisplay(ref)}</li>
                ))}
              </ul>
            )}
          </section>

          <section className="border border-[var(--line)] bg-white">
            <SectionHeader icon={FileText} title="Manual submission gate" />
            <dl className="grid gap-3 p-5 text-sm">
              <Field label="Human review" value={preview.human_review_required ? "Required" : "Not required"} />
              <Field
                label="Submission status"
                value={preview.submission_blocked ? "Submission blocked" : "Human review ready"}
              />
              <Field label="Research feedback gate" value={promotionGateDisplayStatus} />
              <Field label="Review holds" value={blockedStageDisplayCount} />
              <Field label="Provenance refs" value={provenanceRefDisplayCount} />
              <Field label="Research audit" value={preview.run_id} />
            </dl>
            {canPromoteFindingCandidate ? (
              <form action={promoteFindingCandidateAction} className="border-t border-[var(--line)] p-5">
                <p className="mb-3 text-sm text-[var(--muted)]">
                  Promote the review-ready human-reviewed observed claim into Finding DB. Research feedback gates can still
                  block promotion. Submission remains manual.
                </p>
                <button
                  type="submit"
                  className="min-h-10 rounded-md border border-[var(--line)] bg-[var(--foreground)] px-4 text-sm font-semibold text-white"
                >
                  Promote Finding Candidate
                </button>
              </form>
            ) : (
              <div className="border-t border-[var(--line)] p-5 text-sm font-semibold text-[var(--muted)]">
                <p>
                  Promotion waits for a live, human-reviewed observed claim. Research feedback gates can still block promotion.
                </p>
                <p className="mt-2 text-[var(--warning)]">
                  Research feedback gate blocked finding promotion.
                </p>
              </div>
            )}
          </section>

          <section className="border border-[var(--line)] bg-white">
            <SectionHeader icon={ClipboardCheck} title="Learning Outcome" />
            <form action={recordLearningOutcomeAction} className="grid gap-4 p-5 text-sm">
              <p className="font-semibold text-[var(--muted)]">
                advisory_memory_only. Records triage learning for future prioritization without changing validation gate state.
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

function formList(formData: FormData, name: string): string[] {
  return (optionalFormValue(formData, name) ?? "")
    .split(/[\n,]+/)
    .map((item) => item.trim())
    .filter(Boolean);
}

function firstParam(value: string | string[] | undefined): string | undefined {
  if (Array.isArray(value)) {
    return value[0];
  }

  return value || undefined;
}

function formatReviewGateFlag(value: string | undefined): string {
  if (value === "true") {
    return "Review ready";
  }

  if (value === "false") {
    return "Review blocked";
  }

  return value ?? "Unknown";
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
