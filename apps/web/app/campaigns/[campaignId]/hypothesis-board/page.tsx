import { AlertTriangle, ArrowLeft, FlaskConical, ShieldCheck } from "lucide-react";
import Link from "next/link";
import { getCampaignControlCenter, getPipelineRun } from "@/lib/api";
import { toCampaignHypothesisBoardSummaries } from "@/lib/campaigns-data";

type PageProps = {
  params: Promise<{ campaignId: string }>;
};

export default async function CampaignHypothesisBoardPage({ params }: PageProps) {
  const { campaignId } = await params;
  const controlCenter = await getCampaignControlCenter(campaignId, null);
  const runIds = Array.from(
    new Set(
      controlCenter?.pipeline_stages
        .map((stage) => stage.pipeline_run_id)
        .filter((runId): runId is string => Boolean(runId)) ?? [],
    ),
  );
  const runs = (
    await Promise.all(runIds.map((runId) => getPipelineRun(runId, null)))
  ).filter((run): run is NonNullable<typeof run> => run !== null);
  const candidates = toCampaignHypothesisBoardSummaries(runs, controlCenter?.research_review_plans ?? []);

  return (
    <main className="min-h-screen px-5 py-6 sm:px-8 lg:px-10">
      <PageBack campaignId={campaignId} />

      <header className="mt-6 border-b border-[var(--line)] pb-6">
        <p className="flex items-center gap-2 text-sm font-semibold text-[var(--accent-strong)]">
          <FlaskConical size={17} aria-hidden="true" />
          Hypothesis Board
          <span className="rounded-sm border border-[var(--line)] px-2 py-0.5 text-xs font-semibold uppercase text-[var(--muted)]">
            Read only
          </span>
        </p>
        <h1 className="mt-3 max-w-4xl break-words text-3xl font-semibold leading-tight text-balance">
          {campaignId}
        </h1>
        <p className="mt-2 max-w-2xl text-pretty text-[var(--muted)]">
          Candidate vulnerability hypotheses ranked by hunter priority, impact, duplicate risk,
          policy risk, exploit-chain reasoning, refutation state, and evidence path.
        </p>
      </header>

      <section className="grid gap-3 py-5 sm:grid-cols-2 xl:grid-cols-4">
        <Metric label="Research audits" value={runIds.length} />
        <Metric label="Candidates" value={candidates.length} />
        <Metric
          label="High priority"
          value={candidates.filter((candidate) => candidate.reviewPriorityScore >= 70).length}
        />
        <Metric
          label="Needs evidence"
          value={candidates.filter((candidate) => candidate.evidenceNeededCount > 0).length}
        />
        <Metric
          label="Chains mapped"
          value={candidates.filter((candidate) => candidate.primitiveCount > 0).length}
        />
      </section>

      <section className="border border-[var(--line)] bg-white">
        <div className="grid gap-3 border-b border-[var(--line)] px-5 py-4 text-sm font-semibold text-[var(--muted)] lg:grid-cols-[minmax(0,1fr)_130px_130px_150px]">
          <span>Hypothesis</span>
          <span>Priority</span>
          <span>Risk</span>
          <span>Evidence path</span>
        </div>
        {candidates.length === 0 ? (
          <p className="flex items-center gap-2 p-5 text-sm font-semibold text-[var(--muted)]">
            <AlertTriangle size={16} aria-hidden="true" />
            No hypotheses ready for review.
          </p>
        ) : (
          <div className="divide-y divide-[var(--line)]">
            {candidates.map((candidate) => (
              <article
                key={`${candidate.runId}-${candidate.candidateId}`}
                className="grid gap-3 px-5 py-4 text-sm lg:grid-cols-[minmax(0,1fr)_130px_130px_150px]"
              >
                <div className="min-w-0">
                  <p className="break-words font-semibold">{candidate.hypothesis}</p>
                  <dl className="mt-3 grid gap-1 text-xs text-[var(--muted)] sm:grid-cols-2">
                    <Field label="Research audit" value={candidate.runId} />
                    <Field label="Candidate" value={candidate.candidateId} />
                    <Field label="Source" value={candidate.source} />
                    <Field label="Playbook" value={candidate.playbook} />
                    <Field label="Validation" value={candidate.validationMode ?? "No validation mode"} />
                    <Field label="Invariant" value={candidate.brokenInvariant ?? "No invariant"} />
                    <Field label="Refutation" value={candidate.refutationStatus ?? "No refutation"} />
                    <Field
                      label="Chain confidence"
                      value={
                        candidate.chainConfidence === null
                          ? "No confidence"
                          : `${candidate.chainConfidence}%`
                      }
                    />
                  </dl>
                  {candidate.nextAction ? (
                    <p className="mt-3 break-words text-[var(--muted)]">{candidate.nextAction}</p>
                  ) : null}
                  {candidate.chainImpact ? (
                    <p className="mt-3 break-words text-xs font-semibold text-[var(--muted)]">
                      Chain impact: {candidate.chainImpact}
                    </p>
                  ) : null}
                  {candidate.reasons.length > 0 ? (
                    <ul className="mt-3 flex flex-wrap gap-x-4 gap-y-2 text-xs font-semibold uppercase text-[var(--muted)]">
                      {candidate.reasons.map((reason) => (
                        <li key={`${candidate.runId}-${candidate.candidateId}-${reason}`}>{reason}</li>
                      ))}
                    </ul>
                  ) : null}
                </div>
                <div className="grid content-start gap-2">
                  <p className="text-3xl font-semibold tabular-nums">{candidate.reviewPriorityScore}</p>
                  <p className="text-xs font-semibold uppercase text-[var(--muted)]">
                    Review priority
                  </p>
                  <p className="text-xs text-[var(--muted)]">
                    Hunter {candidate.hunterPriorityScore}
                  </p>
                  <StatusText value={candidate.recommendation} />
                  <StatusText value={candidate.candidateStatus} />
                </div>
                <dl className="grid content-start gap-2 text-xs text-[var(--muted)]">
                  <Field label="Impact" value={String(candidate.impactScore)} />
                  <Field label="Duplicate" value={String(candidate.duplicateRiskScore)} />
                  <Field label="Policy score" value={String(candidate.policyRiskScore)} />
                  <Field label="Policy" value={candidate.policyRisk ?? "No policy risk"} />
                  <Field label="Severity" value={candidate.riskLevel ?? "No severity"} />
                </dl>
                <div className="grid content-start gap-2">
                  <GateText value={`${candidate.evidenceNeededCount} needed`} />
                  <p className="text-xs text-[var(--muted)]">
                    {candidate.evidenceFocusCount} evidence focus item(s)
                  </p>
                  <p className="text-xs text-[var(--muted)]">
                    {candidate.primitiveCount} primitive(s), {candidate.preconditionCount} precondition(s)
                  </p>
                  <p className="text-xs text-[var(--muted)]">
                    {candidate.refutationQuestionCount} refutation question(s)
                  </p>
                  <PreviewList label="Primitives" values={candidate.primitives} />
                  <PreviewList label="Preconditions" values={candidate.preconditions} />
                  <PreviewList label="Refutation" values={candidate.refutationQuestions} />
                </div>
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

function PreviewList({ label, values }: { label: string; values: string[] }) {
  if (values.length === 0) {
    return null;
  }

  return (
    <div className="grid gap-1 text-xs text-[var(--muted)]">
      <p className="font-semibold uppercase">{label}</p>
      <ul className="grid gap-1">
        {values.map((value) => (
          <li key={`${label}-${value}`} className="break-words">
            {value}
          </li>
        ))}
      </ul>
    </div>
  );
}

function StatusText({ value }: { value: string }) {
  return <span className="break-words font-semibold">{value}</span>;
}
