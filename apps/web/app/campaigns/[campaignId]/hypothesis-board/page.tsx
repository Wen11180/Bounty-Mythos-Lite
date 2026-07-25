import { AlertTriangle, ArrowLeft, FlaskConical, ShieldCheck } from "lucide-react";
import Link from "next/link";
import { getCampaignControlCenter, getPipelineRun } from "@/lib/api";
import { toCampaignControlSummary, toCampaignHypothesisBoardSummaries } from "@/lib/campaigns-data";
import { formatLabel } from "@/lib/workbench-detail-data";

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
  const researchQueueSuggestions = controlCenter
    ? toCampaignControlSummary(controlCenter).researchQueueSuggestions
    : [];
  const candidates = toCampaignHypothesisBoardSummaries(
    runs,
    controlCenter?.research_review_plans ?? [],
    researchQueueSuggestions,
    campaignId,
  );

  return (
    <main className="min-h-screen px-5 py-6 sm:px-8 lg:px-10">
      <PageBack campaignId={campaignId} />

      <header className="mt-6 border-b border-[var(--line)] pb-6">
        <p className="flex items-center gap-2 text-sm font-semibold text-[var(--accent-strong)]">
          <FlaskConical size={17} aria-hidden="true" />
          假设看板
          <span className="rounded-sm border border-[var(--line)] px-2 py-0.5 text-xs font-semibold uppercase text-[var(--muted)]">
            只读
          </span>
        </p>
        <h1 className="mt-3 max-w-4xl break-words text-3xl font-semibold leading-tight text-balance">
          {campaignId}
        </h1>
        <p className="mt-2 max-w-2xl text-pretty text-[var(--muted)]">
          按研究优先级、影响、重复风险、策略风险、利用链推理、反证状态和证据路径排序的漏洞候选假设。
        </p>
      </header>

      <section className="grid gap-3 py-5 sm:grid-cols-2 xl:grid-cols-4">
        <Metric label="研究审计" value={runIds.length} />
        <Metric label="候选项" value={candidates.length} />
        <Metric
          label="高优先级"
          value={candidates.filter((candidate) => candidate.reviewPriorityScore >= 70).length}
        />
        <Metric
          label="需要证据"
          value={candidates.filter((candidate) => candidate.evidenceNeededCount > 0).length}
        />
        <Metric
          label="已映射利用链"
          value={candidates.filter((candidate) => candidate.primitiveCount > 0).length}
        />
      </section>

      <section className="border border-[var(--line)] bg-white">
        <div className="grid gap-3 border-b border-[var(--line)] px-5 py-4 text-sm font-semibold text-[var(--muted)] lg:grid-cols-[minmax(0,1fr)_130px_130px_150px]">
          <span>假设</span>
          <span>优先级</span>
          <span>风险</span>
          <span>证据路径</span>
        </div>
        {candidates.length === 0 ? (
          <p className="flex items-center gap-2 p-5 text-sm font-semibold text-[var(--muted)]">
            <AlertTriangle size={16} aria-hidden="true" />
            暂无可审核的假设。
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
                    <Field label="研究审计" value={candidate.runId} />
                    <Field label="候选项" value={candidate.candidateId} />
                    <Field label="来源" value={candidate.source} />
                    <Field label="策略手册" value={candidate.playbook} />
                    <Field label="验证" value={candidate.validationMode ?? "暂无验证模式"} />
                    <Field label="安全不变量" value={candidate.brokenInvariant ?? "暂无安全不变量"} />
                    <Field label="反证" value={candidate.refutationStatus ? formatLabel(candidate.refutationStatus) : "暂无反证"} />
                    <Field
                      label="利用链置信度"
                      value={
                        candidate.chainConfidence === null
                          ? "暂无置信度"
                          : `${candidate.chainConfidence}%`
                      }
                    />
                  </dl>
                  {candidate.nextAction ? (
                    <p className="mt-3 break-words text-[var(--muted)]">{candidate.nextAction}</p>
                  ) : null}
                  {candidate.chainImpact ? (
                    <p className="mt-3 break-words text-xs font-semibold text-[var(--muted)]">
                      利用链影响：{candidate.chainImpact}
                    </p>
                  ) : null}
                  {candidate.reasons.length > 0 ? (
                    <ul className="mt-3 flex flex-wrap gap-x-4 gap-y-2 text-xs font-semibold uppercase text-[var(--muted)]">
                      {candidate.reasons.map((reason) => (
                        <li key={`${candidate.runId}-${candidate.candidateId}-${reason}`}>{reason}</li>
                      ))}
                    </ul>
                  ) : null}
                  {candidate.priorityReasons.length > 0 ? (
                    <PreviewList label="优先级依据" values={candidate.priorityReasons} />
                  ) : null}
                  <div className="mt-3 grid gap-3 text-xs text-[var(--muted)] sm:grid-cols-3">
                    <PreviewList label="分诊信号" values={candidate.triageSignals} />
                    <PreviewList label="证据重点" values={candidate.evidenceFocus} />
                    <PreviewList label="源代码事实" values={candidate.sourceFactTypes} />
                  </div>
                  {candidate.researchQueueHandoff ? (
                    <div className="mt-4 grid gap-3 border border-[var(--line)] p-3">
                      <div className="flex flex-wrap items-start justify-between gap-3">
                        <div>
                          <p className="text-xs font-semibold uppercase text-[var(--muted)]">
                            审核队列交接
                          </p>
                          <p className="mt-1 break-words font-semibold">
                            {candidate.researchQueueHandoff.title}
                          </p>
                        </div>
                        <Link
                          href={candidate.researchQueueHandoff.reviewHref}
                          className="inline-flex min-h-9 items-center rounded-md border border-[var(--line)] px-3 text-xs font-semibold"
                        >
                          审核队列
                        </Link>
                      </div>
                      <dl className="grid gap-2 text-xs text-[var(--muted)] sm:grid-cols-2">
                        <Field
                          label="审核门"
                          value={formatLabel(candidate.researchQueueHandoff.safetyGate)}
                        />
                        <Field
                          label="人工审核"
                          value={
                            candidate.researchQueueHandoff.humanApprovalRequired
                              ? "需要处理"
                              : "仅供审核"
                          }
                        />
                        <Field
                          label="操作门"
                          value={
                            candidate.researchQueueHandoff.executionAllowed
                              ? "需要审核"
                              : "仅供审核"
                          }
                        />
                        <Field
                          label="已阻断操作"
                          value={String(candidate.researchQueueHandoff.blockedActionCount)}
                        />
                        <Field
                          label="反证问题"
                          value={String(candidate.researchQueueHandoff.refutationQuestionCount)}
                        />
                        <Field
                          label="验证步骤"
                          value={String(candidate.researchQueueHandoff.validationStepCount)}
                        />
                      </dl>
                      <PreviewList
                        label="所需证据"
                        values={candidate.researchQueueHandoff.requiredEvidence}
                      />
                      <p className="break-words text-xs text-[var(--muted)]">
                        {candidate.researchQueueHandoff.nextAllowedAction}
                      </p>
                    </div>
                  ) : null}
                </div>
                <div className="grid content-start gap-2">
                  <p className="text-3xl font-semibold tabular-nums">{candidate.reviewPriorityScore}</p>
                  <p className="text-xs font-semibold uppercase text-[var(--muted)]">
                    审核优先级
                  </p>
                  <p className="text-xs text-[var(--muted)]">
                    研究评分 {candidate.hunterPriorityScore}
                  </p>
                  <StatusText value={candidate.recommendation} />
                  <StatusText value={candidate.candidateStatus} />
                </div>
                <dl className="grid content-start gap-2 text-xs text-[var(--muted)]">
                  <Field label="影响" value={String(candidate.impactScore)} />
                  <Field label="重复风险" value={String(candidate.duplicateRiskScore)} />
                  <Field label="策略评分" value={String(candidate.policyRiskScore)} />
                  <Field label="策略" value={candidate.policyRisk ?? "暂无策略风险"} />
                  <Field label="严重性" value={candidate.riskLevel ? formatLabel(candidate.riskLevel) : "暂无严重性"} />
                </dl>
                <div className="grid content-start gap-2">
                  <GateText value={`需要 ${candidate.evidenceNeededCount} 项证据`} />
                  <p className="text-xs text-[var(--muted)]">
                    {candidate.evidenceFocusCount} 项证据重点
                  </p>
                  <p className="text-xs text-[var(--muted)]">
                    {candidate.primitiveCount} 个原语，{candidate.preconditionCount} 个前提条件
                  </p>
                  <p className="text-xs text-[var(--muted)]">
                    {candidate.refutationQuestionCount} 个反证问题
                  </p>
                  <PreviewList label="原语" values={candidate.primitives} />
                  <PreviewList label="前提条件" values={candidate.preconditions} />
                  <PreviewList label="反证" values={candidate.refutationQuestions} />
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
      研究活动
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
  return <span className="break-words font-semibold">{formatLabel(value)}</span>;
}
