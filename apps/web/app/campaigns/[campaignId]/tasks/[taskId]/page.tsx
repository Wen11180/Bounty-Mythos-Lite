import { revalidatePath } from "next/cache";
import { AlertTriangle, ArrowLeft, ClipboardCheck, ShieldCheck } from "lucide-react";
import Link from "next/link";
import {
  createResearchRefutationDecision,
  createResearchReviewPlan,
  getCampaignResearchTaskReview,
} from "@/lib/api";
import { toCampaignResearchTaskReviewSummary } from "@/lib/campaigns-data";
import { formatLabel } from "@/lib/workbench-detail-data";

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
            研究审核项暂不可用
          </p>
          <h1 className="mt-3 break-words text-3xl font-semibold text-balance">{taskId}</h1>
          <p className="mt-2 max-w-2xl text-pretty text-[var(--muted)]">
            此审核项未返回已审计的研究审核工作区。
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
      : ["现有已脱敏资料能否反驳此研究候选项？"];
  const reviewEvidencePlan = summary.nonDestructivePlan.length
    ? summary.nonDestructivePlan.slice(0, 5)
    : ["仅收集已脱敏资料摘要和溯源计数。"];
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
        rationale: "根据已脱敏研究审核上下文起草。",
        refutation_questions: reviewRefutationQuestions,
        reviewer: "operator",
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
        rationale: "验证前需要更多已脱敏证据。",
        refutation_answers: [
          "当前已脱敏证据不足以进行验证审核。",
        ],
        reviewer: "operator",
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
          研究审核
          <span className="rounded-sm border border-[var(--line)] px-2 py-0.5 text-xs font-semibold uppercase text-[var(--muted)]">
            只读
          </span>
        </p>
        <h1 className="mt-3 max-w-4xl break-words text-3xl font-semibold leading-tight text-balance">
          {summary.title}
        </h1>
        <p className="mt-2 max-w-2xl text-pretty text-[var(--muted)]">
          用于规划非破坏性证据工作的建议性工作区，仅供审核，不能启动验证、智能体工作或报告提交。
        </p>
      </header>

      <section className="grid gap-3 py-5 sm:grid-cols-2 xl:grid-cols-4">
        <Metric label="优先级" value={summary.priorityScore} />
        <Metric label="状态" value={formatLabel(summary.status)} />
        <Metric label="审核门" value={formatLabel(summary.safetyGate)} />
        <Metric label="操作门" value="仅供审核" />
      </section>

      <div className="grid gap-5 xl:grid-cols-[minmax(0,1fr)_360px]">
        <section className="grid gap-5">
          {summary.autonomousCandidateContext ? (
            <article className="border border-[var(--line)] bg-white">
              <SectionHeader title="自主候选项审核" />
              <div className="grid gap-5 p-5 text-sm">
                <div className="grid gap-4 md:grid-cols-2">
                  <Field
                    label="候选项"
                    value={summary.autonomousCandidateContext.candidateId}
                  />
                  <Field
                    label="状态"
                    value={formatLabel(summary.autonomousCandidateContext.candidateStatus)}
                  />
                  <Field
                    label="流水线审计"
                    value={summary.autonomousCandidateContext.pipelineRunId}
                  />
                  {summary.autonomousCandidateContext.rawPriorityScore !== null ? (
                    <Field
                      label="原始评分"
                      value={String(summary.autonomousCandidateContext.rawPriorityScore)}
                    />
                  ) : null}
                  <Field
                    label="反证"
                    value={formatLabel(summary.autonomousCandidateContext.refutationStatus)}
                  />
                  <Field
                    label="验证计划"
                    value={formatLabel(summary.autonomousCandidateContext.validationPlanStatus)}
                  />
                  <Field
                    label="人工审核"
                    value={
                      summary.autonomousCandidateContext.humanApprovalRequired
                        ? "需要人工审核"
                        : "需要人工审核"
                    }
                  />
                </div>
                <Field
                  label="假设"
                  value={summary.autonomousCandidateContext.hypothesis}
                />
                {summary.autonomousCandidateContext.qualityGateReasons.length > 0 ? (
                  <ListBlock
                    items={summary.autonomousCandidateContext.qualityGateReasons}
                    title="候选项质量门原因"
                  />
                ) : null}
                <ListBlock
                  items={summary.autonomousCandidateContext.refutationQuestions}
                  title="候选项反证问题"
                />
                <ListBlock
                  items={summary.autonomousCandidateContext.triageSignals}
                  title="候选项分诊信号"
                />
                <ListBlock
                  items={summary.autonomousCandidateContext.evidenceFocus}
                  title="候选项证据重点"
                />
                <ListBlock
                  items={summary.autonomousCandidateContext.requiredEvidence}
                  title="候选项所需证据"
                />
                <ListBlock
                  items={summary.autonomousCandidateContext.sourceFactTypes}
                  title="候选项源代码事实"
                />
                <ListBlock
                  items={summary.autonomousCandidateContext.validationSteps}
                  title="候选项验证步骤"
                />
                <ListBlock
                  items={summary.autonomousCandidateContext.blockedActions}
                  title="已阻断操作"
                />
                <ListBlock
                  items={summary.autonomousCandidateContext.safetyNotes}
                  title="安全说明"
                />
              </div>
            </article>
          ) : null}

          {summary.latestReviewPlan ? (
            <article className="border border-[var(--line)] bg-white">
              <SectionHeader title="最近审核计划" />
              <div className="grid gap-5 p-5 text-sm">
                <Field label="计划" value={summary.latestReviewPlan.planId} />
                <Field label="状态" value={formatLabel(summary.latestReviewPlan.status)} />
                <Field label="审核门" value={formatLabel(summary.latestReviewPlan.safetyGate)} />
                <Field label="假设" value={summary.latestReviewPlan.hypothesis} />
                <ListBlock
                  items={summary.latestReviewPlan.refutationQuestions}
                  title="反证问题"
                />
                <ListBlock items={summary.latestReviewPlan.evidencePlan} title="证据计划" />
              </div>
            </article>
          ) : null}

          {summary.latestReviewPlan ? (
            <article className="border border-[var(--line)] bg-white">
              <SectionHeader title="记录需要证据" />
              <div className="grid gap-5 p-5 text-sm">
                <Field label="计划" value={summary.latestReviewPlan.planId} />
                <Field
                  label="决策"
                  value="验证前需要更多已脱敏证据。"
                />
                <form action={recordNeedsEvidenceDecisionAction}>
                  <button
                    type="submit"
                    className="inline-flex min-h-10 items-center rounded-md border border-[var(--line)] px-3 text-sm font-semibold text-[var(--accent-strong)]"
                  >
                    记录需要证据
                  </button>
                </form>
              </div>
            </article>
          ) : null}

          {summary.suggestedRefutationDecision ? (
            <article className="border border-[var(--line)] bg-white">
              <SectionHeader title="建议反证决策" />
              <div className="grid gap-5 p-5 text-sm">
                <div className="grid gap-4 md:grid-cols-2">
                  <Field
                    label="决策"
                    value={formatLabel(summary.suggestedRefutationDecision.decision)}
                  />
                  <Field
                    label="计划"
                    value={summary.suggestedRefutationDecision.planId}
                  />
                  <Field
                    label="反证问题"
                    value={String(summary.suggestedRefutationDecision.refutationQuestionCount)}
                  />
                  <Field
                    label="反证回答"
                    value={String(summary.suggestedRefutationDecision.refutationAnswerCount)}
                  />
                  <Field
                    label="验证模式"
                    value={summary.suggestedRefutationDecision.validationMode ?? "等待验证审核"}
                  />
                  <Field
                    label="目标"
                    value={summary.suggestedRefutationDecision.targetRef ?? "需要研究活动审核"}
                  />
                </div>
                <Field
                  label="下一步审核操作"
                  value={summary.suggestedRefutationDecision.nextAllowedAction}
                />
                <Field
                  label="依据"
                  value={summary.suggestedRefutationDecision.rationale}
                />
              </div>
            </article>
          ) : null}

          {summary.latestRefutationDecision ? (
            <article className="border border-[var(--line)] bg-white">
              <SectionHeader title="最近反证决策" />
              <div className="grid gap-5 p-5 text-sm">
                <Field label="决策" value={formatLabel(summary.latestRefutationDecision.decision)} />
                <Field label="计划" value={summary.latestRefutationDecision.planId} />
                <Field
                  label="审核门记录"
                  value={summary.latestRefutationDecision.approvalId ?? "暂无审核门"}
                />
                <Field
                  label="验证审计"
                  value={summary.latestRefutationDecision.validationRunId ?? "暂无验证审计"}
                />
                <Field label="下一步审核操作" value={summary.latestRefutationDecision.nextAllowedAction} />
                <Field label="依据" value={summary.latestRefutationDecision.rationale} />
                <ListBlock
                  items={summary.latestRefutationDecision.refutationAnswers}
                  title="反证回答"
                />
              </div>
            </article>
          ) : null}

          {summary.latestValidationFeedback ? (
            <article className="border border-[var(--line)] bg-white">
              <SectionHeader title="最近验证反馈" />
              <div className="grid gap-5 p-5 text-sm">
                <Field label="状态" value={formatLabel(summary.latestValidationFeedback.status)} />
                <Field label="结果" value={formatLabel(summary.latestValidationFeedback.outcome)} />
                <Field label="计划" value={summary.latestValidationFeedback.planId} />
                <Field label="审核门记录" value={summary.latestValidationFeedback.approvalId} />
                <Field label="反馈阶段" value={summary.latestValidationFeedback.feedbackStageId} />
                <Field
                  label="验证审计"
                  value={summary.latestValidationFeedback.validationRunId}
                />
                <Field
                  label="证据引用"
                  value={String(summary.latestValidationFeedback.evidenceRefCount)}
                />
                <Field label="审核门" value={formatLabel(summary.latestValidationFeedback.safetyGate)} />
                <Field label="下一步审核操作" value={summary.latestValidationFeedback.nextAllowedAction} />
                <Field
                  label="发现确认"
                  value={
                    summary.latestValidationFeedback.findingConfirmationAllowed
                      ? "需要人工审核"
                      : "确认已阻断"
                  }
                />
                <Link
                  href={`/campaigns/${encodeURIComponent(campaignId)}/feedback-reviews/${encodeURIComponent(summary.latestValidationFeedback.feedbackStageId)}`}
                  className="inline-flex min-h-9 items-center justify-self-start rounded-md border border-[var(--line)] px-3 text-xs font-semibold text-[var(--accent-strong)]"
                >
                  审核晋级门
                </Link>
              </div>
            </article>
          ) : null}

          <article className="border border-[var(--line)] bg-white">
            <SectionHeader title="非破坏性计划" />
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
            <SectionHeader title="起草审核计划" />
            <div className="grid gap-5 p-5 text-sm">
              <Field label="假设" value={reviewHypothesis} />
              <ListBlock items={reviewRefutationQuestions} title="反证问题" />
              <ListBlock items={reviewEvidencePlan} title="证据计划" />
              <form action={createReviewPlanAction}>
                <button
                  type="submit"
                  className="inline-flex min-h-10 items-center rounded-md border border-[var(--line)] px-3 text-sm font-semibold text-[var(--accent-strong)]"
                >
                  起草审核计划
                </button>
              </form>
            </div>
          </article>
        </section>

        <aside className="grid content-start gap-5">
          <section className="border border-[var(--line)] bg-white">
            <SectionHeader title="审核上下文" />
            <dl className="grid gap-3 p-5 text-sm">
              <Field label="审核项" value={summary.taskId} />
              <Field label="推理记忆键" value={summary.queueKey} />
              <Field label="来源" value={summary.source} />
              <Field label="策略手册" value={summary.playbookId ?? "暂无策略手册"} />
              <Field label="攻击面" value={summary.surfaceKey ?? "暂无攻击面"} />
              <Field label="下一步审核操作" value={summary.nextAllowedAction} />
            </dl>
          </section>

          <section className="border border-[var(--line)] bg-white">
            <SectionHeader title="必需人工审核门" />
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
      研究审核
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
