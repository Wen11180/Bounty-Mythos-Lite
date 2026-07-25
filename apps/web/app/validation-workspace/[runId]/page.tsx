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
          <h1 className="text-2xl font-semibold text-balance">验证工作区暂不可用</h1>
          <p className="mt-2 text-pretty text-[var(--muted)]">{safeDisplay(runId)}</p>
        </section>
      </main>
    );
  }

  const isDemoData = run.policy_text_hash === "fallback-only";
  const workspaceDataMode = isDemoData ? "演示数据" : "在线数据";
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
              验证工作区
            </h1>
            <p className="mt-2 text-pretty text-[var(--muted)]">{safeDisplay(run.asset)}</p>
          </div>
          <div className="flex flex-wrap gap-2">
            <ActionLink href={`/runs/${encodeURIComponent(run.id)}`} icon={Target}>
              运行
            </ActionLink>
            <ActionLink href={`/reports/${encodeURIComponent(run.id)}`} icon={FileText}>
              报告
            </ActionLink>
          </div>
        </div>
      </header>
      {isDemoData ? (
        <p className="mt-4 border border-[var(--line)] bg-white px-4 py-3 text-sm font-semibold text-[var(--warning)]">
          当前显示演示数据，因为此验证工作区来自后备运行记录。
        </p>
      ) : null}

      <section className="grid gap-3 py-5 sm:grid-cols-2 xl:grid-cols-4">
        <GateMetric
          label="预检门"
          value={workspace.allowed_to_execute === true}
          trueLabel="预检已审核"
          falseLabel="预检已阻断"
        />
        <GateMetric label="仅测试账号" value={workspace.test_accounts_only !== false} trueLabel="是" falseLabel="否" />
        <GateMetric label="不使用真实用户数据" value={workspace.no_real_user_data !== false} trueLabel="是" falseLabel="否" />
        <GateMetric label="仅非破坏性操作" value={workspace.non_destructive_only !== false} trueLabel="是" falseLabel="否" />
      </section>

      <div className="grid gap-5 xl:grid-cols-[minmax(0,1fr)_360px]">
        <section className="grid gap-5">
          <section className="border border-[var(--line)] bg-white">
            <SectionHeader icon={ClipboardCheck} title="安全步骤" />
            {steps.length === 0 ? (
              <p className="p-5 text-sm text-[var(--muted)]">暂无验证步骤。</p>
            ) : (
              <ol className="divide-y divide-[var(--line)]">
                {steps.map((step, index) => (
                  <li
                    key={`${safeDisplay(step.method)}-${index}`}
                    className="grid gap-3 p-5 text-sm lg:grid-cols-[80px_180px_minmax(0,1fr)]"
                  >
                    <p className="font-semibold tabular-nums">步骤 {index + 1}</p>
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
            <SectionHeader icon={Target} title="声明审核" />
            {claimTasks.length === 0 ? (
              <p className="p-5 text-sm text-[var(--muted)]">暂无声明审核项。</p>
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
                            label="晋级门"
                            value={task.promotion_eligible ? "审核已就绪" : "需要审核"}
                          />
                          <Field label="审核" value={formatLabel(task.review_status)} />
                          <Field label="就绪度" value={formatLabel(task.readiness_level)} />
                          <Field label="质量" value={`${task.quality_score}/100`} />
                          <Field
                            label="关系"
                            value={
                              relationshipContexts.length === 0
                                ? "无"
                                : relationshipContexts.join("、")
                            }
                          />
                          <Field
                            label="重点"
                            value={evidenceFocus.length === 0 ? "无" : evidenceFocus.join("、")}
                          />
                          <Field
                            label="预检状态"
                            value={task.execution_allowed ? "预检已审核" : "预检已阻断"}
                          />
                          <Field
                            label="所需观察"
                            value={requiredTypes.length === 0 ? "无" : requiredTypes.map((type) => formatLabel(type)).join("、")}
                          />
                          <Field
                            label="证据"
                            value={evidenceRefs.length === 0 ? "缺失" : evidenceRefs.join("、")}
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
                              需要可用于报告的安全证据
                            </p>
                            <p className="mt-2 text-sm text-[var(--muted)]">
                              最近一次人工观察仅提供了已脱敏证据引用。在此声明进入报告审核前，请补充已清理的请求响应差异或角色矩阵观察。
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
                            <span className="text-xs font-semibold uppercase text-[var(--muted)]">观察类型</span>
                            <select
                              className="min-h-10 rounded-md border border-[var(--line)] bg-white px-3 outline-none focus:border-[var(--accent)]"
                              name="observation_type"
                              defaultValue={requiredTypes[0] ?? "request_response_diff"}
                            >
                              <option value="request_response_diff">请求响应差异</option>
                              <option value="role_matrix_observation">角色矩阵观察</option>
                            </select>
                          </label>
                          <label className="grid gap-1">
                            <span className="text-xs font-semibold uppercase text-[var(--muted)]">观察人</span>
                            <input
                              className="min-h-10 rounded-md border border-[var(--line)] px-3 outline-none focus:border-[var(--accent)]"
                              name="observer"
                              defaultValue="lead_reviewer"
                            />
                          </label>
                          <label className="grid gap-1">
                            <span className="text-xs font-semibold uppercase text-[var(--muted)]">观察记录</span>
                            <textarea
                              className="min-h-24 rounded-md border border-[var(--line)] px-3 py-2 outline-none focus:border-[var(--accent)]"
                              name="observation"
                            />
                          </label>
                          <label className="grid gap-1">
                            <span className="text-xs font-semibold uppercase text-[var(--muted)]">证据引用</span>
                            <input
                              className="min-h-10 rounded-md border border-[var(--line)] px-3 outline-none focus:border-[var(--accent)]"
                              name="evidence_refs"
                            />
                          </label>
                          <button
                            type="submit"
                            className="min-h-10 justify-self-start rounded-md border border-[var(--line)] bg-[var(--foreground)] px-4 text-sm font-semibold text-white"
                          >
                            记录观察
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
            <SectionHeader icon={FileText} title="人工观察" />
            {manualObservations.length === 0 ? (
              <p className="p-5 text-sm text-[var(--muted)]">暂无可审核的人工观察。</p>
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
                          <Field label="声明" value={observation.claim_id} />
                          <Field label="脱敏" value={formatLabel(observation.redaction_status)} />
                          <Field
                            label="观察边界"
                            value={observation.execution_allowed ? "预检已审核" : "仅供审核"}
                          />
                          <Field
                            label="报告链门"
                            value={observation.report_chain_blocked ? "需要审核" : "审核已就绪"}
                          />
                          <Field label="创建时间" value={observation.created_at} />
                          <Field
                            label="证据"
                            value={evidenceRefs.length === 0 ? "缺失" : evidenceRefs.join("、")}
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
            <SectionHeader icon={ShieldCheck} title="预检门" />
            <dl className="grid gap-3 p-5 text-sm">
              <Field label="工作区" value={formatLabel(workspace.status)} />
              <Field label="计划" value={formatLabel(workspace.validation_plan_status)} />
              <Field label="反证" value={formatLabel(workspace.refutation_status)} />
              <Field label="审核门状态" value={formatLabel(gate?.status)} />
              <Field label="审核门原因" value={formatLabel(gate?.reason)} />
              <Field label="人工审核门" value={gate?.human_approved ? "已记录审核" : "需要审核"} />
            </dl>
          </section>

          <section className="border border-[var(--line)] bg-white">
            <SectionHeader icon={Lock} title="审核要求" />
            {blockedReasons.length === 0 ? (
              <p className="p-5 text-sm text-[var(--muted)]">当前没有待处理的审核要求。</p>
            ) : (
              <ul className="grid gap-2 p-5 text-sm text-[var(--muted)]">
                {blockedReasons.map((reason) => (
                  <li key={reason}>{formatLabel(reason)}</li>
                ))}
              </ul>
            )}
          </section>

          <section className="border border-[var(--line)] bg-white">
            <SectionHeader icon={Target} title="证据提示" />
            {evidenceHints.length === 0 ? (
              <p className="p-5 text-sm text-[var(--muted)]">暂无证据提示。</p>
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
      控制台
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
