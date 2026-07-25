import { ArrowLeft, ClipboardCheck } from "lucide-react";
import { revalidatePath } from "next/cache";
import Link from "next/link";
import {
  getCampaignValidationRuns,
  recordCampaignValidationRunManualResult,
  type ValidationRunManualResultOutcome,
} from "@/lib/api";
import { formatLabel } from "@/lib/workbench-detail-data";

type PageProps = {
  params: Promise<{ campaignId: string; validationRunId: string }>;
};

export default async function CampaignValidationRunManualResultPage({ params }: PageProps) {
  const { campaignId, validationRunId } = await params;
  const runs = await getCampaignValidationRuns(campaignId, []);
  const run = runs.find((item) => item.id === validationRunId) ?? null;

  async function recordManualResultAction(formData: FormData) {
    "use server";

    const reviewer = formText(formData, "reviewer") || "lead_reviewer";
    const summary = formText(formData, "summary") || "已审核的已脱敏人工验证观察。";

    await recordCampaignValidationRunManualResult(
      validationRunId,
      {
        evidence_refs: formLines(formData, "evidence_refs"),
        outcome: formOutcome(formData),
        reviewer,
        summary,
      },
    );

    revalidatePath(`/campaigns/${encodeURIComponent(campaignId)}/validation-runs`);
    revalidatePath(
      `/campaigns/${encodeURIComponent(campaignId)}/validation-runs/${encodeURIComponent(validationRunId)}`,
    );
    revalidatePath(`/campaigns/${encodeURIComponent(campaignId)}/evidence-review`);
    revalidatePath(`/campaigns/${encodeURIComponent(campaignId)}/timeline`);
  }

  return (
    <main className="min-h-screen px-5 py-6 sm:px-8 lg:px-10">
      <PageBack campaignId={campaignId} />

      <header className="mt-6 border-b border-[var(--line)] pb-6">
        <p className="flex items-center gap-2 text-sm font-semibold text-[var(--accent-strong)]">
          <ClipboardCheck size={17} aria-hidden="true" />
          人工验证观察审核
        </p>
        <h1 className="mt-3 max-w-4xl break-words text-3xl font-semibold leading-tight text-balance">
          {validationRunId}
        </h1>
        <p className="mt-2 max-w-2xl text-pretty text-[var(--muted)]">
          审核人工验证观察并附加可用于报告的安全证据引用。此审核门仅记录候选证据。
        </p>
      </header>

      <section className="grid gap-3 py-5 md:grid-cols-3">
        <GateMetric label="仅候选证据" value="审核人工观察" />
        <GateMetric label="证据晋级" value="需要人工审核" />
        <GateMetric label="报告提交" value="受控" />
      </section>

      <section className="grid gap-5 lg:grid-cols-[minmax(0,1fr)_340px]">
        <form
          action={recordManualResultAction}
          className="grid gap-4 border border-[var(--line)] bg-white p-5"
        >
          <label className="grid gap-1">
            <span className="text-xs font-semibold uppercase text-[var(--muted)]">审核人</span>
            <input
              className="min-h-10 rounded-md border border-[var(--line)] px-3 outline-none focus:border-[var(--accent)]"
              name="reviewer"
              defaultValue="lead_reviewer"
            />
          </label>
          <label className="grid gap-1">
            <span className="text-xs font-semibold uppercase text-[var(--muted)]">结果</span>
            <select
              className="min-h-10 rounded-md border border-[var(--line)] px-3 outline-none focus:border-[var(--accent)]"
              name="outcome"
              defaultValue="observed"
            >
              <option value="observed">已观察</option>
              <option value="refuted">已反驳</option>
              <option value="needs_more_evidence">需要更多证据</option>
            </select>
          </label>
          <label className="grid gap-1">
            <span className="text-xs font-semibold uppercase text-[var(--muted)]">摘要</span>
            <textarea
              className="min-h-28 rounded-md border border-[var(--line)] px-3 py-2 outline-none focus:border-[var(--accent)]"
              name="summary"
            />
          </label>
          <label className="grid gap-1">
            <span className="text-xs font-semibold uppercase text-[var(--muted)]">证据引用</span>
            <textarea
              className="min-h-24 rounded-md border border-[var(--line)] px-3 py-2 outline-none focus:border-[var(--accent)]"
              name="evidence_refs"
              placeholder="每行填写一条已脱敏证据引用"
            />
          </label>
          <button
            type="submit"
            className="min-h-10 justify-self-start rounded-md border border-[var(--line)] bg-[var(--foreground)] px-4 text-sm font-semibold text-white"
          >
            审核人工观察
          </button>
        </form>

        <aside className="border border-[var(--line)] bg-white p-5">
          <h2 className="text-lg font-semibold">审核门边界</h2>
          <dl className="mt-4 grid gap-3 text-sm">
            <Field label="验证审计" value={validationRunId} />
            <Field label="研究活动" value={campaignId} />
            <Field label="目标" value={run?.target_ref ?? "暂无目标引用"} />
            <Field label="验证模式" value={run?.validation_mode ? formatLabel(run.validation_mode) : "暂无验证模式"} />
            <Field label="执行门" value="受控" />
            <Field label="报告提交门" value="受控" />
          </dl>
        </aside>
      </section>
    </main>
  );
}

function PageBack({ campaignId }: { campaignId: string }) {
  return (
    <Link
      href={`/campaigns/${encodeURIComponent(campaignId)}/validation-runs`}
      className="inline-flex min-h-10 items-center gap-2 rounded-md border border-[var(--line)] bg-white px-3 text-sm font-semibold"
    >
      <ArrowLeft size={17} aria-hidden="true" />
      验证审计
    </Link>
  );
}

function GateMetric({ label, value }: { label: string; value: string }) {
  return (
    <div className="border border-[var(--line)] bg-white p-4">
      <p className="text-sm text-[var(--muted)]">{label}</p>
      <p className="mt-3 break-words text-2xl font-semibold">{value}</p>
    </div>
  );
}

function Field({ label, value }: { label: string; value: string }) {
  return (
    <div className="grid gap-0.5">
      <dt className="text-xs font-semibold uppercase text-[var(--muted)]">{label}</dt>
      <dd className="break-words font-semibold">{value}</dd>
    </div>
  );
}

function formText(formData: FormData, key: string): string {
  return formData.get(key)?.toString().trim() ?? "";
}

function formLines(formData: FormData, key: string): string[] {
  return formText(formData, key)
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean);
}

function formOutcome(formData: FormData): ValidationRunManualResultOutcome {
  const outcome = formText(formData, "outcome");
  return outcome === "refuted" || outcome === "needs_more_evidence" ? outcome : "observed";
}
