import { ArrowLeft, ShieldCheck } from "lucide-react";
import { revalidatePath } from "next/cache";
import Link from "next/link";
import { completeCampaignCycleReview } from "@/lib/api";

type PageProps = {
  params: Promise<{ campaignId: string; stageId: string }>;
};

export default async function CampaignCycleReviewCompletionPage({ params }: PageProps) {
  const { campaignId, stageId } = await params;

  async function completeCycleReviewAction(formData: FormData) {
    "use server";

    const actor = formText(formData, "actor") || "lead_reviewer";
    const reason = formText(formData, "reason") || "已审核研究活动周期，可规划下一轮只读周期。";

    await completeCampaignCycleReview(
      campaignId,
      stageId,
      { actor, reason },
    );

    revalidatePath(`/campaigns/${encodeURIComponent(campaignId)}`);
    revalidatePath(`/campaigns/${encodeURIComponent(campaignId)}/timeline`);
    revalidatePath(`/campaigns/${encodeURIComponent(campaignId)}/cycle-reviews/${encodeURIComponent(stageId)}`);
  }

  return (
    <main className="min-h-screen px-5 py-6 sm:px-8 lg:px-10">
      <PageBack campaignId={campaignId} />

      <header className="mt-6 border-b border-[var(--line)] pb-6">
        <p className="flex items-center gap-2 text-sm font-semibold text-[var(--accent-strong)]">
          <ShieldCheck size={17} aria-hidden="true" />
          研究活动周期审核
        </p>
        <h1 className="mt-3 max-w-4xl break-words text-3xl font-semibold leading-tight text-balance">
          {stageId}
        </h1>
        <p className="mt-2 max-w-2xl text-pretty text-[var(--muted)]">
          研究活动周期的人工完成门。此页面仅记录审核完成，以便规划下一轮只读周期。
        </p>
      </header>

      <section className="grid gap-3 py-5 md:grid-cols-3">
        <GateMetric label="下一轮只读周期" value="可继续审核" />
        <GateMetric label="验证执行" value="受控" />
        <GateMetric label="报告提交" value="受控" />
      </section>

      <section className="grid gap-5 lg:grid-cols-[minmax(0,1fr)_340px]">
        <form
          action={completeCycleReviewAction}
          className="grid gap-4 border border-[var(--line)] bg-white p-5"
        >
          <label className="grid gap-1">
            <span className="text-xs font-semibold uppercase text-[var(--muted)]">执行人</span>
            <input
              className="min-h-10 rounded-md border border-[var(--line)] px-3 outline-none focus:border-[var(--accent)]"
              name="actor"
              defaultValue="lead_reviewer"
            />
          </label>
          <label className="grid gap-1">
            <span className="text-xs font-semibold uppercase text-[var(--muted)]">原因</span>
            <textarea
              className="min-h-28 rounded-md border border-[var(--line)] px-3 py-2 outline-none focus:border-[var(--accent)]"
              name="reason"
            />
          </label>
          <button
            type="submit"
            className="min-h-10 justify-self-start rounded-md border border-[var(--line)] bg-[var(--foreground)] px-4 text-sm font-semibold text-white"
          >
            完成周期审核
          </button>
        </form>

        <aside className="border border-[var(--line)] bg-white p-5">
          <h2 className="text-lg font-semibold">审核门边界</h2>
          <dl className="mt-4 grid gap-3 text-sm">
            <Field label="周期阶段" value={stageId} />
            <Field label="研究活动" value={campaignId} />
            <Field label="执行门" value="受控" />
            <Field label="提交门" value="受控" />
          </dl>
        </aside>
      </section>
    </main>
  );
}

function PageBack({ campaignId }: { campaignId: string }) {
  return (
    <Link
      href={`/campaigns/${encodeURIComponent(campaignId)}/timeline`}
      className="inline-flex min-h-10 items-center gap-2 rounded-md border border-[var(--line)] bg-white px-3 text-sm font-semibold"
    >
      <ArrowLeft size={17} aria-hidden="true" />
      审核时间线
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
