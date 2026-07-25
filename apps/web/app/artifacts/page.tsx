import Link from "next/link";
import { ArrowLeft, Database, Fingerprint } from "lucide-react";
import { getArtifacts, type ArtifactRecord } from "@/lib/api";
import {
  fallbackArtifacts,
  formatLabel,
  safeDisplay,
  safeRecordEntries,
} from "@/lib/workbench-detail-data";

type PageProps = {
  searchParams?: Promise<Record<string, string | string[] | undefined>>;
};

export default async function ArtifactRepositoryPage({ searchParams }: PageProps) {
  const params = (await searchParams) ?? {};
  const filters = {
    programId: firstParam(params.program_id),
    asset: firstParam(params.asset),
    sourceType: firstParam(params.source_type),
    ingestionStatus: firstParam(params.ingestion_status),
    provenanceRef: firstParam(params.provenance_ref),
    factType: firstParam(params.fact_type),
    usageType: firstParam(params.usage_type),
    usageRunId: firstParam(params.usage_run_id),
    sensitivityLabel: firstParam(params.sensitivity_label),
    redactionStatus: firstParam(params.redaction_status),
    reportChainAllowed: firstParam(params.report_chain_allowed),
  };
  const artifacts = await getArtifacts(fallbackArtifacts(), filters);
  const artifactDataMode =
    artifacts.length > 0 && artifacts.every((artifact) => artifact.source_hash === "fallback-only")
      ? "演示数据"
      : "在线数据";
  const isDemoData = artifactDataMode === "演示数据";

  return (
    <main className="min-h-screen px-5 py-6 sm:px-8 lg:px-10">
      <Link
        href="/"
        className="inline-flex min-h-10 items-center gap-2 rounded-md border border-[var(--line)] bg-white px-3 text-sm font-semibold"
      >
        <ArrowLeft size={17} aria-hidden="true" />
        控制台
      </Link>

      <header className="mt-6 border-b border-[var(--line)] pb-6">
        <p className="flex items-center gap-2 text-sm font-semibold text-[var(--accent-strong)]">
          <Database size={17} aria-hidden="true" />
          资料仓库
          <span className="rounded-sm border border-[var(--line)] px-2 py-0.5 text-xs font-semibold uppercase text-[var(--muted)]">
            {artifactDataMode}
          </span>
        </p>
        <div className="mt-3 flex flex-col gap-4 lg:flex-row lg:items-end lg:justify-between">
          <div>
            <h1 className="max-w-4xl text-3xl font-semibold leading-tight text-balance">
              研究资料审核
            </h1>
            <p className="mt-2 text-pretty text-[var(--muted)]">
              查看规范化资料、溯源、重复导入历史和派生事实。
            </p>
          </div>
          <div className="border border-[var(--line)] bg-white px-4 py-3 text-sm">
            <p className="text-xs font-semibold uppercase text-[var(--muted)]">资料</p>
            <p className="mt-1 font-semibold tabular-nums">{artifacts.length}</p>
          </div>
        </div>
      </header>
      {isDemoData ? (
        <p className="mt-4 border border-[var(--line)] bg-white px-4 py-3 text-sm font-semibold text-[var(--warning)]">
          当前显示演示数据，因为正在展示研究资料摘要样例。
        </p>
      ) : null}

      <form
        action="/artifacts"
        className="mt-5 grid gap-3 border border-[var(--line)] bg-white p-5 sm:grid-cols-2 xl:grid-cols-[repeat(4,minmax(0,1fr))_auto_auto]"
      >
        <FilterField label="项目" name="program_id" defaultValue={filters.programId} />
        <FilterField label="资产" name="asset" defaultValue={filters.asset} />
        <FilterField label="来源类型" name="source_type" defaultValue={filters.sourceType} />
        <FilterField label="状态" name="ingestion_status" defaultValue={filters.ingestionStatus} />
        <FilterField label="溯源引用" name="provenance_ref" defaultValue={filters.provenanceRef} />
        <FilterField label="事实类型" name="fact_type" defaultValue={filters.factType} />
        <FilterField label="使用类型" name="usage_type" defaultValue={filters.usageType} />
        <FilterField label="使用审计" name="usage_run_id" defaultValue={filters.usageRunId} />
        <FilterField label="敏感度" name="sensitivity_label" defaultValue={filters.sensitivityLabel} />
        <FilterField label="脱敏" name="redaction_status" defaultValue={filters.redactionStatus} />
        <FilterField label="报告链" name="report_chain_allowed" defaultValue={filters.reportChainAllowed} />
        <button
          type="submit"
          className="min-h-10 self-end rounded-md border border-[var(--line)] bg-[var(--foreground)] px-4 text-sm font-semibold text-white"
        >
          应用
        </button>
        <Link
          href="/artifacts"
          className="inline-flex min-h-10 items-center justify-center self-end rounded-md border border-[var(--line)] px-4 text-sm font-semibold"
        >
          清除
        </Link>
      </form>

      <section className="mt-5 border border-[var(--line)] bg-white">
        <div className="flex items-center justify-between border-b border-[var(--line)] px-5 py-4">
          <h2 className="text-lg font-semibold">资料审核</h2>
          <Fingerprint size={19} className="text-[var(--accent)]" aria-hidden="true" />
        </div>
        {artifacts.length === 0 ? (
          <p className="p-5 text-sm text-[var(--muted)]">暂无可审核资料。</p>
        ) : (
          <div className="divide-y divide-[var(--line)]">
            {artifacts.map((artifact) => {
              const summary = safeRecordEntries(artifact.payload_summary).slice(0, 3);
              const duplicateCount = Array.isArray(artifact.provenance.duplicate_imports)
                ? artifact.provenance.duplicate_imports.length
                : 0;
              const usageCount = artifact.usage_records?.length ?? 0;
              const safety = artifactSafety(artifact);

              return (
                <article
                  key={artifact.id}
                  className="grid gap-4 p-5 text-sm xl:grid-cols-[minmax(0,1fr)_180px_150px_130px_100px_100px]"
                >
                  <div className="min-w-0">
                    <Link
                      href={`/artifacts/${encodeURIComponent(artifact.id)}`}
                      className="break-words font-semibold text-[var(--foreground)] underline-offset-4 hover:underline"
                    >
                      {safeDisplay(artifact.id)}
                    </Link>
                    <p className="mt-2 break-words text-[var(--muted)]">
                      {safeDisplay(artifact.asset)}
                    </p>
                    {summary.length > 0 ? (
                      <dl className="mt-3 grid gap-1">
                        {summary.map(([key, value]) => (
                          <div key={`${artifact.id}-${key}`} className="grid gap-1 sm:grid-cols-[140px_minmax(0,1fr)]">
                            <dt className="font-semibold">{key}</dt>
                            <dd className="break-words text-[var(--muted)]">{value}</dd>
                          </div>
                        ))}
                      </dl>
                    ) : null}
                  </div>
                  <div>
                    <p className="text-xs font-semibold uppercase text-[var(--muted)]">来源</p>
                    <p className="mt-1 font-semibold">{formatLabel(artifact.source_type)}</p>
                    <p className="mt-2 text-[var(--muted)]">{formatLabel(artifact.kind)}</p>
                  </div>
                  <div>
                    <p className="text-xs font-semibold uppercase text-[var(--muted)]">接入</p>
                    <p className="mt-1 font-semibold">{formatLabel(artifact.ingestion_status)}</p>
                    <p className="mt-2 text-[var(--muted)]">{safeDisplay(artifact.program_id ?? "未分配")}</p>
                  </div>
                  <div>
                    <p className="text-xs font-semibold uppercase text-[var(--muted)]">重复项</p>
                    <p className="mt-1 font-semibold tabular-nums">{duplicateCount}</p>
                  </div>
                  <div>
                    <p className="text-xs font-semibold uppercase text-[var(--muted)]">安全</p>
                    <p className="mt-1 font-semibold">{formatLabel(safety.sensitivityLabel)}</p>
                    <p className="mt-2 text-[var(--muted)]">{formatLabel(safety.redactionStatus)}</p>
                    <p className="mt-2 text-[var(--muted)]">{safety.reportChainAllowed}</p>
                  </div>
                  <div>
                    <p className="text-xs font-semibold uppercase text-[var(--muted)]">使用审计</p>
                    <p className="mt-1 font-semibold tabular-nums">{usageCount}</p>
                  </div>
                </article>
              );
            })}
          </div>
        )}
      </section>
    </main>
  );
}

function artifactSafety(artifact: ArtifactRecord) {
  return {
    sensitivityLabel: safeDisplay(artifact.sensitivity_label, "未知"),
    redactionStatus: safeDisplay(artifact.redaction_status, "未知"),
    reportChainAllowed:
      artifact.report_chain_allowed === true
        ? "报告链审核已就绪"
        : artifact.report_chain_allowed === false
          ? "报告链需要审核"
          : "未知",
  };
}

function firstParam(value: string | string[] | undefined): string | undefined {
  if (Array.isArray(value)) {
    return value[0];
  }

  return value || undefined;
}

function FilterField({
  label,
  name,
  defaultValue,
}: {
  label: string;
  name: string;
  defaultValue?: string;
}) {
  return (
    <label className="grid gap-1 text-sm">
      <span className="text-xs font-semibold uppercase text-[var(--muted)]">{label}</span>
      <input
        name={name}
        defaultValue={defaultValue ?? ""}
        className="min-h-10 rounded-md border border-[var(--line)] px-3 outline-none focus:border-[var(--accent)]"
      />
    </label>
  );
}
