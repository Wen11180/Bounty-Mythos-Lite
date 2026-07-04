import Link from "next/link";
import {
  ArrowLeft,
  Database,
  FileText,
  Fingerprint,
  GitBranch,
  Layers,
  ShieldCheck,
} from "lucide-react";
import { getArtifact, type ArtifactUsageRecord } from "@/lib/api";
import {
  fallbackArtifact,
  formatLabel,
  safeDisplay,
  safeRecordEntries,
} from "@/lib/workbench-detail-data";

type PageProps = {
  params: Promise<{ artifactId: string }>;
};

export default async function ArtifactDetailPage({ params }: PageProps) {
  const { artifactId } = await params;
  const artifact = await getArtifact(artifactId, fallbackArtifact(artifactId));
  const payloadSummary = safeRecordEntries(artifact?.payload_summary);
  const derivedFacts = safeRecordEntries(artifact?.derived_facts);
  const provenance = safeRecordEntries(withoutUsageMetadata(artifact?.provenance));
  const duplicateImports = duplicateImportEntries(artifact?.provenance?.duplicate_imports);
  const usageRecords = usageRecordEntries(
    artifact?.usage_records ?? artifact?.provenance?.usage_records,
  );

  if (!artifact) {
    return (
      <main className="min-h-screen px-5 py-6 sm:px-8 lg:px-10">
        <PageBack />
        <section className="mt-6 border border-[var(--line)] bg-white p-6">
          <h1 className="text-2xl font-semibold text-balance">Artifact not found</h1>
          <p className="mt-2 text-pretty text-[var(--muted)]">{safeDisplay(artifactId)}</p>
        </section>
      </main>
    );
  }

  return (
    <main className="min-h-screen px-5 py-6 sm:px-8 lg:px-10">
      <PageBack />

      <header className="mt-6 border-b border-[var(--line)] pb-6">
        <p className="flex items-center gap-2 text-sm font-semibold text-[var(--accent-strong)]">
          <Database size={17} aria-hidden="true" />
          {safeDisplay(artifact.id)}
        </p>
        <div className="mt-3 flex flex-col gap-4 lg:flex-row lg:items-end lg:justify-between">
          <div>
            <h1 className="max-w-4xl text-3xl font-semibold leading-tight text-balance">
              {safeDisplay(artifact.asset)}
            </h1>
            <p className="mt-2 text-pretty text-[var(--muted)]">
              {formatLabel(artifact.kind)} / {formatLabel(artifact.source_type)}
            </p>
          </div>
          <div className="border border-[var(--line)] bg-white px-4 py-3 text-sm">
            <p className="text-xs font-semibold uppercase text-[var(--muted)]">Ingestion</p>
            <p className="mt-1 font-semibold">{formatLabel(artifact.ingestion_status)}</p>
          </div>
        </div>
      </header>

      <section className="grid gap-3 py-5 sm:grid-cols-2 xl:grid-cols-6">
        <Metric label="Kind" value={formatLabel(artifact.kind)} />
        <Metric label="Source" value={formatLabel(artifact.source_type)} />
        <Metric label="Sensitivity" value={formatLabel(artifact.sensitivity_label)} />
        <Metric label="Summary fields" value={payloadSummary.length} />
        <Metric label="Derived facts" value={derivedFacts.length} />
        <Metric label="Usages" value={usageRecords.length} />
      </section>

      <div className="grid gap-5 xl:grid-cols-[minmax(0,1fr)_360px]">
        <section className="border border-[var(--line)] bg-white">
          <SectionHeader icon={Layers} title="Payload Summary" />
          <KeyValueGrid entries={payloadSummary} empty="No payload summary recorded." />
        </section>

        <aside className="grid content-start gap-5">
          <section className="border border-[var(--line)] bg-white">
            <SectionHeader icon={ShieldCheck} title="Safety Gate" />
            <dl className="grid gap-3 p-5 text-sm">
              <Field label="Sensitivity" value={formatLabel(artifact.sensitivity_label)} />
              <Field label="Redaction" value={formatLabel(artifact.redaction_status)} />
              <Field
                label="Report chain"
                value={artifact.report_chain_allowed ? "Allowed" : "Blocked"}
              />
              <Field
                label="Blockers"
                value={
                  artifact.safety_blockers.length > 0
                    ? artifact.safety_blockers.map(formatSafetyBlocker).join(", ")
                    : "None"
                }
              />
            </dl>
          </section>

          <section className="border border-[var(--line)] bg-white">
            <SectionHeader icon={Fingerprint} title="Provenance" />
            <KeyValueGrid entries={provenance} empty="No provenance summary recorded." />
            {duplicateImports.length > 0 ? (
              <div className="border-t border-[var(--line)] p-5">
                <p className="text-xs font-semibold uppercase text-[var(--muted)]">
                  Duplicate imports
                </p>
                <ul className="mt-3 grid gap-2 text-sm">
                  {duplicateImports.map((entry, index) => (
                    <li
                      key={`${artifact.id}-duplicate-${index}`}
                      className="break-words text-[var(--muted)]"
                    >
                      {entry}
                    </li>
                  ))}
                </ul>
              </div>
            ) : null}
          </section>

          <section className="border border-[var(--line)] bg-white">
            <SectionHeader icon={FileText} title="Derived Facts" />
            <KeyValueGrid entries={derivedFacts} empty="No derived facts recorded." />
          </section>

          <section className="border border-[var(--line)] bg-white">
            <SectionHeader icon={GitBranch} title="Used By" />
            <UsageRecords records={usageRecords} />
          </section>

          <section className="border border-[var(--line)] bg-white">
            <SectionHeader icon={ShieldCheck} title="Digest" />
            <dl className="grid gap-3 p-5 text-sm">
              <Field label="Source hash" value={artifact.source_hash} />
              <Field label="Created" value={artifact.created_at} />
            </dl>
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
      Dashboard
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

function SectionHeader({ icon: Icon, title }: { icon: typeof Database; title: string }) {
  return (
    <div className="flex items-center justify-between border-b border-[var(--line)] px-5 py-4">
      <h2 className="text-lg font-semibold">{title}</h2>
      <Icon size={19} className="text-[var(--accent)]" aria-hidden="true" />
    </div>
  );
}

function KeyValueGrid({ entries, empty }: { entries: [string, string][]; empty: string }) {
  if (entries.length === 0) {
    return <p className="p-5 text-sm text-[var(--muted)]">{empty}</p>;
  }

  return (
    <dl className="grid gap-0 divide-y divide-[var(--line)] text-sm">
      {entries.map(([key, value]) => (
        <div key={key} className="grid gap-2 p-5 md:grid-cols-[180px_minmax(0,1fr)]">
          <dt className="font-semibold">{key}</dt>
          <dd className="break-words text-[var(--muted)]">{value}</dd>
        </div>
      ))}
    </dl>
  );
}

function withoutUsageMetadata(record: Record<string, unknown> | undefined) {
  if (!record) {
    return undefined;
  }

  const rest = { ...record };
  delete rest.duplicate_imports;
  delete rest.usage_records;
  delete rest.safety;
  return rest;
}

function duplicateImportEntries(value: unknown): string[] {
  if (!Array.isArray(value)) {
    return [];
  }

  return value.map((item) => safeDisplay(typeof item === "string" ? item : JSON.stringify(item)));
}

function usageRecordEntries(value: unknown): ArtifactUsageRecord[] {
  if (!Array.isArray(value)) {
    return [];
  }

  return value.filter((item): item is ArtifactUsageRecord => typeof item === "object" && item !== null);
}

function formatSafetyBlocker(value: string): string {
  const knownBlockers: Record<string, string> = {
    contains_secret_like_value: "Contains Secret Like Value",
    contains_real_user_data_risk: "Contains Real User Data Risk",
    missing_safety_metadata: "Missing Safety Metadata",
  };

  return knownBlockers[value] ?? formatLabel(value);
}

function UsageRecords({ records }: { records: ArtifactUsageRecord[] }) {
  if (records.length === 0) {
    return <p className="p-5 text-sm text-[var(--muted)]">No artifact usage recorded.</p>;
  }

  return (
    <ul className="divide-y divide-[var(--line)] text-sm">
      {records.map((record, index) => (
        <li key={`${safeDisplay(record.ref)}-${index}`} className="grid gap-2 p-5">
          <div className="flex flex-wrap items-center gap-2">
            <span className="border border-[var(--line)] px-2 py-1 text-xs font-semibold uppercase text-[var(--muted)]">
              {formatLabel(record.usage_type)}
            </span>
            <span className="font-semibold">{formatLabel(record.stage)}</span>
          </div>
          <p className="break-words text-[var(--muted)]">{safeDisplay(record.ref)}</p>
          <div className="flex flex-wrap gap-2 text-xs text-[var(--muted)]">
            {record.run_id ? <RunLink runId={safeDisplay(record.run_id)} /> : null}
            {record.candidate_id ? <span>{safeDisplay(record.candidate_id)}</span> : null}
            {record.candidate_status ? <span>{formatLabel(record.candidate_status)}</span> : null}
            {record.validation_mode ? <span>{formatLabel(record.validation_mode)}</span> : null}
            {record.refutation_status ? <span>{formatLabel(record.refutation_status)}</span> : null}
            {record.playbook_id ? <span>{formatLabel(record.playbook_id)}</span> : null}
            {typeof record.hunter_priority_score === "number" ? (
              <span>{record.hunter_priority_score} priority</span>
            ) : null}
            {record.learning_signal_id ? <span>{safeDisplay(record.learning_signal_id)}</span> : null}
            {record.outcome ? <span>{formatLabel(record.outcome)}</span> : null}
            {record.surface_key ? <span>{safeDisplay(record.surface_key)}</span> : null}
            {typeof record.bounty_amount === "number" ? (
              <span>{record.bounty_amount} bounty</span>
            ) : null}
            {record.severity_delta ? <span>{formatLabel(record.severity_delta)}</span> : null}
            {record.evidence_quality ? <span>{formatLabel(record.evidence_quality)}</span> : null}
            {record.claim_id ? <span>{safeDisplay(record.claim_id)}</span> : null}
            {record.claim_type ? <span>{formatLabel(record.claim_type)}</span> : null}
            {record.finding_id ? <span>{safeDisplay(record.finding_id)}</span> : null}
            {record.submission_recommendation ? (
              <span>{formatLabel(record.submission_recommendation)}</span>
            ) : null}
            {record.decision ? <span>{formatLabel(record.decision)}</span> : null}
            {record.reviewer ? <span>{safeDisplay(record.reviewer)}</span> : null}
            {record.reviewed_at ? <span>{safeDisplay(record.reviewed_at)}</span> : null}
            {record.observation_id ? <span>{safeDisplay(record.observation_id)}</span> : null}
            {record.observation_type ? <span>{formatLabel(record.observation_type)}</span> : null}
            {record.evidence_type ? <span>{formatLabel(record.evidence_type)}</span> : null}
          </div>
        </li>
      ))}
    </ul>
  );
}

function RunLink({ runId }: { runId: string }) {
  return (
    <Link href={`/runs/${encodeURIComponent(runId)}`} className="font-semibold text-[var(--accent-strong)]">
      {runId}
    </Link>
  );
}

function Field({ label, value }: { label: string; value: unknown }) {
  return (
    <div className="grid gap-1">
      <dt className="text-xs font-semibold uppercase text-[var(--muted)]">{label}</dt>
      <dd className="break-all font-semibold">{safeDisplay(value)}</dd>
    </div>
  );
}
