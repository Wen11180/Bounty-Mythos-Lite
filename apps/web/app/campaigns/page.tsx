import { AlertTriangle, ArrowLeft, ShieldCheck } from "lucide-react";
import { revalidatePath } from "next/cache";
import Link from "next/link";
import { redirect } from "next/navigation";
import { getCampaigns, launchAuthorizedCampaign } from "@/lib/api";
import { campaignBudgetLabel } from "@/lib/campaigns-data";
import { formatLabel, safeDisplay } from "@/lib/workbench-detail-data";

async function launchCampaignAction(formData: FormData) {
  "use server";

  const launched = await launchAuthorizedCampaign({
    allowed_tools: splitList(formData.get("allowed_tools")),
    autonomy_level: formValue(formData, "autonomy_level", "level_0_read_only"),
    authorized_api_artifacts: authorizedApiArtifactsFromForm(formData),
    authorized_code_files: authorizedCodeFilesFromForm(formData),
    budget: {
      time_budget_minutes: numberValue(formData.get("time_budget_minutes")),
      token_budget: numberValue(formData.get("token_budget")),
      tool_call_budget: numberValue(formData.get("tool_call_budget")),
      validation_budget: numberValue(formData.get("validation_budget")),
    },
    created_by: formValue(formData, "created_by", "operator"),
    default_asset: formValue(formData, "default_asset", "authorized.local"),
    name: formValue(formData, "name", "Authorized research campaign"),
    policy_text: formValue(formData, "policy_text", "Authorized testing only."),
    program_id: optionalFormValue(formData.get("program_id")),
    scope_status: formValue(formData, "scope_status", "in_scope"),
    target_classes: splitList(formData.get("target_classes")),
  });

  revalidatePath("/campaigns");

  if (launched) {
    redirect(`/campaigns/${encodeURIComponent(launched.id)}`);
  }
}

export default async function CampaignsPage() {
  const campaigns = await getCampaigns([]);

  return (
    <main className="min-h-screen px-5 py-6 sm:px-8 lg:px-10">
      <PageBack />

      <header className="mt-6 border-b border-[var(--line)] pb-6">
        <p className="flex items-center gap-2 text-sm font-semibold text-[var(--accent-strong)]">
          <ShieldCheck size={17} aria-hidden="true" />
          Campaign Control Center
        </p>
        <h1 className="mt-3 max-w-4xl text-3xl font-semibold leading-tight text-balance">
          Authorized research campaigns
        </h1>
        <p className="mt-2 max-w-2xl text-pretty text-[var(--muted)]">
          Inspect campaign state, blockers, review gates, budgets, and audited agent activity.
        </p>
      </header>

      <section className="mt-6 border border-[var(--line)] bg-white p-5">
        <div className="mb-4 flex items-start justify-between gap-4 border-b border-[var(--line)] pb-4">
          <div>
            <p className="flex items-center gap-2 text-sm font-semibold text-[var(--accent-strong)]">
              <ShieldCheck size={17} aria-hidden="true" />
              Authorized Campaign Launchpad
            </p>
            <p className="mt-2 max-w-3xl text-sm text-[var(--muted)]">
              Scope Guard starts first. Validation, evidence promotion, and report submission stay behind human review gates.
            </p>
          </div>
        </div>
        <form action={launchCampaignAction} className="grid gap-4 lg:grid-cols-2">
          <LaunchField label="Name" name="name" defaultValue="Authorized research campaign" />
          <LaunchField label="Program" name="program_id" defaultValue="program_example" />
          <LaunchField label="Asset" name="default_asset" defaultValue="api.example.com" />
          <label className="grid gap-1 text-sm">
            <span className="text-xs font-semibold uppercase text-[var(--muted)]">Scope</span>
            <select
              name="scope_status"
              defaultValue="in_scope"
              className="min-h-10 rounded-md border border-[var(--line)] bg-white px-3 outline-none focus:border-[var(--accent)]"
            >
              <option value="in_scope">In scope</option>
              <option value="needs_review">Needs review</option>
              <option value="out_of_scope">Out of scope</option>
            </select>
          </label>
          <label className="grid gap-1 text-sm">
            <span className="text-xs font-semibold uppercase text-[var(--muted)]">Autonomy</span>
            <select
              name="autonomy_level"
              defaultValue="level_0_read_only"
              className="min-h-10 rounded-md border border-[var(--line)] bg-white px-3 outline-none focus:border-[var(--accent)]"
            >
              <option value="level_0_read_only">Level 0 read only</option>
              <option value="level_1_local_validation">Level 1 local validation</option>
              <option value="level_2_test_account_validation">Level 2 test-account validation</option>
            </select>
          </label>
          <LaunchField label="Authorized tools" name="allowed_tools" defaultValue="static_analyzer" />
          <LaunchField label="Target classes" name="target_classes" defaultValue="idor" />
          <LaunchField label="Created by" name="created_by" defaultValue="operator" />
          <label className="grid gap-1 text-sm lg:col-span-2">
            <span className="text-xs font-semibold uppercase text-[var(--muted)]">Policy text</span>
            <textarea
              name="policy_text"
              defaultValue="Authorized testing only. No destructive testing, no real user data, no automatic submission."
              className="min-h-28 rounded-md border border-[var(--line)] px-3 py-2 outline-none focus:border-[var(--accent)]"
            />
          </label>
          <LaunchField
            label="Authorized code path"
            name="authorized_code_path"
            defaultValue=""
          />
          <label className="grid gap-1 text-sm">
            <span className="text-xs font-semibold uppercase text-[var(--muted)]">Authorized code snippet</span>
            <textarea
              name="authorized_code_content"
              defaultValue=""
              className="min-h-28 rounded-md border border-[var(--line)] px-3 py-2 font-mono text-xs outline-none focus:border-[var(--accent)]"
            />
          </label>
          <LaunchField
            label="Authorized API artifact kind"
            name="authorized_api_artifact_kind"
            defaultValue=""
          />
          <LaunchField
            label="Authorized API artifact source"
            name="authorized_api_artifact_source"
            defaultValue=""
          />
          <label className="grid gap-1 text-sm lg:col-span-2">
            <span className="text-xs font-semibold uppercase text-[var(--muted)]">Authorized API/HAR JSON</span>
            <textarea
              name="authorized_api_artifact_payload"
              defaultValue=""
              className="min-h-32 rounded-md border border-[var(--line)] px-3 py-2 font-mono text-xs outline-none focus:border-[var(--accent)]"
            />
          </label>
          <div className="grid gap-3 sm:grid-cols-4 lg:col-span-2">
            <LaunchField label="Minutes" name="time_budget_minutes" defaultValue="30" inputMode="numeric" />
            <LaunchField label="Tokens" name="token_budget" defaultValue="5000" inputMode="numeric" />
            <LaunchField label="Tool calls" name="tool_call_budget" defaultValue="10" inputMode="numeric" />
            <LaunchField label="Validations" name="validation_budget" defaultValue="1" inputMode="numeric" />
          </div>
          <button
            type="submit"
            className="inline-flex min-h-10 items-center justify-center gap-2 rounded-md border border-[var(--line)] bg-[var(--foreground)] px-4 text-sm font-semibold text-white lg:col-span-2"
          >
            <ShieldCheck size={17} aria-hidden="true" />
            Create and start safe campaign
          </button>
        </form>
      </section>

      {campaigns.length === 0 ? (
        <section className="mt-6 border border-[var(--line)] bg-white p-6">
          <p className="flex items-center gap-2 text-sm font-semibold text-[var(--warning)]">
            <AlertTriangle size={17} aria-hidden="true" />
            No campaign audit feed
          </p>
          <p className="mt-2 max-w-2xl text-pretty text-[var(--muted)]">
            Launch an authorized campaign to populate the operator console.
          </p>
        </section>
      ) : (
        <section className="mt-5 border border-[var(--line)] bg-white">
          <div className="grid gap-3 border-b border-[var(--line)] px-5 py-4 text-sm font-semibold text-[var(--muted)] md:grid-cols-[minmax(0,1fr)_140px_140px_180px_160px]">
            <span>Campaign</span>
            <span>Status</span>
            <span>Scope</span>
            <span>Budget</span>
            <span>Autonomy</span>
          </div>
          <div className="divide-y divide-[var(--line)]">
            {campaigns.map((campaign) => (
              <Link
                key={campaign.id}
                href={`/campaigns/${encodeURIComponent(campaign.id)}`}
                className="grid gap-3 px-5 py-4 text-sm md:grid-cols-[minmax(0,1fr)_140px_140px_180px_160px]"
              >
                <span className="min-w-0">
                  <span className="block break-words font-semibold">{safeDisplay(campaign.name)}</span>
                  <span className="mt-1 block break-words text-[var(--muted)]">
                    {safeDisplay(campaign.default_asset)}
                  </span>
                </span>
                <StatusText value={campaign.status} />
                <StatusText value={campaign.scope_status} />
                <span className="break-words font-semibold">{campaignBudgetLabel(campaign.budget)}</span>
                <StatusText value={campaign.autonomy_level} />
              </Link>
            ))}
          </div>
        </section>
      )}
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

function StatusText({ value }: { value: string }) {
  return <span className="break-words font-semibold">{formatLabel(value)}</span>;
}

function LaunchField({
  defaultValue,
  inputMode,
  label,
  name,
}: {
  defaultValue: string;
  inputMode?: "numeric";
  label: string;
  name: string;
}) {
  return (
    <label className="grid gap-1 text-sm">
      <span className="text-xs font-semibold uppercase text-[var(--muted)]">{label}</span>
      <input
        name={name}
        defaultValue={defaultValue}
        inputMode={inputMode}
        className="min-h-10 rounded-md border border-[var(--line)] px-3 outline-none focus:border-[var(--accent)]"
      />
    </label>
  );
}

function formValue(formData: FormData, key: string, fallback: string): string {
  return optionalFormValue(formData.get(key)) ?? fallback;
}

function optionalFormValue(value: FormDataEntryValue | null): string | undefined {
  const text = typeof value === "string" ? value.trim() : "";
  return text || undefined;
}

function splitList(value: FormDataEntryValue | null): string[] {
  const text = typeof value === "string" ? value : "";
  return text
    .split(",")
    .map((item) => item.trim())
    .filter(Boolean);
}

function authorizedCodeFilesFromForm(formData: FormData): Array<{ content: string; path: string }> {
  const path = optionalFormValue(formData.get("authorized_code_path"));
  const content = optionalFormValue(formData.get("authorized_code_content"));
  if (!path || !content) {
    return [];
  }
  return [{ content, path }];
}

function authorizedApiArtifactsFromForm(
  formData: FormData,
): Array<{ kind: string; payload: Record<string, unknown>; source_name?: string | null }> {
  const kind = optionalFormValue(formData.get("authorized_api_artifact_kind"));
  const payloadText = optionalFormValue(formData.get("authorized_api_artifact_payload"));
  if (!kind || !payloadText) {
    return [];
  }
  const payload = jsonObjectValue(payloadText);
  if (!payload) {
    return [];
  }
  return [
    {
      kind,
      payload,
      source_name: optionalFormValue(formData.get("authorized_api_artifact_source")) ?? null,
    },
  ];
}

function jsonObjectValue(value: string): Record<string, unknown> | null {
  try {
    const parsed = JSON.parse(value);
    return parsed && typeof parsed === "object" && !Array.isArray(parsed) ? parsed : null;
  } catch {
    return null;
  }
}

function numberValue(value: FormDataEntryValue | null): number | undefined {
  const text = typeof value === "string" ? value.trim() : "";
  if (!text) {
    return undefined;
  }
  const parsed = Number.parseInt(text, 10);
  return Number.isFinite(parsed) && parsed >= 0 ? parsed : undefined;
}
