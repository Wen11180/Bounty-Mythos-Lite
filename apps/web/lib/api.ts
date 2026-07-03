const API_BASE_URL = process.env.NEXT_PUBLIC_API_BASE_URL ?? "http://localhost:8000";

export type ScopeStatus = "in_scope" | "out_of_scope" | "needs_review";
export type PolicyStatus = "allowed" | "blocked" | "needs_review";
export type ValidationStatus =
  | "candidate"
  | "plausible"
  | "policy_checked"
  | "validation_plan_ready"
  | "human_approved"
  | "safely_validated"
  | "refuted_or_confirmed"
  | "report_ready"
  | "human_submitted"
  | "accepted"
  | "duplicate"
  | "informative"
  | "na"
  | "learned";

export type Program = {
  id: string;
  name: string;
  platform: string;
  bounty_range: string;
  scope_status: ScopeStatus;
  automation: string;
  testing_accounts: string;
  api_docs: string;
  public_code: string;
  duplicate_risk: string;
  priority: string;
};

export type Finding = {
  id: string;
  program: string;
  asset: string;
  title: string;
  vuln_type: string;
  severity_estimate: string;
  confidence: number;
  scope_status: ScopeStatus;
  policy_status: PolicyStatus;
  broken_invariant: string;
  validation_status: ValidationStatus;
  refutation_status: string;
  duplicate_likelihood: string;
  submission_recommendation: string;
  evidence_refs: string[];
};

export type ReportDraft = {
  id: string;
  finding_id: string;
  title: string;
  draft: string;
};

async function apiGet<T>(path: string, fallback: T): Promise<T> {
  try {
    const response = await fetch(new URL(path, API_BASE_URL), { cache: "no-store" });

    if (!response.ok) {
      return fallback;
    }

    return (await response.json()) as T;
  } catch {
    return fallback;
  }
}

export function getPrograms(fallback: Program[]): Promise<Program[]> {
  return apiGet("/programs", fallback);
}

export function getFindings(fallback: Finding[]): Promise<Finding[]> {
  return apiGet("/findings", fallback);
}

export function getReports(fallback: ReportDraft[]): Promise<ReportDraft[]> {
  return apiGet("/reports", fallback);
}
