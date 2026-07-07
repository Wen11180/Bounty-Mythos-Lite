export type StudioWorkspaceManifest = {
  name?: string;
  artifacts?: Array<{
    kind?: string;
    source_path?: string;
    redaction_status?: string;
  }>;
  runs?: Array<{
    run_id?: string;
    status?: string;
    candidate_count?: number;
  }>;
  safety?: {
    scope_guard_status?: string;
    blocked_actions?: string[];
  };
};

export type StudioWorkspaceSummary = {
  name: string;
  artifactCount: number;
  runCount: number;
  scopeGuardLabel: string;
  blockedActions: string[];
};

export type StudioCandidateInput = {
  hypothesis_id?: string;
  vuln_type?: string;
  risk?: string;
  location?: string;
  reason?: string;
  evidence_needed?: string[];
  false_positive_checks?: string[];
  ranking_reasons?: string[];
  safe_validation_plan?: string[];
  safe_verification?: boolean;
  safety_blockers?: string[];
  priority_score?: number;
  validation_mode?: string;
  source_facts?: Array<{
    advisory_only?: string;
    artifact_kind?: string;
    fact_type?: string;
    operation_id?: string;
    route_method?: string;
    route_path?: string;
    source_path?: string;
    symbol_name?: string;
  }>;
};

export type StudioCandidateCard = {
  id: string;
  title: string;
  severity: string;
  status: "needs_review" | "blocked" | "needs_evidence";
  affectedEndpoint: string;
  affectedCodePath: string;
  evidenceNeeds: string[];
  refutationQuestions: string[];
  rankingReasons: string[];
  reason: string;
  safeValidationPlan: string[];
  safetyBlockers: string[];
  priorityScore: number;
  validationMode: string;
};

export function toStudioWorkspaceSummary(
  manifest: StudioWorkspaceManifest,
): StudioWorkspaceSummary {
  return {
    name: safeText(manifest.name, "Untitled workspace"),
    artifactCount: manifest.artifacts?.length ?? 0,
    runCount: manifest.runs?.length ?? 0,
    scopeGuardLabel: scopeGuardLabel(manifest.safety?.scope_guard_status),
    blockedActions: manifest.safety?.blocked_actions ?? [],
  };
}

export function toStudioCandidateCards(candidates: StudioCandidateInput[]): StudioCandidateCard[] {
  return candidates.slice(0, 5).map((candidate, index) => {
    const endpoint = endpointFromCandidate(candidate);
    const codePath = codePathFromCandidate(candidate);

    return {
      id: safeText(candidate.hypothesis_id, `H-${String(index + 1).padStart(3, "0")}`),
      title: safeText(candidate.vuln_type, "Candidate hypothesis"),
      severity: safeText(candidate.risk, "medium"),
      status: candidate.safe_verification === false
        ? "blocked"
        : endpoint && codePath
          ? "needs_evidence"
          : "needs_review",
      affectedEndpoint: endpoint || "Endpoint needs review",
      affectedCodePath: codePath || "Code path needs review",
      evidenceNeeds: candidate.evidence_needed ?? [],
      refutationQuestions: candidate.false_positive_checks ?? [],
      rankingReasons: candidate.ranking_reasons ?? [],
      reason: safeText(candidate.reason, "Review rationale unavailable."),
      safeValidationPlan: candidate.safe_validation_plan ?? [],
      safetyBlockers: candidate.safety_blockers ?? [],
      priorityScore: candidate.priority_score ?? 0,
      validationMode: safeText(candidate.validation_mode, "manual_review"),
    };
  });
}

function endpointFromCandidate(candidate: StudioCandidateInput): string {
  const route = candidate.source_facts?.find((fact) => fact.route_path)?.route_path;
  return route || safeText(candidate.location, "");
}

function codePathFromCandidate(candidate: StudioCandidateInput): string {
  const fact = candidate.source_facts?.find((item) => item.source_path || item.symbol_name);
  if (!fact) {
    return "";
  }
  return [fact.source_path, fact.symbol_name].filter(Boolean).join(":");
}

function scopeGuardLabel(value: string | undefined): string {
  if (value === "scope_imported") {
    return "Scope imported";
  }
  if (value === "allowed") {
    return "Allowed";
  }
  if (value === "blocked") {
    return "Blocked";
  }
  return "Missing scope";
}

function safeText(value: unknown, fallback: string): string {
  return typeof value === "string" && value.trim() ? value : fallback;
}
