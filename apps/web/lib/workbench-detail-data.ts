import type {
  ArtifactRecord,
  PipelineArtifactProvenance,
  PipelineRunDetail,
  PipelineValidationGate,
  ReportPreview,
  ValidationWorkspace,
} from "./api";
import {
  fallbackPipelineRuns,
  type PipelineRunSummary,
  type PipelineRunStageSummary,
} from "./pipeline-runs-data";
export { formatLabel, safeDisplay, safeRecordEntries, safeStringList } from "./workbench-display";
import { safeDisplay } from "./workbench-display";

const FALLBACK_DATE = "2026-07-03T00:00:00.000Z";

export function findFallbackRunSummary(runId: string): PipelineRunSummary | null {
  return fallbackPipelineRuns.find((run) => run.runId === runId) ?? null;
}

export function fallbackRunDetail(runId: string): PipelineRunDetail | null {
  const summary = findFallbackRunSummary(runId);

  if (!summary) {
    return null;
  }

  const artifact = fallbackArtifactSummary(summary);
  const validationGate = fallbackValidationGate(summary);
  const validationWorkspace = fallbackValidationWorkspace(summary);

  return {
    id: summary.runId,
    asset: summary.asset,
    policy_text_hash: "fallback-only",
    scope_status: validationGate.status === "blocked" ? "needs_review" : "in_scope",
    hypothesis_count: summary.hypothesisCount,
    blocked_count: summary.blockedCount,
    evidence_count: summary.evidenceCount,
    report_title: summary.reportTitle,
    created_at: FALLBACK_DATE,
    timeline: summary.stages.map(toApiStage),
    artifact,
    validation_gate: validationGate,
    hunter_intelligence: {
      top_recommendation: summary.hunter.recommendation,
      assessments: [
        {
          playbook_label: summary.hunter.playbook,
          hunter_priority_score: summary.hunter.priorityScore,
          impact_score: summary.hunter.impactScore,
          rejection_risk_score: summary.hunter.rejectionRiskScore,
          recommendation: summary.hunter.recommendation,
          next_action: summary.hunter.nextAction,
          safety_notes: ["no_live_requests", "human_review_required", "test_accounts_only"],
        },
      ],
    },
    payload: {
      artifact,
      validation_workspace: validationWorkspace,
      validation_gate: validationGate,
      closed_loop_summary: {
        status: "not_started",
        manual_observation_count: 0,
        reviewed_claim_count: 0,
        finding_candidate_count: 0,
        learning_signal_count: 0,
        lesson_count: 0,
        brain_memory_status: "waiting_for_learning",
        memory_lessons: [],
        blocked_reasons: [],
        safety_notes: [
          "no_live_requests",
          "test_accounts_only",
          "human_review_required",
          "candidate_not_validated",
        ],
        steps: [
          {
            key: "manual_observation",
            label: "Manual Observation",
            status: "waiting",
            reason: "No sanitized manual observation recorded yet.",
            safety_gate: "test_accounts_only",
            next_allowed_action: "Record a sanitized manual observation.",
          },
          {
            key: "claim_review",
            label: "Claim Review",
            status: "waiting",
            reason: "No human claim review decision recorded yet.",
            safety_gate: "human_review_required",
            next_allowed_action: "Review the observed claim with redacted evidence.",
          },
          {
            key: "finding_candidate",
            label: "Finding Candidate",
            status: "waiting",
            reason: "No finding candidate created yet.",
            safety_gate: "candidate_not_validated",
            next_allowed_action: "Create a candidate from a review-ready observed claim.",
          },
          {
            key: "learning_signal",
            label: "Learning Signal",
            status: "waiting",
            reason: "No advisory learning signal linked yet.",
            safety_gate: "advisory_memory_only",
            next_allowed_action: "Record an accepted, duplicate, informative, N/A, or rejected outcome.",
          },
          {
            key: "brain_memory",
            label: "Brain Memory",
            status: "waiting",
            reason: "Program brain is waiting for a learning signal.",
            safety_gate: "no_execution_permission",
            next_allowed_action: "Keep the candidate gated until outcome memory exists.",
          },
        ],
      },
      report_draft: {
        title: summary.reportTitle ?? "Fallback report preview",
        severity: "medium",
        scope_status: validationGate.status,
        safety_notes: ["human_review_required", "test_accounts_only", "non_destructive_validation_only"],
        steps: validationWorkspace.steps?.map((step) => safeDisplay(step.instruction)),
        expected_result: "The protected security boundary should hold.",
        actual_result: "To be filled after safe validation evidence is reviewed.",
        human_review_required: true,
      },
      evidence_bundle: {
        finding_id: summary.runId,
        summary: `${summary.evidenceCount} fallback evidence item(s) attached.`,
        items: [],
        safety_notes: ["test_accounts_only", "no_real_user_data"],
      },
    },
  };
}

export function fallbackArtifact(artifactId: string): ArtifactRecord | null {
  const run = fallbackPipelineRuns.find((item) => item.artifact.artifactId === artifactId);

  if (!run) {
    return null;
  }

  return {
    id: artifactId,
    program_id: null,
    asset: run.asset,
    kind: run.artifact.kind,
    source_type: "fallback_summary",
    source_hash: "fallback-only",
    ingestion_status: "summarized",
    provenance: {
      source: run.artifact.source,
      provenance: run.artifact.provenance,
      safety: {
        sensitivity_label: "low",
        redaction_status: "clean",
        report_chain_allowed: true,
        safety_blockers: [],
      },
    },
    payload_summary: {
      evidence_count: run.artifact.evidenceCount,
      linked_run: run.runId,
    },
    derived_facts: {
      report_title: run.reportTitle,
      validation_gate: run.validationGate.label,
    },
    sensitivity_label: "low",
    redaction_status: "clean",
    report_chain_allowed: true,
    safety_blockers: [],
    usage_records: [],
    created_at: FALLBACK_DATE,
  };
}

export function fallbackArtifacts(): ArtifactRecord[] {
  return fallbackPipelineRuns
    .map((run) => fallbackArtifact(run.artifact.artifactId ?? ""))
    .filter((artifact): artifact is ArtifactRecord => artifact !== null);
}

export function fallbackReportPreview(runId: string): ReportPreview | null {
  const summary = findFallbackRunSummary(runId);

  if (!summary) {
    return null;
  }

  const evidenceRefs = summary.evidenceCount > 0 ? [`${summary.evidenceCount} evidence item(s)`] : [];
  const validationBlockers =
    summary.validationGate.status === "approved" ? [] : ["validation_gate_not_approved"];
  const evidenceBlockers = evidenceRefs.length > 0 ? [] : ["missing_evidence_refs"];

  return {
    run_id: summary.runId,
    title: summary.reportTitle ?? "Fallback report preview",
    severity: "medium",
    scope_status: summary.validationGate.status,
    human_review_required: true,
    submission_blocked: true,
    claim_labels: {
      observed_facts: "observed_fact",
      model_reasoning: "model_reasoning",
      unverified_claims: "unverified_claim",
    },
    sections: {
      observed_facts: [
        `Pipeline run ${summary.runId} targets ${summary.asset}.`,
        `${summary.evidenceCount} sanitized evidence item(s) are attached.`,
      ],
      model_reasoning: summary.stages.map((stage) => stage.detail),
      unverified_claims: [
        "Validation evidence still requires human review before submission.",
        summary.validationGate.approval,
      ],
    },
    claim_ledger: [
      {
        claim_id: "claim_observed_fact_1",
        claim_type: "observed_fact",
        text: `Pipeline run ${summary.runId} targets ${summary.asset}.`,
        status: "needs_human_review",
        quality_score: evidenceRefs.length > 0 ? 100 : 65,
        quality_reasons: [
          "type:observed_fact",
          evidenceRefs.length > 0 ? "has_evidence_refs" : "missing_evidence_refs",
          "has_provenance_refs",
          "redaction:redacted",
          "review:confirmed_observed_fact",
          ...(evidenceRefs.length > 0 ? ["review:evidence_refs"] : []),
          "gate:human_review_required",
        ],
        readiness_level: "human_reviewed_gated",
        evidence_refs: evidenceRefs,
        provenance_refs: [`run:${summary.runId}`],
        redaction_status: "redacted",
        human_review_required: true,
        readiness_blockers: ["human_review_required", ...validationBlockers, ...evidenceBlockers],
        review_status: "confirmed_observed_fact",
        reviewer: "lead_reviewer",
        review_rationale: "Safe fixture observation reviewed; submission remains blocked.",
        reviewed_at: FALLBACK_DATE,
        review_evidence_refs: evidenceRefs,
      },
      {
        claim_id: "claim_model_reasoning_1",
        claim_type: "model_reasoning",
        text: summary.stages[0]?.detail ?? "Candidate reasoning requires validation.",
        status: "model_reasoning_only",
        quality_score: 10,
        quality_reasons: [
          "type:model_reasoning",
          "missing_evidence_refs",
          "has_provenance_refs",
          "redaction:redacted",
          "review:not_reportable",
          "gate:human_review_required",
        ],
        readiness_level: "model_reasoning_only",
        evidence_refs: [],
        provenance_refs: ["hypothesis_engine"],
        redaction_status: "redacted",
        human_review_required: true,
        readiness_blockers: [
          "model_reasoning_not_observed_fact",
          "missing_evidence_refs",
          "human_review_required",
          ...validationBlockers,
        ],
        review_status: "not_reportable",
        reviewer: "lead_reviewer",
        review_rationale: "Model reasoning is useful triage context, not a report fact.",
        reviewed_at: FALLBACK_DATE,
        review_evidence_refs: [],
      },
      {
        claim_id: "claim_unverified_claim_1",
        claim_type: "unverified_claim",
        text: "Validation evidence still requires human review before submission.",
        status: "blocked",
        quality_score: 20,
        quality_reasons: [
          "type:unverified_claim",
          "missing_evidence_refs",
          "has_provenance_refs",
          "redaction:redacted",
          "review:needs_evidence",
          "gate:human_review_required",
        ],
        readiness_level: "unverified_claim",
        evidence_refs: [],
        provenance_refs: ["report_draft", "validation_gate"],
        redaction_status: "redacted",
        human_review_required: true,
        readiness_blockers: [
          "unverified_claim_not_observed_fact",
          "missing_evidence_refs",
          "human_review_required",
          ...validationBlockers,
        ],
        review_status: "needs_evidence",
        reviewer: null,
        review_rationale: "Needs redacted evidence and provenance before report use.",
        reviewed_at: null,
        review_evidence_refs: [],
      },
    ],
    safety_notes: ["human_review_required", "test_accounts_only", "non_destructive_validation_only"],
    evidence_refs: evidenceRefs,
  };
}

function toApiStage(stage: PipelineRunStageSummary) {
  return {
    name: stage.label.toLowerCase().replace(/\s+/g, "_"),
    status: stage.status,
    input_summary: stage.detail,
    output_summary: stage.detail,
    safety_notes: ["no_live_requests"],
    evidence_count: stage.evidenceCount,
    details: {
      agent_boundary: fallbackStageBoundary(stage),
    },
  };
}

function fallbackStageBoundary(stage: PipelineRunStageSummary) {
  const label = stage.label.toLowerCase();

  return {
    role: label.includes("artifact")
      ? "Artifact Agent"
      : label.includes("scope")
        ? "Scope Guard Agent"
        : label.includes("hypothesis")
          ? "Hypothesis Agent"
          : label.includes("validation")
            ? "Validation Planner Agent"
            : label.includes("evidence")
              ? "Evidence Agent"
              : "Bounded Agent",
    allowed_actions: [
      label.includes("validation")
        ? "draft_non_destructive_manual_steps"
        : "summarize_authorized_records",
    ],
    blocked_actions: [
      "execute_live_validation",
      "touch_real_user_data",
      "submit_report",
      "bypass_scope_guard",
    ],
    requires_human_review: ["blocked", "needs_review", "waiting_human"].includes(stage.status),
  };
}

function fallbackArtifactSummary(summary: PipelineRunSummary): PipelineArtifactProvenance {
  return {
    artifact_id: summary.artifact.artifactId ?? undefined,
    kind: summary.artifact.kind,
    source_type: "fallback_summary",
    source: summary.artifact.source,
    provenance: summary.artifact.provenance,
    summary: summary.artifact.provenance,
    evidence_count: summary.artifact.evidenceCount,
    digest: "fallback-only",
    sensitivity_label: "low",
    redaction_status: "clean",
    report_chain_allowed: true,
    safety_blockers: [],
  };
}

function fallbackValidationGate(summary: PipelineRunSummary): PipelineValidationGate {
  return {
    status: summary.validationGate.status,
    label: summary.validationGate.label,
    approval_required: summary.validationGate.status !== "approved",
    approved_by: null,
    summary: summary.validationGate.approval,
    evidence_count: summary.validationGate.evidenceCount,
  };
}

function fallbackValidationWorkspace(summary: PipelineRunSummary): ValidationWorkspace {
  const blocked = summary.validationGate.status !== "approved";

  return {
    status: blocked ? "awaiting_approval" : "ready_for_human_controlled_validation",
    scope_decision: { allowed: !blocked, reason: summary.validationGate.status },
    validation_plan_status: blocked ? "blocked" : "validation_plan_ready",
    refutation_status: blocked ? "blocked" : "passed",
    blocked_reasons: blocked ? ["human_approval_required"] : [],
    human_approval_required: true,
    allowed_to_execute: false,
    test_accounts_only: true,
    no_real_user_data: true,
    non_destructive_only: true,
    approval_gate: {
      human_approval_required: true,
      human_approved: false,
      status: summary.validationGate.status,
      reason: summary.validationGate.approval,
    },
    steps: [
      {
        instruction: summary.hunter.nextAction,
        method: "manual_preparation",
        status: blocked ? "awaiting_approval" : "ready",
        evidence_hints: [{ type: "evidence_needed", purpose: summary.artifact.provenance }],
      },
    ],
    evidence_hints: [{ type: "evidence_needed", purpose: summary.artifact.provenance }],
    manual_observations: [
      {
        observation_id: `manual_observation_${summary.runId}`,
        claim_id: "claim_observed_fact_1",
        observation_type: "manual_observation",
        observer: "lead_reviewer",
        observation: "Safe fixture observation recorded; no live execution was performed.",
        evidence_refs: summary.evidenceCount > 0 ? [`${summary.evidenceCount} evidence item(s)`] : [],
        safety_notes: ["test_accounts_only", "no_real_user_data", "human_review_required"],
        redaction_status: "redacted",
        execution_allowed: false,
        report_chain_blocked: true,
        created_at: FALLBACK_DATE,
      },
    ],
  };
}
