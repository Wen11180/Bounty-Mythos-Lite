import type {
  CampaignAgentRun,
  CampaignApproval,
  CampaignCodebaseMap,
  CampaignControlCenter,
  CampaignPipelineStage,
  CampaignResearchRefutationDecision,
  CampaignResearchTaskReview,
  CampaignTask,
  CampaignValidationRun,
} from "./campaigns-data";
import type {
  StudioAgentHandoffPackInput,
  StudioCandidateHunterExecutionLoopInput,
  StudioCandidateHunterPlanInput,
  StudioCandidateHunterReviewLoopInput,
  StudioCandidateInput,
  StudioMissionSummary,
  StudioWorkspaceManifest,
} from "./studio-data";

const API_BASE_URL =
  process.env.API_BASE_URL ?? process.env.NEXT_PUBLIC_API_BASE_URL ?? "http://localhost:8000";

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

export type CampaignListItem = CampaignControlCenter["campaign"] & {
  budget?: CampaignControlCenter["budget"];
  policy_text_hash?: string;
};

export type AuthorizedCampaignLaunchInput = {
  allowed_tools: string[];
  autonomy_level: string;
  authorized_api_artifacts?: Array<{
    kind: string;
    payload: Record<string, unknown>;
    source_name?: string | null;
  }>;
  authorized_code_files?: Array<{
    content: string;
    path: string;
  }>;
  budget?: {
    time_budget_minutes?: number;
    token_budget?: number;
    tool_call_budget?: number;
    validation_budget?: number;
  };
  created_by: string;
  default_asset: string;
  name: string;
  policy_text: string;
  program_id?: string;
  scope_status: string;
  target_classes: string[];
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
  operating_reasons: string[];
};

export type ReportDraft = {
  id: string;
  finding_id: string;
  title: string;
  draft: string;
};

export type ScopeGuardRule = {
  asset: string;
  scope_status: ScopeStatus;
  automation: string;
  allowed_validation: string[];
  forbidden: string[];
  human_approval_required: boolean;
};

export type ScopeGuardRequest = {
  asset: string;
  validation_type: string;
  human_approved: boolean;
};

export type ScopeGuardDecision = {
  allowed: boolean;
  reason: string;
};

export type PipelineStage = {
  name?: string;
  label?: string;
  stage?: string;
  status?: string;
  summary?: string;
  input_summary?: string;
  output_summary?: string;
  safety_notes?: string[];
  evidence_count?: number;
  details?: {
    agent_boundary?: PipelineStageAgentBoundary;
    lesson_traces?: unknown;
    [key: string]: unknown;
  };
};

export type PipelineStageAgentBoundary = {
  role?: string;
  allowed_actions?: string[];
  blocked_actions?: string[];
  requires_human_review?: boolean;
};

export type PipelineTargetModel = {
  endpoints?: unknown[];
  objects?: unknown[];
  sensitive_actions?: unknown[];
  roles?: string[];
};

export type PipelineInvariant = {
  rule_id?: string;
  invariant?: string;
  objects?: string[];
  actions?: string[];
  risk_level?: string;
  policy_risk?: string;
};

export type PipelineHypothesis = {
  hypothesis?: string;
  vuln_type?: string;
  broken_invariant?: string;
  evidence_needed?: string[];
  false_positive_checks?: string[];
  refutation_status?: string;
  priority_score?: number;
  ranking_reasons?: string[];
  source_facts?: {
    fact_type?: string;
    [key: string]: unknown;
  }[];
  validation_mode?: string;
  risk_level?: string;
  policy_risk?: string;
};

export type PipelineRefutation = {
  status?: string;
  reasons?: string[];
  questions?: string[];
  human_review_required?: boolean;
};

export type PipelineExploitChain = {
  primitives?: string[];
  preconditions?: string[];
  impact?: string;
  confidence?: number;
  safety_notes?: string[];
};

export type PipelineValidationPlan = {
  status?: string;
  methods?: string[];
  steps?: string[];
  human_approval_required?: boolean;
};

export type EvidenceItem = {
  type?: string;
  content?: unknown;
};

export type EvidenceBundle = {
  finding_id?: string;
  summary?: string;
  items?: EvidenceItem[];
  safety_notes?: string[];
};

export type ValidationWorkspaceEvidenceHint = {
  type?: string;
  purpose?: string;
  [key: string]: unknown;
};

export type ValidationWorkspaceApprovalGate = {
  human_approval_required?: boolean;
  human_approved?: boolean;
  status?: string;
  reason?: string;
};

export type ValidationWorkspaceStep = {
  instruction?: string;
  method?: string;
  status?: string;
  evidence_hints?: ValidationWorkspaceEvidenceHint[];
};

export type ManualObservation = {
  observation_id: string;
  claim_id: string;
  observation_type: string;
  observer: string;
  observation: string;
  evidence_refs: string[];
  safety_notes: string[];
  redaction_status: string;
  execution_allowed: boolean;
  report_chain_blocked: boolean;
  created_at: string;
};

export type ValidationWorkspaceClaimTask = {
  claim_id: string;
  claim_type: string;
  claim_text: string;
  status: string;
  promotion_eligible: boolean;
  required_observation_types: string[];
  relationship_contexts?: string[];
  evidence_focus?: string[];
  evidence_refs: string[];
  review_evidence_refs: string[];
  readiness_blockers: string[];
  quality_reasons: string[];
  quality_score: number;
  readiness_level: string;
  review_status: string;
  human_review_required: boolean;
  execution_allowed?: boolean;
  safety_notes?: string[];
};

export type ValidationWorkspace = {
  status?: string;
  scope_decision?: Record<string, unknown>;
  validation_plan_status?: string;
  refutation_status?: string;
  blocked_reasons?: string[];
  human_approval_required?: boolean;
  allowed_to_execute?: boolean;
  test_accounts_only?: boolean;
  no_real_user_data?: boolean;
  non_destructive_only?: boolean;
  approval_gate?: ValidationWorkspaceApprovalGate;
  steps?: ValidationWorkspaceStep[];
  evidence_hints?: ValidationWorkspaceEvidenceHint[];
  manual_observations?: ManualObservation[];
  claim_validation_tasks?: ValidationWorkspaceClaimTask[];
};

export type ClosedLoopSummary = {
  status: string;
  manual_observation_count: number;
  reviewed_claim_count: number;
  finding_candidate_count: number;
  learning_signal_count: number;
  lesson_count?: number;
  brain_memory_status?: string;
  reasoning_context?: ClosedLoopReasoningContext;
  memory_lessons?: ClosedLoopMemoryLesson[];
  blocked_reasons: string[];
  safety_notes: string[];
  steps?: ClosedLoopStep[];
};

export type ClosedLoopReasoningContext = {
  source: string;
  highest_reasoning_review_score: number;
  learning_signal_context_count: number;
  safety_gate: string;
};

export type ClosedLoopMemoryLesson = {
  lesson_id: string;
  scope_type: string;
  scope_key: string;
  playbook_id: string;
  surface_pattern: string;
  recommendation: string;
  confidence: number;
  source_signal_count: number;
  source_signal_ids: string[];
  reasons: string[];
  safety_notes: string[];
};

export type ClosedLoopStep = {
  key: string;
  label: string;
  status: string;
  reason: string;
  safety_gate: string;
  next_allowed_action: string;
};

export type EvidenceSupportSummary = {
  total_count: number;
  status_counts: Record<string, number>;
  missing_required_count: number;
  partially_supported_count: number;
  satisfied_human_gated_count: number;
  unsafe_or_redacted_requirement_count: number;
  top_support_status?: string | null;
  safety_notes: string[];
};

export type PipelineArtifactProvenance = {
  artifact_id?: string;
  artifact_type?: string;
  kind?: string;
  provenance?: string;
  repository?: string;
  source?: string;
  source_type?: string;
  summary?: string;
  evidence_count?: number;
  digest?: string;
  sensitivity_label?: string;
  redaction_status?: string;
  report_chain_allowed?: boolean;
  safety_blockers?: string[];
};

export type ArtifactUsageRecord = {
  usage_type?: string;
  ref?: string;
  run_id?: string;
  stage?: string;
  candidate_id?: string;
  candidate_index?: number;
  candidate_status?: string;
  validation_mode?: string;
  refutation_status?: string;
  playbook_id?: string;
  hunter_priority_score?: number | null;
  learning_signal_id?: string;
  outcome?: string;
  surface_key?: string | null;
  bounty_amount?: number | null;
  severity_delta?: string | null;
  evidence_quality?: string | null;
  evidence_type?: string;
  claim_id?: string;
  claim_type?: string;
  finding_id?: string;
  submission_recommendation?: string;
  decision?: string;
  reviewer?: string;
  reviewed_at?: string;
  observation_id?: string;
  observation_type?: string;
  evidence_refs?: string[];
  safety_notes?: string[];
  [key: string]: unknown;
};

export type PipelineValidationGate = {
  status?: string;
  decision?: string;
  label?: string;
  approval_required?: boolean;
  approved_by?: string | null;
  summary?: string;
  evidence_count?: number;
};

export type HunterAssessment = {
  hypothesis?: string;
  playbook_id?: string;
  playbook_label?: string;
  hunter_priority_score?: number;
  impact_score?: number;
  duplicate_risk_score?: number;
  policy_risk_score?: number;
  rejection_risk_score?: number;
  recommendation?: string;
  next_action?: string;
  reasons?: string[];
  evidence_focus?: string[];
  safety_notes?: string[];
};

export type HunterIntelligence = {
  top_recommendation?: string;
  assessments?: HunterAssessment[];
};

export type HypothesisLifecycleAssessment = {
  candidate_id?: string;
  hypothesis_index?: number;
  hypothesis?: PipelineHypothesis;
  scope_decision?: ScopeGuardDecision;
  refutation?: PipelineRefutation;
  exploit_chain?: PipelineExploitChain;
  validation_plan?: PipelineValidationPlan;
  report_draft?: ReportDraftCandidate;
  evidence_hints?: ValidationWorkspaceEvidenceHint[];
  hunter_assessment?: HunterAssessment | null;
  candidate_status?: string;
};

export type ReportDraftCandidate = {
  title?: string;
  severity?: string;
  scope_status?: string;
  safety_notes?: string[];
  steps?: string[];
  expected_result?: string;
  actual_result?: string;
  human_review_required?: boolean;
};

export type PipelineRunPayload = {
  program_id?: string | null;
  artifact_kind?: string;
  scope_rule?: ScopeGuardRule;
  target_model?: PipelineTargetModel;
  invariants?: PipelineInvariant[];
  hypotheses?: PipelineHypothesis[];
  hypothesis_assessments?: HypothesisLifecycleAssessment[];
  refutation?: PipelineRefutation | null;
  validation_plan?: PipelineValidationPlan | null;
  report_draft?: ReportDraftCandidate | null;
  evidence_bundle?: EvidenceBundle | null;
  timeline?: PipelineStage[];
  artifact?: PipelineArtifactProvenance | null;
  validation_workspace?: ValidationWorkspace | null;
  validation_gate?: PipelineValidationGate | null;
  hunter_intelligence?: HunterIntelligence | null;
  closed_loop_summary?: ClosedLoopSummary | null;
};

export type PipelineRun = {
  id: string;
  program_id?: string | null;
  asset: string;
  policy_text_hash: string;
  scope_status: string;
  hypothesis_count: number;
  blocked_count: number;
  evidence_count: number;
  report_title: string | null;
  created_at: string;
  timeline?: PipelineStage[];
  stages?: PipelineStage[];
  artifact?: PipelineArtifactProvenance;
  artifacts?: PipelineArtifactProvenance[];
  provenance?: PipelineArtifactProvenance;
  validation_gate?: PipelineValidationGate;
  validationGate?: PipelineValidationGate;
  hunter_intelligence?: HunterIntelligence;
  hunterIntelligence?: HunterIntelligence;
  closed_loop_summary?: ClosedLoopSummary | null;
  closedLoopSummary?: ClosedLoopSummary | null;
  evidence_support_summary?: EvidenceSupportSummary | null;
  evidenceSupportSummary?: EvidenceSupportSummary | null;
  payload?: PipelineRunPayload;
};

export type PipelineRunDetail = PipelineRun & {
  payload?: PipelineRunPayload;
};

export type SourceAuditScanRequest = {
  repo_path: string;
  scope_path: string;
  policy_text?: string | null;
  program_id?: string | null;
};

export type SourceAuditScanResponse = {
  run_id: string;
  artifact_id: string;
  report_title: string;
  scope_status: string;
  hypothesis_count: number;
  submission_blocked: boolean;
  safety_notes: string[];
};

export type StudioBlackBoxLabSessionRequest = {
  account_alias: string;
  ready: boolean;
  role_alias: string;
  session_alias: "session_a" | "session_b";
};

export type StudioBlackBoxLabWorkflowRequest = {
  action: "read_only_replay" | "reversible_update" | "test_object_create";
  method: "GET" | "HEAD" | "PATCH" | "POST" | "PUT";
  object_aliases: readonly string[];
  origin: string;
  route_template: string;
  session_alias: "session_a" | "session_b";
  workflow_alias: string;
};

export type StudioBlackBoxLabLeasePreviewRequest = {
  active_origin: string;
  sessions: readonly StudioBlackBoxLabSessionRequest[];
  workflows: readonly StudioBlackBoxLabWorkflowRequest[];
};

export type StudioBlackBoxLabLeasePreviewResponse = {
  active_origin: string;
  blocked_actions: string[];
  execution_allowed: false;
  human_approval_required: true;
  persist_session_state: false;
  profile: "local_lab";
  session_aliases: string[];
  sessions_ready: boolean;
  trace_review_required: true;
  workflow_aliases: string[];
};

export type StudioBlackBoxLabTraceReviewRequest = {
  redacted: true;
  response_schema_fingerprint: string;
  route_template: string;
  session_alias: "session_a" | "session_b";
  workflow_alias: string;
};

export type StudioBlackBoxLabRunApprovalRequest = {
  lease_preview: StudioBlackBoxLabLeasePreviewRequest;
  operator_confirmed: boolean;
  trace_review: readonly StudioBlackBoxLabTraceReviewRequest[];
  validation_run_id: string;
};

export type StudioBlackBoxLabRunApprovalResponse = {
  approval_id: string;
  approval_status: "approved";
  execution_allowed: false;
  lease_digest: string;
  local_runner_dispatch_allowed: true;
  reason: "bounded_local_lab_run_approved";
  report_submission_allowed: false;
  validation_run_id: string;
};

export type StudioBlackBoxRemoteStatusResponse = {
  profile: "remote_human_lease";
  enabled: boolean;
  state:
    | "disabled"
    | "awaiting_lease"
    | "active"
    | "stopped"
    | "expired"
    | "relogin_required";
  expires_at: string | null;
  relogin_required: boolean;
  stop_reason: string | null;
  report_submission_allowed: boolean;
  human_confirmation_allowed: boolean;
};

export type StudioWorkspaceCreateRequest = {
  root_path: string;
  name: string;
};

export type StudioWorkspaceCreateResponse = {
  path: string;
  manifest: StudioWorkspaceManifest;
};

export type StudioArtifactImportRequest = {
  workspace_path: string;
  kind: string;
  source_path: string;
};

export type StudioCandidateModelRequest = {
  enabled: true;
  provider: "openai" | "claude" | "deepseek";
  model: string;
};

export type StudioWorkspaceRunRequest = {
  candidate_model?: StudioCandidateModelRequest;
  workspace_path: string;
};

export type StudioCandidateGenerationSummary = {
  model_requested: boolean;
  provider?: "openai" | "claude" | "deepseek";
  model?: string;
  model_status: "completed" | "model_not_requested" | "needs_model_review";
  model_failure_reason: string | null;
  prompt_hash: string;
  model_latency_ms: number | null;
  baseline_count: number;
  proposed_count: number;
  accepted_count: number;
  rejected_count: number;
  working_candidate_count: number;
  execution_allowed: false;
  dispatch_allowed: false;
  validation_allowed: false;
  candidate_promotion_allowed: false;
  report_submission_allowed: false;
};

export type StudioWorkspaceRunResponse = {
  run_id: string;
  candidate_count: number;
  candidate_generation: StudioCandidateGenerationSummary;
  submission_blocked: boolean;
  report_title: string;
  safety_notes: string[];
  manifest: StudioWorkspaceManifest;
};

export type StudioWorkspaceCampaignLaunchRequest = {
  workspace_path: string;
  default_asset?: string;
  name?: string;
  program_id?: string;
};

export type StudioWorkspaceCampaignLaunchResponse = {
  campaign: CampaignListItem;
  control_center: CampaignControlCenter;
  dispatched_task_ids: string[];
  execution_allowed: false;
  manifest: StudioWorkspaceManifest;
  report_submission_allowed: false;
  safety_gate: string;
  validation_allowed: false;
};

export type StudioWorkspaceCandidatesResponse = {
  run_id: string | null;
  candidates: StudioCandidateInput[];
};

export type StudioWorkspaceMissionResponse = StudioMissionSummary;

export type StudioWorkspaceMissionHandoffResponse = {
  run_id: string | null;
  scope_guard_status: string;
  candidate_count: number;
  quality_summary: StudioMissionSummary["quality_summary"];
  artifacts: StudioMissionSummary["artifacts"];
  agent_handoff_pack: StudioAgentHandoffPackInput;
  candidate_hunter_plan: StudioCandidateHunterPlanInput;
  candidate_hunter_review_loop: StudioCandidateHunterReviewLoopInput;
  candidate_hunter_execution_loop: StudioCandidateHunterExecutionLoopInput;
  safety_gate: string;
  completion_gate: string;
  execution_allowed: false;
  validation_allowed: false;
  report_submission_allowed: false;
};

export type StudioReportExportRequest = {
  workspace_path: string;
  run_id: string;
};

export type StudioCampaignHunterReportExportRequest = {
  workspace_path: string;
  campaign_id: string;
};

export type StudioMissionDossierExportRequest = {
  workspace_path: string;
  run_id: string;
};

export type StudioMissionDossierExportResponse = {
  run_id: string | null;
  agent_queue_path: string | null;
  agent_queue_markdown_path: string | null;
  mission_dossier_path: string | null;
  mission_dossier_markdown_path: string | null;
  report_submission_allowed: false;
  validation_execution_allowed: false;
  mission: StudioMissionSummary;
  manifest: StudioWorkspaceManifest;
};

export type StudioBenchmarkRunRequest = {
  workspace_path: string;
  run_id: string;
  expectations_path: string;
};

export type StudioBenchmarkTemplateRequest = {
  workspace_path: string;
  run_id: string;
};

export type StudioBenchmarkTemplateResponse = {
  run_id: string;
  template: Record<string, unknown>;
  template_path: string | null;
  manifest: StudioWorkspaceManifest;
};

export type StudioBenchmarkRunResponse = {
  run_id: string;
  benchmark: {
    status?: string;
    candidate_count?: number;
    expected_count?: number;
    matched?: number;
    failures?: Array<{ name?: string; reason?: string }>;
    evidence_gaps?: Array<{ name?: string; artifact_kind?: string; reason?: string }>;
    safety?: { forbidden_text_present?: string[] };
  };
  benchmark_path: string | null;
  manifest: StudioWorkspaceManifest;
};

export type StudioReportExportResponse = {
  run_id: string;
  title: string;
  submission_blocked: boolean;
  report_submission_allowed: false;
  report_markdown_path: string | null;
  report: Record<string, unknown>;
  manifest: StudioWorkspaceManifest;
};

export type ArtifactRecord = {
  id: string;
  program_id: string | null;
  asset: string;
  kind: string;
  source_type: string;
  source_hash: string;
  ingestion_status: string;
  provenance: Record<string, unknown>;
  payload_summary: Record<string, unknown>;
  derived_facts: Record<string, unknown>;
  sensitivity_label: string;
  redaction_status: string;
  report_chain_allowed: boolean;
  safety_blockers: string[];
  usage_records?: ArtifactUsageRecord[];
  created_at: string;
};

export type ReportPreviewSections = {
  observed_facts: string[];
  model_reasoning: string[];
  unverified_claims: string[];
};

export type ClaimLedgerEntry = {
  claim_id: string;
  claim_type: string;
  text: string;
  status: string;
  quality_score: number;
  quality_reasons: string[];
  readiness_level: string;
  evidence_refs: string[];
  provenance_refs: string[];
  redaction_status: string;
  human_review_required: boolean;
  readiness_blockers: string[];
  review_status: string;
  reviewer: string | null;
  review_rationale: string | null;
  reviewed_at: string | null;
  review_evidence_refs: string[];
};

export type ReportPreview = {
  run_id: string;
  title: string;
  severity: string;
  scope_status: string;
  human_review_required: boolean;
  submission_blocked: boolean;
  claim_labels: Record<string, string>;
  sections: ReportPreviewSections;
  claim_ledger: ClaimLedgerEntry[];
  safety_notes: string[];
  evidence_refs: string[];
};

export type ClaimReviewDecisionValue =
  | "confirmed_observed_fact"
  | "needs_evidence"
  | "refuted"
  | "not_reportable";

export type ClaimReviewDecisionRequest = {
  claim_id: string;
  decision: ClaimReviewDecisionValue;
  reviewer: string;
  rationale?: string;
  evidence_refs?: string[];
};

export type ClaimReviewDecisionResponse = {
  claim_id: string;
  decision: ClaimReviewDecisionValue;
  reviewer: string;
  rationale: string;
  evidence_refs: string[];
  reviewed_at: string;
};

export type ValidationFeedbackReviewDecisionValue = "allow_finding_promotion";

export type ValidationFeedbackReviewRequest = {
  decision: ValidationFeedbackReviewDecisionValue;
  reviewer: string;
  rationale: string;
};

export type CampaignCycleReviewCompletionRequest = {
  actor: string;
  reason: string;
};

export type ResearchQueueTaskMaterializationRequest = {
  queue_key: string;
  requester: string;
  reason: string;
};

export type ResearchReviewPlanRequest = {
  reviewer: string;
  rationale: string;
  hypothesis: string;
  refutation_questions: string[];
  evidence_plan: string[];
};

export type ResearchRefutationDecisionValue =
  | "refuted"
  | "needs_evidence"
  | "needs_validation_review"
  | "parked_duplicate"
  | "policy_blocked";

export type ResearchCandidateContextSummaryRequest = {
  triage_signal_count: number;
  evidence_focus_count: number;
  source_fact_type_count: number;
  has_authorization_gap_candidate: boolean;
};

export type ResearchRefutationDecisionRequest = {
  plan_id: string;
  reviewer: string;
  decision: ResearchRefutationDecisionValue;
  rationale: string;
  candidate_context_summary?: ResearchCandidateContextSummaryRequest | null;
  refutation_answers?: string[];
  validation_mode?: string | null;
  target_ref?: string | null;
};

export type ManualObservationRequest = {
  claim_id: string;
  observation_type?: string;
  observer: string;
  observation: string;
  evidence_refs?: string[];
  safety_notes?: string[];
};

export type ManualObservationResponse = ManualObservation;

export type ValidationRunManualResultOutcome = "observed" | "refuted" | "needs_more_evidence";

export type ValidationRunManualResultRequest = {
  outcome: ValidationRunManualResultOutcome;
  reviewer: string;
  summary: string;
  evidence_refs?: string[];
};

export type LearningOutcome = "accepted" | "duplicate" | "informative" | "na" | "rejected";
export type LearningSeverityDelta = "up" | "down" | "same";
export type LearningEvidenceQuality = "strong" | "adequate" | "weak";
export type CandidateHunterLearningOutcome =
  | "confirmed"
  | "duplicate"
  | "needs_more_evidence"
  | "refuted";

export type LearningSignal = {
  id?: string | null;
  program_id: string;
  playbook_id: string;
  outcome: LearningOutcome;
  surface_key?: string | null;
  notes: string;
  bounty_amount?: number | null;
  severity_delta?: LearningSeverityDelta | null;
  evidence_quality?: LearningEvidenceQuality | null;
  triager_feedback?: string | null;
  target_relationships?: string[];
  created_at?: string | null;
};

export type LearningOutcomeRequest = {
  outcome: LearningOutcome;
  program_id?: string | null;
  run_id?: string | null;
  playbook_id?: string | null;
  surface_key?: string | null;
  notes?: string;
  bounty_amount?: number | null;
  severity_delta?: LearningSeverityDelta | null;
  evidence_quality?: LearningEvidenceQuality | null;
  triager_feedback?: string | null;
  target_relationships?: string[];
};

export type CandidateHunterLearningOutcomeRequest = {
  candidate_id: string;
  evidence_ready?: boolean;
  learning_evidence_needed_reasons?: string[];
  missing_evidence?: string[];
  missing_required_artifact_kinds?: string[];
  outcome: CandidateHunterLearningOutcome;
  reviewer: string;
  notes: string;
  playbook_id?: string | null;
  program_id?: string | null;
  run_id?: string | null;
  surface_key?: string | null;
  target_relationships?: string[];
  trace_status?: string | null;
};

export type AttackSurfaceAction = {
  action: string;
  method: string;
  path: string;
  roles: string[];
  operation_id?: string | null;
};

export type AttackSurfaceRelationship = {
  parent_object: string;
  child_object: string;
  relationship: string;
  paths: string[];
};

export type AttackSurfaceMemory = {
  objects: string[];
  roles: string[];
  sensitive_actions: AttackSurfaceAction[];
  relationships?: AttackSurfaceRelationship[];
  run_count: number;
};

export type HighValueSurface = {
  surface_key: string;
  object_name: string;
  action: string;
  score: number;
  paths: string[];
  playbooks: string[];
  reasons: string[];
};

export type MythosLesson = {
  id: string;
  scope_type: "program" | "platform" | "global";
  scope_key: string;
  playbook_id: string;
  surface_pattern: string;
  outcome_counts: Record<string, number>;
  evidence_quality_counts: Record<string, number>;
  bounty_total: number;
  severity_delta_counts: Record<string, number>;
  confidence: number;
  recommendation: "boost" | "penalize" | "evidence_needed" | "duplicate_watch";
  score_delta: number;
  reasons: string[];
  source_signal_ids: string[];
  safety_notes: string[];
  created_at?: string | null;
  updated_at?: string | null;
};

export type SkippedMythosLesson = {
  lesson_id: string;
  reason: string;
  scope_type: string;
  scope_key: string;
};

export type LessonAdjustedSurface = {
  surface_key: string;
  lesson_id: string;
  recommendation: string;
  score_delta: number;
  score_before: number;
  score_after: number;
};

export type LearningSummary = {
  accepted_count: number;
  duplicate_count: number;
  informative_count: number;
  na_count: number;
  rejected_count: number;
  rejection_risk_delta: number;
  bounty_total: number;
  strong_evidence_count: number;
  adequate_evidence_count: number;
  weak_evidence_count: number;
  severity_up_count: number;
  severity_down_count: number;
  triager_feedback_count: number;
  evidence_score_delta: number;
  boosted_playbooks: string[];
  penalized_playbooks: string[];
};

export type ProgramIntelligenceProfile = {
  program_id: string;
  program_name: string;
  program_score: number;
  attack_surface_memory: AttackSurfaceMemory;
  high_value_surfaces: HighValueSurface[];
  learning_summary: LearningSummary;
  reasoning_memory?: ReasoningMemorySummary;
  recent_learning_signals: LearningSignal[];
  applied_lessons: MythosLesson[];
  skipped_lessons: SkippedMythosLesson[];
  lesson_adjusted_surfaces: LessonAdjustedSurface[];
  safety_notes: string[];
};

export type ReasoningMemorySummary = {
  source: string;
  highest_reasoning_review_score: number;
  learning_signal_context_count: number;
  candidate_context_count: number;
  top_playbooks: ReasoningMemoryPlaybook[];
  safety_notes: string[];
};

export type ReasoningMemoryPlaybook = {
  playbook_id: string;
  highest_reasoning_review_score: number;
  learning_signal_context_count: number;
  candidate_context_count: number;
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

async function apiPost<T>(path: string, body: unknown): Promise<T> {
  let response: Response;
  try {
    response = await fetch(new URL(path, API_BASE_URL), {
      body: JSON.stringify(body),
      cache: "no-store",
      headers: { "Content-Type": "application/json" },
      method: "POST",
    });
  } catch {
    throw apiNetworkError(`POST ${path} failed`);
  }

  if (!response.ok) {
    throw await apiResponseError(response, `POST ${path} failed`);
  }

  try {
    return (await response.json()) as T;
  } catch {
    throw new ApiRequestError(`POST ${path} returned an invalid response`, response.status, "invalid_response");
  }
}

export type FindingCandidatePromotionGateDetail = {
  blocked_stage_count: number;
  finding_promotion_allowed: false;
  provenance_ref_count: number;
  reason: "blocked_by_research_feedback_gate";
  report_submission_allowed: false;
};

export function isFindingCandidatePromotionGateDetail(
  value: unknown,
): value is FindingCandidatePromotionGateDetail {
  if (!isRecord(value)) {
    return false;
  }

  return (
    value.reason === "blocked_by_research_feedback_gate" &&
    value.finding_promotion_allowed === false &&
    value.report_submission_allowed === false &&
    typeof value.blocked_stage_count === "number" &&
    typeof value.provenance_ref_count === "number"
  );
}

export class ApiRequestError extends Error {
  readonly status: number;
  readonly detail: unknown;

  constructor(message: string, status: number, detail: unknown) {
    super(message);
    this.name = "ApiRequestError";
    this.status = status;
    this.detail = detail;
  }
}

function apiNetworkError(message: string): ApiRequestError {
  return new ApiRequestError(message, 0, "network_error");
}

async function apiResponseError(response: Response, message: string): Promise<ApiRequestError> {
  return new ApiRequestError(message, response.status, await safeApiErrorDetail(response));
}

async function safeApiErrorDetail(response: Response): Promise<unknown> {
  try {
    const payload = (await response.json()) as { detail?: unknown };
    return payload.detail ?? "request_failed";
  } catch {
    return "request_failed";
  }
}

export class SourceAuditScanError extends Error {
  readonly detail: string;
  readonly status: number;

  constructor(message: string, status: number, detail: string) {
    super(message);
    this.name = "SourceAuditScanError";
    this.status = status;
    this.detail = detail;
  }
}

export function getPrograms(fallback: Program[]): Promise<Program[]> {
  return apiGet("/programs", fallback);
}

export function getCampaigns(fallback: CampaignListItem[]): Promise<CampaignListItem[]> {
  return apiGet("/mythos/campaigns", fallback);
}

export async function launchAuthorizedCampaign(
  input: AuthorizedCampaignLaunchInput,
): Promise<CampaignListItem | null> {
  const created = await apiPost<CampaignListItem | null>("/mythos/campaigns", input);

  if (!created) {
    return null;
  }

  return apiPost<CampaignListItem | null>(
    `/mythos/campaigns/${encodeURIComponent(created.id)}/start`,
    {},
  );
}

export function getCampaignControlCenter(
  campaignId: string,
  fallback: CampaignControlCenter | null,
): Promise<CampaignControlCenter | null> {
  return apiGet(
    `/mythos/campaigns/${encodeURIComponent(campaignId)}/control-center`,
    fallback,
  );
}

export function getCampaignAgentRuns(
  campaignId: string,
  fallback: CampaignAgentRun[],
): Promise<CampaignAgentRun[]> {
  return apiGet(`/mythos/campaigns/${encodeURIComponent(campaignId)}/agent-runs`, fallback);
}

export function getCampaignTasks(
  campaignId: string,
  fallback: CampaignTask[],
): Promise<CampaignTask[]> {
  return apiGet(`/mythos/campaigns/${encodeURIComponent(campaignId)}/tasks`, fallback);
}

export function getCampaignResearchTaskReview(
  campaignId: string,
  taskId: string,
  fallback: CampaignResearchTaskReview | null,
): Promise<CampaignResearchTaskReview | null> {
  return apiGet(
    `/mythos/campaigns/${encodeURIComponent(campaignId)}/research-queue/tasks/${encodeURIComponent(taskId)}/review`,
    fallback,
  );
}

export function materializeResearchQueueTask(
  campaignId: string,
  request: ResearchQueueTaskMaterializationRequest,
): Promise<CampaignTask> {
  return apiPost(
    `/mythos/campaigns/${encodeURIComponent(campaignId)}/research-queue/tasks`,
    request,
  );
}

export function createResearchReviewPlan(
  campaignId: string,
  taskId: string,
  request: ResearchReviewPlanRequest,
): Promise<CampaignResearchTaskReview["latest_review_plan"]> {
  return apiPost(
    `/mythos/campaigns/${encodeURIComponent(campaignId)}/research-queue/tasks/${encodeURIComponent(taskId)}/review-plans`,
    request,
  );
}

export function createResearchRefutationDecision(
  campaignId: string,
  taskId: string,
  request: ResearchRefutationDecisionRequest,
): Promise<CampaignResearchRefutationDecision> {
  return apiPost(
    `/mythos/campaigns/${encodeURIComponent(campaignId)}/research-queue/tasks/${encodeURIComponent(taskId)}/review-decisions`,
    request,
  );
}

export function getCampaignApprovals(
  campaignId: string,
  fallback: CampaignApproval[],
): Promise<CampaignApproval[]> {
  return apiGet(`/mythos/campaigns/${encodeURIComponent(campaignId)}/approvals`, fallback);
}

export function getCampaignValidationRuns(
  campaignId: string,
  fallback: CampaignValidationRun[],
): Promise<CampaignValidationRun[]> {
  return apiGet(`/mythos/campaigns/${encodeURIComponent(campaignId)}/validation-runs`, fallback);
}

export function recordCampaignValidationRunManualResult(
  validationRunId: string,
  request: ValidationRunManualResultRequest,
): Promise<CampaignValidationRun> {
  return apiPost(
    `/mythos/validation-runs/${encodeURIComponent(validationRunId)}/manual-results`,
    request,
  );
}

export function getCampaignPipelineStages(
  campaignId: string,
  fallback: CampaignPipelineStage[],
): Promise<CampaignPipelineStage[]> {
  return apiGet(
    `/mythos/campaigns/${encodeURIComponent(campaignId)}/pipeline-stages`,
    fallback,
  );
}

export function getCampaignCodebaseMap(
  campaignId: string,
  fallback: CampaignCodebaseMap,
): Promise<CampaignCodebaseMap> {
  return apiGet(`/mythos/campaigns/${encodeURIComponent(campaignId)}/codebase-map`, fallback);
}

export function getFindings(fallback: Finding[]): Promise<Finding[]> {
  return apiGet("/findings", fallback);
}

export function getReports(fallback: ReportDraft[]): Promise<ReportDraft[]> {
  return apiGet("/reports", fallback);
}

export function getPipelineRuns(fallback: PipelineRun[]): Promise<PipelineRun[]> {
  return apiGet("/mythos/pipeline/runs", fallback);
}

export function runSourceAuditScan(
  request: SourceAuditScanRequest,
): Promise<SourceAuditScanResponse | null> {
  return runSourceAuditScanRequest(request);
}

export function createStudioWorkspace(
  request: StudioWorkspaceCreateRequest,
): Promise<StudioWorkspaceCreateResponse | null> {
  return apiPost("/mythos/studio/workspaces", request);
}

export function previewStudioBlackBoxLabLease(
  request: StudioBlackBoxLabLeasePreviewRequest,
): Promise<StudioBlackBoxLabLeasePreviewResponse | null> {
  return apiPost("/mythos/studio/black-box-lab/leases/preview", request);
}

export function approveStudioBlackBoxLabRun(
  request: StudioBlackBoxLabRunApprovalRequest,
): Promise<StudioBlackBoxLabRunApprovalResponse | null> {
  return apiPost("/mythos/studio/black-box-lab/runs/approve", request);
}

export function getStudioBlackBoxRemoteStatus(): Promise<StudioBlackBoxRemoteStatusResponse> {
  return apiGet("/mythos/studio/black-box-remote/status", {
    profile: "remote_human_lease",
    enabled: false,
    state: "relogin_required",
    expires_at: null,
    relogin_required: true,
    stop_reason: "relogin_required",
    report_submission_allowed: false,
    human_confirmation_allowed: false,
  });
}

export function getStudioWorkspaceManifest(
  workspacePath: string,
  fallback: StudioWorkspaceManifest | null,
): Promise<StudioWorkspaceManifest | null> {
  const query = new URLSearchParams({ workspace_path: workspacePath });
  return apiGet(`/mythos/studio/workspaces/manifest?${query}`, fallback);
}

export function importStudioWorkspaceArtifact(
  request: StudioArtifactImportRequest,
): Promise<StudioWorkspaceManifest | null> {
  return apiPost("/mythos/studio/workspaces/imports", request);
}

export function runStudioWorkspaceResearch(
  request: StudioWorkspaceRunRequest,
): Promise<StudioWorkspaceRunResponse | null> {
  return apiPost("/mythos/studio/workspaces/runs", request);
}

export function launchStudioWorkspaceCampaignHunter(
  request: StudioWorkspaceCampaignLaunchRequest,
): Promise<StudioWorkspaceCampaignLaunchResponse | null> {
  return apiPost("/mythos/studio/workspaces/campaigns/launch", request);
}

export function listStudioWorkspaceCandidates(
  workspacePath: string,
  runId: string | null,
  fallback: StudioWorkspaceCandidatesResponse,
): Promise<StudioWorkspaceCandidatesResponse> {
  const query = new URLSearchParams({ workspace_path: workspacePath });
  if (runId) {
    query.set("run_id", runId);
  }
  return apiGet(`/mythos/studio/workspaces/candidates?${query}`, fallback);
}

export function getStudioWorkspaceMission(
  workspacePath: string,
  runId: string | null,
  fallback: StudioWorkspaceMissionResponse | null,
): Promise<StudioWorkspaceMissionResponse | null> {
  const query = new URLSearchParams({ workspace_path: workspacePath });
  if (runId) {
    query.set("run_id", runId);
  }
  return apiGet(`/mythos/studio/workspaces/mission?${query}`, fallback);
}

export function getStudioWorkspaceMissionHandoff(
  workspacePath: string,
  runId: string | null,
  fallback: StudioWorkspaceMissionHandoffResponse | null,
): Promise<StudioWorkspaceMissionHandoffResponse | null> {
  const query = new URLSearchParams({ workspace_path: workspacePath });
  if (runId) {
    query.set("run_id", runId);
  }
  return apiGet(`/mythos/studio/workspaces/mission/handoff?${query}`, fallback);
}

export function exportStudioWorkspaceReport(
  request: StudioReportExportRequest,
): Promise<StudioReportExportResponse | null> {
  return apiPost("/mythos/studio/workspaces/reports/export", request);
}

export function exportStudioWorkspaceCampaignHunterReport(
  request: StudioCampaignHunterReportExportRequest,
): Promise<StudioReportExportResponse | null> {
  return apiPost("/mythos/studio/workspaces/campaigns/reports/export", request);
}

export function exportStudioWorkspaceMissionDossier(
  request: StudioMissionDossierExportRequest,
): Promise<StudioMissionDossierExportResponse | null> {
  return apiPost("/mythos/studio/workspaces/mission/export", request);
}

export function runStudioWorkspaceBenchmark(
  request: StudioBenchmarkRunRequest,
): Promise<StudioBenchmarkRunResponse | null> {
  return apiPost("/mythos/studio/workspaces/benchmarks/run", request);
}

export function createStudioWorkspaceBenchmarkTemplate(
  request: StudioBenchmarkTemplateRequest,
): Promise<StudioBenchmarkTemplateResponse | null> {
  return apiPost("/mythos/studio/workspaces/benchmarks/template", request);
}

async function runSourceAuditScanRequest(
  request: SourceAuditScanRequest,
): Promise<SourceAuditScanResponse | null> {
  let response: Response;
  try {
    response = await fetch(new URL("/mythos/source-audit/scans", API_BASE_URL), {
      body: JSON.stringify(sourceAuditScanRequestBody(request)),
      cache: "no-store",
      headers: { "Content-Type": "application/json" },
      method: "POST",
    });
  } catch {
    throw apiNetworkError("Source audit scan request failed");
  }

  if (response.status === 403) {
    throw new SourceAuditScanError(
      "Source audit scan blocked by Scope Guard",
      response.status,
      await safeSourceAuditBlockDetail(response),
    );
  }

  if (!response.ok) {
    throw await apiResponseError(response, "Source audit scan request failed");
  }

  try {
    return (await response.json()) as SourceAuditScanResponse;
  } catch {
    throw new ApiRequestError(
      "Source audit scan returned an invalid response",
      response.status,
      "invalid_response",
    );
  }
}

function sourceAuditScanRequestBody(request: SourceAuditScanRequest): SourceAuditScanRequest {
  return {
    ...(request.policy_text ? { policy_text: request.policy_text } : {}),
    ...(request.program_id ? { program_id: request.program_id } : {}),
    repo_path: request.repo_path,
    scope_path: request.scope_path,
  };
}

async function safeSourceAuditBlockDetail(response: Response): Promise<string> {
  try {
    const payload = (await response.json()) as { detail?: unknown };
    return typeof payload.detail === "string" ? payload.detail : "source_audit_blocked";
  } catch {
    return "source_audit_blocked";
  }
}

export function getPipelineRun(
  runId: string,
  fallback: PipelineRunDetail | null,
): Promise<PipelineRunDetail | null> {
  return apiGet(`/mythos/pipeline/runs/${encodeURIComponent(runId)}`, fallback);
}

export function getArtifact(
  artifactId: string,
  fallback: ArtifactRecord | null,
): Promise<ArtifactRecord | null> {
  return apiGet(`/mythos/artifacts/${encodeURIComponent(artifactId)}`, fallback);
}

export type ArtifactFilters = {
  programId?: string;
  asset?: string;
  sourceType?: string;
  ingestionStatus?: string;
  provenanceRef?: string;
  factType?: string;
  usageType?: string;
  usageRunId?: string;
  sensitivityLabel?: string;
  redactionStatus?: string;
  reportChainAllowed?: string;
};

export function getArtifacts(
  fallback: ArtifactRecord[],
  filters?: ArtifactFilters,
): Promise<ArtifactRecord[]> {
  const params = new URLSearchParams();
  if (filters?.programId) {
    params.set("program_id", filters.programId);
  }
  if (filters?.asset) {
    params.set("asset", filters.asset);
  }
  if (filters?.sourceType) {
    params.set("source_type", filters.sourceType);
  }
  if (filters?.ingestionStatus) {
    params.set("ingestion_status", filters.ingestionStatus);
  }
  if (filters?.provenanceRef) {
    params.set("provenance_ref", filters.provenanceRef);
  }
  if (filters?.factType) {
    params.set("fact_type", filters.factType);
  }
  if (filters?.usageType) {
    params.set("usage_type", filters.usageType);
  }
  if (filters?.usageRunId) {
    params.set("usage_run_id", filters.usageRunId);
  }
  if (filters?.sensitivityLabel) {
    params.set("sensitivity_label", filters.sensitivityLabel);
  }
  if (filters?.redactionStatus) {
    params.set("redaction_status", filters.redactionStatus);
  }
  if (filters?.reportChainAllowed) {
    params.set("report_chain_allowed", filters.reportChainAllowed);
  }
  const query = params.toString();
  return apiGet(`/mythos/artifacts${query ? `?${query}` : ""}`, fallback);
}

export function getReportPreview(
  runId: string,
  fallback: ReportPreview | null,
): Promise<ReportPreview | null> {
  return apiGet(`/mythos/pipeline/runs/${encodeURIComponent(runId)}/report-preview`, fallback);
}

export function createFindingCandidate(runId: string): Promise<Finding | null> {
  return createFindingCandidateRequest(runId);
}

async function createFindingCandidateRequest(runId: string): Promise<Finding | null> {
  let response: Response;
  try {
    response = await fetch(
      new URL(`/mythos/pipeline/runs/${encodeURIComponent(runId)}/finding-candidates`, API_BASE_URL),
      {
        body: JSON.stringify({}),
        cache: "no-store",
        headers: { "Content-Type": "application/json" },
        method: "POST",
      },
    );
  } catch {
    throw apiNetworkError("Finding candidate promotion request failed");
  }

  if (response.status === 409) {
    const detail = await safePromotionGateDetail(response.clone());
    if (detail) {
      throw new ApiRequestError("Finding candidate promotion blocked", response.status, detail);
    }
  }

  if (!response.ok) {
    throw await apiResponseError(response, "Finding candidate promotion request failed");
  }

  try {
    return (await response.json()) as Finding;
  } catch {
    throw new ApiRequestError(
      "Finding candidate promotion returned an invalid response",
      response.status,
      "invalid_response",
    );
  }
}

async function safePromotionGateDetail(
  response: Response,
): Promise<FindingCandidatePromotionGateDetail | null> {
  try {
    const payload = (await response.json()) as { detail?: unknown };
    const detail = payload.detail;
    if (!isRecord(detail)) {
      return null;
    }

    if (!isFindingCandidatePromotionGateDetail(detail)) {
      return null;
    }

    return {
      blocked_stage_count: detail.blocked_stage_count,
      finding_promotion_allowed: false,
      provenance_ref_count: detail.provenance_ref_count,
      reason: "blocked_by_research_feedback_gate",
      report_submission_allowed: false,
    };
  } catch {
    return null;
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

export function recordClaimReviewDecision(
  runId: string,
  request: ClaimReviewDecisionRequest,
): Promise<ClaimReviewDecisionResponse> {
  return apiPost(
    `/mythos/pipeline/runs/${encodeURIComponent(runId)}/claim-review-decisions`,
    request,
  );
}

export function reviewValidationFeedbackForFindingPromotion(
  campaignId: string,
  stageId: string,
  request: ValidationFeedbackReviewRequest,
): Promise<CampaignPipelineStage> {
  return apiPost(
    `/mythos/campaigns/${encodeURIComponent(campaignId)}/pipeline-stages/${encodeURIComponent(stageId)}/validation-feedback-review`,
    request,
  );
}

export function completeCampaignCycleReview(
  campaignId: string,
  stageId: string,
  request: CampaignCycleReviewCompletionRequest,
): Promise<CampaignPipelineStage> {
  return apiPost(
    `/mythos/campaigns/${encodeURIComponent(campaignId)}/cycle-reviews/${encodeURIComponent(stageId)}/complete`,
    request,
  );
}

export function recordManualObservation(
  runId: string,
  request: ManualObservationRequest,
): Promise<ManualObservationResponse> {
  return apiPost(
    `/mythos/pipeline/runs/${encodeURIComponent(runId)}/manual-observations`,
    request,
  );
}

export function getMythosBrainProgram(
  programId: string,
  fallback: ProgramIntelligenceProfile,
): Promise<ProgramIntelligenceProfile> {
  return apiGet(`/mythos/brain/programs/${encodeURIComponent(programId)}`, fallback);
}

export function recordMythosBrainOutcome(
  request: LearningOutcomeRequest,
): Promise<ProgramIntelligenceProfile> {
  return apiPost("/mythos/brain/outcomes", request);
}

const candidateHunterLearningOutcomeMap: Record<CandidateHunterLearningOutcome, LearningOutcome> = {
  confirmed: "accepted",
  duplicate: "duplicate",
  needs_more_evidence: "informative",
  refuted: "rejected",
};

const candidateHunterLearningEvidenceQualityMap: Record<
  CandidateHunterLearningOutcome,
  LearningEvidenceQuality
> = {
  confirmed: "adequate",
  duplicate: "adequate",
  needs_more_evidence: "weak",
  refuted: "adequate",
};

function candidateHunterLearningContextValue(value: string): string {
  return value.replace(/[\r\n:]/g, "_").trim().slice(0, 80);
}

function candidateHunterLearningEvidenceRelationships(
  request: CandidateHunterLearningOutcomeRequest,
): string[] {
  const relationships = [...(request.target_relationships ?? [])];
  if (typeof request.evidence_ready === "boolean") {
    relationships.push(`evidence_ready:${request.evidence_ready ? "true" : "false"}`);
  }
  if (request.trace_status) {
    relationships.push(
      `trace_status:${candidateHunterLearningContextValue(request.trace_status)}`,
    );
  }
  for (const missing of (request.missing_evidence ?? []).slice(0, 5)) {
    relationships.push(
      `missing_evidence:${candidateHunterLearningContextValue(missing)}`,
    );
  }
  for (const missing of (request.missing_required_artifact_kinds ?? []).slice(0, 5)) {
    relationships.push(
      `missing_required_artifact:${candidateHunterLearningContextValue(missing)}`,
    );
  }
  for (const reason of (request.learning_evidence_needed_reasons ?? []).slice(0, 5)) {
    relationships.push(
      `learned_evidence:${candidateHunterLearningContextValue(reason)}`,
    );
  }
  return Array.from(new Set(relationships.filter((item) => item.length > 0))).slice(0, 20);
}

function candidateHunterLearningEvidenceNote(
  request: CandidateHunterLearningOutcomeRequest,
): string {
  if (
    typeof request.evidence_ready !== "boolean" &&
    !request.trace_status &&
    (request.missing_evidence?.length ?? 0) === 0 &&
    (request.missing_required_artifact_kinds?.length ?? 0) === 0 &&
    (request.learning_evidence_needed_reasons?.length ?? 0) === 0
  ) {
    return "";
  }

  const missingEvidence =
    request.missing_evidence?.map(candidateHunterLearningContextValue).join(", ") ||
    "none";
  const missingRequired =
    request.missing_required_artifact_kinds
      ?.map(candidateHunterLearningContextValue)
      .join(", ") || "none";
  const traceStatus = candidateHunterLearningContextValue(
    request.trace_status ?? "needs_evidence",
  );
  const learnedEvidence =
    request.learning_evidence_needed_reasons
      ?.map(candidateHunterLearningContextValue)
      .join(", ") || "none";
  const evidenceReady =
    typeof request.evidence_ready === "boolean"
      ? request.evidence_ready
        ? "true"
        : "false"
      : "unknown";
  return ` evidence ready ${evidenceReady}; trace ${traceStatus}; missing evidence ${missingEvidence}; missing required artifacts ${missingRequired}; learned evidence ${learnedEvidence}.`;
}

export function recordCandidateHunterLearningOutcome(
  request: CandidateHunterLearningOutcomeRequest,
): Promise<ProgramIntelligenceProfile> {
  const evidenceNote = candidateHunterLearningEvidenceNote(request);
  const notes = `Candidate hunter outcome (${request.outcome}) by ${request.reviewer}: ${request.notes}${evidenceNote ? `;${evidenceNote}` : ""}`;
  const targetRelationships = candidateHunterLearningEvidenceRelationships(request);

  return recordMythosBrainOutcome(
    {
      evidence_quality: candidateHunterLearningEvidenceQualityMap[request.outcome],
      notes,
      outcome: candidateHunterLearningOutcomeMap[request.outcome],
      playbook_id: request.playbook_id ?? `candidate_hunter:${request.candidate_id}`,
      program_id: request.program_id ?? null,
      run_id: request.run_id ?? null,
      surface_key: request.surface_key ?? request.candidate_id,
      target_relationships:
        targetRelationships.length > 0 ? targetRelationships : undefined,
      triager_feedback: request.notes,
    },
  );
}

export function evaluateScopeGuard(
  rule: ScopeGuardRule,
  request: ScopeGuardRequest,
): Promise<ScopeGuardDecision> {
  return apiPost("/scope-guard/evaluate", { rule, request });
}
