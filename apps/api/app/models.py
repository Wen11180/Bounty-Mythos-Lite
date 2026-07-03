from enum import StrEnum

from pydantic import BaseModel, Field


class ScopeStatus(StrEnum):
    IN_SCOPE = "in_scope"
    OUT_OF_SCOPE = "out_of_scope"
    NEEDS_REVIEW = "needs_review"


class PolicyStatus(StrEnum):
    ALLOWED = "allowed"
    BLOCKED = "blocked"
    NEEDS_REVIEW = "needs_review"


class ValidationStatus(StrEnum):
    CANDIDATE = "candidate"
    PLAUSIBLE = "plausible"
    POLICY_CHECKED = "policy_checked"
    VALIDATION_PLAN_READY = "validation_plan_ready"
    HUMAN_APPROVED = "human_approved"
    SAFELY_VALIDATED = "safely_validated"
    REFUTED_OR_CONFIRMED = "refuted_or_confirmed"
    REPORT_READY = "report_ready"
    HUMAN_SUBMITTED = "human_submitted"
    ACCEPTED = "accepted"
    DUPLICATE = "duplicate"
    INFORMATIVE = "informative"
    NA = "na"
    LEARNED = "learned"


class Program(BaseModel):
    id: str
    name: str
    platform: str
    bounty_range: str
    scope_status: ScopeStatus
    automation: str
    testing_accounts: str
    api_docs: str
    public_code: str
    duplicate_risk: str
    priority: str


class Finding(BaseModel):
    id: str
    program: str
    asset: str
    title: str
    vuln_type: str
    severity_estimate: str
    confidence: float = Field(ge=0, le=1)
    scope_status: ScopeStatus
    policy_status: PolicyStatus
    broken_invariant: str
    validation_status: ValidationStatus
    refutation_status: str
    duplicate_likelihood: str
    submission_recommendation: str
    evidence_refs: list[str]


class ReportDraft(BaseModel):
    id: str
    finding_id: str
    title: str
    draft: str
