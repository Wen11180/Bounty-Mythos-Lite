from datetime import UTC, datetime

from sqlalchemy import JSON, DateTime, Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db import Base


class ProgramRecord(Base):
    __tablename__ = "programs"

    id: Mapped[str] = mapped_column(String(100), primary_key=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    platform: Mapped[str] = mapped_column(String(255), nullable=False)
    bounty_range: Mapped[str] = mapped_column(String(255), nullable=False)
    scope_status: Mapped[str] = mapped_column(String(50), nullable=False)
    automation: Mapped[str] = mapped_column(String(100), nullable=False)
    testing_accounts: Mapped[str] = mapped_column(String(100), nullable=False)
    api_docs: Mapped[str] = mapped_column(String(100), nullable=False)
    public_code: Mapped[str] = mapped_column(String(100), nullable=False)
    duplicate_risk: Mapped[str] = mapped_column(String(100), nullable=False)
    priority: Mapped[str] = mapped_column(String(50), nullable=False)


class ArtifactRecord(Base):
    __tablename__ = "artifacts"

    id: Mapped[str] = mapped_column(String(100), primary_key=True)
    program_id: Mapped[str | None] = mapped_column(ForeignKey("programs.id"), nullable=True)
    asset: Mapped[str] = mapped_column(String(255), nullable=False)
    kind: Mapped[str] = mapped_column(String(50), nullable=False)
    source_type: Mapped[str] = mapped_column(String(50), nullable=False)
    source_hash: Mapped[str] = mapped_column(String(100), nullable=False, unique=True)
    ingestion_status: Mapped[str] = mapped_column(String(50), nullable=False)
    provenance: Mapped[dict] = mapped_column(JSON, nullable=False)
    payload_summary: Mapped[dict] = mapped_column(JSON, nullable=False)
    derived_facts: Mapped[dict] = mapped_column(JSON, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(UTC),
    )

    program_record: Mapped[ProgramRecord | None] = relationship()


class FindingRecord(Base):
    __tablename__ = "findings"

    id: Mapped[str] = mapped_column(String(100), primary_key=True)
    program_id: Mapped[str | None] = mapped_column(ForeignKey("programs.id"), nullable=True)
    program: Mapped[str] = mapped_column(String(255), nullable=False)
    asset: Mapped[str] = mapped_column(String(255), nullable=False)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    vuln_type: Mapped[str] = mapped_column(String(100), nullable=False)
    severity_estimate: Mapped[str] = mapped_column(String(50), nullable=False)
    confidence: Mapped[float] = mapped_column(Float, nullable=False)
    scope_status: Mapped[str] = mapped_column(String(50), nullable=False)
    policy_status: Mapped[str] = mapped_column(String(50), nullable=False)
    broken_invariant: Mapped[str] = mapped_column(Text, nullable=False)
    validation_status: Mapped[str] = mapped_column(String(100), nullable=False)
    refutation_status: Mapped[str] = mapped_column(String(100), nullable=False)
    duplicate_likelihood: Mapped[str] = mapped_column(String(100), nullable=False)
    submission_recommendation: Mapped[str] = mapped_column(String(100), nullable=False)
    evidence_refs: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)

    program_record: Mapped[ProgramRecord | None] = relationship()


class ReportRecord(Base):
    __tablename__ = "reports"

    id: Mapped[str] = mapped_column(String(100), primary_key=True)
    finding_id: Mapped[str] = mapped_column(ForeignKey("findings.id"), nullable=False)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    draft: Mapped[str] = mapped_column(Text, nullable=False)

    finding: Mapped[FindingRecord] = relationship()


class LLMRunRecord(Base):
    __tablename__ = "llm_runs"

    id: Mapped[str] = mapped_column(String(100), primary_key=True)
    provider: Mapped[str] = mapped_column(String(50), nullable=False)
    model: Mapped[str] = mapped_column(String(100), nullable=False)
    prompt_hash: Mapped[str] = mapped_column(String(100), nullable=False)
    mode: Mapped[str] = mapped_column(String(50), nullable=False)
    latency_ms: Mapped[int | None] = mapped_column(nullable=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)


class PipelineRunRecord(Base):
    __tablename__ = "pipeline_runs"

    id: Mapped[str] = mapped_column(String(100), primary_key=True)
    asset: Mapped[str] = mapped_column(String(255), nullable=False)
    policy_text_hash: Mapped[str] = mapped_column(String(100), nullable=False)
    scope_status: Mapped[str] = mapped_column(String(50), nullable=False)
    hypothesis_count: Mapped[int] = mapped_column(Integer, nullable=False)
    blocked_count: Mapped[int] = mapped_column(Integer, nullable=False)
    report_title: Mapped[str | None] = mapped_column(String(255), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(UTC),
    )
    payload: Mapped[dict] = mapped_column(JSON, nullable=False)
