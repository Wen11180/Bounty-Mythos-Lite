"""Add durable per-campaign, per-snapshot local-tool execution slots."""

from datetime import UTC, datetime
from hashlib import sha256
import json
import re

from alembic import op
import sqlalchemy as sa


revision = "0019_campaign_local_tool_execution_slot"
down_revision = "0018_campaign_tool_call_reservations"
branch_labels = None
depends_on = None


_LOCAL_TOOL_TASK_TYPE = "research_director_local_tool_run"
_LOCAL_TOOL_TASK_SCHEMA = "research_director_local_tool_run_v1"
_LEGACY_SLOT_MARKER = "local_tool_execution_slot_legacy"
_SOURCE_SNAPSHOT_DIGEST_PATTERN = re.compile(r"^sha256:[0-9a-f]{64}$", re.ASCII)


def _payload(value: object) -> dict:
    if isinstance(value, dict):
        return dict(value)
    if isinstance(value, str):
        try:
            decoded = json.loads(value)
        except json.JSONDecodeError:
            return {}
        return dict(decoded) if isinstance(decoded, dict) else {}
    return {}


def _slot_id(campaign_id: str, source_snapshot_digest: str) -> str:
    identity = f"{campaign_id}:{source_snapshot_digest}".encode("utf-8")
    return f"local_tool_slot_{sha256(identity).hexdigest()}"


def upgrade() -> None:
    op.create_table(
        "campaign_local_tool_execution_slots",
        sa.Column("id", sa.String(length=100), nullable=False),
        sa.Column("campaign_id", sa.String(length=100), nullable=False),
        sa.Column("source_snapshot_digest", sa.String(length=100), nullable=False),
        sa.Column("active_task_id", sa.String(length=100), nullable=True),
        sa.Column(
            "active_execution_claim_id",
            sa.String(length=100),
            nullable=True,
        ),
        sa.Column(
            "legacy_active_task_count",
            sa.Integer(),
            nullable=False,
            server_default=sa.text("0"),
        ),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["campaign_id"], ["campaigns.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "campaign_id",
            "source_snapshot_digest",
            name="uq_campaign_local_tool_execution_slots_campaign_snapshot",
        ),
    )
    bind = op.get_bind()
    campaign_tasks = sa.table(
        "campaign_tasks",
        sa.column("id", sa.String(length=100)),
        sa.column("campaign_id", sa.String(length=100)),
        sa.column("task_type", sa.String(length=100)),
        sa.column("status", sa.String(length=50)),
        sa.column("payload", sa.JSON()),
        sa.column("execution_claim_id", sa.String(length=100)),
        sa.column("created_at", sa.DateTime(timezone=True)),
    )
    slots = sa.table(
        "campaign_local_tool_execution_slots",
        sa.column("id", sa.String(length=100)),
        sa.column("campaign_id", sa.String(length=100)),
        sa.column("source_snapshot_digest", sa.String(length=100)),
        sa.column("active_task_id", sa.String(length=100)),
        sa.column("active_execution_claim_id", sa.String(length=100)),
        sa.column("legacy_active_task_count", sa.Integer()),
        sa.column("created_at", sa.DateTime(timezone=True)),
    )
    claimed_snapshots: set[tuple[str, str]] = set()
    active_tasks = bind.execute(
        sa.select(
            campaign_tasks.c.id,
            campaign_tasks.c.campaign_id,
            campaign_tasks.c.task_type,
            campaign_tasks.c.status,
            campaign_tasks.c.payload,
            campaign_tasks.c.execution_claim_id,
        )
        .where(campaign_tasks.c.status.in_(("dispatched", "running")))
        .order_by(
            campaign_tasks.c.campaign_id,
            campaign_tasks.c.created_at,
            campaign_tasks.c.id,
        )
    ).mappings()
    for task in active_tasks:
        payload = _payload(task["payload"])
        source_snapshot_digest = payload.get("source_snapshot_digest")
        execution_claim_id = task["execution_claim_id"]
        if (
            task["task_type"] != _LOCAL_TOOL_TASK_TYPE
            or payload.get("schema_version") != _LOCAL_TOOL_TASK_SCHEMA
            or payload.get("execution_lease_required") is not True
            or not isinstance(source_snapshot_digest, str)
            or _SOURCE_SNAPSHOT_DIGEST_PATTERN.fullmatch(source_snapshot_digest) is None
            or not isinstance(execution_claim_id, str)
            or not execution_claim_id
        ):
            continue
        campaign_id = task["campaign_id"]
        identity = (campaign_id, source_snapshot_digest)
        if identity in claimed_snapshots:
            payload[_LEGACY_SLOT_MARKER] = True
            bind.execute(
                sa.update(campaign_tasks)
                .where(campaign_tasks.c.id == task["id"])
                .values(payload=payload)
            )
            bind.execute(
                sa.update(slots)
                .where(slots.c.campaign_id == campaign_id)
                .where(slots.c.source_snapshot_digest == source_snapshot_digest)
                .values(
                    legacy_active_task_count=(
                        slots.c.legacy_active_task_count + 1
                    )
                )
            )
            continue
        bind.execute(
            sa.insert(slots).values(
                id=_slot_id(campaign_id, source_snapshot_digest),
                campaign_id=campaign_id,
                source_snapshot_digest=source_snapshot_digest,
                active_task_id=task["id"],
                active_execution_claim_id=execution_claim_id,
                legacy_active_task_count=0,
                created_at=datetime.now(UTC),
            )
        )
        claimed_snapshots.add(identity)


def downgrade() -> None:
    op.drop_table("campaign_local_tool_execution_slots")
