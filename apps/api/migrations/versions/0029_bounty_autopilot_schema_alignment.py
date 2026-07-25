"""Align published schema with current Autopilot ORM metadata."""

from alembic import op
import sqlalchemy as sa


revision = "0029_bounty_autopilot_schema_alignment"
down_revision = "0028_bounty_autopilot_r2_observation_pair"
branch_labels = None
depends_on = None


def _index_exists(table_name: str, index_name: str) -> bool:
    return any(
        index["name"] == index_name
        for index in sa.inspect(op.get_bind()).get_indexes(table_name)
    )


def _column_is_nullable(table_name: str, column_name: str) -> bool:
    return next(
        column["nullable"]
        for column in sa.inspect(op.get_bind()).get_columns(table_name)
        if column["name"] == column_name
    )


def _create_index_if_missing(
    index_name: str,
    table_name: str,
    columns: list[str],
) -> None:
    if not _index_exists(table_name, index_name):
        op.create_index(index_name, table_name, columns)


def upgrade() -> None:
    _create_index_if_missing(
        "ix_execution_leases_campaign_status",
        "execution_leases",
        ["campaign_id", "status"],
    )
    _create_index_if_missing(
        "ix_execution_request_ledger_campaign_lease",
        "execution_request_ledger",
        ["campaign_id", "lease_id"],
    )
    _create_index_if_missing(
        "ix_autopilot_observations_campaign_branch",
        "autopilot_observations",
        ["campaign_id", "branch_id"],
    )
    if _column_is_nullable("llm_runs", "created_at"):
        op.execute(
            "UPDATE llm_runs SET created_at = CURRENT_TIMESTAMP WHERE created_at IS NULL"
        )
        with op.batch_alter_table("llm_runs") as batch_op:
            batch_op.alter_column(
                "created_at",
                existing_type=sa.DateTime(timezone=True),
                nullable=False,
            )


def downgrade() -> None:
    if not _column_is_nullable("llm_runs", "created_at"):
        with op.batch_alter_table("llm_runs") as batch_op:
            batch_op.alter_column(
                "created_at",
                existing_type=sa.DateTime(timezone=True),
                nullable=True,
            )
    for index_name, table_name in (
        ("ix_autopilot_observations_campaign_branch", "autopilot_observations"),
        ("ix_execution_request_ledger_campaign_lease", "execution_request_ledger"),
        ("ix_execution_leases_campaign_status", "execution_leases"),
    ):
        if _index_exists(table_name, index_name):
            op.drop_index(index_name, table_name=table_name)
