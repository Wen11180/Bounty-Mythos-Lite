"""Make each R2 reservation consumable exactly once."""

from alembic import op
import sqlalchemy as sa


revision = "0030_bounty_autopilot_observation_replay_guard"
down_revision = "0029_bounty_autopilot_schema_alignment"
branch_labels = None
depends_on = None


_TABLE_NAME = "autopilot_observations"
_LEGACY_INDEX = "ix_autopilot_observations_campaign_comparison_reservation"
_UNIQUE_INDEX = "uq_autopilot_observations_campaign_comparison_reservation"


def _index(index_name: str) -> dict | None:
    return next(
        (
            item
            for item in sa.inspect(op.get_bind()).get_indexes(_TABLE_NAME)
            if item["name"] == index_name
        ),
        None,
    )


def _has_replayed_reservation() -> bool:
    return (
        op.get_bind()
        .execute(
            sa.text(
                """
                SELECT 1
                FROM (
                    SELECT campaign_id, reservation_id AS consumed_reservation_id
                    FROM autopilot_observations
                    WHERE reservation_id IS NOT NULL
                    UNION ALL
                    SELECT campaign_id, comparison_reservation_id AS consumed_reservation_id
                    FROM autopilot_observations
                    WHERE comparison_reservation_id IS NOT NULL
                ) AS consumed_reservations
                GROUP BY campaign_id, consumed_reservation_id
                HAVING COUNT(*) > 1
                LIMIT 1
                """
            )
        )
        .scalar()
        is not None
    )


def upgrade() -> None:
    if _has_replayed_reservation():
        raise RuntimeError("autopilot_observation_reservation_replay")
    unique_index = _index(_UNIQUE_INDEX)
    if unique_index is None or not unique_index.get("unique"):
        if unique_index is not None:
            op.drop_index(_UNIQUE_INDEX, table_name=_TABLE_NAME)
        op.create_index(
            _UNIQUE_INDEX,
            _TABLE_NAME,
            ["campaign_id", "comparison_reservation_id"],
            unique=True,
        )
    if _index(_LEGACY_INDEX) is not None:
        op.drop_index(_LEGACY_INDEX, table_name=_TABLE_NAME)


def downgrade() -> None:
    if _index(_UNIQUE_INDEX) is not None:
        op.drop_index(_UNIQUE_INDEX, table_name=_TABLE_NAME)
    if _index(_LEGACY_INDEX) is None:
        op.create_index(
            _LEGACY_INDEX,
            _TABLE_NAME,
            ["campaign_id", "comparison_reservation_id"],
        )
