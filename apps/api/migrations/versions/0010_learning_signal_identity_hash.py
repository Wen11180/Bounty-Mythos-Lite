"""Add learning signal identity hash."""

from alembic import op
import sqlalchemy as sa


revision = "0010_learning_signal_identity_hash"
down_revision = "0009_approval_record_expiry"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("learning_signals") as batch_op:
        batch_op.add_column(sa.Column("identity_hash", sa.String(length=100), nullable=True))
        batch_op.create_index(
            "uq_learning_signals_identity_hash",
            ["identity_hash"],
            unique=True,
        )


def downgrade() -> None:
    with op.batch_alter_table("learning_signals") as batch_op:
        batch_op.drop_index("uq_learning_signals_identity_hash")
        batch_op.drop_column("identity_hash")
