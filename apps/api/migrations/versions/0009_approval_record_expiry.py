"""Add approval record expiry."""

from alembic import op
import sqlalchemy as sa


revision = "0009_approval_record_expiry"
down_revision = "0008_validation_runs"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("approval_records") as batch_op:
        batch_op.add_column(sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("approval_records") as batch_op:
        batch_op.drop_column("expires_at")
