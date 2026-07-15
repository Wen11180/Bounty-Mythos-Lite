"""Add redacted field-pilot metadata to learning signals."""

from alembic import op
import sqlalchemy as sa


revision = "0012_field_pilot_feedback"
down_revision = "0011_artifact_program_scope"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("learning_signals") as batch_op:
        batch_op.add_column(sa.Column("field_pilot_feedback", sa.JSON(), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("learning_signals") as batch_op:
        batch_op.drop_column("field_pilot_feedback")
