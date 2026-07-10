"""Scope artifact source hashes to their program."""

from alembic import op


revision = "0011_artifact_program_scope"
down_revision = "0010_learning_signal_identity_hash"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table(
        "artifacts",
        naming_convention={"uq": "uq_%(table_name)s_%(column_0_name)s"},
    ) as batch_op:
        batch_op.drop_constraint("uq_artifacts_source_hash", type_="unique")
        batch_op.create_unique_constraint(
            "uq_artifacts_program_source_hash",
            ["program_id", "source_hash"],
        )


def downgrade() -> None:
    with op.batch_alter_table("artifacts") as batch_op:
        batch_op.drop_constraint("uq_artifacts_program_source_hash", type_="unique")
        batch_op.create_unique_constraint("uq_artifacts_source_hash", ["source_hash"])
