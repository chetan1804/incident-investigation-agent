"""Add confirmed incident resolution fields."""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "20260908_0006"
down_revision: str | None = "20260907_0005"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("incidents") as batch_op:
        batch_op.add_column(sa.Column("resolved_at", sa.DateTime(timezone=True), nullable=True))
        batch_op.add_column(sa.Column("root_cause", sa.Text(), nullable=True))
        batch_op.add_column(sa.Column("resolution_summary", sa.Text(), nullable=True))
        batch_op.add_column(
            sa.Column("resolution_confirmed_by", sa.String(length=255), nullable=True)
        )
        batch_op.create_index(
            op.f("ix_incidents_resolved_at"), ["resolved_at"], unique=False
        )


def downgrade() -> None:
    with op.batch_alter_table("incidents") as batch_op:
        batch_op.drop_index(op.f("ix_incidents_resolved_at"))
        batch_op.drop_column("resolution_confirmed_by")
        batch_op.drop_column("resolution_summary")
        batch_op.drop_column("root_cause")
        batch_op.drop_column("resolved_at")
