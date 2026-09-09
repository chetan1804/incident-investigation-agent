"""Add metric anomaly evidence."""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "20260909_0007"
down_revision: str | None = "20260908_0006"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "metric_anomalies",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("anomaly_id", sa.String(length=64), nullable=False),
        sa.Column("service_id", sa.Integer(), nullable=False),
        sa.Column("incident_id", sa.Integer(), nullable=True),
        sa.Column("metric_name", sa.String(length=255), nullable=False),
        sa.Column("observed_value", sa.Float(), nullable=False),
        sa.Column("baseline_value", sa.Float(), nullable=False),
        sa.Column("unit", sa.String(length=64), nullable=True),
        sa.Column("severity", sa.String(length=32), nullable=False),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("metadata_json", sa.JSON(), nullable=True),
        sa.ForeignKeyConstraint(["incident_id"], ["incidents.id"]),
        sa.ForeignKeyConstraint(["service_id"], ["services.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_metric_anomalies_id"), "metric_anomalies", ["id"])
    op.create_index(
        op.f("ix_metric_anomalies_anomaly_id"),
        "metric_anomalies",
        ["anomaly_id"],
        unique=True,
    )
    op.create_index(
        op.f("ix_metric_anomalies_service_id"), "metric_anomalies", ["service_id"]
    )
    op.create_index(
        op.f("ix_metric_anomalies_incident_id"), "metric_anomalies", ["incident_id"]
    )
    op.create_index(
        op.f("ix_metric_anomalies_observed_at"), "metric_anomalies", ["observed_at"]
    )


def downgrade() -> None:
    op.drop_table("metric_anomalies")
