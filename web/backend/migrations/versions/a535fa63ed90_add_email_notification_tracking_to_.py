"""add email notification tracking to alert_events

Revision ID: a535fa63ed90
Revises: 7e0d23d49895
Create Date: 2026-09-27 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'a535fa63ed90'
down_revision: Union[str, None] = '7e0d23d49895'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Purely additive, parallel to the existing notified/notify_error
    # columns which are webhook-specific -- ml/evaluate_alerts.py now also
    # sends email (via ml/emailer.py, a global ALERT_EMAIL_RECIPIENTS list,
    # not a per-rule column -- kept simple rather than adding a second
    # per-rule recipients field alongside webhook_url) and needs its own
    # success/failure tracking, since a rule can succeed on one channel
    # and fail on the other.
    op.add_column('alert_events', sa.Column('email_notified', sa.Boolean(), nullable=False, server_default=sa.false()))
    op.add_column('alert_events', sa.Column('email_notify_error', sa.String(length=1024), nullable=True))


def downgrade() -> None:
    op.drop_column('alert_events', 'email_notify_error')
    op.drop_column('alert_events', 'email_notified')
