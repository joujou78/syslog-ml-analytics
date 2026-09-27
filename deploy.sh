#!/usr/bin/env bash
# Single command for any future deploy of this project. Replaces the
# multi-step manual process that repeatedly went wrong in practice
# deploying this exact codebase:
#   - a git/.git file-ownership mismatch silently failed `git pull` for
#     the administrator login (only the syslog-ml user could write
#     .git's internal files) for an unknown number of days, with no
#     error visible until someone thought to check the actual commit
#     range a pull updated through
#   - alembic, run directly rather than via systemd, needs the real
#     database credentials sourced manually -- easy to get subtly wrong
#     (see app/core/config.py's cors_origins field for one such trap
#     that's now fixed, but the general risk of running outside
#     systemd's own EnvironmentFile= parsing remains)
#
# Run as: sudo /opt/syslog-ml/deploy.sh
# (Needs root to restart services and reload systemd; the git/alembic
# work itself always happens as the syslog-ml user, regardless of who
# invoked this script, so file ownership never drifts.)
set -euo pipefail

REPO_DIR="/opt/syslog-ml"
WEB_BACKEND_DIR="$REPO_DIR/web/backend"

if [ "$(id -u)" -ne 0 ]; then
    echo "Run this with sudo (it restarts services and reloads systemd)." >&2
    exit 1
fi

echo "==> Pulling latest code (as syslog-ml, regardless of who invoked this)..."
sudo -u syslog-ml git -C "$REPO_DIR" pull origin main

echo "==> Running database migrations..."
sudo -u syslog-ml bash -c "
    set -a
    source /etc/syslog-ml/web-api.env
    cd '$WEB_BACKEND_DIR' && ./.venv/bin/alembic upgrade head
"

echo "==> Syncing systemd unit files..."
cp "$REPO_DIR"/systemd/*.service "$REPO_DIR"/systemd/*.timer /etc/systemd/system/
cp "$REPO_DIR"/web/systemd/*.service /etc/systemd/system/
systemctl daemon-reload

echo "==> Restarting persistent services (classifier, web API)..."
# Only these two run continuously and need an explicit restart to load
# new code. Every other syslog-ml-* unit (evaluate_alerts, daily_digest,
# backup_and_purge_events, detect_silent_devices, resolve_pending,
# reverify_devices) is a oneshot triggered by its own timer -- it
# re-reads both its code and its (just daemon-reloaded) unit file fresh
# on its next scheduled firing, so restarting it here would just be
# no-op busywork.
systemctl restart syslog-ml-classifier
systemctl restart syslog-ml-web-api

echo "==> Done."
echo "    A brand-new *.timer (one that didn't exist before this deploy)"
echo "    still needs a one-time, deliberate:"
echo "      sudo systemctl enable --now <name>.timer"
echo "    This script never does that automatically -- enabling a new"
echo "    periodic job is a decision, not a side effect of a code pull."
