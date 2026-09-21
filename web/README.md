# Syslog ML Analytics — Web App

FastAPI + Postgres backend, React (Vite + TypeScript) frontend. Provides
device/credential management, log search, and alerting now, with an ML
feedback/correction loop planned as a later phase (see "Roadmap" below).

**Log search** (`GET /api/logs/search`, "Log Search" in the nav) is a
filtered, paginated query straight over `syslog_ml.events` in ClickHouse —
no new database, no new data path. Filters: time range (defaults to the
last 24h), hostname, source IP, program, severity, category, and a
case-insensitive keyword match on the message. It fetches one row past the
page size to derive "more results exist" instead of running `COUNT(*)`
over the match set, since an unbounded count on a table sized for
high-volume retention is the expensive query the skip indexes in
`clickhouse/init.sql` exist to help you avoid, not something to run on
every search.

**Alerts** ("Alerts" in the nav) manage `alert_rules` here in Postgres
(name, enabled, window/threshold/cooldown, the same filter fields as log
search, an "anomalies only" toggle, and an optional webhook URL); a
separate process, `ml/evaluate_alerts.py`, does the actual evaluation
against ClickHouse and writes `alert_events` — see the pipeline README's
"Alerting" section for how that worker runs. Rule management is
admin/analyst; viewing rules and history is open to any authenticated
role, same split as `/devices`.

## Why this stack

- **FastAPI**: shares Python with the rest of the pipeline (`ml/`), async,
  typed, and gives an OpenAPI schema for free.
- **Postgres**, separate from ClickHouse: the web app's own state (users,
  SNMP credentials, audit log, ML feedback) is comparatively small,
  relational, and needs transactional writes — a poor fit for ClickHouse,
  which stays dedicated to the high-volume append-only log events.
- **SNMP credentials moved from a CSV file into this database**: same
  "opt-in, never guessed" principle as before, now with an admin-only UI,
  encryption at rest (Fernet), and an audit trail instead of a flat file
  anyone with VM access could read in plaintext. `ml/device_resolver.py`
  reads from this same table now — one source of truth.
- **React SPA**: the app has real interactive state (forms, filters, role-
  gated views) that suits client-side routing better than server-rendered
  pages.

## Structure

```
web/
  backend/
    app/
      core/       # config, JWT + bcrypt auth, Fernet encryption for secrets
      db/         # SQLAlchemy async models (users, snmp_credentials, ...)
      schemas/    # Pydantic request/response models
      services/   # business logic, separated from route handlers
      api/routes/ # thin FastAPI route handlers
      clickhouse_client.py
    migrations/   # Alembic
    scripts/create_admin.py   # bootstrap the first admin account
  frontend/
    src/
      api/        # typed API client (axios)
      auth/       # AuthContext (JWT storage, login/logout)
      components/ # Layout, ProtectedRoute (role-gated)
      pages/      # Login, Devices, Credentials
    e2e/smoke.mjs # Playwright smoke test of the real auth/RBAC/CRUD flow
  systemd/        # production unit for the API (gunicorn+uvicorn workers)
  nginx/          # reverse proxy + static SPA serving config
```

## Local development

Backend:

```bash
cd web/backend
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
# Postgres running locally with a syslog_ml DB/user (see Step 1 below)
export SYSLOG_ML_DATABASE_URL=postgresql+asyncpg://syslog_ml:syslog_ml@localhost:5432/syslog_ml
.venv/bin/alembic upgrade head
.venv/bin/python scripts/create_admin.py --username admin
.venv/bin/uvicorn app.main:app --reload --port 8000
```

Frontend (separate terminal):

```bash
cd web/frontend
npm install
npm run dev   # http://localhost:5173, proxies /api to :8000 (see vite.config.ts)
```

Smoke test (with both servers running):

```bash
cd web/frontend
ADMIN_USERNAME=admin ADMIN_PASSWORD=<the password you set> npm run test:e2e
```

## Production install (Ubuntu/Debian, continuing from the pipeline's own README)

Assumes Step 1 (service account/directories) from the top-level
`syslog-ml-analytics/README.md` is already done.

### 1. Install Postgres

```bash
sudo apt-get install -y postgresql
sudo -u postgres psql -c "CREATE USER syslog_ml WITH PASSWORD '<pick a real password>';"
sudo -u postgres psql -c "CREATE DATABASE syslog_ml OWNER syslog_ml;"
```

### 2. Deploy the backend

```bash
sudo cp -r web/backend /opt/syslog-ml/web/backend
cd /opt/syslog-ml/web/backend
sudo python3 -m venv .venv
sudo .venv/bin/pip install -r requirements.txt

sudo cp systemd/web-api.env.example /etc/syslog-ml/web-api.env   # from repo root's web/systemd/
sudo $EDITOR /etc/syslog-ml/web-api.env   # fill in real secrets
sudo chmod 600 /etc/syslog-ml/web-api.env
sudo chown syslog-ml:syslog-ml /etc/syslog-ml/web-api.env /opt/syslog-ml/web/backend -R

# Run the migration and create the first admin as the syslog-ml user so
# file ownership stays consistent:
sudo -u syslog-ml SYSLOG_ML_DATABASE_URL=postgresql+asyncpg://syslog_ml:<password>@localhost:5432/syslog_ml \
  /opt/syslog-ml/web/backend/.venv/bin/alembic upgrade head
sudo -u syslog-ml SYSLOG_ML_DATABASE_URL=postgresql+asyncpg://syslog_ml:<password>@localhost:5432/syslog_ml \
  /opt/syslog-ml/web/backend/.venv/bin/python scripts/create_admin.py --username admin
```

**Checkpoint** — confirm `alembic upgrade head` reports success and the admin script prints a user ID.

### 3. Wire up the API systemd service and the resolver's shared credentials

```bash
sudo cp web/systemd/syslog-ml-web-api.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now syslog-ml-web-api

# The resolver (from the pipeline README) needs the SAME database and
# encryption key as the web app:
sudo cp systemd/syslog-ml-resolver.env.example /etc/syslog-ml/resolver.env   # from repo root's systemd/
sudo $EDITOR /etc/syslog-ml/resolver.env   # DATABASE_URL + CREDENTIAL_ENCRYPTION_KEY, matching web-api.env
sudo chmod 600 /etc/syslog-ml/resolver.env
sudo chown syslog-ml:syslog-ml /etc/syslog-ml/resolver.env
sudo systemctl restart syslog-ml-resolver.timer   # if already running from before
```

**Checkpoint:** `curl http://127.0.0.1:8000/api/health` should return `{"status":"ok"}`.

### 4. Build and serve the frontend

Ubuntu 22.04's default `apt install nodejs` gives you Node 12.x from the
Ubuntu archive — too old for this frontend's build tooling (Vite 8), which
I confirmed by checking what Vite actually requires. Install a current
Node LTS from NodeSource instead (`deb.nodesource.com` is blocked from
this sandbox too, so the exact command below is from training data, not a
live check — if it 404s or errors, NodeSource's current setup instructions
are the fallback):

```bash
curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
sudo apt-get install -y nodejs
node --version   # should print v20.x, not v12.x
```

Then build and deploy:

```bash
sudo apt-get install -y nginx
cd web/frontend
npm ci
npm run build
sudo mkdir -p /opt/syslog-ml/web/frontend
sudo cp -r dist /opt/syslog-ml/web/frontend/dist

sudo cp web/nginx/syslog-ml-web.conf /etc/nginx/sites-available/syslog-ml-web
sudo ln -s /etc/nginx/sites-available/syslog-ml-web /etc/nginx/sites-enabled/
sudo nginx -t && sudo systemctl reload nginx
```

**Checkpoint** — open `http://<vm-ip>/` and confirm the login page loads,
then log in with the admin account from Step 2.

## Honest limitations

- No TLS in the provided nginx config — this handles login credentials and
  SNMP secrets, so put it behind HTTPS (a reverse proxy with certbot, or
  your existing TLS termination) before exposing it beyond a trusted
  network. I didn't set this up because I don't know your domain/cert
  situation.
- Tested in this session against a real local Postgres and a real browser
  (Playwright) for the full auth/RBAC/credential-CRUD/persistence flow —
  not tested against a live ClickHouse (none available in this sandbox),
  so the Devices, Log Search, and Alerts pages' actual data rendering (as
  opposed to their error handling, which was exercised) is unverified
  until you run them against your real ClickHouse instance.
- The alert rule CRUD (create/list/update/delete/history) was verified
  against a real local Postgres, and `ml/evaluate_alerts.py`'s rule
  evaluation, cooldown logic, and webhook delivery were verified end to end
  against that same Postgres plus a mock ClickHouse client and a real local
  HTTP server standing in for a webhook receiver — not against your actual
  network traffic, so confirm a rule fires as expected on real data before
  relying on it.
- Password reset / account recovery isn't built — the only way to regain
  access if the sole admin's password is lost is `scripts/create_admin.py`
  won't help (it refuses existing usernames) or a manual DB update.

## Roadmap (not yet built)

- **ML feedback loop**: the `classification_feedback` table already exists
  (see `app/db/models.py`) but has no API/UI yet — review predicted
  categories, correct wrong ones, feed corrections back into
  `ml/train_classifier.py`.
- **Event correlation**: grouping related events (e.g. several anomalies
  from the same host in a short window) into a single "incident" rather
  than one alert per event. Not built — alerting fires per rule match, not
  per correlated group.
- **Alert notification channels beyond a webhook** (email/SMS): the
  evaluator only POSTs a webhook today; see the pipeline README's
  "Alerting" section for why.
