# Syslog ML Analytics — Web App

FastAPI + Postgres backend, React (Vite + TypeScript) frontend. Provides
device/credential management, log search, and alerting now, with an ML
feedback/correction loop planned as a later phase (see "Roadmap" below).

**Timestamps are displayed in Beirut local time** across every page
(Devices, Log Search, Alerts, Credentials) via `src/utils/time.ts` --
using the real `Asia/Beirut` IANA timezone (not a fixed offset), so it
stays correct across DST if Lebanon observes it, confirmed against both
a September (+3h) and January (+2h) UTC timestamp. This is display-only:
every timestamp is still stored and transmitted as UTC end-to-end (see
the pipeline README's `clickhouse/init.sql`), which every window/TTL/
comparison query in this codebase assumes -- only the last rendering
step converts it. **Known gap**: the Log Search page's Start/End filter
inputs (`<input type="datetime-local">`) are not converted the same
way -- they still submit the browser's own local wall-clock time as a
naive value straight to the API, so filtering by a specific time range
can be off if the viewer's browser isn't itself set to Beirut time.

**Devices** ("Devices" in the nav) is paginated (10/25/50/100/500 per page,
same `has_more`-based approach as log search) and auto-refreshes its
current page every 30 seconds in the background, since devices resolve
and new ones appear continuously — no manual reload needed to stay
current. The page size and current offset are preserved across
auto-refreshes; only an explicit page-size change or Previous/Next click
resets or moves the offset.

It's also searchable by hostname, IP, vendor, and a start/end time range
(defaults to the last 24h, same as log search). hostname/vendor match
against each device's most-recently-seen identity, so they're applied in
a ClickHouse `HAVING` clause (after the per-device `argMax` aggregation)
rather than `WHERE`; IP matches the raw `source_ip` column directly.
Applying a search resets pagination back to the first page. Covered by
`web/frontend/e2e/devices_search.mjs` (`npm run test:e2e:devices-search`).

**Log search** (`GET /api/logs/search`, "Log Search" in the nav) is a
filtered, paginated query straight over `syslog_ml.events` in ClickHouse —
no new database, no new data path. Filters: time range (defaults to the
last 24h), hostname, source IP, program, severity, category, an
"anomalies only" toggle, and a case-insensitive keyword match on the
message. Each result row shows which anomaly signal(s) fired (see the
pipeline README's "Anomaly flagging" section). It fetches one row past
the page size to derive "more results exist" instead of running
`COUNT(*)` over the match set, since an unbounded count on a table sized
for high-volume retention is the expensive query the skip indexes in
`clickhouse/init.sql` exist to help you avoid, not something to run on
every search. Page size is selectable (10/25/50/100/500), same as
Devices.

**Export** (`GET /api/logs/export`, "Export CSV"/"Export XML" buttons on
the Log Search page) downloads every row matching the *currently applied*
filters -- not just the current page -- as a single CSV or XML file, up
to `EXPORT_MAX_ROWS` (50,000; a `X-Export-Truncated: true` response
header, surfaced as a warning in the UI, tells you if the real match set
was larger). Shares the same filter-building logic as `/logs/search` via
`log_search_service._build_conditions`, so a filter added to one search
path can't silently drift from the other. Covered by
`web/frontend/e2e/logs_export.mjs` (`npm run test:e2e:logs-export`).

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
- **Bulk credential pool import** (Credentials page): for a known set of
  community strings with no per-device mapping, paste them all under one
  shared scope instead of entering devices one at a time. See the pipeline
  README's "Credential pools" section for how the resolver uses this to
  discover and auto-save each device's own credential.
- **Relay Source IPs** (admin nav, `relay_source_ips` table): the same
  "admin-managed in Postgres, not a config file/env var" pattern applied
  to the list of syslog relay IPs `ml/consumer.py` trusts enough to
  recover per-device identity from a relayed message's body — see the
  pipeline README's "Relay Source IPs" section for what this actually
  does and why it's a narrow, explicit allowlist rather than automatic.
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

### Applying a future migration (after `git pull` adds a new one)

Every later `alembic upgrade head` needs `SYSLOG_ML_DATABASE_URL` set
explicitly, same as above — without it, `Settings()`'s class default
(`postgresql+asyncpg://syslog_ml:syslog_ml@localhost:5432/syslog_ml`, a
dev-only placeholder password) silently applies instead of your real one,
and alembic fails with "password authentication failed" that has nothing
to do with the migration itself. Reuse the password already deployed
rather than retyping it:

```bash
sudo grep SYSLOG_ML_DATABASE_URL /etc/syslog-ml/web-api.env
cd /opt/syslog-ml/web/backend
sudo -u syslog-ml SYSLOG_ML_DATABASE_URL='<value from the grep above>' .venv/bin/alembic upgrade head
sudo systemctl restart syslog-ml-web-api
```

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
- The credential pool's bulk import, the fast-path/discovery/auto-save
  logic in `device_resolver.py`, and the upsert-on-rotation behavior in
  `save_discovered_credential()` were verified end to end against a real
  local Postgres and, since finding and fixing a real bug during initial
  net-flow testing (below), a real local `snmpd` agent too — not against
  your specific real devices' network paths/firmware, so if resolution
  behaves unexpectedly, check `journalctl -u syslog-ml-resolver` for which
  credential(s) were tried.
- **A real bug, found and fixed during initial deployment**: `snmpget_args()`
  was passing `-v v2c`/`-v v1` to the `snmpget` CLI (matching how the
  version is stored in the database), but net-snmp's `-v` flag only
  accepts `1`/`2c`/`3` without the `v` prefix — `-v v2c` fails immediately
  with "Invalid version specified", indistinguishable in the logs from a
  wrong community. This silently broke every v1/v2c SNMP resolution
  attempt since the resolver was first written, not something introduced
  by the credential-pool work — it just took a real multi-candidate pool
  test against a real device to surface clearly. Confirmed against a real
  local `snmpd`: `-v v2c` fails with exit code 1, `-v 2c` succeeds.
- The multi-signal anomaly detection (`always_severe`, `security_content`,
  `severity_spike`, `volume_spike`, plus the pre-existing `rare_template`)
  was verified with real inputs run through the actual `to_row()`/
  `DeviceBaselineCache` code — including the trickier stateful cases (a
  device's in-memory "worst severity" baseline updating after a spike so
  the same severity doesn't re-trigger, and a volume-spike signal
  correctly clearing once traffic returns to normal) — but against
  synthetic ClickHouse responses, since real ClickHouse isn't reachable
  from this sandbox. The `GROUP BY source_ip` baseline query itself is
  unverified against your real `events` table size; if it looks slow,
  widen `ANOMALY_BASELINE_REFRESH_SECONDS` before widening the window.
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
