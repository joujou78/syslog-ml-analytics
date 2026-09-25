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
last 24h), hostname, source IP (free text -- too high-cardinality for a
dropdown), vendor, anomaly type, program, severity, category, an
"anomalies only" toggle, and a case-insensitive keyword match on the
message. Each result row shows which anomaly signal(s) fired (see the
pipeline README's "Anomaly flagging" section). It fetches one row past
the page size to derive "more results exist" instead of running
`COUNT(*)` over the match set, since an unbounded count on a table sized
for high-volume retention is the expensive query the skip indexes in
`clickhouse/init.sql` exist to help you avoid, not something to run on
every search. Page size is selectable (10/25/50/100/500), same as
Devices.

**Filter dropdowns**: Severity and Anomaly type are fixed, small enums
defined in code (there are only ever 8 severities and 6 anomaly reasons),
so their options are hardcoded in the frontend, same treatment. Vendor
and Program aren't fixed enums -- they're whatever's actually shown up in
your fleet -- so `GET /api/logs/filter-options` returns the real distinct
values via a single `groupUniqArray` pass over `syslog_ml.events`,
bounded to the last `FILTER_OPTIONS_LOOKBACK_DAYS` (30) so the query
doesn't get slower as the table grows (it now retains data indefinitely).
If a filter value arrives via a deep link (e.g. an Anomaly Summary
drill-down) that isn't in that 30-day window, it's still shown as a valid
selected option -- the dropdown never silently drops a value it didn't
happen to fetch.

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
role, same split as `/devices`. The same page's **"Currently silent
devices"** section (`GET /api/device-silence`) is a different kind of
alert — not rule-based, but a device whose own historical logging pattern
predicts activity by now and hasn't logged in that long. See the pipeline
README's "Device-silence detection" section for the worker
(`ml/detect_silent_devices.py`) that maintains this; the page itself is a
read-only view over `device_silence_state`, open to any authenticated
role like the rest of this page.

**Audit Log** ("Audit Log" in the nav, admin-only) is a read-only view
(`GET /api/audit`, `/api/audit/actions`) over `audit_log` — a record of
every administrative action across the system (alert rules, SNMP
credentials, relay source IPs, anomaly acknowledgments, query console
usage), written by each of those features' own service functions. Admin-
only because it's broader-reaching than any single page it covers, not
because any individual entry is more sensitive than what its own page
already shows (a credential's audit target is its `ip_or_cidr`, never the
actual community string or passphrase).

**Anomaly Windows** (`GET /api/anomaly-windows`, "Anomaly Windows" in the
nav) is a read-only, paginated view over `syslog_ml.device_window_anomalies`
— the periodic, windowed template-mix detector's own scored output (see
the pipeline README's "Windowed template-mix anomaly detection" section),
distinct from the per-event anomalies Log Search filters on. Defaults to
flagged windows only, over the last 24h; toggle to "all scored windows" to
see the unflagged ones too, e.g. to sanity-check what a device's normal
score range looks like. Each row shows whether it was judged against that
device's own model or a pooled vendor baseline. hostname is joined live
from `events` (not stored on the anomaly table itself, since a device's
resolved identity can change after the fact) using the same
`FINAL`-qualified read pattern needed because the underlying table is a
`ReplacingMergeTree` -- each window is scored exactly once (see
ml/template_mix_anomaly.py's own note on why), so `FINAL` here is only
guarding against the rare checkpoint-restart overlap case, not routine
ongoing rescoring.

**Anomaly Summary** (`GET /api/anomaly-summary/devices` and `/vendors`,
"Anomaly Summary" in the nav) answers a different question than Anomaly
Windows or Log Search: not "what happened recently" but "how many times,
total, has each device produced each *type* of anomaly (rare_template,
always_severe, security_content, severity_spike, volume_spike,
unusual_template_mix), since the beginning of your data". Built from
`syslog_ml.events` with `arrayJoin(anomaly_reasons)` to unnest the array
column — an event tagged with two reasons contributes to two separate
(device, reason) rows, not one. No time filter, deliberately: this is a
cumulative view, not a rolling window.

Each (device, anomaly type) row can be **acknowledged** — a persistent
"reviewed and handled" flag stored in Postgres'
`anomaly_acknowledgments` (upserted, unique on `(source_ip,
anomaly_reason)`), with an optional free-text note (e.g. "restarted
switch, resolved") and who/when. By explicit choice, it does **not**
auto-reset when a new matching event arrives later — it stays
acknowledged until someone explicitly un-acknowledges it. That's a real
tradeoff: a genuinely recurring problem can go unnoticed behind an old
ack if nobody thinks to re-check it, chosen anyway because a stable flag
was wanted over one that silently flips back on every recurrence.
Acknowledging/un-acknowledging is admin/analyst (same split as alert rule
management); viewing is open to any authenticated role.

The "By vendor" toggle switches to a read-only rollup (`GROUP BY vendor,
reason` instead of `source_ip, reason`) for a fleet-wide view of which
anomaly types are common for a given vendor and how many distinct devices
are affected — not individually acknowledgable, since an ack is
meaningful per-device (you fix one specific box), not per-vendor. Export
(CSV/XML) respects whichever view is currently selected.

A separate **Metric** selector switches the whole page from "Anomaly
type" to **Category** (`GET /api/anomaly-summary/devices/by-category` and
`/vendors/by-category`) — the same (device or vendor) × count report
shape, but grouped by `predicted_category` (AUTH, SECURITY, HARDWARE,
NETWORK, ...) over *all* events, not just anomalous ones, and with no
acknowledgment column (a category isn't an issue to mark "handled").
Export takes the same `group_by` toggle plus a `metric=anomaly|category`
parameter.

**Honest cost caveat, worse than the anomaly metric's already-noted one**:
Category's queries scan and aggregate *all* of `syslog_ml.events` with no
time bound and no `is_anomaly` filter (every event has a category; only
some are anomalies), and since `events` now retains data indefinitely (no
TTL — see the pipeline README), this full scan only gets more expensive
as the table grows, with nothing here capping it. Accepted deliberately,
consistent with wanting genuinely cumulative "since the start" counts
rather than a rolling window — but if it becomes slow in practice, the
fix is a periodic pre-aggregated rollup (the same pattern
`device_window_anomalies` already uses for the windowed anomaly
detector), not silently adding a time filter that would quietly change
what the numbers mean.

Every count in either metric is a link into **Log Search**, pre-filtered
to exactly that row (`source_ip` + `anomaly_reason`/`predicted_category`
for a device row, `vendor` + the same for a vendor rollup row) — so
"how many times" always has a "show me which ones" one click away. This
needed two additions to Log Search itself: `vendor` and `anomaly_reason`
filters (the latter via `has(anomaly_reasons, ...)`, since that column is
an array — an event can carry more than one reason), and Log Search now
reads its initial filter state from the URL's query string on mount (once,
not kept in sync afterward) so a link like `/logs?vendor=cisco&anomaly_reason=severity_spike`
actually lands pre-filled instead of on an empty form. The link also
carries `start=<that row's first_seen>`, since without it Log Search's own
24h default window would silently show "no results" for a cumulative
count that includes events far older than a day.

**Query Console** (`POST /api/query-console/execute`, "Query Console" in
the admin nav) is full, unrestricted SQL access against ClickHouse from
the browser — including `ALTER`, `DELETE`, `DROP`, and `TRUNCATE`. This is
a deliberate departure from this app's usual "narrow, explicit allowlist"
posture (Relay Source IPs, SNMP Credentials): built this way by explicit
request, not by default. Admin-only, and every query is written to
`audit_log` (full query text, actor, timestamp) **before** it executes —
not after — so a query that crashes the worker or times out still leaves
a record of what was attempted, since the audit trail is this feature's
only real safety net. `SELECT`/`SHOW`/`DESCRIBE`/`EXPLAIN`/`WITH`
statements return a results table (capped at 1,000 rows); anything else
runs via ClickHouse's command path and just confirms success, since
DDL/mutations don't return rows. A 30-second query timeout is a backstop
against one runaway query tying up a web worker indefinitely, not a
substitute for the admin knowing what they're running. There is
deliberately no query history or saved-queries feature (yet) — the audit
log is the record.

**Log Assistant** (`POST /api/log-assistant/search` and `/ask`, "Log
Assistant" in the nav) is a different kind of lookup than everything
above: a plain-language question, answered by finding log lines that are
semantically *related* to it via embeddings + OpenSearch, fused with a
BM25 keyword match so an exact IP/hostname/error code in the question
still reliably surfaces the lines containing it (see the pipeline
README's "Retrieval is hybrid, not pure vector search" for why) and, for
`/ask`, having a local LLM (Ollama) read those lines and write an answer.
See the pipeline README's "Log Assistant" section for the indexing
pipeline (`ml/log_assistant_indexer.py`) and the OpenSearch/Ollama install
steps this depends on. `/search` alone (the
page's "Search only" button) skips the LLM call entirely and just returns
matching log lines with their similarity score — useful when you want
results in under a second instead of waiting on CPU-bound inference.
Both endpoints take the same optional `source_ip`/`vendor`/`start`/`end`
filters as Log Search, applied as OpenSearch k-NN *pre*-filters (not a
post-filter on the unfiltered top-k — see `log_assistant_service.py`'s
`_build_query`, which needs the index's `lucene` engine specifically for
this to work correctly at all). Open to any authenticated role, same as
Log Search — the LLM call being slow on CPU-only hardware is a
performance characteristic for whoever asks, not a reason to restrict who
can.

Anomaly Windows and Anomaly Summary each add an **"Explain with AI"**
link per row, pre-filling a question plus that row's device and a padded
time range around it (the flagged instant/window itself padded with
before/after minutes — see `utils/time.ts`'s `padWindow` — since an LLM
asked about one bare timestamp has nothing to reason over). Anomaly
Summary's link anchors on `last_seen`, not `first_seen` like its own Log
Search drill-down links — deliberately different, since "explain this"
is about what's happening *now* (or most recently), while the Log Search
link's `first_seen` anchor exists only to keep a cumulative count's
default 24h window from looking empty.

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
- **Audit Log and device-silence detection were verified against a real
  local ClickHouse and Postgres both** (a real, if very old, ClickHouse
  server — not just mocked — became available in this session's sandbox
  after installing it directly, better coverage than most of this file's
  other entries could get): the audit log's join/ordering/action-filter
  query, and `ml/detect_silent_devices.py`'s full newly-silent /
  still-silent-within-cooldown / recovered state machine, including the
  Postgres migration's upgrade and downgrade both applying cleanly. Also
  verified in a real browser (Playwright) end to end — login, nav,
  render, filter — via `e2e/test_audit_log.mjs` and
  `e2e/test_device_silence.mjs`. Not verified against your actual device
  traffic's real inter-arrival patterns, so the default
  `SILENCE_MULTIPLIER`/`SILENCE_MIN_MINUTES` may need tuning once you see
  real data — see the pipeline README's "Device-silence detection"
  section.
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
- **Log Assistant's OpenSearch/Ollama calls were never exercised against
  real OpenSearch or Ollama** — this session's sandbox couldn't reach
  either service to install them (see the pipeline README's "Log
  Assistant" section for why, and exactly what *was* verified instead:
  the real `opensearch-py` client library, and the full FastAPI route
  stack against mocked responses shaped like each service's documented
  API). If a request to `/log-assistant/search` or `/ask` fails after you
  install the real services, a `502` response means the backend reached
  this code path but OpenSearch or Ollama itself returned an error or
  wasn't reachable — check `journalctl -u opensearch`/`-u ollama` first.

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
