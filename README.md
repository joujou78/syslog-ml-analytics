# Syslog ML Analytics (native install, Ubuntu/Debian)

A syslog analytics stack with its own database and ML classification layer,
installed directly on your VM (no Docker), sitting **alongside** your
existing rsyslog/syslog-ng + LogAnalyzer setup — that pipeline is untouched.

## Architecture

```
network devices --syslog--> rsyslog (existing) ----------> LogAnalyzer DB (unchanged)
                                  |
                                  +--omfile (JSON copy)--> /var/log/syslog-ml/raw.jsonl
                                                                   |
                                                     syslog-ml-classifier.service (tails file)
                                                     - device identity lookup (cached)
                                                     - Drain3 template mining
                                                     - ML category classifier
                                                     - is_anomaly (rare/new template)
                                                                   |
                                                              ClickHouse
                                                                 |     |
                                                           Grafana   syslog-ml-alert-evaluator.timer
                                                                     (every 1 min) -> webhook

                          (separate, async, every 10 min)
          syslog-ml-resolver.timer -> resolve_pending.py
             for each IP seen but not yet identified:
               - has a credential in Postgres (snmp_credentials table,
                 managed via the web app)? -> SNMP sysName/sysDescr/sysObjectID
               - writes result into ClickHouse device_inventory
```

There's also a web app (`web/`) for managing SNMP credentials through a UI
instead of hand-editing files, viewing device/resolution status, searching
logs, managing alert rules, and (planned) ML feedback — see `web/README.md`.
It's optional: the pipeline above works standalone with Grafana as the only UI
(alert rules just wouldn't have anywhere to be managed without it).

No message broker: one VM, one rsyslog instance receiving everything, so a
locally tailed file is enough durability without adding a Kafka/Redpanda
service to operate.

## Why this design, and what it deliberately doesn't do

- **No SNMP credential guessing.** The resolver only ever attempts SNMP
  with a community/user an admin explicitly entered in the
  `snmp_credentials` table (Postgres, encrypted at rest, managed through
  the web app's admin UI — see `web/README.md`) — never a default/common
  string nobody entered. A "credential pool" (see below) is still this
  same rule, not an exception to it: it just lets one scope hold several
  admin-entered candidates instead of one, for when you have a known set
  of communities but no per-device mapping yet.
- **Identity has three tiers, always labeled:** `resolution_method` on every
  event is `snmp` (verified via sysName), `syslog_reported` (the device's
  own hostname claim, unverified), or `unresolved` (source IP only). The
  Grafana dashboard's "Device identity resolution" panel shows the split so
  you can see the onboarding backlog shrink over time — nothing pretends to
  know a hostname it doesn't.
- **Classification is TF-IDF + linear SVM on Drain3-mined templates**, not a
  transformer. It's the right cost/accuracy trade-off for CPU-only, 10M+
  lines/day; see the "algorithm" note in `ml/train_classifier.py`'s
  docstring for the reasoning.
- **No labeled training data exists yet.** `ml/labeling_rules.py`'s
  keyword rules bootstrap categories until you train on reviewed labels.
  Treat early `predicted_category` values as a rough sort, not verified
  fact — especially for vendor-specific message formats the generic rules
  don't cover yet.
- Sizing/timing constants (10-minute resolver interval, 60s inventory cache
  refresh, etc.) are reasonable starting points, not measured against your
  actual traffic — watch resource usage and adjust.

### Why ClickHouse, and not a separate time-series database

`raw.jsonl` is a transient hand-off file between rsyslog and the
classifier; it's never queried, so it isn't what needs to scale. The data
that actually needs fast writes and fast search is `syslog_ml.events`, and
that's already in ClickHouse: a column-oriented, time-partitioned database
built for exactly this kind of workload (it's the engine behind large-scale
log pipelines such as Cloudflare's and Uber's, at far higher volume than
one VM will see). `events` is already partitioned by day (`PARTITION BY
toYYYYMMDD(event_time)`), is retained indefinitely (no TTL -- see
`clickhouse/init.sql`'s comment on that tradeoff), has an `events_by_minute`
rollup for fast dashboards, and now has skip indexes on `message`,
`program`, `predicted_category`, and `source_ip` (see
`clickhouse/init.sql` and `clickhouse/migrations/001_search_indexes.sql`)
to keep the upcoming log-search feature fast.

A dedicated time-series database (TimescaleDB, InfluxDB, VictoriaMetrics)
was not introduced, because those are built for narrow
timestamp-plus-numeric-value data (CPU%, request latency), not rows that
mix free-text `message`, categorical fields, and keyword search, which is
what log events are. I cannot point to a benchmark comparing this exact
workload across all three run on this VM's hardware, so this is an
architectural judgment, not a measured result: flag it if you want it
verified before relying on it further. One caveat that is a fact rather
than a judgment call: this VM runs a single ClickHouse node with no
replication or sharding. If ingest volume ever outgrows one machine,
ClickHouse's own clustering (distributed tables, sharding) is the scale-out
path, not a rewrite to a different database.

## Step 1 — create the service account and directories

```bash
sudo groupadd --system syslog-ml
sudo useradd --system --gid syslog-ml --home /opt/syslog-ml --shell /usr/sbin/nologin syslog-ml

sudo mkdir -p /opt/syslog-ml /etc/syslog-ml /var/lib/syslog-ml
sudo mkdir -p -m 2770 /var/log/syslog-ml   # setgid + group-write, so rsyslog (in the syslog-ml group) can create files here
sudo chown syslog-ml:syslog-ml /var/lib/syslog-ml
sudo chown root:syslog-ml /var/log/syslog-ml /etc/syslog-ml
```

## Step 2 — install ClickHouse (official repo)

The repo/key setup below is confirmed working (verified live during initial
setup — the `/rpm/...` key path really is correct for the `.deb` repo too,
a documented ClickHouse quirk, not a typo):

```bash
sudo apt-get update
sudo apt-get install -y apt-transport-https ca-certificates curl gnupg
curl -fsSL 'https://packages.clickhouse.com/rpm/lts/repodata/repomd.xml.key' | sudo gpg --dearmor -o /usr/share/keyrings/clickhouse-keyring.gpg
echo "deb [signed-by=/usr/share/keyrings/clickhouse-keyring.gpg] https://packages.clickhouse.com/deb stable main" | sudo tee /etc/apt/sources.list.d/clickhouse.list
sudo apt-get update
```

**CPU compatibility warning:** the latest ClickHouse (26.x at time of
writing) crashes with `Illegal instruction (core dumped)` on VMs whose
CPU lacks `avx2` — common on hypervisors that expose a conservative
"compatibility" CPU model for live-migration support, even on genuinely
modern hardware. Check first:

```bash
grep -m1 flags /proc/cpuinfo | tr ' ' '\n' | grep -E '^(sse4_2|ssse3|avx|avx2)$'
```

If `avx2` is missing, install a pinned older version instead of latest
(23.8.16.40 is confirmed working on such a VM — pin all three packages
together or apt will pull `clickhouse-common-static` at the newer,
incompatible version):

```bash
sudo apt-get install -y clickhouse-server=23.8.16.40 clickhouse-client=23.8.16.40 clickhouse-common-static=23.8.16.40
```

If `avx2` **is** present, just install normally:
```bash
sudo apt-get install -y clickhouse-server clickhouse-client
```

Either way:
```bash
sudo systemctl enable --now clickhouse-server
```

During install you'll be prompted to set a password for the `default`
user. This project's scripts default to **no password** (simplest for a
single VM where ClickHouse only listens on localhost) — if you don't want
to manage a password, reset it to empty instead of typing one:
```bash
sudo rm -f /etc/clickhouse-server/users.d/default-password.xml
sudo systemctl restart clickhouse-server
clickhouse-client --query "SELECT 1"   # should print 1, no password needed
```
If you'd rather keep a real password, that's supported too — see
`systemd/clickhouse.env.example` and `web/systemd/web-api.env.example`
for where to set `CLICKHOUSE_PASSWORD` / `SYSLOG_ML_CLICKHOUSE_PASSWORD`.

Apply the schema (run from inside the repo directory):

```bash
cd ~/syslog-ml-analytics   # wherever you cloned it -- this must be your cwd
sudo cp clickhouse/init.sql /tmp/init.sql
clickhouse-client --multiquery < /tmp/init.sql
clickhouse-client --query "SHOW TABLES FROM syslog_ml"
```

**Checkpoint** — confirm `device_inventory` and `events` are listed before continuing.

## Step 3 — install Grafana (official repo)

> Same caveat as Step 2: `apt.grafana.com` and `grafana.com` are blocked
> from this session, so this is unverified live. If `apt-get update` fails
> on the grafana.list repo, check Grafana's current Debian install docs.

```bash
sudo mkdir -p /etc/apt/keyrings
curl -fsSL https://apt.grafana.com/gpg.key | sudo gpg --dearmor -o /etc/apt/keyrings/grafana.gpg
echo "deb [signed-by=/etc/apt/keyrings/grafana.gpg] https://apt.grafana.com stable main" | sudo tee /etc/apt/sources.list.d/grafana.list
sudo apt-get update
sudo apt-get install -y grafana
sudo grafana-cli plugins install grafana-clickhouse-datasource
sudo systemctl enable --now grafana-server
```

Provision the datasource and dashboard:

```bash
sudo cp grafana/provisioning/datasources/clickhouse.yaml /etc/grafana/provisioning/datasources/
sudo cp grafana/provisioning/dashboards/dashboard.yaml /etc/grafana/provisioning/dashboards/
sudo mkdir -p /var/lib/grafana/dashboards
sudo cp grafana/dashboards/syslog_ml_overview.json /var/lib/grafana/dashboards/
sudo systemctl restart grafana-server
```

**Checkpoint** — open `http://<vm-ip>:3000` (default admin/admin, change it), confirm the ClickHouse datasource connects and the "Syslog ML" dashboard folder appears (panels will be empty until Step 5).

## Step 4 — install the Python pipeline

```bash
sudo apt-get install -y python3-venv snmp snmp-mibs-downloader
sudo cp -r ml /opt/syslog-ml/ml
sudo python3 -m venv /opt/syslog-ml/venv
sudo /opt/syslog-ml/venv/bin/pip install -r /opt/syslog-ml/ml/requirements.txt
sudo chown syslog-ml:syslog-ml /opt/syslog-ml/ml/*.py
```

SNMP credentials now live in Postgres (managed via the web app's admin UI)
rather than a file here — set up `web/` (see `web/README.md`) before or
after this step; the resolver in Step 5 needs `/etc/syslog-ml/resolver.env`
pointing at that same database to do anything useful, but the rest of the
pipeline (ingestion, classification) works fine without it.

## Step 5 — wire up rsyslog and the systemd services

On Debian/Ubuntu, rsyslog normally runs as the `syslog` user (group
`syslog`), not root -- it needs to actually be a member of the
`syslog-ml` group to write into the setgid directory Step 1 created, or
its `omfile` action fails silently into a suspend/retry loop (`journalctl
-u rsyslog` would show `open error: Permission denied` on `raw.jsonl` if
you skip this):

```bash
sudo usermod -aG syslog-ml syslog
```

**If this VM needs to actually receive syslog from the network** (rather
than only mirroring its own local logs), rsyslog also needs a listener --
by default it only processes messages generated on the box itself:

```bash
sudo cp rsyslog/10-network-listener.conf /etc/rsyslog.d/
```

Then open the port(s) in whatever firewall(s) sit in front of this VM --
both the OS firewall and, if the VM is hosted rather than on hardware you
control, any security-group/network-ACL layer above the OS:

```bash
sudo ufw allow 514/udp
sudo ufw allow 514/tcp
```

```bash
sudo cp rsyslog/60-syslog-ml.conf /etc/rsyslog.d/
sudo systemctl restart rsyslog

sudo cp systemd/syslog-ml-classifier.service systemd/syslog-ml-resolver.service systemd/syslog-ml-resolver.timer /etc/systemd/system/
sudo cp systemd/syslog-ml-alert-evaluator.service systemd/syslog-ml-alert-evaluator.timer /etc/systemd/system/
sudo cp systemd/syslog-ml-reverify.service systemd/syslog-ml-reverify.timer /etc/systemd/system/
sudo cp systemd/syslog-ml-silence-detector.service systemd/syslog-ml-silence-detector.timer /etc/systemd/system/

# The resolver, the alert evaluator, and the re-verify job all need
# credentials for the shared Postgres DB (the alert evaluator only reads
# DATABASE_URL out of this file, ignores CREDENTIAL_ENCRYPTION_KEY) + the
# same Fernet key the web app encrypts SNMP secrets with (see
# web/README.md Step 3 for the matching web-api.env):
sudo cp systemd/syslog-ml-resolver.env.example /etc/syslog-ml/resolver.env
sudo $EDITOR /etc/syslog-ml/resolver.env
sudo chmod 600 /etc/syslog-ml/resolver.env
sudo chown syslog-ml:syslog-ml /etc/syslog-ml/resolver.env

sudo systemctl daemon-reload
sudo systemctl enable --now syslog-ml-classifier.service
sudo systemctl enable --now syslog-ml-resolver.timer
sudo systemctl enable --now syslog-ml-alert-evaluator.timer
sudo systemctl enable --now syslog-ml-reverify.timer
sudo systemctl enable --now syslog-ml-silence-detector.timer
```

**Checkpoint:**

```bash
sudo tail -f /var/log/syslog-ml/raw.jsonl              # confirm rsyslog is writing
sudo journalctl -u syslog-ml-classifier -f              # confirm it's processing
clickhouse-client --query "SELECT count() FROM syslog_ml.events"
clickhouse-client --query "SELECT count() FROM syslog_ml.events WHERE is_anomaly = 1"
sudo journalctl -u syslog-ml-alert-evaluator -f         # confirm it runs every minute, no errors
sudo journalctl -u syslog-ml-silence-detector -f        # confirm it runs every 10 minutes, no errors
```

### Anomaly flagging

`events.is_anomaly` is populated by the classifier itself (`ml/consumer.py`),
not a separate process. It's actually six independent signals
(`ml/anomaly_signals.py` for the stateless two, `DeviceBaselineCache` in
`consumer.py` for two that need per-device history, `ml/template_mix_anomaly.py`
for the sixth — see below) — any one firing sets `is_anomaly = 1`, and
`events.anomaly_reasons` (an array column) records *which* one(s) did, the
same "always label the reason, not just a verdict" principle already used
for `resolution_method` and `vendor_source`:

- **`rare_template`**: the message's Drain3 template has matched
  `ANOMALY_RARE_THRESHOLD` (default 5) times or fewer in its whole
  lifetime — new or still-rare for this traffic, not yet routine.
- **`always_severe`**: severity is `emerg`/`alert`/`crit`, unconditionally.
- **`security_content`**: the message matches the same `SECURITY` category
  weak-supervision rule the classifier already uses (see
  `labeling_rules.py`) — reused, not duplicated, so tuning one tunes both.
- **`severity_spike`**: this specific device just logged something worse
  than anything it's logged in the last `ANOMALY_BASELINE_WINDOW_DAYS`
  (default 7) — a device that's only ever logged info/notice suddenly
  logging `err` gets flagged even though `err` isn't unconditionally
  severe.
- **`volume_spike`**: this specific device is currently logging at
  `ANOMALY_VOLUME_SPIKE_MULTIPLIER` (default 5x) or more its own historical
  average rate — catches things like a flapping interface flooding the
  same (non-rare) message.
- **`unusual_template_mix`**: this device's *mix* of Drain3 template types
  over the last 5-minute window looks statistically different from its own
  normal mix (or its vendor's, for a device without enough history of its
  own yet) — see "Windowed template-mix anomaly detection" below. Unlike
  the other five, this one is retrospective: it can only be judged once a
  window has closed, so it's applied to already-inserted rows via a
  targeted mutation, not inline as each message arrives.

The middle two (severity_spike, volume_spike) are per-device, not global
thresholds, since "unusual" only
means something relative to what's normal *for that device* — a device
that always logs at `err` isn't anomalous for continuing to do so, and a
naturally chatty device isn't anomalous for being chatty. A brand-new
device has no baseline yet and can't trigger either signal until it
survives at least one baseline refresh — there's nothing to compare
against yet, so it's correctly silent rather than guessing.

**Honest cost caveat**: unlike the device inventory cache (a cheap
lookup), the per-device baseline is a `GROUP BY source_ip` aggregate over
`ANOMALY_BASELINE_WINDOW_DAYS` of `events` — a real query cost on a table
sized for high-volume retention, which is why it refreshes far less often
(`ANOMALY_BASELINE_REFRESH_SECONDS`, default 600s) than the inventory
cache's 60s. Widening the window or shortening the refresh interval
trades ClickHouse load for fresher baselines.

Drain3's cluster state persists to `DRAIN3_STATE_FILE`
(`/var/lib/syslog-ml/drain3_state.bin` by default, snapshotted every
`DRAIN3_SNAPSHOT_INTERVAL_MINUTES`) specifically so `rare_template`
survives a classifier restart — without it, every template would look
"new" again after each restart and you'd see a burst of false anomalies.
One honest caveat: on this VM's very first run (no snapshot file yet, no
baseline history yet), a startup burst across all five signals is
expected and one-time, not a bug — give it some real traffic (and at
least one baseline refresh interval) before trusting `is_anomaly` counts.

In the web app, search "Anomalies only" on the Log Search page to see
everything currently flagged, with the reason(s) shown per row.

### Windowed template-mix anomaly detection

The five signals above all judge one message (or one device's running
counters) at a time. `ml/template_mix_anomaly.py` asks a different
question: does this device's overall *mix* of log message types over the
last few minutes look normal, even if no single message in it looks
unusual on its own? A device quietly switching from its usual mix of
routine interface/DHCP chatter to mostly error-type messages, for
instance, might not trip `rare_template` or `severity_spike` at all if
none of those individual templates are new or unconditionally severe —
but the *shift in composition* is itself a meaningful signal, and this is
the same technique (windowed event-count vectors + an unsupervised
outlier detector) that the [loglizer](https://github.com/logpai/loglizer)
research toolkit uses for offline log anomaly benchmarks, adapted here to
run continuously on live traffic.

**How it works**, once per `TEMPLATE_MIX_REFRESH_SECONDS` (default 900s,
15 min):

1. Bucket each device's recent events (last `TEMPLATE_MIX_LOOKBACK_DAYS`,
   default 7) into `TEMPLATE_MIX_WINDOW_MINUTES` (default 5) windows, and
   count how many times each Drain3 template occurred in each window.
2. Project each window into a fixed-size vector: the count of that
   device's `TEMPLATE_MIX_TOP_K_TEMPLATES` (default 50) most frequent
   templates, plus one "other" bucket for everything else — bounded
   dimensionality even as new templates keep appearing over time, so the
   model never has to be rebuilt from scratch just because Drain3 mined a
   new template somewhere.
3. **Hybrid model scope**: a device with at least
   `TEMPLATE_MIX_MIN_WINDOWS_FOR_DEVICE` (default 30) windows of its own
   history gets its own `IsolationForest`, trained on nothing but its own
   past behavior. A lower-traffic device that hasn't accumulated that much
   yet falls back to a *vendor-level* model instead — pooled from every
   window of every device sharing that vendor (needs
   `TEMPLATE_MIX_MIN_WINDOWS_FOR_VENDOR`, default 30, pooled windows) — so
   it's still compared against something meaningful rather than going
   unscored indefinitely. A device with neither isn't scored yet.
4. Score every window that's completed since the last cycle (not just the
   newest one — with a 15-minute cycle and 5-minute windows, only scoring
   "the latest" would silently skip two out of every three windows). A
   restart resumes from `syslog_ml.device_window_anomalies`'s own recorded
   checkpoint rather than either re-backfilling everything or leaving a
   gap.
5. `TEMPLATE_MIX_CONTAMINATION` (default 0.01) is passed explicitly to
   `IsolationForest` rather than using its `"auto"` setting — verified in
   testing that `"auto"` over-flags by 20-30% on realistic windowed data
   here, far too high for a signal meant to be rare. 0.01 assumes roughly
   1% of windows are genuinely anomalous; tune it if that doesn't match
   what you see in practice.

**Where it surfaces**: every scored window (flagged or not) is written to
`syslog_ml.device_window_anomalies` — browse it on the new **Anomaly
Windows** page, which shows which model scope (device-specific or vendor
baseline) applies to each row. Separately, since that table alone
wouldn't hook into Log Search's or Alerts' existing `is_anomaly`/
`anomaly_reasons` filtering, a *newly*-flagged window triggers one
targeted `ALTER TABLE events UPDATE ... WHERE source_ip = ... AND
event_time >= window_start AND event_time < window_end` — tagging every
event in that window (not just the ones that look individually odd) with
`unusual_template_mix`. This only ever fires for windows actually flagged
anomalous (expected to be a small fraction), guarded by
`NOT has(anomaly_reasons, 'unusual_template_mix')` so re-scoring the same
window twice never double-tags it — never for the much larger common case
of a normal window, which is what keeps it affordable despite ClickHouse
mutations being relatively heavy in general.

**Honest cost caveat**: the per-cycle query groups by
`(source_ip, window, template_id)` across the whole lookback window —
finer-grained, and so more expensive, than the simple `GROUP BY source_ip`
the severity/volume baseline above already does. It runs on the same
single-threaded loop as everything else in `consumer.py`, so a slow cycle
briefly delays tailing new lines, the same tradeoff `DeviceBaselineCache`
already makes at its own (shorter) interval. Widen
`TEMPLATE_MIX_REFRESH_SECONDS` or shorten `TEMPLATE_MIX_LOOKBACK_DAYS` if
this becomes a real cost on your traffic volume.

### Alerting

`ml/evaluate_alerts.py` (run every minute by `syslog-ml-alert-evaluator.timer`)
evaluates every enabled rule from the web app's "Alerts" page against
`syslog_ml.events`: a rule fires when at least *threshold* matching events
(optionally filtered by hostname/source IP/program/severity/category, or
restricted to `is_anomaly=1` events) occur within the trailing *window*,
and won't fire again until *cooldown* has elapsed since it last fired. A
firing writes a row to Postgres (`alert_events`, visible in the same page)
and, if the rule has a `webhook_url`, POSTs a JSON payload to it (works
with a Slack incoming webhook, PagerDuty, or any endpoint that accepts a
POST). There's no email delivery in this version — a webhook was the
simplest channel to build and test without requiring SMTP credentials;
point it at a service that turns webhooks into email/SMS if you need that.

### Device-silence detection

Every anomaly signal above (`rare_template`, `always_severe`,
`security_content`, `severity_spike`, `volume_spike`,
`unusual_template_mix`) detects a device logging too much or unusually.
None of them detect a device that stops logging entirely — for a security
appliance or network switch, that can mean it crashed, lost connectivity,
or was tampered with, and without this it's invisible.

`ml/detect_silent_devices.py` (run every 10 minutes by
`syslog-ml-silence-detector.timer`) learns each device's own average
inter-arrival time from `SILENCE_BASELINE_WINDOW_DAYS` (default 7) of
history — deliberately device-relative, not a fixed timeout, since a
firewall logging every few seconds and a switch logging every few hours
are both "silent" at wildly different absolute gaps. A device needs at
least `SILENCE_MIN_BASELINE_EVENTS` (default 20) events in that window
before its baseline is trusted at all. It's flagged once the actual gap
since last-seen exceeds `SILENCE_MULTIPLIER` (default 10) times that
baseline, with `SILENCE_MIN_MINUTES` (default 30) as an absolute floor so
a very chatty device isn't flagged over an ordinary few-minute pause.

State lives in Postgres (`device_silence_state`, one row per *currently*
silent device — deleted the moment it logs again, so this table always
reflects live state, not history) and shows up in the web app's Alerts
page under "Currently silent devices," visible to any authenticated role
the same as alert rules/history. A transition either way (newly silent,
or recovered) POSTs to `SILENCE_WEBHOOK_URL` if configured, same payload
shape and Slack/PagerDuty/generic-endpoint compatibility as
`evaluate_alerts.py`'s webhooks; a device that stays silent re-notifies
only every `SILENCE_RENOTIFY_MINUTES` (default 240), not on every 10-minute
run, so an ongoing outage doesn't spam the channel.

### Passive vendor detection (no SNMP credential needed)

Real vendor identification uses SNMP (`sysObjectID`), which -- like
hostname resolution -- only runs for an IP that has a credential in
`snmp_credentials`. For everything else, `ml/vendor_signatures.py` makes a
best-effort guess at vendor from the syslog message's own format: Cisco's
`%FACILITY-SEVERITY-MNEMONIC:` convention (matched anywhere in the
message, since real IOS devices usually prefix it with a sequence number
and timestamp), Junos's `junos@2636.` structured data, FortiOS's
`devname=`/`logid=` key-value style, Palo Alto's CSV `TRAFFIC`/`THREAT`/...
header, and RouterOS's interface up/down and wireless scan-list message
formats. This runs automatically in the classifier for every event that
doesn't already have an SNMP-verified identity -- no configuration needed.
The Cisco and RouterOS patterns were corrected against real messages
sampled from this deployment's own traffic, not just vendor
documentation -- see the comment at the top of `vendor_signatures.py` for
what changed and why.

**This is a format guess, not identity verification**, and every event
carries `vendor_source` (`snmp` | `passive` | `unknown`) so the Devices
page can show the difference (a "(pattern-detected)" hint next to the
vendor name) rather than presenting a guess as fact. Two honest limits:
a device configured to log in a non-default format won't match anything,
and Arista/HP/Dell often deliberately mimic Cisco's exact format for CLI
compatibility, so that pattern lands in a `cisco_like` bucket rather than
claiming a specific one of those four. Add an SNMP credential for a device
whenever you want its vendor (and hostname) actually confirmed rather than
guessed.

### Credential pools: resolving many devices without a per-IP mapping

If you have a known, finite set of SNMP community strings in use across
your devices but no record of which IP uses which one, entering one
credential per device by hand doesn't scale. The web app's SNMP
Credentials page has a **bulk import** for exactly this: paste your
communities (one per line) under one shared scope (e.g. `0.0.0.0/0`), and
each becomes its own candidate row in `snmp_credentials`.

**This is still never guessing an unknown/default string** — every
candidate is one an admin explicitly entered as theirs, and SNMP is only
ever attempted against an IP that has already sent this VM syslog
traffic, never an arbitrary address. What changes is only *how many*
admin-entered candidates get tried per device instead of assuming there's
exactly one.

How resolution uses a pool:
1. **Fast path**: if a device already has its own exact-host (`/32`)
   credential — either entered by hand or auto-discovered previously —
   that's tried first, alone.
2. **Discovery**: if not, `resolve_pending.py` tries each pool candidate
   against the device (real SNMP round-trips, most specific credential
   first) until one actually responds.
3. **Auto-save**: the first community that works for a device is saved as
   that device's own `/32` credential, tagged `auto_discovered` (visible
   and editable in the Credentials page) — future cycles query that
   device directly instead of re-trying the whole pool.
4. **Twice-daily self-heal**: `syslog-ml-reverify.timer` (see Step 5)
   re-checks every already-resolved device. If its saved credential still
   works, nothing changes. If the community has since rotated, it
   re-tries the pool and updates the saved credential to whichever new
   one matches — so a rotated community heals itself within half a day
   rather than silently going stale.

**One honest scaling caveat**: discovering a *brand-new* device tries
pool candidates one at a time, each a real SNMP round-trip with its own
timeout — with "dozens to a few hundred" candidates, resolving one
never-before-seen device can take a while (worst case, if none of them
match, every single one times out). This runs in the background
(`resolve_pending.py`, every 10 minutes) and never blocks log ingestion,
but if you have many brand-new devices appearing at once and resolution
feels slow, that's expected with a large pool, not a bug — the fast path
in step 1 above is what keeps steady-state resolution quick once each
device's credential has been discovered.

### If syslog arrives relayed through another server, not directly from devices

If devices send to an existing collector (e.g. the LogAnalyzer setup)
which then forwards a copy to this VM, rather than devices sending here
directly, **device identity resolution does not work out of the box** --
this is a real limitation, not a bug to file:

- `source_ip`/`fromhost-ip` will be the **relay's** IP for every event,
  not the originating device's -- the network-layer signal our design
  relies on collapses to one value.
- If the relay doesn't preserve each device's original hostname in the
  forwarded message either, there's no usable in-message signal to fall
  back on.
- The SNMP resolver polls by IP, so it ends up polling the relay itself,
  not the actual devices.

Every event in this setup will show `resolution_method = 'unresolved'`
with the relay's IP as `hostname` -- correct given what the pipeline can
actually observe, but not useful for per-device analytics. Real fixes,
in order of how much they preserve of the original design:

1. **Point devices at this VM directly** (in addition to or instead of
   the existing collector) -- restores the original network-layer signal
   this design assumes.
2. **Reconfigure the relay to preserve/inject per-device identity** --
   e.g. have it forward using RFC 5424 with structured data carrying the
   original source IP, if your relay's syslog daemon supports that.
3. **The "Relay Source IPs" admin page** (below) -- if your relay's
   rsyslog already preserves the original device's `HOSTNAME` field on
   forward (many do, by default, even without RFC 5424), you don't need
   to reconfigure anything: list that relay's IP and the pipeline
   recovers per-device identity from what's already arriving.

#### Relay Source IPs: recovering per-device identity from a listed relay

Confirmed on a real relay setup (rsyslog forwarding from a LogAnalyzer
collector): even though `fromhost-ip` collapses to the relay's own IP for
every event, the relay's rsyslog still forwarded each device's original
`HOSTNAME` field untouched -- for a MikroTik device with no `/system
identity` name configured, that field held the device's own management
IP (e.g. `172.20.0.74`), not the relay's. That's enough to recover real
per-device identity and analytics *without* touching the relay or the
devices, whenever it holds.

Add the relay's IP via **Relay Source IPs** in the web app's admin nav
(`web/frontend/src/pages/Relays.tsx`, `POST /api/relays`) -- admin-only,
same as SNMP Credentials. `ml/consumer.py`'s `RelaySourceIpCache` reads
this list directly from the same Postgres database the web app writes to
(same pattern as the resolver reading `snmp_credentials`), refreshed
every `RELAY_LIST_REFRESH_SECONDS` (default 60s) -- no service restart
needed after adding or removing an entry. Requires `DATABASE_URL` to be
set for `syslog-ml-classifier.service` (it now also reads
`/etc/syslog-ml/resolver.env`, the same file the resolver already uses,
for this); if unset or Postgres is unreachable, the list just stays
empty (or keeps its last known snapshot) and every `source_ip` is
treated as a direct device, same as before this feature existed.

For an event whose `source_ip` is in this list, `ml/consumer.py`
checks `reported_hostname` for a well-formed IP address different from
the relay's own -- and if found, substitutes it in as that event's
*effective* `source_ip` for identity resolution, SNMP polling, grouping
(Devices page, Log Search), and the per-device anomaly baselines. The
original network-level relay IP isn't discarded: it's kept in the new
`relayed_via` column (empty for everything that didn't go through a
relay), so the substitution stays traceable rather than silently
overwriting what was actually observed on the wire.

This is opt-in per relay IP, not an automatic heuristic applied to all
traffic: `reported_hostname` is still a self-reported, spoofable
message-body field (see `rsyslog/60-syslog-ml.conf`'s comment on why
`source_ip` is normally trusted instead of it), so widening that trust
only makes sense for IPs you've deliberately identified as relays.

If `reported_hostname` isn't an IP but is still a real, distinguishing
name -- confirmed on the same real relay: a Cisco ACS appliance reported
its own name (`ACSSERVER`) rather than an IP -- it's used as that event's
identity too, just without an IP to SNMP-poll: `resolution_method` is
`syslog_reported` (final, not queued for resolution) and grouping/the
anomaly baseline key off the hostname string itself. Generic placeholders
devices fall back to when they have no identity configured at all
(`localhost`, `localhost.localdomain`) are deliberately excluded --
they're not distinguishing, so those events fall through to whatever
identity the relay's own `source_ip` otherwise resolves to (its SNMP
hostname if known, its bare IP if not -- never the placeholder string
itself). This exclusion isn't relay-specific: any device, relayed or not,
that self-reports one of these generic placeholders shows its IP instead
of the placeholder, for the same reason.

**Only fixes what's already in the data.** If your relay doesn't preserve
per-device identity in the forwarded message at all (check with `sudo
grep '"source_ip": *"<relay-ip>"' /var/log/syslog-ml/raw.jsonl | tail -3`
and look at `reported_hostname`), this can't recover it -- fall back to
option 1 or 2 above.

#### `RELAY_TIMEZONE_OFFSET_HOURS`: correcting a relay that timestamps in local time

Confirmed on the same real relay: `event_time` for its traffic was 3 hours
*ahead* of `received_at` (the real wall-clock insert time) -- net-flow's
own clock is correctly UTC (`timedatectl` confirmed NTP-synced), so this
isn't a net-flow problem. The legacy BSD syslog format these messages use
has no timezone field at all, and whatever wrote this relay's copy of the
timestamp (the relay itself, or the origin devices) put local time
(Beirut, UTC+3) into it -- rsyslog then took that number at face value
and stored it as if it were already UTC.

**Not all of this relay's traffic is skewed, though** -- confirmed:
some of the same device's messages (an ACSSERVER appliance) arrive
already correct. A blanket "always subtract 3h for this relay" rule
wrongly shifts those into the past instead, so `ml/consumer.py` applies
the correction per-message: only when `event_time` claims to be more
than `RELAY_TIMEZONE_FUTURE_TOLERANCE_MINUTES` (default `30`) ahead of
the real processing time -- a message can't legitimately be from the
future, whereas a merely delayed/backlogged one is late, not early, so
this only ever fires in the direction the actual bug produces -- and
even then, only if subtracting `RELAY_TIMEZONE_OFFSET_HOURS` (default
`3`) genuinely brings it closer to now instead of further away. Both are
scoped to traffic from an IP in the Relay Source IPs list, since that's
the only population this has been confirmed against -- unlike that list
itself, these two are still env vars (`sudo systemctl edit
syslog-ml-classifier`), since they're global tuning constants, not
per-relay data. Set `RELAY_TIMEZONE_OFFSET_HOURS=0` to disable this
entirely if it turns out not to apply to your relay, or
override it to a different fixed offset if your relay's local timezone
isn't UTC+3. This is a flat offset, not a named IANA timezone -- it
doesn't account for DST -- because that's what was actually observed
and asked for; if your relay's local time observes DST, this will need
revisiting twice a year.

**Doesn't retroactively fix already-inserted rows.** Only events
processed after this deploys get the correction; historical rows keep
their originally-recorded (off-by-3-hours) `event_time`.

### Cisco ACS/ISE multi-part message reassembly

Cisco ACS/ISE splits any message too long for one UDP syslog datagram
into multiple separate syslog messages (program names like
`CSCOacs_TACACS_Diagnostics`, `CSCOacs_Failed_Attempts`,
`CSCOacs_TACACS_Accounting`), each carrying the same
`<message-id> <total-segments> <this-segment-index>` numeric prefix so
the receiver can stitch them back together. `ml/consumer.py`'s
`AcsMultipartReassembler` buffers these by `(source_ip, message_id)` and
inserts one merged row per complete group instead of one broken partial
row per segment — this also strips that numeric prefix from
single-segment ACS messages, so every ACS row in Log Search reads as the
actual message text, not raw protocol plumbing. This runs automatically;
no setup needed. If a segment is lost (UDP), `ACS_REASSEMBLY_TIMEOUT_SECONDS`
(default `10`) controls how long it waits before giving up and inserting
whatever segments did arrive — check `journalctl -u syslog-ml-classifier`
for `"incomplete after"` warnings if you ever see a still-truncated ACS
message.

### Optional: receive SNMP traps too (separate from syslog)

SNMP traps are a different protocol (default UDP 162, not 514) and need
their own receiver (`snmptrapd`, from net-snmp) -- rsyslog can't receive
them directly. The simplest integration: point `snmptrapd` at the local
syslog socket, so traps flow into the same `raw.jsonl` pipeline as
everything else.

```bash
sudo apt-get install -y snmptrapd
sudo cp snmptrapd/snmptrapd.conf.example /etc/snmp/snmptrapd.conf
sudo nano /etc/snmp/snmptrapd.conf   # add a line per community your devices actually use -- never a permissive catch-all; $EDITOR is unlikely to be set
sudo ufw allow 162/udp
```

On Ubuntu 22.04, `snmptrapd` is **socket-activated** (`snmptrapd.socket`
triggers `snmptrapd.service` on demand) and runs as an unprivileged
`Debian-snmp` user, not root. Two things confirmed only by actually
running this on a real VM, neither obvious from the package alone:

**1. A directory ownership bug in the Ubuntu package itself.**
`/var/lib/snmp/cert_indexes` (used for TLS transport support, unrelated
to plain v1/v2c traps) gets created owned by `root:root` with `700`
permissions, while everything else in `/var/lib/snmp/` correctly belongs
to `Debian-snmp`. `snmptrapd` still touches this path at startup even
without TLS, so it fails immediately with a bare `fopen: Permission
denied` (no filename in the message) until this is fixed:

```bash
sudo chown -R Debian-snmp:Debian-snmp /var/lib/snmp/cert_indexes
```

**2. Making it log via syslog** needs a systemd override that changes
*only* the logging flag, keeping everything else identical to the
package's own `ExecStart` (check yours with `systemctl cat snmptrapd`
first -- don't assume it matches):

```bash
sudo mkdir -p /etc/systemd/system/snmptrapd.service.d
sudo tee /etc/systemd/system/snmptrapd.service.d/override.conf > /dev/null <<'EOF'
[Service]
ExecStart=
ExecStart=/usr/sbin/snmptrapd -Lsd -f udp:162 udp6:162
EOF
sudo systemctl daemon-reload
sudo systemctl restart snmptrapd.socket
```

Do **not** add a `-p <pidfile>` flag to that `ExecStart` -- the packaged
unit uses `Type=notify` with no `PIDFile=`, and `Debian-snmp` can't write
one to `/run/` anyway; adding one reproduces the same bare permission
error as the `cert_indexes` issue and is easy to misdiagnose as the same
bug.

**Checkpoint:**

```bash
sudo systemctl status snmptrapd.service --no-pager   # expect: active (running)
snmptrap -v2c -c public localhost '' 1.3.6.1.4.1.8072.2.3.0.1
sleep 2
sudo tail -3 /var/log/syslog-ml/raw.jsonl             # expect a line with program "snmptrapd"
clickhouse-client --query "SELECT count() FROM syslog_ml.events WHERE program LIKE '%snmptrapd%'"
```

If `systemctl start snmptrapd.socket` ever fails with `Address already
in use` after an earlier failed attempt, check for a leftover manual
test process still holding port 162 (`ps aux | grep snmptrapd`) before
assuming it's the same bug again -- `kill %1` on a backgrounded job
doesn't reliably work across separate pasted command blocks.

**Same identity caveat applies, worse:** `snmptrapd` re-emits traps via
the *local* syslog socket, so `fromhost-ip` for every trap-derived event
will be `127.0.0.1`/this VM, regardless of relay topology. The originating
device's address is only present as text inside the trap's rendered
message body (snmptrapd's default format includes it), not in a
structured field -- something a future improvement could parse out, not
built yet.

That same local-socket delivery is also why `rsyslog/60-syslog-ml.conf`
explicitly allow-lists `programname == 'snmptrapd'` into the ML pipeline's
ruleset: everything *else* arriving via that local path (this VM's own
`gunicorn`/`sudo`/`systemd` output, forwarded from `journald`) is
deliberately excluded (see that file's own comments) so it doesn't pollute
Log Search as if it were device traffic. If you rename or wrap the
`snmptrapd` binary such that its logged `programname` isn't literally
`snmptrapd`, traps will stop reaching `raw.jsonl` silently -- the same
`sudo tail -3 /var/log/syslog-ml/raw.jsonl` checkpoint above catches that.

## Step 6 — train the real classifier (after a few hours/days of traffic)

```bash
clickhouse-client --query "SELECT message FROM syslog_ml.events FORMAT JSONEachRow" > /tmp/logs.jsonl
sudo -u syslog-ml /opt/syslog-ml/venv/bin/python /opt/syslog-ml/ml/train_classifier.py \
  --input /tmp/logs.jsonl --output /var/lib/syslog-ml/classifier.joblib
sudo systemctl restart syslog-ml-classifier
```

Better: export a sample, hand-correct the `category` field for a few hundred
rows across your different vendors, and re-run with that file — the script
prefers a real `category` field over the weak-supervision guess.

## Step 7 — Log Assistant (semantic search + local LLM Q&A)

Everything above judges logs by statistics (rare templates, severity/volume
baselines, template-mix outliers). This is a different kind of feature:
answering a question typed in plain language — "why has sw1 been logging
interface errors this morning?" — by finding the log lines that are
semantically *related* to it (even if they don't share the same words) and
having a local LLM read them and answer. Modeled on the design
[sislogIQ](https://github.com/Toxa/sislogIQ) describes (that repo itself
ships only a README, no working code — this project's own implementation
is what actually exists): OpenSearch for retrieval, [Ollama](https://ollama.com)
for local inference — nothing here calls out to an external API; the whole
thing runs on your own hardware.

**Architecture**: a new standalone process, `ml/log_assistant_indexer.py`
(its own systemd service, deliberately separate from `consumer.py` — see
its module docstring for why), tails `syslog_ml.events` the same way
`consumer.py` tails the raw log file, embeds each new event with Ollama,
and writes the vector into an OpenSearch index. It polls every
`INDEXER_POLL_SECONDS` (default `5`) — a new event typically becomes
searchable within a few seconds of arriving, not instantly (true
per-message push would mean embedding synchronously inside `consumer.py`'s
own ingest path, which is exactly the coupling this being a separate
process avoids — see its docstring). The web backend then does two things
against that index: `/api/log-assistant/search` (semantic search alone)
and `/api/log-assistant/ask` (search, then hand the results to an LLM as
context and return its answer — the **Log Assistant** page in the web
UI). Anomaly Windows and Anomaly Summary both link into it with an
**"Explain with AI"** action that pre-fills a question and the relevant
device/time range.

**Retrieval is hybrid, not pure vector search.** A vector-only k-NN search
is weak on exactly the things network logs are full of and embeddings
represent poorly: exact IP addresses, hostnames, error codes, session IDs
— typing an IP into the question should reliably find every line
containing it, which semantic similarity alone doesn't guarantee.
`opensearch/setup_index.py` sets up a search pipeline that fuses a BM25
keyword match (on the raw `message` field) with the k-NN vector clause
using reciprocal rank fusion (RRF, native to OpenSearch 2.19+) as the
index's default pipeline, so both `search` and `ask` get the benefit
without the query code needing to know the pipeline exists.

**The LLM's system prompt lives in a file, not in code**:
`web/backend/app/prompts/log_assistant_system.txt`. Edit it and restart
`syslog-ml-web-api` to change how the assistant is instructed to answer —
no code change needed. Override `SYSLOG_ML_LOG_ASSISTANT_SYSTEM_PROMPT_FILE`
to point at a different file entirely; a missing/unreadable file falls
back to a built-in default rather than breaking "Ask".

**Hardware note**: this needs real headroom — see this repo's own
deploy history for a concrete example. A 4-core/7.8GB VM already running
ClickHouse, Postgres, the classifier, and the web backend had only ~4GB
free; that's not enough to also run OpenSearch's JVM plus a capable local
LLM. **16GB is the tested target** this section assumes. A rough budget at
that size (watch `free -h` after deploying — this is a starting point, not
a guarantee):

| Component | Approx. RAM |
|---|---|
| Existing stack (ClickHouse, Postgres, classifier, gunicorn) | 3–4 GB |
| OpenSearch JVM heap | 2 GB |
| OpenSearch off-heap + OS overhead | ~1 GB |
| Ollama + `llama3.1:8b-instruct-q4_K_M` loaded | ~6 GB |
| OS buffer / headroom | remainder |

Drop to a smaller chat model (e.g. `llama3.2:3b-instruct-q4_K_M`, ~2GB) if
16GB is still tight, or if this ever needs to run on hardware smaller than
the target above — everything below is a config change (`ollama pull` a
different model, update `SYSLOG_ML_OLLAMA_CHAT_MODEL`), not a code change.

**CPU matters as much as RAM: check for AVX2/FMA before relying on
throughput numbers.** `llama.cpp` (what Ollama runs under the hood) is
heavily optimized around AVX2+FMA; without them it falls back to a much
slower path. Check with:

```bash
grep -o -E "\bavx\b|\bavx2\b|\bfma\b" /proc/cpuinfo | sort -u
```

If only `avx` shows up (no `avx2`, no `fma`) — confirmed on a shared
VMware host's `Intel Xeon E5-2620` (a 2012 "Sandy Bridge-EP" chip; AVX2/FMA
arrived with the next generation, Haswell, in 2013) — two things follow,
and neither is a bug to chase:

- **Keep models resident.** Ollama's default 5-minute idle unload means
  every request after a gap pays a full model-load cost again — measured
  at ~55 seconds for `llama3.1:8b-instruct-q4_K_M` on that host, which
  looks like "this hardware can't do this at all" but is really just a
  reload tax. Set `OLLAMA_KEEP_ALIVE=-1` on the `ollama` systemd service
  (`sudo systemctl edit ollama`) once there's RAM to spare for permanent
  residency. Once warm, the same host measured ~4.5 tokens/sec chat
  generation and ~1.2 messages/sec embedding — slow next to modern
  hardware, but genuinely usable for an occasional-question tool.
- **~1.2 msg/sec embedding throughput will not keep up with indexing
  every event on a busy host.** Measure your own traffic
  (`SELECT count() FROM syslog_ml.events WHERE received_at >= now() -
  INTERVAL 1 HOUR`) before assuming it will. On the host this was measured
  on, ordinary traffic ran ~2–4.6 msg/sec sustained — indexing everything
  would mean the backlog only grows, never catches up. Set
  `INDEXER_ANOMALIES_ONLY=true` (see `ml/log_assistant_indexer.py`) to
  index only `is_anomaly=1` events instead of everything — on that same
  host, anomalies ran ~0.33 msg/sec, comfortably inside the ~1.2 msg/sec
  budget, and it matches how this feature is actually used (the "Explain
  with AI" links are anomaly-focused, not general log browsing). A
  7-day cold-start backfill of anomalies-only traffic at that host's
  measured rate takes on the order of ~2 days to fully catch up, then
  tracks new anomalies close to real-time indefinitely after that.

None of this applies if your CPU has AVX2/FMA (most anything from 2014
onward) — indexing every event and getting fast chat responses should
both just work at the RAM budget above.

- **A backfill can still starve an interactive chat request even on
  AVX2/FMA hardware.** The throughput numbers above are averages; the
  indexer's poll loop (`run_cycle` in `ml/log_assistant_indexer.py`)
  fetches and embeds batch after batch back-to-back with no pause while a
  backlog exists, so all cores can be saturated for the backlog's whole
  duration, not just briefly. Confirmed on net-flow (AVX2/FMA present):
  a chat completion that took ~6s uncontended took 238s while a backfill
  was running the same batch loop. Set `INDEXER_BATCH_SLEEP_SECONDS`
  (default `0`, e.g. `1.0`) to add a pause between batches, giving
  interactive requests a periodic CPU opening at the cost of a longer
  backfill — independent of, and worth combining with, the
  `proxy_read_timeout` (`web/nginx/syslog-ml-web.conf`) /
  `SYSLOG_ML_OLLAMA_TIMEOUT_SECONDS` (`web/backend/app/core/config.py`)
  timeouts, which only stop a slow request from being killed outright and
  don't make it any faster.
- **Prefer OS-level scheduling priority over the sleep, where available.**
  `systemd/syslog-ml-log-assistant-indexer.service` sets `Nice=15` and
  `CPUWeight=20`, which asks the kernel to yield this service's CPU time to
  everything else on the box (left at the default priority) only when
  something else actually wants to run — unlike
  `INDEXER_BATCH_SLEEP_SECONDS`, which pauses unconditionally, this doesn't
  slow the backfill down at all when nothing else needs the CPU. It's
  coarser, though (a whole ~13s embedding batch is one scheduling unit, so
  a chat request that lands mid-batch still waits on it) — keep both.

**Install OpenSearch** (single node, no Docker — same "native systemd
service" approach as everything else here):

```bash
curl -fsSL https://artifacts.opensearch.org/publickeys/opensearch.pgp | sudo gpg --dearmor -o /usr/share/keyrings/opensearch-keyring
echo "deb [signed-by=/usr/share/keyrings/opensearch-keyring] https://artifacts.opensearch.org/releases/bundle/opensearch/2.x/apt stable main" | sudo tee /etc/apt/sources.list.d/opensearch-2.x.list
sudo apt update && sudo apt install opensearch
```

Two edits to `/etc/opensearch/opensearch.yml` before starting it:

```yaml
network.host: 127.0.0.1     # loopback only -- nothing outside this host talks to it directly
plugins.security.disabled: true
```

`plugins.security.disabled` trades OpenSearch's built-in auth/TLS for
simplicity, the same posture this project already takes with ClickHouse's
own password-less default-user setup — safe specifically *because* it's
bound to loopback and only this host's own backend process ever talks to
it, not because the data itself is unimportant. Don't do this if you ever
bind it to a non-loopback address. Then:

```bash
sudo systemctl enable --now opensearch
```

**Install Ollama** (its own installer sets up a systemd service):

```bash
curl -fsSL https://ollama.com/install.sh | sh
ollama pull nomic-embed-text                 # embedding model -- must match OLLAMA_EMBED_MODEL below
ollama pull llama3.1:8b-instruct-q4_K_M       # chat model -- must match SYSLOG_ML_OLLAMA_CHAT_MODEL below
```

**Warm both models up before enabling the indexer or restarting the
backend.** Loading a model for the first time is far slower than any later
call once it's warm -- confirmed on a 4-core deploy target: the indexer's
first embed call (which also had to load the model) took close to 20
minutes under CPU contention with the rest of the stack, well past any
reasonable request timeout, even though every call after that was fast.
Doing the load here, with nothing else waiting on it, means the indexer's
first real attempt gets a warm model instead of potentially timing out:

```bash
curl -s http://localhost:11434/api/embed -d '{"model":"nomic-embed-text","input":["warm up"]}' > /dev/null
curl -s http://localhost:11434/api/chat -d '{"model":"llama3.1:8b-instruct-q4_K_M","messages":[{"role":"user","content":"hi"}],"stream":false}' > /dev/null
```

**Create the OpenSearch index and hybrid-search pipeline**, then enable the indexer:

```bash
sudo -u syslog-ml /opt/syslog-ml/venv/bin/pip install -r /opt/syslog-ml/ml/requirements.txt
sudo -u syslog-ml /opt/syslog-ml/venv/bin/python /opt/syslog-ml/opensearch/setup_index.py
sudo cp /opt/syslog-ml/systemd/syslog-ml-log-assistant-indexer.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now syslog-ml-log-assistant-indexer
```

Add to the backend's env (wherever `SYSLOG_ML_DATABASE_URL` etc. are set,
see `web/README.md`) if you changed any of the defaults:

```
SYSLOG_ML_OPENSEARCH_URL=http://localhost:9200
SYSLOG_ML_OPENSEARCH_INDEX=syslog_ml_log_events
SYSLOG_ML_OLLAMA_URL=http://localhost:11434
SYSLOG_ML_OLLAMA_EMBED_MODEL=nomic-embed-text
SYSLOG_ML_OLLAMA_CHAT_MODEL=llama3.1:8b-instruct-q4_K_M
```

**Honest testing caveat**: this project's own development sandbox
couldn't reach `opensearch.org` or `ollama.com` (blocked by that sandbox's
own egress proxy — not a constraint that applies to your own server), so
none of the OpenSearch/Ollama-facing code paths could be run end-to-end
against the real services while writing them. Semantic search alone (no
chat model) has since been confirmed live against a real OpenSearch +
Ollama install; the "Ask" chat path has not yet, on this project's own
memory-constrained deploy target (see below). The **hybrid-search
pipeline** (RRF fusion, `opensearch/setup_index.py`'s
`_ensure_hybrid_pipeline` and `log_assistant_service.py`'s `hybrid` query)
is newer still and hasn't been run against a live OpenSearch at all --
its `opensearch-py` client calls (`search_pipeline.put`,
`indices.put_settings`) were confirmed to match that library's real
method signatures, and the request-body shape was cross-checked against
OpenSearch's own documented syntax, but treat the first real search after
installing this as that feature's actual smoke test: if a search comes
back empty or errors where the old vector-only version wouldn't have,
check `journalctl -u syslog-ml-web-api` and confirm
`GET /syslog_ml_log_events/_settings` shows `index.search.default_pipeline`
set to `log_assistant_hybrid_rrf` (or your `HYBRID_SEARCH_PIPELINE`
override). What *was* verified: the full FastAPI route stack
(`/log-assistant/search`, `/log-assistant/ask`, error handling, request
validation) was tested against a mocked OpenSearch client and mocked
Ollama HTTP responses, including the exact JSON shapes those two
services' documented APIs return. The frontend page and its "Explain with
AI" deep links were verified in a real browser. Check both services' own
logs (`journalctl -u opensearch`, `journalctl -u ollama`, `journalctl -u
syslog-ml-log-assistant-indexer`) if anything doesn't work as expected.

## Files

- `clickhouse/init.sql` — `device_inventory`, `events`, the per-minute rollup, and `device_window_anomalies`.
- `rsyslog/10-network-listener.conf` — enables rsyslog to receive syslog over the network (UDP/TCP 514), routed into the `syslogMlNetwork` ruleset so this VM's own local/journald traffic isn't mixed in.
- `rsyslog/60-syslog-ml.conf` — mirrors that network-only ruleset's feed to a local JSON file (plus an explicit `snmptrapd` allow-list, since it logs traps via that same local path -- see "Windowed template-mix anomaly detection" and the SNMP trap section below).
- `snmptrapd/` — optional SNMP trap receiver config, feeding traps into the same pipeline via local syslog.
- `ml/consumer.py` — tails the file, resolves identity, classifies, flags anomalies, writes to ClickHouse.
- `ml/anomaly_signals.py` — stateless anomaly signals (always_severe, security_content); the per-device ones (severity_spike, volume_spike) live in `consumer.py`'s `DeviceBaselineCache`.
- `ml/template_mix_anomaly.py` — the sixth anomaly signal: periodic, windowed, per-device/per-vendor template-mix outlier detection (`unusual_template_mix`).
- `ml/device_resolver.py` / `ml/resolve_pending.py` — the opt-in SNMP identity resolver, including credential-pool discovery/auto-save (reads credentials from Postgres, see `web/`).
- `ml/reverify_devices.py` — twice-daily re-check of already-resolved devices; self-heals an auto-discovered credential if its community rotates.
- `ml/vendor_signatures.py` — passive, no-credential vendor detection from syslog message format.
- `ml/labeling_rules.py` — weak-supervision category rules (tune for your vendors).
- `ml/train_classifier.py` — trains the TF-IDF + linear SVM classifier.
- `ml/evaluate_alerts.py` — evaluates alert rules against ClickHouse, fires webhooks.
- `ml/log_assistant_indexer.py` — embeds new events into OpenSearch for the Log Assistant's semantic search/ask features (see "Log Assistant" above).
- `opensearch/` — the log-embedding index's mapping (`log_events_index.json`) and its one-time setup script.
- `systemd/` — unit files for the classifier, resolver timer, alert evaluator timer, re-verify timer, and the Log Assistant indexer.
- `grafana/` — provisioned datasource + starter dashboard.
- `web/` — FastAPI + React admin app, including Log Search, the anomaly pages, Query Console, and Log Assistant (see `web/README.md`).
