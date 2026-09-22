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
toYYYYMMDD(event_time)`), has a 90-day TTL, has an `events_by_minute`
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
```

**Checkpoint:**

```bash
sudo tail -f /var/log/syslog-ml/raw.jsonl              # confirm rsyslog is writing
sudo journalctl -u syslog-ml-classifier -f              # confirm it's processing
clickhouse-client --query "SELECT count() FROM syslog_ml.events"
clickhouse-client --query "SELECT count() FROM syslog_ml.events WHERE is_anomaly = 1"
sudo journalctl -u syslog-ml-alert-evaluator -f         # confirm it runs every minute, no errors
```

### Anomaly flagging

`events.is_anomaly` is populated by the classifier itself (`ml/consumer.py`),
not a separate process. It's actually five independent signals
(`ml/anomaly_signals.py` for the stateless two, `DeviceBaselineCache` in
`consumer.py` for the two that need per-device history) — any one firing
sets `is_anomaly = 1`, and `events.anomaly_reasons` (an array column)
records *which* one(s) did, the same "always label the reason, not just a
verdict" principle already used for `resolution_method` and
`vendor_source`:

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

The last two are per-device, not global thresholds, since "unusual" only
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
3. **`RELAY_SOURCE_IPS`** (below) -- if your relay's rsyslog already
   preserves the original device's `HOSTNAME` field on forward (many do,
   by default, even without RFC 5424), you don't need to reconfigure
   anything: opt that relay's IP in and the pipeline recovers per-device
   identity from what's already arriving.

#### `RELAY_SOURCE_IPS`: recovering per-device identity from an opted-in relay

Confirmed on a real relay setup (rsyslog forwarding from a LogAnalyzer
collector): even though `fromhost-ip` collapses to the relay's own IP for
every event, the relay's rsyslog still forwarded each device's original
`HOSTNAME` field untouched -- for a MikroTik device with no `/system
identity` name configured, that field held the device's own management
IP (e.g. `172.20.0.74`), not the relay's. That's enough to recover real
per-device identity and analytics *without* touching the relay or the
devices, whenever it holds:

```bash
sudo systemctl edit syslog-ml-classifier
```
```ini
[Service]
Environment=RELAY_SOURCE_IPS=192.168.247.33,192.168.255.33
```
```bash
sudo systemctl restart syslog-ml-classifier
```

For an event whose `source_ip` matches one of these, `ml/consumer.py`
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

**Only fixes what's already in the data.** If your relay doesn't preserve
per-device identity in the forwarded message at all (check with `sudo
grep '"source_ip": *"<relay-ip>"' /var/log/syslog-ml/raw.jsonl | tail -3`
and look at `reported_hostname`), this can't recover it -- fall back to
option 1 or 2 above.

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

## Files

- `clickhouse/init.sql` — `device_inventory`, `events`, and the per-minute rollup.
- `rsyslog/10-network-listener.conf` — enables rsyslog to receive syslog over the network (UDP/TCP 514), not just local messages.
- `rsyslog/60-syslog-ml.conf` — mirrors rsyslog's feed to a local JSON file.
- `snmptrapd/` — optional SNMP trap receiver config, feeding traps into the same pipeline via local syslog.
- `ml/consumer.py` — tails the file, resolves identity, classifies, flags anomalies, writes to ClickHouse.
- `ml/anomaly_signals.py` — stateless anomaly signals (always_severe, security_content); the per-device ones (severity_spike, volume_spike) live in `consumer.py`'s `DeviceBaselineCache`.
- `ml/device_resolver.py` / `ml/resolve_pending.py` — the opt-in SNMP identity resolver, including credential-pool discovery/auto-save (reads credentials from Postgres, see `web/`).
- `ml/reverify_devices.py` — twice-daily re-check of already-resolved devices; self-heals an auto-discovered credential if its community rotates.
- `ml/vendor_signatures.py` — passive, no-credential vendor detection from syslog message format.
- `ml/labeling_rules.py` — weak-supervision category rules (tune for your vendors).
- `ml/train_classifier.py` — trains the TF-IDF + linear SVM classifier.
- `ml/evaluate_alerts.py` — evaluates alert rules against ClickHouse, fires webhooks.
- `systemd/` — unit files for the classifier, resolver timer, alert evaluator timer, and re-verify timer.
- `grafana/` — provisioned datasource + starter dashboard.
- `web/` — FastAPI + React admin app for managing SNMP credentials and viewing device status (see `web/README.md`).
