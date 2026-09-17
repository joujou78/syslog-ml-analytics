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
                                                                   |
                                                              ClickHouse
                                                                   |
                                                                Grafana

                          (separate, async, every 10 min)
          syslog-ml-resolver.timer -> resolve_pending.py
             for each IP seen but not yet identified:
               - has a credential in Postgres (snmp_credentials table,
                 managed via the web app)? -> SNMP sysName/sysDescr/sysObjectID
               - writes result into ClickHouse device_inventory
```

There's also a web app (`web/`) for managing SNMP credentials through a UI
instead of hand-editing files, viewing device/resolution status, and
(planned) log search and ML feedback — see `web/README.md`. It's optional:
the pipeline above works standalone with Grafana as the only UI.

No message broker: one VM, one rsyslog instance receiving everything, so a
locally tailed file is enough durability without adding a Kafka/Redpanda
service to operate.

## Why this design, and what it deliberately doesn't do

- **No SNMP credential guessing.** Since communities aren't centrally
  tracked, the resolver only ever attempts SNMP for an IP that has a row in
  the `snmp_credentials` table (Postgres, encrypted at rest, managed
  through the web app's admin UI — see `web/README.md`) — never a
  default/common-string guess. Add rows as you onboard devices; everything
  else keeps working in the meantime.
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

```bash
sudo cp rsyslog/60-syslog-ml.conf /etc/rsyslog.d/
sudo systemctl restart rsyslog

sudo cp systemd/syslog-ml-classifier.service systemd/syslog-ml-resolver.service systemd/syslog-ml-resolver.timer /etc/systemd/system/

# The resolver needs credentials for the shared Postgres DB + the same
# Fernet key the web app encrypts SNMP secrets with (see web/README.md
# Step 3 for the matching web-api.env):
sudo cp systemd/syslog-ml-resolver.env.example /etc/syslog-ml/resolver.env
sudo $EDITOR /etc/syslog-ml/resolver.env
sudo chmod 600 /etc/syslog-ml/resolver.env
sudo chown syslog-ml:syslog-ml /etc/syslog-ml/resolver.env

sudo systemctl daemon-reload
sudo systemctl enable --now syslog-ml-classifier.service
sudo systemctl enable --now syslog-ml-resolver.timer
```

**Checkpoint:**

```bash
sudo tail -f /var/log/syslog-ml/raw.jsonl              # confirm rsyslog is writing
sudo journalctl -u syslog-ml-classifier -f              # confirm it's processing
clickhouse-client --query "SELECT count() FROM syslog_ml.events"
```

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
- `rsyslog/60-syslog-ml.conf` — mirrors rsyslog's feed to a local JSON file.
- `ml/consumer.py` — tails the file, resolves identity, classifies, writes to ClickHouse.
- `ml/device_resolver.py` / `ml/resolve_pending.py` — the opt-in SNMP identity resolver (reads credentials from Postgres, see `web/`).
- `ml/labeling_rules.py` — weak-supervision category rules (tune for your vendors).
- `ml/train_classifier.py` — trains the TF-IDF + linear SVM classifier.
- `systemd/` — unit files for the classifier and the resolver timer.
- `grafana/` — provisioned datasource + starter dashboard.
- `web/` — FastAPI + React admin app for managing SNMP credentials and viewing device status (see `web/README.md`).
