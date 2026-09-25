# sislogIQ (Log Assistant) activation runbook — net-flow

One-time steps to turn on semantic search + local LLM Q&A once `net-flow`
is resized to 16GB. All commands assume `net-flow`; run them as
`administrator` (they `sudo` where needed). Background and rationale for
each step: `README.md` § "Step 7 — Log Assistant".

## 0. Confirm the resize actually landed

```bash
free -h
nproc
grep -o -E "\bavx\b|\bavx2\b|\bfma\b" /proc/cpuinfo | sort -u
```

Total memory should read ~16GB. Do not continue past this point on the
old (~7.8GB) box — the existing stack (ClickHouse, Postgres, the
classifier, gunicorn) already uses most of it; adding OpenSearch's JVM
heap and a loaded Ollama model on top risks OOM-killing the live syslog
pipeline, not just failing to start.

**If the CPU flags check shows only `avx` (no `avx2`, no `fma`)** — true on
net-flow's actual hardware (Intel Xeon E5-2620, confirmed after the RAM
resize) — read README's "CPU matters as much as RAM" under the Log
Assistant section before continuing. Short version: set
`OLLAMA_KEEP_ALIVE=-1` on the `ollama` service once it's installed (step 2)
so models don't pay a ~55-second reload cost after every idle gap, and set
`INDEXER_ANOMALIES_ONLY=true` on the indexer service (step 3) since ~1.2
msg/sec measured embedding throughput on that CPU can't keep up with
indexing every event on a busy host. Neither is needed on a CPU with
AVX2/FMA.

## 1. Install OpenSearch (native, loopback-only)

```bash
curl -fsSL https://artifacts.opensearch.org/publickeys/opensearch.pgp | sudo gpg --dearmor -o /usr/share/keyrings/opensearch-keyring
echo "deb [signed-by=/usr/share/keyrings/opensearch-keyring] https://artifacts.opensearch.org/releases/bundle/opensearch/2.x/apt stable main" | sudo tee /etc/apt/sources.list.d/opensearch-2.x.list
sudo apt update && sudo apt install opensearch
```

Edit `/etc/opensearch/opensearch.yml`:

```yaml
network.host: 127.0.0.1
plugins.security.disabled: true
```

`plugins.security.disabled` is safe specifically because this binds to
loopback only — never do this if you ever bind it to a non-loopback
address.

```bash
sudo systemctl enable --now opensearch
sudo systemctl status opensearch   # confirm "active (running)" before continuing
curl -s http://localhost:9200      # should return a JSON cluster banner
```

## 2. Install Ollama + pull models

```bash
curl -fsSL https://ollama.com/install.sh | sh
ollama pull nomic-embed-text
ollama pull llama3.1:8b-instruct-q4_K_M
```

If `free -h` still looks tight after this, drop to a smaller chat model
instead (config change only, no code change):

```bash
ollama pull llama3.2:3b-instruct-q4_K_M
# then set SYSLOG_ML_OLLAMA_CHAT_MODEL=llama3.2:3b-instruct-q4_K_M in step 4
```

```bash
sudo systemctl status ollama       # confirm "active (running)"
ollama list                        # confirm both models are present
```

**Set models to stay resident, don't rely on the default 5-minute
keep-alive.** Ollama unloads an idle model after 5 minutes by default, and
reloading it costs real time (measured on net-flow's actual hardware: ~55
seconds for the 8B chat model, once RAM was no longer the constraint) --
easy to mistake for "this hardware can't do this at all" when it's really
just a reload tax paid on every gap between uses. With RAM to spare after
the resize, keep both models loaded permanently instead:

```bash
sudo systemctl edit ollama
```
Add:
```ini
[Service]
Environment=OLLAMA_KEEP_ALIVE=-1
```
```bash
sudo systemctl daemon-reload
sudo systemctl restart ollama
```

**Then warm up both models before enabling the indexer or restarting the
backend.** Loading a model into memory for the first time is far slower
than any later call once it's warm — confirmed on net-flow's 4-core box
(pre-resize): the *first* embed call (which also had to load the model)
took close to 20 minutes under CPU contention with the rest of the stack,
well past any reasonable request timeout, even though every call
afterward was fast. Doing that load here, with no timeout and nothing
else waiting on it, means step 3's indexer gets a warm model on its very
first real attempt instead of potentially timing out and retrying:

```bash
curl -s http://localhost:11434/api/embed -d '{"model":"nomic-embed-text","input":["warm up"]}' > /dev/null
curl -s http://localhost:11434/api/chat -d '{"model":"llama3.1:8b-instruct-q4_K_M","messages":[{"role":"user","content":"hi"}],"stream":false}' > /dev/null
```

Both may take a while the first time (this is expected and fine — there's no
timeout here to race against). With `OLLAMA_KEEP_ALIVE=-1` set above, they
now stay loaded indefinitely, not just for a 5-minute window.

**If `grep -o -E "\bavx2\b|\bfma\b" /proc/cpuinfo` came back empty in step
0** (no AVX2/FMA — true on net-flow's actual CPU), also check real embedding
throughput against real traffic before enabling the indexer in step 3:

```bash
time curl -s http://localhost:11434/api/embed -d '{"model":"nomic-embed-text","input":["sample line one","sample line two","sample line three","sample line four","sample line five"]}' -o /dev/null
clickhouse-client --query "SELECT count() FROM syslog_ml.events WHERE received_at >= now() - INTERVAL 1 HOUR"
clickhouse-client --query "SELECT count() FROM syslog_ml.events WHERE received_at >= now() - INTERVAL 1 HOUR AND is_anomaly = 1"
```

Divide that curl's time by 5 for messages/sec once warm, then compare
against the hourly counts (÷3600 for msg/sec) to see whether indexing
everything is realistic on this host, or whether step 3 needs
`INDEXER_ANOMALIES_ONLY=true`. See README's "CPU matters as much as RAM"
for net-flow's own measured numbers (~1.2 msg/sec capacity vs. ~2-4.6
msg/sec all-traffic vs. ~0.33 msg/sec anomalies-only).

## 3. Create the OpenSearch index + hybrid-search pipeline, and enable the indexer

`setup_index.py` now also creates a search pipeline that fuses BM25 keyword
matching with the k-NN vector search (RRF) and sets it as this index's
default — pure vector search alone misses exact IPs/hostnames/error codes
that a keyword match catches instantly. See README's Log Assistant section
for the full rationale.

```bash
sudo -u syslog-ml /opt/syslog-ml/venv/bin/pip install -r /opt/syslog-ml/ml/requirements.txt
sudo -u syslog-ml /opt/syslog-ml/venv/bin/python /opt/syslog-ml/opensearch/setup_index.py
sudo cp /opt/syslog-ml/systemd/syslog-ml-log-assistant-indexer.service /etc/systemd/system/
sudo systemctl daemon-reload
```

**If step 2's throughput check showed indexing everything isn't realistic
on this host** (no AVX2/FMA, all-traffic rate exceeds measured embedding
capacity), scope the indexer to anomalies only before enabling it:

```bash
sudo systemctl edit syslog-ml-log-assistant-indexer
```
Add:
```ini
[Service]
Environment=INDEXER_ANOMALIES_ONLY=true
```

Then enable either way:

```bash
sudo systemctl enable --now syslog-ml-log-assistant-indexer
sudo systemctl status syslog-ml-log-assistant-indexer   # confirm "active (running)"
journalctl -u syslog-ml-log-assistant-indexer -f        # watch it embed real events; Ctrl-C once you see it running cleanly
```

## 4. Point the backend at OpenSearch + Ollama

Only needed if you changed any default above (index name, model names,
non-default ports). Add to `/etc/syslog-ml/web-api.env`:

```
SYSLOG_ML_OPENSEARCH_URL=http://localhost:9200
SYSLOG_ML_OPENSEARCH_INDEX=syslog_ml_log_events
SYSLOG_ML_OLLAMA_URL=http://localhost:11434
SYSLOG_ML_OLLAMA_EMBED_MODEL=nomic-embed-text
SYSLOG_ML_OLLAMA_CHAT_MODEL=llama3.1:8b-instruct-q4_K_M
```

```bash
sudo systemctl restart syslog-ml-web-api
sudo systemctl status syslog-ml-web-api   # confirm "active (running)"
```

## 5. Smoke test

This is the actual first real end-to-end test of this feature — the
build sandbox couldn't reach opensearch.org/ollama.com, so none of the
OpenSearch/Ollama-facing code paths ran against the real services before
now (see README's "Honest testing caveat" under Step 7).

1. Open the web app → **Log Assistant** page.
2. Ask a real question about recent traffic (e.g. "what has ACSSERVER
   been logging in the last hour?").
3. Expect: a list of semantically relevant log lines, then an LLM-written
   answer citing them.

If it doesn't work as expected, check in this order:

```bash
journalctl -u syslog-ml-log-assistant-indexer -n 100   # is it actually embedding events?
journalctl -u opensearch -n 100
journalctl -u ollama -n 100
journalctl -u syslog-ml-web-api -n 100
```

## 6. Watch memory for the first hour

```bash
free -h   # re-check a few times over the first hour of real usage
```

Rough budget this was sized against (starting point, not a guarantee —
see README):

| Component | Approx. RAM |
|---|---|
| Existing stack (ClickHouse, Postgres, classifier, gunicorn) | 3–4 GB |
| OpenSearch JVM heap | 2 GB |
| OpenSearch off-heap + OS overhead | ~1 GB |
| Ollama + `llama3.1:8b-instruct-q4_K_M` loaded | ~6 GB |
| OS buffer / headroom | remainder |

If it's consistently tight, switch to the smaller chat model (step 2)
rather than letting it run close to OOM.
