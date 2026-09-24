# sislogIQ (Log Assistant) activation runbook — net-flow

One-time steps to turn on semantic search + local LLM Q&A once `net-flow`
is resized to 16GB. All commands assume `net-flow`; run them as
`administrator` (they `sudo` where needed). Background and rationale for
each step: `README.md` § "Step 7 — Log Assistant".

## 0. Confirm the resize actually landed

```bash
free -h
```

Total memory should read ~16GB. Do not continue past this point on the
old (~7.8GB) box — the existing stack (ClickHouse, Postgres, the
classifier, gunicorn) already uses most of it; adding OpenSearch's JVM
heap and a loaded Ollama model on top risks OOM-killing the live syslog
pipeline, not just failing to start.

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

## 3. Create the OpenSearch index and enable the indexer

```bash
sudo -u syslog-ml /opt/syslog-ml/venv/bin/pip install -r /opt/syslog-ml/ml/requirements.txt
sudo -u syslog-ml /opt/syslog-ml/venv/bin/python /opt/syslog-ml/opensearch/setup_index.py
sudo cp /opt/syslog-ml/systemd/syslog-ml-log-assistant-indexer.service /etc/systemd/system/
sudo systemctl daemon-reload
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
