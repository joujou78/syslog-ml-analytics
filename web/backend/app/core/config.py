import json

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_prefix="SYSLOG_ML_", extra="ignore")

    # Postgres holds the web app's own state: users, SNMP credentials, ML
    # feedback/corrections. Kept separate from ClickHouse, which stays a
    # write-heavy, read-mostly store for the log events themselves.
    database_url: str = "postgresql+asyncpg://syslog_ml:syslog_ml@localhost:5432/syslog_ml"

    clickhouse_host: str = "localhost"
    clickhouse_port: int = 8123
    clickhouse_user: str = "default"
    clickhouse_password: str = ""

    # Log Assistant (semantic search + local-LLM "ask") -- see README.
    # Populated by ml/log_assistant_indexer.py; same index name/URL both
    # sides must agree on (see opensearch/setup_index.py).
    opensearch_url: str = "http://localhost:9200"
    opensearch_index: str = "syslog_ml_log_events"
    # Must mirror ml/log_assistant_indexer.py's OWN identically-named env
    # var exactly (bare INDEXER_ANOMALIES_ONLY, no SYSLOG_ML_ prefix --
    # that script reads os.environ directly, not through this Settings
    # class, so validation_alias is used to bypass the usual prefix here).
    # Confirmed live as a real gap: build_coverage_note's "N matching log
    # line(s) exist... but haven't been indexed for semantic search YET"
    # note counted ALL rows matching the filter regardless of is_anomaly,
    # which is actively misleading once this flag is on -- the
    # overwhelming majority of a typical window's raw rows are ordinary,
    # non-anomalous chatter the indexer will NEVER embed under this
    # setting, not just "not yet". Confirmed live: a 30-row window with
    # only 10 is_anomaly=1 rows (5 from two actually-flagged
    # unusual_template_mix sub-windows) got the identical "not indexed
    # yet" wording a genuinely quiet, fully-caught-up window would, with
    # nothing to tell a user which case they're actually in.
    indexer_anomalies_only: bool = Field(default=False, validation_alias="INDEXER_ANOMALIES_ONLY")
    ollama_url: str = "http://localhost:11434"
    # Must match ml/log_assistant_indexer.py's OLLAMA_EMBED_MODEL -- a
    # question is embedded with this model to kNN-search against vectors
    # the indexer produced with it; mismatched models search meaninglessly.
    ollama_embed_model: str = "nomic-embed-text"
    # The larger model that turns retrieved log lines into an answer.
    # Pick one that actually fits the host's RAM (see README's Log
    # Assistant section for a memory budget) -- nothing here enforces that.
    ollama_chat_model: str = "llama3.1:8b-instruct-q4_K_M"
    # Confirmed on net-flow: an uncontended chat completion took ~6s, but
    # the same request took 4+ minutes while something else (the Log
    # Assistant indexer's own embedding backfill) was competing for the
    # same CPU -- 60s was nowhere near enough headroom for that reality.
    # Deliberately a few seconds SHORTER than web/nginx/syslog-ml-web.conf's
    # `/api/log-assistant/` proxy_read_timeout (300s): when a request truly
    # can't finish in time, this should always fire first, so the caller
    # gets our own clean 502 (a real `detail` message, see
    # log_assistant.py's _upstream_error) instead of nginx's blunt 504
    # (plain HTML, no detail -- confirmed on net-flow this reliably got
    # misread as "OpenSearch/Ollama is down" instead of "this was just
    # slow"). If nginx's timeout is ever lowered, lower this to stay under
    # it; this must never be >= nginx's value or the race is undefined.
    ollama_timeout_seconds: float = 290.0
    # Bounds worst-case "ask" latency deterministically, which the timeout
    # above alone doesn't: confirmed on net-flow that a genuinely
    # content-rich question (many real matching log lines, e.g. "top up
    # down ports" against a network that logs plenty of real interface
    # flaps) can induce a long generated answer that -- at this CPU-only
    # hardware's measured ~4.5-5 tokens/sec decode speed -- takes minutes on
    # its own, regardless of indexer contention. A trivial question (e.g.
    # "test") gets a short answer and finishes in seconds; a real one can
    # hit the 300s timeout even with no other load on the box. 400 tokens is
    # roughly 300-400 words -- plenty for a concise analysis answer, and
    # ~80-90s worst case at this hardware's measured decode speed, leaving
    # real margin under ollama_timeout_seconds even under some contention.
    ollama_num_predict: int = 400
    # Confirmed live as a real gap the single-call timeout above doesn't
    # close: ask()'s tool-calling loop can make up to MAX_TOOL_ITERATIONS
    # (log_assistant_service.py) separate Ollama calls, each independently
    # budgeted up to ollama_timeout_seconds -- so the loop's total worst
    # case is MAX_TOOL_ITERATIONS * ollama_timeout_seconds, far beyond
    # nginx's single 300s proxy_read_timeout for the whole HTTP request.
    # A real question ("what was happening in its logs...") needed a
    # second round after its first tool call (semantic_search) came back
    # empty due to indexer lag -- the cumulative time crossed nginx's
    # ceiling before the backend's own per-call timeout ever had a chance
    # to fire, so nginx's blunt connection drop won the race instead of
    # this app's own clean, explained error -- the exact "misread as down"
    # failure ollama_timeout_seconds' own comment already describes
    # avoiding for a single slow call, just via a path that guard didn't
    # cover. ask() now tracks a wall-clock deadline across the WHOLE loop
    # using this budget (not just per-call) and gives up cleanly, with its
    # own explained message, before nginx's timeout can win that race.
    # Deliberately leaves real margin under nginx's 300s on top of
    # ollama_timeout_seconds' own margin, for tool-execution time
    # (ClickHouse/OpenSearch queries) between model calls, which eats into
    # the same 300s window but isn't itself bounded by ollama_timeout_seconds.
    ask_total_timeout_seconds: float = 270.0
    # Caps how many CPU threads THIS call is allowed to use. Root-caused on
    # net-flow (8 cores): with no cap, each llama-server process (one per
    # loaded model -- the embed model AND the chat model are separate
    # processes) defaults to using up to all 8 cores for its own inference.
    # The indexer's embed calls and an interactive chat completion can
    # genuinely run at the same time, and observed directly via `top`
    # during a hang: both llama-server processes actively computing at
    # once, 300%+ CPU each, total load average over 13 on an 8-core box --
    # severe thread oversubscription, not a code bug, not Ollama itself
    # hanging. 6 threads leaves headroom so the embed model (capped
    # separately, see ml/log_assistant_indexer.py's OLLAMA_EMBED_NUM_THREAD)
    # can still get real CPU time without the two fighting for all 8 cores.
    ollama_chat_num_thread: int = 6
    # Empty means "use the built-in prompts/log_assistant_system.txt next to
    # the service code" (see log_assistant_service.py) -- override only to
    # point at a different file without touching the shipped default.
    log_assistant_system_prompt_file: str = ""

    jwt_secret: str = "changeme-generate-a-real-secret-with-openssl-rand-hex-32"
    jwt_algorithm: str = "HS256"
    jwt_expire_minutes: int = 60 * 8

    # Dev-only default. Generate a real one with:
    #   python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
    credential_encryption_key: str = "l_4kEGewM6ILrPN6XDKa9tW2gW7FxcG4pisE1GkoL8M="

    # Deliberately a plain str field (not list[str]) with an explicit
    # validation_alias pinning it to the exact env var name this project
    # has always used -- pydantic-settings JSON-decodes a list[str] field
    # at the SOURCE level, before any field_validator ever runs, and that
    # decode fails outright the moment this value is supplied any way
    # other than systemd's own EnvironmentFile= parsing (e.g. sourcing the
    # same file through bash for a one-off manual command like alembic --
    # confirmed the hard way deploying this exact project: bash's quote
    # removal turns `["a","b"]` into the invalid `[a,b]`). A plain string
    # never enters that decode path at all, so it's simply immune to this
    # failure mode regardless of how it's supplied. See cors_origins below
    # for the parsed form actually used by the app.
    cors_origins_raw: str = Field(default="http://localhost:5173", validation_alias="SYSLOG_ML_CORS_ORIGINS")

    @property
    def cors_origins(self) -> list[str]:
        """Comma-separated (e.g. SYSLOG_ML_CORS_ORIGINS=https://a,https://b).
        Also tolerates a legacy JSON-array-formatted value, for anyone who
        had it set that way already."""
        value = self.cors_origins_raw.strip()
        if value.startswith("["):
            try:
                return json.loads(value)
            except json.JSONDecodeError:
                value = value.strip("[]")
        return [origin.strip() for origin in value.split(",") if origin.strip()]


settings = Settings()
