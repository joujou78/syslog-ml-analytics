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
    ollama_url: str = "http://localhost:11434"
    # Must match ml/log_assistant_indexer.py's OLLAMA_EMBED_MODEL -- a
    # question is embedded with this model to kNN-search against vectors
    # the indexer produced with it; mismatched models search meaninglessly.
    ollama_embed_model: str = "nomic-embed-text"
    # The larger model that turns retrieved log lines into an answer.
    # Pick one that actually fits the host's RAM (see README's Log
    # Assistant section for a memory budget) -- nothing here enforces that.
    ollama_chat_model: str = "llama3.1:8b-instruct-q4_K_M"
    ollama_timeout_seconds: float = 60.0
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

    cors_origins: list[str] = ["http://localhost:5173"]


settings = Settings()
