import clickhouse_connect
from clickhouse_connect.driver.client import Client

from app.core.config import settings

_client: Client | None = None


def get_clickhouse_client() -> Client:
    global _client
    if _client is None:
        _client = clickhouse_connect.get_client(
            host=settings.clickhouse_host, port=settings.clickhouse_port
        )
    return _client
