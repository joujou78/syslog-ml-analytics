"""
Creates the OpenSearch index that ml/log_assistant_indexer.py writes to and
web/backend's log_assistant_service.py queries -- run once after installing
OpenSearch (see README's "Log Assistant" section), and safe to re-run
(no-ops if the index already exists; it does NOT update the mapping of an
existing index, since OpenSearch can't change a knn_vector field's
dimension in place -- delete and recreate if you switch embedding models).

    python3 setup_index.py

Reads the same OPENSEARCH_* / EMBEDDING_DIM env vars as the indexer and the
backend, so the three agree on where the index lives and how wide its
vectors are.
"""
import json
import os
import sys
from pathlib import Path

from opensearchpy import OpenSearch

OPENSEARCH_URL = os.environ.get("OPENSEARCH_URL", "http://localhost:9200")
OPENSEARCH_INDEX = os.environ.get("OPENSEARCH_INDEX", "syslog_ml_log_events")
# Must match the output dimension of OLLAMA_EMBED_MODEL (see ml/log_assistant_indexer.py).
# nomic-embed-text -> 768. Changing this after the index is created has no
# effect -- delete the index and re-run this script instead.
EMBEDDING_DIM = int(os.environ.get("EMBEDDING_DIM", "768"))


def main():
    body = json.loads((Path(__file__).parent / "log_events_index.json").read_text())
    body["mappings"]["properties"]["embedding"]["dimension"] = EMBEDDING_DIM

    client = OpenSearch(hosts=[OPENSEARCH_URL])
    if client.indices.exists(index=OPENSEARCH_INDEX):
        print(f"Index '{OPENSEARCH_INDEX}' already exists, leaving it as-is.")
        return
    client.indices.create(index=OPENSEARCH_INDEX, body=body)
    print(f"Created index '{OPENSEARCH_INDEX}' (embedding dimension {EMBEDDING_DIM}).")


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(f"Failed to set up OpenSearch index: {exc}", file=sys.stderr)
        sys.exit(1)
