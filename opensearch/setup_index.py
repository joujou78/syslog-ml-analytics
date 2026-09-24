"""
Creates the OpenSearch index that ml/log_assistant_indexer.py writes to and
web/backend's log_assistant_service.py queries, and the hybrid-search
pipeline that combines BM25 keyword matching with k-NN vector search over
it -- run once after installing OpenSearch (see README's "Log Assistant"
section), and safe to re-run: the index creation itself no-ops if the
index already exists (it does NOT update the mapping of an existing index,
since OpenSearch can't change a knn_vector field's dimension in place --
delete and recreate if you switch embedding models), but the search
pipeline setup always re-applies (both PUTs are idempotent), so re-running
this is also how you'd pick up a change to HYBRID_SEARCH_PIPELINE's config.

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

# Pure vector (k-NN) search alone misses the things network logs are full of
# and embeddings represent poorly: exact IP addresses, hostnames, error
# codes, session IDs. A keyword search for "172.22.21.165" or "ACSSERVER"
# finds it instantly; a vector search might not rank it highly at all.
# Reciprocal rank fusion (RRF) combines a BM25 match (on `message`) with the
# k-NN clause so both kinds of query are covered -- introduced as a native
# OpenSearch search pipeline processor (score-ranker-processor) in 2.19.
# Set as this index's own default search pipeline here (one-time setup,
# same as the index mapping itself) so log_assistant_service.py's queries
# don't need to reference it per-request. rank_constant=60 is OpenSearch's
# own documented default.
HYBRID_SEARCH_PIPELINE = os.environ.get("HYBRID_SEARCH_PIPELINE", "log_assistant_hybrid_rrf")


def _ensure_hybrid_pipeline(client: OpenSearch):
    client.search_pipeline.put(
        id=HYBRID_SEARCH_PIPELINE,
        body={
            "description": "RRF fusion of BM25 (message) and k-NN (embedding) for Log Assistant",
            "phase_results_processors": [
                {"score-ranker-processor": {"combination": {"technique": "rrf", "rank_constant": 60}}}
            ],
        },
    )
    client.indices.put_settings(
        index=OPENSEARCH_INDEX,
        body={"index": {"search": {"default_pipeline": HYBRID_SEARCH_PIPELINE}}},
    )
    print(f"Set '{HYBRID_SEARCH_PIPELINE}' as the default search pipeline for '{OPENSEARCH_INDEX}'.")


def main():
    body = json.loads((Path(__file__).parent / "log_events_index.json").read_text())
    body["mappings"]["properties"]["embedding"]["dimension"] = EMBEDDING_DIM

    client = OpenSearch(hosts=[OPENSEARCH_URL])
    if client.indices.exists(index=OPENSEARCH_INDEX):
        print(f"Index '{OPENSEARCH_INDEX}' already exists, leaving its mapping as-is.")
    else:
        client.indices.create(index=OPENSEARCH_INDEX, body=body)
        print(f"Created index '{OPENSEARCH_INDEX}' (embedding dimension {EMBEDDING_DIM}).")

    # Re-run safe regardless of whether the index above was just created or
    # already existed -- PUT on a search pipeline and an index setting are
    # both idempotent, unlike index creation.
    _ensure_hybrid_pipeline(client)


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(f"Failed to set up OpenSearch index: {exc}", file=sys.stderr)
        sys.exit(1)
