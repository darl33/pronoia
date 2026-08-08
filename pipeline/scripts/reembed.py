"""Re-embed every report after the embedding model changes (DESIGN.md §5.3).

    uv run python -m scripts.reembed [--batch-size N] [--limit N] [--dry-run]

§5.3 says embeddings are BYO at deployment, not hot-swappable. This is what
makes that migration path real rather than hypothetical.

Safe to re-run after an interruption: the work query skips rows already on the
configured model, and each batch commits on its own, so a second run resumes
where the first stopped and a completed run is a no-op. Not one big
transaction -- that would hold locks throughout and lose all progress on any
failure, the opposite of what a recovery tool should do.
"""

from __future__ import annotations

import argparse
import logging
import sys

from dotenv import load_dotenv

from enrich.client import get_embedding_client
from enrich.config import REPORT_EMBEDDING_DIM, ConfigError, resolve_completion
from enrich.db import list_reports_needing_embedding, update_report_embedding
from ingest.db import get_engine

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
log = logging.getLogger("scripts.reembed")

DEFAULT_BATCH_SIZE = 32


def _resolve_embedder():
    try:
        completion_config = resolve_completion()
    except ConfigError as exc:
        raise SystemExit(f"LLM config: {exc}") from exc

    embedder = get_embedding_client(completion_config)
    if embedder is None:
        raise SystemExit(
            "no embedding provider resolved, so there is nothing to re-embed with. "
            "Set EMBEDDING_BASE_URL (and EMBEDDING_MODEL), or start a local runtime. "
            "Run `pronoia doctor` to see what resolved."
        )
    return embedder


def _check_dimension(embedder) -> int:
    """Refuse to start on a width mismatch.

    Fatal here, unlike the enrichment path where it degrades to NULL (§5.4):
    the caller asked to re-embed everything, so reporting progress while
    writing nothing would be the worst outcome.
    """
    dimension = embedder.dimension
    if dimension != REPORT_EMBEDDING_DIM:
        raise SystemExit(
            f"{embedder.model} produces {dimension}-dimensional vectors but "
            f"report.embedding is VECTOR({REPORT_EMBEDDING_DIM}).\n\n"
            "Changing the dimension needs a schema migration ALTERing the column "
            "*and* this full re-embed, in that order. See the README section "
            "'Changing the embedding model'."
        )
    return dimension


def reembed(engine, embedder, *, batch_size: int, limit: int | None, dry_run: bool) -> int:
    dimension = _check_dimension(embedder)

    with engine.begin() as conn:
        pending = list_reports_needing_embedding(conn, embedding_model=embedder.model, limit=limit)

    total = len(pending)
    if not total:
        log.info("nothing to do: every report is already embedded by %s", embedder.model)
        return 0

    log.info(
        "re-embedding %d report(s) with %s (%d dimensions) in batches of %d",
        total, embedder.model, dimension, batch_size,
    )
    if dry_run:
        log.info("--dry-run: no rows written")
        return 0

    done = 0
    for start in range(0, total, batch_size):
        batch = pending[start : start + batch_size]
        vectors = embedder.embed([row["summary"] for row in batch])

        if len(vectors) != len(batch):
            raise SystemExit(
                f"embedding provider returned {len(vectors)} vectors for a batch of "
                f"{len(batch)}; refusing to guess which vector belongs to which report"
            )

        # One transaction per batch: the vector and both provenance columns for
        # every row in the batch land together or not at all.
        with engine.begin() as conn:
            for row, vector in zip(batch, vectors):
                if len(vector) != dimension:
                    raise SystemExit(
                        f"report {row['id']} got a {len(vector)}-dimensional vector, "
                        f"expected {dimension}; the provider is not stable, stopping "
                        "before writing a mixed batch"
                    )
                update_report_embedding(
                    conn,
                    report_id=row["id"],
                    embedding=vector,
                    embedding_model=embedder.model,
                    embedding_dim=dimension,
                )

        done += len(batch)
        log.info("  %d/%d (%.0f%%)", done, total, 100 * done / total)

    log.info("done: %d report(s) now embedded by %s", done, embedder.model)
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Re-embed all reports with the currently configured embedding model."
    )
    parser.add_argument("--batch-size", type=int, default=DEFAULT_BATCH_SIZE)
    parser.add_argument("--limit", type=int, default=None, help="stop after N reports")
    parser.add_argument(
        "--dry-run", action="store_true", help="report what would be re-embedded, write nothing"
    )
    args = parser.parse_args()

    if args.batch_size < 1:
        parser.error("--batch-size must be at least 1")

    load_dotenv()
    embedder = _resolve_embedder()
    return reembed(
        get_engine(),
        embedder,
        batch_size=args.batch_size,
        limit=args.limit,
        dry_run=args.dry_run,
    )


if __name__ == "__main__":
    sys.exit(main())
