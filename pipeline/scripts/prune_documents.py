"""Delete a feed's documents and everything derived from them.

    uv run python -m scripts.prune_documents --feed ACSC --reset-poll-state
    uv run python -m scripts.prune_documents --feed MISP --drop-feed --apply

Dry-run by default: it prints what it would delete and exits. `--apply` is
required to touch anything, because this cascades through report and its child
tables and is not reversible.

Two situations it exists for, both of which the ingestion path cannot fix on
its own: docs/DECISIONS.md#re-ingesting-a-feed
"""

from __future__ import annotations

import argparse
import sys

from dotenv import load_dotenv
from sqlalchemy import delete, func, select, update

from enrich.db import (
    actor_review_queue,
    enrichment_run,
    ioc,
    report,
    report_actor,
    report_target,
    report_technique,
)
from ingest.db import feed, get_engine, raw_document


def _summarize(conn, feed_ids):
    documents = conn.execute(
        select(raw_document.c.id).where(raw_document.c.feed_id.in_(feed_ids))
    ).scalars().all()
    reports = conn.execute(
        select(report.c.id).where(report.c.document_id.in_(documents))
    ).scalars().all() if documents else []
    runs = conn.execute(
        select(func.count()).select_from(enrichment_run)
        .where(enrichment_run.c.document_id.in_(documents))
    ).scalar_one() if documents else 0
    return documents, reports, runs


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="scripts.prune_documents",
        description="Delete a feed's documents and derived rows. Dry-run unless --apply.",
    )
    parser.add_argument("--feed", required=True,
                        help="match against feed.name (prefix, case-sensitive)")
    parser.add_argument("--drop-feed", action="store_true",
                        help="also delete the feed row itself")
    parser.add_argument("--reset-poll-state", action="store_true",
                        help="clear etag/last_modified/last_polled_at so the next poll "
                             "re-ingests instead of getting a 304")
    parser.add_argument("--apply", action="store_true", help="actually delete")
    args = parser.parse_args(argv)

    load_dotenv()
    engine = get_engine()

    with engine.begin() as conn:
        feeds = conn.execute(
            select(feed.c.id, feed.c.name).where(feed.c.name.like(f"{args.feed}%"))
        ).all()
        if not feeds:
            print(f"no feed matching {args.feed!r}")
            return 1

        feed_ids = [row.id for row in feeds]
        documents, reports, runs = _summarize(conn, feed_ids)

        print("feeds matched:")
        for row in feeds:
            print(f"  {row.name}")
        print(f"\nwould delete: {len(documents)} raw_document, {len(reports)} report "
              f"(+ their actor/technique/target/ioc/review rows), {runs} enrichment_run")
        if args.drop_feed:
            print(f"would delete: {len(feeds)} feed row(s)")
        if args.reset_poll_state:
            print("would clear: etag, last_modified, last_polled_at")

        if not args.apply:
            print("\ndry run -- nothing changed. Re-run with --apply to delete.")
            return 0

        for table in (report_actor, report_technique, report_target, ioc, actor_review_queue):
            conn.execute(delete(table).where(table.c.report_id.in_(reports)))
        conn.execute(delete(report).where(report.c.id.in_(reports)))
        conn.execute(delete(enrichment_run).where(enrichment_run.c.document_id.in_(documents)))
        conn.execute(delete(raw_document).where(raw_document.c.id.in_(documents)))

        if args.reset_poll_state:
            conn.execute(update(feed).where(feed.c.id.in_(feed_ids)).values(
                etag=None, last_modified=None, last_polled_at=None))
        if args.drop_feed:
            conn.execute(delete(feed).where(feed.c.id.in_(feed_ids)))

        print("\ndeleted.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
