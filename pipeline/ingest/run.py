"""Ingestion entrypoint: poll every enabled feed that is due, store new
documents, update poll state. Intended to be invoked periodically by cron
(DESIGN.md §2 lists "cron / APScheduler" as equally valid; a cron-invoked
script needs no extra long-running dependency, so that's what this is).

    uv run python -m ingest.run
"""

from __future__ import annotations

import logging

from dotenv import load_dotenv

from ingest.dedup import content_hash
from ingest.db import (
    get_engine,
    insert_raw_document,
    list_due_feeds,
    update_feed_poll_state,
    upsert_feed_seed,
)
from ingest.feeds import FEED_SEEDS
from ingest.fetch import (
    FetchResult,
    HttpError,
    NotModified,
    ResponseTooLarge,
    TooManyRedirects,
    fetch_url,
)
from ingest.parsers import parse_feed_body
from ingest.ssrf import SSRFBlocked
from ingest.xml_safe import UnsafeXmlRejected

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
log = logging.getLogger("ingest.run")


def seed_feeds() -> None:
    engine = get_engine()
    with engine.begin() as conn:
        for seed in FEED_SEEDS:
            upsert_feed_seed(
                conn,
                name=seed.name,
                url=seed.url,
                kind=seed.kind,
                poll_interval_minutes=seed.poll_interval_minutes,
            )


def poll_feed(conn, row) -> tuple[int, int]:
    """Returns (documents_stored, documents_deduped)."""
    try:
        result = fetch_url(row["url"], etag=row["etag"], last_modified=row["last_modified"])
    except (SSRFBlocked, ResponseTooLarge, TooManyRedirects, HttpError) as exc:
        log.warning("blocked/failed fetching feed %r (%s): %s", row["name"], row["url"], exc)
        return 0, 0
    except Exception:
        log.exception("unexpected error fetching feed %r (%s)", row["name"], row["url"])
        return 0, 0

    if isinstance(result, NotModified):
        log.info("feed %r not modified since last poll", row["name"])
        update_feed_poll_state(
            conn,
            feed_id=row["id"],
            etag=row["etag"],
            last_modified=row["last_modified"],
            polled_at=_now(),
        )
        return 0, 0

    assert isinstance(result, FetchResult)

    try:
        docs = parse_feed_body(row["kind"], result.body, result.final_url, row["name"])
    except UnsafeXmlRejected as exc:
        log.warning("rejected unsafe XML from feed %r: %s", row["name"], exc)
        docs = []
    except Exception:
        log.exception("failed to parse feed %r (%s)", row["name"], row["url"])
        docs = []

    stored = deduped = 0
    for doc in docs:
        h = content_hash(doc.raw_html or doc.clean_text or "")
        inserted = insert_raw_document(
            conn,
            feed_id=row["id"],
            source_url=doc.source_url,
            content_hash=h,
            title=doc.title,
            published_at=doc.published_at,
            raw_html=doc.raw_html,
            clean_text=doc.clean_text,
        )
        if inserted:
            stored += 1
        else:
            deduped += 1

    update_feed_poll_state(
        conn,
        feed_id=row["id"],
        etag=result.etag or row["etag"],
        last_modified=result.last_modified or row["last_modified"],
        polled_at=_now(),
    )
    log.info("feed %r: %d stored, %d deduped (of %d parsed)", row["name"], stored, deduped, len(docs))
    return stored, deduped


def _now():
    from datetime import datetime, timezone

    return datetime.now(timezone.utc)


def main() -> None:
    load_dotenv()
    seed_feeds()

    engine = get_engine()
    with engine.begin() as conn:
        due = list_due_feeds(conn)
    log.info("%d feed(s) due for polling", len(due))

    total_stored = total_deduped = 0
    for row in due:
        with engine.begin() as conn:
            stored, deduped = poll_feed(conn, row)
        total_stored += stored
        total_deduped += deduped

    log.info("done: %d new document(s), %d deduped", total_stored, total_deduped)


if __name__ == "__main__":
    main()
