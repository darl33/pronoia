"""SQLAlchemy Core tables mirroring db/migrations, plus bound-parameter-only
helpers. The schema is owned by db/migrations, not here.

docs/DECISIONS.md#schema-ownership
"""

from __future__ import annotations

import os
from datetime import datetime, timezone

from sqlalchemy import (
    BigInteger,
    Boolean,
    Column,
    DateTime,
    ForeignKey,
    Integer,
    LargeBinary,
    MetaData,
    Table,
    Text,
    create_engine,
    select,
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.engine import Engine
from uuid6 import uuid7

metadata = MetaData()

feed = Table(
    "feed",
    metadata,
    Column("id", UUID(as_uuid=True), primary_key=True),
    Column("name", Text, nullable=False),
    Column("url", Text, nullable=False, unique=True),
    Column("kind", Text, nullable=False),
    Column("poll_interval_minutes", Integer, nullable=False, server_default="360"),
    Column("etag", Text),
    Column("last_modified", Text),
    Column("last_polled_at", DateTime(timezone=True)),
    Column("enabled", Boolean, nullable=False, server_default="true"),
    Column("fetch_articles", Boolean, nullable=False, server_default="false"),
)

raw_document = Table(
    "raw_document",
    metadata,
    Column("id", UUID(as_uuid=True), primary_key=True),
    Column("feed_id", UUID(as_uuid=True), ForeignKey("feed.id"), nullable=False),
    Column("source_url", Text, nullable=False),
    Column("fetched_at", DateTime(timezone=True), nullable=False),
    Column("content_hash", LargeBinary, nullable=False),
    Column("title", Text),
    Column("published_at", DateTime(timezone=True)),
    Column("raw_html", Text),
    Column("clean_text", Text),
)


def get_engine() -> Engine:
    url = os.environ["PIPELINE_DATABASE_URL"]
    return create_engine(url, future=True)


def upsert_feed_seed(
    conn, *, name: str, url: str, kind: str, poll_interval_minutes: int,
    fetch_articles: bool = False,
) -> None:
    """Idempotently register a feed definition. Existing poll state
    (etag/last_modified/last_polled_at) is left untouched."""
    stmt = pg_insert(feed).values(
        id=uuid7(),
        name=name,
        url=url,
        kind=kind,
        poll_interval_minutes=poll_interval_minutes,
        fetch_articles=fetch_articles,
    )
    stmt = stmt.on_conflict_do_update(
        index_elements=[feed.c.url],
        set_={
            "name": stmt.excluded.name,
            "kind": stmt.excluded.kind,
            "fetch_articles": stmt.excluded.fetch_articles,
        },
    )
    conn.execute(stmt)


def list_due_feeds(conn):
    """Feeds that are enabled and either never polled or past their
    poll_interval_minutes."""
    now = datetime.now(timezone.utc)
    rows = conn.execute(select(feed).where(feed.c.enabled.is_(True))).mappings().all()
    due = []
    for row in rows:
        if row["last_polled_at"] is None:
            due.append(row)
            continue
        elapsed_minutes = (now - row["last_polled_at"]).total_seconds() / 60
        if elapsed_minutes >= row["poll_interval_minutes"]:
            due.append(row)
    return due


def raw_document_exists(conn, *, feed_id, content_hash: bytes) -> bool:
    """Has this feed entry already been stored?

    Lets the caller skip fetching an article body it is about to discard as a
    dedup hit -- otherwise every poll re-requests every article forever. ON
    CONFLICT is still the real guarantee; this only avoids the wasted request.
    """
    return conn.execute(
        select(raw_document.c.id)
        .where(raw_document.c.feed_id == feed_id)
        .where(raw_document.c.content_hash == content_hash)
        .limit(1)
    ).first() is not None


def insert_raw_document(
    conn,
    *,
    feed_id,
    source_url: str,
    content_hash: bytes,
    title: str | None,
    published_at: datetime | None,
    raw_html: str | None,
    clean_text: str | None,
) -> bool:
    """Returns True if a new row was inserted, False if it was a dedup hit."""
    stmt = (
        pg_insert(raw_document)
        .values(
            id=uuid7(),
            feed_id=feed_id,
            source_url=source_url,
            fetched_at=datetime.now(timezone.utc),
            content_hash=content_hash,
            title=title,
            published_at=published_at,
            raw_html=raw_html,
            clean_text=clean_text,
        )
        .on_conflict_do_nothing(index_elements=[raw_document.c.feed_id, raw_document.c.content_hash])
        .returning(raw_document.c.id)
    )
    result = conn.execute(stmt)
    return result.first() is not None


def update_feed_poll_state(
    conn, *, feed_id, etag: str | None, last_modified: str | None, polled_at: datetime
) -> None:
    conn.execute(
        feed.update()
        .where(feed.c.id == feed_id)
        .values(etag=etag, last_modified=last_modified, last_polled_at=polled_at)
    )
