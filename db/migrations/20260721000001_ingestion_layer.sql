-- Ingestion layer: feed registry + raw fetched documents.
-- Single source of truth for both the Python pipeline and the Rust API (DESIGN.md §2, §4).

CREATE TABLE feed (
    id            UUID PRIMARY KEY,
    name          TEXT NOT NULL,
    url           TEXT NOT NULL UNIQUE,
    kind          TEXT NOT NULL CHECK (kind IN ('rss','atom','html','json')),
    poll_interval_minutes INT NOT NULL DEFAULT 360,
    etag          TEXT,
    last_modified TEXT,
    last_polled_at TIMESTAMPTZ,
    enabled       BOOLEAN NOT NULL DEFAULT true
);

CREATE TABLE raw_document (
    id            UUID PRIMARY KEY,
    feed_id       UUID NOT NULL REFERENCES feed(id),
    source_url    TEXT NOT NULL,
    fetched_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    content_hash  BYTEA NOT NULL,          -- sha256 of canonical body, dedup key
    title         TEXT,
    published_at  TIMESTAMPTZ,
    raw_html      TEXT,                    -- as fetched, never rendered
    clean_text    TEXT,                    -- sanitized extraction (see §6)
    UNIQUE (feed_id, content_hash)
);
