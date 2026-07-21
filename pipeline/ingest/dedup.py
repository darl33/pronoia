"""Content-hash dedup key (DESIGN.md §4: `raw_document.content_hash`,
unique on (feed_id, content_hash))."""

from __future__ import annotations

import hashlib

from ingest.sanitize import normalize_whitespace


def content_hash(body: str) -> bytes:
    canonical = normalize_whitespace(body).encode("utf-8")
    return hashlib.sha256(canonical).digest()
