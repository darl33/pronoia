"""Following feed links (ingest/article.py).

same_site is the security-relevant part -- following links out of feed content
means fetching URLs a publisher chose, so §6's allowlist has to keep meaning
something. The rest covers degrading safely: a failed fetch must never cost us
the document. Synthetic pages and hostnames only (CLAUDE.md).
"""

from __future__ import annotations

import pytest

from ingest.article import (
    THIN_CONTENT_CHARS,
    enrich_document,
    extract_article_html,
    needs_article_fetch,
    same_site,
)
from ingest.parsers import ParsedDocument

FEED = "https://www.example-cert.test/rss/advisories"


# ---- same_site: the SSRF narrowing ----


@pytest.mark.parametrize(
    "article_url",
    [
        "https://www.example-cert.test/advisories/one",  # same host
        "https://www.example-cert.test:443/advisories/one",  # explicit default port
        "https://cdn.www.example-cert.test/advisories/one",  # subdomain of the feed host
        "https://WWW.EXAMPLE-CERT.TEST/advisories/one",  # case-insensitive
    ],
)
def test_same_site_allows_the_feeds_own_host(article_url):
    assert same_site(FEED, article_url) is True


@pytest.mark.parametrize(
    "article_url, why",
    [
        ("https://evil.test/advisories/one", "unrelated host"),
        ("https://example-cert.test.evil.test/x", "feed host as a prefix of an attacker domain"),
        ("https://www.example-cert.test.evil.test/x", "suffix-confusion on the full host"),
        ("https://other.example-cert.test/x", "sibling host, not a subdomain of the feed host"),
        ("https://169.254.169.254/latest/meta-data/", "cloud metadata address"),
        ("https://127.0.0.1/admin", "loopback"),
        ("http://www.example-cert.test/advisories/one", "http, not https"),
        ("file:///etc/passwd", "non-http scheme"),
        ("not a url at all", "unparseable"),
        ("", "empty"),
    ],
)
def test_same_site_blocks_everything_else(article_url, why):
    assert same_site(FEED, article_url) is False, why


def test_same_site_is_not_a_substring_check():
    """The classic bug: `article_host.endswith(feed_host)` without the dot lets
    `evilwww.example-cert.test` through."""
    assert same_site(FEED, "https://evilwww.example-cert.test/x") is False


# ---- body extraction ----


def test_prefers_the_largest_article_tag():
    """Publisher templates wrap related-content teasers in their own <article>
    tags; the real body is the biggest one."""
    html = f"""
      <html><body>
        <article>Related: a short teaser.</article>
        <article>{"The actual advisory body. " * 50}</article>
        <article>Another teaser.</article>
      </body></html>
    """
    extracted = extract_article_html(html)
    assert "The actual advisory body." in extracted
    assert "a short teaser" not in extracted


def test_falls_back_to_main_when_there_is_no_article():
    html = "<html><body><nav>menu</nav><main>Advisory content here.</main></body></html>"
    assert "Advisory content here." in extract_article_html(html)


def test_returns_none_when_no_container_matches():
    """None means "keep the feed content", not "store an empty document"."""
    assert extract_article_html("<html><body><div>orphan text</div></body></html>") is None


def test_empty_article_tag_is_not_treated_as_content():
    assert extract_article_html("<html><body><article>   </article></body></html>") is None


# ---- when to bother ----


def test_thin_feed_entries_are_worth_a_fetch():
    assert needs_article_fetch("x" * 85) is True
    assert needs_article_fetch("") is True
    assert needs_article_fetch(None) is True


def test_fat_feed_entries_are_left_alone():
    """Talos ships the whole post already; re-fetching would be pure waste."""
    assert needs_article_fetch("x" * (THIN_CONTENT_CHARS + 1)) is False


# ---- enrich_document degrades safely ----


def _doc(clean_text: str, url: str = "https://www.example-cert.test/advisories/one"):
    return ParsedDocument(
        source_url=url,
        title="synthetic advisory",
        published_at=None,
        raw_html=clean_text,
        clean_text=clean_text,
    )


def test_enrich_replaces_a_thin_body(monkeypatch):
    body = "Full synthetic advisory text. " * 40
    monkeypatch.setattr(
        "ingest.article.fetch_article_body", lambda *a, **k: (f"<article>{body}</article>", body)
    )
    doc = _doc("teaser")

    assert enrich_document(doc, FEED) is True
    assert doc.clean_text == body
    assert "<article>" in doc.raw_html


def test_enrich_keeps_feed_content_when_the_fetch_fails(monkeypatch):
    """A dead link, a 403 or an SSRF block must not cost us the document."""
    monkeypatch.setattr("ingest.article.fetch_article_body", lambda *a, **k: None)
    doc = _doc("teaser")

    assert enrich_document(doc, FEED) is False
    assert doc.clean_text == "teaser"


def test_enrich_rejects_an_article_shorter_than_the_teaser(monkeypatch):
    """Extracting a nav block instead of the body would *lose* information."""
    monkeypatch.setattr(
        "ingest.article.fetch_article_body", lambda *a, **k: ("<article>Skip to content</article>", "Skip to content")
    )
    doc = _doc("a" * 200)

    assert enrich_document(doc, FEED) is False
    assert doc.clean_text == "a" * 200


def test_enrich_never_fetches_off_site(monkeypatch):
    """The same_site gate is inside fetch_article_body, so prove it is reached:
    a real fetch would raise here."""
    def explode(*a, **k):
        raise AssertionError("fetch_url must not be called for an off-site link")

    monkeypatch.setattr("ingest.article.fetch_url", explode)
    doc = _doc("teaser", url="https://evil.test/advisories/one")

    assert enrich_document(doc, FEED) is False
    assert doc.clean_text == "teaser"
