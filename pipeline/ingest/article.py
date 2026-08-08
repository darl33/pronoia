"""Follow a feed entry's link and store the real article body (DESIGN.md §3, §6).

ACSC publishes one-line teasers, so those raw_document rows held 85-300 chars
and §5 extraction had nothing to work with. Talos ships full posts already.

Following links out of feed *content* widens the SSRF surface, so it is
narrowed three ways: `same_site` restricts targets to the feed's own host;
everything still goes through `fetch_url` (https-only, DNS validated and
pinned, redirects re-validated, 10 MB cap); and any failure falls back to the
feed content rather than losing the document.

same_site is the load-bearing one -- ssrf.py validates *addresses*, but only a
same-site check stops feed content pointing us anywhere on the internet.
"""

from __future__ import annotations

import logging

from bs4 import BeautifulSoup

from ingest.fetch import FetchResult, fetch_url
from ingest.sanitize import html_to_clean_text
from ingest.ssrf import validate_url_scheme

log = logging.getLogger("ingest.article")

# Under this, a feed entry is a teaser worth fetching properly; over it, the
# feed already gave us the body (Talos averages ~11k).
THIN_CONTENT_CHARS = 600

# Less text than the teaser means the extraction picked the wrong container.
MIN_IMPROVEMENT_RATIO = 1.2


def same_site(feed_url: str, article_url: str) -> bool:
    """True if `article_url` is on the feed's own host, or a subdomain of it.

    Stricter than eTLD+1, which would need a public-suffix list and would treat
    every *.gov.au sibling as same-site. Widen explicitly if a feed ever needs
    it; don't loosen the rule.
    """
    try:
        feed_host, _ = validate_url_scheme(feed_url)
        article_host, _ = validate_url_scheme(article_url)
    except Exception:
        # An unparseable or non-https URL is not same-site by definition.
        return False

    feed_host = feed_host.lower().rstrip(".")
    article_host = article_host.lower().rstrip(".")
    return article_host == feed_host or article_host.endswith("." + feed_host)


def extract_article_html(html: str) -> str | None:
    """Largest <article>, else <main>, else None.

    Largest rather than first: ACSC pages carry 3-5 <article> tags because the
    template wraps related-content teasers in them, and the body is reliably
    the biggest. Rejected a readability library -- heavier dependency, fuzzier
    heuristics to defend in review.
    """
    soup = BeautifulSoup(html, "html.parser")

    articles = soup.find_all("article")
    if articles:
        best = max(articles, key=lambda el: len(el.get_text(" ", strip=True)))
        if best.get_text(strip=True):
            return str(best)

    main = soup.find("main")
    if main is not None and main.get_text(strip=True):
        return str(main)

    return None


def needs_article_fetch(clean_text: str | None) -> bool:
    return len(clean_text or "") < THIN_CONTENT_CHARS


def fetch_article_body(feed_url: str, article_url: str, **fetch_kwargs) -> tuple[str, str] | None:
    """Return (raw_html, clean_text), or None to keep the feed content.

    Never raises -- every failure path returns None so the caller falls back.
    """
    if not same_site(feed_url, article_url):
        log.warning(
            "not following %s: off-site from feed %s (see ingest/article.py same_site)",
            article_url,
            feed_url,
        )
        return None

    try:
        result = fetch_url(article_url, **fetch_kwargs)
    except Exception as exc:
        log.warning("article fetch failed for %s: %s", article_url, exc)
        return None

    if not isinstance(result, FetchResult):
        return None

    html = result.body.decode("utf-8", errors="replace")
    article_html = extract_article_html(html)
    if article_html is None:
        log.warning("no <article> or <main> found at %s; keeping feed content", article_url)
        return None

    return article_html, html_to_clean_text(article_html)


def enrich_document(doc, feed_url: str, **fetch_kwargs) -> bool:
    """Replace a thin document's body with the real article; True if replaced.

    Mutates in place, after the caller has hashed the feed entry -- see
    ingest/run.py for why that ordering matters.
    """
    if not needs_article_fetch(doc.clean_text):
        return False

    fetched = fetch_article_body(feed_url, doc.source_url, **fetch_kwargs)
    if fetched is None:
        return False

    raw_html, clean_text = fetched
    if len(clean_text) < len(doc.clean_text or "") * MIN_IMPROVEMENT_RATIO:
        log.warning(
            "article at %s yielded %d chars vs %d in the feed entry; keeping the feed content",
            doc.source_url,
            len(clean_text),
            len(doc.clean_text or ""),
        )
        return False

    doc.raw_html = raw_html
    doc.clean_text = clean_text
    return True
