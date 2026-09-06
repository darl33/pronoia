"""The real feed sources for the weeks 1-2 ingestion slice (DESIGN.md §3)."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class FeedSeed:
    name: str
    url: str
    kind: str
    poll_interval_minutes: int = 360
    # Follow each entry's link for the article body (ingest/article.py). Off by
    # default -- extra traffic and extra SSRF surface, so feeds opt in.
    fetch_articles: bool = False


FEED_SEEDS: list[FeedSeed] = [
    FeedSeed(
        name="CISA Cybersecurity Advisories",
        url="https://www.cisa.gov/cybersecurity-advisories/all.xml",
        kind="rss",
    ),
    FeedSeed(
        name="CISA Cybersecurity Advisories (AA series)",
        url="https://www.cisa.gov/cybersecurity-advisories/cybersecurity-advisories.xml",
        kind="rss",
        # The AA-numbered joint advisories: named actors, ATT&CK tables, real
        # bodies. all.xml above is dominated by ICS/product advisories and
        # crowds these out entirely. docs/DECISIONS.md#cisa-advisory-types
    ),
    FeedSeed(
        name="ACSC Advisories",
        url="https://www.cyber.gov.au/rss/advisories",
        kind="rss",
        # One-line teasers (85-300 chars); the body is behind the link.
        fetch_articles=True,
    ),
    FeedSeed(
        name="Cisco Talos Blog",
        url="https://blog.talosintelligence.com/rss/",
        kind="rss",
        # Already ships the full post in <content:encoded> (~11k chars).
        fetch_articles=False,
    ),
]

# The MISP galaxy is deliberately NOT a feed: refdata/misp.py loads it from its
# own URL. As a feed it lands in raw_document and gets sent to the model as if
# it were a threat report. See docs/DECISIONS.md#reference-data-is-not-a-feed
