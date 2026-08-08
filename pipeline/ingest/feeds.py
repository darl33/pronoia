"""The real feed sources for the weeks 1-2 ingestion slice (DESIGN.md §3)."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class FeedSeed:
    name: str
    url: str
    kind: str
    poll_interval_minutes: int = 360
    # Follow each entry's link and store the article body instead of the feed
    # teaser (ingest/article.py). Off by default: it is extra outbound traffic
    # and extra SSRF surface, so each feed opts in explicitly.
    fetch_articles: bool = False


FEED_SEEDS: list[FeedSeed] = [
    FeedSeed(
        name="CISA Cybersecurity Advisories",
        url="https://www.cisa.gov/cybersecurity-advisories/all.xml",
        kind="rss",
    ),
    FeedSeed(
        name="ACSC Advisories",
        url="https://www.cyber.gov.au/rss/advisories",
        kind="rss",
        # Publishes a one-line teaser per advisory (85-300 chars); the body
        # lives behind the link on the same host.
        fetch_articles=True,
    ),
    FeedSeed(
        name="Cisco Talos Blog",
        url="https://blog.talosintelligence.com/rss/",
        kind="rss",
        # Already ships the full post in <content:encoded> (~11k chars average),
        # so following links would be 15 pointless requests per poll.
        fetch_articles=False,
    ),
    FeedSeed(
        name="MISP Galaxy: Threat Actor Clusters",
        url="https://raw.githubusercontent.com/MISP/misp-galaxy/main/clusters/threat-actor.json",
        kind="json",
        poll_interval_minutes=10080,  # reference data, weekly is plenty
    ),
]
