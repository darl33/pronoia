"""The real feed sources for the weeks 1-2 ingestion slice (DESIGN.md §3)."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class FeedSeed:
    name: str
    url: str
    kind: str
    poll_interval_minutes: int = 360


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
    ),
    FeedSeed(
        name="Cisco Talos Blog",
        url="https://blog.talosintelligence.com/rss/",
        kind="rss",
    ),
    FeedSeed(
        name="MISP Galaxy: Threat Actor Clusters",
        url="https://raw.githubusercontent.com/MISP/misp-galaxy/main/clusters/threat-actor.json",
        kind="json",
        poll_interval_minutes=10080,  # reference data, weekly is plenty
    ),
]
