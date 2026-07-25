"""Import the MISP galaxy threat-actor cluster into threat_actor
(DESIGN.md §3, §4).

This is the canonical-name + alias table guardrail 4 resolves against, and it
is the reason the actor dimension is queryable at all: one report's "Sandworm
Team" and another's "APT44" have to land on the same row.

`suspected_origin_country` comes from the cluster's `meta.country`. That is
reference data recording what the CTI community reports about an actor -- §4
is explicit that the column holds origin "as *reported*". It is not, and must
not become, a per-report attribution: guardrail 5 keeps the model from
inferring origin, and this column is not consulted when writing report_actor.
"""

from __future__ import annotations

import json
import logging
import uuid

from ingest.fetch import fetch_url

log = logging.getLogger("refdata.misp")

MISP_GALAXY_URL = (
    "https://raw.githubusercontent.com/MISP/misp-galaxy/main/clusters/threat-actor.json"
)


def _valid_country(value) -> str | None:
    if isinstance(value, str) and len(value.strip()) == 2 and value.strip().isalpha():
        return value.strip().upper()
    return None


def _valid_uuid(value):
    try:
        return uuid.UUID(str(value))
    except (ValueError, AttributeError, TypeError):
        return None


def parse_misp_galaxy(body: bytes) -> list[dict]:
    cluster = json.loads(body.decode("utf-8"))

    actors = []
    for entry in cluster.get("values", []):
        canonical_name = (entry.get("value") or "").strip()
        if not canonical_name:
            continue

        meta = entry.get("meta") or {}
        synonyms = meta.get("synonyms") or []
        aliases = sorted(
            {
                alias.strip()
                for alias in synonyms
                if isinstance(alias, str)
                and alias.strip()
                and alias.strip().casefold() != canonical_name.casefold()
            }
        )

        actors.append(
            {
                "canonical_name": canonical_name,
                "aliases": aliases,
                "misp_uuid": _valid_uuid(entry.get("uuid")),
                "suspected_origin_country": _valid_country(meta.get("country")),
            }
        )

    return actors


def fetch_misp_galaxy() -> bytes:
    log.info("fetching MISP galaxy from %s", MISP_GALAXY_URL)
    return fetch_url(MISP_GALAXY_URL).body
