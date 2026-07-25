"""Reference-data loader entrypoint. Idempotent; safe to re-run to refresh.

    uv run python -m refdata.run
"""

from __future__ import annotations

import logging

from dotenv import load_dotenv

from enrich.db import upsert_attack_technique, upsert_threat_actor
from ingest.db import get_engine
from refdata.attack import fetch_attack_bundle, parse_attack_bundle
from refdata.misp import fetch_misp_galaxy, parse_misp_galaxy

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
log = logging.getLogger("refdata.run")


def load_attack(engine) -> int:
    techniques = parse_attack_bundle(fetch_attack_bundle())
    with engine.begin() as conn:
        for technique in techniques:
            upsert_attack_technique(conn, **technique)
    log.info("loaded %d ATT&CK techniques", len(techniques))
    return len(techniques)


def load_misp(engine) -> int:
    actors = parse_misp_galaxy(fetch_misp_galaxy())
    with engine.begin() as conn:
        for actor in actors:
            upsert_threat_actor(conn, **actor)
    alias_count = sum(len(actor["aliases"]) for actor in actors)
    log.info("loaded %d threat actors with %d aliases", len(actors), alias_count)
    return len(actors)


def main() -> None:
    load_dotenv()
    engine = get_engine()
    load_attack(engine)
    load_misp(engine)


if __name__ == "__main__":
    main()
