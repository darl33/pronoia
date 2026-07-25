"""Import the MITRE ATT&CK enterprise STIX bundle into attack_technique
(DESIGN.md §3, §4).

This table is the closed world guardrail 2 validates against, so what it
contains is a security-relevant decision, not just a data load:

  * revoked and deprecated techniques are skipped. Keeping them would let the
    model cite retired IDs and have them pass the closed-world check.
  * only `attack-pattern` objects carrying an ATT&CK `external_id` are used;
    the bundle also contains groups, software, mitigations, and relationships.
"""

from __future__ import annotations

import json
import logging

from ingest.fetch import fetch_url

log = logging.getLogger("refdata.attack")

ATTACK_STIX_URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/"
    "master/enterprise-attack/enterprise-attack.json"
)

# The 10 MB transport cap in ingest.fetch is a decompression-bomb defense for
# untrusted feed content (DESIGN.md §6). This is a pinned, known-good reference
# bundle from a fixed URL that is legitimately ~55 MB, so the cap is raised for
# this one call rather than weakened globally.
ATTACK_BUNDLE_MAX_BYTES = 96 * 1024 * 1024


def parse_attack_bundle(body: bytes) -> list[dict]:
    bundle = json.loads(body.decode("utf-8"))

    techniques = []
    for obj in bundle.get("objects", []):
        if obj.get("type") != "attack-pattern":
            continue
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue

        technique_id = next(
            (
                ref.get("external_id")
                for ref in obj.get("external_references", [])
                if ref.get("source_name") == "mitre-attack" and ref.get("external_id")
            ),
            None,
        )
        if not technique_id:
            continue

        tactics = [
            phase["phase_name"]
            for phase in obj.get("kill_chain_phases", [])
            if phase.get("kill_chain_name") == "mitre-attack" and phase.get("phase_name")
        ]
        if not tactics:
            continue

        techniques.append(
            {
                "technique_id": technique_id,
                "name": obj.get("name") or technique_id,
                # §4 models `tactic` as a single TEXT column, but ATT&CK
                # techniques are genuinely many-to-many with tactics (T1055 is
                # both defense-evasion and privilege-escalation). Joining
                # preserves the data; dropping to one would silently lose it.
                # Flagged as a schema question for §12 -- a report_technique
                # tactic join table would be the real fix.
                "tactic": ",".join(sorted(set(tactics))),
            }
        )

    return techniques


def fetch_attack_bundle() -> bytes:
    log.info("fetching ATT&CK STIX bundle from %s", ATTACK_STIX_URL)
    result = fetch_url(ATTACK_STIX_URL, max_bytes=ATTACK_BUNDLE_MAX_BYTES)
    return result.body
