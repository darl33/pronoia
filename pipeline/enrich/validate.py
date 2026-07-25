"""Applies guardrails 2, 3, 4 and the §6 IOC rule to a schema-valid Extraction,
producing the rows that are actually allowed to be written.

Nothing here trusts the model. An Extraction that passed guardrail 1 is
well-formed, not correct: it can still name techniques that don't exist, quote
text that isn't in the document, name actors we've never heard of, and label a
URL as a hash. This module is where each of those becomes a drop with a reason
rather than a row.

Drops are returned, not just logged, so the caller can report them and so §7's
eval harness can measure them per (model, prompt_version).
"""

from __future__ import annotations

from dataclasses import dataclass, field

from enrich.actors import ActorIndex, ActorResolution
from enrich.contract import Extraction
from enrich.defang import defang_ioc
from enrich.evidence import EvidenceIndex
from enrich.techniques import TechniqueIndex


@dataclass(frozen=True)
class Drop:
    guardrail: str
    value: str
    reason: str


@dataclass
class ResolvedActor:
    actor_id: object
    raw_name: str
    attribution_confidence: str


@dataclass
class UnresolvedActor:
    raw_name: str
    attribution_confidence: str
    resolution: ActorResolution


@dataclass
class ValidatedTechnique:
    technique_id: str
    evidence_quote: str


@dataclass
class ValidatedIoc:
    kind: str
    value_defanged: str


@dataclass
class ValidatedExtraction:
    extraction: Extraction
    actors: list[ResolvedActor] = field(default_factory=list)
    review_queue: list[UnresolvedActor] = field(default_factory=list)
    techniques: list[ValidatedTechnique] = field(default_factory=list)
    iocs: list[ValidatedIoc] = field(default_factory=list)
    drops: list[Drop] = field(default_factory=list)


def validate_extraction(
    extraction: Extraction,
    *,
    clean_text: str,
    technique_index: TechniqueIndex,
    actor_index: ActorIndex,
) -> ValidatedExtraction:
    result = ValidatedExtraction(extraction=extraction)
    evidence_index = EvidenceIndex(clean_text)

    # Guardrails 2 and 3: a technique mention must name a real ATT&CK ID *and*
    # carry a quote that is actually in the document. Both must hold.
    seen_techniques: set[str] = set()
    for mention in extraction.techniques:
        technique_id = mention.technique_id

        closed_world = technique_index.check(technique_id)
        if not closed_world.ok:
            result.drops.append(Drop("closed_world_technique", technique_id, closed_world.reason))
            continue

        evidence = evidence_index.check(mention.evidence_quote)
        if not evidence.ok:
            result.drops.append(
                Drop("evidence_quote", f"{technique_id}: {mention.evidence_quote!r}", evidence.reason)
            )
            continue

        # report_technique is keyed (report_id, technique_id); keep the first
        # surviving quote rather than letting a later duplicate overwrite it.
        if technique_id in seen_techniques:
            continue
        seen_techniques.add(technique_id)

        result.techniques.append(
            ValidatedTechnique(technique_id=technique_id, evidence_quote=mention.evidence_quote)
        )

    # Guardrail 4: resolve or queue for review. Never invent an actor.
    seen_actor_ids: set[object] = set()
    for mention in extraction.actors:
        resolution = actor_index.resolve(mention.name)
        if not resolution.resolved:
            result.review_queue.append(
                UnresolvedActor(
                    raw_name=mention.name,
                    attribution_confidence=mention.attribution_confidence,
                    resolution=resolution,
                )
            )
            result.drops.append(
                Drop(
                    "actor_resolution",
                    mention.name,
                    "unresolved; routed to actor_review_queue",
                )
            )
            continue

        if resolution.actor_id in seen_actor_ids:
            continue
        seen_actor_ids.add(resolution.actor_id)

        result.actors.append(
            ResolvedActor(
                actor_id=resolution.actor_id,
                raw_name=mention.name,
                attribution_confidence=mention.attribution_confidence,
            )
        )

    # §6: defang unconditionally, and drop anything whose value disagrees with
    # its claimed kind -- a mislabelled IOC is a defanging bypass.
    for mention in extraction.iocs:
        defanged = defang_ioc(mention.kind, mention.value)
        if not defanged.ok:
            # The raw value is deliberately not in the drop record: it may be a
            # live indicator, and drops get logged.
            result.drops.append(Drop("ioc_defang", f"<{mention.kind}>", defanged.reason))
            continue
        result.iocs.append(
            ValidatedIoc(kind=mention.kind, value_defanged=defanged.value_defanged)
        )

    return result
