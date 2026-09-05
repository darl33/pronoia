"""The gold-set fixture schema and loader (DESIGN.md §7).

A fixture is a .json annotation plus the .txt document it annotates. Validation
is deliberately loud: annotations the pipeline's own vocabulary cannot express
are reported as gold-set defects, not absorbed into the score.

Rationale: docs/DECISIONS.md#gold-set
Annotation format: eval/gold/README.md
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from eval.vocab import is_in_vocabulary, normalize_sector

GOLD_DIR = Path(__file__).parent / "gold"

SourceKind = Literal["cisa", "acsc", "vendor_blog", "synthetic"]
AttributionConfidence = Literal["suspected", "likely", "confirmed_by_source"]


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class GoldActor(_Strict):
    """`name` should be the MISP canonical name, but an alias also resolves --
    the loader pushes both through ActorIndex, the same resolution the pipeline
    applies to model output, so the two sides are compared as the same entity.

    `attribution_confidence` is recorded for completeness and is *not* scored:
    §7 lists precision/recall over actors, techniques and targets, and adding
    an unrequested field to the headline metric would make the numbers harder
    to compare against the target, not easier.
    """

    name: str = Field(min_length=1, max_length=200)
    attribution_confidence: AttributionConfidence | None = None


class GoldTechnique(_Strict):
    technique_id: str = Field(min_length=5, max_length=16)
    # True = the ID (or its exact ATT&CK name) is written in the document, so a
    # regex can find it. The false ones are where §7's lift is measured.
    explicit_in_text: bool
    note: str | None = Field(default=None, max_length=500)

    @field_validator("technique_id")
    @classmethod
    def _normalize(cls, value: str) -> str:
        return value.upper()


class GoldTarget(_Strict):
    country: str | None = None  # ISO 3166-1 alpha-2
    sector: str | None = None   # eval/vocab.py SECTORS

    @field_validator("country")
    @classmethod
    def _normalize_country(cls, value: str | None) -> str | None:
        return value.strip().upper() if value else None

    @model_validator(mode="after")
    def _at_least_one(self) -> "GoldTarget":
        if self.country is None and self.sector is None:
            raise ValueError("a target needs a country, a sector, or both")
        return self


class GoldAnnotation(_Strict):
    actors: list[GoldActor] = Field(default_factory=list)
    techniques: list[GoldTechnique] = Field(default_factory=list)
    targets: list[GoldTarget] = Field(default_factory=list)


class GoldDocument(_Strict):
    text_file: str
    title: str
    source_url: str | None = None
    source_kind: SourceKind
    published_on: date | None = None


class GoldFixture(_Strict):
    """One annotated document.

    `status` exists because an empty annotation is ambiguous: it means either
    "this document genuinely contains no actors" (a real and valuable negative
    case) or "nobody has annotated this yet". Scoring the second as the first
    would report a fabricated recall of 1.0 on an empty gold set. Placeholders
    are excluded from every run and counted in the scorecard instead.
    """

    id: str = Field(min_length=1, max_length=100)
    status: Literal["annotated", "placeholder"]
    document: GoldDocument
    annotation: GoldAnnotation
    annotated_by: str | None = None
    annotated_on: date | None = None
    notes: str | None = None

    # Filled by the loader from document.text_file.
    text: str = ""

    @property
    def is_annotated(self) -> bool:
        return self.status == "annotated"

    # ---- the gold side of each scored field, in the scorer's vocabulary ----

    def technique_ids(self) -> set[str]:
        return {technique.technique_id for technique in self.annotation.techniques}

    def implicit_technique_ids(self) -> set[str]:
        return {t.technique_id for t in self.annotation.techniques if not t.explicit_in_text}

    def countries(self) -> set[str]:
        return {t.country for t in self.annotation.targets if t.country}

    def sectors(self) -> set[str]:
        return {normalize_sector(t.sector) for t in self.annotation.targets if t.sector}


@dataclass
class GoldSet:
    fixtures: list[GoldFixture] = field(default_factory=list)
    placeholders: list[GoldFixture] = field(default_factory=list)
    # Gold-set defects, not model failures; surfaced separately in the scorecard.
    defects: list[str] = field(default_factory=list)

    def __len__(self) -> int:
        return len(self.fixtures)


def load_fixture(path: Path) -> GoldFixture:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if "text" in payload:
        raise ValueError(
            f"{path.name}: document text belongs in the sibling .txt file named by "
            "document.text_file, not inline"
        )
    fixture = GoldFixture.model_validate(payload)

    text_path = path.parent / fixture.document.text_file
    if not text_path.is_file():
        raise FileNotFoundError(f"{path.name} references {fixture.document.text_file}, which is missing")

    # model_copy, not mutation: every other field came from the file.
    return fixture.model_copy(update={"text": text_path.read_text(encoding="utf-8")})


def _check_annotation(fixture: GoldFixture, *, technique_index=None, actor_index=None) -> list[str]:
    """Cross-check one annotation against the pipeline's own reference data."""
    defects: list[str] = []

    if not fixture.text.strip():
        defects.append(f"{fixture.id}: {fixture.document.text_file} is empty")

    for technique in fixture.annotation.techniques:
        if technique_index is None:
            continue
        check = technique_index.check(technique.technique_id)
        if not check.ok:
            # Unscoreable: the pipeline can never produce it, so it would be a
            # guaranteed false negative measuring the annotation, not the model.
            defects.append(
                f"{fixture.id}: gold technique {technique.technique_id} {check.reason}"
            )

    for actor in fixture.annotation.actors:
        if actor_index is None:
            continue
        if not actor_index.resolve(actor.name).resolved:
            defects.append(
                f"{fixture.id}: gold actor {actor.name!r} does not resolve against "
                "threat_actor -- use the MISP canonical name or a known alias"
            )

    for target in fixture.annotation.targets:
        if target.country and (len(target.country) != 2 or not target.country.isalpha()):
            defects.append(
                f"{fixture.id}: gold country {target.country!r} is not an ISO 3166-1 alpha-2 code"
            )
        if target.sector:
            normalized = normalize_sector(target.sector)
            if not is_in_vocabulary(normalized):
                defects.append(
                    f"{fixture.id}: gold sector {target.sector!r} is outside the controlled "
                    "vocabulary (eval/vocab.py SECTORS)"
                )

    return defects


def load_gold_set(
    directory: Path = GOLD_DIR, *, technique_index=None, actor_index=None
) -> GoldSet:
    """Load and validate every fixture in `directory`.

    The indexes are optional so the gold set can be linted without a database,
    but passing them is what makes the check meaningful -- without them the
    loader can only verify shape, not that the annotation is expressible in
    the vocabulary the pipeline actually has.
    """
    gold_set = GoldSet()
    seen_ids: dict[str, str] = {}

    for path in sorted(directory.glob("*.json")):
        fixture = load_fixture(path)

        if fixture.id in seen_ids:
            raise ValueError(f"{path.name}: duplicate fixture id {fixture.id!r} (also in {seen_ids[fixture.id]})")
        seen_ids[fixture.id] = path.name

        if not fixture.is_annotated:
            gold_set.placeholders.append(fixture)
            continue

        gold_set.defects.extend(
            _check_annotation(fixture, technique_index=technique_index, actor_index=actor_index)
        )
        gold_set.fixtures.append(fixture)

    return gold_set
