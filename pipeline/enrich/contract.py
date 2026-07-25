"""The extraction contract (DESIGN.md §5.1): the single JSON shape the model
is asked to return, mirrored by the DB schema in §4.

`extra="forbid"` is deliberate. A model that invents a field is a model that
has drifted from the contract, and we would rather burn the one retry making
that visible than silently accept a payload we don't understand.
"""

from __future__ import annotations

import re
from datetime import date
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

AttributionConfidence = Literal["suspected", "likely", "confirmed_by_source"]
IocKind = Literal["ipv4", "ipv6", "domain", "url", "sha256", "md5", "email"]

_ISO_3166_ALPHA2 = re.compile(r"^[A-Z]{2}$")


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class ActorMention(_Strict):
    """Free text as the model saw it. Resolution against threat_actor happens
    in Python afterwards (guardrail 4) -- the model is never asked to guess an
    internal ID."""

    name: str = Field(min_length=1, max_length=200)
    attribution_confidence: AttributionConfidence


class TechniqueMention(_Strict):
    technique_id: str = Field(min_length=5, max_length=16)
    evidence_quote: str = Field(min_length=1, max_length=1000)

    @field_validator("technique_id")
    @classmethod
    def _normalize_technique_id(cls, value: str) -> str:
        return value.upper()


class Target(_Strict):
    country: str | None = None  # ISO 3166-1 alpha-2
    sector: str | None = Field(default=None, max_length=100)

    @field_validator("country")
    @classmethod
    def _normalize_country(cls, value: str | None) -> str | None:
        if value is None:
            return None
        normalized = value.strip().upper()
        if not _ISO_3166_ALPHA2.match(normalized):
            raise ValueError(f"country must be an ISO 3166-1 alpha-2 code, got {value!r}")
        return normalized


class Ioc(_Strict):
    """`value` is whatever the model emitted; it is defanged post-hoc and
    unconditionally before storage (DESIGN.md §6, enrich/defang.py)."""

    kind: IocKind
    value: str = Field(min_length=1, max_length=2048)


class Extraction(_Strict):
    summary: str = Field(min_length=1, max_length=600)
    report_date: date | None = None
    confidence: Literal["low", "medium", "high"]
    actors: list[ActorMention] = Field(default_factory=list)
    techniques: list[TechniqueMention] = Field(default_factory=list)
    targets: list[Target] = Field(default_factory=list)
    iocs: list[Ioc] = Field(default_factory=list)
