"""SQLAlchemy Core table definitions for the enrichment layer, mirroring
db/migrations/20260725000001_enrichment_layer.sql exactly, plus bound-parameter-
only helpers (DESIGN.md §6: "SQLAlchemy bound parameters (Python); no
string-built SQL anywhere").

Shares ingest.db's MetaData so raw_document is resolvable for the foreign keys
and joins here; the schema itself is still owned by db/migrations.
"""

from __future__ import annotations

from sqlalchemy import (
    ARRAY,
    Boolean,
    Column,
    Date,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    Table,
    Text,
    select,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.dialects.postgresql import insert as pg_insert
from uuid6 import uuid7

from ingest.db import metadata, raw_document

threat_actor = Table(
    "threat_actor",
    metadata,
    Column("id", UUID(as_uuid=True), primary_key=True),
    Column("canonical_name", Text, nullable=False, unique=True),
    Column("aliases", ARRAY(Text), nullable=False),
    Column("suspected_origin_country", Text),
    Column("misp_uuid", UUID(as_uuid=True)),
)

attack_technique = Table(
    "attack_technique",
    metadata,
    Column("technique_id", Text, primary_key=True),
    Column("name", Text, nullable=False),
    Column("tactic", Text, nullable=False),
)

enrichment_run = Table(
    "enrichment_run",
    metadata,
    Column("id", UUID(as_uuid=True), primary_key=True),
    Column("document_id", UUID(as_uuid=True), ForeignKey("raw_document.id"), nullable=False),
    Column("model", Text, nullable=False),
    Column("prompt_version", Text, nullable=False),
    Column("started_at", DateTime(timezone=True), nullable=False),
    Column("finished_at", DateTime(timezone=True)),
    Column("status", Text, nullable=False),
    Column("raw_response", JSONB),
    Column("attempt", Integer, nullable=False),
)

# `embedding VECTOR(1024)` is intentionally absent: pgvector's type has no
# SQLAlchemy Core mapping here and nothing in this milestone writes it. The
# column exists in the migration; leaving it out of the Table just means this
# module can't touch it.
report = Table(
    "report",
    metadata,
    Column("id", UUID(as_uuid=True), primary_key=True),
    Column("document_id", UUID(as_uuid=True), ForeignKey("raw_document.id"), nullable=False, unique=True),
    Column("enrichment_run_id", UUID(as_uuid=True), ForeignKey("enrichment_run.id"), nullable=False),
    Column("summary", Text, nullable=False),
    Column("report_date", Date),
    Column("confidence", Text, nullable=False),
)

report_actor = Table(
    "report_actor",
    metadata,
    Column("report_id", UUID(as_uuid=True), ForeignKey("report.id"), primary_key=True),
    Column("actor_id", UUID(as_uuid=True), ForeignKey("threat_actor.id"), primary_key=True),
    Column("attribution_confidence", Text, nullable=False),
)

report_technique = Table(
    "report_technique",
    metadata,
    Column("report_id", UUID(as_uuid=True), ForeignKey("report.id"), primary_key=True),
    Column("technique_id", Text, ForeignKey("attack_technique.technique_id"), primary_key=True),
    Column("evidence_quote", Text),
)

report_target = Table(
    "report_target",
    metadata,
    Column("id", UUID(as_uuid=True), primary_key=True),
    Column("report_id", UUID(as_uuid=True), ForeignKey("report.id"), nullable=False),
    Column("country", Text),
    Column("sector", Text),
)

ioc = Table(
    "ioc",
    metadata,
    Column("id", UUID(as_uuid=True), primary_key=True),
    Column("report_id", UUID(as_uuid=True), ForeignKey("report.id"), nullable=False),
    Column("kind", Text, nullable=False),
    Column("value_defanged", Text, nullable=False),
)

actor_review_queue = Table(
    "actor_review_queue",
    metadata,
    Column("id", UUID(as_uuid=True), primary_key=True),
    Column("report_id", UUID(as_uuid=True), ForeignKey("report.id"), nullable=False),
    Column("raw_name", Text, nullable=False),
    Column("attribution_confidence", Text, nullable=False),
    Column("best_match_actor_id", UUID(as_uuid=True), ForeignKey("threat_actor.id")),
    Column("best_match_score", Float),
    Column("created_at", DateTime(timezone=True)),
    Column("resolved", Boolean),
)


# ---------- reference data ----------


def load_technique_ids(conn) -> set[str]:
    rows = conn.execute(select(attack_technique.c.technique_id)).scalars().all()
    return set(rows)


def load_threat_actors(conn):
    return conn.execute(
        select(threat_actor.c.id, threat_actor.c.canonical_name, threat_actor.c.aliases)
    ).mappings().all()


def upsert_attack_technique(conn, *, technique_id: str, name: str, tactic: str) -> None:
    stmt = pg_insert(attack_technique).values(
        technique_id=technique_id, name=name, tactic=tactic
    )
    conn.execute(
        stmt.on_conflict_do_update(
            index_elements=[attack_technique.c.technique_id],
            set_={"name": stmt.excluded.name, "tactic": stmt.excluded.tactic},
        )
    )


def upsert_threat_actor(
    conn, *, canonical_name: str, aliases: list[str], misp_uuid, suspected_origin_country
) -> None:
    stmt = pg_insert(threat_actor).values(
        id=uuid7(),
        canonical_name=canonical_name,
        aliases=aliases,
        misp_uuid=misp_uuid,
        suspected_origin_country=suspected_origin_country,
    )
    conn.execute(
        stmt.on_conflict_do_update(
            index_elements=[threat_actor.c.canonical_name],
            set_={
                "aliases": stmt.excluded.aliases,
                "misp_uuid": stmt.excluded.misp_uuid,
                "suspected_origin_country": stmt.excluded.suspected_origin_country,
            },
        )
    )


# ---------- enrichment ----------


def list_documents_needing_enrichment(conn, limit: int | None = None):
    """Documents with clean_text and no report yet."""
    stmt = (
        select(raw_document.c.id, raw_document.c.title, raw_document.c.clean_text)
        .outerjoin(report, report.c.document_id == raw_document.c.id)
        .where(report.c.id.is_(None))
        .where(raw_document.c.clean_text.isnot(None))
        .order_by(raw_document.c.fetched_at)
    )
    if limit is not None:
        stmt = stmt.limit(limit)
    return conn.execute(stmt).mappings().all()


def insert_enrichment_run(
    conn, *, document_id, model, prompt_version, started_at, finished_at, status,
    raw_response, attempt,
):
    """One row per attempt -- a failed attempt stays in the table as the audit
    trail (DESIGN.md §5.2 guardrail 1: "Two failures = give up, keep the audit
    trail")."""
    run_id = uuid7()
    conn.execute(
        enrichment_run.insert().values(
            id=run_id,
            document_id=document_id,
            model=model,
            prompt_version=prompt_version,
            started_at=started_at,
            finished_at=finished_at,
            status=status,
            raw_response=raw_response,
            attempt=attempt,
        )
    )
    return run_id


def insert_report(conn, *, document_id, enrichment_run_id, summary, report_date, confidence):
    report_id = uuid7()
    conn.execute(
        report.insert().values(
            id=report_id,
            document_id=document_id,
            enrichment_run_id=enrichment_run_id,
            summary=summary,
            report_date=report_date,
            confidence=confidence,
        )
    )
    return report_id


def insert_report_actor(conn, *, report_id, actor_id, attribution_confidence) -> None:
    conn.execute(
        pg_insert(report_actor)
        .values(
            report_id=report_id,
            actor_id=actor_id,
            attribution_confidence=attribution_confidence,
        )
        .on_conflict_do_nothing(index_elements=[report_actor.c.report_id, report_actor.c.actor_id])
    )


def insert_report_technique(conn, *, report_id, technique_id, evidence_quote) -> None:
    conn.execute(
        pg_insert(report_technique)
        .values(report_id=report_id, technique_id=technique_id, evidence_quote=evidence_quote)
        .on_conflict_do_nothing(
            index_elements=[report_technique.c.report_id, report_technique.c.technique_id]
        )
    )


def insert_report_target(conn, *, report_id, country, sector) -> None:
    conn.execute(
        report_target.insert().values(
            id=uuid7(), report_id=report_id, country=country, sector=sector
        )
    )


def insert_ioc(conn, *, report_id, kind, value_defanged) -> None:
    conn.execute(
        pg_insert(ioc)
        .values(id=uuid7(), report_id=report_id, kind=kind, value_defanged=value_defanged)
        .on_conflict_do_nothing(
            index_elements=[ioc.c.report_id, ioc.c.kind, ioc.c.value_defanged]
        )
    )


def enqueue_actor_for_review(
    conn, *, report_id, raw_name, attribution_confidence, best_match_actor_id, best_match_score
) -> None:
    conn.execute(
        pg_insert(actor_review_queue)
        .values(
            id=uuid7(),
            report_id=report_id,
            raw_name=raw_name,
            attribution_confidence=attribution_confidence,
            best_match_actor_id=best_match_actor_id,
            best_match_score=best_match_score,
        )
        .on_conflict_do_nothing(
            index_elements=[actor_review_queue.c.report_id, actor_review_queue.c.raw_name]
        )
    )
