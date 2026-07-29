"""Enrichment entrypoint: for every raw_document without a report, run the
extraction, apply the guardrails, and write the rows that survive.

    uv run python -m enrich.run [--limit N] [--document-id UUID]

Transaction shape: each attempt's enrichment_run row is committed on its own,
before the report is written. A failed or crashed run must still leave its
audit trail (DESIGN.md §5.2 guardrail 1), which it wouldn't if the run rows
shared a transaction with the report insert and rolled back with it.
"""

from __future__ import annotations

import argparse
import json
import logging

from dotenv import load_dotenv

from enrich.actors import ActorIndex
from enrich.client import (
    TRUNCATION_STOP_REASONS,
    build_completion_client,
    get_embedding_client,
)
from enrich.config import REPORT_EMBEDDING_DIM, ConfigError, resolve_completion
from enrich.db import (
    enqueue_actor_for_review,
    insert_enrichment_run,
    insert_ioc,
    insert_report,
    insert_report_actor,
    insert_report_target,
    insert_report_technique,
    list_documents_needing_enrichment,
    load_technique_ids,
    load_threat_actors,
)
from enrich.extract import run_extraction
from enrich.prompt import prompt_version, render_user_prompt, system_prompt
from enrich.techniques import TechniqueIndex
from enrich.validate import validate_extraction
from ingest.db import get_engine

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
log = logging.getLogger("enrich.run")


def _record_attempts(engine, document_id, model, version, outcome):
    """Persist one enrichment_run row per attempt; return the id of the ok run."""
    ok_run_id = None
    for attempt in outcome.attempts:
        with engine.begin() as conn:
            run_id = insert_enrichment_run(
                conn,
                document_id=document_id,
                model=model,
                prompt_version=version,
                started_at=attempt.started_at,
                finished_at=attempt.finished_at,
                status=attempt.status,
                # raw_response is JSONB and the whole point is auditing what the
                # model said -- including when that wasn't valid JSON. Wrap the
                # unparseable case as a JSON string so nothing is lost.
                raw_response=json.dumps(attempt.raw_response) if attempt.raw_response else None,
                attempt=attempt.attempt,
            )
        if attempt.status == "ok":
            ok_run_id = run_id
    return ok_run_id


def _embed_summary(embedder, summary: str):
    """Return (embedding, model, dim), or three Nones.

    Embeddings are optional and must never block a run (DESIGN.md §5.4): every
    failure here degrades to a NULL `report.embedding` and the document is
    still enriched, its actors, techniques, targets and IOCs all written.
    Semantic search is the only thing that suffers, and it is already the top
    cut line (§10).

    What gets embedded is the model's own summary, not `clean_text`. The
    summary is 2-3 sentences, so it fits any embedding context window and needs
    no chunking; embedding full report text would require the chunk-and-merge
    path §5.3 defers to the second backend.
    """
    if embedder is None:
        return None, None, None

    try:
        vector = embedder.embed([summary])[0]
    except Exception:
        log.warning("embedding failed; leaving report.embedding NULL", exc_info=True)
        return None, None, None

    if len(vector) != REPORT_EMBEDDING_DIM:
        log.warning(
            "embedding model %s returned %d dimensions but report.embedding is "
            "VECTOR(%d); leaving it NULL",
            embedder.model,
            len(vector),
            REPORT_EMBEDDING_DIM,
        )
        return None, None, None

    return vector, embedder.model, len(vector)


def _persist(engine, *, document_id, run_id, validated, embedder):
    extraction = validated.extraction
    embedding, embedding_model, embedding_dim = _embed_summary(embedder, extraction.summary)

    with engine.begin() as conn:
        report_id = insert_report(
            conn,
            document_id=document_id,
            enrichment_run_id=run_id,
            summary=extraction.summary,
            report_date=extraction.report_date,
            confidence=extraction.confidence,
            embedding=embedding,
            embedding_model=embedding_model,
            embedding_dim=embedding_dim,
        )

        for actor in validated.actors:
            insert_report_actor(
                conn,
                report_id=report_id,
                actor_id=actor.actor_id,
                attribution_confidence=actor.attribution_confidence,
            )

        for unresolved in validated.review_queue:
            enqueue_actor_for_review(
                conn,
                report_id=report_id,
                raw_name=unresolved.raw_name,
                attribution_confidence=unresolved.attribution_confidence,
                best_match_actor_id=unresolved.resolution.best_match_actor_id,
                best_match_score=unresolved.resolution.best_match_score,
            )

        for technique in validated.techniques:
            insert_report_technique(
                conn,
                report_id=report_id,
                technique_id=technique.technique_id,
                evidence_quote=technique.evidence_quote,
            )

        for target in extraction.targets:
            if target.country is None and target.sector is None:
                continue
            insert_report_target(
                conn, report_id=report_id, country=target.country, sector=target.sector
            )

        for indicator in validated.iocs:
            insert_ioc(
                conn,
                report_id=report_id,
                kind=indicator.kind,
                value_defanged=indicator.value_defanged,
            )

    return report_id


def enrich_document(
    engine, client, row, *, technique_index, actor_index, version, embedder=None
) -> bool:
    document_id = row["id"]
    title = row["title"] or str(document_id)

    outcome = run_extraction(
        client, system_prompt(), render_user_prompt(row["clean_text"])
    )
    run_id = _record_attempts(engine, document_id, client.model, version, outcome)

    if outcome.final.stop_reason in TRUNCATION_STOP_REASONS:
        # Not a guardrail branch -- a truncated response fails the JSON parse
        # like any other malformed output. It just has a different fix
        # (raise max_tokens) and is worth naming in the log.
        log.warning("response for %r was truncated (stop_reason=%s)", title, outcome.final.stop_reason)

    if not outcome.succeeded:
        log.warning(
            "extraction failed for %r after %d attempt(s): %s (%s)",
            title,
            len(outcome.attempts),
            outcome.final.status,
            (outcome.final.error or "")[:200],
        )
        return False

    validated = validate_extraction(
        outcome.final.extraction,
        clean_text=row["clean_text"],
        technique_index=technique_index,
        actor_index=actor_index,
    )

    for drop in validated.drops:
        log.info("dropped [%s] %s -- %s", drop.guardrail, drop.value, drop.reason)

    _persist(
        engine,
        document_id=document_id,
        run_id=run_id,
        validated=validated,
        embedder=embedder,
    )
    log.info(
        "enriched %r: %d actor(s), %d technique(s), %d target(s), %d ioc(s), "
        "%d review-queue, %d drop(s)",
        title,
        len(validated.actors),
        len(validated.techniques),
        len(validated.extraction.targets),
        len(validated.iocs),
        len(validated.review_queue),
        len(validated.drops),
    )
    return True


def _resolve_embedder(completion_config):
    """Resolve slot 2 and check its width once, at startup.

    Checking the dimension here rather than per-document is the §5.4 "fail at
    config time, not mid-run" rule applied to the one thing that *can* be
    checked cheaply: one probe call tells us whether the vectors will fit
    VECTOR(1024), and a provider that can't is dropped now instead of logging a
    warning once per document for the whole batch.
    """
    embedder = get_embedding_client(completion_config)
    if embedder is None:
        log.info("no embedding provider resolved; reports will have a NULL embedding (§5.4)")
        return None

    try:
        dimension = embedder.dimension
    except Exception:
        log.warning(
            "embedding provider %s did not answer; continuing without embeddings",
            embedder.model,
            exc_info=True,
        )
        return None

    if dimension != REPORT_EMBEDDING_DIM:
        log.warning(
            "embedding model %s produces %d dimensions but report.embedding is "
            "VECTOR(%d); continuing without embeddings. See the README section "
            "'Changing the embedding model'.",
            embedder.model,
            dimension,
            REPORT_EMBEDDING_DIM,
        )
        return None

    return embedder


def main() -> None:
    parser = argparse.ArgumentParser(description="Run LLM enrichment over un-enriched documents.")
    parser.add_argument("--limit", type=int, default=None, help="max documents to process")
    args = parser.parse_args()

    load_dotenv()
    engine = get_engine()

    try:
        completion_config = resolve_completion()
    except ConfigError as exc:
        # The message names the variable that fixes it (§5.4). Raising it as a
        # SystemExit rather than a traceback keeps that message the last thing
        # the reader sees.
        raise SystemExit(f"LLM config: {exc}\n\nRun `pronoia doctor` for the full picture.") from exc

    client = build_completion_client(completion_config)
    embedder = _resolve_embedder(completion_config)
    version = prompt_version()

    with engine.begin() as conn:
        technique_index = TechniqueIndex(load_technique_ids(conn))
        actor_index = ActorIndex(load_threat_actors(conn))
        documents = list_documents_needing_enrichment(conn, limit=args.limit)

    if not len(technique_index) or not len(actor_index):
        raise SystemExit(
            "reference data is empty -- run `uv run python -m refdata.run` first "
            "(the closed-world and actor guardrails have nothing to validate against)"
        )

    log.info(
        "provider=%s model=%s embedding=%s prompt_version=%s techniques=%d "
        "actor_names=%d documents=%d",
        completion_config.provider,
        client.model,
        embedder.model if embedder else "disabled",
        version,
        len(technique_index),
        len(actor_index),
        len(documents),
    )

    enriched = 0
    for row in documents:
        try:
            if enrich_document(
                engine,
                client,
                row,
                technique_index=technique_index,
                actor_index=actor_index,
                version=version,
                embedder=embedder,
            ):
                enriched += 1
        except Exception:
            log.exception("unexpected error enriching document %s", row["id"])

    log.info("done: %d/%d document(s) produced reports", enriched, len(documents))


if __name__ == "__main__":
    main()
