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
from enrich.client import build_completion_client, get_embedding_client
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
from enrich.chunk import BudgetTooSmall, document_budget_chars
from enrich.extract import extract_document
from enrich.prompt import prompt_version, render_user_prompt, system_prompt
from enrich.techniques import TechniqueIndex
from enrich.validate import validate_extraction
from ingest.db import get_engine

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
log = logging.getLogger("enrich.run")


def _record_attempts(engine, document_id, model, version, outcome):
    """Persist one enrichment_run row per attempt; return the id of an ok run.

    On a chunked document (§5.3) that is one row per chunk per attempt, tagged
    with chunk_index. The returned id is the *first* successful run, which is
    what report.enrichment_run_id points at: the column is a single FK, so a
    merged extraction from five chunks has to name one of them, and the first
    is the only choice that is stable across re-runs.
    """
    ok_run_id = None
    for chunk_index, attempt in outcome.attempts:
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
                chunk_index=chunk_index,
            )
        if attempt.status == "ok" and ok_run_id is None:
            ok_run_id = run_id
    return ok_run_id


def _embed_summary(embedder, summary: str):
    """Return (embedding, model, dim), or three Nones.

    Never blocks a run (§5.4): any failure leaves report.embedding NULL and the
    document is still fully enriched. Embeds the summary, not clean_text --
    2-3 sentences fit any context window, so no chunking (§5.3, deferred).
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
    engine, client, row, *, technique_index, actor_index, version, max_input_tokens,
    embedder=None,
) -> bool:
    document_id = row["id"]
    title = row["title"] or str(document_id)

    outcome = extract_document(
        client,
        system_prompt(),
        render_user_prompt,
        row["clean_text"],
        max_input_tokens=max_input_tokens,
    )
    run_id = _record_attempts(engine, document_id, client.model, version, outcome)

    if outcome.was_chunked:
        # Worth saying out loud: a chunked document is a degraded extraction
        # (§5.3) -- no call saw the whole text, so cross-chunk reasoning and a
        # single coherent summary are both gone.
        log.info("%r exceeded the context budget; extracted in %d chunks", title, outcome.chunk_count)
    for failed in outcome.failed_chunks:
        log.warning(
            "chunk %s of %r produced nothing: %s (%s)",
            failed.index,
            title,
            failed.outcome.final.status,
            (failed.outcome.final.error or "")[:200],
        )

    if outcome.truncated:
        # Not a guardrail branch -- a truncated response fails the JSON parse
        # like any other malformed output. It just has a different fix
        # (raise max_tokens) and is worth naming in the log.
        log.warning("a response for %r was truncated (raise max_tokens)", title)

    if not outcome.succeeded:
        log.warning(
            "extraction failed for %r after %d call(s): %s (%s)",
            title,
            len(outcome.attempts),
            outcome.status,
            (outcome.error or "")[:200],
        )
        return False

    validated = validate_extraction(
        outcome.extraction,
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

    §5.4 "fail at config time, not mid-run": one probe drops a mismatched
    provider now, rather than warning once per document for the whole batch.
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

    # §5.4 "fail at config time, not mid-run": the budget depends only on
    # config and the prompt files, so a value too small to fit any document is
    # knowable now rather than on the first document of a long batch.
    try:
        document_budget_chars(
            completion_config.max_input_tokens,
            prompt_overhead_chars=len(system_prompt()) + len(render_user_prompt("")),
        )
    except BudgetTooSmall as exc:
        raise SystemExit(f"context budget: {exc}") from exc

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
        "provider=%s model=%s embedding=%s prompt_version=%s max_input_tokens=%d "
        "techniques=%d actor_names=%d documents=%d",
        completion_config.provider,
        client.model,
        embedder.model if embedder else "disabled",
        version,
        completion_config.max_input_tokens,
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
                max_input_tokens=completion_config.max_input_tokens,
                embedder=embedder,
            ):
                enriched += 1
        except Exception:
            log.exception("unexpected error enriching document %s", row["id"])

    log.info("done: %d/%d document(s) produced reports", enriched, len(documents))


if __name__ == "__main__":
    main()
