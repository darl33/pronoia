"""`pronoia doctor` (DESIGN.md §5.4): resolve config, one cheap round-trip per
endpoint, print what is enabled, what is degraded, and the env var for each gap.

Prevents discovering a bad key three hours into a batch run, and makes §5.4's
claim checkable rather than asserted.

Round-trips are free or near-free -- count_tokens, GET /v1/models, one short
embed. A diagnostic that costs money is one people stop running.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass

from enrich.client import (
    EnrichmentError,
    build_completion_client,
    build_embedding_client,
)
from enrich.config import (
    REPORT_EMBEDDING_DIM,
    ConfigError,
    resolve_completion,
    resolve_embedding,
)

OK = "ok"
DEGRADED = "degraded"
ERROR = "error"


@dataclass
class Check:
    component: str
    status: str
    detail: str
    fix: str = ""


def _check_database() -> tuple[Check, object | None]:
    url = os.environ.get("PIPELINE_DATABASE_URL", "").strip()
    if not url:
        return Check("database", ERROR, "not configured", "set PIPELINE_DATABASE_URL"), None

    try:
        from sqlalchemy import text

        from ingest.db import get_engine

        engine = get_engine()
        with engine.begin() as conn:
            conn.execute(text("SELECT 1"))
    except Exception as exc:
        return Check("database", ERROR, f"unreachable: {_short(exc)}", "check PIPELINE_DATABASE_URL"), None

    return Check("database", OK, "connected"), engine


def _check_schema(engine) -> list[Check]:
    """REPORT_EMBEDDING_DIM must equal the migration's VECTOR(n).

    Nothing makes them agree automatically, and drift fails every embedding
    write at INSERT time -- exactly the mid-run discovery §5.4 prevents.
    """
    if engine is None:
        return []

    from sqlalchemy import text

    try:
        with engine.begin() as conn:
            # pgvector stores a vector's declared dimension directly in
            # atttypmod; there is no information_schema equivalent.
            column_dim = conn.execute(
                text(
                    "SELECT atttypmod FROM pg_attribute "
                    "WHERE attrelid = 'report'::regclass AND attname = 'embedding'"
                )
            ).scalar()
    except Exception as exc:
        return [Check("schema", ERROR, f"could not read report.embedding: {_short(exc)}", "apply db/migrations")]

    if column_dim == REPORT_EMBEDDING_DIM:
        return [Check("schema", OK, f"report.embedding is VECTOR({column_dim})")]
    return [
        Check(
            "schema",
            ERROR,
            f"report.embedding is VECTOR({column_dim}) but REPORT_EMBEDDING_DIM is {REPORT_EMBEDDING_DIM}",
            "make enrich/config.py and db/migrations agree -- see README "
            "'Changing the embedding model'",
        )
    ]


def _check_reference_data(engine) -> list[Check]:
    """Empty reference tables mean the §5.2 closed-world and actor guardrails
    have nothing to validate against, and enrich.run refuses to start."""
    if engine is None:
        return []

    from enrich.db import count_reports, embedding_model_counts, load_technique_ids, load_threat_actors

    try:
        with engine.begin() as conn:
            techniques = len(load_technique_ids(conn))
            actors = len(load_threat_actors(conn))
            reports = count_reports(conn)
            vintages = embedding_model_counts(conn)
    except Exception as exc:
        return [Check("reference data", ERROR, f"query failed: {_short(exc)}", "apply db/migrations")]

    checks = []
    if techniques and actors:
        checks.append(Check("reference data", OK, f"{techniques} techniques, {actors} actor names"))
    else:
        checks.append(
            Check(
                "reference data",
                ERROR,
                f"{techniques} techniques, {actors} actor names",
                "run `uv run python -m refdata.run`",
            )
        )

    embedded = ", ".join(
        f"{model or 'none'}={count}" for model, count in vintages
    ) or "no reports yet"
    stale = [model for model, _ in vintages if model is not None]
    checks.append(
        Check(
            "stored embeddings",
            OK if len(stale) <= 1 else DEGRADED,
            f"{reports} report(s): {embedded}",
            "" if len(stale) <= 1 else "mixed vintages -- run `uv run python -m scripts.reembed`",
        )
    )
    return checks


def _check_completions() -> tuple[list[Check], object | None]:
    try:
        config = resolve_completion()
    except ConfigError as exc:
        return [Check("completions", ERROR, "unresolved", str(exc))], None

    checks = [
        Check("completions", OK, f"{config.provider} / {config.model} via {config.base_url}", config.source)
    ]

    # Printed even though nothing is wrong: this is the one setting that
    # silently changes *how* a document is extracted (§5.3), and both halves
    # share one window on a local model.
    checks.append(
        Check(
            "  token budget",
            OK,
            f"{config.max_input_tokens:,} in / {config.max_output_tokens:,} out; "
            "longer documents are chunked",
            "set MAX_INPUT_TOKENS / MAX_OUTPUT_TOKENS to match your model's window",
        )
    )

    client = build_completion_client(config)
    try:
        checks.append(Check("  reachability", OK, client.ping()))
    except EnrichmentError as exc:
        checks.append(Check("  reachability", ERROR, "call failed", _provider_fix(exc)))
    return checks, config


def _check_embeddings(completion_config) -> list[Check]:
    if completion_config is None:
        return []

    config = resolve_embedding(completion_config)
    if config is None:
        return [
            Check(
                "embeddings",
                DEGRADED,
                "no provider resolved -- reports get a NULL embedding, /search stays off",
                "set EMBEDDING_BASE_URL (and EMBEDDING_MODEL), or start Ollama on :11434",
            )
        ]

    checks = [
        Check("embeddings", OK, f"{config.provider} / {config.model} via {config.base_url}", config.source)
    ]

    client = build_embedding_client(config)
    try:
        dimension = client.dimension
    except EnrichmentError as exc:
        checks.append(
            Check(
                "  reachability",
                DEGRADED,
                "call failed",
                f"{_provider_fix(exc)} (the run continues without embeddings)",
            )
        )
        return checks

    if dimension == REPORT_EMBEDDING_DIM:
        checks.append(Check("  dimension", OK, f"{dimension} matches report.embedding VECTOR({REPORT_EMBEDDING_DIM})"))
    else:
        checks.append(
            Check(
                "  dimension",
                DEGRADED,
                f"{dimension} != VECTOR({REPORT_EMBEDDING_DIM}); embeddings will be skipped",
                "set EMBEDDING_MODEL to a model of this width, or see README "
                "'Changing the embedding model' to migrate the column",
            )
        )
    return checks


def _short(exc: object, limit: int = 120) -> str:
    text = " ".join(str(exc).split())
    return text if len(text) <= limit else text[: limit - 3] + "..."


# An expired key, a wrong model id, a rate limit and an empty credit balance
# all arrive as one HTTP error with four different fixes, so quote the
# provider's own `message` rather than guessing one.
_PROVIDER_MESSAGE_RE = re.compile(r"'message':\s*'([^']+)'")


def _provider_fix(exc: object) -> str:
    """The provider's own message if it gave one, else a generic hint.
    Untruncated -- it is the last column on the line, so length costs nothing."""
    match = _PROVIDER_MESSAGE_RE.search(str(exc))
    if match:
        return match.group(1)
    return f"{_short(exc)} -- check LLM_API_KEY, or LLM_BASE_URL / LLM_MODEL for this endpoint"


def _render(checks: list[Check]) -> str:
    headers = ("COMPONENT", "STATUS", "DETAIL", "FIX")
    rows = [headers] + [(c.component, c.status.upper(), c.detail, c.fix) for c in checks]
    widths = [max(len(row[i]) for row in rows) for i in range(3)]
    lines = [
        "  ".join(cell.ljust(width) for cell, width in zip(row[:3], widths)) + ("  " + row[3] if row[3] else "")
        for row in rows
    ]
    lines.insert(1, "  ".join("-" * width for width in widths))
    return "\n".join(line.rstrip() for line in lines)


def run_doctor() -> int:
    """Print the table; return 0 unless something is genuinely broken.

    DEGRADED does not fail the exit code: no embedding provider is the
    supported one-key path (§5.4), not a broken build.
    """
    database, engine = _check_database()
    completions, completion_config = _check_completions()

    checks = completions + _check_embeddings(completion_config) + [database]
    checks += _check_schema(engine) + _check_reference_data(engine)

    print(_render(checks))

    failed = [check for check in checks if check.status == ERROR]
    degraded = [check for check in checks if check.status == DEGRADED]
    print()
    print(f"{len(checks) - len(failed) - len(degraded)} ok, {len(degraded)} degraded, {len(failed)} error")
    return 1 if failed else 0
