"""The eval harness (DESIGN.md §7).

    uv run python -m eval.run_eval                      # primary backend + baseline
    uv run python -m eval.run_eval --backend both       # + local, and a comparison table
    uv run python -m eval.run_eval --baseline-only      # no model calls, no cost
    uv run python -m eval.run_eval --limit 5            # smoke test

It reads reference data from Postgres (attack_technique, threat_actor) so the
closed-world and actor-resolution guardrails are the real ones, runs the live
extraction path over every annotated fixture in `gold/`, scores it against the
annotations, and writes a committed markdown scorecard per backend.

**Backends (§7).** `--backend primary` is normal config resolution (§5.4);
`--backend local` reads `EVAL_LOCAL_BASE_URL` / `EVAL_LOCAL_MODEL`, falling back
to `LLM_BASE_URL` / `LLM_MODEL`. Separate variables for one reason: `--backend
both` holds two configurations at once, and sharing them would collapse the
comparison into a model against itself.

**Cost.** One model call per document per backend. `--baseline-only` exercises
the whole harness, metrics and gold-set validation included, with no API calls.
"""

from __future__ import annotations

import argparse
import logging
import os
import sys
from pathlib import Path

from dotenv import load_dotenv

from enrich.actors import ActorIndex
from enrich.client import build_completion_client
from enrich.config import (
    LOCAL_MAX_INPUT_TOKENS,
    LOCAL_MAX_OUTPUT_TOKENS,
    OPENAI_COMPATIBLE,
    CompletionConfig,
    ConfigError,
    discover_local,
    probe_openai_compatible,
    resolve_completion,
    resolve_max_input_tokens,
    resolve_max_output_tokens,
)
from enrich.chunk import BudgetTooSmall, document_budget_chars
from enrich.db import load_technique_ids, load_threat_actors
from enrich.prompt import prompt_version, render_user_prompt, system_prompt
from enrich.techniques import TechniqueIndex
from eval.baseline import KeywordBaseline
from eval.gold import GOLD_DIR, GoldSet, load_gold_set
from eval.predict import predict_llm
from eval.score import score_system
from eval.scorecard import (
    SCORECARD_DIR,
    RunMetadata,
    comparison_path,
    git_commit,
    now,
    render_comparison,
    render_scorecard,
    scorecard_path,
    write,
)
from ingest.db import get_engine

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
log = logging.getLogger("eval.run_eval")

BACKENDS = ("primary", "local", "both")


def _env(name: str) -> str | None:
    value = os.environ.get(name, "").strip()
    return value or None


def resolve_local_backend() -> CompletionConfig:
    """The §7 second backend: an OpenAI-compatible endpoint, hosted or local.

    Never the native SDK path -- the point of this backend is to exercise the
    one adapter §5.3 claims reaches everything else.
    """
    base_url = _env("EVAL_LOCAL_BASE_URL") or _env("LLM_BASE_URL")
    model = _env("EVAL_LOCAL_MODEL") or _env("LLM_MODEL")
    api_key = _env("EVAL_LOCAL_API_KEY")

    if base_url is None:
        discovered = discover_local()
        if discovered is None:
            raise ConfigError(
                "no local backend to evaluate against. Set EVAL_LOCAL_BASE_URL to an "
                "OpenAI-compatible /v1 endpoint (and EVAL_LOCAL_MODEL if it does not "
                "advertise a usable default), or start Ollama or vLLM locally."
            )
        base_url, model_ids = discovered
        source = f"local discovery at {base_url}"
    else:
        model_ids = probe_openai_compatible(base_url, api_key) or []
        source = "EVAL_LOCAL_BASE_URL" if _env("EVAL_LOCAL_BASE_URL") else "LLM_BASE_URL"

    if model is None:
        # Unlike the pipeline's resolution this refuses to fall back to
        # model_ids[0]: an unidentified model in a committed scorecard defeats
        # the scorecard's whole point, which is being attributable.
        model = next((m for m in model_ids if "embed" not in m.lower()), None)
    if model is None:
        raise ConfigError(
            f"{base_url} did not advertise a usable completion model. Set "
            "EVAL_LOCAL_MODEL to the model this endpoint serves."
        )

    return CompletionConfig(
        provider=OPENAI_COMPATIBLE,
        base_url=base_url,
        model=model,
        api_key=api_key,
        native_sdk=False,
        source=source,
        # /v1/models does not report a context window, so the conservative
        # local pair stands unless the env overrides it.
        max_input_tokens=resolve_max_input_tokens(LOCAL_MAX_INPUT_TOKENS),
        max_output_tokens=resolve_max_output_tokens(LOCAL_MAX_OUTPUT_TOKENS),
    )


def load_reference_data(engine):
    """attack_technique + threat_actor, plus the id -> canonical_name map the
    scorer needs to report resolved actors by name."""
    with engine.begin() as conn:
        technique_ids = load_technique_ids(conn)
        actor_rows = load_threat_actors(conn)

    technique_index = TechniqueIndex(technique_ids)
    actor_index = ActorIndex(actor_rows)
    canonical_names = {row["id"]: row["canonical_name"] for row in actor_rows}

    if not len(technique_index) or not len(actor_index):
        raise SystemExit(
            "reference data is empty -- run `uv run python -m refdata.run` first. "
            "Without it the closed-world and actor guardrails have nothing to "
            "validate against, and every score would be zero for that reason "
            "rather than for a real one."
        )

    return technique_index, actor_index, canonical_names, actor_rows


def check_budget(config: CompletionConfig) -> None:
    """§5.4: a budget too small to fit any document is a config error, and it
    is knowable before the first model call rather than during it."""
    try:
        document_budget_chars(
            config.max_input_tokens,
            prompt_overhead_chars=len(system_prompt()) + len(render_user_prompt("")),
        )
    except BudgetTooSmall as exc:
        raise SystemExit(f"backend {config.provider!r}: {exc}") from exc


def run_llm_backend(name: str, config: CompletionConfig, fixtures, *,
                    technique_index, actor_index, canonical_names):
    check_budget(config)
    client = build_completion_client(config)
    log.info(
        "backend=%s provider=%s model=%s endpoint=%s tokens=%d/%d (%s)",
        name, config.provider, config.model, config.base_url,
        config.max_input_tokens, config.max_output_tokens, config.source,
    )

    predictions = []
    for position, fixture in enumerate(fixtures, start=1):
        log.info("[%s] %d/%d %s", name, position, len(fixtures), fixture.id)
        prediction = predict_llm(
            client, fixture,
            technique_index=technique_index,
            actor_index=actor_index,
            canonical_names=canonical_names,
            max_input_tokens=config.max_input_tokens,
            max_output_tokens=config.max_output_tokens,
        )
        if not prediction.succeeded:
            log.warning(
                "[%s] %s produced no extraction: %s (%s)",
                name, fixture.id, prediction.status, (prediction.error or "")[:200],
            )
        predictions.append(prediction)

    return score_system(config.model, "llm", fixtures, predictions)


def report_gold_set(gold_set: GoldSet) -> None:
    log.info(
        "gold set: %d annotated fixture(s), %d placeholder(s) skipped",
        len(gold_set.fixtures), len(gold_set.placeholders),
    )
    for placeholder in gold_set.placeholders:
        log.info("  placeholder (not scored): %s", placeholder.id)
    for defect in gold_set.defects:
        # Loud on purpose: a defect depresses the score for a reason that has
        # nothing to do with the model.
        log.warning("  gold-set defect: %s", defect)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="eval.run_eval",
        description="Score the live enrichment pipeline against the gold set (DESIGN.md §7).",
    )
    parser.add_argument("--backend", choices=BACKENDS, default="primary",
                        help="which completion backend(s) to evaluate (default: primary)")
    parser.add_argument("--baseline-only", action="store_true",
                        help="run the non-LLM baseline only; makes no API calls")
    parser.add_argument("--limit", type=int, default=None,
                        help="score at most N fixtures (smoke test)")
    parser.add_argument("--gold-dir", type=Path, default=GOLD_DIR)
    parser.add_argument("--out-dir", type=Path, default=SCORECARD_DIR)
    args = parser.parse_args(argv)

    load_dotenv()
    engine = get_engine()
    technique_index, actor_index, canonical_names, actor_rows = load_reference_data(engine)

    gold_set = load_gold_set(
        args.gold_dir, technique_index=technique_index, actor_index=actor_index
    )
    report_gold_set(gold_set)

    if not gold_set.fixtures:
        raise SystemExit(
            f"no annotated fixtures in {args.gold_dir}. Fill in a placeholder and set its "
            '"status" to "annotated" -- see gold/README.md.'
        )

    fixtures = gold_set.fixtures[: args.limit] if args.limit else gold_set.fixtures
    version = prompt_version()

    baseline = score_system(
        "regex + alias baseline", "baseline", fixtures,
        [KeywordBaseline(actor_rows, technique_index).predict(f) for f in fixtures],
    )

    if args.baseline_only:
        # No scorecard: a scorecard is a claim about a (model, prompt_version)
        # pair, and there is no model here. Print the floor and stop.
        print(f"\nBaseline only — {len(fixtures)} document(s), prompt {version}\n")
        for field_name in ("actors", "techniques (parent)", "targets: countries",
                           "targets: sectors"):
            counts = baseline.micro(field_name)
            print(f"  {field_name:<28} P={counts.precision:.3f} R={counts.recall:.3f} "
                  f"F1={counts.f1:.3f}  (gold items: {counts.support})")
        print()
        return 0

    selected = ["primary", "local"] if args.backend == "both" else [args.backend]
    results = []

    for name in selected:
        try:
            config = resolve_completion() if name == "primary" else resolve_local_backend()
        except ConfigError as exc:
            raise SystemExit(f"backend {name!r}: {exc}\n\nRun `uv run pronoia doctor` "
                             "for the full picture.") from exc

        scored = run_llm_backend(
            name, config, fixtures,
            technique_index=technique_index,
            actor_index=actor_index,
            canonical_names=canonical_names,
        )
        metadata = RunMetadata(
            backend=name,
            provider=config.provider,
            model=config.model,
            base_url=config.base_url,
            prompt_version=version,
            generated_at=now(),
            git_commit=git_commit(),
            gold_documents=len(fixtures),
            placeholders=len(gold_set.placeholders),
            max_input_tokens=config.max_input_tokens,
            max_output_tokens=config.max_output_tokens,
        )
        path = write(
            scorecard_path(metadata, args.out_dir),
            render_scorecard(metadata, scored, baseline, gold_set),
        )
        log.info("wrote %s", path)

        parent = scored.micro("techniques (parent)")
        print(f"\n{name}: {config.model} — techniques (parent) F1 = {parent.f1:.3f}, "
              f"actors F1 = {scored.micro('actors').f1:.3f}, "
              f"{len(scored.failures)} extraction failure(s)")
        print(f"  scorecard: {path}")

        results.append((metadata, scored))

    if len(results) > 1:
        path = write(
            comparison_path(version, args.out_dir),
            render_comparison(version, results, baseline),
        )
        log.info("wrote %s", path)
        print(f"\ncross-backend comparison: {path}\n")

    return 0


if __name__ == "__main__":
    sys.exit(main())
