"""Scorecard rendering (eval/scorecard.py).

A smoke test with a purpose: rendering happens after a run has already spent a
model call per document per backend, so a formatting crash there is the most
expensive possible place for one. Covers the failure and defect branches too.
"""

from __future__ import annotations

from enrich.actors import ActorIndex
from enrich.techniques import TechniqueIndex
from eval.baseline import KeywordBaseline
from eval.gold import GOLD_DIR, load_gold_set
from eval.predict import Prediction
from eval.score import score_system
from eval.scorecard import (
    RunMetadata,
    comparison_path,
    git_commit,
    now,
    render_comparison,
    render_scorecard,
    scorecard_path,
    slug,
)
from tests.test_eval_gold import ACTOR_ROWS, TECHNIQUE_IDS


def _gold_set():
    return load_gold_set(
        GOLD_DIR,
        technique_index=TechniqueIndex(TECHNIQUE_IDS),
        actor_index=ActorIndex(ACTOR_ROWS),
    )


def _llm_predictions(fixtures):
    """One good extraction and one hard failure: the two render paths."""
    good, failed = fixtures
    return [
        Prediction(
            fixture_id=good.id,
            system="llm",
            actors={"Volt Typhoon"},
            techniques=good.technique_ids(),
            countries=good.countries(),
            sectors=good.sectors() | {"aerospace"},  # one off-vocabulary answer
            techniques_emitted=8,
            techniques_closed_world_ok=7,
            evidence_quotes_valid=6,
            actors_emitted=2,
            actors_unresolved=1,
            sectors_off_vocabulary=1,
            input_tokens=4000,
            output_tokens=900,
            attempts=1,
        ),
        Prediction(
            fixture_id=failed.id,
            system="llm",
            status="schema_fail",
            error="techniques.0.evidence_quote\n  Field required",
            attempts=2,
        ),
    ]


def _scores():
    gold_set = _gold_set()
    fixtures = gold_set.fixtures
    llm = score_system("test-model", "llm", fixtures, _llm_predictions(fixtures))
    baseline_system = KeywordBaseline(ACTOR_ROWS, TechniqueIndex(TECHNIQUE_IDS))
    baseline = score_system(
        "baseline", "baseline", fixtures, [baseline_system.predict(f) for f in fixtures]
    )
    return gold_set, llm, baseline


def _metadata() -> RunMetadata:
    return RunMetadata(
        backend="primary",
        provider="anthropic",
        model="claude-sonnet-5",
        base_url="https://api.anthropic.com",
        prompt_version="abc123def456",
        generated_at=now(),
        git_commit=git_commit(),
        gold_documents=2,
        placeholders=3,
        max_input_tokens=150_000,
    )


def test_renders_every_section():
    gold_set, llm, baseline = _scores()
    markdown = render_scorecard(_metadata(), llm, baseline, gold_set)

    for heading in [
        "## Run",
        "## Headline — micro-averaged, LLM vs non-LLM baseline",
        "## Macro-averaged (per-document mean F1)",
        "## The lift: recall on implicitly-described techniques",
        "## Guardrail telemetry (§5.2)",
        "## Extraction failures",
        "## Per document",
        "## Reading these numbers",
    ]:
        assert heading in markdown

    assert "claude-sonnet-5" in markdown
    assert "abc123def456" in markdown


def test_failed_extraction_is_reported_not_hidden():
    gold_set, llm, baseline = _scores()
    markdown = render_scorecard(_metadata(), llm, baseline, gold_set)

    assert "schema_fail" in markdown
    assert "0002-fin7-health-ransomware" in markdown
    # Its gold items count as false negatives, so recall drops below 1.0.
    assert llm.micro("techniques (parent)").recall < 1.0


def test_off_vocabulary_sectors_are_surfaced():
    gold_set, llm, baseline = _scores()
    assert "`aerospace`" in render_scorecard(_metadata(), llm, baseline, gold_set)


def test_undefined_metrics_render_as_not_available():
    """The baseline writes no quotes, so validity is undefined, not 0.0%."""
    _, llm, baseline = _scores()
    assert baseline.evidence_quote_validity is None
    assert "n/a" in render_comparison("abc123def456", [(_metadata(), llm)], baseline)


def test_comparison_table_names_every_backend():
    _, llm, baseline = _scores()
    local = RunMetadata(**{**_metadata().__dict__, "backend": "local", "model": "qwen3:8b"})
    markdown = render_comparison("abc123def456", [(_metadata(), llm), (local, llm)], baseline)

    assert "primary (claude-sonnet-5)" in markdown
    assert "local (qwen3:8b)" in markdown
    assert "baseline" in markdown


def test_paths_are_keyed_for_overwrite_not_accumulation(tmp_path):
    metadata = RunMetadata(**{**_metadata().__dict__, "model": "anthropic/claude-sonnet-5"})

    path = scorecard_path(metadata, tmp_path)
    assert path.name == "primary--anthropic-claude-sonnet-5--abc123def456.md"
    assert scorecard_path(metadata, tmp_path) == path  # same config, same file

    assert comparison_path("abc123def456", tmp_path).name == "cross-backend--abc123def456.md"


def test_slug_is_filename_safe():
    assert slug("anthropic/claude-sonnet-5") == "anthropic-claude-sonnet-5"
    assert slug("Qwen3:8B") == "qwen3-8b"
