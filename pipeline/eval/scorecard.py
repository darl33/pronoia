"""Markdown scorecards, one per (backend, model, prompt_version) (DESIGN.md §7),
plus the cross-backend comparison table.

Filename keying and in-file run metadata: docs/DECISIONS.md#scorecards
"""

from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from eval.gold import GoldSet
from eval.score import FIELDS, SystemScore, unknown_sectors

SCORECARD_DIR = Path(__file__).parent / "scorecards"

# §7's target, for the primary backend only. Alternative backends are
# characterized, not gated, so it is printed everywhere but asserted for one.
PARENT_F1_TARGET = 0.85


@dataclass(frozen=True)
class RunMetadata:
    backend: str
    provider: str
    model: str
    base_url: str
    prompt_version: str
    generated_at: str
    git_commit: str
    gold_documents: int
    placeholders: int
    max_input_tokens: int
    max_output_tokens: int = 0


def git_commit() -> str:
    """Short hash, suffixed '-dirty' when the tree has uncommitted changes --
    numbers from a modified tree replicate from no commit."""
    try:
        commit = subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"],
            capture_output=True, text=True, check=True, cwd=Path(__file__).parent,
        ).stdout.strip()
        dirty = subprocess.run(
            ["git", "status", "--porcelain"],
            capture_output=True, text=True, check=True, cwd=Path(__file__).parent,
        ).stdout.strip()
    except (subprocess.CalledProcessError, FileNotFoundError):
        return "unknown"
    return f"{commit}-dirty" if dirty else commit


def slug(text: str) -> str:
    """Filename-safe. Model ids carry slashes ('anthropic/claude-sonnet-5')."""
    return re.sub(r"[^A-Za-z0-9._-]+", "-", text).strip("-").lower()


def scorecard_path(metadata: RunMetadata, directory: Path = SCORECARD_DIR) -> Path:
    return directory / f"{slug(metadata.backend)}--{slug(metadata.model)}--{metadata.prompt_version}.md"


def comparison_path(prompt_version: str, directory: Path = SCORECARD_DIR) -> Path:
    """Keyed on prompt_version alone -- the table only means anything with the
    prompt held constant."""
    return directory / f"cross-backend--{prompt_version}.md"


def now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%SZ")


# ---------- formatting ----------


def _num(value: float | None, places: int = 3) -> str:
    """'n/a' rather than 0.000 for an undefined metric -- see metrics.rate."""
    return "n/a" if value is None else f"{value:.{places}f}"


def _pct(value: float | None) -> str:
    return "n/a" if value is None else f"{value * 100:.1f}%"


def _table(header: list[str], rows: list[list[str]]) -> str:
    lines = ["| " + " | ".join(header) + " |",
             "|" + "|".join("---" for _ in header) + "|"]
    lines += ["| " + " | ".join(row) + " |" for row in rows]
    return "\n".join(lines)


# ---------- sections ----------


def _headline(llm: SystemScore, baseline: SystemScore) -> str:
    rows = []
    for field_name in FIELDS:
        llm_counts = llm.micro(field_name)
        base_counts = baseline.micro(field_name)
        rows.append([
            field_name,
            _num(llm_counts.precision), _num(llm_counts.recall), f"**{_num(llm_counts.f1)}**",
            _num(base_counts.precision), _num(base_counts.recall), _num(base_counts.f1),
            f"{_num(llm_counts.f1 - base_counts.f1, 3)}",
            str(llm_counts.support),
        ])
    return _table(
        ["Field", "LLM P", "LLM R", "LLM F1", "Base P", "Base R", "Base F1", "ΔF1", "Gold items"],
        rows,
    )


def _macro(llm: SystemScore, baseline: SystemScore) -> str:
    rows = [
        [field_name, _num(llm.macro_f1(field_name)), _num(baseline.macro_f1(field_name))]
        for field_name in FIELDS
    ]
    return _table(["Field", "LLM macro-F1", "Baseline macro-F1"], rows)


def _lift(llm: SystemScore, baseline: SystemScore) -> str:
    rows = []
    for label, parent in (("sub-technique", False), ("parent", True)):
        llm_recall = llm.implicit_recall(parent=parent)
        base_recall = baseline.implicit_recall(parent=parent)
        delta = None if llm_recall is None or base_recall is None else llm_recall - base_recall
        rows.append([label, _num(llm_recall), _num(base_recall), _num(delta)])
    return _table(["Granularity", "LLM recall", "Baseline recall", "Δ"], rows)


def _guardrails(llm: SystemScore) -> str:
    rows = [
        ["Evidence-quote validity (§5.2 guardrail 3)", _pct(llm.evidence_quote_validity),
         "share of emitted quotes found verbatim in the document"],
        ["Closed-world pass rate (guardrail 2)", _pct(llm.closed_world_pass_rate),
         "share of emitted technique IDs that exist in ATT&CK"],
        ["Actor review-queue rate (guardrail 4)", _pct(llm.actor_review_rate),
         "share of actor mentions that did not resolve to a threat_actor row"],
        ["Off-vocabulary sectors", str(llm.off_vocabulary_sectors),
         "sector strings outside eval/vocab.py SECTORS"],
        ["Documents chunked (§5.3)", str(llm.chunked_documents),
         "documents no single call saw whole -- cross-chunk reasoning is gone"],
        ["Chunks that produced nothing", str(llm.failed_chunks),
         "silent under-extraction: the rest of the document still merged"],
    ]
    return _table(["Guardrail", "Rate", "What it measures"], rows)


def _per_document(llm: SystemScore, baseline: SystemScore) -> str:
    base_by_id = {doc.fixture_id: doc for doc in baseline.documents}
    rows = []
    for doc in llm.documents:
        base = base_by_id.get(doc.fixture_id)
        rows.append([
            doc.fixture_id,
            doc.status,
            _num(doc.counts["actors"].f1),
            _num(doc.counts["techniques (parent)"].f1),
            _num(doc.counts["targets: countries"].f1),
            _num(doc.counts["targets: sectors"].f1),
            _num(base.counts["techniques (parent)"].f1) if base else "n/a",
        ])
    return _table(
        ["Fixture", "Status", "Actors F1", "Tech-parent F1", "Country F1", "Sector F1",
         "Base tech-parent F1"],
        rows,
    )


def _failures(llm: SystemScore) -> str:
    failures = llm.failures
    if not failures:
        return "None. Every gold document produced a validated extraction.\n"

    lines = [
        "These documents produced no report. Their gold items are counted as false",
        "negatives above, which is what the dataset would look like.",
        "",
    ]
    lines.append(_table(
        ["Fixture", "Status", "Attempts", "Error"],
        [[p.fixture_id, p.status, str(p.attempts), (p.error or "")[:160].replace("\n", " ")]
         for p in failures],
    ))
    return "\n".join(lines) + "\n"


def render_scorecard(
    metadata: RunMetadata, llm: SystemScore, baseline: SystemScore, gold_set: GoldSet
) -> str:
    parent_f1 = llm.micro("techniques (parent)").f1
    input_tokens, output_tokens = llm.total_tokens
    gaps = unknown_sectors(llm.predictions)

    sections = [
        f"# Eval scorecard — {metadata.model} @ {metadata.backend}",
        "",
        f"Prompt version `{metadata.prompt_version}` · generated {metadata.generated_at} · "
        f"commit `{metadata.git_commit}`",
        "",
        "Generated by `uv run python -m eval.run_eval` (DESIGN.md §7). Do not edit by hand.",
        "",
        "## Run",
        "",
        _table(["Key", "Value"], [
            ["Backend", metadata.backend],
            ["Provider", metadata.provider],
            ["Model", f"`{metadata.model}`"],
            ["Endpoint", f"`{metadata.base_url}`"],
            ["Prompt version", f"`{metadata.prompt_version}`"],
            ["Git commit", f"`{metadata.git_commit}`"],
            ["Generated at", metadata.generated_at],
            ["Gold documents scored", str(metadata.gold_documents)],
            ["Placeholder fixtures skipped", str(metadata.placeholders)],
            ["Token budget (in / out)", f"{metadata.max_input_tokens:,} / {metadata.max_output_tokens:,}"],
            ["Documents chunked (§5.3)", f"{llm.chunked_documents} of {len(llm.predictions)}"],
            ["Tokens (in / out)", f"{input_tokens:,} / {output_tokens:,}"],
        ]),
        "",
        "## Headline — micro-averaged, LLM vs non-LLM baseline",
        "",
        _headline(llm, baseline),
        "",
        f"**§7 target:** >{PARENT_F1_TARGET} F1 on techniques at parent granularity. "
        f"This run: **{_num(parent_f1)}** — {'met' if parent_f1 > PARENT_F1_TARGET else 'not met'}. "
        "(§7 sets this target for the primary backend only; alternative backends are "
        "characterized, not gated.)",
        "",
        "## Macro-averaged (per-document mean F1)",
        "",
        _macro(llm, baseline),
        "",
        "A large macro/micro gap means performance depends on document size. Documents "
        "with an empty gold set *and* an empty prediction are excluded from the macro "
        "mean — see the conventions in `eval/metrics.py`.",
        "",
        "## The lift: recall on implicitly-described techniques",
        "",
        "Techniques annotated `explicit_in_text: false` — described in prose, ID never "
        "written down. This is the subset the baseline structurally cannot reach, and "
        "the reason §7 asks for a baseline at all. Precision is not reported here: a "
        "prediction carries no explicit/implicit label, so it cannot be attributed to "
        "the subset.",
        "",
        _lift(llm, baseline),
        "",
        "## Guardrail telemetry (§5.2)",
        "",
        _guardrails(llm),
        "",
    ]

    if gaps:
        sections += [
            "Sector strings the model produced that are outside the controlled "
            "vocabulary: " + ", ".join(f"`{gap}`" for gap in sorted(gaps)) + ". These are "
            "prompt or vocabulary work, not model errors.",
            "",
        ]

    sections += [
        "## Extraction failures",
        "",
        _failures(llm),
        "## Per document",
        "",
        _per_document(llm, baseline),
        "",
    ]

    if gold_set.defects:
        sections += [
            "## Gold-set defects",
            "",
            "Annotations the pipeline's own reference data cannot express. Each one "
            "depresses the score above for a reason that has nothing to do with the "
            "model, so it is listed rather than absorbed.",
            "",
            *[f"- {defect}" for defect in gold_set.defects],
            "",
        ]

    sections += [
        "## Reading these numbers",
        "",
        "- **Micro, not macro, is the headline.** tp/fp/fn are pooled across documents "
        "and divided once, so every gold item weighs the same.",
        "- **A failed extraction is scored, not skipped.** No rows written means every "
        "gold item is a false negative — the dataset's real state.",
        "- **Techniques are scored at both granularities** and never merged. The gap "
        "between them is how much of the error is sub-technique choice rather than "
        "missing the behaviour entirely.",
        "- **Targets are scored as two fields**, country and sector, not as pairs.",
        "- **Unresolved actors are counted, not scored.** They go to the review queue "
        "and never reach `report_actor`, so they are not part of the output.",
        "",
    ]

    return "\n".join(sections)


def render_comparison(prompt_version: str, results: list[tuple[RunMetadata, SystemScore]],
                      baseline: SystemScore) -> str:
    """The cross-backend table (§7). The baseline column is shared: it does not
    depend on the backend, so it is the fixed floor both are read against."""
    header = ["Field"] + [f"{meta.backend} ({meta.model})" for meta, _ in results] + ["baseline"]

    rows = []
    for field_name in FIELDS:
        row = [field_name]
        row += [_num(score.micro(field_name).f1) for _, score in results]
        row.append(_num(baseline.micro(field_name).f1))
        rows.append(row)

    diagnostics = [
        ["implicit-technique recall (parent)"]
        + [_num(score.implicit_recall(parent=True)) for _, score in results]
        + [_num(baseline.implicit_recall(parent=True))],
        ["evidence-quote validity"]
        + [_pct(score.evidence_quote_validity) for _, score in results]
        + ["n/a"],
        ["closed-world pass rate"]
        + [_pct(score.closed_world_pass_rate) for _, score in results]
        + ["n/a"],
        ["extraction failures"]
        + [str(len(score.failures)) for _, score in results]
        + ["0"],
        ["documents chunked (§5.3)"]
        + [str(score.chunked_documents) for _, score in results]
        + ["0"],
        ["context budget (tokens)"]
        + [f"{meta.max_input_tokens:,}" for meta, _ in results]
        + ["n/a"],
    ]

    return "\n".join([
        "# Cross-backend comparison",
        "",
        f"Prompt version `{prompt_version}` · generated {now()} · commit `{git_commit()}`",
        "",
        "DESIGN.md §7: the same gold set, the same prompt, the same guardrails, run "
        "against each configured completion backend. This is what makes the "
        "provider-agnostic claim in §5.3 measured rather than asserted. A local model "
        "scoring materially worse — particularly on implicit technique extraction — is "
        "the expected finding, not a bug.",
        "",
        "## F1 by field",
        "",
        _table(header, rows),
        "",
        "## Diagnostics",
        "",
        _table(header, diagnostics),
        "",
        "The baseline column is identical across backends by construction: it does not "
        "call a model. It is here as the fixed floor both backends are read against.",
        "",
        "Where the two backends chunked different numbers of documents, they were not "
        "answering the same question: a chunked document is extracted in fragments that "
        "no single call saw together (§5.3). That is the honest form of the "
        "provider-agnostic claim — the pipeline runs everywhere, and the cost of running "
        "it on a small context window is this row plus the scores above it.",
        "",
        "Per-backend detail, including per-document scores and failure reasons, is in "
        "the individual scorecards in this directory.",
        "",
    ])


def write(path: Path, content: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return path
