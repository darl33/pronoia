"""Turn an ingested raw_document into a gold-set fixture stub (DESIGN.md §7).

    uv run python -m eval.export_fixture --list
    uv run python -m eval.export_fixture --document-id UUID
    uv run python -m eval.export_fixture --auto 5 --source-kind vendor_blog

Writes `gold/NNNN-slug.txt` (the document, defanged) and `gold/NNNN-slug.json`
(a skeleton with `status: "placeholder"`), then the annotation is done by hand.

Everything it writes is marked placeholder, never annotated: the harness skips
those, so an exported-but-unannotated fixture can never be scored as if its
empty annotation were real.

Candidate ranking and the defanging tradeoff:
docs/DECISIONS.md#exporting-fixtures, docs/DECISIONS.md#defanging-fixtures
"""

from __future__ import annotations

import argparse
import json
import re
import sys

from dotenv import load_dotenv
from sqlalchemy import func, select

from enrich.defang import defang_text
from eval.gold import GOLD_DIR
from ingest.db import feed, get_engine, raw_document

# Below this a document is a teaser or a stub, not something to annotate.
MIN_USEFUL_CHARS = 1500

# An ATT&CK ID written out, the strongest signal that a document carries
# technique content a regex baseline can also see.
_TECHNIQUE_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")

# Words that mark actor/campaign reporting rather than a product advisory.
_THREAT_WORDS = (
    "threat actor", "apt", "campaign", "attribut", "state-sponsored",
    "ransomware", "intrusion", "adversary", "espionage", "tradecraft",
)

_SOURCE_KINDS = {"cisa": "cisa", "acsc": "acsc"}


def source_kind_for(feed_name: str) -> str:
    lowered = feed_name.lower()
    for needle, kind in _SOURCE_KINDS.items():
        if lowered.startswith(needle):
            return kind
    return "vendor_blog"


def score(title: str, text: str) -> int:
    """Rough annotation-value ranking. Not a filter -- the operator picks."""
    lowered = text.lower()
    points = len(set(_TECHNIQUE_RE.findall(text))) * 5
    points += sum(3 for word in _THREAT_WORDS if word in lowered)
    points += min(len(text) // 5000, 6)
    return points


def slugify(title: str, limit: int = 48) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", (title or "untitled").lower()).strip("-")
    return slug[:limit].rstrip("-") or "untitled"


def next_index(directory) -> int:
    used = [
        int(match.group(1))
        for path in directory.glob("*.json")
        if (match := re.match(r"^(\d{4})-", path.name))
    ]
    return max(used, default=0) + 1


def candidates(conn, *, source_kind: str | None = None, limit: int | None = None):
    rows = conn.execute(
        select(
            raw_document.c.id, raw_document.c.title, raw_document.c.source_url,
            raw_document.c.published_at, raw_document.c.clean_text, feed.c.name,
        )
        .select_from(raw_document.join(feed, feed.c.id == raw_document.c.feed_id))
        .where(func.length(raw_document.c.clean_text) >= MIN_USEFUL_CHARS)
        # Reference-data feeds (MISP galaxy JSON) are not threat reports.
        .where(feed.c.kind != "json")
    ).mappings().all()

    scored = []
    for row in rows:
        kind = source_kind_for(row["name"])
        if source_kind and kind != source_kind:
            continue
        scored.append((score(row["title"] or "", row["clean_text"]), kind, row))
    scored.sort(key=lambda item: -item[0])
    return scored[:limit] if limit else scored


def exported_document_urls(directory) -> set[str]:
    """source_urls already exported, so --auto never offers a duplicate."""
    urls = set()
    for path in directory.glob("*.json"):
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            continue
        url = (payload.get("document") or {}).get("source_url")
        if url:
            urls.add(url)
    return urls


def export(row, kind: str, directory, index: int) -> tuple[str, int]:
    text, defanged = defang_text(row["clean_text"])
    fixture_id = f"{index:04d}-{slugify(row['title'])}"

    (directory / f"{fixture_id}.txt").write_text(text, encoding="utf-8")
    (directory / f"{fixture_id}.json").write_text(
        json.dumps(
            {
                "id": fixture_id,
                "status": "placeholder",
                "document": {
                    "text_file": f"{fixture_id}.txt",
                    "title": row["title"] or "TODO: the document's own title",
                    "source_url": row["source_url"],
                    "source_kind": kind,
                    "published_on": row["published_at"].date().isoformat()
                    if row["published_at"] else None,
                },
                "annotation": {"actors": [], "techniques": [], "targets": []},
                "annotated_by": None,
                "annotated_on": None,
                "notes": (
                    f"Exported from raw_document {row['id']}; {defanged} indicator(s) "
                    "defanged. Annotate per gold/README.md, then set status to "
                    '"annotated". Read the document before annotating, and do not '
                    "look at the pipeline's output first."
                ),
            },
            indent=2,
        ) + "\n",
        encoding="utf-8",
    )
    return fixture_id, defanged


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="eval.export_fixture",
        description="Export ingested documents as gold-set fixture stubs (DESIGN.md §7).",
    )
    parser.add_argument("--list", action="store_true", help="rank candidates, export nothing")
    parser.add_argument("--document-id", help="export this raw_document")
    parser.add_argument("--auto", type=int, help="export the top N ranked candidates")
    parser.add_argument("--source-kind", choices=("cisa", "acsc", "vendor_blog"))
    parser.add_argument("--gold-dir", default=GOLD_DIR, type=type(GOLD_DIR))
    args = parser.parse_args(argv)

    load_dotenv()
    engine = get_engine()
    directory = args.gold_dir
    directory.mkdir(parents=True, exist_ok=True)

    with engine.begin() as conn:
        if args.document_id:
            row = conn.execute(
                select(
                    raw_document.c.id, raw_document.c.title, raw_document.c.source_url,
                    raw_document.c.published_at, raw_document.c.clean_text, feed.c.name,
                )
                .select_from(raw_document.join(feed, feed.c.id == raw_document.c.feed_id))
                .where(raw_document.c.id == args.document_id)
            ).mappings().first()
            if row is None:
                print(f"no raw_document {args.document_id}")
                return 1
            fixture_id, defanged = export(
                row, source_kind_for(row["name"]), directory, next_index(directory)
            )
            print(f"wrote {fixture_id} ({defanged} indicator(s) defanged)")
            return 0

        ranked = candidates(conn, source_kind=args.source_kind)

        if args.list or not args.auto:
            print(f"{'score':>5} {'chars':>7}  {'kind':<11} title")
            for points, kind, row in ranked[:40]:
                print(f"{points:>5} {len(row['clean_text']):>7}  {kind:<11} {(row['title'] or '')[:58]}")
            print(f"\n{len(ranked)} candidate(s). Export with --auto N or --document-id UUID.")
            return 0

        already = exported_document_urls(directory)
        index = next_index(directory)
        exported = 0
        for points, kind, row in ranked:
            if exported >= args.auto:
                break
            if row["source_url"] in already:
                continue
            fixture_id, defanged = export(row, kind, directory, index)
            print(f"  {fixture_id}  (score {points}, {defanged} indicator(s) defanged)")
            index += 1
            exported += 1

        print(f"\nexported {exported} fixture(s) as placeholders -- annotate per gold/README.md")
    return 0


if __name__ == "__main__":
    sys.exit(main())
