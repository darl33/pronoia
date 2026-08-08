# Gold set — annotation format

Hand-annotated reports, the ground truth every number in `../scorecards/` is
measured against (DESIGN.md §7). Target size is **30 documents: 10 CISA/ACSC
advisories and 20 vendor blog posts**, annotated once and committed.

Everything here is read-only input to the harness. Nothing in this directory is
generated, and the harness never writes to it.

---

## A fixture is two files

| File | What it holds |
|---|---|
| `NNNN-slug.txt` | the document text, exactly as the pipeline would see it |
| `NNNN-slug.json` | the annotation |

The text lives in its own file rather than inline in the JSON because it is the
one thing a human has to read while annotating, and a few thousand characters
of `\n`-escaped prose on one line is unreadable to annotate and useless to
diff.

`0001-volt-typhoon-utilities` and `0002-fin7-health-ransomware` are worked
examples — copy their shape. `0003`–`0005` are empty placeholders to fill in.

### Producing the `.txt`

Paste what the pipeline would store in `raw_document.clean_text`: plain text,
no HTML, no navigation chrome, no cookie banner, no "related posts" tail. Use
the same sanitizer the ingestion path uses, so the evidence-quote guardrail is
matching against the same string shape it will see in production:

```bash
uv run python -c "
from pathlib import Path
from ingest.sanitize import html_to_clean_text
print(html_to_clean_text(Path('saved-page.html').read_text()))
" > eval/gold/0003-my-fixture.txt
```

**Defang every indicator before saving** (`hxxp`, `[.]`), per the repo rule
against live IOCs anywhere in the tree including fixtures. This does not affect
scoring: IOCs are not a scored field, and the model reads the same defanged
text the annotator did.

---

## The annotation

```json
{
  "id": "0001-volt-typhoon-utilities",
  "status": "annotated",
  "document": {
    "text_file": "0001-volt-typhoon-utilities.txt",
    "title": "Pre-positioning in Australian utility networks",
    "source_url": "https://example.invalid/report",
    "source_kind": "vendor_blog",
    "published_on": "2026-04-22"
  },
  "annotation": {
    "actors": [
      { "name": "Volt Typhoon", "attribution_confidence": "confirmed_by_source" }
    ],
    "techniques": [
      { "technique_id": "T1078", "explicit_in_text": false, "note": "valid contractor accounts" },
      { "technique_id": "T1090", "explicit_in_text": true,  "note": "cited by ID" }
    ],
    "targets": [
      { "country": "AU", "sector": "water and sewerage" }
    ]
  },
  "annotated_by": "darl33",
  "annotated_on": "2026-08-08",
  "notes": "free text; why any judgement call went the way it did"
}
```

Unknown keys are rejected. A typo in a hand-edited fixture should stop the run,
not be silently ignored.

| Field | Required | Notes |
|---|---|---|
| `id` | yes | unique across the directory; conventionally the filename stem |
| `status` | yes | `annotated` or `placeholder` |
| `document.text_file` | yes | sibling `.txt` filename |
| `document.title` | yes | the document's own title |
| `document.source_url` | no | `null` for synthetic fixtures |
| `document.source_kind` | yes | `cisa` \| `acsc` \| `vendor_blog` \| `synthetic` |
| `document.published_on` | no | `YYYY-MM-DD` |
| `annotated_by`, `annotated_on`, `notes` | no | provenance; not scored |

### `status`

`placeholder` fixtures are skipped by the harness and counted in the scorecard.
An empty annotation is ambiguous — it means either "this document genuinely
names no actors" (a real and valuable negative case) or "nobody has annotated
this yet" — and scoring the second as the first reports a fabricated recall of
1.0. Set `status` to `annotated` only when you have read the whole document,
including when the correct annotation is an empty list.

---

## Annotation rules

### Actors

Use the **MISP canonical name** (`threat_actor.canonical_name`). A known alias
also works — the loader resolves gold names through the same `ActorIndex` the
pipeline applies to model output, so both sides are compared as the same
entity, which is the entire point of guardrail 4. If a name resolves to
nothing, the loader reports it as a gold-set defect and the scorecard lists it
separately from anything the model did.

- Annotate actors the report **names**. If the report describes activity
  without naming a group, the correct annotation is an empty list.
- Do not add an actor from your own knowledge because you recognise the
  tradecraft. §5.2 guardrail 5 forbids the model from doing that; the gold set
  has to hold itself to the same rule or it penalises the behaviour it wants.
- `attribution_confidence` is recorded but **not scored**. §7 lists
  precision/recall over actors, techniques and targets; adding an unrequested
  dimension to the headline metric would make it harder to compare against the
  target, not easier.

### Techniques

- Only ATT&CK **enterprise** IDs present in `attack_technique`. A gold ID the
  closed-world guardrail would reject is unscoreable — the pipeline can never
  produce it, so it is a guaranteed false negative that measures the
  annotation rather than the model. The loader flags these.
- Annotate at the granularity the **document** supports. If the text says a
  malicious attachment arrived by mail, that is `T1566.001`. If it says only
  "a phishing campaign", annotate `T1566` and stop. Scoring runs at both
  sub-technique and parent granularity, so a defensible parent-level
  annotation is never punished by the parent-level metric.
- Annotate the behaviour, not the vocabulary. "The operators scheduled a task
  that relaunched the loader hourly" is `T1053.005` whether or not the phrase
  "scheduled task" appears.

#### `explicit_in_text` — the field that makes the baseline worth running

`true` when the technique ID is **written in the document** (an ATT&CK table,
an inline `T1059.001`). `false` when the behaviour is described in prose and
only a reader who knows ATT&CK maps it.

This is what §7's baseline comparison rests on: a regex can only find the
`true` ones, so the model's recall on the `false` subset is its measured lift.
Getting this field wrong does not change the headline F1, but it silently
destroys the lift number, which is the most interesting line in the scorecard.

Judgement call: if the document spells out the technique's exact ATT&CK **name**
("Spearphishing Attachment") without the ID, mark it `false` — the regex
baseline matches IDs, not names, so it cannot reach it.

### Targets

**Victims only.** The attacker's suspected origin country is never a target —
that mirrors the rule in the system prompt, and it is the specific place the
keyword baseline is expected to lose (it tags "Russian actors targeting
Ukrainian energy" with both RU and UA).

- `country` is ISO 3166-1 alpha-2, uppercase.
- One entry per (country, sector) pair the report supports. Country and sector
  are **scored as two separate fields**, not as pairs, so a target with only
  one of the two is fine and costs nothing on the other field.
- Do not infer a country from an actor's usual targeting or from a vendor's
  headquarters. If the report says "European energy operators" with no country
  named, annotate `{"sector": "energy"}` and leave `country` out.

#### Sector vocabulary

Sectors are scored as exact strings after normalization, so the annotation must
use this vocabulary. It is the SOCI Act critical infrastructure sector list
(DESIGN.md §1) plus the non-SOCI sectors that dominate CTI reporting. The list
and its synonym map live in [`../vocab.py`](../vocab.py).

```
communications                  government
data storage and processing     manufacturing
defence industry                technology
energy                          media
financial services              retail
food and grocery                legal
health care                     military
higher education and research   ngo
space technology
transport
water and sewerage
```

Common surface forms are mapped for you (`healthcare` → `health care`,
`telecom` → `communications`, `aviation` → `transport`, `energy sector` →
`energy`). Anything outside the vocabulary is left as-is and reported as
off-vocabulary rather than silently coerced — a model answering "aerospace" is
a vocabulary gap to fix in the prompt, not an error to hide. If a document
needs a sector that genuinely is not on the list, add it to `SECTORS` in
`vocab.py` in the same commit as the fixture.

---

## What is deliberately not annotated

`summary`, `report_date`, `confidence`, `attribution_confidence` and `iocs`.
§7 names four metrics — precision/recall/F1 over actors, techniques and
targets, plus evidence-quote validity — and the gold set covers exactly those.
Annotating fields nobody scores costs annotation time, which is the binding
constraint on getting to 30 documents, and invites a scorecard that reports
numbers without a target attached to them.

IOC extraction is covered by the guardrail tests in `pipeline/tests/`, where
correctness is a property of the defanging code rather than a judgement call.

---

## Workflow

```bash
# 1. add the .txt and .json pair, status "placeholder"
# 2. annotate, flip status to "annotated"

# 3. lint the gold set and see the keyword floor -- no API calls, no cost
uv run python -m eval.run_eval --baseline-only

# 4. score the live pipeline against it
uv run python -m eval.run_eval
uv run python -m eval.run_eval --backend both     # + the §7 cross-backend table
```

Step 3 is the one to run after every annotation. It loads and validates every
fixture, resolves each gold actor and technique against the database, and
reports any it cannot express — for free.
