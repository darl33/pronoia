# Implementation decisions

Why the code does what it does. [DESIGN.md](DESIGN.md) is the specification —
architecture, schema, threat model, methodology. This is the record of the
judgement calls made while implementing it: the ones where a reasonable
alternative exists, where the obvious approach is wrong, or where a value was
chosen empirically.

**The convention this document exists to support:** comments in the codebase
are short and operational — what a line does, what a constant is for, what a
caller must know. Rationale lives here, one section per decision, referenced
from code as `# see docs/DECISIONS.md#anchor` where a reader would otherwise
have to guess. Keeping it in one place means the reasoning can be read as an
argument rather than reconstructed from forty files, and it stops the same
paragraph being re-explained at three call sites.

Section numbers in `§n` form refer to DESIGN.md.

---

## 1. Ingestion

### <a id="request-headers"></a>Request headers: bare User-Agent, gzip only

Both values were found empirically against the real feeds and both are pinned
by `tests/test_request_headers.py`.

**`User-Agent: Pronoia-Ingest/0.1`**, deliberately with no `(+https://...)`
bot-announcement suffix. ACSC's edge resets the connection (HTTP/2
`INTERNAL_ERROR`) for *any* `(+url)`-style UA — including a genuine Googlebot
string — but serves a bare one.

**`Accept-Encoding: gzip`**, set explicitly to override httpx's default of
`gzip, deflate`. CISA's edge returns 403 to any request advertising `deflate`.
This was originally misdiagnosed as a User-Agent problem; isolating header by
header showed the same bare UA gets 403 with `gzip, deflate` and 200 with
`gzip`, on CISA, ACSC, Talos and raw.githubusercontent alike. Narrowing to gzip
also slightly shrinks the §6 decompression-bomb surface — one decoder instead
of three — though the byte cap on the *decoded* stream is the real control
regardless of which encoding a server picks.

### <a id="ssrf"></a>SSRF: validate the address, then pin it

Checking the hostname string is not enough. The resolver is re-run and
re-validated on every redirect hop, and the address used for the actual TCP
connect is the exact one that was validated — otherwise a second,
attacker-controlled DNS answer at connect time reintroduces the hole (DNS
rebinding). Rejected ranges include RFC1918, loopback, link-local, and the
169.254.169.254 cloud metadata address.

### <a id="xxe"></a>XXE: reject DOCTYPE outright

`defusedxml` already blocks external entity expansion, internal entity
expansion and billion-laughs bombs. `forbid_dtd` goes further and rejects any
DOCTYPE declaration at all, rather than trying to distinguish a "safe" DOCTYPE
from a malicious one.

`ingest/sanitize.py` uses the stdlib `html.parser` backend rather than an
lxml-backed one, so HTML extraction carries no XXE surface of its own,
independent of `xml_safe.py`.

### <a id="article-bodies"></a>Following feed links for article bodies

ACSC publishes one-line teasers (85–300 characters), which left `raw_document`
rows with nothing for §5 extraction to work with. Talos already ships full
posts in `<content:encoded>` (~11k characters), so following its links would be
15 pointless requests per poll. Hence `feed.fetch_articles`, opt-in per feed.

Following links out of feed *content* widens the SSRF surface, so it is
narrowed three ways: `same_site` restricts targets to the feed's own host;
every request still goes through `fetch_url` (https-only, DNS validated and
pinned, redirects re-validated, 10 MB cap); and any failure falls back to the
feed content rather than losing the document. `same_site` is the load-bearing
one — `ssrf.py` validates *addresses*, but only a same-site check stops feed
content pointing the fetcher anywhere on the internet.

### <a id="dedup-hash"></a>Hash the feed entry, not the fetched page

The content hash is taken from the feed entry before any article body replaces
it. Hashing the fetched page would tie document identity to the publisher's
template, so a rotating banner or build-id comment would produce a new
`raw_document` on every poll. Dedup is also checked *before* the article
request: the insert would deduplicate anyway, but only after re-requesting
every article, every poll.

### <a id="attack-bundle-cap"></a>Raising the size cap for the ATT&CK bundle

The 10 MB transport cap is a decompression-bomb defense for untrusted feed
content. The ATT&CK STIX bundle is a pinned, known-good file from a fixed URL
that is legitimately ~55 MB, so the cap is raised for that one call rather than
weakened globally.

---

## 2. Reference data

### <a id="closed-world-contents"></a>What goes in `attack_technique`

This table is the closed world guardrail 2 validates against, so its contents
are a security-relevant decision rather than a data load. Revoked and
deprecated techniques are skipped — keeping them would let the model cite
retired IDs and have them pass the check. Only `attack-pattern` objects
carrying an ATT&CK `external_id` are used; the bundle also holds groups,
software, mitigations and relationships.

**Known schema gap.** §4 models `tactic` as a single TEXT column, but ATT&CK
techniques are genuinely many-to-many with tactics (T1055 is both
defense-evasion and privilege-escalation). The loader joins them to preserve
the data; dropping to one would silently lose it. The real fix is a join table,
noted as an open schema question.

### <a id="misp-origin"></a>`suspected_origin_country` is reference data, not attribution

It comes from the MISP cluster's `meta.country` and records what the CTI
community reports about an actor — §4 is explicit that the column holds origin
"as *reported*". It is not, and must not become, a per-report attribution:
guardrail 5 keeps the model from inferring origin, and this column is never
consulted when writing `report_actor`.

---

## 3. The extraction contract

### <a id="extra-forbid"></a>`extra="forbid"` on every contract model

A model that invents a field has drifted from the contract. Burning the one
retry to make that visible beats silently accepting a payload we do not
understand. The same rule applies to the gold-set schema in `eval/gold.py`,
where a typo'd key in a hand-edited fixture should stop the run rather than be
ignored.

---

## <a id="guardrails"></a>4. Guardrails (§5.2)

`enrich/validate.py` composes 2, 3, 4 and the IOC rule. Nothing there trusts
the model: an Extraction that passed guardrail 1 is well-formed, not correct.
It can still name techniques that do not exist, quote text that is not in the
document, name actors nobody has heard of, and label a URL as a hash. Drops are
*returned*, not merely logged, so the caller can report them and the §7 harness
can measure them per (model, prompt_version).

### <a id="g1-structured-output"></a>1. Structured output

Asking for JSON is not the control — models wrap it in fences, prepend prose,
or invent fields. The control is: strip fences, `model_validate_json`, and on
failure record `invalid_json` or `schema_fail` on the `enrichment_run` and retry
once with the validation error appended.

Only a fence enclosing the *whole* response is stripped. A response with prose
around a fenced block is a contract violation, not something to salvage —
salvaging it would hide the failure from the eval.

Two attempts, capped on purpose: a model that fails the contract twice with the
error in front of it will not succeed on the third, and an uncapped retry loop
against a paid API is how a pipeline quietly bankrupts itself. Failed attempts
stay as rows, so recurring schema failure is visible in the data, not just logs.

Splitting `invalid_json` from `schema_fail` is what makes the failure legible:
the first says the model did not emit JSON, the second says it emitted JSON that
is not this contract.

Token usage and stop reason are carried from `CompletionResult` for cost
tracking and truncation detection. They are recorded and logged but never
branched on — the guardrail decides on the parse result alone, whatever the
provider claims.

### <a id="g2-closed-world"></a>2. Closed-world technique IDs

Telling the model to emit only real ATT&CK IDs is not the control; checking
every ID against `attack_technique` afterwards and dropping it if absent is.
Inventing plausible-looking IDs (T1566.004, T1071.005) is the single most
common hallucination class in this task, and a set membership test kills all of
it.

Well-formedness is checked before membership only so the log line can
distinguish "made up an ID" from "emitted something that is not an ATT&CK ID at
all".

### <a id="g3-evidence-quotes"></a>3. Evidence quotes

Every technique mention carries a quote, and that quote must appear as a
substring of `clean_text` after normalization or the mention is dropped. This
converts an unfalsifiable claim ("the report describes spearphishing") into a
checkable one.

Normalization is applied to *both* haystack and needle, so these are
canonicalizations rather than a relaxation of the match — the same input always
lands on the same form.

**Forgiven**, because the HTML→text path and vendor CMSes introduce them while a
model re-typing the sentence will not: whitespace runs, NFKC-foldable Unicode,
and typographic variants with an ASCII equivalent (curly quotes, dashes).

**Not forgiven**: case, because verbatim means verbatim and re-casing is
paraphrase; and elision, because a quote is not evidence of what sits inside its
"...".

The 20-character floor is a weaker second check: a span short enough to occur
incidentally ("the attacker") is not evidence even when it is present.

### <a id="g4-actor-resolution"></a>4. Actor resolution

The model emits free-text actor names — whatever the report called them. Python
resolves those against `threat_actor` canonical names and aliases:
case-insensitive exact match first, then difflib fuzzy matching above a 0.9
ratio. Anything unresolved goes to `actor_review_queue` for a human, never into
`report_actor`.

The point is that the actor dimension stays trustworthy. One report's "Sandworm
Team" and another's "APT44" have to become the same row or §8's correlation
queries are meaningless, and an unrecognized name has to stay visibly
unrecognized rather than quietly becoming a new actor.

**First writer wins** on alias collisions. MISP aliases collide across clusters
(several groups claim "APT15"), and silently rebinding a name to whichever
cluster loaded last would be worse than keeping it stable.

### <a id="g5-attribution"></a>5. Attribution discipline

Lives in prompt text: record attribution as the source states it, set
`attribution_confidence` from the source's own language, never infer a country
of origin or a sponsor. `targets` are the victims described, never the
attacker's suspected origin.

### <a id="g6-prompt-injection"></a>6. Prompt injection

Half in `prompts/extract_system.md` — the "this is data, not instructions" rule
— and half in `enrich/prompt.py`, which strips the closing marker from the
document before enclosing it, because a delimiter the payload can forge is not
a delimiter.

The real defense is structural: a successful injection still has to pass schema
validation, the closed-world check and evidence quoting, so the blast radius is
one bad row.

**Prompt versioning.** `prompt_version` is the git tree hash of `prompts/`,
computed from working-tree content. It matches
`git rev-parse --short HEAD:pipeline/enrich/prompts` when the directory is clean
but is defined mid-edit too, so a run is attributable to the exact prompt bytes
that produced it — which is what §7's per-(model, prompt_version) scorecards
need.

---

## 5. <a id="ioc-defang"></a>IOC defanging

Two things happen, and the second matters more than the first.

1. **Defanging proper**: `hxxp` / `[.]` / `[:]` / `[@]` substitution, so a stored
   indicator cannot be clicked, resolved, or pasted into a browser by accident.
2. **Kind/value agreement.** The `kind` field comes from the model, and defanging
   is kind-specific — so a mislabelled IOC is a defanging bypass. A live URL
   emitted as `kind='sha256'` would be stored verbatim and fanged if the label
   were trusted. Every value is validated against its claimed kind and dropped on
   mismatch, rather than stored under a kind we cannot defang.

The fanged form exists only inside `defang_ioc`, to normalize input the model may
have already defanged. It is never returned and never persisted. For the same
reason a dropped IOC's raw value is deliberately absent from the drop record:
it may be a live indicator, and drops get logged.

Only the authority is dot-escaped in a URL; escaping dots in the path would
corrupt the indicator, since a filename in the path is part of it.

---

## 6. Provider abstraction and configuration

### <a id="two-slots"></a>Two slots, not one

`CompletionClient` and `EmbeddingClient` are separate protocols because
Anthropic has no embeddings API, so the completions provider and the embeddings
provider are *always* different services here. An abstraction covering only the
first is not "BYO model".

`complete()` returns a result object rather than a bare `str` so token usage and
stop reason survive; it does not parse, validate or retry, which is guardrail
1's job and keeps that guardrail portable across providers.

Two completion implementations and deliberately no more: `AnthropicClient` and
one `OpenAICompatibleClient` reaching Ollama, vLLM, LM Studio, OpenRouter and
Groq. N vendor clients would buy almost nothing on top of it — which is also why
that one adapter's response parsing is load-bearing in a way a per-vendor
client's would not be, and is tested against canned responses.

Adapter details worth knowing: the Anthropic path uses adaptive thinking, which
puts thinking blocks in `content` alongside the text, so only text blocks are
the answer. The OpenAI-compatible path sends `max_tokens`, not
`max_completion_tokens` — the older spelling is what every local runtime
accepts, and reaching those is the entire point. Embedding responses are sorted
by `index` because providers may return out of order, and a permuted batch
attaches every vector to the wrong report.

### <a id="key-inference"></a>Provider inferred from the key (§5.4)

Resolution order: explicit `LLM_BASE_URL`, else infer from the `LLM_API_KEY`
prefix, else probe localhost. Each provider carries a default base URL and
model, so a bare key is a working configuration.

The prefix table is ordered longest-first, and asserted so: `sk-ant-`,
`sk-proj-` and `sk-or-v1-` all start with `sk-`, so a shortest-first table would
resolve every Anthropic key to OpenAI.

An explicit base URL alongside a recognized key means an OpenAI-compatible proxy
in front of the vendor, so it also switches off the native SDK path.

An unrecognized prefix raises a `ConfigError` naming `LLM_BASE_URL` rather than
crashing. Every config message names the variable that fixes it; a config error
the reader cannot act on is worse than no message.

The zero-key path probes `localhost:11434` (Ollama) and `localhost:8000` (vLLM).
Both speak OpenAI-compatible `/v1`, so one probe covers them and neither needs a
vendor client.

### <a id="embeddings-degrade"></a>Embeddings degrade, never block

`resolve_embedding` never raises. If nothing resolves, `report.embedding` stays
NULL and everything except semantic search works untouched — that is what keeps
the one-key promise. Failure to embed a single document is likewise non-fatal.

If the completion provider has no embeddings API, the resolver looks for a local
one: a reviewer running Ollama for embeddings and a hosted key for extraction is
an ordinary setup that should need no configuration.

`request_dimension` is only sent to providers that accept an OpenAI-style
`dimensions` parameter — sending it elsewhere is a 400. For those that do, asking
for the width the schema already has is the difference between OpenAI's
1536-wide default working out of the box and silently degrading against
`VECTOR(1024)`.

Vector width is **measured, not looked up by model name**: the same name is
served at different widths in practice, and a guessed `embedding_dim` would
defeat the point of recording provenance.

### <a id="doctor"></a>`pronoia doctor`

Resolves config, makes one cheap round-trip per endpoint, and prints what is
enabled, what is degraded and the env var for each gap. Prevents discovering a
bad key three hours into a batch run, and makes §5.4's claim checkable rather
than asserted.

Round-trips are free or near-free — `count_tokens`, `GET /v1/models`, one short
embed. A diagnostic that costs money is one people stop running.

An expired key, a wrong model id, a rate limit and an empty credit balance all
arrive as one HTTP error with four different fixes, so the provider's own
`message` is quoted rather than a fix being guessed.

`REPORT_EMBEDDING_DIM` must equal the migration's `VECTOR(n)`. Nothing makes
them agree automatically and drift fails every embedding write at INSERT time,
so doctor reads the column's real width from `pg_attribute.atttypmod` — pgvector
stores the declared dimension there and has no `information_schema` equivalent.

---

## 7. <a id="context-budget"></a>Context budget: chunking and merging (§5.3)

### Estimating tokens

`CHARS_PER_TOKEN = 3.5` is low on purpose. English prose runs nearer 4.0, so 3.5
over-estimates the cost of a chunk and errs toward chunks that are too small.
The other direction is a context-length error mid-batch — the exact failure this
exists to prevent — and no generic tokenizer is available, because the
OpenAI-compatible adapter reaches runtimes whose tokenizer cannot be known from
here.

`RETRY_RESERVE_TOKENS` leaves room for the retry prompt, which re-sends the
document with the validation error appended. Without it a document that just
fits would overflow on the retry, turning a recoverable schema failure into an
unrecoverable context error.

Prompt overhead is *measured* from the real prompt files (rendering the template
with an empty document) rather than estimated: the system prompt and the user
template both charge against the same window the document does.

### Per-backend defaults

| Backend | input | output |
|---|---|---|
| Anthropic | 150,000 | 16,000 |
| Other hosted | 100,000 | 16,000 |
| OpenAI-compatible / local | 6,000 | 2,048 |

All well below each vendor's real window, because the budget is a
character-heuristic estimate and the cost of being wrong is a hard failure at
the top of the range against one extra call near it.

The local default is deliberately small: `/v1/models` does not report a context
window, so it cannot be discovered, and an 8k model is the common case for an
unconfigured reviewer. Chunking a document that would have fit costs an extra
call; not chunking one that does not fit loses the document entirely.

**Output is capped alongside input** because the two share one window. Asking an
8k model for 16k of output is a hard error on vLLM and a silent clamp on Ollama,
so the local pair (6k + 2k) has to fit inside 8k. 2k is enough for a chunk's
worth of extraction JSON with quotes.

`MAX_INPUT_TOKENS` and `MAX_OUTPUT_TOKENS` override both. A bad value warns and
falls back rather than raising — these are tuning knobs, and a typo should not
stop a batch that runs fine on the default. A budget too small to fit any
document *is* fatal, and is checked once at startup per §5.4's "fail at config
time, not mid-run".

### Splitting

**Every chunk is a contiguous slice** of `clean_text`, produced by slicing and
never by splitting and rejoining. A span the model copies out of a chunk is
therefore still verbatim in the whole document, which is what keeps
[guardrail 3](#g3-evidence-quotes) working — otherwise it would drop the model's
*honest* quotes on exactly the long documents chunking exists to rescue.

Breaks land on the largest available boundary: paragraph, then sentence, then
word, then a hard cut. A technique is normally described within one paragraph,
so an evidence sentence is rarely severed. The tiers exist so the hard cut — the
only break that can sever a sentence — is reached only by pathological input,
such as a base64 blob that survived sanitization.

**No overlap.** It would double-bill boundary sentences on precisely the small
backends being chunked, to insure against a boundary that paragraph-splitting
already avoids. The merge is a union anyway.

### Merging

Only `actors`, `techniques`, `targets` and `iocs` are genuine unions with dedup.
The three scalars cannot be, and each is a documented loss:

- **`summary`** becomes a concatenation of per-chunk summaries, truncated to the
  contract's cap at a sentence boundary where possible. It is no longer an
  abstract of the document, because no call saw the document. This is the most
  visible cost of chunking, and `summary` is the one field rendered as prose in
  the UI (§9.2), so a mid-sentence cut would show.
- **`report_date`** takes the first stated, in document order. Reports state the
  date of the activity early, and a later date usually refers to prior reporting.
- **`confidence`** takes the *lowest*. A record assembled from fragments cannot
  honestly be more confident than its least confident fragment.

Within the unions: the **strongest** attribution the source stated anywhere wins,
because guardrail 5 forbids inferring beyond the source, not reading it at its
word. The **first** evidence quote wins for a repeated technique, matching
`validate.py` — `report_technique` holds one quote per (report_id, technique_id).

### Partial failure

A chunked document whose third chunk fails still merges the chunks that worked.
That is the degradation §5.3 asks for — the alternative is discarding four good
chunks because the fifth returned bad JSON — but it is silent under-extraction
unless counted, so failed chunks are logged by the pipeline and reported per
backend in the §7 scorecard.

**Chunking degrades rather than fixes.** The honest framing is that the pipeline
*runs* everywhere, and the cross-backend scorecard reports what running it on a
small context window costs.

---

## 8. Persistence

### <a id="transaction-shape"></a>Transaction shape

Each attempt's `enrichment_run` row is committed on its own, before the report is
written. A failed or crashed run must still leave its audit trail
([guardrail 1](#g1-structured-output)), which it would not if the run rows shared
a transaction with the report insert and rolled back with it.

`raw_response` is JSONB and the whole point is auditing what the model said —
including when that was not valid JSON — so the unparseable case is wrapped as a
JSON string rather than dropped.

`report.enrichment_run_id` is a single FK, so a merged extraction from five
chunks has to name one of them. The **first** ok run is used: it is the only
choice stable across re-runs.

`chunk_index` is NULL unless the document was chunked. Without the column, a
chunked document writes several rows that all read `attempt = 1`, and the audit
trail becomes unreadable for exactly the documents most likely to fail.

### <a id="embedding-provenance"></a>Embedding provenance and re-embedding

`embedding_model` and `embedding_dim` travel with the vector in one statement — a
vector that outlives its provenance is the mixed-vintage state §5.3 exists to
prevent, and the CHECK constraint would reject the intermediate anyway.

`scripts/reembed.py` makes §5.3's "BYO at deployment, not hot-swappable"
migration path real rather than hypothetical. It is safe to re-run after an
interruption: the work query skips rows already on the configured model
(`IS DISTINCT FROM`, so never-embedded NULL rows match too) and each batch
commits on its own, so a second run resumes where the first stopped and a
completed run is a no-op. Deliberately not one big transaction — that would hold
locks throughout and lose all progress on any failure, the opposite of what a
recovery tool should do.

### <a id="schema-ownership"></a>Schema ownership

`db/migrations` owns the schema. The SQLAlchemy Core table definitions in
`ingest/db.py` and `enrich/db.py` mirror it exactly and never define it; the
enrichment tables share ingest's `MetaData` so `raw_document` is resolvable for
foreign keys and joins. All helpers are bound-parameter only — §6: "no
string-built SQL anywhere".

---

## 9. Evaluation harness (§7)

### <a id="eval-isolation"></a>Nothing in `eval/` writes to the database

It reads reference data so the guardrails it exercises are the real ones, and
runs against fixtures in `gold/`. An eval must not be able to contaminate the
dataset it is measuring. The harness calls `extract_document` and
`validate_extraction` directly rather than reimplementing them — §7 measures "the
live pipeline", so anything reimplemented would be a second, unshipped system
whose scores describe nothing. The one omitted step is the database write.

### <a id="metric-conventions"></a>Metric conventions

Hand-written and dependency-free: every metric reduces to comparing two sets and
counting the three ways they disagree, which a reader can check in a minute. An
eval framework would add a vocabulary and hidden averaging defaults in exchange
for nothing.

Three conventions are load-bearing, so they are stated rather than inherited:

1. **Zero denominators.** Predicting nothing scores 1.0 only when there was
   nothing to find. Silence on a document with three actors is 0.0, not vacuous
   perfection. A degenerate empty/empty document scores 1.0 by convention rather
   than performance, and is excluded from the macro mean so a gold set full of
   empty fields cannot inflate its own numbers.
2. **Micro is the headline.** Pooling tp/fp/fn before dividing gives every gold
   item equal weight; macro is dominated by one-item documents. Macro is reported
   beside it, since a large gap means performance depends on document length.
3. **A failed extraction is scored, not skipped.** No rows written means every
   gold item is a false negative — what the dataset would actually look like, and
   the honest treatment for the cross-backend comparison, where a small local
   model fails outright more often than it extracts badly.

`rate()` returns None rather than 0.0 on an empty denominator: "no quotes
emitted" and "every quote invalid" are opposite findings and must not print
identically.

Set membership is exact string equality, so every normalization (granularity,
actor canonicalization, sector vocabulary) happens in the caller where it is
visible. Fuzzy matching hidden inside a scorer is how eval numbers stop meaning
anything.

### <a id="what-is-compared"></a>What gets compared to what

- **Techniques are scored twice**, at sub-technique and parent granularity, never
  merged into one number. Sub-technique choice is often a judgement the source
  does not settle (is a mailed link T1566.001 or .002?) while the parent claim is
  not, which is why §7 sets its >0.85 target at parent granularity. Both are
  reported so the gap shows how much error is granularity rather than substance.
  Rolling up collapses: predicting T1566.001 and T1566.002 against a gold T1566
  is one correct claim, not a hit plus a false positive.
- **Targets are scored as two fields, not pairs.** Gold (AU, water) against a
  predicted (AU, null) is one hit and one omission; scoring the pair jointly
  would record a total miss on both. The country set is also what §8's
  `/correlate` consumes.
- **Actors are scored on resolved identity**, not the model's raw string:
  guardrail 4 exists so "Sandworm Team" and "APT44" become one row, and an eval
  comparing raw strings would mark the system wrong for succeeding at that.
  Unresolved actors are counted, not scored — they never reach `report_actor`, so
  they are not part of the output and cannot be false positives. The count is
  reported because a rising review-queue rate is a reference-data problem, not a
  model one.
- **Only recall is reported on the implicit-technique subset.** Predictions carry
  no explicit/implicit label — that annotation exists on the gold side only — so
  a false positive cannot be attributed to the subset. Recall is well defined
  there; precision is not.

Evidence-quote validity is recomputed rather than read off `validate_extraction`'s
drop list, which checks the closed world first and short-circuits: a hallucinated
ID never reaches the quote check, so counting drops would shrink the denominator
and flatter the rate. §7 wants the rate over every quote the model wrote.

### <a id="gold-set"></a>The gold set

A fixture is a pair of files: a `.json` annotation and the `.txt` document it
annotates. The split is not cosmetic — report text is thousands of characters
with meaningful line breaks, and inlining it as a JSON string makes the one thing
a human must read while annotating unreadable and every diff useless.

Validation at load time is deliberately loud. The failure this prevents is a gold
set that quietly disagrees with the system's vocabulary — an actor name not in
MISP, a technique ID ATT&CK retired, a sector spelled a way nothing will produce.
Each silently depresses the score and looks exactly like a model failure. So the
loader resolves the annotation through the *same* indexes the pipeline uses and
reports what it could not resolve as a **gold-set defect**, separately from
anything the model did. A gold ID the closed-world guardrail would reject is
unscoreable: the pipeline can never produce it, so it is a guaranteed false
negative that measures the annotation, not the model.

`explicit_in_text` is the annotation that makes the baseline comparison worth
running. True means the ID (or its exact ATT&CK name) is written in the document,
so a regex can find it; false means the behaviour is described in prose and only
a reader who knows ATT&CK maps it. §7's claim is that the LLM's lift shows up on
the false ones, and this field is what turns that into a measurement.

`status: placeholder` fixtures are skipped and counted. An empty annotation means
either "this document names no actors" or "nobody has annotated it yet", and
scoring the second as the first reports a fabricated recall of 1.0.

Full annotation format: [`pipeline/eval/gold/README.md`](../pipeline/eval/gold/README.md).

### <a id="baseline"></a>The non-LLM baseline

Regex for technique IDs the document cites by ID, alias string matching for
actors. It is built to be beaten, and its weaknesses are the argument:

- **Techniques.** It finds one only where the document writes the ID out, so its
  recall is roughly the `explicit_in_text` fraction of the gold set. The gap
  between that and the model's recall on the implicit subset is what §7 wants.
- **Actors.** Alias matching is genuinely strong here. If the LLM does not beat
  it by much, that is a true finding rather than a broken baseline.
- **Targets.** It cannot tell a victim from an attacker: "Russian actors
  targeting Ukrainian energy" yields RU and UA where the gold has only UA.
  Precision suffers exactly where the prompt's attribution discipline works.

It must be beaten *fairly*, and must not get quietly cleverer — matching
technique *names*, or learning to read context, would shrink the measured lift
without anyone noticing. So it shares the closed-world check and the
country/sector vocabulary with the real path, and its known limits are asserted
in tests rather than merely tolerated.

Implementation choices that keep it a fair floor: aliases below a minimum length
are dropped, because MISP carries fragments like "APT" and bare group numbers
that match half of English — a baseline is allowed to be dumb, but one that tags
every document with six actors is noise, not a floor. Matches resolve to
canonical names so its output is in the same vocabulary as the LLM path's.
First writer wins on collisions, mirroring `ActorIndex`, so answers do not depend
on JSON key order. Alias search is one longest-first alternation rather than ~5k
searches per document, and longest-first matters: "APT 28" must win over "APT 2".

The baseline cites IDs verbatim from the document, so its evidence validity is
trivially 1.0 and its closed-world pass rate is whatever ATT&CK says about the
IDs the author wrote. Both are recorded for shape parity; neither is an
interesting number, and the scorecard prints them as n/a rather than as
achievements.

### <a id="vocab"></a>Controlled vocabularies

`normalize_sector` is applied to *both* sides before scoring: without it
"healthcare", "Health Care" and "health sector" are three answers and the sector
metric measures spelling. Only unambiguous synonyms belong in the map — the
temptation is to add "utilities" (energy? water?) or "critical infrastructure"
(all of them), and guessing there would fabricate agreement between the model and
the annotator. Trailing nouns that add nothing ("energy sector" → "energy") are
stripped only *after* a direct lookup fails, so "defence industry" resolves as
itself rather than being truncated to "defence".

Anything outside the vocabulary is left as-is and counted as off-vocabulary
rather than coerced: "aerospace" should surface as a vocabulary gap to fix in the
prompt, not disappear.

`COUNTRY_NAMES` is how the baseline finds target countries at all. It is
deliberately partial and hand-written: growing it would make the baseline
stronger without making it smarter, and the honest limitation to state is "the
baseline knows these names and no others" — which is only honest if the list is
visible in one place. Two-letter abbreviations are matched **case-sensitively**,
because a case-insensitive "US" also matches the pronoun and "in"/"it" are
prepositions; folding case would put a country on nearly every document.

### <a id="scorecards"></a>Scorecards

One per (backend, model, prompt_version). Being committed output explains two
otherwise-fussy properties: the filename is keyed on that triple so a re-run
overwrites its own cell instead of accumulating near-duplicates, and the run
metadata — timestamp, git commit, whether the tree was dirty — lives *inside* the
file. A scorecard you cannot attribute to a commit is decoration, and numbers
from a dirty tree replicate from no commit at all.

§7's >0.85 parent-F1 target applies to the primary backend only; alternative
backends are characterized, not gated, so the line is printed for every backend
and asserted for one.

The cross-backend comparison is keyed on `prompt_version` alone, because the
table is only meaningful with the prompt held constant. The baseline column is
shared: it does not depend on the backend, so it is the fixed floor both are read
against.

`--backend primary` is normal config resolution; `--backend local` reads
`EVAL_LOCAL_BASE_URL` / `EVAL_LOCAL_MODEL`, falling back to `LLM_BASE_URL` /
`LLM_MODEL`. Separate variables for one reason: `--backend both` holds two
configurations at once, and sharing them would collapse the comparison into a
model against itself. Unlike the pipeline's own resolution, the eval refuses to
fall back to the first advertised model — an unidentified model in a committed
scorecard defeats the scorecard's whole point.

`--baseline-only` writes no scorecard: a scorecard is a claim about a (model,
prompt_version) pair, and there is no model in that run.

---

## 10. Testing

Everything in fixtures is synthetic per the repo rule: RFC 5737 documentation
addresses (192.0.2.0/24), RFC 2606 reserved domains (`.example` / `.invalid`),
and hashes made of repeated hex. No real indicator appears anywhere in the repo,
fanged or defanged.

Guardrails 5 and 6 live partly in prompt text, which a unit test cannot assert
the model obeys — that is what the §7 eval measures. What is testable is the
mechanical half: the rules are present in the versioned prompt that gets sent,
the report text is enclosed as data, and a document cannot forge its way out of
that enclosure. The structural defense §5.2 calls the real one is covered by the
other guardrail tests.

`test_validate_extraction.py` runs one schema-valid Extraction carrying a good
and a bad instance of every failure mode through `validate_extraction`. It is the
test that would catch a guardrail implemented correctly but never wired into the
write path.

Local discovery is monkeypatched in the config tests so the suite passes
identically with and without Ollama running. `prompt_version` deliberately tracks
the working tree rather than HEAD, so a test comparing the two skips rather than
fails while `prompts/` is dirty.
