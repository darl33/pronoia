# pronoia
connecting CTI reporting to geopolitical events

## Configuration

The only variable you need is `LLM_API_KEY`. The provider, base URL and model
are inferred from the key prefix (`sk-ant-` → Anthropic, `sk-` → OpenAI, `gsk_`
→ Groq, `sk-or-v1-` → OpenRouter), and `LLM_BASE_URL` / `LLM_MODEL` override
that when set. With no key at all, `http://localhost:11434` (Ollama) and
`http://localhost:8000` (vLLM) are probed at startup, so a fully local run
needs no configuration whatsoever.

Embeddings are a separate provider and are optional: if none resolves, the
pipeline skips embedding, `report.embedding` stays NULL, and everything except
semantic search works untouched.

To see exactly what resolved, what is degraded, and which variable fixes each
gap:

```bash
cd pipeline && uv run pronoia doctor
```

## Changing the embedding model

If you are here because `/search` returned a **503**, that is the system
refusing to compare vectors from two different embedding models. Skip to
[the fix](#the-fix). The rest of this section explains why the error exists and
why changing the model is a migration rather than a config edit.

### Why the dimension is fixed, and cannot be hot-swapped

`report.embedding` is declared `VECTOR(1024)` in
[`db/migrations/20260725000001_enrichment_layer.sql`](db/migrations/20260725000001_enrichment_layer.sql).
That number is a **setup-time decision**, not a runtime setting. Two consequences
follow, and neither has a clever workaround:

1. **A different model usually means a different width.** `text-embedding-3-small`
   is 1536 dimensions, `nomic-embed-text` is 768, `mxbai-embed-large` is 1024.
   Postgres will not put a 1536-wide vector into a `VECTOR(1024)` column, so
   pointing `EMBEDDING_MODEL` at a new model does not silently work — it fails.
2. **Same width is not the same space.** Two 1024-dimensional models produce
   vectors that *fit* the column and are still meaningless to compare. Cosine
   similarity between them returns confident, well-formed, wrong answers. This
   is the worse failure, because nothing errors.

So embeddings are BYO **at deployment**, not hot-swappable. What the system does
instead of pretending otherwise: every embedded row records `embedding_model`
and `embedding_dim`, so mixed vintages are *detectable*, and `pipeline/scripts/reembed.py`
exists so the migration path is real rather than hypothetical.

### What a change actually requires

| Changing to a model with… | You need |
|---|---|
| the **same** dimension (1024) | a full re-embed |
| a **different** dimension | a schema migration altering `VECTOR(n)` **and** a full re-embed |

Both are one-way for the stored data: there is no partial state where half the
corpus is queryable. That is why `/search` fails closed rather than serving
degraded results while you work.

### The fix

**Case A — same dimension (1024).** No schema change; re-embed everything.

```bash
cd pipeline

# 1. Point the config at the new model. Both the pipeline and the Rust API read
#    these two variables (§5.3), so this is one edit consumed in two languages.
#    In .env:
#      EMBEDDING_MODEL=<new-model>
#      EMBEDDING_BASE_URL=<its endpoint, if it differs from the LLM one>

# 2. Confirm it resolves and is actually 1024-wide before touching any data.
uv run pronoia doctor

# 3. See what would be re-embedded, without writing.
uv run python -m scripts.reembed --dry-run

# 4. Re-embed. Batches commit independently, so this is interruptible and
#    safe to re-run: it resumes at the first row that is not yet on the new
#    model, and a completed run is a no-op.
uv run python -m scripts.reembed

# 5. Restart the API so it picks up the new EMBEDDING_MODEL.
```

**Case B — different dimension (e.g. moving to a 1536-wide model).** The column
has to change first, and the existing vectors cannot survive it.

```bash
cd /path/to/geosec

# 1. Write a new additive migration in db/migrations/, e.g.
#    20260801000001_embedding_dim_1536.sql:
#
#      -- Existing vectors are 1024-wide and cannot be reinterpreted at 1536.
#      -- Dropping them is not data loss: every one is reproducible from
#      -- report.summary by scripts/reembed.py, which is the next step.
#      UPDATE report SET embedding = NULL, embedding_model = NULL, embedding_dim = NULL;
#      ALTER TABLE report ALTER COLUMN embedding TYPE VECTOR(1536);
#
#    Do this in one migration: the NULL-out must precede the ALTER, or the
#    ALTER fails on every existing row.

# 2. Apply it.
docker compose exec -T db psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" \
  < db/migrations/20260801000001_embedding_dim_1536.sql

# 3. Update REPORT_EMBEDDING_DIM in pipeline/enrich/config.py to match.
#    `pronoia doctor` reads the column's real width out of the catalog and
#    reports an error if the two disagree, so run it before step 4 rather than
#    discovering the mismatch on the first INSERT.

# 4. Point EMBEDDING_MODEL at the new model, then follow Case A steps 2-5.
```

### Verifying afterwards

The check that matters is that **no rows are left on a stale `embedding_model`**.
One vintage, and it is the one you configured:

```sql
SELECT embedding_model, embedding_dim, count(*)
FROM report
GROUP BY 1, 2
ORDER BY 3 DESC;
```

A healthy result has at most **two** groups: your current model, and a
`NULL` group for reports that have never been embedded (which is fine — those
are simply invisible to `/search`). Two non-NULL model names means the re-embed
did not finish; re-run `scripts/reembed.py`, which will pick up exactly the rows
still on the old name.

`uv run pronoia doctor` reports the same thing in its `stored embeddings` row
and flags mixed vintages as degraded.

### Why `/search` returns 503 instead of just answering

Per [§8](docs/DESIGN.md), the API compares the configured `EMBEDDING_MODEL`
against the `embedding_model` recorded on the rows it is about to search. If
they disagree it returns **503**, by design, rather than running a cosine
similarity across two different vector spaces.

That failure is deliberate and it is the useful one. The alternative — comparing
the vectors anyway — returns a ranked list of plausible-looking results with no
error, no warning, and no way to tell it apart from a correct answer. A 503
that names the mismatch costs you one search; silent nonsense costs you trust in
every search you have already run.

(Distinct from a 501: `/search` returns **501** when *no* embedding provider is
configured at all, which is the supported degraded mode of §5.4, not a
mismatch.)

> The Rust API is not built yet — `/search` and its 503 are the specified
> contract in [§8](docs/DESIGN.md) that this schema and re-embed path exist to
> uphold, and land with the API milestone.
