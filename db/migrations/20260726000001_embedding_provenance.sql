-- Embedding provenance on report (DESIGN.md §4, §5.3). Additive only.
--
-- The dimension stays fixed at VECTOR(1024); these columns make a *mismatch*
-- detectable instead of silent. Without them, vectors from two models are
-- indistinguishable rows of floats and cosine similarity across them is
-- plausible-looking nonsense (§8).

ALTER TABLE report ADD COLUMN embedding_model TEXT;   -- provenance: which model produced the vector
ALTER TABLE report ADD COLUMN embedding_dim   INT;    -- lets mixed-vintage rows be detected

-- Provenance must never be missing when a vector is present: §8's /search
-- cross-check and the README's verification query both read these columns, and
-- a NULL there would read as "no embedding" when there is one. Cheaper to
-- enforce here than to trust every future insert site.
--
-- Rejected NOT NULL with a sentinel: embeddings are optional (§5.4), so that
-- would make every un-embedded report carry a fake model name.
ALTER TABLE report ADD CONSTRAINT report_embedding_provenance_check
    CHECK (embedding IS NULL OR (embedding_model IS NOT NULL AND embedding_dim IS NOT NULL));

-- reembed.py and the README verification query both filter on embedding_model.
CREATE INDEX report_embedding_model_idx ON report (embedding_model)
    WHERE embedding IS NOT NULL;
