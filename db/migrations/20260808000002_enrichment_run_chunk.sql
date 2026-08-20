-- Chunk provenance on enrichment_run (DESIGN.md §5.3 context budget). Additive only.
--
-- A document longer than the backend's MAX_INPUT_TOKENS is split and extracted
-- in several calls, so one document can now produce several enrichment_run
-- rows that all say attempt=1. Without this column the audit trail guardrail 1
-- exists to provide -- which call failed, and on what -- becomes unreadable for
-- exactly the documents most likely to fail: the long ones.
--
-- NULL means the document fit in one call and was not chunked. That is the
-- common case on a hosted backend, and it deliberately does not look like
-- chunk 0.
ALTER TABLE enrichment_run ADD COLUMN chunk_index INT;

-- Reading one document's calls back in order is the whole point of the column.
CREATE INDEX enrichment_run_document_chunk_idx
    ON enrichment_run (document_id, chunk_index, attempt);
