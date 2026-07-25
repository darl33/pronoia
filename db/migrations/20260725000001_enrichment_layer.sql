-- Enrichment layer: LLM extraction runs and the validated rows they produce,
-- plus the two reference tables the guardrails validate against (DESIGN.md §4, §5).
--
-- Every table below except actor_review_queue is transcribed from §4 verbatim.
-- actor_review_queue is not in §4 but is required by §5.2 guardrail 4:
-- "Unresolved names go to a review queue table, not silently into the dataset."

CREATE EXTENSION IF NOT EXISTS vector;

-- ============ reference data (loaded, not extracted) ============

CREATE TABLE threat_actor (
    id            UUID PRIMARY KEY,
    canonical_name TEXT NOT NULL UNIQUE,    -- from MISP galaxy
    aliases       TEXT[] NOT NULL DEFAULT '{}',
    suspected_origin_country CHAR(2),       -- ISO 3166-1, as *reported*
    misp_uuid     UUID
);

CREATE TABLE attack_technique (             -- loaded from ATT&CK STIX bundle
    technique_id  TEXT PRIMARY KEY,         -- e.g. 'T1566.001'
    name          TEXT NOT NULL,
    tactic        TEXT NOT NULL
);

-- ============ enrichment ============

CREATE TABLE enrichment_run (
    id            UUID PRIMARY KEY,
    document_id   UUID NOT NULL REFERENCES raw_document(id),
    model         TEXT NOT NULL,            -- e.g. 'claude-sonnet-4-6'
    prompt_version TEXT NOT NULL,           -- git-tracked prompt template id
    started_at    TIMESTAMPTZ NOT NULL,
    finished_at   TIMESTAMPTZ,
    status        TEXT NOT NULL CHECK (status IN
                    ('pending','ok','invalid_json','schema_fail','api_error')),
    raw_response  JSONB,                    -- full model output, kept for audit
    attempt       INT NOT NULL DEFAULT 1
);

CREATE INDEX enrichment_run_document_idx ON enrichment_run (document_id);

CREATE TABLE report (                       -- one validated extraction per document
    id            UUID PRIMARY KEY,
    document_id   UUID NOT NULL UNIQUE REFERENCES raw_document(id),
    enrichment_run_id UUID NOT NULL REFERENCES enrichment_run(id),
    summary       TEXT NOT NULL,            -- model-written 2-3 sentence abstract
    report_date   DATE,                     -- date of activity described, not publish date
    confidence    TEXT NOT NULL CHECK (confidence IN ('low','medium','high')),
    embedding     VECTOR(1024)              -- pgvector, semantic search
);

CREATE TABLE report_actor (
    report_id     UUID NOT NULL REFERENCES report(id),
    actor_id      UUID NOT NULL REFERENCES threat_actor(id),
    attribution_confidence TEXT NOT NULL CHECK
                    (attribution_confidence IN ('suspected','likely','confirmed_by_source')),
    PRIMARY KEY (report_id, actor_id)
);

CREATE TABLE report_technique (
    report_id     UUID NOT NULL REFERENCES report(id),
    technique_id  TEXT NOT NULL REFERENCES attack_technique(technique_id),
    evidence_quote TEXT,                    -- verbatim span from clean_text (see eval, §7)
    PRIMARY KEY (report_id, technique_id)
);

CREATE TABLE report_target (
    id            UUID PRIMARY KEY,
    report_id     UUID NOT NULL REFERENCES report(id),
    country       CHAR(2),                  -- ISO 3166-1
    sector        TEXT                      -- controlled vocab incl. SOCI sectors
);

CREATE TABLE ioc (
    id            UUID PRIMARY KEY,
    report_id     UUID NOT NULL REFERENCES report(id),
    kind          TEXT NOT NULL CHECK (kind IN
                    ('ipv4','ipv6','domain','url','sha256','md5','email')),
    value_defanged TEXT NOT NULL,           -- ONLY defanged form is stored
    UNIQUE (report_id, kind, value_defanged)
);

-- ============ guardrail 4 review queue (§5.2) ============

-- An actor name the model emitted that did not resolve to a threat_actor row.
-- Parked here for human review rather than being invented into the dataset;
-- nothing downstream reads this table.
CREATE TABLE actor_review_queue (
    id            UUID PRIMARY KEY,
    report_id     UUID NOT NULL REFERENCES report(id),
    raw_name      TEXT NOT NULL,            -- as emitted by the model
    attribution_confidence TEXT NOT NULL CHECK
                    (attribution_confidence IN ('suspected','likely','confirmed_by_source')),
    best_match_actor_id UUID REFERENCES threat_actor(id),  -- closest miss, if any
    best_match_score REAL,                  -- difflib ratio of that closest miss
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    resolved      BOOLEAN NOT NULL DEFAULT false,
    UNIQUE (report_id, raw_name)
);
