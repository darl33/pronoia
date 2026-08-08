-- Per-feed opt-in to following entry links and storing the full article body.
--
-- Talos ships whole posts in <content:encoded>; ACSC publishes one-line
-- teasers that left clean_text at 85-300 chars. Following the link fixes that,
-- but it is extra outbound traffic and extra SSRF surface (ingest/article.py),
-- so it is opt-in. Default false so a feed added later cannot silently start
-- crawling article pages.
ALTER TABLE feed ADD COLUMN fetch_articles BOOLEAN NOT NULL DEFAULT false;
