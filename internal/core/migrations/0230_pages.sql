-- pages (SPEC-v2 8.3, 8.4): /e/ sitemap membership, the anonymised search log and the answer
-- pages the janitor mints from it. Expand-only; nothing here holds IPs or identities.

-- an error signature is in answers.xml only while its top hit is indexable (8.3)
CREATE TABLE IF NOT EXISTS e_pages (
  sig     text PRIMARY KEY CHECK (length(sig) <= 160),
  kb_id   text NOT NULL,
  lastmod timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS e_pages_lastmod_idx ON e_pages (lastmod DESC);

-- qn = lowercased, whitespace-collapsed, secret-masked, lexicon-clean query (<= 200 bytes), counted
-- only with >= 1 hit; days moves once per calendar day; supers_h = HMAC(day key, super-group) set
CREATE TABLE IF NOT EXISTS search_log (
  qn       text PRIMARY KEY CHECK (length(qn) <= 200),
  n        int NOT NULL DEFAULT 0,
  days     int NOT NULL DEFAULT 0,
  last_day date NOT NULL DEFAULT current_date,
  last_at  timestamptz NOT NULL DEFAULT now(),
  top_id   text NOT NULL DEFAULT '',
  supers_h bytea[] NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS search_log_days_idx ON search_log (days DESC, n DESC);
CREATE INDEX IF NOT EXISTS search_log_last_idx ON search_log (last_at);

-- slug = ascii slug of the top entry's title (<= 80) + '-' + 4 hex of sha256(qn); kb_ids[1] is the
-- top entry, the rest the related ones; gone marks a page whose entries all disappeared (410)
CREATE TABLE IF NOT EXISTS answer_pages (
  slug    text PRIMARY KEY CHECK (slug ~ '^[a-z0-9][a-z0-9-]{0,84}$'),
  qn      text NOT NULL UNIQUE,
  kb_ids  text[] NOT NULL DEFAULT '{}',
  created timestamptz NOT NULL DEFAULT now(),
  updated timestamptz NOT NULL DEFAULT now(),
  gone    bool NOT NULL DEFAULT false
);
CREATE INDEX IF NOT EXISTS answer_pages_created_idx ON answer_pages (created DESC);
