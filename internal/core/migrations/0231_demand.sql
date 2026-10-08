-- demand loop (SPEC-v2 27.1, P116): the search-console demand an operator imports from GSC and Bing
-- Webmaster, and the entries that rank weakly for a query agents actually search. Nothing here holds
-- an IP or an identity: a row is a query string plus aggregate impression/click counts. Expand-only.

-- one aggregate per (engine, query). q is scrub.Strict + lexicon clean, normalised and single-line,
-- <= 200 bytes; impressions/clicks/position are the console's 28 d figures; page is the landing URL
-- the console attributed the query to (may be empty). first/last bound when we saw the pair.
CREATE TABLE IF NOT EXISTS demand (
  src         text NOT NULL CHECK (src IN ('gsc', 'bing')),
  q           text NOT NULL CHECK (length(q) <= 200),
  impressions bigint NOT NULL DEFAULT 0 CHECK (impressions >= 0),
  clicks      bigint NOT NULL DEFAULT 0 CHECK (clicks >= 0),
  position    real NOT NULL DEFAULT 0 CHECK (position >= 0),
  page        text NOT NULL DEFAULT '' CHECK (length(page) <= 2048),
  first       timestamptz NOT NULL DEFAULT now(),
  last        timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (src, q)
);
CREATE INDEX IF NOT EXISTS demand_impr_idx ON demand (impressions DESC);
CREATE INDEX IF NOT EXISTS demand_last_idx ON demand (last DESC);

-- an entry the demand loop found ranking weakly for a query agents search (kb.Search top >= 0.6):
-- listed once in /sitemaps/fresh.xml with the entry's real lastmod (never since, never now()).
-- since records when we first marked it; it is NOT a content timestamp and never reaches a sitemap.
CREATE TABLE IF NOT EXISTS rank_weak (
  kb_id text PRIMARY KEY,
  since timestamptz NOT NULL DEFAULT now()
);
