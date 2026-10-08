-- news (SPEC-v2 27.3 "Daily rollup and since your last visit", P91). Daily audit rollup and a
-- per-root "changed:" delta the resume bundle shows once and then advances past.

-- Daily rollup of the owner audit ring (10.5): one row per (root, UTC day, op) with the count.
-- Filled at 00:10 UTC by the news janitor and on demand for the requested window by GET
-- /v1/me/log/daily. Idempotent upsert so a re-roll of today refreshes the count.
CREATE TABLE IF NOT EXISTS audit_daily (
  root text NOT NULL,
  day  date NOT NULL,
  op   text NOT NULL,
  n    int  NOT NULL DEFAULT 0,
  PRIMARY KEY (root, day, op)
);

-- "since your last visit" cursor: the highest event seq the root has already been shown in a
-- resume "changed:" section. Advances only when resume renders the section.
ALTER TABLE identities ADD COLUMN IF NOT EXISTS news_cursor bigint NOT NULL DEFAULT 0;

-- Helper index for the delta's "kb hide|edit|supersede where the root is author or voter" leg
-- (already created by 0001; the guard keeps this migration standalone).
CREATE INDEX IF NOT EXISTS kb_votes_root_idx ON kb_votes (root);
