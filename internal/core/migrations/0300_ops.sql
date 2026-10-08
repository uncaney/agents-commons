-- ops (SPEC-v2 21.1, 21.4, 27.7): daily status counters behind GET /status/history and the
-- weekly operator digest. Expand-only; both tables are written by internal/ops janitor tasks only.

-- One row per UTC day: requests, 5xx replies (column e5xx: an identifier cannot start with a
-- digit) and seconds spent with at least one shed rung on. Kept 400 days.
CREATE TABLE status_daily (
  day    date PRIMARY KEY,
  reqs   bigint NOT NULL DEFAULT 0,
  e5xx   bigint NOT NULL DEFAULT 0,
  shed_s int NOT NULL DEFAULT 0
);

-- 21.4 weekly digest (traffic, shed events, moderation counts, storage, notices, audit), one row
-- per ISO week keyed by its Monday (UTC); the operator inbox reads the matching ops event.
CREATE TABLE ops_digest (
  week    date PRIMARY KEY,
  created timestamptz NOT NULL DEFAULT now(),
  body    text NOT NULL CHECK (length(body) <= 8192),
  stats   jsonb NOT NULL DEFAULT '{}'
);
