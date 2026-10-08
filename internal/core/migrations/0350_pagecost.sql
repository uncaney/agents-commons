-- 27.9 web token-cost map: one row per canonical URL (scheme://host/path, query and fragment
-- dropped) with crowd-measured token counts. uh = sha256(canonical url); url/host/rd/path are the
-- canonical parts (rd = registrable domain, so GET /pc/h/example.com also covers docs.example.com).
-- Aggregates are recomputed in the write transaction from pagecost_samples collapsed to one sample
-- per super-group (medians over distinct roots/supers; anonymous samples weigh 0.5). alt is a
-- cheaper twin on the same registrable domain, shown once alt_ok_w >= 2 (distinct super-groups
-- other than the proposer's, alt_sup) and alt_ok_w > alt_bad_w. Rows idle 180 d are deleted;
-- nothing is exported.
CREATE TABLE pagecost (
  uh        bytea PRIMARY KEY,
  url       text NOT NULL,
  host      text NOT NULL,
  rd        text NOT NULL,
  path      text NOT NULL,
  n         int NOT NULL DEFAULT 0,
  tok_p50   int NOT NULL DEFAULT 0,
  tok_min   int NOT NULL DEFAULT 0,
  tok_max   int NOT NULL DEFAULT 0,
  bytes_p50 bigint NOT NULL DEFAULT 0,
  fmt       text NOT NULL DEFAULT 'html' CHECK (fmt IN ('html', 'md', 'txt', 'json', 'pdf')),
  alt       text NOT NULL DEFAULT '',
  alt_sup   text NOT NULL DEFAULT '',
  alt_ok_w  real NOT NULL DEFAULT 0,
  alt_bad_w real NOT NULL DEFAULT 0,
  first     timestamptz NOT NULL DEFAULT now(),
  last      timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX pagecost_uh16_idx ON pagecost (substring(uh from 1 for 8));
CREATE INDEX pagecost_host_idx ON pagecost (host, tok_p50 DESC);
CREATE INDEX pagecost_rd_idx ON pagecost (rd, tok_p50 DESC);
CREATE INDEX pagecost_last_idx ON pagecost (last);

-- One sample per (uh, who, day); who is a root id or 'n:' || HMAC'd IP group (anonymous X-PoW),
-- sup the HMAC'd super-group (24.24: never raw network keys), w the weight (1 token, 0.5
-- anonymous). At most 32 samples per uh (the oldest beyond are deleted in the write tx).
CREATE TABLE pagecost_samples (
  uh      bytea NOT NULL REFERENCES pagecost (uh) ON DELETE CASCADE,
  who     text NOT NULL,
  sup     text NOT NULL,
  w       real NOT NULL DEFAULT 1,
  tok     int NOT NULL CHECK (tok > 0),
  bytes   bigint NOT NULL DEFAULT 0,
  fmt     text NOT NULL CHECK (fmt IN ('html', 'md', 'txt', 'json', 'pdf')),
  day     date NOT NULL DEFAULT current_date,
  created timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (uh, who, day)
);
CREATE INDEX pagecost_samples_who_idx ON pagecost_samples (who);
CREATE INDEX pagecost_samples_created_idx ON pagecost_samples (created);

-- altok / altbad votes on the current alt of a row (token roots only, one vote per root; votes are
-- deleted when the alt is replaced). Counted per distinct super-group.
CREATE TABLE pagecost_alt_votes (
  uh      bytea NOT NULL REFERENCES pagecost (uh) ON DELETE CASCADE,
  who     text NOT NULL,
  sup     text NOT NULL,
  ok      boolean NOT NULL,
  created timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (uh, who)
);
CREATE INDEX pagecost_alt_votes_who_idx ON pagecost_alt_votes (who);
