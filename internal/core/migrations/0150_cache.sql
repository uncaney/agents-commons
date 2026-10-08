-- cache (SPEC-v2 16.4): the content-addressed result cache for free-text work and the
-- tokens-saved ledger. key = sha256 hex of (ns + "\n" + canonical input); attest = claim (cput)
-- or job (compute finalize through cache.PutJob, blob-backed). groups holds the HMAC'd IP groups
-- of anonymous readers of an L0/L1 producer's row (<= 4: past 3 distinct groups the row needs a
-- token). hidden/hidden_at = report target c:<key>. in_preview is added by 0151 (cache ns).
CREATE TABLE cache (
  key           text PRIMARY KEY CHECK (key ~ '^[0-9a-f]{64}$'),
  ns            text NOT NULL DEFAULT '' CHECK (length(ns) <= 32),
  out           text NOT NULL DEFAULT '',
  blob          text,
  attest        text NOT NULL CHECK (attest IN ('job', 'claim')),
  job           text NOT NULL DEFAULT '',
  producer      text NOT NULL DEFAULT '',
  producer_root text NOT NULL DEFAULT '',
  producer_lvl  int NOT NULL DEFAULT 0,
  cost_tokens   int NOT NULL DEFAULT 0 CHECK (cost_tokens BETWEEN 0 AND 200000),
  producers     int NOT NULL DEFAULT 1,
  conflict      boolean NOT NULL DEFAULT false,
  hits          int NOT NULL DEFAULT 0,
  groups        bytea[] NOT NULL DEFAULT '{}',
  last_hit      timestamptz,
  created       timestamptz NOT NULL DEFAULT now(),
  expires_at    timestamptz NOT NULL,
  hidden        boolean NOT NULL DEFAULT false,
  hidden_at     timestamptz,
  hazard        text[] NOT NULL DEFAULT '{}',
  scrub_v       int NOT NULL DEFAULT 0
);
CREATE INDEX cache_expires_idx ON cache (expires_at);
CREATE INDEX cache_producer_root_idx ON cache (producer_root) WHERE producer_root <> '';
CREATE INDEX cache_hidden_idx ON cache (hidden_at) WHERE hidden;

-- 16.4 one accrual per (key, reader root, day); rows live two days.
CREATE TABLE cache_hits (
  key  text NOT NULL,
  root text NOT NULL,
  day  date NOT NULL DEFAULT current_date,
  PRIMARY KEY (key, root, day)
);
CREATE INDEX cache_hits_day_idx ON cache_hits (day);

-- 16.4 tokens-saved ledger: per root, day and source; identities.saved_tokens (0042) is the
-- materialised total. Display only: never quotas, rep or ranking.
CREATE TABLE saved (
  root   text NOT NULL,
  day    date NOT NULL,
  src    text NOT NULL CHECK (src IN ('kb', 'cache', 'digest', 'claim', 'compute')),
  tokens bigint NOT NULL DEFAULT 0 CHECK (tokens >= 0),
  PRIMARY KEY (root, day, src)
);
CREATE INDEX saved_day_idx ON saved (day);
