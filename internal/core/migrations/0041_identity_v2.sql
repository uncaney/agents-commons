-- identity v2 (SPEC-v2 3.2-3.5, 26.4, 27.6, 27.8): identities columns, super-group and ASN
-- registration counters, recovery attempt counters. Expand-only; the four columns shared with
-- 0080 (cohort, seed, verified_contrib, trusted) are declared identically there.
ALTER TABLE identities
  ADD COLUMN IF NOT EXISTS cohort text NOT NULL DEFAULT '',
  ADD COLUMN IF NOT EXISTS ip_class text NOT NULL DEFAULT '',
  ADD COLUMN IF NOT EXISTS asn bigint NOT NULL DEFAULT 0,
  ADD COLUMN IF NOT EXISTS scopes text[],
  ADD COLUMN IF NOT EXISTS token_class text NOT NULL DEFAULT 'full',
  ADD COLUMN IF NOT EXISTS recovery_hash bytea,
  ADD COLUMN IF NOT EXISTS token_hash_prev bytea,
  ADD COLUMN IF NOT EXISTS rotated_at timestamptz,
  ADD COLUMN IF NOT EXISTS erasing_at timestamptz,
  ADD COLUMN IF NOT EXISTS seed bool NOT NULL DEFAULT false,
  ADD COLUMN IF NOT EXISTS trusted bool NOT NULL DEFAULT false,
  ADD COLUMN IF NOT EXISTS family text NOT NULL DEFAULT '',
  ADD COLUMN IF NOT EXISTS family_at timestamptz,
  ADD COLUMN IF NOT EXISTS model text NOT NULL DEFAULT '',
  ADD COLUMN IF NOT EXISTS cutoff text NOT NULL DEFAULT '',
  ADD COLUMN IF NOT EXISTS last_seen timestamptz,
  ADD COLUMN IF NOT EXISTS verified_contrib int NOT NULL DEFAULT 0,
  ADD COLUMN IF NOT EXISTS verified_noncompute int NOT NULL DEFAULT 0,
  ADD COLUMN IF NOT EXISTS public_stats bool NOT NULL DEFAULT false,
  ADD COLUMN IF NOT EXISTS pub bytea,
  ADD COLUMN IF NOT EXISTS pub_prev bytea,
  ADD COLUMN IF NOT EXISTS pub_at timestamptz,
  ADD COLUMN IF NOT EXISTS mk_wrapped bytea;
-- the previous hash is honoured 60 s after a rotation (3.4)
CREATE INDEX IF NOT EXISTS identities_token_hash_prev_idx ON identities (token_hash_prev) WHERE token_hash_prev IS NOT NULL;
CREATE INDEX IF NOT EXISTS identities_erasing_idx ON identities (erasing_at) WHERE erasing_at IS NOT NULL;

-- per-registration network keys: super-group for the hourly cap, ASN for the hosting curve (27.8)
ALTER TABLE reg_ips
  ADD COLUMN IF NOT EXISTS super text NOT NULL DEFAULT '',
  ADD COLUMN IF NOT EXISTS asn bigint NOT NULL DEFAULT 0;
CREATE INDEX IF NOT EXISTS reg_ips_super_at_idx ON reg_ips (super, at);
CREATE INDEX IF NOT EXISTS reg_ips_asn_at_idx ON reg_ips (asn, at) WHERE asn <> 0;

-- 3.2 per-super-group daily registration counter (atomic bump, 4x the group cap)
CREATE TABLE IF NOT EXISTS reg_supers (
  super text NOT NULL,
  day   date NOT NULL,
  n     int  NOT NULL DEFAULT 0,
  PRIMARY KEY (super, day)
);

-- 3.2 / 27.8 ASN policy (operator rows via /admin/asn, 'auto' rows by the registration path)
CREATE TABLE IF NOT EXISTS asn_policy (
  asn     bigint PRIMARY KEY,
  class   text NOT NULL CHECK (class IN ('shared', 'residential', 'hosting', 'blocked')),
  note    text NOT NULL DEFAULT '',
  updated timestamptz NOT NULL DEFAULT now()
);

-- 27.8 per-ASN daily registrations (hosting cap 200/day)
CREATE TABLE IF NOT EXISTS reg_asn (
  asn bigint NOT NULL,
  day date   NOT NULL,
  n   int    NOT NULL DEFAULT 0,
  PRIMARY KEY (asn, day)
);

-- 3.4 recovery failures per (id, caller super-group) per day; the per-id total is the sum.
CREATE TABLE IF NOT EXISTS recover_attempts (
  id    text NOT NULL,
  super text NOT NULL,
  day   date NOT NULL,
  n     int  NOT NULL DEFAULT 0,
  PRIMARY KEY (id, super, day)
);
