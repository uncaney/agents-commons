-- trust (SPEC-v2 4.1-4.5, 17.3, 27.4, 27.8): standing columns, vouches, rep_log, decay marker.

-- Shared identity columns, declared identically (ADD COLUMN IF NOT EXISTS) in 0041 and here so
-- either migration may land first (0: expand/contract only).
ALTER TABLE identities ADD COLUMN IF NOT EXISTS cohort text NOT NULL DEFAULT '';
ALTER TABLE identities ADD COLUMN IF NOT EXISTS seed bool NOT NULL DEFAULT false;
ALTER TABLE identities ADD COLUMN IF NOT EXISTS verified_contrib int NOT NULL DEFAULT 0;
ALTER TABLE identities ADD COLUMN IF NOT EXISTS verified_noncompute int NOT NULL DEFAULT 0;
ALTER TABLE identities ADD COLUMN IF NOT EXISTS trusted bool NOT NULL DEFAULT false;
-- 27.4 (owner 0081, same definition): last verified contribution, read by GovWeight (60 d rule).
ALTER TABLE identities ADD COLUMN IF NOT EXISTS last_verified_at timestamptz;
-- 27.8 (owner 0041, same definition): ASN recorded at registration when TRUST_ASN=1; read by
-- NetKeySQL/CollapseSQL/Distinct. asn_policy is 0041's table; the IF NOT EXISTS copy below only
-- matters on a database migrated without 0041 (isolated builders), production runs 0041 first.
ALTER TABLE identities ADD COLUMN IF NOT EXISTS asn bigint NOT NULL DEFAULT 0;
CREATE TABLE IF NOT EXISTS asn_policy (
  asn     bigint PRIMARY KEY,
  class   text NOT NULL CHECK (class IN ('shared', 'residential', 'hosting', 'blocked')),
  note    text NOT NULL DEFAULT '',
  updated timestamptz NOT NULL DEFAULT now()
);

-- 17.3 vouches: one voucher per vouchee, <= 3 live per voucher (enforced in code).
CREATE TABLE vouches (
  voucher text NOT NULL,
  vouchee text PRIMARY KEY,
  at      timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX vouches_voucher_idx ON vouches (voucher);

-- 4.2 reputation log: every core.AddRep change through core.RepLogger = trust.RecordRep.
CREATE TABLE rep_log (
  root  text NOT NULL,
  delta int NOT NULL,
  kind  text NOT NULL,
  ref   text NOT NULL DEFAULT '',
  at    timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX rep_log_root_at_idx ON rep_log (root, at DESC);
CREATE INDEX rep_log_at_idx ON rep_log (at);

-- 4.2 decay marker: last observed verified_contrib per root and when it was last seen changing
-- (or last decayed); -1 rep per 14 d while it does not move, floor 0.
CREATE TABLE rep_decay (
  root text PRIMARY KEY,
  vc   int NOT NULL,
  at   timestamptz NOT NULL DEFAULT now()
);
