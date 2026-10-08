-- econ (SPEC-v2 16.1, 21.2, 21.4, 4.8): credit classes, the ledger with the v1 opening balance,
-- admin_log, audit_fail, ident_retention. Expand-only; core.Migrate runs the file in one transaction.

-- 16.1 credit classes: grant = credits - earned (never transferable), earned transferable.
ALTER TABLE identities
  ADD COLUMN IF NOT EXISTS earned bigint NOT NULL DEFAULT 0 CHECK (earned >= 0),
  ADD COLUMN IF NOT EXISTS saved_tokens bigint NOT NULL DEFAULT 0;

-- 16.1 ledger: every credit movement. Pseudo-ids: mint (registration, faucet, v1 opening), burn
-- (purge, unpayable payouts, charge remainders), hold (reservations and escrows while a job, bounty
-- or review is open), rollup (12-month retention keeps mint/burn totals exact), subkeys (one
-- aggregate opening row), s:<slug> and friends belong to later packages.
CREATE TABLE ledger (
  id      bigserial PRIMARY KEY,
  ts      timestamptz NOT NULL DEFAULT now(),
  from_id text NOT NULL,
  to_id   text NOT NULL,
  class   text NOT NULL CHECK (class IN ('grant', 'earned')),
  amount  bigint NOT NULL CHECK (amount > 0),
  reason  text NOT NULL,
  ref     text NOT NULL DEFAULT ''
);
CREATE INDEX ledger_ts_idx ON ledger (ts);
CREATE INDEX ledger_from_idx ON ledger (from_id, id DESC);
CREATE INDEX ledger_to_idx ON ledger (to_id, id DESC);
CREATE INDEX ledger_mint_idx ON ledger (amount) WHERE from_id = 'mint';
CREATE INDEX ledger_burn_idx ON ledger (amount) WHERE to_id = 'burn';

-- 21.4 every /admin call (successes and the first failures of each minute per IP group).
CREATE TABLE admin_log (
  at         timestamptz NOT NULL DEFAULT now(),
  ip_group   text NOT NULL DEFAULT '',
  token_kind text NOT NULL,
  action     text NOT NULL,
  arg        text NOT NULL DEFAULT ''
);
CREATE INDEX admin_log_at_idx ON admin_log (at);

-- 16.1 conservation audit failures (the operator inbox reads the matching ops event).
CREATE TABLE audit_fail (
  at     timestamptz NOT NULL DEFAULT now(),
  detail text NOT NULL
);

-- 21.2 dead-root retention: (id, reg_ip, created) kept 12 months after the row is deleted.
CREATE TABLE ident_retention (
  id         text PRIMARY KEY,
  reg_ip     text NOT NULL DEFAULT '',
  created    timestamptz NOT NULL,
  deleted_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX ident_retention_deleted_idx ON ident_retention (deleted_at);

-- Opening balance (16.1), same transaction as the table. One grant row per root for its balance plus
-- the reservations of its active jobs; one aggregate row for every subkey balance.
INSERT INTO ledger (from_id, to_id, class, amount, reason)
SELECT 'mint', i.id, 'grant', i.credits + r.reserved, 'v1-opening'
FROM identities i
CROSS JOIN LATERAL (SELECT coalesce(sum(j.reserved), 0) AS reserved FROM jobs j
                    WHERE j.root = i.id AND j.status IN ('queued', 'running')) r
WHERE i.parent IS NULL AND i.credits + r.reserved > 0;

INSERT INTO ledger (from_id, to_id, class, amount, reason)
SELECT 'mint', 'subkeys', 'grant', sum(credits), 'v1-opening' FROM identities WHERE parent IS NOT NULL
HAVING sum(credits) > 0;

-- earned backfilled from the v1 payouts that are still recoverable: ceil(used_s) + 1 per reported
-- replica that agreed with the finalized fingerprint of a done job, capped at the root's credits.
UPDATE identities i SET earned = LEAST(i.credits, s.total)
FROM (SELECT r.worker_root, sum((j.used_ms + 999) / 1000 + 1)::bigint AS total
      FROM replicas r JOIN jobs j ON j.id = r.job
      WHERE j.status = 'done' AND r.state = 'reported' AND r.worker_root IS NOT NULL
        AND r.status IN ('ok', 'exit') AND coalesce(r.out, '') = j.out AND coalesce(r.code, 0) = j.code
      GROUP BY r.worker_root) s
WHERE i.id = s.worker_root AND i.parent IS NULL;

-- Registration mints and subkey transfers land in the ledger from the identities insert itself, so
-- every path that creates a row (createRoot in auth.go, the OAuth consent page, fixtures) is covered
-- inside its own transaction. Go code must therefore never add a second 'register' mint row.
CREATE FUNCTION ledger_identity_insert() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF NEW.credits > 0 THEN
    IF NEW.parent IS NULL THEN
      INSERT INTO ledger (from_id, to_id, class, amount, reason) VALUES ('mint', NEW.id, 'grant', NEW.credits, 'register');
    ELSE
      INSERT INTO ledger (from_id, to_id, class, amount, reason) VALUES ('hold', NEW.id, 'grant', NEW.credits, 'subkey');
    END IF;
  END IF;
  RETURN NULL;
END $$;
CREATE TRIGGER identities_ledger_ins AFTER INSERT ON identities
  FOR EACH ROW EXECUTE FUNCTION ledger_identity_insert();

-- 24.5 "earned never exceeds credits" holds at the row level whatever lowers credits (Reserve takes
-- grant first; revocations zero credits): the transferable part is clamped to the balance.
CREATE FUNCTION identities_earned_clamp() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF NEW.earned > NEW.credits THEN
    NEW.earned := NEW.credits;
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER identities_earned_clamp BEFORE UPDATE OF credits, earned ON identities
  FOR EACH ROW EXECUTE FUNCTION identities_earned_clamp();
