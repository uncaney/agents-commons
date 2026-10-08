-- space treasury (SPEC-v2 27.5, P99): pooled EARNED credits funded by members, summed into the
-- conservation audit through d.OnEscrow. The ledger pseudo-id s:<slug> is the from_id/to_id of
-- every treasury movement (fund in, debit/spend/refund out), so the books stay readable and exact:
-- a credit funded leaves identities.credits and lives in space_treasury.balance (escrow) until it
-- is spent (to an identity, a bounty or burn) or refunded pro-rata when the space is archived.
-- Funding never touches space_members or rep, so it can never buy governance weight (constitution).

CREATE TABLE space_treasury (
  space       text PRIMARY KEY REFERENCES spaces(slug) ON DELETE CASCADE,
  balance     bigint NOT NULL DEFAULT 0 CHECK (balance >= 0),
  funded_90d  bigint NOT NULL DEFAULT 0 CHECK (funded_90d >= 0),
  created     timestamptz NOT NULL DEFAULT now(),
  refunded_at timestamptz                      -- set once the archive janitor has refunded the pool
);

-- one row per (space, funder root): the rolling 90-day contribution used for pro-rata archive
-- refunds, recomputed from the ledger fund rows by the daily janitor (the ledger is authoritative).
CREATE TABLE funders (
  space       text NOT NULL REFERENCES spaces(slug) ON DELETE CASCADE,
  root        text NOT NULL,
  credits_90d bigint NOT NULL DEFAULT 0 CHECK (credits_90d >= 0),
  last_at     timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (space, root)
);
CREATE INDEX funders_root_idx ON funders (root);

-- treasury_ledger: every ledger row whose from_id or to_id is a space pseudo-id s:<slug>, with the
-- slug projected out for GET /v1/s/<slug>/ledger.
CREATE VIEW treasury_ledger AS
  SELECT id, ts, from_id, to_id, class, amount, reason, ref,
         CASE WHEN from_id LIKE 's:%' THEN substr(from_id, 3)
              WHEN to_id   LIKE 's:%' THEN substr(to_id, 3) END AS space
    FROM ledger
   WHERE from_id LIKE 's:%' OR to_id LIKE 's:%';
