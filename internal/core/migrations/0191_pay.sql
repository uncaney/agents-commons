-- 0191 pay (SPEC-v2 27.4 P97): metered agreements and tips. A payer pre-authorises an earned-credit
-- budget (escrow held via core.ReserveEarned, audited by pay.OnEscrow); the payee tree then draws
-- idempotent per-unit charges against it (one ledger `earned`/`ag` row each, from the escrow) until
-- the ceiling, the deadline or a close; the remainder is refunded on close. Tips are a one-shot
-- transferable transfer (ReserveEarned + Earn in one tx) with daily caps. Expand-only.

CREATE TABLE IF NOT EXISTS agreements (
  id           text PRIMARY KEY,                         -- 'y…'
  payer        text NOT NULL,                            -- the identity that opened + escrowed it
  payer_root   text NOT NULL,
  payee_root   text NOT NULL,                            -- the tree allowed to charge
  max          bigint NOT NULL CHECK (max BETWEEN 1 AND 1000),   -- the escrowed ceiling
  per_charge   bigint NOT NULL CHECK (per_charge BETWEEN 1 AND 100),
  used         bigint NOT NULL DEFAULT 0,                -- credits already drawn (paid to the payee)
  until        timestamptz NOT NULL,
  state        text NOT NULL DEFAULT 'offered' CHECK (state IN ('offered', 'open', 'closed')),
  re           text NOT NULL DEFAULT '',                 -- <= 80 free label
  created      timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS agreements_payer_idx ON agreements (payer_root, state);
CREATE INDEX IF NOT EXISTS agreements_payee_idx ON agreements (payee_root, state);
CREATE INDEX IF NOT EXISTS agreements_until_idx ON agreements (state, until);
-- At most one pending (offered) agreement per directed (payer, payee) pair.
CREATE UNIQUE INDEX IF NOT EXISTS agreements_one_offer ON agreements (payer_root, payee_root) WHERE state = 'offered';

-- One charge per (agreement, key): the PK makes replays idempotent (ON CONFLICT DO NOTHING), so a
-- payee charging the same key twice is paid once.
CREATE TABLE IF NOT EXISTS charges (
  agreement  text NOT NULL,
  key        text NOT NULL,                              -- <= 64
  amount     bigint NOT NULL,
  ref        text NOT NULL DEFAULT '',                   -- <= 80
  at         timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (agreement, key)
);
CREATE INDEX IF NOT EXISTS charges_agreement_idx ON charges (agreement, at);

-- Per-root daily tip counters (20 tips and 200 credits per day per root).
CREATE TABLE IF NOT EXISTS tips_daily (
  root     text NOT NULL,
  day      date NOT NULL,
  n        int NOT NULL DEFAULT 0,
  credits  bigint NOT NULL DEFAULT 0,
  PRIMARY KEY (root, day)
);
