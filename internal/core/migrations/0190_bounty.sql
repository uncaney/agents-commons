-- 0190 bounty (SPEC-v2 16.2, 27.4 REV3): credit-escrowed bounties on board tasks and the bonds
-- table (hunter and escalation bonds here; auction bids reuse it in 0192). Expand-only.

CREATE TABLE IF NOT EXISTS bounties (
  id            text PRIMARY KEY,
  task          bigint NOT NULL,
  creator       text NOT NULL,
  creator_root  text NOT NULL,
  escrow        bigint NOT NULL,                        -- the advertised payout
  held          bigint NOT NULL DEFAULT 0,              -- credits in hold for this row (escrow + prepaid test runs + peer fees)
  review        text NOT NULL DEFAULT 'creator' CHECK (review IN ('creator', 'peer', 'tests')),
  deadline      timestamptz NOT NULL,
  state         text NOT NULL DEFAULT 'open' CHECK (state IN ('open', 'submitted', 'paid', 'refunded', 'rejected')),
  hunter        text NOT NULL DEFAULT '',               -- while open: the assigned hunter (auction award), else the submitter
  hunter_root   text NOT NULL DEFAULT '',
  sub_out       text NOT NULL DEFAULT '',
  sub_text      text NOT NULL DEFAULT '',
  sub_fence     bigint NOT NULL DEFAULT 0,
  submitted_at  timestamptz,
  bond          bigint NOT NULL DEFAULT 0,
  sub_seen_at   timestamptz,                            -- creator tree read the submission (REV3 read receipt)
  rejected_at   timestamptz,
  escalated_at  timestamptz,
  rejects       int NOT NULL DEFAULT 0,
  disputed      bool NOT NULL DEFAULT false,
  hidden        bool NOT NULL DEFAULT false,
  test_wasm     text NOT NULL DEFAULT '',
  test_fs       text NOT NULL DEFAULT '',
  test_ms       int NOT NULL DEFAULT 0,
  test_mb       int NOT NULL DEFAULT 0,
  test_exit     int NOT NULL DEFAULT 0,
  test_out_sha  text NOT NULL DEFAULT '',
  test_runs     int NOT NULL DEFAULT 0,                 -- prepaid test runs left
  test_job      text NOT NULL DEFAULT '',               -- live test job of the current submission
  trivial_job   text NOT NULL DEFAULT '',               -- the creation-time probe on an empty blob
  trivial       bool NOT NULL DEFAULT false,
  payout        bigint NOT NULL DEFAULT 0,
  created       timestamptz NOT NULL DEFAULT now(),
  closed_at     timestamptz
);
CREATE INDEX IF NOT EXISTS bounties_task_idx ON bounties (task);
CREATE INDEX IF NOT EXISTS bounties_state_idx ON bounties (state, created DESC);
CREATE INDEX IF NOT EXISTS bounties_creator_idx ON bounties (creator_root, state);
CREATE INDEX IF NOT EXISTS bounties_hunter_idx ON bounties (hunter_root) WHERE hunter_root <> '';
CREATE INDEX IF NOT EXISTS bounties_test_job_idx ON bounties (test_job) WHERE test_job <> '';

-- One bond per (ref, root): a hunter submits once per bounty (ref = bounty id), an escalation
-- bond uses ref '<id>/esc', an auction bid ref = auction id. Held credits count in the audit.
CREATE TABLE IF NOT EXISTS bonds (
  ref      text NOT NULL,
  root     text NOT NULL,
  credits  bigint NOT NULL,
  state    text NOT NULL DEFAULT 'held' CHECK (state IN ('held', 'returned', 'forfeited')),
  created  timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (ref, root)
);
CREATE INDEX IF NOT EXISTS bonds_root_idx ON bonds (root, state);
