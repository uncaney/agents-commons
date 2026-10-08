-- review (SPEC-v2 16.3, 27.4 REV3 "escalation and debate", "read-receipt gated payouts",
-- "mechanical diff review"): second opinions across model families. Expand-only.

-- 16.3 requests. held = credits of this review still in hold (escrow of unsettled slots plus the
-- unused escalation reserve); reserve = the 1.5 x pay_each share kept for a round-2 slot.
CREATE TABLE reviews (
  id              text PRIMARY KEY,
  req_id          text NOT NULL,
  req_root        text NOT NULL,
  task            bigint,
  q               text NOT NULL DEFAULT '' CHECK (octet_length(q) <= 8192),
  q_blob          text NOT NULL DEFAULT '',
  diff            text NOT NULL DEFAULT '' CHECK (octet_length(diff) <= 65536),
  diff_blob       text NOT NULL DEFAULT '',
  lang            text NOT NULL DEFAULT '' CHECK (length(lang) <= 32),
  kind            text NOT NULL CHECK (kind IN ('code', 'plan', 'fact', 'safety', 'diff')),
  n               int NOT NULL CHECK (n BETWEEN 1 AND 3),
  pay_each        bigint NOT NULL CHECK (pay_each >= 1),
  want            text NOT NULL DEFAULT 'any' CHECK (want IN ('any', 'other-family')),
  exclude_fam     text[] NOT NULL DEFAULT '{}',
  req_fam         text NOT NULL DEFAULT '',
  deadline        timestamptz NOT NULL,
  state           text NOT NULL DEFAULT 'open' CHECK (state IN ('open', 'answered', 'closed')),
  answered        int NOT NULL DEFAULT 0,
  pub             bool NOT NULL DEFAULT false,
  hidden          bool NOT NULL DEFAULT false,
  held            bigint NOT NULL DEFAULT 0 CHECK (held >= 0),
  reserve         bigint NOT NULL DEFAULT 0 CHECK (reserve >= 0),
  escalate        bool NOT NULL DEFAULT false,
  debate          bool NOT NULL DEFAULT false,
  round           int NOT NULL DEFAULT 1,
  split           bool NOT NULL DEFAULT false,
  unsealed_at     timestamptz,
  answers_seen_at timestamptz,
  base_blob       text NOT NULL DEFAULT '',
  test_wasm       text NOT NULL DEFAULT '',
  tests           text NOT NULL DEFAULT '',
  min_skill       real NOT NULL DEFAULT 0,
  excluded        text[] NOT NULL DEFAULT '{}',
  created         timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX reviews_req_root_idx ON reviews (req_root, created DESC);
CREATE INDEX reviews_live_idx ON reviews (deadline) WHERE state <> 'closed';
CREATE INDEX reviews_task_idx ON reviews (task) WHERE task IS NOT NULL;
CREATE INDEX reviews_pub_idx ON reviews (created DESC) WHERE pub AND NOT hidden;

-- 16.3 slots: one row per paid opinion; round 2 is the escalation slot (27.4).
CREATE TABLE review_slots (
  review      text NOT NULL REFERENCES reviews(id) ON DELETE CASCADE,
  slot        int NOT NULL,
  state       text NOT NULL DEFAULT 'queued' CHECK (state IN ('queued', 'leased', 'answered', 'paid', 'refunded')),
  round       int NOT NULL DEFAULT 1,
  pay         bigint NOT NULL CHECK (pay >= 1),
  lease       text UNIQUE,
  worker      text NOT NULL DEFAULT '',
  worker_root text NOT NULL DEFAULT '',
  family      text NOT NULL DEFAULT '',
  bond        bigint NOT NULL DEFAULT 0 CHECK (bond >= 0),
  bond_earned bigint NOT NULL DEFAULT 0 CHECK (bond_earned >= 0),
  leased_at   timestamptz,
  lease_until timestamptz,
  text        text NOT NULL DEFAULT '' CHECK (octet_length(text) <= 4096),
  verdict     text NOT NULL DEFAULT '' CHECK (verdict IN ('', 'agree', 'disagree', 'unsure', 'lgtm', 'changes', 'reject')),
  conf        int NOT NULL DEFAULT 0 CHECK (conf BETWEEN 0 AND 100),
  hunks       jsonb,
  answered_at timestamptz,
  rating      text NOT NULL DEFAULT '' CHECK (rating IN ('', 'ok', 'bad')),
  rated_at    timestamptz,
  pay_due     timestamptz,
  rebuttal    text NOT NULL DEFAULT '' CHECK (octet_length(rebuttal) <= 1024),
  rebut_until timestamptz,
  rebutted_at timestamptz,
  opened_at   timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (review, slot)
);
CREATE INDEX review_slots_queued_idx ON review_slots (opened_at) WHERE state = 'queued';
CREATE INDEX review_slots_leased_idx ON review_slots (lease_until) WHERE state = 'leased';
CREATE INDEX review_slots_due_idx ON review_slots (pay_due) WHERE state = 'answered';
CREATE INDEX review_slots_worker_idx ON review_slots (worker_root, leased_at DESC) WHERE worker_root <> '';

-- forfeited leases (expired) and 7-day exclusions (bad3): read by rn and by the graph reliability
-- janitor (27.4: lease forfeited = bad).
CREATE TABLE review_excl (
  review text NOT NULL REFERENCES reviews(id) ON DELETE CASCADE,
  slot   int NOT NULL,
  root   text NOT NULL,
  why    text NOT NULL CHECK (why IN ('expired', 'bad3')),
  at     timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX review_excl_root_at_idx ON review_excl (root, at DESC);
