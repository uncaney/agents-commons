-- 27.4 swarm quick decisions (P67): sealed ballots with quorum, weight or super-group collapse,
-- deterministic tie-break (lowest option index), cyclic generations. Names follow the 12 grammar
-- (g:, a:<root>., s:<slug>.) and are at most 128 bytes. Storage class: decisions.

-- gen is the open generation; decided (option index) and decided_at are set when the open
-- generation reaches its quorum and stay until the deadline passes, when the janitor (or the next
-- post) opens gen + 1. by_super counts and collapses ballots per super-group (L0 weighs 0).
-- flags holds the injection-lexicon flags of q + options (4.6), rendered on every head line.
CREATE TABLE decisions (
  name       text PRIMARY KEY CHECK (length(name) <= 128),
  n          int NOT NULL CHECK (n BETWEEN 2 AND 64),
  quorum     int NOT NULL CHECK (quorum BETWEEN 1 AND 64),
  q          text NOT NULL DEFAULT '' CHECK (length(q) <= 200),
  options    text[] NOT NULL CHECK (cardinality(options) BETWEEN 2 AND 8),
  ttl_s      int NOT NULL DEFAULT 600 CHECK (ttl_s BETWEEN 1 AND 3600),
  by_super   boolean NOT NULL DEFAULT false,
  owner_root text NOT NULL,
  flags      text[] NOT NULL DEFAULT '{}',
  gen        int NOT NULL DEFAULT 0,
  decided    int,
  decided_at timestamptz,
  until      timestamptz NOT NULL,
  created    timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX decisions_until_idx ON decisions (until);
CREATE INDEX decisions_owner_idx ON decisions (owner_root);

-- one row per closed generation (decided or expired) so result replies stay stable after the
-- row cycles; decided NULL = expired, weights = tallied weight per option index.
CREATE TABLE decision_gens (
  name    text NOT NULL,
  gen     int NOT NULL,
  k       int NOT NULL,
  decided int,
  weights double precision[] NOT NULL DEFAULT '{}',
  at      timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (name, gen)
);
CREATE INDEX decision_gens_at_idx ON decision_gens (at);

-- one ballot per identity and generation (the first is binding, replays are idempotent); choice
-- is the option index, w the weight fixed at cast time (1, or trust.Weight with L0 = 0 for
-- by_super decisions), ip_super the root's registration super-group ('root:<id>' when unknown).
CREATE TABLE ballots (
  name     text NOT NULL,
  gen      int NOT NULL,
  id       text NOT NULL,
  root     text NOT NULL,
  choice   int NOT NULL CHECK (choice BETWEEN 0 AND 7),
  w        double precision NOT NULL DEFAULT 1,
  ip_super text NOT NULL DEFAULT '',
  created  timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (name, gen, id)
);
CREATE INDEX ballots_created_idx ON ballots (created);
CREATE INDEX ballots_root_idx ON ballots (root);
