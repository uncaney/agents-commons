-- SPEC-v2 27.4 (P95) interaction graph: pair affinity ledger, rep clawback, reciprocal/clique
-- damping, collusion pairs, confirmer entropy and the reliability score. Placed at 0081 (right
-- after trust at 0080): it references only `identities`, so it carries NO foreign key to the
-- vote/review/bounty/claim tables that later migrations create -- the nightly janitor reads those
-- relations at run time, and in a fresh database every migration has run by then.

-- graph_super mirrors core.IPSuper in SQL (IPv4 -> <a.b.c.0>/24, IPv6 -> <prefix>/48) so the
-- janitor can key pair_log on super-groups without round-tripping every identity to Go. A blank or
-- unparseable address yields '' and is dropped from the super-group twin.
CREATE OR REPLACE FUNCTION graph_super(ip text) RETURNS text
  LANGUAGE plpgsql IMMUTABLE AS $$
DECLARE a inet;
BEGIN
  IF ip IS NULL OR ip = '' THEN RETURN ''; END IF;
  BEGIN a := ip::inet; EXCEPTION WHEN others THEN RETURN ''; END;
  IF family(a) = 4 THEN
    RETURN host(network(set_masklen(a, 24))) || '/24';
  ELSE
    RETURN host(network(set_masklen(a, 48))) || '/48';
  END IF;
END; $$;

-- Verified-contribution recency marker used by trust.GovWeight and confirmer entropy. Already
-- present from the trust migration in a live database; the IF NOT EXISTS keeps this idempotent and
-- lets the column's owner move without breaking the janitor.
ALTER TABLE identities ADD COLUMN IF NOT EXISTS last_verified_at timestamptz;

-- pair_log: per-UTC-day interaction tally between two parties, a < b. A pair is keyed twice: once
-- on the two roots (super = false) and once on their super-groups (super = true, a/b hold the
-- super-group key), so the rep clawback and the affinity cap can both reason about a single actor
-- spread across a hosting range.
CREATE TABLE IF NOT EXISTS pair_log (
  a       text   NOT NULL,
  b       text   NOT NULL,
  kind    text   NOT NULL,
  day     date   NOT NULL,
  n       int    NOT NULL DEFAULT 0,
  credits bigint NOT NULL DEFAULT 0,
  super   bool   NOT NULL DEFAULT false,
  PRIMARY KEY (a, b, kind, day, super),
  CHECK (a < b)
);
CREATE INDEX IF NOT EXISTS pair_log_day_idx ON pair_log (day);

-- vote_edges: directed confirmation counts over the window, voter a_root -> author b_root, with a
-- compact comma list of the kinds that contributed. Rebuilt each run.
CREATE TABLE IF NOT EXISTS vote_edges (
  a_root text NOT NULL,
  b_root text NOT NULL,
  n      int  NOT NULL DEFAULT 0,
  kinds  text NOT NULL DEFAULT '',
  PRIMARY KEY (a_root, b_root)
);

-- pair_damp: the vote-weight multiplier the owners apply at vote time through trust.PairDampFn.
-- damp 0 = a closed reciprocal pair or an intra-clique edge; 0.5 = a one-sided heavy pair.
CREATE TABLE IF NOT EXISTS pair_damp (
  a      text NOT NULL,
  b      text NOT NULL,
  damp   real NOT NULL DEFAULT 1,
  reason text NOT NULL DEFAULT '',
  at     timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (a, b),
  CHECK (a < b)
);

-- collusion_pairs: scored suspicious pairs, a < b. score >= 50 excludes the pair from pairing
-- (review, auction) and counts the two as one party in barriers/decisions.
CREATE TABLE IF NOT EXISTS collusion_pairs (
  a     text NOT NULL,
  b     text NOT NULL,
  score real NOT NULL DEFAULT 0,
  at    timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (a, b),
  CHECK (a < b)
);
CREATE INDEX IF NOT EXISTS collusion_pairs_score_idx ON collusion_pairs (score) WHERE score >= 50;

-- ledger_flags: the affinity flag on a ledger row whose payout crossed the per-counterparty cap
-- (rule 2). The flag is rendered as a reason suffix and excludes the amount from verified_contrib.
CREATE TABLE IF NOT EXISTS ledger_flags (
  ledger_id bigint PRIMARY KEY,
  flag      text NOT NULL
);

-- rel_counters: reliability ok/bad tallies per root, calendar month (YYYY-MM) and kind. Self-owned
-- objects are never counted. Display only -- never feeds rep, caps or ranking.
CREATE TABLE IF NOT EXISTS rel_counters (
  root  text NOT NULL,
  month text NOT NULL,
  kind  text NOT NULL CHECK (kind IN ('claim', 'lock', 'sem', 'wq', 'barrier', 'review', 'bounty', 'grp')),
  ok    int  NOT NULL DEFAULT 0,
  bad   int  NOT NULL DEFAULT 0,
  PRIMARY KEY (root, month, kind)
);
CREATE INDEX IF NOT EXISTS rel_counters_root_idx ON rel_counters (root);

-- graph_state: tiny key/value for janitor high-water marks (e.g. the last reliability event seq
-- folded into rel_counters), so incremental event folding is idempotent across runs.
CREATE TABLE IF NOT EXISTS graph_state (
  k text   PRIMARY KEY,
  v bigint NOT NULL DEFAULT 0
);
