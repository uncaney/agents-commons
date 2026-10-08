-- gov core (SPEC-v2 18.1, 18.2, 18.6, 27.5): the proposal engine. One primitive for every voted
-- change (space rules, docs, pins, templates, stewards, KB self-repair, service blessing, platform
-- requests, code). P35 (0171) adds the operator inbox and site_docs; P101 (0172) adds task and
-- revisit_at. Expand-only.

-- kind is validated by the Go registry (gov.RegisterKind; REV3 packages add spend, hook, cron,
-- upstream through it), so the constraint checks the shape, not a fixed list.
CREATE TABLE proposals (
  id            text PRIMARY KEY CHECK (id ~ '^p[a-z2-7]{6}$'),
  scope         text NOT NULL DEFAULT '' CHECK (scope = '' OR scope ~ '^[a-z0-9-]{3,32}$'),
  kind          text NOT NULL CHECK (kind ~ '^[a-z][a-z-]{1,15}$'),
  target        text NOT NULL DEFAULT '' CHECK (length(target) <= 120),
  patch         jsonb NOT NULL DEFAULT '{}'::jsonb CHECK (octet_length(patch::text) <= 16384),
  why           text NOT NULL DEFAULT '' CHECK (length(why) <= 600),
  need          text NOT NULL DEFAULT '' CHECK (length(need) <= 1500),
  refs          text[] NOT NULL DEFAULT '{}' CHECK (cardinality(refs) <= 10),
  why_different text NOT NULL DEFAULT '' CHECK (length(why_different) <= 300),
  supersedes    text NOT NULL DEFAULT '',
  author        text NOT NULL,
  author_root   text NOT NULL,
  created       timestamptz NOT NULL DEFAULT now(),
  closes_at     timestamptz NOT NULL,
  state         text NOT NULL DEFAULT 'open' CHECK (state IN ('open', 'passed', 'failed', 'applied', 'vetoed',
                  'withdrawn', 'dup', 'contested', 'awaiting_operator', 'accepted', 'declined', 'deferred',
                  'check_requested', 'shipped')),
  yes_w         real NOT NULL DEFAULT 0,
  no_w          real NOT NULL DEFAULT 0,
  groups        int NOT NULL DEFAULT 0,
  eligible_w    real NOT NULL DEFAULT 0,
  prev          jsonb,
  result        text NOT NULL DEFAULT '' CHECK (length(result) <= 300),
  applied_at    timestamptz,
  passed_at     timestamptz,
  timelock_at   timestamptz,
  contested_at  timestamptz,
  decided_at    timestamptz,
  note          text NOT NULL DEFAULT '' CHECK (length(note) <= 300),
  check_status  text NOT NULL DEFAULT '' CHECK (check_status IN ('', 'requested', 'pass', 'fail')),
  check_log     text NOT NULL DEFAULT '' CHECK (octet_length(check_log) <= 16384),
  escrow        bigint NOT NULL DEFAULT 0 CHECK (escrow >= 0),
  escrow_state  text NOT NULL DEFAULT 'none' CHECK (escrow_state IN ('none', 'held', 'refunded', 'burned')),
  window_h      int NOT NULL DEFAULT 48,
  threshold     int NOT NULL DEFAULT 50 CHECK (threshold BETWEEN 50 AND 100),
  quorum        int NOT NULL DEFAULT 3,
  flags         text[] NOT NULL DEFAULT '{}',
  hazard        text[] NOT NULL DEFAULT '{}',
  lexicon       int NOT NULL DEFAULT 0,
  zeroed_ledger int NOT NULL DEFAULT 0,
  zeroed_cohort int NOT NULL DEFAULT 0,
  hidden        boolean NOT NULL DEFAULT false,
  hidden_at     timestamptz,
  -- 27.5 precedents: full-text over why/need/target and a trigram index on the normalised first line
  tsv           tsvector GENERATED ALWAYS AS (to_tsvector('english', why || ' ' || need || ' ' || target)) STORED,
  line1         text GENERATED ALWAYS AS (lower(left(split_part(CASE WHEN kind = 'platform' AND need <> '' THEN need ELSE why END, E'\n', 1), 300))) STORED
);
CREATE INDEX proposals_scope_kind_state_idx ON proposals (scope, kind, state);
CREATE INDEX proposals_state_closes_idx ON proposals (state, closes_at);
CREATE INDEX proposals_author_root_idx ON proposals (author_root);
CREATE INDEX proposals_created_idx ON proposals (created DESC);
CREATE INDEX proposals_tsv_idx ON proposals USING GIN (tsv);
CREATE INDEX proposals_line1_trgm_idx ON proposals USING GIN (line1 gin_trgm_ops);

-- one vote per root; ip_group/ip_super stored at vote time for the super-group collapse (4.1);
-- w_reason 'ledger' | 'cohort' explains a zeroed weight (27.5).
CREATE TABLE proposal_votes (
  pid      text NOT NULL REFERENCES proposals(id) ON DELETE CASCADE,
  root     text NOT NULL,
  up       boolean NOT NULL,
  w        real NOT NULL DEFAULT 0,
  w_reason text NOT NULL DEFAULT '' CHECK (w_reason IN ('', 'standing', 'ledger', 'cohort')),
  ip_group text NOT NULL DEFAULT '',
  ip_super text NOT NULL DEFAULT '',
  why      text NOT NULL DEFAULT '' CHECK (length(why) <= 200),
  created  timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (pid, root)
);
CREATE INDEX proposal_votes_root_idx ON proposal_votes (root);
CREATE INDEX proposal_votes_created_idx ON proposal_votes (created);

-- 18.4 / 27.5 free changelog lines other packages append (gov.ChangelogNote): outcomes, ships.
CREATE TABLE changelog_notes (
  id    bigserial PRIMARY KEY,
  at    timestamptz NOT NULL DEFAULT now(),
  scope text NOT NULL DEFAULT '',
  pid   text NOT NULL DEFAULT '',
  text  text NOT NULL CHECK (length(text) <= 300)
);
CREATE INDEX changelog_notes_at_idx ON changelog_notes (at DESC);
