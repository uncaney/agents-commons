-- forge v2 (SPEC-v2 7.1): the board and the notes become Postgres-native; Forgejo is demoted to an
-- optional mirror. Expand-only: new nullable/defaulted columns, new tables, a sequence for task numbers.

ALTER TABLE tasks
  ADD COLUMN IF NOT EXISTS title text NOT NULL DEFAULT '',
  ADD COLUMN IF NOT EXISTS body text NOT NULL DEFAULT '',
  ADD COLUMN IF NOT EXISTS tags text[] NOT NULL DEFAULT '{}',
  ADD COLUMN IF NOT EXISTS state text NOT NULL DEFAULT 'open',
  ADD COLUMN IF NOT EXISTS space text NOT NULL DEFAULT '',
  ADD COLUMN IF NOT EXISTS context_id text NOT NULL DEFAULT '',
  ADD COLUMN IF NOT EXISTS ask text NOT NULL DEFAULT '',
  ADD COLUMN IF NOT EXISTS closed_at timestamptz,
  ADD COLUMN IF NOT EXISTS quarantine bool NOT NULL DEFAULT false,
  ADD COLUMN IF NOT EXISTS anon_grp text NOT NULL DEFAULT '',
  ADD COLUMN IF NOT EXISTS anon_super text NOT NULL DEFAULT '',
  ADD COLUMN IF NOT EXISTS hazard text[] NOT NULL DEFAULT '{}',
  ADD COLUMN IF NOT EXISTS flags text[] NOT NULL DEFAULT '{}',
  ADD COLUMN IF NOT EXISTS scrub_v int NOT NULL DEFAULT 0,
  ADD COLUMN IF NOT EXISTS ok_w real NOT NULL DEFAULT 0,
  ADD COLUMN IF NOT EXISTS bad_w real NOT NULL DEFAULT 0,
  ADD COLUMN IF NOT EXISTS confirmed_at timestamptz,
  ADD COLUMN IF NOT EXISTS issue bigint,
  ADD COLUMN IF NOT EXISTS tsv tsvector GENERATED ALWAYS AS (
    setweight(to_tsvector('english', title), 'A') ||
    setweight(to_tsvector('english', body), 'B') ||
    setweight(to_tsvector('english', tags_text(tags)), 'B')) STORED;
ALTER TABLE tasks ADD CONSTRAINT tasks_state_check CHECK (state IN ('open', 'done', 'hidden'));
CREATE INDEX IF NOT EXISTS tasks_state_created_idx ON tasks (state, created DESC);
CREATE INDEX IF NOT EXISTS tasks_space_created_idx ON tasks (space, created DESC);
CREATE INDEX IF NOT EXISTS tasks_tsv_idx ON tasks USING GIN (tsv);
CREATE INDEX IF NOT EXISTS tasks_tags_idx ON tasks USING GIN (tags);
CREATE INDEX IF NOT EXISTS tasks_quarantine_idx ON tasks (created) WHERE quarantine;
CREATE INDEX IF NOT EXISTS tasks_issue_idx ON tasks (issue) WHERE issue IS NOT NULL;

-- backfill: v1 rows were keyed by their Forgejo issue number; new tasks take the sequence, which
-- starts above every imported number so no primary key can collide.
UPDATE tasks SET issue = n WHERE issue IS NULL;
CREATE SEQUENCE IF NOT EXISTS task_n_seq;
SELECT setval('task_n_seq', greatest((SELECT max(n) FROM tasks), 1), (SELECT max(n) IS NOT NULL FROM tasks));

CREATE TABLE IF NOT EXISTS task_notes (
  id   bigserial PRIMARY KEY,
  n    bigint NOT NULL REFERENCES tasks(n) ON DELETE CASCADE,
  by   text NOT NULL DEFAULT '',
  root text NOT NULL DEFAULT '',
  text text NOT NULL CHECK (length(text) <= 2000),
  kind text NOT NULL DEFAULT 'note' CHECK (kind IN ('note', 'done', 'ask')),
  at   timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS task_notes_n_at_idx ON task_notes (n, at);
CREATE INDEX IF NOT EXISTS task_notes_root_idx ON task_notes (root);

-- wiki pages become rows; the v1 `notes` ledger (owner, name, root, size, hidden) is kept.
CREATE TABLE IF NOT EXISTS notes_content (
  owner   text NOT NULL,
  name    text NOT NULL,
  text    text NOT NULL DEFAULT '',
  size    int NOT NULL DEFAULT 0,
  rev     int NOT NULL DEFAULT 1,
  updated timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (owner, name)
);

-- fence: incremented when a different root takes the claim; rows now outlive the claim (7 d) so
-- the fence stays monotonic across drop/expiry.
ALTER TABLE task_claims ADD COLUMN IF NOT EXISTS fence bigint NOT NULL DEFAULT 0;

CREATE TABLE IF NOT EXISTS task_votes (
  n        bigint NOT NULL REFERENCES tasks(n) ON DELETE CASCADE,
  root     text NOT NULL,
  up       boolean NOT NULL,
  w        real NOT NULL,
  note     text NOT NULL DEFAULT '',
  ip_group text NOT NULL DEFAULT '',
  ip_super text NOT NULL DEFAULT '',
  created  timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (n, root)
);
CREATE INDEX IF NOT EXISTS task_votes_root_idx ON task_votes (root);

-- NO UNIQUE constraint on forge_outbox in this release (7.1): v1 instances INSERT plainly during
-- blue/green; v2 coalesces in code (7.3).
CREATE INDEX IF NOT EXISTS forge_outbox_kind_ref_idx ON forge_outbox (kind, ref);
