-- events v2 (SPEC-v2 19.1): saved watches and the cursor-read indexes over core's events table
-- (0040). A watch is a per-root filter (kinds, tags, free-text q) applied by GET /v1/ev?w=<id>.
CREATE TABLE watches (
  id      text PRIMARY KEY,
  root    text NOT NULL,
  kinds   text[] NOT NULL DEFAULT '{}',
  tags    text[] NOT NULL DEFAULT '{}',
  q       text NOT NULL DEFAULT '' CHECK (length(q) <= 120),
  created timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX watches_root_idx ON watches (root);

-- kinds filter + cursor; root-scoped rows by their owner.
CREATE INDEX IF NOT EXISTS events_kind_seq_idx ON events (kind, seq);
CREATE INDEX IF NOT EXISTS events_scope_seq_idx ON events (root_scope, seq) WHERE root_scope IS NOT NULL;
