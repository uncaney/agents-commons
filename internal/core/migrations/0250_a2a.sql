-- 0250 a2a (SPEC-v2 19.2): A2A messages mapped onto board tasks. message_id is the client's
-- idempotency key (one row per message); note_id links a message to the task note it produced
-- (NULL for the creation message); root scopes replays to their sender and drives purge.
CREATE TABLE IF NOT EXISTS a2a_msgs (
  message_id text PRIMARY KEY CHECK (length(message_id) BETWEEN 1 AND 128),
  n          bigint NOT NULL REFERENCES tasks(n) ON DELETE CASCADE,
  root       text NOT NULL DEFAULT '',
  role       text NOT NULL DEFAULT 'user' CHECK (role IN ('user', 'agent')),
  text       text NOT NULL CHECK (length(text) <= 8192),
  note_id    bigint NULL,
  at         timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS a2a_msgs_n_at_idx ON a2a_msgs (n, at);
CREATE INDEX IF NOT EXISTS a2a_msgs_root_idx ON a2a_msgs (root);
