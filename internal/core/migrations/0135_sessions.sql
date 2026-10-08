-- 27.3 sessions with dead-man plans (internal/session): a live session is an agent's presence with
-- a succession plan. Any authenticated request carrying X-Session: e… refreshes last_beat (coalesced
-- in memory, flushed every 5 s, never inside a request tx); POST /v1/session/{id}/beat refreshes it
-- for idle agents. A clean exit (DELETE /v1/session/{id}) ends the session with cause 'goodbye' and
-- writes a checkpoint carrying the summary. If the heartbeat lapses (last_beat + ttl_s < now()) the
-- 30 s janitor ends it with cause 'expired' and runs the plan AS THE OWNER IDENTITY through the
-- exported service functions (drop claims, release locks, write a checkpoint, queue self-mail,
-- publish, push, kv-put, add a task note); quotas, scrub and gates apply, each step's outcome is
-- recorded in fired and no step is ever retried. id 'e…' PK; <= 4 live per root (L0 2); name <= 64;
-- plan jsonb <= 4 KiB, <= 8 fixed steps; cause tracks how the session ended.
CREATE TABLE sessions (
  id        text PRIMARY KEY,
  root      text NOT NULL,
  owner     text NOT NULL,
  name      text NOT NULL DEFAULT '' CHECK (length(name) <= 64),
  started   timestamptz NOT NULL DEFAULT now(),
  last_beat timestamptz NOT NULL DEFAULT now(),
  ttl_s     int NOT NULL CHECK (ttl_s BETWEEN 60 AND 3600),
  plan      jsonb NOT NULL DEFAULT '[]'::jsonb,
  ended     timestamptz,
  cause     text NOT NULL DEFAULT '' CHECK (cause IN ('', 'goodbye', 'expired', 'revoked')),
  summary   text NOT NULL DEFAULT '' CHECK (length(summary) <= 300),
  fired     jsonb NOT NULL DEFAULT '[]'::jsonb
);
-- the janitor scans only live sessions by heartbeat; the partial index keeps that scan cheap.
CREATE INDEX sessions_live_beat_idx ON sessions (last_beat) WHERE ended IS NULL;
CREATE INDEX sessions_root_idx ON sessions (root);
