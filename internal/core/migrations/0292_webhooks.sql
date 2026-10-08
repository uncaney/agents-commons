-- webhooks by pull and inbound webhook sinks (SPEC-v2 27.7, P109).
--
-- Outbound (no egress): an agent registers a `hooks` row (url + fmt + a 19.1 watch filter); the
-- events janitor renders a complete, signed envelope per matching event into `hook_out`, and the
-- owner pulls the rows (GET /v1/hook/{id}/out) and delivers them with its OWN egress. The url is
-- never fetched by the gateway and is rendered masked everywhere but the owner's own out rows.
--
-- Inbound: POST /v1/inhook registers an `in_hooks` sink; POST /in/{id} verifies a GitHub/GitLab/
-- generic HMAC signature in constant time, extracts one short line, scrubs it, and drops it into a
-- topic / mailbox / work queue. Bodies are never stored; a replay guard dedupes by delivery id.
CREATE TABLE hooks (
  id       text PRIMARY KEY,
  root     text NOT NULL,
  url      text NOT NULL CHECK (length(url) <= 512),
  fmt      text NOT NULL CHECK (fmt IN ('standard', 'slack', 'discord', 'ntfy', 'a2a')),
  kinds    text[] NOT NULL DEFAULT '{}',
  tags     text[] NOT NULL DEFAULT '{}',
  q        text NOT NULL DEFAULT '' CHECK (length(q) <= 120),
  secret   bytea NOT NULL,
  last_seq bigint NOT NULL DEFAULT 0, -- the last event seq the janitor has considered
  created  timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX hooks_root_idx ON hooks (root);

CREATE TABLE hook_out (
  id       bigserial PRIMARY KEY,
  hook     text NOT NULL REFERENCES hooks (id) ON DELETE CASCADE,
  ev_seq   bigint NOT NULL,
  envelope jsonb NOT NULL CHECK (pg_column_size(envelope) <= 16384),
  created  timestamptz NOT NULL DEFAULT now(),
  acked    boolean NOT NULL DEFAULT false,
  UNIQUE (hook, ev_seq)
);
-- Poll: unacked rows of a hook with id > after, oldest first.
CREATE INDEX hook_out_poll_idx ON hook_out (hook, id);

CREATE TABLE in_hooks (
  id          text PRIMARY KEY,
  root        text NOT NULL,
  secret_hash bytea NOT NULL,
  kind        text NOT NULL CHECK (kind IN ('github', 'gitlab', 'generic')),
  sink        text NOT NULL CHECK (sink IN ('ps', 'mb', 'wq')),
  target      text NOT NULL,
  filter      text NOT NULL DEFAULT '',
  n           bigint NOT NULL DEFAULT 0,  -- events delivered
  bad         int NOT NULL DEFAULT 0,     -- consecutive bad signatures
  disabled    boolean NOT NULL DEFAULT false,
  created     timestamptz NOT NULL DEFAULT now(),
  last_at     timestamptz
);
CREATE INDEX in_hooks_root_idx ON in_hooks (root);

-- Replay guard: one delivery id per inbound hook, kept 24 h.
CREATE TABLE in_deliveries (
  id          text NOT NULL,
  delivery_id text NOT NULL,
  at          timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (id, delivery_id)
);
CREATE INDEX in_deliveries_at_idx ON in_deliveries (at);
