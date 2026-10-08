-- Server-side subscriptions and reactive functions (SPEC-v2 27.4, P93). A sub binds a topic to a
-- sink (work queue, mailbox, KV or a catalog service function) with an optional filter and an each
-- or digest mode. The delivery goroutine pulls new topic messages after last_seq and writes them to
-- the sink, advancing last_seq in the same transaction so delivery is exactly-once. Expand-only.
--
-- The exactly-once marker of a queue sink also needs the partial unique index on q_items(queue,key)
-- that 27.4 assigns to this package; the key column itself was added by P17 (0130).

CREATE TABLE subs (
  id              text PRIMARY KEY CHECK (id ~ '^u[a-z2-7]{6}$'),
  root            text NOT NULL,
  topic           text NOT NULL,
  sink_kind       text NOT NULL CHECK (sink_kind IN ('wq', 'mb', 'kv', 'fn')),
  sink            text NOT NULL CHECK (length(sink) <= 160),
  to_kind         text NOT NULL DEFAULT '' CHECK (to_kind IN ('', 'topic', 'mail', 'kv')),
  to_key          text NOT NULL DEFAULT '' CHECK (length(to_key) <= 160),
  filter          text NOT NULL DEFAULT '' CHECK (length(filter) <= 120),
  mode            text NOT NULL DEFAULT 'each' CHECK (mode IN ('each', 'digest')),
  last_seq        bigint NOT NULL DEFAULT 0,
  created         timestamptz NOT NULL DEFAULT now(),
  errors          int NOT NULL DEFAULT 0,
  paused          boolean NOT NULL DEFAULT false,
  hop_max         int NOT NULL DEFAULT 2 CHECK (hop_max >= 1),
  until           timestamptz,
  max_credits_day int NOT NULL DEFAULT 50 CHECK (max_credits_day >= 0),
  digest_at       timestamptz
);
CREATE INDEX subs_root_idx ON subs (root);
CREATE INDEX subs_topic_idx ON subs (topic) WHERE NOT paused;

-- Buffered lines for a digest-mode mailbox sink, keyed by (sub, seq) so the same message is never
-- buffered twice; flushed to one mail every 10 min (<= 20 envelope lines).
CREATE TABLE sub_digest (
  sub  text NOT NULL REFERENCES subs(id) ON DELETE CASCADE,
  seq  bigint NOT NULL,
  line text NOT NULL,
  at   timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (sub, seq)
);

-- The exactly-once marker of a work-queue sink (27.4): swarm.Push uses
-- ON CONFLICT (queue, key) WHERE key <> '' DO NOTHING, which needs this matching partial index.
CREATE UNIQUE INDEX IF NOT EXISTS q_items_queue_key_idx ON q_items (queue, key) WHERE key <> '';
