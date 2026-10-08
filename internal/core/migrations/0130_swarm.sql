-- 12 swarm primitives: fenced locks, cyclic barriers, rendezvous, ordered topics with cursors, work
-- queues with receipts, shared rate limiter. Names follow the 12 grammar (g:, a:<root>., s:<slug>.,
-- r:<room>.) and are at most 128 bytes. Storage classes: swarm (locks, barriers, rv, queues) and
-- topic_msgs.

-- 12.1 fenced locks: the row outlives a release (fence stays monotonic); until <= now() = free.
-- notified = true means no expiry notice is owed (released, or already sent).
CREATE TABLE locks (
  name      text PRIMARY KEY CHECK (length(name) <= 128),
  holder    text NOT NULL DEFAULT '',
  root      text NOT NULL DEFAULT '',
  fence     bigint NOT NULL DEFAULT 0,
  until     timestamptz NOT NULL DEFAULT now(),
  since     timestamptz NOT NULL DEFAULT now(),
  on_expire text NOT NULL DEFAULT '',
  notified  boolean NOT NULL DEFAULT true
);
CREATE INDEX locks_until_idx ON locks (until);
CREATE INDEX locks_root_idx ON locks (root) WHERE root <> '';

-- 12.2 cyclic barriers: gen is the open generation; by_super counts distinct super-groups.
CREATE TABLE barriers (
  name       text PRIMARY KEY CHECK (length(name) <= 128),
  n          int NOT NULL CHECK (n BETWEEN 2 AND 64),
  gen        int NOT NULL DEFAULT 0,
  ttl_s      int NOT NULL DEFAULT 600,
  until      timestamptz NOT NULL,
  owner_root text NOT NULL,
  by_super   boolean NOT NULL DEFAULT false,
  allow      text[] NOT NULL DEFAULT '{}',
  tripped_at timestamptz,
  expired_at timestamptz,
  created    timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX barriers_until_idx ON barriers (until);
CREATE INDEX barriers_owner_idx ON barriers (owner_root);

-- one row per closed generation (tripped or expired) so gather replies stay stable.
CREATE TABLE barrier_gens (
  name    text NOT NULL,
  gen     int NOT NULL,
  n       int NOT NULL,
  k       int NOT NULL,
  tripped boolean NOT NULL,
  at      timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (name, gen)
);
CREATE INDEX barrier_gens_at_idx ON barrier_gens (at);

CREATE TABLE barrier_parties (
  name    text NOT NULL,
  gen     int NOT NULL,
  id      text NOT NULL,
  root    text NOT NULL,
  rank    int NOT NULL,
  data    text NOT NULL DEFAULT '' CHECK (length(data) <= 1024),
  arrived timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (name, gen, id)
);
CREATE INDEX barrier_parties_arrived_idx ON barrier_parties (arrived);
CREATE INDEX barrier_parties_root_idx ON barrier_parties (root);

-- 12.3 rendezvous: khash = HMAC(server secret, key); the key itself is never stored.
CREATE TABLE rv (
  id         text PRIMARY KEY,
  khash      bytea NOT NULL UNIQUE,
  cap        int NOT NULL CHECK (cap BETWEEN 2 AND 16),
  owner_root text NOT NULL DEFAULT '',
  created    timestamptz NOT NULL DEFAULT now(),
  until      timestamptz NOT NULL
);
CREATE INDEX rv_until_idx ON rv (until);
CREATE INDEX rv_owner_idx ON rv (owner_root);

CREATE TABLE rv_peers (
  rv    text NOT NULL REFERENCES rv(id) ON DELETE CASCADE,
  id    text NOT NULL,
  root  text NOT NULL,
  data  text NOT NULL DEFAULT '' CHECK (length(data) <= 1024),
  until timestamptz NOT NULL,
  PRIMARY KEY (rv, id)
);
CREATE INDEX rv_peers_until_idx ON rv_peers (until);
CREATE INDEX rv_peers_root_idx ON rv_peers (root);

-- 12.4 ordered topics: last_seq is bumped in the insert transaction (gapless, totally ordered).
CREATE TABLE topics (
  name       text PRIMARY KEY CHECK (length(name) <= 128),
  owner_root text NOT NULL,
  mode       text NOT NULL DEFAULT 'open' CHECK (mode IN ('open', 'members')),
  last_seq   bigint NOT NULL DEFAULT 0,
  msgs       int NOT NULL DEFAULT 0,
  created    timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX topics_owner_idx ON topics (owner_root);

-- flags carries markers such as via=sub (27.4 subscriptions); hidden is the ps:<topic>/<seq> report.
CREATE TABLE topic_msgs (
  topic   text NOT NULL,
  seq     bigint NOT NULL,
  by      text NOT NULL,
  root    text NOT NULL,
  text    text NOT NULL CHECK (length(text) <= 4096),
  key     text NOT NULL DEFAULT '' CHECK (length(key) <= 64),
  flags   text[] NOT NULL DEFAULT '{}',
  hidden  boolean NOT NULL DEFAULT false,
  created timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (topic, seq)
);
CREATE UNIQUE INDEX topic_msgs_key_idx ON topic_msgs (topic, root, key) WHERE key <> '';
CREATE INDEX topic_msgs_created_idx ON topic_msgs (created);
CREATE INDEX topic_msgs_root_idx ON topic_msgs (root);

CREATE TABLE topic_cursors (
  topic   text NOT NULL,
  root    text NOT NULL,
  seq     bigint NOT NULL DEFAULT 0,
  updated timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (topic, root)
);
CREATE INDEX topic_cursors_root_idx ON topic_cursors (root);

-- 12.5 work queues: items = live (ready + leased) count, dlq = dead count (caches recomputed by
-- the janitor); on_dlq publishes DLQ events to topic <name>.dlq.
CREATE TABLE queues (
  name       text PRIMARY KEY CHECK (length(name) <= 128),
  owner_root text NOT NULL,
  mode       text NOT NULL DEFAULT 'open' CHECK (mode IN ('open', 'members')),
  items      int NOT NULL DEFAULT 0,
  dlq        int NOT NULL DEFAULT 0,
  on_dlq     boolean NOT NULL DEFAULT false,
  created    timestamptz NOT NULL DEFAULT now(),
  last_at    timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX queues_owner_idx ON queues (owner_root);

-- key is the exactly-once marker of 27.4 (P93 adds the partial unique index in 0131); vis_until is
-- the lease deadline while leased and the not-before time while ready (nack delay).
CREATE TABLE q_items (
  id         bigserial PRIMARY KEY,
  queue      text NOT NULL,
  body       text NOT NULL CHECK (length(body) <= 4096),
  state      text NOT NULL DEFAULT 'ready' CHECK (state IN ('ready', 'leased', 'done', 'dead')),
  receipt    text UNIQUE,
  deliveries int NOT NULL DEFAULT 0,
  vis_until  timestamptz,
  key        text NOT NULL DEFAULT '' CHECK (length(key) <= 64),
  created    timestamptz NOT NULL DEFAULT now(),
  done_at    timestamptz
);
CREATE INDEX q_items_queue_state_idx ON q_items (queue, state, id);
CREATE INDEX q_items_leased_idx ON q_items (vis_until) WHERE state = 'leased';
CREATE INDEX q_items_done_idx ON q_items (done_at) WHERE state IN ('done', 'dead');

-- 12.6 shared upstream rate limiter: key is a hash of the canonical name (never the agent's
-- upstream name in clear); ok records the last decision so one UPDATE … RETURNING is atomic.
CREATE TABLE rl_buckets (
  key    text PRIMARY KEY,
  root   text NOT NULL DEFAULT '',
  tokens real NOT NULL,
  last   timestamptz NOT NULL DEFAULT now(),
  ok     boolean NOT NULL DEFAULT true
);
CREATE INDEX rl_buckets_root_idx ON rl_buckets (root);
CREATE INDEX rl_buckets_last_idx ON rl_buckets (last);
