-- mem (SPEC-v2 10.1-10.5, 26.4, 27.3): checkpoints with lineage, the KV store, later (messages to
-- a future self) and the view the mailbox reads delivered rows through. The audit ring lives in
-- core (0040); mem trims it.

-- 10.2 checkpoints: one lineage per (root, name), last 5 seqs kept, 30 d TTL refreshed on read.
-- pub_scope: '' private, 'all' anonymous /cp/<id>, 'room:<id>' room members (27.9). groups holds
-- the HMAC'd reader IP groups of a public checkpoint (the 4th distinct group unpublishes an owner
-- below L2). sections is the parsed cp1 body (27.3); sealed rows are stored opaque (26.4).
CREATE TABLE checkpoints (
  id         text PRIMARY KEY,
  root       text NOT NULL,
  owner      text NOT NULL,
  name       text NOT NULL,
  seq        int NOT NULL,
  summary    text NOT NULL DEFAULT '',
  body       text NOT NULL DEFAULT '',
  blob       text,
  pub        boolean NOT NULL DEFAULT false,
  pub_scope  text NOT NULL DEFAULT '',
  hazard     text[] NOT NULL DEFAULT '{}',
  sections   jsonb,
  sealed     boolean NOT NULL DEFAULT false,
  hidden     boolean NOT NULL DEFAULT false,
  groups     bytea[] NOT NULL DEFAULT '{}',
  scrub_v    int NOT NULL DEFAULT 0,
  created    timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz NOT NULL,
  UNIQUE (root, name, seq)
);
CREATE INDEX checkpoints_expires_idx ON checkpoints (expires_at);
CREATE INDEX checkpoints_root_created_idx ON checkpoints (root, created DESC);

-- 10.3 KV: namespaces a:<root> s:<slug> g:<name> x:<rv> r:<room>; v <= 4 KiB text; fence per 12.1.
CREATE TABLE kv (
  ns         text NOT NULL,
  k          text NOT NULL,
  v          bytea NOT NULL,
  ver        bigint NOT NULL DEFAULT 1,
  fence      bigint NOT NULL DEFAULT 0,
  expires_at timestamptz NOT NULL,
  root       text NOT NULL,
  updated    timestamptz NOT NULL DEFAULT now(),
  sealed     boolean NOT NULL DEFAULT false,
  hidden     boolean NOT NULL DEFAULT false,
  scrub_v    int NOT NULL DEFAULT 0,
  PRIMARY KEY (ns, k)
);
CREATE INDEX kv_expires_idx ON kv (expires_at);
CREATE INDEX kv_root_idx ON kv (root);

-- 10.4 later: self-messages delivered at deliver_at or when a condition holds (cond_kind in
-- t k j kv b r, cond_ref the id part, cond_seen the KV version seen at creation). The mailbox
-- reads and marks delivered rows through mem_later_delivered (an updatable simple view).
CREATE TABLE mem_later (
  id           text PRIMARY KEY,
  root         text NOT NULL,
  text         text NOT NULL,
  subject      text NOT NULL DEFAULT '',
  deliver_at   timestamptz,
  cond_kind    text NOT NULL DEFAULT '',
  cond_ref     text NOT NULL DEFAULT '',
  cond_seen    bigint NOT NULL DEFAULT 0,
  delivered    boolean NOT NULL DEFAULT false,
  delivered_at timestamptz,
  read_at      timestamptz,
  created      timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX mem_later_root_idx ON mem_later (root, created DESC);
CREATE INDEX mem_later_due_idx ON mem_later (deliver_at) WHERE NOT delivered AND cond_kind = '';
CREATE INDEX mem_later_cond_idx ON mem_later (cond_kind, cond_ref) WHERE NOT delivered AND cond_kind <> '';
CREATE INDEX mem_later_delivered_idx ON mem_later (root, delivered_at DESC) WHERE delivered;

CREATE VIEW mem_later_delivered AS
  SELECT id, root, subject, text, deliver_at, delivered_at, read_at, cond_kind, cond_ref, created
  FROM mem_later WHERE delivered;
