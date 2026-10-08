-- core wire (SPEC-v2 0, 10.5, 12.7, 19.1, 20, 21): audit ring, event log, content origin,
-- egress outbox, idempotency keys, string-valued flags, and the system root row.

-- 10.5 owner audit log: ids and ops only, 30 d / last 1000 rows per root (ring kept by mem).
CREATE TABLE audit (
  root text NOT NULL,
  id   text NOT NULL,
  ts   timestamptz NOT NULL DEFAULT now(),
  op   text NOT NULL,
  ref  text NOT NULL DEFAULT '',
  n    int NOT NULL DEFAULT 0
);
CREATE INDEX audit_root_ts_idx ON audit (root, ts DESC);

-- 19.1 event log: public kinds anonymous, root_scope rows only for that root.
CREATE TABLE events (
  seq        bigserial PRIMARY KEY,
  at         timestamptz NOT NULL DEFAULT now(),
  kind       text NOT NULL,
  ref        text NOT NULL DEFAULT '',
  root_scope text,
  title      text NOT NULL DEFAULT '' CHECK (length(title) <= 160)
);
CREATE INDEX events_at_idx ON events (at);

-- 4.8 / 24.16 content origin: who wrote what from where; kept 12 months, never exported.
CREATE TABLE content_origin (
  kind text NOT NULL,
  ref  text NOT NULL,
  root text NOT NULL DEFAULT '',
  id   text NOT NULL DEFAULT '',
  ip   text NOT NULL DEFAULT '',
  at   timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX content_origin_ref_idx ON content_origin (kind, ref);
CREATE INDEX content_origin_at_idx ON content_origin (at);

-- 20 egress outbox: the courier polls it through INTERNAL_LISTEN; live = done_at IS NULL.
CREATE TABLE egress_outbox (
  id       bigserial PRIMARY KEY,
  kind     text NOT NULL,
  payload  jsonb NOT NULL,
  attempts int NOT NULL DEFAULT 0,
  next_at  timestamptz NOT NULL DEFAULT now(),
  done_at  timestamptz,
  last_err text NOT NULL DEFAULT '',
  created  timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX egress_outbox_live_idx ON egress_outbox (kind, next_at) WHERE done_at IS NULL;
CREATE INDEX egress_outbox_created_idx ON egress_outbox (kind, created);

-- 12.7 idempotency: placeholder row first, result stored after the op ran; 24 h TTL.
CREATE TABLE idem (
  root     text NOT NULL,
  key      text NOT NULL CHECK (length(key) <= 64),
  route    text NOT NULL,
  req_hash bytea NOT NULL,
  status   int,
  body     text,
  created  timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (root, key)
);
CREATE INDEX idem_created_idx ON idem (created);

-- flags gain a string value (maintenance_until, edgekv:<path> hashes); v is unchanged.
ALTER TABLE flags ADD COLUMN IF NOT EXISTS s text NOT NULL DEFAULT '';

-- 0: the system root. Never issued a token (unmatchable hash), funded only by the admin faucet.
INSERT INTO identities (id, name, parent, root, token_hash, credits)
VALUES ('asystem', 'system', NULL, 'asystem', sha256(('system-' || gen_random_uuid()::text)::bytea), 0)
ON CONFLICT (id) DO NOTHING;
