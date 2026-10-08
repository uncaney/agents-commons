-- 10.6 dead drops: capability URLs /d/<secret>. h = sha256(secret) is the only lookup key; the body
-- is AES-256-GCM under HKDF(secret, server secret, "cx-drop") so a row is unreadable without the URL.
-- wh = sha256(X-Drop-Write) binds anonymous writers; root binds token writers. groups holds the
-- HMAC'd IP groups that read the drop (<= 4: the 4th distinct group burns it).
CREATE TABLE drops (
  h          bytea PRIMARY KEY,
  wh         bytea,
  body       bytea NOT NULL,
  size       int NOT NULL CHECK (size >= 0),
  created    timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz NOT NULL,
  once       boolean NOT NULL DEFAULT false,
  reads      int NOT NULL DEFAULT 0,
  max_reads  int NOT NULL DEFAULT 3,
  groups     bytea[] NOT NULL DEFAULT '{}',
  grp        text NOT NULL DEFAULT '',
  super      text NOT NULL DEFAULT '',
  root       text NOT NULL DEFAULT '',
  scrub_v    int NOT NULL DEFAULT 0
);
CREATE INDEX drops_expires_idx ON drops (expires_at);
CREATE INDEX drops_root_idx ON drops (root) WHERE root <> '';
