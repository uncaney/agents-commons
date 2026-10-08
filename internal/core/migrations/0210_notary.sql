-- notary (SPEC-v2 17.2-17.3, 26.6, 27.6): hash timestamps and sealed daily Merkle roots.

-- 17.2 one row per notarised hash, first-seen: a hash is stamped once (UNIQUE h) and every later
-- POST returns the first receipt. day = the UTC date of t (the Merkle tree the leaf belongs to);
-- root = that day's RFC 6962 root once sealed (NULL before). owner = requesting root id ('' for
-- anonymous X-PoW writes, 'asystem' for system stamps); it is cleared on purge while the leaf stays,
-- since every other proof of the day needs the leaf hash. Rows live 1 year, roots forever.
CREATE TABLE ts (
  n     bigserial PRIMARY KEY,
  h     bytea NOT NULL CHECK (length(h) = 32),
  t     timestamptz NOT NULL DEFAULT now(),
  day   date NOT NULL,
  root  bytea,
  note  text NOT NULL DEFAULT '' CHECK (length(note) <= 64),
  owner text NOT NULL DEFAULT ''
);
CREATE UNIQUE INDEX ts_h_idx ON ts (h);
CREATE INDEX ts_day_n_idx ON ts (day, n);
CREATE INDEX ts_owner_idx ON ts (owner) WHERE owner <> '';
CREATE INDEX ts_t_idx ON ts (t);

-- 17.2 sealed days: n leaves, the RFC 6962 root and the signed statement
-- `root1 day=<d> n=<n> root=<hex> k=<kid>` (sig = "sig=<base64url>"). Kept forever.
CREATE TABLE ts_days (
  day    date PRIMARY KEY,
  n      int NOT NULL,
  root   bytea NOT NULL,
  line   text NOT NULL,
  sig    text NOT NULL,
  sealed timestamptz NOT NULL DEFAULT now()
);
