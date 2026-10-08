-- xmail (SECURITY-E2EE-v2 4.5-4.9, 7.2, 8.1; SPEC-v2 26.1-26.5): the sealed mailbox. Opaque
-- envelope rows with their cleartext headers, signed relay receipts and sender request signatures,
-- per-inbox policy and counters, allow/block roots, spent first-contact stamps, poll leases, sealed
-- state blobs (CAS), epoch shares (mode D+), sender freezes, successions and the live-ciphertext
-- counter. No table here holds a key, a plaintext or a client IP; ciphertext tables, shares, state,
-- leases and stamps are excluded from backups (E2EE 8.6).

-- per-identity inbox: policy (8.1), the random-offset sequence (4.5), capacity and revocation.
CREATE TABLE x_inbox (
  id         text PRIMARY KEY,
  root       text NOT NULL,
  mode       text NOT NULL DEFAULT 'stamp' CHECK (mode IN ('open', 'stamp', 'allow', 'closed')),
  bits       smallint NOT NULL DEFAULT 0 CHECK (bits BETWEEN 0 AND 40),
  poll       text NOT NULL DEFAULT 'early' CHECK (poll IN ('early', 'fixed')),
  next_seq   bigint NOT NULL,
  max_rows   int NOT NULL DEFAULT 1000,
  max_bytes  bigint NOT NULL DEFAULT 4194304,
  rows       int NOT NULL DEFAULT 0,
  bytes      bigint NOT NULL DEFAULT 0,
  revoked_at timestamptz,
  updated    timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX x_inbox_root_idx ON x_inbox (root);

-- allow-list and blocks resolve to roots server side; the id given is kept for GET /v1/x/policy.
CREATE TABLE x_allow (
  inbox text NOT NULL,
  root  text NOT NULL,
  id    text NOT NULL,
  PRIMARY KEY (inbox, root)
);
CREATE TABLE x_block (
  inbox text NOT NULL,
  root  text NOT NULL,
  id    text NOT NULL,
  at    timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (inbox, root)
);

-- 4.6 the ciphertext row (deleted on ack or TTL) with its 71-byte cleartext header.
CREATE TABLE x_env (
  to_id     text NOT NULL,
  seq       bigint NOT NULL,
  mid       bytea NOT NULL CHECK (length(mid) = 16),
  from_id   text NOT NULL,
  from_root text NOT NULL,
  cs        smallint NOT NULL,
  size      int NOT NULL,
  epoch     bigint NOT NULL DEFAULT 0,
  scrub     text NOT NULL DEFAULT 'none' CHECK (scrub IN ('client', 'none')),
  hdr       bytea NOT NULL CHECK (length(hdr) = 71),
  body      bytea NOT NULL,
  hidden    boolean NOT NULL DEFAULT false,
  rcpt      bytea NOT NULL CHECK (length(rcpt) = 64),
  at        timestamptz NOT NULL DEFAULT now(),
  exp       timestamptz NOT NULL,
  PRIMARY KEY (to_id, seq),
  UNIQUE (to_id, mid)
);
CREATE INDEX x_env_exp_idx ON x_env (exp);
CREATE INDEX x_env_from_root_idx ON x_env (from_root, to_id);
CREATE INDEX x_env_epoch_idx ON x_env (to_id, epoch);

-- 4.6 metadata and signatures outlive the ciphertext (reports, quotas, purge accounting), 30 d.
CREATE TABLE x_ledger (
  to_id      text NOT NULL,
  seq        bigint NOT NULL,
  mid        bytea NOT NULL CHECK (length(mid) = 16),
  from_id    text NOT NULL,
  from_root  text NOT NULL,
  size       int NOT NULL,
  hdr        bytea NOT NULL CHECK (length(hdr) = 71),
  rcpt       bytea NOT NULL CHECK (length(rcpt) = 64),
  send_ts    bigint NOT NULL,
  send_nonce bytea NOT NULL CHECK (length(send_nonce) = 16),
  send_sig   bytea NOT NULL CHECK (length(send_sig) = 64),
  at         timestamptz NOT NULL DEFAULT now(),
  exp        timestamptz NOT NULL,
  PRIMARY KEY (to_id, seq)
);
CREATE INDEX x_ledger_exp_idx ON x_ledger (exp);
CREATE INDEX x_ledger_from_root_idx ON x_ledger (from_root, at);

-- 8.1 spent first-contact stamps (2 d).
CREATE TABLE x_stamps (
  to_id text NOT NULL,
  h     bytea NOT NULL CHECK (length(h) = 16),
  day   date NOT NULL DEFAULT current_date,
  PRIMARY KEY (to_id, h)
);
CREATE INDEX x_stamps_day_idx ON x_stamps (day);

-- 4.9 one poller per identity (60 s, renewable).
CREATE TABLE x_lease (
  id    text PRIMARY KEY,
  dev   text NOT NULL,
  until timestamptz NOT NULL
);

-- 7.2 sealed state blob, compare-and-swap on ver; every accepted PUT is a kind 6 klog receipt.
CREATE TABLE x_state (
  id      text PRIMARY KEY,
  ver     bigint NOT NULL,
  blob    bytea NOT NULL CHECK (length(blob) <= 65536),
  updated timestamptz NOT NULL DEFAULT now()
);

-- 4.9 mode D+ epoch shares: random bytes minted per (root, epoch), returned only sealed under lk,
-- deleted 48 h after the last envelope of the epoch left the inbox.
CREATE TABLE epoch_shares (
  root text NOT NULL,
  e    bigint NOT NULL,
  b    bytea NOT NULL CHECK (length(b) = 32),
  exp  timestamptz NOT NULL,
  PRIMARY KEY (root, e)
);
CREATE INDEX epoch_shares_exp_idx ON epoch_shares (exp);

-- 8.1 sender freezes (`err auth mail-frozen`): written by revocation here and by the reports package.
CREATE TABLE x_frozen (
  id    text PRIMARY KEY,
  until timestamptz NOT NULL,
  basis text NOT NULL DEFAULT ''
);

-- 3.7 successions (kind 4 leaves): the double-signed statement peers re-pin on.
CREATE TABLE x_succ (
  old_id  text NOT NULL,
  new_id  text NOT NULL,
  ik_new  bytea NOT NULL CHECK (length(ik_new) = 32),
  sig_old bytea NOT NULL CHECK (length(sig_old) = 64),
  sig_new bytea NOT NULL CHECK (length(sig_new) = 64),
  leaf    bigint NOT NULL,
  at      timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (old_id, new_id)
);

-- live ciphertext bytes (E2E_MAX_BYTES budget, 507 `err quota e2e budget`), kept exact by every
-- insert and delete so the check is one row read.
CREATE TABLE x_bytes (
  k text PRIMARY KEY,
  n bigint NOT NULL DEFAULT 0
);
INSERT INTO x_bytes (k, n) VALUES ('live', 0);
