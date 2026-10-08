-- keys (SECURITY-E2EE-v2 3.2-3.8, 9.3-9.4; SPEC-v2 26.1, 26.6): the key directory, the RFC 6962
-- key log with every internal node stored, signed tree heads and cosignatures, single-use request
-- nonces, the online-key certificate chain and the policy packs.

-- 3.1-3.2 every published bundle (canonical || sigs, <= 16 KiB) with the server-side facts the
-- directory serves. state: current (served, sealable), pending (legacy first publish or ik
-- rotation inside its 24 h window; never used for sealing), superseded (an older seq), void
-- (contested legacy publish, D14), revoked (purge or revoke tombstone). hash = sha256(canonical):
-- the kind 1 leaf's item_hash and the next bundle's prev_hash.
CREATE TABLE key_bundles (
  id            text NOT NULL,
  seq           int  NOT NULL CHECK (seq >= 1),
  root          text NOT NULL,
  bundle        bytea NOT NULL CHECK (length(bundle) <= 16384),
  hash          bytea NOT NULL CHECK (length(hash) = 32),
  ik            bytea NOT NULL CHECK (length(ik) = 32),
  rk            bytea NOT NULL CHECK (length(rk) = 32),
  policy        text NOT NULL CHECK (policy IN ('plain', 'both', 'e2ee')),
  iat           timestamptz NOT NULL,
  exp           timestamptz NOT NULL,
  state         text NOT NULL CHECK (state IN ('current', 'pending', 'superseded', 'void', 'revoked')),
  leaf          bigint,
  pending_leaf  bigint,
  published     timestamptz NOT NULL DEFAULT now(),
  pending_until timestamptz,
  revoked_at    timestamptz,
  PRIMARY KEY (id, seq)
);
CREATE UNIQUE INDEX key_bundles_current_idx ON key_bundles (id) WHERE state = 'current';
CREATE UNIQUE INDEX key_bundles_pending_idx ON key_bundles (id) WHERE state = 'pending';
CREATE INDEX key_bundles_root_idx ON key_bundles (root);
CREATE INDEX key_bundles_pending_until_idx ON key_bundles (pending_until) WHERE state = 'pending';

-- 3.3 leaves: leaf = sha256(0x00 || u8(kind) || id || item_hash || u64(idx)). Kinds: 1 bundle,
-- 2 tombstone, 3 pending, 4 succession, 5 policy pack, 6 sealed-state receipt, 7 admin action,
-- 8 witness anchor. seq is the bundle seq (or the pack version) for /v1/log/id listings.
CREATE TABLE klog (
  idx       bigint PRIMARY KEY,
  kind      smallint NOT NULL CHECK (kind BETWEEN 1 AND 8),
  id        text NOT NULL,
  seq       int NOT NULL DEFAULT 0,
  item_hash bytea NOT NULL CHECK (length(item_hash) = 32),
  leaf      bytea NOT NULL CHECK (length(leaf) = 32),
  at        timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX klog_id_idx ON klog (id, idx);

-- 3.3 every perfect-subtree node (level 0 = leaves), so proofs are O(log n) point reads.
CREATE TABLE knodes (
  level smallint NOT NULL,
  pos   bigint NOT NULL,
  hash  bytea NOT NULL CHECK (length(hash) = 32),
  PRIMARY KEY (level, pos)
);

-- 3.3 signed tree heads: sig = Ed25519(online_sk, "cx1/sth" || u64(size) || root || u64(at)).
-- One row per size; a head is re-signed (new at) every 10 min while the size stands still.
CREATE TABLE ksth (
  size bigint PRIMARY KEY,
  root bytea NOT NULL CHECK (length(root) = 32),
  at   timestamptz NOT NULL DEFAULT now(),
  sig  bytea NOT NULL CHECK (length(sig) = 64)
);

-- 3.4 cosignatures of a head by witnesses (w1, w2) or established roots (their ik), over
-- "cx1/witness" || u64(size) || root || u64(head_at); head_at is the at the signer saw.
CREATE TABLE kcosign (
  size    bigint NOT NULL REFERENCES ksth (size) ON DELETE CASCADE,
  signer  text NOT NULL,
  head_at timestamptz NOT NULL,
  sig     bytea NOT NULL CHECK (length(sig) = 64),
  at      timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (size, signer)
);
CREATE INDEX kcosign_signer_at_idx ON kcosign (signer, at);

-- 3.5 single-use request nonces (purged by the janitor; excluded from backups, unlogged).
CREATE UNLOGGED TABLE req_nonces (
  id    text NOT NULL,
  nonce bytea NOT NULL CHECK (length(nonce) = 16),
  exp   timestamptz NOT NULL,
  PRIMARY KEY (id, nonce)
);
CREATE INDEX req_nonces_exp_idx ON req_nonces (exp);

-- 3.6 online-key certificates pushed by the operator (root-signed, 30 d); the gateway serves the
-- newest valid one for its online key and self-certifies while none exists (wave 1).
CREATE TABLE server_keys (
  seq        int PRIMARY KEY,
  online_pub bytea NOT NULL CHECK (length(online_pub) = 32),
  cert       bytea NOT NULL CHECK (length(cert) = 116),
  nbf        timestamptz NOT NULL,
  exp        timestamptz NOT NULL,
  installed  timestamptz NOT NULL DEFAULT now()
);

-- 9.4 policy packs: the served JSON body, its hash (logged as a kind 5 leaf) and that leaf.
CREATE TABLE policy_pack (
  v    int PRIMARY KEY,
  hash bytea NOT NULL CHECK (length(hash) = 32),
  body bytea NOT NULL,
  leaf bigint,
  at   timestamptz NOT NULL DEFAULT now()
);

-- 26.6 a key change (ik or rk) refuses ?all=1 tree pulls for 24 h and is limited to one per 24 h.
ALTER TABLE identities ADD COLUMN IF NOT EXISTS keys_changed_at timestamptz;
