-- groups cxg1 (SECURITY-E2EE-v2 5.1-5.6; SPEC-v2 26): the Delivery Service for sealed groups. The
-- server is exactly an MLS Delivery Service: it holds the roster (visible by design, 5.5), gives a
-- total order to opaque rows (commits, welcomes, proposals, app messages) whose headers are
-- cleartext AAD, enforces the epoch CAS and the roster rules, and never holds a key, a plaintext or
-- a ciphertext key. Server-originated removals are the lawful lever (5.5). Content is zero-knowledge;
-- the roster, counters, epochs and the franking commitments are not. Rows are hard-deleted at ttl_d
-- (Postgres only, never Forgejo) and the whole group is fully deletable (D6: excluded from backups).

-- one group: 'g…' id, suite, caps, the epoch and the shared total-order sequence (random offset at
-- creation, 4.5), the live byte count, the creator root, idle tracking and the pending-proposal gate.
CREATE TABLE grp (
  id           text PRIMARY KEY,
  cs           smallint NOT NULL CHECK (cs IN (1, 2)),
  max_n        int NOT NULL CHECK (max_n BETWEEN 1 AND 64),
  ttl_d        int NOT NULL CHECK (ttl_d BETWEEN 1 AND 30),
  epoch        bigint NOT NULL DEFAULT 1,
  last_seq     bigint NOT NULL,
  bytes        bigint NOT NULL DEFAULT 0,
  creator_root text NOT NULL,
  pending      int NOT NULL DEFAULT 0,
  frozen       boolean NOT NULL DEFAULT false,
  created      timestamptz NOT NULL DEFAULT now(),
  idle         timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX grp_creator_idx ON grp (creator_root);
CREATE INDEX grp_idle_idx ON grp (idle);

-- the roster the server can read (5.5): one row per live member, its stable idx, the identity and
-- its root, the exact log leaf of the bundle used (so every member runs the DVR on the same bytes),
-- the role (0 member, 1 admin) and the epoch it joined at.
CREATE TABLE grp_members (
  gid         text NOT NULL REFERENCES grp(id) ON DELETE CASCADE,
  idx         int NOT NULL,
  id          text NOT NULL,
  root        text NOT NULL,
  leaf        bigint NOT NULL,
  ik          bytea NOT NULL CHECK (length(ik) = 32),
  role        smallint NOT NULL DEFAULT 0,
  since_epoch bigint NOT NULL,
  PRIMARY KEY (gid, idx),
  UNIQUE (gid, id)
);
CREATE INDEX grp_members_root_idx ON grp_members (root);

-- former members, kept 12 months so a removed member can still file a franking report and for the
-- legal record (5.5); never a key or a plaintext.
CREATE TABLE grp_members_tomb (
  gid        text NOT NULL,
  idx        int NOT NULL,
  id         text NOT NULL,
  root       text NOT NULL,
  left_epoch bigint NOT NULL,
  at         timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (gid, idx, at)
);
CREATE INDEX grp_members_tomb_root_idx ON grp_members_tomb (root);
CREATE INDEX grp_members_tomb_at_idx ON grp_members_tomb (at);

-- the shared, totally-ordered log (5.3): opaque body with its 85-byte cleartext header (AAD), the
-- member request signature (send_sig, 3.5), the online-key relay receipt (4.4). kind: 1 app, 2
-- commit, 3 proposal, 4 welcome, 5 object. to_id is set only on welcomes addressed to a joiner.
CREATE TABLE grp_rows (
  gid        text NOT NULL REFERENCES grp(id) ON DELETE CASCADE,
  seq        bigint NOT NULL,
  kind       smallint NOT NULL CHECK (kind BETWEEN 1 AND 5),
  epoch      bigint NOT NULL,
  idx        int NOT NULL,
  gen        bigint NOT NULL DEFAULT 0,
  to_id      text,
  hdr        bytea NOT NULL CHECK (length(hdr) = 85),
  body       bytea NOT NULL,
  sig        bytea NOT NULL CHECK (length(sig) = 64),
  rcpt       bytea NOT NULL CHECK (length(rcpt) = 64),
  send_ts    bigint NOT NULL DEFAULT 0,
  send_nonce bytea NOT NULL DEFAULT '\x',
  send_sig   bytea NOT NULL DEFAULT '\x',
  size       int NOT NULL,
  at         timestamptz NOT NULL DEFAULT now(),
  exp        timestamptz NOT NULL,
  PRIMARY KEY (gid, seq),
  UNIQUE (gid, idx, gen)
);
CREATE INDEX grp_rows_exp_idx ON grp_rows (exp);
CREATE INDEX grp_rows_inv_idx ON grp_rows (to_id) WHERE kind = 4 AND to_id IS NOT NULL;

-- server-originated removal proposals (5.5), the lawful lever: one row per removed idx until a
-- member lands a commit whose pp covers it. basis records why (purge|leave|admin). A member reads
-- these to build the next commit; app writes are refused (409 err pending) while any row is open.
CREATE TABLE grp_pending (
  gid   text NOT NULL REFERENCES grp(id) ON DELETE CASCADE,
  pseq  bigint NOT NULL,
  idx   int NOT NULL,
  basis text NOT NULL DEFAULT 'admin' CHECK (basis IN ('purge', 'leave', 'admin')),
  at    timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (gid, pseq)
);

-- 5.6 shared encrypted state for swarms (kanban, plan, votes): a compare-and-swap blob keyed by the
-- group, opaque ciphertext, bumped by one per accepted PUT. Snapshots (every 200 ops or on demand)
-- are kept by ver so a newcomer or a reset agent fetches the latest plus the log tail.
CREATE TABLE grp_state (
  gid     text PRIMARY KEY REFERENCES grp(id) ON DELETE CASCADE,
  ver     bigint NOT NULL DEFAULT 0,
  blob    bytea NOT NULL DEFAULT '\x',
  updated timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE grp_snapshots (
  gid  text NOT NULL REFERENCES grp(id) ON DELETE CASCADE,
  ver  bigint NOT NULL,
  blob bytea NOT NULL,
  at   timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (gid, ver)
);

-- content-blind barriers on opaque names (5.4): one arrival row per (gid, k, member idx, gen); the
-- barrier trips when n distinct members have arrived. Locks and leader election reuse the swarm
-- `locks` table through swarm.AcquireTx with the group id as namespace, so they are not duplicated.
CREATE TABLE grp_barrier (
  gid  text NOT NULL REFERENCES grp(id) ON DELETE CASCADE,
  k    text NOT NULL,
  gen  int NOT NULL DEFAULT 0,
  idx  int NOT NULL,
  at   timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (gid, k, gen, idx)
);

-- franking evidence for a group report (5.3, 26.3): a (former) member revealed kf for one row and the
-- server recomputed the franking commitment C over the plaintext it showed, ran scrub/lexicon/hazard
-- in memory, and stored only kinds, score and sha256 (90 d), never the text.
CREATE TABLE grp_evidence (
  gid       text NOT NULL,
  seq       bigint NOT NULL,
  by_id     text NOT NULL,
  by_root   text NOT NULL,
  upheld    boolean NOT NULL,
  kinds     text[] NOT NULL DEFAULT '{}',
  score     int NOT NULL DEFAULT 0,
  pt_sha    bytea NOT NULL CHECK (length(pt_sha) = 32),
  at        timestamptz NOT NULL DEFAULT now(),
  exp       timestamptz NOT NULL,
  PRIMARY KEY (gid, seq, by_id)
);
CREATE INDEX grp_evidence_exp_idx ON grp_evidence (exp);
