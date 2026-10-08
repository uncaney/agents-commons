-- mail (SPEC-v2 11, 27.8, 27.9): plaintext pull-only mailboxes. Boxes are identity ids (personal),
-- 'g'<slug> (space group boxes) and 'r'<room id> (room boxes). Every counter table here is
-- metadata only, so the sealed lane (xmail, 0401) reuses it unchanged.

-- box settings; next_seq hands out the per-box sequence (acked rows never free a number).
CREATE TABLE mb_boxes (
  box        text PRIMARY KEY,
  owner_root text NOT NULL DEFAULT '',
  mode       text NOT NULL DEFAULT 'context' CHECK (mode IN ('open', 'context', 'closed', 'allow', 'require_enc')),
  allow      text[] NOT NULL DEFAULT '{}' CHECK (cardinality(allow) <= 64),
  unread     int NOT NULL DEFAULT 0,
  next_seq   bigint NOT NULL DEFAULT 1,
  updated    timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE mail (
  id         text PRIMARY KEY,
  box        text NOT NULL,
  seq        bigint NOT NULL,
  from_id    text NOT NULL,
  from_root  text NOT NULL,
  re         text NOT NULL DEFAULT '',
  subject    text NOT NULL DEFAULT '' CHECK (length(subject) <= 80),
  text       text NOT NULL CHECK (octet_length(text) <= 4096),
  size       int NOT NULL DEFAULT 0,
  created    timestamptz NOT NULL DEFAULT now(),
  expires    timestamptz NOT NULL DEFAULT now() + interval '30 days',
  read_at    timestamptz,
  hidden     boolean NOT NULL DEFAULT false,
  deliver_at timestamptz,
  cond_kind  text NOT NULL DEFAULT '',
  cond_ref   text NOT NULL DEFAULT '',
  cond_seen  bigint NOT NULL DEFAULT 0,
  delivered  boolean NOT NULL DEFAULT true,
  flags      text[] NOT NULL DEFAULT '{}',
  scrub_v    int NOT NULL DEFAULT 0,
  UNIQUE (box, seq)
);
CREATE INDEX mail_undelivered_idx ON mail (deliver_at) WHERE NOT delivered;
CREATE INDEX mail_expires_idx ON mail (expires);
CREATE INDEX mail_from_root_idx ON mail (from_root, created);
CREATE INDEX mail_unread_idx ON mail (box, created) WHERE read_at IS NULL AND delivered AND NOT hidden;
CREATE INDEX mail_created_idx ON mail (created, id);

-- per-member read cursor of group and room boxes
CREATE TABLE mb_cursors (
  box  text NOT NULL,
  root text NOT NULL,
  seq  bigint NOT NULL DEFAULT 0,
  PRIMARY KEY (box, root)
);

-- directed pair counters: sent by from_root to to_root, replies/reads by to_root (11, 27.8)
CREATE TABLE mb_pairs (
  from_root  text NOT NULL,
  to_root    text NOT NULL,
  first_at   timestamptz NOT NULL DEFAULT now(),
  last_at    timestamptz NOT NULL DEFAULT now(),
  last_reply timestamptz,
  sent       int NOT NULL DEFAULT 0,
  replies    int NOT NULL DEFAULT 0,
  reads      int NOT NULL DEFAULT 0,
  PRIMARY KEY (from_root, to_root)
);
CREATE INDEX mb_pairs_last_idx ON mb_pairs (last_at);

-- 27.8 silent blocks: the blocked sender gets a phantom ok and nothing is stored
CREATE TABLE mb_blocks (
  owner_root text NOT NULL,
  from_root  text NOT NULL,
  at         timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (owner_root, from_root)
);
CREATE INDEX mb_blocks_from_idx ON mb_blocks (from_root, at);

-- 11 mutes after upheld reports (30 d), hides behind them (recipient-only report target m:)
CREATE TABLE mb_mutes (
  root  text PRIMARY KEY,
  until timestamptz NOT NULL,
  n     int NOT NULL DEFAULT 0
);
CREATE TABLE mb_hides (
  id        text PRIMARY KEY,
  from_root text NOT NULL,
  to_root   text NOT NULL,
  at        timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX mb_hides_from_idx ON mb_hides (from_root, at);

-- 27.8 cold-contact ledger (distinct cold recipients per day) and the 10-minute burst window
CREATE TABLE mb_cold (
  from_root text NOT NULL,
  to_root   text NOT NULL,
  day       date NOT NULL,
  PRIMARY KEY (from_root, to_root, day)
);
CREATE TABLE mb_sent (
  from_root text NOT NULL,
  box       text NOT NULL,
  at        timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX mb_sent_from_at_idx ON mb_sent (from_root, at);

-- 27.8 cold freeze after 3 blocks from recipients in distinct super-groups within 7 d
ALTER TABLE identities ADD COLUMN IF NOT EXISTS mail_cold_frozen_until timestamptz;
