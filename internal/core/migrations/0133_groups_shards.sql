-- 27.4 membership groups with epochs and deterministic shard ownership (P96): consumer-group
-- semantics over a fixed shard space. Members join-or-heartbeat a named group; on any membership
-- change the epoch is bumped and every live member is re-ranked densely by (since, id), so each
-- member deterministically owns the shards {s : s mod n == rank}. The epoch fences dependent
-- writes (grp.CheckFence, composed into mem.FenceCheckFn by P60a). Names follow the 12 grammar
-- (g:, a:<root>., s:<slug>.) and are at most 128 bytes. Storage class: groups.

-- one group: the live epoch, the ranked member count n, the shard space (1..4096), the member TTL
-- (reaped past since+ttl_s on the next touch or by the janitor), the creator root, the distinct
-- flag (one ranked member per super-group), the on_change notify target (JSON {"ps":"<topic>"}),
-- the moderation hide flag and idle tracking for the 7 d sweep.
CREATE TABLE groups (
  name       text PRIMARY KEY CHECK (length(name) <= 128),
  epoch      bigint NOT NULL DEFAULT 1,
  n          int NOT NULL DEFAULT 0,
  shards     int NOT NULL DEFAULT 1 CHECK (shards BETWEEN 1 AND 4096),
  ttl_s      int NOT NULL DEFAULT 30 CHECK (ttl_s BETWEEN 10 AND 600),
  owner_root text NOT NULL,
  "distinct" boolean NOT NULL DEFAULT false,
  on_change  text NOT NULL DEFAULT '',
  hidden     boolean NOT NULL DEFAULT false,
  touched    timestamptz NOT NULL DEFAULT now(),
  created    timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX groups_owner_idx ON groups (owner_root);
CREATE INDEX groups_touched_idx ON groups (touched);

-- one row per live member (<= 64 per group): the identity and its root, the dense rank (-1 while
-- standby behind another member of its super-group in a distinct group), the registration
-- super-group used for the distinct collapse, the join instant (stable across heartbeats, the
-- deterministic rank key with id), the heartbeat deadline and an opaque <= 512 byte data blob
-- rendered indented to the other members.
CREATE TABLE group_members (
  name  text NOT NULL,
  id    text NOT NULL,
  root  text NOT NULL,
  rank  int NOT NULL DEFAULT -1,
  super text NOT NULL DEFAULT '',
  since timestamptz NOT NULL DEFAULT now(),
  until timestamptz NOT NULL,
  data  text NOT NULL DEFAULT '' CHECK (length(data) <= 512),
  PRIMARY KEY (name, id)
);
CREATE INDEX group_members_root_idx ON group_members (root);
CREATE INDEX group_members_until_idx ON group_members (until);

-- per-root epoch-bump ledger for the flapping limit (27.4: 30 bumps/h/root -> 429 err rate
-- flapping). One row per bump a root causes through its own join or leave; reaps of other members
-- are not charged. Swept on the hourly horizon by the janitor.
CREATE TABLE group_flaps (
  root text NOT NULL,
  at   timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX group_flaps_root_at_idx ON group_flaps (root, at);
