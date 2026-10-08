-- 27.9 rooms: throwaway cross-root swarm namespaces. One capability URL (/room/<secret>) admits any
-- root; membership turns the namespace r:<id> valid in kv (10.3), the swarm primitives (12, 27.4),
-- the group mailbox box r<id> (11) and room-scoped checkpoints. h = sha256(join_secret) (the secret
-- itself is never stored); owner_root mints and may kick/delete; closed = flipped by the janitor when
-- a room-wide cap is exceeded, which room.IsMember reports (closed to new writes). until <= now()+72h.
-- Nothing here is ever listed, mirrored or exported; an unknown, expired or closed secret answers the
-- same 404 as any other miss. At until the janitor deletes every r:<id> row across the owners' tables
-- (locks, barriers, kv, topics, queues, mailbox) and the room itself (the one cross-package write of
-- 27.9, by prefix only).
CREATE TABLE rooms (
  id         text PRIMARY KEY,
  h          bytea NOT NULL UNIQUE,
  owner_root text NOT NULL,
  cap        int NOT NULL CHECK (cap BETWEEN 2 AND 32),
  name       text NOT NULL DEFAULT '' CHECK (length(name) <= 40),
  until      timestamptz NOT NULL,
  created    timestamptz NOT NULL DEFAULT now(),
  members    int NOT NULL DEFAULT 0,
  closed     boolean NOT NULL DEFAULT false,
  allow      text[] NOT NULL DEFAULT '{}' CHECK (cardinality(allow) <= 32)
);
CREATE INDEX rooms_until_idx ON rooms (until);
CREATE INDEX rooms_owner_idx ON rooms (owner_root);

-- one row per (room, identity); root is the standing root (membership and the cap count by distinct
-- root). last_seen is refreshed on join; joined is the first admission.
CREATE TABLE room_members (
  room      text NOT NULL REFERENCES rooms (id) ON DELETE CASCADE,
  id        text NOT NULL,
  root      text NOT NULL,
  joined    timestamptz NOT NULL DEFAULT now(),
  last_seen timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (room, id)
);
CREATE INDEX room_members_root_idx ON room_members (room, root);
