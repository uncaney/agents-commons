-- P94 / SPEC-v2 27.4: counting semaphores with fenced permits, atomic multi-lock and lease
-- handover. A semaphore is one row with a fixed width n and a monotonic fence; every acquisition
-- bumps the fence and stamps the permit it hands out, so a permit's fence is unique and monotonic
-- and can fence g: KV writes and queue acks exactly like a lock (sem.CheckFence). Permits outlive
-- their release only through the sem row's fence staying monotonic; a permit row is reused in place
-- once its lease has lapsed. Multi-lock and the three handover paths reuse the swarm `locks` and
-- `task_claims` tables through swarm.AcquireTx / swarm.Handover / forge.ClaimHandover, so nothing
-- is duplicated here.

-- one semaphore: the name (same 12 grammar as locks), its fixed width, the shared fence, the
-- per-root ceiling (default ceil(n/2)), the creator root and idle tracking for the janitor.
CREATE TABLE sems (
  name       text PRIMARY KEY,
  n          int NOT NULL CHECK (n BETWEEN 1 AND 64),
  fence      bigint NOT NULL DEFAULT 0,
  per_root   int NOT NULL CHECK (per_root BETWEEN 1 AND 64),
  owner_root text NOT NULL,
  created    timestamptz NOT NULL DEFAULT now(),
  idle_since timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX sems_owner_idx ON sems (owner_root);
CREATE INDEX sems_idle_idx ON sems (idle_since);

-- one permit per (name, slot): slot is 1..n. A row exists only once its slot has been taken at
-- least once; until <= now() means the slot is free (reusable in place). holder/root/fence/since
-- describe the live lease. on_expire carries the topic to publish permit-expired to, and notified
-- gates the one-shot expiry notice (like swarm.locks).
CREATE TABLE sem_permits (
  name      text NOT NULL REFERENCES sems(name) ON DELETE CASCADE,
  slot      int NOT NULL,
  holder    text NOT NULL,
  root      text NOT NULL,
  fence     bigint NOT NULL,
  since     timestamptz NOT NULL DEFAULT now(),
  until     timestamptz NOT NULL,
  on_expire text NOT NULL DEFAULT '',
  notified  boolean NOT NULL DEFAULT false,
  PRIMARY KEY (name, slot)
);
CREATE INDEX sem_permits_root_idx ON sem_permits (root);
CREATE INDEX sem_permits_until_idx ON sem_permits (until);
