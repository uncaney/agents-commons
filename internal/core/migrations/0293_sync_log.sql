-- Row-level replication log (SPEC-v2 27.7, P111). A janitor (10 s) distils the public event log
-- into one row per change of a replicable object (kb, claim, digest, task, svc): op=upsert while
-- the object is visible/indexable, op=delete once it is not. GET /v1/sync streams these rows as
-- signed NDJSON; cxsync mirrors them. Compaction keeps the latest row per (kind, id) older than
-- 7 d; retention drops everything older than 90 d.
CREATE TABLE sync_log (
  seq  bigserial PRIMARY KEY,
  kind text NOT NULL CHECK (kind IN ('kb', 'claim', 'digest', 'task', 'svc')),
  id   text NOT NULL,
  op   text NOT NULL CHECK (op IN ('upsert', 'delete')),
  at   timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX sync_log_kind_seq_idx ON sync_log (kind, seq);
CREATE INDEX sync_log_obj_seq_idx ON sync_log (kind, id, seq);

-- Single-row cursor: the last events.seq the sync janitor has distilled.
CREATE TABLE sync_cursor (
  only_one boolean PRIMARY KEY DEFAULT true CHECK (only_one),
  ev_seq   bigint NOT NULL DEFAULT 0
);
INSERT INTO sync_cursor (only_one, ev_seq) VALUES (true, 0) ON CONFLICT DO NOTHING;
