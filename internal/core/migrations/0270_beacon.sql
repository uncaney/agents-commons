-- 19.3 beacons: one row per outage report. root NULL = anonymous (X-PoW, weight 0.2); ipgroup /
-- ipsuper are the reporter's network keys (nets = distinct super-groups). Rows live 72 h: the
-- janitor rolls them up into st_hourly first, then deletes them. No note column: pages show
-- numbers only.
CREATE TABLE beacons (
  id      bigserial PRIMARY KEY,
  target  text NOT NULL,
  sym     text NOT NULL CHECK (sym IN ('529', '5xx', 'timeout', 'auth', 'slow', 'ok')),
  root    text,
  ipgroup text NOT NULL DEFAULT '',
  ipsuper text NOT NULL DEFAULT '',
  created timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX beacons_target_created_idx ON beacons (target, created DESC);
CREATE INDEX beacons_created_idx ON beacons (created);
CREATE INDEX beacons_super_idx ON beacons (ipsuper);
CREATE INDEX beacons_root_idx ON beacons (root) WHERE root IS NOT NULL;

-- 27.1 indexable status pages: hourly rollup (weighted reports, distinct roots and nets in the
-- hour, symptom counts), kept 90 d.
CREATE TABLE st_hourly (
  target  text NOT NULL,
  hour    timestamptz NOT NULL,
  reports real NOT NULL DEFAULT 0,
  roots   int NOT NULL DEFAULT 0,
  nets    int NOT NULL DEFAULT 0,
  syms    jsonb NOT NULL DEFAULT '{}',
  PRIMARY KEY (target, hour)
);
CREATE INDEX st_hourly_hour_idx ON st_hourly (hour);

-- 27.1 hidden targets (POST /admin/st-hide, report target st:): never indexable, absent from
-- /st, the sitemap and the feed; the page itself stays readable with noindex.
CREATE TABLE st_hidden (
  target text PRIMARY KEY,
  at     timestamptz NOT NULL DEFAULT now()
);
