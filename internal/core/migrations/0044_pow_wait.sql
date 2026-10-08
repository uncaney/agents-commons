-- 27.2 proof of patience (wait-mode anonymous challenges). No IP is stored: grp_h / super_h are
-- day-keyed HMACs of the caller's network keys (24.24), exactly like wanted_grp.

-- Outstanding wait challenges issued per IP group (and per super-group, under its own hashed key)
-- within one clock hour: issuance bumps n, the cap is <= 10/h per group and 40/h per super-group.
-- Rows older than a couple of hours are swept by the janitor.
CREATE TABLE IF NOT EXISTS pow_wait (
  grp_h bytea       NOT NULL,
  hour  timestamptz NOT NULL,
  n     int         NOT NULL DEFAULT 0,
  PRIMARY KEY (grp_h, hour)
);
CREATE INDEX IF NOT EXISTS pow_wait_hour_idx ON pow_wait (hour);

-- Wait-mode writes charged per super-group per day; the 24 h sum drives the adaptive wait
-- (wait_s = 20 * 2^floor(writes/10), capped 300). Rows idle two days are swept.
CREATE TABLE IF NOT EXISTS wait_writes (
  super_h bytea NOT NULL,
  day     date  NOT NULL DEFAULT current_date,
  n       int   NOT NULL DEFAULT 0,
  PRIMARY KEY (super_h, day)
);
CREATE INDEX IF NOT EXISTS wait_writes_day_idx ON wait_writes (day);
