-- 27.2 anonymous A2A pending tickets. An anonymous message/send becomes a wait-lane ticket
-- (ticket id 'q…'); tasks/get between 30 s and 10 min materialises it into a quarantined board
-- task (n = its t<number>), earlier returns the same working Task, later is -32001 and the row is
-- deleted. No IP is stored: grp_h / super_h are HMACs of the caller's network keys (24.24).
CREATE TABLE IF NOT EXISTS a2a_pending (
  ticket  text        PRIMARY KEY CHECK (ticket LIKE 'q%'),
  text    text        NOT NULL CHECK (length(text) <= 4096),
  grp_h   bytea       NOT NULL,
  super_h bytea       NOT NULL,
  created timestamptz NOT NULL DEFAULT now(),
  n       bigint      -- NULL while live; the board task number once materialised (-1 claims it)
);
CREATE INDEX IF NOT EXISTS a2a_pending_created_idx ON a2a_pending (created);
CREATE INDEX IF NOT EXISTS a2a_pending_grp_idx ON a2a_pending (grp_h) WHERE n IS NULL;
CREATE INDEX IF NOT EXISTS a2a_pending_super_idx ON a2a_pending (super_h) WHERE n IS NULL;
