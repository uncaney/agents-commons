-- compute audit (SPEC-v2 14.5, 14.6): re-execution audits by operator-trusted donors and the
-- revoked list behind GET /att/revoked.txt. Expand-only: three new tables. audit_queue (priority
-- audits asked by cross-root cache hits, 14.1) is 0070's.

-- One row per audit of a finalised job: pending from the moment the kind='audit' copy is submitted
-- (audit = its job id) until the compute_audit janitor compares the two results. priority marks
-- the audits the queue asked for; reason carries the queue reason, then the settlement detail.
CREATE TABLE audits (
  id         bigserial PRIMARY KEY,
  job        text NOT NULL,
  audit      text NOT NULL DEFAULT '',
  priority   bool NOT NULL DEFAULT false,
  reason     text NOT NULL DEFAULT '',
  result     text NOT NULL DEFAULT 'pending' CHECK (result IN ('pending', 'match', 'mismatch', 'inconclusive')),
  at         timestamptz NOT NULL DEFAULT now(),
  settled_at timestamptz
);
CREATE INDEX audits_job_idx ON audits (job);
CREATE UNIQUE INDEX audits_audit_idx ON audits (audit) WHERE audit <> '';
CREATE INDEX audits_pending_idx ON audits (at) WHERE result = 'pending';
CREATE INDEX audits_at_idx ON audits (at);

-- Revoked results: a (wasm, input) pair whose result a trusted re-run contradicted (line = the
-- att1 receipt of the revoked job, job = its id) or a whole module (input = '') banned as a
-- compile bomb (compute.RevokeFn). RevokedFn reads it on every cache lookup; /att/revoked.txt
-- lists it; rows are kept one year (14.6).
CREATE TABLE revoked (
  wasm   text NOT NULL,
  input  text NOT NULL DEFAULT '',
  line   text NOT NULL DEFAULT '',
  reason text NOT NULL,
  job    text NOT NULL DEFAULT '',
  at     timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (wasm, input)
);
CREATE INDEX revoked_at_idx ON revoked (at);

-- Marker of the last hourly sampling pass (the janitor ticks every 30 s): one row, k = 'sample'.
CREATE TABLE audit_runs (
  k       text PRIMARY KEY,
  last_at timestamptz NOT NULL
);
