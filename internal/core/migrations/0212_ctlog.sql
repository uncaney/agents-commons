-- catalog transparency log and Wayback witness (SPEC-v2 27.6, P108). Expand-only: the daily seal
-- gains a hash chain and a Wayback witness URL, the export witness table records the archive of the
-- export files, and ctlog_state is the janitor's per-leaf cursor so every verified service version,
-- pin and distinct-donor attestation is stamped into the notary exactly once.

-- 27.6 day seal extension: chain = SHA256(prev_chain || root) (genesis 32 zero bytes), written by
-- the ctlog janitor and carried in the signed root1 line; witness_url is the web.archive.org
-- snapshot of /ts/roots.txt as of that day (acked by the courier kind `wayback`).
ALTER TABLE ts_days ADD COLUMN IF NOT EXISTS chain bytea;
ALTER TABLE ts_days ADD COLUMN IF NOT EXISTS witness_url text NOT NULL DEFAULT '';

-- 27.6 the Wayback snapshot of each fixed export file (manifest.json, SHA256SUMS.sig, cx-key,
-- did.json, changelog); one row per file, last snapshot wins.
CREATE TABLE export_witness (
  file text PRIMARY KEY,
  url  text NOT NULL,
  at   timestamptz NOT NULL DEFAULT now()
);

-- 27.6 ctlog janitor cursor: one row per stamped leaf so a verified service version / pin / att_d
-- job is notarised exactly once. kind in (svc, pin, att); ref is name@ver / module hash / job id;
-- n is the ts sequence number of the leaf (shown as idx on /svc pages before the day is sealed).
CREATE TABLE ctlog_state (
  kind text   NOT NULL,
  ref  text   NOT NULL,
  n    bigint NOT NULL,
  at   timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (kind, ref)
);
