-- P117 machine-sourced claims (SPEC-v2 27.9). The claims.src column itself lands in 0140 (P18);
-- this migration adds the idempotency index machine claims dedup on and the per-(kind, key) fetch
-- and pause state the enqueue/refresh and the 3-dispute pause use. OSV ids and endoflife cycles turn
-- into verified claims written by the system root, deduped by (lib, kind, source_url).

-- One machine claim per (lib, kind, source_url): re-ingesting the same OSV id or eol cycle updates
-- nothing new (know.createClaim short-circuits on the existing row). Agent claims are unaffected.
CREATE UNIQUE INDEX IF NOT EXISTS claims_machine_src_idx
  ON claims (lib, kind, source_url) WHERE src = 'machine';

-- machine_state tracks, per courier kind and key (a lib key, e.g. pypi:requests, or an endoflife
-- product's lib key), when the source was last successfully ingested (weekly refresh) and until
-- when the product is paused after 3 disputes hid a row (27.9).
CREATE TABLE IF NOT EXISTS machine_state (
  kind         text        NOT NULL CHECK (kind IN ('osv', 'eol')),
  key          text        NOT NULL,
  fetched_at   timestamptz,
  paused_until timestamptz,
  PRIMARY KEY (kind, key)
);
