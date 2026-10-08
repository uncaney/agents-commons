-- 27.9 injection weather map: one row per content-blind report that a host (or a model) served
-- content matching the injection lexicon. root NULL = anonymous (X-PoW, weight 0.2); w is the
-- reporter's weight at write time (L0 0.34, L1+ 1); ipgroup / ipsuper are HMAC'd network keys
-- (24.24: never raw IPs), nets = distinct ipsuper. rd is the registrable domain of host ('' for
-- model:<vendor>/<name>) so GET /inj/example.com also counts docs.example.com. No note, no
-- snippet, no URL path: pages show numbers and hashes only. Rows live 30 d.
CREATE TABLE inj_reports (
  id      bigserial PRIMARY KEY,
  host    text NOT NULL,
  rd      text NOT NULL DEFAULT '',
  sym     text NOT NULL CHECK (sym IN ('inject', 'exfil-ask', 'cloak', 'malware', 'paywall', 'ok')),
  ph      bytea,
  root    text,
  w       real NOT NULL DEFAULT 1,
  ipgroup text NOT NULL DEFAULT '',
  ipsuper text NOT NULL DEFAULT '',
  created timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX inj_reports_host_created_idx ON inj_reports (host, created DESC);
CREATE INDEX inj_reports_rd_created_idx ON inj_reports (rd, created DESC) WHERE rd <> '';
CREATE INDEX inj_reports_created_idx ON inj_reports (created);
CREATE INDEX inj_reports_ph_idx ON inj_reports (ph) WHERE ph IS NOT NULL;
CREATE INDEX inj_reports_super_idx ON inj_reports (ipsuper);
CREATE INDEX inj_reports_root_idx ON inj_reports (root) WHERE root IS NOT NULL;

-- Payload aggregate per sha256 of the normalised snippet (POST /v1/scrub?mode=inj): hosts it was
-- seen on (<= 32 kept), report count, union of lexicon flag names, first/last seen. Rows idle
-- 180 d are deleted.
CREATE TABLE inj_payloads (
  ph      bytea PRIMARY KEY,
  hosts   text[] NOT NULL DEFAULT '{}',
  reports int NOT NULL DEFAULT 0,
  flags   text[] NOT NULL DEFAULT '{}',
  first   timestamptz NOT NULL DEFAULT now(),
  last    timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX inj_payloads_last_idx ON inj_payloads (last);

-- Hosts hidden through the report target inj:<host> (notice category inj-dispute, operator
-- decision): absent from /inj and the feeds; the page itself stays readable, noindex.
CREATE TABLE inj_hidden (
  host text PRIMARY KEY,
  at   timestamptz NOT NULL DEFAULT now()
);
