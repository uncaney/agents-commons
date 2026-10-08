-- catalog (SPEC-v2 15.1-15.3, 27.6): WASM service names, their versions (one hash each), votes,
-- the calls ledger that settles fees and feeds stats, and pin requests for modules above 4 MiB.
-- Expand-only. "desc" is quoted: it is the SPEC column name and a SQL keyword.

CREATE TABLE services (
  name            text PRIMARY KEY CHECK (name ~ '^[a-z0-9][a-z0-9-]{1,31}$'),
  owner_root      text NOT NULL,
  "desc"          text NOT NULL DEFAULT '' CHECK (length("desc") <= 200),
  usage           text NOT NULL DEFAULT '' CHECK (length(usage) <= 600),
  stable_ver      int NOT NULL DEFAULT 0,
  stable_at       timestamptz,
  calls           bigint NOT NULL DEFAULT 0,
  other_calls     bigint NOT NULL DEFAULT 0,
  last_other_call timestamptz,
  hidden          bool NOT NULL DEFAULT false,
  hidden_at       timestamptz,
  nocons_run      int NOT NULL DEFAULT 0,
  created         timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX services_owner_idx ON services (owner_root);

CREATE TABLE service_versions (
  name             text NOT NULL REFERENCES services(name) ON DELETE CASCADE,
  ver              int NOT NULL CHECK (ver > 0),
  wasm             text NOT NULL,
  size             bigint NOT NULL DEFAULT 0,
  fs               text NOT NULL DEFAULT '',
  manifest         jsonb NOT NULL DEFAULT '{}'::jsonb CHECK (octet_length(manifest::text) <= 4096),
  created          timestamptz NOT NULL DEFAULT now(),
  state            text NOT NULL DEFAULT 'pending' CHECK (state IN ('pending', 'verified', 'rejected', 'failing')),
  tested           text NOT NULL DEFAULT '' CHECK (length(tested) <= 300),
  kat_jobs         text[] NOT NULL DEFAULT '{}',
  kat_retries      int NOT NULL DEFAULT 0,
  recheck_job      text NOT NULL DEFAULT '',
  verified_at      timestamptz,
  rechecked_at     timestamptz,
  failing_since    timestamptz,
  nondeterministic bool NOT NULL DEFAULT false,
  ok_w             real NOT NULL DEFAULT 0,
  bad_w            real NOT NULL DEFAULT 0,
  calls            bigint NOT NULL DEFAULT 0,
  fails            bigint NOT NULL DEFAULT 0,
  nocons           bigint NOT NULL DEFAULT 0,
  ms_p50           int NOT NULL DEFAULT 0,
  ms_samples       int[] NOT NULL DEFAULT '{}',
  lexicon          int NOT NULL DEFAULT 0,
  flags            text[] NOT NULL DEFAULT '{}',
  hazard           text[] NOT NULL DEFAULT '{}',
  PRIMARY KEY (name, ver),
  UNIQUE (name, wasm)
);
CREATE INDEX service_versions_state_idx ON service_versions (state);
CREATE INDEX service_versions_wasm_idx ON service_versions (wasm);

CREATE TABLE service_votes (
  name     text NOT NULL,
  ver      int NOT NULL,
  root     text NOT NULL,
  ip_group text NOT NULL DEFAULT '',
  ip_super text NOT NULL DEFAULT '',
  up       bool NOT NULL,
  w        real NOT NULL,
  lvl      int NOT NULL DEFAULT 0,
  note     text NOT NULL DEFAULT '' CHECK (length(note) <= 200),
  created  timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (name, ver, root),
  FOREIGN KEY (name, ver) REFERENCES service_versions(name, ver) ON DELETE CASCADE
);
CREATE INDEX service_votes_root_idx ON service_votes (root);

-- one row per call through the catalog: the fee held until the job settles (OnDone), the stats
-- source (7d=, fail=, calls from other roots) and the vote eligibility window.
CREATE TABLE service_calls (
  job     text PRIMARY KEY,
  name    text NOT NULL,
  ver     int NOT NULL,
  caller  text NOT NULL,
  root    text NOT NULL,
  fee     int NOT NULL DEFAULT 0,
  settled bool NOT NULL DEFAULT false,
  created timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX service_calls_name_created_idx ON service_calls (name, ver, created);
CREATE INDEX service_calls_root_idx ON service_calls (root, created);
CREATE INDEX service_calls_unsettled_idx ON service_calls (created) WHERE NOT settled;

-- pin requests (15.2): L2 roots, one per week per root, delivered to the operator inbox as an event.
CREATE TABLE service_pin_requests (
  root    text NOT NULL,
  name    text NOT NULL,
  hash    text NOT NULL,
  size    bigint NOT NULL DEFAULT 0,
  created timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX service_pin_requests_root_idx ON service_pin_requests (root, created);
