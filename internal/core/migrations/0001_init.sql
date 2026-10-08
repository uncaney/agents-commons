CREATE EXTENSION IF NOT EXISTS pg_trgm;

-- identities: roots (parent NULL, root = id) and subkeys. rep lives on the root row.
CREATE TABLE identities (
  id          text PRIMARY KEY,
  name        text NOT NULL,
  parent      text REFERENCES identities(id) ON DELETE CASCADE,
  root        text NOT NULL,
  token_hash  bytea NOT NULL UNIQUE,
  credits     bigint NOT NULL DEFAULT 0 CHECK (credits >= 0),
  rep         int NOT NULL DEFAULT 0,
  reg_ip      text NOT NULL DEFAULT '',
  created     timestamptz NOT NULL DEFAULT now(),
  expires_at  timestamptz,
  revoked_at  timestamptz
);
CREATE INDEX identities_root_idx ON identities (root);
CREATE INDEX identities_parent_idx ON identities (parent);

CREATE TABLE used_challenges (
  c   text PRIMARY KEY,
  exp timestamptz NOT NULL
);

CREATE TABLE reg_ips (
  ip text NOT NULL,
  at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX reg_ips_ip_at_idx ON reg_ips (ip, at);

-- freeze flags: reg|write|compute|all
CREATE TABLE flags (
  k       text PRIMARY KEY,
  v       boolean NOT NULL,
  updated timestamptz NOT NULL DEFAULT now()
);

-- daily counters: scope = root id or 'ip:<ip>'; kind = quota or rep-cap name.
CREATE TABLE counters (
  scope text NOT NULL,
  kind  text NOT NULL,
  day   date NOT NULL,
  n     int NOT NULL DEFAULT 0,
  PRIMARY KEY (scope, kind, day)
);

CREATE FUNCTION tags_text(text[]) RETURNS text
  LANGUAGE sql IMMUTABLE PARALLEL SAFE
  RETURN array_to_string($1, ' ');

CREATE TABLE kb (
  id           text PRIMARY KEY,
  kind         text NOT NULL CHECK (kind IN ('fix','status','note')),
  title        text NOT NULL,
  symptom      text NOT NULL DEFAULT '',
  cause        text NOT NULL DEFAULT '',
  fix          text NOT NULL DEFAULT '',
  versions     text NOT NULL DEFAULT '',
  tags         text[] NOT NULL DEFAULT '{}',
  author       text NOT NULL,
  author_root  text NOT NULL,
  ok_w         real NOT NULL DEFAULT 0,
  bad_w        real NOT NULL DEFAULT 0,
  created      timestamptz NOT NULL DEFAULT now(),
  confirmed_at timestamptz,
  expires_at   timestamptz NOT NULL,
  hidden       boolean NOT NULL DEFAULT false,
  tsv          tsvector GENERATED ALWAYS AS (
                 setweight(to_tsvector('english', title), 'A') ||
                 setweight(to_tsvector('english', symptom), 'B') ||
                 setweight(to_tsvector('english', cause), 'C') ||
                 setweight(to_tsvector('english', fix), 'C') ||
                 setweight(to_tsvector('english', tags_text(tags)), 'B')
               ) STORED
);
CREATE INDEX kb_tsv_idx ON kb USING GIN (tsv);
CREATE INDEX kb_trgm_idx ON kb USING GIN ((title || ' ' || symptom) gin_trgm_ops);
CREATE INDEX kb_created_idx ON kb (created DESC);
CREATE INDEX kb_author_root_idx ON kb (author_root);
CREATE INDEX kb_expires_idx ON kb (expires_at);

CREATE TABLE kb_votes (
  kb_id   text NOT NULL REFERENCES kb(id) ON DELETE CASCADE,
  root    text NOT NULL,
  up      boolean NOT NULL,
  w       real NOT NULL,
  note    text NOT NULL DEFAULT '',
  created timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (kb_id, root)
);
CREATE INDEX kb_votes_root_idx ON kb_votes (root);

-- board ledger (issues live in Forgejo; this maps issue number -> creator for quotas/purge)
CREATE TABLE tasks (
  n       bigint PRIMARY KEY,
  id      text NOT NULL,
  root    text NOT NULL,
  created timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX tasks_root_idx ON tasks (root);

CREATE TABLE task_claims (
  n     bigint PRIMARY KEY,
  id    text NOT NULL,
  root  text NOT NULL,
  until timestamptz NOT NULL
);
CREATE INDEX task_claims_until_idx ON task_claims (until);

-- notes ledger (pages live in the Forgejo wiki)
CREATE TABLE notes (
  owner   text NOT NULL,
  name    text NOT NULL,
  root    text NOT NULL,
  size    int NOT NULL DEFAULT 0,
  updated timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (owner, name)
);
CREATE INDEX notes_root_idx ON notes (root);

CREATE TABLE forge_outbox (
  id       bigserial PRIMARY KEY,
  kind     text NOT NULL,
  ref      text NOT NULL,
  payload  bytea NOT NULL,
  attempts int NOT NULL DEFAULT 0,
  next_at  timestamptz NOT NULL DEFAULT now(),
  last_err text NOT NULL DEFAULT '',
  created  timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX forge_outbox_next_idx ON forge_outbox (next_at);

CREATE TABLE blobs (
  hash       text PRIMARY KEY,
  size       bigint NOT NULL,
  owner_root text NOT NULL,
  last_ref   timestamptz NOT NULL DEFAULT now(),
  created    timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX blobs_owner_idx ON blobs (owner_root);
CREATE INDEX blobs_last_ref_idx ON blobs (last_ref);

CREATE TABLE jobs (
  id          text PRIMARY KEY,
  submitter   text NOT NULL,
  root        text NOT NULL,
  wasm        text NOT NULL,
  input       text NOT NULL,
  ms          int NOT NULL,
  mb          int NOT NULL,
  reserved    bigint NOT NULL DEFAULT 0,
  status      text NOT NULL DEFAULT 'queued' CHECK (status IN ('queued','running','done','failed')),
  out         text NOT NULL DEFAULT '',
  used_ms     int NOT NULL DEFAULT 0,
  reason      text NOT NULL DEFAULT '',
  created     timestamptz NOT NULL DEFAULT now(),
  finished_at timestamptz
);
CREATE INDEX jobs_root_idx ON jobs (root);
CREATE INDEX jobs_active_idx ON jobs (status) WHERE status IN ('queued','running');

CREATE TABLE replicas (
  id          bigserial PRIMARY KEY,
  job         text NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
  state       text NOT NULL DEFAULT 'queued' CHECK (state IN ('queued','leased','reported')),
  lease       text UNIQUE,
  worker      text,
  worker_root text,
  deadline    timestamptz,
  status      text,
  code        int,
  out         text,
  ms          int,
  reported_at timestamptz,
  created     timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX replicas_job_idx ON replicas (job);
CREATE INDEX replicas_queued_idx ON replicas (created) WHERE state = 'queued';
CREATE INDEX replicas_leased_idx ON replicas (deadline) WHERE state = 'leased';

CREATE TABLE reports (
  target   text NOT NULL,
  reporter text NOT NULL,
  why      text NOT NULL DEFAULT '',
  created  timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (target, reporter)
);
