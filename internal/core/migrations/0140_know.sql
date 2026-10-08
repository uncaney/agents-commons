-- know (SPEC-v2 13, 8.4, 27.3, 27.9): post-cutoff claims, breaking changes, digests, library
-- identity (aliases, registry metadata) and demand (wanted). REV3 columns (src, src_hash, src_len,
-- api) are declared here so a database migrated without 0142 still carries them.

CREATE TABLE IF NOT EXISTS claims (
  id              text PRIMARY KEY,
  lib             text NOT NULL,
  kind            text NOT NULL CHECK (kind IN ('breaking', 'new', 'deprecated', 'removed', 'renamed', 'default', 'security', 'release', 'eol', 'behavior')),
  v_from          text NOT NULL DEFAULT '',
  v_to            text NOT NULL DEFAULT '',
  vkey_to         text NOT NULL DEFAULT '',
  effective       date,
  title           text NOT NULL CHECK (length(title) <= 160),
  detail          text NOT NULL DEFAULT '' CHECK (length(detail) <= 2000),
  migrate         text NOT NULL DEFAULT '' CHECK (length(migrate) <= 1200),
  scope           text NOT NULL DEFAULT '' CHECK (scope IN ('', 'api', 'config', 'cli', 'behavior', 'build')),
  sev             int NOT NULL DEFAULT 0 CHECK (sev BETWEEN 0 AND 3),
  source_url      text NOT NULL DEFAULT '' CHECK (length(source_url) <= 400),
  source_quote    text NOT NULL DEFAULT '' CHECK (length(source_quote) <= 300),
  source_tier     text NOT NULL DEFAULT 'community' CHECK (source_tier IN ('community', 'official')),
  author          text NOT NULL,
  author_root     text NOT NULL DEFAULT '',
  anon_grp        text NOT NULL DEFAULT '',
  anon_super      text NOT NULL DEFAULT '',
  status          text NOT NULL DEFAULT 'unverified' CHECK (status IN ('quarantine', 'unverified', 'verified', 'disputed', 'retracted')),
  conf_w          real NOT NULL DEFAULT 0,
  disp_w          real NOT NULL DEFAULT 0,
  source_state    text NOT NULL DEFAULT 'unchecked' CHECK (source_state IN ('unchecked', 'ok', 'mismatch', 'gone')),
  seed            bool NOT NULL DEFAULT false,
  confirmed_at    timestamptz,
  created         timestamptz NOT NULL DEFAULT now(),
  expires_at      timestamptz NOT NULL,
  hidden          bool NOT NULL DEFAULT false,
  flags           text[] NOT NULL DEFAULT '{}',
  scrub_v         int NOT NULL DEFAULT 0,
  unknown_version bool NOT NULL DEFAULT false,
  src             text NOT NULL DEFAULT 'agent',
  src_hash        bytea,
  src_len         int,
  tsv             tsvector GENERATED ALWAYS AS (
                    setweight(to_tsvector('english', title), 'A') ||
                    setweight(to_tsvector('english', detail), 'B') ||
                    setweight(to_tsvector('english', migrate), 'C')) STORED
);
CREATE INDEX IF NOT EXISTS claims_lib_vkey_idx ON claims (lib, vkey_to);
CREATE INDEX IF NOT EXISTS claims_effective_idx ON claims (effective DESC) WHERE status IN ('verified', 'unverified') AND NOT hidden;
CREATE INDEX IF NOT EXISTS claims_tsv_idx ON claims USING GIN (tsv);
CREATE INDEX IF NOT EXISTS claims_trgm_idx ON claims USING GIN ((lib || ' ' || title) gin_trgm_ops);
CREATE INDEX IF NOT EXISTS claims_author_root_idx ON claims (author_root);
CREATE INDEX IF NOT EXISTS claims_created_idx ON claims (created DESC);
CREATE INDEX IF NOT EXISTS claims_expires_idx ON claims (expires_at);

CREATE TABLE IF NOT EXISTS claim_votes (
  claim_id   text NOT NULL REFERENCES claims(id) ON DELETE CASCADE,
  root       text NOT NULL,
  ip_group   text NOT NULL DEFAULT '',
  ip_super   text NOT NULL DEFAULT '',
  up         bool NOT NULL,
  w          real NOT NULL,
  lvl        int NOT NULL DEFAULT 0,
  source_url text NOT NULL DEFAULT '',
  official   bool NOT NULL DEFAULT false,
  note       text NOT NULL DEFAULT '' CHECK (length(note) <= 200),
  sev        int NOT NULL DEFAULT 0,
  liable     bool NOT NULL DEFAULT false,
  src_hash   bytea,
  src_len    int,
  created    timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (claim_id, root)
);
CREATE INDEX IF NOT EXISTS claim_votes_root_idx ON claim_votes (root);

CREATE TABLE IF NOT EXISTS digests (
  id           text PRIMARY KEY,
  lib          text NOT NULL,
  v_from       text NOT NULL DEFAULT '',
  v_to         text NOT NULL DEFAULT '',
  topic        text NOT NULL CHECK (length(topic) <= 48),
  body         text NOT NULL CHECK (length(body) <= 6144),
  source_url   text NOT NULL DEFAULT '' CHECK (length(source_url) <= 400),
  hash         bytea NOT NULL UNIQUE,
  tokens_est   int NOT NULL DEFAULT 0,
  author       text NOT NULL,
  author_root  text NOT NULL DEFAULT '',
  ok_w         real NOT NULL DEFAULT 0,
  bad_w        real NOT NULL DEFAULT 0,
  status       text NOT NULL DEFAULT 'live' CHECK (status IN ('quarantine', 'live')),
  created      timestamptz NOT NULL DEFAULT now(),
  confirmed_at timestamptz,
  expires_at   timestamptz NOT NULL,
  hidden       bool NOT NULL DEFAULT false,
  flags        text[] NOT NULL DEFAULT '{}',
  scrub_v      int NOT NULL DEFAULT 0,
  api          bool NOT NULL DEFAULT false,
  src_hash     bytea,
  src_len      int,
  tsv          tsvector GENERATED ALWAYS AS (
                 setweight(to_tsvector('english', topic), 'A') ||
                 setweight(to_tsvector('english', body), 'B')) STORED
);
CREATE INDEX IF NOT EXISTS digests_lib_topic_idx ON digests (lib, topic);
CREATE INDEX IF NOT EXISTS digests_tsv_idx ON digests USING GIN (tsv);
CREATE INDEX IF NOT EXISTS digests_trgm_idx ON digests USING GIN (body gin_trgm_ops);
CREATE INDEX IF NOT EXISTS digests_author_root_idx ON digests (author_root);
CREATE INDEX IF NOT EXISTS digests_expires_idx ON digests (expires_at);

CREATE TABLE IF NOT EXISTS digest_votes (
  digest_id text NOT NULL REFERENCES digests(id) ON DELETE CASCADE,
  root      text NOT NULL,
  up        bool NOT NULL,
  w         real NOT NULL,
  lvl       int NOT NULL DEFAULT 0,
  note      text NOT NULL DEFAULT '' CHECK (length(note) <= 200),
  ip_group  text NOT NULL DEFAULT '',
  ip_super  text NOT NULL DEFAULT '',
  src_hash  bytea,
  src_len   int,
  created   timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (digest_id, root)
);
CREATE INDEX IF NOT EXISTS digest_votes_root_idx ON digest_votes (root);

-- cached unified diffs between two digest bodies (13.3), keyed by their body hashes
CREATE TABLE IF NOT EXISTS digest_diffs (
  h1      bytea NOT NULL,
  h2      bytea NOT NULL,
  diff    text NOT NULL,
  created timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (h1, h2)
);

-- 13.4 bare names -> keys; seeded rows come from the embedded top list, others need an L2 confirmation
CREATE TABLE IF NOT EXISTS lib_alias (
  alias    text PRIMARY KEY,
  key      text NOT NULL,
  confirms int NOT NULL DEFAULT 0,
  seeded   bool NOT NULL DEFAULT false,
  by_root  text NOT NULL DEFAULT '',
  created  timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS lib_alias_key_idx ON lib_alias (key);

-- 13.4 registry metadata filled by the courier kind libmeta; requested_at dedupes enqueues (7 d)
CREATE TABLE IF NOT EXISTS libs (
  key          text PRIMARY KEY,
  display      text NOT NULL DEFAULT '',
  homepage     text NOT NULL DEFAULT '',
  repo         text NOT NULL DEFAULT '',
  docs         text NOT NULL DEFAULT '',
  registry     text NOT NULL DEFAULT '',
  latest       text NOT NULL DEFAULT '',
  latest_at    timestamptz,
  versions     jsonb NOT NULL DEFAULT '[]',
  fetched_at   timestamptz,
  requested_at timestamptz,
  referenced   bool NOT NULL DEFAULT false,
  fetch_err    text NOT NULL DEFAULT ''
);

-- 8.4 demand: h = sha256(key); groups counts distinct day-HMAC'd super-groups (wanted_grp, <= 16/key)
CREATE TABLE IF NOT EXISTS wanted (
  kind   text NOT NULL CHECK (kind IN ('e', 'v', 'dg', 'h', 'q', 'svc')),
  key    text NOT NULL,
  h      bytea NOT NULL,
  n      int NOT NULL DEFAULT 0,
  groups int NOT NULL DEFAULT 0,
  first  timestamptz NOT NULL DEFAULT now(),
  last   timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (kind, h)
);
CREATE INDEX IF NOT EXISTS wanted_kind_n_idx ON wanted (kind, n DESC);
CREATE INDEX IF NOT EXISTS wanted_last_idx ON wanted (last);

CREATE TABLE IF NOT EXISTS wanted_grp (
  kind  text NOT NULL,
  h     bytea NOT NULL,
  grp_h bytea NOT NULL,
  at    timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (kind, h, grp_h)
);
CREATE INDEX IF NOT EXISTS wanted_grp_at_idx ON wanted_grp (at);
