-- compute v2 (SPEC-v2 14.1-14.4, 14.6, 27.6): result cache, attestations, lifecycle, caps and pins,
-- blob metadata (wasmscan / zipscan), private lanes, donor diagnostics and signatures, blob tenure.
-- Expand-only: defaulted or nullable columns, new tables, one widened CHECK (replicas.state gains
-- 'cancelled'). jobs.att holds the signed att1 statement line and jobs.att_sig its "sig=<b64url>".

ALTER TABLE jobs
  ADD COLUMN IF NOT EXISTS att text NOT NULL DEFAULT '',
  ADD COLUMN IF NOT EXISTS att_sig text NOT NULL DEFAULT '',
  ADD COLUMN IF NOT EXISTS att_d bool NOT NULL DEFAULT false,
  ADD COLUMN IF NOT EXISTS cache_scope text NOT NULL DEFAULT 'root',
  ADD COLUMN IF NOT EXISTS cached_from text NOT NULL DEFAULT '',
  ADD COLUMN IF NOT EXISTS wasm_size bigint NOT NULL DEFAULT 0,
  ADD COLUMN IF NOT EXISTS svc text NOT NULL DEFAULT '',
  ADD COLUMN IF NOT EXISTS kind text NOT NULL DEFAULT 'job',
  ADD COLUMN IF NOT EXISTS published bool NOT NULL DEFAULT false,
  ADD COLUMN IF NOT EXISTS max_wait_until timestamptz,
  ADD COLUMN IF NOT EXISTS fs text NOT NULL DEFAULT '',
  ADD COLUMN IF NOT EXISTS lane text NOT NULL DEFAULT 'public',
  ADD COLUMN IF NOT EXISTS sub_lvl int NOT NULL DEFAULT 0,
  ADD COLUMN IF NOT EXISTS pipe text NOT NULL DEFAULT '',
  ADD COLUMN IF NOT EXISTS bounty text NOT NULL DEFAULT '',
  ADD COLUMN IF NOT EXISTS sub text NOT NULL DEFAULT '',
  ADD COLUMN IF NOT EXISTS charged bigint NOT NULL DEFAULT 0,
  ADD COLUMN IF NOT EXISTS saved_ms int NOT NULL DEFAULT 0,
  ADD COLUMN IF NOT EXISTS saved_credits int NOT NULL DEFAULT 0;
ALTER TABLE jobs ADD CONSTRAINT jobs_kind_check CHECK (kind IN ('job', 'audit', 'kat'));
ALTER TABLE jobs ADD CONSTRAINT jobs_lane_check CHECK (lane IN ('public', 'own', 'trusted'));
ALTER TABLE jobs ADD CONSTRAINT jobs_cache_scope_check CHECK (cache_scope IN ('root', 'global', 'revoked'));
-- 14.1 result cache key (wasm, input, fs, mb) over finished jobs; 14.6 retention by finished_at.
CREATE INDEX IF NOT EXISTS jobs_cache_idx ON jobs (wasm, input, fs, mb) WHERE status = 'done';
CREATE INDEX IF NOT EXISTS jobs_finished_idx ON jobs (finished_at) WHERE finished_at IS NOT NULL;
CREATE INDEX IF NOT EXISTS jobs_max_wait_idx ON jobs (max_wait_until) WHERE max_wait_until IS NOT NULL AND status IN ('queued', 'running');
CREATE INDEX IF NOT EXISTS jobs_cached_from_idx ON jobs (root) WHERE cached_from <> '';

-- 14.3 cancelled leases answer 410 to the donor's done; 27.6 diagnostics and donor signature;
-- leased_at feeds p50_wait_s of /v1/w/stats.
ALTER TABLE replicas
  ADD COLUMN IF NOT EXISTS diag jsonb,
  ADD COLUMN IF NOT EXISTS dsig bytea,
  ADD COLUMN IF NOT EXISTS leased_at timestamptz;
ALTER TABLE replicas DROP CONSTRAINT IF EXISTS replicas_state_check;
ALTER TABLE replicas ADD CONSTRAINT replicas_state_check CHECK (state IN ('queued', 'leased', 'reported', 'cancelled'));

-- 14.2 / 14.4 / 27.6 blobs: public (published), pinned_by (admin|seed), kind sniffed at upload,
-- tenure (used_at set by Submit, touches = re-uploads), private (owner-only, 24 h, own lane).
ALTER TABLE blobs
  ADD COLUMN IF NOT EXISTS public bool NOT NULL DEFAULT false,
  ADD COLUMN IF NOT EXISTS pinned_by text NOT NULL DEFAULT '',
  ADD COLUMN IF NOT EXISTS kind text NOT NULL DEFAULT 'opaque',
  ADD COLUMN IF NOT EXISTS used_at timestamptz,
  ADD COLUMN IF NOT EXISTS touches int NOT NULL DEFAULT 0,
  ADD COLUMN IF NOT EXISTS private bool NOT NULL DEFAULT false;
ALTER TABLE blobs ADD CONSTRAINT blobs_kind_check CHECK (kind IN ('wasm', 'text', 'opaque'));
-- v1 rows predate tenure: they keep the 7-day last_ref TTL only.
UPDATE blobs SET used_at = created WHERE used_at IS NULL;
CREATE INDEX IF NOT EXISTS blobs_tenure_idx ON blobs (created) WHERE used_at IS NULL;

-- 14.3 / 27.6 blob metadata: wasmscan (wasm), zipscan (zip), tier-1 scan of UTF-8 inputs and of
-- wasm data segments (text). Not a foreign key: a banned module keeps its row after GC so the
-- compile-bomb memory survives re-uploads (gc deletes rows whose banned = '').
CREATE TABLE blob_meta (
  hash             text PRIMARY KEY,
  kind             text NOT NULL DEFAULT 'wasm' CHECK (kind IN ('wasm', 'zip', 'text')),
  size             bigint NOT NULL DEFAULT 0,
  imports          jsonb NOT NULL DEFAULT '[]',
  import_count     int NOT NULL DEFAULT 0,
  bad_import       text NOT NULL DEFAULT '',
  has_memory       bool NOT NULL DEFAULT false,
  min_pages        bigint NOT NULL DEFAULT 0,
  max_pages        bigint NOT NULL DEFAULT 0,
  has_max          bool NOT NULL DEFAULT false,
  memory64         bool NOT NULL DEFAULT false,
  funcs            int NOT NULL DEFAULT 0,
  has_start        bool NOT NULL DEFAULT false,
  producers        text NOT NULL DEFAULT '',
  truncated        bool NOT NULL DEFAULT false,
  parse_err        text NOT NULL DEFAULT '',
  entries          int NOT NULL DEFAULT 0,
  unpacked         bigint NOT NULL DEFAULT 0,
  fs_unusable      text NOT NULL DEFAULT '',
  runs_ok          int NOT NULL DEFAULT 0,
  ok_roots         text[] NOT NULL DEFAULT '{}',
  compile_timeouts int NOT NULL DEFAULT 0,
  ct_roots         text[] NOT NULL DEFAULT '{}',
  banned           text NOT NULL DEFAULT '',
  secret_kinds     text[] NOT NULL DEFAULT '{}',
  compile_ms       int[] NOT NULL DEFAULT '{}',
  mem_pages        int[] NOT NULL DEFAULT '{}',
  created          timestamptz NOT NULL DEFAULT now()
);

-- 14.4 pins: modules above 4 MiB a donor may opt into (admin, or catalog seeds with note 'seed').
CREATE TABLE pins (
  hash    text PRIMARY KEY,
  name    text NOT NULL,
  ver     text NOT NULL DEFAULT '',
  size    bigint NOT NULL DEFAULT 0,
  note    text NOT NULL DEFAULT '',
  created timestamptz NOT NULL DEFAULT now()
);

-- 14.2 reproductions (POST /v1/j/{id}/reproduce, P13b writes; repro=<k>/<n> on /att pages).
CREATE TABLE reproductions (
  job     text NOT NULL,
  by_root text NOT NULL,
  match   bool NOT NULL,
  at      timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX reproductions_job_idx ON reproductions (job);

-- 14.6 retention: finished jobs/replicas > 30 d are rolled up here, then deleted.
CREATE TABLE job_stats_daily (
  day           date PRIMARY KEY,
  jobs          bigint NOT NULL DEFAULT 0,
  ms            bigint NOT NULL DEFAULT 0,
  credits       bigint NOT NULL DEFAULT 0,
  cached        bigint NOT NULL DEFAULT 0,
  saved_ms      bigint NOT NULL DEFAULT 0,
  saved_credits bigint NOT NULL DEFAULT 0
);

-- 14.1 / 14.5 priority audits: a root-scoped cached result another root asked for (served first by
-- the hourly compute_audit of P45).
CREATE TABLE audit_queue (
  job    text PRIMARY KEY,
  reason text NOT NULL DEFAULT '',
  at     timestamptz NOT NULL DEFAULT now()
);
