-- kb v2 (SPEC-v2 6.1): quarantine, anonymous rows, hazards, lexicon flags, revisions, applies,
-- spaces, seed rows, attestations, negative knowledge on votes, versions index, read telemetry,
-- tombstones. Expand-only: every column is nullable or defaulted; nothing is renamed or dropped.
ALTER TABLE kb
  ADD COLUMN IF NOT EXISTS quarantine bool NOT NULL DEFAULT false,
  ADD COLUMN IF NOT EXISTS anon_grp text NOT NULL DEFAULT '',
  ADD COLUMN IF NOT EXISTS anon_super text NOT NULL DEFAULT '',
  ADD COLUMN IF NOT EXISTS hazard text[] NOT NULL DEFAULT '{}',
  ADD COLUMN IF NOT EXISTS flags text[] NOT NULL DEFAULT '{}',
  ADD COLUMN IF NOT EXISTS rev int NOT NULL DEFAULT 1,
  ADD COLUMN IF NOT EXISTS edited_by text NOT NULL DEFAULT '',
  ADD COLUMN IF NOT EXISTS edited_after_confirm bool NOT NULL DEFAULT false,
  ADD COLUMN IF NOT EXISTS ok_w_prev real NOT NULL DEFAULT 0,
  ADD COLUMN IF NOT EXISTS superseded_by text NOT NULL DEFAULT '',
  ADD COLUMN IF NOT EXISTS applies jsonb NOT NULL DEFAULT '[]',
  ADD COLUMN IF NOT EXISTS space text NOT NULL DEFAULT '',
  ADD COLUMN IF NOT EXISTS seed bool NOT NULL DEFAULT false,
  ADD COLUMN IF NOT EXISTS att text NOT NULL DEFAULT '',
  ADD COLUMN IF NOT EXISTS license text NOT NULL DEFAULT '',
  ADD COLUMN IF NOT EXISTS why_safe text NOT NULL DEFAULT '',
  ADD COLUMN IF NOT EXISTS scrub_v int NOT NULL DEFAULT 0,
  ADD COLUMN IF NOT EXISTS stale bool NOT NULL DEFAULT false,
  ADD COLUMN IF NOT EXISTS restored_at timestamptz,
  ADD COLUMN IF NOT EXISTS immune_until timestamptz,
  -- when the row was hidden (votes, reports, notices): the 30 d appeal window of 4.7 counts from here
  ADD COLUMN IF NOT EXISTS hidden_at timestamptz;

-- author_root is '' for anonymous rows (author 'anon'); the v1 NOT NULL stays.
-- kind gains antipattern (6.3).
ALTER TABLE kb DROP CONSTRAINT IF EXISTS kb_kind_check;
ALTER TABLE kb ADD CONSTRAINT kb_kind_check CHECK (kind IN ('fix', 'status', 'note', 'antipattern'));

CREATE INDEX IF NOT EXISTS kb_tags_idx ON kb USING GIN (tags);
CREATE INDEX IF NOT EXISTS kb_space_created_idx ON kb (space, created DESC) WHERE space <> '';
CREATE INDEX IF NOT EXISTS kb_quarantine_idx ON kb (quarantine) WHERE quarantine;
CREATE INDEX IF NOT EXISTS kb_hidden_at_idx ON kb (hidden_at) WHERE hidden;

ALTER TABLE kb_votes
  ADD COLUMN IF NOT EXISTS ip_group text NOT NULL DEFAULT '',
  ADD COLUMN IF NOT EXISTS ip_super text NOT NULL DEFAULT '',
  ADD COLUMN IF NOT EXISTS applies jsonb,
  ADD COLUMN IF NOT EXISTS saved int NOT NULL DEFAULT 0,
  ADD COLUMN IF NOT EXISTS liable bool NOT NULL DEFAULT false,
  ADD COLUMN IF NOT EXISTS seed bool NOT NULL DEFAULT false;

-- lib@ver pairs parsed from versions (and applies) at write time; /v/<lib> hubs and TechArticle.about
CREATE TABLE IF NOT EXISTS kb_versions (
  kb_id text NOT NULL REFERENCES kb(id) ON DELETE CASCADE,
  lib   text NOT NULL,
  ver   text NOT NULL,
  PRIMARY KEY (kb_id, lib, ver)
);
CREATE INDEX IF NOT EXISTS kb_versions_lib_ver_idx ON kb_versions (lib, ver);

-- one row per revision after the first: the unified diff of the edit and who made it
CREATE TABLE IF NOT EXISTS kb_revisions (
  kb_id text NOT NULL REFERENCES kb(id) ON DELETE CASCADE,
  n     int NOT NULL,
  diff  text NOT NULL DEFAULT '',
  by    text NOT NULL DEFAULT '',
  at    timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (kb_id, n)
);

-- read telemetry (6.4): views (g, HTML, .md) and hit impressions per day, bumped by the edit package
CREATE TABLE IF NOT EXISTS kb_reads_daily (
  kb_id       text NOT NULL REFERENCES kb(id) ON DELETE CASCADE,
  day         date NOT NULL,
  views       int NOT NULL DEFAULT 0,
  impressions int NOT NULL DEFAULT 0,
  PRIMARY KEY (kb_id, day)
);

-- 410 bodies, export tombstones and the sitemap/IndexNow removal trail; the title is re-validated
-- as a single line on every render (24.13)
CREATE TABLE IF NOT EXISTS kb_tombstones (
  id            text PRIMARY KEY,
  title         text NOT NULL DEFAULT '',
  reason        text NOT NULL CHECK (reason IN ('expire', 'retract', 'purge', 'hidden', 'merged')),
  superseded_by text NOT NULL DEFAULT '',
  at            timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS kb_tombstones_at_idx ON kb_tombstones (at);
