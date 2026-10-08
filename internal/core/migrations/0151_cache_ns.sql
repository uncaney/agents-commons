-- cache namespaces (SPEC-v2 27.3): declared canonicalisation recipes for the result cache. A
-- namespace owner (L2+, 5 per root) stores a recipe of up to 8 RE2 {re,to} rules plus the built-in
-- booleans (lower, strip_ts, strip_hex, strip_paths, strip_lines); cachens.Canon applies it
-- server-side so a producer (cput) and a reader (cget) meeting the same post-canonical input share
-- one key. A recipe change bumps v so rows written under the old recipe stay reachable under the old
-- version (key = sha256(ns + "@" + v + "\n" + canonical)). A namespace that was never declared keeps
-- the default NFC/LF/trim canonicalisation at v=0. OnPurge clears owner_root but keeps the row, so
-- old keys remain reachable.
CREATE TABLE cache_ns (
  ns         text PRIMARY KEY CHECK (ns ~ '^[a-z0-9][a-z0-9.-]{0,31}$'),
  owner_root text NOT NULL DEFAULT '',
  v          int NOT NULL DEFAULT 1 CHECK (v >= 1),
  rules      jsonb NOT NULL DEFAULT '{}'::jsonb,
  descr      text NOT NULL DEFAULT '' CHECK (length(descr) <= 120),
  created    timestamptz NOT NULL DEFAULT now(),
  updated    timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX cache_ns_owner_idx ON cache_ns (owner_root) WHERE owner_root <> '';

-- near-miss lookup (27.3): the scrubbed, canonicalised one-line preview of each cache row's input,
-- with a trigram index for similarity() search within a namespace. Bodies are never compared or
-- returned; the preview is already tier-1/tier-2 scrubbed by the cput write path.
ALTER TABLE cache ADD COLUMN IF NOT EXISTS in_preview text NOT NULL DEFAULT '';
CREATE INDEX IF NOT EXISTS cache_in_preview_trgm_idx ON cache USING GIN (in_preview gin_trgm_ops) WHERE in_preview <> '';
