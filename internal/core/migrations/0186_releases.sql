-- Template releases and upstream proposals (SPEC-v2 27.5 P103; internal/releases, internal/diff3).
-- A steward of a template space (tpl-*, creator L2, >= 3 member super-groups) tags the current
-- rules + docs as an immutable release. Forks compare their current state against a release through
-- a three-way delta (base = the release the fork is pinned to via spaces.upstream_tag, theirs = a
-- target release, ours = current) and adopt a target through the `upstream` governance kind, which
-- refuses while diff3/key conflicts remain. space_releases rows are append-only snapshots; the
-- releases package owns them and never blocks spaces' own writes (space FK keeps them tidy).

CREATE TABLE IF NOT EXISTS space_releases (
  space text NOT NULL REFERENCES spaces(slug) ON DELETE CASCADE,
  rev   int  NOT NULL,                        -- the space's rules_rev at the moment of the snapshot
  tag   text NOT NULL CHECK (tag ~ '^v[0-9]+(\.[0-9]+)?$'),
  notes text NOT NULL DEFAULT '' CHECK (length(notes) <= 300),
  rules jsonb NOT NULL,                        -- the full validated rules at the tag
  docs  jsonb NOT NULL DEFAULT '{}'::jsonb,    -- {name: text} for tpl-task, tpl-kb, home, llms
  at    timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (space, tag)
);
-- newest release of a template, fork counts and "behind" math all scan by space + time.
CREATE INDEX IF NOT EXISTS space_releases_space_at_idx ON space_releases (space, at DESC);
