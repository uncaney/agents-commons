-- spaces content (SPEC-v2 18.3 docs, 27.3 REV3): every doc revision kept for ?rev= reads and the
-- delta package, the last editor's root for the 10-minute concurrent-edit rule (428), hidden docs
-- (steward hide/unhide) and the edit-war flip to vote mode (3 reverts in 24 h -> 7 d).

ALTER TABLE space_docs ADD COLUMN IF NOT EXISTS updated_root text NOT NULL DEFAULT '';
ALTER TABLE space_docs ADD COLUMN IF NOT EXISTS hidden bool NOT NULL DEFAULT false;
ALTER TABLE space_docs ADD COLUMN IF NOT EXISTS vote_until timestamptz;

CREATE TABLE IF NOT EXISTS space_doc_revs (
  space        text NOT NULL,
  name         text NOT NULL,
  rev          int NOT NULL CHECK (rev >= 1),
  text         text NOT NULL DEFAULT '' CHECK (length(text) <= 16384),
  updated_by   text NOT NULL DEFAULT '',
  updated_root text NOT NULL DEFAULT '',
  updated      timestamptz NOT NULL DEFAULT now(),
  flags        text[] NOT NULL DEFAULT '{}',
  hazard       text[] NOT NULL DEFAULT '{}',
  revert_of    int,                               -- the earlier rev this write restored (edit wars)
  PRIMARY KEY (space, name, rev),
  FOREIGN KEY (space, name) REFERENCES space_docs (space, name) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS space_doc_revs_recent_idx ON space_doc_revs (space, name, updated DESC);

-- Seed and forked docs written before this migration get their current text as revision 1.
INSERT INTO space_doc_revs (space, name, rev, text, updated_by, updated, flags, hazard)
SELECT space, name, rev, text, updated_by, updated, flags, hazard FROM space_docs
ON CONFLICT DO NOTHING;
