-- P79 (SPEC-v2 27.1, 27.3): revision snapshots for pinned renditions and shared delta reads.
-- kb_revisions gains a jsonb snapshot of the row at revision n, filled by a trigger so revision n
-- renders without replaying diffs (P11c keeps writing the diff column). notes_revs is the ring of
-- 10 revisions per wiki note the delta package diffs (written through forge.NoteRevFn, set by P60a).
-- Expand-only: a nullable column, new table, new triggers; nothing is renamed or dropped.

ALTER TABLE kb_revisions ADD COLUMN IF NOT EXISTS snapshot jsonb;

-- The snapshot of revision n is to_jsonb(NEW) minus the internal columns that must never leak to a
-- public rendition (network fingerprints, the scrub version and the search vector); a missing key
-- is a no-op, so the list is safe across schema drift. The upsert lands on the very row P11c's edit
-- writes for revision n (kb_id, n = NEW.rev), so no extra kb_revisions rows are created and the
-- edit-trail contract (one row per edit) is preserved. The current revision renders from the live
-- row, so the trigger fires only when rev changes (an edit), never on the initial insert.
CREATE OR REPLACE FUNCTION kb_rev_snapshot() RETURNS trigger AS $$
BEGIN
  INSERT INTO kb_revisions (kb_id, n, snapshot)
  VALUES (NEW.id, NEW.rev,
          to_jsonb(NEW) - 'author_root' - 'anon_grp' - 'anon_super' - 'scrub_v' - 'tsv')
  ON CONFLICT (kb_id, n) DO UPDATE SET snapshot = EXCLUDED.snapshot;
  RETURN NULL;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS kb_rev_snapshot ON kb;
CREATE TRIGGER kb_rev_snapshot
  AFTER UPDATE OF rev ON kb
  FOR EACH ROW WHEN (NEW.rev IS DISTINCT FROM OLD.rev)
  EXECUTE FUNCTION kb_rev_snapshot();

-- wiki-note revision ring (27.3): the last 10 revisions of each (owner, name) note, diffed by the
-- delta package. forge.NoteRevFn inserts a row per edit; the trigger trims the ring to 10.
CREATE TABLE IF NOT EXISTS notes_revs (
  owner text NOT NULL,
  name  text NOT NULL,
  rev   int  NOT NULL,
  text  text NOT NULL DEFAULT '',
  at    timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (owner, name, rev)
);
CREATE INDEX IF NOT EXISTS notes_revs_recent_idx ON notes_revs (owner, name, rev DESC);

CREATE OR REPLACE FUNCTION notes_revs_ring() RETURNS trigger AS $$
BEGIN
  DELETE FROM notes_revs
  WHERE owner = NEW.owner AND name = NEW.name
    AND rev <= (
      SELECT rev FROM notes_revs
      WHERE owner = NEW.owner AND name = NEW.name
      ORDER BY rev DESC OFFSET 10 LIMIT 1
    );
  RETURN NULL;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS notes_revs_ring ON notes_revs;
CREATE TRIGGER notes_revs_ring
  AFTER INSERT ON notes_revs
  FOR EACH ROW EXECUTE FUNCTION notes_revs_ring();
