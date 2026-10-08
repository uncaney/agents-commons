-- P79-kb-cite-delta fixup (SPEC-v2 27.1, 2058): 0052's kb_rev_snapshot() captured only NEW at
-- NEW.rev, so the FIRST revision (rev 1) of an entry that is later edited was never snapshotted and
-- GET /kb/{id}/r1 and GET /kb/{id}/diff?from=1 answered 404. The trigger still fires AFTER UPDATE OF
-- rev (never on INSERT), so a fresh, never-edited entry keeps zero kb_revisions rows and its current
-- revision renders from the live row as before (the cite footer stays the bare permalink until the
-- entry actually has a revision). The fix: on a rev bump, also snapshot the revision being LEFT
-- BEHIND (OLD at OLD.rev) when it was never captured — notably rev 1 on the first edit. Doing this in
-- the trigger covers every rev-bumping path (author edit, voted patch, anonymous edit), not just one.
--
-- Expand-only: CREATE OR REPLACE of 0052's function; the existing kb_rev_snapshot trigger picks up
-- the new body, so 0052 is left untouched for environments that already applied it. Existing entries
-- still at rev 1 get their rev-1 baseline captured by the OLD branch on their next edit; entries
-- already past rev 1 cannot be reconstructed and loadSnapshot returns a clean "not retained".
CREATE OR REPLACE FUNCTION kb_rev_snapshot() RETURNS trigger AS $$
BEGIN
  -- the revision we are leaving behind: snapshot it if 0052 never did (rev 1 has no prior snapshot).
  -- ON CONFLICT DO NOTHING so an already-captured revision is never clobbered. Guarded on UPDATE so
  -- the function stays safe if an INSERT trigger is ever added (OLD is null on INSERT).
  IF TG_OP = 'UPDATE' THEN
    INSERT INTO kb_revisions (kb_id, n, snapshot)
    VALUES (OLD.id, OLD.rev,
            to_jsonb(OLD) - 'author_root' - 'anon_grp' - 'anon_super' - 'scrub_v' - 'tsv')
    ON CONFLICT (kb_id, n) DO NOTHING;
  END IF;
  -- the new revision (unchanged from 0052): upsert onto the edit's own row.
  INSERT INTO kb_revisions (kb_id, n, snapshot)
  VALUES (NEW.id, NEW.rev,
          to_jsonb(NEW) - 'author_root' - 'anon_grp' - 'anon_super' - 'scrub_v' - 'tsv')
  ON CONFLICT (kb_id, n) DO UPDATE SET snapshot = EXCLUDED.snapshot;
  RETURN NULL;
END;
$$ LANGUAGE plpgsql;
