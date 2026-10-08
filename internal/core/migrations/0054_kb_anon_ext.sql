-- kb anonymous author key and anonymous confirmations (SPEC-v2 27.2, P78). Expand-only: every
-- column is nullable or defaulted; nothing is renamed or dropped.
--
-- anon_wh   = sha256 of the 26-char base32 author key handed to an anonymous poster once (NULL when
--             the row was never anonymous, was adopted, or the key was burned on a leak).
-- anon_edits= anonymous author-key PATCHes applied (capped at 5 in code).
-- anon_ok /  anon_bad = soft confirmation counters driven by /w/k/{id}/ok|bad; they feed ranking and
--             the `anon+n-m` header line only and are never counted in ok_w/bad_w, promotion,
--             hiding, reputation or upvoteCount.
ALTER TABLE kb
  ADD COLUMN IF NOT EXISTS anon_wh    bytea,
  ADD COLUMN IF NOT EXISTS anon_edits int NOT NULL DEFAULT 0,
  ADD COLUMN IF NOT EXISTS anon_ok    int NOT NULL DEFAULT 0,
  ADD COLUMN IF NOT EXISTS anon_bad   int NOT NULL DEFAULT 0;

-- One anonymous confirmation per IP group per entry per day: grp_h = HMAC(day-key, group)[:16], so
-- the key rotates daily (no raw network key is ever stored) and rows older than 30 days are pruned.
-- kind is the confirmation's direction; the PK is group-and-entry so a group's ok and bad on the
-- same entry the same day collapse to one row.
CREATE TABLE IF NOT EXISTS kb_votes_anon (
  kb_id text  NOT NULL REFERENCES kb(id) ON DELETE CASCADE,
  grp_h bytea NOT NULL,
  day   date  NOT NULL DEFAULT current_date,
  kind  text  NOT NULL CHECK (kind IN ('ok', 'bad')),
  PRIMARY KEY (kb_id, grp_h)
);
CREATE INDEX IF NOT EXISTS kb_votes_anon_day_idx ON kb_votes_anon (day);

-- Anonymous `bad` reasons, shown as anon-marked fails: hints to reviewers; capped at 20 per entry in
-- code and dropped with the entry.
CREATE TABLE IF NOT EXISTS kb_anon_fails (
  kb_id text NOT NULL REFERENCES kb(id) ON DELETE CASCADE,
  why   text NOT NULL,
  day   date NOT NULL DEFAULT current_date
);
CREATE INDEX IF NOT EXISTS kb_anon_fails_kb_idx ON kb_anon_fails (kb_id);
