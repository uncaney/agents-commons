-- operator announcements (SPEC-v2 27.7, P115). The operator posts a maintenance / incident /
-- change / notice line through POST /admin/announce; each row is published as a signed ann1 line on
-- topic g:sys and the /f/sys feed, listed on GET /status while active or upcoming, and (for
-- maintenance) surfaced on /v1/me and /v1/me/resume. Expand-only, one table owned by
-- internal/announce; written only by the admin call acting as the system root.
CREATE TABLE announcements (
  id      bigserial PRIMARY KEY,
  kind    text NOT NULL CHECK (kind IN ('maintenance', 'incident', 'change', 'notice')),
  text    text NOT NULL CHECK (length(text) <= 300),
  starts  timestamptz NOT NULL,
  ends    timestamptz NOT NULL,
  created timestamptz NOT NULL DEFAULT now()
);

-- Active and upcoming lookups (GET /status, the me/resume maintenance notice) scan by ends.
CREATE INDEX announcements_ends_idx ON announcements (ends);
