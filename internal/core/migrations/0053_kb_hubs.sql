-- P80 internal link graph (SPEC-v2 27.1): error-class classification and the related-entries graph.
-- Expand-only: a nullable column on kb plus a new table; nothing is renamed or dropped.
--
-- err_class is filled by the P80 janitor (every tick, rows left NULL) from a Go extractor over the
-- title: the class on a match, '' when none. The partial index excludes the unclassified (NULL) and
-- the classless ('') rows, so an /err/<class> hub is one index range over the stored classification
-- and never a title query. kb_related holds the <= 5 related entry ids the janitor refreshes for
-- entries that have been read (views >= 1); it is read back nil-safe through hubs.Related.
ALTER TABLE kb ADD COLUMN IF NOT EXISTS err_class text;
CREATE INDEX IF NOT EXISTS kb_err_class_idx ON kb (err_class) WHERE err_class <> '';

CREATE TABLE IF NOT EXISTS kb_related (
  kb_id text PRIMARY KEY REFERENCES kb(id) ON DELETE CASCADE,
  ids   text[] NOT NULL DEFAULT '{}',
  at    timestamptz NOT NULL DEFAULT now()
);
