-- kb recall (SPEC-v2 27.1 hash lookup, 27.9 recall repair; P76). Hash lookup over the ErrSig of an
-- entry's title and of its "also known as" phrasings, and the kb_aka table the aka write path fills.
-- Expand-only: every column is nullable or defaulted; nothing is renamed or dropped.
--
-- sig    = kb.ErrSig(title), backfilled by the janitor for rows left NULL (older rows, bulk imports).
-- sig_h  = sha256 of the UTF-8 bytes of sig, generated and indexed so GET /h/<hex> is one btree probe.
-- aka_text = denormalised join of the entry's accepted akas, maintained in the aka write tx; it feeds
--            tsv_aka (full text) and a trigram index so P11's Search can match an entry by an alias.

-- convert_to is only STABLE (its result could vary with the destination encoding), so Postgres refuses
-- it inside a generated column. The destination encoding here is the constant 'UTF8', which makes the
-- composition deterministic, so we wrap it in an IMMUTABLE SQL function and generate sig_h from that.
CREATE OR REPLACE FUNCTION kb_sig_h(t text) RETURNS bytea
  LANGUAGE sql IMMUTABLE PARALLEL SAFE RETURNS NULL ON NULL INPUT
  AS $$ SELECT sha256(convert_to(t, 'UTF8')) $$;

ALTER TABLE kb
  ADD COLUMN IF NOT EXISTS sig      text,
  ADD COLUMN IF NOT EXISTS sig_h    bytea GENERATED ALWAYS AS (kb_sig_h(sig)) STORED,
  ADD COLUMN IF NOT EXISTS aka_text text NOT NULL DEFAULT '',
  ADD COLUMN IF NOT EXISTS tsv_aka  tsvector GENERATED ALWAYS AS (to_tsvector('english', aka_text)) STORED;

CREATE INDEX IF NOT EXISTS kb_sig_h_idx ON kb (sig_h) WHERE sig_h IS NOT NULL;
CREATE INDEX IF NOT EXISTS kb_tsv_aka_idx ON kb USING GIN (tsv_aka);
CREATE INDEX IF NOT EXISTS kb_aka_text_trgm_idx ON kb USING GIN (aka_text gin_trgm_ops) WHERE aka_text <> '';

-- One "also known as" phrasing of an entry (SPEC-v2 27.9). h = sha256 of the normalised text keys the
-- row (and the PK with kb_id); sig/sig_h carry the ErrSig of the phrasing so /h/<hex> resolves alias
-- hashes the same way it resolves titles. ok_w accrues the one L2 confirmation a quarantined aka needs;
-- quarantine mirrors the entry's state (akas never make an entry indexable).
CREATE TABLE IF NOT EXISTS kb_aka (
  kb_id      text  NOT NULL REFERENCES kb(id) ON DELETE CASCADE,
  h          bytea NOT NULL,
  text       text  NOT NULL CHECK (char_length(text) <= 160),
  sig        text  NOT NULL DEFAULT '',
  sig_h      bytea GENERATED ALWAYS AS (kb_sig_h(sig)) STORED,
  by         text  NOT NULL DEFAULT '',
  root       text  NOT NULL DEFAULT '',
  ok_w       real  NOT NULL DEFAULT 0,
  quarantine bool  NOT NULL DEFAULT false,
  created    timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (kb_id, h)
);
CREATE INDEX IF NOT EXISTS kb_aka_sig_h_idx ON kb_aka (sig_h) WHERE sig_h IS NOT NULL;
CREATE INDEX IF NOT EXISTS kb_aka_root_idx ON kb_aka (root) WHERE root <> '';
