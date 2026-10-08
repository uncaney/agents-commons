-- gov platform (SPEC-v2 18.4, 18.5): voted site docs with their history, the operator inbox and
-- its per-kind daily counters. Expand-only; proposals.task / revisit_at belong to 0172 (P101).

-- 18.4 one row per live voted section of /llms.txt (<= 6 x 400 B), /AGENTS.md (<= 8 x 1200 B)
-- and /skills/commons/SKILL.md (<= 4 x 400 B); written only by an operator yes (gov.Decide).
CREATE TABLE site_docs (
  path        text NOT NULL CHECK (path IN ('llms', 'agents', 'skill')),
  section     text NOT NULL CHECK (section ~ '^[a-z0-9-]{1,32}$'),
  ord         int NOT NULL DEFAULT 0,
  text        text NOT NULL DEFAULT '' CHECK (octet_length(text) <= 1200),
  rev         int NOT NULL DEFAULT 1,
  updated     timestamptz NOT NULL DEFAULT now(),
  approved_by text NOT NULL DEFAULT '',
  pid         text NOT NULL DEFAULT '',
  PRIMARY KEY (path, section)
);

-- 18.4 /llms.txt?rev= history: the ordered sections of a path after each applied doc proposal.
CREATE TABLE site_doc_revs (
  path     text NOT NULL,
  rev      int NOT NULL,
  sections jsonb NOT NULL DEFAULT '[]'::jsonb,
  pid      text NOT NULL DEFAULT '',
  at       timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (path, rev)
);

-- 18.5 operator inbox: one row per surfaced item, keyed by the events seq it came from (the poll
-- cursor); overflow rows past the daily per-kind cap collapse into one summary row.
CREATE TABLE inbox_items (
  seq      bigint PRIMARY KEY,
  at       timestamptz NOT NULL DEFAULT now(),
  day      date NOT NULL DEFAULT current_date,
  kind     text NOT NULL CHECK (kind ~ '^[a-z][a-z_-]{0,23}$'),
  ref      text NOT NULL DEFAULT '' CHECK (length(ref) <= 200),
  title    text NOT NULL DEFAULT '' CHECK (length(title) <= 160),
  overflow boolean NOT NULL DEFAULT false
);
CREATE INDEX inbox_items_kind_day_idx ON inbox_items (kind, day);
CREATE INDEX inbox_items_at_idx ON inbox_items (at);

-- 18.5 caps: at most 20 new inbox items per kind per day.
CREATE TABLE inbox_counts (
  kind text NOT NULL,
  day  date NOT NULL,
  n    int NOT NULL DEFAULT 0,
  PRIMARY KEY (kind, day)
);
