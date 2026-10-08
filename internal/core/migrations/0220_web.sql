-- web (SPEC-v2 4.7, 4.8): reports v2 bookkeeping and the LCEN/DSA notices. Expand-only.

-- 4.7 reports gain the network keys of the reporting request (anonymous super-group collapse).
ALTER TABLE reports ADD COLUMN IF NOT EXISTS ip_group text NOT NULL DEFAULT '';
ALTER TABLE reports ADD COLUMN IF NOT EXISTS ip_super text NOT NULL DEFAULT '';
CREATE INDEX IF NOT EXISTS reports_created_idx ON reports (created);

-- 4.7 reporter trust: multiplies the reporter's weight; 1.0 by default, x0.5 per reversed hide,
-- +0.1 per hide that stands 30 d, capped at 2.0. reporter = root id, 'ip:<group>' or 'notice:<id>'.
CREATE TABLE report_trust (
  reporter text PRIMARY KEY,
  score    double precision NOT NULL DEFAULT 1 CHECK (score >= 0 AND score <= 2),
  reversed int NOT NULL DEFAULT 0,
  upheld   int NOT NULL DEFAULT 0,
  updated  timestamptz NOT NULL DEFAULT now()
);

-- 4.7 one row per hide decided by web: the reporters behind it, the author it reached and the
-- outcome once settled (reversed by an appeal or the operator, upheld after 30 d). A reversed row
-- immunises its target against report-hides for 30 d; notice hides wait for the operator.
CREATE TABLE report_hides (
  target     text PRIMARY KEY,
  kind       text NOT NULL,
  ref        text NOT NULL,
  reason     text NOT NULL CHECK (reason IN ('report', 'notice')),
  author     text NOT NULL DEFAULT '',
  reporters  text[] NOT NULL DEFAULT '{}',
  hidden_at  timestamptz NOT NULL DEFAULT now(),
  settled_at timestamptz,
  outcome    text NOT NULL DEFAULT '' CHECK (outcome IN ('', 'upheld', 'reversed'))
);
CREATE INDEX report_hides_open_idx ON report_hides (hidden_at) WHERE settled_at IS NULL;
CREATE INDEX report_hides_author_idx ON report_hides (author, hidden_at);

-- 4.8 notices: id n…, the target it resolved to, what the notifier wrote (reason, email never leave
-- the admin plane), the network keys, the action taken and the operator's decision.
CREATE TABLE notices (
  id           text PRIMARY KEY,
  target       text NOT NULL,
  url          text NOT NULL DEFAULT '' CHECK (length(url) <= 512),
  reason       text NOT NULL DEFAULT '' CHECK (length(reason) <= 2000),
  category     text NOT NULL CHECK (category IN ('personal-data', 'credentials', 'csam', 'malware', 'copyright', 'defamation', 'other')),
  email        text NOT NULL DEFAULT '' CHECK (length(email) <= 254),
  ip_group     text NOT NULL DEFAULT '',
  ip_super     text NOT NULL DEFAULT '',
  created      timestamptz NOT NULL DEFAULT now(),
  action       text NOT NULL CHECK (action IN ('hidden', 'reported', 'queued')),
  acted_at     timestamptz,
  counter      text NOT NULL DEFAULT '' CHECK (length(counter) <= 2000),
  counter_root text NOT NULL DEFAULT '',
  counter_at   timestamptz,
  decided_at   timestamptz,
  decision     text NOT NULL DEFAULT '' CHECK (decision IN ('', 'upheld', 'reversed')),
  note         text NOT NULL DEFAULT '' CHECK (length(note) <= 300)
);
CREATE INDEX notices_created_idx ON notices (created DESC);
CREATE INDEX notices_target_idx ON notices (target);
CREATE INDEX notices_email_reversed_idx ON notices (email) WHERE decision = 'reversed';
