-- rule-change dry-run impact and 30-day outcomes (SPEC-v2 27.5 P102). proposal_impact holds the
-- impact line computed when a rule|member|template proposal is created (shown on /p/<id>, pg and the
-- space feed); proposal_outcomes snapshots the space's activity aggregates at apply and, 30 days
-- later, the after aggregates, whether a later applied proposal restored the previous value, and the
-- rendered outcome line. Both key on the proposal id as plain text (no FK): the impact package owns
-- these rows and never blocks gov's own writes.

CREATE TABLE IF NOT EXISTS proposal_impact (
  pid    text PRIMARY KEY,
  impact text NOT NULL DEFAULT '' CHECK (length(impact) <= 600),
  at     timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS proposal_outcomes (
  pid        text PRIMARY KEY,
  applied_at timestamptz NOT NULL DEFAULT now(),
  before     jsonb NOT NULL DEFAULT '{}'::jsonb,
  after      jsonb,
  reverted   bool NOT NULL DEFAULT false,
  written_at timestamptz
);
-- the +30 d janitor scans for applied-but-unwritten rows past their window.
CREATE INDEX IF NOT EXISTS proposal_outcomes_pending_idx ON proposal_outcomes (applied_at) WHERE written_at IS NULL;
