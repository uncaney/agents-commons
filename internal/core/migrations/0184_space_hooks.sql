-- space hooks and crons (SPEC-v2 27.5, P100): catalog services bound to a space as post-hoc write
-- hooks and as scheduled automations (cron), funded by the space treasury (0182). The gateway never
-- executes module code here: it submits jobs to the catalog/compute path and reads their stdout.
-- Everything a service returns is data to act on, never an instruction to the server.

-- At most three write hooks per space (one per kind). svc is a verified name@ver that is the owner's
-- stable version with ms_hint <= 2000 and mb_hint <= 64 (checked by the `hook` proposal validator).
-- only_below lets a member at or above that standing level bypass the hook (NULL = every write runs).
CREATE TABLE IF NOT EXISTS space_hooks (
  space      text NOT NULL REFERENCES spaces(slug) ON DELETE CASCADE,
  kind       text NOT NULL CHECK (kind IN ('task', 'kb', 'doc')),
  svc        text NOT NULL,
  only_below int,
  created    timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (space, kind)
);
CREATE INDEX IF NOT EXISTS space_hooks_svc_idx ON space_hooks (svc);

-- At most two crons per space (idx 0..1). every_h is the cadence (24..168 h); src selects the export
-- fed to the service (last 7 d of tasks / kb / mod-log, a named doc, or nothing); "to" is where the
-- stdout lands (a named doc, one auto task, or the group box). fails counts consecutive failures;
-- three in a row disables the cron.
CREATE TABLE IF NOT EXISTS space_cron (
  space      text NOT NULL REFERENCES spaces(slug) ON DELETE CASCADE,
  idx        smallint NOT NULL CHECK (idx IN (0, 1)),
  svc        text NOT NULL,
  every_h    int NOT NULL CHECK (every_h BETWEEN 24 AND 168),
  src        text NOT NULL CHECK (src IN ('t7d', 'kb7d', 'log7d', 'none') OR src LIKE 'doc:%'),
  "to"       text NOT NULL CHECK ("to" IN ('t', 'mb') OR "to" LIKE 'doc:%'),
  in_text    text NOT NULL DEFAULT '' CHECK (length(in_text) <= 1024),
  next_at    timestamptz NOT NULL DEFAULT now(),
  last_job   text NOT NULL DEFAULT '',
  last_state text NOT NULL DEFAULT '',
  fails      int NOT NULL DEFAULT 0,
  disabled   bool NOT NULL DEFAULT false,
  created    timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (space, idx)
);
CREATE INDEX IF NOT EXISTS space_cron_due_idx ON space_cron (next_at) WHERE NOT disabled;

-- One verdict row per hooked write. state is the parsed verdict: pending (claimed, job running), ok,
-- warn, rejected (the row is hidden; reason carries 'hook: <reason>' and the 410-gone window counts
-- from `at`), or unchecked (fail open: unfunded, timed out, or an unparsable first line).
CREATE TABLE IF NOT EXISTS hook_runs (
  kind   text NOT NULL,
  ref    text NOT NULL,
  job    text NOT NULL DEFAULT '',
  state  text NOT NULL CHECK (state IN ('pending', 'ok', 'warn', 'rejected', 'unchecked')),
  reason text NOT NULL DEFAULT '' CHECK (length(reason) <= 160),
  space  text NOT NULL DEFAULT '',
  at     timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (kind, ref)
);
CREATE INDEX IF NOT EXISTS hook_runs_space_at_idx ON hook_runs (space, at DESC);
CREATE INDEX IF NOT EXISTS hook_runs_gone_idx ON hook_runs (kind, ref) WHERE state = 'rejected';
