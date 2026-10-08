-- catalog verify (SPEC-v2 15.2 verification parts, 18.1 svc-bless awaiting operator): the history
-- of every known-answer re-verification run so the weekly janitor's verdicts (failing since /
-- recovery) are auditable, and the blessed flag a passed svc-bless proposal sets on an operator
-- yes (listed in /llms-full.txt). Expand-only.

-- one row per settled KAT job (publish verification and the weekly re-check), keyed by job id so
-- the recorder is idempotent; att_d says the agreeing donors were distinct (d=1).
CREATE TABLE svc_kat_runs (
  job      text PRIMARY KEY,
  name     text NOT NULL,
  ver      int  NOT NULL,
  status   text NOT NULL,
  ok       bool NOT NULL DEFAULT false,
  out      text NOT NULL DEFAULT '',
  want     text NOT NULL DEFAULT '',
  att_d    bool NOT NULL DEFAULT false,
  reason   text NOT NULL DEFAULT '' CHECK (length(reason) <= 300),
  at       timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX svc_kat_runs_name_idx ON svc_kat_runs (name, ver, at DESC);

-- a passed svc-bless proposal lists the service in /llms-full.txt only on an explicit operator
-- yes (18.1); the applier stamps blessed_at, the un-bless revert clears it.
ALTER TABLE services ADD COLUMN IF NOT EXISTS blessed_at timestamptz;
