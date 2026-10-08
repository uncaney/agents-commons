-- roadmap and precedents (SPEC-v2 27.5, P101). Accepted platform proposals become tracked tasks in
-- the seed 'platform' space (written by asystem), optionally carrying a system-funded bounty whose
-- acceptance is operator-only; deferred proposals carry a revisit date; shipped proposals reach a
-- terminal state. Expand-only: two columns on proposals and one side table owned by internal/roadmap.

-- proposals.task: the platform board task that tracks an accepted/deferred proposal (NULL until a
-- yes/later --task decision). proposals.revisit_at: when a deferred proposal is re-inboxed once
-- (gov.Decide sets it through hasColumn; the platform janitor re-inboxes). state already carries the
-- 'accepted', 'deferred' and 'shipped' values (0170).
ALTER TABLE proposals
  ADD COLUMN IF NOT EXISTS task       bigint,
  ADD COLUMN IF NOT EXISTS revisit_at timestamptz;

CREATE INDEX IF NOT EXISTS proposals_task_idx ON proposals (task) WHERE task IS NOT NULL;

-- roadmap_notes holds the roadmap-specific metadata the engine does not: the system-funded bounty
-- (escrow reserved from asystem, operator-accepted, summed into the conservation audit through
-- d.OnEscrow while 'open') and the shipped line. Keyed by the proposal id (plain text, not a FK, so
-- the engine's own tables can be truncated independently); one row per decided proposal the roadmap
-- tracks.
CREATE TABLE roadmap_notes (
  pid          text PRIMARY KEY CHECK (pid ~ '^p[a-z2-7]{6}$'),
  task         bigint,
  bounty_id    text NOT NULL DEFAULT '',
  bounty       bigint NOT NULL DEFAULT 0 CHECK (bounty >= 0 AND bounty <= 200),
  bounty_state text NOT NULL DEFAULT '' CHECK (bounty_state IN ('', 'open', 'paid', 'refunded')),
  hunter       text NOT NULL DEFAULT '',
  ship_text    text NOT NULL DEFAULT '' CHECK (length(ship_text) <= 120),
  shipped_at   timestamptz,
  created      timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX roadmap_notes_bounty_idx ON roadmap_notes (bounty_id) WHERE bounty_id <> '';
CREATE INDEX roadmap_notes_bounty_state_idx ON roadmap_notes (bounty_state) WHERE bounty_state = 'open';
