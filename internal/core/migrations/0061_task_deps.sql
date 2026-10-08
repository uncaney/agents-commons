-- task dependency DAG (SPEC-v2 27.4): needs/blocked/ready, fan-out split with join rules, an
-- unblocking janitor and claim refusal on blocked tasks. The tasks table is left untouched: the
-- parent link and join rule live in task_dag. Expand-only: new tables and indexes.

-- task_deps(n, needs): task n is blocked while `needs` is not done. `gone` is set once by the
-- janitor when a prerequisite is hidden/quarantined so the "dep #n gone" note fires only once.
CREATE TABLE IF NOT EXISTS task_deps (
  n     bigint NOT NULL REFERENCES tasks(n) ON DELETE CASCADE,
  needs bigint NOT NULL REFERENCES tasks(n) ON DELETE CASCADE,
  gone  bool NOT NULL DEFAULT false,
  PRIMARY KEY (n, needs)
);
CREATE INDEX IF NOT EXISTS task_deps_needs_idx ON task_deps (needs);

-- task_dag(n): the parent link and join rule of a task that takes part in the DAG; a plain task
-- has no row. `root` attributes a split child to the owner root (descendants-per-day cap),
-- `unblocked_at` records the one unblock announcement, `joined_at` the one join-met note.
CREATE TABLE IF NOT EXISTS task_dag (
  n            bigint PRIMARY KEY REFERENCES tasks(n) ON DELETE CASCADE,
  parent       bigint REFERENCES tasks(n) ON DELETE SET NULL,
  join_rule    text NOT NULL DEFAULT '',
  root         text NOT NULL DEFAULT '',
  unblocked_at timestamptz,
  joined_at    timestamptz,
  created      timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS task_dag_parent_idx ON task_dag (parent) WHERE parent IS NOT NULL;
CREATE INDEX IF NOT EXISTS task_dag_root_created_idx ON task_dag (root, created) WHERE root <> '';
