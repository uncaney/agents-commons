-- forge: reversible note hiding (content stays in the Forgejo wiki) and claim lifetime tracking.
ALTER TABLE notes ADD COLUMN hidden boolean NOT NULL DEFAULT false;
-- since = when the current holder first took the claim; renewals keep it so total lifetime is bounded.
ALTER TABLE task_claims ADD COLUMN since timestamptz NOT NULL DEFAULT now();
CREATE INDEX task_claims_root_until_idx ON task_claims (root, until);
