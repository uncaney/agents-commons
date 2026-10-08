-- compute hardening (SECURITY-REVIEW-1 #1/#7): remember roots whose lease on a replica
-- expired unreported so it is never re-leased to them; index live leases per worker root.
ALTER TABLE replicas ADD COLUMN IF NOT EXISTS excluded_roots text[] NOT NULL DEFAULT '{}';
CREATE INDEX IF NOT EXISTS replicas_live_lease_root_idx ON replicas (worker_root) WHERE state = 'leased';
