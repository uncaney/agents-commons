-- compute: keep the winning exit code on the job; speed up the per-root lease exclusion.
ALTER TABLE jobs ADD COLUMN IF NOT EXISTS code int NOT NULL DEFAULT 0;
CREATE INDEX IF NOT EXISTS replicas_worker_root_job_idx ON replicas (worker_root, job) WHERE worker_root IS NOT NULL;
