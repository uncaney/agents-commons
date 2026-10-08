-- 0072 service pipelines (SPEC-v2 27.6, P107): stdout-to-stdin chaining of catalog
-- services/modules in one submission. One pipe runs its 2..8 steps sequentially through
-- compute's job queue; each step's output blob is the next step's input. State lives here; the
-- jobs themselves carry jobs.pipe = pipes.id (added by 0070) so compute.OnDone can chain.
CREATE TABLE IF NOT EXISTS pipes (
    id         text PRIMARY KEY,                       -- 'q…'
    root       text NOT NULL,                          -- owning root (purge, listing)
    submitter  text NOT NULL,                          -- identity that pays the per-step fees
    steps      jsonb NOT NULL,                         -- resolved steps [{wasm,ms,mb,interp,code}] (2..8)
    nsteps     int  NOT NULL,                          -- cardinality(steps), for the reply head
    in0        text NOT NULL DEFAULT '',               -- step-0 data input (blob hash)
    outs       text[] NOT NULL DEFAULT '{}',           -- output hash per completed step (partial on failure)
    cur        int  NOT NULL DEFAULT 0,                -- completed steps so far (= cardinality(outs))
    cur_job    text NOT NULL DEFAULT '',               -- in-flight step job id ('' when none in flight)
    pending    boolean NOT NULL DEFAULT false,         -- a step settled; the advancer must act
    state      text NOT NULL DEFAULT 'running' CHECK (state IN ('running', 'done', 'failed')),
    fail_idx   int  NOT NULL DEFAULT -1,               -- index of the failed step (-1 = none)
    reason     text NOT NULL DEFAULT '',               -- failure reason (one line)
    ms_total   int  NOT NULL DEFAULT 0,                -- summed used_ms across completed steps
    att        text NOT NULL DEFAULT '',               -- signed pipe1 statement line (set at the end)
    att_sig    text NOT NULL DEFAULT '',               -- its sig=… token
    wait       int  NOT NULL DEFAULT 0,                -- caller's long-poll budget hint (seconds)
    mb         int  NOT NULL DEFAULT 0,                -- memory cap applied to every step
    created    timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS pipes_root ON pipes (root, created DESC);
-- The advancer scans only pipes with a settled-but-unadvanced step.
CREATE INDEX IF NOT EXISTS pipes_pending ON pipes (created) WHERE pending AND state = 'running';
