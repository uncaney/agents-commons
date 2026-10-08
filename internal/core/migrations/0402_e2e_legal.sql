-- e2e legal (SECURITY-E2EE-v2 8.3-8.6, SPEC-v2 26.3): recipient-reveal report evidence, the
-- diversity-gated penalty queue, the operator review queue and the batch-tick ledger. No table here
-- holds a plaintext or a key: x_evidence keeps the scanner verdict (kinds, score, sha256) and the
-- self-contained signatures (hdr, rcpt, send_sig) that prove the sender committed to this payload and
-- the origin accepted it, never the message. x_evidence is admin-only and, unlike the ciphertext
-- tables, is INCLUDED in backups (the operator's LCEN notice-and-action record); 90 d retention,
-- longer only while the notice it supports stays open.

-- 8.3 the verified-report evidence row. kind 'frank' holds the scanner verdict of 26.3; kind
-- 'bad-frank' records an unverifiable franking claim (4.4) with no verdict (sender flagged).
CREATE TABLE x_evidence (
  id            bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  kind          text NOT NULL CHECK (kind IN ('frank', 'bad-frank')),
  ref           text NOT NULL,                      -- locator: m:<to>/<seq> or g:<gid>/<seq>
  from_id       text NOT NULL,
  from_root     text NOT NULL,
  at            timestamptz NOT NULL,               -- origin accept time of the reported envelope
  hdr           bytea NOT NULL CHECK (length(hdr) = 71),
  rcpt          bytea NOT NULL CHECK (length(rcpt) = 64),
  send_sig      bytea NOT NULL CHECK (length(send_sig) = 64),
  kinds         text NOT NULL DEFAULT '',           -- scanner kinds+flags+hazards, comma-joined; never the text
  score         int NOT NULL DEFAULT 0,             -- lexicon score
  sha256        bytea CHECK (sha256 IS NULL OR length(sha256) = 32),   -- hash of the plaintext payload
  pol           int NOT NULL DEFAULT 0,             -- scrub pack version the header pinned
  upheld        boolean NOT NULL DEFAULT false,     -- lexicon >= 2, credential solicitation or a hazard (26.3)
  why           text NOT NULL DEFAULT '',           -- the reporter's judgement (<= 200)
  reporter_root text NOT NULL,
  reporter_ipg  text NOT NULL DEFAULT '',           -- reporter IP group (distinct-net diversity, pseudonymous)
  reporter_est  boolean NOT NULL DEFAULT false,     -- reporter was established at report time (D12)
  report_ts     bigint NOT NULL DEFAULT 0,
  report_nonce  bytea,
  report_sig    bytea,                              -- the reporter's own X-Cx-Sig, verbatim (admin-only)
  created       timestamptz NOT NULL DEFAULT now(),
  exp           timestamptz NOT NULL,               -- created + 90 d, extended while a notice is open
  notice_ref    text                                -- set while an open notice depends on this row
);
CREATE INDEX x_evidence_from_idx ON x_evidence (from_root, created);
CREATE INDEX x_evidence_exp_idx ON x_evidence (exp);
CREATE INDEX x_evidence_reporter_idx ON x_evidence (reporter_root, from_root);

-- D12 diversity-gated penalties, applied at the next batch tick (never synchronously with a report).
-- At most one pending penalty per sender root; a tick sets x_frozen and AddRep(-5) then marks it applied.
CREATE TABLE x_penalties (
  id         bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  from_root  text NOT NULL,
  basis      text NOT NULL DEFAULT 'reports',
  until      timestamptz NOT NULL,                  -- frozen_until to set
  rep_delta  int NOT NULL DEFAULT 0,
  created    timestamptz NOT NULL DEFAULT now(),
  applied_at timestamptz                            -- NULL until a batch tick applies it
);
CREATE UNIQUE INDEX x_penalties_one_pending ON x_penalties (from_root) WHERE applied_at IS NULL;
CREATE INDEX x_penalties_pending_idx ON x_penalties (created) WHERE applied_at IS NULL;

-- 8.3 operator review queue: everything below the auto-freeze threshold, every bad-frank claim and
-- every report from a cold root. Surfaced by GET /admin/x/queue and the ops inbox event (x-review).
CREATE TABLE x_review_queue (
  id         bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  evidence   bigint REFERENCES x_evidence (id) ON DELETE CASCADE,
  from_root  text NOT NULL,
  ref        text NOT NULL,
  reason     text NOT NULL DEFAULT '',
  weight     double precision NOT NULL DEFAULT 0,
  created    timestamptz NOT NULL DEFAULT now(),
  decided_at timestamptz,
  decision   text CHECK (decision IN ('purge', 'freeze', 'dismiss')),
  note       text NOT NULL DEFAULT ''
);
CREATE INDEX x_review_open_idx ON x_review_queue (created) WHERE decided_at IS NULL;

-- 8.3/D11 batch-tick ledger: one row per processed tick (00:00/06:00/12:00/18:00 UTC by default,
-- E2E_BATCH_HOURS), so each tick's penalties and generic statements of reasons are applied once.
CREATE TABLE batch_ticks (
  tick       timestamptz PRIMARY KEY,
  penalties  int NOT NULL DEFAULT 0,
  statements int NOT NULL DEFAULT 0,
  at         timestamptz NOT NULL DEFAULT now()
);
