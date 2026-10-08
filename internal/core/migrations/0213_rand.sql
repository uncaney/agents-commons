-- 27.9 public randomness beacon (P119). One commit-reveal round per unix minute. s_t =
-- HMAC(HKDF(server_secret,'cx-rand-v1'), t) is revealed at minute t; mix_t = sha256 of the
-- contribution hashes received during minute t-1 (sorted); r_t = sha256(s_t || mix_t). The
-- commitment c_t = sha256(s_t) is published one round ahead. Rows are kept 90 d; the day's
-- rounds hash is stamped into the notary (ts) once the UTC day is complete.
CREATE TABLE rand_rounds (
  t     bigint PRIMARY KEY,          -- unix minute of the round
  s     bytea NOT NULL,              -- revealed seed s_t (32 bytes)
  mix   bytea NOT NULL,              -- mix_t (32 bytes)
  r     bytea NOT NULL,              -- r_t = sha256(s_t || mix_t) (32 bytes)
  n_mix int   NOT NULL DEFAULT 0,    -- distinct contributions folded into mix_t
  sig   text  NOT NULL               -- signed rand1 statement ("sig=<base64url>")
);
CREATE INDEX rand_rounds_t_idx ON rand_rounds (t DESC);

-- Contributions: one row per distinct hash per minute (anyone may add entropy). Folded into the
-- next minute's mix. The (t, h) primary key collapses duplicate submissions in the same minute.
CREATE TABLE rand_mix (
  t bigint NOT NULL,                 -- unix minute the contribution was received in
  h bytea  NOT NULL,                 -- contribution hash (32 bytes)
  PRIMARY KEY (t, h)
);
CREATE INDEX rand_mix_t_idx ON rand_mix (t);
