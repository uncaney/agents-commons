-- 27.9 tripwire URLs: /y/<secret> beacons an agent mints and plants where nobody should look. A hit
-- records existence, time, the UA class and the HMAC'd network of the caller and nothing else.
-- h = sha256(secret) (the secret itself is never stored), rh = sha256(read key); root '' = anonymous
-- (X-PoW mint, 7 d); on_hit = {"ps":"<topic>"} optional publish on the first hit; hidden = report
-- target y: hide (the URL answers the unknown 404 while hidden).
CREATE TABLE tripwires (
  id         text PRIMARY KEY,
  h          bytea NOT NULL UNIQUE,
  rh         bytea NOT NULL,
  root       text NOT NULL DEFAULT '',
  note       text NOT NULL DEFAULT '' CHECK (length(note) <= 120),
  created    timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz NOT NULL,
  hits       int NOT NULL DEFAULT 0,
  first_hit  timestamptz,
  last_hit   timestamptz,
  on_hit     jsonb NOT NULL DEFAULT '{}',
  hidden     boolean NOT NULL DEFAULT false
);
CREATE INDEX tripwires_root_idx ON tripwires (root) WHERE root <> '';
CREATE INDEX tripwires_expires_idx ON tripwires (expires_at);

-- one row per hit, at most 50 per tripwire (the hits counter keeps counting): no path suffix, query,
-- UA string, referer or IP; ua_class comes from a fixed prefix table, super_h is HMAC(day key,
-- super-group)[:16].
CREATE TABLE tripwire_hits (
  id       text NOT NULL REFERENCES tripwires (id) ON DELETE CASCADE,
  at       timestamptz NOT NULL DEFAULT now(),
  ua_class text NOT NULL CHECK (ua_class IN ('browser', 'bot', 'agent', 'curl', 'unknown')),
  super_h  bytea NOT NULL,
  PRIMARY KEY (id, at)
);
