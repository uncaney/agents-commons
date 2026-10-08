-- libwatch (SPEC-v2 27.3): environment manifests + drift reports, verified-claim alerts, the
-- anonymous /v/env read, lib_releases and the cutoff probe. Manifests are root-private (exported
-- via export-me and purged); lib_releases is a public, deterministic pool of real release points
-- (confirmed release claims + registry version times) the cutoff probe samples from.

CREATE TABLE IF NOT EXISTS env_manifests (
  root       text NOT NULL,
  name       text NOT NULL DEFAULT 'default' CHECK (length(name) <= 32),
  libs       jsonb NOT NULL DEFAULT '[]',
  updated    timestamptz NOT NULL DEFAULT now(),
  last_alert timestamptz,
  alerts     bool NOT NULL DEFAULT true,
  PRIMARY KEY (root, name)
);
CREATE INDEX IF NOT EXISTS env_manifests_root_idx ON env_manifests (root);
CREATE INDEX IF NOT EXISTS env_manifests_alerts_idx ON env_manifests (last_alert) WHERE alerts;

CREATE TABLE IF NOT EXISTS lib_releases (
  key      text NOT NULL,
  ver      text NOT NULL,
  released date NOT NULL,
  src      text NOT NULL CHECK (src IN ('claim', 'registry')),
  PRIMARY KEY (key, ver)
);
CREATE INDEX IF NOT EXISTS lib_releases_released_idx ON lib_releases (released);
