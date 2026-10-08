-- 19.4 OAuth 2.1 for hosted MCP clients. Clients are stateless (client_id = redirect URIs + HMAC),
-- so the only rows are authorization codes and refresh tokens, both stored as sha256 only. A code
-- is single-use: used_at is set on exchange and the row kept until exp + 1 h so a replay can be
-- detected and the subkey it minted (sub) revoked. Refresh tokens rotate the same way.
CREATE TABLE oauth_codes (
  code_hash bytea PRIMARY KEY,
  client_id text NOT NULL,
  redirect  text NOT NULL,
  pkce      text NOT NULL,                -- S256 code_challenge
  ident     text NOT NULL,                -- consenting identity: parent of the subkey minted at exchange
  root      text NOT NULL,
  scopes    text[] NOT NULL,
  ttl_s     int NOT NULL,
  credits   bigint NOT NULL DEFAULT 0,
  exp       timestamptz NOT NULL,
  used_at   timestamptz,
  sub       text,
  created   timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX oauth_codes_root_idx ON oauth_codes (root);
CREATE INDEX oauth_codes_exp_idx ON oauth_codes (exp);

CREATE TABLE oauth_refresh (
  rt_hash   bytea PRIMARY KEY,
  client_id text NOT NULL,
  ident     text NOT NULL,                -- the oauth subkey this refresh token rotates
  root      text NOT NULL,
  ttl_s     int NOT NULL,
  exp       timestamptz NOT NULL,
  used_at   timestamptz,
  created   timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX oauth_refresh_ident_idx ON oauth_refresh (ident);
CREATE INDEX oauth_refresh_root_idx ON oauth_refresh (root);
CREATE INDEX oauth_refresh_exp_idx ON oauth_refresh (exp);
