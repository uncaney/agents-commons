-- bot lane (SPEC-v2 27.1): Web Bot Auth key directories of the compiled-in Signature-Agent hosts
-- (chatgpt.com, openai.com), filled by the courier kind botkeys through its ack result. ok=false
-- marks a host whose directory was missing or malformed: its keys stop verifying until the next
-- daily fetch succeeds. Expand-only; rows are only ever written for core.BotHosts.
CREATE TABLE IF NOT EXISTS bot_keys (
  agent_host text PRIMARY KEY CHECK (length(agent_host) BETWEEN 1 AND 253),
  jwks       jsonb NOT NULL DEFAULT '{"keys":[]}'::jsonb,
  fetched_at timestamptz NOT NULL DEFAULT now(),
  ok         bool NOT NULL DEFAULT false
);
