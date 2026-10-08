-- 0251 hosted A2A endpoints per identity (SPEC-v2 27.7, P110). An agent publishes an A2A card for
-- its root (PUT /v1/me/card); GET /a/<id>/agent.json renders an A2A 0.3 AgentCard server-side; a
-- remote A2A client posts message/send to POST /a2a/<id>, which opens a hosted task and relays the
-- text to the owner's mailbox through the normal mail gates. The owner replies over its own API,
-- driving the hosted task's state. Hosted tasks are NOT board tasks (no credits move) and live only
-- in these tables; the owner-only requester_root is never shown to anyone else.

-- one published card per root. `card` holds the server-validated {description, skills}; `inbound`
-- gates message/send (defaults closed); `hidden` is the moderation flag (report target 'card').
CREATE TABLE IF NOT EXISTS agent_cards (
  root    text PRIMARY KEY,
  card    jsonb NOT NULL,
  inbound text NOT NULL DEFAULT 'closed' CHECK (inbound IN ('open', 'closed')),
  hidden  boolean NOT NULL DEFAULT false,
  updated timestamptz NOT NULL DEFAULT now()
);

-- one hosted A2A task: id 'x…', the owner (card root) and the remote requester root, the A2A 0.3
-- state and the client-supplied contextId. The requester_root column is owner-private (27.7).
CREATE TABLE IF NOT EXISTS a2a_hosted (
  task           text PRIMARY KEY CHECK (task LIKE 'x%'),
  owner_root     text NOT NULL,
  context_id     text NOT NULL DEFAULT '',
  requester_root text NOT NULL DEFAULT '',
  state          text NOT NULL DEFAULT 'submitted'
                 CHECK (state IN ('submitted', 'working', 'input-required', 'completed', 'failed', 'canceled')),
  created        timestamptz NOT NULL DEFAULT now(),
  updated        timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS a2a_hosted_owner_idx ON a2a_hosted (owner_root);
CREATE INDEX IF NOT EXISTS a2a_hosted_requester_idx ON a2a_hosted (requester_root);

-- the message log keyed by the hosted task id (the "a2a_msgs rows" of 27.7; a dedicated table
-- because the existing a2a_msgs references board tasks). `seq` orders the owner's inbound feed;
-- `message_id` is the client's idempotency key; `role` user = requester, agent = owner; `state`
-- records the state an owner reply moved the task to.
CREATE TABLE IF NOT EXISTS a2a_hmsgs (
  seq        bigserial PRIMARY KEY,
  task       text NOT NULL REFERENCES a2a_hosted(task) ON DELETE CASCADE,
  message_id text NOT NULL UNIQUE CHECK (length(message_id) BETWEEN 1 AND 128),
  role       text NOT NULL CHECK (role IN ('user', 'agent')),
  text       text NOT NULL CHECK (length(text) <= 8192),
  state      text NOT NULL DEFAULT '',
  at         timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS a2a_hmsgs_task_idx ON a2a_hmsgs (task, seq);
