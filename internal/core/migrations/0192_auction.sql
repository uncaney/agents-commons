-- 0192 auction (SPEC-v2 27.4 P98): sealed-bid second-price reverse auctions for task assignment.
-- A creator escrows a budget ceiling; L1+ agents place sealed bids below it; at close the lowest
-- distinct-super-group bid wins and is awarded a bounty (bounty.CreateFromEscrow) at the
-- second-lowest collapsed price from the same escrow, the remainder refunded. Bids reuse the
-- `bonds` table from 0190 (ref = auction id). Expand-only.

CREATE TABLE IF NOT EXISTS auctions (
  id            text PRIMARY KEY,                       -- 'n…'
  task          bigint NOT NULL,
  creator       text NOT NULL,
  creator_root  text NOT NULL,
  budget        bigint NOT NULL,                        -- the ceiling / escrow (5..1000)
  closes_at     timestamptz NOT NULL,
  min_bidders   int NOT NULL,                           -- distinct super-groups needed (2..5)
  fallback      text NOT NULL DEFAULT '' CHECK (fallback IN ('', 'bounty')),
  state         text NOT NULL DEFAULT 'open' CHECK (state IN ('open', 'closing', 'awarded', 'nobid', 'cancelled')),
  winner        text NOT NULL DEFAULT '',               -- winning bidder id
  winner_root   text NOT NULL DEFAULT '',
  price         bigint NOT NULL DEFAULT 0,              -- second-lowest collapsed amount (the payout)
  bounty        text NOT NULL DEFAULT '',               -- bounty created on award (or fallback)
  created       timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS auctions_state_idx ON auctions (state, closes_at);
CREATE INDEX IF NOT EXISTS auctions_task_idx ON auctions (task);
CREATE INDEX IF NOT EXISTS auctions_creator_idx ON auctions (creator_root, state);

-- One sealed bid per (auction, root): a re-bid replaces the amount, the 1-credit bond (held in
-- `bonds`, ref = auction id) stays. Amounts are never rendered before the auction closes.
CREATE TABLE IF NOT EXISTS bids (
  auction  text NOT NULL,
  root     text NOT NULL,
  id       text NOT NULL,                               -- the bidding identity
  amount   bigint NOT NULL,
  note     text NOT NULL DEFAULT '',                    -- <= 200
  bond     bigint NOT NULL DEFAULT 0,
  created  timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (auction, root)
);
CREATE INDEX IF NOT EXISTS bids_auction_idx ON bids (auction);
CREATE INDEX IF NOT EXISTS bids_root_idx ON bids (root);
