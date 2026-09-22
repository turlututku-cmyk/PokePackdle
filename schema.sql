CREATE TABLE IF NOT EXISTS users (
  id      INTEGER PRIMARY KEY AUTOINCREMENT,
  key     TEXT NOT NULL UNIQUE,      -- the username in lower case, so "CdukingGD" and "cdukinggd" are the same account
  display TEXT NOT NULL,             -- the username as the player typed it
  salt    TEXT NOT NULL,
  hash    TEXT NOT NULL,
  created INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS scores (
  id      INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL REFERENCES users(id),
  day     TEXT NOT NULL,             -- YYYY-MM-DD
  score   INTEGER NOT NULL,
  ts      INTEGER NOT NULL,
  UNIQUE (user_id, day)              -- one counted score per account per day
);

CREATE INDEX IF NOT EXISTS scores_by_day ON scores (day, score DESC);

-- "new pack" grants an admin has given to players (the server also creates this table by itself on first use)
CREATE TABLE IF NOT EXISTS packgrants (
  id      INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  day     TEXT NOT NULL,             -- the day whose score was cleared
  ts      INTEGER NOT NULL
);

-- the shared chat room (the server also creates this table by itself on first use)
CREATE TABLE IF NOT EXISTS chat (
  id      INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  text    TEXT NOT NULL,
  ts      INTEGER NOT NULL
);

-- every card from a counted daily pack (the server also creates this table by itself on first use)
CREATE TABLE IF NOT EXISTS cards (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id     INTEGER NOT NULL,
  poke_id     INTEGER NOT NULL,
  tier        INTEGER NOT NULL,
  shiny       INTEGER NOT NULL,
  ts          INTEGER NOT NULL,
  in_trade_id INTEGER             -- set while the card is offered in an open trade
);

-- trades between two players (the server also creates this table by itself on first use)
CREATE TABLE IF NOT EXISTS trades (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  from_user  INTEGER NOT NULL,
  to_user    INTEGER NOT NULL,
  status     TEXT NOT NULL,        -- pending | open | completed | declined | cancelled
  from_ready INTEGER NOT NULL DEFAULT 0,
  to_ready   INTEGER NOT NULL DEFAULT 0,
  created    INTEGER NOT NULL,
  updated    INTEGER NOT NULL
);

-- users.best_pts and users.best_name (a player's best pull, for their profile) are added automatically on first use too
