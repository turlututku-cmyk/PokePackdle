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
