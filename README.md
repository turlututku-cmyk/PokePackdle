# PokePackdle

A pack-opening RNG race. Open one random 10-card pack a day, score it from each card's stats, and race everyone on a shared leaderboard. There's also an Unlimited tab for practice packs that never count.

- `public/index.html` is the game. Creature art is original and drawn in code.
- `worker.js`, `schema.sql` and `wrangler.toml` are the server: shared accounts and the leaderboard, on Cloudflare Workers with a D1 database (it also serves the game page).
- Setup notes: the Worker needs a D1 database (its id goes in `wrangler.toml`) and a secret named `TOKEN_SECRET`.

Fan project, not affiliated with or endorsed by the owners of the Pokémon trademarks.
