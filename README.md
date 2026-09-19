# PokePackdle server (shared accounts and one leaderboard)

This small server makes PokePackdle multiplayer: every player, on any browser or device, shares the same accounts, unique usernames and one leaderboard. It runs on Cloudflare Workers with a D1 (SQLite) database. Both have a free tier that's plenty for a game among friends.

Without it, the game still works on its own, with accounts saved only in each browser.

## Set it up (about 10 minutes)

You do these steps yourself, in your own account. **Never share your Cloudflare password or API token with anyone, including an AI assistant.**

1. Install Node.js (the LTS version) from https://nodejs.org.
2. Create a free Cloudflare account at https://dash.cloudflare.com/sign-up if you don't have one.
3. Open PowerShell in this `server` folder and run these one at a time:

   ```powershell
   npx wrangler login
   ```
   A browser window opens. Sign in to Cloudflare and click **Allow**.

   ```powershell
   npx wrangler d1 create pokepackdle
   ```
   It prints a `database_id`. Copy it into `wrangler.toml`, replacing `PASTE-YOUR-DATABASE-ID-HERE`.

   ```powershell
   npx wrangler d1 execute pokepackdle --remote --file=schema.sql
   ```
   This creates the two tables (users and scores).

   Make up a long random secret. It signs login tokens. This prints one you can use:
   ```powershell
   [guid]::NewGuid().ToString('N') + [guid]::NewGuid().ToString('N')
   ```
   Then store it (paste it when asked, and keep a copy somewhere private):
   ```powershell
   npx wrangler secret put TOKEN_SECRET
   ```

   ```powershell
   npx wrangler deploy
   ```
   It prints your server address, like `https://pokepackdle-api.YOURNAME.workers.dev`.

4. Check it works: open `https://pokepackdle-api.YOURNAME.workers.dev/api/leaderboard` in a browser. You should see `{"day":"...","players":[]}`.
5. Open `index.html` in a text editor, find the line

   ```js
   const CLOUD_URL = "";
   ```
   and put your server address between the quotes. Save.

Now anyone using that `index.html` shares accounts and the leaderboard. To let friends play, put `index.html` somewhere online (for example GitHub Pages) and send them the link.

## How it works

- **Accounts:** usernames are unique across all players and not case-sensitive, so `CdukingGD` and `cdukinggd` are the same name. Passwords are stored as salted PBKDF2 hashes, never in plain text. Logins last 30 days.
- **Scores:** when a player finishes their pack of the day, the game posts the score. Each account's first score for a day is the one that counts. Practice ("Unlimited") packs are never posted.
- **Leaderboard:** shows today's score, best pack and days played for every player.

## Limits to know about

- **Scores come from the player's browser.** A determined player could send a fake score. Stopping that would mean the server picks the packs and works out the scores itself. That's a bigger change.
- **No rate limiting.** For a small group that's fine. If it gets popular, add Cloudflare's rate limiting rules.
- **Open access.** The server accepts requests from any website. To restrict it to your own page, change `Access-Control-Allow-Origin` in `worker.js` to your page's address.
- **Local accounts aren't moved.** Accounts and stats already saved in a browser stay there. Players sign up again on the server.
- **The admin panel is hidden** when the shared server is on, because it only manages accounts saved in one browser.
- **Days follow each player's own clock.** The server accepts a score for a date within one day of its own date.
