/* PokePackdle server: shared accounts and a shared leaderboard.
   Runs on Cloudflare Workers, with a D1 (SQLite) database bound as DB and a secret named TOKEN_SECRET. */

const enc = new TextEncoder();
const CORS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "Content-Type, Authorization",
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
  "Access-Control-Max-Age": "86400",
};
const json = (data, status = 200) => new Response(JSON.stringify(data), {status, headers:{"Content-Type":"application/json", ...CORS}});
const fail = (status, error, message) => json({error, message}, status);
const hex = buf => Array.from(new Uint8Array(buf), b => b.toString(16).padStart(2, "0")).join("");
const b64u = buf => btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
const fromB64u = s => Uint8Array.from(atob(s.replace(/-/g, "+").replace(/_/g, "/")), c => c.charCodeAt(0));
const utcDay = () => new Date().toISOString().slice(0, 10);
const isDay = s => typeof s === "string" && /^\d{4}-\d{2}-\d{2}$/.test(s) && !Number.isNaN(Date.parse(s));
const readBody = async req => { try { return await req.json(); } catch { return {}; } };

/* admins are the usernames listed in the ADMINS setting (comma separated, set in wrangler.toml). The server checks the
   caller's login on every admin request, so the buttons in the game are only a convenience. */
const adminKeys = env => String(env.ADMINS || "").split(",").map(s => s.trim().toLowerCase()).filter(Boolean);
const isAdminKey = (env, key) => adminKeys(env).includes(String(key).toLowerCase());

/* passwords are stored as salted PBKDF2 hashes, never in plain text */
async function hashPassword(password, salt){
  const key = await crypto.subtle.importKey("raw", enc.encode(password), "PBKDF2", false, ["deriveBits"]);
  return hex(await crypto.subtle.deriveBits({name:"PBKDF2", salt:enc.encode(salt), iterations:100000, hash:"SHA-256"}, key, 256));
}
function sameText(a, b){
  if (a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return d === 0;
}

/* login tokens are signed with TOKEN_SECRET, so the server doesn't have to keep sessions */
async function sign(secret, text){
  const key = await crypto.subtle.importKey("raw", enc.encode(secret), {name:"HMAC", hash:"SHA-256"}, false, ["sign"]);
  return b64u(await crypto.subtle.sign("HMAC", key, enc.encode(text)));
}
async function makeToken(env, uid){
  const body = b64u(enc.encode(JSON.stringify({uid, exp:Date.now() + 30 * 864e5})));
  return body + "." + await sign(env.TOKEN_SECRET, body);
}
async function readToken(env, req){
  const h = req.headers.get("Authorization") || "", t = h.startsWith("Bearer ") ? h.slice(7) : "", [body, sig] = t.split(".");
  if (!body || !sig || !env.TOKEN_SECRET) return null;
  if (!sameText(sig, await sign(env.TOKEN_SECRET, body))) return null;
  try { const p = JSON.parse(new TextDecoder().decode(fromB64u(body))); return p.exp > Date.now() ? p.uid : null; } catch { return null; }
}

async function signup(req, env){
  const {username, password} = await readBody(req);
  if (typeof username !== "string" || !/^[A-Za-z0-9_]{3,16}$/.test(username)) return fail(400, "badname", "Username must be 3–16 letters, numbers or underscores.");
  if (typeof password !== "string" || password.length < 6 || password.length > 100) return fail(400, "badpass", "Password needs 6 to 100 characters.");
  const key = username.toLowerCase();
  if (await env.DB.prepare("SELECT id FROM users WHERE key = ?").bind(key).first()) return fail(409, "taken", "That username is taken.");
  const salt = hex(crypto.getRandomValues(new Uint8Array(16))), hash = await hashPassword(password, salt);
  let res;
  try { res = await env.DB.prepare("INSERT INTO users (key, display, salt, hash, created) VALUES (?, ?, ?, ?, ?)").bind(key, username, salt, hash, Date.now()).run(); }
  catch { return fail(409, "taken", "That username is taken."); }   /* two people signing up at the same moment */
  const id = res.meta.last_row_id;
  return json({token:await makeToken(env, id), user:{id, display:username, admin:isAdminKey(env, key)}});
}

async function login(req, env){
  const {username, password} = await readBody(req);
  if (typeof username !== "string" || typeof password !== "string") return fail(401, "badlogin", "Wrong username or password.");
  const row = await env.DB.prepare("SELECT id, key, display, salt, hash FROM users WHERE key = ?").bind(username.toLowerCase()).first();
  const hash = await hashPassword(password, row ? row.salt : "0".repeat(32));   /* always hash, so timing doesn't reveal whether a name exists */
  if (!row || !sameText(hash, row.hash)) return fail(401, "badlogin", "Wrong username or password.");
  return json({token:await makeToken(env, row.id), user:{id:row.id, display:row.display, admin:isAdminKey(env, row.key)}});
}

/* "new pack" grants: when an admin gives a player a new pack, a row lands here. The game asks for the newest one and, if it
   hasn't seen it yet, deals the player a fresh pack. The table is created on first use, so no manual database step is needed. */
let grantsReady = false;
async function ensureGrants(env){
  if (grantsReady) return;
  await env.DB.prepare("CREATE TABLE IF NOT EXISTS packgrants (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL, day TEXT NOT NULL, ts INTEGER NOT NULL)").run();
  grantsReady = true;
}

async function me(req, env){
  const uid = await readToken(env, req);
  if (!uid) return fail(401, "auth", "Log in again.");
  const row = await env.DB.prepare("SELECT id, key, display FROM users WHERE id = ?").bind(uid).first();
  if (!row) return fail(401, "auth", "Log in again.");
  let grant = {id:0, day:null};
  try {
    await ensureGrants(env);
    const g = await env.DB.prepare("SELECT id, day FROM packgrants WHERE user_id = ? ORDER BY id DESC LIMIT 1").bind(uid).first();
    if (g) grant = {id:g.id, day:g.day};
  } catch {}   /* never let this stop a login check */
  return json({user:{id:row.id, display:row.display, admin:isAdminKey(env, row.key)}, grant});
}

/* the columns that hold each player's best pull, shown on their profile. Added to the existing users table on first use,
   since the table already existed before this feature (a fresh install gets them straight from schema.sql instead). */
let userColsReady = false;
async function ensureUserCols(env){
  if (userColsReady) return;
  const info = await env.DB.prepare("PRAGMA table_info(users)").all();
  const names = new Set(info.results.map(r => r.name));
  if (!names.has("best_pts")) await env.DB.prepare("ALTER TABLE users ADD COLUMN best_pts INTEGER").run();
  if (!names.has("best_name")) await env.DB.prepare("ALTER TABLE users ADD COLUMN best_name TEXT").run();
  userColsReady = true;
}

/* every card from a counted daily pack, so trading has something real to move between accounts. The table is created on
   first use. in_trade_id marks a card as currently offered in that open trade (NULL when it's free to offer or trade). */
let cardsReady = false;
async function ensureCards(env){
  if (cardsReady) return;
  await env.DB.prepare(
    "CREATE TABLE IF NOT EXISTS cards (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL, poke_id INTEGER NOT NULL, " +
    "tier INTEGER NOT NULL, shiny INTEGER NOT NULL, ts INTEGER NOT NULL, in_trade_id INTEGER)"
  ).run();
  cardsReady = true;
}

/* one score per account per day. The first score for a day is the one that counts. A counted score can also carry the
   pack's 10 cards (for the player's server-side inventory) and a best-pull for their profile. */
async function score(req, env){
  const uid = await readToken(env, req);
  if (!uid) return fail(401, "auth", "Log in again.");
  const b = await readBody(req), s = b.score, today = utcDay(), day = isDay(b.day) ? b.day : today;
  if (!Number.isInteger(s) || s < 0 || s > 20000) return fail(400, "badscore", "That score isn't valid.");
  if (Math.abs(Date.parse(day) - Date.parse(today)) > 864e5) return fail(400, "badday", "That day isn't valid.");
  if (!await env.DB.prepare("SELECT id FROM users WHERE id = ?").bind(uid).first()) return fail(401, "auth", "Log in again.");   /* the account may have been deleted */
  const r = await env.DB.prepare("INSERT OR IGNORE INTO scores (user_id, day, score, ts) VALUES (?, ?, ?, ?)").bind(uid, day, s, Date.now()).run();
  const counted = r.meta.changes > 0;
  if (counted) {
    const cards = Array.isArray(b.cards) ? b.cards.slice(0, 10) : [];
    if (cards.length && cards.every(c => Number.isInteger(c.id) && c.id >= 1 && c.id <= 1025 && Number.isInteger(c.t) && c.t >= 0 && c.t <= 6 && (c.s === 0 || c.s === 1))) {
      try {
        await ensureCards(env);
        const now = Date.now();
        await env.DB.batch(cards.map(c => env.DB.prepare("INSERT INTO cards (user_id, poke_id, tier, shiny, ts) VALUES (?, ?, ?, ?, ?)").bind(uid, c.id, c.t, c.s, now)));
      } catch {}   /* the score itself still counts even if the card ledger has trouble */
    }
    const bp = b.bestPull;
    if (bp && Number.isInteger(bp.pts) && bp.pts > 0 && typeof bp.name === "string") {
      try {
        await ensureUserCols(env);
        await env.DB.prepare("UPDATE users SET best_pts = ?, best_name = ? WHERE id = ? AND (best_pts IS NULL OR best_pts < ?)").bind(bp.pts, bp.name.slice(0, 40), uid, bp.pts).run();
      } catch {}
    }
  }
  return json({ok:true, counted, day});
}

/* a player's own card collection, grouped (so a stack of the same card is one row with a count) */
async function cardsList(req, env){
  const uid = await readToken(env, req);
  if (!uid) return fail(401, "auth", "Log in again.");
  await ensureCards(env);
  const rows = await env.DB.prepare(
    "SELECT poke_id AS id, tier AS t, shiny AS s, COUNT(*) AS n, MAX(id) AS last FROM cards WHERE user_id = ? GROUP BY poke_id, tier, shiny ORDER BY last DESC"
  ).bind(uid).all();
  const total = await env.DB.prepare("SELECT COUNT(*) AS n FROM cards WHERE user_id = ?").bind(uid).first();
  return json({groups:rows.results, total:total ? total.n : 0});
}

/* a player's public profile: what anyone logged in can see about them, plus whether there's already a trade between us */
async function profile(req, env){
  const uid = await readToken(env, req);
  if (!uid) return fail(401, "auth", "Log in again.");
  const name = new URL(req.url).searchParams.get("name"), target = await findUser(env, name);
  if (!target) return fail(404, "nouser", "No player with that name.");
  await ensureUserCols(env);
  const day = utcDay();
  const row = await env.DB.prepare(
    "SELECT u.created, u.best_pts, u.best_name, COUNT(s.id) AS days, MAX(s.score) AS best, MAX(CASE WHEN s.day = ? THEN s.score END) AS today " +
    "FROM users u LEFT JOIN scores s ON s.user_id = u.id WHERE u.id = ? GROUP BY u.id"
  ).bind(day, target.id).first();
  await ensureTrades(env);
  const between = uid === target.id ? null : await env.DB.prepare(
    "SELECT id, status, from_user, to_user FROM trades WHERE status IN ('pending','open') AND ((from_user = ? AND to_user = ?) OR (from_user = ? AND to_user = ?)) LIMIT 1"
  ).bind(uid, target.id, target.id, uid).first();
  return json({
    profile:{
      name:target.display, admin:isAdminKey(env, target.key), created:row.created, days:row.days,
      best:row.best, today:row.today, bestPts:row.best_pts, bestName:row.best_name,
    },
    self:uid === target.id,
    trade:between ? {id:between.id, status:between.status, mine:between.from_user === uid} : null,
  });
}

/* ---------- trading ---------- */
/* A trade goes pending (a request) -> open (both sides can place cards and mark ready) -> completed (cards swap, once both
   are ready at once) or cancelled/declined. Cards offered in an open trade are locked (in_trade_id) so the same card can't
   be offered twice at once; nothing moves until both sides are ready together. The table is created on first use. */
let tradesReady = false;
async function ensureTrades(env){
  if (tradesReady) return;
  await env.DB.prepare(
    "CREATE TABLE IF NOT EXISTS trades (id INTEGER PRIMARY KEY AUTOINCREMENT, from_user INTEGER NOT NULL, to_user INTEGER NOT NULL, " +
    "status TEXT NOT NULL, from_ready INTEGER NOT NULL DEFAULT 0, to_ready INTEGER NOT NULL DEFAULT 0, created INTEGER NOT NULL, updated INTEGER NOT NULL)"
  ).run();
  tradesReady = true;
}
const MAX_OPEN_TRADES = 20;
const otherSide = (t, uid) => t.from_user === uid ? t.to_user : t.from_user;

async function tradeRow(env, id, uid){
  await ensureTrades(env);
  const t = await env.DB.prepare("SELECT * FROM trades WHERE id = ?").bind(id).first();
  return t && (t.from_user === uid || t.to_user === uid) ? t : null;
}

async function tradesList(req, env){
  const uid = await readToken(env, req);
  if (!uid) return fail(401, "auth", "Log in again.");
  await ensureTrades(env); await ensureCards(env);
  const rows = (await env.DB.prepare(
    "SELECT t.*, uf.display AS from_name, ut.display AS to_name FROM trades t " +
    "JOIN users uf ON uf.id = t.from_user JOIN users ut ON ut.id = t.to_user " +
    "WHERE t.from_user = ? OR t.to_user = ? ORDER BY t.updated DESC LIMIT 60"
  ).bind(uid, uid).all()).results;
  const shape = t => ({
    id:t.id, status:t.status, mine:t.from_user === uid, with:t.from_user === uid ? t.to_name : t.from_name,
    myReady:!!(t.from_user === uid ? t.from_ready : t.to_ready), theirReady:!!(t.from_user === uid ? t.to_ready : t.from_ready), updated:t.updated,
  });
  return json({
    incoming:rows.filter(t => t.status === "pending" && t.to_user === uid).map(shape),
    outgoing:rows.filter(t => t.status === "pending" && t.from_user === uid).map(shape),
    open:rows.filter(t => t.status === "open").map(shape),
    recent:rows.filter(t => ["completed", "declined", "cancelled"].includes(t.status)).slice(0, 10).map(shape),
  });
}

async function tradeRequest(req, env){
  const uid = await readToken(env, req);
  if (!uid) return fail(401, "auth", "Log in again.");
  const {name} = await readBody(req), target = await findUser(env, name);
  if (!target) return fail(404, "nouser", "No player with that name.");
  if (target.id === uid) return fail(400, "self", "You can't trade with yourself.");
  await ensureTrades(env);
  const existing = await env.DB.prepare(
    "SELECT id FROM trades WHERE status IN ('pending','open') AND ((from_user = ? AND to_user = ?) OR (from_user = ? AND to_user = ?))"
  ).bind(uid, target.id, target.id, uid).first();
  if (existing) return fail(409, "exists", "There's already a trade with that player.");
  const mine = await env.DB.prepare("SELECT COUNT(*) AS n FROM trades WHERE status IN ('pending','open') AND (from_user = ? OR to_user = ?)").bind(uid, uid).first();
  if (mine && mine.n >= MAX_OPEN_TRADES) return fail(429, "toomany", "You have too many open trades already.");
  const now = Date.now();
  const r = await env.DB.prepare("INSERT INTO trades (from_user, to_user, status, created, updated) VALUES (?, ?, 'pending', ?, ?)").bind(uid, target.id, now, now).run();
  return json({ok:true, id:r.meta.last_row_id});
}

async function tradeRespond(req, env){
  const uid = await readToken(env, req);
  if (!uid) return fail(401, "auth", "Log in again.");
  const {id, accept} = await readBody(req), t = await tradeRow(env, id, uid);
  if (!t) return fail(404, "notrade", "That trade isn't there any more.");
  if (t.status !== "pending" || t.to_user !== uid) return fail(400, "badstate", "That trade can't be answered right now.");
  await env.DB.prepare("UPDATE trades SET status = ?, updated = ? WHERE id = ?").bind(accept ? "open" : "declined", Date.now(), id).run();
  return json({ok:true});
}

async function tradeCancel(req, env){
  const uid = await readToken(env, req);
  if (!uid) return fail(401, "auth", "Log in again.");
  const {id} = await readBody(req), t = await tradeRow(env, id, uid);
  if (!t) return fail(404, "notrade", "That trade isn't there any more.");
  if (!["pending", "open"].includes(t.status)) return fail(400, "badstate", "That trade is already finished.");
  await ensureCards(env);
  await env.DB.prepare("UPDATE cards SET in_trade_id = NULL WHERE in_trade_id = ?").bind(id).run();
  await env.DB.prepare("UPDATE trades SET status = 'cancelled', updated = ? WHERE id = ?").bind(Date.now(), id).run();
  return json({ok:true});
}

/* replaces my side of the trade with the cards named in the request (as {id, t, s, qty} groups), locking or releasing
   cards as needed. If I don't own as many of a card as I asked to offer, it offers what it can and says so. */
async function tradeOffer(req, env){
  const uid = await readToken(env, req);
  if (!uid) return fail(401, "auth", "Log in again.");
  const {id, items} = await readBody(req), t = await tradeRow(env, id, uid);
  if (!t) return fail(404, "notrade", "That trade isn't there any more.");
  if (t.status !== "open") return fail(400, "badstate", "This trade isn't open for offers.");
  if (!Array.isArray(items)) return fail(400, "baditems", "That offer isn't valid.");
  await ensureCards(env);
  await env.DB.prepare("UPDATE cards SET in_trade_id = NULL WHERE in_trade_id = ? AND user_id = ?").bind(id, uid).run();
  const short = [];
  for (const it of items.slice(0, 30)) {
    const pid = it.id, tier = it.t, shiny = it.s ? 1 : 0, qty = Math.max(0, Math.min(99, it.qty | 0));
    if (!Number.isInteger(pid) || !Number.isInteger(tier) || !qty) continue;
    const free = await env.DB.prepare(
      "SELECT id FROM cards WHERE user_id = ? AND poke_id = ? AND tier = ? AND shiny = ? AND in_trade_id IS NULL LIMIT ?"
    ).bind(uid, pid, tier, shiny, qty).all();
    if (free.results.length) await env.DB.batch(free.results.map(c => env.DB.prepare("UPDATE cards SET in_trade_id = ? WHERE id = ?").bind(id, c.id)));
    if (free.results.length < qty) short.push({id:pid, t:tier, s:shiny, wanted:qty, got:free.results.length});
  }
  await env.DB.prepare("UPDATE trades SET from_ready = 0, to_ready = 0, updated = ? WHERE id = ?").bind(Date.now(), id).run();
  return json({ok:true, short});
}

/* everything currently on the table for a trade, grouped per side */
async function tradeOffers(env, id){
  const rows = (await env.DB.prepare("SELECT user_id, poke_id AS id, tier AS t, shiny AS s FROM cards WHERE in_trade_id = ?").bind(id).all()).results;
  const group = uid => { const m = new Map(); for (const r of rows) if (r.user_id === uid) { const k = r.id + ":" + r.t + ":" + r.s; m.set(k, {id:r.id, t:r.t, s:r.s, qty:(m.get(k)?.qty || 0) + 1}); } return [...m.values()]; };
  return group;
}

async function tradeReady(req, env){
  const uid = await readToken(env, req);
  if (!uid) return fail(401, "auth", "Log in again.");
  const {id, ready} = await readBody(req), t = await tradeRow(env, id, uid);
  if (!t) return fail(404, "notrade", "That trade isn't there any more.");
  if (t.status !== "open") return fail(400, "badstate", "This trade isn't open.");
  const mineField = t.from_user === uid ? "from_ready" : "to_ready";
  await env.DB.prepare("UPDATE trades SET " + mineField + " = ?, updated = ? WHERE id = ?").bind(ready ? 1 : 0, Date.now(), id).run();
  const now = await env.DB.prepare("SELECT * FROM trades WHERE id = ?").bind(id).first();
  let completed = false;
  if (now.from_ready && now.to_ready) {
    await ensureCards(env);
    const cards = (await env.DB.prepare("SELECT id, user_id FROM cards WHERE in_trade_id = ?").bind(id).all()).results;
    const swaps = cards.map(c => env.DB.prepare("UPDATE cards SET user_id = ?, in_trade_id = NULL WHERE id = ?").bind(c.user_id === t.from_user ? t.to_user : t.from_user, c.id));
    swaps.push(env.DB.prepare("UPDATE trades SET status = 'completed', updated = ? WHERE id = ?").bind(Date.now(), id));
    if (swaps.length) await env.DB.batch(swaps);
    completed = true;
  }
  return json({ok:true, completed});
}

/* the detail of one trade: both sides' offers, ready state, and the other player's name */
async function tradeDetail(req, env){
  const uid = await readToken(env, req);
  if (!uid) return fail(401, "auth", "Log in again.");
  const id = parseInt(new URL(req.url).searchParams.get("id"), 10), t = await tradeRow(env, id, uid);
  if (!t) return fail(404, "notrade", "That trade isn't there any more.");
  await ensureCards(env);
  const group = await tradeOffers(env, id);
  const other = await env.DB.prepare("SELECT display FROM users WHERE id = ?").bind(otherSide(t, uid)).first();
  return json({
    status:t.status, with:other ? other.display : "?", mine:t.from_user === uid,
    myOffer:group(uid), theirOffer:group(otherSide(t, uid)),
    myReady:!!(t.from_user === uid ? t.from_ready : t.to_ready), theirReady:!!(t.from_user === uid ? t.to_ready : t.from_ready),
  });
}

async function leaderboard(req, env){
  const q = new URL(req.url).searchParams.get("day"), day = isDay(q) ? q : utcDay();
  const rows = await env.DB.prepare(
    "SELECT u.display AS name, MAX(s.score) AS best, COUNT(*) AS days, MAX(CASE WHEN s.day = ? THEN s.score END) AS today " +
    "FROM scores s JOIN users u ON u.id = s.user_id GROUP BY u.id ORDER BY (today IS NULL), today DESC, best DESC LIMIT 100"
  ).bind(day).all();
  return json({day, players:rows.results});
}

/* ---------- admin ---------- */
async function requireAdmin(req, env){
  const uid = await readToken(env, req);
  if (!uid) return null;
  const row = await env.DB.prepare("SELECT id, key, display FROM users WHERE id = ?").bind(uid).first();
  return row && isAdminKey(env, row.key) ? row : null;
}
const findUser = (env, name) => typeof name === "string" ? env.DB.prepare("SELECT id, key, display FROM users WHERE key = ?").bind(name.toLowerCase()).first() : Promise.resolve(null);

async function adminUsers(req, env){
  if (!await requireAdmin(req, env)) return fail(403, "forbidden", "Admins only.");
  const q = new URL(req.url).searchParams.get("day"), day = isDay(q) ? q : utcDay();
  const rows = await env.DB.prepare(
    "SELECT u.id, u.display AS name, u.created, COUNT(s.id) AS days, MAX(s.score) AS best, MAX(CASE WHEN s.day = ? THEN s.score END) AS today " +
    "FROM users u LEFT JOIN scores s ON s.user_id = u.id GROUP BY u.id ORDER BY u.created DESC LIMIT 500"
  ).bind(day).all();
  return json({day, users:rows.results.map(r => ({...r, admin:isAdminKey(env, r.name)}))});
}

async function adminPassword(req, env){
  if (!await requireAdmin(req, env)) return fail(403, "forbidden", "Admins only.");
  const {name, password} = await readBody(req), target = await findUser(env, name);
  if (!target) return fail(404, "nouser", "No player with that name.");
  if (typeof password !== "string" || password.length < 6 || password.length > 100) return fail(400, "badpass", "Password needs 6 to 100 characters.");
  const salt = hex(crypto.getRandomValues(new Uint8Array(16)));
  await env.DB.prepare("UPDATE users SET salt = ?, hash = ? WHERE id = ?").bind(salt, await hashPassword(password, salt), target.id).run();
  return json({ok:true});
}

async function adminDelete(req, env){
  const admin = await requireAdmin(req, env);
  if (!admin) return fail(403, "forbidden", "Admins only.");
  const {name} = await readBody(req), target = await findUser(env, name);
  if (!target) return fail(404, "nouser", "No player with that name.");
  if (target.id === admin.id || isAdminKey(env, target.key)) return fail(400, "protected", "Admin accounts can't be deleted here.");
  await env.DB.prepare("DELETE FROM scores WHERE user_id = ?").bind(target.id).run();
  try { await ensureGrants(env); await env.DB.prepare("DELETE FROM packgrants WHERE user_id = ?").bind(target.id).run(); } catch {}
  try { await ensureChat(env); await env.DB.prepare("DELETE FROM chat WHERE user_id = ?").bind(target.id).run(); } catch {}
  try {
    await ensureTrades(env); await ensureCards(env);
    await env.DB.prepare("UPDATE cards SET in_trade_id = NULL WHERE in_trade_id IN (SELECT id FROM trades WHERE from_user = ? OR to_user = ?)").bind(target.id, target.id).run();
    await env.DB.prepare("DELETE FROM trades WHERE from_user = ? OR to_user = ?").bind(target.id, target.id).run();
    await env.DB.prepare("DELETE FROM cards WHERE user_id = ?").bind(target.id).run();
  } catch {}
  await env.DB.prepare("DELETE FROM users WHERE id = ?").bind(target.id).run();
  return json({ok:true});
}

async function adminClearScore(req, env){
  if (!await requireAdmin(req, env)) return fail(403, "forbidden", "Admins only.");
  const b = await readBody(req), target = await findUser(env, b.name);
  if (!target) return fail(404, "nouser", "No player with that name.");
  const day = isDay(b.day) ? b.day : utcDay();
  const r = await env.DB.prepare("DELETE FROM scores WHERE user_id = ? AND day = ?").bind(target.id, day).run();
  return json({ok:true, removed:r.meta.changes});
}

/* ---------- chat ---------- */
/* One shared room for everyone who is logged in. The table is created on first use. Messages are plain text (the game
   shows them as text, never as HTML), capped at 200 characters, rate limited, and only the newest 1,000 are kept. */
let chatReady = false;
async function ensureChat(env){
  if (chatReady) return;
  await env.DB.prepare("CREATE TABLE IF NOT EXISTS chat (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL, text TEXT NOT NULL, ts INTEGER NOT NULL)").run();
  chatReady = true;
}

/* the newest 50 messages. "messages" holds the ones after ?after=ID, "ids" lists everything still there, so the game can drop deleted ones */
async function chatList(req, env){
  const uid = await readToken(env, req);
  if (!uid) return fail(401, "auth", "Log in again.");
  await ensureChat(env);
  const after = parseInt(new URL(req.url).searchParams.get("after"), 10);
  const res = await env.DB.prepare(
    "SELECT c.id, c.text, c.ts, u.display AS name, u.key AS ukey FROM chat c JOIN users u ON u.id = c.user_id ORDER BY c.id DESC LIMIT 50"
  ).all();
  const rows = res.results.reverse();
  return json({
    messages:rows.filter(r => !(after > 0) || r.id > after).map(r => ({id:r.id, name:r.name, text:r.text, ts:r.ts, admin:isAdminKey(env, r.ukey)})),
    ids:rows.map(r => r.id),
  });
}

async function chatSend(req, env){
  const uid = await readToken(env, req);
  if (!uid) return fail(401, "auth", "Log in again.");
  const {text} = await readBody(req);
  const t = typeof text === "string" ? text.replace(/[ -]/g, " ").replace(/\s+/g, " ").trim() : "";
  if (!t) return fail(400, "empty", "Type a message first.");
  if (t.length > 200) return fail(400, "long", "Messages can be up to 200 characters.");
  const u = await env.DB.prepare("SELECT id, key, display FROM users WHERE id = ?").bind(uid).first();
  if (!u) return fail(401, "auth", "Log in again.");
  await ensureChat(env);
  const now = Date.now();
  const recent = await env.DB.prepare("SELECT COUNT(*) AS n, MAX(ts) AS last FROM chat WHERE user_id = ? AND ts > ?").bind(uid, now - 60000).first();
  if (recent && recent.last && now - recent.last < 1500) return fail(429, "slow", "Slow down a little.");
  if (recent && recent.n >= 20) return fail(429, "slow", "That's a lot of messages. Wait a minute and try again.");
  const r = await env.DB.prepare("INSERT INTO chat (user_id, text, ts) VALUES (?, ?, ?)").bind(uid, t, now).run();
  const id = r.meta.last_row_id;
  if (id % 50 === 0) await env.DB.prepare("DELETE FROM chat WHERE id <= ?").bind(id - 1000).run();
  return json({ok:true, message:{id, name:u.display, text:t, ts:now, admin:isAdminKey(env, u.key)}});
}

async function adminChatDelete(req, env){
  if (!await requireAdmin(req, env)) return fail(403, "forbidden", "Admins only.");
  const {id} = await readBody(req);
  if (!Number.isInteger(id)) return fail(400, "badid", "That message isn't valid.");
  await ensureChat(env);
  await env.DB.prepare("DELETE FROM chat WHERE id = ?").bind(id).run();
  return json({ok:true});
}

async function adminChatClear(req, env){
  if (!await requireAdmin(req, env)) return fail(403, "forbidden", "Admins only.");
  await ensureChat(env);
  const r = await env.DB.prepare("DELETE FROM chat").run();
  return json({ok:true, removed:r.meta.changes});
}

/* gives a player a new pack: their latest score (from today or yesterday) is removed from the leaderboard and a grant is
   recorded, so the game deals them a fresh pack that counts. */
async function adminNewPack(req, env){
  if (!await requireAdmin(req, env)) return fail(403, "forbidden", "Admins only.");
  const {name} = await readBody(req), target = await findUser(env, name);
  if (!target) return fail(404, "nouser", "No player with that name.");
  await ensureGrants(env);
  const today = utcDay();
  const last = await env.DB.prepare("SELECT day FROM scores WHERE user_id = ? ORDER BY day DESC LIMIT 1").bind(target.id).first();
  const day = last && Math.abs(Date.parse(last.day) - Date.parse(today)) <= 864e5 ? last.day : today;
  const r = await env.DB.prepare("DELETE FROM scores WHERE user_id = ? AND day = ?").bind(target.id, day).run();
  await env.DB.prepare("INSERT INTO packgrants (user_id, day, ts) VALUES (?, ?, ?)").bind(target.id, day, Date.now()).run();
  return json({ok:true, removed:r.meta.changes, day});
}

export default {
  async fetch(req, env){
    if (req.method === "OPTIONS") return new Response(null, {status:204, headers:CORS});
    const path = new URL(req.url).pathname.replace(/\/+$/, "");
    try {
      if (req.method === "POST" && path === "/api/signup") return await signup(req, env);
      if (req.method === "POST" && path === "/api/login") return await login(req, env);
      if (req.method === "POST" && path === "/api/score") return await score(req, env);
      if (req.method === "GET" && path === "/api/me") return await me(req, env);
      if (req.method === "GET" && path === "/api/leaderboard") return await leaderboard(req, env);
      if (req.method === "GET" && path === "/api/admin/users") return await adminUsers(req, env);
      if (req.method === "POST" && path === "/api/admin/password") return await adminPassword(req, env);
      if (req.method === "POST" && path === "/api/admin/delete") return await adminDelete(req, env);
      if (req.method === "POST" && path === "/api/admin/clearscore") return await adminClearScore(req, env);
      if (req.method === "POST" && path === "/api/admin/newpack") return await adminNewPack(req, env);
      if (req.method === "GET" && path === "/api/chat") return await chatList(req, env);
      if (req.method === "POST" && path === "/api/chat") return await chatSend(req, env);
      if (req.method === "POST" && path === "/api/admin/chat/delete") return await adminChatDelete(req, env);
      if (req.method === "POST" && path === "/api/admin/chat/clear") return await adminChatClear(req, env);
      if (req.method === "GET" && path === "/api/cards") return await cardsList(req, env);
      if (req.method === "GET" && path === "/api/profile") return await profile(req, env);
      if (req.method === "GET" && path === "/api/trades") return await tradesList(req, env);
      if (req.method === "GET" && path === "/api/trades/detail") return await tradeDetail(req, env);
      if (req.method === "POST" && path === "/api/trades/request") return await tradeRequest(req, env);
      if (req.method === "POST" && path === "/api/trades/respond") return await tradeRespond(req, env);
      if (req.method === "POST" && path === "/api/trades/offer") return await tradeOffer(req, env);
      if (req.method === "POST" && path === "/api/trades/ready") return await tradeReady(req, env);
      if (req.method === "POST" && path === "/api/trades/cancel") return await tradeCancel(req, env);
      if (path === "" || path === "/api") return json({ok:true, name:"pokepackdle-api"});
      return fail(404, "notfound", "Not found.");
    } catch (e) {
      return fail(500, "server", "Something went wrong on the server.");
    }
  },
};
