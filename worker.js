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

/* one score per account per day. The first score for a day is the one that counts. */
async function score(req, env){
  const uid = await readToken(env, req);
  if (!uid) return fail(401, "auth", "Log in again.");
  const b = await readBody(req), s = b.score, today = utcDay(), day = isDay(b.day) ? b.day : today;
  if (!Number.isInteger(s) || s < 0 || s > 20000) return fail(400, "badscore", "That score isn't valid.");
  if (Math.abs(Date.parse(day) - Date.parse(today)) > 864e5) return fail(400, "badday", "That day isn't valid.");
  if (!await env.DB.prepare("SELECT id FROM users WHERE id = ?").bind(uid).first()) return fail(401, "auth", "Log in again.");   /* the account may have been deleted */
  const r = await env.DB.prepare("INSERT OR IGNORE INTO scores (user_id, day, score, ts) VALUES (?, ?, ?, ?)").bind(uid, day, s, Date.now()).run();
  return json({ok:true, counted:r.meta.changes > 0, day});
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
      if (path === "" || path === "/api") return json({ok:true, name:"pokepackdle-api"});
      return fail(404, "notfound", "Not found.");
    } catch (e) {
      return fail(500, "server", "Something went wrong on the server.");
    }
  },
};
