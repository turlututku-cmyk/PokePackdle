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
  return json({token:await makeToken(env, id), user:{id, display:username}});
}

async function login(req, env){
  const {username, password} = await readBody(req);
  if (typeof username !== "string" || typeof password !== "string") return fail(401, "badlogin", "Wrong username or password.");
  const row = await env.DB.prepare("SELECT id, display, salt, hash FROM users WHERE key = ?").bind(username.toLowerCase()).first();
  const hash = await hashPassword(password, row ? row.salt : "0".repeat(32));   /* always hash, so timing doesn't reveal whether a name exists */
  if (!row || !sameText(hash, row.hash)) return fail(401, "badlogin", "Wrong username or password.");
  return json({token:await makeToken(env, row.id), user:{id:row.id, display:row.display}});
}

async function me(req, env){
  const uid = await readToken(env, req);
  if (!uid) return fail(401, "auth", "Log in again.");
  const row = await env.DB.prepare("SELECT id, display FROM users WHERE id = ?").bind(uid).first();
  return row ? json({user:row}) : fail(401, "auth", "Log in again.");
}

/* one score per account per day. The first score for a day is the one that counts. */
async function score(req, env){
  const uid = await readToken(env, req);
  if (!uid) return fail(401, "auth", "Log in again.");
  const b = await readBody(req), s = b.score, today = utcDay(), day = isDay(b.day) ? b.day : today;
  if (!Number.isInteger(s) || s < 0 || s > 20000) return fail(400, "badscore", "That score isn't valid.");
  if (Math.abs(Date.parse(day) - Date.parse(today)) > 864e5) return fail(400, "badday", "That day isn't valid.");
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
      if (path === "" || path === "/api") return json({ok:true, name:"pokepackdle-api"});
      return fail(404, "notfound", "Not found.");
    } catch (e) {
      return fail(500, "server", "Something went wrong on the server.");
    }
  },
};
