'use strict';
/*
 * Brankas — server self-hosted.
 * Model zero-knowledge:
 *   klien: masterKey = PBKDF2(password, kdfSalt)  ->  encKey = HKDF(masterKey,"enc")  (tidak pernah dikirim)
 *                                                  ->  authKey = HKDF(masterKey,"auth") (dikirim saat login)
 *   server: menyimpan scrypt(authKey) + vault terenkripsi. Server tidak bisa mendekripsi vault.
 */
const path = require('path');
const crypto = require('crypto');
// baca .env di root proyek bila ada (Node >= 20.12)
try { process.loadEnvFile(path.join(__dirname, '..', '.env')); } catch { /* tidak ada .env */ }
const express = require('express');
const { db } = require('./db');

// ---------- konfigurasi (environment) ----------
const PORT = parseInt(process.env.PORT || '3000', 10);
const HOST = process.env.HOST || '127.0.0.1';
const SIGNUP_MODE = (process.env.SIGNUP_MODE || 'first').toLowerCase(); // first | open | code | closed
const SIGNUP_CODE = process.env.SIGNUP_CODE || '';
const SESSION_HOURS = parseInt(process.env.SESSION_HOURS || '12', 10);
const COOKIE_SECURE = (process.env.COOKIE_SECURE || 'true') !== 'false';
const TRUST_PROXY = process.env.TRUST_PROXY || 'loopback';
const MAX_VAULT_BYTES = 10 * 1024 * 1024;
const COOKIE = COOKIE_SECURE ? '__Host-brankas_sid' : 'brankas_sid';
const ATTACH_MAX = parseInt(process.env.ATTACH_MAX_MB || '25', 10) * 1048576;      // per file
const ATTACH_QUOTA = parseInt(process.env.ATTACH_QUOTA_MB || '500', 10) * 1048576; // per akun
// Cloudflare Turnstile (aktif hanya bila kedua kunci diisi)
const TS_SITE = process.env.TURNSTILE_SITE_KEY || '';
const TS_SECRET = process.env.TURNSTILE_SECRET_KEY || '';
const TURNSTILE = !!(TS_SITE && TS_SECRET);

// verifikasi token Turnstile ke Cloudflare (gagal = tolak; token hanya sekali pakai)
async function turnstileOk(token, ip) {
  if (!TURNSTILE) return true;
  if (typeof token !== 'string' || !token || token.length > 2048) return false;
  try {
    const body = new URLSearchParams({ secret: TS_SECRET, response: token, remoteip: ip || '', idempotency_key: crypto.randomUUID() });
    const r = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', { method: 'POST', body, signal: AbortSignal.timeout(8000) });
    const j = await r.json();
    return j.success === true;
  } catch (e) {
    console.error('Turnstile tidak bisa dihubungi:', e.message);
    return false;
  }
}
const TS_FAIL = { error: 'Verifikasi keamanan gagal atau kedaluwarsa. Ulangi centang "Saya bukan robot".' };

if (SIGNUP_MODE === 'code' && SIGNUP_CODE.length < 8) {
  console.error('SIGNUP_MODE=code membutuhkan SIGNUP_CODE minimal 8 karakter.');
  process.exit(1);
}

// rahasia server untuk salt palsu (mencegah enumerasi username)
let serverSecret = db.prepare('SELECT v FROM meta WHERE k = ?').get('secret')?.v;
if (!serverSecret) {
  serverSecret = crypto.randomBytes(32).toString('base64');
  db.prepare('INSERT INTO meta (k, v) VALUES (?, ?)').run('secret', serverSecret);
}

// ---------- util ----------
const now = () => Date.now();
const sha256 = (s) => crypto.createHash('sha256').update(s).digest('hex');
const SCRYPT = { N: 16384, r: 8, p: 1, maxmem: 64 * 1024 * 1024 };
const scrypt = (pw, salt) => new Promise((res, rej) =>
  crypto.scrypt(pw, salt, 32, SCRYPT, (e, k) => (e ? rej(e) : res(k))));
const B64 = /^[A-Za-z0-9+/]+={0,2}$/;
const isB64 = (s, min, max) => typeof s === 'string' && s.length >= min && s.length <= max && B64.test(s);
const normUser = (u) => (typeof u === 'string' ? u.trim().toLowerCase() : '');
const validUser = (u) => /^[a-z0-9][a-z0-9._@+-]{2,63}$/.test(u);
const KDF_ITER_MIN = 100000, KDF_ITER_MAX = 5000000;

function validVault(v) {
  return v && typeof v === 'object' && isB64(v.iv, 16, 24) && isB64(v.ct, 16, MAX_VAULT_BYTES)
    && JSON.stringify(v).length <= MAX_VAULT_BYTES;
}
function fakeSalt(username) {
  return crypto.createHmac('sha256', serverSecret).update('salt:' + username).digest().subarray(0, 16).toString('base64');
}
function signupAllowed(code) {
  switch (SIGNUP_MODE) {
    case 'open': return true;
    case 'code': return typeof code === 'string' && code.length === SIGNUP_CODE.length
      && crypto.timingSafeEqual(Buffer.from(code), Buffer.from(SIGNUP_CODE));
    case 'first': return db.prepare('SELECT COUNT(*) AS n FROM users').get().n === 0;
    default: return false;
  }
}

// rate limiter sederhana di memori
const buckets = new Map();
function limited(key, max, windowMs) {
  const t = now();
  let b = buckets.get(key);
  if (!b || b.reset < t) { b = { n: 0, reset: t + windowMs }; buckets.set(key, b); }
  b.n++;
  return b.n > max;
}
setInterval(() => { const t = now(); for (const [k, b] of buckets) if (b.reset < t) buckets.delete(k); }, 60000).unref();
setInterval(() => db.prepare('DELETE FROM sessions WHERE expires_at < ?').run(now()), 3600000).unref();

// ---------- sesi ----------
function readCookie(req) {
  const raw = req.headers.cookie || '';
  for (const part of raw.split(';')) {
    const i = part.indexOf('=');
    if (i > 0 && part.slice(0, i).trim() === COOKIE) return decodeURIComponent(part.slice(i + 1).trim());
  }
  return null;
}
function setSession(req, res, userId, wrapKey) {
  const token = crypto.randomBytes(32).toString('base64url');
  const exp = now() + SESSION_HOURS * 3600000;
  db.prepare('INSERT INTO sessions (token_hash, user_id, created_at, expires_at, ip, ua, wrap_key) VALUES (?,?,?,?,?,?,?)')
    .run(sha256(token), userId, now(), exp, req.ip, String(req.headers['user-agent'] || '').slice(0, 200),
      isB64(wrapKey, 40, 48) ? wrapKey : null);
  res.cookie(COOKIE, token, { httpOnly: true, secure: COOKIE_SECURE, sameSite: 'strict', path: '/', maxAge: SESSION_HOURS * 3600000 });
}
function auth(req, res, next) {
  const token = readCookie(req);
  if (!token) return res.status(401).json({ error: 'Belum login.' });
  const s = db.prepare('SELECT user_id, expires_at FROM sessions WHERE token_hash = ?').get(sha256(token));
  if (!s || s.expires_at < now()) return res.status(401).json({ error: 'Sesi berakhir. Silakan login lagi.' });
  req.userId = s.user_id;
  req.tokenHash = sha256(token);
  next();
}
async function verifyAuthKey(user, authKey) {
  if (!user || !isB64(authKey, 40, 48)) return false;
  const h = await scrypt(Buffer.from(authKey, 'base64'), Buffer.from(user.auth_salt, 'base64'));
  return crypto.timingSafeEqual(h, Buffer.from(user.auth_hash, 'base64'));
}

// ---------- app ----------
const app = express();
app.set('trust proxy', TRUST_PROXY);
app.disable('x-powered-by');

app.use((req, res, next) => {
  res.set({
    'Content-Security-Policy': "default-src 'self'; script-src 'self' https://challenges.cloudflare.com; frame-src https://challenges.cloudflare.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'",
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'Referrer-Policy': 'no-referrer',
    'Permissions-Policy': 'camera=(), microphone=(), geolocation=()',
    'Cross-Origin-Opener-Policy': 'same-origin',
  });
  if (COOKIE_SECURE) res.set('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  next();
});

// API: hanya JSON + header khusus (perlindungan CSRF tambahan selain SameSite=Strict)
app.use('/api', (req, res, next) => {
  res.set('Cache-Control', 'no-store');
  const isAttach = req.path.startsWith('/attachments');
  const okType = req.is('application/json')
    || req.method === 'DELETE'
    || (isAttach && req.is('application/octet-stream'));
  if (req.method !== 'GET' && (req.get('X-Brankas') !== '1' || !okType)) {
    return res.status(400).json({ error: 'Permintaan tidak valid.' });
  }
  next();
});
app.use('/api', express.json({ limit: MAX_VAULT_BYTES + 64 * 1024 }));

app.get('/api/config', (req, res) => {
  const first = db.prepare('SELECT COUNT(*) AS n FROM users').get().n === 0;
  const signup = SIGNUP_MODE === 'first' ? (first ? 'open' : 'closed') : ['open', 'code'].includes(SIGNUP_MODE) ? SIGNUP_MODE : 'closed';
  res.json({ signup, first, attachMax: ATTACH_MAX, turnstileSiteKey: TURNSTILE ? TS_SITE : null });
});

app.post('/api/prelogin', (req, res) => {
  if (limited('pre:' + req.ip, 60, 15 * 60000)) return res.status(429).json({ error: 'Terlalu banyak percobaan. Coba lagi nanti.' });
  const username = normUser(req.body?.username);
  if (!validUser(username)) return res.status(400).json({ error: 'Username tidak valid.' });
  const u = db.prepare('SELECT kdf_salt, kdf_iter FROM users WHERE username = ?').get(username);
  res.json(u ? { kdfSalt: u.kdf_salt, kdfIter: u.kdf_iter } : { kdfSalt: fakeSalt(username), kdfIter: 310000 });
});

// ---------- undangan (Tambah user) ----------
function findInvite(code) {
  if (typeof code !== 'string' || code.length < 16 || code.length > 64) return null;
  return db.prepare('SELECT * FROM invites WHERE code_hash = ? AND used_at IS NULL AND expires_at > ?').get(sha256(code), now()) || null;
}
// dipakai halaman daftar untuk mengecek link undangan
app.post('/api/invite/check', (req, res) => {
  if (limited('inv:' + req.ip, 30, 15 * 60000)) return res.status(429).json({ error: 'Terlalu banyak percobaan.' });
  const inv = findInvite(req.body?.code);
  if (!inv) return res.status(404).json({ error: 'Link undangan tidak berlaku (sudah dipakai atau kedaluwarsa).' });
  res.json({ username: inv.username, expiresAt: inv.expires_at });
});

function admin(req, res, next) {
  const u = db.prepare('SELECT is_admin FROM users WHERE id = ?').get(req.userId);
  if (!u?.is_admin) return res.status(403).json({ error: 'Hanya admin.' });
  next();
}
app.get('/api/admin/users', auth, admin, (req, res) => {
  const rows = db.prepare(`SELECT u.id, u.username, u.is_admin, u.created_at, u.last_login, length(u.vault) AS vault_size,
      (SELECT COALESCE(SUM(size), 0) FROM attachments a WHERE a.user_id = u.id) AS attach_size
    FROM users u ORDER BY u.created_at`).all();
  res.json(rows.map((r) => ({ ...r, is_admin: !!r.is_admin, me: r.id === req.userId })));
});
app.get('/api/admin/invites', auth, admin, (req, res) => {
  res.json(db.prepare('SELECT id, username, created_at, expires_at FROM invites WHERE used_at IS NULL AND expires_at > ? ORDER BY created_at DESC').all(now()));
});
app.post('/api/admin/invites', auth, admin, (req, res) => {
  const hours = Number(req.body?.hours);
  if (![24, 72, 168].includes(hours)) return res.status(400).json({ error: 'Masa berlaku tidak valid.' });
  let username = req.body?.username ? normUser(req.body.username) : null;
  if (username && !validUser(username)) return res.status(400).json({ error: 'Username 3–64 karakter: huruf kecil, angka, . _ @ + -' });
  if (username && db.prepare('SELECT 1 FROM users WHERE username = ?').get(username)) return res.status(409).json({ error: 'Username sudah dipakai.' });
  const code = crypto.randomBytes(18).toString('base64url');
  const exp = now() + hours * 3600000;
  db.prepare('INSERT INTO invites (code_hash, username, created_by, created_at, expires_at) VALUES (?,?,?,?,?)').run(sha256(code), username, req.userId, now(), exp);
  res.status(201).json({ code, username, expiresAt: exp });
});
app.delete('/api/admin/invites/:id', auth, admin, (req, res) => {
  db.prepare('DELETE FROM invites WHERE id = ? AND used_at IS NULL').run(Number(req.params.id) || 0);
  res.json({ ok: true });
});
app.post('/api/admin/users/:id/delete', auth, admin, (req, res) => {
  const id = Number(req.params.id) || 0;
  if (id === req.userId) return res.status(400).json({ error: 'Hapus akunmu sendiri lewat Pengaturan.' });
  const r = db.prepare('DELETE FROM users WHERE id = ?').run(id);
  res.json({ ok: !!r.changes });
});

app.post('/api/register', async (req, res) => {
  if (limited('reg:' + req.ip, 10, 60 * 60000)) return res.status(429).json({ error: 'Terlalu banyak pendaftaran dari alamat ini.' });
  const { kdfSalt, kdfIter, authKey, vault, signupCode, inviteCode } = req.body || {};
  const username = normUser(req.body?.username);
  if (!(await turnstileOk(req.body?.turnstile, req.ip))) return res.status(403).json(TS_FAIL);
  const invite = findInvite(inviteCode);
  if (inviteCode && !invite) return res.status(403).json({ error: 'Link undangan tidak berlaku (sudah dipakai atau kedaluwarsa).' });
  if (!invite && !signupAllowed(signupCode)) {
    return res.status(403).json({ error: SIGNUP_MODE === 'code' ? 'Kode pendaftaran salah.' : 'Pendaftaran akun baru ditutup di server ini.' });
  }
  if (invite?.username && invite.username !== username) {
    return res.status(400).json({ error: `Undangan ini khusus untuk username "${invite.username}".` });
  }
  if (!validUser(username)) return res.status(400).json({ error: 'Username 3–64 karakter: huruf kecil, angka, . _ @ + -' });
  if (!isB64(kdfSalt, 16, 64) || !Number.isInteger(kdfIter) || kdfIter < KDF_ITER_MIN || kdfIter > KDF_ITER_MAX
      || !isB64(authKey, 40, 48) || !validVault(vault)) {
    return res.status(400).json({ error: 'Data pendaftaran tidak valid.' });
  }
  if (db.prepare('SELECT 1 FROM users WHERE username = ?').get(username)) return res.status(409).json({ error: 'Username sudah dipakai.' });
  const authSalt = crypto.randomBytes(16);
  const authHash = await scrypt(Buffer.from(authKey, 'base64'), authSalt);
  const t = now();
  let info;
  try {
    info = db.transaction(() => {
      const first = db.prepare('SELECT COUNT(*) AS n FROM users').get().n === 0;
      const r = db.prepare(`INSERT INTO users (username, kdf_salt, kdf_iter, auth_salt, auth_hash, vault, rev, created_at, updated_at, last_login, is_admin)
        VALUES (?,?,?,?,?,?,1,?,?,?,?)`).run(username, kdfSalt, kdfIter, authSalt.toString('base64'), authHash.toString('base64'), JSON.stringify(vault), t, t, t, first ? 1 : 0);
      if (invite) {
        const u = db.prepare('UPDATE invites SET used_at = ?, used_by = ? WHERE id = ? AND used_at IS NULL').run(t, r.lastInsertRowid, invite.id);
        if (!u.changes) throw Object.assign(new Error('invite used'), { code: 'INVITE_USED' });
      }
      return r;
    })();
  } catch (e) {
    if (String(e.code).startsWith('SQLITE_CONSTRAINT')) return res.status(409).json({ error: 'Username sudah dipakai.' });
    if (e.code === 'INVITE_USED') return res.status(403).json({ error: 'Link undangan sudah dipakai.' });
    throw e;
  }
  setSession(req, res, info.lastInsertRowid, req.body?.wrapKey);
  res.status(201).json({ username, rev: 1, isAdmin: !!db.prepare('SELECT is_admin FROM users WHERE id = ?').get(info.lastInsertRowid).is_admin });
});

app.post('/api/login', async (req, res) => {
  const username = normUser(req.body?.username);
  if (limited('login-ip:' + req.ip, 20, 15 * 60000) || limited('login-u:' + username, 10, 15 * 60000)) {
    return res.status(429).json({ error: 'Terlalu banyak percobaan login. Tunggu 15 menit.' });
  }
  if (!(await turnstileOk(req.body?.turnstile, req.ip))) return res.status(403).json(TS_FAIL);
  const u = validUser(username) ? db.prepare('SELECT * FROM users WHERE username = ?').get(username) : null;
  let ok = false;
  if (u) ok = await verifyAuthKey(u, req.body?.authKey);
  else await scrypt(Buffer.from('x'), Buffer.alloc(16)); // samakan waktu respons
  if (!ok) return res.status(401).json({ error: 'Username atau password salah.' });
  db.prepare('UPDATE users SET last_login = ? WHERE id = ?').run(now(), u.id);
  setSession(req, res, u.id, req.body?.wrapKey);
  res.json({ username: u.username, vault: JSON.parse(u.vault), rev: u.rev, isAdmin: !!u.is_admin });
});

app.post('/api/logout', (req, res) => {
  const token = readCookie(req);
  if (token) db.prepare('DELETE FROM sessions WHERE token_hash = ?').run(sha256(token));
  res.clearCookie(COOKIE, { httpOnly: true, secure: COOKIE_SECURE, sameSite: 'strict', path: '/' });
  res.json({ ok: true });
});

app.get('/api/me', auth, (req, res) => {
  const u = db.prepare('SELECT username, rev, created_at FROM users WHERE id = ?').get(req.userId);
  res.json(u);
});

// pulihkan sesi setelah refresh: kunci pembungkus hanya keluar dengan cookie sesi yang valid
app.get('/api/session', auth, (req, res) => {
  const s = db.prepare(`SELECT u.username, u.is_admin, s.wrap_key FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.token_hash = ?`).get(req.tokenHash);
  res.json({ username: s.username, wrapKey: s.wrap_key, isAdmin: !!s.is_admin });
});

app.get('/api/vault', auth, (req, res) => {
  const u = db.prepare('SELECT vault, rev FROM users WHERE id = ?').get(req.userId);
  res.json({ vault: JSON.parse(u.vault), rev: u.rev });
});

app.put('/api/vault', auth, (req, res) => {
  const { vault, rev } = req.body || {};
  if (!validVault(vault) || !Number.isInteger(rev)) return res.status(400).json({ error: 'Vault tidak valid.' });
  const r = db.prepare('UPDATE users SET vault = ?, rev = rev + 1, updated_at = ? WHERE id = ? AND rev = ?')
    .run(JSON.stringify(vault), now(), req.userId, rev);
  if (!r.changes) {
    const cur = db.prepare('SELECT rev FROM users WHERE id = ?').get(req.userId);
    return res.status(409).json({ error: 'Vault diubah dari perangkat lain.', rev: cur.rev });
  }
  res.json({ rev: rev + 1 });
});

// ganti master password: klien mengenkripsi ulang vault dengan kunci baru
app.post('/api/account/password', auth, async (req, res) => {
  if (limited('chg:' + req.userId, 10, 15 * 60000)) return res.status(429).json({ error: 'Terlalu banyak percobaan.' });
  const { authKey, newKdfSalt, newKdfIter, newAuthKey, vault, rev } = req.body || {};
  const u = db.prepare('SELECT * FROM users WHERE id = ?').get(req.userId);
  if (!(await verifyAuthKey(u, authKey))) return res.status(401).json({ error: 'Master password lama salah.' });
  if (!isB64(newKdfSalt, 16, 64) || !Number.isInteger(newKdfIter) || newKdfIter < KDF_ITER_MIN || newKdfIter > KDF_ITER_MAX
      || !isB64(newAuthKey, 40, 48) || !validVault(vault) || !Number.isInteger(rev)) {
    return res.status(400).json({ error: 'Data tidak valid.' });
  }
  if (rev !== u.rev) return res.status(409).json({ error: 'Vault diubah dari perangkat lain. Muat ulang lalu coba lagi.', rev: u.rev });
  const authSalt = crypto.randomBytes(16);
  const authHash = await scrypt(Buffer.from(newAuthKey, 'base64'), authSalt);
  db.transaction(() => {
    db.prepare(`UPDATE users SET kdf_salt=?, kdf_iter=?, auth_salt=?, auth_hash=?, vault=?, rev=rev+1, updated_at=? WHERE id=?`)
      .run(newKdfSalt, newKdfIter, authSalt.toString('base64'), authHash.toString('base64'), JSON.stringify(vault), now(), u.id);
    db.prepare('DELETE FROM sessions WHERE user_id = ? AND token_hash != ?').run(u.id, req.tokenHash); // keluarkan perangkat lain
  })();
  res.json({ rev: u.rev + 1 });
});

app.post('/api/account/delete', auth, async (req, res) => {
  if (limited('del:' + req.userId, 5, 15 * 60000)) return res.status(429).json({ error: 'Terlalu banyak percobaan.' });
  const u = db.prepare('SELECT * FROM users WHERE id = ?').get(req.userId);
  if (!(await verifyAuthKey(u, req.body?.authKey))) return res.status(401).json({ error: 'Master password salah.' });
  db.prepare('DELETE FROM users WHERE id = ?').run(u.id);
  res.clearCookie(COOKIE, { httpOnly: true, secure: COOKIE_SECURE, sameSite: 'strict', path: '/' });
  res.json({ ok: true });
});

// ---------- lampiran ----------
const ATT_ID = /^[a-f0-9]{32}$/;
const usage = (uid) => db.prepare('SELECT COALESCE(SUM(size), 0) AS n FROM attachments WHERE user_id = ?').get(uid).n;

app.get('/api/attachments/usage', auth, (req, res) => {
  res.json({ used: usage(req.userId), quota: ATTACH_QUOTA, max: ATTACH_MAX });
});

app.post('/api/attachments', auth, express.raw({ type: 'application/octet-stream', limit: ATTACH_MAX + 1024 }), (req, res) => {
  const buf = req.body;
  if (!Buffer.isBuffer(buf) || buf.length < 16) return res.status(400).json({ error: 'File tidak valid.' });
  if (usage(req.userId) + buf.length > ATTACH_QUOTA) return res.status(413).json({ error: 'Kuota lampiran akun ini sudah penuh.' });
  const id = crypto.randomBytes(16).toString('hex');
  db.prepare('INSERT INTO attachments (id, user_id, size, created_at, data) VALUES (?,?,?,?,?)').run(id, req.userId, buf.length, now(), buf);
  res.status(201).json({ id, size: buf.length });
});

app.get('/api/attachments/:id', auth, (req, res) => {
  if (!ATT_ID.test(req.params.id)) return res.status(400).json({ error: 'ID tidak valid.' });
  const row = db.prepare('SELECT data FROM attachments WHERE id = ? AND user_id = ?').get(req.params.id, req.userId);
  if (!row) return res.status(404).json({ error: 'Lampiran tidak ditemukan.' });
  res.set('Content-Type', 'application/octet-stream');
  res.send(row.data);
});

// salin lampiran (untuk fitur Duplikat item)
app.post('/api/attachments/:id/copy', auth, (req, res) => {
  if (!ATT_ID.test(req.params.id)) return res.status(400).json({ error: 'ID tidak valid.' });
  const row = db.prepare('SELECT size FROM attachments WHERE id = ? AND user_id = ?').get(req.params.id, req.userId);
  if (!row) return res.status(404).json({ error: 'Lampiran tidak ditemukan.' });
  if (usage(req.userId) + row.size > ATTACH_QUOTA) return res.status(413).json({ error: 'Kuota lampiran akun ini sudah penuh.' });
  const id = crypto.randomBytes(16).toString('hex');
  db.prepare('INSERT INTO attachments (id, user_id, size, created_at, data) SELECT ?, user_id, size, ?, data FROM attachments WHERE id = ? AND user_id = ?')
    .run(id, now(), req.params.id, req.userId);
  res.status(201).json({ id });
});

app.delete('/api/attachments/:id', auth, (req, res) => {
  if (!ATT_ID.test(req.params.id)) return res.status(400).json({ error: 'ID tidak valid.' });
  db.prepare('DELETE FROM attachments WHERE id = ? AND user_id = ?').run(req.params.id, req.userId);
  res.json({ ok: true });
});

app.use('/api', (req, res) => res.status(404).json({ error: 'Tidak ditemukan.' }));

// file statis web app
app.use(express.static(path.join(__dirname, '..', 'public'), { index: 'index.html', maxAge: 0 }));

app.use((err, req, res, next) => {
  if (err.type === 'entity.too.large') return res.status(413).json({ error: 'Ukuran data melebihi batas server.' });
  if (err.type === 'entity.parse.failed') return res.status(400).json({ error: 'JSON tidak valid.' });
  console.error(err);
  res.status(500).json({ error: 'Kesalahan server.' });
});

app.listen(PORT, HOST, () => {
  console.log(`Brankas berjalan di http://${HOST}:${PORT}  (signup: ${SIGNUP_MODE}, cookie secure: ${COOKIE_SECURE}, turnstile: ${TURNSTILE ? 'aktif' : 'nonaktif'})`);
});
