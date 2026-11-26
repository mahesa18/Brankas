'use strict';
// Alat admin: node server/cli.js list-users | delete-user <username> | logout-all <username>
const { db } = require('./db');
const [cmd, arg] = process.argv.slice(2);
const fmt = (t) => (t ? new Date(t).toISOString().replace('T', ' ').slice(0, 16) : '-');

if (cmd === 'list-users') {
  const rows = db.prepare('SELECT username, created_at, last_login, length(vault) AS size FROM users ORDER BY username').all();
  if (!rows.length) console.log('Belum ada akun.');
  for (const r of rows) console.log(`${r.username.padEnd(30)} dibuat ${fmt(r.created_at)}  login ${fmt(r.last_login)}  vault ${(r.size / 1024).toFixed(1)} KB`);
} else if (cmd === 'delete-user' && arg) {
  const r = db.prepare('DELETE FROM users WHERE username = ?').run(arg.toLowerCase());
  console.log(r.changes ? `Akun "${arg}" dihapus.` : `Akun "${arg}" tidak ditemukan.`);
} else if (cmd === 'make-admin' && arg) {
  const r = db.prepare('UPDATE users SET is_admin = 1 WHERE username = ?').run(arg.toLowerCase());
  console.log(r.changes ? `"${arg}" sekarang admin.` : 'Akun tidak ditemukan.');
} else if (cmd === 'logout-all' && arg) {
  const u = db.prepare('SELECT id FROM users WHERE username = ?').get(arg.toLowerCase());
  if (!u) { console.log('Akun tidak ditemukan.'); process.exit(1); }
  const r = db.prepare('DELETE FROM sessions WHERE user_id = ?').run(u.id);
  console.log(`${r.changes} sesi dihapus.`);
} else {
  console.log('Pemakaian:\n  npm run list-users\n  npm run delete-user -- <username>\n  node server/cli.js logout-all <username>');
  process.exit(1);
}
