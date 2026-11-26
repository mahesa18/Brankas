'use strict';
const path = require('path');
const fs = require('fs');
const Database = require('better-sqlite3');

const DB_PATH = path.resolve(process.env.DB_PATH || path.join(__dirname, '..', 'data', 'brankas.db'));
fs.mkdirSync(path.dirname(DB_PATH), { recursive: true });

const db = new Database(DB_PATH);
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');
db.pragma('busy_timeout = 5000');

db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  username    TEXT    NOT NULL UNIQUE,
  kdf_salt    TEXT    NOT NULL,           -- salt PBKDF2 di klien (base64)
  kdf_iter    INTEGER NOT NULL,
  auth_salt   TEXT    NOT NULL,           -- salt scrypt di server (base64)
  auth_hash   TEXT    NOT NULL,           -- scrypt(authKey dari klien)
  vault       TEXT    NOT NULL,           -- vault terenkripsi AES-GCM (JSON), tidak bisa dibaca server
  rev         INTEGER NOT NULL DEFAULT 1, -- versi vault untuk deteksi konflik
  created_at  INTEGER NOT NULL,
  updated_at  INTEGER NOT NULL,
  last_login  INTEGER
);
CREATE TABLE IF NOT EXISTS sessions (
  token_hash  TEXT    PRIMARY KEY,        -- sha256 token; token asli hanya ada di cookie
  user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  created_at  INTEGER NOT NULL,
  expires_at  INTEGER NOT NULL,
  ip          TEXT,
  ua          TEXT
);
CREATE INDEX IF NOT EXISTS sessions_user ON sessions(user_id);
CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v TEXT NOT NULL);
`);

// migrasi: kunci pembungkus sesi (agar vault tetap terbuka setelah refresh)
if (!db.prepare('PRAGMA table_info(sessions)').all().some((c) => c.name === 'wrap_key')) {
  db.exec('ALTER TABLE sessions ADD COLUMN wrap_key TEXT');
}

// lampiran terenkripsi (server hanya menyimpan ciphertext & ukurannya)
db.exec(`
CREATE TABLE IF NOT EXISTS attachments (
  id          TEXT    PRIMARY KEY,
  user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  size        INTEGER NOT NULL,
  created_at  INTEGER NOT NULL,
  data        BLOB    NOT NULL
);
CREATE INDEX IF NOT EXISTS attachments_user ON attachments(user_id);
`);

// admin: akun pertama otomatis admin
if (!db.prepare('PRAGMA table_info(users)').all().some((c) => c.name === 'is_admin')) {
  db.exec('ALTER TABLE users ADD COLUMN is_admin INTEGER NOT NULL DEFAULT 0');
}
if (!db.prepare('SELECT 1 FROM users WHERE is_admin = 1').get()) {
  db.prepare('UPDATE users SET is_admin = 1 WHERE id = (SELECT MIN(id) FROM users)').run();
}
// undangan untuk menambah user (kode asli hanya ada di link; server menyimpan hash-nya)
db.exec(`
CREATE TABLE IF NOT EXISTS invites (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  code_hash   TEXT    NOT NULL UNIQUE,
  username    TEXT,
  created_by  INTEGER REFERENCES users(id) ON DELETE SET NULL,
  created_at  INTEGER NOT NULL,
  expires_at  INTEGER NOT NULL,
  used_at     INTEGER,
  used_by     INTEGER REFERENCES users(id) ON DELETE SET NULL
);
`);

module.exports = { db, DB_PATH };
