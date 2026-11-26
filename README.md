# Brankas — Password Manager Self-hosted

Password manager untuk login, kartu, identitas, catatan aman, SSH key, dan API key.
Server dan databasenya berjalan di VPS kamu sendiri.

## Keamanan (zero-knowledge)

```
master password ──PBKDF2-SHA256 (600.000x)──► masterKey ──HKDF──┬─► encKey  (tetap di browser, mengenkripsi vault AES-256-GCM)
                                                                └─► authKey (dikirim saat login, disimpan server sebagai scrypt hash)
```

- Server **tidak pernah** menerima master password atau isi vault. Yang tersimpan di database hanya
  username, salt, hash scrypt dari `authKey`, dan vault yang sudah terenkripsi.
- Kalau database bocor, isinya tetap tidak bisa dibaca tanpa master password.
- Lampiran dienkripsi per file di browser (kunci acak per file, tersimpan di dalam vault). Server hanya tahu ukurannya.
- Akibatnya: **master password tidak bisa direset**. Kalau lupa, vault akun itu hilang.
- Pengamanan lain: sesi cookie `HttpOnly` + `Secure` + `SameSite=Strict`, header CSRF, CSP ketat,
  pembatasan percobaan login, dan respons yang sama untuk username yang tidak ada.

## Struktur

```
public/          web app (HTML/CSS/JS) — dilayani oleh server
server/server.js API + penyaji file statis (Express)
server/db.js     skema SQLite (better-sqlite3)
server/cli.js    alat admin (daftar/hapus akun)
deploy/          systemd service, konfigurasi Nginx, skrip backup
.env.example     contoh konfigurasi
```

## Menjalankan di komputer sendiri (uji coba)

```bash
npm install
cp .env.example .env          # lalu ubah COOKIE_SECURE=false
npm start                     # buka http://localhost:3000
```

npm 11+ bisa memblokir skrip instalasi `better-sqlite3`. Kalau server gagal start, jalankan:
`npm install-scripts approve better-sqlite3 && npm rebuild better-sqlite3`.

## Deploy ke VPS (Ubuntu/Debian)

Butuh: VPS, domain/subdomain (mis. `vault.domainanda.com`) yang A-record-nya mengarah ke IP VPS.

```bash
# 1. Paket dasar + Node.js 22
sudo apt update && sudo apt install -y nginx certbot python3-certbot-nginx build-essential
curl -fsSL https://deb.nodesource.com/setup_22.x | sudo -E bash -
sudo apt install -y nodejs

# 2. User khusus + kode aplikasi
sudo useradd --system --home /opt/brankas --shell /usr/sbin/nologin brankas
sudo mkdir -p /opt/brankas
# salin isi folder proyek ini ke /opt/brankas (scp / rsync / git clone), TANPA node_modules dan data
sudo chown -R brankas:brankas /opt/brankas
cd /opt/brankas
sudo -u brankas npm ci --omit=dev     # (npm 11: approve better-sqlite3 seperti di atas bila perlu)
sudo -u brankas mkdir -p data

# 3. Konfigurasi
sudo -u brankas cp .env.example .env
sudo -u brankas nano .env             # COOKIE_SECURE=true, atur SIGNUP_MODE
sudo chmod 600 .env

# 4. Service
sudo cp deploy/brankas.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now brankas
sudo systemctl status brankas         # harus "active (running)"

# 5. Nginx + HTTPS
sudo cp deploy/nginx.conf /etc/nginx/sites-available/brankas
sudo sed -i 's/vault.domainanda.com/DOMAIN-KAMU/g' /etc/nginx/sites-available/brankas
sudo ln -s /etc/nginx/sites-available/brankas /etc/nginx/sites-enabled/
# sertifikat pertama: sementara komentari blok server 443, lalu:
sudo certbot --nginx -d DOMAIN-KAMU
sudo nginx -t && sudo systemctl reload nginx

# 6. Firewall
sudo ufw allow OpenSSH && sudo ufw allow 'Nginx Full' && sudo ufw enable
```

Buka `https://DOMAIN-KAMU`, klik **Daftar**, dan buat akun pertama.
Dengan `SIGNUP_MODE=first` (bawaan), pendaftaran otomatis tertutup setelah akun pertama dibuat.

### Menambah akun untuk orang lain

Cara utama: masuk sebagai **admin** (akun pertama otomatis admin), lalu **+ Tambah → Tambah user** atau menu **Pengguna**. Aplikasi membuat link undangan sekali pakai (berlaku 24 jam–7 hari, bisa dikunci ke username tertentu). User baru membuka link itu dan membuat master password sendiri; admin tidak pernah tahu password-nya dan tidak bisa melihat isi vault-nya. Undangan bisa dibatalkan, dan admin bisa menghapus user dari halaman Pengguna. Admin tambahan: `node server/cli.js make-admin <username>`.

Alternatif tanpa undangan: 
Ubah `.env` menjadi `SIGNUP_MODE=code` dan `SIGNUP_CODE=<kode-acak-panjang>`, lalu
`sudo systemctl restart brankas`. Bagikan kodenya. Setelah semua orang mendaftar, kembalikan ke `closed`.

### Admin

```bash
cd /opt/brankas
sudo -u brankas npm run list-users
sudo -u brankas npm run delete-user -- namauser
sudo -u brankas node server/cli.js logout-all namauser
```

### Backup database

Instalasi Docker memakai systemd timer (tanggal 1 setiap bulan, 02.30 WIB), lalu salinannya diunggah ke Google Drive (rclone, /etc/brankas/rclone.conf, izin drive.file):

```bash
sudo cp /opt/brankas/deploy/brankas-backup.{service,timer} /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now brankas-backup.timer
sudo systemctl start brankas-backup.service      # jalankan sekarang (uji)
sudo ls -la /var/backups/brankas                 # brankas-YYYY-MM-DD_HHMMSS.db.gz, disimpan ±6 bulan (Drive ±12 bulan)
```

Pemulihan: hentikan container (`docker compose stop`), `gunzip -c <file>.db.gz > /opt/brankas/data/brankas.db`,
hapus `brankas.db-wal`/`-shm` lama, `chown brankas:brankas` file itu, lalu `docker compose start`.
Simpan juga salinan di luar VPS. Selain itu, tiap pengguna bisa mengekspor backup terenkripsi
sendiri dari menu **Impor & Ekspor**.

### Update aplikasi

Salin versi baru ke `/opt/brankas` (jangan timpa `.env` dan `data/`), lalu
`sudo -u brankas npm ci --omit=dev && sudo systemctl restart brankas`.

## Konfigurasi (`.env`)

| Variabel | Default | Keterangan |
|---|---|---|
| `HOST` | `127.0.0.1` | Alamat dengar server Node |
| `PORT` | `3000` | Port server Node |
| `DB_PATH` | `./data/brankas.db` | File database SQLite |
| `SIGNUP_MODE` | `first` | `first` / `code` / `open` / `closed` |
| `SIGNUP_CODE` | – | Wajib (min. 8 karakter) bila `SIGNUP_MODE=code` |
| `ATTACH_MAX_MB` | `25` | Ukuran maksimal per lampiran (samakan dengan `client_max_body_size` Nginx) |
| `ATTACH_QUOTA_MB` | `500` | Kuota total lampiran per akun |
| `SESSION_HOURS` | `12` | Lama sesi login |
| `COOKIE_SECURE` | `true` | `false` hanya untuk uji lewat http:// |
| `TRUST_PROXY` | `loopback` | Proxy tepercaya untuk IP klien |

## API

| Metode | Path | Keterangan |
|---|---|---|
| GET | `/api/config` | Status pendaftaran |
| POST | `/api/prelogin` | Ambil salt & iterasi KDF untuk username |
| POST | `/api/register` | Buat akun + vault awal terenkripsi |
| POST | `/api/login` | Login dengan `authKey`, mengembalikan vault terenkripsi |
| POST | `/api/logout` | Akhiri sesi |
| GET/PUT | `/api/vault` | Ambil / simpan vault (PUT memakai `rev` untuk deteksi konflik) |
| POST | `/api/account/password` | Ganti master password (vault dienkripsi ulang di klien) |
| POST | `/api/account/delete` | Hapus akun |
| GET | `/api/session` | Pulihkan sesi setelah refresh (kunci pembungkus sesi) |
| POST | `/api/attachments` | Unggah lampiran terenkripsi (`application/octet-stream`) |
| GET/DELETE | `/api/attachments/:id` | Unduh / hapus lampiran |
| POST | `/api/attachments/:id/copy` | Salin lampiran (untuk Duplikat item) |
| GET | `/api/attachments/usage` | Pemakaian & kuota lampiran |

Semua permintaan non-GET wajib berupa JSON dan membawa header `X-Brankas: 1`.
