# Brankas — Password Manager Self-hosted

Password manager untuk **login, kartu, identitas, catatan aman, SSH key, dan API key** yang berjalan di
server kamu sendiri. Semua isi vault dienkripsi di browser sebelum dikirim ke server (*zero-knowledge*).

**Fitur:** folder, favorit, arsip, lampiran terenkripsi, generator password 8–32 karakter,
impor/ekspor (backup terenkripsi, JSON, CSV), multi-user dengan undangan admin, sesi tetap aktif saat
refresh, verifikasi Cloudflare Turnstile, infografik ringkasan vault, dan tampilan responsif untuk HP.

---

## Daftar isi

1. [Keamanan](#keamanan-zero-knowledge)
2. [Struktur proyek](#struktur-proyek)
3. [Menjalankan di komputer sendiri](#menjalankan-di-komputer-sendiri)
4. [Deploy ke VPS dengan Docker (disarankan)](#deploy-ke-vps-dengan-docker-disarankan)
5. [Cloudflare Turnstile](#cloudflare-turnstile-opsional)
6. [Backup otomatis & Google Drive](#backup-otomatis--google-drive)
7. [Update aplikasi](#update-aplikasi)
8. [Admin & pengguna](#admin--pengguna)
9. [Pemulihan dari backup](#pemulihan-dari-backup)
10. [Troubleshooting](#troubleshooting)
11. [Alternatif: deploy tanpa Docker](#alternatif-deploy-tanpa-docker)
12. [Konfigurasi `.env`](#konfigurasi-env)
13. [API](#api)

---

## Keamanan (zero-knowledge)

```
master password ──PBKDF2-SHA256 (600.000x)──► masterKey ──HKDF──┬─► encKey  (tetap di browser, mengenkripsi vault AES-256-GCM)
                                                                └─► authKey (dikirim saat login, disimpan server sebagai hash scrypt)
```

- Server **tidak pernah** menerima master password atau isi vault. Database hanya berisi username, salt,
  hash scrypt dari `authKey`, dan vault yang sudah terenkripsi.
- Lampiran dienkripsi per file di browser dengan kunci acak; server hanya tahu ukurannya.
- Kalau database bocor, isinya tetap tidak bisa dibaca tanpa master password.
- Konsekuensinya: **master password tidak bisa direset**. Kalau lupa, isi vault akun itu hilang.
- Pengamanan lain: cookie sesi `HttpOnly` + `Secure` + `SameSite=Strict`, header anti-CSRF, CSP ketat,
  pembatasan percobaan login, respons seragam untuk username yang tidak ada, dan Turnstile (opsional).

## Struktur proyek

```
public/                    web app (HTML/CSS/JS, logo, halaman kebijakan privasi)
server/server.js           API + penyaji file statis (Express)
server/db.js               skema & migrasi SQLite (better-sqlite3)
server/cli.js              alat admin baris perintah
Dockerfile                 image produksi (Node 22, berjalan sebagai user biasa)
docker-compose.yml         container terisolasi: jaringan sendiri, read-only, port hanya 127.0.0.1
deploy/brankas.caddy       contoh konfigurasi Caddy (reverse proxy + HTTPS otomatis)
deploy/nginx.conf          contoh konfigurasi Nginx
deploy/backup.sh           skrip backup database (+ unggah ke Google Drive)
deploy/brankas-backup.*    systemd service & timer backup bulanan
deploy/brankas.service     systemd service (hanya untuk deploy tanpa Docker)
.env.example               contoh konfigurasi
```

## Menjalankan di komputer sendiri

Butuh Node.js 20.12+.

```bash
npm install
cp .env.example .env          # lalu ubah COOKIE_SECURE=false
npm start                     # buka http://localhost:3000
```

npm 11+ bisa memblokir skrip instalasi `better-sqlite3`. Kalau server gagal start, jalankan
`npm install-scripts approve better-sqlite3 && npm rebuild better-sqlite3`.

Aplikasi harus dibuka lewat server (`http://localhost:3000`), bukan dengan membuka `index.html` langsung.

---

## Deploy ke VPS dengan Docker (disarankan)

Brankas berjalan di container sendiri sehingga **tidak mengganggu aplikasi lain** di server yang sama:
jaringan Docker sendiri, user Linux sendiri, filesystem read-only, tanpa hak istimewa, memori dibatasi
512 MB, dan port hanya terbuka di `127.0.0.1` (diakses lewat reverse proxy, bukan langsung dari internet).

**Yang dibutuhkan**

- VPS Linux (contoh di bawah: Ubuntu 24.04) dengan akses root/sudo.
- Subdomain, misalnya `vault.domainmu.com`, dengan **A-record** ke IP VPS.
  Kalau memakai Cloudflare, set **DNS only** (awan abu-abu) setidaknya saat sertifikat pertama dibuat.
- Reverse proxy yang menangani HTTPS: **Caddy** (paling mudah) atau **Nginx**.

### 1. Pasang Docker

Lewati langkah ini kalau Docker sudah ada (`docker --version`).

```bash
sudo apt-get update && sudo apt-get install -y ca-certificates curl
sudo install -m 0755 -d /etc/apt/keyrings
sudo curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
sudo chmod a+r /etc/apt/keyrings/docker.asc
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo $VERSION_CODENAME) stable" \
  | sudo tee /etc/apt/sources.list.d/docker.list >/dev/null
sudo apt-get update
sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
sudo systemctl enable --now docker
```

### 2. Ambil kode & buat user khusus

```bash
sudo git clone https://github.com/mahesa18/Brankas.git /opt/brankas
cd /opt/brankas

# user sistem khusus untuk container (tanpa login shell)
sudo useradd --system --no-create-home --home-dir /opt/brankas --shell /usr/sbin/nologin brankas

# folder data: hanya bisa dibaca user brankas
sudo mkdir -p data
sudo chown brankas:brankas data && sudo chmod 700 data
```

> Jangan memakai UID 1000 untuk container: di banyak VPS UID itu milik user lain/aplikasi lain.
> Karena itu container dijalankan sebagai user `brankas` (lihat `BRANKAS_UID` di langkah 3).

### 3. Konfigurasi `.env`

```bash
sudo cp .env.example .env
sudo chmod 600 .env
# isi UID/GID user brankas agar container berjalan sebagai user tersebut
printf "\nBRANKAS_UID=%s\nBRANKAS_GID=%s\n" "$(id -u brankas)" "$(id -g brankas)" | sudo tee -a .env >/dev/null
sudo nano .env
```

Yang wajib diperhatikan di `.env`:

| Variabel | Nilai untuk produksi |
|---|---|
| `COOKIE_SECURE` | `true` (wajib HTTPS) |
| `SIGNUP_MODE` | `first`: akun pertama menjadi admin, lalu pendaftaran tertutup otomatis |
| `TURNSTILE_SITE_KEY` / `TURNSTILE_SECRET_KEY` | opsional, lihat [Cloudflare Turnstile](#cloudflare-turnstile-opsional) |
| `BRANKAS_UID` / `BRANKAS_GID` | sudah terisi dari perintah di atas |

`HOST`, `PORT`, `DB_PATH`, dan `TRUST_PROXY` diatur otomatis oleh `docker-compose.yml`; tidak perlu diubah.
Port di host bisa diganti lewat variabel `BRANKAS_PORT` (bawaan `3100`).

### 4. Jalankan container

```bash
cd /opt/brankas
sudo docker compose up -d --build
sudo docker ps --filter name=brankas          # tunggu sampai status "(healthy)"
curl -s http://127.0.0.1:3100/api/config      # harus membalas JSON
```

### 5. Reverse proxy + HTTPS

**Caddy** (sertifikat HTTPS dibuat & diperpanjang otomatis):

```bash
sudo mkdir -p /etc/caddy/sites
sudo cp deploy/brankas.caddy /etc/caddy/sites/brankas.caddy
sudo nano /etc/caddy/sites/brankas.caddy      # ganti nama domain dengan domainmu
```

Pastikan `/etc/caddy/Caddyfile` memuat file di folder itu (tambahkan satu baris bila belum ada):

```
import /etc/caddy/sites/*.caddy
```

Lalu validasi dan **reload** (bukan restart, agar situs lain tidak terputus):

```bash
sudo caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile
sudo systemctl reload caddy
```

Isi minimal blok Caddy untuk Brankas:

```
vault.domainmu.com {
	encode zstd gzip
	request_body {
		max_size 30MB
	}
	header {
		-Server
		-Via
		defer
	}
	reverse_proxy 127.0.0.1:3100
}
```

**Nginx:** pakai `deploy/nginx.conf`, ganti `vault.domainanda.com` dengan domainmu dan ubah
`proxy_pass http://127.0.0.1:3000;` menjadi `proxy_pass http://127.0.0.1:3100;`, lalu buat sertifikat
dengan `sudo certbot --nginx -d vault.domainmu.com` dan `sudo nginx -t && sudo systemctl reload nginx`.

### 6. Firewall

Cukup buka SSH, HTTP, dan HTTPS. Port `3100` **tidak perlu** dibuka karena hanya terikat ke `127.0.0.1`.

```bash
sudo ufw allow OpenSSH && sudo ufw allow 80/tcp && sudo ufw allow 443/tcp && sudo ufw enable
```

### 7. Buat akun admin

Buka `https://vault.domainmu.com` **segera**, klik **Daftar**, dan buat akun pertama. Akun pertama otomatis
menjadi **admin**, dan setelah itu pendaftaran tertutup sendiri (`SIGNUP_MODE=first`).
User lain ditambahkan lewat undangan (lihat [Admin & pengguna](#admin--pengguna)).

Cek akhir:

```bash
curl -sI https://vault.domainmu.com | head -1          # HTTP 200
curl -s -o /dev/null -w "%{http_code}\n" http://IP-VPS:3100/ || echo "port 3100 tertutup dari luar (benar)"
```

---

## Cloudflare Turnstile (opsional)

Menambahkan verifikasi "bukan robot" di halaman **Masuk** dan **Daftar**. Server memeriksa token ke Cloudflare
sebelum memproses login, sehingga bot dan tebakan password otomatis ditolak.

1. Buka **dash.cloudflare.com → Turnstile → Add widget**. Isi hostname = domain Brankas, mode **Managed**.
   Domain tidak harus dikelola di Cloudflare.
2. Isi kunci di `/opt/brankas/.env` (jangan bagikan Secret Key):
   ```
   TURNSTILE_SITE_KEY=0x4AAAA...
   TURNSTILE_SECRET_KEY=0x4AAAA...
   ```
3. Terapkan: `sudo docker compose up -d`. Log harus menampilkan `turnstile: aktif`:
   `sudo docker logs brankas | tail -1`.

Untuk menonaktifkan, kosongkan kedua baris lalu jalankan `sudo docker compose up -d` lagi.
Selama Turnstile aktif, login bergantung pada ketersediaan layanan Cloudflare.

---

## Backup otomatis & Google Drive

`deploy/backup.sh` membuat salinan database yang konsisten **tanpa menghentikan** container (backup online
SQLite), memeriksa integritasnya, mengompresnya ke `/var/backups/brankas/` (hanya root), lalu, bila
dikonfigurasi, mengunggahnya ke Google Drive. Jadwal bawaan: **tanggal 1 setiap bulan pukul 02.30 WIB**.
Masa simpan: ±6 bulan di VPS dan ±12 bulan di Google Drive (ubah `KEEP_DAYS` / `REMOTE_KEEP` di skrip).

### Pasang timer backup

```bash
sudo chmod 700 /opt/brankas/deploy/backup.sh
sudo cp /opt/brankas/deploy/brankas-backup.service /opt/brankas/deploy/brankas-backup.timer /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now brankas-backup.timer
sudo systemctl start brankas-backup.service          # uji sekarang
sudo journalctl -u brankas-backup.service -n 5       # harus ada "Backup OK"
sudo ls -la /var/backups/brankas
systemctl list-timers brankas-backup.timer           # jadwal berikutnya
```

### Salinan ke Google Drive (disarankan)

Backup hanya di VPS ikut hilang kalau VPS rusak. Brankas memakai **rclone** dengan izin minimal
`drive.file` (hanya bisa mengakses file yang dibuatnya sendiri) dan file konfigurasi terpisah
`/etc/brankas/rclone.conf`, sehingga tidak mengganggu konfigurasi rclone aplikasi lain.

**a. Buat Client ID Google sendiri.** Client bawaan rclone sedang dihentikan, jadi langkah ini perlu.

1. **console.cloud.google.com** → buat project baru, misalnya `Brankas Backup`.
2. **APIs & Services → Library → Google Drive API → Enable**.
3. **Google Auth Platform / OAuth consent screen → Get started**: App name, support email, **External**,
   contact email. Jangan upload logo (agar tidak perlu verifikasi). Bila tombol Publish tidak aktif, isi
   *Application home page* (`https://vault.domainmu.com`), *Privacy policy* (`https://vault.domainmu.com/privasi.html`),
   dan *Authorised domain*.
4. **Audience → Publish app**. Status harus **In production**; status *Testing* membuat izin kedaluwarsa tiap 7 hari.
5. **Clients → Create client → Desktop app** → catat **Client ID** dan **Client secret**.

**b. Login Google sekali (di komputer yang punya browser), lalu kirim konfigurasinya ke VPS:**

```bash
# di laptop (rclone terpasang), hasilkan konfigurasi tanpa menampilkan token
rclone config create brankas-gdrive drive scope=drive.file \
  client_id="ID.apps.googleusercontent.com" client_secret="GOCSPX-..." --config ./brankas-rclone.conf

# kirim ke VPS lalu hapus salinan lokal
ssh root@IP-VPS 'install -d -m 700 /etc/brankas && cat > /etc/brankas/rclone.conf && chmod 600 /etc/brankas/rclone.conf' < ./brankas-rclone.conf
rm ./brankas-rclone.conf
```

**c. Pasang rclone di VPS & uji:**

```bash
sudo apt-get install -y rclone      # atau: curl https://rclone.org/install.sh | sudo bash
sudo rclone --config /etc/brankas/rclone.conf mkdir brankas-gdrive:Brankas-Backup
sudo systemctl start brankas-backup.service
sudo journalctl -u brankas-backup.service -n 5      # harus ada "Diunggah ke Google Drive"
```

Selain backup server, setiap pengguna bisa mengunduh **backup terenkripsi** vault-nya sendiri dari menu
**Impor & Ekspor**.

---

## Update aplikasi

```bash
cd /opt/brankas
sudo git pull                          # .env dan data/ tidak ikut berubah (diabaikan git)
sudo docker compose up -d --build      # build ulang & ganti container (downtime beberapa detik)
sudo docker ps --filter name=brankas   # tunggu "(healthy)"
sudo docker image prune -f             # bersihkan image lama
```

Migrasi database berjalan otomatis saat container start. Setelah update, pengguna cukup me-refresh
browser; file JS/CSS diberi nomor versi sehingga tidak tertahan cache.

Kalau `backup.sh`, service, atau timer berubah, salin ulang ke `/etc/systemd/system/` lalu
`sudo systemctl daemon-reload`. Kalau konfigurasi Caddy berubah, `caddy validate` lalu `systemctl reload caddy`.

---

## Admin & pengguna

Akun pertama otomatis menjadi **admin**. Admin melihat menu **Pengguna** dan pilihan **+ Tambah → Tambah user**.

- **Tambah user lewat undangan.** Admin membuat link undangan sekali pakai (berlaku 24 jam, 3 hari, atau 7 hari,
  bisa dikunci ke username tertentu). User baru membuka link itu dan membuat master password sendiri;
  admin tidak pernah tahu password-nya dan tidak bisa melihat isi vault-nya.
  Buat undangan dari domain produksi, karena link memakai alamat yang sedang dibuka.
- Undangan bisa dibatalkan, dan admin bisa menghapus user dari halaman **Pengguna**.
- Alternatif tanpa undangan: `SIGNUP_MODE=code` + `SIGNUP_CODE=<kode-acak-panjang>` di `.env`,
  `sudo docker compose up -d`, bagikan kodenya, lalu kembalikan ke `closed`.

Perintah admin dari server:

```bash
cd /opt/brankas
sudo docker exec brankas node server/cli.js list-users
sudo docker exec brankas node server/cli.js make-admin <username>
sudo docker exec brankas node server/cli.js logout-all <username>
sudo docker exec brankas node server/cli.js delete-user <username>
```

---

## Pemulihan dari backup

```bash
cd /opt/brankas
sudo docker compose stop
sudo ls /var/backups/brankas                           # pilih file backup
sudo sh -c 'gunzip -c /var/backups/brankas/brankas-YYYY-MM-DD_HHMMSS.db.gz > data/brankas.db'
sudo rm -f data/brankas.db-wal data/brankas.db-shm
sudo chown brankas:brankas data/brankas.db
sudo docker compose start
```

Dari Google Drive: unduh file `.db.gz` dari folder **Brankas-Backup**
(`sudo rclone --config /etc/brankas/rclone.conf copy brankas-gdrive:Brankas-Backup/<file> /tmp/`), lalu ikuti langkah di atas.

---

## Troubleshooting

| Gejala | Pemeriksaan / solusi |
|---|---|
| Container tidak `healthy` | `sudo docker logs brankas --tail 50`. Biasanya `.env` salah format (baris tanpa `=`) atau izin folder `data/`. |
| `docker compose` error membaca `.env` | Setiap baris harus `NAMA=nilai` atau diawali `#`, tanpa spasi di sekitar `=`. |
| Error izin di `data/` | `sudo chown -R brankas:brankas /opt/brankas/data && sudo chmod 700 /opt/brankas/data` |
| Situs 502 dari Caddy/Nginx | Cek container berjalan dan `curl http://127.0.0.1:3100/api/config`. Pastikan proxy mengarah ke port `3100`. |
| Sertifikat HTTPS gagal | DNS harus sudah mengarah ke VPS; untuk Cloudflare set **DNS only**. Cek `journalctl -u caddy -n 50`. |
| Login selalu "Verifikasi keamanan gagal" | Hostname widget Turnstile harus sama dengan domain; cek Site/Secret Key di `.env`. |
| Backup tidak terunggah ke Drive | `journalctl -u brankas-backup.service -n 20`. Status Google app harus **In production**. |
| Tampilan lama setelah update | Refresh paksa browser (Ctrl+F5). |
| Lupa master password | Tidak bisa dipulihkan (enkripsi end-to-end). Admin bisa menghapus akun agar user mendaftar ulang lewat undangan. |

---

## Alternatif: deploy tanpa Docker

Untuk VPS yang tidak memakai Docker: Node.js 22 + systemd + Nginx.

```bash
# Node.js 22 & paket
sudo apt update && sudo apt install -y nginx certbot python3-certbot-nginx build-essential git
curl -fsSL https://deb.nodesource.com/setup_22.x | sudo -E bash - && sudo apt install -y nodejs

# kode & user
sudo useradd --system --home /opt/brankas --shell /usr/sbin/nologin brankas
sudo git clone https://github.com/mahesa18/Brankas.git /opt/brankas
cd /opt/brankas && sudo chown -R brankas:brankas /opt/brankas
sudo -u brankas npm ci --omit=dev
sudo -u brankas mkdir -p data
sudo -u brankas cp .env.example .env && sudo chmod 600 .env && sudo nano .env   # COOKIE_SECURE=true

# service
sudo cp deploy/brankas.service /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now brankas

# Nginx + HTTPS (proxy ke port 3000)
sudo cp deploy/nginx.conf /etc/nginx/sites-available/brankas
sudo sed -i 's/vault.domainanda.com/DOMAIN-KAMU/g' /etc/nginx/sites-available/brankas
sudo ln -s /etc/nginx/sites-available/brankas /etc/nginx/sites-enabled/
sudo certbot --nginx -d DOMAIN-KAMU && sudo nginx -t && sudo systemctl reload nginx
```

Perintah admin tanpa Docker: `cd /opt/brankas && sudo -u brankas node server/cli.js list-users`.
`deploy/backup.sh` ditulis untuk instalasi Docker (memakai `docker exec`); tanpa Docker, sesuaikan
langkah pertamanya agar menjalankan `node` langsung di `/opt/brankas`.

---

## Konfigurasi `.env`

| Variabel | Default | Keterangan |
|---|---|---|
| `HOST` | `127.0.0.1` | Alamat dengar server (Docker: diatur `docker-compose.yml`) |
| `PORT` | `3000` | Port server di dalam container / proses |
| `BRANKAS_PORT` | `3100` | Port di host untuk container (hanya `127.0.0.1`) |
| `DB_PATH` | `./data/brankas.db` | File database SQLite (Docker: `/data/brankas.db`) |
| `SIGNUP_MODE` | `first` | `first` / `code` / `open` / `closed` |
| `SIGNUP_CODE` | – | Wajib (min. 8 karakter) bila `SIGNUP_MODE=code` |
| `ATTACH_MAX_MB` | `25` | Ukuran maksimal per lampiran (samakan dengan batas upload reverse proxy) |
| `ATTACH_QUOTA_MB` | `500` | Kuota total lampiran per akun |
| `SESSION_HOURS` | `12` | Lama sesi login |
| `COOKIE_SECURE` | `true` | `false` hanya untuk uji lewat `http://` |
| `TRUST_PROXY` | `loopback` | Proxy tepercaya untuk IP klien (Docker: `loopback,uniquelocal`) |
| `TURNSTILE_SITE_KEY` | – | Site Key Cloudflare Turnstile (kosong = nonaktif) |
| `TURNSTILE_SECRET_KEY` | – | Secret Key Cloudflare Turnstile |
| `BRANKAS_UID` / `BRANKAS_GID` | `10001` | User host yang menjalankan container |

## API

| Metode | Path | Keterangan |
|---|---|---|
| GET | `/api/config` | Status pendaftaran, batas lampiran, site key Turnstile |
| POST | `/api/prelogin` | Ambil salt & iterasi KDF untuk username |
| POST | `/api/register` | Buat akun + vault awal terenkripsi (opsional `inviteCode`, `turnstile`) |
| POST | `/api/login` | Login dengan `authKey` (+ `turnstile`), mengembalikan vault terenkripsi |
| POST | `/api/logout` | Akhiri sesi |
| GET | `/api/session` | Pulihkan sesi setelah refresh (kunci pembungkus sesi) |
| GET/PUT | `/api/vault` | Ambil / simpan vault (PUT memakai `rev` untuk deteksi konflik) |
| POST | `/api/account/password` | Ganti master password (vault dienkripsi ulang di klien) |
| POST | `/api/account/delete` | Hapus akun |
| POST | `/api/attachments` | Unggah lampiran terenkripsi (`application/octet-stream`) |
| GET/DELETE | `/api/attachments/:id` | Unduh / hapus lampiran |
| POST | `/api/attachments/:id/copy` | Salin lampiran (untuk Duplikat item) |
| GET | `/api/attachments/usage` | Pemakaian & kuota lampiran |
| POST | `/api/invite/check` | Cek link undangan |
| GET | `/api/admin/users` | Daftar user (admin) |
| GET/POST | `/api/admin/invites` | Daftar / buat undangan (admin) |
| DELETE | `/api/admin/invites/:id` | Batalkan undangan (admin) |
| POST | `/api/admin/users/:id/delete` | Hapus user (admin) |

Semua permintaan non-GET wajib membawa header `X-Brankas: 1` dan berupa JSON
(kecuali unggah lampiran dan `DELETE`).

## Lisensi & privasi

Kebijakan privasi layanan tersedia di `/privasi.html` pada instalasi Brankas.
