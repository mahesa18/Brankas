#!/bin/sh
# Backup database Brankas (instalasi Docker). Aman dijalankan saat server berjalan (SQLite online backup).
# Dijalankan bulanan (tgl 1, 02.30 WIB) oleh brankas-backup.timer. Manual: sudo /opt/brankas/deploy/backup.sh
# Isi database: akun + vault & lampiran yang sudah terenkripsi. Tanpa master password, isinya tidak bisa dibaca.
set -eu

APP_DIR=/opt/brankas
DEST=/var/backups/brankas
KEEP_DAYS=190      # ±6 backup bulanan di VPS
CONTAINER=brankas
STAMP=$(date +%F_%H%M%S)
TMP_NAME=".backup-$STAMP.db"

umask 077
mkdir -p "$DEST"
chmod 700 "$DEST"

# 1. salinan konsisten dibuat di dalam container (folder /data = $APP_DIR/data)
docker exec "$CONTAINER" node -e '
const D = require("better-sqlite3");
const src = new D("/data/brankas.db", { readonly: true });
src.backup(process.argv[1]).then(() => {
  src.close();
  const bk = new D(process.argv[1]);
  bk.pragma("journal_mode = DELETE");           // satu file mandiri, tanpa -wal/-shm
  const chk = bk.pragma("integrity_check", { simple: true });
  bk.close();
  if (chk !== "ok") { console.error("integrity_check: " + chk); process.exit(2); }
}).catch((e) => { console.error(e.message); process.exit(1); });
' "/data/$TMP_NAME"

# 2. pindahkan keluar dari folder data, kunci untuk root, kompres
OUT="$DEST/brankas-$STAMP.db"
mv "$APP_DIR/data/$TMP_NAME" "$OUT"
rm -f "$APP_DIR/data/$TMP_NAME-wal" "$APP_DIR/data/$TMP_NAME-shm"
chown root:root "$OUT"
chmod 600 "$OUT"
gzip -9 "$OUT"

# 3. hapus backup lebih lama dari KEEP_DAYS hari
find "$DEST" -name 'brankas-*.db.gz' -mtime +"$KEEP_DAYS" -delete

echo "Backup OK: $OUT.gz ($(du -h "$OUT.gz" | cut -f1))"

# 4. salinan di luar VPS: Google Drive (rclone, konfigurasi khusus Brankas, izin drive.file)
RCLONE_CONF=/etc/brankas/rclone.conf
REMOTE="brankas-gdrive:Brankas-Backup"
REMOTE_KEEP=370d   # ±12 backup bulanan di Google Drive
if [ -f "$RCLONE_CONF" ]; then
  rclone --config "$RCLONE_CONF" copy "$OUT.gz" "$REMOTE" --retries 5 --low-level-retries 10
  rclone --config "$RCLONE_CONF" delete "$REMOTE" --min-age "$REMOTE_KEEP" --include "brankas-*.db.gz"
  echo "Diunggah ke Google Drive: $REMOTE/$(basename "$OUT.gz")"
else
  echo "Lewati unggah Google Drive: $RCLONE_CONF belum ada"
fi
