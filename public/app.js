/* Brankas — password manager self-hosted.
 * Semua data dienkripsi di browser: PBKDF2-SHA256 (310k iterasi) -> AES-256-GCM.
 * Mode akun (server self-hosted): masterKey -> HKDF -> encKey (tetap di browser) + authKey (untuk login).
 * Server hanya menyimpan vault terenkripsi; master password & isi vault tidak pernah dikirim.
 * Struktur data v2: { v:2, folders:[{id,name}], items:[{id,type,name,folder,fav,created,updated,...field}] }
 */
(() => {
  'use strict';

  const LEGACY_KEY = 'kunci.vault';   // vault lokal dari versi tanpa akun
  const SETTINGS_KEY = 'brankas.settings';
  const ITER = 600000;                 // PBKDF2-SHA256 untuk akun baru
  const enc = new TextEncoder();
  const dec = new TextDecoder();
  const $ = (s) => document.querySelector(s);

  // ---------- state ----------
  let cryptoKey = null, salt = null, data = null;
  let username = null, rev = 0, kdfIter = ITER;
  let attachMax = 25 * 1048576;  // diperbarui dari /api/config
  let isAdmin = false;
  // Cloudflare Turnstile
  let tsSiteKey = null, tsWidget = null, tsToken = null;
  function loadTurnstile() {
    if (!tsSiteKey || tsWidget !== null) return;
    const box = $('#ts-box'); box.hidden = false;
    window.__brankasTs = () => {
      tsWidget = window.turnstile.render(box, {
        sitekey: tsSiteKey, theme: 'dark', size: 'flexible', language: 'id', action: 'login',
        callback: (t) => { tsToken = t; $('#lock-err').textContent = ''; },
        'expired-callback': () => { tsToken = null; },
        'error-callback': () => { tsToken = null; $('#lock-err').textContent = 'Verifikasi keamanan gagal dimuat. Muat ulang halaman.'; },
      });
    };
    document.head.append(h('script', { src: 'https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit&onload=__brankasTs', async: true, defer: true }));
  }
  function resetTurnstile() { tsToken = null; if (tsWidget !== null && window.turnstile) window.turnstile.reset(tsWidget); }
  const selected = new Set();   // item terpilih di daftar Semua item
  let invite = null;             // { code, username } saat membuka link undangan
  let view = 'items';          // items | generator | transfer | settings
  let filter = 'all';          // all | fav | type:<t> | folder:<id>
  let sel = null;
  let showDetail = false;     // layar HP: tampilkan detail, bukan daftar
  const revealed = new Set();  // field keys yang sedang ditampilkan di detail
  let lastActive = Date.now();

  // migrasi penyimpanan dari nama lama (Kunci -> Brankas)
  for (const k of ['settings', 'lastUser']) {
    const old = localStorage.getItem('kunci.' + k);
    if (old !== null && localStorage.getItem('brankas.' + k) === null) localStorage.setItem('brankas.' + k, old);
    localStorage.removeItem('kunci.' + k);
  }
  const settings = Object.assign(
    { autolock: 5, clipclear: true, gen: { len: 20, upper: true, lower: true, digit: true, sym: true, simple: false } },
    safeParse(localStorage.getItem(SETTINGS_KEY)) || {}
  );
  function saveSettings() { localStorage.setItem(SETTINGS_KEY, JSON.stringify(settings)); }
  function safeParse(s) { try { return s ? JSON.parse(s) : null; } catch { return null; } }

  // ---------- crypto ----------
  const b64 = (buf) => { let s = ''; new Uint8Array(buf).forEach((b) => { s += String.fromCharCode(b); }); return btoa(s); };
  const unb64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));

  async function pbkdf2Bits(password, saltBytes, iter) {
    const base = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveBits']);
    return crypto.subtle.deriveBits({ name: 'PBKDF2', salt: saltBytes, iterations: iter, hash: 'SHA-256' }, base, 256);
  }
  // masterKey -> HKDF -> encKey (tidak pernah keluar dari browser) + authKey (dikirim ke server untuk login)
  async function deriveKeys(password, saltBytes, iter) {
    const master = await crypto.subtle.importKey('raw', await pbkdf2Bits(password, saltBytes, iter), 'HKDF', false, ['deriveKey', 'deriveBits']);
    // label HKDF bawaan nama lama "Kunci" — JANGAN diubah, akun yang sudah ada bergantung padanya
    const hk = (info) => ({ name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(32), info: enc.encode(info) });
    const encKey = await crypto.subtle.deriveKey(hk('kunci-enc-v2'), master, { name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']);
    const authKey = b64(await crypto.subtle.deriveBits(hk('kunci-auth-v2'), master, 256));
    return { encKey, authKey };
  }
  async function legacyKey(password, saltBytes, iter) { // format v1 (vault lokal lama)
    const base = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveKey']);
    return crypto.subtle.deriveKey({ name: 'PBKDF2', salt: saltBytes, iterations: iter, hash: 'SHA-256' }, base, { name: 'AES-GCM', length: 256 }, false, ['decrypt']);
  }
  async function seal(key, obj) {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, enc.encode(JSON.stringify(obj)));
    return { v: 2, iv: b64(iv), ct: b64(ct) };
  }
  async function unseal(key, box) {
    const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: unb64(box.iv) }, key, unb64(box.ct));
    return JSON.parse(dec.decode(pt));
  }
  // file backup mandiri: cukup master password untuk membukanya (v1 lokal lama & v2 akun)
  async function decryptBlob(password, blob) {
    const s2 = unb64(blob.salt), iter = blob.iter || 310000;
    const key = blob.v === 2 ? (await deriveKeys(password, s2, iter)).encKey : await legacyKey(password, s2, iter);
    return { obj: await unseal(key, blob) };
  }
  const isEncBlob = (b) => b && typeof b.salt === 'string' && typeof b.iv === 'string' && typeof b.ct === 'string';

  // ---------- server API ----------
  async function api(method, url, body) {
    const headers = { 'X-Brankas': '1' };
    if (body) headers['Content-Type'] = 'application/json';
    let r;
    try { r = await fetch(url, { method, credentials: 'same-origin', headers, body: body ? JSON.stringify(body) : undefined }); }
    catch { throw new Error('Server tidak bisa dihubungi. Periksa koneksi.'); }
    let j = {};
    try { j = await r.json(); } catch {}
    if (!r.ok) { const e = new Error(j.error || `Kesalahan server (${r.status})`); e.status = r.status; throw e; }
    return j;
  }
  // simpan ke server berurutan (tiap simpan membawa nomor revisi)
  let saving = Promise.resolve();
  function persist() {
    const job = saving.then(async () => {
      if (!cryptoKey) return;
      const vault = await seal(cryptoKey, data);
      try { rev = (await api('PUT', '/api/vault', { vault, rev })).rev; }
      catch (e) {
        if (e.status === 409) { await reloadVault(); toast('Vault diubah di perangkat lain — data terbaru dimuat. Ulangi perubahanmu.'); }
        else if (e.status === 401) lock('Sesi berakhir. Silakan masuk lagi.');
        else toast('Gagal menyimpan: ' + e.message);
        throw e;
      }
    });
    saving = job.catch(() => {});
    return job;
  }
  async function reloadVault() {
    const r = await api('GET', '/api/vault');
    data = migrate(await unseal(cryptoKey, r.vault)); rev = r.rev;
    render();
  }

  // ---------- jenis item ----------
  const TYPES = {
    login: {
      label: 'Login', plural: 'Login', icon: 'globe', color: '#8BE9B4',
      fields: [
        { k: 'user', label: 'Username / email', copy: true },
        { k: 'pass', label: 'Password', secret: true, gen: true, required: true, mono: true },
        { k: 'url', label: 'Situs (URL)', link: true, placeholder: 'contoh.com' },
        { k: 'note', label: 'Catatan', type: 'textarea' },
      ],
      sub: (i) => i.user || i.url || '',
    },
    card: {
      label: 'Kartu', plural: 'Kartu', icon: 'card', color: '#F5C76B',
      fields: [
        { k: 'holder', label: 'Nama pemegang kartu', copy: true },
        { k: 'number', label: 'Nomor kartu', secret: true, mono: true, required: true, placeholder: '1234 5678 9012 3456' },
        { k: 'brand', label: 'Jenis', type: 'select', options: ['Visa', 'Mastercard', 'JCB', 'Amex', 'GPN', 'Lainnya'] },
        { k: 'exp', label: 'Berlaku sampai (MM/YY)', mono: true, placeholder: '08/29' },
        { k: 'cvv', label: 'CVV', secret: true, mono: true },
        { k: 'pin', label: 'PIN', secret: true, mono: true },
        { k: 'note', label: 'Catatan', type: 'textarea' },
      ],
      sub: (i) => [i.brand, i.number ? '•••• ' + i.number.replace(/\s/g, '').slice(-4) : ''].filter(Boolean).join(' '),
    },
    identity: {
      label: 'Identitas', plural: 'Identitas', icon: 'id', color: '#9DB8FF',
      fields: [
        { k: 'fullname', label: 'Nama lengkap', copy: true },
        { k: 'email', label: 'Email', copy: true },
        { k: 'phone', label: 'Telepon', copy: true },
        { k: 'idnum', label: 'No. KTP / Paspor / SIM', secret: true, mono: true },
        { k: 'birth', label: 'Tanggal lahir', type: 'date' },
        { k: 'address', label: 'Alamat', type: 'textarea', copy: true },
        { k: 'note', label: 'Catatan', type: 'textarea' },
      ],
      sub: (i) => i.fullname || i.email || '',
    },
    note: {
      label: 'Catatan', plural: 'Catatan aman', icon: 'note', color: '#C9A8FF',
      fields: [{ k: 'body', label: 'Isi catatan', type: 'textarea', copy: true, rows: 8 }],
      sub: (i) => (i.body || '').split('\n')[0],
    },
    ssh: {
      label: 'SSH key', plural: 'SSH key', icon: 'key', color: '#7FD8E8',
      fields: [
        { k: 'host', label: 'Host', copy: true, mono: true, placeholder: 'server.contoh.com' },
        { k: 'user', label: 'User', copy: true, mono: true },
        { k: 'pub', label: 'Public key', type: 'textarea', mono: true, copy: true },
        { k: 'priv', label: 'Private key', type: 'textarea', mono: true, secret: true, required: true },
        { k: 'passphrase', label: 'Passphrase', secret: true, mono: true },
        { k: 'note', label: 'Catatan', type: 'textarea' },
      ],
      sub: (i) => [i.user, i.host].filter(Boolean).join('@'),
    },
    apikey: {
      label: 'API key', plural: 'API key', icon: 'code', color: '#FF9B85',
      fields: [
        { k: 'key', label: 'API key / secret', secret: true, mono: true, required: true, placeholder: 'Tempel key di sini' },
        { k: 'env', label: 'Environment', type: 'seg', options: ['Production', 'Staging', 'Development'], def: 'Production' },
        { k: 'expiry', label: 'Kedaluwarsa', type: 'date' },
        { k: 'note', label: 'Catatan / dipakai di', placeholder: 'mis. checkout-service' },
      ],
      sub: (i) => [i.env, i.note].filter(Boolean).join(' · '),
    },
  };
  const TYPE_ORDER = ['login', 'card', 'identity', 'note', 'ssh', 'apikey'];

  // ---------- migrasi data v1 -> v2 ----------
  function migrate(d) {
    if (d && Array.isArray(d.items)) { d.folders ||= []; return d; }
    const out = { v: 2, folders: [], items: [] };
    const folderOf = (name) => {
      if (!name) return null;
      let f = out.folders.find((x) => x.name === name);
      if (!f) { f = { id: uid(), name }; out.folders.push(f); }
      return f.id;
    };
    (d?.passwords || []).forEach((p) => out.items.push({
      id: p.id || uid(), type: 'login', name: p.name, user: p.user, pass: p.pass, url: p.url, note: p.note,
      folder: folderOf(p.cat), fav: !!p.fav, created: p.updated || Date.now(), updated: p.updated || Date.now() }));
    (d?.apiKeys || []).forEach((k) => out.items.push({
      id: k.id || uid(), type: 'apikey', name: k.service, key: k.key, env: k.env, expiry: k.expiry, note: k.note,
      folder: null, fav: false, created: k.created || Date.now(), updated: k.created || Date.now() }));
    return out;
  }

  // ---------- generator ----------
  const SETS = { upper: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', lower: 'abcdefghijklmnopqrstuvwxyz', digit: '0123456789', sym: '!@#$%^&*()-_=+[]{};:,.?/' };
  const charsets = (o) => ['upper', 'lower', 'digit', 'sym'].filter((k) => o[k]).map((k) => (o.simple ? SETS[k].replace(/[IOlo01]/g, '') : SETS[k]));
  function rnd(n) {
    const a = new Uint32Array(1), lim = Math.floor(0x100000000 / n) * n;
    do crypto.getRandomValues(a); while (a[0] >= lim);
    return a[0] % n;
  }
  function generate(o) {
    const sets = charsets(o);
    if (!sets.length) return '';
    const len = Math.min(32, Math.max(8, o.len | 0)), all = sets.join('');
    const out = sets.map((s) => s[rnd(s.length)]);
    while (out.length < len) out.push(all[rnd(all.length)]);
    for (let i = out.length - 1; i > 0; i--) { const j = rnd(i + 1); [out[i], out[j]] = [out[j], out[i]]; }
    return out.join('');
  }

  // ---------- strength ----------
  const COMMON = /^(password|passw0rd|qwerty|123456|12345678|abc123|admin|letmein|iloveyou|rahasia|sayang)/i;
  function strength(pw) {
    if (!pw) return { lvl: 0, bits: 0, label: 'Kosong' };
    let pool = 0;
    if (/[a-z]/.test(pw)) pool += 26;
    if (/[A-Z]/.test(pw)) pool += 26;
    if (/[0-9]/.test(pw)) pool += 10;
    if (/[^a-zA-Z0-9]/.test(pw)) pool += 24;
    let bits = Math.round(pw.length * Math.log2(Math.max(pool, 2)));
    if (COMMON.test(pw) || /(.)\1{3,}/.test(pw)) bits = Math.min(bits, 30);
    const lvl = bits >= 100 ? 4 : bits >= 72 ? 3 : bits >= 50 ? 2 : 1;
    return { lvl, bits, label: ['', 'Lemah', 'Sedang', 'Kuat', 'Sangat kuat'][lvl] };
  }
  const SCOL = ['#2A2F3A', '#FF9B85', '#F5C76B', '#9DE8B8', '#8BE9B4'];

  // ---------- DOM helpers ----------
  function h(tag, attrs, ...kids) {
    const el = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs || {})) {
      if (v == null || v === false) continue;
      if (k === 'class') el.className = v;
      else if (k === 'style') el.style.cssText = v;
      else if (k.startsWith('on')) el.addEventListener(k.slice(2), v);
      else el.setAttribute(k, v === true ? '' : v);
    }
    for (const c of kids.flat()) if (c != null && c !== false && c !== '') el.append(c.nodeType ? c : String(c));
    return el;
  }
  const ICONS = {
    eye: '<path d="M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7S2 12 2 12Z"/><circle cx="12" cy="12" r="3"/>',
    eyeOff: '<path d="M10.6 5.1A10 10 0 0 1 12 5c6.5 0 10 7 10 7a17 17 0 0 1-3 3.9M6.6 6.6A17 17 0 0 0 2 12s3.5 7 10 7a9.7 9.7 0 0 0 5.4-1.6"/><path d="m2 2 20 20"/><path d="M9.9 9.9a3 3 0 0 0 4.2 4.2"/>',
    copy: '<rect x="9" y="9" width="12" height="12" rx="2"/><path d="M5 15H4a1 1 0 0 1-1-1V4a1 1 0 0 1 1-1h10a1 1 0 0 1 1 1v1"/>',
    edit: '<path d="M12 20h9"/><path d="M16.5 3.5a2.1 2.1 0 0 1 3 3L7 19l-4 1 1-4Z"/>',
    trash: '<path d="M3 6h18"/><path d="M8 6V4h8v2"/><path d="M19 6l-1 14H6L5 6"/>',
    star: '<path d="m12 3 2.8 5.7 6.2.9-4.5 4.4 1 6.2L12 17.3 6.5 20.2l1-6.2L3 9.6l6.2-.9Z"/>',
    dice: '<path d="M21 12a9 9 0 1 1-3-6.7"/><path d="M21 3v6h-6"/>',
    ext: '<path d="M15 3h6v6"/><path d="M10 14 21 3"/><path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/>',
    globe: '<circle cx="12" cy="12" r="9"/><path d="M3 12h18"/><path d="M12 3a14 14 0 0 1 0 18 14 14 0 0 1 0-18Z"/>',
    card: '<rect x="2.5" y="5" width="19" height="14" rx="2"/><path d="M2.5 10h19"/>',
    id: '<rect x="2.5" y="4.5" width="19" height="15" rx="2"/><circle cx="8.5" cy="11" r="2.2"/><path d="M5.5 16c.6-1.6 1.8-2.3 3-2.3s2.4.7 3 2.3"/><path d="M14 10h4.5M14 14h3"/>',
    note: '<path d="M6 3h9l4 4v14H6z"/><path d="M14 3v5h5"/><path d="M9 13h6M9 17h4"/>',
    key: '<circle cx="7.5" cy="14.5" r="3.5"/><path d="M10 12 20 2"/><path d="m16 6 3 3"/><path d="m14 8 2 2"/>',
    code: '<path d="m8 8-5 4 5 4"/><path d="m16 8 5 4-5 4"/><path d="m14 4-4 16"/>',
    folder: '<path d="M3 6.5A1.5 1.5 0 0 1 4.5 5H9l2 2.5h8.5A1.5 1.5 0 0 1 21 9v9.5a1.5 1.5 0 0 1-1.5 1.5h-15A1.5 1.5 0 0 1 3 18.5z"/>',
    grid: '<rect x="3.5" y="3.5" width="7" height="7" rx="1.5"/><rect x="13.5" y="3.5" width="7" height="7" rx="1.5"/><rect x="3.5" y="13.5" width="7" height="7" rx="1.5"/><rect x="13.5" y="13.5" width="7" height="7" rx="1.5"/>',
    gen: '<path d="M21 12a9 9 0 1 1-3-6.7"/><path d="M21 3v6h-6"/>',
    swap: '<path d="M7 4v16"/><path d="m3 8 4-4 4 4"/><path d="M17 20V4"/><path d="m21 16-4 4-4-4"/>',
    chev: '<path d="m9 6 6 6-6 6"/>',
    x: '<path d="M18 6 6 18"/><path d="m6 6 12 12"/>',
    more: '<circle cx="12" cy="5" r="1.4" fill="currentColor"/><circle cx="12" cy="12" r="1.4" fill="currentColor"/><circle cx="12" cy="19" r="1.4" fill="currentColor"/>',
    archive: '<rect x="3" y="4" width="18" height="5" rx="1"/><path d="M5 9v10a1 1 0 0 0 1 1h12a1 1 0 0 0 1-1V9"/><path d="M10 13h4"/>',
    clip: '<path d="m21 11-8.6 8.6a5.5 5.5 0 0 1-7.8-7.8l8.6-8.6a3.7 3.7 0 0 1 5.2 5.2l-8.6 8.6a1.8 1.8 0 0 1-2.6-2.6L15 7.6"/>',
    download: '<path d="M12 3v12"/><path d="m7 10 5 5 5-5"/><path d="M5 21h14"/>',
    users: '<circle cx="9" cy="8" r="3.5"/><path d="M2.5 20c.8-3.6 3.4-5.5 6.5-5.5s5.7 1.9 6.5 5.5"/><path d="M16 4.6a3.5 3.5 0 0 1 0 6.8"/><path d="M18.5 14.8c1.6.8 2.6 2.6 3 5.2"/>',
    userPlus: '<circle cx="10" cy="8" r="3.5"/><path d="M3 20c.8-3.6 3.6-5.5 7-5.5 1.4 0 2.7.3 3.8.9"/><path d="M19 14v6M16 17h6"/>',
    mail: '<rect x="3" y="5" width="18" height="14" rx="2"/><path d="m3.5 6.5 8.5 6 8.5-6"/>',
    alert: '<path d="M12 3 2 20h20Z"/><path d="M12 10v4"/><path d="M12 17h.01"/>',
    check: '<circle cx="12" cy="12" r="9"/><path d="m8 12 3 3 5-6"/>',
    gear: '<circle cx="12" cy="12" r="3"/><path d="M12 2v3M12 19v3M4.9 4.9l2.1 2.1M17 17l2.1 2.1M2 12h3M19 12h3M4.9 19.1 7 17M17 7l2.1-2.1"/>',
  };
  function icon(name, fill) {
    const s = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
    s.setAttribute('viewBox', '0 0 24 24'); s.setAttribute('aria-hidden', 'true');
    if (fill) s.style.fill = 'currentColor';
    s.innerHTML = ICONS[name]; // markup statis, bukan input pengguna
    return s;
  }
  const iconBtn = (name, label, onclick, opts = {}) =>
    h('button', { type: 'button', class: opts.class || 'icon-btn', 'aria-label': label, title: label, onclick, style: opts.style }, icon(name, opts.fill));

  let toastT;
  function toast(msg) {
    const t = $('#toast'); t.textContent = msg; t.classList.add('show');
    clearTimeout(toastT); toastT = setTimeout(() => t.classList.remove('show'), 2400);
  }
  let clipT;
  async function copy(text, what) {
    try {
      await navigator.clipboard.writeText(text);
      toast(`${what} disalin${settings.clipclear ? ' · dihapus dalam 30 dtk' : ''}`);
      if (settings.clipclear) {
        clearTimeout(clipT);
        clipT = setTimeout(async () => {
          try { if ((await navigator.clipboard.readText()) === text) await navigator.clipboard.writeText(''); }
          catch { try { await navigator.clipboard.writeText(''); } catch {} }
        }, 30000);
      }
    } catch { toast('Gagal menyalin — izinkan akses clipboard'); }
  }
  const uid = () => b64(crypto.getRandomValues(new Uint8Array(9))).replace(/[+/=]/g, '');
  const fmtDate = (ts) => new Date(ts).toLocaleDateString('id-ID', { day: 'numeric', month: 'short', year: 'numeric' });
  const safeUrl = (u) => {
    if (!u) return null;
    try { const x = new URL(/^[a-z]+:\/\//i.test(u) ? u : 'https://' + u); return /^https?:$/.test(x.protocol) ? x.href : null; }
    catch { return null; }
  };
  const folderName = (id) => data.folders.find((f) => f.id === id)?.name;
  function download(name, text, type) {
    const a = h('a', { href: URL.createObjectURL(new Blob([text], { type })), download: name });
    document.body.append(a); a.click(); a.remove();
    setTimeout(() => URL.revokeObjectURL(a.href), 1000);
  }
  const today = () => new Date().toISOString().slice(0, 10);

  // ---------- sesi bertahan saat refresh ----------
  // encKey dibungkus (AES-GCM) dengan kunci acak per sesi. Hasil bungkusan disimpan di sessionStorage tab ini,
  // kunci pembungkusnya disimpan server bersama sesi (hanya keluar dengan cookie HttpOnly yang valid).
  const SESS_KEY = 'brankas.sess', UI_KEY = 'brankas.ui';
  let wrapRaw = null;
  async function saveSession() {
    if (!wrapRaw || !cryptoKey) return;
    const wk = await crypto.subtle.importKey('raw', wrapRaw, 'AES-GCM', false, ['encrypt']);
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const w = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, wk, await crypto.subtle.exportKey('raw', cryptoKey));
    sessionStorage.setItem(SESS_KEY, JSON.stringify({ u: username, salt: b64(salt), iter: kdfIter, iv: b64(iv), w: b64(w) }));
  }
  async function restoreSession() {
    const st = safeParse(sessionStorage.getItem(SESS_KEY));
    if (!st) return false;
    try {
      const s = await api('GET', '/api/session');
      if (s.username !== st.u || !s.wrapKey) throw new Error('sesi tidak cocok');
      wrapRaw = unb64(s.wrapKey);
      const wk = await crypto.subtle.importKey('raw', wrapRaw, 'AES-GCM', false, ['decrypt']);
      const raw = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: unb64(st.iv) }, wk, unb64(st.w));
      cryptoKey = await crypto.subtle.importKey('raw', raw, { name: 'AES-GCM' }, true, ['encrypt', 'decrypt']);
      username = st.u; salt = unb64(st.salt); kdfIter = st.iter; isAdmin = !!s.isAdmin;
      const r = await api('GET', '/api/vault');
      data = migrate(await unseal(cryptoKey, r.vault)); rev = r.rev;
      return true;
    } catch {
      sessionStorage.removeItem(SESS_KEY);
      cryptoKey = null; data = null; wrapRaw = null; username = null;
      return false;
    }
  }
  function enterApp(ui) {
    $('#lock').hidden = true; $('#app').hidden = false;
    lastActive = Date.now();
    go(ui?.view || 'items', ui?.filter || 'all');
  }

  // ---------- akun: masuk / daftar / kunci ----------
  let mode = 'login', signupMode = 'closed';
  function setMode(m) {
    mode = m;
    const reg = m === 'register';
    $('#tab-login').setAttribute('aria-selected', String(!reg));
    $('#tab-reg').setAttribute('aria-selected', String(reg));
    $('#mp2-wrap').hidden = !reg; $('#mp2').required = reg;
    const needCode = reg && signupMode === 'code' && !invite;
    $('#code-wrap').hidden = !needCode; $('#code').required = needCode;
    $('#reg-hint').hidden = !reg;
    $('#lock-title').textContent = reg ? 'Buat akun Brankas' : 'Masuk ke Brankas';
    $('#lock-sub').textContent = reg
      ? 'Master password mengenkripsi vault di perangkatmu. Server tidak pernah melihatnya.'
      : 'Masukkan username dan master password. Vault didekripsi hanya di perangkat ini.';
    $('#lock-btn').textContent = reg ? 'Buat akun' : 'Masuk';
    $('#mp').autocomplete = reg ? 'new-password' : 'current-password';
    $('#mp').minLength = reg ? 10 : 1;
    $('#lock-err').textContent = '';
    const bound = reg && invite?.username;
    $('#lu').readOnly = !!bound;
    if (bound) $('#lu').value = invite.username;
    if (reg && invite) $('#lock-sub').textContent = 'Kamu diundang ke Brankas. Buat master password untuk akunmu — server tidak pernah melihatnya.';
  }
  function showLock(msg) {
    $('#app').hidden = true; $('#lock').hidden = false;
    loadTurnstile();
    $('#tabs').hidden = signupMode === 'closed' && !invite;
    setMode(invite ? 'register' : signupMode === 'closed' ? 'login' : (signupMode === 'open-first' ? 'register' : mode));
    if (msg) $('#lock-err').textContent = msg;
    $('#lu').value = invite ? (invite.username || '') : (localStorage.getItem('brankas.lastUser') || '');
    $('#mp').value = ''; $('#mp2').value = ''; $('#code').value = '';
    setTimeout(() => ($('#lu').value ? $('#mp') : $('#lu')).focus(), 0);
  }
  function lock(msg) {
    if (cryptoKey) api('POST', '/api/logout', {}).catch(() => {});
    sessionStorage.removeItem(SESS_KEY); sessionStorage.removeItem(UI_KEY); wrapRaw = null;
    cryptoKey = null; data = null; salt = null; username = null; rev = 0; sel = null; showDetail = false; revealed.clear(); isAdmin = false;
    $('#app').classList.remove('drawer');
    if ($('#modal').open) $('#modal').close();
    closeView();
    closeItemMenu();
    closeMenu();
    ['#list', '#view-body', '#nav-items', '#nav-folders'].forEach((q) => $(q).replaceChildren());
    showLock(typeof msg === 'string' ? msg : '');
  }

  // username: huruf kecil otomatis, spasi jadi titik (mis. "Indra Mahendra" -> "indra.mahendra")
  $('#lu').addEventListener('input', (e) => {
    const el = e.target, v = el.value.toLowerCase().replace(/\s+/g, '.');
    if (v !== el.value) { const p = el.selectionStart; el.value = v; el.setSelectionRange(p, p); }
  });
  $('#tab-login').addEventListener('click', () => setMode('login'));
  $('#tab-reg').addEventListener('click', () => setMode('register'));

  $('#lock-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const user = $('#lu').value.trim().toLowerCase(), pw = $('#mp').value, err = $('#lock-err'), btn = $('#lock-btn');
    err.textContent = '';
    btn.disabled = true; const label = btn.textContent; btn.textContent = 'Memproses…';
    const registering = mode === 'register';
    if (tsSiteKey && !tsToken) { err.textContent = 'Selesaikan verifikasi keamanan (Cloudflare) dulu.'; btn.disabled = false; btn.textContent = label; return; }
    wrapRaw = crypto.getRandomValues(new Uint8Array(32));
    try {
      if (!/^[a-z0-9][a-z0-9._@+-]{2,63}$/.test(user)) throw new Error('Username 3–64 karakter: huruf kecil, angka, . _ @ + -');
      if (registering) {
        if (pw.length < 10) throw new Error('Master password minimal 10 karakter.');
        if (pw !== $('#mp2').value) throw new Error('Kedua master password tidak sama.');
        const s2 = crypto.getRandomValues(new Uint8Array(16));
        const k = await deriveKeys(pw, s2, ITER);
        const fresh = { v: 2, folders: [], items: [] };
        const r = await api('POST', '/api/register', {
          username: user, kdfSalt: b64(s2), kdfIter: ITER, authKey: k.authKey,
          vault: await seal(k.encKey, fresh), signupCode: $('#code').value || undefined, inviteCode: invite?.code, wrapKey: b64(wrapRaw), turnstile: tsToken || undefined });
        cryptoKey = k.encKey; salt = s2; kdfIter = ITER; rev = r.rev; data = fresh; isAdmin = !!r.isAdmin; invite = null;
        if (signupMode === 'open-first') signupMode = 'closed';
      } else {
        const pre = await api('POST', '/api/prelogin', { username: user });
        const s2 = unb64(pre.kdfSalt);
        const k = await deriveKeys(pw, s2, pre.kdfIter);
        const r = await api('POST', '/api/login', { username: user, authKey: k.authKey, wrapKey: b64(wrapRaw), turnstile: tsToken || undefined });
        let obj;
        try { obj = await unseal(k.encKey, r.vault); } catch { throw new Error('Vault tidak bisa didekripsi.'); }
        cryptoKey = k.encKey; salt = s2; kdfIter = pre.kdfIter; rev = r.rev; data = migrate(obj); isAdmin = !!r.isAdmin;
      }
      username = user;
      localStorage.setItem('brankas.lastUser', user);
      await saveSession();
      $('#mp').value = ''; $('#mp2').value = ''; $('#code').value = '';
      enterApp();
      if (registering) toast('Akun dibuat. Selamat datang!');
      else if (localStorage.getItem(LEGACY_KEY)) toast('Ada vault lama di browser ini — impor lewat menu Impor & Ekspor');
    } catch (ex) {
      err.textContent = ex.message;
    } finally { btn.disabled = false; btn.textContent = label; resetTurnstile(); }
  });

  document.querySelectorAll('[data-toggle]').forEach((b) => b.addEventListener('click', () => {
    const inp = document.getElementById(b.dataset.toggle);
    const show = inp.type === 'password';
    inp.type = show ? 'text' : 'password';
    b.setAttribute('aria-label', show ? 'Sembunyikan password' : 'Tampilkan password');
  }));
  $('#lock-now').addEventListener('click', () => lock());
  $('#acc-lock').addEventListener('click', () => lock());

  ['mousemove', 'keydown', 'pointerdown', 'scroll', 'touchstart'].forEach((ev) =>
    window.addEventListener(ev, () => { lastActive = Date.now(); }, { passive: true }));
  setInterval(() => {
    if (cryptoKey && Date.now() - lastActive > settings.autolock * 60000) { lock(); toast('Vault dikunci otomatis'); }
  }, 5000);

  // ---------- navigasi ----------
  const isMobile = () => matchMedia('(max-width:860px)').matches;
  function setDrawer(open) {
    $('#app').classList.toggle('drawer', open);
    $('#menu-open').setAttribute('aria-expanded', String(open));
    if (open) $('#side').querySelector('.nav')?.focus();
  }
  $('#menu-open').addEventListener('click', () => setDrawer(true));
  $('#scrim').addEventListener('click', () => setDrawer(false));
  $('#m-lock').addEventListener('click', () => lock());
  document.addEventListener('keydown', (e) => { if (e.key === 'Escape' && $('#app').classList.contains('drawer')) setDrawer(false); });

  function go(v, f) {
    view = v;
    setDrawer(false);
    if (f !== undefined) { filter = f; sel = null; selected.clear(); showDetail = false; revealed.clear(); $('#search').value = ''; }
    document.querySelectorAll('.view').forEach((s) => { s.hidden = s.id !== 'v-' + v; });
    if (cryptoKey) sessionStorage.setItem(UI_KEY, JSON.stringify({ view, filter }));
    render();
  }
  function navBtn(label, ic, active, onclick, count, color) {
    return h('button', { type: 'button', class: 'nav' + (active ? ' active' : ''), 'aria-current': active ? 'page' : null, onclick },
      h('span', { style: color ? `color:${color};display:flex` : 'display:flex' }, icon(ic)),
      h('span', { class: 'lbl' }, label),
      count != null ? h('span', { class: 'count' }, count) : null);
  }
  function renderNav() {
    const live = data.items.filter((i) => !i.archived);
    const cnt = (fn) => live.filter(fn).length;
    const isItems = view === 'items';
    $('#nav-items').replaceChildren(
      navBtn('Semua item', 'grid', isItems && filter === 'all', () => go('items', 'all'), live.length),
      navBtn('Favorit', 'star', isItems && filter === 'fav', () => go('items', 'fav'), cnt((i) => i.fav)),
      ...TYPE_ORDER.map((t) => navBtn(TYPES[t].plural, TYPES[t].icon, isItems && filter === 'type:' + t, () => go('items', 'type:' + t), cnt((i) => i.type === t))),
      navBtn('Arsip', 'archive', isItems && filter === 'archive', () => go('items', 'archive'), data.items.length - live.length));
    $('#nav-folders').replaceChildren(...(data.folders.length
      ? [...data.folders].sort((a, b) => a.name.localeCompare(b.name)).map((f) =>
          navBtn(f.name, 'folder', isItems && filter === 'folder:' + f.id, () => go('items', 'folder:' + f.id), cnt((i) => i.folder === f.id)))
      : [h('p', { class: 'small muted', style: 'padding:4px 12px' }, 'Belum ada folder')]));
    $('#nav-tools').replaceChildren(
      navBtn('Generator', 'gen', view === 'generator', () => go('generator')),
      navBtn('Impor & Ekspor', 'swap', view === 'transfer', () => go('transfer')),
      ...(isAdmin ? [navBtn('Pengguna', 'users', view === 'users', () => go('users'))] : []),
      navBtn('Pengaturan', 'gear', view === 'settings', () => go('settings')));
  }
  function render() {
    if (!data) return;
    renderNav();
    if (view === 'items') renderItems();
    if (viewDlg.open) renderView();
    if (view === 'generator') renderGen();
    if (view === 'settings') renderSettings();
    if (view === 'users') renderUsers();
    if (view === 'transfer') { $('#imp-result').textContent = ''; $('#legacy-wrap').hidden = !localStorage.getItem(LEGACY_KEY); }
  }

  // ---------- menu Tambah ----------
  const addBtn = $('#add-btn'), addMenu = $('#add-menu');
  function buildMenu() {
    addMenu.replaceChildren(
      ...TYPE_ORDER.map((t) => h('button', { type: 'button', role: 'menuitem', class: 'menu-item', onclick: () => { closeMenu(); editItem(null, t); } },
        icon(TYPES[t].icon), TYPES[t].label)),
      h('hr', { role: 'separator' }),
      h('button', { type: 'button', role: 'menuitem', class: 'menu-item', onclick: () => { closeMenu(); editFolder(null); } }, icon('folder'), 'Folder'),
      ...(isAdmin ? [h('hr', { role: 'separator' }),
        h('button', { type: 'button', role: 'menuitem', class: 'menu-item', onclick: () => { closeMenu(); addUser(); } }, icon('userPlus'), 'Tambah user')] : []));
  }
  function openMenu() {
    buildMenu(); addMenu.hidden = false; addBtn.setAttribute('aria-expanded', 'true');
    addMenu.querySelector('.menu-item').focus();
  }
  function closeMenu() { addMenu.hidden = true; addBtn.setAttribute('aria-expanded', 'false'); }
  addBtn.addEventListener('click', (e) => { e.stopPropagation(); addMenu.hidden ? openMenu() : closeMenu(); });
  document.addEventListener('click', (e) => { if (!addMenu.hidden && !addMenu.contains(e.target)) closeMenu(); });
  addMenu.addEventListener('keydown', (e) => {
    const items = [...addMenu.querySelectorAll('.menu-item')];
    const i = items.indexOf(document.activeElement);
    if (e.key === 'ArrowDown') { e.preventDefault(); items[(i + 1) % items.length].focus(); }
    else if (e.key === 'ArrowUp') { e.preventDefault(); items[(i - 1 + items.length) % items.length].focus(); }
    else if (e.key === 'Escape') { closeMenu(); addBtn.focus(); }
    else if (e.key === 'Tab') closeMenu();
  });

  // ---------- daftar & detail ----------
  $('#search').addEventListener('input', renderItems);

  function currentFolder() { return filter.startsWith('folder:') ? data.folders.find((f) => 'folder:' + f.id === filter) : null; }

  function renderItems() {
    const q = $('#search').value.trim().toLowerCase();
    const folder = currentFolder();
    if (filter.startsWith('folder:') && !folder) filter = 'all';
    let title = 'Semua item';
    if (filter === 'fav') title = 'Favorit';
    else if (filter === 'archive') title = 'Arsip';
    else if (filter.startsWith('type:')) title = TYPES[filter.slice(5)].plural;
    else if (folder) title = folder.name;
    $('#items-title').textContent = title;
    $('#folder-acts').hidden = !folder;

    const items = data.items
      .filter((i) => (filter === 'archive' ? i.archived : !i.archived))
      .filter((i) => filter === 'all' || filter === 'archive' || (filter === 'fav' ? i.fav : filter.startsWith('type:') ? i.type === filter.slice(5) : i.folder === folder?.id))
      .filter((i) => !q || [i.name, TYPES[i.type].sub(i), i.url, i.host, i.email].some((x) => (x || '').toLowerCase().includes(q)))
      .sort((a, b) => (b.fav - a.fav) || (a.name || '').localeCompare(b.name || ''));
    $('#items-sub').textContent = `${items.length} item${folder ? ' di folder ini' : ''} · klik kartu untuk melihat & menyalin isinya`;

    const list = $('#list');
    if (filter === 'all') { list.className = 'all-view'; renderAllView(list, items); return; }
    list.className = 'item-grid';
    if (!items.length) {
      list.replaceChildren(h('p', { class: 'empty card' }, data.items.length || folder ? 'Tidak ada item di sini.' : 'Vault masih kosong. Klik “Tambah” untuk menyimpan login, kartu, catatan, dan lainnya.'));
      return;
    }
    list.replaceChildren(...items.map((i) => {
      const T = TYPES[i.type];
      const s = i.type === 'login' && i.pass ? strength(i.pass) : null;
      return h('div', { class: 'item-card' },
        h('button', { type: 'button', class: 'ic-open', 'aria-haspopup': 'dialog', 'aria-label': 'Buka ' + (i.name || 'item'), onclick: () => openView(i) }),
        h('span', { class: 'ic-top' },
          h('span', { class: 'type-ico', style: `background:${T.color}` }, icon(T.icon)),
          h('span', { class: 'ic-badges' },
            i.fav ? h('span', { class: 'ic-fav', title: 'Favorit' }, icon('star', true), h('span', { class: 'sr' }, 'Favorit')) : null,
            i.attachments?.length ? h('span', { class: 'ic-att', title: i.attachments.length + ' lampiran' }, icon('clip'), i.attachments.length, h('span', { class: 'sr' }, ' lampiran')) : null,
            h('span', { class: 'badge' }, T.label),
            h('button', { type: 'button', class: 'ic-more', 'aria-label': 'Opsi untuk ' + (i.name || 'item'), title: 'Opsi', 'aria-haspopup': 'menu', 'aria-expanded': 'false',
              onclick: (e) => openItemMenu(i, e.currentTarget) }, icon('more')))),
        h('span', { class: 'ic-txt' },
          h('span', { class: 't1' }, i.name || '(tanpa nama)'),
          h('span', { class: 't2' }, T.sub(i) || '—')),
        h('span', { class: 'ic-foot' },
          h('span', { class: 'ic-folder' }, icon('folder'), folderName(i.folder) || 'Tanpa folder'),
          s ? h('span', { class: 'tag', style: `color:${SCOL[s.lvl]}` }, s.label) : h('span', { class: 'small muted' }, fmtDate(i.updated))));
    }));
  }

  // ---------- menu opsi per kartu (⋮) ----------
  const itemMenu = h('div', { class: 'menu item-menu', role: 'menu', 'aria-label': 'Opsi item', hidden: true });
  document.body.append(itemMenu);
  let menuFor = null, menuBtn = null;
  function openItemMenu(it, btn) {
    if (menuFor === it.id && !itemMenu.hidden) { closeItemMenu(true); return; }
    closeItemMenu(); closeMenu();
    menuFor = it.id; menuBtn = btn;
    const act = (ic, label, fn, cls) => h('button', { type: 'button', role: 'menuitem', class: 'menu-item' + (cls ? ' ' + cls : ''),
      onclick: () => { closeItemMenu(); fn(); } }, icon(ic), label);
    const save = async (msg) => { render(); try { await persist(); toast(msg); } catch {} };
    itemMenu.replaceChildren(
      act('star', it.fav ? 'Hapus dari favorit' : 'Favorit', () => { it.fav = !it.fav; save(it.fav ? 'Ditambahkan ke favorit' : 'Dihapus dari favorit'); }),
      act('edit', 'Edit', () => editItem(it)),
      act('clip', 'Lampiran', () => { openView(it); viewDlg.querySelector('.vd-att')?.scrollIntoView({ block: 'center' }); }),
      act('copy', 'Duplikat', async () => {
        const t = Date.now();
        const c = { ...structuredClone(it), id: uid(), name: (it.name || '') + ' (salinan)', fav: false, archived: false, created: t, updated: t };
        if (c.attachments?.length) {
          try { for (const a of c.attachments) a.id = (await api('POST', `/api/attachments/${a.id}/copy`, {})).id; }
          catch (e) { c.attachments = []; toast('Lampiran tidak ikut disalin: ' + e.message); }
        }
        data.items.push(c);
        save('Item diduplikat');
      }),
      act('archive', it.archived ? 'Pulihkan dari arsip' : 'Arsipkan', () => {
        it.archived = !it.archived; it.updated = Date.now();
        save(it.archived ? 'Item diarsipkan' : 'Item dipulihkan');
      }),
      h('hr', { role: 'separator' }),
      act('trash', 'Hapus', () => {
        if (!confirm(`Hapus “${it.name}”?`)) return;
        data.items = data.items.filter((x) => x.id !== it.id);
        save('Dihapus').then(() => purgeAttachments(it));
      }, 'danger'));
    itemMenu.hidden = false;
    btn.setAttribute('aria-expanded', 'true');
    const r = btn.getBoundingClientRect(), m = itemMenu.getBoundingClientRect();
    let top = r.bottom + 6;
    if (top + m.height > innerHeight - 8) top = Math.max(8, r.top - m.height - 6);
    const left = Math.max(8, Math.min(r.right - m.width, innerWidth - m.width - 8));
    itemMenu.style.top = top + 'px'; itemMenu.style.left = left + 'px';
    itemMenu.querySelector('.menu-item').focus();
  }
  function closeItemMenu(focusBack) {
    if (itemMenu.hidden) return;
    itemMenu.hidden = true;
    menuBtn?.setAttribute('aria-expanded', 'false');
    if (focusBack && menuBtn?.isConnected) menuBtn.focus();
    menuFor = null;
  }
  document.addEventListener('click', (e) => { if (!itemMenu.hidden && !itemMenu.contains(e.target) && !e.target.closest('.ic-more')) closeItemMenu(); });
  window.addEventListener('resize', () => closeItemMenu());
  document.addEventListener('scroll', (e) => { if (!itemMenu.contains(e.target)) closeItemMenu(); }, true);
  itemMenu.addEventListener('keydown', (e) => {
    const els = [...itemMenu.querySelectorAll('.menu-item')];
    const i = els.indexOf(document.activeElement);
    if (e.key === 'ArrowDown') { e.preventDefault(); els[(i + 1) % els.length].focus(); }
    else if (e.key === 'ArrowUp') { e.preventDefault(); els[(i - 1 + els.length) % els.length].focus(); }
    else if (e.key === 'Escape') { e.preventDefault(); closeItemMenu(true); }
    else if (e.key === 'Tab') closeItemMenu();
  });

  // ---------- Semua item: infografik + daftar ----------
  const STRENGTH = [['Kuat', '#8BE9B4', (l) => l >= 3], ['Sedang', '#EFB94F', (l) => l === 2], ['Lemah', '#E8616B', (l) => l <= 1]];
  function daysLeft(d) { return Math.round((new Date(d + 'T00:00:00') - new Date(today() + 'T00:00:00')) / 86400000); }

  function renderAllView(list, items) {
    const live = data.items.filter((i) => !i.archived);
    $('#items-sub').textContent = `${items.length} item · klik nama item untuk melihat & menyalin isinya`;
    if (!live.length) {
      list.replaceChildren(h('p', { class: 'empty card' }, 'Vault masih kosong. Klik “Tambah” untuk menyimpan login, kartu, catatan, dan lainnya.'));
      return;
    }

    // --- angka ringkasan ---
    const fav = live.filter((i) => i.fav).length;
    const attCount = live.reduce((a, i) => a + (i.attachments?.length || 0), 0);
    const attSize = live.reduce((a, i) => a + (i.attachments || []).reduce((b, x) => b + (x.size || 0), 0), 0);
    const logins = live.filter((i) => i.type === 'login' && i.pass);
    const lvls = logins.map((i) => strength(i.pass).lvl);
    const weak = lvls.filter((l) => l <= 1).length;
    const expiring = live.filter((i) => i.type === 'apikey' && i.expiry && daysLeft(i.expiry) <= 30).length;
    const attention = weak + expiring;
    const tile = (label, value, sub, ic, warn) => h('div', { class: 'stat' + (warn ? ' warn' : '') },
      h('span', { class: 'stat-label' }, icon(ic), label),
      h('span', { class: 'stat-value' }, String(value)),
      h('span', { class: 'stat-sub' }, sub));

    // --- grafik batang: item per jenis (satu seri, satu warna) ---
    const byType = TYPE_ORDER.map((t) => ({ t, n: live.filter((i) => i.type === t).length }));
    const max = Math.max(1, ...byType.map((x) => x.n));
    const typeChart = h('div', { class: 'bars', role: 'list' },
      byType.map(({ t, n }) => h('button', { type: 'button', class: 'bar-row', role: 'listitem', title: `${TYPES[t].plural}: ${n} item`,
          'aria-label': `${TYPES[t].plural}: ${n} item`, onclick: () => go('items', 'type:' + t) },
        h('span', { class: 'bar-label' }, h('span', { class: 'bar-ico', style: `color:${TYPES[t].color}` }, icon(TYPES[t].icon)), TYPES[t].label),
        h('span', { class: 'bar-track' }, n ? h('span', { class: 'bar-fill', style: `width:${Math.max(3, (n / max) * 100)}%` }) : null),
        h('span', { class: 'bar-val' }, String(n)))));

    // --- grafik kekuatan password (status, selalu dengan label + angka) ---
    const groups = STRENGTH.map(([label, color, test]) => ({ label, color, n: lvls.filter(test).length }));
    const strengthChart = logins.length
      ? h('div', { class: 'seg-wrap' },
          h('div', { class: 'seg-bar', role: 'img', 'aria-label': groups.map((g) => `${g.label} ${g.n}`).join(', ') },
            groups.filter((g) => g.n).map((g) => h('span', { class: 'seg', title: `${g.label}: ${g.n} password`, style: `flex:${g.n};background:${g.color}` }))),
          h('div', { class: 'seg-legend' }, groups.map((g) => h('span', { class: 'seg-key' },
            h('i', { style: `background:${g.color}` }), g.label, h('b', {}, String(g.n))))),
          h('p', { class: 'small muted' }, weak
            ? `${weak} password lemah — buka item Login-nya lalu ganti dengan password dari Generator.`
            : 'Semua password login cukup kuat.'))
      : h('p', { class: 'muted small' }, 'Belum ada item Login.');

    const dash = h('section', { class: 'dash', 'aria-label': 'Ringkasan vault' },
      h('div', { class: 'stats' },
        tile('Total item', live.length, `${data.folders.length} folder`, 'grid'),
        tile('Favorit', fav, fav ? 'ditandai bintang' : 'belum ada', 'star'),
        tile('Lampiran', attCount, attCount ? fmtSize(attSize) : 'belum ada', 'clip'),
        tile('Perlu perhatian', attention, attention ? [weak && `${weak} password lemah`, expiring && `${expiring} API key segera kedaluwarsa`].filter(Boolean).join(' · ') : 'semua aman', attention ? 'alert' : 'check', attention > 0)),
      h('div', { class: 'charts' },
        h('section', { class: 'card chart-card', 'aria-labelledby': 'ch-type' },
          h('h2', { id: 'ch-type' }, 'Item per jenis'), typeChart),
        h('section', { class: 'card chart-card', 'aria-labelledby': 'ch-str' },
          h('h2', { id: 'ch-str' }, 'Kekuatan password login'), strengthChart)));

    // --- daftar item (seperti referensi) ---
    for (const id of [...selected]) if (!items.some((i) => i.id === id)) selected.delete(id);
    const allOn = items.length > 0 && items.every((i) => selected.has(i.id));
    const bulk = selected.size ? h('div', { class: 'bulk' },
      h('span', {}, `${selected.size} dipilih`),
      h('button', { type: 'button', class: 'btn', onclick: () => bulkAct('fav') }, icon('star'), 'Favorit'),
      h('button', { type: 'button', class: 'btn', onclick: () => bulkAct('archive') }, icon('archive'), 'Arsipkan'),
      h('button', { type: 'button', class: 'btn danger', onclick: () => bulkAct('delete') }, icon('trash'), 'Hapus'),
      h('button', { type: 'button', class: 'btn', onclick: () => { selected.clear(); renderItems(); } }, 'Batal')) : null;

    const table = h('div', { class: 'tbl card', role: 'table', 'aria-label': 'Semua item' },
      h('div', { class: 'tr th', role: 'row' },
        h('span', { class: 'c-chk', role: 'columnheader' }, h('input', { type: 'checkbox', 'aria-label': 'Pilih semua item', checked: allOn,
          onchange: (e) => { items.forEach((i) => (e.target.checked ? selected.add(i.id) : selected.delete(i.id))); renderItems(); } })),
        h('span', { class: 'c-ico', role: 'columnheader' }, h('span', { class: 'sr' }, 'Jenis')),
        h('span', { class: 'c-name', role: 'columnheader' }, 'Nama'),
        h('span', { class: 'c-owner', role: 'columnheader' }, 'Pemilik'),
        h('span', { class: 'c-opt', role: 'columnheader' }, 'Opsi')),
      items.length ? items.map((i) => {
        const T = TYPES[i.type];
        return h('div', { class: 'tr' + (selected.has(i.id) ? ' on' : ''), role: 'row' },
          h('span', { class: 'c-chk', role: 'cell' }, h('input', { type: 'checkbox', 'aria-label': 'Pilih ' + (i.name || 'item'), checked: selected.has(i.id),
            onchange: (e) => { e.target.checked ? selected.add(i.id) : selected.delete(i.id); renderItems(); } })),
          h('span', { class: 'c-ico', role: 'cell', title: T.label }, h('span', { style: `color:${T.color};display:flex` }, icon(T.icon)), h('span', { class: 'sr' }, T.label)),
          h('span', { class: 'c-name', role: 'cell' },
            h('button', { type: 'button', class: 'name-link', 'aria-haspopup': 'dialog', onclick: () => openView(i) }, i.name || '(tanpa nama)'),
            i.fav ? h('span', { class: 'ic-fav', title: 'Favorit' }, icon('star', true), h('span', { class: 'sr' }, 'Favorit')) : null,
            i.attachments?.length ? h('span', { class: 'ic-att', title: i.attachments.length + ' lampiran' }, icon('clip'), i.attachments.length) : null),
          h('span', { class: 'c-owner', role: 'cell' }, h('span', { class: 'owner-badge' }, 'Saya')),
          h('span', { class: 'c-opt', role: 'cell' }, h('button', { type: 'button', class: 'ic-more', 'aria-label': 'Opsi untuk ' + (i.name || 'item'), title: 'Opsi',
            'aria-haspopup': 'menu', 'aria-expanded': 'false', onclick: (e) => openItemMenu(i, e.currentTarget) }, icon('more'))));
      }) : h('p', { class: 'empty' }, 'Tidak ada item yang cocok dengan pencarian.'));

    list.replaceChildren(...[dash, h('h2', { class: 'list-title' }, 'Semua item'), bulk, table].filter(Boolean));
  }

  async function bulkAct(kind) {
    const its = data.items.filter((i) => selected.has(i.id));
    if (!its.length) return;
    if (kind === 'delete' && !confirm(`Hapus ${its.length} item terpilih? Tidak bisa dibatalkan.`)) return;
    const t = Date.now();
    if (kind === 'fav') { const allFav = its.every((i) => i.fav); its.forEach((i) => { i.fav = !allFav; }); }
    if (kind === 'archive') its.forEach((i) => { i.archived = true; i.updated = t; });
    if (kind === 'delete') data.items = data.items.filter((i) => !selected.has(i.id));
    selected.clear();
    render();
    try {
      await persist();
      if (kind === 'delete') its.forEach(purgeAttachments);
      toast(kind === 'delete' ? `${its.length} item dihapus` : kind === 'archive' ? `${its.length} item diarsipkan` : 'Favorit diperbarui');
    } catch {}
  }

  // ---------- jendela detail: muncul saat kartu diklik ----------
  const viewDlg = $('#view-dlg');
  let viewing = null;
  function openView(it) {
    viewing = it.id; revealed.clear();
    renderView();
    if (!viewDlg.open) viewDlg.showModal();
    viewDlg.querySelector('.vd-close')?.focus();
  }
  function closeView() { if (viewDlg.open) viewDlg.close(); }
  viewDlg.addEventListener('close', () => { viewing = null; revealed.clear(); $('#view-body').replaceChildren(); });
  viewDlg.addEventListener('click', (e) => { if (e.target === viewDlg) closeView(); }); // klik di luar jendela

  function renderView() {
    const it = data?.items.find((x) => x.id === viewing);
    if (!it) { closeView(); return; }
    const T = TYPES[it.type];
    const rows = [];
    for (const f of T.fields) {
      const v = it[f.k];
      if (!v) continue;
      const open = revealed.has(f.k);
      const btns = [];
      if (f.secret) btns.push(iconBtn(open ? 'eyeOff' : 'eye', (open ? 'Sembunyikan ' : 'Tampilkan ') + f.label,
        () => { open ? revealed.delete(f.k) : revealed.add(f.k); renderView(); }));
      if (f.link && safeUrl(v)) btns.push(h('a', { class: 'icon-btn', href: safeUrl(v), target: '_blank', rel: 'noopener noreferrer', 'aria-label': 'Buka situs', title: 'Buka situs' }, icon('ext')));
      btns.push(iconBtn('copy', 'Salin ' + f.label, () => copy(v, f.label)));

      let display = v;
      if (f.type === 'date') display = new Date(v + 'T00:00:00').toLocaleDateString('id-ID', { day: 'numeric', month: 'long', year: 'numeric' });
      if (f.secret && !open) display = f.type === 'textarea' ? `•••••••• (${v.split('\n').length} baris tersembunyi)` : '•'.repeat(Math.min(v.length, 18));
      if (it.type === 'card' && f.k === 'number' && open) display = v.replace(/\s/g, '').replace(/(.{4})(?=.)/g, '$1 ');

      const extra = [];
      if (it.type === 'login' && f.k === 'pass') {
        const s = strength(v);
        extra.push(h('div', { class: 'meter-row vd-meter' },
          h('div', { class: 'meter' }, h('i', { style: `width:${s.lvl * 25}%;background:${SCOL[s.lvl]}` })),
          h('span', { class: 'tag', style: `color:${SCOL[s.lvl]}` }, `${s.label} · ${s.bits} bit`)));
      }
      if (it.type === 'apikey' && f.k === 'expiry') {
        const days = Math.round((new Date(v + 'T00:00:00') - new Date(today() + 'T00:00:00')) / 86400000);
        extra.push(h('span', { class: 'small', style: `color:${days <= 0 ? '#FF9B85' : days <= 30 ? '#F5C76B' : 'var(--muted)'}` },
          days < 0 ? 'Sudah kedaluwarsa' : days === 0 ? 'Kedaluwarsa hari ini' : `${days} hari lagi`));
      }
      rows.push(h('div', { class: 'vd-field' },
        h('div', { class: 'vd-fmain' },
          h('span', { class: 'vd-label' }, f.label),
          h('div', { class: 'vd-val' + (f.mono ? ' mono' : '') + (f.type === 'textarea' ? ' multi' : '') }, display),
          extra),
        h('div', { class: 'vd-acts' }, btns)));
    }
    const when = (ts) => new Date(ts).toLocaleString('id-ID', { day: 'numeric', month: 'short', year: 'numeric', hour: '2-digit', minute: '2-digit', second: '2-digit' });
    $('#view-body').replaceChildren(
      h('header', { class: 'vd-head' },
        h('h2', { id: 'view-title' }, 'Lihat ' + T.label.toLowerCase()),
        iconBtn('x', 'Tutup', closeView, { class: 'icon-btn vd-close' })),
      h('div', { class: 'vd-body' },
        h('section', { class: 'vd-card vd-ident' },
          h('div', { class: 'vd-name' },
            h('span', { class: 'type-ico', style: `background:${T.color}` }, icon(T.icon)),
            h('h3', {}, it.name || '(tanpa nama)'),
            it.fav ? h('span', { class: 'ic-fav', title: 'Favorit' }, icon('star', true), h('span', { class: 'sr' }, 'Favorit')) : null),
          h('div', { class: 'vd-meta' },
            h('span', {}, icon('folder'), folderName(it.folder) || 'Tanpa folder'),
            it.archived ? h('span', {}, icon('archive'), 'Diarsipkan') : null)),
        h('h4', { class: 'vd-sec' }, 'Detail'),
        h('section', { class: 'vd-card vd-fields' }, rows.length ? rows : h('p', { class: 'muted small' }, 'Belum ada isi.')),
        h('h4', { class: 'vd-sec' }, 'Lampiran'),
        attachSection(it),
        h('h4', { class: 'vd-sec' }, 'Riwayat item'),
        h('section', { class: 'vd-card vd-hist' },
          h('p', {}, 'Terakhir diubah: ', when(it.updated)),
          h('p', {}, 'Dibuat: ', when(it.created || it.updated)))),
      h('footer', { class: 'vd-foot' },
        h('button', { type: 'button', class: 'btn primary', onclick: () => { closeView(); editItem(it, null, true); } }, 'Edit'),
        h('span', { class: 'grow' }),
        iconBtn('star', it.fav ? 'Hapus dari favorit' : 'Jadikan favorit', async () => { it.fav = !it.fav; renderView(); render(); try { await persist(); } catch {} },
          { class: 'icon-btn lg', fill: it.fav, style: it.fav ? 'color:#F5C76B' : null }),
        iconBtn('trash', 'Hapus', async () => {
          if (!confirm(`Hapus “${it.name}”?`)) return;
          data.items = data.items.filter((x) => x.id !== it.id);
          closeView(); render();
          try { await persist(); purgeAttachments(it); toast('Dihapus'); } catch {}
        }, { class: 'icon-btn lg vd-del' })));
  }

  // ---------- lampiran ----------
  // Tiap file dienkripsi AES-256-GCM dengan kunci acak sendiri; kunci + nama file disimpan di vault (terenkripsi).
  const fmtSize = (n) => (n < 1024 ? n + ' B' : n < 1048576 ? (n / 1024).toFixed(1) + ' KB' : (n / 1048576).toFixed(1) + ' MB');
  let uploading = null; // id item yang sedang mengunggah
  async function apiBin(method, url, bytes) {
    const headers = { 'X-Brankas': '1' };
    if (bytes) headers['Content-Type'] = 'application/octet-stream';
    let r;
    try { r = await fetch(url, { method, credentials: 'same-origin', headers, body: bytes }); }
    catch { throw new Error('Server tidak bisa dihubungi.'); }
    if (!r.ok) {
      let j = {}; try { j = await r.json(); } catch {}
      if (r.status === 401) lock('Sesi berakhir. Silakan masuk lagi.');
      const e = new Error(j.error || (r.status === 413 ? 'File terlalu besar.' : `Kesalahan server (${r.status})`)); e.status = r.status; throw e;
    }
    return method === 'GET' ? new Uint8Array(await r.arrayBuffer()) : r.json();
  }
  async function uploadAttachments(it, files) {
    const ok = [], tooBig = files.filter((f) => f.size > attachMax);
    if (tooBig.length) toast(`Dilewati (lebih dari ${fmtSize(attachMax)}): ${tooBig.map((f) => f.name).join(', ')}`);
    uploading = it.id; renderView();
    try {
      for (const file of files.filter((f) => f.size <= attachMax)) {
        const keyRaw = crypto.getRandomValues(new Uint8Array(32)), iv = crypto.getRandomValues(new Uint8Array(12));
        const key = await crypto.subtle.importKey('raw', keyRaw, 'AES-GCM', false, ['encrypt']);
        const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, await file.arrayBuffer()));
        const r = await apiBin('POST', '/api/attachments', ct);
        (it.attachments ||= []).push({ id: r.id, name: file.name, type: file.type || 'application/octet-stream', size: file.size, key: b64(keyRaw), iv: b64(iv), added: Date.now() });
        it.updated = Date.now();
        await persist();
        ok.push(file.name);
      }
      if (ok.length) toast(ok.length === 1 ? `“${ok[0]}” dilampirkan` : `${ok.length} file dilampirkan`);
    } catch (e) {
      toast('Gagal mengunggah: ' + e.message);
    } finally {
      uploading = null; render();
    }
  }
  async function downloadAttachment(a) {
    const ct = await apiBin('GET', '/api/attachments/' + a.id);
    const key = await crypto.subtle.importKey('raw', unb64(a.key), 'AES-GCM', false, ['decrypt']);
    let pt;
    try { pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: unb64(a.iv) }, key, ct); }
    catch { throw new Error('Lampiran rusak atau tidak cocok.'); }
    download(a.name, pt, a.type);
  }
  async function removeAttachment(it, a) {
    if (!confirm(`Hapus lampiran “${a.name}”?`)) return;
    it.attachments = (it.attachments || []).filter((x) => x.id !== a.id);
    it.updated = Date.now();
    render();
    await persist();
    api('DELETE', '/api/attachments/' + a.id).catch(() => {});
    toast('Lampiran dihapus');
  }
  function purgeAttachments(it) {
    for (const a of it.attachments || []) api('DELETE', '/api/attachments/' + a.id).catch(() => {});
  }
  function attachSection(it) {
    const list = it.attachments || [];
    const input = h('input', { type: 'file', multiple: true, hidden: true });
    input.addEventListener('change', () => { const files = [...input.files]; input.value = ''; if (files.length) uploadAttachments(it, files); });
    const busy = uploading === it.id;
    return h('section', { class: 'vd-card vd-att' },
      list.length
        ? list.map((a) => h('div', { class: 'att-row' },
            h('span', { class: 'att-ico' }, icon('clip')),
            h('div', { class: 'att-txt' }, h('span', { class: 'att-name' }, a.name), h('span', { class: 'small muted' }, fmtSize(a.size))),
            iconBtn('download', 'Unduh ' + a.name, () => downloadAttachment(a).catch((e) => toast(e.message))),
            iconBtn('trash', 'Hapus lampiran ' + a.name, () => removeAttachment(it, a).catch((e) => toast(e.message)), { class: 'icon-btn vd-del' })))
        : h('p', { class: 'muted small att-empty' }, 'Belum ada lampiran.'),
      h('div', { class: 'att-foot' },
        h('button', { type: 'button', class: 'btn', disabled: busy, onclick: () => input.click() }, icon('clip'), busy ? 'Mengunggah…' : 'Tambah lampiran'),
        h('span', { class: 'small muted' }, `Maks. ${fmtSize(attachMax)} per file · terenkripsi`),
        input));
  }

  // ---------- pengguna & undangan (admin) ----------
  const fmtWhen = (ts) => (ts ? new Date(ts).toLocaleString('id-ID', { day: 'numeric', month: 'short', year: 'numeric', hour: '2-digit', minute: '2-digit' }) : 'belum pernah');
  async function renderUsers() {
    const ul = $('#users-list'), il = $('#invites-list');
    try {
      const [users, invites] = await Promise.all([api('GET', '/api/admin/users'), api('GET', '/api/admin/invites')]);
      if (view !== 'users') return;
      ul.replaceChildren(...users.map((u) => h('div', { class: 'user-row' },
        h('span', { class: 'user-av' }, (u.username[0] || '?').toUpperCase()),
        h('div', { class: 'user-txt' },
          h('span', { class: 'user-name' }, u.username,
            u.is_admin ? h('span', { class: 'badge accent-badge' }, 'Admin') : null,
            u.me ? h('span', { class: 'badge' }, 'Kamu') : null),
          h('span', { class: 'small muted' }, `Login terakhir: ${fmtWhen(u.last_login)} · ${fmtSize(u.vault_size + u.attach_size)}`)),
        u.me ? null : iconBtn('trash', 'Hapus user ' + u.username, () => deleteUser(u), { class: 'icon-btn vd-del' }))));
      il.replaceChildren(...(invites.length
        ? invites.map((i) => h('div', { class: 'user-row' },
            h('span', { class: 'user-av inv' }, icon('mail')),
            h('div', { class: 'user-txt' },
              h('span', { class: 'user-name' }, i.username || 'Username bebas'),
              h('span', { class: 'small muted' }, 'Berlaku sampai ' + fmtWhen(i.expires_at))),
            iconBtn('x', 'Batalkan undangan', async () => {
              if (!confirm('Batalkan undangan ini? Link-nya tidak bisa dipakai lagi.')) return;
              try { await api('DELETE', '/api/admin/invites/' + i.id); toast('Undangan dibatalkan'); renderUsers(); } catch (e) { toast(e.message); }
            })))
        : [h('p', { class: 'muted small' }, 'Tidak ada undangan aktif. Klik “Tambah user” untuk membuat link undangan.')]));
    } catch (e) {
      ul.replaceChildren(h('p', { class: 'err' }, e.message));
    }
  }
  function addUser() {
    openModal({
      title: 'Tambah user', okLabel: 'Buat link undangan',
      fields: [
        { k: 'username', label: 'Username (opsional)', placeholder: 'kosongkan agar user memilih sendiri' },
        { k: 'hours', label: 'Link berlaku selama', type: 'select', options: [['24', '24 jam'], ['72', '3 hari'], ['168', '7 hari']], value: '72' },
      ],
      async onSave(v) {
        const r = await api('POST', '/api/admin/invites', { username: v.username || undefined, hours: Number(v.hours) });
        const link = `${location.origin}/#invite=${r.code}`;
        setTimeout(() => showInvite(link, r), 0);
        if (view === 'users') renderUsers();
      },
    });
    $('#modal-body').append(h('p', { class: 'small muted' },
      'User baru membuka link undangan lalu membuat master password sendiri. Kamu tidak akan tahu password-nya, dan tidak bisa melihat isi vault-nya.'));
  }
  function showInvite(link, r) {
    openModal({
      title: 'Link undangan dibuat', okLabel: 'Salin link',
      fields: [{ k: 'link', label: 'Kirim link ini ke user baru', value: link, mono: true, readonly: true }],
      async onSave() { await copy(link, 'Link undangan'); },
    });
    $('#modal-body').append(h('p', { class: 'small muted' },
      `${r.username ? `Khusus username “${r.username}”. ` : ''}Berlaku sampai ${fmtWhen(r.expiresAt)} dan hanya bisa dipakai sekali. Simpan sekarang — link ini tidak bisa ditampilkan lagi.`));
  }
  async function deleteUser(u) {
    if (!confirm(`Hapus user “${u.username}” beserta SEMUA isi vault dan lampirannya? Tidak bisa dibatalkan.`)) return;
    if (prompt(`Ketik ${u.username} untuk konfirmasi`) !== u.username) return;
    try { await api('POST', `/api/admin/users/${u.id}/delete`, {}); toast('User dihapus'); renderUsers(); } catch (e) { toast(e.message); }
  }
  $('#user-add').addEventListener('click', addUser);

  // ---------- form item ----------
  function editItem(it, type, reopen) {
    type = it?.type || type;
    const T = TYPES[type];
    const defFolder = it ? it.folder : currentFolder()?.id;
    openModal({
      title: (it ? 'Edit ' : 'Tambah ') + T.label,
      fields: [
        { k: 'name', label: 'Nama', value: it?.name, required: true, placeholder: type === 'login' ? 'mis. Email kantor' : '' },
        ...T.fields.map((f) => ({ ...f, value: it ? it[f.k] : f.def })),
        { k: 'folder', label: 'Folder', type: 'select', options: [['', 'Tanpa folder'], ...data.folders.map((f) => [f.id, f.name])], value: defFolder || '' },
      ],
      async onSave(v) {
        v.folder = v.folder || null;
        let target = it;
        if (it) Object.assign(it, v, { updated: Date.now() });
        else {
          target = { id: uid(), type, fav: false, created: Date.now(), updated: Date.now(), ...v };
          data.items.push(target);
          if (!(filter === 'all' || filter === 'type:' + type || filter === 'folder:' + target.folder)) filter = 'type:' + type;
        }
        await persist(); go('items'); toast('Tersimpan');
        if (reopen) setTimeout(() => openView(target), 0);
      },
    });
  }

  // ---------- folder ----------
  function editFolder(f) {
    openModal({
      title: f ? 'Ganti nama folder' : 'Folder baru',
      fields: [{ k: 'name', label: 'Nama folder', value: f?.name, required: true, placeholder: 'mis. Kerja' }],
      async onSave(v) {
        if (!v.name) throw new Error('Nama wajib diisi.');
        if (data.folders.some((x) => x.name.toLowerCase() === v.name.toLowerCase() && x !== f)) throw new Error('Folder dengan nama itu sudah ada.');
        if (f) f.name = v.name;
        else { const n = { id: uid(), name: v.name }; data.folders.push(n); filter = 'folder:' + n.id; sel = null; }
        await persist(); go('items'); toast('Folder disimpan');
      },
    });
  }
  $('#folder-add').addEventListener('click', () => editFolder(null));
  $('#folder-rename').addEventListener('click', () => editFolder(currentFolder()));
  $('#folder-del').addEventListener('click', async () => {
    const f = currentFolder(); if (!f) return;
    const n = data.items.filter((i) => i.folder === f.id).length;
    if (!confirm(`Hapus folder “${f.name}”?${n ? ` ${n} item di dalamnya tetap ada (tanpa folder).` : ''}`)) return;
    data.items.forEach((i) => { if (i.folder === f.id) i.folder = null; });
    data.folders = data.folders.filter((x) => x !== f);
    await persist(); go('items', 'all'); toast('Folder dihapus');
  });

  // ---------- modal ----------
  let modalSave = null;
  function openModal({ title, fields, onSave, okLabel }) {
    $('#modal-title').textContent = title;
    $('#modal-err').textContent = '';
    $('#modal-ok').textContent = okLabel || 'Simpan';
    const body = $('#modal-body');
    body.replaceChildren(...fields.map((f) => {
      const id = 'f-' + f.k;
      let input;
      if (f.type === 'select') {
        input = h('select', { id, name: f.k }, f.options.map((o) => {
          const [val, lab] = Array.isArray(o) ? o : [o, o];
          return h('option', { value: val, selected: val === (f.value ?? '') }, lab);
        }));
      } else if (f.type === 'textarea') {
        input = h('textarea', { id, name: f.k, class: f.mono ? 'mono' : null, rows: f.rows || (f.mono ? 5 : 3), required: f.required, spellcheck: f.mono ? 'false' : null });
        input.value = f.value || '';
      } else if (f.type === 'seg') {
        const hidden = h('input', { type: 'hidden', name: f.k, value: f.value || f.options[0] });
        const seg = h('div', { class: 'seg', role: 'group', 'aria-labelledby': id + '-l' });
        const paint = () => seg.querySelectorAll('button').forEach((b) => { const on = b.dataset.v === hidden.value; b.classList.toggle('on', on); b.setAttribute('aria-pressed', String(on)); });
        f.options.forEach((o) => seg.append(h('button', { type: 'button', 'data-v': o, onclick: () => { hidden.value = o; paint(); } }, o === 'Development' ? 'Dev' : o)));
        paint();
        return h('div', { class: 'stack', style: 'gap:6px' }, h('span', { id: id + '-l', class: 'small strong', style: 'color:var(--text-2)' }, f.label), seg, hidden);
      } else {
        input = h('input', { id, name: f.k, type: f.type || (f.secret ? 'password' : 'text'), class: f.mono ? 'mono' : null, required: f.required, placeholder: f.placeholder, readonly: f.readonly, spellcheck: 'false', autocomplete: 'off' });
        input.value = f.value || '';
      }
      let control = input;
      if (f.secret && f.type !== 'textarea') {
        const row = h('div', { class: 'inline-gen' }, input,
          iconBtn('eye', 'Tampilkan', (e) => { input.type = input.type === 'password' ? 'text' : 'password'; e.currentTarget.setAttribute('aria-label', input.type === 'password' ? 'Tampilkan' : 'Sembunyikan'); }, { class: 'icon-btn lg bordered' }));
        if (f.gen) {
          const meter = h('span', { class: 'tag' });
          const upd = () => { const s = strength(input.value); meter.textContent = input.value ? `${s.label} · ${s.bits} bit` : ''; meter.style.color = SCOL[s.lvl]; };
          input.addEventListener('input', upd); upd();
          row.append(iconBtn('dice', 'Buat password acak', () => {
            input.value = generate(settings.gen) || generate({ len: 20, upper: 1, lower: 1, digit: 1, sym: 1 });
            input.type = 'text'; upd();
          }, { class: 'icon-btn lg bordered' }));
          control = h('div', { class: 'stack', style: 'gap:6px' }, row, meter);
        } else control = row;
      }
      return h('div', { class: 'stack', style: 'gap:6px' }, h('label', { for: id }, f.label), control);
    }));
    modalSave = onSave;
    $('#modal').showModal();
    setTimeout(() => body.querySelector('input:not([type=hidden]),select,textarea')?.focus(), 0);
  }
  $('#modal-cancel').addEventListener('click', () => $('#modal').close());
  const KEEP_RAW = new Set(['pass', 'key', 'note', 'body', 'priv', 'pub', 'passphrase', 'address', 'pw']);
  $('#modal-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const v = {};
    for (const [k, val] of new FormData(e.target).entries()) v[k] = KEEP_RAW.has(k) ? val : String(val).trim();
    const ok = $('#modal-ok'); ok.disabled = true;
    try { await modalSave(v); $('#modal').close(); }
    catch (ex) { $('#modal-err').textContent = ex.message; }
    finally { ok.disabled = false; }
  });
  const askPassword = (title, label) => new Promise((resolve) => {
    let done = false;
    openModal({ title, okLabel: 'Lanjut', fields: [{ k: 'pw', label, secret: true, required: true, mono: true }],
      async onSave(v) { done = true; resolve(v.pw); } });
    $('#modal').addEventListener('close', () => { if (!done) resolve(null); }, { once: true });
  });

  // ---------- generator ----------
  const GEN_OPTS = [['upper', 'Huruf besar', 'A–Z'], ['lower', 'Huruf kecil', 'a–z'], ['digit', 'Angka', '0–9'], ['sym', 'Simbol', '!@#$%&*'], ['simple', 'Hindari karakter mirip', 'tanpa I l 1 O 0']];
  let genPw = '';
  function renderGen() {
    const g = settings.gen;
    $('#gen-len').value = g.len; $('#gen-len-val').textContent = g.len;
    $('#gen-opts').replaceChildren(...GEN_OPTS.map(([k, label, sample]) =>
      h('button', { type: 'button', class: 'opt', role: 'switch', 'aria-checked': String(!!g[k]), onclick: () => { g[k] = !g[k]; saveSettings(); renderGen(); } },
        h('span', { class: 'l' }, h('b', {}, label), h('small', {}, sample)), h('span', { class: 'sw' }, h('i')))));
    const none = !charsets(g).length;
    $('#gen-err').textContent = none ? 'Pilih minimal satu jenis karakter.' : '';
    genPw = none ? '' : generate(g);
    $('#gen-pw').textContent = genPw || '—';
    const pool = charsets(g).join('').length;
    const bits = pool ? Math.round(g.len * Math.log2(pool)) : 0;
    const lvl = !bits ? 0 : bits >= 100 ? 4 : bits >= 72 ? 3 : bits >= 50 ? 2 : 1;
    $('#gen-bars').querySelectorAll('i').forEach((b, i) => { b.style.background = i < lvl ? SCOL[lvl] : ''; });
    const st = $('#gen-strength');
    st.textContent = `${['Tidak valid', 'Lemah', 'Sedang', 'Kuat', 'Sangat kuat'][lvl]} · ${bits} bit`;
    st.style.color = lvl ? SCOL[lvl] : 'var(--muted)';
    $('#gen-copy').disabled = none;
  }
  $('#gen-len').addEventListener('input', (e) => { settings.gen.len = +e.target.value; saveSettings(); renderGen(); });
  $('#gen-regen').addEventListener('click', renderGen);
  $('#gen-copy').addEventListener('click', () => genPw && copy(genPw, 'Password'));

  // ---------- ekspor ----------
  $('#exp-enc').addEventListener('click', async () => {
    const box = await seal(cryptoKey, data);
    const blob = { app: 'brankas', v: 2, kdf: 'PBKDF2-SHA256+HKDF', iter: kdfIter, salt: b64(salt), iv: box.iv, ct: box.ct };
    download(`brankas-backup-${today()}.json`, JSON.stringify(blob), 'application/json');
    toast('Backup terenkripsi diunduh');
  });
  $('#exp-json').addEventListener('click', () => {
    if (!confirm('File JSON ini TIDAK terenkripsi — siapa pun yang memegang file bisa membaca semua password. Lanjutkan?')) return;
    const out = { app: 'brankas', format: 'plain', version: 2, exported: new Date().toISOString(), folders: data.folders, items: data.items.map(({ attachments, ...rest }) => rest) };
    download(`brankas-export-${today()}.json`, JSON.stringify(out, null, 2), 'application/json');
    toast(`${data.items.length} item diekspor`);
  });
  const csvCell = (s) => { s = s == null ? '' : String(s); return /[",\n\r]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s; };
  $('#exp-csv').addEventListener('click', () => {
    const logins = data.items.filter((i) => i.type === 'login');
    if (!logins.length) { toast('Belum ada item Login untuk diekspor'); return; }
    if (!confirm('File CSV TIDAK terenkripsi. Lanjutkan?')) return;
    const rows = [['folder', 'name', 'url', 'username', 'password', 'note'],
      ...logins.map((i) => [folderName(i.folder) || '', i.name, i.url, i.user, i.pass, i.note])];
    download(`brankas-login-${today()}.csv`, '﻿' + rows.map((r) => r.map(csvCell).join(',')).join('\r\n'), 'text/csv');
    toast(`${logins.length} login diekspor ke CSV`);
  });

  // ---------- impor ----------
  function parseCSV(text) {
    const rows = []; let row = [], cell = '', q = false;
    text = text.replace(/^﻿/, '');
    for (let i = 0; i < text.length; i++) {
      const c = text[i];
      if (q) {
        if (c === '"') { if (text[i + 1] === '"') { cell += '"'; i++; } else q = false; }
        else cell += c;
      } else if (c === '"') q = true;
      else if (c === ',') { row.push(cell); cell = ''; }
      else if (c === '\n' || c === '\r') {
        if (c === '\r' && text[i + 1] === '\n') i++;
        row.push(cell); rows.push(row); row = []; cell = '';
      } else cell += c;
    }
    if (cell || row.length) { row.push(cell); rows.push(row); }
    return rows.filter((r) => r.some((x) => x.trim()));
  }
  function csvToItems(text) {
    const rows = parseCSV(text);
    if (rows.length < 2) throw new Error('CSV kosong atau tanpa header.');
    const head = rows[0].map((x) => x.trim().toLowerCase());
    const col = (...names) => head.findIndex((x) => names.includes(x));
    const c = {
      name: col('name', 'title', 'nama'), url: col('url', 'login_uri', 'website', 'uri', 'situs'),
      user: col('username', 'login_username', 'user', 'email', 'login'), pass: col('password', 'login_password', 'pass'),
      note: col('note', 'notes', 'extra', 'catatan'), folder: col('folder', 'grouping', 'group'),
    };
    if (c.pass < 0) throw new Error('Kolom "password" tidak ditemukan di CSV.');
    return rows.slice(1).map((r) => {
      const g = (k) => (c[k] >= 0 ? (r[c[k]] || '') : '');
      let name = g('name').trim();
      if (!name) { try { name = new URL(safeUrl(g('url'))).hostname; } catch { name = g('user') || 'Login'; } }
      return { type: 'login', name, url: g('url').trim(), user: g('user').trim(), pass: g('pass'), note: g('note'), _folder: g('folder').trim() };
    }).filter((i) => i.pass || i.user);
  }
  async function mergeItems(items, folders = []) {
    const now = Date.now();
    const idMap = {};
    for (const f of folders) {
      if (!f?.name) continue;
      let ex = data.folders.find((x) => x.id === f.id) || data.folders.find((x) => x.name.toLowerCase() === f.name.toLowerCase());
      if (!ex) { ex = { id: f.id || uid(), name: String(f.name) }; data.folders.push(ex); }
      idMap[f.id] = ex.id;
    }
    const folderByName = (name) => {
      if (!name) return null;
      let ex = data.folders.find((x) => x.name.toLowerCase() === name.toLowerCase());
      if (!ex) { ex = { id: uid(), name }; data.folders.push(ex); }
      return ex.id;
    };
    let added = 0, updated = 0, skipped = 0;
    for (const raw of items) {
      if (!raw || !TYPES[raw.type]) { skipped++; continue; }
      const it = { ...raw };
      delete it.attachments;
      it.folder = it._folder !== undefined ? folderByName(it._folder) : (it.folder ? idMap[it.folder] || (data.folders.some((f) => f.id === it.folder) ? it.folder : null) : null);
      delete it._folder;
      it.name = String(it.name || TYPES[it.type].label);
      it.fav = !!it.fav; it.created ||= now; it.updated ||= now;
      const byId = it.id && data.items.find((x) => x.id === it.id);
      if (byId) {
        if ((it.updated || 0) > (byId.updated || 0)) { Object.assign(byId, it); updated++; } else skipped++;
        continue;
      }
      const dup = data.items.find((x) => x.type === it.type && x.name === it.name && (it.type !== 'login' || (x.user === it.user && x.pass === it.pass)));
      if (dup && it.type === 'login') { skipped++; continue; }
      it.id = it.id || uid();
      data.items.push(it); added++;
    }
    await persist();
    return { added, updated, skipped };
  }
  async function handleImport(file) {
    const res = $('#imp-result');
    res.className = 'small'; res.textContent = 'Memproses…';
    try {
      const text = await file.text();
      let r;
      if (/\.csv$/i.test(file.name) || (!text.trim().startsWith('{') && text.includes(','))) {
        r = await mergeItems(csvToItems(text));
      } else {
        const obj = safeParse(text);
        if (!obj) throw new Error('File bukan JSON atau CSV yang valid.');
        if (isEncBlob(obj)) {
          const pw = await askPassword('Buka file backup', 'Master password file backup');
          if (pw == null) { res.textContent = 'Impor dibatalkan.'; return; }
          let dec2;
          try { dec2 = await decryptBlob(pw, obj); } catch { throw new Error('Master password backup salah.'); }
          const m = migrate(dec2.obj);
          r = await mergeItems(m.items, m.folders);
        } else if (Array.isArray(obj.items)) {
          r = await mergeItems(obj.items, obj.folders || []);
        } else if (obj.passwords || obj.apiKeys) {
          const m = migrate(obj); r = await mergeItems(m.items, m.folders);
        } else throw new Error('Format JSON tidak dikenali.');
      }
      res.className = 'small ok';
      res.textContent = `Selesai: ${r.added} item baru, ${r.updated} diperbarui, ${r.skipped} dilewati (duplikat/tidak valid).`;
      renderNav();
    } catch (ex) {
      res.className = 'small err'; res.textContent = ex.message;
    }
  }
  $('#imp-file').addEventListener('change', (e) => { const f = e.target.files[0]; e.target.value = ''; if (f) handleImport(f); });
  const drop = $('#drop');
  ['dragenter', 'dragover'].forEach((ev) => drop.addEventListener(ev, (e) => { e.preventDefault(); drop.classList.add('over'); }));
  ['dragleave', 'drop'].forEach((ev) => drop.addEventListener(ev, () => drop.classList.remove('over')));
  drop.addEventListener('drop', (e) => { e.preventDefault(); const f = e.dataTransfer.files[0]; if (f) handleImport(f); });

  // ---------- pengaturan ----------
  function renderSettings() {
    $('#autolock').value = String(settings.autolock);
    $('#clipclear').checked = !!settings.clipclear;
    $('#acc-name').textContent = username;
  }
  $('#autolock').addEventListener('change', (e) => { settings.autolock = +e.target.value; saveSettings(); toast('Disimpan'); });
  $('#clipclear').addEventListener('change', (e) => { settings.clipclear = e.target.checked; saveSettings(); });

  $('#legacy-btn').addEventListener('click', async () => {
    const text = localStorage.getItem(LEGACY_KEY);
    if (!text) return;
    await handleImport({ name: 'vault-lama.json', text: async () => text });
    if ($('#imp-result').classList.contains('ok') && confirm('Impor selesai. Hapus salinan vault lama dari browser ini?')) {
      localStorage.removeItem(LEGACY_KEY);
      $('#legacy-wrap').hidden = true;
    }
  });

  $('#chg-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const err = $('#chg-err'); err.textContent = '';
    const oldPw = $('#chg-old').value, newPw = $('#chg-new').value;
    if (newPw.length < 10) { err.textContent = 'Master password baru minimal 10 karakter.'; return; }
    const btn = e.target.querySelector('button[type=submit]'); btn.disabled = true;
    try {
      await saving;
      const oldK = await deriveKeys(oldPw, salt, kdfIter);
      const s2 = crypto.getRandomValues(new Uint8Array(16));
      const k = await deriveKeys(newPw, s2, ITER);
      const vault = await seal(k.encKey, data);
      const r = await api('POST', '/api/account/password', { authKey: oldK.authKey, newKdfSalt: b64(s2), newKdfIter: ITER, newAuthKey: k.authKey, vault, rev });
      cryptoKey = k.encKey; salt = s2; kdfIter = ITER; rev = r.rev;
      await saveSession();
      e.target.reset();
      toast('Master password diganti. Perangkat lain sudah dikeluarkan.');
    } catch (ex) { err.textContent = ex.message; }
    finally { btn.disabled = false; }
  });

  $('#del-acc').addEventListener('click', async () => {
    if (!confirm(`Hapus akun “${username}” beserta SEMUA isinya dari server? Tidak bisa dibatalkan.`)) return;
    const pw = await askPassword('Hapus akun', 'Master password untuk konfirmasi');
    if (pw == null) return;
    try {
      const k = await deriveKeys(pw, salt, kdfIter);
      await api('POST', '/api/account/delete', { authKey: k.authKey });
      cryptoKey = null; // sesi sudah dihapus server
      localStorage.removeItem('brankas.lastUser');
      lock('Akun sudah dihapus.');
    } catch (ex) { toast(ex.message); }
  });

  // ---------- boot ----------
  if (!window.crypto?.subtle) {
    document.body.textContent = 'Browser ini tidak mendukung Web Crypto. Buka lewat https:// atau localhost.';
    return;
  }
  api('GET', '/api/config')
    .then(async (c) => {
      signupMode = c.signup === 'open' && c.first ? 'open-first' : c.signup;
      if (c.attachMax) attachMax = c.attachMax;
      tsSiteKey = c.turnstileSiteKey || null;
      const inv = location.hash.match(/^#invite=([A-Za-z0-9_-]{16,64})$/);
      if (inv) {
        history.replaceState(null, '', location.pathname);
        try { const r = await api('POST', '/api/invite/check', { code: inv[1] }); invite = { code: inv[1], username: r.username }; showLock(); }
        catch (e) { showLock(e.message); }
        return;
      }
      if (await restoreSession()) enterApp(safeParse(sessionStorage.getItem(UI_KEY)));
      else showLock();
    })
    .catch(() => {
      showLock(location.protocol === 'file:'
        ? 'Aplikasi ini perlu dijalankan lewat server (npm start), bukan dibuka sebagai file.'
        : 'Server tidak bisa dihubungi.');
      $('#lock-btn').disabled = true;
    });
})();
