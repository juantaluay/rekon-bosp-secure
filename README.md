# Rekon BOSP — Server Node.js (Versi Aman)

Backend **Node.js (Express)** + penyimpanan **file JSON** untuk Dashboard Rekonsiliasi Dana BOSP Kabupaten Minahasa Tenggara.

**Versi 1.1.0-secure** — sudah diperbaiki dari sisi keamanan.

## Apa yang diamankan

| Item | Sebelum | Sesudah |
|------|---------|---------|
| Password | Plain text di JSON | bcrypt hash (cost 12) |
| Auth | Tidak ada di hampir semua endpoint | JWT + cookie HttpOnly + middleware `requireAuth` |
| Role | Hanya dicek di frontend | RBAC di backend (Admin Dinas / Operator / BUD) |
| Data Operator | Bisa lihat semua sekolah | Hanya sekolahnya sendiri |
| Upload | Folder `/uploads` publik | Hanya via `/api/file/:name` setelah login |
| Rate limit | Tidak ada | Umum + khusus login |
| Header | Default | Helmet |
| Audit | Tidak ada | `data/audit.log` |
| Password di response | Dikirim ke client | Dihapus (`sanitizeUser`) |

## Instalasi

```bash
cd rekon-bosp-server-secure
cp .env.example .env
# Edit .env — WAJIB isi JWT_SECRET yang kuat
npm install
npm run init-db
# Jika sudah punya users.json lama (password plain):
npm run hash-passwords
npm start
```

Buka: http://localhost:3000

### Akun default (GANTI SEBELUM PRODUKSI)

| Username  | Password        | Peran            |
|-----------|-----------------|------------------|
| admin     | admin2024       | Admin Dinas      |
| operator  | operator2024    | Operator Sekolah |

## Frontend

Frontend lama (`public/index.html`) masih berfungsi. Agar cookie auth terkirim, pastikan request fetch/XHR menggunakan:

```js
credentials: 'include'
```

atau menyimpan `token` dari response login dan mengirim header:

```js
Authorization: Bearer <token>
```

Server mendukung **kedua** cara (cookie HttpOnly dan Bearer token).

## API ringkas

| Method | Path | Auth | Keterangan |
|--------|------|------|------------|
| GET | /api/health | - | Health check |
| POST | /api/login | - | Login → cookie + token |
| POST | /api/logout | ✓ | Logout |
| GET | /api/me | ✓ | User saat ini |
| GET | /api/data?year= | ✓ | Data (disaring per role) |
| POST | /api/save | ✓ | Simpan data |
| GET/POST | /api/schools | ✓ | Admin saja untuk write |
| GET/POST | /api/users | ✓ | Admin saja |
| POST | /api/upload | ✓ | Upload PDF |
| GET | /api/file/:name | ✓ | Download PDF |

## Production checklist

1. Set `NODE_ENV=production`
2. Set `JWT_SECRET` panjang & acak (jangan commit)
3. Ganti semua password default
4. Jalankan di belakang HTTPS (nginx / Caddy)
5. Set `CORS_ORIGIN` ke domain resmi
6. Backup rutin folder `data/`
7. Monitor `data/audit.log`

```bash
npm install -g pm2
pm2 start server.js --name rekon-bosp
pm2 save && pm2 startup
```

## Catatan

Ini masih penyimpanan berbasis file JSON. Untuk skala lebih besar / multi-server, pertimbangkan migrasi ke PostgreSQL + session store terpusat.
