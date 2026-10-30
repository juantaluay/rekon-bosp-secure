# Catatan Keamanan — Rekon BOSP Secure

## Perubahan keamanan utama

1. **Password di-hash** dengan bcryptjs (cost 12). Tidak ada password plain text di storage setelah migrasi.
2. **JWT + cookie HttpOnly** — session aman, tidak mudah dicuri via XSS.
3. **Middleware `requireAuth`** di semua endpoint sensitif.
4. **RBAC** — Operator Sekolah hanya akses data sekolahnya sendiri.
5. **Upload terproteksi** — file hanya bisa diunduh setelah login (`/api/file/...`).
6. **Rate limiting** — login dibatasi 15x / 15 menit.
7. **Helmet** — header keamanan HTTP.
8. **Audit log** — setiap aksi penting dicatat di `data/audit.log`.
9. **Password tidak pernah** dikirim ke frontend.

## Migrasi dari versi lama

```bash
cp .env.example .env
# Edit JWT_SECRET!
npm install
npm run hash-passwords   # hash password plain yang masih ada
npm start
```

Server juga **auto-upgrade** password plain saat user login berhasil (sekali).

## Frontend

Agar cookie terkirim, pastikan semua `fetch` ke API memakai:

```javascript
credentials: 'include'
```

Atau simpan `token` dari response login dan kirim:

```
Authorization: Bearer <token>
```

Kedua cara didukung server.

## Production wajib

- [ ] `NODE_ENV=production`
- [ ] `JWT_SECRET` kuat & unik
- [ ] Ganti password admin & operator
- [ ] HTTPS (reverse proxy)
- [ ] `CORS_ORIGIN` spesifik
- [ ] Backup `data/` rutin
