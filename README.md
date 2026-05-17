# Sistem Auth Argon2id

Implementasi sistem login/register menggunakan **Argon2id** tersedia dalam dua versi:
Python (Flask) dan Node.js (Express). Keduanya menggunakan logika yang identik.

---

## Struktur Folder

```
auth-argon2/
├── python/
│   ├── auth.py          ← Core logic (Argon2, JWT, SQLite, rate limiting)
│   ├── app.py           ← Flask web app (routes)
│   └── requirements.txt ← Dependencies
│
└── nodejs/
    ├── auth.js          ← Core logic (Argon2, JWT, SQLite, rate limiting)
    ├── app.js           ← Express web app (routes)
    └── package.json     ← Dependencies
```

---

## Fitur

| Fitur | Keterangan |
|-------|------------|
| Argon2id | Hash password dengan t=3, m=64MB, p=4 |
| SQLite | Database lokal, tanpa setup server |
| JWT | Access token (15 menit) + Refresh token (7 hari) |
| Rate limiting | Blokir setelah 5 kali gagal login dalam 5 menit |
| Anti timing attack | Dummy verify jika username tidak ditemukan |
| Password validation | Min 8 karakter, huruf kapital, angka, spesial |
| Auto rehash | Perbarui hash otomatis jika parameter Argon2 berubah |

---

## Endpoints

| Method | Endpoint | Keterangan |
|--------|----------|------------|
| POST | `/register` | Daftar akun baru |
| POST | `/login` | Login, dapat access + refresh token |
| POST | `/refresh` | Perbarui access token |
| POST | `/logout` | Logout (hapus refresh token) |
| GET | `/me` | Info user (butuh Authorization header) |

---

## Python (Flask)

### Setup
```bash
cd python
pip install -r requirements.txt
python app.py
# → http://localhost:5000
```

### Contoh request
```bash
# Register
curl -X POST http://localhost:5000/register \
     -H "Content-Type: application/json" \
     -d '{"username":"budi","email":"budi@email.com","password":"Rahasia123!"}'

# Login
curl -X POST http://localhost:5000/login \
     -H "Content-Type: application/json" \
     -d '{"username":"budi","password":"Rahasia123!"}'

# Akses endpoint protected
curl http://localhost:5000/me \
     -H "Authorization: Bearer <access_token>"

# Refresh token
curl -X POST http://localhost:5000/refresh \
     -H "Content-Type: application/json" \
     -d '{"refresh_token":"<refresh_token>"}'

# Logout
curl -X POST http://localhost:5000/logout \
     -H "Content-Type: application/json" \
     -d '{"refresh_token":"<refresh_token>"}'
```

---

## Node.js (Express)

### Setup
```bash
cd nodejs
npm install
npm start
# → http://localhost:3000
```

### Contoh request
```bash
# Register
curl -X POST http://localhost:3000/register \
     -H "Content-Type: application/json" \
     -d '{"username":"budi","email":"budi@email.com","password":"Rahasia123!"}'

# Login
curl -X POST http://localhost:3000/login \
     -H "Content-Type: application/json" \
     -d '{"username":"budi","password":"Rahasia123!"}'

# Akses endpoint protected
curl http://localhost:3000/me \
     -H "Authorization: Bearer <accessToken>"

# Refresh token
curl -X POST http://localhost:3000/refresh \
     -H "Content-Type: application/json" \
     -d '{"refreshToken":"<refreshToken>"}'

# Logout
curl -X POST http://localhost:3000/logout \
     -H "Content-Type: application/json" \
     -d '{"refreshToken":"<refreshToken>"}'
```

---

## Catatan Production

- Ganti `JWT_SECRET` dengan environment variable (`os.environ` / `process.env`)
- Aktifkan HTTPS
- Ganti SQLite dengan PostgreSQL/MySQL untuk skala besar
- Tambahkan logging & monitoring
