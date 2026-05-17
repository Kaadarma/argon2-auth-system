# Secure Authentication System with Argon2id

Implementasi sistem autentikasi modern menggunakan **Argon2id**, **JWT**, dan **SQLite** berbasis **Python Flask**.

Sistem ini mendukung:
- Register & Login
- Access Token dan Refresh Token
- Rate limiting (anti brute-force)
- Password validation
- Auto rehash Argon2
- Protected endpoint authentication

---

## Struktur Folder

```text
auth-argon2-jwt/
│
├── app.py              # Flask routes & protected endpoints
├── auth.py             # Core authentication logic
├── app.db              # SQLite database (auto-generated)
├── requirements.txt    # Python dependencies
└── README.md
```

---

## Teknologi yang Digunakan

| Teknologi | Fungsi |
|------------|--------|
| Flask | Web framework |
| Argon2id | Password hashing |
| SQLite | Database lokal |
| JWT | Authentication token |
| Python | Backend language |

---

## Fitur

| Fitur | Keterangan |
|-------|------------|
| Argon2id | Hash password modern (memory-hard) |
| SQLite | Database lokal tanpa setup server |
| JWT Authentication | Access token + Refresh token |
| Refresh Token | Login tetap aktif tanpa input password ulang |
| Rate Limiting | Blokir brute-force login |
| Anti Timing Attack | Dummy verify jika username tidak ditemukan |
| Password Validation | Minimal 8 karakter, huruf besar, angka, simbol |
| Auto Rehash | Update hash otomatis jika parameter Argon2 berubah |
| Protected Routes | Endpoint membutuhkan Bearer token |

---

## Endpoint API

| Method | Endpoint | Deskripsi |
|--------|----------|-----------|
| POST | `/register` | Registrasi user baru |
| POST | `/login` | Login dan mendapatkan access token |
| POST | `/refresh` | Generate access token baru |
| POST | `/logout` | Logout dan revoke refresh token |
| GET | `/me` | Data user (protected route) |

---

## Setup dan Menjalankan Project

### 1. Clone Repository

```bash
git clone https://github.com/username/auth-argon2-jwt.git
cd auth-argon2-jwt
```

---

### 2. Install Dependencies

```bash
pip install -r requirements.txt
```

---

### 3. Jalankan Flask App

```bash
python app.py
```

Server berjalan di:

```text
http://localhost:5000
```

---

## Contoh API Request

### Register

```bash
curl -X POST http://localhost:5000/register \
-H "Content-Type: application/json" \
-d '{
"username":"budi",
"email":"budi@email.com",
"password":"Rahasia123!"
}'
```

---

### Login

```bash
curl -X POST http://localhost:5000/login \
-H "Content-Type: application/json" \
-d '{
"username":"budi",
"password":"Rahasia123!"
}'
```

Contoh response:

```json
{
  "success": true,
  "access_token": "eyJhbGciOi...",
  "refresh_token": "4fd83a...",
  "expires_in": 900
}
```

---

### Protected Endpoint (`/me`)

Gunakan access token:

```bash
curl http://localhost:5000/me \
-H "Authorization: Bearer <access_token>"
```

---

### Refresh Token

```bash
curl -X POST http://localhost:5000/refresh \
-H "Content-Type: application/json" \
-d '{
"refresh_token":"<refresh_token>"
}'
```

---

### Logout

```bash
curl -X POST http://localhost:5000/logout \
-H "Content-Type: application/json" \
-d '{
"refresh_token":"<refresh_token>"
}'
```

---

## Konsep Sistem

Alur autentikasi:

```text
Register
Password
↓
Argon2id Hash
↓
Database

Login
Password
↓
Argon2 Verify
↓
JWT Access + Refresh Token
↓
Protected API Access
```

---

## Security Features

- Argon2id password hashing
- JWT access token authentication
- Refresh token mechanism
- Brute-force protection
- Anti timing attack
- Password strength validation
- Auto hash migration (rehash)

---

## Production Notes

Untuk deployment production:

- Gunakan environment variable untuk `JWT_SECRET`
- Aktifkan HTTPS/TLS
- Gunakan PostgreSQL/MySQL untuk skala besar
- Tambahkan logging dan monitoring
- Simpan secret di `.env`

---

## License

Project ini dibuat untuk pembelajaran dan implementasi authentication system modern menggunakan Argon2id dan JWT.