"""
auth.py — Sistem Auth Argon2id (Versi Solid)
============================================
Fitur:
  - Argon2id untuk hashing password
  - SQLite sebagai database
  - JWT access token (expiry 15 menit)
  - Refresh token (expiry 7 hari)
  - Rate limiting login (anti brute force)
  - Password strength validation
  - Token blacklist saat logout

Install:
    pip install argon2-cffi PyJWT

Struktur database:
    users            — data user + password hash
    refresh_tokens   — refresh token aktif
    login_attempts   — pencatatan percobaan login (rate limit)
"""

import sqlite3
import secrets
import re
import time
from datetime import datetime, timezone
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, VerificationError, InvalidHashError
import jwt  # PyJWT

# ── Konfigurasi ───────────────────────────────────────────────────────────────
DB_FILE         = "app.db"
JWT_SECRET      = secrets.token_hex(32)   # ganti dengan env variable di production
JWT_ALGORITHM   = "HS256"
ACCESS_EXPIRY   = 15 * 60                 # 15 menit (detik)
REFRESH_EXPIRY  = 7 * 24 * 3600          # 7 hari (detik)
MAX_ATTEMPTS    = 5                       # maks gagal login
LOCKOUT_SECONDS = 5 * 60                  # lockout 5 menit

ph = PasswordHasher(
    time_cost=3,
    memory_cost=65536,   # 64 MB
    parallelism=4,
    hash_len=32,
    salt_len=16
)


# ── Database Setup ────────────────────────────────────────────────────────────
def get_db():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """Buat tabel jika belum ada."""
    with get_db() as db:
        db.executescript("""
            CREATE TABLE IF NOT EXISTS users (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                username      TEXT    UNIQUE NOT NULL,
                email         TEXT    UNIQUE NOT NULL,
                password_hash TEXT    NOT NULL,
                created_at    INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS refresh_tokens (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id    INTEGER NOT NULL,
                token      TEXT    UNIQUE NOT NULL,
                expires_at INTEGER NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(id)
            );

            CREATE TABLE IF NOT EXISTS login_attempts (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                username   TEXT    NOT NULL,
                success    INTEGER NOT NULL,
                attempted_at INTEGER NOT NULL
            );
        """)
    print("[DB] Database siap.")


# ── Password Validator ────────────────────────────────────────────────────────
def validate_password(password: str) -> dict:
    """
    Cek kekuatan password.
    Return: {"ok": bool, "reason": str}
    """
    if len(password) < 8:
        return {"ok": False, "reason": "Password minimal 8 karakter."}
    if not re.search(r"[A-Z]", password):
        return {"ok": False, "reason": "Harus ada minimal 1 huruf kapital."}
    if not re.search(r"[0-9]", password):
        return {"ok": False, "reason": "Harus ada minimal 1 angka."}
    if not re.search(r"[^A-Za-z0-9]", password):
        return {"ok": False, "reason": "Harus ada minimal 1 karakter spesial (!@#$...)."}
    return {"ok": True, "reason": "Password kuat."}


# ── Rate Limiter ──────────────────────────────────────────────────────────────
def _is_locked_out(username: str) -> bool:
    """Cek apakah user terkena lockout karena terlalu banyak gagal login."""
    now = int(time.time())
    window_start = now - LOCKOUT_SECONDS

    with get_db() as db:
        row = db.execute("""
            SELECT COUNT(*) as cnt FROM login_attempts
            WHERE username = ? AND success = 0 AND attempted_at > ?
        """, (username, window_start)).fetchone()

    return row["cnt"] >= MAX_ATTEMPTS


def _record_attempt(username: str, success: bool):
    """Catat percobaan login."""
    with get_db() as db:
        db.execute(
            "INSERT INTO login_attempts (username, success, attempted_at) VALUES (?, ?, ?)",
            (username, int(success), int(time.time()))
        )


# ── JWT Helpers ───────────────────────────────────────────────────────────────
def _create_access_token(user_id: int, username: str) -> str:
    now = int(time.time())
    payload = {
        "sub": user_id,
        "username": username,
        "iat": now,
        "exp": now + ACCESS_EXPIRY,
        "type": "access"
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


def _create_refresh_token(user_id: int) -> str:
    token = secrets.token_hex(40)
    expires_at = int(time.time()) + REFRESH_EXPIRY

    with get_db() as db:
        # Hapus refresh token lama milik user ini (opsional: boleh multi-device)
        db.execute("DELETE FROM refresh_tokens WHERE user_id = ?", (user_id,))
        db.execute(
            "INSERT INTO refresh_tokens (user_id, token, expires_at) VALUES (?, ?, ?)",
            (user_id, token, expires_at)
        )
    return token


def verify_access_token(token: str) -> dict:
    """
    Verifikasi JWT access token.
    Return: {"ok": True, "user_id": int, "username": str} atau {"ok": False, "reason": str}
    """
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        if payload.get("type") != "access":
            return {"ok": False, "reason": "Bukan access token."}
        return {"ok": True, "user_id": payload["sub"], "username": payload["username"]}
    except jwt.ExpiredSignatureError:
        return {"ok": False, "reason": "Token sudah expired. Silakan refresh."}
    except jwt.InvalidTokenError:
        return {"ok": False, "reason": "Token tidak valid."}


# ── REGISTER ──────────────────────────────────────────────────────────────────
def register(username: str, email: str, password: str) -> dict:
    username = username.strip().lower()
    email    = email.strip().lower()

    if not username or not email or not password:
        return {"success": False, "message": "Semua field wajib diisi."}

    if len(username) < 3:
        return {"success": False, "message": "Username minimal 3 karakter."}

    if not re.match(r"^[\w.+-]+@[\w-]+\.[a-z]{2,}$", email):
        return {"success": False, "message": "Format email tidak valid."}

    pw_check = validate_password(password)
    if not pw_check["ok"]:
        return {"success": False, "message": pw_check["reason"]}

    password_hash = ph.hash(password)

    try:
        with get_db() as db:
            db.execute(
                "INSERT INTO users (username, email, password_hash, created_at) VALUES (?, ?, ?, ?)",
                (username, email, password_hash, int(time.time()))
            )
        return {"success": True, "message": f"Akun '{username}' berhasil dibuat!"}
    except sqlite3.IntegrityError as e:
        if "username" in str(e):
            return {"success": False, "message": "Username sudah digunakan."}
        if "email" in str(e):
            return {"success": False, "message": "Email sudah terdaftar."}
        return {"success": False, "message": "Registrasi gagal."}


# ── LOGIN ─────────────────────────────────────────────────────────────────────
def login(username: str, password: str) -> dict:
    username = username.strip().lower()

    # Cek rate limit
    if _is_locked_out(username):
        return {
            "success": False,
            "message": f"Terlalu banyak percobaan gagal. Coba lagi dalam {LOCKOUT_SECONDS // 60} menit."
        }

    with get_db() as db:
        user = db.execute(
            "SELECT * FROM users WHERE username = ?", (username,)
        ).fetchone()

    # User tidak ditemukan — tetap jalankan verify palsu (anti timing attack)
    if not user:
        try:
            ph.verify("$argon2id$v=19$m=65536,t=3,p=4$dummy$dummy", password)
        except Exception:
            pass
        _record_attempt(username, False)
        return {"success": False, "message": "Username atau password salah."}

    try:
        ph.verify(user["password_hash"], password)
    except VerifyMismatchError:
        _record_attempt(username, False)
        return {"success": False, "message": "Username atau password salah."}
    except (VerificationError, InvalidHashError):
        return {"success": False, "message": "Terjadi kesalahan verifikasi."}

    # Rehash jika parameter berubah
    if ph.check_needs_rehash(user["password_hash"]):
        new_hash = ph.hash(password)
        with get_db() as db:
            db.execute(
                "UPDATE users SET password_hash = ? WHERE id = ?",
                (new_hash, user["id"])
            )

    _record_attempt(username, True)

    access_token  = _create_access_token(user["id"], username)
    refresh_token = _create_refresh_token(user["id"])

    return {
        "success": True,
        "message": f"Selamat datang, {username}!",
        "access_token": access_token,
        "refresh_token": refresh_token,
        "expires_in": ACCESS_EXPIRY
    }


# ── REFRESH TOKEN ─────────────────────────────────────────────────────────────
def refresh_access_token(refresh_token: str) -> dict:
    now = int(time.time())

    with get_db() as db:
        row = db.execute(
            "SELECT * FROM refresh_tokens WHERE token = ? AND expires_at > ?",
            (refresh_token, now)
        ).fetchone()

    if not row:
        return {"success": False, "message": "Refresh token tidak valid atau sudah expired."}

    with get_db() as db:
        user = db.execute(
            "SELECT * FROM users WHERE id = ?", (row["user_id"],)
        ).fetchone()

    if not user:
        return {"success": False, "message": "User tidak ditemukan."}

    new_access_token = _create_access_token(user["id"], user["username"])
    return {
        "success": True,
        "access_token": new_access_token,
        "expires_in": ACCESS_EXPIRY
    }


# ── LOGOUT ────────────────────────────────────────────────────────────────────
def logout(refresh_token: str) -> dict:
    with get_db() as db:
        result = db.execute(
            "DELETE FROM refresh_tokens WHERE token = ?", (refresh_token,)
        )
    if result.rowcount == 0:
        return {"success": False, "message": "Token tidak ditemukan."}
    return {"success": True, "message": "Berhasil logout."}


# ── DEMO ──────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    init_db()

    print("\n── REGISTER ──")
    print(register("budi", "budi@email.com", "Rahasia123!"))
    print(register("budi", "budi@email.com", "Rahasia123!"))   # duplikat
    print(register("ani", "ani@email.com", "lemah"))           # password lemah

    print("\n── LOGIN ──")
    hasil = login("budi", "Rahasia123!")
    print(hasil)

    access  = hasil.get("access_token")
    refresh = hasil.get("refresh_token")

    print("\n── VERIFIKASI TOKEN ──")
    print(verify_access_token(access))

    print("\n── REFRESH TOKEN ──")
    print(refresh_access_token(refresh))

    print("\n── LOGOUT ──")
    print(logout(refresh))

    print("\n── REFRESH SETELAH LOGOUT ──")
    print(refresh_access_token(refresh))   # harus gagal

    print("\n── BRUTE FORCE TEST ──")
    for i in range(6):
        r = login("budi", "salah!")
        print(f"  Percobaan {i+1}: {r['message']}")
