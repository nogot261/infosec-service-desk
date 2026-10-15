"""Пароли, проверка ввода и токены форм."""

import hashlib
import hmac
import secrets

ITERATIONS = 310_000


def password_hash(password: str) -> str:
    if len(password) < 10:
        raise ValueError("Пароль должен содержать не менее 10 символов")
    salt = secrets.token_bytes(16)
    key = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, ITERATIONS)
    return f"pbkdf2_sha256${ITERATIONS}${salt.hex()}${key.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        algorithm, iterations, salt, expected = stored.split("$")
        if algorithm != "pbkdf2_sha256":
            return False
        key = hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), bytes.fromhex(salt), int(iterations)
        )
        return hmac.compare_digest(key, bytes.fromhex(expected))
    except (ValueError, TypeError, OverflowError):
        return False


def clean_text(value: str, name: str, *, minimum: int = 1, maximum: int = 500) -> str:
    cleaned = value.strip()
    if not minimum <= len(cleaned) <= maximum:
        raise ValueError(f"{name}: допустимая длина от {minimum} до {maximum} символов")
    return cleaned


def new_csrf_token() -> str:
    return secrets.token_urlsafe(32)


def check_csrf(expected: str | None, received: str | None) -> bool:
    return bool(expected and received and hmac.compare_digest(expected, received))
