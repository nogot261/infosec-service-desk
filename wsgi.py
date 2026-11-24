"""Точка входа для Render и Gunicorn.

Публичный сервер работает только с учебными данными. Пароли демо-пользователей
на Render задаются через секретную переменную окружения.
"""
import os
import shutil
from pathlib import Path

from infosec_desk.db import connect
from infosec_desk.security import password_hash
from infosec_desk.web import create_app

ROOT = Path(__file__).resolve().parent
key = os.environ.get("INFOSEC_SECRET_KEY", "")
if len(key) < 32:
    raise RuntimeError("INFOSEC_SECRET_KEY must be set to a random secret of 32+ chars")

demo_password = os.environ.get("INFOSEC_DEMO_PASSWORD", "")
if len(demo_password) < 14:
    raise RuntimeError("INFOSEC_DEMO_PASSWORD must be set to a random password of 14+ chars")

db_path = Path(os.environ.get("INFOSEC_DB_PATH", "/tmp/infosec_desk_render_demo.sqlite3"))
db_path.parent.mkdir(parents=True, exist_ok=True)
if not db_path.exists():
    shutil.copy2(ROOT / "instance" / "demo.sqlite3", db_path)

# В публичной демонстрации нельзя оставлять известные учебные пароли.
with connect(db_path) as db:
    for username in ("admin", "operator", "employee"):
        db.execute(
            "UPDATE users SET password_hash=? WHERE username=?",
            (password_hash(demo_password), username),
        )

app = create_app(db_path=db_path, secret_key=key)
