"""Проверка первого запуска и служебных команд."""

import os
import subprocess
import sys
from pathlib import Path

from infosec_desk.db import connect
from infosec_desk.security import verify_password

ROOT = Path(__file__).resolve().parents[1]


def test_same_launcher_initializes_database(tmp_path):
    path = tmp_path / "service.sqlite3"
    env = os.environ.copy()
    env["INFOSEC_DB_PATH"] = str(path)
    result = subprocess.run(
        [sys.executable, str(ROOT / "run.py"), "init-db"],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
        check=True,
    )
    assert "База данных готова" in result.stdout
    with connect(path) as db:
        assert db.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0


def test_bootstrap_password_is_random_and_hashed(tmp_path, monkeypatch):
    from infosec_desk import __main__

    path = tmp_path / "first.sqlite3"
    calls = []
    import uvicorn

    monkeypatch.setattr(uvicorn, "run", lambda app, **kwargs: calls.append(kwargs))
    monkeypatch.setattr(sys, "argv", ["run.py", "--db", str(path), "--port", "8008"])
    __main__.main()

    with connect(path) as db:
        user = db.execute("SELECT * FROM users WHERE username='admin'").fetchone()
    assert user is not None
    assert user["password_hash"].startswith("pbkdf2_sha256$")
    assert calls and calls[0]["port"] == 8008


def test_no_exposing_service_without_secret(tmp_path, monkeypatch):
    import pytest
    from infosec_desk import __main__

    path = tmp_path / "service.sqlite3"
    monkeypatch.delenv("INFOSEC_SECRET_KEY", raising=False)
    monkeypatch.setattr(sys, "argv", ["run.py", "--db", str(path), "--host", "0.0.0.0"])
    with pytest.raises(SystemExit):
        __main__.main()
