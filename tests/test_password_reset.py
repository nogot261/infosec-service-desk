"""Проверки восстановления пароля администратора."""

import sys

import pytest

from infosec_desk import __main__
from infosec_desk.db import connect, initialize
from infosec_desk.service import authenticate, create_user, reset_admin_password


def test_reset_password_for_existing_admin(tmp_path, monkeypatch, capsys):
    path = tmp_path / "existing.sqlite3"
    initialize(path)
    user_id = create_user(path, "admin", "Администратор", "OldPassword123!", "admin")
    monkeypatch.setattr(sys, "argv", ["run.py", "reset-password", "--db", str(path)])
    passwords = iter(["NewPassword123!", "NewPassword123!"])
    monkeypatch.setattr(__main__.getpass, "getpass", lambda prompt: next(passwords))
    __main__.main()
    assert authenticate(path, "admin", "OldPassword123!") is None
    assert authenticate(path, "admin", "NewPassword123!")["id"] == user_id
    with connect(path) as db:
        assert db.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 1
        assert db.execute("SELECT action FROM audit_events").fetchone()[0] == "password_reset"
    assert "Пароль администратора admin изменен" in capsys.readouterr().out


def test_reset_password_rejects_mismatch(tmp_path, monkeypatch):
    path = tmp_path / "service.sqlite3"
    initialize(path)
    create_user(path, "admin", "Администратор", "OldPassword123!", "admin")
    monkeypatch.setattr(sys, "argv", ["run.py", "reset-password", "--db", str(path)])
    passwords = iter(["NewPassword123!", "WrongPassword123!"])
    monkeypatch.setattr(__main__.getpass, "getpass", lambda prompt: next(passwords))
    with pytest.raises(SystemExit):
        __main__.main()
    assert authenticate(path, "admin", "OldPassword123!") is not None


def test_reset_password_rejects_non_admin(tmp_path):
    path = tmp_path / "service.sqlite3"
    initialize(path)
    create_user(path, "employee", "Сотрудник", "OldPassword123!", "requester")
    with pytest.raises(ValueError, match="администратор"):
        reset_admin_password(path, "employee", "NewPassword123!")
    assert authenticate(path, "employee", "OldPassword123!") is not None
