"""Сопровождение: резервная копия SQLite и контроль локального пакета обновления."""

import json
import sqlite3
from pathlib import Path

PACKAGE_VERSION = "1.0.0"


def backup_database(db_path, target_path):
    """Создает согласованную копию работающей базы через SQLite Backup API."""
    original = Path(db_path).resolve()
    target = Path(target_path).resolve()
    if not original.is_file():
        raise ValueError("Исходная база данных не найдена")
    if original == target:
        raise ValueError("Резервную копию нельзя записать поверх исходной базы")
    if target.exists():
        raise ValueError("Файл резервной копии уже существует")
    target.parent.mkdir(parents=True, exist_ok=True)
    try:
        with sqlite3.connect(original) as src, sqlite3.connect(target) as dst:
            src.backup(dst)
            result = dst.execute("PRAGMA integrity_check").fetchone()[0]
            if result != "ok":
                raise ValueError("Резервная копия не прошла проверку целостности")
    except Exception:
        if target.exists():
            target.unlink()
        raise
    return target


def inspect_update_manifest(path):
    """Проверяет метаданные локального релиза без загрузки и исполнения кода."""
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError("Некорректный файл манифеста") from exc
    if not isinstance(data, dict) or set(data) != {"format", "version", "sha256"}:
        raise ValueError("Некорректная структура манифеста")
    version, sha256 = data["version"], data["sha256"]
    if data["format"] != "infosec-release-v1":
        raise ValueError("Неподдерживаемый формат манифеста")
    if not isinstance(version, str) or not (
        len(version.split(".")) == 3 and all(p.isdigit() for p in version.split("."))
    ):
        raise ValueError("Некорректная версия релиза")
    if not isinstance(sha256, str) or len(sha256) != 64 or any(
        c not in "0123456789abcdef" for c in sha256.lower()
    ):
        raise ValueError("Некорректная контрольная сумма")
    current = tuple(int(p) for p in PACKAGE_VERSION.split("."))
    requested = tuple(int(p) for p in version.split("."))
    return {"installed": PACKAGE_VERSION, "available": version,
            "needs_update": requested > current, "sha256": sha256.lower()}
