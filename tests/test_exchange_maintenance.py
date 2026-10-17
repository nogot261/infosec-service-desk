"""Тесты файлового взаимодействия и безопасного резервирования."""

import json
import sqlite3

import pytest

from infosec_desk.db import connect
from infosec_desk.exchange import export_assets, import_assets
from infosec_desk.maintenance import backup_database, inspect_update_manifest


def test_assets_json_roundtrip(db_path, tmp_path):
    source = tmp_path / "assets.json"
    assert export_assets(db_path, source) == 1
    assert source.read_text(encoding="utf-8").startswith("{\n")
    data = json.loads(source.read_text(encoding="utf-8"))
    data["items"].append({"inventory_no": "FW-02", "name": "Антивирус",
                          "location": "Серверная", "protection_class": "Базовый",
                          "description": "Новая система"})
    source.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
    result = import_assets(db_path, source)
    assert result == {"added": 1, "skipped": 1}
    assert import_assets(db_path, source) == {"added": 0, "skipped": 2}
    with connect(db_path) as db:
        assert db.execute("SELECT COUNT(*) FROM assets").fetchone()[0] == 2


def test_import_is_atomic(db_path, tmp_path):
    f = tmp_path / "broken.json"
    first = {"inventory_no": "FW-02", "name": "Test", "location": "Lab",
             "protection_class": "Class", "description": ""}
    broken = dict(first, inventory_no="FW-03", name="")
    f.write_text(json.dumps({"format": "infosec-assets-v1", "items": [first, broken]}),
                 encoding="utf-8")
    with pytest.raises(ValueError):
        import_assets(db_path, f)
    with connect(db_path) as db:
        assert db.execute("SELECT COUNT(*) FROM assets").fetchone()[0] == 1


def test_import_rejects_unsupported_format(db_path, tmp_path):
    f = tmp_path / "bad.json"
    f.write_text('{"format":"wrong","items":[]}', encoding="utf-8")
    with pytest.raises(ValueError, match="формат"):
        import_assets(db_path, f)


def test_backup_and_no_overwrite(db_path, tmp_path):
    target = tmp_path / "backup.sqlite3"
    backup_database(db_path, target)
    with sqlite3.connect(target) as db:
        assert db.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 4
    with pytest.raises(ValueError, match="существует"):
        backup_database(db_path, target)
    with pytest.raises(ValueError, match="поверх"):
        backup_database(db_path, db_path)


def test_inspect_update_manifest(tmp_path):
    f = tmp_path / "release.json"
    f.write_text(json.dumps({"format": "infosec-release-v1", "version": "1.1.0",
                            "sha256": "f" * 64}), encoding="utf-8")
    result = inspect_update_manifest(f)
    assert result["needs_update"]
    assert result["installed"] == "1.0.0"
    f.write_text('{"format": "infosec-release-v1", "version": "bad", "sha256": "ff"}',
                 encoding="utf-8")
    with pytest.raises(ValueError):
        inspect_update_manifest(f)
