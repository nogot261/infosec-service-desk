"""Проверяемый файловый обмен реестром средств защиты.

Не является подключением к внутренним ИС университета.
"""

import json
from pathlib import Path

from .db import connect, transaction
from .security import clean_text

FORMAT = "infosec-assets-v1"
FIELDS = ("inventory_no", "name", "location", "protection_class", "description")
MAX_FILE_BYTES = 2 * 1024 * 1024
MAX_ITEMS = 1000


def export_assets(db_path, file_path):
    """Сохраняет каталог средств защиты в JSON UTF-8."""
    with connect(db_path) as db:
        rows = [dict(row) for row in db.execute(
            "SELECT inventory_no,name,location,protection_class,description "
            "FROM assets ORDER BY inventory_no"
        )]
    payload = {"format": FORMAT, "items": rows}
    output = Path(file_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return len(rows)


def import_assets(db_path, file_path):
    """Атомарно добавляет новые объекты; существующие по номеру пропускает."""
    source = Path(file_path)
    if source.stat().st_size > MAX_FILE_BYTES:
        raise ValueError("Файл импорта слишком большой")
    try:
        payload = json.loads(source.read_text(encoding="utf-8-sig"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError("Файл не является допустимым JSON") from exc
    if not isinstance(payload, dict) or payload.get("format") != FORMAT:
        raise ValueError("Неподдерживаемый формат импорта")
    items = payload.get("items")
    if not isinstance(items, list) or len(items) > MAX_ITEMS:
        raise ValueError("Поле items должно содержать не более 1000 элементов")
    clean_rows = []
    seen = set()
    limits = {"inventory_no": 32, "name": 120, "location": 120,
              "protection_class": 80, "description": 1000}
    for number, item in enumerate(items, start=1):
        if not isinstance(item, dict) or set(item) != set(FIELDS):
            raise ValueError(f"Строка {number}: неверный состав полей")
        values = {}
        for field in FIELDS:
            value = item[field]
            if not isinstance(value, str):
                raise ValueError(f"Строка {number}: поле {field} должно быть строкой")
            values[field] = clean_text(
                value, field, minimum=0 if field == "description" else 1,
                maximum=limits[field],
            )
        if values["inventory_no"] in seen:
            raise ValueError(f"Повтор инвентарного номера в файле: {values['inventory_no']}")
        seen.add(values["inventory_no"])
        clean_rows.append(tuple(values[field] for field in FIELDS))
    with transaction(db_path) as db:
        before = db.total_changes
        db.executemany(
            "INSERT OR IGNORE INTO assets(inventory_no,name,location,protection_class,description) "
            "VALUES(?,?,?,?,?)", clean_rows,
        )
        added = db.total_changes - before
        db.execute(
            "INSERT INTO audit_events(actor_id,action,details) VALUES(NULL,?,?)",
            ("assets_import", f"Файловый импорт: добавлено {added}, всего в файле {len(items)}"),
        )
    return {"added": added, "skipped": len(items) - added}
