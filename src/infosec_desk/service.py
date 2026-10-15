"""Бизнес-операции с заявками и справочниками."""

from .db import connect, transaction
from .security import clean_text, password_hash

CATEGORIES = {
    "access": "Управление доступом",
    "antivirus": "Антивирусная защита",
    "network": "Сетевая защита",
    "crypto": "Криптографическая защита",
    "backup": "Резервное копирование",
    "other": "Прочее",
}
PRIORITIES = {"low": "Низкий", "normal": "Обычный", "high": "Высокий", "critical": "Критический"}
STATUSES = {
    "new": "Новая",
    "in_progress": "В работе",
    "on_hold": "Приостановлена",
    "resolved": "Решена",
    "closed": "Закрыта",
}
ROLES = {"requester": "Заявитель", "operator": "Специалист", "admin": "Администратор"}
TRANSITIONS = {
    "new": {"in_progress", "on_hold"},
    "in_progress": {"on_hold", "resolved"},
    "on_hold": {"in_progress"},
    "resolved": {"closed", "in_progress"},
    "closed": set(),
}


def create_user(db_path, username, full_name, password, role="requester"):
    username = clean_text(username, "Логин", minimum=3, maximum=40).lower()
    full_name = clean_text(full_name, "ФИО", maximum=120)
    if not all(ch.isascii() and (ch.isalnum() or ch in "._-") for ch in username):
        raise ValueError("Логин: только латинские буквы, цифры, точка, дефис, подчеркивание")
    if role not in ROLES:
        raise ValueError("Недопустимая роль")
    with transaction(db_path) as db:
        cursor = db.execute(
            "INSERT INTO users(username,full_name,password_hash,role) VALUES(?,?,?,?)",
            (username, full_name, password_hash(password), role),
        )
        return cursor.lastrowid


def reset_admin_password(db_path, username, password):
    """Смена пароля администратора через локальную консоль."""
    username = clean_text(username, "Логин", minimum=3, maximum=40).lower()
    hashed = password_hash(password)
    with transaction(db_path) as db:
        user = db.execute(
            "SELECT id,role FROM users WHERE username=? COLLATE NOCASE AND active=1",
            (username,),
        ).fetchone()
        if user is None or user["role"] != "admin":
            raise ValueError("Активный администратор с таким логином не найден")
        db.execute("UPDATE users SET password_hash=? WHERE id=?", (hashed, user["id"]))
        db.execute(
            "INSERT INTO audit_events(actor_id,action,details) VALUES(NULL,?,?)",
            ("password_reset", f"Пароль администратора {username} изменен локально"),
        )


def authenticate(db_path, username, password):
    from .security import verify_password

    with connect(db_path) as db:
        user = db.execute(
            "SELECT * FROM users WHERE username = ? COLLATE NOCASE AND active = 1",
            (username.strip(),),
        ).fetchone()
    return dict(user) if user and verify_password(password, user["password_hash"]) else None


def find_user(db_path, user_id):
    with connect(db_path) as db:
        row = db.execute(
            "SELECT id,username,full_name,role,active FROM users WHERE id=?", (user_id,)
        ).fetchone()
    return dict(row) if row and row["active"] else None


def users(db_path):
    with connect(db_path) as db:
        return [dict(row) for row in db.execute(
            "SELECT id,username,full_name,role,active FROM users ORDER BY full_name"
        )]


def assets(db_path):
    with connect(db_path) as db:
        return [dict(row) for row in db.execute("SELECT * FROM assets ORDER BY name")]


def add_asset(db_path, inventory_no, name, location, protection_class, description=""):
    inventory_no = clean_text(inventory_no, "Инвентарный номер", maximum=32)
    name = clean_text(name, "Название средства", maximum=120)
    location = clean_text(location, "Местоположение", maximum=120)
    protection_class = clean_text(protection_class, "Класс защиты", maximum=80)
    description = clean_text(description, "Описание", minimum=0, maximum=1000)
    with transaction(db_path) as db:
        cursor = db.execute(
            "INSERT INTO assets(inventory_no,name,location,protection_class,description) "
            "VALUES(?,?,?,?,?)",
            (inventory_no, name, location, protection_class, description),
        )
        return cursor.lastrowid


def _ticket_select():
    return """SELECT t.*, a.name AS asset_name, u.full_name AS author_name,
        s.full_name AS assignee_name FROM tickets t
        JOIN users u ON t.author_id=u.id
        LEFT JOIN users s ON t.assignee_id=s.id
        LEFT JOIN assets a ON t.asset_id=a.id"""


def list_tickets(db_path, user, status="", query=""):
    parts, params = [], []
    if user["role"] == "requester":
        parts.append("t.author_id=?")
        params.append(user["id"])
    if status in STATUSES:
        parts.append("t.status=?")
        params.append(status)
    if query.strip():
        parts.append("(t.title LIKE ? OR t.description LIKE ? OR CAST(t.id AS TEXT) LIKE ?)")
        params.extend([f"%{query.strip()}%"] * 3)
    where = " WHERE " + " AND ".join(parts) if parts else ""
    with connect(db_path) as db:
        result = db.execute(_ticket_select() + where + " ORDER BY t.id DESC LIMIT 500", params)
        return [dict(row) for row in result]


def get_ticket(db_path, user, ticket_id):
    with connect(db_path) as db:
        row = db.execute(_ticket_select() + " WHERE t.id=?", (ticket_id,)).fetchone()
        if not row or (user["role"] == "requester" and row["author_id"] != user["id"]):
            return None
        notes = db.execute(
            """SELECT c.*,u.full_name AS author_name FROM comments c
               JOIN users u ON u.id=c.author_id
               WHERE c.ticket_id=? ORDER BY c.id""", (ticket_id,)
        ).fetchall()
        events = db.execute(
            """SELECT a.*,u.full_name AS actor_name FROM audit_events a
               LEFT JOIN users u ON u.id=a.actor_id
               WHERE a.ticket_id=? ORDER BY a.id DESC""", (ticket_id,)
        ).fetchall()
    return dict(row), [dict(n) for n in notes], [dict(e) for e in events]


def create_ticket(db_path, user, title, description, category, priority, asset_id=None):
    title = clean_text(title, "Тема", minimum=5, maximum=160)
    description = clean_text(description, "Описание", minimum=10, maximum=4000)
    if category not in CATEGORIES or priority not in PRIORITIES:
        raise ValueError("Недопустимая категория или приоритет")
    with transaction(db_path) as db:
        if asset_id is not None:
            asset = db.execute("SELECT 1 FROM assets WHERE id=?", (asset_id,)).fetchone()
            if asset is None:
                raise ValueError("Средство защиты не найдено")
        cursor = db.execute(
            """INSERT INTO tickets(title,description,category,priority,asset_id,author_id)
               VALUES(?,?,?,?,?,?)""",
            (title, description, category, priority, asset_id, user["id"]),
        )
        ticket_id = cursor.lastrowid
        db.execute(
            "INSERT INTO audit_events(actor_id,ticket_id,action,details) VALUES(?,?,?,?)",
            (user["id"], ticket_id, "created", "Заявка зарегистрирована"),
        )
        return ticket_id


def add_comment(db_path, user, ticket_id, body):
    body = clean_text(body, "Комментарий", minimum=2, maximum=2000)
    if get_ticket(db_path, user, ticket_id) is None:
        raise PermissionError("Заявка недоступна")
    with transaction(db_path) as db:
        db.execute(
            "INSERT INTO comments(ticket_id,author_id,body) VALUES(?,?,?)",
            (ticket_id, user["id"], body),
        )
        db.execute(
            "INSERT INTO audit_events(actor_id,ticket_id,action,details) VALUES(?,?,?,?)",
            (user["id"], ticket_id, "commented", "Добавлен комментарий"),
        )


def update_ticket(db_path, user, ticket_id, status, assignee_id):
    if user["role"] not in {"operator", "admin"}:
        raise PermissionError("Недостаточно прав")
    if status not in STATUSES:
        raise ValueError("Недопустимый статус")
    with transaction(db_path) as db:
        current = db.execute(
            "SELECT status,assignee_id FROM tickets WHERE id=?", (ticket_id,)
        ).fetchone()
        if not current:
            raise ValueError("Заявка не найдена")
        if status != current["status"] and status not in TRANSITIONS[current["status"]]:
            raise ValueError("Недопустимый переход между статусами")
        if assignee_id is not None:
            assignee = db.execute(
                "SELECT role,active FROM users WHERE id=?", (assignee_id,)
            ).fetchone()
            if (
                not assignee or not assignee["active"]
                or assignee["role"] not in {"operator", "admin"}
            ):
                raise ValueError("Исполнителем может быть только активный специалист")
        if status == current["status"] and assignee_id == current["assignee_id"]:
            return
        db.execute(
            """UPDATE tickets SET status=?, assignee_id=?,updated_at=datetime('now'),
               closed_at=CASE WHEN ?='closed' THEN datetime('now') ELSE NULL END WHERE id=?""",
            (status, assignee_id, status, ticket_id),
        )
        details = (
            f"Статус: {current['status']} -> {status}; "
            f"исполнитель: {current['assignee_id']} -> {assignee_id}"
        )
        db.execute(
            "INSERT INTO audit_events(actor_id,ticket_id,action,details) VALUES(?,?,?,?)",
            (user["id"], ticket_id, "updated", details),
        )


def statistics(db_path, user):
    tickets = list_tickets(db_path, user)
    return {
        "total": len(tickets),
        "open": sum(t["status"] not in ("resolved", "closed") for t in tickets),
        "resolved": sum(t["status"] in ("resolved", "closed") for t in tickets),
        "critical": sum(t["priority"] == "critical" and t["status"] != "closed" for t in tickets),
        "by_status": {key: sum(t["status"] == key for t in tickets) for key in STATUSES},
    }


def audit_events(db_path, limit=100):
    with connect(db_path) as db:
        return [dict(row) for row in db.execute(
            """SELECT a.*,u.full_name AS actor_name FROM audit_events a
               LEFT JOIN users u ON a.actor_id=u.id ORDER BY a.id DESC LIMIT ?""", (limit,)
        )]
