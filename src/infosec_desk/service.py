"""Бизнес-операции с заявками и справочниками."""
from .db import connect, transaction
from .security import clean_text, password_hash
CATEGORIES = {'access': 'Управление доступом', 'antivirus': 'Антивирусная защита', 'network': 'Сетевая защита', 'crypto': 'Криптографическая защита', 'backup': 'Резервное копирование', 'other': 'Прочее'}
PRIORITIES = {'low': 'Низкий', 'normal': 'Обычный', 'high': 'Высокий', 'critical': 'Критический'}
STATUSES = {'new': 'Новая', 'in_progress': 'В работе', 'on_hold': 'Приостановлена', 'resolved': 'Решена', 'closed': 'Закрыта'}
ROLES = {'requester': 'Заявитель', 'operator': 'Специалист', 'admin': 'Администратор'}
TRANSITIONS = {'new': {'in_progress', 'on_hold'}, 'in_progress': {'on_hold', 'resolved'}, 'on_hold': {'in_progress'}, 'resolved': {'closed', 'in_progress'}, 'closed': set()}

def create_user(db_path, username, full_name, password, role='requester'):
    username = clean_text(username, 'Логин', minimum=3, maximum=40).lower()
    full_name = clean_text(full_name, 'ФИО', maximum=120)
    if not all((ch.isascii() and (ch.isalnum() or ch in '._-') for ch in username)):
        raise ValueError('Логин: только латинские буквы, цифры, точка, дефис, подчеркивание')
    if role not in ROLES:
        raise ValueError('Недопустимая роль')
    with transaction(db_path) as db:
        cursor = db.execute('INSERT INTO users(username,full_name,password_hash,role) VALUES(?,?,?,?)', (username, full_name, password_hash(password), role))
        return cursor.lastrowid

def reset_admin_password(db_path, username, password):
    """Меняет пароль администратора при локальном доступе к БД."""
    username = clean_text(username, 'Логин', minimum=3, maximum=40).lower()
    hashed = password_hash(password)
    with transaction(db_path) as db:
        user = db.execute('SELECT id, role FROM users WHERE username=? COLLATE NOCASE AND active=1', (username,)).fetchone()
        if user is None or user['role'] != 'admin':
            raise ValueError('Активный администратор не найден')
        db.execute('UPDATE users SET password_hash=? WHERE id=?', (hashed, user['id']))
        db.execute('INSERT INTO audit_events(actor_id, action, details) VALUES(?,?,?)', (None, 'password_reset', f'Пароль администратора {username} изменен локально'))

def authenticate(db_path, username, password):
    from .security import verify_password
    with connect(db_path) as db:
        user = db.execute('SELECT * FROM users WHERE username = ? COLLATE NOCASE AND active = 1', (username.strip(),)).fetchone()
    return dict(user) if user and verify_password(password, user['password_hash']) else None

def find_user(db_path, user_id):
    with connect(db_path) as db:
        row = db.execute('SELECT id,username,full_name,role,active FROM users WHERE id=?', (user_id,)).fetchone()
    return dict(row) if row and row['active'] else None

def users(db_path):
    with connect(db_path) as db:
        return [dict(row) for row in db.execute('SELECT id,username,full_name,role,active FROM users ORDER BY full_name')]

def assets(db_path):
    with connect(db_path) as db:
        return [dict(row) for row in db.execute('SELECT * FROM assets WHERE active=1 ORDER BY name')]

def add_asset(db_path, inventory_no, name, location, protection_class, description=''):
    inventory_no = clean_text(inventory_no, 'Инвентарный номер', maximum=32)
    name = clean_text(name, 'Название средства', maximum=120)
    location = clean_text(location, 'Местоположение', maximum=120)
    protection_class = clean_text(protection_class, 'Класс защиты', maximum=80)
    description = clean_text(description, 'Описание', minimum=0, maximum=1000)
    with transaction(db_path) as db:
        cursor = db.execute('INSERT INTO assets(inventory_no,name,location,protection_class,description) VALUES(?,?,?,?,?)', (inventory_no, name, location, protection_class, description))
        return cursor.lastrowid

def edit_user(db_path, actor, user_id, username, full_name, role, active=True):
    """Администратор корректирует запись, не удаляя историю заявок."""
    if actor['role'] != 'admin':
        raise PermissionError('Недостаточно прав')
    username = clean_text(username, 'Логин', minimum=3, maximum=40).lower()
    full_name = clean_text(full_name, 'ФИО', maximum=120)
    if not all((ch.isascii() and (ch.isalnum() or ch in '._-') for ch in username)):
        raise ValueError('Недопустимый логин')
    if role not in ROLES:
        raise ValueError('Недопустимая роль')
    active = int(bool(active))
    if user_id == actor['id'] and (not active or role != 'admin'):
        raise ValueError('Нельзя отключить себя или снять собственные права администратора')
    with transaction(db_path) as db:
        old = db.execute('SELECT * FROM users WHERE id=?', (user_id,)).fetchone()
        if old is None:
            raise ValueError('Пользователь не найден')
        if old['role'] == 'admin' and old['active'] and (role != 'admin' or not active):
            total = db.execute("SELECT count(*) FROM users WHERE role='admin' AND active=1").fetchone()[0]
            if total <= 1:
                raise ValueError('В системе должен остаться активный администратор')
        db.execute('UPDATE users SET username=?,full_name=?,role=?,active=? WHERE id=?', (username, full_name, role, active, user_id))
        db.execute('INSERT INTO audit_events(actor_id,action,details) VALUES(?,?,?)', (actor['id'], 'user_edited', f"Учетная запись {old['username']} обновлена: {username}"))

def delete_user(db_path, actor, user_id):
    """Логическое удаление: связанные заявки и история сохраняются."""
    if actor['id'] == user_id:
        raise ValueError('Нельзя удалить собственную учетную запись')
    with connect(db_path) as db:
        row = db.execute('SELECT * FROM users WHERE id=?', (user_id,)).fetchone()
    if not row:
        raise ValueError('Пользователь не найден')
    edit_user(db_path, actor, user_id, row['username'], row['full_name'], row['role'], False)

def edit_asset(db_path, actor, asset_id, inventory_no, name, location, protection_class, description='', active=True):
    if actor['role'] != 'admin':
        raise PermissionError('Недостаточно прав')
    inventory_no = clean_text(inventory_no, 'Инвентарный номер', maximum=32)
    name = clean_text(name, 'Название средства', maximum=120)
    location = clean_text(location, 'Местоположение', maximum=120)
    protection_class = clean_text(protection_class, 'Класс защиты', maximum=80)
    description = clean_text(description, 'Описание', minimum=0, maximum=1000)
    with transaction(db_path) as db:
        old = db.execute('SELECT inventory_no FROM assets WHERE id=?', (asset_id,)).fetchone()
        if not old:
            raise ValueError('Средство защиты не найдено')
        db.execute('UPDATE assets SET inventory_no=?,name=?,location=?,protection_class=?,\n               description=?,active=? WHERE id=?', (inventory_no, name, location, protection_class, description, int(bool(active)), asset_id))
        db.execute('INSERT INTO audit_events(actor_id,action,details) VALUES(?,?,?)', (actor['id'], 'asset_edited', f"СЗИ {old['inventory_no']} обновлено"))

def delete_asset(db_path, actor, asset_id):
    """Скрывает СЗИ из справочника без разрыва связей с заявками."""
    if actor['role'] != 'admin':
        raise PermissionError('Недостаточно прав')
    with transaction(db_path) as db:
        row = db.execute('SELECT inventory_no FROM assets WHERE id=?', (asset_id,)).fetchone()
        if not row:
            raise ValueError('Средство защиты не найдено')
        db.execute('UPDATE assets SET active=0 WHERE id=?', (asset_id,))
        db.execute('INSERT INTO audit_events(actor_id,action,details) VALUES(?,?,?)', (actor['id'], 'asset_archived', f"СЗИ {row['inventory_no']} исключено из действующего справочника"))

def _ticket_select():
    return 'SELECT t.*, a.name AS asset_name, u.full_name AS author_name,\n        s.full_name AS assignee_name FROM tickets t\n        JOIN users u ON t.author_id=u.id\n        LEFT JOIN users s ON t.assignee_id=s.id\n        LEFT JOIN assets a ON t.asset_id=a.id'

def list_tickets(db_path, user, status='', query='', limit=None):
    parts, params = ([], [])
    if user['role'] == 'requester':
        parts.append('t.author_id=?')
        params.append(user['id'])
    if status in STATUSES:
        parts.append('t.status=?')
        params.append(status)
    if query.strip():
        parts.append('(t.title LIKE ? OR t.description LIKE ? OR CAST(t.id AS TEXT) LIKE ?)')
        params.extend([f'%{query.strip()}%'] * 3)
    where = ' WHERE ' + ' AND '.join(parts) if parts else ''
    with connect(db_path) as db:
        sql = _ticket_select() + where + ' ORDER BY t.id DESC'
        if limit is not None:
            sql += ' LIMIT ?'
            params.append(int(limit))
        result = db.execute(sql, params)
        return [dict(row) for row in result]

def get_ticket(db_path, user, ticket_id):
    with connect(db_path) as db:
        row = db.execute(_ticket_select() + ' WHERE t.id=?', (ticket_id,)).fetchone()
        if not row or (user['role'] == 'requester' and row['author_id'] != user['id']):
            return None
        notes = db.execute('SELECT c.*,u.full_name AS author_name FROM comments c\n               JOIN users u ON u.id=c.author_id\n               WHERE c.ticket_id=? ORDER BY c.id', (ticket_id,)).fetchall()
        events = db.execute('SELECT a.*,u.full_name AS actor_name FROM audit_events a\n               LEFT JOIN users u ON u.id=a.actor_id\n               WHERE a.ticket_id=? ORDER BY a.id DESC', (ticket_id,)).fetchall()
    return (dict(row), [dict(n) for n in notes], [dict(e) for e in events])

def create_ticket(db_path, user, title, description, category, priority, asset_id=None):
    title = clean_text(title, 'Тема', minimum=5, maximum=160)
    description = clean_text(description, 'Описание', minimum=10, maximum=4000)
    if category not in CATEGORIES or priority not in PRIORITIES:
        raise ValueError('Недопустимая категория или приоритет')
    with transaction(db_path) as db:
        if asset_id is not None:
            asset = db.execute('SELECT 1 FROM assets WHERE id=? AND active=1', (asset_id,)).fetchone()
            if asset is None:
                raise ValueError('Средство защиты не найдено')
        cursor = db.execute('INSERT INTO tickets(title,description,category,priority,asset_id,author_id)\n               VALUES(?,?,?,?,?,?)', (title, description, category, priority, asset_id, user['id']))
        ticket_id = cursor.lastrowid
        db.execute('INSERT INTO audit_events(actor_id,ticket_id,action,details) VALUES(?,?,?,?)', (user['id'], ticket_id, 'created', 'Заявка зарегистрирована'))
        db.execute('INSERT INTO ticket_status_history(ticket_id,actor_id,old_status,new_status) VALUES(?,?,?,?)', (ticket_id, user['id'], None, 'new'))
        return ticket_id

def add_comment(db_path, user, ticket_id, body):
    body = clean_text(body, 'Комментарий', minimum=2, maximum=2000)
    if get_ticket(db_path, user, ticket_id) is None:
        raise PermissionError('Заявка недоступна')
    with transaction(db_path) as db:
        db.execute('INSERT INTO comments(ticket_id,author_id,body) VALUES(?,?,?)', (ticket_id, user['id'], body))
        db.execute('INSERT INTO audit_events(actor_id,ticket_id,action,details) VALUES(?,?,?,?)', (user['id'], ticket_id, 'commented', 'Добавлен комментарий'))
        t = db.execute('SELECT author_id,assignee_id FROM tickets WHERE id=?', (ticket_id,)).fetchone()
        for uid in set((t['author_id'], t['assignee_id'])) - {None, user['id']}:
            db.execute('INSERT INTO notifications(user_id,ticket_id,text) VALUES(?,?,?)', (uid, ticket_id, 'В заявке появился новый комментарий'))

def update_ticket(db_path, user, ticket_id, status, assignee_id):
    if user['role'] not in {'operator', 'admin'}:
        raise PermissionError('Недостаточно прав')
    if status not in STATUSES:
        raise ValueError('Недопустимый статус')
    with transaction(db_path) as db:
        current = db.execute('SELECT status,assignee_id FROM tickets WHERE id=?', (ticket_id,)).fetchone()
        if not current:
            raise ValueError('Заявка не найдена')
        if status != current['status'] and status not in TRANSITIONS[current['status']]:
            raise ValueError('Недопустимый переход между статусами')
        if assignee_id is not None:
            assignee = db.execute('SELECT role,active FROM users WHERE id=?', (assignee_id,)).fetchone()
            if not assignee or not assignee['active'] or assignee['role'] not in {'operator', 'admin'}:
                raise ValueError('Исполнителем может быть только активный специалист')
        if status == current['status'] and assignee_id == current['assignee_id']:
            return
        db.execute("UPDATE tickets SET status=?, assignee_id=?,updated_at=datetime('now'),\n               resolved_at=CASE\n                   WHEN ?='resolved' AND status!='resolved' THEN datetime('now')\n                   WHEN ?='in_progress' THEN NULL ELSE resolved_at END,\n               closed_at=CASE WHEN ?='closed' THEN datetime('now') ELSE NULL END WHERE id=?", (status, assignee_id, status, status, status, ticket_id))

        def assignee_label(value):
            if value is None:
                return 'не назначен'
            row = db.execute('SELECT username FROM users WHERE id=?', (value,)).fetchone()
            return row['username'] if row else 'учетная запись отсутствует'
        changes = []
        if status != current['status']:
            changes.append(f"Статус: {STATUSES[current['status']]} -> {STATUSES[status]}")
        if assignee_id != current['assignee_id']:
            changes.append(f"Исполнитель: {assignee_label(current['assignee_id'])} -> {assignee_label(assignee_id)}")
        db.execute('INSERT INTO audit_events(actor_id,ticket_id,action,details) VALUES(?,?,?,?)', (user['id'], ticket_id, 'updated', '; '.join(changes)))
        if status != current['status']:
            db.execute('INSERT INTO ticket_status_history(ticket_id,actor_id,old_status,new_status) VALUES(?,?,?,?)', (ticket_id, user['id'], current['status'], status))
        requester = db.execute('SELECT author_id FROM tickets WHERE id=?', (ticket_id,)).fetchone()[0]
        for uid in set((requester, assignee_id)) - {None, user['id']}:
            db.execute('INSERT INTO notifications(user_id,ticket_id,text) VALUES(?,?,?)', (uid, ticket_id, 'Изменено состояние заявки: ' + '; '.join(changes)))

def statistics(db_path, user):
    """Подсчитывает показатели SQL-запросом без ограничения реестра в 500 строк."""
    condition = 'WHERE author_id=?' if user['role'] == 'requester' else ''
    params = (user['id'],) if condition else ()
    with connect(db_path) as db:
        row = db.execute(f"SELECT COUNT(*) AS total,\n                COALESCE(SUM(CASE WHEN status NOT IN ('resolved','closed') THEN 1 ELSE 0 END), 0) AS open,\n                COALESCE(SUM(CASE WHEN status IN ('resolved','closed') THEN 1 ELSE 0 END), 0) AS resolved,\n                COALESCE(SUM(CASE WHEN priority='critical' AND status!='closed' THEN 1 ELSE 0 END), 0)\n                    AS critical\n            FROM tickets {condition}", params).fetchone()
        by_status = db.execute(f'SELECT status, COUNT(*) AS total FROM tickets {condition} GROUP BY status', params).fetchall()
    counts = {item['status']: item['total'] for item in by_status}
    return {'total': row['total'], 'open': row['open'], 'resolved': row['resolved'], 'critical': row['critical'], 'by_status': {key: counts.get(key, 0) for key in STATUSES}}

def audit_events(db_path, limit=100):
    with connect(db_path) as db:
        return [dict(row) for row in db.execute('SELECT a.*,u.full_name AS actor_name FROM audit_events a\n               LEFT JOIN users u ON a.actor_id=u.id ORDER BY a.id DESC LIMIT ?', (limit,))]

def list_services(db_path, active_only=False):
    with connect(db_path) as db:
        sql = 'SELECT * FROM service_catalog' + (' WHERE active=1' if active_only else '') + ' ORDER BY name'
        return [dict(x) for x in db.execute(sql)]

def add_service(db_path, code, name, description, category):
    code = clean_text(code, 'Код', maximum=40)
    name = clean_text(name, 'Название', maximum=120)
    description = clean_text(description, 'Описание', minimum=0, maximum=1000)
    if category not in CATEGORIES:
        raise ValueError('Недопустимая категория')
    with transaction(db_path) as db:
        db.execute('INSERT INTO service_catalog(code,name,description,category) VALUES(?,?,?,?)', (code, name, description, category))

def toggle_service(db_path, service_id):
    with transaction(db_path) as db:
        db.execute('UPDATE service_catalog SET active=1-active WHERE id=?', (service_id,))

def create_feedback(db_path, name, email, subject, body):
    name = clean_text(name, 'Имя', maximum=100)
    email = clean_text(email, 'Email', maximum=140)
    if '@' not in email or len(email.split('@')[-1]) < 3:
        raise ValueError('Введите корректный адрес')
    subject = clean_text(subject, 'Тема', maximum=140)
    body = clean_text(body, 'Сообщение', minimum=10, maximum=3000)
    with transaction(db_path) as db:
        db.execute('INSERT INTO feedback_messages(sender_name,sender_email,subject,body) VALUES(?,?,?,?)', (name, email, subject, body))

def list_feedback(db_path):
    with connect(db_path) as db:
        return [dict(x) for x in db.execute('SELECT * FROM feedback_messages ORDER BY id DESC')]

def mark_feedback(db_path, id):
    with transaction(db_path) as db:
        db.execute("UPDATE feedback_messages SET state='processed' WHERE id=?", (id,))

def list_attachments(db_path, ticket_id):
    with connect(db_path) as db:
        return [dict(x) for x in db.execute('SELECT id,ticket_id,author_id,filename,mime_type,uploaded_at FROM ticket_attachments WHERE ticket_id=? ORDER BY id', (ticket_id,))]

def add_attachment(db_path, user, ticket_id, filename, mime_type, content):
    if get_ticket(db_path, user, ticket_id) is None:
        raise PermissionError('Заявка недоступна')
    filename = clean_text(filename, 'Имя файла', maximum=160)
    allowed = {'application/pdf', 'image/png', 'image/jpeg', 'text/plain'}
    if mime_type not in allowed:
        raise ValueError('Недопустимый формат вложения')
    if not content or len(content) > 2000000:
        raise ValueError('Допустимы файлы от 1 байта до 2 МБ')
    with transaction(db_path) as db:
        db.execute('INSERT INTO ticket_attachments(ticket_id,author_id,filename,mime_type,content) VALUES(?,?,?,?,?)', (ticket_id, user['id'], filename, mime_type, content))
        db.execute('INSERT INTO audit_events(actor_id,ticket_id,action,details) VALUES(?,?,?,?)', (user['id'], ticket_id, 'attachment', 'Добавлен файл ' + filename))

def get_attachment(db_path, user, attachment_id):
    with connect(db_path) as db:
        row = db.execute('SELECT * FROM ticket_attachments WHERE id=?', (attachment_id,)).fetchone()
        if not row or not get_ticket(db_path, user, row['ticket_id']):
            return None
        return dict(row)

def status_history(db_path, ticket_id):
    with connect(db_path) as db:
        return [dict(x) for x in db.execute('SELECT h.*,u.full_name actor_name FROM ticket_status_history h LEFT JOIN users u ON u.id=h.actor_id WHERE h.ticket_id=? ORDER BY h.id DESC', (ticket_id,))]

def user_notifications(db_path, user_id):
    with connect(db_path) as db:
        return [dict(x) for x in db.execute('SELECT * FROM notifications WHERE user_id=? ORDER BY id DESC LIMIT 100', (user_id,))]

def mark_notifications_read(db_path, user_id):
    with transaction(db_path) as db:
        db.execute('UPDATE notifications SET is_read=1 WHERE user_id=?', (user_id,))

def get_settings(db_path):
    with connect(db_path) as db:
        settings = {r['setting_key']: r['setting_value'] for r in db.execute('SELECT * FROM application_settings')}
    return {'help_email': settings.get('help_email', 'Уточняется у администратора'), 'office_hours': settings.get('office_hours', 'Пн-Пт, 09:00-18:00'), 'site_title': settings.get('site_title', 'InfoSec Desk')}

def set_setting(db_path, key, value):
    if key not in {'help_email', 'office_hours', 'site_title'}:
        raise ValueError('Недопустимый параметр')
    value = clean_text(value, 'Значение', maximum=140)
    with transaction(db_path) as db:
        db.execute('INSERT INTO application_settings(setting_key,setting_value) VALUES(?,?) ON CONFLICT(setting_key) DO UPDATE SET setting_value=excluded.setting_value', (key, value))

def admin_analytics(db_path):
    with connect(db_path) as db:
        return {t: db.execute(f'SELECT COUNT(*) FROM {t}').fetchone()[0] for t in ('tickets', 'users', 'assets', 'comments', 'feedback_messages', 'ticket_attachments', 'service_catalog', 'audit_events')}
