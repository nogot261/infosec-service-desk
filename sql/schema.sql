-- Схема учета заявок на обслуживание средств защиты информации
PRAGMA foreign_keys = ON;
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY,
    username TEXT NOT NULL UNIQUE COLLATE NOCASE,
    full_name TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL CHECK (role IN ('requester', 'operator', 'admin')),
    active INTEGER NOT NULL DEFAULT 1 CHECK (active IN (0, 1)),
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS assets (
    id INTEGER PRIMARY KEY,
    inventory_no TEXT NOT NULL UNIQUE,
    name TEXT NOT NULL,
    location TEXT NOT NULL,
    protection_class TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    active INTEGER NOT NULL DEFAULT 1 CHECK (active IN (0, 1)),
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS tickets (
    id INTEGER PRIMARY KEY,
    title TEXT NOT NULL,
    description TEXT NOT NULL,
    category TEXT NOT NULL CHECK (category IN
       ('access', 'antivirus', 'network', 'crypto', 'backup', 'other')),
    priority TEXT NOT NULL CHECK (priority IN ('low', 'normal', 'high', 'critical')),
    status TEXT NOT NULL DEFAULT 'new' CHECK (status IN
       ('new', 'in_progress', 'on_hold', 'resolved', 'closed')),
    asset_id INTEGER REFERENCES assets(id) ON DELETE RESTRICT,
    author_id INTEGER NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    assignee_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now')),
    closed_at TEXT,
    resolved_at TEXT,
    due_at TEXT
);
CREATE TABLE IF NOT EXISTS comments (
    id INTEGER PRIMARY KEY,
    ticket_id INTEGER NOT NULL REFERENCES tickets(id) ON DELETE CASCADE,
    author_id INTEGER NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    body TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS audit_events (
    id INTEGER PRIMARY KEY,
    actor_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
    ticket_id INTEGER REFERENCES tickets(id) ON DELETE SET NULL,
    action TEXT NOT NULL,
    details TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_ticket_status ON tickets(status, created_at);
CREATE INDEX IF NOT EXISTS idx_ticket_author ON tickets(author_id, created_at);
CREATE INDEX IF NOT EXISTS idx_ticket_assignee ON tickets(assignee_id, status);
CREATE INDEX IF NOT EXISTS idx_audit_ticket ON audit_events(ticket_id, id);
CREATE INDEX IF NOT EXISTS idx_comments_ticket ON comments(ticket_id, id);


-- Каталог услуг используется при регистрации новых заявок.
CREATE TABLE IF NOT EXISTS service_catalog (
 id INTEGER PRIMARY KEY, code TEXT NOT NULL UNIQUE, name TEXT NOT NULL,
 description TEXT NOT NULL DEFAULT '', category TEXT NOT NULL, active INTEGER NOT NULL DEFAULT 1
);
-- Обращения посетителей публичной формы обратной связи.
CREATE TABLE IF NOT EXISTS feedback_messages (
 id INTEGER PRIMARY KEY, sender_name TEXT NOT NULL, sender_email TEXT NOT NULL,
 subject TEXT NOT NULL, body TEXT NOT NULL, state TEXT NOT NULL DEFAULT 'new',
 created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
-- Вложения хранятся в БД, при чтении контролируются права на заявку.
CREATE TABLE IF NOT EXISTS ticket_attachments (
 id INTEGER PRIMARY KEY, ticket_id INTEGER NOT NULL REFERENCES tickets(id) ON DELETE CASCADE,
 author_id INTEGER NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
 filename TEXT NOT NULL, mime_type TEXT NOT NULL, content BLOB NOT NULL,
 uploaded_at TEXT NOT NULL DEFAULT (datetime('now'))
);
-- Машинно читаемые переходы статусов; audit_events сохраняет полный журнал.
CREATE TABLE IF NOT EXISTS ticket_status_history (
 id INTEGER PRIMARY KEY, ticket_id INTEGER NOT NULL REFERENCES tickets(id) ON DELETE CASCADE,
 actor_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
 old_status TEXT, new_status TEXT NOT NULL,
 occurred_at TEXT NOT NULL DEFAULT (datetime('now'))
);
-- Сообщения пользователя о назначении, комментариях и смене статуса.
CREATE TABLE IF NOT EXISTS notifications (
 id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 ticket_id INTEGER REFERENCES tickets(id) ON DELETE SET NULL,
 text TEXT NOT NULL, is_read INTEGER NOT NULL DEFAULT 0,
 created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
-- Системные настройки, изменяемые администратором.
CREATE TABLE IF NOT EXISTS application_settings (
 setting_key TEXT PRIMARY KEY, setting_value TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_attachments_ticket ON ticket_attachments(ticket_id);
CREATE INDEX IF NOT EXISTS idx_feedback_state ON feedback_messages(state,created_at);
CREATE INDEX IF NOT EXISTS idx_history_ticket ON ticket_status_history(ticket_id,id);
CREATE INDEX IF NOT EXISTS idx_notifications_user ON notifications(user_id,is_read,id);
