import pytest

from infosec_desk.db import connect
from infosec_desk.security import password_hash, verify_password
from infosec_desk.service import (
    add_comment,
    create_ticket,
    find_user,
    get_ticket,
    list_tickets,
    update_ticket,
)


def test_password_uses_salt_and_verifies():
    first = password_hash("Password12345")
    second = password_hash("Password12345")
    assert first != second
    assert verify_password("Password12345", first)
    assert not verify_password("incorrect", first)
    assert not verify_password("Password12345", "broken")


def test_create_ticket_and_audit(db_path):
    user = find_user(db_path, 3)
    ticket_id = create_ticket(db_path, user, "Проблема с доступом", "Не удается войти в защищенный раздел", "access", "high", 1)
    assert ticket_id == 1
    record, comments, history = get_ticket(db_path, user, ticket_id)
    assert record["asset_name"] == "Межсетевой экран"
    assert record["status"] == "new"
    assert not comments
    assert history[0]["action"] == "created"


def test_requester_sees_only_own_tickets(db_path):
    alice = find_user(db_path, 3)
    bob = find_user(db_path, 4)
    create_ticket(db_path, alice, "Настройка контроля", "Проверить правила доступа в подразделении", "access", "normal")
    assert len(list_tickets(db_path, alice)) == 1
    assert list_tickets(db_path, bob) == []
    assert get_ticket(db_path, bob, 1) is None
    with pytest.raises(PermissionError):
        add_comment(db_path, bob, 1, "Неавторизованный комментарий")


def test_restrict_status_transition(db_path):
    alice = find_user(db_path, 3)
    operator = find_user(db_path, 2)
    ticket_id = create_ticket(db_path, alice, "Проверить защиту", "Выполнить диагностику защиты сети", "network", "normal")
    with pytest.raises(PermissionError):
        update_ticket(db_path, alice, ticket_id, "in_progress", 2)
    with pytest.raises(ValueError):
        update_ticket(db_path, operator, ticket_id, "closed", 2)
    update_ticket(db_path, operator, ticket_id, "in_progress", 2)
    update_ticket(db_path, operator, ticket_id, "resolved", 2)
    update_ticket(db_path, operator, ticket_id, "closed", 2)
    with pytest.raises(ValueError):
        update_ticket(db_path, operator, ticket_id, "new", 2)
    with connect(db_path) as db:
        record = db.execute("SELECT status,closed_at FROM tickets WHERE id=?", (ticket_id,)).fetchone()
    assert record["status"] == "closed" and record["closed_at"]


def test_operator_cannot_assign_requester(db_path):
    alice = find_user(db_path, 3)
    op = find_user(db_path, 2)
    ticket = create_ticket(db_path, alice, "Новая проблема доступа", "Проверить доступ к конфигурации", "access", "high")
    with pytest.raises(ValueError):
        update_ticket(db_path, op, ticket, "in_progress", 4)


def test_validate_fields_and_sql_injection(db_path):
    alice = find_user(db_path, 3)
    with pytest.raises(ValueError):
        create_ticket(db_path, alice, "abc", "short", "access", "high")
    create_ticket(db_path, alice, "Проверка фильтра", "Описание для фильтра по заявкам", "access", "high")
    assert not list_tickets(db_path, alice, query="%' OR 1=1 --")
    with connect(db_path) as db:
        assert db.execute("SELECT COUNT(*) FROM tickets").fetchone()[0] == 1


def test_comment_creates_audit(db_path):
    alice = find_user(db_path, 3)
    ticket = create_ticket(db_path, alice, "Ошибка антивируса", "Нужно проверить журнал обновлений", "antivirus", "high")
    add_comment(db_path, alice, ticket, "Проблема воспроизводится")
    _, comments, events = get_ticket(db_path, alice, ticket)
    assert comments[0]["body"] == "Проблема воспроизводится"
    assert events[0]["action"] == "commented"
