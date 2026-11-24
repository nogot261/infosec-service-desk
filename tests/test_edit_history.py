"""Редактирование справочников, история и отметки времени."""

import sqlite3
from pathlib import Path

import pytest
from infosec_desk.db import connect, initialize
from infosec_desk.service import (
    add_asset, assets, create_ticket, delete_asset, delete_user, edit_asset,
    edit_user, find_user, get_ticket, update_ticket, users,
)
from infosec_desk.web import create_app


def test_edit_user_and_soft_delete(db_path):
    admin = find_user(db_path, 1)
    edit_user(db_path, admin, 3, 'alice_new', 'Мария Иванова', 'requester')
    assert next(x for x in users(db_path) if x['id'] == 3)['username'] == 'alice_new'
    delete_user(db_path, admin, 3)
    assert find_user(db_path, 3) is None
    assert next(x for x in users(db_path) if x['id'] == 3)['active'] == 0
    with pytest.raises(ValueError):
        delete_user(db_path, admin, 1)
    with pytest.raises(PermissionError):
        edit_user(db_path, {'role': 'requester', 'id': 3}, 4, 'someone', 'Some One', 'requester')


def test_edit_asset_and_hide_without_losing_ticket(db_path):
    admin = find_user(db_path, 1)
    requester = find_user(db_path, 3)
    ticket = create_ticket(db_path, requester, 'Проблема с межсетевым экраном',
                           'Описание проблемы с защитой сети', 'network', 'high', 1)
    edit_asset(db_path, admin, 1, 'FW-0001', 'СЗИ обновлено', 'Офис', 'Сеть')
    assert next(x for x in assets(db_path) if x['id'] == 1)['name'] == 'СЗИ обновлено'
    delete_asset(db_path, admin, 1)
    assert all(x['id'] != 1 for x in assets(db_path))
    assert get_ticket(db_path, requester, ticket)[0]['asset_name'] == 'СЗИ обновлено'


def test_history_uses_names_and_resolved_closed_at(db_path):
    requester, operator = find_user(db_path, 3), find_user(db_path, 2)
    ticket = create_ticket(db_path, requester, 'Ошибка при входе в сервис',
                           'Подробное описание сбоя при входе', 'access', 'normal')
    update_ticket(db_path, operator, ticket, 'in_progress', 2)
    update_ticket(db_path, operator, ticket, 'resolved', 2)
    record, _, events = get_ticket(db_path, operator, ticket)
    assert record['resolved_at'] is not None and record['closed_at'] is None
    assert any('Исполнитель:' in e['details'] and 'operator' in e['details'] for e in events)
    assert all('in_progress' not in e['details'] and 'resolved' not in e['details'] for e in events)
    update_ticket(db_path, operator, ticket, 'closed', 2)
    assert get_ticket(db_path, operator, ticket)[0]['closed_at'] is not None


def test_migration_old_sqlite_adds_columns(tmp_path):
    path = tmp_path / 'legacy.db'
    initialize(path)
    with sqlite3.connect(path) as db:
        db.execute('ALTER TABLE assets RENAME TO old_assets')
        # Проверяем перенос старой схемы с сохранением структуры прочих таблиц
        db.execute('CREATE TABLE assets AS SELECT id,inventory_no,name,location,protection_class,description,created_at FROM old_assets')
        db.execute('DROP TABLE old_assets')
    initialize(path)
    with connect(path) as db:
        assert 'active' in [r['name'] for r in db.execute('PRAGMA table_info(assets)')]
        assert 'resolved_at' in [r['name'] for r in db.execute('PRAGMA table_info(tickets)')]


def test_edit_routes_reject_non_admin(client):
    from conftest import csrf, login

    login(client)
    assert client.post('/users/3/edit', data={
        'csrf_token': csrf(client, '/tickets'), 'username': 'bad',
        'full_name': 'Не должно измениться', 'role': 'admin', 'active': '1',
    }).status_code == 403
    assert client.post('/assets/1/delete', data={
        'csrf_token': csrf(client, '/tickets'),
    }).status_code == 403
    client.post('/logout', data={'csrf_token': csrf(client, '/')})
    login(client, 'admin', 'AdminTest123!')
    response = client.post('/assets/1/edit', data={
        'csrf_token': csrf(client, '/assets'), 'inventory_no': 'FW-02',
        'name': 'Исправленное СЗИ', 'location': 'Кабинет 1',
        'protection_class': 'Сетевая защита',
    }, follow_redirects=True)
    assert response.status_code == 200
    assert 'Исправленное СЗИ' in response.get_data(as_text=True)
    result = client.post('/users/3/edit', data={
        'csrf_token': csrf(client, '/users'), 'username': 'alice_1',
        'full_name': 'Алиса Петрова', 'role': 'requester', 'active': '1',
    }, follow_redirects=True)
    assert result.status_code == 200 and 'alice_1' in result.get_data(as_text=True)
