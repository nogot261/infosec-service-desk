"""Приемочные проверки дополнительных требований к преддипломной практике."""

import csv
import io
import re
from openpyxl import load_workbook

from conftest import csrf, login
from infosec_desk.db import connect


def test_public_pages_without_login(client):
    from infosec_desk.web import PUBLIC_PAGES
    assert len(PUBLIC_PAGES) >= 10
    for slug in PUBLIC_PAGES:
        result = client.get(f"/public/{slug}")
        assert result.status_code == 200
        assert 'Хлебные крошки' in result.get_data(as_text=True)
    assert client.get('/feedback').status_code == 200


def test_admin_and_personal_pages_have_access_checks(client):
    admin_pages = ('/users', '/audit', '/admin/services', '/admin/feedback',
                   '/admin/settings', '/admin/analytics', '/admin/data-exchange')
    personal_pages = ('/', '/tickets', '/tickets/new', '/assets',
                      '/profile', '/my-activity', '/notifications', '/my-help')
    for url in admin_pages + personal_pages:
        assert client.get(url).status_code == 303
    login(client)
    for url in personal_pages:
        assert client.get(url).status_code == 200
    for url in admin_pages:
        assert client.get(url).status_code == 403
    client.post('/logout', data={'csrf_token': csrf(client, '/')})
    login(client, 'admin', 'AdminTest123!')
    for url in admin_pages:
        assert client.get(url).status_code == 200


def test_feedback_saved_and_admin_can_review(client, db_path):
    form = {'csrf_token': csrf(client, '/feedback'), 'sender_name': 'Посетитель',
            'sender_email': 'visitor@example.org', 'subject': 'Вопрос',
            'body': 'Подскажите, как оформить новое обращение.'}
    assert client.post('/feedback', data=form).status_code == 303
    with connect(db_path) as db:
        assert db.execute('SELECT COUNT(*) FROM feedback_messages').fetchone()[0] == 1
    login(client, 'admin', 'AdminTest123!')
    assert 'Подскажите, как оформить' in client.get('/admin/feedback').get_data(as_text=True)


def test_complete_and_filtered_csv_export_501(client, db_path):
    with connect(db_path) as db:
        db.executemany(
            "INSERT INTO tickets(title,description,category,priority,status,author_id) "
            "VALUES(?,?,?,?,?,?)",
            [(f'Учебное обращение {i}', 'Проверка экспорта реестра заявок',
              'access', 'normal', 'closed' if i < 251 else 'new', 3)
             for i in range(501)],
        )
        db.commit()
    login(client, 'operator', 'OperatorTest123!')
    response = client.get('/export.csv')
    assert response.status_code == 200
    data = list(csv.reader(io.StringIO(response.data.decode('utf-8-sig')), delimiter=';'))
    assert len(data) == 502  # 501 заявка + строка заголовков
    response = client.get('/export.csv?status=closed')
    filtered = list(csv.reader(io.StringIO(response.data.decode('utf-8-sig')), delimiter=';'))
    assert len(filtered) == 252  # 251 заявка + строка заголовков
    xlsx = load_workbook(io.BytesIO(client.get('/export.xlsx').data))
    assert xlsx.active.max_row == 502
    xlsx_filtered = load_workbook(io.BytesIO(client.get('/export.xlsx?status=closed').data))
    assert xlsx_filtered.active.max_row == 252


def test_json_asset_exchange_and_upload_csrf(client, db_path):
    login(client, 'admin', 'AdminTest123!')
    exported = client.get('/admin/assets.json')
    assert exported.status_code == 200
    assert exported.get_json()['format'] == 'infosec-assets-v1'
    response = client.post('/admin/assets.json', data={})
    assert response.status_code == 403


def test_new_database_has_used_entities(db_path):
    with connect(db_path) as db:
        tables = {r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    assert len(tables - {'sqlite_sequence'}) >= 10
    for name in ('service_catalog', 'feedback_messages', 'ticket_attachments',
                 'ticket_status_history', 'notifications', 'application_settings'):
        assert name in tables
