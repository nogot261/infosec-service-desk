"""Предметная проверка без запуска веб-сервера и без сторонних пакетов."""
import csv
import gc
from contextlib import closing
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from infosec_desk.db import connect, initialize
from infosec_desk import service
from infosec_desk.exchange import export_assets, import_assets


def main():
    completed = []
    demo = ROOT / "instance" / "demo.sqlite3"
    assert demo.is_file(), "Не найдена учебная БД"
    with closing(connect(demo)) as db:
        tables = {r[0] for r in db.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name!='sqlite_sequence'"
        )}
        assert len(tables) == 11
        completed.append("БД содержит 11 таблиц")
        assert db.execute("SELECT count(*) FROM users").fetchone()[0] == 3
        completed.append("Три учебные учётные записи")
        assert db.execute("SELECT count(*) FROM tickets").fetchone()[0] == 501
        assert db.execute("SELECT count(*) FROM tickets WHERE status='closed'").fetchone()[0] == 251
        completed.append("Реестр содержит 501 заявку, 251 закрытую")
        assert db.execute("SELECT count(*) FROM comments WHERE ticket_id=1").fetchone()[0] == 2
        assert [r[0] for r in db.execute(
            "SELECT new_status FROM ticket_status_history WHERE ticket_id=1 ORDER BY id"
        )] == ['new', 'in_progress', 'resolved', 'closed']
        completed.append("В истории заявки № 1 четыре состояния и два комментария")
        user = dict(db.execute("SELECT * FROM users WHERE username='operator'").fetchone())
        requester = dict(db.execute("SELECT * FROM users WHERE username='employee'").fetchone())
    assert len(service.list_tickets(demo, user)) == 501
    assert len(service.list_tickets(demo, user, status='closed')) == 251
    completed.append("Предметные выборки возвращают 501 и 251 запись")
    for kind, target in [('all_501', 502), ('closed_251', 252)]:
        with (ROOT / 'samples' / f'registry_{kind}.csv').open(encoding='utf-8-sig', newline='') as fp:
            assert len(list(csv.reader(fp, delimiter=';'))) == target
    completed.append("Контрольные CSV содержат 501 и 251 строки плюс заголовок")
    with tempfile.TemporaryDirectory() as tempdir:
        db_file = Path(tempdir) / 'exercise.sqlite3'
        initialize(db_file)
        operator_id = service.create_user(db_file, 'oper', 'Специалист', 'Security123!', 'operator')
        owner_id = service.create_user(db_file, 'owner', 'Заявитель', 'Security123!', 'requester')
        stranger_id = service.create_user(db_file, 'stranger', 'Другой заявитель', 'Security123!', 'requester')
        op = {'id': operator_id, 'role': 'operator'}
        owner = {'id': owner_id, 'role': 'requester'}
        stranger = {'id': stranger_id, 'role': 'requester'}
        ticket_id = service.create_ticket(db_file, owner, 'Проверка доступа',
            'У сотрудника отсутствует доступ к защищенной папке', 'access', 'high')
        assert service.get_ticket(db_file, stranger, ticket_id) is None
        completed.append("Другой заявитель не видит чужое обращение")
        try:
            service.update_ticket(db_file, op, ticket_id, 'closed', operator_id)
        except ValueError:
            pass
        else:
            raise AssertionError('Недопустимый переход new -> closed принят')
        service.update_ticket(db_file, op, ticket_id, 'in_progress', operator_id)
        service.add_comment(db_file, owner, ticket_id, 'Дополнительное описание сбоя')
        service.update_ticket(db_file, op, ticket_id, 'resolved', operator_id)
        service.update_ticket(db_file, op, ticket_id, 'closed', operator_id)
        assert service.get_ticket(db_file, owner, ticket_id)[0]['closed_at']
        completed.append("Проверка допустимых статусов и даты закрытия")
        service.create_feedback(db_file, 'Посетитель', 'visitor@example.org',
            'Вопрос', 'Нужно уточнить порядок подачи обращения')
        with closing(connect(db_file)) as db:
            assert db.execute('SELECT count(*) FROM feedback_messages').fetchone()[0] == 1
        completed.append("Форма обратной связи сохраняет запись через предметную функцию")
        service.add_asset(db_file, 'AV-001', 'Антивирус', 'Серверная', 'Антивирусная защита')
        payload=Path(tempdir) / 'assets.json'
        assert export_assets(db_file, payload) == 1
        result=import_assets(db_file, payload)
        assert result['added'] == 0 and result['skipped'] == 1
        completed.append("JSON справочника экспортируется и импортируется без дублей")
        # SQLite-соединения в предметных функциях могут закрыться после GC.
        # На Windows открытый файл базы нельзя удалить из временной папки.
        gc.collect()
    for idx, check in enumerate(completed, 1):
        print(f'{idx:02d}. OK - {check}')
    print(f'ИТОГО: {len(completed)} предметных проверок пройдено')


if __name__ == '__main__':
    main()
