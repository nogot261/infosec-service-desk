"""Команды запуска и администрирования."""

import argparse
import getpass
import os
import secrets
import sqlite3
from pathlib import Path

from .db import connect, initialize
from .exchange import export_assets, import_assets
from .maintenance import backup_database, inspect_update_manifest
from .service import add_asset, create_ticket, create_user, reset_admin_password, add_service, update_ticket, list_tickets


def seed_demo(db_path):
    with connect(db_path) as db:
        if db.execute("SELECT COUNT(*) FROM users").fetchone()[0]:
            print("База уже содержит пользователей. Демонстрационные данные не добавлены")
            return
    accounts = [
        ("admin", "Администратор системы", "admin"),
        ("operator", "Специалист отдела защиты", "operator"),
        ("employee", "Сотрудник организации", "requester"),
    ]
    for login, name, role in accounts:
        create_user(db_path, login, name, "DemoPass123!", role)
    add_asset(db_path, "FW-001", "Межсетевой экран", "Серверная", "Сетевая защита")
    add_asset(db_path, "AV-002", "Сервер антивирусной защиты", "ЦОД", "Антивирусная защита")
    requester = next(x for x in _users(db_path) if x["username"] == "employee")
    create_ticket(
        db_path, requester, "Ошибка доступа к защищенному ресурсу",
        "После обновления учетной записи доступ к общему каталогу ограничен.",
        "access", "high", 1,
    )
    create_ticket(
        db_path, requester, "Проверка актуальности антивирусных баз",
        "Требуется проверить получение обновлений на рабочей станции отдела.",
        "antivirus", "normal", 2,
    )
    for code, name, description, category in (
        ("ACCESS", "Доступ к ресурсу", "Ошибки входа и управления правами", "access"),
        ("AV", "Антивирусная защита", "Настройка и обновление защиты", "antivirus"),
        ("NETWORK", "Сетевая защита", "Проверка доступа и межсетевого экрана", "network"),
        ("CRYPTO", "Криптографическая защита", "Сертификаты и шифрование", "crypto"),
        ("BACKUP", "Резервное копирование", "Копии и восстановление данных", "backup"),
    ):
        add_service(db_path, code, name, description, category)
    # Дополнительные учебные заявки нужны для проверки полного экспорта.
    # Реальных персональных данных в учебном комплекте нет.
    with connect(db_path) as db:
        db.execute("BEGIN")
        for i in range(3, 502):
            status = "closed" if i % 2 else "new"
            db.execute(
                """INSERT INTO tickets(
                       title, description, category, priority, status, author_id,
                       assignee_id, resolved_at, closed_at
                   ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    f"Учебное обращение {i}",
                    f"Тестовая заявка номер {i} для проверки фильтрации и экспорта.",
                    "access" if i % 2 else "antivirus", "normal", status,
                    requester["id"], 2 if status == "closed" else None,
                    "2026-11-23 11:00:00" if status == "closed" else None,
                    "2026-11-23 12:00:00" if status == "closed" else None,
                ),
            )
            db.execute(
                "INSERT INTO ticket_status_history(ticket_id,actor_id,old_status,new_status) VALUES(?,?,?,?)",
                (i, requester["id"], None, "new"),
            )
            if status == "closed":
                for old_status, new_status in (("new", "in_progress"),
                                                ("in_progress", "resolved"),
                                                ("resolved", "closed")):
                    db.execute(
                        "INSERT INTO ticket_status_history(ticket_id,actor_id,old_status,new_status) VALUES(?,?,?,?)",
                        (i, 2, old_status, new_status),
                    )
        db.commit()
    print("Демонстрационные пользователи: admin, operator, employee")
    print("Пароль для всех: DemoPass123! (только для локального знакомства)")


def _users(db_path):
    with connect(db_path) as db:
        return [dict(row) for row in db.execute("SELECT * FROM users")]


def main():
    parser = argparse.ArgumentParser(
        description="Учет заявок на обслуживание средств защиты информации"
    )
    parser.add_argument(
        "command", nargs="?",
        choices=["serve", "init-db", "create-admin", "reset-password", "seed-demo",
                 "import-assets", "export-assets", "backup-db", "check-update"],
        default="serve",
    )
    parser.add_argument("--file", help="Файл обмена, резервной копии или обновления")
    parser.add_argument("--username", default="admin")
    parser.add_argument("--db", default=os.getenv("INFOSEC_DB_PATH", "instance/infosec.sqlite3"))
    parser.add_argument("--host", default=os.getenv("INFOSEC_HOST", "127.0.0.1"))
    parser.add_argument("--port", type=int, default=int(os.getenv("INFOSEC_PORT", "8000")))
    args = parser.parse_args()
    db_path = Path(args.db).resolve()
    initialize(db_path)

    if args.command == "init-db":
        print(f"База данных готова: {db_path}")
        return
    if args.command == "create-admin":
        username = input("Логин администратора: ").strip()
        full_name = input("ФИО: ").strip()
        password = getpass.getpass("Пароль (минимум 10 символов): ")
        try:
            create_user(db_path, username, full_name, password, "admin")
        except (ValueError, sqlite3.IntegrityError) as exc:
            parser.error(str(exc))
        print("Администратор создан")
        return
    if args.command == "reset-password":
        password = getpass.getpass("Новый пароль (не менее 10 символов): ")
        confirm = getpass.getpass("Повторите пароль: ")
        if password != confirm:
            parser.error("Пароли не совпадают")
        try:
            reset_admin_password(db_path, args.username, password)
        except ValueError as exc:
            parser.error(str(exc))
        print(f"Пароль администратора {args.username} изменен")
        return
    if args.command in {"import-assets", "export-assets", "backup-db", "check-update"}:
        if not args.file:
            parser.error("Укажите путь к файлу аргументом --file")
        try:
            if args.command == "import-assets":
                result = import_assets(db_path, args.file)
                print(f"Импортировано: {result['added']}; пропущено: {result['skipped']}")
            elif args.command == "export-assets":
                print(f"Экспортировано объектов: {export_assets(db_path, args.file)}")
            elif args.command == "backup-db":
                print(f"Резервная копия: {backup_database(db_path, args.file)}")
            else:
                report = inspect_update_manifest(args.file)
                status = ("есть новая версия" if report["needs_update"]
                          else "обновление не требуется")
                print(f"Текущая версия: {report['installed']}; "
                      f"доступная версия: {report['available']}; {status}")
        except (OSError, ValueError) as exc:
            parser.error(str(exc))
        return
    if args.command == "seed-demo":
        seed_demo(db_path)
        return
    from .web import create_app

    with connect(db_path) as db:
        count = db.execute("SELECT COUNT(*) FROM users").fetchone()[0]
    if not count:
        password = secrets.token_urlsafe(18)
        create_user(db_path, "admin", "Администратор системы", password, "admin")
        print("Создана первоначальная учетная запись:")
        print("  Логин: admin")
        print(f"  Пароль: {password}")
        print("Сохраните пароль. Повторно он не выводится")
    if args.host not in {"127.0.0.1", "localhost", "::1"} and not os.getenv("INFOSEC_SECRET_KEY"):
        parser.error("Для сетевого запуска задайте INFOSEC_SECRET_KEY и настройте HTTPS")
    app = create_app(db_path)
    print(f"Адрес: http://{args.host}:{args.port}")
    app.run(host=args.host, port=args.port, debug=False, use_reloader=False)


if __name__ == "__main__":
    main()
