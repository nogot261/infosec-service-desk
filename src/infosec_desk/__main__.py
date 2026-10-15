"""Команды запуска и администрирования."""

import argparse
import getpass
import os
import secrets
import sqlite3
from pathlib import Path

from .db import connect, initialize
from .service import add_asset, create_ticket, create_user, find_user


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
    print("Демонстрационные пользователи: admin, operator, employee")
    print("Пароль для всех: DemoPass123! (только для локального знакомства)")


def _users(db_path):
    with connect(db_path) as db:
        return [dict(row) for row in db.execute("SELECT * FROM users")]


def main():
    parser = argparse.ArgumentParser(description="Учет заявок на обслуживание средств защиты информации")
    parser.add_argument("command", nargs="?", choices=["serve", "init-db", "create-admin", "seed-demo"], default="serve")
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
    if args.command == "seed-demo":
        seed_demo(db_path)
        return
    import uvicorn
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
    uvicorn.run(app, host=args.host, port=args.port, log_level="info")


if __name__ == "__main__":
    main()
