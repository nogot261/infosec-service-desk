"""Веб-интерфейс системы учета заявок."""

import csv
import io
import os
import secrets
import sqlite3
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware

from . import service
from .db import connect, initialize
from .security import check_csrf, new_csrf_token

PACKAGE_DIR = Path(__file__).resolve().parent


def create_app(db_path: str | Path | None = None, secret_key: str | None = None) -> FastAPI:
    db_path = Path(db_path or os.getenv("INFOSEC_DB_PATH", "instance/infosec.sqlite3")).resolve()
    initialize(db_path)

    app = FastAPI(
        title="Учет заявок на обслуживание систем защиты информации",
        docs_url=None, redoc_url=None,
    )
    app.state.db_path = db_path
    app.add_middleware(
        SessionMiddleware,
        secret_key=secret_key or os.getenv("INFOSEC_SECRET_KEY") or secrets.token_urlsafe(48),
        same_site="lax",
        https_only=os.getenv("INFOSEC_SECURE_COOKIES", "0") == "1",
        max_age=60 * 60 * 8,
    )
    app.mount("/static", StaticFiles(directory=str(PACKAGE_DIR / "static")), name="static")
    templates = Jinja2Templates(directory=str(PACKAGE_DIR / "templates"))
    templates.env.filters["ticket_no"] = lambda value: f"З-{value:06d}"
    templates.env.globals.update(
        categories=service.CATEGORIES,
        priorities=service.PRIORITIES,
        statuses=service.STATUSES,
        roles=service.ROLES,
    )

    def current_user(request: Request):
        user_id = request.session.get("user_id")
        return service.find_user(db_path, user_id) if user_id is not None else None

    def render(request: Request, template: str, **context):
        if "csrf_token" not in request.session:
            request.session["csrf_token"] = new_csrf_token()
        return templates.TemplateResponse(
            request,
            template,
            {
                "user": current_user(request),
                "csrf_token": request.session["csrf_token"],
                "message": request.session.pop("message", ""),
                "error": request.session.pop("error", ""),
                **context,
            },
        )

    def flash_redirect(request, path, message="", error=""):
        if message:
            request.session["message"] = message
        if error:
            request.session["error"] = error
        return RedirectResponse(path, status_code=303)

    def require_user(request: Request, roles=None):
        user = current_user(request)
        if user is None:
            raise HTTPException(status_code=401, detail="Войдите в систему")
        if roles and user["role"] not in roles:
            raise HTTPException(status_code=403, detail="Недостаточно прав")
        return user

    async def secure_form(request: Request):
        data = await request.form()
        if not check_csrf(request.session.get("csrf_token"), data.get("csrf_token")):
            raise HTTPException(status_code=403, detail="Ошибка проверки формы. Обновите страницу")
        return data

    @app.get("/health")
    def health():
        with connect(db_path) as db:
            db.execute("SELECT 1").fetchone()
        return {"status": "ok"}

    @app.get("/login", response_class=HTMLResponse)
    def login(request: Request):
        if current_user(request):
            return RedirectResponse("/", status_code=303)
        return render(request, "login.html", title="Вход")

    @app.post("/login")
    async def login_post(request: Request):
        data = await secure_form(request)
        user = service.authenticate(
            db_path, str(data.get("username", "")), str(data.get("password", ""))
        )
        if user is None:
            return flash_redirect(request, "/login", error="Неверный логин или пароль")
        request.session.clear()
        request.session["user_id"] = user["id"]
        request.session["csrf_token"] = new_csrf_token()
        return RedirectResponse("/", status_code=303)

    @app.post("/logout")
    async def logout(request: Request):
        await secure_form(request)
        request.session.clear()
        return RedirectResponse("/login", status_code=303)

    @app.get("/", response_class=HTMLResponse)
    def dashboard(request: Request):
        user = require_user(request)
        return render(
            request,
            "dashboard.html",
            title="Панель управления",
            stats=service.statistics(db_path, user),
            tickets=service.list_tickets(db_path, user)[:8],
        )

    @app.get("/tickets", response_class=HTMLResponse)
    def tickets_page(request: Request, status: str = "", q: str = ""):
        user = require_user(request)
        return render(
            request, "tickets.html", title="Заявки",
            tickets=service.list_tickets(db_path, user, status, q),
            status_filter=status, search=q,
        )

    @app.get("/tickets/new", response_class=HTMLResponse)
    def new_ticket_page(request: Request):
        require_user(request)
        return render(
            request, "ticket_new.html", title="Новая заявка", assets=service.assets(db_path)
        )

    @app.post("/tickets")
    async def create_ticket_post(request: Request):
        user = require_user(request)
        data = await secure_form(request)
        try:
            asset_id = int(data["asset_id"]) if data.get("asset_id") else None
            ticket_id = service.create_ticket(
                db_path, user, str(data.get("title", "")), str(data.get("description", "")),
                str(data.get("category", "")), str(data.get("priority", "")), asset_id,
            )
        except (ValueError, sqlite3.IntegrityError) as exc:
            return flash_redirect(request, "/tickets/new", error=str(exc))
        return flash_redirect(request, f"/tickets/{ticket_id}", message="Заявка зарегистрирована")

    @app.get("/tickets/{ticket_id}", response_class=HTMLResponse)
    def ticket_page(request: Request, ticket_id: int):
        user = require_user(request)
        details = service.get_ticket(db_path, user, ticket_id)
        if details is None:
            raise HTTPException(status_code=404, detail="Заявка не найдена")
        ticket, comments, events = details
        assignees = [x for x in service.users(db_path) if x["active"] and x["role"] != "requester"]
        return render(
            request, "ticket_detail.html", title=f"Заявка З-{ticket_id:06d}",
            ticket=ticket, comments=comments, events=events, assignees=assignees,
            transitions=service.TRANSITIONS[ticket["status"]],
        )

    @app.post("/tickets/{ticket_id}/comments")
    async def comment_post(request: Request, ticket_id: int):
        user = require_user(request)
        data = await secure_form(request)
        try:
            service.add_comment(db_path, user, ticket_id, str(data.get("body", "")))
        except ValueError as exc:
            return flash_redirect(request, f"/tickets/{ticket_id}", error=str(exc))
        except PermissionError:
            raise HTTPException(status_code=404, detail="Заявка не найдена") from None
        return flash_redirect(request, f"/tickets/{ticket_id}", message="Комментарий сохранен")

    @app.post("/tickets/{ticket_id}/update")
    async def update_ticket_post(request: Request, ticket_id: int):
        user = require_user(request, {"operator", "admin"})
        data = await secure_form(request)
        try:
            assignee_id = int(data["assignee_id"]) if data.get("assignee_id") else None
            service.update_ticket(
                db_path, user, ticket_id, str(data.get("status", "")), assignee_id
            )
        except (ValueError, sqlite3.IntegrityError) as exc:
            return flash_redirect(request, f"/tickets/{ticket_id}", error=str(exc))
        return flash_redirect(request, f"/tickets/{ticket_id}", message="Изменения сохранены")

    @app.get("/assets", response_class=HTMLResponse)
    def assets_page(request: Request):
        require_user(request)
        return render(
            request, "assets.html", title="Средства защиты", assets=service.assets(db_path)
        )

    @app.post("/assets")
    async def assets_post(request: Request):
        require_user(request, {"admin"})
        data = await secure_form(request)
        try:
            service.add_asset(
                db_path, str(data.get("inventory_no", "")), str(data.get("name", "")),
                str(data.get("location", "")), str(data.get("protection_class", "")),
                str(data.get("description", "")),
            )
        except (ValueError, sqlite3.IntegrityError) as exc:
            return flash_redirect(request, "/assets", error=f"Не удалось сохранить: {exc}")
        return flash_redirect(request, "/assets", message="Средство защиты добавлено")

    @app.get("/users", response_class=HTMLResponse)
    def users_page(request: Request):
        require_user(request, {"admin"})
        return render(request, "users.html", title="Пользователи", users=service.users(db_path))

    @app.post("/users")
    async def users_post(request: Request):
        require_user(request, {"admin"})
        data = await secure_form(request)
        try:
            service.create_user(
                db_path, str(data.get("username", "")), str(data.get("full_name", "")),
                str(data.get("password", "")), str(data.get("role", "requester")),
            )
        except (ValueError, sqlite3.IntegrityError) as exc:
            return flash_redirect(
                request, "/users", error=f"Не удалось создать учетную запись: {exc}"
            )
        return flash_redirect(request, "/users", message="Пользователь создан")

    @app.get("/audit", response_class=HTMLResponse)
    def audit_page(request: Request):
        require_user(request, {"admin"})
        return render(
            request, "audit.html", title="Журнал действий", events=service.audit_events(db_path)
        )

    @app.get("/export.csv")
    def csv_export(request: Request):
        user = require_user(request, {"operator", "admin"})
        records = service.list_tickets(db_path, user)
        buf = io.StringIO()
        writer = csv.writer(buf, delimiter=";")
        writer.writerow(
            ["Номер", "Тема", "Категория", "Приоритет", "Статус",
             "Автор", "Исполнитель", "Создана"]
        )
        for row in records:
            values = [
                f"З-{row['id']:06d}", row["title"], service.CATEGORIES[row["category"]],
                service.PRIORITIES[row["priority"]], service.STATUSES[row["status"]],
                row["author_name"], row["assignee_name"] or "", row["created_at"],
            ]
            writer.writerow(
                ["'" + str(v) if str(v).startswith(("=", "+", "-", "@")) else v
                 for v in values]
            )
        return Response(
            "\ufeff" + buf.getvalue(), media_type="text/csv; charset=utf-8",
            headers={
                "Content-Disposition": 'attachment; filename="infosec_tickets.csv"',
                "Cache-Control": "no-store",
            },
        )

    @app.exception_handler(HTTPException)
    async def handle_http_error(request: Request, exc: HTTPException):
        if exc.status_code == 401 and request.url.path != "/login":
            return RedirectResponse("/login", status_code=303)
        return HTMLResponse(
            f"<html lang='ru'><meta charset='utf-8'><title>Ошибка</title>"
            f"<body style='font:16px Arial;margin:4em'><h1>Ошибка {exc.status_code}</h1>"
            f"<p>{'Недостаточно прав' if exc.status_code == 403 else 'Страница не найдена'}</p>"
            "<a href='/'>На главную</a></body></html>",
            status_code=exc.status_code,
        )

    return app
