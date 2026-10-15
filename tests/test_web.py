from conftest import csrf, login


def test_health(client):
    assert client.get("/health").json() == {"status": "ok"}


def test_guest_redirect(client):
    response = client.get("/tickets", follow_redirects=False)
    assert response.status_code == 303
    assert response.headers["location"] == "/login"


def test_login_and_logout(client):
    assert login(client).status_code == 200
    assert "Панель управления" in client.get("/").text
    token = csrf(client, "/")
    response = client.post("/logout", data={"csrf_token": token}, follow_redirects=False)
    assert response.status_code == 303
    assert client.get("/tickets", follow_redirects=False).status_code == 303


def test_login_rejects_bad_password(client):
    response = client.post(
        "/login",
        data={"csrf_token": csrf(client), "username": "alice", "password": "bad"},
        follow_redirects=True,
    )
    assert "Неверный логин или пароль" in response.text


def test_csrf_rejects_missing_token(client):
    login(client)
    response = client.post(
        "/tickets",
        data={
            "title": "Проверка доступа",
            "description": "Проверка защиты с требуемой длиной",
            "category": "access",
            "priority": "normal",
        },
    )
    assert response.status_code == 403


def test_create_ticket_web(client):
    login(client)
    response = client.post("/tickets", data={
        "csrf_token": csrf(client, "/tickets/new"),
        "title": "Проблема с сертификатом",
        "description": "При подключении возникает ошибка сертификата",
        "category": "crypto",
        "priority": "critical",
        "asset_id": "1",
    }, follow_redirects=True)
    assert response.status_code == 200
    assert "Проблема с сертификатом" in response.text
    assert "З-000001" in response.text


def test_requester_denied_admin_and_export(client):
    login(client)
    assert client.get("/users").status_code == 403
    assert client.get("/audit").status_code == 403
    assert client.get("/export.csv").status_code == 403


def test_operator_can_update_and_export(client):
    login(client)
    client.post("/tickets", data={
        "csrf_token": csrf(client, "/tickets/new"),
        "title": "Проблема настройки сети", "description": "Проверить журналы сетевого экрана",
        "category": "network", "priority": "high",
    })
    client.post("/logout", data={"csrf_token": csrf(client, "/")})
    login(client, "operator", "OperatorTest123!")
    response = client.post("/tickets/1/update", data={
        "csrf_token": csrf(client, "/tickets/1"), "status": "in_progress", "assignee_id": "2"
    }, follow_redirects=True)
    assert "В работе" in response.text
    exported = client.get("/export.csv")
    assert exported.status_code == 200 and "text/csv" in exported.headers["content-type"]
    assert "Проблема настройки сети" in exported.content.decode("utf-8-sig")


def test_admin_can_create_user_and_asset(client):
    login(client, "admin", "AdminTest123!")
    result = client.post("/users", data={
        "csrf_token": csrf(client, "/users"),
        "username": "specialist2", "full_name": "Второй специалист",
        "password": "SpecialistTest123!", "role": "operator",
    }, follow_redirects=True)
    assert "specialist2" in result.text
    result = client.post("/assets", data={
        "csrf_token": csrf(client, "/assets"),
        "inventory_no": "AV-20", "name": "Антивирусный сервер",
        "location": "ЦОД", "protection_class": "Антивирусная защита",
    }, follow_redirects=True)
    assert "Антивирусный сервер" in result.text


def test_html_escaping(client):
    login(client)
    payload = "<script>alert('x')</script>"
    client.post("/tickets", data={
        "csrf_token": csrf(client, "/tickets/new"),
        "title": payload,
        "description": "Проверка безопасного вывода текста в шаблоне",
        "category": "other", "priority": "normal",
    })
    result = client.get("/tickets/1")
    assert "&lt;script&gt;" in result.text
    assert payload not in result.text
