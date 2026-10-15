import pytest
from fastapi.testclient import TestClient

from infosec_desk.db import initialize
from infosec_desk.service import add_asset, create_user
from infosec_desk.web import create_app


@pytest.fixture
def db_path(tmp_path):
    path = tmp_path / "desk.sqlite3"
    initialize(path)
    create_user(path, "admin", "Главный администратор", "AdminTest123!", "admin")
    create_user(path, "operator", "Специалист ИБ", "OperatorTest123!", "operator")
    create_user(path, "alice", "Алиса", "AliceTest123!", "requester")
    create_user(path, "bob", "Борис", "BobTest123!", "requester")
    add_asset(path, "FW-01", "Межсетевой экран", "Серверная", "Сетевой")
    return path


@pytest.fixture
def client(db_path):
    with TestClient(create_app(db_path, secret_key="test-secret-not-for-production")) as client:
        yield client


def csrf(client, path="/login"):
    from bs4 import BeautifulSoup

    page = client.get(path)
    return BeautifulSoup(page.text, "html.parser").find("input", {"name": "csrf_token"})["value"]


def login(client, username="alice", password="AliceTest123!"):
    return client.post(
        "/login", data={"csrf_token": csrf(client), "username": username, "password": password},
        follow_redirects=True,
    )
