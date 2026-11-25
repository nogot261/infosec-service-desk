"""Проверки отступов и структуры форм на основных страницах."""

import re
from pathlib import Path

from conftest import csrf, login


ROOT = Path(__file__).resolve().parents[1]
TEMPLATES = ROOT / "src/infosec_desk/templates"
STYLE = ROOT / "src/infosec_desk/static/style.css"


def test_feedback_form_is_padded_and_works(client):
    html = client.get("/feedback").get_data(as_text=True)
    assert 'class="panel form-card"' in html
    assert 'class="panel-body"' in html
    for field in ("feedback-name", "feedback-email", "feedback-subject", "feedback-body"):
        assert f'for="{field}"' in html
        assert f'id="{field}"' in html
    assert 'class="form-actions"' in html

    response = client.post(
        "/feedback",
        data={
            "csrf_token": csrf(client, "/feedback"),
            "sender_name": "Проверяющий",
            "sender_email": "teacher@example.org",
            "subject": "Проверка формы",
            "body": "Проверка отправки формы обратной связи",
        },
        follow_redirects=True,
    )
    assert response.status_code == 200
    assert "Сообщение зарегистрировано" in response.get_data(as_text=True)


def test_admin_forms_are_padded(client):
    login(client, "admin", "AdminTest123!")
    for route in ("/admin/settings", "/admin/services", "/admin/data-exchange"):
        response = client.get(route)
        assert response.status_code == 200
        html = response.get_data(as_text=True)
        assert 'class="panel-body"' in html
        assert 'class="form-actions"' in html
        assert "class=\"stack\"" in html


def test_lists_and_tables_have_readable_wrappers(client):
    login(client, "admin", "AdminTest123!")
    for route in ("/profile", "/my-activity", "/notifications", "/my-help"):
        html = client.get(route).get_data(as_text=True)
        assert 'class="panel-body' in html
    for route in ("/admin/feedback", "/admin/services", "/admin/analytics"):
        html = client.get(route).get_data(as_text=True)
        assert 'class="table-wrap"' in html
        assert 'class="data-table"' in html


def test_every_panel_uses_padding_or_table_layout():
    section_pattern = re.compile(r'<section\b[^>]*\bclass="([^"]*\bpanel\b[^"]*)"[^>]*>', re.S)
    first_element_pattern = re.compile(r'<([a-z]+)\b[^>]*\bclass="([^"]*)"[^>]*>', re.S)
    allowed_wrappers = {"panel-body", "field-panel", "table-wrap", "panel-header", "filters"}
    for path in TEMPLATES.glob("*.html"):
        content = path.read_text(encoding="utf-8")
        for section in section_pattern.finditer(content):
            if "public-content" in section.group(1):
                continue
            following = content[section.end():]
            first = first_element_pattern.search(following)
            assert first is not None, f"{path.name}: пустой блок"
            classes = set(first.group(2).split())
            assert allowed_wrappers & classes, f"{path.name}: содержимое блока без отступов"


def test_compact_responsive_cards_and_table_scroll():
    css = STYLE.read_text(encoding="utf-8")
    assert ".form-card { width: 100%; max-width: 760px; }" in css
    assert ".form-card .panel-body { padding: 30px 34px; }" in css
    assert ".table-wrap { overflow-x: auto; }" in css
    assert "@media(max-width:540px)" in css
    assert ".form-card .panel-body { padding: 22px 18px; }" in css
