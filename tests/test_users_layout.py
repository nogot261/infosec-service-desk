"""Проверки таблицы пользователей и формы редактирования."""
from pathlib import Path
from conftest import login

STYLE = Path(__file__).resolve().parents[1] / "src/infosec_desk/static/style.css"

def test_user_actions_are_consistent_and_editor_spans_table(client):
    login(client, "admin", "AdminTest123!")
    response = client.get("/users")
    assert response.status_code == 200
    html = response.get_data(as_text=True)
    assert 'data-user-editor-target="user-editor-' in html
    assert 'aria-expanded="false"' in html
    assert 'class="user-editor-row"' in html
    assert 'colspan="5"' in html
    assert 'class="user-editor-form stack"' in html
    assert 'class="secondary danger button-sm"' in html
    assert "Отключить" in html
    assert "Сохранить изменения" in html
    assert 'action="/users/' in html

def test_user_form_grid_alignment_and_table_css():
    css = STYLE.read_text(encoding="utf-8")
    assert "gap: 18px; align-items: start;" in css
    assert ".users-table .table-actions" in css
    assert ".users-table .user-editor-row[hidden]" in css
    assert ".users-table .user-editor-form" in css
