"""Проверка видимых элементов открытых страниц без привязки к браузеру."""

from pathlib import Path

from conftest import login


STYLE = Path(__file__).resolve().parents[1] / "src/infosec_desk/static/style.css"


def test_guest_has_login_link_in_top_right(client):
    page = client.get("/public/overview").get_data(as_text=True)
    assert 'class="topbar-account"' in page
    assert 'class="topbar-login" href="/login"' in page
    assert "Гость" in page
    assert "Войти" in page
    assert 'href="/login">Вход</a>' in page


def test_authenticated_user_has_no_duplicate_login_button(client):
    login(client)
    page = client.get("/").get_data(as_text=True)
    assert 'class="topbar-account"' in page
    assert 'class="topbar-login"' not in page


def test_public_page_has_padded_content_and_actions(client):
    page = client.get("/public/overview").get_data(as_text=True)
    assert 'class="panel public-content"' in page
    assert 'class="public-intro"' in page
    assert 'class="public-points"' in page
    assert 'class="public-actions"' in page
    assert 'href="/feedback"' in page


def test_footer_has_author_and_visible_contacts_link(client):
    page = client.get("/public/overview").get_data(as_text=True)
    assert "Разработчик: Коробейникова Мария Вячеславовна" in page
    assert 'href="/public/contacts">Контакты службы</a>' in page
    assert "Преддипломная практика." not in page


def test_responsive_style_rules_exist():
    css = STYLE.read_text(encoding="utf-8")
    assert "width: min(100%, 445px)" in css
    assert ".public-content { margin-top: 0; padding: 28px 34px 30px; }" in css
    assert '.site-footer a { color: var(--accent); text-decoration: underline' in css
    assert "@media (max-width: 540px)" in css
    assert "scrollbar-width: thin" in css
