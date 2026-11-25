"""Проверка нулевой статистики и разграничения заявок."""
import re

from conftest import login
from infosec_desk import service


def test_empty_statistics_are_zero_for_every_role(db_path):
    for user_id in (1, 2, 3, 4):
        user = service.find_user(db_path, user_id)
        stats = service.statistics(db_path, user)
        assert {key: stats[key] for key in ("total", "open", "resolved", "critical")} == {
            "total": 0, "open": 0, "resolved": 0, "critical": 0,
        }
        assert all(value == 0 for value in stats["by_status"].values())


def test_empty_dashboard_renders_four_zeroes(client):
    login(client, "alice", "AliceTest123!")
    response = client.get("/")
    assert response.status_code == 200
    values = re.findall(r'class="metric-value">([^<]*)</strong>', response.get_data(as_text=True))
    assert values == ["0", "0", "0", "0"]


def test_statistics_count_only_visible_tickets(db_path):
    alice = service.find_user(db_path, 3)
    bob = service.find_user(db_path, 4)
    admin = service.find_user(db_path, 1)
    service.create_ticket(db_path, alice, "Сбой сертификата", "Не удается проверить сертификат", "crypto", "critical")
    service.create_ticket(db_path, bob, "Проблема с доступом", "Нет доступа к защищенному ресурсу", "access", "high")
    assert service.statistics(db_path, alice)["total"] == 1
    assert service.statistics(db_path, bob)["total"] == 1
    assert service.statistics(db_path, admin)["total"] == 2
    assert service.statistics(db_path, alice)["critical"] == 1
    assert service.statistics(db_path, bob)["critical"] == 0
