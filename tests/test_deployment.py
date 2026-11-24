"""Проверка точки входа в Render (без реального внешнего сервера)."""
import os
import subprocess
import sys
from pathlib import Path


def test_wsgi_with_temporary_demo_database(tmp_path):
    project_root = Path(__file__).resolve().parents[1]
    env = os.environ.copy()
    env['INFOSEC_SECRET_KEY'] = 'test-secret-for-local-render-deployment-2026'
    env['INFOSEC_DEMO_PASSWORD'] = 'test-only-random-demo-password-2026'
    env['INFOSEC_DB_PATH'] = str(tmp_path / 'demo.sqlite3')
    env['PYTHONPATH'] = str(project_root / 'src')
    script = (
        "import wsgi; from infosec_desk.service import authenticate; "
        "client=wsgi.app.test_client();"
        "assert client.get('/health').status_code == 200;"
        "assert client.get('/public/overview').status_code == 200;"
        "assert authenticate(wsgi.app.db_path,'admin','DemoPass123!') is None;"
        "assert authenticate(wsgi.app.db_path,'admin','test-only-random-demo-password-2026');"
        "print('render entrypoint ok')"
    )
    result = subprocess.run(
        [sys.executable, '-c', script], cwd=project_root, env=env,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=30,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert (tmp_path / 'demo.sqlite3').exists()
