"""Проверки переноса настроек в единый установщик."""

import importlib.util
import os
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("infosec_launcher", ROOT / "run.py")
launcher = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(launcher)


def test_install_dependencies_preserves_proxy_settings(monkeypatch):
    saved = {}
    monkeypatch.setenv("ALL_PROXY", "socks5h://127.0.0.1:10080")

    def fake_run(command, *, env, check):
        saved.update(command=command, env=env, check=check)
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(subprocess, "run", fake_run)
    launcher.install_dependencies(Path(sys.executable))

    assert saved["check"]
    assert saved["env"]["ALL_PROXY"] == "socks5h://127.0.0.1:10080"
    assert saved["env"]["PYTHONPATH"].split(os.pathsep)[0] == str(launcher.ROOT / "vendor")
    assert saved["command"][-2:] == ["-r", str(launcher.ROOT / "requirements.txt")]


def test_dependency_failure_returns_clean_message(monkeypatch, capsys):
    def fail(*args, **kwargs):
        raise subprocess.CalledProcessError(1, ["pip"])

    monkeypatch.setattr(subprocess, "run", fail)
    with pytest.raises(SystemExit) as exc:
        launcher.install_dependencies(Path(sys.executable))
    assert exc.value.code == 1
    assert "настройки прокси" in capsys.readouterr().err


def test_proxy_vendor_is_importable():
    script = 'import socks; print(socks.__version__)'
    env = os.environ.copy()
    env["PYTHONPATH"] = str(launcher.ROOT / "vendor")
    result = subprocess.run(
        [sys.executable, "-c", script], env=env, text=True,
        capture_output=True, check=True, encoding="utf-8",
    )
    assert result.stdout.strip() == "1.7.1"
