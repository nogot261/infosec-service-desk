"""Единая точка запуска приложения на Windows и Linux."""

import importlib.util
import os
import subprocess
import sys
import venv
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "src"))

REQUIRED_MODULES = ("fastapi", "uvicorn", "jinja2", "multipart", "itsdangerous")


def install_dependencies(interpreter: Path) -> None:
    """Устанавливает зависимости, включая работу pip через SOCKS-прокси."""
    env = os.environ.copy()
    vendor = ROOT / "vendor"
    env["PYTHONPATH"] = os.pathsep.join(
        part for part in (str(vendor), env.get("PYTHONPATH", "")) if part
    )
    env["PIP_DISABLE_PIP_VERSION_CHECK"] = "1"
    command = [str(interpreter), "-m", "pip", "install", "-r", str(ROOT / "requirements.txt")]
    print("Установка зависимостей проекта...", flush=True)
    try:
        subprocess.run(command, env=env, check=True)
    except subprocess.CalledProcessError:
        print(
            "\nНе удалось установить зависимости. Проверьте подключение к интернету "
            "и настройки прокси (HTTP_PROXY, HTTPS_PROXY, ALL_PROXY, PIP_PROXY).",
            file=sys.stderr,
        )
        raise SystemExit(1) from None


def prepare_runtime() -> None:
    """При необходимости создает окружение и устанавливает зависимости."""
    if all(importlib.util.find_spec(name) is not None for name in REQUIRED_MODULES):
        return

    if sys.prefix == sys.base_prefix:
        directory = ROOT / ".venv"
        if not directory.exists():
            print("Создание локального окружения Python...", flush=True)
            venv.EnvBuilder(with_pip=True).create(directory)
        interpreter = directory / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
        install_dependencies(interpreter)
        raise SystemExit(subprocess.call([str(interpreter), __file__, *sys.argv[1:]]))

    install_dependencies(Path(sys.executable))


def main() -> None:
    if os.name == "nt":
        for stream in (sys.stdout, sys.stderr):
            if hasattr(stream, "reconfigure"):
                stream.reconfigure(encoding="utf-8", errors="replace")
    os.chdir(ROOT)
    command = sys.argv[1] if len(sys.argv) > 1 else "serve"
    if command == "serve" or command.startswith("--"):
        prepare_runtime()
    from infosec_desk.__main__ import main as app_main

    app_main()


if __name__ == "__main__":
    main()
