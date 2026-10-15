"""Единая точка запуска приложения на Windows и Linux."""

import importlib.util
import os
import subprocess
import sys
import venv
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "src"))


def prepare_runtime() -> None:
    """При необходимости создает окружение и устанавливает зависимости."""
    required = ("fastapi", "uvicorn", "jinja2", "multipart", "itsdangerous")
    if all(importlib.util.find_spec(name) is not None for name in required):
        return

    if sys.prefix == sys.base_prefix:
        directory = ROOT / ".venv"
        if not directory.exists():
            print("Создание локального окружения Python...")
            venv.EnvBuilder(with_pip=True).create(directory)
        interpreter = directory / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
        print("Установка зависимостей проекта...")
        subprocess.run([str(interpreter), "-m", "pip", "install", "-e", str(ROOT)], check=True)
        raise SystemExit(subprocess.call([str(interpreter), __file__, *sys.argv[1:]]))

    print("Установка зависимостей проекта...")
    subprocess.run([sys.executable, "-m", "pip", "install", "-e", str(ROOT)], check=True)


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
