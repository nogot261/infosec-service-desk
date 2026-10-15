"""Единый запуск приложения на Windows и Ubuntu."""

import importlib.util
import os
import subprocess
import sys
import venv
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "src"))
REQUIRED_MODULES = ("fastapi", "uvicorn", "jinja2", "multipart", "itsdangerous")


def has_dependencies() -> bool:
    return all(importlib.util.find_spec(name) is not None for name in REQUIRED_MODULES)


def install_dependencies(interpreter: Path) -> None:
    """Установка с поддержкой прокси через включенный модуль PySocks."""
    env = os.environ.copy()
    vendor = ROOT / "vendor"
    env["PYTHONPATH"] = os.pathsep.join(
        part for part in (str(vendor), env.get("PYTHONPATH", "")) if part
    )
    env["PIP_DISABLE_PIP_VERSION_CHECK"] = "1"
    print("Установка зависимостей...", flush=True)
    try:
        subprocess.run(
            [str(interpreter), "-m", "pip", "install", "-r", str(ROOT / "requirements.txt")],
            env=env, check=True,
        )
    except subprocess.CalledProcessError:
        print("Установка не удалась. Проверьте интернет и настройки прокси.", file=sys.stderr)
        raise SystemExit(1) from None


def prepare_runtime() -> None:
    """Однократно создает окружение. При следующих запусках не вызывает pip."""
    if sys.prefix != sys.base_prefix:
        if not has_dependencies():
            install_dependencies(Path(sys.executable))
        return

    directory = ROOT / ".venv"
    interpreter = directory / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
    if directory.is_dir():
        probe = subprocess.run(
            [str(interpreter), "-c", "import fastapi,uvicorn,jinja2,multipart,itsdangerous"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False,
        )
        if probe.returncode == 0:
            raise SystemExit(subprocess.call([str(interpreter), __file__, *sys.argv[1:]]))

    if has_dependencies():
        return

    if not directory.exists():
        print("Создание локального окружения Python...", flush=True)
        venv.EnvBuilder(with_pip=True).create(directory)
    install_dependencies(interpreter)
    raise SystemExit(subprocess.call([str(interpreter), __file__, *sys.argv[1:]]))


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
