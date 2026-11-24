"""Подсчёт собственных непустых строк в исходниках, разметке, стилях и тестах."""
from pathlib import Path

root = Path(__file__).resolve().parent.parent
extensions = {'.py', '.html', '.css', '.sql'}
excluded = {'vendor', '.venv', '__pycache__', '.git', '.pytest_cache', 'dist', 'build', 'mockups'}
total = 0
for file in sorted(root.rglob('*')):
    if file.suffix not in extensions or set(file.parts) & excluded:
        continue
    if not file.is_file():
        continue
    count = sum(
        bool(line.strip()) and not line.lstrip().startswith(('#', '--', '/*', '*'))
        for line in file.read_text(encoding='utf-8').splitlines()
    )
    total += count
    print(f'{count:5} {file.relative_to(root)}')
print(f'Total (including own tests): {total}')
