$ErrorActionPreference = 'Stop'
if (-not (Get-Command py -ErrorAction SilentlyContinue)) { throw 'Python launcher (py) was not found.' }
if (-not (Test-Path -LiteralPath '.venv')) { py -3 -m venv .venv }
$python = Join-Path (Get-Location) '.venv\Scripts\python.exe'
& $python -m pip install --upgrade pip
& $python -m pip install -e '.[dev,full]'
& $python -m ruff check .
& $python -m pytest -q

