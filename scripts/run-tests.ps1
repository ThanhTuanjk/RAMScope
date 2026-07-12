$ErrorActionPreference = 'Stop'
$python = Join-Path (Get-Location) '.venv\Scripts\python.exe'
if (-not (Test-Path -LiteralPath $python)) { throw 'Create the environment first with scripts\dev-setup.ps1.' }
& $python -m compileall -q src tests
& $python -m ruff check .
& $python -m mypy src
& $python -m pytest -q
& $python -m build

