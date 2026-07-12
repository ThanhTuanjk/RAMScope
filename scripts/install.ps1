param(
    [ValidateSet('core', 'full')]
    [string]$Extras = 'full'
)

$ErrorActionPreference = 'Stop'

if (-not (Get-Command py -ErrorAction SilentlyContinue)) {
    throw 'Python launcher (py) was not found. Install Python 3.10+ first.'
}

if (-not (Test-Path -LiteralPath '.venv')) {
    py -3 -m venv .venv
}

$python = Join-Path (Get-Location) '.venv\Scripts\python.exe'
& $python -m pip install --upgrade pip
if ($Extras -eq 'full') {
    & $python -m pip install -e '.[full]'
} else {
    & $python -m pip install -e .
}
& $python -m ramscope doctor
Write-Host 'RAMScope is installed. Run: .\.venv\Scripts\ramscope.exe --help'

