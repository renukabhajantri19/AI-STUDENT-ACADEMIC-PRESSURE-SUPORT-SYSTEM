$ErrorActionPreference = "Stop"

$projectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $projectRoot

$venvPython = Join-Path $projectRoot ".venv\Scripts\python.exe"
if (Test-Path $venvPython) {
    & $venvPython -m uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
    exit $LASTEXITCODE
}

Write-Error "Project virtual environment not found. Create it and install requirements first:`n  py -m venv .venv`n  .venv\Scripts\python.exe -m pip install -r requirements.txt"
