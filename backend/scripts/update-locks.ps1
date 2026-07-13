Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$Backend = Split-Path -Parent (Split-Path -Parent $PSCommandPath)
Push-Location $Backend
try {
    if (-not (Get-Command uv -ErrorAction SilentlyContinue)) {
        throw "uv is required. Install it with: python -m pip install uv"
    }

    uv pip compile --universal --generate-hashes requirements.in -o requirements.lock
    uv pip compile --universal --generate-hashes requirements-memory.in -o requirements-memory.lock
    uv pip compile --universal --generate-hashes requirements-dev.in -o requirements-dev.lock
}
finally {
    Pop-Location
}
