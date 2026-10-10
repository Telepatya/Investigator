Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$Backend = Split-Path -Parent (Split-Path -Parent $PSCommandPath)
Push-Location $Backend
try {
    if (-not (Get-Command uv -ErrorAction SilentlyContinue)) {
        throw "uv is required. Install it with: python -m pip install uv"
    }

    # Resolve for the oldest supported interpreter regardless of which Python
    # runs this script. Keep the arguments identical to update-locks.sh so the
    # recorded lock headers match. $ErrorActionPreference does not apply to a
    # native command's exit code, so check it explicitly and stop at the first
    # failure instead of leaving a partly updated set of locks.
    foreach ($Name in @("requirements", "requirements-memory", "requirements-dev")) {
        uv pip compile --universal --generate-hashes --python-version 3.11 "$Name.in" -o "$Name.lock"
        if ($LASTEXITCODE -ne 0) {
            throw "uv pip compile failed for $Name.in (exit $LASTEXITCODE)"
        }
    }
}
finally {
    Pop-Location
}
