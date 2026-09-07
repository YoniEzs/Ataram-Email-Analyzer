<#
.SYNOPSIS
    Set up and launch Ataram Email Analyzer on Windows.

.DESCRIPTION
    Creates backend\.venv if it is missing, installs the runtime dependencies
    into it, then starts the desktop entry point. A browser tab opens by
    itself at http://127.0.0.1:8321.

    Run from anywhere:
        powershell -ExecutionPolicy Bypass -File scripts\run-windows.ps1

    -ExecutionPolicy Bypass is needed because Windows blocks unsigned scripts
    by default. It applies to this one invocation only and changes nothing
    machine-wide.

    Why a script at all: PowerShell 5.1 -- still the default on Windows 10 and
    11 -- has no '&&', so the README steps have to be run one line at a time.
    This does them in order and stops at the first real failure.

.PARAMETER Port
    Port to listen on. Default 8321. If it is taken the app picks a free one
    and prints the URL it actually used.

.PARAMETER NoBrowser
    Do not open a browser tab.

.PARAMETER Reinstall
    Delete and rebuild the virtual environment. Use after changing Python
    versions or when an install is wedged.
#>

[CmdletBinding()]
param(
    [int]$Port = 8321,
    [switch]$NoBrowser,
    [switch]$Reinstall
)

$ErrorActionPreference = 'Stop'

# Resolve paths from the script's own location, so the working directory the
# user happens to be in does not matter.
$RepoRoot = Split-Path -Parent $PSScriptRoot
$Backend = Join-Path $RepoRoot 'backend'
$VenvDir = Join-Path $Backend '.venv'
$VenvPython = Join-Path $VenvDir 'Scripts\python.exe'

if (-not (Test-Path (Join-Path $Backend 'app\desktop.py'))) {
    throw "Could not find backend\app\desktop.py under '$RepoRoot'. Run this script from inside a checkout of the repository."
}

function Find-Python {
    <#
      Returns the path to a usable interpreter.

      yara-python 4.5.4 publishes Windows wheels for CPython 3.9-3.13 only.
      On 3.14 pip falls back to building it from source, which fails with a
      confusing compiler error unless Visual C++ Build Tools are installed.
      Catching that here is the whole point: the failure it prevents looks
      like a broken project rather than a missing wheel.
    #>
    $candidates = @()
    # The py launcher can name an exact version even when 'python' is another.
    if (Get-Command py -ErrorAction SilentlyContinue) {
        foreach ($v in @('3.12', '3.11', '3.13')) {
            $candidates += ,@('py', @("-$v"))
        }
    }
    if (Get-Command python -ErrorAction SilentlyContinue) {
        $candidates += ,@('python', @())
    }

    foreach ($candidate in $candidates) {
        $exe = $candidate[0]
        $prefix = $candidate[1]
        try {
            $version = & $exe @prefix -c 'import sys; print("%d.%d" % sys.version_info[:2])' 2>$null
        } catch {
            continue
        }
        if ($LASTEXITCODE -ne 0 -or -not $version) { continue }
        $parts = ([string]($version | Select-Object -Last 1)).Trim().Split('.')
        if ($parts.Count -lt 2) { continue }
        $major = [int]$parts[0]
        $minor = [int]$parts[1]
        if ($major -eq 3 -and $minor -ge 11 -and $minor -le 13) {
            return [pscustomobject]@{ Exe = $exe; Prefix = $prefix; Version = $version.Trim() }
        }
    }
    return $null
}

if ($Reinstall -and (Test-Path $VenvDir)) {
    Write-Host 'Removing the existing virtual environment...'
    Remove-Item -Recurse -Force $VenvDir
}

if (-not (Test-Path $VenvPython)) {
    $python = Find-Python
    if ($null -eq $python) {
        throw @'
No supported Python found. This project needs CPython 3.11, 3.12 or 3.13.

3.14 does not work yet: yara-python has no 3.14 Windows wheel, so pip tries
to compile it and fails without Visual C++ Build Tools.

Install 3.12 from https://www.python.org/downloads/ (tick "Add python.exe to
PATH"), then run this script again.
'@
    }

    Write-Host "Creating the virtual environment with Python $($python.Version)..."
    # Splat, not @(...): an array literal would pass an empty string as an
    # argument when Prefix is empty, and 'python "" -m venv' fails.
    $pythonArgs = $python.Prefix
    & $python.Exe @pythonArgs -m venv $VenvDir
    if ($LASTEXITCODE -ne 0) { throw 'Failed to create the virtual environment.' }
}

Write-Host 'Installing dependencies (first run takes a minute)...'
# waitress is not in requirements-prod.txt: the server deployment uses
# gunicorn, which does not run on Windows, so the desktop build asks for
# waitress separately.
& $VenvPython -m pip install --disable-pip-version-check --quiet `
    -r (Join-Path $Backend 'requirements-prod.txt') waitress
if ($LASTEXITCODE -ne 0) { throw 'Dependency installation failed. Re-run with -Reinstall if the environment is in a bad state.' }

$envFile = Join-Path $Backend '.env'
if (-not (Test-Path $envFile)) {
    Write-Host ''
    Write-Host 'Note: no backend\.env found. WHOIS, reverse DNS, RDAP, ASN and DKIM' -ForegroundColor Yellow
    Write-Host '      still run, but IP reputation stays empty until ABUSEIPDB_KEY is' -ForegroundColor Yellow
    Write-Host '      set. Copy backend\.env.example to backend\.env to add keys.' -ForegroundColor Yellow
    Write-Host ''
}

$env:ATARAM_PORT = $Port
if ($NoBrowser) { $env:ATARAM_NO_BROWSER = '1' }

Write-Host 'Starting Ataram Email Analyzer (Ctrl+C to quit)...'
Push-Location $Backend
try {
    & $VenvPython -m app.desktop
} finally {
    Pop-Location
}
