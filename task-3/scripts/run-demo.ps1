<#
.SYNOPSIS
    Start the Task 3 training app on 127.0.0.1.

.DESCRIPTION
    Resolves PHP in this order: $env:APEX_PHP, php on PATH, then the portable
    runtime at ..\..\_runtime\php\php.exe (installed by the Full Stack track).

    The bind address is hard-coded to 127.0.0.1. There is no option to expose
    the deliberately vulnerable application on another interface.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File task-3/scripts/run-demo.ps1
    powershell -ExecutionPolicy Bypass -File task-3/scripts/run-demo.ps1 -Port 8095
#>
param(
    [int]$Port = 8091
)

$ErrorActionPreference = 'Stop'

if ($Port -lt 1024 -or $Port -gt 65535) {
    throw "Port must be between 1024 and 65535."
}

$TaskRoot     = Split-Path -Parent $PSScriptRoot
$Workspace    = Split-Path -Parent $TaskRoot
$Router       = Join-Path $TaskRoot 'public\router.php'
$DocRoot      = Join-Path $TaskRoot 'public'
$DataDir      = Join-Path $TaskRoot 'vulnerable\data'

function Resolve-Php {
    if ($env:APEX_PHP -and (Test-Path $env:APEX_PHP)) { return $env:APEX_PHP }
    $onPath = Get-Command php -ErrorAction SilentlyContinue
    if ($onPath) { return $onPath.Source }
    $portable = Join-Path $Workspace '_runtime\php\php.exe'
    if (Test-Path $portable) { return $portable }
    throw "PHP not found. Set APEX_PHP, put php on PATH, or run the Full Stack track's setup-runtime.ps1."
}

$Php = Resolve-Php
New-Item -ItemType Directory -Force -Path $DataDir | Out-Null

Write-Host ''
Write-Host '  ApexPlanet - Task 3 Web Security Lab' -ForegroundColor Cyan
Write-Host '  ====================================' -ForegroundColor Cyan
Write-Host '  TRAINING ONLY: deliberately vulnerable. Fake data. Localhost only.' -ForegroundColor Yellow
Write-Host ''
Write-Host "  App:        http://127.0.0.1:$Port/"
Write-Host "  PHP:        $Php"
Write-Host "  Events:     $DataDir\security.jsonl"
Write-Host "  Access log: $DataDir\access.log"
Write-Host ''
Write-Host '  In another terminal, generate the proof-of-concept traffic:' -ForegroundColor Gray
Write-Host "    python task-3/scripts/demo_attacks.py --base-url http://127.0.0.1:$Port" -ForegroundColor Gray
Write-Host '  Then run the SIEM:' -ForegroundColor Gray
Write-Host '    python task-5/siem/detect.py' -ForegroundColor Gray
Write-Host ''
Write-Host '  Press Ctrl+C to stop.' -ForegroundColor Gray
Write-Host ''

& $Php -d extension=pdo_sqlite -d extension=sqlite3 -S "127.0.0.1:$Port" -t $DocRoot $Router
exit $LASTEXITCODE
