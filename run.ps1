#Requires -Version 5.1
<#
.SYNOPSIS
    Builds and runs hostspy with the minimum amount of clicks.

.DESCRIPTION
    Must run elevated (Administrator): it edits the hosts file and binds :443/:80.
    It builds the binary if the sources changed, regenerates/installs the
    self-signed certificate when needed, then runs hostspy. On exit the hosts
    file is restored.

.PARAMETER NoBuild
    Skip the build step.

.PARAMETER ForceCert
    Regenerate and reinstall the certificate (needed after changing certificateDomains).

.PARAMETER StopWinNAT
    Stop the Windows NAT service (winnat) while hostspy runs and start it again on
    exit. Use it when a port such as SC2's 1119 is inside a Windows excluded port
    range. WSL2/Docker/Hyper-V networking pauses while winnat is stopped.

.EXAMPLE
    .\run.ps1
#>
param(
    [switch]$NoBuild,
    [switch]$ForceCert,
    [switch]$StopWinNAT,
    [string]$Config = "config.json",
    [string]$GoExe = "go"
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSCommandPath
Set-Location $root

function Test-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $p = New-Object Security.Principal.WindowsPrincipal($id)
    return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (-not (Test-Admin)) {
    Write-Host "Requesting Administrator privileges..." -ForegroundColor Yellow

    $argList = @(
        '-NoProfile'
        '-ExecutionPolicy', 'Bypass'
        '-File', ('"{0}"' -f $PSCommandPath)
        '-Config', ('"{0}"' -f $Config)
        '-GoExe', ('"{0}"' -f $GoExe)
    )
    if ($NoBuild) { $argList += '-NoBuild' }
    if ($ForceCert) { $argList += '-ForceCert' }
    if ($StopWinNAT) { $argList += '-StopWinNAT' }

    Start-Process -FilePath 'powershell.exe' -Verb RunAs -ArgumentList $argList
    exit
}

if (-not (Test-Path $GoExe)) {
    $candidate = (Get-Command go -ErrorAction SilentlyContinue).Source
    if ($candidate) {
        $GoExe = $candidate
    } else {
        throw "go.exe not found. Pass -GoExe <path>."
    }
}

if (-not $NoBuild) {
    $needsBuild = $true
    if (Test-Path ".\hostspy.exe") {
        $exe = Get-Item ".\hostspy.exe"
        $newest = Get-ChildItem -Recurse -Include *.go |
            Sort-Object LastWriteTime -Descending |
            Select-Object -First 1
        if ($newest -and $exe.LastWriteTime -gt $newest.LastWriteTime) {
            $needsBuild = $false
        }
    }
    if ($needsBuild) {
        Write-Host "Building hostspy..." -ForegroundColor Cyan
        & $GoExe build -o hostspy.exe ./cmd/hostspy
        if ($LASTEXITCODE -ne 0) { throw "build failed" }
    }
}

# Always ensure/install: ca.Ensure regenerates the certificate when the
# configured names changed, and re-adding the same certificate is harmless.
Write-Host "Ensuring certificate..." -ForegroundColor Cyan
$certArgs = @('-config', $Config)
if ($ForceCert) { $certArgs += '-regen-cert' }
$certArgs += '-install-cert'
& ".\hostspy.exe" @certArgs
if ($LASTEXITCODE -ne 0) { throw "certificate install failed" }

# Warn early when a TCP interception port is inside a Windows excluded range
# (usually reserved by Hyper-V/WSL/NAT). Binding would fail with a permissions
# error that is hard to interpret otherwise.
try {
    $cfgData = Get-Content $Config -Raw | ConvertFrom-Json
    $tcpPorts = @($cfgData.interceptPorts | Where-Object { $_ })
} catch {
    $tcpPorts = @()
}
$excludedHit = $false
if ($tcpPorts.Count -gt 0) {
    $excluded = @()
    netsh interface ipv4 show excludedportrange protocol=tcp 2>$null | ForEach-Object {
        if ($_ -match '^\s*(\d+)\s+(\d+)\s*\*?\s*$') {
            $excluded += [pscustomobject]@{ Start = [int]$Matches[1]; End = [int]$Matches[2] }
        }
    }
    foreach ($p in $tcpPorts) {
        foreach ($r in $excluded) {
            if ($p -ge $r.Start -and $p -le $r.End) {
                $excludedHit = $true
                Write-Host "WARNING: TCP port $p is in a Windows excluded range ($($r.Start)-$($r.End))." -ForegroundColor Yellow
                Write-Host "         Hyper-V/WSL/NAT reserves it, so binding will fail." -ForegroundColor Yellow
                Write-Host "         Use .\run.ps1 -StopWinNAT, or manually: net stop winnat -> run hostspy -> net start winnat." -ForegroundColor Yellow
            }
        }
    }
}

$stopWinnat = [bool]$StopWinNAT
if ($excludedHit -and -not $stopWinnat -and $Host.Name -eq 'ConsoleHost') {
    $answer = Read-Host "Stop winnat for this session and restart it on exit? [y/N]"
    if ($answer -match '^(?i)y') { $stopWinnat = $true }
}

# Clean any stale block before starting (ignore errors when there is none).
& ".\hostspy.exe" -restore 2>&1 | Out-Null

$winnatStopped = $false
if ($stopWinnat) {
    $svc = Get-Service winnat -ErrorAction SilentlyContinue
    if ($svc -and $svc.Status -eq 'Running') {
        Write-Host "Stopping winnat so excluded ports can be bound..." -ForegroundColor Cyan
        net stop winnat /y | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "could not stop winnat" }
        $winnatStopped = $true
        Start-Sleep -Milliseconds 500
    }
}

Write-Host ""
Write-Host "Starting hostspy. Press Ctrl+C to stop and restore hosts." -ForegroundColor Green
Write-Host ""

try {
    & ".\hostspy.exe" -config $Config
} finally {
    & ".\hostspy.exe" -restore 2>&1 | Out-Null
    if ($winnatStopped) {
        net start winnat | Out-Null
        Write-Host "winnat restarted." -ForegroundColor Yellow
    }
    Write-Host "hosts restored." -ForegroundColor Yellow
}
