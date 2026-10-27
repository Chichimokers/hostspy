#Requires -Version 5.1
<#
.SYNOPSIS
    Restores the hosts file if hostspy was killed without cleaning up.
#>
$ErrorActionPreference = "Continue"
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $root

$hosts = "$env:WINDIR\System32\drivers\etc\hosts"
$content = Get-Content $hosts -Raw

if ($content -match '# HOSTSPY-START') {
    $pattern = '(?s)\r?\n?# HOSTSPY-START.*?# HOSTSPY-END\r?\n?'
    $new = [regex]::Replace($content, $pattern, "`r`n")
    Set-Content -Path $hosts -Value $new -NoNewline
    ipconfig /flushdns | Out-Null
    Write-Host "hostspy block removed from hosts." -ForegroundColor Green
} else {
    Write-Host "No hostspy block found in hosts." -ForegroundColor Yellow
}

if (Test-Path "$hosts.hostspy.bak") {
    Write-Host "Backup available at $hosts.hostspy.bak" -ForegroundColor DarkGray
}

Get-Content $hosts | Select-String -Pattern 'ageofempires|worldsedgelink|relic\.link' | ForEach-Object { $_.Line }
