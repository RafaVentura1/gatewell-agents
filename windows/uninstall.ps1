<#
.SYNOPSIS
    Removes the Gatewell agent from this machine.

.PARAMETER KeepState
    Leave %ProgramData%\Gatewell in place. Useful when reinstalling, since it
    preserves the device_id so the endpoint keeps its identity in the platform
    rather than enrolling again as a new device.

.EXAMPLE
    .\uninstall.ps1
    .\uninstall.ps1 -KeepState
#>

[CmdletBinding()]
param(
    [switch]$KeepState,
    [string]$InstallDir = "$env:ProgramFiles\Gatewell"
)

$ErrorActionPreference = 'Stop'
$ServiceName = 'GatewellAgent'

$identity  = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "uninstall.ps1 must be run from an elevated PowerShell prompt."
}

$svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($svc) {
    Write-Host "Stopping service..."
    if ($svc.Status -ne 'Stopped') {
        Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
        $svc.WaitForStatus('Stopped', '00:00:30')
    }
    & sc.exe delete $ServiceName | Out-Null
    Start-Sleep -Seconds 2
    Write-Host "  Service removed"
} else {
    Write-Host "Service not installed."
}

if (Test-Path $InstallDir) {
    Remove-Item $InstallDir -Recurse -Force
    Write-Host "  Removed $InstallDir"
}

if ($KeepState) {
    Write-Host "  Keeping $env:ProgramData\Gatewell (device identity preserved)"
} else {
    $state = "$env:ProgramData\Gatewell"
    if (Test-Path $state) {
        Remove-Item $state -Recurse -Force
        Write-Host "  Removed $state"
    }

    # device_id is mirrored in the registry so a cleared ProgramData folder
    # still recovers the same identity. Remove it too for a full uninstall.
    $reg = 'HKLM:\SOFTWARE\Gatewell'
    if (Test-Path $reg) {
        Remove-Item $reg -Recurse -Force
        Write-Host "  Removed $reg"
    }
}

Write-Host ""
Write-Host "Gatewell agent uninstalled." -ForegroundColor Green
