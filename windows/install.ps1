<#
.SYNOPSIS
    Installs the Gatewell agent as a Windows Service.

.DESCRIPTION
    Handles both build shapes:

      1. Self-contained single file  -> GatewellAgent.exe
         What build-windows.yml produces. No prerequisites on the endpoint.

      2. Framework-dependent          -> GatewellAgent.dll
         Runs via the installed dotnet host. Requires the .NET 8 runtime.

    The script picks whichever is present in the same folder and registers the
    service with the correct binPath, auto-start, LocalSystem identity, and a
    restart-on-failure policy.

.PARAMETER InstallDir
    Where to copy the agent. Defaults to C:\Program Files\Gatewell.

.EXAMPLE
    # From an elevated PowerShell prompt, in the folder holding the build:
    .\install.ps1
#>

[CmdletBinding()]
param(
    [string]$InstallDir = "$env:ProgramFiles\Gatewell"
)

$ErrorActionPreference = 'Stop'

$ServiceName = 'GatewellAgent'
$DisplayName = 'Gatewell Endpoint Agent'
$Description = 'Reports device heartbeat, executes remediation scripts, and forwards security events and EDR telemetry to the Gatewell platform.'

# ---- must be elevated -------------------------------------------------------
$identity  = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "install.ps1 must be run from an elevated PowerShell prompt."
}

$source = Split-Path -Parent $MyInvocation.MyCommand.Path

# ---- decide which build shape we have ---------------------------------------
$exe = Join-Path $source 'GatewellAgent.exe'
$dll = Join-Path $source 'GatewellAgent.dll'

if (Test-Path $exe) {
    $mode = 'self-contained'
}
elseif (Test-Path $dll) {
    $mode = 'framework-dependent'

    $dotnet = (Get-Command dotnet -ErrorAction SilentlyContinue).Source
    if (-not $dotnet) {
        throw @"
This is a framework-dependent build and the .NET runtime was not found.

Either install the .NET 8 Desktop/Runtime from
  https://dotnet.microsoft.com/download/dotnet/8.0
or use the self-contained GatewellAgent.exe produced by build-windows.yml,
which has no prerequisites.
"@
    }
}
else {
    throw "Neither GatewellAgent.exe nor GatewellAgent.dll was found in $source."
}

Write-Host "Installing Gatewell agent ($mode)" -ForegroundColor Cyan

# ---- stop and remove any previous install -----------------------------------
$existing = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($existing) {
    Write-Host "  Removing existing service..."
    if ($existing.Status -ne 'Stopped') {
        Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
        $existing.WaitForStatus('Stopped', '00:00:30')
    }
    & sc.exe delete $ServiceName | Out-Null
    Start-Sleep -Seconds 2
}

# ---- copy files -------------------------------------------------------------
New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null

$patterns = if ($mode -eq 'self-contained') {
    @('GatewellAgent.exe')
} else {
    @('GatewellAgent.dll', 'GatewellAgent.deps.json', 'GatewellAgent.runtimeconfig.json')
}

foreach ($p in $patterns) {
    $src = Join-Path $source $p
    if (-not (Test-Path $src)) { throw "Required file missing: $p" }
    Copy-Item $src -Destination $InstallDir -Force
}
Write-Host "  Copied to $InstallDir"

# ---- build binPath ----------------------------------------------------------
# Quoting matters: sc.exe needs the whole command quoted, and the dotnet form
# needs its own inner quotes around each path.
if ($mode -eq 'self-contained') {
    $binPath = "`"$InstallDir\GatewellAgent.exe`""
} else {
    $binPath = "`"$dotnet`" `"$InstallDir\GatewellAgent.dll`""
}

# ---- create the service -----------------------------------------------------
$create = & sc.exe create $ServiceName `
    binPath= $binPath `
    DisplayName= $DisplayName `
    start= auto `
    obj= LocalSystem 2>&1

if ($LASTEXITCODE -ne 0) { throw "sc.exe create failed: $create" }

& sc.exe description $ServiceName $Description | Out-Null

# Restart after 30s, then 60s, then every 2 minutes. Reset the counter daily.
& sc.exe failure $ServiceName reset= 86400 `
    actions= restart/30000/restart/60000/restart/120000 | Out-Null

Write-Host "  Service registered"

# ---- start ------------------------------------------------------------------
Start-Service -Name $ServiceName
$svc = Get-Service -Name $ServiceName
$svc.WaitForStatus('Running', '00:00:30')

Write-Host ""
Write-Host "Gatewell agent installed and running." -ForegroundColor Green
Write-Host ""
Write-Host "  Status : Get-Service $ServiceName"
Write-Host "  Logs   : $env:ProgramData\Gatewell\logs\agent.log"
Write-Host "           Event Viewer > Windows Logs > Application (source: GatewellAgent)"
Write-Host "  Remove : .\uninstall.ps1"
Write-Host ""
Write-Host "The device should appear in Gatewell within 60 seconds."
