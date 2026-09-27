<#
.SYNOPSIS
    Installs (or removes) the log shipper as a scheduled task running as SYSTEM.

.DESCRIPTION
    Copies Send-EndpointLogs.ps1 + EndpointConfig.psd1 to a locked-down folder
    (SYSTEM/Administrators write only, since the task runs as SYSTEM), locks the
    state folder the same way, then registers the task. No credentials are involved.

    Runs fine as an Intune Win32 app: Intune executes the install/uninstall command as
    NT AUTHORITY\SYSTEM, and this script accepts that (see the elevation check below)
    instead of requiring a member of the local Administrators group. It also writes an
    HKLM registry marker Intune can use as a detection rule with no separate script:
        Rule type: Registry
        Key path:  HKLM\SOFTWARE\LogShipper
        Value:     InstalledVersion
        Detection: String comparison, equals <Version> (match the -Version you pass here)

.EXAMPLE
    .\Install-LogShipperTask.ps1 -IntervalMinutes 5
.EXAMPLE
    .\Install-LogShipperTask.ps1 -Remove
.EXAMPLE
    # As packaged for Intune (Win32 app), install command:
    powershell.exe -NoProfile -ExecutionPolicy Bypass -File Install-LogShipperTask.ps1 -IntervalMinutes 5 -Version 1.0.0
    # uninstall command:
    powershell.exe -NoProfile -ExecutionPolicy Bypass -File Install-LogShipperTask.ps1 -Remove
#>
#Requires -Version 5.1
[CmdletBinding(SupportsShouldProcess)]
param(
    [string]$InstallPath = (Join-Path $env:ProgramFiles 'LogShipper'),
    [ValidateRange(1, 1440)][int]$IntervalMinutes = 5,
    [string]$TaskName = 'LogShipper-Secretless',
    [string]$Version = '1.0.0',
    [switch]$OverwriteConfig,
    [switch]$Remove
)

$ErrorActionPreference = 'Stop'
$stateDir = Join-Path $env:ProgramData 'LogShipper'
$regKey = 'HKLM:\SOFTWARE\LogShipper'

# Deliberately not "#Requires -RunAsAdministrator": that check tests membership in the local
# Administrators group plus UAC elevation, and an Intune Win32 app's install command runs as
# NT AUTHORITY\SYSTEM, which is not a member of Administrators even though it has full rights.
# Accept either an elevated admin (manual/lab use) or SYSTEM (Intune/SCCM/scheduled deployment).
$id = [Security.Principal.WindowsIdentity]::GetCurrent()
$isSystem = $id.User.Value -eq 'S-1-5-18'
$isElevatedAdmin = (New-Object Security.Principal.WindowsPrincipal($id)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isSystem -and -not $isElevatedAdmin) {
    throw 'This script must run as SYSTEM (e.g. via Intune) or from an elevated (Run as Administrator) session.'
}

function Set-LockedAcl {
    param([string]$Path)
    # SIDs, not names, so this works on any OS language: SYSTEM, Administrators (full), Users (read/execute)
    & icacls.exe $Path /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-32-545:(OI)(CI)RX' | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "icacls failed on $Path (exit $LASTEXITCODE)" }
}

if ($Remove) {
    if ($PSCmdlet.ShouldProcess($TaskName, 'Unregister scheduled task and remove install folder')) {
        if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) {
            Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
        }
        if (Test-Path -LiteralPath $InstallPath) { Remove-Item -LiteralPath $InstallPath -Recurse -Force }
        if (Test-Path -LiteralPath $regKey) { Remove-Item -LiteralPath $regKey -Recurse -Force }
        Write-Output "Removed task '$TaskName' and $InstallPath. State/log kept in $stateDir."
    }
    return
}

$srcScript = Join-Path $PSScriptRoot 'Send-EndpointLogs.ps1'
$srcConfig = Join-Path $PSScriptRoot 'EndpointConfig.psd1'
foreach ($f in @($srcScript, $srcConfig)) {
    if (-not (Test-Path -LiteralPath $f)) { throw "Missing $f" }
}

if ($PSCmdlet.ShouldProcess($InstallPath, 'Install log shipper')) {
    $null = New-Item -ItemType Directory -Path $InstallPath -Force
    $null = New-Item -ItemType Directory -Path $stateDir -Force

    $dstScript = Join-Path $InstallPath 'Send-EndpointLogs.ps1'
    $dstConfig = Join-Path $InstallPath 'EndpointConfig.psd1'
    Copy-Item -LiteralPath $srcScript -Destination $dstScript -Force
    if ($OverwriteConfig -or -not (Test-Path -LiteralPath $dstConfig)) {
        Copy-Item -LiteralPath $srcConfig -Destination $dstConfig -Force
    }

    Set-LockedAcl -Path $InstallPath
    Set-LockedAcl -Path $stateDir

    $action = New-ScheduledTaskAction -Execute 'powershell.exe' `
        -Argument ('-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "{0}"' -f $dstScript) `
        -WorkingDirectory $InstallPath
    $trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) `
        -RepetitionInterval (New-TimeSpan -Minutes $IntervalMinutes) `
        -RepetitionDuration (New-TimeSpan -Days 3650)
    $principal = New-ScheduledTaskPrincipal -UserId 'NT AUTHORITY\SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    $settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -MultipleInstances IgnoreNew `
        -ExecutionTimeLimit (New-TimeSpan -Minutes 30) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries

    $null = Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger `
        -Principal $principal -Settings $settings -Force `
        -Description 'Ships Windows event logs to the secretless ingestion Azure Function.'

    # Marker for Intune's registry-based detection rule: HKLM:\SOFTWARE\LogShipper\InstalledVersion.
    $null = New-Item -Path $regKey -Force
    New-ItemProperty -Path $regKey -Name 'InstalledVersion' -Value $Version -PropertyType String -Force | Out-Null
    New-ItemProperty -Path $regKey -Name 'InstallDate' -Value ((Get-Date).ToString('o')) -PropertyType String -Force | Out-Null
    New-ItemProperty -Path $regKey -Name 'TaskName' -Value $TaskName -PropertyType String -Force | Out-Null

    Write-Output "Installed '$TaskName' (every $IntervalMinutes min, runs as SYSTEM)."
    Write-Output "Edit $dstConfig, then test:  powershell -File `"$dstScript`" -TestRecord -Verbose"
}
