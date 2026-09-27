<#
.SYNOPSIS
    Ships Windows Hello for Business Operational events to the ingestion Azure Function.

.DESCRIPTION
    This machine holds NO secret and NO token. It POSTs JSON to the Function URL
    (optionally presenting a machine certificate for mTLS). The Function authenticates
    to Azure Monitor with its own system-assigned managed identity (no client secret,
    no Key Vault) and forwards the batch to the DCE.

    - PowerShell 5.1 compatible (no PS7-only syntax).
    - Per-log bookmark (time + RecordId) so nothing is sent twice; bookmark only
      advances after the Function accepts a batch.
    - Single-instance guard (named mutex), local rolling log file.

.PARAMETER TestRecord
    Sends one synthetic record and exits (use to validate the whole pipeline).

.NOTES
    Edit ConvertTo-LogRecord / New-TestRecord so the field names match the columns
    declared in your DCR stream / custom table.
#>
#Requires -Version 5.1
[CmdletBinding()]
param(
    [string]$ConfigPath = (Join-Path $PSScriptRoot 'EndpointConfig.psd1'),
    [switch]$TestRecord
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

#region helpers ---------------------------------------------------------------

function Get-Cfg {
    param([hashtable]$Table, [string]$Name, $Default)
    if ($Table.ContainsKey($Name) -and $null -ne $Table[$Name] -and "$($Table[$Name])" -ne '') { return $Table[$Name] }
    return $Default
}

function Write-Log {
    param([string]$Message, [ValidateSet('INFO', 'WARN', 'ERROR')][string]$Level = 'INFO')
    $line = '{0} [{1}] {2}' -f (Get-Date).ToString('yyyy-MM-dd HH:mm:ss'), $Level, $Message
    Write-Verbose $line
    try { Add-Content -LiteralPath $script:LogFile -Value $line -Encoding UTF8 } catch { }
}

function Read-State {
    param([string]$Path)
    $state = @{}
    if (Test-Path -LiteralPath $Path) {
        try {
            $raw = Get-Content -LiteralPath $Path -Raw -Encoding UTF8
            $obj = $raw | ConvertFrom-Json
            foreach ($p in $obj.PSObject.Properties) {
                $state[$p.Name] = @{ Ticks = [int64]$p.Value.Ticks; RecordId = [int64]$p.Value.RecordId }
            }
        }
        catch { Write-Log "State file unreadable, starting fresh: $($_.Exception.Message)" 'WARN' }
    }
    return $state
}

function Save-State {
    param([string]$Path, [hashtable]$State)
    $out = @{}
    foreach ($k in $State.Keys) { $out[$k] = @{ Ticks = $State[$k].Ticks; RecordId = $State[$k].RecordId } }
    $json = ConvertTo-Json -InputObject $out -Depth 4
    $tmp = "$Path.tmp"
    [IO.File]::WriteAllText($tmp, $json, (New-Object Text.UTF8Encoding($false)))
    Move-Item -LiteralPath $tmp -Destination $Path -Force
}

# ---- Record shape: Custom-HelloForBusiness3_CL -------------------------------
function ConvertTo-LogRecord {
    param($WinEvent, [int]$MaxMessageChars)
    $msg = $null
    try { $msg = $WinEvent.Message } catch { }
    if ([string]::IsNullOrEmpty($msg)) {
        $msg = (@($WinEvent.Properties | ForEach-Object { [string]$_.Value }) -join ' | ')
    }
    if ($msg.Length -gt $MaxMessageChars) { $msg = $msg.Substring(0, $MaxMessageChars) }

    return [ordered]@{
        TimeGenerated    = $WinEvent.TimeCreated.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffffffZ')
        EventId           = [int]$WinEvent.Id
        LevelDisplayName = [string]$WinEvent.LevelDisplayName
        ProviderName     = [string]$WinEvent.ProviderName
        MachineName      = [string]$WinEvent.MachineName
        UserId           = [string]$WinEvent.UserId
        TaskDisplayName  = [string]$WinEvent.TaskDisplayName
        Message          = $msg
    }
}

function New-TestRecord {
    return [ordered]@{
        TimeGenerated    = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffffffZ')
        EventId           = 0
        LevelDisplayName = 'Information'
        ProviderName     = 'Send-EndpointLogs.ps1'
        MachineName      = $env:COMPUTERNAME
        UserId           = ''
        TaskDisplayName  = ''
        Message          = 'Test record from Send-EndpointLogs.ps1 -TestRecord'
    }
}

function Get-ClientCertificate {
    param([hashtable]$ClientCertCfg)

    $mode = Get-Cfg $ClientCertCfg 'Mode' 'None'
    if ($mode -eq 'None' -or [string]::IsNullOrWhiteSpace($mode)) { return $null }

    if ($mode -eq 'Thumbprint') {
        $thumb = ([string](Get-Cfg $ClientCertCfg 'Thumbprint' '') -replace '\s', '').ToUpper()
        if (-not $thumb) { throw "ClientCert.Mode is 'Thumbprint' but Thumbprint is not set." }
        $cert = Get-ChildItem -Path Cert:\LocalMachine\My | Where-Object { $_.Thumbprint -eq $thumb } | Select-Object -First 1
        if (-not $cert) { throw "Client certificate $thumb not found in LocalMachine\My" }
        if (-not $cert.HasPrivateKey) { throw "Client certificate $thumb has no accessible private key" }
        return $cert
    }

    if ($mode -ne 'AutoSelect') { throw "Unknown ClientCert.Mode '$mode'. Use AutoSelect, Thumbprint, or None." }

    $clientAuthOid = '1.3.6.1.5.5.7.3.2'
    $requireEku = [bool](Get-Cfg $ClientCertCfg 'RequireClientAuthEku' $true)
    $issuerPatterns = @(@(Get-Cfg $ClientCertCfg 'IssuerContains' @()) | Where-Object { $_ -and $_ -notlike '<*' })
    $now = Get-Date

    $candidates = @(Get-ChildItem -Path Cert:\LocalMachine\My | Where-Object {
            $_.HasPrivateKey -and $_.NotBefore -le $now -and $_.NotAfter -ge $now
        })

    if ($requireEku) {
        $candidates = @($candidates | Where-Object {
                $eku = $_.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.37' }
                $eku -and @(@($eku.EnhancedKeyUsages) | Where-Object { $_.Value -eq $clientAuthOid }).Count -gt 0
            })
    }

    if ($issuerPatterns.Count -gt 0) {
        $matched = @($candidates | Where-Object {
                $issuer = $_.Issuer
                @($issuerPatterns | Where-Object { $issuer -like "*$_*" }).Count -gt 0
            })
        if ($matched.Count -gt 0) { $candidates = $matched }
        else { Write-Log 'ClientCert.IssuerContains matched no certificate; falling back to any client-auth-capable cert. Configure IssuerContains to avoid an ambiguous pick.' 'WARN' }
    }
    elseif ($candidates.Count -gt 1) {
        Write-Log "ClientCert.IssuerContains is not set and $($candidates.Count) client-auth-capable certs were found; the pick may be ambiguous (e.g. an 802.1x cert vs. an Entra join cert). Set IssuerContains." 'WARN'
    }

    if ($candidates.Count -eq 0) { return $null }
    # Prefer the cert with the most remaining validity (the freshest SCEP renewal).
    return ($candidates | Sort-Object -Property NotAfter -Descending | Select-Object -First 1)
}

function Get-NewEvents {
    param([hashtable]$LogCfg, $Bookmark, [int]$LookbackMinutes, [int]$MaxEvents)

    if ($Bookmark) {
        $startUtc = New-Object DateTime -ArgumentList @([int64]$Bookmark.Ticks, [DateTimeKind]::Utc)
    }
    else {
        $startUtc = (Get-Date).ToUniversalTime().AddMinutes(-$LookbackMinutes)
    }

    $filter = @{ LogName = $LogCfg.LogName; StartTime = $startUtc.ToLocalTime() }
    if ($LogCfg.ContainsKey('Levels') -and @($LogCfg.Levels).Count -gt 0) { $filter.Level = [int[]]@($LogCfg.Levels) }
    if ($LogCfg.ContainsKey('EventIds') -and @($LogCfg.EventIds).Count -gt 0) { $filter.Id = [int[]]@($LogCfg.EventIds) }

    try {
        $events = @(Get-WinEvent -FilterHashtable $filter -MaxEvents $MaxEvents -Oldest -ErrorAction Stop)
    }
    catch {
        if ($_.FullyQualifiedErrorId -like 'NoMatchingEventsFound*') { return @() }
        throw
    }

    if ($Bookmark) {
        $bt = [int64]$Bookmark.Ticks
        $br = [int64]$Bookmark.RecordId
        $events = @($events | Where-Object {
                $t = $_.TimeCreated.ToUniversalTime().Ticks
                ($t -gt $bt) -or (($t -eq $bt) -and ([int64]$_.RecordId -gt $br))
            })
    }
    return $events
}

function Send-Payload {
    param([string]$Json)
    # Send as UTF-8 bytes; PS 5.1 would otherwise encode string bodies as ISO-8859-1.
    $bytes = [Text.Encoding]::UTF8.GetBytes($Json)
    $req = @{
        Uri             = $script:FunctionUrl
        Method          = 'Post'
        Body            = $bytes
        ContentType     = 'application/json; charset=utf-8'
        TimeoutSec      = $script:TimeoutSec
        UseBasicParsing = $true
        ErrorAction     = 'Stop'
    }
    if ($script:ClientCert) { $req.Certificate = $script:ClientCert }

    for ($attempt = 0; $attempt -le $script:MaxRetries; $attempt++) {
        try {
            $null = Invoke-WebRequest @req
            return
        }
        catch {
            $ex = $_.Exception
            $status = 0
            if ($ex.PSObject.Properties['Response'] -and $ex.Response) {
                try { $status = [int]$ex.Response.StatusCode } catch { }
            }
            $retryable = ($status -eq 0) -or ($status -eq 408) -or ($status -eq 429) -or ($status -ge 500)
            if (-not $retryable -or $attempt -ge $script:MaxRetries) {
                throw "HTTP $status - $($ex.Message)"
            }
            $delay = [Math]::Min(60, [Math]::Pow(2, $attempt) * 2) + (Get-Random -Minimum 0 -Maximum 3)
            Write-Log "Send failed (HTTP $status), retry $($attempt + 1)/$($script:MaxRetries) in ${delay}s" 'WARN'
            Start-Sleep -Seconds $delay
        }
    }
}

function Submit-Batch {
    param([string]$LogName, $Jsons, [int64]$LastTicks, [int64]$LastRecordId)
    $body = '{"records":[' + ($Jsons -join ',') + ']}'
    Send-Payload -Json $body
    $script:State[$LogName] = @{ Ticks = $LastTicks; RecordId = $LastRecordId }
    Save-State -Path $script:StatePath -State $script:State
    $script:TotalSent += $Jsons.Count
}

#endregion

#region setup -----------------------------------------------------------------

if (-not (Test-Path -LiteralPath $ConfigPath)) { throw "Config not found: $ConfigPath" }
$cfg = Import-PowerShellDataFile -Path $ConfigPath

$stateDir = Get-Cfg $cfg 'StateDir' (Join-Path $env:ProgramData 'LogShipper')
$null = New-Item -ItemType Directory -Path $stateDir -Force
$script:LogFile = Join-Path $stateDir 'shipper.log'
$script:StatePath = Join-Path $stateDir 'state.json'
if ((Test-Path -LiteralPath $script:LogFile) -and ((Get-Item -LiteralPath $script:LogFile).Length -gt 5MB)) {
    Move-Item -LiteralPath $script:LogFile -Destination "$($script:LogFile).1" -Force
}

$script:FunctionUrl = [string](Get-Cfg $cfg 'FunctionUrl' '')
if ([string]::IsNullOrWhiteSpace($script:FunctionUrl) -or $script:FunctionUrl -like '*<*') {
    throw 'FunctionUrl is not configured in EndpointConfig.psd1'
}
$script:TimeoutSec = [int](Get-Cfg $cfg 'RequestTimeoutSec' 60)
$script:MaxRetries = [int](Get-Cfg $cfg 'MaxRetries' 4)
$maxBytes = [int](Get-Cfg $cfg 'MaxBatchBytes' 700000)
$maxRecs = [int](Get-Cfg $cfg 'MaxBatchRecords' 2000)
$maxEvents = [int](Get-Cfg $cfg 'MaxEventsPerLogPerRun' 5000)
$lookback = [int](Get-Cfg $cfg 'InitialLookbackMinutes' 60)
$maxMsg = [int](Get-Cfg $cfg 'MaxMessageChars' 8000)

# Client certificate for mTLS (private key stays in the machine store).
$script:ClientCert = $null
$clientCertCfg = Get-Cfg $cfg 'ClientCert' @{}
try {
    $script:ClientCert = Get-ClientCertificate -ClientCertCfg $clientCertCfg
}
catch {
    throw "Client certificate selection failed: $($_.Exception.Message)"
}
if ($script:ClientCert) {
    Write-Log "Using client certificate: Subject='$($script:ClientCert.Subject)' Issuer='$($script:ClientCert.Issuer)' Thumbprint=$($script:ClientCert.Thumbprint) NotAfter=$($script:ClientCert.NotAfter)"
}
elseif ((Get-Cfg $clientCertCfg 'Mode' 'None') -ne 'None') {
    Write-Log 'ClientCert.Mode requests a certificate but none matched. If the Function requires mTLS, calls will fail at the App Service layer before reaching the endpoint check.' 'WARN'
}

$script:State = Read-State -Path $script:StatePath
$script:TotalSent = 0
$jitterSec = [int](Get-Cfg $cfg 'MaxStartupJitterSec' 0)

#endregion

#region main ------------------------------------------------------------------

$mutex = New-Object System.Threading.Mutex($false, 'Global\LogShipperSingleInstance')
if (-not $mutex.WaitOne(0)) {
    Write-Log 'Another instance is running; exiting.'
    exit 0
}

$failures = 0
try {
    if (-not $TestRecord -and $jitterSec -gt 0) {
        Start-Sleep -Seconds (Get-Random -Minimum 0 -Maximum $jitterSec)
    }

    if ($TestRecord) {
        $rec = New-TestRecord
        $json = ConvertTo-Json -InputObject $rec -Compress -Depth 3
        Send-Payload -Json ('{"records":[' + $json + ']}')
        Write-Log 'Test record accepted by the Function.'
        Write-Output 'Test record accepted by the Function.'
        exit 0
    }

    $logs = @($cfg.Logs)
    if ($logs.Count -eq 0) { throw 'No Logs configured.' }

    foreach ($logCfg in $logs) {
        $logName = [string]$logCfg.LogName
        $bookmark = $null
        if ($script:State.ContainsKey($logName)) { $bookmark = $script:State[$logName] }

        try {
            $events = @(Get-NewEvents -LogCfg $logCfg -Bookmark $bookmark -LookbackMinutes $lookback -MaxEvents $maxEvents)
        }
        catch {
            Write-Log "Query failed for '$logName': $($_.Exception.Message)" 'ERROR'
            $failures++
            continue
        }
        if ($events.Count -eq 0) { continue }

        $jsons = New-Object 'System.Collections.Generic.List[string]'
        $bytes = 0
        $lastTicks = [int64]0
        $lastRid = [int64]0
        $ok = $true

        foreach ($e in $events) {
            $rec = ConvertTo-LogRecord -WinEvent $e -MaxMessageChars $maxMsg
            $j = ConvertTo-Json -InputObject $rec -Compress -Depth 3
            $jb = [Text.Encoding]::UTF8.GetByteCount($j) + 1

            if ($jsons.Count -gt 0 -and ((($bytes + $jb) -gt $maxBytes) -or ($jsons.Count -ge $maxRecs))) {
                try { Submit-Batch -LogName $logName -Jsons $jsons -LastTicks $lastTicks -LastRecordId $lastRid }
                catch {
                    Write-Log "Batch failed for '$logName': $($_.Exception.Message)" 'ERROR'
                    $failures++
                    $ok = $false
                    break
                }
                $jsons.Clear()
                $bytes = 0
            }
            $jsons.Add($j)
            $bytes += $jb
            $lastTicks = $e.TimeCreated.ToUniversalTime().Ticks
            $lastRid = [int64]$e.RecordId
        }

        if ($ok -and $jsons.Count -gt 0) {
            try { Submit-Batch -LogName $logName -Jsons $jsons -LastTicks $lastTicks -LastRecordId $lastRid }
            catch {
                Write-Log "Batch failed for '$logName': $($_.Exception.Message)" 'ERROR'
                $failures++
            }
        }
    }

    Write-Log "Run complete. Sent=$($script:TotalSent) Failures=$failures"
}
catch {
    Write-Log "Fatal: $($_.Exception.Message)" 'ERROR'
    $failures++
}
finally {
    $mutex.ReleaseMutex()
    $mutex.Dispose()
}

if ($failures -gt 0) { exit 1 } else { exit 0 }

#endregion
