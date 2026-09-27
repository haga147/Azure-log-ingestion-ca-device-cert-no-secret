using namespace System.Net

# HTTP-triggered proxy: validates the caller and payload, then forwards records to the DCE
# using a token issued to this Function's system-assigned managed identity (no client secret).
#
# Request:  POST  { "records": [ { ...columns... }, ... ] }
# Responses: 200 accepted | 400 bad payload | 401/403 caller rejected | 413 too large
#            502 DCE rejected the data | 503 transient (caller should retry) | 500 config/internal

param($Request, $TriggerMetadata)

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'Helpers.ps1')

function Send-Response {
    param([HttpStatusCode]$Code, $Body, [hashtable]$Headers = @{})
    Push-OutputBinding -Name Response -Value ([HttpResponseContext]@{
            StatusCode  = $Code
            ContentType = 'application/json'
            Headers     = $Headers
            Body        = (ConvertTo-Json -InputObject $Body -Compress)
        })
}

try {
    $settings = Get-IngestSettings

    # 1) Caller check (only enforced when ALLOWED_CERT_THUMBPRINTS and/or TRUSTED_ISSUER_CERTS_BASE64 is set)
    if (-not (Test-CallerCertificate -Headers $Request.Headers -AllowedThumbprints $settings.AllowedThumbprints `
                -TrustedIssuerCertsB64 $settings.TrustedIssuerCertsB64 -RequireClientAuthEku $settings.RequireClientAuthEku)) {
        Write-Warning 'Rejected: client certificate missing, expired, or not on the allow-list.'
        Send-Response -Code Forbidden -Body @{ error = 'forbidden' }
        return
    }

    # 2) Size + shape validation
    $raw = [string]$Request.RawBody
    if ([string]::IsNullOrWhiteSpace($raw)) {
        Send-Response -Code BadRequest -Body @{ error = 'empty body' }
        return
    }
    if ([Text.Encoding]::UTF8.GetByteCount($raw) -gt $settings.MaxBodyBytes) {
        Send-Response -Code RequestEntityTooLarge -Body @{ error = "body exceeds $($settings.MaxBodyBytes) bytes" }
        return
    }

    try { $payload = $raw | ConvertFrom-Json }
    catch {
        Send-Response -Code BadRequest -Body @{ error = 'invalid JSON' }
        return
    }
    if ($null -eq $payload -or -not $payload.PSObject.Properties['records']) {
        Send-Response -Code BadRequest -Body @{ error = "expected { ""records"": [ ... ] }" }
        return
    }

    $records = @($payload.records)
    if ($records.Count -lt 1 -or $records.Count -gt $settings.MaxRecords) {
        Send-Response -Code BadRequest -Body @{ error = "records must contain 1..$($settings.MaxRecords) items" }
        return
    }

    # 3) Normalize: optional column allow-list, stamp TimeGenerated if absent
    $nowIso = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffffffZ')
    $clean = New-Object 'System.Collections.Generic.List[object]'
    foreach ($r in $records) {
        if ($null -eq $r -or $r -isnot [System.Management.Automation.PSCustomObject]) {
            Send-Response -Code BadRequest -Body @{ error = 'each record must be a JSON object' }
            return
        }
        $h = [ordered]@{}
        foreach ($p in $r.PSObject.Properties) {
            if ($settings.AllowedColumns.Count -eq 0 -or $settings.AllowedColumns -contains $p.Name) {
                $h[$p.Name] = $p.Value
            }
        }
        if (-not $h.Contains('TimeGenerated')) { $h['TimeGenerated'] = $nowIso }
        $clean.Add($h)
    }

    # 4) Forward to the DCE
    Invoke-LogIngestion -Settings $settings -Records $clean
    Write-Host "Ingested $($clean.Count) record(s)."
    Send-Response -Code OK -Body @{ accepted = $clean.Count }
}
catch {
    $ex = $_.Exception
    $kind = [string]$ex.Data['Kind']
    $status = 0
    if ($ex.Data['Status']) { $status = [int]$ex.Data['Status'] }

    # Full detail goes to the Function log (App Insights); callers only get a generic error.
    # (Write-Warning, not Write-Error: with ErrorActionPreference=Stop, Write-Error would throw here.)
    Write-Warning "IngestLogs failed [$kind]: $($ex.Message)"

    switch ($kind) {
        'dce-transient' { Send-Response -Code ServiceUnavailable -Body @{ error = 'upstream unavailable, retry' } -Headers @{ 'Retry-After' = '30' } }
        'dce' { Send-Response -Code BadGateway -Body @{ error = 'ingestion rejected'; upstreamStatus = $status } }
        'auth' { Send-Response -Code BadGateway -Body @{ error = 'upstream authentication failed' } }
        'config' { Send-Response -Code InternalServerError -Body @{ error = 'server configuration error' } }
        default { Send-Response -Code InternalServerError -Body @{ error = 'internal error' } }
    }
}
