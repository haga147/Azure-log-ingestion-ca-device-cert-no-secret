# Helpers for the IngestLogs function (dot-sourced by run.ps1).
# Syntax is kept PS 5.1-safe. The Functions host itself runs PowerShell 7.x.
#
# No secret exists in this design: the Function's system-assigned managed identity gets a
# token for Azure Monitor from the platform and calls the DCE with it. There is no app
# registration secret, no Key Vault read, and nothing credential-like in app settings.

if (-not $global:IngestCache) { $global:IngestCache = @{} }

function ConvertTo-ListFromSetting {
    param([string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value)) { return @() }
    return @(($Value -split '[,;\s]+') | Where-Object { $_ })
}

function Get-IngestSettings {
    $required = 'DCE_INGEST_URI', 'DCR_IMMUTABLE_ID', 'STREAM_NAME'
    $missing = @($required | Where-Object { [string]::IsNullOrWhiteSpace([Environment]::GetEnvironmentVariable($_)) })
    if ($missing.Count -gt 0) { throw "Missing app settings: $($missing -join ', ')" }

    $opt = {
        param($name, $default)
        $v = [Environment]::GetEnvironmentVariable($name)
        if ([string]::IsNullOrWhiteSpace($v)) { $default } else { $v }
    }

    return [pscustomobject]@{
        DceUri             = $env:DCE_INGEST_URI
        DcrImmutableId     = $env:DCR_IMMUTABLE_ID
        StreamName         = $env:STREAM_NAME
        MonitorResource    = & $opt 'MONITOR_RESOURCE' 'https://monitor.azure.com'
        MaxRecords         = [int](& $opt 'MAX_RECORDS' 5000)
        MaxBodyBytes       = [int](& $opt 'MAX_BODY_BYTES' 950000)
        AllowedColumns     = @(ConvertTo-ListFromSetting $env:ALLOWED_COLUMNS)
        # Per-device allow-list. Fine for a handful of pilot machines; do not use this at fleet scale.
        AllowedThumbprints = @(ConvertTo-ListFromSetting $env:ALLOWED_CERT_THUMBPRINTS | ForEach-Object { $_.ToUpper() })
        # Fleet-scale trust: base64 DER of one or more ISSUING CA certificates (not secret - these are public
        # certs), semicolon-separated. Any caller certificate that chains to one of these is accepted, so you
        # never have to enumerate individual device thumbprints.
        TrustedIssuerCertsB64 = @(ConvertTo-ListFromSetting $env:TRUSTED_ISSUER_CERTS_BASE64)
        RequireClientAuthEku  = -not ('false' -eq (& $opt 'REQUIRE_CLIENT_AUTH_EKU' 'true'))
    }
}

function Get-TrustedIssuerCertificates {
    param([string[]]$Base64Certs)
    $key = 'issuerCerts:' + ($Base64Certs -join ',').GetHashCode()
    if ($global:IngestCache.ContainsKey($key)) { return $global:IngestCache[$key] }
    $certs = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2Collection
    foreach ($b64 in $Base64Certs) {
        try {
            [void]$certs.Add((New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 -ArgumentList (, [Convert]::FromBase64String($b64))))
        }
        catch { Write-Warning "TRUSTED_ISSUER_CERTS_BASE64 contains an unparseable certificate entry; skipped." }
    }
    $global:IngestCache[$key] = $certs
    return $certs
}

function New-IngestException {
    param([string]$Kind, [string]$Message, [int]$Status = 0)
    $e = New-Object System.Exception $Message
    $e.Data['Kind'] = $Kind
    $e.Data['Status'] = $Status
    return $e
}

function Get-HttpErrorInfo {
    param($ErrorRecord)
    $status = 0
    $ex = $ErrorRecord.Exception
    if ($ex.PSObject.Properties['Response'] -and $ex.Response) {
        try { $status = [int]$ex.Response.StatusCode } catch { }
    }
    $detail = $ex.Message
    if ($ErrorRecord.ErrorDetails -and $ErrorRecord.ErrorDetails.Message) { $detail = $ErrorRecord.ErrorDetails.Message }
    if ($detail.Length -gt 500) { $detail = $detail.Substring(0, 500) }
    return [pscustomobject]@{ Status = $status; Detail = $detail }
}

# Caller check (mTLS). App Service forwards the client cert in X-ARR-ClientCert when
# "Client certificate mode" is Require/Optional. Two trust mechanisms, checked in order:
#   1. AllowedThumbprints - exact per-device match. Use only for a small pilot; does not scale to a fleet.
#   2. TrustedIssuerCertsB64 - the cert chains to one of your issuing CAs. This is the fleet-scale mechanism:
#      one CA config entry covers every device it has issued a cert to, so enrolling a new machine (e.g. via
#      Intune/NDES autoenrollment) needs no Function-side change.
# If neither is configured, the check is disabled and any caller is accepted (fine for initial bring-up only).
function Test-CallerCertificate {
    param($Headers, [string[]]$AllowedThumbprints, [string[]]$TrustedIssuerCertsB64, [bool]$RequireClientAuthEku = $true)

    $haveAllowList = $AllowedThumbprints -and $AllowedThumbprints.Count -gt 0
    $haveIssuers = $TrustedIssuerCertsB64 -and $TrustedIssuerCertsB64.Count -gt 0
    if (-not $haveAllowList -and -not $haveIssuers) { return $true }

    $b64 = $Headers['x-arr-clientcert']
    if ([string]::IsNullOrWhiteSpace($b64)) {
        Write-Warning 'Caller certificate rejected: X-ARR-ClientCert header is missing.'
        return $false
    }
    try {
        $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 -ArgumentList (, [Convert]::FromBase64String($b64))
    }
    catch {
        Write-Warning 'Caller certificate rejected: X-ARR-ClientCert is not valid Base64 certificate data.'
        return $false
    }
    Write-Host "Caller certificate received: Subject='$($cert.Subject)' Issuer='$($cert.Issuer)' Thumbprint=$($cert.Thumbprint) NotAfter=$($cert.NotAfter)"

    $now = Get-Date
    if ($cert.NotBefore -gt $now -or $cert.NotAfter -lt $now) {
        Write-Warning "Caller certificate rejected: certificate is outside its validity period (NotBefore=$($cert.NotBefore), NotAfter=$($cert.NotAfter))."
        return $false
    }

    if ($haveAllowList -and ($AllowedThumbprints -contains $cert.Thumbprint.ToUpper())) { return $true }

    if ($haveIssuers) {
        if ($RequireClientAuthEku) {
            $clientAuthOid = '1.3.6.1.5.5.7.3.2'
            $hasEku = $false
            foreach ($ext in $cert.Extensions) {
                if ($ext -is [System.Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension]) {
                    foreach ($u in $ext.EnhancedKeyUsages) { if ($u.Value -eq $clientAuthOid) { $hasEku = $true } }
                }
            }
            if (-not $hasEku) {
                Write-Warning 'Caller certificate rejected: Client Authentication EKU is missing.'
                return $false
            }
        }

        $issuerCerts = Get-TrustedIssuerCertificates -Base64Certs $TrustedIssuerCertsB64
        if ($issuerCerts.Count -eq 0) {
            Write-Warning 'Caller certificate rejected: no trusted issuer certificates could be parsed from TRUSTED_ISSUER_CERTS_BASE64.'
            return $false
        }

        $chain = New-Object System.Security.Cryptography.X509Certificates.X509Chain
        foreach ($issuerCert in $issuerCerts) {
            [void]$chain.ChainPolicy.ExtraStore.Add($issuerCert)
        }
        # These certs are validated against a trust list we supply, not the OS root store, and this Function
        # does not have network access to check revocation, so revocation checking is off here. Short-lived
        # device certs (e.g. Intune-issued, auto-renewed) are the usual mitigation; add CRL/OCSP checking if
        # your CA setup supports it from this Function's network.
        $chain.ChainPolicy.RevocationMode = [System.Security.Cryptography.X509Certificates.X509RevocationMode]::NoCheck
        $chain.ChainPolicy.VerificationFlags = [System.Security.Cryptography.X509Certificates.X509VerificationFlags]::AllowUnknownCertificateAuthority
        $built = $chain.Build($cert)
        if (-not $built) {
            $statuses = @($chain.ChainStatus | ForEach-Object { $_.Status.ToString() }) -join ', '
            Write-Warning "Caller certificate rejected: certificate chain could not be built. ChainStatus=$statuses"
            return $false
        }

        $chainThumbprints = @($chain.ChainElements | ForEach-Object { $_.Certificate.Thumbprint })
        foreach ($ic in $issuerCerts) {
            if ($chainThumbprints -contains $ic.Thumbprint) { return $true }
        }
        $chainTop = $chain.ChainElements[$chain.ChainElements.Count - 1].Certificate.Thumbprint
        Write-Warning "Caller certificate rejected: configured issuer was not present in the certificate chain (chainTop=$chainTop)."
    }
    else {
        Write-Warning 'Caller certificate rejected: certificate thumbprint was not on the configured allow-list.'
    }
    return $false
}

# Token for the given resource, issued to the Function's system-assigned managed identity.
function Get-ManagedIdentityToken {
    param([Parameter(Mandatory)][string]$Resource)
    $key = "mi:$Resource"
    $c = $global:IngestCache[$key]
    if ($c -and $c.Expires -gt (Get-Date).ToUniversalTime().AddMinutes(5)) { return $c.Token }

    if (-not $env:IDENTITY_ENDPOINT -or -not $env:IDENTITY_HEADER) {
        throw (New-IngestException 'config' 'Managed identity endpoint unavailable. Is the system-assigned identity enabled on the Function App?')
    }
    $uri = '{0}?resource={1}&api-version=2019-08-01' -f $env:IDENTITY_ENDPOINT, [uri]::EscapeDataString($Resource)
    try {
        $r = Invoke-RestMethod -Uri $uri -Method Get -Headers @{ 'X-IDENTITY-HEADER' = $env:IDENTITY_HEADER } -ErrorAction Stop
    }
    catch {
        $i = Get-HttpErrorInfo $_
        throw (New-IngestException 'auth' "Managed identity token request failed (HTTP $($i.Status)): $($i.Detail)" $i.Status)
    }

    $exp = (Get-Date).ToUniversalTime().AddMinutes(30)
    $n = 0L
    if ([int64]::TryParse([string]$r.expires_on, [ref]$n)) { $exp = [DateTimeOffset]::FromUnixTimeSeconds($n).UtcDateTime }
    $global:IngestCache[$key] = @{ Token = [string]$r.access_token; Expires = $exp }
    return [string]$r.access_token
}

# Sends already-validated records to the DCE with the managed identity's token.
# Retries once on a 401 (stale cached token).
function Invoke-LogIngestion {
    param($Settings, $Records)

    # Copy into a typed object[] (not @($Records)) so a single record still serializes as an array.
    # @() over a generic List[object] throws "Argument types do not match" on PowerShell 7.6 / .NET 10.
    [object[]]$recordArray = foreach ($r in $Records) { $r }
    $json = ConvertTo-Json -InputObject $recordArray -Depth 6 -Compress
    $bytes = [Text.Encoding]::UTF8.GetBytes($json)
    $uri = '{0}/dataCollectionRules/{1}/streams/{2}?api-version=2023-01-01' -f `
        $Settings.DceUri.TrimEnd('/'), $Settings.DcrImmutableId, $Settings.StreamName

    for ($try = 1; $try -le 2; $try++) {
        $token = Get-ManagedIdentityToken -Resource $Settings.MonitorResource
        try {
            $null = Invoke-WebRequest -Uri $uri -Method Post -Headers @{ Authorization = "Bearer $token" } `
                -ContentType 'application/json; charset=utf-8' -Body $bytes -UseBasicParsing -ErrorAction Stop
            return
        }
        catch {
            $i = Get-HttpErrorInfo $_
            if ($try -eq 1 -and $i.Status -eq 401) {
                $global:IngestCache.Remove("mi:$($Settings.MonitorResource)")
                continue
            }
            $kind = 'dce'
            if ($i.Status -eq 0 -or $i.Status -eq 429 -or $i.Status -ge 500) { $kind = 'dce-transient' }
            throw (New-IngestException $kind "DCE returned HTTP $($i.Status): $($i.Detail)" $i.Status)
        }
    }
}
