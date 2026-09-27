<#
.SYNOPSIS
    Deploys the IngestLogs code and app settings to an EXISTING Function App, and optionally
    grants its managed identity publish rights on the EXISTING DCR.

.DESCRIPTION
    Run from an admin workstation after Connect-AzAccount. No Azure resources are created.
    There is no secret anywhere in this design: the Function authenticates to the DCE with
    its system-assigned managed identity. Every app setting set here is plain configuration.

    The zip is built with forward-slash entry names (Compress-Archive in PS 5.1 writes
    backslashes, which break Linux Function Apps).

.PARAMETER DcrResourceId
    Optional. Full resource ID of the DCR. When given, the Function's managed identity is
    granted "Monitoring Metrics Publisher" on it (skipped if already assigned).
    Omit if that role assignment already exists or is managed elsewhere.

.EXAMPLE
    .\Publish-IngestFunction.ps1 -ResourceGroupName rg-logs -FunctionAppName func-logingest `
        -DceIngestUri https://dce-logs-abcd.eastus-1.ingest.monitor.azure.com `
        -DcrImmutableId dcr-0123456789abcdef0123456789abcdef -StreamName Custom-HelloForBusiness_CL `
        -DcrResourceId /subscriptions/<sub>/resourceGroups/rg-logs/providers/Microsoft.Insights/dataCollectionRules/dcr-logs
#>
#Requires -Version 5.1
#Requires -Modules Az.Accounts, Az.Functions, Az.Websites, Az.Resources
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)][string]$ResourceGroupName,
    [Parameter(Mandatory)][string]$FunctionAppName,
    [Parameter(Mandatory)][string]$DceIngestUri,
    [Parameter(Mandatory)][string]$DcrImmutableId,
    [Parameter(Mandatory)][string]$StreamName,
    [string]$DcrResourceId,
    [string[]]$AllowedCertThumbprints = @(),
    # Paths to one or more issuing CA certificate files (.cer/.crt, public - not secret). Fleet-scale caller
    # trust: any device certificate chaining to one of these is accepted, with no per-device configuration.
    [string[]]$TrustedIssuerCertPaths = @(),
    [string[]]$AllowedColumns = @(),
    [string]$SourcePath = (Join-Path $PSScriptRoot '..\function'),
    [switch]$SkipSettings,
    [switch]$SkipCode
)

$ErrorActionPreference = 'Stop'

function New-FunctionZip {
    param([string]$Source, [string]$ZipPath)
    Add-Type -AssemblyName System.IO.Compression, System.IO.Compression.FileSystem
    if (Test-Path -LiteralPath $ZipPath) { Remove-Item -LiteralPath $ZipPath -Force }
    $root = (Resolve-Path -LiteralPath $Source).Path.TrimEnd('\')
    $zip = [System.IO.Compression.ZipFile]::Open($ZipPath, [System.IO.Compression.ZipArchiveMode]::Create)
    try {
        Get-ChildItem -LiteralPath $root -Recurse -File | ForEach-Object {
            $rel = $_.FullName.Substring($root.Length + 1).Replace('\', '/')
            [void][System.IO.Compression.ZipFileExtensions]::CreateEntryFromFile(
                $zip, $_.FullName, $rel, [System.IO.Compression.CompressionLevel]::Optimal)
        }
    }
    finally { $zip.Dispose() }
}

# The script assumes the caller has already authenticated to Azure and has permission to
# update the target Function App settings and assign RBAC on the existing DCR.
if (-not (Get-AzContext)) { throw 'Not signed in. Run Connect-AzAccount first.' }

# Locate the target Azure Function. This script does not create any Azure resources; it only
# configures an existing Function App that was already provisioned separately.
$app = Get-AzFunctionApp -ResourceGroupName $ResourceGroupName -Name $FunctionAppName
if (-not $app) { throw "Function App '$FunctionAppName' not found in '$ResourceGroupName'." }

# The Function App must expose a system-assigned managed identity so it can authenticate to
# the DCE/DCR without any shared secrets.
$principalId = [string]$app.IdentityPrincipalId
if ([string]::IsNullOrWhiteSpace($principalId) -or [string]$app.IdentityType -notmatch 'SystemAssigned') {
    Write-Warning 'The Function App does not report a system-assigned identity. Enable it (Function App > Identity) - this design cannot authenticate without it.'
}

# Grant the Function App's managed identity permission to publish metrics to the existing DCR.
# This is required only when the DCR already exists and there is no separate role assignment flow.
if ($DcrResourceId -and $principalId) {
    $role = 'Monitoring Metrics Publisher'
    $existing = Get-AzRoleAssignment -ObjectId $principalId -RoleDefinitionName $role -Scope $DcrResourceId -ErrorAction SilentlyContinue |
        Where-Object { $_.Scope -eq $DcrResourceId }
    if ($existing) {
        Write-Output "Role '$role' already assigned to the Function's identity on the DCR."
    }
    elseif ($PSCmdlet.ShouldProcess($DcrResourceId, "Assign '$role' to Function identity $principalId")) {
        $null = New-AzRoleAssignment -ObjectId $principalId -RoleDefinitionName $role -Scope $DcrResourceId
        Write-Output "Assigned '$role' on the DCR. Allow up to ~30 minutes to propagate."
    }
}

if (-not $SkipSettings) {
    # These are the settings consumed by the function code at runtime. They tell the
    # ingestion module where to send logs, which stream to use, and which issuer certs are trusted.
    $settings = @{
        DCE_INGEST_URI   = $DceIngestUri
        DCR_IMMUTABLE_ID = $DcrImmutableId
        STREAM_NAME      = $StreamName
    }
    if (@($AllowedCertThumbprints).Count -gt 0) { $settings['ALLOWED_CERT_THUMBPRINTS'] = (@($AllowedCertThumbprints) -join ',') }
    if (@($AllowedColumns).Count -gt 0) { $settings['ALLOWED_COLUMNS'] = (@($AllowedColumns) -join ',') }
    if (@($TrustedIssuerCertPaths).Count -gt 0) {
        # Convert one or more public X.509 issuer certificates into a Base64 payload that the
        # function can validate against client device chains without storing any private material.
        $b64 = @($TrustedIssuerCertPaths | ForEach-Object {
                $full = (Resolve-Path -LiteralPath $_).Path
                $text = Get-Content -LiteralPath $full -Raw -ErrorAction SilentlyContinue
                if ($text -and $text -match '-----BEGIN CERTIFICATE-----') {
                    # PEM: strip the header/footer and any other blocks (e.g. a private key), keep only
                    # the first certificate block, and re-derive the raw DER bytes from it.
                    $m = [regex]::Match($text, '-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----', 'Singleline')
                    if (-not $m.Success) { throw "No CERTIFICATE block found in $full" }
                    [Convert]::ToBase64String([Convert]::FromBase64String(($m.Groups[1].Value -replace '\s', '')))
                }
                else {
                    # Already DER.
                    [Convert]::ToBase64String([IO.File]::ReadAllBytes($full))
                }
            })
        $settings['TRUSTED_ISSUER_CERTS_BASE64'] = ($b64 -join ';')
    }

    # Persist the configuration to the existing Azure Function so code and settings are in sync.
    if ($PSCmdlet.ShouldProcess($FunctionAppName, "Merge $($settings.Count) app setting(s)")) {
        $null = Update-AzFunctionAppSetting -ResourceGroupName $ResourceGroupName -Name $FunctionAppName -AppSetting $settings -Force
        Write-Output "App settings updated: $($settings.Keys -join ', ')"
    }
}

if (-not $SkipCode) {
    # Zip-deploy the current function source. This keeps the deployment consistent with the code
    # in the repo and avoids needing to re-create Azure resources or manual file copies.
    $zipPath = Join-Path ([IO.Path]::GetTempPath()) ("ingestfunc-{0}.zip" -f [guid]::NewGuid().ToString('N'))
    try {
        New-FunctionZip -Source $SourcePath -ZipPath $zipPath
        if ($PSCmdlet.ShouldProcess($FunctionAppName, 'Zip-deploy function code')) {
            $null = Publish-AzWebApp -ResourceGroupName $ResourceGroupName -Name $FunctionAppName -ArchivePath $zipPath -Force
            Write-Output 'Code deployed.'
        }
    }
    finally {
        if (Test-Path -LiteralPath $zipPath) { Remove-Item -LiteralPath $zipPath -Force }
    }
}

Write-Output ''
Write-Output 'Checklist (existing resources):'
Write-Output '  [ ] Function App has a system-assigned identity'
Write-Output '  [ ] That identity has "Monitoring Metrics Publisher" on the DCR (pass -DcrResourceId to assign it)'
Write-Output '  [ ] DCR stream columns match the record fields the endpoint sends'
