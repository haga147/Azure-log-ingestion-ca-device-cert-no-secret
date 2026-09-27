# Azure-log-ingestion (secretless)

```
endpoint (SYSTEM task) --HTTPS POST--> Azure Function --MI token--> DCE --> DCR --> Log Analytics table
                                          (system-assigned managed identity, Monitoring Metrics Publisher on the DCR)
```

There is no secret anywhere: no app registration secret, no Key Vault, no token stored on the endpoint. The Function gets a short-lived Azure Monitor token for its own managed identity from the platform and calls the DCE with it.

## Layout

| Path | Purpose |
|---|---|
| `endpoint/EndpointConfig.psd1` | Function URL, batching, which event logs to ship |
| `endpoint/Send-EndpointLogs.ps1` | Collects events, bookmarks, batches, POSTs to the Function (`-TestRecord` for a smoke test) |
| `endpoint/Install-LogShipperTask.ps1` | Installs/removes the SYSTEM scheduled task and locks the folders |
| `function/host.json`, `function/IngestLogs/*` | HTTP-triggered Function: validate, get a managed identity token, POST to DCE |
| `admin/Publish-IngestFunction.ps1` | Sets app settings, optionally grants the DCR role, and zip-deploys code to the EXISTING Function App |

## Prerequisites (existing resources, not created here)

1. Function App has a **system-assigned identity** enabled.
2. That identity has **Monitoring Metrics Publisher** on the DCR (`Publish-IngestFunction.ps1 -DcrResourceId ...` can assign it; role changes can take up to ~30 minutes to take effect).
3. The DCR stream / custom table columns match the fields in `ConvertTo-LogRecord` (endpoint script). Defaults: `TimeGenerated, Computer, EventLog, Provider, EventId, Level, LevelName, RecordId, Message`.
4. Function App runtime: PowerShell (7.x is fine; the code is PS 5.1-safe syntax).

## Function app settings (all plain configuration)

`DCE_INGEST_URI`, `DCR_IMMUTABLE_ID`, `STREAM_NAME` (e.g. `Custom-EndpointEvents_CL`)

Optional: `TRUSTED_ISSUER_CERTS_BASE64` (fleet-scale caller trust, see below), `ALLOWED_CERT_THUMBPRINTS` (pilot-only per-device trust), `REQUIRE_CLIENT_AUTH_EKU` (default `true`), `ALLOWED_COLUMNS`, `MAX_RECORDS` (5000), `MAX_BODY_BYTES` (950000), `MONITOR_RESOURCE` (`https://monitor.azure.com`).

## Deploy

```powershell
Connect-AzAccount
.\admin\Publish-IngestFunction.ps1 -ResourceGroupName "<fn-rg>" -FunctionAppName "<fn-app-name>" `
  -DceIngestUri "<dce-uri>" `
  -DcrImmutableId "<dcr-immutable-id>" `
  -StreamName "<Custom-HelloForBusiness_CL>" `
  -TrustedIssuerCertPaths "<C:\Temp\Certs\AVDRICH Intune Issuing CA.cer>"
```

Leave out `-DcrResourceId` if the role assignment already exists. Leave out `-TrustedIssuerCertPaths` if you're not enforcing mTLS yet (not recommended for production at fleet scale).

## Endpoint

```powershell
# edit endpoint\EndpointConfig.psd1 (FunctionUrl, ClientCert.IssuerContains), then as admin:
.\endpoint\Install-LogShipperTask.ps1 -IntervalMinutes 5
& "$env:ProgramFiles\LogShipper\Send-EndpointLogs.ps1" -TestRecord -Verbose
```

Logs and bookmark: `%ProgramData%\LogShipper\` (`shipper.log`, `state.json`). Remove with `-Remove`.

### Deploying via Intune (Win32 app)

Edit `EndpointConfig.psd1` first (`FunctionUrl`, `ClientCert.IssuerContains`) - it's shared by the whole fleet, so bake the real values in before packaging.

1. Package the `endpoint\` folder (`Send-EndpointLogs.ps1`, `EndpointConfig.psd1`, `Install-LogShipperTask.ps1`) with the [Microsoft Win32 Content Prep Tool](https://learn.microsoft.com/mem/intune/apps/apps-win32-prepare):
   ```
   IntuneWinAppUtil.exe -c endpoint -s Install-LogShipperTask.ps1 -o out
   ```
2. Create a Win32 app in Intune with the `.intunewin` output. Install/uninstall commands:
   - Install: `powershell.exe -NoProfile -ExecutionPolicy Bypass -File Install-LogShipperTask.ps1 -IntervalMinutes 5 -Version 1.0.0`
   - Uninstall: `powershell.exe -NoProfile -ExecutionPolicy Bypass -File Install-LogShipperTask.ps1 -Remove`
   - Install behavior: **System** (Intune runs this as `NT AUTHORITY\SYSTEM`; the script's elevation check accepts that without needing local admin).
3. Detection rule (registry, no script needed - the install script writes this key):
   - Key path: `HKLM\SOFTWARE\LogShipper`
   - Value: `InstalledVersion`
   - Detection method: String comparison, equals `1.0.0` (match whatever you pass to `-Version`)
4. **Rollout rings:** assign to a small pilot Entra group first, then widen in stages, rather than all 80k at once - this is your main defense against a bad config (e.g. a wrong `FunctionUrl`) reaching the whole fleet before anyone notices. Startup jitter (above) smooths load within a ring; rings smooth risk across the rollout timeline.
5. **Config updates:** the install script won't overwrite an existing `EndpointConfig.psd1` unless `-OverwriteConfig` is added to the install command - so a routine app update (e.g. bumping `-Version` for a script fix) leaves a machine's config alone by default. Add `-OverwriteConfig` to the install command when you deploy a package specifically to push new config to the fleet.

## Caller authentication (no stored secret)

The Function is `authLevel: anonymous`, because a Function key would be a secret on the endpoint. Restrict who can call it with:

- **mTLS, issuer-based trust (recommended at fleet scale):** set the Function App's *Client certificate mode* to Require. `EndpointConfig.psd1`'s `ClientCert` block picks a matching certificate from each machine's own `LocalMachine\My` store at runtime (`Mode = 'AutoSelect'`), so one config works for all 80k endpoints - no per-device thumbprint to deploy.

  **Reusing an existing device cert:** if endpoints already carry certs for 802.1x/Wi-Fi/VPN (SCEP) *and* Hybrid/Entra device join, use the **802.1x SCEP cert**, not the join cert. The join cert is issued by a Microsoft-managed CA with no exportable issuer certificate, so there's nothing to hand the Function as a trust anchor. The SCEP cert comes from your own internal issuing CA - for an EJBCA-issued fleet, that's the **Issuing/Sub CA** (not the Root) that actually signs the SCEP certs; export its certificate from EJBCA's Admin UI (CA Structure & CRLs → your CA → Info → download PEM or DER) and pass it to `-TrustedIssuerCertPaths` when running `Publish-IngestFunction.ps1` - it base64-encodes it (PEM or DER, either works) into `TRUSTED_ISSUER_CERTS_BASE64`. Set `ClientCert.IssuerContains` on the endpoint to a substring of that CA's name, so a box carrying both certs picks the SCEP one and not the join cert.

  Any caller certificate that chains to a configured CA is accepted - no per-device list to maintain, so enrolling machine #80,001 needs no Function-side change. Revocation isn't checked (the Function has no network path to your CRL/OCSP), so this relies on the certs being short-lived and auto-renewed (as SCEP certs typically are) rather than long-lived.
- **mTLS, per-device allow-list (pilot only):** `ALLOWED_CERT_THUMBPRINTS` matches exact leaf thumbprints. Fine for a handful of test machines; an app setting cannot hold 80,000 thumbprints, so don't use this as the fleet mechanism.
- **Network:** App Service access restrictions (IP allow-list) or a private endpoint, as a second layer alongside either of the above.

If both `TRUSTED_ISSUER_CERTS_BASE64` and `ALLOWED_CERT_THUMBPRINTS` are empty, the check is disabled and any caller is accepted - fine for initial bring-up, not for production.

## Scale (80k endpoints)

- **Request rate.** A 5-minute schedule across 80k machines averages ~267 requests/sec. Azure Monitor's Logs Ingestion API is currently documented at up to 300,000 requests/minute and 500 MB/minute overall, with a separate 2 GB/minute cap per individual DCR - your steady-state load has headroom, but only if it's spread out. (Check the current [Azure Monitor service limits](https://learn.microsoft.com/azure/azure-monitor/service-limits) before you commit to a fleet size, since these can change and can sometimes be raised via support.)
- **Startup jitter.** Task Scheduler firing all 80k machines on the same wall-clock trigger would burst well past those limits for a few seconds, then retry-storm. `EndpointConfig.psd1`'s `MaxStartupJitterSec` (default 240) makes each run sleep a random delay before it starts, spreading the fleet across most of the interval. Keep it comfortably under `IntervalMinutes * 60`.
- **Batch size.** Each POST already stays under the 1 MB per-call limit (`MaxBatchBytes` / `MAX_BODY_BYTES` default to ~700-950 KB) - no change needed here.
- **Function hosting plan.** A Consumption plan's cold starts and per-instance concurrency limits aren't a good fit for constant fleet-wide traffic. Use Premium (Elastic Premium) with a minimum instance count, and watch for 429s/5xxs in the endpoint logs and App Insights as you ramp up.
- **Rollout.** Deploy the scheduled task to endpoints in waves (Intune/GPO ring deployment) rather than all at once, both to catch issues early and to avoid a first-ever synchronized burst before jitter has "settled" the fleet across the interval.

## Troubleshooting

| Symptom | Likely cause |
|---|---|
| Function 500 "server configuration error" | Missing app setting, or the system-assigned identity is not enabled |
| Function 502 "upstream authentication failed" | Managed identity token request failed (identity disabled or platform issue; see Function log) |
| Function 502 with `upstreamStatus` 403 | Identity lacks Monitoring Metrics Publisher on the DCR, or the assignment hasn't propagated yet |
| Function 502 with `upstreamStatus` 400 | Record fields don't match the DCR stream schema |
| Endpoint HTTP 403 | Client cert missing, expired, doesn't chain to a trusted issuer, or lacks the Client Authentication EKU |
| Bursts of 429s at the top of every interval | Startup jitter too low/disabled for the fleet size; increase `MaxStartupJitterSec` |
