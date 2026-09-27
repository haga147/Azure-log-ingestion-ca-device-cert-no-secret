@{
    # Public URL of the ingestion Function. Contains NO key or token.
    FunctionUrl            = 'https://avdrich-powershell-fn-a4a5f6f0bcf2fuhk.centralus-01.azurewebsites.net/api/IngestLogs'

    # mTLS client certificate. Every endpoint shares this one config; each machine picks its own
    # matching cert at runtime, from Cert:\LocalMachine\My (SYSTEM's store - the scheduled task
    # runs as SYSTEM, so a user-store cert would not be visible). The private key never leaves
    # the machine.
    #
    # Mode:
    #   'AutoSelect'  - pick the best matching cert from LocalMachine\My (see filters below).
    #                   Use this for the fleet: the 802.1x/Wi-Fi-VPN SCEP cert already deployed
    #                   is the right choice here, NOT the Hybrid/Entra device-join cert - that one
    #                   is issued by a Microsoft-managed CA with no exportable issuer cert, so the
    #                   Function has nothing to validate its chain against.
    #   'Thumbprint'  - use one exact cert (testing/pilot only; doesn't scale to a fleet).
    #   'None'        - no client certificate sent.
    ClientCert = @{
        Mode = 'AutoSelect'

        # Mode = 'Thumbprint' only.
        Thumbprint = ''

        # Mode = 'AutoSelect' only. Substring match(es) against the candidate cert's Issuer name
        # (case-insensitive), to select the 802.1x SCEP cert over any other client-auth-capable
        # cert on the box (e.g. the Entra join cert). Match this to your internal issuing CA's
        # name, e.g. 'AVDRICH Intune Issuing CA'. Leave empty to skip issuer filtering (not
        # recommended once more than one matching cert can be present).
        IssuerContains = @('AVDRICH Intune Issuing CA')

        # Require the Client Authentication EKU (1.3.6.1.5.5.7.3.2). Leave true.
        RequireClientAuthEku = $true
    }

    # Random delay (seconds) before each run starts, so a large fleet on the same schedule doesn't
    # all call the Function in the same instant. Keep below (IntervalMinutes * 60) in the scheduled
    # task. At 80k endpoints on a 5-min cycle, 240s spreads the fleet to ~330 req/s average.
    MaxStartupJitterSec    = 240

    RequestTimeoutSec      = 60
    MaxRetries             = 4          # per batch, exponential backoff on timeouts / 408 / 429 / 5xx
    MaxBatchBytes          = 700000     # keep well under the 1 MB Logs Ingestion API limit
    MaxBatchRecords        = 2000
    MaxEventsPerLogPerRun  = 5000       # backlog is drained across successive runs
    InitialLookbackMinutes = 60         # first run only (no bookmark yet)
    MaxMessageChars        = 8000

    # Blank = %ProgramData%\LogShipper (log file + bookmark state). Must be a literal path if set.
    StateDir               = ''

    # Collect the log whose events match the Custom-HelloForBusiness_CL DCR stream schema.
    Logs = @(
        @{ LogName = 'Microsoft-Windows-HelloForBusiness/Operational' }
    )
}
