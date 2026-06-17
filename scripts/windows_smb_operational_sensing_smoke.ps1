param(
    [int]$TotalTimeoutSeconds = 90
)

$ErrorActionPreference = "Stop"
$repoRoot = Split-Path -Parent $PSScriptRoot
$processName = "smb_operational_foreground_smoke"
$executable = Join-Path $repoRoot "target\debug\examples\smb_operational_foreground_smoke.exe"
$outputFile = Join-Path $env:TEMP "sentinel-smb-operational-smoke-$([guid]::NewGuid().ToString('N')).jsonl"
$errorFile = Join-Path $env:TEMP "sentinel-smb-operational-smoke-$([guid]::NewGuid().ToString('N')).err"

try {
    & cargo build -p sentinel-app-core --example smb_operational_foreground_smoke -j 1 --quiet
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $executable)) {
        throw "smb operational foreground smoke build failed"
    }

    $process = Start-Process `
        -FilePath $executable `
        -WorkingDirectory $repoRoot `
        -NoNewWindow `
        -PassThru `
        -RedirectStandardOutput $outputFile `
        -RedirectStandardError $errorFile

    if (-not $process.WaitForExit($TotalTimeoutSeconds * 1000)) {
        Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue
        throw "smb operational foreground smoke timed out"
    }
    if ($null -ne $process.ExitCode -and $process.ExitCode -ne 0) {
        $stderr = Get-Content -Raw -ErrorAction SilentlyContinue $errorFile
        throw "smb operational foreground smoke failed: $stderr"
    }

    $jsonLine = Get-Content $outputFile | Where-Object { $_.Trim().StartsWith("{") } | Select-Object -Last 1
    if (-not $jsonLine) {
        throw "smb operational foreground smoke emitted no JSON report"
    }
    $report = $jsonLine | ConvertFrom-Json

    if (-not $report.disabled_by_default) {
        throw "smb operational provider was not disabled by default"
    }
    if ($report.activation_result -notin @("active", "degraded", "error")) {
        throw "smb operational activation produced unexpected state '$($report.activation_result)'"
    }
    if ($report.stop_result -ne "stopped") {
        throw "smb operational provider did not stop cleanly: $($report.stop_result)"
    }
    if (-not $report.clean_shutdown -or [int]$report.unjoined_workers -ne 0) {
        throw "smb operational foreground smoke did not shut down cleanly"
    }
    if ([int]$report.read_only_side_effects -ne 0 -or $report.response_execution_allowed) {
        throw "smb operational smoke widened read-only or response execution scope"
    }
    if ($report.process_network_attribution_available -or $report.packet_visibility_available) {
        throw "smb operational smoke widened unrelated network visibility"
    }
    if (-not $report.privacy_boundary_holds -or $report.raw_value_exposure_detected) {
        throw "smb operational smoke reported a privacy boundary violation"
    }
    if ([int]$report.lateral_invocations -ne 0 -or [int]$report.lateral_consumed -ne 0) {
        throw "single SMB operational source unexpectedly claimed lateral movement consumption"
    }

    $serialized = $report | ConvertTo-Json -Compress
    $stderrText = Get-Content -Raw -ErrorAction SilentlyContinue $errorFile
    $privacySurface = "$serialized`n$stderrText"
    $forbiddenMarkers = @(
        "raw_user",
        "raw_domain",
        "raw_share",
        "share_name",
        "unc",
        "hostname",
        "workstation",
        "client_address",
        "ipaddress",
        "username",
        "account_name",
        "session_id",
        '"sid"',
        '"pid"',
        "payload",
        "cookie",
        "credential",
        "access_token",
        "api_key",
        "private_key",
        "certificate_content",
        "command_line",
        "executable_path",
        "nonce",
        "secret"
    )
    foreach ($forbidden in $forbiddenMarkers) {
        if ($privacySurface.ToLowerInvariant().Contains($forbidden)) {
            throw "smb operational smoke privacy check found forbidden marker '$forbidden'"
        }
    }
    if ($privacySurface -match '(?<![A-Za-z0-9])(?:\d{1,3}\.){3}\d{1,3}(?![A-Za-z0-9])') {
        throw "smb operational smoke privacy check found an IPv4-looking value"
    }
    if ($privacySurface -match '(?i)\bS-\d-\d+(?:-\d+){1,}\b') {
        throw "smb operational smoke privacy check found a SID-looking value"
    }
    if ($privacySurface -match '(?i)\b[A-Z]:\\') {
        throw "smb operational smoke privacy check found a Windows path"
    }

    Start-Sleep -Milliseconds 200
    $remaining = @(Get-Process -Name $processName -ErrorAction SilentlyContinue).Count
    if ($remaining -ne 0) {
        throw "smb operational foreground smoke left $remaining process(es)"
    }

    if ($report.honest_status -eq "real") {
        $requiredPositive = @(
            "provider_enabled",
            "raw_events",
            "schema_accepted",
            "normalized_remote_access_observations",
            "normalized_batches",
            "published_batches",
            "eventbus_publications",
            "dag_dispatches",
            "auth_detector_invocations",
            "auth_consumed",
            "remote_admin_invocations",
            "remote_admin_consumed",
            "downstream_facts",
            "security_facts_refreshed",
            "canonical_generation_updates"
        )
        foreach ($field in $requiredPositive) {
            if ([int64]$report.$field -le 0) {
                throw "smb operational foreground smoke counter '$field' was not positive"
            }
        }
        if (-not $report.latest_batch_cached -or [int]$report.latest_batch_observations -le 0) {
            throw "smb operational foreground smoke did not cache the latest normalized batch"
        }
        if (-not $report.provider_zero_smb_only) {
            throw "smb operational foreground smoke touched unrelated provider-zero counters"
        }

        [pscustomobject]@{
            status = "real"
            honest_status = $report.honest_status
            execution_context = $report.execution_context
            provider_enabled = [int]$report.provider_enabled
            raw_events = [int]$report.raw_events
            schema_accepted = [int]$report.schema_accepted
            normalized_auth_observations = [int]$report.normalized_auth_observations
            normalized_remote_access_observations = [int]$report.normalized_remote_access_observations
            normalized_batches = [int]$report.normalized_batches
            published_batches = [int]$report.published_batches
            eventbus_publications = [int]$report.eventbus_publications
            dag_dispatches = [int]$report.dag_dispatches
            auth_detector_invocations = [int]$report.auth_detector_invocations
            auth_consumed = [int]$report.auth_consumed
            remote_admin_invocations = [int]$report.remote_admin_invocations
            remote_admin_consumed = [int]$report.remote_admin_consumed
            downstream_facts = [int]$report.downstream_facts
            security_facts_refreshed = [int]$report.security_facts_refreshed
            canonical_generation_updates = [int64]$report.canonical_generation_updates
            privacy_check = "pass"
            clean_shutdown = $report.clean_shutdown
            unjoined_workers = [int]$report.unjoined_workers
            remaining_servicehost_processes = $remaining
        } | ConvertTo-Json -Compress
    } elseif ($report.honest_status -eq "blocked_by_env") {
        [pscustomobject]@{
            status = "blocked_by_env"
            honest_status = $report.honest_status
            reason = $report.blocked_reason
            execution_context = $report.execution_context
            activation_result = $report.activation_result
            provider_enabled = [int]$report.provider_enabled
            raw_events = [int]$report.raw_events
            normalized_batches = [int]$report.normalized_batches
            eventbus_publications = [int]$report.eventbus_publications
            downstream_facts = [int]$report.downstream_facts
            privacy_check = "pass"
            clean_shutdown = $report.clean_shutdown
            unjoined_workers = [int]$report.unjoined_workers
            remaining_servicehost_processes = $remaining
        } | ConvertTo-Json -Compress
    } else {
        throw "smb operational smoke returned unsupported honest_status '$($report.honest_status)'"
    }
}
finally {
    Remove-Item -LiteralPath $outputFile -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $errorFile -Force -ErrorAction SilentlyContinue
}
