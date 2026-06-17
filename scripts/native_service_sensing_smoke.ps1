param(
    [int]$TotalTimeoutSeconds = 90
)

$ErrorActionPreference = "Stop"
$repoRoot = Split-Path -Parent $PSScriptRoot
$processName = "native_service_foreground_smoke"
$executable = Join-Path $repoRoot "target\debug\examples\native_service_foreground_smoke.exe"
$outputFile = Join-Path $env:TEMP "sentinel-native-service-smoke-$([guid]::NewGuid().ToString('N')).jsonl"
$errorFile = Join-Path $env:TEMP "sentinel-native-service-smoke-$([guid]::NewGuid().ToString('N')).err"

try {
    & cargo build -p sentinel-app-core --example native_service_foreground_smoke -j 1 --quiet
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $executable)) {
        throw "native service foreground smoke build failed"
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
        throw "native service foreground smoke timed out"
    }
    if ($null -ne $process.ExitCode -and $process.ExitCode -ne 0) {
        $stderr = Get-Content -Raw -ErrorAction SilentlyContinue $errorFile
        throw "native service foreground smoke failed: $stderr"
    }

    $jsonLine = Get-Content $outputFile | Where-Object { $_.Trim().StartsWith("{") } | Select-Object -Last 1
    if (-not $jsonLine) {
        throw "native service foreground smoke emitted no JSON report"
    }
    $report = $jsonLine | ConvertFrom-Json

    $requiredPositive = @(
        "provider_enabled",
        "raw_service_observations",
        "schema_accepted",
        "normalized_observations",
        "service_category_aggregates",
        "published_batches",
        "eventbus_publications",
        "dag_executions",
        "plugin_runtime_invocations",
        "native_fact_observations_consumed",
        "native_facts_produced",
        "security_facts_refreshed",
        "endpoint_threat_invocations",
        "endpoint_threat_observations_consumed",
        "evidence_quality_records",
        "settings_read_model_updates",
        "canonical_generation_updates"
    )
    foreach ($field in $requiredPositive) {
        if ([int64]$report.$field -le 0) {
            throw "native service foreground smoke counter '$field' was not positive"
        }
    }

    foreach ($field in @(
        "schema_rejected",
        "malformed",
        "rate_limited",
        "queue_dropped",
        "duplicate_suppressed"
    )) {
        if ([int64]$report.$field -ne 0) {
            throw "native service foreground smoke counter '$field' was not zero"
        }
    }
    if (-not $report.authorization_granted -or -not $report.authorization_revoked) {
        throw "native service foreground smoke authorization lifecycle was incomplete"
    }
    if (-not $report.clean_shutdown -or [int]$report.unjoined_workers -ne 0) {
        throw "native service foreground smoke did not shut down cleanly"
    }
    if ([int]$report.endpoint_threat_outputs -ne 0) {
        throw "benign service-category sample unexpectedly produced Endpoint Threat outputs"
    }
    if ([int]$report.fusion_outputs -ne 0 -or [int]$report.risk_outputs -ne 0) {
        throw "single benign service-category source unexpectedly produced fusion or risk outputs"
    }

    $serialized = $report | ConvertTo-Json -Compress
    $stderrText = Get-Content -Raw -ErrorAction SilentlyContinue $errorFile
    $privacySurface = "$serialized`n$stderrText"
    $forbiddenMarkers = @(
        "service_name",
        "display_name",
        "executable_path",
        "command_line",
        "account_name",
        "username",
        '"sid"',
        '"pid"',
        "registry_path",
        "raw_ip",
        "raw_port",
        "packet_payload",
        "credential",
        "access_token",
        "nonce",
        "secret"
    )
    foreach ($forbidden in $forbiddenMarkers) {
        if ($privacySurface.ToLowerInvariant().Contains($forbidden)) {
            throw "native service smoke privacy check found forbidden marker '$forbidden'"
        }
    }
    if ($privacySurface -match '(?<![A-Za-z0-9])(?:\d{1,3}\.){3}\d{1,3}(?![A-Za-z0-9])') {
        throw "native service smoke privacy check found an IPv4-looking value"
    }
    if ($privacySurface -match '(?i)\bS-\d-\d+(?:-\d+){1,}\b') {
        throw "native service smoke privacy check found a SID-looking value"
    }
    if ($privacySurface -match '(?i)\b[A-Z]:\\') {
        throw "native service smoke privacy check found a Windows path"
    }

    Start-Sleep -Milliseconds 200
    $remaining = @(Get-Process -Name $processName -ErrorAction SilentlyContinue).Count
    if ($remaining -ne 0) {
        throw "native service foreground smoke left $remaining process(es)"
    }

    [pscustomobject]@{
        status = "pass"
        execution_context = $report.execution_context
        authorization_granted = $report.authorization_granted
        authorization_revoked = $report.authorization_revoked
        provider_enabled = [int]$report.provider_enabled
        raw_service_observations = [int]$report.raw_service_observations
        schema_accepted = [int]$report.schema_accepted
        schema_rejected = [int]$report.schema_rejected
        malformed = [int]$report.malformed
        rate_limited = [int]$report.rate_limited
        queue_dropped = [int]$report.queue_dropped
        duplicate_suppressed = [int]$report.duplicate_suppressed
        normalized_observations = [int]$report.normalized_observations
        service_category_aggregates = [int]$report.service_category_aggregates
        published_batches = [int]$report.published_batches
        eventbus_publications = [int]$report.eventbus_publications
        dag_executions = [int]$report.dag_executions
        plugin_runtime_invocations = [int]$report.plugin_runtime_invocations
        native_fact_observations_consumed = [int]$report.native_fact_observations_consumed
        native_facts_produced = [int]$report.native_facts_produced
        security_facts_refreshed = [int]$report.security_facts_refreshed
        endpoint_threat_invocations = [int]$report.endpoint_threat_invocations
        endpoint_threat_observations_consumed = [int]$report.endpoint_threat_observations_consumed
        endpoint_threat_outputs = [int]$report.endpoint_threat_outputs
        fusion_outputs = [int]$report.fusion_outputs
        evidence_quality_records = [int]$report.evidence_quality_records
        risk_outputs = [int]$report.risk_outputs
        settings_read_model_updates = [int]$report.settings_read_model_updates
        canonical_generation_updates = [int64]$report.canonical_generation_updates
        provider_availability = $report.provider_availability
        provider_health = $report.provider_health
        privacy_check = "pass"
        clean_shutdown = $report.clean_shutdown
        unjoined_workers = [int]$report.unjoined_workers
        remaining_servicehost_processes = $remaining
    } | ConvertTo-Json -Compress
}
finally {
    Remove-Item -LiteralPath $outputFile -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $errorFile -Force -ErrorAction SilentlyContinue
}
