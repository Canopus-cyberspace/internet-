param(
    [int]$TotalTimeoutSeconds = 90
)

$ErrorActionPreference = "Stop"
$repoRoot = Split-Path -Parent $PSScriptRoot
$processName = "native_health_foreground_smoke"
$executable = Join-Path $repoRoot "target\debug\examples\native_health_foreground_smoke.exe"
$outputFile = Join-Path $env:TEMP "sentinel-native-health-smoke-$([guid]::NewGuid().ToString('N')).jsonl"
$errorFile = Join-Path $env:TEMP "sentinel-native-health-smoke-$([guid]::NewGuid().ToString('N')).err"

try {
    & cargo build -p sentinel-app-core --example native_health_foreground_smoke -j 1 --quiet
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $executable)) {
        throw "native health foreground smoke build failed"
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
        throw "native health foreground smoke timed out"
    }
    if ($null -ne $process.ExitCode -and $process.ExitCode -ne 0) {
        $stderr = Get-Content -Raw -ErrorAction SilentlyContinue $errorFile
        throw "native health foreground smoke failed: $stderr"
    }

    $jsonLine = Get-Content $outputFile | Where-Object { $_.Trim().StartsWith("{") } | Select-Object -Last 1
    if (-not $jsonLine) {
        throw "native health foreground smoke emitted no JSON report"
    }
    $report = $jsonLine | ConvertFrom-Json

    $requiredPositive = @(
        "provider_enabled",
        "raw_records",
        "schema_accepted",
        "normalized_records",
        "published_batches",
        "eventbus_publications",
        "dag_dispatches",
        "plugin_runtime_invocations",
        "observations_consumed",
        "downstream_facts",
        "endpoint_consumer_invocations",
        "endpoint_observations_consumed",
        "evidence_quality_records",
        "read_model_generation_updates"
    )
    foreach ($field in $requiredPositive) {
        if ([int64]$report.$field -le 0) {
            throw "native health foreground smoke counter '$field' was not positive"
        }
    }
    if (-not $report.authorization_granted) {
        throw "native health foreground smoke authorization was not granted"
    }
    if (-not $report.clean_shutdown -or [int]$report.unjoined_workers -ne 0) {
        throw "native health foreground smoke did not shut down cleanly"
    }

    $serialized = $report | ConvertTo-Json -Compress
    $forbiddenKeys = @(
        "raw_ip",
        "raw_port",
        "packet_payload",
        "process_id",
        "process_name",
        "executable_path",
        "command_line",
        "username",
        "sid",
        "credential",
        "access_token",
        "nonce",
        "secret"
    )
    foreach ($forbidden in $forbiddenKeys) {
        if ($serialized.ToLowerInvariant().Contains($forbidden)) {
            throw "native health smoke privacy check found forbidden marker '$forbidden'"
        }
    }
    if ($serialized -match '(?<![A-Za-z0-9])(?:\d{1,3}\.){3}\d{1,3}(?![A-Za-z0-9])') {
        throw "native health smoke privacy check found an IPv4-looking value"
    }

    Start-Sleep -Milliseconds 200
    $remaining = @(Get-Process -Name $processName -ErrorAction SilentlyContinue).Count
    if ($remaining -ne 0) {
        throw "native health foreground smoke left $remaining process(es)"
    }

    [pscustomobject]@{
        status = "pass"
        execution_context = $report.execution_context
        authorization_granted = $report.authorization_granted
        provider_enabled = [int]$report.provider_enabled
        raw_records = [int]$report.raw_records
        schema_accepted = [int]$report.schema_accepted
        schema_rejected = [int]$report.schema_rejected
        normalized_records = [int]$report.normalized_records
        published_batches = [int]$report.published_batches
        eventbus_publications = [int]$report.eventbus_publications
        dag_dispatches = [int]$report.dag_dispatches
        plugin_runtime_invocations = [int]$report.plugin_runtime_invocations
        observations_consumed = [int]$report.observations_consumed
        downstream_facts = [int]$report.downstream_facts
        endpoint_consumer_invocations = [int]$report.endpoint_consumer_invocations
        endpoint_observations_consumed = [int]$report.endpoint_observations_consumed
        endpoint_outputs = [int]$report.endpoint_outputs
        fusion_facts_consumed = [int]$report.fusion_facts_consumed
        evidence_quality_records = [int]$report.evidence_quality_records
        risk_outputs = [int]$report.risk_outputs
        read_model_generation_updates = [int64]$report.read_model_generation_updates
        provider_availability = $report.provider_availability
        resource_pressure = $report.resource_pressure
        freshness = $report.freshness
        privacy_check = "pass"
        clean_shutdown = $report.clean_shutdown
        unjoined_workers = [int]$report.unjoined_workers
        remaining_processes = $remaining
    } | ConvertTo-Json -Compress
}
finally {
    Remove-Item -LiteralPath $outputFile -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $errorFile -Force -ErrorAction SilentlyContinue
}
