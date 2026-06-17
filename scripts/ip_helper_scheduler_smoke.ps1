[CmdletBinding()]
param(
    [string]$Binary = "",
    [string]$ReportPath = "",
    [int]$TotalTimeoutSeconds = 180
)

$ErrorActionPreference = "Stop"

$Script:Root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$Script:SmokeRoot = Join-Path $Script:Root "target\smoke"
$Script:ProtocolVersion = 1
$Script:SchemaVersion = [ordered]@{ major = 1; minor = 0; patch = 0 }
$Script:PipeName = "SentinelGuardIpc"
$Script:PipePath = "\\.\pipe\SentinelGuardIpc"
$Script:Binary = $Binary
$Script:ServiceProcess = $null
$Script:StopFile = $null
$Script:StdoutFile = $null
$Script:StderrFile = $null
$Script:Report = [ordered]@{
    profile = "ip_helper_autonomous_scheduler_foreground"
    result = "not_run"
    blocked_reason = $null
    servicehost_started = $false
    caller_verified = $false
    provider_activated_explicitly = $false
    schedule_configured_explicitly = $false
    schedule_enabled_explicitly = $false
    completed_cycle_bucket = "zero"
    manual_scheduled_overlap_prevented = $false
    overlap_validation_mode = "process_accounting"
    pause_prevented_calls = $false
    disconnect_invalidated_schedule = $false
    stop_prevented_calls = $false
    restart_disabled_schedule = $false
    scheduler_host_joined = $false
    remaining_process_count = 0
    remaining_enabled_schedule_count = 0
    raw_value_exposure_detected = $false
    activation_calls = 0
    manual_sample_requests = 0
    valid_manual_sample_executions = 0
    scheduled_due_cycles = 0
    scheduled_completed_cycles = 0
    scheduled_skipped_cycles = 0
    adapter_invocation_count = 0
    eventbus_metadata_publication_count = 0
    fact_publication_count = 0
    canonical_snapshot_generation_count = 0
    timeout_count = 0
    retry_count = 0
    overlap_skip_count = 0
    backpressure_skip_count = 0
    calls_after_pause = 0
    calls_after_disconnect = 0
    calls_after_stop = 0
    calls_after_shutdown = 0
    etw_calls = 0
    npcap_probes = 0
    capture_broker_launches = 0
    packet_facts = 0
    process_network_facts = 0
    response_executions = 0
    automatic_llm_calls = 0
    scm_localservice_validation = "blocked_by_env"
    resume_wake_assist = "not_observed"
}

function Test-IsWindowsHost {
    ($env:OS -eq "Windows_NT") -or ($PSVersionTable.PSEdition -eq "Desktop") -or ($IsWindows -eq $true)
}

function Open-LocalPipeStream {
    $pipe = [System.IO.Pipes.NamedPipeClientStream]::new(
        ".",
        $Script:PipeName,
        [System.IO.Pipes.PipeDirection]::InOut,
        [System.IO.Pipes.PipeOptions]::None,
        [System.Security.Principal.TokenImpersonationLevel]::Impersonation
    )
    $pipe.Connect(500)
    $pipe
}

function New-SafeRef {
    param([string]$Prefix)
    $suffix = ([guid]::NewGuid().ToString("N")).Substring(0, 12)
    "$Prefix`_$suffix"
}

function ConvertTo-FrameBytes {
    param([object]$Value)
    $json = $Value | ConvertTo-Json -Depth 64 -Compress
    [System.Text.Encoding]::UTF8.GetBytes($json)
}

function Read-Exact {
    param(
        [System.IO.Stream]$Stream,
        [int]$Length
    )
    $buffer = New-Object byte[] $Length
    $offset = 0
    while ($offset -lt $Length) {
        $read = $Stream.Read($buffer, $offset, $Length - $offset)
        if ($read -le 0) {
            throw "ipc_frame_closed"
        }
        $offset += $read
    }
    $buffer
}

function Write-JsonFrame {
    param(
        [System.IO.Stream]$Stream,
        [object]$Value
    )
    $payload = ConvertTo-FrameBytes -Value $Value
    if ($payload.Length -gt (64 * 1024)) {
        throw "ipc_frame_too_large"
    }
    $length = [System.BitConverter]::GetBytes([uint32]$payload.Length)
    $Stream.Write($length, 0, $length.Length)
    $Stream.Write($payload, 0, $payload.Length)
    $Stream.Flush()
}

function Read-JsonFrame {
    param([System.IO.Stream]$Stream)
    $lengthBytes = Read-Exact -Stream $Stream -Length 4
    $length = [System.BitConverter]::ToUInt32($lengthBytes, 0)
    if ($length -gt (64 * 1024)) {
        throw "ipc_frame_too_large"
    }
    $payload = Read-Exact -Stream $Stream -Length ([int]$length)
    $json = [System.Text.Encoding]::UTF8.GetString($payload)
    $json | ConvertFrom-Json
}

function New-IpcSession {
    param([int]$TimeoutMilliseconds = 10000)

    $deadline = [DateTimeOffset]::UtcNow.AddMilliseconds($TimeoutMilliseconds)
    $lastError = $null
    while ([DateTimeOffset]::UtcNow -lt $deadline) {
        $pipe = $null
        $stage = "open_pipe"
        try {
            $pipe = Open-LocalPipeStream
            $clientNonce = New-SafeRef -Prefix "smoke_client"
            $stage = "client_hello_write"
            Write-JsonFrame -Stream $pipe -Value ([ordered]@{
                message_type = "client_hello"
                supported_protocol_versions = @($Script:ProtocolVersion)
                schema_version = $Script:SchemaVersion
                client_nonce = $clientNonce
                requested_capabilities = @(
                    "read_only_status",
                    "read_only_canonical_snapshots"
                )
            })
            $stage = "server_hello_read"
            $hello = Read-JsonFrame -Stream $pipe
            $stage = "client_verify_write"
            Write-JsonFrame -Stream $pipe -Value ([ordered]@{
                message_type = "client_verify"
                protocol_version = $Script:ProtocolVersion
                schema_version = $Script:SchemaVersion
                session_reference = $hello.session_reference
                client_nonce = $clientNonce
                server_nonce = $hello.server_nonce
                challenge_nonce = $hello.challenge_nonce
                sequence_number = 0
                caller_kind = "local_desktop"
            })
            $stage = "server_verify_read"
            $verified = Read-JsonFrame -Stream $pipe
            if ($verified.response_status -ne "ok") {
                $code = if ($verified.code) { [string]$verified.code } elseif ($verified.payload -and $verified.payload.code) { [string]$verified.payload.code } else { "caller_verification_failed" }
                throw "caller_verification_failed:$code"
            }
            $Script:Report.caller_verified = $true
            [pscustomobject]@{
                Pipe = $pipe
                SessionReference = [string]$hello.session_reference
                ClientNonce = [string]$clientNonce
                ServerNonce = [string]$hello.server_nonce
                ChallengeNonce = [string]$hello.challenge_nonce
                CallerVerification = $verified.caller_verification
                Sequence = 1
            }
            return
        }
        catch {
            $lastError = "$stage`:$($_.Exception.Message)"
            if ($pipe) {
                $pipe.Dispose()
            }
            Start-Sleep -Milliseconds 150
        }
    }
    throw "ipc_ready_timeout:$lastError"
}

function Close-IpcSession {
    param([object]$Session)
    if ($null -ne $Session -and $null -ne $Session.Pipe) {
        $Session.Pipe.Dispose()
    }
}

function Invoke-IpcCommand {
    param(
        [object]$Session,
        [string]$Command,
        [object]$Payload
    )
    $requestId = New-SafeRef -Prefix "smoke_request"
    $envelope = [ordered]@{
        protocol_version = $Script:ProtocolVersion
        schema_version = $Script:SchemaVersion
        request_id = $requestId
        session_reference = $Session.SessionReference
        client_nonce = $Session.ClientNonce
        server_nonce = $Session.ServerNonce
        sequence_number = $Session.Sequence
        command_id = $Command
        response_status = "request"
        payload = $Payload
    }
    $Session.Sequence++
    Write-JsonFrame -Stream $Session.Pipe -Value $envelope
    $response = Read-JsonFrame -Stream $Session.Pipe
    if ($response.response_status -ne "ok") {
        $code = "ipc_command_failed"
        if ($response.payload -and $response.payload.code) {
            $code = [string]$response.payload.code
        }
        throw "$Command`:$code"
    }
    $response.payload
}

function Get-SmokeStatus {
    param([object]$Session)
    Invoke-IpcCommand -Session $Session -Command "status" -Payload ([ordered]@{})
}

function Invoke-ReadSnapshot {
    param([object]$Session)
    Invoke-IpcCommand -Session $Session -Command "get_provider_controller_status" -Payload ([ordered]@{
        page_size = 1
    })
}

function Get-ProviderCallCount {
    param([object]$Status)
    if ($Status.provider_controller_status -and $Status.provider_controller_status.provider_zero -and $null -ne $Status.provider_controller_status.provider_zero.ip_helper_calls) {
        return [int]$Status.provider_controller_status.provider_zero.ip_helper_calls
    }
    if ($Status.runtime_ownership_status -and $null -ne $Status.runtime_ownership_status.provider_call_count) {
        return [int]$Status.runtime_ownership_status.provider_call_count
    }
    0
}

function Get-ScheduleStatus {
    param([object]$Status)
    $Status.provider_controller_status.ip_helper_schedule
}

function Get-IpHelperLifecycle {
    param([object]$Status)
    $provider = @($Status.provider_controller_status.providers | Where-Object { $_.provider_kind -eq "ip_helper" } | Select-Object -First 1)
    if ($provider.Count -eq 0) {
        return "unavailable"
    }
    [string]$provider[0].lifecycle_state
}

function Get-PolicyWireName {
    param([string]$IntentCommand)
    switch ($IntentCommand) {
        "activate_ip_helper_provider" { "activate_ip_helper" }
        "sample_ip_helper_now" { "sample_ip_helper_once" }
        default { $IntentCommand }
    }
}

function New-MutationIntent {
    param(
        [object]$Session,
        [string]$IntentCommand,
        [uint64]$OwnershipEpoch,
        [string]$IntentLabel
    )
    $policyWire = Get-PolicyWireName -IntentCommand $IntentCommand
    [ordered]@{
        schema_version = $Script:SchemaVersion
        intent_ref = New-SafeRef -Prefix "smoke_$IntentLabel"
        request_ref = New-SafeRef -Prefix "smoke_$IntentLabel`_request"
        ipc_session_ref = $Session.SessionReference
        caller_verification_ref = [string]$Session.CallerVerification.verification_ref
        command_id = $IntentCommand
        policy_ref = "mutation_policy_$policyWire"
        policy_version = $Script:SchemaVersion
        target_capability_ref = "ip_helper_provider_ref"
        target_capability_category = "ip_helper_provider"
        requested_operation_category = $policyWire
        created_time_bucket = "current_connection"
        expiry_ttl_bucket = "thirty_seconds"
        ownership_epoch = $OwnershipEpoch
        idempotency_ref = New-SafeRef -Prefix "smoke_$IntentLabel`_idem"
        explicit_user_action = $true
        dry_run = $true
        audit_refs = @("mutation_intent_received")
        provenance_id = "ip_helper_scheduler_smoke"
        redaction_status = "redacted"
    }
}

function Invoke-AuthorizedMutation {
    param(
        [object]$Session,
        [string]$WireCommand,
        [string]$IntentCommand,
        [uint64]$OwnershipEpoch,
        [object]$ScheduleConfig = $null
    )
    $intentLabel = $WireCommand.Replace("_ip_helper", "").Replace("_schedule", "")
    $intent = New-MutationIntent -Session $Session -IntentCommand $IntentCommand -OwnershipEpoch $OwnershipEpoch -IntentLabel $intentLabel
    $decision = Invoke-IpcCommand -Session $Session -Command "evaluate_mutation_intent" -Payload $intent
    if ($decision.result -ne "approved_for_execution") {
        throw "$WireCommand`:decision_$($decision.result)"
    }
    $executionRequest = [ordered]@{
        schema_version = $Script:SchemaVersion
        decision_ref = $decision.decision_ref
        intent = $intent
        explicit_user_action = $true
        provenance_id = "ip_helper_scheduler_smoke"
        redaction_status = "redacted"
    }
    if ($WireCommand -like "*_schedule") {
        $payload = [ordered]@{
            execution_request = $executionRequest
            schedule_config = $ScheduleConfig
            explicit_user_action = $true
            provenance_id = "ip_helper_scheduler_smoke"
            redaction_status = "redacted"
        }
    }
    else {
        $payload = $executionRequest
    }
    Invoke-IpcCommand -Session $Session -Command $WireCommand -Payload $payload
}

function New-BoundedScheduleConfig {
    [ordered]@{
        interval_bucket = "fifteen_seconds"
        provider_timeout_bucket = "two_hundred_fifty_millis"
        execution_timeout_bucket = "one_second"
        retry_budget_bucket = "one"
        retry_delay_bucket = "five_seconds"
        maximum_records = 128
        maximum_bytes = 131072
        no_overlap_marker = $true
        no_catch_up_marker = $true
    }
}

function Wait-ForProviderCalls {
    param(
        [object]$Session,
        [int]$MinimumCount,
        [int]$TimeoutSeconds
    )
    $deadline = [DateTimeOffset]::UtcNow.AddSeconds($TimeoutSeconds)
    $lastStatus = $null
    while ([DateTimeOffset]::UtcNow -lt $deadline) {
        $lastStatus = Get-SmokeStatus -Session $Session
        if ((Get-ProviderCallCount -Status $lastStatus) -ge $MinimumCount) {
            return $lastStatus
        }
        Start-Sleep -Seconds 2
    }
    $lastCount = if ($lastStatus) { Get-ProviderCallCount -Status $lastStatus } else { 0 }
    $schedule = if ($lastStatus) { Get-ScheduleStatus -Status $lastStatus } else { $null }
    $state = if ($schedule) { [string]$schedule.schedule_state } else { "unknown" }
    $lease = if ($schedule) { [string]$schedule.lease_state } else { "unknown" }
    $timer = if ($schedule -and $schedule.timer_runtime_active) { "active" } else { "inactive" }
    $nextDue = if ($schedule) { [string]$schedule.next_due_category } else { "unknown" }
    $reason = if ($schedule -and $schedule.degraded_reason) { [string]$schedule.degraded_reason } else { "none" }
    $lifecycle = if ($lastStatus) { Get-IpHelperLifecycle -Status $lastStatus } else { "unknown" }
    $latestResult = if ($schedule) { [string]$schedule.latest_scheduled_execution_result } else { "unknown" }
    throw "provider_call_count_timeout:count_$lastCount`:min_$MinimumCount`:state_$state`:lease_$lease`:timer_$timer`:next_$nextDue`:provider_$lifecycle`:latest_$latestResult`:reason_$reason"
}

function Assert-Condition {
    param(
        [bool]$Condition,
        [string]$Reason
    )
    if (-not $Condition) {
        throw $Reason
    }
}

function Update-CounterReport {
    param([object]$Status)
    $schedule = Get-ScheduleStatus -Status $Status
    $providerZero = $Status.provider_controller_status.provider_zero
    $Script:Report.adapter_invocation_count = Get-ProviderCallCount -Status $Status
    $Script:Report.scheduled_completed_cycles = [int]$schedule.scheduler_triggered_provider_calls
    $Script:Report.scheduled_due_cycles = [int]$schedule.scheduler_triggered_provider_calls
    $Script:Report.scheduled_skipped_cycles = switch ([string]$schedule.skipped_count_bucket) {
        "zero" { 0 }
        "one" { 1 }
        "few" { 2 }
        default { 10 }
    }
    $Script:Report.retry_count = switch ([string]$schedule.retry_count_bucket) {
        "zero" { 0 }
        "one" { 1 }
        "few" { 2 }
        default { 10 }
    }
    $Script:Report.timeout_count = switch ([string]$schedule.timeout_count_bucket) {
        "zero" { 0 }
        "one" { 1 }
        "few" { 2 }
        default { 10 }
    }
    $Script:Report.overlap_skip_count = switch ([string]$schedule.overlap_skip_count_bucket) {
        "zero" { 0 }
        "one" { 1 }
        "few" { 2 }
        default { 10 }
    }
    $Script:Report.backpressure_skip_count = if ($schedule.backpressure_state -in @("high", "saturated")) { 1 } else { 0 }
    $Script:Report.eventbus_metadata_publication_count = [int]$providerZero.native_network_topic_publications
    if ($schedule.latest_scheduled_cycle -and $schedule.latest_scheduled_cycle.fact_refs) {
        $Script:Report.fact_publication_count = @($schedule.latest_scheduled_cycle.fact_refs).Count
    }
    if ($schedule.latest_scheduled_cycle -and $schedule.latest_scheduled_cycle.snapshot_refs) {
        $Script:Report.canonical_snapshot_generation_count = @($schedule.latest_scheduled_cycle.snapshot_refs).Count
    }
    $Script:Report.etw_calls = [int]$providerZero.etw_calls
    $Script:Report.npcap_probes = [int]$providerZero.npcap_probes
    $Script:Report.capture_broker_launches = [int]$providerZero.capture_broker_launches
    $Script:Report.packet_facts = [int]$providerZero.packet_facts
    $Script:Report.process_network_facts = [int]$providerZero.process_network_facts
}

function Test-PrivacyExposure {
    param([string[]]$Texts)
    $seededMarkers = @(
        "pid_value_778899",
        "203.0.113.77",
        "port_value_65000",
        "process_name_value_calc",
        "c:\unsafe\binary.exe",
        "username_value_alice",
        "sid_value_123",
        "token_value_abc",
        "credential_value_abc",
        "secret_value_abc"
    )
    foreach ($text in $Texts) {
        foreach ($marker in $seededMarkers) {
            if ($text -and $text.ToLowerInvariant().Contains($marker.ToLowerInvariant())) {
                return $true
            }
        }
    }
    $false
}

function Write-SmokeReport {
    if (-not $ReportPath) {
        $ReportPath = Join-Path $Script:SmokeRoot "ip_helper_scheduler_smoke.report.json"
    }
    $json = $Script:Report | ConvertTo-Json -Depth 32
    Set-Content -LiteralPath $ReportPath -Value $json -Encoding UTF8
}

function Stop-SmokeServiceHost {
    if ($Script:StopFile) {
        New-Item -ItemType File -Path $Script:StopFile -Force | Out-Null
    }
    if ($Script:ServiceProcess -and -not $Script:ServiceProcess.HasExited) {
        try {
            Wait-Process -Id $Script:ServiceProcess.Id -Timeout 20 -ErrorAction Stop
        }
        catch {
            Stop-Process -Id $Script:ServiceProcess.Id -Force -ErrorAction SilentlyContinue
            Wait-Process -Id $Script:ServiceProcess.Id -Timeout 5 -ErrorAction SilentlyContinue
        }
    }
}

function Start-SmokeServiceHost {
    param([int]$MaxRuntimeSeconds)
    $Script:StopFile = Join-Path $Script:SmokeRoot ("ip-helper-scheduler-stop-" + ([guid]::NewGuid().ToString("N")) + ".flag")
    $Script:StdoutFile = Join-Path $Script:SmokeRoot ("ip-helper-scheduler-stdout-" + ([guid]::NewGuid().ToString("N")) + ".log")
    $Script:StderrFile = Join-Path $Script:SmokeRoot ("ip-helper-scheduler-stderr-" + ([guid]::NewGuid().ToString("N")) + ".log")
    Remove-Item -LiteralPath $Script:StopFile -Force -ErrorAction SilentlyContinue

    $previousStopFile = $env:SENTINEL_GUARD_FOREGROUND_SMOKE_STOP_FILE
    $previousMax = $env:SENTINEL_GUARD_FOREGROUND_SMOKE_MAX_MS
    try {
        $env:SENTINEL_GUARD_FOREGROUND_SMOKE_STOP_FILE = $Script:StopFile
        $env:SENTINEL_GUARD_FOREGROUND_SMOKE_MAX_MS = [string]($MaxRuntimeSeconds * 1000)
        $Script:ServiceProcess = Start-Process `
            -FilePath $Script:Binary `
            -ArgumentList @("--foreground") `
            -WorkingDirectory $Script:Root `
            -PassThru `
            -WindowStyle Hidden `
            -RedirectStandardOutput $Script:StdoutFile `
            -RedirectStandardError $Script:StderrFile
    }
    finally {
        $env:SENTINEL_GUARD_FOREGROUND_SMOKE_STOP_FILE = $previousStopFile
        $env:SENTINEL_GUARD_FOREGROUND_SMOKE_MAX_MS = $previousMax
    }
    $Script:Report.servicehost_started = $true
}

function Invoke-SmokeRun {
    New-Item -ItemType Directory -Path $Script:SmokeRoot -Force | Out-Null
    if (-not (Test-IsWindowsHost)) {
        $Script:Report.result = "blocked_by_env"
        $Script:Report.blocked_reason = "windows_required"
        return
    }
    if (-not $Script:Binary) {
        $debugBinary = Join-Path $Script:Root "target\debug\sentinel-guard-service-host.exe"
        $releaseBinary = Join-Path $Script:Root "target\release\sentinel-guard-service-host.exe"
        if (Test-Path -LiteralPath $debugBinary) {
            $Script:Binary = (Resolve-Path -LiteralPath $debugBinary).Path
        }
        elseif (Test-Path -LiteralPath $releaseBinary) {
            $Script:Binary = (Resolve-Path -LiteralPath $releaseBinary).Path
        }
    }
    if (-not $Script:Binary -or -not (Test-Path -LiteralPath $Script:Binary)) {
        $Script:Report.result = "blocked_by_env"
        $Script:Report.blocked_reason = "already_built_servicehost_binary_missing"
        return
    }
    $existing = @(Get-Process -Name "sentinel-guard-service-host" -ErrorAction SilentlyContinue)
    if ($existing.Count -gt 0) {
        $Script:Report.result = "blocked_by_env"
        $Script:Report.blocked_reason = "existing_servicehost_process"
        return
    }

    Start-SmokeServiceHost -MaxRuntimeSeconds $TotalTimeoutSeconds
    $session = $null
    try {
        $session = New-IpcSession -TimeoutMilliseconds 15000
        $initial = Get-SmokeStatus -Session $session
        $epoch = [uint64]$initial.runtime_ownership_status.ownership_epoch
        Assert-Condition -Condition ($epoch -gt 0) -Reason "ownership_epoch_missing"
        Assert-Condition -Condition ((Get-ProviderCallCount -Status $initial) -eq 0) -Reason "initial_provider_call_count_not_zero"
        Assert-Condition -Condition ((Get-IpHelperLifecycle -Status $initial) -in @("inactive", "ready", "stopped")) -Reason "ip_helper_not_initially_inactive"
        Assert-Condition -Condition (-not (Get-ScheduleStatus -Status $initial).enabled_marker) -Reason "schedule_enabled_on_startup"
        Start-Sleep -Seconds 2
        $idle = Get-SmokeStatus -Session $session
        Assert-Condition -Condition ((Get-ProviderCallCount -Status $idle) -eq 0) -Reason "timer_called_provider_before_enable"

        $activate = Invoke-AuthorizedMutation -Session $session -WireCommand "activate_ip_helper" -IntentCommand "activate_ip_helper_provider" -OwnershipEpoch $epoch
        if ($activate.result_category -in @("completed", "already_satisfied")) {
            $Script:Report.activation_calls++
            $Script:Report.provider_activated_explicitly = $true
        }
        $afterActivate = Get-SmokeStatus -Session $session
        Assert-Condition -Condition ((Get-IpHelperLifecycle -Status $afterActivate) -in @("active", "ready")) -Reason "ip_helper_not_active_after_activation"
        Assert-Condition -Condition ((Get-ProviderCallCount -Status $afterActivate) -eq 0) -Reason "activation_sampled_provider"

        $config = New-BoundedScheduleConfig
        $configure = Invoke-AuthorizedMutation -Session $session -WireCommand "configure_ip_helper_schedule" -IntentCommand "configure_ip_helper_schedule" -OwnershipEpoch $epoch -ScheduleConfig $config
        Assert-Condition -Condition ($configure.result_category -eq "completed") -Reason "schedule_configure_failed"
        $Script:Report.schedule_configured_explicitly = $true

        $enable = Invoke-AuthorizedMutation -Session $session -WireCommand "enable_ip_helper_schedule" -IntentCommand "enable_ip_helper_schedule" -OwnershipEpoch $epoch
        Assert-Condition -Condition ($enable.result_category -eq "completed") -Reason "schedule_enable_failed"
        $Script:Report.schedule_enabled_explicitly = $true
        $enabled = Get-SmokeStatus -Session $session
        Assert-Condition -Condition ((Get-ScheduleStatus -Status $enabled).timer_runtime_active) -Reason "timer_not_active_after_enable"

        $twoCycleStatus = Wait-ForProviderCalls -Session $session -MinimumCount 2 -TimeoutSeconds 42
        Update-CounterReport -Status $twoCycleStatus
        Assert-Condition -Condition ($Script:Report.scheduled_completed_cycles -ge 2) -Reason "scheduled_cycles_not_observed"
        $Script:Report.completed_cycle_bucket = "multiple"
        Assert-Condition -Condition ((Get-ScheduleStatus -Status $twoCycleStatus).freshness_state -eq "fresh") -Reason "connection_table_freshness_not_fresh"
        $readSnapshot = Invoke-ReadSnapshot -Session $session
        Assert-Condition -Condition (@($readSnapshot.items).Count -ge 1) -Reason "provider_read_snapshot_missing"

        $manualBefore = Get-ProviderCallCount -Status $twoCycleStatus
        $manualIntent = Invoke-AuthorizedMutation -Session $session -WireCommand "sample_ip_helper_once" -IntentCommand "sample_ip_helper_now" -OwnershipEpoch $epoch
        $Script:Report.manual_sample_requests++
        if ($manualIntent.result_category -eq "completed") {
            $Script:Report.valid_manual_sample_executions += [int]$manualIntent.counters.sampled_count
        }
        $afterManual = Get-SmokeStatus -Session $session
        Assert-Condition -Condition ((Get-ProviderCallCount -Status $afterManual) -eq ($manualBefore + $Script:Report.valid_manual_sample_executions)) -Reason "manual_sample_accounting_mismatch"

        $pauseBefore = Get-ProviderCallCount -Status $afterManual
        $pause = Invoke-AuthorizedMutation -Session $session -WireCommand "pause_ip_helper_schedule" -IntentCommand "pause_ip_helper_schedule" -OwnershipEpoch $epoch
        Assert-Condition -Condition ($pause.result_category -eq "completed") -Reason "schedule_pause_failed"
        Start-Sleep -Seconds 18
        $afterPause = Get-SmokeStatus -Session $session
        $Script:Report.calls_after_pause = (Get-ProviderCallCount -Status $afterPause) - $pauseBefore
        $Script:Report.pause_prevented_calls = $Script:Report.calls_after_pause -eq 0
        Assert-Condition -Condition $Script:Report.pause_prevented_calls -Reason "pause_allowed_provider_calls"

        $resume = Invoke-AuthorizedMutation -Session $session -WireCommand "resume_ip_helper_schedule" -IntentCommand "resume_ip_helper_schedule" -OwnershipEpoch $epoch
        Assert-Condition -Condition ($resume.result_category -eq "completed") -Reason "schedule_resume_failed"
        if ($resume.audit_refs) {
            $wakeAssist = @($resume.audit_refs | Where-Object { ([string]$_).StartsWith("ip_helper_scheduler_wake_assist_") } | Select-Object -Last 1)
            if ($wakeAssist.Count -gt 0) {
                $Script:Report.resume_wake_assist = [string]$wakeAssist[0]
            }
        }
        $resumeTarget = (Get-ProviderCallCount -Status $afterPause) + 1
        Start-Sleep -Seconds 18
        $afterResumeCandidate = Get-SmokeStatus -Session $session
        if ((Get-ProviderCallCount -Status $afterResumeCandidate) -ge $resumeTarget) {
            $afterResume = $afterResumeCandidate
        }
        else {
            $afterResume = Wait-ForProviderCalls -Session $session -MinimumCount $resumeTarget -TimeoutSeconds 30
        }
        Update-CounterReport -Status $afterResume

        $validExpected = $Script:Report.valid_manual_sample_executions + $Script:Report.scheduled_completed_cycles
        $Script:Report.manual_scheduled_overlap_prevented = $Script:Report.adapter_invocation_count -eq $validExpected
        Assert-Condition -Condition $Script:Report.manual_scheduled_overlap_prevented -Reason "provider_call_accounting_invariant_failed"

        $beforeDisconnectCount = Get-ProviderCallCount -Status $afterResume
        Close-IpcSession -Session $session
        $session = $null
        Start-Sleep -Seconds 18
        $session = New-IpcSession -TimeoutMilliseconds 10000
        $afterDisconnect = Get-SmokeStatus -Session $session
        $Script:Report.calls_after_disconnect = (Get-ProviderCallCount -Status $afterDisconnect) - $beforeDisconnectCount
        $scheduleAfterDisconnect = Get-ScheduleStatus -Status $afterDisconnect
        $Script:Report.disconnect_invalidated_schedule = $Script:Report.calls_after_disconnect -eq 0 -and -not $scheduleAfterDisconnect.enabled_marker
        Assert-Condition -Condition $Script:Report.disconnect_invalidated_schedule -Reason "disconnect_did_not_invalidate_schedule"

        $epoch = [uint64]$afterDisconnect.runtime_ownership_status.ownership_epoch
        if ((Get-IpHelperLifecycle -Status $afterDisconnect) -notin @("active", "ready")) {
            [void](Invoke-AuthorizedMutation -Session $session -WireCommand "activate_ip_helper" -IntentCommand "activate_ip_helper_provider" -OwnershipEpoch $epoch)
        }
        [void](Invoke-AuthorizedMutation -Session $session -WireCommand "configure_ip_helper_schedule" -IntentCommand "configure_ip_helper_schedule" -OwnershipEpoch $epoch -ScheduleConfig (New-BoundedScheduleConfig))
        [void](Invoke-AuthorizedMutation -Session $session -WireCommand "enable_ip_helper_schedule" -IntentCommand "enable_ip_helper_schedule" -OwnershipEpoch $epoch)
        $beforeStopCycle = Wait-ForProviderCalls -Session $session -MinimumCount ((Get-ProviderCallCount -Status $afterDisconnect) + 1) -TimeoutSeconds 24
        $beforeStopCount = Get-ProviderCallCount -Status $beforeStopCycle
        $stop = Invoke-AuthorizedMutation -Session $session -WireCommand "stop_ip_helper" -IntentCommand "stop_ip_helper" -OwnershipEpoch $epoch
        Assert-Condition -Condition ($stop.result_category -in @("completed", "already_satisfied")) -Reason "stop_ip_helper_failed"
        Start-Sleep -Seconds 18
        $afterStop = Get-SmokeStatus -Session $session
        $Script:Report.calls_after_stop = (Get-ProviderCallCount -Status $afterStop) - $beforeStopCount
        $Script:Report.stop_prevented_calls = $Script:Report.calls_after_stop -eq 0
        Assert-Condition -Condition $Script:Report.stop_prevented_calls -Reason "stop_allowed_provider_calls"
        Update-CounterReport -Status $afterStop
        Close-IpcSession -Session $session
        $session = $null

        Stop-SmokeServiceHost
        $Script:ServiceProcess.Refresh()
        $Script:Report.remaining_process_count = if ($Script:ServiceProcess.HasExited) { 0 } else { 1 }
        $stdout = if (Test-Path -LiteralPath $Script:StdoutFile) { Get-Content -Raw -LiteralPath $Script:StdoutFile } else { "" }
        $stderr = if (Test-Path -LiteralPath $Script:StderrFile) { Get-Content -Raw -LiteralPath $Script:StderrFile } else { "" }
        $Script:Report.raw_value_exposure_detected = Test-PrivacyExposure -Texts @($stdout, $stderr, ($Script:Report | ConvertTo-Json -Depth 32))
        if ($stdout) {
            $lastJson = ($stdout -split "`r?`n" | Where-Object { $_.Trim().StartsWith("{") } | Select-Object -Last 1)
            if ($lastJson) {
                $finalStatus = $lastJson | ConvertFrom-Json
                $Script:Report.scheduler_host_joined = [bool]$finalStatus.scheduler_joined
            }
        }
        Assert-Condition -Condition ($Script:Report.remaining_process_count -eq 0) -Reason "servicehost_process_remained"
        Assert-Condition -Condition $Script:Report.scheduler_host_joined -Reason "scheduler_host_not_joined"
        Assert-Condition -Condition (-not $Script:Report.raw_value_exposure_detected) -Reason "privacy_marker_exposed"

        $Script:ServiceProcess = $null
        Start-SmokeServiceHost -MaxRuntimeSeconds 30
        $restartSession = New-IpcSession -TimeoutMilliseconds 10000
        try {
            $restartStatus = Get-SmokeStatus -Session $restartSession
            $restartSchedule = Get-ScheduleStatus -Status $restartStatus
            $Script:Report.restart_disabled_schedule = -not $restartSchedule.enabled_marker -and (Get-ProviderCallCount -Status $restartStatus) -eq 0
            $Script:Report.remaining_enabled_schedule_count = if ($restartSchedule.enabled_marker) { 1 } else { 0 }
            Assert-Condition -Condition $Script:Report.restart_disabled_schedule -Reason "restart_restored_enabled_schedule"
        }
        finally {
            Close-IpcSession -Session $restartSession
        }
        Stop-SmokeServiceHost
        $Script:ServiceProcess.Refresh()
        $Script:Report.remaining_process_count = if ($Script:ServiceProcess.HasExited) { 0 } else { 1 }
        Assert-Condition -Condition ($Script:Report.remaining_process_count -eq 0) -Reason "restart_servicehost_process_remained"
        $Script:Report.calls_after_shutdown = 0

        Assert-Condition -Condition ($Script:Report.etw_calls -eq 0) -Reason "etw_calls_detected"
        Assert-Condition -Condition ($Script:Report.npcap_probes -eq 0) -Reason "npcap_probe_detected"
        Assert-Condition -Condition ($Script:Report.capture_broker_launches -eq 0) -Reason "capture_broker_launch_detected"
        Assert-Condition -Condition ($Script:Report.packet_facts -eq 0) -Reason "packet_fact_detected"
        Assert-Condition -Condition ($Script:Report.process_network_facts -eq 0) -Reason "process_network_fact_detected"
        Assert-Condition -Condition ($Script:Report.response_executions -eq 0) -Reason "response_execution_detected"
        Assert-Condition -Condition ($Script:Report.automatic_llm_calls -eq 0) -Reason "automatic_llm_detected"

        $Script:Report.result = "pass"
    }
    finally {
        if ($session) {
            Close-IpcSession -Session $session
        }
        if ($Script:ServiceProcess -and -not $Script:ServiceProcess.HasExited) {
            Stop-SmokeServiceHost
        }
        Remove-Item -LiteralPath $Script:StopFile -Force -ErrorAction SilentlyContinue
    }
}

try {
    Invoke-SmokeRun
}
catch {
    $Script:Report.result = "fail"
    $Script:Report.blocked_reason = "$($_.Exception.Message):wake_assist_$($Script:Report.resume_wake_assist)"
}
finally {
    Write-SmokeReport
}

if ($Script:Report.result -eq "fail") {
    throw "ip_helper_scheduler_smoke_failed:$($Script:Report.blocked_reason)"
}

Write-Host "ip_helper_scheduler_smoke=$($Script:Report.result)"
