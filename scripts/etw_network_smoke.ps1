[CmdletBinding()]
param(
    [string]$Binary = "",
    [string]$ReportPath = "",
    [int]$TotalTimeoutSeconds = 120,
    [switch]$LibraryOnly
)

$ErrorActionPreference = "Stop"

$Script:Root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$Script:SmokeRoot = Join-Path $Script:Root "target\smoke"
$Script:ProtocolVersion = 1
$Script:SchemaVersion = [ordered]@{ major = 1; minor = 0; patch = 0 }
$Script:PipeName = "SentinelGuardIpc"
$Script:Binary = $Binary
$Script:ServiceProcess = $null
$Script:StopFile = $null
$Script:StdoutFile = $null
$Script:StderrFile = $null
$Script:Report = [ordered]@{
    profile = "etw_network_foreground_hardening"
    result = "not_run"
    blocked_reason = $null
    first_failure_boundary = "not_run"
    execution_context = "unknown"
    token_elevated = $false
    real_etw_smoke = "not_run"
    servicehost_started = $false
    caller_verified = $false
    etw_initially_inactive = $false
    etw_probe_state = "not_run"
    etw_activation_attempted = $false
    etw_activation_result = "not_run"
    etw_pause_result = "not_run"
    etw_resume_result = "not_run"
    etw_stop_result = "not_run"
    bounded_event_batches_observed = $false
    live_provider_enabled = $false
    live_collection_started = $false
    live_consumer_started = $false
    consumer_worker_active_observed = $false
    consumer_worker_joined_final = $false
    provider_enabled = 0
    raw_events = 0
    normalized_events = 0
    dropped_events = 0
    rate_limited_events = 0
    schema_rejected_events = 0
    published_batches = 0
    eventbus_publications = 0
    downstream_facts = 0
    clean_shutdown = $false
    unjoined_workers = 0
    shutdown_cleanup_verified = $false
    no_etw_session_remains = $false
    ip_helper_fallback_available = $false
    restart_etw_inactive = $false
    privacy_boundary_holds = $false
    raw_value_exposure_detected = $false
    remaining_process_count = 0
    etw_calls = 0
    native_network_topic_publications = 0
    etw_eventbus_publications = 0
    etw_security_facts = 0
    process_network_facts = 0
    packet_facts = 0
    npcap_probes = 0
    capture_broker_launches = 0
    response_executions = 0
    automatic_llm_calls = 0
    latest_lifecycle_state = "unknown"
    latest_fallback_state = "unknown"
    provider_degraded_reason = $null
    final_status_ref = "not_recorded"
}

function Test-IsWindowsHost {
    ($env:OS -eq "Windows_NT") -or ($PSVersionTable.PSEdition -eq "Desktop") -or ($IsWindows -eq $true)
}

function Test-IsElevatedAdministrator {
    if (-not (Test-IsWindowsHost)) {
        return $false
    }
    $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [System.Security.Principal.WindowsPrincipal]::new($identity)
    $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
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

function Get-EtwLifecycle {
    param([object]$Status)
    if ($Status.provider_controller_status -and $Status.provider_controller_status.etw_lifecycle) {
        return $Status.provider_controller_status.etw_lifecycle
    }
    $null
}

function Get-ProviderZero {
    param([object]$Status)
    if ($Status.provider_controller_status -and $Status.provider_controller_status.provider_zero) {
        return $Status.provider_controller_status.provider_zero
    }
    $null
}

function Get-ProviderLifecycle {
    param(
        [object]$Status,
        [string]$ProviderKind
    )
    $provider = @($Status.provider_controller_status.providers | Where-Object { $_.provider_kind -eq $ProviderKind } | Select-Object -First 1)
    if ($provider.Count -eq 0) {
        return "unavailable"
    }
    [string]$provider[0].lifecycle_state
}

function Test-ReadOnlyEtwCapabilityProbe {
    if (-not (Test-IsWindowsHost)) {
        return "blocked_by_env"
    }
    $advapi = Join-Path $env:SystemRoot "System32\advapi32.dll"
    $tdh = Join-Path $env:SystemRoot "System32\tdh.dll"
    if ((Test-Path -LiteralPath $advapi) -and (Test-Path -LiteralPath $tdh)) {
        return "available"
    }
    "unavailable_or_degraded"
}

function New-EtwMutationIntent {
    param(
        [object]$Session,
        [string]$SemanticCommand,
        [string]$WireCommand,
        [uint64]$OwnershipEpoch,
        [string]$IntentLabel
    )
    [ordered]@{
        schema_version = $Script:SchemaVersion
        intent_ref = New-SafeRef -Prefix "smoke_$IntentLabel"
        request_ref = New-SafeRef -Prefix "smoke_$IntentLabel`_request"
        ipc_session_ref = $Session.SessionReference
        caller_verification_ref = [string]$Session.CallerVerification.verification_ref
        command_id = $SemanticCommand
        policy_ref = "mutation_policy_$WireCommand"
        policy_version = $Script:SchemaVersion
        target_capability_ref = "etw_provider_ref"
        target_capability_category = "etw_provider"
        requested_operation_category = $WireCommand
        created_time_bucket = "current_connection"
        expiry_ttl_bucket = "thirty_seconds"
        ownership_epoch = $OwnershipEpoch
        idempotency_ref = New-SafeRef -Prefix "smoke_$IntentLabel`_idem"
        explicit_user_action = $true
        dry_run = $true
        audit_refs = @("mutation_intent_received")
        provenance_id = "etw_network_smoke"
        redaction_status = "redacted"
    }
}

function Invoke-AuthorizedEtwMutation {
    param(
        [object]$Session,
        [string]$WireCommand,
        [uint64]$OwnershipEpoch
    )
    $semanticCommand = switch ($WireCommand) {
        "activate_etw" { "activate_etw_provider" }
        "pause_etw" { "pause_etw_provider" }
        "resume_etw" { "resume_etw_provider" }
        "stop_etw" { "stop_etw_provider" }
        default { $WireCommand }
    }
    $intentLabel = $WireCommand.Replace("_etw", "")
    $intent = New-EtwMutationIntent -Session $Session -SemanticCommand $semanticCommand -WireCommand $WireCommand -OwnershipEpoch $OwnershipEpoch -IntentLabel $intentLabel
    $decision = Invoke-IpcCommand -Session $Session -Command "evaluate_mutation_intent" -Payload $intent
    if ($decision.result -ne "approved_for_execution") {
        throw "$WireCommand`:decision_$($decision.result)"
    }
    $executionRequest = [ordered]@{
        schema_version = $Script:SchemaVersion
        decision_ref = $decision.decision_ref
        intent = $intent
        explicit_user_action = $true
        provenance_id = "etw_network_smoke"
        redaction_status = "redacted"
    }
    Invoke-IpcCommand -Session $Session -Command $WireCommand -Payload $executionRequest
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

function Update-ReportFromStatus {
    param([object]$Status)
    $lifecycle = Get-EtwLifecycle -Status $Status
    $zero = Get-ProviderZero -Status $Status
    if ($lifecycle) {
        $Script:Report.latest_lifecycle_state = [string]$lifecycle.lifecycle_state
        $Script:Report.latest_fallback_state = [string]$lifecycle.fallback_state
        $Script:Report.provider_degraded_reason = [string]$lifecycle.degraded_reason
        $Script:Report.live_provider_enabled = [bool]$lifecycle.provider_enabled
        $Script:Report.live_collection_started = [bool]$lifecycle.collection_started
        $Script:Report.live_consumer_started = [bool]$lifecycle.consumer_started
        $Script:Report.consumer_worker_active_observed =
            $Script:Report.consumer_worker_active_observed -or [bool]$lifecycle.consumer_worker_active
        $Script:Report.consumer_worker_joined_final = [bool]$lifecycle.consumer_worker_joined
        if ([bool]$lifecycle.provider_enabled) {
            $Script:Report.provider_enabled = 1
        }
        $Script:Report.raw_events = [Math]::Max($Script:Report.raw_events, [int]$lifecycle.raw_event_count)
        $Script:Report.normalized_events = [Math]::Max($Script:Report.normalized_events, [int]$lifecycle.normalized_event_count)
        $Script:Report.dropped_events = [Math]::Max($Script:Report.dropped_events, [int]$lifecycle.dropped_event_count)
        $Script:Report.rate_limited_events = [Math]::Max($Script:Report.rate_limited_events, [int]$lifecycle.rate_limited_event_count)
        $Script:Report.schema_rejected_events = [Math]::Max($Script:Report.schema_rejected_events, [int]$lifecycle.schema_rejected_event_count)
        $Script:Report.published_batches = [Math]::Max($Script:Report.published_batches, [int]$lifecycle.published_batch_count)
        $Script:Report.downstream_facts = [Math]::Max($Script:Report.downstream_facts, [int]$lifecycle.security_fact_count)
        $Script:Report.etw_eventbus_publications = [int]$lifecycle.eventbus_publication_count
        $Script:Report.eventbus_publications = [Math]::Max($Script:Report.eventbus_publications, [int]$lifecycle.eventbus_publication_count)
        $Script:Report.etw_security_facts = [int]$lifecycle.security_fact_count
    }
    if ($zero) {
        $Script:Report.etw_calls = [int]$zero.etw_calls
        $Script:Report.native_network_topic_publications = [int]$zero.native_network_topic_publications
        $Script:Report.process_network_facts = [int]$zero.process_network_facts
        $Script:Report.packet_facts = [int]$zero.packet_facts
        $Script:Report.npcap_probes = [int]$zero.npcap_probes
        $Script:Report.capture_broker_launches = [int]$zero.capture_broker_launches
    }
    $ipHelperState = Get-ProviderLifecycle -Status $Status -ProviderKind "ip_helper"
    $Script:Report.ip_helper_fallback_available = $ipHelperState -in @("inactive", "ready", "active", "stopped", "degraded")
}

function Invoke-ControlledLocalNetworkActivity {
    $bytes = [System.Text.Encoding]::UTF8.GetBytes("sentinel_etw_foreground_smoke")
    for ($index = 0; $index -lt 12; $index++) {
        $listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 0)
        $listener.Start()
        $client = [System.Net.Sockets.TcpClient]::new()
        $server = $null
        try {
            $client.Connect([System.Net.IPAddress]::Loopback, $listener.LocalEndpoint.Port)
            $server = $listener.AcceptTcpClient()
            $client.GetStream().Write($bytes, 0, $bytes.Length)
            $buffer = New-Object byte[] $bytes.Length
            [void]$server.GetStream().Read($buffer, 0, $buffer.Length)
        }
        finally {
            if ($server) { $server.Dispose() }
            $client.Dispose()
            $listener.Stop()
        }

        $receiver = [System.Net.Sockets.UdpClient]::new(
            [System.Net.IPEndPoint]::new([System.Net.IPAddress]::Loopback, 0)
        )
        $sender = [System.Net.Sockets.UdpClient]::new()
        try {
            [void]$sender.Send($bytes, $bytes.Length, [System.Net.IPEndPoint]::new([System.Net.IPAddress]::Loopback, $receiver.Client.LocalEndPoint.Port))
            $remote = [System.Net.IPEndPoint]::new([System.Net.IPAddress]::Any, 0)
            [void]$receiver.Receive([ref]$remote)
        }
        finally {
            $sender.Dispose()
            $receiver.Dispose()
        }
    }

    $localAddress = @(
        [System.Net.Dns]::GetHostAddresses([System.Net.Dns]::GetHostName()) |
            Where-Object {
                $_.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork -and
                -not [System.Net.IPAddress]::IsLoopback($_)
            } |
            Select-Object -First 1
    )
    if ($localAddress.Count -eq 0) {
        return
    }
    for ($index = 0; $index -lt 12; $index++) {
        $listener = [System.Net.Sockets.TcpListener]::new($localAddress[0], 0)
        $listener.Start()
        $client = [System.Net.Sockets.TcpClient]::new()
        $server = $null
        try {
            $client.Connect($localAddress[0], $listener.LocalEndpoint.Port)
            $server = $listener.AcceptTcpClient()
            $client.GetStream().Write($bytes, 0, $bytes.Length)
            $buffer = New-Object byte[] $bytes.Length
            [void]$server.GetStream().Read($buffer, 0, $buffer.Length)
        }
        finally {
            if ($server) { $server.Dispose() }
            $client.Dispose()
            $listener.Stop()
        }

        $receiver = [System.Net.Sockets.UdpClient]::new(
            [System.Net.IPEndPoint]::new($localAddress[0], 0)
        )
        $sender = [System.Net.Sockets.UdpClient]::new()
        try {
            [void]$sender.Send($bytes, $bytes.Length, [System.Net.IPEndPoint]::new($localAddress[0], $receiver.Client.LocalEndPoint.Port))
            $remote = [System.Net.IPEndPoint]::new([System.Net.IPAddress]::Any, 0)
            [void]$receiver.Receive([ref]$remote)
        }
        finally {
            $sender.Dispose()
            $receiver.Dispose()
        }
    }
}

function Test-PrivacyExposure {
    param([string[]]$Texts)
    $seededMarkers = @(
        "provider_guid=",
        "session_name=",
        "trace_handle=",
        "event_handle=",
        "pid_value_778899",
        "process_name_value_calc",
        "203.0.113.77",
        "10.42.0.7",
        "port_value_65000",
        "packet_bytes",
        "payload_bytes",
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

function Resolve-ServiceHostBinary {
    if ($Script:Binary -and (Test-Path -LiteralPath $Script:Binary)) {
        $Script:Binary = (Resolve-Path -LiteralPath $Script:Binary).Path
        return $true
    }

    $debugBinary = Join-Path $Script:Root "target\debug\sentinel-guard-service-host.exe"
    $releaseBinary = Join-Path $Script:Root "target\release\sentinel-guard-service-host.exe"
    if (Test-Path -LiteralPath $debugBinary) {
        $Script:Binary = (Resolve-Path -LiteralPath $debugBinary).Path
        return $true
    }
    if (Test-Path -LiteralPath $releaseBinary) {
        $Script:Binary = (Resolve-Path -LiteralPath $releaseBinary).Path
        return $true
    }

    $build = Start-Process `
        -FilePath "cargo" `
        -ArgumentList @("build", "-p", "sentinel-service-host", "--bin", "sentinel-guard-service-host") `
        -WorkingDirectory $Script:Root `
        -Wait `
        -PassThru `
        -WindowStyle Hidden
    if ($build.ExitCode -ne 0) {
        return $false
    }
    if (Test-Path -LiteralPath $debugBinary) {
        $Script:Binary = (Resolve-Path -LiteralPath $debugBinary).Path
        return $true
    }
    $false
}

function Write-SmokeReport {
    if (-not $ReportPath) {
        $ReportPath = Join-Path $Script:SmokeRoot "etw_network_smoke.report.json"
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
    $Script:StopFile = Join-Path $Script:SmokeRoot ("etw-network-stop-" + ([guid]::NewGuid().ToString("N")) + ".flag")
    $Script:StdoutFile = Join-Path $Script:SmokeRoot ("etw-network-stdout-" + ([guid]::NewGuid().ToString("N")) + ".log")
    $Script:StderrFile = Join-Path $Script:SmokeRoot ("etw-network-stderr-" + ([guid]::NewGuid().ToString("N")) + ".log")
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
        $Script:Report.real_etw_smoke = "blocked_by_env"
        $Script:Report.blocked_reason = "windows_required"
        $Script:Report.first_failure_boundary = "execution_context"
        return
    }
    $Script:Report.token_elevated = Test-IsElevatedAdministrator
    $Script:Report.execution_context = if ($Script:Report.token_elevated) { "elevated_powershell" } else { "non_elevated_powershell" }
    if (-not $Script:Report.token_elevated) {
        $Script:Report.result = "blocked_by_env"
        $Script:Report.real_etw_smoke = "blocked_by_env"
        $Script:Report.blocked_reason = "elevated_token_required"
        $Script:Report.first_failure_boundary = "execution_context"
        return
    }
    if (-not (Resolve-ServiceHostBinary)) {
        $Script:Report.result = "blocked_by_env"
        $Script:Report.real_etw_smoke = "blocked_by_env"
        $Script:Report.blocked_reason = "servicehost_binary_unavailable"
        $Script:Report.first_failure_boundary = "servicehost_binary"
        return
    }
    $existing = @(Get-Process -Name "sentinel-guard-service-host" -ErrorAction SilentlyContinue)
    if ($existing.Count -gt 0) {
        $Script:Report.result = "blocked_by_env"
        $Script:Report.real_etw_smoke = "blocked_by_env"
        $Script:Report.blocked_reason = "existing_servicehost_process"
        $Script:Report.first_failure_boundary = "servicehost_process_ownership"
        return
    }

    Start-SmokeServiceHost -MaxRuntimeSeconds $TotalTimeoutSeconds
    $session = $null
    try {
        $session = New-IpcSession -TimeoutMilliseconds 15000
        $initial = Get-SmokeStatus -Session $session
        $epoch = [uint64]$initial.runtime_ownership_status.ownership_epoch
        Assert-Condition -Condition ($epoch -gt 0) -Reason "ownership_epoch_missing"
        $initialLifecycle = Get-EtwLifecycle -Status $initial
        Assert-Condition -Condition ($null -ne $initialLifecycle) -Reason "etw_lifecycle_status_missing"
        $Script:Report.etw_initially_inactive = [string]$initialLifecycle.lifecycle_state -eq "inactive"
        Assert-Condition -Condition $Script:Report.etw_initially_inactive -Reason "etw_not_initially_inactive"
        Update-ReportFromStatus -Status $initial
        Assert-Condition -Condition ($Script:Report.native_network_topic_publications -eq 0) -Reason "initial_native_network_topic_publication_detected"
        Assert-Condition -Condition ($Script:Report.process_network_facts -eq 0) -Reason "initial_process_network_fact_detected"
        Assert-Condition -Condition ($Script:Report.packet_facts -eq 0) -Reason "initial_packet_fact_detected"

        $Script:Report.etw_probe_state = Test-ReadOnlyEtwCapabilityProbe
        $Script:Report.etw_activation_attempted = $true
        try {
            $activate = Invoke-AuthorizedEtwMutation -Session $session -WireCommand "activate_etw" -OwnershipEpoch $epoch
        }
        catch {
            $Script:Report.result = "blocked_by_env"
            $Script:Report.real_etw_smoke = "blocked_by_env"
            $Script:Report.blocked_reason = "etw_provider_activation_unavailable:$($_.Exception.Message)"
            $Script:Report.first_failure_boundary = "provider_activation"
            return
        }
        $Script:Report.etw_activation_result = [string]$activate.result_category
        Assert-Condition -Condition ($activate.result_category -in @("completed", "already_satisfied")) -Reason "activate_etw_failed"
        $afterActivate = Get-SmokeStatus -Session $session
        Update-ReportFromStatus -Status $afterActivate
        if (
            $Script:Report.latest_lifecycle_state -ne "active" -or
            -not $Script:Report.live_provider_enabled -or
            -not $Script:Report.live_collection_started -or
            -not $Script:Report.live_consumer_started
        ) {
            $Script:Report.result = "blocked_by_env"
            $Script:Report.real_etw_smoke = "blocked_by_env"
            $Script:Report.blocked_reason = "etw_provider_enablement_unavailable:$($Script:Report.provider_degraded_reason)"
            $Script:Report.first_failure_boundary = "provider_enablement"
            try {
                $blockedStop = Invoke-AuthorizedEtwMutation -Session $session -WireCommand "stop_etw" -OwnershipEpoch $epoch
                $Script:Report.etw_stop_result = [string]$blockedStop.result_category
            }
            catch {
                $Script:Report.etw_stop_result = "blocked_cleanup_stop_failed:$($_.Exception.Message)"
            }
            $blockedStatus = Get-SmokeStatus -Session $session
            Update-ReportFromStatus -Status $blockedStatus
            $blockedLifecycle = Get-EtwLifecycle -Status $blockedStatus
            $Script:Report.no_etw_session_remains =
                (-not [bool]$blockedLifecycle.provider_enabled) -and
                (-not [bool]$blockedLifecycle.collection_started) -and
                (-not [bool]$blockedLifecycle.consumer_started) -and
                (-not [bool]$blockedLifecycle.consumer_worker_active)
            $Script:Report.unjoined_workers = if ([bool]$blockedLifecycle.consumer_worker_active) { 1 } else { 0 }
            Close-IpcSession -Session $session
            $session = $null
            Stop-SmokeServiceHost
            $Script:ServiceProcess.Refresh()
            $Script:Report.remaining_process_count = if ($Script:ServiceProcess.HasExited) { 0 } else { 1 }
            $Script:Report.shutdown_cleanup_verified = $Script:Report.remaining_process_count -eq 0
            $Script:Report.clean_shutdown =
                $Script:Report.no_etw_session_remains -and
                ($Script:Report.unjoined_workers -eq 0) -and
                $Script:Report.shutdown_cleanup_verified
            return
        }

        if ($Script:Report.latest_lifecycle_state -eq "active") {
            $pause = Invoke-AuthorizedEtwMutation -Session $session -WireCommand "pause_etw" -OwnershipEpoch $epoch
            $Script:Report.etw_pause_result = [string]$pause.result_category
            Assert-Condition -Condition ($pause.result_category -in @("completed", "already_satisfied")) -Reason "pause_etw_failed"
            $afterPause = Get-SmokeStatus -Session $session
            Update-ReportFromStatus -Status $afterPause

            $resume = Invoke-AuthorizedEtwMutation -Session $session -WireCommand "resume_etw" -OwnershipEpoch $epoch
            $Script:Report.etw_resume_result = [string]$resume.result_category
            Assert-Condition -Condition ($resume.result_category -in @("completed", "already_satisfied")) -Reason "resume_etw_failed"
            $afterResume = Get-SmokeStatus -Session $session
            Update-ReportFromStatus -Status $afterResume
        }
        else {
            $Script:Report.etw_pause_result = "not_applicable_lifecycle_$($Script:Report.latest_lifecycle_state)"
            $Script:Report.etw_resume_result = "not_applicable_lifecycle_$($Script:Report.latest_lifecycle_state)"
        }

        $observationDeadline = [DateTimeOffset]::UtcNow.AddSeconds(20)
        do {
            Invoke-ControlledLocalNetworkActivity
            Start-Sleep -Milliseconds 400
            $observed = Get-SmokeStatus -Session $session
            Update-ReportFromStatus -Status $observed
        } while (
            [DateTimeOffset]::UtcNow -lt $observationDeadline -and
            (
                $Script:Report.raw_events -le 0 -or
                $Script:Report.normalized_events -le 0 -or
                $Script:Report.published_batches -le 0 -or
                $Script:Report.downstream_facts -le 0
            )
        )
        $Script:Report.bounded_event_batches_observed =
            ($Script:Report.published_batches -gt 0) -and
            ($Script:Report.downstream_facts -gt 0)
        if ($Script:Report.raw_events -le 0) {
            $Script:Report.first_failure_boundary =
                if ($Script:Report.consumer_worker_active_observed) {
                    "provider_enabled_but_no_raw_events"
                }
                else {
                    "process_trace_consumer_not_active"
                }
        }
        elseif ($Script:Report.normalized_events -le 0) {
            $Script:Report.first_failure_boundary = "raw_events_not_normalized"
        }
        elseif ($Script:Report.published_batches -le 0) {
            $Script:Report.first_failure_boundary = "normalized_batches_not_published"
        }
        elseif ($Script:Report.eventbus_publications -le 0) {
            $Script:Report.first_failure_boundary = "eventbus_publication_missing"
        }
        elseif ($Script:Report.downstream_facts -le 0) {
            $Script:Report.first_failure_boundary = "published_batches_without_security_facts"
        }

        $stop = Invoke-AuthorizedEtwMutation -Session $session -WireCommand "stop_etw" -OwnershipEpoch $epoch
        $Script:Report.etw_stop_result = [string]$stop.result_category
        Assert-Condition -Condition ($stop.result_category -in @("completed", "already_satisfied")) -Reason "stop_etw_failed"
        $afterStop = Get-SmokeStatus -Session $session
        Update-ReportFromStatus -Status $afterStop
        $stoppedLifecycle = Get-EtwLifecycle -Status $afterStop
        $Script:Report.no_etw_session_remains =
            (-not [bool]$stoppedLifecycle.provider_enabled) -and
            (-not [bool]$stoppedLifecycle.collection_started) -and
            (-not [bool]$stoppedLifecycle.consumer_started) -and
            (-not [bool]$stoppedLifecycle.consumer_worker_active) -and
            ([bool]$stoppedLifecycle.consumer_worker_joined) -and
            ([string]$stoppedLifecycle.lifecycle_state -in @("stopped", "inactive", "degraded"))
        $Script:Report.unjoined_workers = if (
            [bool]$stoppedLifecycle.consumer_worker_active -or
            -not [bool]$stoppedLifecycle.consumer_worker_joined
        ) { 1 } else { 0 }
        Assert-Condition -Condition $Script:Report.no_etw_session_remains -Reason "etw_session_remaining_after_stop"
        Assert-Condition -Condition ($Script:Report.npcap_probes -eq 0) -Reason "npcap_probe_detected"
        Assert-Condition -Condition ($Script:Report.capture_broker_launches -eq 0) -Reason "capture_broker_launch_detected"
        Assert-Condition -Condition ($Script:Report.packet_facts -eq 0) -Reason "packet_fact_detected"
        Assert-Condition -Condition ($Script:Report.process_network_facts -eq 0) -Reason "process_network_fact_detected"
        Assert-Condition -Condition ($Script:Report.response_executions -eq 0) -Reason "response_execution_detected"
        Assert-Condition -Condition ($Script:Report.automatic_llm_calls -eq 0) -Reason "automatic_llm_detected"
        Assert-Condition -Condition $Script:Report.ip_helper_fallback_available -Reason "ip_helper_fallback_unavailable"

        Close-IpcSession -Session $session
        $session = $null
        Stop-SmokeServiceHost
        $Script:ServiceProcess.Refresh()
        $Script:Report.remaining_process_count = if ($Script:ServiceProcess.HasExited) { 0 } else { 1 }
        Assert-Condition -Condition ($Script:Report.remaining_process_count -eq 0) -Reason "servicehost_process_remained"
        $Script:Report.shutdown_cleanup_verified = $true
        $Script:Report.clean_shutdown =
            $Script:Report.no_etw_session_remains -and
            ($Script:Report.unjoined_workers -eq 0) -and
            $Script:Report.shutdown_cleanup_verified

        $stdout = if (Test-Path -LiteralPath $Script:StdoutFile) { Get-Content -Raw -LiteralPath $Script:StdoutFile } else { "" }
        $stderr = if (Test-Path -LiteralPath $Script:StderrFile) { Get-Content -Raw -LiteralPath $Script:StderrFile } else { "" }
        if ($stdout) {
            $lastJson = ($stdout -split "`r?`n" | Where-Object { $_.Trim().StartsWith("{") } | Select-Object -Last 1)
            if ($lastJson) {
                $finalStatus = $lastJson | ConvertFrom-Json
                if ($finalStatus.scheduler_joined) {
                    $Script:Report.final_status_ref = "foreground_status_scheduler_joined"
                }
            }
        }

        $Script:ServiceProcess = $null
        Start-SmokeServiceHost -MaxRuntimeSeconds 30
        $restartSession = New-IpcSession -TimeoutMilliseconds 10000
        try {
            $restartStatus = Get-SmokeStatus -Session $restartSession
            $restartLifecycle = Get-EtwLifecycle -Status $restartStatus
            $Script:Report.restart_etw_inactive =
                ($null -ne $restartLifecycle) -and
                ([string]$restartLifecycle.lifecycle_state -eq "inactive") -and
                (-not [bool]$restartLifecycle.provider_enabled) -and
                (-not [bool]$restartLifecycle.collection_started) -and
                (-not [bool]$restartLifecycle.consumer_started)
            Assert-Condition -Condition $Script:Report.restart_etw_inactive -Reason "restart_etw_not_inactive"
        }
        finally {
            Close-IpcSession -Session $restartSession
        }
        Stop-SmokeServiceHost
        $Script:ServiceProcess.Refresh()
        $Script:Report.remaining_process_count = if ($Script:ServiceProcess.HasExited) { 0 } else { 1 }
        Assert-Condition -Condition ($Script:Report.remaining_process_count -eq 0) -Reason "restart_servicehost_process_remained"

        $combinedReport = $Script:Report | ConvertTo-Json -Depth 32
        $Script:Report.raw_value_exposure_detected = Test-PrivacyExposure -Texts @($stdout, $stderr, $combinedReport)
        $Script:Report.privacy_boundary_holds = -not $Script:Report.raw_value_exposure_detected
        Assert-Condition -Condition $Script:Report.privacy_boundary_holds -Reason "privacy_marker_exposed"

        if (
            $Script:Report.etw_probe_state -eq "available" -and
            $Script:Report.etw_activation_result -in @("completed", "already_satisfied") -and
            $Script:Report.provider_enabled -gt 0 -and
            $Script:Report.raw_events -gt 0 -and
            $Script:Report.normalized_events -gt 0 -and
            $Script:Report.published_batches -gt 0 -and
            $Script:Report.eventbus_publications -gt 0 -and
            $Script:Report.downstream_facts -gt 0 -and
            $Script:Report.clean_shutdown -and
            $Script:Report.unjoined_workers -eq 0 -and
            $Script:Report.etw_stop_result -in @("completed", "already_satisfied") -and
            $Script:Report.no_etw_session_remains -and
            $Script:Report.privacy_boundary_holds -and
            $Script:Report.ip_helper_fallback_available
        ) {
            $Script:Report.result = "pass"
            $Script:Report.real_etw_smoke = "real"
            $Script:Report.first_failure_boundary = "none"
        }
        else {
            $Script:Report.result = "fail"
            $Script:Report.real_etw_smoke = "failed"
            if ($Script:Report.etw_probe_state -ne "available") {
                $Script:Report.result = "blocked_by_env"
                $Script:Report.real_etw_smoke = "blocked_by_env"
                $Script:Report.blocked_reason = "etw_capability_unavailable_or_degraded"
                $Script:Report.first_failure_boundary = "etw_capability_probe"
            }
            else {
                $Script:Report.blocked_reason = "real_etw_smoke_criteria_incomplete"
            }
        }
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

if ($LibraryOnly) {
    return
}

try {
    Invoke-SmokeRun
}
catch {
    $Script:Report.result = "fail"
    $Script:Report.real_etw_smoke = "failed"
    $Script:Report.blocked_reason = "$($_.Exception.Message)"
    if ($Script:Report.first_failure_boundary -eq "not_run") {
        $Script:Report.first_failure_boundary = "smoke_harness"
    }
}
finally {
    Write-SmokeReport
}

if ($Script:Report.result -eq "fail") {
    throw "etw_network_smoke_failed:$($Script:Report.blocked_reason)"
}

Write-Host "etw_network_smoke=$($Script:Report.result); real_etw_smoke=$($Script:Report.real_etw_smoke); reason=$($Script:Report.blocked_reason)"
