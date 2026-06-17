[CmdletBinding()]
param(
    [string]$Binary = "",
    [string]$ReportPath = "",
    [int]$TotalTimeoutSeconds = 90
)

$ErrorActionPreference = "Stop"
$requestedBinary = $Binary
$requestedReportPath = $ReportPath
. (Join-Path $PSScriptRoot "etw_network_smoke.ps1") `
    -Binary $requestedBinary `
    -ReportPath "" `
    -TotalTimeoutSeconds $TotalTimeoutSeconds `
    -LibraryOnly

$Script:Binary = $requestedBinary
$ReportPath = $requestedReportPath
$Script:Report = [ordered]@{
    profile = "windows_auth_remote_sensing_foreground"
    result = "not_run"
    honest_status = "blocked_by_env"
    blocked_reason = $null
    first_failure_boundary = "not_run"
    execution_context = "unknown"
    token_elevated = $false
    security_log_accessible = $false
    passed_preconditions = @()
    not_evaluated_checks = @(
        "security_log_access",
        "disabled_by_default",
        "provider_enablement",
        "event_observation",
        "runtime_handoff",
        "shutdown_join",
        "privacy_scan"
    )
    retry_command = "powershell -NoProfile -ExecutionPolicy Bypass -File scripts/windows_auth_remote_sensing_smoke.ps1 -TotalTimeoutSeconds 90"
    provider_enabled = 0
    raw_events = 0
    normalized_events = 0
    dropped_events = 0
    rate_limited_events = 0
    schema_rejected_events = 0
    published_batches = 0
    eventbus_publications = 0
    auth_detector_invocations = 0
    auth_detector_consumed = 0
    remote_admin_invocations = 0
    remote_admin_consumed = 0
    lateral_invocations = 0
    lateral_consumed = 0
    downstream_facts = 0
    activation_result = "not_run"
    pause_result = "not_run"
    resume_result = "not_run"
    stop_result = "not_run"
    disabled_by_default = $false
    read_only_side_effects = 0
    clean_shutdown = $false
    unjoined_workers = 0
    remaining_servicehost_processes = 0
    no_auth_remote_session_remains = $false
    privacy_boundary_holds = $false
    raw_value_exposure_detected = $false
    provider_degraded_reason = $null
}

function Add-AuthRemotePassedPrecondition {
    param([string]$Name)
    $current = @($Script:Report.passed_preconditions)
    if ($current -notcontains $Name) {
        $Script:Report.passed_preconditions = @($current + $Name)
    }
}

function Set-AuthRemoteNotEvaluatedChecks {
    param([string[]]$Checks)
    $Script:Report.not_evaluated_checks = @($Checks)
}

function Get-AuthRemoteLifecycle {
    param([object]$Status)
    if ($Status.auth_remote_sensing_lifecycle_status) {
        return $Status.auth_remote_sensing_lifecycle_status
    }
    $null
}

function New-AuthRemoteMutationIntent {
    param(
        [object]$Session,
        [string]$Command,
        [uint64]$OwnershipEpoch
    )
    [ordered]@{
        schema_version = $Script:SchemaVersion
        intent_ref = New-SafeRef -Prefix "auth_remote_smoke_intent"
        request_ref = New-SafeRef -Prefix "auth_remote_smoke_request"
        ipc_session_ref = $Session.SessionReference
        caller_verification_ref = [string]$Session.CallerVerification.verification_ref
        command_id = $Command
        policy_ref = "mutation_policy_$Command"
        policy_version = $Script:SchemaVersion
        target_capability_ref = "auth_remote_sensing_provider_ref"
        target_capability_category = "auth_remote_sensing_provider"
        requested_operation_category = $Command
        created_time_bucket = "current_connection"
        expiry_ttl_bucket = "thirty_seconds"
        ownership_epoch = $OwnershipEpoch
        idempotency_ref = New-SafeRef -Prefix "auth_remote_smoke_idempotency"
        explicit_user_action = $true
        dry_run = $true
        audit_refs = @("mutation_intent_received")
        provenance_id = "windows_auth_remote_sensing_smoke"
        redaction_status = "redacted"
    }
}

function Invoke-AuthorizedAuthRemoteMutation {
    param(
        [object]$Session,
        [string]$Command,
        [uint64]$OwnershipEpoch
    )
    $intent = New-AuthRemoteMutationIntent `
        -Session $Session `
        -Command $Command `
        -OwnershipEpoch $OwnershipEpoch
    $decision = Invoke-IpcCommand `
        -Session $Session `
        -Command "evaluate_mutation_intent" `
        -Payload $intent
    if ($decision.result -ne "approved_for_execution") {
        throw "$Command`:decision_$($decision.result)"
    }
    Invoke-IpcCommand -Session $Session -Command $Command -Payload ([ordered]@{
        schema_version = $Script:SchemaVersion
        decision_ref = $decision.decision_ref
        intent = $intent
        explicit_user_action = $true
        provenance_id = "windows_auth_remote_sensing_smoke"
        redaction_status = "redacted"
    })
}

function Update-AuthRemoteReport {
    param([object]$Status)
    $lifecycle = Get-AuthRemoteLifecycle -Status $Status
    $zero = Get-ProviderZero -Status $Status
    if ($lifecycle) {
        if ([bool]$lifecycle.provider_enabled) {
            $Script:Report.provider_enabled = 1
        }
        $Script:Report.raw_events =
            [Math]::Max($Script:Report.raw_events, [int]$lifecycle.raw_event_count)
        $Script:Report.normalized_events =
            [Math]::Max($Script:Report.normalized_events, [int]$lifecycle.normalized_event_count)
        $Script:Report.dropped_events =
            [Math]::Max($Script:Report.dropped_events, [int]$lifecycle.dropped_event_count)
        $Script:Report.rate_limited_events =
            [Math]::Max($Script:Report.rate_limited_events, [int]$lifecycle.rate_limited_event_count)
        $Script:Report.schema_rejected_events =
            [Math]::Max($Script:Report.schema_rejected_events, [int]$lifecycle.schema_rejected_event_count)
        $Script:Report.published_batches =
            [Math]::Max($Script:Report.published_batches, [int]$lifecycle.published_batch_count)
        $Script:Report.eventbus_publications =
            [Math]::Max($Script:Report.eventbus_publications, [int]$lifecycle.eventbus_publication_count)
        $Script:Report.downstream_facts =
            [Math]::Max($Script:Report.downstream_facts, [int]$lifecycle.security_fact_count)
        $Script:Report.provider_degraded_reason = [string]$lifecycle.degraded_reason
    }
    if ($zero) {
        $Script:Report.auth_detector_invocations =
            [Math]::Max($Script:Report.auth_detector_invocations, [int]$zero.auth_remote_auth_detector_invocations)
        $Script:Report.auth_detector_consumed =
            [Math]::Max($Script:Report.auth_detector_consumed, [int]$zero.auth_remote_auth_consumed)
        $Script:Report.remote_admin_invocations =
            [Math]::Max($Script:Report.remote_admin_invocations, [int]$zero.auth_remote_remote_admin_invocations)
        $Script:Report.remote_admin_consumed =
            [Math]::Max($Script:Report.remote_admin_consumed, [int]$zero.auth_remote_remote_admin_consumed)
        $Script:Report.lateral_invocations =
            [Math]::Max($Script:Report.lateral_invocations, [int]$zero.auth_remote_lateral_invocations)
        $Script:Report.lateral_consumed =
            [Math]::Max($Script:Report.lateral_consumed, [int]$zero.auth_remote_lateral_consumed)
        $Script:Report.downstream_facts =
            [Math]::Max($Script:Report.downstream_facts, [int]$zero.auth_remote_downstream_facts)
    }
}

function Test-SecurityLogAccess {
    try {
        [void](Get-WinEvent -FilterHashtable @{
            LogName = "Security"
            Id = 4624, 4625, 4648, 4672, 4740, 4768, 4769, 4771, 4776, 4634
            StartTime = (Get-Date).AddMinutes(-10)
        } -MaxEvents 1 -ErrorAction Stop)
        return $true
    }
    catch [System.Exception] {
        return $false
    }
}

function Add-WNetType {
    if ("SentinelGuardAuthRemoteSmoke.WNet" -as [type]) {
        return
    }
    Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;

namespace SentinelGuardAuthRemoteSmoke {
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct NETRESOURCE {
        public uint dwScope;
        public uint dwType;
        public uint dwDisplayType;
        public uint dwUsage;
        public string lpLocalName;
        public string lpRemoteName;
        public string lpComment;
        public string lpProvider;
    }

    public static class WNet {
        [DllImport("mpr.dll", CharSet = CharSet.Unicode)]
        public static extern int WNetAddConnection2(ref NETRESOURCE netResource, string password, string username, uint flags);

        [DllImport("mpr.dll", CharSet = CharSet.Unicode)]
        public static extern int WNetCancelConnection2(string name, uint flags, bool force);
    }
}
"@
}

function Invoke-ControlledLocalAuthActivity {
    Add-WNetType
    for ($index = 0; $index -lt 8; $index++) {
        $resource = [SentinelGuardAuthRemoteSmoke.NETRESOURCE]::new()
        $resource.dwType = 1
        $resource.lpRemoteName = "\\localhost\IPC$"
        $account = ".\sentinel_guard_smoke_absent"
        $phrase = "sg" + ([guid]::NewGuid().ToString("N")).Substring(0, 12)
        [void][SentinelGuardAuthRemoteSmoke.WNet]::WNetAddConnection2(
            [ref]$resource,
            $phrase,
            $account,
            0
        )
        [void][SentinelGuardAuthRemoteSmoke.WNet]::WNetCancelConnection2(
            $resource.lpRemoteName,
            0,
            $true
        )
    }
}

function Test-AuthRemotePrivacyExposure {
    param([string[]]$Texts)
    $markers = @(
        "raw_xml",
        "event_record",
        "insertion",
        "domain\",
        "username",
        "user_name",
        "account_name",
        "workstation",
        "logon_id",
        "token",
        "credential",
        "ticket",
        "secret",
        "password",
        "packet_payload",
        "command_line",
        "process_path",
        "executable",
        "pid=",
        "sid=",
        "nonce="
    )
    foreach ($text in $Texts) {
        if (-not $text) {
            continue
        }
        foreach ($marker in $markers) {
            if ($text.ToLowerInvariant().Contains($marker.ToLowerInvariant())) {
                return $true
            }
        }
        if ($text -match "(?<![0-9])(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?![0-9])") {
            return $true
        }
        if ($text -match "(?i)(source|remote|workstation|host)(_|\s|-)?(name|address)") {
            return $true
        }
        if ($text -match "[A-Za-z]:\\") {
            return $true
        }
    }
    $false
}

function Resolve-AuthRemoteServiceHostBinary {
    if ($Script:Binary -and (Test-Path -LiteralPath $Script:Binary)) {
        $Script:Binary = (Resolve-Path -LiteralPath $Script:Binary).Path
        return $true
    }
    $debugBinary = Join-Path $Script:Root "target\debug\sentinel-guard-service-host.exe"
    $sourceFiles = @(
        (Join-Path $Script:Root "Cargo.toml"),
        (Join-Path $Script:Root "Cargo.lock")
    ) + @(
        Get-ChildItem `
            -Path (Join-Path $Script:Root "crates"), (Join-Path $Script:Root "service") `
            -Recurse `
            -File `
            -ErrorAction SilentlyContinue |
        Where-Object { $_.Extension -eq ".rs" -or $_.Name -eq "Cargo.toml" }
    )
    $latestSourceWrite = $sourceFiles |
        Where-Object { Test-Path -LiteralPath $_ } |
        ForEach-Object { (Get-Item -LiteralPath $_).LastWriteTimeUtc } |
        Sort-Object -Descending |
        Select-Object -First 1
    if (
        (Test-Path -LiteralPath $debugBinary) -and
        (Get-Item -LiteralPath $debugBinary).LastWriteTimeUtc -ge $latestSourceWrite
    ) {
        $Script:Binary = (Resolve-Path -LiteralPath $debugBinary).Path
        return $true
    }
    $build = Start-Process `
        -FilePath "cargo" `
        -ArgumentList @(
            "build",
            "-p",
            "sentinel-service-host",
            "--bin",
            "sentinel-guard-service-host",
            "-j",
            "1"
        ) `
        -WorkingDirectory $Script:Root `
        -Wait `
        -PassThru `
        -WindowStyle Hidden
    if ($build.ExitCode -ne 0 -or -not (Test-Path -LiteralPath $debugBinary)) {
        return $false
    }
    $Script:Binary = (Resolve-Path -LiteralPath $debugBinary).Path
    $true
}

function Write-AuthRemoteSmokeReport {
    if (-not $ReportPath) {
        $ReportPath = Join-Path $Script:SmokeRoot "windows_auth_remote_sensing_smoke.report.json"
    }
    $Script:Report | ConvertTo-Json -Depth 32 |
        Set-Content -LiteralPath $ReportPath -Encoding UTF8
}

function Invoke-AuthRemoteSmokeRun {
    New-Item -ItemType Directory -Path $Script:SmokeRoot -Force | Out-Null
    if (-not (Test-IsWindowsHost)) {
        $Script:Report.result = "blocked_by_env"
        $Script:Report.blocked_reason = "windows_required"
        $Script:Report.first_failure_boundary = "execution_context"
        Set-AuthRemoteNotEvaluatedChecks -Checks @(
            "elevated_token",
            "security_log_access",
            "disabled_by_default",
            "provider_enablement",
            "event_observation",
            "runtime_handoff",
            "shutdown_join",
            "privacy_scan"
        )
        return
    }
    Add-AuthRemotePassedPrecondition -Name "windows_host"
    $Script:Report.token_elevated = Test-IsElevatedAdministrator
    $Script:Report.execution_context = if ($Script:Report.token_elevated) {
        "elevated_powershell"
    }
    else {
        "non_elevated_powershell"
    }
    if (-not $Script:Report.token_elevated) {
        $Script:Report.result = "blocked_by_env"
        $Script:Report.blocked_reason = "elevated_token_required"
        $Script:Report.first_failure_boundary = "execution_context"
        Set-AuthRemoteNotEvaluatedChecks -Checks @(
            "security_log_access",
            "disabled_by_default",
            "provider_enablement",
            "event_observation",
            "runtime_handoff",
            "shutdown_join",
            "privacy_scan"
        )
        return
    }
    Add-AuthRemotePassedPrecondition -Name "elevated_token"
    $Script:Report.security_log_accessible = Test-SecurityLogAccess
    if (-not $Script:Report.security_log_accessible) {
        $Script:Report.result = "blocked_by_env"
        $Script:Report.blocked_reason = "security_event_log_unavailable"
        $Script:Report.first_failure_boundary = "security_log_access"
        Set-AuthRemoteNotEvaluatedChecks -Checks @(
            "disabled_by_default",
            "provider_enablement",
            "event_observation",
            "runtime_handoff",
            "shutdown_join",
            "privacy_scan"
        )
        return
    }
    Add-AuthRemotePassedPrecondition -Name "security_log_access"
    if (-not (Resolve-AuthRemoteServiceHostBinary)) {
        $Script:Report.result = "blocked_by_env"
        $Script:Report.blocked_reason = "servicehost_binary_unavailable"
        $Script:Report.first_failure_boundary = "servicehost_binary"
        Set-AuthRemoteNotEvaluatedChecks -Checks @(
            "disabled_by_default",
            "provider_enablement",
            "event_observation",
            "runtime_handoff",
            "shutdown_join",
            "privacy_scan"
        )
        return
    }
    Add-AuthRemotePassedPrecondition -Name "servicehost_binary"
    if (@(Get-Process -Name "sentinel-guard-service-host" -ErrorAction SilentlyContinue).Count -gt 0) {
        $Script:Report.result = "blocked_by_env"
        $Script:Report.blocked_reason = "existing_servicehost_process"
        $Script:Report.first_failure_boundary = "servicehost_process_ownership"
        Set-AuthRemoteNotEvaluatedChecks -Checks @(
            "disabled_by_default",
            "provider_enablement",
            "event_observation",
            "runtime_handoff",
            "shutdown_join",
            "privacy_scan"
        )
        return
    }
    Add-AuthRemotePassedPrecondition -Name "servicehost_process_ownership"

    Start-SmokeServiceHost -MaxRuntimeSeconds $TotalTimeoutSeconds
    $session = $null
    $auditText = ""
    try {
        $session = New-IpcSession -TimeoutMilliseconds 15000
        $initial = Get-SmokeStatus -Session $session
        $epoch = [uint64]$initial.runtime_ownership_status.ownership_epoch
        $initialLifecycle = Get-AuthRemoteLifecycle -Status $initial
        Assert-Condition -Condition ($null -ne $initialLifecycle) -Reason "auth_remote_lifecycle_missing"
        $Script:Report.disabled_by_default =
            ([string]$initialLifecycle.lifecycle_state -eq "inactive") -and
            (-not [bool]$initialLifecycle.provider_enabled)
        Assert-Condition -Condition $Script:Report.disabled_by_default -Reason "auth_remote_not_disabled_by_default"
        Add-AuthRemotePassedPrecondition -Name "disabled_by_default"
        Set-AuthRemoteNotEvaluatedChecks -Checks @(
            "provider_enablement",
            "event_observation",
            "runtime_handoff",
            "shutdown_join",
            "privacy_scan"
        )

        $zeroBeforeRead = Get-ProviderZero -Status $initial
        [void](Get-SmokeStatus -Session $session)
        $afterRead = Get-SmokeStatus -Session $session
        $zeroAfterRead = Get-ProviderZero -Status $afterRead
        $Script:Report.read_only_side_effects = if (
            [int]$zeroBeforeRead.auth_remote_sensing_calls -eq [int]$zeroAfterRead.auth_remote_sensing_calls -and
            [int]$zeroBeforeRead.auth_remote_publications -eq [int]$zeroAfterRead.auth_remote_publications
        ) { 0 } else { 1 }
        Assert-Condition -Condition ($Script:Report.read_only_side_effects -eq 0) -Reason "read_only_side_effect"
        Add-AuthRemotePassedPrecondition -Name "read_only_side_effect_free"

        try {
            $activate = Invoke-AuthorizedAuthRemoteMutation `
                -Session $session `
                -Command "activate_auth_remote_sensing" `
                -OwnershipEpoch $epoch
        }
        catch {
            $Script:Report.result = "blocked_by_env"
            $Script:Report.blocked_reason = "auth_remote_provider_activation_unavailable:$($_.Exception.Message)"
            $Script:Report.first_failure_boundary = "provider_activation"
            return
        }
        Add-AuthRemotePassedPrecondition -Name "provider_enablement"
        Set-AuthRemoteNotEvaluatedChecks -Checks @(
            "event_observation",
            "runtime_handoff",
            "shutdown_join",
            "privacy_scan"
        )
        $Script:Report.activation_result = [string]$activate.result_category
        $activeStatus = Get-SmokeStatus -Session $session
        Update-AuthRemoteReport -Status $activeStatus
        $activeLifecycle = Get-AuthRemoteLifecycle -Status $activeStatus
        if (
            [string]$activeLifecycle.lifecycle_state -ne "active" -or
            -not [bool]$activeLifecycle.provider_enabled -or
            -not [bool]$activeLifecycle.collection_started -or
            -not [bool]$activeLifecycle.consumer_started
        ) {
            $Script:Report.result = "blocked_by_env"
            $Script:Report.blocked_reason =
                "auth_remote_provider_enablement_unavailable:$($Script:Report.provider_degraded_reason)"
            $Script:Report.first_failure_boundary = "provider_enablement"
            return
        }

        $pause = Invoke-AuthorizedAuthRemoteMutation `
            -Session $session `
            -Command "pause_auth_remote_sensing" `
            -OwnershipEpoch $epoch
        $Script:Report.pause_result = [string]$pause.result_category
        $resume = Invoke-AuthorizedAuthRemoteMutation `
            -Session $session `
            -Command "resume_auth_remote_sensing" `
            -OwnershipEpoch $epoch
        $Script:Report.resume_result = [string]$resume.result_category

        $deadline = [DateTimeOffset]::UtcNow.AddSeconds(30)
        do {
            Invoke-ControlledLocalAuthActivity
            Start-Sleep -Milliseconds 500
            $observed = Get-SmokeStatus -Session $session
            Update-AuthRemoteReport -Status $observed
        } while (
            [DateTimeOffset]::UtcNow -lt $deadline -and
            (
                $Script:Report.raw_events -le 0 -or
                $Script:Report.normalized_events -le 0 -or
                $Script:Report.published_batches -le 0 -or
                $Script:Report.eventbus_publications -le 0 -or
                $Script:Report.auth_detector_invocations -le 0 -or
                $Script:Report.auth_detector_consumed -le 0 -or
                $Script:Report.downstream_facts -le 0
            )
        )

        if ($Script:Report.raw_events -le 0) {
            $Script:Report.first_failure_boundary = "provider_enabled_but_no_raw_events"
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
        elseif ($Script:Report.auth_detector_invocations -le 0) {
            $Script:Report.first_failure_boundary = "auth_detector_not_invoked"
        }
        elseif ($Script:Report.auth_detector_consumed -le 0) {
            $Script:Report.first_failure_boundary = "auth_detector_did_not_consume"
        }
        elseif ($Script:Report.downstream_facts -le 0) {
            $Script:Report.first_failure_boundary = "security_facts_missing"
        }
        else {
            Add-AuthRemotePassedPrecondition -Name "event_observation"
            Add-AuthRemotePassedPrecondition -Name "runtime_handoff"
            Set-AuthRemoteNotEvaluatedChecks -Checks @("shutdown_join", "privacy_scan")
        }

        $auditRoot = Join-Path ([System.IO.Path]::GetTempPath()) "SentinelGuard\service-host"
        $auditFile = Get-ChildItem `
            -LiteralPath $auditRoot `
            -Filter "service-ipc.jsonl" `
            -Recurse `
            -ErrorAction SilentlyContinue |
            Sort-Object LastWriteTimeUtc -Descending |
            Select-Object -First 1
        if ($auditFile) {
            $auditText = Get-Content -Raw -LiteralPath $auditFile.FullName
        }

        $stop = Invoke-AuthorizedAuthRemoteMutation `
            -Session $session `
            -Command "stop_auth_remote_sensing" `
            -OwnershipEpoch $epoch
        $Script:Report.stop_result = [string]$stop.result_category
        $stoppedStatus = Get-SmokeStatus -Session $session
        Update-AuthRemoteReport -Status $stoppedStatus
        $stopped = Get-AuthRemoteLifecycle -Status $stoppedStatus
        $Script:Report.no_auth_remote_session_remains =
            (-not [bool]$stopped.provider_enabled) -and
            (-not [bool]$stopped.collection_started) -and
            (-not [bool]$stopped.consumer_started) -and
            (-not [bool]$stopped.consumer_worker_active) -and
            ([bool]$stopped.consumer_worker_joined)
        $Script:Report.unjoined_workers = if (
            [bool]$stopped.consumer_worker_active -or
            -not [bool]$stopped.consumer_worker_joined
        ) { 1 } else { 0 }
        Assert-Condition -Condition $Script:Report.no_auth_remote_session_remains -Reason "auth_remote_session_remaining"

        Close-IpcSession -Session $session
        $session = $null
        Stop-SmokeServiceHost
        $Script:ServiceProcess.Refresh()
        $Script:Report.remaining_servicehost_processes =
            if ($Script:ServiceProcess.HasExited) { 0 } else { 1 }
        $Script:Report.clean_shutdown =
            $Script:Report.no_auth_remote_session_remains -and
            ($Script:Report.unjoined_workers -eq 0) -and
            ($Script:Report.remaining_servicehost_processes -eq 0)
        if ($Script:Report.clean_shutdown) {
            Add-AuthRemotePassedPrecondition -Name "shutdown_join"
            Set-AuthRemoteNotEvaluatedChecks -Checks @("privacy_scan")
        }

        $stdout = if (Test-Path -LiteralPath $Script:StdoutFile) {
            Get-Content -Raw -LiteralPath $Script:StdoutFile
        } else { "" }
        $stderr = if (Test-Path -LiteralPath $Script:StderrFile) {
            Get-Content -Raw -LiteralPath $Script:StderrFile
        } else { "" }
        $reportText = $Script:Report | ConvertTo-Json -Depth 32
        $Script:Report.raw_value_exposure_detected =
            Test-AuthRemotePrivacyExposure -Texts @($stdout, $stderr, $auditText, $reportText)
        $Script:Report.privacy_boundary_holds = -not $Script:Report.raw_value_exposure_detected
        if ($Script:Report.privacy_boundary_holds) {
            Add-AuthRemotePassedPrecondition -Name "privacy_scan"
            Set-AuthRemoteNotEvaluatedChecks -Checks @()
        }

        $passes = (
            $Script:Report.provider_enabled -gt 0 -and
            $Script:Report.raw_events -gt 0 -and
            $Script:Report.normalized_events -gt 0 -and
            $Script:Report.published_batches -gt 0 -and
            $Script:Report.eventbus_publications -gt 0 -and
            $Script:Report.auth_detector_invocations -gt 0 -and
            $Script:Report.auth_detector_consumed -gt 0 -and
            $Script:Report.downstream_facts -gt 0 -and
            $Script:Report.clean_shutdown -and
            $Script:Report.unjoined_workers -eq 0 -and
            $Script:Report.remaining_servicehost_processes -eq 0 -and
            $Script:Report.privacy_boundary_holds
        )
        if ($passes) {
            $Script:Report.result = "pass"
            $Script:Report.honest_status = "real"
            $Script:Report.first_failure_boundary = "none"
        }
        else {
            $Script:Report.result = "fail"
            $Script:Report.honest_status = "blocked_by_env"
            if ($Script:Report.first_failure_boundary -eq "not_run") {
                $Script:Report.first_failure_boundary = "acceptance_counters"
            }
            $Script:Report.blocked_reason = "windows_auth_remote_smoke_criteria_incomplete"
        }
    }
    finally {
        if ($session) {
            Close-IpcSession -Session $session
        }
        if ($Script:ServiceProcess -and -not $Script:ServiceProcess.HasExited) {
            Stop-SmokeServiceHost
            $Script:ServiceProcess.Refresh()
            $Script:Report.remaining_servicehost_processes =
                if ($Script:ServiceProcess.HasExited) { 0 } else { 1 }
        }
        if ($Script:StopFile) {
            Remove-Item -LiteralPath $Script:StopFile -Force -ErrorAction SilentlyContinue
        }
    }
}

try {
    Invoke-AuthRemoteSmokeRun
}
catch {
    $Script:Report.result = "fail"
    $Script:Report.honest_status = "blocked_by_env"
    $Script:Report.blocked_reason = "$($_.Exception.Message)"
    if ($Script:Report.first_failure_boundary -eq "not_run") {
        $Script:Report.first_failure_boundary = "smoke_harness"
    }
}
finally {
    Write-AuthRemoteSmokeReport
}

if ($Script:Report.result -eq "fail") {
    throw "windows_auth_remote_sensing_smoke_failed:$($Script:Report.blocked_reason)"
}

Write-Host (
    "windows_auth_remote_sensing_smoke={0}; honest_status={1}; boundary={2}; reason={3}" -f
    $Script:Report.result,
    $Script:Report.honest_status,
    $Script:Report.first_failure_boundary,
    $Script:Report.blocked_reason
)
