[CmdletBinding()]
param(
    [switch]$ContinueOnFailure
)

$ErrorActionPreference = "Stop"

$Script:Root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$Script:Smokes = New-Object System.Collections.Generic.List[object]
$Script:Warnings = New-Object System.Collections.Generic.List[string]
$Script:StopRemaining = $false
$Script:RustMsvcReady = $true
$Script:RustMsvcError = $null
$Script:Environment = [ordered]@{
    os = [System.Environment]::OSVersion.VersionString
    rust_toolchain = "unknown"
    rustc_host = "unknown"
    msvc_linker = "not_checked"
    rust_lld = "not_checked"
    windows_sdk_kernel32_lib = "not_checked"
    vc_runtime_msvcrt_lib = "not_checked"
    linker_strategy = "not_checked"
    visual_studio_env_script = $null
}

Set-Location $Script:Root

function Get-IsoTimestamp {
    (Get-Date).ToUniversalTime().ToString("o")
}

function Test-IsWindowsHost {
    ($env:OS -eq "Windows_NT") -or ($PSVersionTable.PSEdition -eq "Desktop") -or ($IsWindows -eq $true)
}

function Test-IsAdministrator {
    if (-not (Test-IsWindowsHost)) {
        return $false
    }

    try {
        $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = [System.Security.Principal.WindowsPrincipal]::new($identity)
        return $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
    }
    catch {
        return $false
    }
}

function Skip-Smoke {
    param([string]$Message)

    throw "__SMOKE_SKIP__:$Message"
}

function Get-GitCommit {
    $previousErrorActionPreference = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    try {
        $output = & git -C $Script:Root rev-parse --short HEAD 2>$null
        if ($LASTEXITCODE -eq 0 -and $output) {
            return ($output | Select-Object -First 1).ToString().Trim()
        }
    }
    catch {
        return "unknown"
    }
    finally {
        $ErrorActionPreference = $previousErrorActionPreference
    }
    "unknown"
}

function Add-Warning {
    param([string]$Message)
    $Script:Warnings.Add($Message) | Out-Null
    Write-Host "  warning: $Message"
}

function Convert-NativeOutputLine {
    param([object]$Line)

    if ($Line -is [System.Management.Automation.ErrorRecord]) {
        return $Line.Exception.Message
    }

    $Line.ToString()
}

function Invoke-ProcessText {
    param(
        [string]$FilePath,
        [string[]]$Arguments = @(),
        [string]$WorkingDirectory = $Script:Root
    )

    Push-Location $WorkingDirectory
    try {
        $previousErrorActionPreference = $ErrorActionPreference
        $ErrorActionPreference = "Continue"
        try {
            $output = & $FilePath @Arguments 2>&1
            $exitCode = $LASTEXITCODE
        }
        catch {
            $output = @($_)
            $exitCode = 1
        }
        finally {
            $ErrorActionPreference = $previousErrorActionPreference
        }

        [pscustomobject]@{
            exit_code = $exitCode
            output = @($output | ForEach-Object { Convert-NativeOutputLine -Line $_ })
        }
    }
    finally {
        Pop-Location
    }
}

function Invoke-SmokeCommand {
    param(
        [string]$Label,
        [string]$FilePath,
        [string[]]$Arguments,
        [string]$WorkingDirectory = $Script:Root
    )

    Push-Location $WorkingDirectory
    try {
        Write-Host "  $Label> $FilePath $($Arguments -join ' ')"
        $previousErrorActionPreference = $ErrorActionPreference
        $ErrorActionPreference = "Continue"
        try {
            $output = & $FilePath @Arguments 2>&1
            $exitCode = $LASTEXITCODE
        }
        finally {
            $ErrorActionPreference = $previousErrorActionPreference
        }
        if ($exitCode -ne 0) {
            $text = ($output | ForEach-Object { Convert-NativeOutputLine -Line $_ }) -join [Environment]::NewLine
            if ($text.Length -gt 12000) {
                $text = $text.Substring($text.Length - 12000)
            }
            throw "$Label failed with exit code $exitCode`n$text"
        }
        return ($output | ForEach-Object { Convert-NativeOutputLine -Line $_ })
    }
    finally {
        Pop-Location
    }
}

function Test-MicrosoftLinker {
    param([string]$Path)

    if (-not $Path -or -not (Test-Path -LiteralPath $Path)) {
        return $false
    }

    $result = Invoke-ProcessText -FilePath $Path -Arguments @("/?")
    $text = ($result.output -join [Environment]::NewLine)
    $text -match "Microsoft.*Incremental Linker"
}

function Get-MicrosoftLinkerPath {
    $commands = @(Get-Command link.exe -ErrorAction SilentlyContinue)
    foreach ($command in $commands) {
        if (Test-MicrosoftLinker -Path $command.Source) {
            return $command.Source
        }
    }

    $roots = @(${env:ProgramFiles(x86)}, $env:ProgramFiles) | Where-Object { $_ }
    foreach ($root in $roots) {
        $vsRoot = Join-Path $root "Microsoft Visual Studio"
        if (-not (Test-Path -LiteralPath $vsRoot)) {
            continue
        }
        $candidate = Get-ChildItem -LiteralPath $vsRoot -Filter link.exe -Recurse -ErrorAction SilentlyContinue |
            Where-Object { $_.FullName -match "\\VC\\Tools\\MSVC\\" } |
            Select-Object -First 1
        if ($candidate -and (Test-MicrosoftLinker -Path $candidate.FullName)) {
            return $candidate.FullName
        }
    }

    $null
}

function Get-RustLldPath {
    $command = Get-Command rust-lld -ErrorAction SilentlyContinue
    if ($command) {
        return $command.Source
    }

    $sysroot = Invoke-ProcessText -FilePath "rustc" -Arguments @("--print", "sysroot")
    if ($sysroot.exit_code -ne 0 -or $sysroot.output.Count -lt 1) {
        return $null
    }

    $candidate = Join-Path ([string]$sysroot.output[0]) "lib\rustlib\x86_64-pc-windows-msvc\bin\rust-lld.exe"
    if (Test-Path -LiteralPath $candidate) {
        return $candidate
    }

    $null
}

function Find-LibraryFile {
    param(
        [string]$FileName,
        [string[]]$SearchRoots
    )

    $libPaths = @($env:LIB -split ";" | Where-Object { $_ })
    foreach ($path in $libPaths) {
        $candidate = Join-Path $path $FileName
        if (Test-Path -LiteralPath $candidate) {
            return $candidate
        }
    }

    foreach ($root in ($SearchRoots | Where-Object { $_ } | Select-Object -Unique)) {
        if (-not (Test-Path -LiteralPath $root)) {
            continue
        }
        $candidate = Get-ChildItem -LiteralPath $root -Filter $FileName -Recurse -ErrorAction SilentlyContinue |
            Where-Object { $_.FullName -match "\\x64\\" } |
            Select-Object -First 1
        if ($candidate) {
            return $candidate.FullName
        }
    }

    $null
}

function Enable-RustLldFallback {
    $rustLld = Get-RustLldPath
    if ($rustLld) {
        $Script:Environment.rust_lld = $rustLld
    }
    else {
        $Script:Environment.rust_lld = "missing"
        return $false
    }

    $windowsKitRoots = @(
        (Join-Path ${env:ProgramFiles(x86)} "Windows Kits"),
        (Join-Path $env:ProgramFiles "Windows Kits")
    )
    $visualStudioRoots = @(
        (Join-Path ${env:ProgramFiles(x86)} "Microsoft Visual Studio"),
        (Join-Path $env:ProgramFiles "Microsoft Visual Studio")
    )

    $kernel32 = Find-LibraryFile -FileName "kernel32.lib" -SearchRoots $windowsKitRoots
    $msvcrt = Find-LibraryFile -FileName "msvcrt.lib" -SearchRoots $visualStudioRoots

    $Script:Environment.windows_sdk_kernel32_lib = if ($kernel32) { $kernel32 } else { "missing" }
    $Script:Environment.vc_runtime_msvcrt_lib = if ($msvcrt) { $msvcrt } else { "missing" }

    if (-not $kernel32 -or -not $msvcrt) {
        return $false
    }

    $extraLibPaths = @(
        (Split-Path -Parent $kernel32),
        (Split-Path -Parent $msvcrt)
    ) | Select-Object -Unique
    $existingLib = @($env:LIB -split ";" | Where-Object { $_ })
    $env:LIB = @($existingLib + $extraLibPaths | Select-Object -Unique) -join ";"

    $existingRustFlags = @($env:RUSTFLAGS -split " " | Where-Object { $_ })
    if ($existingRustFlags -notcontains "-Clinker=$rustLld") {
        $env:RUSTFLAGS = @($existingRustFlags + "-Clinker=$rustLld") -join " "
    }

    $Script:Environment.linker_strategy = "rust-lld"
    Add-Warning "Using Rust bundled linker fallback: $rustLld."
    $true
}

function Get-VisualStudioEnvScript {
    $installPaths = @()
    $vswhere = Join-Path ${env:ProgramFiles(x86)} "Microsoft Visual Studio\Installer\vswhere.exe"
    if (Test-Path -LiteralPath $vswhere) {
        $result = Invoke-ProcessText `
            -FilePath $vswhere `
            -Arguments @("-latest", "-products", "*", "-requires", "Microsoft.VisualStudio.Component.VC.Tools.x86.x64", "-property", "installationPath")
        if ($result.exit_code -eq 0) {
            $installPaths += @($result.output | Where-Object { $_ } | Select-Object -First 1)
        }
    }

    $years = @("2022", "2019", "2017")
    $editions = @("BuildTools", "Community", "Professional", "Enterprise")
    foreach ($year in $years) {
        foreach ($edition in $editions) {
            $installPaths += (Join-Path ${env:ProgramFiles(x86)} "Microsoft Visual Studio\$year\$edition")
        }
    }

    foreach ($installPath in ($installPaths | Where-Object { $_ } | Select-Object -Unique)) {
        $scripts = @(
            (Join-Path $installPath "Common7\Tools\VsDevCmd.bat"),
            (Join-Path $installPath "VC\Auxiliary\Build\vcvars64.bat")
        )
        foreach ($script in $scripts) {
            if (Test-Path -LiteralPath $script) {
                return $script
            }
        }
    }

    $null
}

function Import-CmdEnvironment {
    param([string]$ScriptPath)

    if (-not (Test-Path -LiteralPath $ScriptPath)) {
        throw "Visual Studio environment script not found: $ScriptPath"
    }

    $leaf = Split-Path -Leaf $ScriptPath
    $arguments = if ($leaf -ieq "VsDevCmd.bat") {
        "`"$ScriptPath`" -arch=x64 -host_arch=x64 >nul && set"
    }
    else {
        "`"$ScriptPath`" >nul && set"
    }

    $result = Invoke-ProcessText -FilePath "cmd.exe" -Arguments @("/s", "/c", $arguments)
    if ($result.exit_code -ne 0) {
        $text = $result.output -join [Environment]::NewLine
        throw "Failed to import Visual Studio build environment from $ScriptPath`n$text"
    }

    foreach ($line in $result.output) {
        if ($line -match "^(.*?)=(.*)$") {
            [Environment]::SetEnvironmentVariable($matches[1], $matches[2], "Process")
        }
    }
}

function Initialize-RustMsvcToolchain {
    $toolchain = Invoke-ProcessText -FilePath "rustup" -Arguments @("show", "active-toolchain")
    if ($toolchain.exit_code -eq 0 -and $toolchain.output.Count -gt 0) {
        $Script:Environment.rust_toolchain = [string]$toolchain.output[0]
    }

    $rustc = Invoke-ProcessText -FilePath "rustc" -Arguments @("-vV")
    if ($rustc.exit_code -eq 0) {
        foreach ($line in $rustc.output) {
            if ($line -match "^host:\s*(.+)$") {
                $Script:Environment.rustc_host = $matches[1]
                break
            }
        }
    }

    if (-not (Test-IsWindowsHost) -or $Script:Environment.rustc_host -notmatch "windows-msvc") {
        $Script:Environment.msvc_linker = "not_required"
        $Script:RustMsvcReady = $true
        return
    }

    $linker = Get-MicrosoftLinkerPath
    if (-not $linker) {
        $envScript = Get-VisualStudioEnvScript
        if ($envScript) {
            Import-CmdEnvironment -ScriptPath $envScript
            $Script:Environment.visual_studio_env_script = $envScript
            $linker = Get-MicrosoftLinkerPath
            if ($linker) {
                Add-Warning "Imported Visual Studio build environment from $envScript."
            }
        }
    }

    if ($linker) {
        $Script:Environment.msvc_linker = $linker
        $Script:RustMsvcReady = $true
        $Script:Environment.linker_strategy = "msvc-link"
        return
    }

    $Script:Environment.msvc_linker = "missing"
    if (Enable-RustLldFallback) {
        $Script:RustMsvcReady = $true
        return
    }

    $Script:Environment.linker_strategy = "unavailable"
    $Script:RustMsvcReady = $false
    $Script:RustMsvcError = "MSVC Rust target '$($Script:Environment.rustc_host)' requires a Windows linker environment. Microsoft link.exe is unavailable, and the rust-lld fallback cannot resolve Windows SDK/VC import libraries. Install Visual Studio Build Tools 2017 or later with the C++ build tools workload and Windows SDK, or run this smoke from a Visual Studio Developer PowerShell."
    Add-Warning $Script:RustMsvcError
}

function Assert-RustMsvcToolchain {
    if (-not $Script:RustMsvcReady) {
        throw $Script:RustMsvcError
    }
}

function Add-SmokeResult {
    param(
        [string]$Name,
        [string]$Status,
        [long]$DurationMs,
        [string]$ErrorMessage = $null,
        [object]$Details = $null
    )

    $record = [ordered]@{
        name = $Name
        status = $Status
        duration_ms = $DurationMs
    }
    if ($ErrorMessage) {
        $record.error = $ErrorMessage
    }
    if ($null -ne $Details) {
        $record.details = $Details
    }
    $Script:Smokes.Add([pscustomobject]$record) | Out-Null
}

function Convert-SmokeJsonValue {
    param([object]$Value)

    if ($null -eq $Value) {
        return $null
    }

    if ($Value -is [string] -or $Value -is [bool] -or $Value -is [byte] -or $Value -is [int16] -or $Value -is [int] -or $Value -is [long] -or $Value -is [single] -or $Value -is [double] -or $Value -is [decimal]) {
        return $Value
    }

    if ($Value -is [System.Collections.IDictionary]) {
        $map = [ordered]@{}
        foreach ($key in $Value.Keys) {
            $map[[string]$key] = Convert-SmokeJsonValue -Value $Value[$key]
        }
        return $map
    }

    if ($Value -is [System.Collections.IEnumerable] -and -not ($Value -is [string])) {
        $items = @()
        foreach ($item in $Value) {
            $items += Convert-SmokeJsonValue -Value $item
        }
        return $items
    }

    $properties = @($Value.PSObject.Properties | Where-Object { $_.MemberType -in @("NoteProperty", "Property") })
    if ($properties.Count -gt 0) {
        $map = [ordered]@{}
        foreach ($property in $properties) {
            $map[$property.Name] = Convert-SmokeJsonValue -Value $property.Value
        }
        return $map
    }

    $Value.ToString()
}

function Get-SmokeReportRecords {
    foreach ($smoke in $Script:Smokes) {
        $record = [ordered]@{
            name = [string]$smoke.name
            status = [string]$smoke.status
            duration_ms = [long]$smoke.duration_ms
        }

        if ($smoke.PSObject.Properties.Name -contains "error") {
            $record.error = [string]$smoke.error
        }

        if ($smoke.PSObject.Properties.Name -contains "details") {
            $record.details = Convert-SmokeJsonValue -Value $smoke.details
        }

        [pscustomobject]$record
    }
}

function Invoke-Smoke {
    param(
        [string]$Name,
        [scriptblock]$Action
    )

    if ($Script:StopRemaining) {
        Write-Host "SKIP $Name"
        Add-SmokeResult `
            -Name $Name `
            -Status "skipped" `
            -DurationMs 0 `
            -ErrorMessage "Skipped after an earlier failure; rerun with -ContinueOnFailure for a full matrix."
        return
    }

    Write-Host "START $Name"
    $timer = [System.Diagnostics.Stopwatch]::StartNew()
    try {
        $details = & $Action
        $timer.Stop()
        Add-SmokeResult -Name $Name -Status "pass" -DurationMs $timer.ElapsedMilliseconds -Details $details
        Write-Host "PASS  $Name ($($timer.ElapsedMilliseconds) ms)"
    }
    catch {
        $timer.Stop()
        $message = $_.Exception.Message
        if ($message.StartsWith("__SMOKE_SKIP__:")) {
            $reason = $message.Substring("__SMOKE_SKIP__:".Length)
            Add-SmokeResult -Name $Name -Status "skipped" -DurationMs $timer.ElapsedMilliseconds -ErrorMessage $reason
            Write-Host "SKIP  $Name ($($timer.ElapsedMilliseconds) ms)"
            Write-Host $reason
            return
        }
        Add-SmokeResult -Name $Name -Status "fail" -DurationMs $timer.ElapsedMilliseconds -ErrorMessage $message
        Write-Host "FAIL  $Name ($($timer.ElapsedMilliseconds) ms)"
        Write-Host $message
        if (-not $ContinueOnFailure) {
            $Script:StopRemaining = $true
        }
    }
}

function Read-Exact {
    param(
        [System.IO.Stream]$Stream,
        [byte[]]$Buffer,
        [int]$Length
    )

    $offset = 0
    while ($offset -lt $Length) {
        $read = $Stream.Read($Buffer, $offset, $Length - $offset)
        if ($read -le 0) {
            throw "Named Pipe closed while reading IPC response."
        }
        $offset += $read
    }
}

function Invoke-ServicePipeCommand {
    param(
        [string]$Command,
        [hashtable]$Params
    )

    $pipe = [System.IO.Pipes.NamedPipeClientStream]::new(
        ".",
        "SentinelGuardIpc",
        [System.IO.Pipes.PipeDirection]::InOut,
        [System.IO.Pipes.PipeOptions]::None
    )
    try {
        $pipe.Connect(5000)
        $request = [ordered]@{
            id = [guid]::NewGuid().ToString()
            command = $Command
            params = $Params
            timestamp = Get-IsoTimestamp
        }
        $json = $request | ConvertTo-Json -Compress -Depth 24
        $payload = [System.Text.Encoding]::UTF8.GetBytes($json)
        $length = [System.BitConverter]::GetBytes([uint32]$payload.Length)
        $pipe.Write($length, 0, $length.Length)
        $pipe.Write($payload, 0, $payload.Length)
        $pipe.Flush()

        $lengthBuffer = New-Object byte[] 4
        Read-Exact -Stream $pipe -Buffer $lengthBuffer -Length 4
        $responseLength = [System.BitConverter]::ToUInt32($lengthBuffer, 0)
        if ($responseLength -gt (64 * 1024)) {
            throw "IPC response exceeded 64 KiB frame limit: $responseLength"
        }
        $responseBuffer = New-Object byte[] $responseLength
        Read-Exact -Stream $pipe -Buffer $responseBuffer -Length $responseLength
        $responseJson = [System.Text.Encoding]::UTF8.GetString($responseBuffer)
        return $responseJson | ConvertFrom-Json -Depth 24
    }
    finally {
        $pipe.Dispose()
    }
}

function Get-ExePath {
    param(
        [string]$Profile,
        [string]$Name
    )

    $fileName = if (Test-IsWindowsHost) { "$Name.exe" } else { $Name }
    Join-Path $Script:Root (Join-Path "target/$Profile" $fileName)
}

function Get-DirectorySizeBytes {
    param([string]$Path)

    if (-not (Test-Path -LiteralPath $Path)) {
        return 0L
    }
    $sum = Get-ChildItem -LiteralPath $Path -Recurse -File | Measure-Object -Property Length -Sum
    if ($null -eq $sum.Sum) {
        return 0L
    }
    [long]$sum.Sum
}

function Test-FrontendDist {
    $dist = Join-Path $Script:Root "frontend/dist"
    $index = Join-Path $dist "index.html"
    $assets = Join-Path $dist "assets"

    if (-not (Test-Path -LiteralPath $dist)) {
        throw "frontend/dist was not produced."
    }
    if (-not (Test-Path -LiteralPath $index)) {
        throw "frontend/dist/index.html was not produced."
    }
    if (-not (Test-Path -LiteralPath $assets)) {
        throw "frontend/dist/assets was not produced."
    }

    $jsBundles = @(Get-ChildItem -LiteralPath $assets -Filter "*.js" -File)
    if ($jsBundles.Count -lt 1) {
        throw "frontend/dist/assets does not contain a JavaScript bundle."
    }

    $sourceMaps = @(Get-ChildItem -LiteralPath $dist -Recurse -Filter "*.map" -File)
    if ($sourceMaps.Count -gt 0) {
        throw "Production frontend dist contains source maps: $($sourceMaps[0].FullName)"
    }

    $distFiles = @(Get-ChildItem -LiteralPath $dist -Recurse -File)
    $localhost = $distFiles | Select-String -SimpleMatch "localhost" -List
    if ($localhost) {
        throw "Production frontend dist contains localhost reference: $($localhost.Path)"
    }

    $sensitiveConsolePattern = "console\.error[^;]*(raw_packet|raw_payload|payload_blob|http_body|cookie|token|credential|api_key|private_key|authorization)"
    $sensitiveConsole = $distFiles | Select-String -Pattern $sensitiveConsolePattern -List
    if ($sensitiveConsole) {
        throw "Production frontend dist contains a sensitive console.error pattern: $($sensitiveConsole.Path)"
    }

    $genericConsoleError = @($distFiles | Select-String -Pattern "console\.error" -List)

    $sizeBytes = Get-DirectorySizeBytes -Path $dist
    if ($sizeBytes -gt 5MB) {
        Add-Warning "Frontend dist is larger than 5 MiB uncompressed: $sizeBytes bytes."
    }

    [pscustomobject]@{
        dist_size_bytes = $sizeBytes
        js_bundle_count = $jsBundles.Count
        source_map_count = $sourceMaps.Count
        generic_console_error_files = $genericConsoleError.Count
    }
}

function Test-TauriBinary {
    $binary = Get-ExePath -Profile "release" -Name "sentinel-guard-desktop"
    if (-not (Test-Path -LiteralPath $binary)) {
        throw "Tauri desktop binary not found: $binary"
    }
    $sizeBytes = (Get-Item -LiteralPath $binary).Length
    if ($sizeBytes -gt 100MB) {
        Add-Warning "Tauri desktop binary is larger than 100 MiB: $sizeBytes bytes."
    }

    $version = Invoke-ProcessText -FilePath $binary -Arguments @("--version")
    if ($version.exit_code -ne 0) {
        $text = $version.output -join [Environment]::NewLine
        throw "Tauri desktop binary --version failed with exit code $($version.exit_code)`n$text"
    }

    $help = Invoke-ProcessText -FilePath $binary -Arguments @("--help")
    if ($help.exit_code -ne 0) {
        $text = $help.output -join [Environment]::NewLine
        throw "Tauri desktop binary --help failed with exit code $($help.exit_code)`n$text"
    }

    [pscustomobject]@{
        binary = $binary
        binary_size_bytes = $sizeBytes
        version_exit_code = $version.exit_code
        help_exit_code = $help.exit_code
    }
}

function Remove-DirectoryWithinRoot {
    param(
        [string]$Path,
        [string]$AllowedRoot
    )

    if (-not (Test-Path -LiteralPath $Path)) {
        return
    }

    $root = (Resolve-Path -LiteralPath $AllowedRoot).Path
    $target = (Resolve-Path -LiteralPath $Path).Path
    if (-not $target.StartsWith($root, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "Refusing to remove directory outside release smoke root: $target"
    }

    Remove-Item -LiteralPath $Path -Recurse -Force
}

function Write-Utf8NoBomFile {
    param(
        [string]$Path,
        [string]$Content
    )

    $encoding = [System.Text.UTF8Encoding]::new($false)
    [System.IO.File]::WriteAllText($Path, $Content, $encoding)
}

function Wait-ForSessionStart {
    param(
        [string]$StdoutPath,
        [System.Diagnostics.Process]$Process,
        [int]$TimeoutSeconds = 45
    )

    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    while ((Get-Date) -lt $deadline) {
        if (Test-Path -LiteralPath $StdoutPath) {
            $text = Get-Content -LiteralPath $StdoutPath -Raw -ErrorAction SilentlyContinue
            if ($text -match "SESSION_START") {
                return $text
            }
        }

        if ($Process.HasExited) {
            throw "Desktop process exited before SESSION_START with code $($Process.ExitCode)."
        }

        Start-Sleep -Milliseconds 250
    }

    throw "Timed out waiting for SESSION_START in $StdoutPath."
}

function Stop-SmokeProcess {
    param([System.Diagnostics.Process]$Process)

    if ($null -eq $Process) {
        return
    }

    if (-not $Process.HasExited) {
        Stop-Process -Id $Process.Id -Force -ErrorAction SilentlyContinue
    }

    Wait-Process -Id $Process.Id -Timeout 5 -ErrorAction SilentlyContinue
}

function Start-PortableSmokeLaunch {
    param(
        [string]$Binary,
        [string]$PortableRoot,
        [string]$Label
    )

    $stdout = Join-Path $PortableRoot "release-smoke-portable-$Label-stdout.log"
    $stderr = Join-Path $PortableRoot "release-smoke-portable-$Label-stderr.log"
    foreach ($path in @($stdout, $stderr)) {
        if (Test-Path -LiteralPath $path) {
            Remove-Item -LiteralPath $path -Force
        }
    }

    $process = Start-Process `
        -FilePath $Binary `
        -ArgumentList @("--profile", "portable") `
        -WorkingDirectory $PortableRoot `
        -RedirectStandardOutput $stdout `
        -RedirectStandardError $stderr `
        -WindowStyle Hidden `
        -PassThru
    $text = Wait-ForSessionStart -StdoutPath $stdout -Process $process

    [pscustomobject]@{
        process = $process
        stdout = $stdout
        stderr = $stderr
        text = $text
    }
}

function Get-SessionStartLine {
    param([string]$Text)

    ($Text -split "`r?`n" | Where-Object { $_ -match "SESSION_START" } | Select-Object -First 1)
}

function Test-PortableAbandonedSessionCleanup {
    if (-not (Test-IsWindowsHost)) {
        throw "Portable Tauri startup smoke is Windows-only."
    }

    $binary = Get-ExePath -Profile "release" -Name "sentinel-guard-desktop"
    if (-not (Test-Path -LiteralPath $binary)) {
        throw "Tauri desktop binary not found: $binary"
    }

    $portableRoot = Split-Path -Parent $binary
    $sessionsRoot = Join-Path $portableRoot "temp\sessions"
    $logsRoot = Join-Path $portableRoot "logs"
    $auditLog = Join-Path $logsRoot "audit.log"
    $processes = New-Object System.Collections.Generic.List[object]

    try {
        Remove-DirectoryWithinRoot -Path $sessionsRoot -AllowedRoot $portableRoot
        New-Item -ItemType Directory -Force -Path $sessionsRoot | Out-Null
        New-Item -ItemType Directory -Force -Path $logsRoot | Out-Null
        if (Test-Path -LiteralPath $auditLog) {
            Remove-Item -LiteralPath $auditLog -Force
        }

        $initialAbandonedId = [guid]::NewGuid().ToString()
        $abandonedRoot = Join-Path $sessionsRoot $initialAbandonedId
        New-Item -ItemType Directory -Force -Path $abandonedRoot | Out-Null
        $marker = [ordered]@{
            marker = "SENTINEL_GUARD_SESSION"
            version = 1
            session_id = $initialAbandonedId
            created_at = Get-IsoTimestamp
            app_version = "release-smoke"
            session_mode = "portable-no-retention"
        }
        Write-Utf8NoBomFile `
            -Path (Join-Path $abandonedRoot ".sentinel_session") `
            -Content ($marker | ConvertTo-Json -Compress)
        Write-Utf8NoBomFile `
            -Path (Join-Path $abandonedRoot "session.db") `
            -Content "metadata-only-release-smoke"

        $unknownRoot = Join-Path $sessionsRoot "not-a-sentinel-session"
        New-Item -ItemType Directory -Force -Path $unknownRoot | Out-Null
        Write-Utf8NoBomFile `
            -Path (Join-Path $unknownRoot "note.txt") `
            -Content "must be skipped by release smoke"

        $first = Start-PortableSmokeLaunch -Binary $binary -PortableRoot $portableRoot -Label "first"
        $processes.Add($first.process) | Out-Null
        if ($first.text -notmatch "cleaned_abandoned=1") {
            throw "First portable launch did not report cleaned_abandoned=1.`n$($first.text)"
        }
        if ($first.text -notmatch "skipped_unknown=1") {
            throw "First portable launch did not report skipped_unknown=1.`n$($first.text)"
        }
        if (Test-Path -LiteralPath $abandonedRoot) {
            throw "Initial abandoned session still exists: $abandonedRoot"
        }
        if (-not (Test-Path -LiteralPath $unknownRoot)) {
            throw "Unknown session entry was deleted: $unknownRoot"
        }
        if (-not (Test-Path -LiteralPath $auditLog)) {
            throw "Portable cleanup audit log was not written: $auditLog"
        }
        $auditText = Get-Content -LiteralPath $auditLog -Raw
        if ($auditText -notmatch "abandoned_session_cleaned" -or $auditText -notmatch [regex]::Escape($initialAbandonedId)) {
            throw "Portable cleanup audit did not record the staged abandoned session."
        }

        $firstLiveDirs = @(Get-ChildItem -LiteralPath $sessionsRoot -Directory | Where-Object { $_.Name -ne "not-a-sentinel-session" })
        if ($firstLiveDirs.Count -ne 1) {
            throw "Expected one live session after first portable launch, found $($firstLiveDirs.Count)."
        }
        $firstLiveId = $firstLiveDirs[0].Name
        Stop-SmokeProcess -Process $first.process

        $second = Start-PortableSmokeLaunch -Binary $binary -PortableRoot $portableRoot -Label "second"
        $processes.Add($second.process) | Out-Null
        if ($second.text -notmatch "cleaned_abandoned=1") {
            throw "Second portable launch did not clean the crash-left session.`n$($second.text)"
        }
        if ($second.text -notmatch "skipped_unknown=1") {
            throw "Second portable launch did not preserve skipped unknown count.`n$($second.text)"
        }
        $firstLiveRoot = Join-Path $sessionsRoot $firstLiveId
        if (Test-Path -LiteralPath $firstLiveRoot) {
            throw "Crash-left portable session was not cleaned on second startup: $firstLiveRoot"
        }
        $auditText = Get-Content -LiteralPath $auditLog -Raw
        if ($auditText -notmatch [regex]::Escape($firstLiveId)) {
            throw "Portable cleanup audit did not record the crash-left session cleanup."
        }

        [pscustomobject]@{
            binary = $binary
            initial_abandoned_cleaned = $initialAbandonedId
            crash_left_session_cleaned = $firstLiveId
            unknown_entry_preserved = (Test-Path -LiteralPath $unknownRoot)
            first_session_start = Get-SessionStartLine -Text $first.text
            second_session_start = Get-SessionStartLine -Text $second.text
            audit_log = $auditLog
        }
    }
    finally {
        foreach ($process in $processes) {
            Stop-SmokeProcess -Process $process
        }
        Remove-DirectoryWithinRoot -Path $sessionsRoot -AllowedRoot $portableRoot
    }
}

function Test-ServiceStandalone {
    if (-not (Test-IsWindowsHost)) {
        Skip-Smoke "Service Named Pipe smoke is Windows-only."
    }

    if (-not (Test-IsAdministrator)) {
        Skip-Smoke "Standalone service IPC smoke requires an elevated/admin PowerShell session because the Named Pipe ACL may reject a standard user."
    }

    $binary = Get-ExePath -Profile "debug" -Name "sentinel-guard-elevated"
    if (-not (Test-Path -LiteralPath $binary)) {
        throw "Elevated service binary not found: $binary"
    }

    $process = $null
    try {
        $process = Start-Process `
            -FilePath $binary `
            -ArgumentList "--standalone" `
            -PassThru `
            -WindowStyle Hidden
        Start-Sleep -Milliseconds 750

        $ping = Invoke-ServicePipeCommand -Command "ping" -Params @{ nonce = "release-smoke-nonce" }
        if ($ping.error -ne $null) {
            throw "Service ping returned error: $($ping.error.code)"
        }
        if ($ping.result.nonce -ne "release-smoke-nonce") {
            throw "Service ping did not echo nonce."
        }
        if (-not $ping.result.version) {
            throw "Service ping did not return version."
        }
        if ([double]$ping.result.uptime_ms -le 0) {
            throw "Service ping uptime was not positive."
        }

        $status = Invoke-ServicePipeCommand -Command "status" -Params @{}
        if ($status.error -ne $null -or $status.result.service_status -ne "running") {
            throw "Service status response was not running."
        }

        $capture = Invoke-ServicePipeCommand -Command "capture_health" -Params @{}
        if ($capture.error -ne $null -or $null -eq $capture.result.capture_active) {
            throw "Service capture_health response was invalid."
        }

        $processes = Invoke-ServicePipeCommand -Command "process_snapshot" -Params @{}
        if ($processes.error -ne $null -or $null -eq $processes.result.processes) {
            throw "Service process_snapshot response was invalid."
        }

        $unknown = Invoke-ServicePipeCommand -Command "start_capture" -Params @{}
        if ($unknown.error.code -ne "COMMAND_NOT_ALLOWED") {
            throw "Unknown command did not return COMMAND_NOT_ALLOWED."
        }

        [pscustomobject]@{
            binary = $binary
            service_pid = $process.Id
            ping_version = $ping.result.version
            process_count = @($processes.result.processes).Count
        }
    }
    finally {
        if ($null -ne $process -and -not $process.HasExited) {
            Stop-Process -Id $process.Id -Force
            Wait-Process -Id $process.Id -Timeout 5 -ErrorAction SilentlyContinue
        }
    }
}

Initialize-RustMsvcToolchain

Invoke-Smoke "rust_fmt" {
    $null = Invoke-SmokeCommand -Label "rust_fmt" -FilePath "cargo" -Arguments @("fmt", "--", "--check")
}

Invoke-Smoke "rust_check" {
    Assert-RustMsvcToolchain
    $null = Invoke-SmokeCommand -Label "rust_check" -FilePath "cargo" -Arguments @("check", "--workspace")
}

Invoke-Smoke "rust_test" {
    Assert-RustMsvcToolchain
    $null = Invoke-SmokeCommand -Label "rust_test" -FilePath "cargo" -Arguments @("test", "--workspace")
}

Invoke-Smoke "rust_clippy" {
    Assert-RustMsvcToolchain
    $null = Invoke-SmokeCommand -Label "rust_clippy" -FilePath "cargo" -Arguments @("clippy", "--workspace", "--all-targets", "--all-features", "--", "-D", "warnings")
}

Invoke-Smoke "frontend_typecheck" {
    $null = Invoke-SmokeCommand -Label "frontend_typecheck" -FilePath "corepack" -Arguments @("pnpm", "typecheck") -WorkingDirectory (Join-Path $Script:Root "frontend")
}

Invoke-Smoke "frontend_test" {
    $null = Invoke-SmokeCommand -Label "frontend_test" -FilePath "corepack" -Arguments @("pnpm", "test") -WorkingDirectory (Join-Path $Script:Root "frontend")
}

Invoke-Smoke "frontend_build" {
    $null = Invoke-SmokeCommand -Label "frontend_build" -FilePath "corepack" -Arguments @("pnpm", "build") -WorkingDirectory (Join-Path $Script:Root "frontend")
    Test-FrontendDist
}

Invoke-Smoke "tauri_build" {
    Assert-RustMsvcToolchain
    $null = Invoke-SmokeCommand -Label "tauri_build" -FilePath "cargo" -Arguments @("build", "-p", "sentinel-guard-desktop", "--release")
    Test-TauriBinary
}

Invoke-Smoke "native_portable_import_ui" {
    Assert-RustMsvcToolchain
    $powerShellHost = (Get-Process -Id $PID).Path
    $nativeSmoke = Invoke-SmokeCommand -Label "native_demo_smoke" -FilePath $powerShellHost -Arguments @(
        "-NoProfile",
        "-ExecutionPolicy",
        "Bypass",
        "-File",
        (Join-Path $Script:Root "scripts/native_demo_smoke.ps1"),
        "-Binary",
        (Get-ExePath -Profile "release" -Name "sentinel-guard-desktop")
    )
    (($nativeSmoke -join [Environment]::NewLine) | ConvertFrom-Json)
}

Invoke-Smoke "portable_abandoned_cleanup" {
    Assert-RustMsvcToolchain
    Test-PortableAbandonedSessionCleanup
}

Invoke-Smoke "portable_import_traceability" {
    Assert-RustMsvcToolchain
    $null = Invoke-SmokeCommand -Label "portable_import_app_core" -FilePath "cargo" -Arguments @(
        "test",
        "-p",
        "sentinel-app-core",
        "portable_import_reaches_risk_and_report_traceability_path",
        "--lib"
    )
    $null = Invoke-SmokeCommand -Label "portable_import_desktop" -FilePath "cargo" -Arguments @(
        "test",
        "-p",
        "sentinel-guard-desktop",
        "desktop_portable_capture_import_smoke_covers_har_jsonl_traceability_and_cleanup",
        "--lib"
    )
    [pscustomobject]@{
        formats = @("har", "jsonl")
        preview_confirm_ingest = $true
        network_risk_report_export_traceability = $true
        no_raw_retention = $true
        zero_leftover_session_import_temp_artifacts = $true
    }
}

Invoke-Smoke "db_bootstrap" {
    Assert-RustMsvcToolchain
    $null = Invoke-SmokeCommand -Label "db_bootstrap" -FilePath "cargo" -Arguments @("test", "-p", "sentinel-storage", "runtime::tests", "--lib")
}

Invoke-Smoke "service_stub" {
    Assert-RustMsvcToolchain
    $null = Invoke-SmokeCommand -Label "service_build" -FilePath "cargo" -Arguments @("build", "-p", "sentinel-guard-elevated")
    $null = Invoke-SmokeCommand -Label "service_ipc_unit" -FilePath "cargo" -Arguments @("test", "-p", "sentinel-guard-elevated", "runtime_ipc::tests", "--lib")
    Test-ServiceStandalone
}

Invoke-Smoke "fixture_e2e" {
    Assert-RustMsvcToolchain
    $null = Invoke-SmokeCommand -Label "fixture_story" -FilePath "cargo" -Arguments @("test", "-p", "sentinel-app-core", "default_fixture_replays_full_safe_story", "--lib")
    $null = Invoke-SmokeCommand -Label "vertical_slice" -FilePath "cargo" -Arguments @("test", "-p", "sentinel-app-core", "vertical_slice_report_proves_required_task_500_slices", "--lib")
}

$passed = @($Script:Smokes | Where-Object { $_.status -eq "pass" }).Count
$failed = @($Script:Smokes | Where-Object { $_.status -eq "fail" }).Count
$skipped = @($Script:Smokes | Where-Object { $_.status -eq "skipped" }).Count
$overall = if ($failed -eq 0) { "pass" } else { "fail" }
$smokeRecords = @(Get-SmokeReportRecords)
$warningRecords = @($Script:Warnings | ForEach-Object { [string]$_ })

$report = [ordered]@{
    timestamp = Get-IsoTimestamp
    git_commit = Get-GitCommit
    environment = Convert-SmokeJsonValue -Value $Script:Environment
    smokes = $smokeRecords
    summary = [ordered]@{
        total = $Script:Smokes.Count
        passed = $passed
        failed = $failed
        skipped = $skipped
    }
    warnings = $warningRecords
    overall = $overall
}

$reportPath = Join-Path $Script:Root "smoke_report.json"
$report | ConvertTo-Json -Depth 32 | Set-Content -LiteralPath $reportPath -Encoding UTF8
Write-Host "WROTE $reportPath"
Write-Host "OVERALL $overall (pass=$passed fail=$failed skipped=$skipped)"

if ($overall -eq "pass") {
    exit 0
}
exit 1
