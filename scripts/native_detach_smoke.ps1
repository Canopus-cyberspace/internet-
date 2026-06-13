[CmdletBinding()]
param(
    [string]$Binary = "",
    [int]$TimeoutSeconds = 45
)

$ErrorActionPreference = "Stop"

$Root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
if (-not $Binary) {
    $Binary = Join-Path $Root "target\debug\sentinel-guard-desktop.exe"
}

function Test-IsWindowsHost {
    ($env:OS -eq "Windows_NT") -or ($PSVersionTable.PSEdition -eq "Desktop") -or ($IsWindows -eq $true)
}

function Get-SessionDirectoryCount {
    param([string]$SessionsRoot)

    if (-not (Test-Path -LiteralPath $SessionsRoot)) {
        return 0
    }

    @(
        Get-ChildItem -LiteralPath $SessionsRoot -Directory -ErrorAction SilentlyContinue
    ).Count
}

function Convert-NativeOutputLine {
    param([object]$Line)

    if ($Line -is [System.Management.Automation.ErrorRecord]) {
        return $Line.Exception.Message
    }

    $Line.ToString()
}

function Stop-NativeSmokeProcess {
    param([System.Diagnostics.Process]$Process)

    if ($null -eq $Process) {
        return
    }

    if (-not $Process.HasExited) {
        [void]$Process.CloseMainWindow()
        try {
            Wait-Process -Id $Process.Id -Timeout 10 -ErrorAction Stop
        }
        catch {
            Stop-Process -Id $Process.Id -Force -ErrorAction SilentlyContinue
            Wait-Process -Id $Process.Id -Timeout 5 -ErrorAction SilentlyContinue
        }
    }
}

if (-not (Test-IsWindowsHost)) {
    throw "skipped-windows-only: native Tauri detached-window smoke requires Windows WebView2."
}

$node = Get-Command node -ErrorAction SilentlyContinue
if (-not $node) {
    throw "blocked-by-env: node is required for WebView2 DevTools Protocol smoke automation."
}

$binaryPath = (Resolve-Path -LiteralPath $Binary).Path
$binaryDir = Split-Path -Parent $binaryPath
$sessionsRoot = Join-Path $binaryDir "temp\sessions"
$initialSessions = Get-SessionDirectoryCount -SessionsRoot $sessionsRoot

$port = Get-Random -Minimum 42000 -Maximum 60999
$previousWebViewArgs = $env:WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS
$webViewArgs = @(
    $previousWebViewArgs,
    "--remote-debugging-port=$port"
) | Where-Object { $_ } | Select-Object -Unique
$env:WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS = $webViewArgs -join " "

$nodeScript = Join-Path ([System.IO.Path]::GetTempPath()) "sentinel-native-detach-smoke-$port.mjs"
$nodeSource = @'
const port = Number(process.argv[2]);
const timeoutMs = Number(process.argv[3] ?? "45000");
const startedAt = Date.now();

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
const deadline = () => startedAt + timeoutMs;

function assertWebSocket() {
  if (typeof WebSocket === "undefined") {
    throw new Error("blocked-by-env: node global WebSocket is unavailable; use Node 22 or newer.");
  }
}

async function targets() {
  let lastError;
  while (Date.now() < deadline()) {
    try {
      const response = await fetch(`http://127.0.0.1:${port}/json/list`);
      if (response.ok) {
        return await response.json();
      }
      lastError = new Error(`CDP target list HTTP ${response.status}`);
    } catch (error) {
      lastError = error;
    }
    await sleep(250);
  }
  throw lastError ?? new Error("Timed out waiting for WebView2 DevTools target list.");
}

async function waitTarget(predicate, label) {
  while (Date.now() < deadline()) {
    const list = await targets();
    const target = list.find(predicate);
    if (target) {
      return target;
    }
    await sleep(250);
  }
  throw new Error(`Timed out waiting for target: ${label}`);
}

class CdpSession {
  constructor(webSocketDebuggerUrl) {
    this.webSocketDebuggerUrl = webSocketDebuggerUrl;
    this.nextId = 0;
    this.pending = new Map();
  }

  async open() {
    this.socket = new WebSocket(this.webSocketDebuggerUrl);
    this.socket.onmessage = (event) => {
      const message = JSON.parse(event.data);
      if (message.id && this.pending.has(message.id)) {
        const { resolve, reject } = this.pending.get(message.id);
        this.pending.delete(message.id);
        if (message.error) {
          reject(new Error(JSON.stringify(message.error)));
        } else {
          resolve(message.result);
        }
      }
    };
    await new Promise((resolve, reject) => {
      this.socket.onopen = resolve;
      this.socket.onerror = reject;
    });
    await this.send("Runtime.enable");
  }

  send(method, params = {}) {
    const id = ++this.nextId;
    this.socket.send(JSON.stringify({ id, method, params }));
    const timeout = Math.max(1000, Math.min(5000, deadline() - Date.now()));
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pending.delete(id);
        reject(new Error(`${method} timed out after ${timeout} ms`));
      }, timeout);
      this.pending.set(id, {
        resolve: (value) => {
          clearTimeout(timer);
          resolve(value);
        },
        reject: (error) => {
          clearTimeout(timer);
          reject(error);
        },
      });
    });
  }

  async eval(expression) {
    const result = await this.send("Runtime.evaluate", {
      expression,
      awaitPromise: true,
      returnByValue: true,
    });
    if (result.exceptionDetails) {
      throw new Error(JSON.stringify(result.exceptionDetails));
    }
    return result.result.value;
  }

  close() {
    this.socket?.close();
  }
}

async function connect(target) {
  const cdp = new CdpSession(target.webSocketDebuggerUrl);
  await cdp.open();
  return cdp;
}

async function waitEval(cdp, expression, label) {
  while (Date.now() < deadline()) {
    const value = await cdp.eval(expression);
    if (value) {
      return value;
    }
    await sleep(250);
  }
  throw new Error(`Timed out waiting for DOM state: ${label}`);
}

async function click(cdp, expression, label) {
  const clicked = await waitEval(cdp, expression, label);
  if (!clicked) {
    throw new Error(`Click failed: ${label}`);
  }
}

function textClickExpression(selector, text) {
  return `(() => {
    const match = [...document.querySelectorAll(${JSON.stringify(selector)})]
      .find((element) => (element.textContent || "").trim().includes(${JSON.stringify(text)}));
    if (!match) return false;
    match.dispatchEvent(new MouseEvent("pointerdown", { bubbles: true, cancelable: true, view: window }));
    match.dispatchEvent(new MouseEvent("mousedown", { bubbles: true, cancelable: true, view: window }));
    match.dispatchEvent(new MouseEvent("mouseup", { bubbles: true, cancelable: true, view: window }));
    match.click();
    return true;
  })()`;
}

function selectorClickExpression(selector) {
  return `(() => {
    const match = document.querySelector(${JSON.stringify(selector)});
    if (!match) return false;
    match.dispatchEvent(new MouseEvent("pointerdown", { bubbles: true, cancelable: true, view: window }));
    match.dispatchEvent(new MouseEvent("mousedown", { bubbles: true, cancelable: true, view: window }));
    match.dispatchEvent(new MouseEvent("mouseup", { bubbles: true, cancelable: true, view: window }));
    match.click();
    return true;
  })()`;
}

function childRoutePredicate(route) {
  return (target) =>
    typeof target.url === "string" &&
    isAppUrl(target.url) &&
    target.url.includes(route);
}

function isAppUrl(url) {
  return url.startsWith("http://tauri.localhost") || url.startsWith("http://localhost:1420");
}

async function verifySnapshot(target, pane) {
  const cdp = await connect(target);
  try {
    const text = await waitEval(
      cdp,
      `(() => {
        const text = document.body?.innerText || "";
        if (!text.includes("Selected entity snapshot")) return null;
        return text;
      })()`,
      `${pane} selected entity snapshot`,
    );
    const sensitivePattern = /(api_key|session_token|credential|private_key|raw_packet|payload|http_body|cookie|password|authorization)/i;
    if (sensitivePattern.test(text)) {
      throw new Error(`${pane} detached snapshot rendered a sensitive marker.`);
    }
    await Promise.race([
      cdp
        .eval(selectorClickExpression('button[title="Restore pane to main window"]'))
        .catch(() => false),
      sleep(750),
    ]);
    return {
      pane,
      title: target.title,
      url: target.url,
      has_snapshot: true,
      text_sample: text.replace(/\s+/g, " ").slice(0, 180),
    };
  } finally {
    cdp.close();
  }
}

async function main() {
  assertWebSocket();
    const mainTarget = await waitTarget(
      (target) =>
        typeof target.url === "string" &&
      isAppUrl(target.url) &&
      !target.url.includes("/detached/"),
    "main Sentinel Guard window",
  );
  const mainCdp = await connect(mainTarget);
  try {
    await waitEval(mainCdp, `document.readyState === "complete"`, "main document complete");
    await sleep(2000);
    await click(mainCdp, textClickExpression("a", "Investigation"), "Investigation sidebar nav");
    await waitEval(mainCdp, `location.pathname === "/investigation"`, "Investigation route");
    await waitEval(mainCdp, `document.querySelectorAll(".shell-table-row:not(.header)").length > 0`, "Investigation rows");
    await click(mainCdp, selectorClickExpression(".shell-table-row:not(.header)"), "first Investigation row");
    await click(mainCdp, selectorClickExpression('button[title="Detach inspector"]'), "Detach inspector");
    const inspector = await waitTarget(childRoutePredicate("/detached/inspector"), "detached inspector");
    await click(mainCdp, selectorClickExpression('button[title="Detach active evidence tab"]'), "Detach evidence");
    const evidence = await waitTarget(childRoutePredicate("/detached/evidence"), "detached evidence");
    await click(mainCdp, textClickExpression("button", "Timeline"), "Timeline drawer tab");
    await click(mainCdp, selectorClickExpression('button[title="Detach active timeline tab"]'), "Detach timeline");
    const timeline = await waitTarget(childRoutePredicate("/detached/timeline"), "detached timeline");

    const snapshots = [];
    snapshots.push(await verifySnapshot(inspector, "inspector"));
    snapshots.push(await verifySnapshot(evidence, "evidence"));
    snapshots.push(await verifySnapshot(timeline, "timeline"));

    console.log(JSON.stringify({
      status: "pass",
      main_url: mainTarget.url,
      child_windows: snapshots,
    }));
  } finally {
    mainCdp.close();
  }
}

main().catch((error) => {
  console.error(error?.stack ?? String(error));
  process.exit(1);
});
'@

$utf8NoBom = [System.Text.UTF8Encoding]::new($false)
[System.IO.File]::WriteAllText($nodeScript, $nodeSource, $utf8NoBom)

$process = $null
try {
    $process = Start-Process `
        -FilePath $binaryPath `
        -ArgumentList @("--profile", "portable") `
        -WorkingDirectory $binaryDir `
        -PassThru

    $previousErrorActionPreference = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    try {
        $nodeOutput = & $node.Source $nodeScript $port ($TimeoutSeconds * 1000) 2>&1
        $nodeExit = $LASTEXITCODE
    }
    finally {
        $ErrorActionPreference = $previousErrorActionPreference
    }
    $nodeText = ($nodeOutput | ForEach-Object { Convert-NativeOutputLine -Line $_ }) -join [Environment]::NewLine
    if ($nodeExit -ne 0) {
        throw "Native detached-window smoke failed with exit code $nodeExit`n$nodeText"
    }

    Stop-NativeSmokeProcess -Process $process
    $process = $null

    $remainingSessions = Get-SessionDirectoryCount -SessionsRoot $sessionsRoot
    if ($remainingSessions -ne 0) {
        throw "Portable session cleanup failed; found $remainingSessions session directories in $sessionsRoot."
    }

    $details = $nodeText | ConvertFrom-Json -Depth 24
    $details | Add-Member -NotePropertyName binary -NotePropertyValue $binaryPath
    $details | Add-Member -NotePropertyName remote_debugging_port -NotePropertyValue $port
    $details | Add-Member -NotePropertyName initial_portable_sessions -NotePropertyValue $initialSessions
    $details | Add-Member -NotePropertyName remaining_portable_sessions -NotePropertyValue $remainingSessions
    $details | ConvertTo-Json -Depth 24
}
finally {
    Stop-NativeSmokeProcess -Process $process
    $env:WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS = $previousWebViewArgs
    if (Test-Path -LiteralPath $nodeScript) {
        Remove-Item -LiteralPath $nodeScript -Force
    }
}
