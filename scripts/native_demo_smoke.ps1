[CmdletBinding()]
param(
    [string]$Binary = "",
    [int]$TimeoutSeconds = 120
)

$ErrorActionPreference = "Stop"

$Root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$FrontendRoot = Join-Path $Root "frontend"
$TargetRoot = Join-Path $Root "target"
$DevUrl = "http://localhost:1420"
if (-not $Binary) {
    $Binary = Join-Path $TargetRoot "debug\sentinel-guard-desktop.exe"
}

function Test-IsWindowsHost {
    ($env:OS -eq "Windows_NT") -or ($PSVersionTable.PSEdition -eq "Desktop") -or ($IsWindows -eq $true)
}

function Test-HttpEndpoint {
    param([string]$Uri)

    try {
        $response = Invoke-WebRequest -UseBasicParsing -Uri $Uri -TimeoutSec 2
        return $response.StatusCode -ge 200 -and $response.StatusCode -lt 500
    }
    catch {
        return $false
    }
}

function Wait-HttpEndpoint {
    param(
        [string]$Uri,
        [int]$Seconds
    )

    $deadline = [DateTimeOffset]::UtcNow.AddSeconds($Seconds)
    while ([DateTimeOffset]::UtcNow -lt $deadline) {
        if (Test-HttpEndpoint -Uri $Uri) {
            return
        }
        Start-Sleep -Milliseconds 250
    }
    throw "blocked-by-env: timed out waiting for frontend dev server at $Uri."
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

function Get-CaptureImportPreviewArtifactCount {
    param([string]$SessionsRoot)

    if (-not (Test-Path -LiteralPath $SessionsRoot)) {
        return 0
    }

    @(
        Get-ChildItem -LiteralPath $SessionsRoot -Recurse -File -Filter "capture_import_preview-*.json" -ErrorAction SilentlyContinue
    ).Count
}

function Assert-NoForbiddenMarkers {
    param(
        [string]$Label,
        [string]$Text,
        [string[]]$Markers
    )

    if ([string]::IsNullOrEmpty($Text)) {
        return
    }

    foreach ($marker in ($Markers | Where-Object { $_ })) {
        if ($Text.Contains($marker)) {
            throw "$Label leaked forbidden marker: $marker"
        }
    }
}

function Convert-NativeOutputLine {
    param([object]$Line)

    if ($Line -is [System.Management.Automation.ErrorRecord]) {
        return $Line.Exception.Message
    }

    $Line.ToString()
}

function Stop-OwnedProcess {
    param([System.Diagnostics.Process]$Process)

    if ($null -eq $Process -or $Process.HasExited) {
        return
    }

    [void]$Process.CloseMainWindow()
    try {
        Wait-Process -Id $Process.Id -Timeout 10 -ErrorAction Stop
    }
    catch {
        Stop-Process -Id $Process.Id -Force -ErrorAction SilentlyContinue
        Wait-Process -Id $Process.Id -Timeout 5 -ErrorAction SilentlyContinue
    }
}

if (-not (Test-IsWindowsHost)) {
    throw "skipped-windows-only: native command-backed demo smoke requires Windows WebView2."
}

$node = Get-Command node -ErrorAction SilentlyContinue
if (-not $node) {
    throw "blocked-by-env: node is required for WebView2 DevTools Protocol smoke automation."
}

$viteScript = Join-Path $FrontendRoot "node_modules\vite\bin\vite.js"
if (-not (Test-Path -LiteralPath $viteScript)) {
    throw "blocked-by-env: frontend dependencies are unavailable; run corepack pnpm install before native demo smoke."
}

$cargo = Get-Command cargo -ErrorAction SilentlyContinue
if (-not $cargo) {
    throw "blocked-by-env: cargo is required for portable import native smoke coverage."
}

if (-not (Test-Path -LiteralPath $Binary)) {
    $previousErrorActionPreference = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    try {
        $buildOutput = & $cargo.Source build -p sentinel-guard-desktop 2>&1
        $buildExit = $LASTEXITCODE
    }
    finally {
        $ErrorActionPreference = $previousErrorActionPreference
    }
    if ($buildExit -ne 0) {
        $buildText = ($buildOutput | ForEach-Object { Convert-NativeOutputLine -Line $_ }) -join [Environment]::NewLine
        throw "blocked-by-env: desktop binary is unavailable at $Binary and debug build failed with exit code $buildExit`n$buildText"
    }
}
if (-not (Test-Path -LiteralPath $Binary)) {
    throw "blocked-by-env: desktop binary is unavailable at $Binary; build sentinel-guard-desktop before native demo smoke."
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

$nodeScript = Join-Path ([System.IO.Path]::GetTempPath()) "sentinel-native-demo-smoke-$port.mjs"
$stdoutPath = Join-Path $TargetRoot "native-demo-smoke-$port.stdout.log"
$stderrPath = Join-Path $TargetRoot "native-demo-smoke-$port.stderr.log"
$viteStdoutPath = Join-Path $TargetRoot "native-demo-smoke-$port.vite.stdout.log"
$viteStderrPath = Join-Path $TargetRoot "native-demo-smoke-$port.vite.stderr.log"
$fixtureRoot = Join-Path ([System.IO.Path]::GetTempPath()) "sentinel-native-import-fixtures-$port"
$harFixturePath = Join-Path $fixtureRoot "network.har"
$jsonlFixturePath = Join-Path $fixtureRoot "network.jsonl"
$nodeSource = @'
const port = Number(process.argv[2]);
const timeoutMs = Number(process.argv[3] ?? "90000");
const harPath = process.argv[4];
const jsonlPath = process.argv[5];
const startedAt = Date.now();

const splitFileName = (value) => String(value ?? "").split(/[\\/]/).pop() ?? String(value ?? "");
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
const deadline = () => startedAt + timeoutMs;
const forbiddenMarkers = [
  harPath,
  jsonlPath,
  harPath ? harPath.replace(/\\/g, "/") : "",
  jsonlPath ? jsonlPath.replace(/\\/g, "/") : "",
  splitFileName(harPath),
  splitFileName(jsonlPath),
  "access_token=secret",
  "session_token=shh",
  "token=abcdef1234567890",
  "uploader.example.test/upload/42",
  "uploader.example.test/upload/43",
  "uploader.example.test/upload/44",
  "uploader.example.test/upload/45",
  "jsonl.example.test/upload/9",
  "jsonl.example.test/upload/10",
  "C:/Users/Alice/Desktop",
  "Alice",
  "user=alice",
  "curl/8.8.0",
  "python-requests/2.32.0",
].filter(Boolean);

function assert(condition, message) {
  if (!condition) {
    throw new Error(message);
  }
}

function assertWebSocket() {
  if (typeof WebSocket === "undefined") {
    throw new Error("blocked-by-env: node global WebSocket is unavailable; use Node 22 or newer.");
  }
  if (!harPath || !jsonlPath) {
    throw new Error("blocked-by-env: native smoke fixture paths were not provided.");
  }
}

function assertNoForbiddenText(label, text) {
  const haystack = String(text ?? "");
  for (const marker of forbiddenMarkers) {
    assert(!haystack.includes(marker), `${label} leaked forbidden marker: ${marker}`);
  }
}

function numericValue(value, label) {
  const parsed = Number.parseInt(String(value ?? ""), 10);
  assert(Number.isFinite(parsed), `${label} was not numeric: ${value}`);
  return parsed;
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

function isAppUrl(url) {
  return url.startsWith("http://tauri.localhost") || url.startsWith("http://localhost:1420");
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
    const timeout = Math.max(5000, Math.min(30000, deadline() - Date.now()));
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

  async eval(expression, awaitPromise = true) {
    const result = await this.send("Runtime.evaluate", {
      expression,
      awaitPromise,
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

async function waitFor(check, label) {
  while (Date.now() < deadline()) {
    const value = await check();
    if (value) {
      return value;
    }
    await sleep(250);
  }
  throw new Error(`Timed out waiting for ${label}`);
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

function exactTextClickExpression(selector, text) {
  return `(() => {
    const match = [...document.querySelectorAll(${JSON.stringify(selector)})]
      .find((element) => (element.textContent || "").trim() === ${JSON.stringify(text)});
    if (!match) return false;
    match.dispatchEvent(new MouseEvent("pointerdown", { bubbles: true, cancelable: true, view: window }));
    match.dispatchEvent(new MouseEvent("mousedown", { bubbles: true, cancelable: true, view: window }));
    match.dispatchEvent(new MouseEvent("mouseup", { bubbles: true, cancelable: true, view: window }));
    match.click();
    return true;
  })()`;
}

function pageEvidenceExpression(page, selector, minimum, extra = "true") {
  return `(() => {
    if (location.pathname !== ${JSON.stringify(page)}) return null;
    const body = document.body?.textContent || "";
    const visibleBody = document.body?.innerText || "";
    const records = [...document.querySelectorAll(${JSON.stringify(selector)})];
    if (records.length < ${minimum}) return null;
    if (!(${extra})) return null;
    return {
      route: location.pathname,
      records: records.length,
      command_mentions: (visibleBody.match(/\\bcommand\\b/gi) || []).length,
      command_records: records.filter((record) => /command/i.test(record.textContent || "")).length,
      fallback_marker_visible: /\\b(MOCK_ONLY|STUB_ONLY|NOT_FOR_PRODUCTION|PRODUCT_STUB)\\b/i.test(visibleBody + "\\n" + body),
      record_text_samples: records.slice(0, 3).map((record) => (record.textContent || "").replace(/\\s+/g, " ").slice(0, 120)),
      text_sample: visibleBody.replace(/\\s+/g, " ").slice(0, 220),
    };
  })()`;
}

function assertCommandBackedPage(label, evidence, minimumCommandMentions = 1) {
  assert(evidence.records > 0, `${label} rendered no product records.`);
  assert(
    evidence.command_mentions + evidence.command_records >= minimumCommandMentions,
    `${label} did not expose command-backed source evidence.`,
  );
  assert(!evidence.fallback_marker_visible, `${label} rendered a product fallback marker.`);
}

async function navigate(cdp, label, route) {
  await click(cdp, textClickExpression("a", label), `${label} sidebar nav`);
  await waitEval(cdp, `location.pathname === ${JSON.stringify(route)}`, `${label} route`);
}

function importPanelSummaryExpression(summaryKind) {
  return `(() => {
    const panel = document.querySelector(".network-import-panel");
    if (!panel) return null;
    const summary = panel.querySelector('.network-import-preview[data-summary="${summaryKind}"]');
    if (!summary) return null;
    const badges = {};
    for (const badge of summary.querySelectorAll(".status-badge[data-status-label]")) {
      const label = badge.getAttribute("data-status-label");
      if (!label) continue;
      badges[label] = (badge.querySelector("strong")?.textContent || "").trim();
    }
    const confirmButton = [...panel.querySelectorAll("button.toolbar-button")]
      .find((button) => (button.textContent || "").trim() === "Confirm Ingest");
    const checkbox = panel.querySelector('label.response-check-row input[type="checkbox"]');
    return {
      badges,
      body: panel.innerText || "",
      confirm_disabled: confirmButton ? confirmButton.disabled : null,
      checkbox_checked: checkbox ? checkbox.checked : null,
    };
  })()`;
}

async function readImportSummary(cdp, summaryKind) {
  return cdp.eval(importPanelSummaryExpression(summaryKind));
}

async function readImportPanelDebugState(cdp) {
  return cdp.eval(`(() => {
    const panel = document.querySelector(".network-import-panel");
    if (!panel) return null;
    return {
      body: panel.innerText || "",
      has_error_callout: [...panel.querySelectorAll(".response-callout span")]
        .some((node) => (node.textContent || "").includes("Portable import returned a redacted error.")),
      confirm_button_disabled: [...panel.querySelectorAll("button.toolbar-button")]
        .find((candidate) => (candidate.textContent || "").trim() === "Confirm Ingest")?.disabled ?? null,
    };
  })()`);
}

async function waitImportSummary(cdp, summaryKind, expectedBadges, label) {
  let lastState = null;
  let lastDebug = null;
  try {
    return await waitFor(async () => {
      lastState = await readImportSummary(cdp, summaryKind);
      lastDebug = await readImportPanelDebugState(cdp);
      if (!lastState) {
        return null;
      }
      for (const [badgeLabel, badgeValue] of Object.entries(expectedBadges)) {
        if (lastState.badges[badgeLabel] !== String(badgeValue)) {
          return null;
        }
      }
      return lastState;
    }, label);
  } catch (error) {
    const detail = JSON.stringify({
      last_summary: lastState,
      last_panel: lastDebug,
      expected_badges: expectedBadges,
    });
    throw new Error(`${error.message}\n${detail}`);
  }
}

async function waitImportConfirmState(cdp, expectedDisabled, expectedChecked, label) {
  return waitFor(async () => {
    const state = await cdp.eval(`(() => {
      const panel = document.querySelector(".network-import-panel");
      if (!panel) return null;
      const button = [...panel.querySelectorAll("button.toolbar-button")]
        .find((candidate) => (candidate.textContent || "").trim() === "Confirm Ingest");
      const checkbox = panel.querySelector('label.response-check-row input[type="checkbox"]');
      if (!button || !checkbox) return null;
      return {
        disabled: button.disabled,
        checked: checkbox.checked,
      };
    })()`);
    if (!state) {
      return null;
    }
    if (state.disabled !== expectedDisabled || state.checked !== expectedChecked) {
      return null;
    }
    return state;
  }, label);
}

async function emitPortableDrop(cdp, path) {
  const result = await cdp.eval(`(async () => {
    const smokeDriver = window.__SENTINEL_SMOKE__?.portableImportDropPaths;
    if (typeof smokeDriver !== "function") {
      return { ok: false, reason: "portable import smoke driver unavailable" };
    }
    smokeDriver([${JSON.stringify(path)}]);
    return { ok: true };
  })()`);
  assert(
    result?.ok,
    `Failed to drive the portable import panel for ${splitFileName(path)}: ${result?.reason ?? "unknown reason"}`,
  );
}

async function assertUiClean(cdp, label) {
  const body = await cdp.eval(`document.body?.innerText || ""`);
  assertNoForbiddenText(label, body);
  return body;
}

async function selectNetworkView(cdp, label) {
  await click(cdp, textClickExpression(".network-view-item", label), `Network ${label} view`);
  return waitFor(async () => {
    const state = await cdp.eval(`(() => {
      if (location.pathname !== "/network") return null;
      const title = document.querySelector(".network-table-panel .analysis-panel-header strong")?.textContent?.trim();
      if (title !== ${JSON.stringify(label)}) return null;
      return {
        title,
        rows: document.querySelectorAll(".network-table-panel .network-table-row:not(.header):not(.network-table-empty)").length,
        local_graph_nodes: document.querySelectorAll(".local-connection-panel .graph-node-chip").length,
        body: document.body?.innerText || "",
      };
    })()`);
    return state;
  }, `Network ${label} table`);
}

async function captureNetworkCounts(cdp) {
  const flows = await selectNetworkView(cdp, "Flows");
  const dns = await selectNetworkView(cdp, "DNS");
  const tls = await selectNetworkView(cdp, "TLS");
  assertNoForbiddenText("Network Flows view", flows.body);
  assertNoForbiddenText("Network DNS view", dns.body);
  assertNoForbiddenText("Network TLS view", tls.body);
  assert(tls.local_graph_nodes >= 1, "Network local connection graph did not render graph chips.");
  return {
    flows: flows.rows,
    dns: dns.rows,
    tls: tls.rows,
    local_graph_nodes: tls.local_graph_nodes,
  };
}

async function importPortableFixture(cdp, fixture) {
  await emitPortableDrop(cdp, fixture.path);
  const preview = await waitImportSummary(
    cdp,
    "preview",
    {
      "Source type": fixture.sourceLabel,
      "Flows": fixture.preview.flows,
      "Sessions": fixture.preview.sessions,
      "DNS": fixture.preview.dns,
      "TLS": fixture.preview.tls,
      "HTTP": fixture.preview.http,
    },
    `${fixture.name} preview summary`,
  );
  assert(preview.badges["Provenance"], `${fixture.name} preview did not expose a provenance id.`);
  assert(preview.badges["Redaction"], `${fixture.name} preview did not expose a redaction status.`);
  assert(
    numericValue(preview.badges["Declared topics"], `${fixture.name} declared topic count`) >= 1,
    `${fixture.name} preview did not expose any declared topics.`,
  );
  assertNoForbiddenText(`${fixture.name} preview`, preview.body);
  await waitImportConfirmState(
    cdp,
    true,
    false,
    `${fixture.name} confirm disabled before approval`,
  );
  await click(
    cdp,
    textClickExpression("label.response-check-row", "This redacted preview is approved for metadata ingest"),
    `${fixture.name} preview approval`,
  );
  await waitImportConfirmState(
    cdp,
    false,
    true,
    `${fixture.name} confirm enabled after approval`,
  );
  await click(
    cdp,
    exactTextClickExpression("button.toolbar-button", "Confirm Ingest"),
    `${fixture.name} confirm ingest`,
  );
  const result = await waitImportSummary(
    cdp,
    "result",
    {
      "Source type": fixture.sourceLabel,
      "Flows": fixture.preview.flows,
      "Sessions": fixture.preview.sessions,
      "DNS": fixture.preview.dns,
      "TLS": fixture.preview.tls,
      "HTTP": fixture.preview.http,
      "Report traceability": "ready",
    },
    `${fixture.name} result summary`,
  );
  assert(result.badges["Provenance"], `${fixture.name} result did not preserve provenance id.`);
  assert(
    numericValue(result.badges["Findings"], `${fixture.name} finding count`) > 0,
    `${fixture.name} result did not report findings.`,
  );
  assertNoForbiddenText(`${fixture.name} result`, result.body);
  return {
    preview_badges: preview.badges,
    result_badges: result.badges,
    graph_hints_present: result.badges["Graph hints"] === "present",
    findings: numericValue(result.badges["Findings"], `${fixture.name} finding count`),
    alerts: numericValue(result.badges["Alerts"], `${fixture.name} alert count`),
    incidents: numericValue(result.badges["Incidents"], `${fixture.name} incident count`),
  };
}

async function readReportsState(cdp) {
  const state = await cdp.eval(`(() => {
    if (location.pathname !== "/reports") return null;
    const body = document.body?.textContent || "";
    return {
      body,
      redaction_passed: body.includes("Policy") && body.includes("Passed"),
      export_history_rows: document.querySelectorAll(".export-history-row:not(.header):not(.export-history-empty)").length,
      command_export_history_rows: document.querySelectorAll('.export-history-row[data-source="command"]').length,
      session_export_history_rows: document.querySelectorAll('.export-history-row[data-source="session"]').length,
      trace_headers_visible: body.includes("Graph refs") && body.includes("Evidence refs") && body.includes("Response refs"),
      command_rows_with_graph_refs: Array.from(document.querySelectorAll('.export-history-row[data-source="command"]'))
        .filter((row) => Number(row.getAttribute("data-graph-ref-count") || "0") > 0).length,
      command_rows_with_evidence_refs: Array.from(document.querySelectorAll('.export-history-row[data-source="command"]'))
        .filter((row) => Number(row.getAttribute("data-evidence-ref-count") || "0") > 0).length,
      command_rows_with_response_refs: Array.from(document.querySelectorAll('.export-history-row[data-source="command"]'))
        .filter((row) => Number(row.getAttribute("data-response-ref-count") || "0") > 0).length,
      sensitive_value_visible: /(?:api[_ -]?key|session[_ -]?token|password|authorization|cookie)\s*[:=]\s*\S+/i.test(body),
    };
  })()`);
  if (!state) {
    throw new Error("Reports page state was unavailable.");
  }
  return state;
}

async function setReportDestinationMetadata(cdp, value) {
  const updatedValue = await cdp.eval(`(() => {
    const section = [...document.querySelectorAll(".report-side-panel")]
      .find((panel) => (panel.querySelector(".analysis-panel-header strong")?.textContent || "").trim() === "Export detail");
    if (!section) return null;
    const input = section.querySelector('input:not([type="checkbox"])');
    if (!input) return null;
    const descriptor = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value");
    descriptor?.set?.call(input, ${JSON.stringify(value)});
    input.dispatchEvent(new Event("input", { bubbles: true }));
    input.dispatchEvent(new Event("change", { bubbles: true }));
    return input.value;
  })()`);
  assert(updatedValue === value, "Failed to set report export destination metadata.");
}

async function requestAppShutdown(cdp) {
  const result = await cdp.eval(`(() => {
    const invoke = window.__TAURI__?.core?.invoke;
    if (typeof invoke !== "function") {
      return { ok: false, reason: "core.invoke unavailable" };
    }
    void invoke("shutdown_app");
    return { ok: true };
  })()`, false);
  assert(result?.ok, `Failed to request app shutdown: ${result?.reason ?? "unknown reason"}`);
}

async function exportSelectedReport(cdp, baselineRows) {
  await setReportDestinationMetadata(cdp, "portable import traceability");
  await click(
    cdp,
    textClickExpression("label.response-check-row", "Redaction and local export confirmed"),
    "Reports export confirmation",
  );
  await click(
    cdp,
    exactTextClickExpression("button.toolbar-button", "Export"),
    "Reports export button",
  );
  const state = await waitFor(async () => {
    const current = await readReportsState(cdp);
    if (current.export_history_rows <= baselineRows) {
      return null;
    }
    return current;
  }, "Reports export history refresh after export");
  return state;
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
  const cdp = await connect(mainTarget);
  try {
    await waitEval(cdp, `document.readyState === "complete"`, "main document complete");
    await waitEval(
      cdp,
      `document.querySelector('nav[aria-label="Primary navigation"]') !== null`,
      "primary navigation",
    );

    await click(cdp, textClickExpression('button[title="Run safe demo story"]', "Demo"), "safe demo trigger");
    await sleep(1500);
    await waitEval(
      cdp,
      `(() => {
        const button = document.querySelector('button[title="Run safe demo story"]');
        return button && !button.disabled && (button.textContent || "").includes("Demo");
      })()`,
      "safe demo replay completion",
    );

    const pages = [];

    await navigate(cdp, "Investigation", "/investigation");
    const baselineInvestigation = await waitEval(
      cdp,
      pageEvidenceExpression(
        "/investigation",
        ".case-list-row:not(.header):not(.case-list-empty)",
        6,
        `body.includes("Case list")`,
      ),
      "Investigation command-backed cases",
    );
    assertCommandBackedPage("Investigation", baselineInvestigation);
    await assertUiClean(cdp, "Investigation baseline UI");
    pages.push({ page: "Investigation baseline", ...baselineInvestigation });

    await navigate(cdp, "Network", "/network");
    const baselineNetwork = await waitEval(
      cdp,
      pageEvidenceExpression(
        "/network",
        ".network-table-row:not(.header):not(.network-table-empty)",
        4,
        `body.includes("Flows") && body.includes("DNS") && body.includes("TLS")`,
      ),
      "Network command-backed metadata",
    );
    await navigate(cdp, "Reports", "/reports");
    const reportsBefore = await waitEval(
      cdp,
      pageEvidenceExpression(
        "/reports",
        ".report-list-row",
        1,
        `body.includes("Redaction summary") && body.includes("Policy") && body.includes("Passed") && body.includes("Export history")`,
      ),
      "Reports redacted command data",
    );
    assertCommandBackedPage("Reports", reportsBefore, 0);
    const reportSafetyBefore = await readReportsState(cdp);
    assert(reportSafetyBefore.redaction_passed, "Reports page did not show a passed redaction policy.");
    assert(reportSafetyBefore.export_history_rows >= 1, "Reports page did not render command-backed export history.");
    assert(reportSafetyBefore.command_export_history_rows >= 1, "Reports page export history did not expose command source.");
    assert(reportSafetyBefore.trace_headers_visible, "Reports page export history did not expose graph/evidence/response ref headers.");
    assert(reportSafetyBefore.command_rows_with_graph_refs >= 1, "Reports page export history did not expose command-backed graph refs.");
    assert(reportSafetyBefore.command_rows_with_evidence_refs >= 1, "Reports page export history did not expose command-backed evidence refs.");
    assert(reportSafetyBefore.command_rows_with_response_refs >= 1, "Reports page export history did not expose command-backed response refs.");
    assert(!reportSafetyBefore.sensitive_value_visible, "Reports page rendered a sensitive-looking value.");
    assertNoForbiddenText("Reports baseline UI", reportSafetyBefore.body);
    pages.push({ page: "Reports baseline", ...reportsBefore, ...reportSafetyBefore });

    await navigate(cdp, "Network", "/network");
    const baselineNetworkCounts = await captureNetworkCounts(cdp);

    const harImport = await importPortableFixture(cdp, {
      name: "HAR",
      path: harPath,
      sourceLabel: "HAR metadata",
      preview: {
        flows: 4,
        sessions: 4,
        dns: 0,
        tls: 4,
        http: 4,
      },
    });
    const networkAfterHar = await captureNetworkCounts(cdp);
    assert(
      networkAfterHar.flows === baselineNetworkCounts.flows + 4,
      `HAR import did not refresh flow rows by +4 (before=${baselineNetworkCounts.flows}, after=${networkAfterHar.flows}).`,
    );
    assert(
      networkAfterHar.dns === baselineNetworkCounts.dns,
      `HAR import unexpectedly changed DNS rows (before=${baselineNetworkCounts.dns}, after=${networkAfterHar.dns}).`,
    );
    assert(
      networkAfterHar.tls === baselineNetworkCounts.tls + 4,
      `HAR import did not refresh TLS rows by +4 (before=${baselineNetworkCounts.tls}, after=${networkAfterHar.tls}).`,
    );

    const jsonlImport = await importPortableFixture(cdp, {
      name: "JSONL",
      path: jsonlPath,
      sourceLabel: "JSONL metadata",
      preview: {
        flows: 2,
        sessions: 2,
        dns: 1,
        tls: 1,
        http: 2,
      },
    });
    const networkAfterJsonl = await captureNetworkCounts(cdp);
    assert(
      networkAfterJsonl.flows === baselineNetworkCounts.flows + 6,
      `JSONL import did not refresh flow rows to baseline+6 (before=${baselineNetworkCounts.flows}, after=${networkAfterJsonl.flows}).`,
    );
    assert(
      networkAfterJsonl.dns === baselineNetworkCounts.dns + 1,
      `JSONL import did not refresh DNS rows by +1 (before=${baselineNetworkCounts.dns}, after=${networkAfterJsonl.dns}).`,
    );
    assert(
      networkAfterJsonl.tls === baselineNetworkCounts.tls + 5,
      `JSONL import did not refresh TLS rows to baseline+5 (before=${baselineNetworkCounts.tls}, after=${networkAfterJsonl.tls}).`,
    );
    await assertUiClean(cdp, "Network post-import UI");
    pages.push({
      page: "Network portable import",
      baseline: baselineNetworkCounts,
      after_har: networkAfterHar,
      after_jsonl: networkAfterJsonl,
      har_import: harImport,
      jsonl_import: jsonlImport,
    });

    await navigate(cdp, "Investigation", "/investigation");
    const investigationAfterImport = await waitEval(
      cdp,
      pageEvidenceExpression(
        "/investigation",
        ".case-list-row:not(.header):not(.case-list-empty)",
        baselineInvestigation.records + 1,
        `body.includes("Case list")`,
      ),
      "Investigation cases after portable imports",
    );
    assertCommandBackedPage("Investigation post-import", investigationAfterImport);
    assert(
      investigationAfterImport.records > baselineInvestigation.records,
      `Portable imports did not increase investigation cases (before=${baselineInvestigation.records}, after=${investigationAfterImport.records}).`,
    );
    await assertUiClean(cdp, "Investigation post-import UI");
    pages.push({ page: "Investigation post-import", ...investigationAfterImport });

    await navigate(cdp, "Graph", "/graph");
    const graph = await waitEval(
      cdp,
      pageEvidenceExpression(
        "/graph",
        ".react-flow__node",
        1,
        `body.includes("Nodes 13") && body.includes("Edges 14") && body.includes("command")`,
      ),
      "Graph command-backed GraphViewModel",
    );
    assertCommandBackedPage("Graph", graph);
    await assertUiClean(cdp, "Graph UI");
    pages.push({
      page: "Graph",
      portable_graph_hints_present: harImport.graph_hints_present || jsonlImport.graph_hints_present,
      ...graph,
    });

    await navigate(cdp, "Response", "/response");
    const response = await waitEval(
      cdp,
      pageEvidenceExpression(
        "/response",
        ".response-table-row:not(.header):not(.response-table-empty)",
        1,
        `body.includes("Recommended actions") && body.includes("Frontend execution") && body.includes("Unavailable") && body.includes("Execution disabled")`,
      ),
      "Response recommend-only actions",
    );
    assertCommandBackedPage("Response", response);
    await click(cdp, textClickExpression(".response-view-button", "Active"), "Response Active view");
    const activeState = await waitEval(
      cdp,
      `(() => {
        const body = document.body?.textContent || "";
        const activeRows = document.querySelectorAll(".response-table-active .response-table-row:not(.header):not(.response-table-empty)").length;
        if (!body.includes("No active response executions are reported by Rust Core.")) return null;
        return { active_rows: activeRows, execution_disabled: body.includes("Execution disabled") };
      })()`,
      "Response no active execution state",
    );
    assert(activeState.active_rows === 0, "Response page reported active execution during safe demo replay.");
    assert(activeState.execution_disabled, "Response page did not expose disabled execution safety state.");
    await assertUiClean(cdp, "Response UI");
    pages.push({ page: "Response", ...response, ...activeState });

    await navigate(cdp, "Reports", "/reports");
    const reportsAfterImport = await waitEval(
      cdp,
      pageEvidenceExpression(
        "/reports",
        ".report-list-row",
        1,
        `body.includes("Redaction summary") && body.includes("Policy") && body.includes("Passed") && body.includes("Export history")`,
      ),
      "Reports redacted command data after portable imports",
    );
    assertCommandBackedPage("Reports post-import", reportsAfterImport, 0);
    const reportSafetyAfterExport = await exportSelectedReport(
      cdp,
      reportSafetyBefore.export_history_rows,
    );
    assert(
      reportSafetyAfterExport.export_history_rows > reportSafetyBefore.export_history_rows,
      "Reports export history did not grow after export.",
    );
    assert(reportSafetyAfterExport.trace_headers_visible, "Reports page lost export-history trace headers after export.");
    assert(reportSafetyAfterExport.command_rows_with_graph_refs >= 1, "Reports page did not expose command-backed graph refs after export.");
    assert(reportSafetyAfterExport.command_rows_with_evidence_refs >= 1, "Reports page did not expose command-backed evidence refs after export.");
    assert(reportSafetyAfterExport.command_rows_with_response_refs >= 1, "Reports page did not expose command-backed response refs after export.");
    assert(!reportSafetyAfterExport.sensitive_value_visible, "Reports page rendered a sensitive-looking value after export.");
    assertNoForbiddenText("Reports post-import UI", reportSafetyAfterExport.body);
    pages.push({
      page: "Reports post-import",
      ...reportsAfterImport,
      before_export_history_rows: reportSafetyBefore.export_history_rows,
      ...reportSafetyAfterExport,
    });

    await navigate(cdp, "Settings", "/settings");
    await click(cdp, textClickExpression(".settings-section-button", "Runtime Profile"), "Settings Runtime Profile section");
    const settings = await waitEval(
      cdp,
      pageEvidenceExpression(
        "/settings",
        ".settings-status-row",
        6,
        `body.includes("Runtime profile") && body.includes("Profile source") && body.includes("command")`,
      ),
      "Settings command-backed runtime profile",
    );
    assertCommandBackedPage("Settings", settings);
    await click(cdp, textClickExpression(".settings-section-button", "Service Status"), "Settings Service Status section");
    const serviceState = await waitEval(
      cdp,
      `(() => {
        const body = document.body?.textContent || "";
        const lower = body.toLowerCase();
        const portable = /portable[- ]no[- ]retention/.test(lower);
        if (!lower.includes("service status") || !lower.includes("profile mode") || !portable) return null;
        return {
          status_rows: document.querySelectorAll(".settings-status-row").length,
          profile_mode_portable: portable,
          source_command: lower.includes("source") && lower.includes("command"),
        };
      })()`,
      "Settings portable service status",
    );
    assert(serviceState.source_command, "Settings service status did not expose command source.");
    await assertUiClean(cdp, "Settings UI");
    pages.push({ page: "Settings", ...settings, ...serviceState });

    console.log(JSON.stringify({
      status: "pass",
      main_url: mainTarget.url,
      demo_trigger: "toolbar mutation",
      forbidden_marker_count: forbiddenMarkers.length,
      pages,
    }));
    await requestAppShutdown(cdp);
    await sleep(1000);
  } finally {
    cdp.close();
  }
}

main().catch((error) => {
  console.error(error?.stack ?? String(error));
  process.exit(1);
});
'@

$utf8NoBom = [System.Text.UTF8Encoding]::new($false)
[System.IO.File]::WriteAllText($nodeScript, $nodeSource, $utf8NoBom)
[System.IO.Directory]::CreateDirectory($fixtureRoot) | Out-Null
[System.IO.File]::WriteAllText(
    $harFixturePath,
    @'
{"log":{"entries":[{"startedDateTime":"2026-06-11T02:00:00Z","time":150,"serverIPAddress":"203.0.113.10","request":{"method":"POST","url":"https://uploader.example.test/upload/42?access_token=secret","headersSize":240,"bodySize":64000,"headers":[{"name":"User-Agent","value":"curl/8.8.0"}]},"response":{"status":201,"headersSize":180,"bodySize":1024,"headers":[],"content":{"mimeType":"application/json","size":1024}}},{"startedDateTime":"2026-06-11T02:00:10Z","time":80,"serverIPAddress":"203.0.113.10","request":{"method":"POST","url":"https://uploader.example.test/upload/43?user=alice","headersSize":220,"bodySize":1024,"headers":[{"name":"User-Agent","value":"curl/8.8.0"}]},"response":{"status":201,"headersSize":180,"bodySize":120,"headers":[],"content":{"mimeType":"application/json","size":120}}},{"startedDateTime":"2026-06-11T02:00:20Z","time":75,"serverIPAddress":"203.0.113.10","request":{"method":"POST","url":"https://uploader.example.test/upload/44?session_token=shh","headersSize":220,"bodySize":1100,"headers":[{"name":"User-Agent","value":"curl/8.8.0"}]},"response":{"status":201,"headersSize":180,"bodySize":110,"headers":[],"content":{"mimeType":"application/json","size":110}}},{"startedDateTime":"2026-06-11T02:00:30Z","time":70,"serverIPAddress":"203.0.113.10","request":{"method":"POST","url":"https://uploader.example.test/upload/45?path=C:/Users/Alice/Desktop","headersSize":220,"bodySize":1200,"headers":[{"name":"User-Agent","value":"curl/8.8.0"}]},"response":{"status":201,"headersSize":180,"bodySize":100,"headers":[],"content":{"mimeType":"application/json","size":100}}}]}}
'@,
    $utf8NoBom
)
[System.IO.File]::WriteAllText(
    $jsonlFixturePath,
    @'
{"timestamp":"2026-06-11T10:05:00Z","src_ip":"192.0.2.15","src_port":51515,"dst_ip":"203.0.113.22","dst_port":443,"protocol":"tcp","direction":"outbound","bytes_out":72000,"bytes_in":2200,"packets_out":5,"packets_in":3,"http":{"method":"POST","url":"https://jsonl.example.test/upload/9?token=abcdef1234567890","status_code":200,"request_size_bytes":72000,"response_size_bytes":2200,"content_type":"application/json","user_agent":"python-requests/2.32.0"},"dns":{"query_name":"api.jsonl.example.test","query_type":"A","resolver_ip":"192.0.2.53","client_ip":"192.0.2.15","answers":[{"answer_type":"ip","value":"203.0.113.22","ttl_seconds":60}]},"tls":{"sni":"api.jsonl.example.test","alpn":["h2"],"tls_version":"TLS1.3","cipher_suite":"TLS_AES_256_GCM_SHA384"}}
{"timestamp":"2026-06-11T10:05:30Z","src_ip":"192.0.2.15","src_port":51516,"dst_ip":"203.0.113.22","dst_port":443,"protocol":"tcp","direction":"outbound","bytes_out":76000,"bytes_in":1800,"packets_out":5,"packets_in":2,"http":{"method":"POST","url":"https://jsonl.example.test/upload/10?path=C:/Users/Alice/Desktop","status_code":200,"request_size_bytes":76000,"response_size_bytes":1800,"content_type":"application/json","user_agent":"python-requests/2.32.0"}}
'@,
    $utf8NoBom
)

$viteProcess = $null
$desktopProcess = $null
$startedVite = $false
$portableImportSmokeTest = "desktop_portable_capture_import_smoke_covers_har_jsonl_traceability_and_cleanup"
try {
    $previousErrorActionPreference = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    try {
        $portableImportOutput = & $cargo.Source test -p sentinel-guard-desktop $portableImportSmokeTest --lib 2>&1
        $portableImportExit = $LASTEXITCODE
    }
    finally {
        $ErrorActionPreference = $previousErrorActionPreference
    }
    if ($portableImportExit -ne 0) {
        $portableImportText = ($portableImportOutput | ForEach-Object { Convert-NativeOutputLine -Line $_ }) -join [Environment]::NewLine
        throw "Portable import native smoke preflight failed with exit code $portableImportExit`n$portableImportText"
    }

    if (-not (Test-HttpEndpoint -Uri $DevUrl)) {
        $viteProcess = Start-Process `
            -FilePath $node.Source `
            -ArgumentList @($viteScript, "--host", "localhost", "--port", "1420", "--strictPort") `
            -WorkingDirectory $FrontendRoot `
            -RedirectStandardOutput $viteStdoutPath `
            -RedirectStandardError $viteStderrPath `
            -WindowStyle Hidden `
            -PassThru
        $startedVite = $true
        Wait-HttpEndpoint -Uri $DevUrl -Seconds 30
    }

    $desktopProcess = Start-Process `
        -FilePath $binaryPath `
        -ArgumentList @("--profile", "portable") `
        -WorkingDirectory $binaryDir `
        -RedirectStandardOutput $stdoutPath `
        -RedirectStandardError $stderrPath `
        -WindowStyle Hidden `
        -PassThru

    $previousErrorActionPreference = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    try {
        $nodeOutput = & $node.Source $nodeScript $port ($TimeoutSeconds * 1000) $harFixturePath $jsonlFixturePath 2>&1
        $nodeExit = $LASTEXITCODE
    }
    finally {
        $ErrorActionPreference = $previousErrorActionPreference
    }
    $nodeText = ($nodeOutput | ForEach-Object { Convert-NativeOutputLine -Line $_ }) -join [Environment]::NewLine
    if ($nodeExit -ne 0) {
        throw "Native command-backed demo smoke failed with exit code $nodeExit`n$nodeText"
    }

    $remainingPreviewArtifacts = Get-CaptureImportPreviewArtifactCount -SessionsRoot $sessionsRoot
    if ($remainingPreviewArtifacts -ne 0) {
        throw "Portable import preview cleanup failed; found $remainingPreviewArtifacts preview artifacts under $sessionsRoot."
    }

    try {
        Wait-Process -Id $desktopProcess.Id -Timeout 15 -ErrorAction Stop
    }
    catch {
        Stop-OwnedProcess -Process $desktopProcess
    }
    $desktopProcess = $null

    $remainingSessions = Get-SessionDirectoryCount -SessionsRoot $sessionsRoot
    if ($remainingSessions -ne 0) {
        throw "Portable session cleanup failed; found $remainingSessions session directories in $sessionsRoot."
    }

    $stdout = Get-Content -LiteralPath $stdoutPath -Raw -ErrorAction SilentlyContinue
    $stderr = Get-Content -LiteralPath $stderrPath -Raw -ErrorAction SilentlyContinue
    $viteStdout = Get-Content -LiteralPath $viteStdoutPath -Raw -ErrorAction SilentlyContinue
    $viteStderr = Get-Content -LiteralPath $viteStderrPath -Raw -ErrorAction SilentlyContinue
    $forbiddenMarkers = @(
        $harFixturePath,
        $jsonlFixturePath,
        ($harFixturePath -replace "\\", "/"),
        ($jsonlFixturePath -replace "\\", "/"),
        [System.IO.Path]::GetFileName($harFixturePath),
        [System.IO.Path]::GetFileName($jsonlFixturePath),
        "access_token=secret",
        "session_token=shh",
        "token=abcdef1234567890",
        "uploader.example.test/upload/42",
        "uploader.example.test/upload/43",
        "uploader.example.test/upload/44",
        "uploader.example.test/upload/45",
        "jsonl.example.test/upload/9",
        "jsonl.example.test/upload/10",
        "C:/Users/Alice/Desktop",
        "Alice",
        "user=alice",
        "curl/8.8.0",
        "python-requests/2.32.0"
    )
    Assert-NoForbiddenMarkers -Label "Native desktop stdout" -Text $stdout -Markers $forbiddenMarkers
    Assert-NoForbiddenMarkers -Label "Native desktop stderr" -Text $stderr -Markers $forbiddenMarkers
    Assert-NoForbiddenMarkers -Label "Vite stdout" -Text $viteStdout -Markers $forbiddenMarkers
    Assert-NoForbiddenMarkers -Label "Vite stderr" -Text $viteStderr -Markers $forbiddenMarkers
    if (-not $stdout.Contains("STARTUP_PORTABLE_NO_RETENTION")) {
        throw "Native demo smoke did not record portable no-retention startup evidence."
    }
    if (-not $stdout.Contains("DEMO_STORY_REPLAY")) {
        throw "Native demo smoke did not record safe demo replay evidence."
    }

    $details = $nodeText | ConvertFrom-Json
    $details | Add-Member -NotePropertyName binary -NotePropertyValue $binaryPath
    $details | Add-Member -NotePropertyName remote_debugging_port -NotePropertyValue $port
    $details | Add-Member -NotePropertyName vite_started_by_smoke -NotePropertyValue $startedVite
    $details | Add-Member -NotePropertyName initial_portable_sessions -NotePropertyValue $initialSessions
    $details | Add-Member -NotePropertyName remaining_import_preview_artifacts -NotePropertyValue $remainingPreviewArtifacts
    $details | Add-Member -NotePropertyName remaining_portable_sessions -NotePropertyValue $remainingSessions
    $details | Add-Member -NotePropertyName runtime_demo_replay_logged -NotePropertyValue $true
    $details | Add-Member -NotePropertyName portable_no_retention_logged -NotePropertyValue $true
    $details | Add-Member -NotePropertyName portable_import_smoke_test -NotePropertyValue $portableImportSmokeTest
    $details | Add-Member -NotePropertyName portable_import_formats -NotePropertyValue @("har", "jsonl")
    $details | ConvertTo-Json -Depth 24
}
finally {
    Stop-OwnedProcess -Process $desktopProcess
    if ($startedVite) {
        Stop-OwnedProcess -Process $viteProcess
    }
    $env:WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS = $previousWebViewArgs
    if (Test-Path -LiteralPath $nodeScript) {
        Remove-Item -LiteralPath $nodeScript -Force
    }
    if (Test-Path -LiteralPath $fixtureRoot) {
        Remove-Item -LiteralPath $fixtureRoot -Recurse -Force
    }
}
