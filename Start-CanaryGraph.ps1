param([switch]$NoBrowser)
$ErrorActionPreference = 'Stop'
$runtime = Get-Command node -ErrorAction SilentlyContinue
if ($runtime) { $nodePath = $runtime.Source }
else {
    $bundledNode = Join-Path $env:USERPROFILE '.cache\codex-runtimes\codex-primary-runtime\dependencies\node\bin\node.exe'
    if (Test-Path -LiteralPath $bundledNode) { $nodePath = $bundledNode }
    else { throw 'Node.js 20 or newer is required. Install it from nodejs.org, then run this launcher again.' }
}
$labUrl = 'http://127.0.0.1:4317'
$serverFile = Join-Path $PSScriptRoot 'server.js'
try {
    $existing = Invoke-RestMethod -Uri "$labUrl/api/state" -TimeoutSec 2
    if ($existing.fingerprint -and $existing.csrf) {
        if (-not $NoBrowser) { Start-Process $labUrl }
        Write-Host "CanaryGraph is already running at $labUrl"
        return
    }
} catch { }
$stdoutFile = Join-Path $PSScriptRoot 'server.log'
$stderrFile = Join-Path $PSScriptRoot 'server-error.log'
$labProcess = Start-Process -FilePath $nodePath -ArgumentList @(('"' + $serverFile + '"')) -WorkingDirectory $PSScriptRoot -WindowStyle Hidden -PassThru -RedirectStandardOutput $stdoutFile -RedirectStandardError $stderrFile
Set-Content -LiteralPath (Join-Path $PSScriptRoot 'server.pid') -Value $labProcess.Id
$ready = $false
for ($attempt = 0; $attempt -lt 30; $attempt++) {
    if ($labProcess.HasExited) { throw (Get-Content -LiteralPath $stderrFile -Raw) }
    try {
        $health = Invoke-RestMethod -Uri "$labUrl/api/state" -TimeoutSec 1
        if ($health.fingerprint -and $health.csrf) { $ready = $true; break }
    } catch { }
    Start-Sleep -Milliseconds 200
}
if (-not $ready) { throw "Startup was not confirmed. Inspect $stderrFile" }
if (-not $NoBrowser) { Start-Process $labUrl }
Write-Host "CanaryGraph is running at $labUrl"
Write-Host 'Use Stop-CanaryGraph.ps1 to stop the local server.'
