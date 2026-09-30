$ErrorActionPreference = 'Stop'
$pidFile = Join-Path $PSScriptRoot 'server.pid'
if (-not (Test-Path -LiteralPath $pidFile)) { Write-Host 'No saved server process.'; return }
$labProcessId = [int](Get-Content -LiteralPath $pidFile)
$labProcess = Get-CimInstance Win32_Process -Filter "ProcessId = $labProcessId"
$expectedScript = Join-Path $PSScriptRoot 'server.js'
if ($labProcess -and $labProcess.Name -eq 'node.exe' -and $labProcess.CommandLine.Contains($expectedScript)) {
    Stop-Process -Id $labProcessId
    Write-Host 'CanaryGraph stopped. Your evidence is preserved.'
} elseif ($labProcess) { throw 'Saved process ID belongs to another process. Nothing was stopped.' }
else { Write-Host 'CanaryGraph is already stopped.' }
Remove-Item -LiteralPath $pidFile
