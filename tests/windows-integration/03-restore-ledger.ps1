# 03-restore-ledger.ps1 -- ledger + intent + rules converge after restore
#
# Run ONLY on a rollbackable Windows VM, as Administrator.
#
# Usage (repo root):
#   cd src-tauri; cargo build --bin cs; cd ..
#   .\tests\windows-integration\03-restore-ledger.ps1

$ErrorActionPreference = 'Stop'

$repoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$cs = Join-Path $repoRoot 'src-tauri\target\debug\cs.exe'
if (-not (Test-Path $cs)) {
    Write-Host "FAIL: missing binary $cs (run: cargo build --bin cs)" -ForegroundColor Red
    exit 2
}

# Data dir: portable mode uses .\ClaudeSwitcherData next to the exe;
# otherwise %USERPROFILE%\.claude-switcher.
$dataDir = Join-Path $env:USERPROFILE '.claude-switcher'
$lockFile = Join-Path $dataDir 'eguard-uncovered-lock.json'
$readyFile = Join-Path $dataDir 'eguard-uncovered-lock-ready.json'
$cutFile = Join-Path $dataDir 'eguard-network-cut.json'

$failures = New-Object System.Collections.ArrayList

Write-Host "== 03 restore ledger consistency ==" -ForegroundColor Cyan
& $cs --exit-restore | Out-Null

# Manufacture a realistic crime scene: one isolation rule + uncovered intent.
$exe = Join-Path $env:SystemRoot 'System32\notepad.exe'
New-NetFirewallRule -DisplayName 'ClaudeSwitcher UncoveredLock ledger-test Out 000000000000' `
    -Direction Outbound -Action Block -Program $exe -Enabled True | Out-Null

New-Item -ItemType Directory -Force $dataDir | Out-Null
Set-Content -Path $lockFile -Value '{"since":0}' -Encoding UTF8
Set-Content -Path $readyFile -Value '{"verified_at":0,"revision":0,"rules":1,"agents":[]}' -Encoding UTF8

# Best effort: a stale network-cut ledger if the schema allows it.
if (-not (Test-Path $cutFile)) {
    Write-Host "  (no network-cut ledger present; skipping that part)" -ForegroundColor Yellow
}

& $cs --exit-restore
$exitCode = $LASTEXITCODE
Write-Host "  restore exit code = $exitCode"
if ($exitCode -ne 0) {
    [void]$failures.Add("--exit-restore should exit 0, got $exitCode")
}

$ruleCount = @(Get-NetFirewallRule -DisplayName 'ClaudeSwitcher*' -ErrorAction SilentlyContinue).Count
Write-Host "  remaining rules = $ruleCount"
if ($ruleCount -ne 0) { [void]$failures.Add("rules should be cleared, got $ruleCount") }

if (Test-Path $lockFile) { [void]$failures.Add("uncovered intent file should be removed") }
if (Test-Path $readyFile) { [void]$failures.Add("uncovered ready file should be removed") }

Write-Host "  lock file exists  = $(Test-Path $lockFile)"
Write-Host "  ready file exists = $(Test-Path $readyFile)"
Write-Host "  cut ledger exists = $(Test-Path $cutFile)"

if ($failures.Count -eq 0) {
    Write-Host "PASS: 03 restore ledger consistency" -ForegroundColor Green
    exit 0
}
Write-Host "FAIL: 03 restore ledger consistency" -ForegroundColor Red
foreach ($f in $failures) { Write-Host "  - $f" -ForegroundColor Red }
exit 1
