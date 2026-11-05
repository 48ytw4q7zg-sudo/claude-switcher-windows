# 03-restore-ledger.ps1 -- cut ledger + intent + rules all converge after restore
#
# Run ONLY on a rollbackable Windows VM, as Administrator.
#
# Usage (repo root):
#   cd src-tauri; cargo build --bin cs; cd ..
#   .\tests\windows-integration\03-restore-ledger.ps1
#
# SAFETY (L-18): refuses to run when real product state is present.
#
# What it proves (P2-01): the restore path cleans up a REAL cut transaction -
# a genuinely constructed netcut ledger, a real firewall rule, and the
# uncovered-lock intent + ready record - not just "files I happened to find".

$ErrorActionPreference = 'Stop'

$repoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$cs = Join-Path $repoRoot 'src-tauri\target\debug\cs.exe'
if (-not (Test-Path $cs)) {
    Write-Host "FAIL: missing binary $cs (run: cargo build --bin cs)" -ForegroundColor Red
    exit 2
}

# Portable mode redirects the data dir; detect it so the fixture lands in the
# same place the binary reads from.
$dataDir = Join-Path $repoRoot 'ClaudeSwitcherData'
if (-not (Test-Path $dataDir)) { $dataDir = Join-Path $env:USERPROFILE '.claude-switcher' }

$lockFile  = Join-Path $dataDir 'eguard-uncovered-lock.json'
$readyFile = Join-Path $dataDir 'eguard-uncovered-lock-ready.json'
$cutFile   = Join-Path $dataDir 'netcut.json'

function Get-ProductRuleCount {
    try {
        @(Get-NetFirewallRule -DisplayName 'ClaudeSwitcher*' -ErrorAction Stop).Count
    } catch {
        throw "cannot query existing ClaudeSwitcher rules: $($_.Exception.Message)"
    }
}

$failures = New-Object System.Collections.ArrayList
Write-Host "== 03 restore ledger consistency ==" -ForegroundColor Cyan

# L-18: refuse to touch a machine that already has product state.
try {
    $startCount = Get-ProductRuleCount
} catch {
    Write-Host "FAIL: $($_.Exception.Message)" -ForegroundColor Red
    exit 2
}
if ($startCount -ne 0) {
    Write-Host "FAIL: this machine already has $startCount ClaudeSwitcher rule(s)." -ForegroundColor Red
    Write-Host "      Restore those via the product itself; start from a clean VM snapshot." -ForegroundColor Red
    exit 3
}
if ((Test-Path $cutFile) -or (Test-Path $lockFile)) {
    Write-Host "FAIL: existing product state present in $dataDir - refusing to overwrite it." -ForegroundColor Red
    exit 3
}

New-Item -ItemType Directory -Force $dataDir | Out-Null

# ---- 1. Build a REAL cut transaction ledger (firewall mode, no NICs) ----
# shape: egate_netcut::CutState, written by the product when it cuts the network.
$ledger = @{
    mode                = 'firewall'
    firewall            = $true
    planned_adapters    = @()
    completed_adapters  = @()
    adapter_snapshots   = @()
    nics                = @()
    since               = [int][double]::Parse((Get-Date -UFormat %s))
    # CutPhase is snake_case in serde: prepared | firewall_applied | nics_applied | applied
    phase               = 'firewall_applied'
} | ConvertTo-Json -Depth 5
Set-Content -Path $cutFile -Value $ledger -Encoding UTF8
Write-Host "  constructed cut ledger at $cutFile"

# ---- 2. Real firewall rule for the cut + uncovered intent/ready records ----
$exe = Join-Path $env:SystemRoot 'System32\notepad.exe'
New-NetFirewallRule -DisplayName 'ClaudeSwitcher Egate Cut All' `
    -Direction Outbound -Action Block -Enabled True -ErrorAction Stop | Out-Null
New-NetFirewallRule -DisplayName 'ClaudeSwitcher UncoveredLock ledger-test Out 000000000000' `
    -Direction Outbound -Action Block -Program $exe -Enabled True -ErrorAction Stop | Out-Null

Set-Content -Path $lockFile  -Value '{"since":0}' -Encoding UTF8
Set-Content -Path $readyFile -Value '{"verified_at":0,"revision":0,"rules":1,"agents":[]}' -Encoding UTF8

$pre = Get-ProductRuleCount
Write-Host "  prepared: rules=$pre lock=$(Test-Path $lockFile) ready=$(Test-Path $readyFile) ledger=$(Test-Path $cutFile)"
if ($pre -ne 2) { [void]$failures.Add("expected 2 prepared rules, got $pre") }

# ---- 3. Restore ----
& $cs --exit-restore
$exitCode = $LASTEXITCODE
Write-Host "  restore exit code = $exitCode"
if ($exitCode -ne 0) {
    [void]$failures.Add("--exit-restore should exit 0, got $exitCode")
}

$rules = Get-ProductRuleCount
Write-Host "  remaining rules = $rules"
if ($rules -ne 0) { [void]$failures.Add("rules should be cleared, got $rules") }

# The ledger is the network-cut transaction record: it must be gone once the
# network is confirmed restored (the product clears it in restore_locked()).
if (Test-Path $cutFile) { [void]$failures.Add("cut ledger should be cleared after a complete restore") }
if (Test-Path $lockFile) { [void]$failures.Add("uncovered intent file should be removed") }
if (Test-Path $readyFile) { [void]$failures.Add("uncovered ready file should be removed") }

Write-Host "  ledger exists = $(Test-Path $cutFile)"
Write-Host "  lock  exists = $(Test-Path $lockFile)"
Write-Host "  ready exists = $(Test-Path $readyFile)"

if ($failures.Count -eq 0) {
    Write-Host "PASS: 03 restore ledger consistency" -ForegroundColor Green
    exit 0
}
Write-Host "FAIL: 03 restore ledger consistency" -ForegroundColor Red
foreach ($f in $failures) { Write-Host "  - $f" -ForegroundColor Red }
exit 1
