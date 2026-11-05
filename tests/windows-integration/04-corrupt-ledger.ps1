# 04-corrupt-ledger.ps1 -- a corrupt cut ledger must NOT be guessed at
#
# Run ONLY on a rollbackable Windows VM, as Administrator.
#
# P2-01 scenario: "断网账本损坏 -> 不猜测系统状态、不删除恢复信息".
#
# What it proves: when netcut.json cannot be parsed, the restore path must
# refuse to delete the firewall rule and must not overwrite the ledger. That
# record is the ONLY record of what was cut; destroying it would leave the
# machine with a blocking rule and no way to know what to restore.
# The expected outcome is therefore a NON-ZERO exit code from --egate-restore.

$ErrorActionPreference = 'Stop'

$repoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$cs = Join-Path $repoRoot 'src-tauri\target\debug\cs.exe'
if (-not (Test-Path $cs)) {
    Write-Host "FAIL: missing binary $cs (run: cargo build --bin cs)" -ForegroundColor Red
    exit 2
}

$dataDir = Join-Path $repoRoot 'ClaudeSwitcherData'
if (-not (Test-Path $dataDir)) { $dataDir = Join-Path $env:USERPROFILE '.claude-switcher' }
$cutFile = Join-Path $dataDir 'netcut.json'

function Get-ProductRuleCount {
    try {
        @(Get-NetFirewallRule -DisplayName 'ClaudeSwitcher*' -ErrorAction Stop).Count
    } catch {
        throw "cannot query existing ClaudeSwitcher rules: $($_.Exception.Message)"
    }
}

$failures = New-Object System.Collections.ArrayList
Write-Host "== 04 corrupt ledger must not be guessed ==" -ForegroundColor Cyan

try {
    $startCount = Get-ProductRuleCount
} catch {
    Write-Host "FAIL: $($_.Exception.Message)" -ForegroundColor Red
    exit 2
}
if ($startCount -ne 0) {
    Write-Host "FAIL: this machine already has $startCount ClaudeSwitcher rule(s); refusing to touch it." -ForegroundColor Red
    exit 3
}
if (Test-Path $cutFile) {
    Write-Host "FAIL: existing cut ledger in $dataDir - refusing to overwrite it." -ForegroundColor Red
    exit 3
}

New-Item -ItemType Directory -Force $dataDir | Out-Null

# A blocking rule + a ledger the product cannot parse.
New-NetFirewallRule -DisplayName 'ClaudeSwitcher Egate Cut All' `
    -Direction Outbound -Action Block -Enabled True -ErrorAction Stop | Out-Null
Set-Content -Path $cutFile -Value '{ this is not valid json' -Encoding UTF8

$before = Get-ProductRuleCount
Write-Host "  prepared: rules=$before corrupt-ledger=$(Test-Path $cutFile)"

& $cs --exit-restore
$exitCode = $LASTEXITCODE
Write-Host "  restore exit code = $exitCode"

# The safety property: refuse, and keep both the rule and the ledger.
if ($exitCode -eq 0) {
    [void]$failures.Add("restore must NOT report success when the ledger is unparseable")
}
$after = Get-ProductRuleCount
if ($after -ne $before) {
    [void]$failures.Add("rule count changed ($before -> $after); a corrupt ledger must not lead to deletions")
}
if (-not (Test-Path $cutFile)) {
    [void]$failures.Add("corrupt ledger must be preserved as the only record of what was cut")
}

Write-Host "  rules before=$before after=$after ledger-preserved=$(Test-Path $cutFile)"

# Cleanup: this fixture is a deliberate dead-end, so clear it here.
Remove-NetFirewallRule -DisplayName 'ClaudeSwitcher Egate Cut All' -ErrorAction SilentlyContinue
Remove-Item -LiteralPath $cutFile -Force -ErrorAction SilentlyContinue
Write-Host "  fixture cleaned up"

if ($failures.Count -eq 0) {
    Write-Host "PASS: 04 corrupt ledger is preserved, restore refuses" -ForegroundColor Green
    exit 0
}
Write-Host "FAIL: 04 corrupt ledger" -ForegroundColor Red
foreach ($f in $failures) { Write-Host "  - $f" -ForegroundColor Red }
exit 1
