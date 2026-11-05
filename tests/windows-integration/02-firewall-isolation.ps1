# 02-firewall-isolation.ps1 -- three rule kinds coexist, full restore clears all
#
# Run ONLY on a rollbackable Windows VM, as Administrator.
# Creates and deletes real firewall rules; does not touch network adapters.
#
# Usage (repo root):
#   cd src-tauri; cargo build --bin cs; cd ..
#   .\tests\windows-integration\02-firewall-isolation.ps1

$ErrorActionPreference = 'Stop'

$repoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$cs = Join-Path $repoRoot 'src-tauri\target\debug\cs.exe'
if (-not (Test-Path $cs)) {
    Write-Host "FAIL: missing binary $cs (run: cargo build --bin cs)" -ForegroundColor Red
    exit 2
}

function Get-ProductRuleCount {
    @(Get-NetFirewallRule -DisplayName 'ClaudeSwitcher*' -ErrorAction SilentlyContinue).Count
}

function Show-Evidence($label) {
    $count = Get-ProductRuleCount
    Write-Host ("  {0,-12} ClaudeSwitcher rules = {1}" -f $label, $count)
    return $count
}

$failures = New-Object System.Collections.ArrayList

Write-Host "== 02 firewall isolation and restore ==" -ForegroundColor Cyan
& $cs --exit-restore | Out-Null
$before = Show-Evidence 'BEFORE'
if ($before -ne 0) {
    Write-Host "  (start point not clean; recorded, continuing)" -ForegroundColor Yellow
}

$exe = Join-Path $env:SystemRoot 'System32\notepad.exe'
$rules = @(
    @{ Name = 'ClaudeSwitcher AppIsolation integration-test Out 0123456789ab'; Dir = 'Outbound' },
    @{ Name = 'ClaudeSwitcher AppIsolation integration-test In 0123456789ab'; Dir = 'Inbound' },
    @{ Name = 'ClaudeSwitcher UncoveredLock integration-test Out fedcba987654'; Dir = 'Outbound' },
    @{ Name = 'ClaudeSwitcher Egate claude Out'; Dir = 'Outbound' }
)
foreach ($rule in $rules) {
    New-NetFirewallRule -DisplayName $rule.Name -Direction $rule.Dir -Action Block `
        -Program $exe -Enabled True | Out-Null
}
$created = Show-Evidence 'CREATED'
if ($created -ne 4) {
    [void]$failures.Add("expected 4 rules after creation, got $created")
}

& $cs --exit-restore
$exitCode = $LASTEXITCODE
Write-Host "  restore exit code = $exitCode"
if ($exitCode -ne 0) {
    [void]$failures.Add("--exit-restore should exit 0, got $exitCode")
}

$after = Show-Evidence 'AFTER'
if ($after -ne 0) {
    [void]$failures.Add("rules should be cleared, got $after")
}

& $cs --exit-restore | Out-Null
$idempotent = $LASTEXITCODE
Write-Host "  second restore exit code = $idempotent"
if ($idempotent -ne 0) {
    [void]$failures.Add("idempotent restore should exit 0, got $idempotent")
}

if ($failures.Count -eq 0) {
    Write-Host "PASS: 02 firewall isolation and restore" -ForegroundColor Green
    exit 0
}
Write-Host "FAIL: 02 firewall isolation and restore" -ForegroundColor Red
foreach ($f in $failures) { Write-Host "  - $f" -ForegroundColor Red }
exit 1
