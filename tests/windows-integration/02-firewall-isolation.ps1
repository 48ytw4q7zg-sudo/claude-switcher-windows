# 02-firewall-isolation.ps1 -- three rule kinds coexist, full restore clears all
#
# Run ONLY on a rollbackable Windows VM, as Administrator.
# Creates and deletes real firewall rules; does not touch network adapters.
#
# Usage (repo root):
#   cd src-tauri; cargo build --bin cs; cd ..
#   .\tests\windows-integration\02-firewall-isolation.ps1
#
# SAFETY (L-18): this script REFUSES to run when the machine already holds
# ClaudeSwitcher product state. It must not be used to "clean up" a real
# developer machine - that is product recovery, not a test fixture.

$ErrorActionPreference = 'Stop'

$repoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$cs = Join-Path $repoRoot 'src-tauri\target\debug\cs.exe'
if (-not (Test-Path $cs)) {
    Write-Host "FAIL: missing binary $cs (run: cargo build --bin cs)" -ForegroundColor Red
    exit 2
}

function Get-ProductRuleCount {
    # L-18: use -ErrorAction Stop. With SilentlyContinue, "cannot query" is
    # indistinguishable from "zero rules" - the test would then report PASS on
    # a machine where it never actually checked anything.
    try {
        @(Get-NetFirewallRule -DisplayName 'ClaudeSwitcher*' -ErrorAction Stop).Count
    } catch {
        throw "cannot query existing ClaudeSwitcher rules: $($_.Exception.Message)"
    }
}

function Show-Evidence($label) {
    $count = Get-ProductRuleCount
    Write-Host ("  {0,-12} ClaudeSwitcher rules = {1}" -f $label, $count)
    return $count
}

$failures = New-Object System.Collections.ArrayList

Write-Host "== 02 firewall isolation and restore ==" -ForegroundColor Cyan

# L-18: refuse to run against a machine that already has product state.
# Running --exit-restore here would destroy a real user's isolation state.
try {
    $startCount = Get-ProductRuleCount
} catch {
    Write-Host "FAIL: $($_.Exception.Message)" -ForegroundColor Red
    exit 2
}
if ($startCount -ne 0) {
    Write-Host "FAIL: this machine already has $startCount ClaudeSwitcher rule(s)." -ForegroundColor Red
    Write-Host "      This script creates test rules; it must NOT be used to clear" -ForegroundColor Red
    Write-Host "      real product state. Restore those rules via the product itself." -ForegroundColor Red
    Write-Host "      Start from a clean VM snapshot." -ForegroundColor Red
    exit 3
}

$exe = Join-Path $env:SystemRoot 'System32\notepad.exe'
$rules = @(
    @{ Name = 'ClaudeSwitcher AppIsolation integration-test Out 0123456789ab'; Dir = 'Outbound' },
    @{ Name = 'ClaudeSwitcher AppIsolation integration-test In 0123456789ab';  Dir = 'Inbound'  },
    @{ Name = 'ClaudeSwitcher UncoveredLock integration-test Out fedcba987654'; Dir = 'Outbound' },
    @{ Name = 'ClaudeSwitcher Egate claude Out'; Dir = 'Outbound' }
)

foreach ($rule in $rules) {
    try {
        New-NetFirewallRule -DisplayName $rule.Name -Direction $rule.Dir -Action Block `
            -Program $exe -Enabled True -ErrorAction Stop | Out-Null
    } catch {
        [void]$failures.Add("create failed for $($rule.Name): $($_.Exception.Message)")
    }
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
