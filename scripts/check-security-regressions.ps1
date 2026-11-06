# check-security-regressions.ps1 -- named security-regression groups
#
# Shared by .github/workflows/ci.yml and windows-build.yml so the two gates
# can never diverge (P2-02). Last release round they did: CI failed on a stale
# test name while the release build went green, because the release ran the
# unfiltered `cargo test --lib` while CI ran the named groups.
#
# Rules this script enforces:
#   * every group must match >= 1 test (cargo exits 0 even for 0 matches);
#   * every group must pass.
#
# Note: group names are SUBSTRING filters against test names. Renaming a test
# requires updating the list here -- otherwise it silently stops covering it.

$ErrorActionPreference = 'Continue'
Push-Location (Join-Path $PSScriptRoot '..\src-tauri')
try {
    $groups = @(
        'ps_protocol',
        'tun_path_requires_both_families_and_trusted_dns',
        'route_evidence_is_bound_to_its_target',
        'gui_identity_separates_cli_from_unknown',
        'classify_rejects_cli_and_unknown_paths',
        'arm_readiness_tests',
        'automatic_release_aborts_when_state_changed',
        'isolation_refuses_when_expected_revision_is_stale',
        'release_report_never_claims_success_with_failures',
        'aborted_trip_does_not_touch_isolation_state',
        'legacy_cleanup_never_targets_the_global_cut_rule',
        'tun_access_counts_only_with_route_evidence',
        'unknown_reconfirm_backs_off_and_caps',
        'auto_probe_requires_proven_udp_route',
        'unsigned_updates_are_never_auto_executed',
        'trip_summary',
        'trip_outcome_state_policy',
        'uncovered_auto_release',
        'strict_blocked_makes_zero_outbound_connections',
        'strict_proxy_path_is_used_and_redirects_are_refused',
        'tun_route_issuses_zero_dns_queries',
        'trusted_dns_channel_is_not_available_yet',
        'ready_reconciliation_only_counts_uncovered_source',
        'revision_bumps_only_for_security_relevant_changes',
        'strict_leak_mode_locks_down_on_unproven_access',
        'uncovered_lock_reason_distinguishes_strict_mode',
        # v0.7.6 additions
        'proxy_override_wildcards_follow_windows_semantics',
        'bypass_verdict_is_three_state_and_conservative',
        'verdict_rejects_system_proxy_when_bypass_risks_monitored_host',
        'builtin_claude_cannot_be_downgraded_to_reachability',
        'builtin_anchor_kind_is_pinned_in_both_directions',
        'lost_config_after_initialization_is_not_treated_as_fresh',
        'genuine_first_install_is_still_fresh',
        'ready_without_rule_specs_is_never_valid',
        'monitor_interval_is_clamped_to_monitor_range_not_probe_timeout',
        'kill_outcome_keeps_skipped_out_of_side_effects',
        # v0.7.7 additions
        'preparing_intent_is_never_cleared_as_orphan',
        'uncovered_txn_ids_are_unique',
        'legacy_intent_without_txn_refuses_auto_cleanup',
        'strict_leak_toggle_checks_prerequisites',
        'reset_targets_rejected_when_gate_is_armed',
        'task_lookup_is_three_state'
    )
    $failed = @()
    foreach ($g in $groups) {
        $output = & cargo test --lib $g 2>&1
        $code = $LASTEXITCODE
        if ($code -ne 0) {
            $failed += $g
            Write-Host "FAIL  $g"
        } else {
            # cargo returns 0 even when the filter matched nothing, so look at
            # the `test result:` line for a non-zero passed count.
            $summary = ($output | Select-String '^test result:' | Select-Object -Last 1)
            if (-not $summary -or $summary -notmatch 'ok\.\s+[1-9][0-9]*\s+passed') {
                $failed += "$g (no tests matched)"
                Write-Host "ZERO  $g"
            } else {
                Write-Host "OK    $g"
            }
        }
    }
    if ($failed.Count -gt 0) {
        Write-Host ""
        Write-Host "security regression scenarios failed or missing: $($failed -join ', ')" -ForegroundColor Red
        exit 1
    }
    Write-Host ""
    Write-Host "all $($groups.Count) security regression scenarios present and passing" -ForegroundColor Green
    exit 0
} finally {
    Pop-Location
}
