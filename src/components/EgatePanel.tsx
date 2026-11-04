import { formatError, formatMessage } from '../uiText';
import { useCallback, useEffect, useState } from 'react';
import { invoke } from '@tauri-apps/api/core';
import {
  CheckCircle2,
  Globe2,
  Loader2,
  RefreshCw,
  RotateCcw,
  Save,
  ShieldAlert,
  XCircle,
} from 'lucide-react';
import type { AppConfig, CutState, EgateReport, EgateTarget, EnvCheck, LeakReport, TripReport } from './types';

/** 锚点类型的中文名（技术值只在展示时翻译）。 */
const ANCHOR_LABELS: Record<string, string> = {
  auto: '自动识别',
  trace: 'Cloudflare trace',
  json_ip: 'JSON IP',
  gemini_region: '页面地区标记',
  reachability: '仅可达性',
};

/** 判定结果的中文标签与样式类。 */
const VERDICT_LABELS: Record<string, { text: string; cls: string }> = {
  pass: { text: '通过', cls: 'pill ok' },
  fail: { text: '未通过', cls: 'pill bad' },
  unverified: { text: '无法确认', cls: 'pill muted' },
  disabled: { text: '已停用', cls: 'pill muted' },
};

/** 接入路径的中文标签。 */
const ACCESS_LABELS: Record<string, string> = {
  system_proxy: '系统代理',
  tun: 'TUN 直连',
  uncovered: '未接入代理',
  unknown: '无法确认',
};

const emptyTarget = (): EgateTarget => ({
  id: '',
  name: '',
  anchor_url: 'https://',
  anchor_kind: 'auto',
  expect_ips: [],
  expect_regions: [],
  enabled: true,
  timeout_secs: 10,
});

/**
 * 出口门禁面板（融合 ClaudeGuard 的按目标出口校验）。
 *
 * 当前批次交付：目标表查看/编辑/保存/恢复默认、开关与阈值、单轮检查与接入路径。
 * 熔断执行（结束进程 / 防火墙隔离 / 断网）按批次接入，界面会明确说明当前只报告不熔断。
 */
export function EgatePanel() {
  const [config, setConfig] = useState<AppConfig | null>(null);
  const [targets, setTargets] = useState<EgateTarget[]>([]);
  const [report, setReport] = useState<EgateReport | null>(null);
  const [tripReport, setTripReport] = useState<TripReport | null>(null);
  const [leakReport, setLeakReport] = useState<LeakReport | null>(null);
  const [cutState, setCutState] = useState<CutState | null>(null);
  const [cutMode, setCutMode] = useState<'off' | 'firewall' | 'nics'>('off');
  const [networkNote, setNetworkNote] = useState<string | null>(null);
  const [monitor, setMonitor] = useState<{ paused: boolean; remaining_secs: number; tripped: boolean } | null>(null);
  const [launchNote, setLaunchNote] = useState<string | null>(null);
  const [envCheck, setEnvCheck] = useState<EnvCheck | null>(null);
  const [envNote, setEnvNote] = useState<string | null>(null);
  const [quarantineCount, setQuarantineCount] = useState<number | null>(null);
  const [loading, setLoading] = useState(true);
  const [checking, setChecking] = useState(false);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [note, setNote] = useState<string | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const cfg = await invoke<AppConfig>('get_appconfig');
      setConfig(cfg);
      setTargets(cfg.egate_targets?.length ? cfg.egate_targets : await invoke<EgateTarget[]>('egate_get_targets'));
    } catch (e) {
      setConfig(null);
      setError(formatError(e));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  const check = async () => {
    setChecking(true);
    setError(null);
    setNote(null);
    try {
      const result = await invoke<EgateReport>('egate_check_once');
      setReport(result);
    } catch (e) {
      setReport(null);
      setError(formatError(e));
    } finally {
      setChecking(false);
    }
  };

  const refreshQuarantine = useCallback(async () => {
    try {
      const count = await invoke<number | null>('egate_quarantine_count');
      setQuarantineCount(count);
    } catch {
      setQuarantineCount(null);
    }
  }, []);

  useEffect(() => {
    refreshQuarantine();
    invoke<CutState | null>('egate_cut_state')
      .then(setCutState)
      .catch(() => setCutState(null));
    invoke<{ paused: boolean; remaining_secs: number; tripped: boolean }>('egate_monitor_status')
      .then(setMonitor)
      .catch(() => setMonitor(null));
  }, [refreshQuarantine]);

  /** 通过门禁启动 Claude（出口未通过会被拒绝）。 */
  const launchClaude = async () => {
    setSaving(true);
    setError(null);
    setLaunchNote(null);
    try {
      const result = await invoke<{ launched: boolean; reason?: string; note?: string }>(
        'egate_launch_claude',
      );
      setLaunchNote(
        result.launched
          ? formatMessage(result.note ?? '已请求启动 Claude')
          : formatMessage(result.reason ?? '出口校验未通过，已阻止启动'),
      );
    } catch (e) {
      setError(formatError(e));
    } finally {
      setSaving(false);
    }
  };

  /** 环境一致性检查（只读）。 */
  const checkEnv = async () => {
    setChecking(true);
    setError(null);
    setEnvNote(null);
    try {
      setEnvCheck(await invoke<EnvCheck>('egate_env_check'));
    } catch (e) {
      setEnvCheck(null);
      setError(formatError(e));
    } finally {
      setChecking(false);
    }
  };

  /** 把时区对齐到出口（走账本，可还原）。 */
  const alignEnv = async () => {
    setSaving(true);
    setError(null);
    setEnvNote(null);
    try {
      const record = await invoke<{ city: string; tz_from: string; tz_to: string }>(
        'egate_env_align',
        { city: '' },
      );
      setEnvNote(`已将时区从 ${record.tz_from} 改为 ${record.tz_to}（可随时还原）`);
      setEnvCheck(await invoke<EnvCheck>('egate_env_check').catch(() => null));
    } catch (e) {
      setError(formatError(e));
    } finally {
      setSaving(false);
    }
  };

  /** 按账本还原环境。 */
  const restoreEnv = async () => {
    setSaving(true);
    setError(null);
    setEnvNote(null);
    try {
      setEnvNote(formatMessage(await invoke<string>('egate_env_restore')));
      setEnvCheck(await invoke<EnvCheck>('egate_env_check').catch(() => null));
    } catch (e) {
      setError(formatError(e));
    } finally {
      setSaving(false);
    }
  };

  /** 暂停 / 恢复守护。 */
  const togglePause = async () => {
    setSaving(true);
    setError(null);
    try {
      if (monitor?.paused) {
        await invoke('egate_resume');
      } else {
        await invoke('egate_pause', { minutes: 30 });
      }
      setMonitor(
        await invoke<{ paused: boolean; remaining_secs: number; tripped: boolean }>(
          'egate_monitor_status',
        ).catch(() => null),
      );
    } catch (e) {
      setError(formatError(e));
    } finally {
      setSaving(false);
    }
  };

  /** 执行断网（最高强度动作，需二次确认）。 */
  const cutNetwork = async () => {
    if (cutMode === 'off') {
      setNetworkNote('请先选择断网档位。');
      return;
    }
    const label = cutMode === 'nics' ? '禁用物理网卡' : '防火墙全局阻断';
    // 断网会让整机断网，必须显式确认。
    if (!window.confirm(`确认执行「${label}」？这会让整台电脑暂时断网，直到你点「恢复网络」。`)) {
      return;
    }
    setSaving(true);
    setError(null);
    setNetworkNote(null);
    try {
      const result = await invoke<{ ok: boolean; note: string }>('egate_cut_network', { mode: cutMode });
      setNetworkNote(formatMessage(result.note));
      setCutState(await invoke<CutState | null>('egate_cut_state').catch(() => null));
    } catch (e) {
      setError(formatError(e));
    } finally {
      setSaving(false);
    }
  };

  /** 恢复网络。 */
  const restoreNetwork = async () => {
    setSaving(true);
    setError(null);
    setNetworkNote(null);
    try {
      const result = await invoke<{ ok: boolean; note: string }>('egate_restore_network');
      setNetworkNote(formatMessage(result.note));
      setCutState(await invoke<CutState | null>('egate_cut_state').catch(() => null));
    } catch (e) {
      setError(formatError(e));
    } finally {
      setSaving(false);
    }
  };

  /** 执行熔断：结束守护对象进程 + 防火墙隔离（真实系统修改）。 */
  const trip = async () => {
    setSaving(true);
    setError(null);
    setNote(null);
    try {
      const result = await invoke<TripReport>('egate_trip_now');
      setTripReport(result);
      await refreshQuarantine();
    } catch (e) {
      setError(formatError(e));
    } finally {
      setSaving(false);
    }
  };

  /** 观察被守护进程是否绕过系统代理直连公网（只读）。 */
  const watchLeak = async () => {
    setChecking(true);
    setError(null);
    setNote(null);
    try {
      setLeakReport(await invoke<LeakReport>('egate_leak_watch'));
    } catch (e) {
      setLeakReport(null);
      setError(formatError(e));
    } finally {
      setChecking(false);
    }
  };

  /** 解除全部隔离规则。 */
  const release = async () => {    setSaving(true);
    setError(null);
    setNote(null);
    try {
      const removed = await invoke<number>('egate_release_now');
      setTripReport(null);
      await refreshQuarantine();
      setNote(`已解除隔离（清理 ${removed} 条规则）。`);
    } catch (e) {
      setError(formatError(e));
    } finally {
      setSaving(false);
    }
  };

  const save = async () => {
    setSaving(true);
    setError(null);
    setNote(null);
    try {
      await invoke('egate_save_targets', { targets });
      const enabled = config?.egate_enabled ?? false;
      await invoke('egate_update_settings', {
        enabled,
        tripThreshold: config?.egate_trip_threshold ?? 2,
        intervalSecs: config?.egate_interval_secs ?? 15,
        enforceAccess: config?.egate_enforce_access ?? true,
        leakTrip: config?.egate_leak_trip ?? false,
      });
      setNote('目标配置已保存。');
      await load();
    } catch (e) {
      setError(formatError(e));
    } finally {
      setSaving(false);
    }
  };

  const reset = async () => {
    setSaving(true);
    setError(null);
    setNote(null);
    try {
      const defaults = await invoke<EgateTarget[]>('egate_reset_targets');
      setTargets(defaults);
      setNote('已恢复内置默认目标。保存后生效。');
    } catch (e) {
      setError(formatError(e));
    } finally {
      setSaving(false);
    }
  };

  const update = (index: number, patch: Partial<EgateTarget>) => {
    setTargets((prev) => prev.map((item, i) => (i === index ? { ...item, ...patch } : item)));
  };

  const busy = loading || checking || saving;
  const overall = report?.overall;

  return (
    <div className="panel">
      <div className="panel-title">
        <Globe2 />
        <span>出口门禁（按目标校验）</span>
      </div>

      <p className="telemetry-intro">
        每个被守护的目标各测各的出口：Claude 走 claude.ai、Codex 走 chatgpt.com，互不牵连。
        任一启用目标未通过才判定失败；拿不到出口信息时只报告「无法确认」，不会误判。
        受支持的出口地区为新加坡、日本、美国三选一。
      </p>

      <div className="clash-summary" style={{ gridTemplateColumns: 'repeat(3, minmax(0,1fr))' }}>
        <div>
          <span>整体判定</span>
          <strong>
            {overall
              ? VERDICT_LABELS[overall.verdict]?.text ?? overall.verdict
              : loading
                ? '读取中'
                : '未检查'}
          </strong>
        </div>
        <div>
          <span>接入路径</span>
          <strong>
            {report ? ACCESS_LABELS[report.access.path] ?? report.access.path : '未检查'}
          </strong>
        </div>
        <div>
          <span>启用状态</span>
          <strong>{config?.egate_enabled ? '已开启' : '已关闭'}</strong>
        </div>
      </div>

      {report?.skipped_reason && (
        <div className="inline-warning" style={{ marginTop: 10 }}>
          {formatMessage(report.skipped_reason)}
        </div>
      )}

      <div className="profile-actions" style={{ marginTop: 12 }}>
        <button className="primary" onClick={check} disabled={busy}>
          {checking ? <Loader2 className="spin" /> : <RefreshCw />}
          立即检查一轮
        </button>
        <button className="ghost" onClick={save} disabled={busy || !targets.length}>
          {saving ? <Loader2 className="spin" /> : <Save />}
          保存目标配置
        </button>
        <button className="ghost" onClick={reset} disabled={busy} title="恢复内置默认目标表">
          <RotateCcw />
          恢复默认
        </button>
      </div>

      <div className="profile-actions" style={{ marginTop: 8 }}>
        <button
          className="danger"
          onClick={trip}
          disabled={busy}
          title="结束守护对象进程并按 exe 施加防火墙隔离（真实系统修改）"
        >
          {saving ? <Loader2 className="spin" /> : <ShieldAlert />}
          执行熔断（结束进程 + 隔离）
        </button>
        <button className="ghost" onClick={release} disabled={busy} title="删除本工具添加的全部隔离规则">
          <RotateCcw />
          解除隔离
        </button>
        <button className="ghost" onClick={watchLeak} disabled={busy} title="检查被守护进程是否绕过代理直连公网">
          <ShieldAlert />
          直连泄露观察
        </button>
        <button className="ghost" onClick={togglePause} disabled={busy} title="暂停期间照常检测，但不会执行熔断">
          {monitor?.paused ? '恢复守护' : '暂停守护 30 分钟'}
        </button>
        {monitor?.paused && (
          <span className="pill muted">
            已暂停（剩余 {Math.max(1, Math.round((monitor.remaining_secs ?? 0) / 60))} 分钟）
          </span>
        )}
        {monitor?.tripped && <span className="pill bad">熔断中</span>}
        {quarantineCount !== null && (
          <span className="pill muted">当前隔离规则：{quarantineCount} 条</span>
        )}
      </div>

      <div className="profile-actions" style={{ marginTop: 8 }}>
        <button className="primary" onClick={launchClaude} disabled={busy} title="通过出口校验后才启动 Claude">
          <CheckCircle2 />
          通过门禁启动 Claude
        </button>
        {launchNote && (
          <span className="usage-note" style={{ alignSelf: 'center' }}>
            {launchNote}
          </span>
        )}
      </div>

      <div style={{ marginTop: 14, paddingTop: 12, borderTop: '1px dashed rgba(72,66,52,0.25)' }}>
        <strong style={{ fontSize: 13 }}>断网档位（最高强度熔断动作）</strong>
        <div className="telemetry-options" style={{ marginTop: 8 }}>
          {([
            ['off', '不断网'],
            ['firewall', '防火墙全局阻断'],
            ['nics', '禁用物理网卡'],
          ] as const).map(([value, label]) => (
            <button
              key={value}
              className={cutMode === value ? 'primary' : 'ghost'}
              onClick={() => setCutMode(value)}
              disabled={busy}
            >
              {label}
            </button>
          ))}
        </div>
        <div className="profile-actions" style={{ marginTop: 8 }}>
          <button className="danger" onClick={cutNetwork} disabled={busy || cutMode === 'off'}>
            执行断网
          </button>
          <button className="ghost" onClick={restoreNetwork} disabled={busy}>
            恢复网络
          </button>
          {cutState && (
            <span className="pill bad">当前处于断网状态（{cutState.mode}）</span>
          )}
        </div>
        {networkNote && (
          <div className="inline-warning" style={{ marginTop: 8 }}>
            {networkNote}
          </div>
        )}
        <p className="usage-note" style={{ marginTop: 8 }}>
          断网会让整台电脑暂时无法上网。断网现场会写入本机账本，程序崩溃或被结束后
          下次启动会自动恢复网络。
        </p>
      </div>

      <div style={{ marginTop: 14, paddingTop: 12, borderTop: '1px dashed rgba(72,66,52,0.25)' }}>
        <strong style={{ fontSize: 13 }}>环境一致性（时区与出口）</strong>
        <div className="profile-actions" style={{ marginTop: 8 }}>
          <button className="ghost" onClick={checkEnv} disabled={busy}>
            检查一致性
          </button>
          <button className="ghost" onClick={alignEnv} disabled={busy}>
            对齐到时区出口
          </button>
          <button className="ghost" onClick={restoreEnv} disabled={busy}>
            还原环境改动
          </button>
        </div>
        {envCheck && (
          <div className={envCheck.mismatched ? 'inline-warning' : 'inline-success'} style={{ marginTop: 8 }}>
            {formatMessage(envCheck.note)}
          </div>
        )}
        {envNote && <div className="inline-success" style={{ marginTop: 8 }}>{envNote}</div>}
        <p className="usage-note" style={{ marginTop: 8 }}>
          检查只提示不熔断（保持中文系统是正当选择）。对齐会记录改动前的值，
          随时可以一键还原。
        </p>
      </div>

      {leakReport && (
        <div
          className={leakReport.direct_total > 0 ? 'inline-warning' : 'inline-success'}
          style={{ marginTop: 10 }}
        >
          <strong>
            {leakReport.applicable
              ? `直连观察：${leakReport.direct_total} 条直连`
              : '直连观察：本次不具备判定条件'}
          </strong>
          <div style={{ marginTop: 4, fontSize: 12 }}>
            {formatMessage(leakReport.note)}
            {leakReport.applicable &&
              `（被守护连接 ${leakReport.agent_conns}：走代理 ${leakReport.proxied}，本地 ${leakReport.local}）`}
          </div>
          {leakReport.direct.map((conn) => (
            <div key={`${conn.pid}-${conn.remote}-${conn.port}`} style={{ marginTop: 2, fontSize: 12 }}>
              {conn.agent}（PID {conn.pid}）→ {conn.remote}:{conn.port}
            </div>
          ))}
        </div>
      )}

      {tripReport && (
        <div className={tripReport.isolated ? 'inline-warning' : 'inline-error'} style={{ marginTop: 10 }}>
          <strong>{tripReport.note}</strong>
          {tripReport.agents.map((agent) => (
            <div key={agent.agent} style={{ marginTop: 4, fontSize: 12 }}>
              {agent.agent}：
              {agent.verified
                ? `已隔离（${agent.rules_verified} 条规则生效${
                    agent.killed.length ? `，结束 ${agent.killed.length} 个进程` : ''
                  }）`
                : `未确认生效（${formatMessage(agent.note)}）`}
            </div>
          ))}
        </div>
      )}

      {note && <div className="inline-success" style={{ marginTop: 10 }}>{note}</div>}
      {error && (
        <div className="inline-error" style={{ marginTop: 10 }}>
          <ShieldAlert /> {error}
        </div>
      )}

      {report && report.targets.length > 0 && (
        <div className="check-list" style={{ marginTop: 14 }}>
          {report.targets.map((item) => {
            const info = VERDICT_LABELS[item.verdict] ?? VERDICT_LABELS.unverified;
            return (
              <div className="check-row" key={item.id}>
                <span className={`check-dot ${item.verdict === 'pass' ? 'ok' : item.verdict === 'fail' ? 'fail' : 'warn'}`}>
                  {item.verdict === 'pass' ? <CheckCircle2 /> : <XCircle />}
                </span>
                <div className="check-row-body">
                  <strong>
                    {item.name} <span className={info.cls}>{info.text}</span>
                  </strong>
                  <span>
                    {formatMessage(item.reason)}
                    {item.ip ? ` · 出口 ${item.ip}` : ''}
                    {item.country ? `（${item.country}）` : ''}
                    {` · ${item.latency_ms}ms`}
                    {item.fail_streak > 0 ? ` · 连续失败 ${item.fail_streak} 次` : ''}
                  </span>
                </div>
              </div>
            );
          })}
        </div>
      )}

      <div style={{ marginTop: 16 }}>
        <strong style={{ fontSize: 13 }}>监控目标</strong>
        {loading && <div className="empty">正在读取目标配置…</div>}
        {!loading && targets.length === 0 && (
          <div className="empty">没有配置任何目标。点「恢复默认」写入内置目标表。</div>
        )}
        {targets.map((target, index) => (
          <div key={`${index}-${target.id}`} className="mcp-form" style={{ marginTop: 10 }}>
            <div className="mcp-form-head">
              <input
                value={target.name}
                placeholder="目标名称，例如 Claude 出口"
                onChange={(e) => update(index, { name: e.target.value })}
                disabled={busy}
                style={{ flex: 1 }}
              />
              <select
                value={target.anchor_kind}
                onChange={(e) => update(index, { anchor_kind: e.target.value as EgateTarget['anchor_kind'] })}
                disabled={busy}
              >
                {Object.entries(ANCHOR_LABELS).map(([value, label]) => (
                  <option key={value} value={value}>
                    {label}
                  </option>
                ))}
              </select>
              <label className="perm-check">
                <input
                  type="checkbox"
                  checked={target.enabled}
                  onChange={(e) => update(index, { enabled: e.target.checked })}
                  disabled={busy}
                />
                启用
              </label>
            </div>            <input
              value={target.anchor_url}
              placeholder="探测地址，例如 https://claude.ai/cdn-cgi/trace"
              onChange={(e) => update(index, { anchor_url: e.target.value })}
              disabled={busy}
            />
            <div className="mcp-form-head">
              <input
                value={target.expect_ips.join(', ')}
                placeholder="期望出口 IP（逗号分隔，可留空）"
                onChange={(e) =>
                  update(index, {
                    expect_ips: e.target.value
                      .split(/[,，]/)
                      .map((v) => v.trim())
                      .filter(Boolean),
                  })
                }
                disabled={busy}
              />
              <input
                value={target.expect_regions.join(', ')}
                placeholder="期望地区码（逗号分隔，如 US,JP）"
                onChange={(e) =>
                  update(index, {
                    expect_regions: e.target.value
                      .split(/[,，]/)
                      .map((v) => v.trim())
                      .filter(Boolean),
                  })
                }
                disabled={busy}
              />
              <input
                type="number"
                value={target.timeout_secs}
                min={1}
                max={30}
                title="单次探测超时（秒）"
                onChange={(e) => update(index, { timeout_secs: Number(e.target.value) || 10 })}
                disabled={busy}
                style={{ width: 80 }}
              />
            </div>
          </div>
        ))}
      </div>

      <p className="usage-note" style={{ marginTop: 12 }}>
        熔断会结束守护对象的进程并按可执行文件施加出/入站防火墙阻断（需管理员权限），
        隔离后回查规则确已生效才报告成功。未接入代理链路时本工具不会发起探测，
        避免把真实家宽出口暴露给被测站点。断网档位、自愈账本与常驻循环尚未接入。
      </p>
    </div>
  );
}
