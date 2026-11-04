import { compactNumber, formatError } from '../uiText';
import { useCallback, useEffect, useMemo, useState } from 'react';
import { invoke } from '@tauri-apps/api/core';
import { getCurrentWebviewWindow } from '@tauri-apps/api/webviewWindow';
import './ClaudeTrayPopup.css';

interface ProfileMeta {
  email?: string | null;
  subscription_type?: string | null;
  rate_limit_tier?: string | null;
}

interface ClaudeStatus {
  keychain_exists: boolean;
  keychain_parse_ok: boolean;
  current_profile_name?: string | null;
  meta: ProfileMeta;
}

interface ClashStatus {
  available: boolean;
  now?: string | null;
}

interface TokenTotals {
  input_tokens: number;
  cache_creation_input_tokens: number;
  cache_read_input_tokens: number;
  output_tokens: number;
  total_tokens: number;
}

interface UsageWindow {
  label: string;
  totals: TokenTotals;
  message_count: number;
  reset_at?: string | null;
  used_percent?: number | null;
}

interface ClaudeUsageSnapshot {
  updated_at: string;
  scanned_files: number;
  scanned_messages: number;
  latest_message_at?: string | null;
  session: UsageWindow;
  weekly: UsageWindow;
  today: UsageWindow;
  last_30_days: UsageWindow;
  top_model?: string | null;
}

interface TrayData {
  status: ClaudeStatus | null;
  clash: ClashStatus | null;
  usage: ClaudeUsageSnapshot | null;
}

const PLAN_CAPACITY = {
  standard: {
    session: 250_000_000,
    weekly: 1_000_000_000,
  },
  max: {
    session: 1_000_000_000,
    weekly: 5_000_000_000,
  },
};


function displayedTokens(totals?: TokenTotals | null) {
  if (!totals) return 0;
  return totals.total_tokens ?? 0;
}

function formatCountdown(value?: string | null) {
  if (!value) return '未知';
  const diff = new Date(value).getTime() - Date.now();
  if (diff <= 0) return '已重置';
  const minutes = Math.floor(diff / 60000);
  const hours = Math.floor(minutes / 60);
  const rest = minutes % 60;
  return hours > 0 ? `${hours} 小时 ${rest} 分钟` : `${rest} 分钟`;
}

function shortEmail(value?: string | null) {
  if (!value) return '未读取账号';
  const [name, domain] = value.split('@');
  if (!domain) return value;
  return `${name.slice(0, 3)}***@${domain}`;
}

function accountLabel(status: ClaudeStatus | null) {
  if (status?.meta.email) return shortEmail(status.meta.email);
  return status?.current_profile_name || '未读取账号';
}

function planLabel(status: ClaudeStatus | null) {
  return status?.meta.subscription_type || status?.meta.rate_limit_tier || 'Claude';
}

function capacities(status: ClaudeStatus | null) {
  const label = `${status?.meta.subscription_type ?? ''} ${status?.meta.rate_limit_tier ?? ''}`;
  return /max|team|enterprise/i.test(label) ? PLAN_CAPACITY.max : PLAN_CAPACITY.standard;
}

function remainingPercent(window: UsageWindow | undefined, capacity: number) {
  if (typeof window?.used_percent === 'number') {
    return Math.max(0, Math.min(100, Math.round(100 - window.used_percent)));
  }
  if (!window || capacity <= 0) return 100;
  const used = Math.min(100, (window.totals.total_tokens / capacity) * 100);
  return Math.max(0, Math.round(100 - used));
}

function statusClass(percent: number) {
  if (percent > 50) return 'healthy';
  if (percent > 10) return 'warning';
  return 'critical';
}

function statusLabel(percent: number) {
  if (percent > 50) return '充足';
  if (percent > 10) return '偏低';
  return '不足';
}

function QuotaCard({
  icon,
  title,
  percent,
  resetAt,
}: {
  icon: string;
  title: string;
  percent: number;
  resetAt?: string | null;
}) {
  const level = statusClass(percent);
  return (
    <div className={`ctp-card ${level}`}>
      <div className="ctp-card-header">
        <span className="ctp-card-icon">{icon}</span>
        <span>{title}</span>
        <span className={`ctp-status ${level}`}>{statusLabel(percent)}</span>
      </div>
      <div className="ctp-card-value">
        {percent}
        <span className="ctp-unit">%</span>
        <span className="ctp-remaining">剩余</span>
      </div>
      <div className="ctp-progress">
        <div className={`ctp-progress-bar ${level}`} style={{ width: `${percent}%` }} />
      </div>
      <div className="ctp-reset">距离重置：{formatCountdown(resetAt)}</div>
    </div>
  );
}

export function ClaudeTrayPopup() {
  const [data, setData] = useState<TrayData>({ status: null, clash: null, usage: null });
  const [loading, setLoading] = useState(false);

  const fetchData = useCallback(async () => {
    setLoading(true);
    try {
      // 三个调用各自兜底：任何一个失败都不该让整个弹窗停在旧数据上
      // （原实现 get_status 没有 catch，reject 会冒泡成未处理的 Promise 异常）。
      const [status, clash, usage] = await Promise.all([
        invoke<ClaudeStatus>('get_status').catch(() => null),
        invoke<ClashStatus>('get_clash_status').catch(() => null),
        invoke<ClaudeUsageSnapshot>('get_claude_usage').catch(() => null),
      ]);
      // status 失败时保留上一次的账号信息，只更新成功拿到的部分。
      setData((prev) => ({
        status: status ?? prev.status,
        clash,
        usage: usage ?? prev.usage,
      }));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    document.documentElement.classList.add('is-claude-tray-popup');
    document.body.classList.add('is-claude-tray-popup');

    let interval: number | undefined;
    const start = () => {
      if (interval !== undefined) return;
      // 弹窗重新可见时立刻刷新一次，再按 30 秒轮询。
      fetchData();
      interval = window.setInterval(fetchData, 30000);
    };
    const stop = () => {
      if (interval === undefined) return;
      window.clearInterval(interval);
      interval = undefined;
    };
    // 关键：弹窗失焦后由后端 hide()，但组件并不卸载——不暂停的话
    // 隐藏状态下仍每 30 秒跑一次 get_claude_usage（全量扫 ~/.claude/projects）。
    const onVisibility = () =>
      document.visibilityState === 'visible' ? start() : stop();

    start();
    document.addEventListener('visibilitychange', onVisibility);

    return () => {
      stop();
      document.removeEventListener('visibilitychange', onVisibility);
      document.documentElement.classList.remove('is-claude-tray-popup');
      document.body.classList.remove('is-claude-tray-popup');
    };
  }, [fetchData]);

  const cap = useMemo(() => capacities(data.status), [data.status]);
  const sessionLeft = remainingPercent(data.usage?.session, cap.session);
  const weeklyLeft = remainingPercent(data.usage?.weekly, cap.weekly);
  const sessionTokens = displayedTokens(data.usage?.session.totals);
  const todayTokens = displayedTokens(data.usage?.today.totals);
  const proxyOn = !!data.clash?.available;
  const keychainOk = !!data.status?.keychain_exists && !!data.status?.keychain_parse_ok;

  const openDashboard = async () => {
    await invoke('show_main_window_cmd');
    await getCurrentWebviewWindow().hide();
  };

  return (
    <div className="claude-tray-popup">
      <div className="ctp-header">
        <div className="ctp-title">
          <div className="ctp-logo">✦</div>
          <div>
            <div className="ctp-name">Claude 账号切换器</div>
            <div className="ctp-subtitle">用量监测</div>
          </div>
        </div>
        <div className={proxyOn ? 'ctp-badge running' : 'ctp-badge'}>
          ● {proxyOn ? '代理可用' : '代理未连接'}
        </div>
      </div>

      <div className="ctp-account">
        {accountLabel(data.status)}
        <span className="ctp-plan">{planLabel(data.status)}</span>
        <span className={keychainOk ? 'ctp-auth ok' : 'ctp-auth'}>{keychainOk ? '凭据正常' : '凭据缺失'}</span>
      </div>

      <div className="ctp-cards">
        <QuotaCard
          icon="⚡"
          title="会话额度估算"
          percent={sessionLeft}
          resetAt={data.usage?.session.reset_at}
        />
        <QuotaCard
          icon="◷"
          title="每周额度估算"
          percent={weeklyLeft}
          resetAt={data.usage?.weekly.reset_at}
        />
      </div>

      <div className="ctp-cards">
        <div className="ctp-card today">
          <div className="ctp-card-header">
            <span className="ctp-card-icon">☉</span>
            <span>今日用量</span>
          </div>
          <div className="ctp-card-value today-value">
            {compactNumber(todayTokens)}
            <span className="ctp-remaining">词元</span>
          </div>
          <div className="ctp-token-detail">
            {data.usage?.today.message_count ?? 0} 条用量记录
          </div>
        </div>

        <div className="ctp-card tokens">
          <div className="ctp-card-header">
            <span className="ctp-card-icon">#</span>
            <span>会话词元用量</span>
          </div>
          <div className="ctp-card-value token-value">
            {compactNumber(sessionTokens)}
            <span className="ctp-remaining">词元</span>
          </div>
          <div className="ctp-token-detail">
            输入 {compactNumber(data.usage?.session.totals.input_tokens)} / 输出{' '}
            {compactNumber(data.usage?.session.totals.output_tokens)}
          </div>
        </div>
      </div>

      <div className="ctp-meta">
        <span>模型</span>
        <b>{data.usage?.top_model || '暂无'}</b>
      </div>
      <div className="ctp-meta">
        <span>代理节点</span>
        <b>{data.clash?.now || '未读取'}</b>
      </div>

      <div className="ctp-actions">
        <button className="ctp-btn primary" onClick={openDashboard}>
          打开主界面
        </button>
        <button className="ctp-btn" onClick={fetchData} disabled={loading}>
          {loading ? '刷新中' : '刷新'}
        </button>
      </div>
    </div>
  );
}
